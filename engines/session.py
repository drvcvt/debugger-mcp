"""Debug session management for CDB/KD subprocesses.

Each DebugSession wraps a cdb.exe or kd.exe process, communicating
via stdin/stdout pipes with a background reader thread for non-blocking I/O.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .symbols import build_symbol_environment

logger = logging.getLogger("debugger-mcp")

# Prompt patterns
USERMODE_PROMPT = re.compile(r"\d+:\d+(:x86)?>\s*$")
KERNEL_PROMPT = re.compile(r"(lkd|kd)>\s*$")
INPUT_PROMPT = re.compile(r"\d+:\d+(:x86)?>\s*$|(?:lkd|kd)>\s*$")

# Debugger search locations
CDB_SEARCH_PATHS = [
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
    # WinDbg Preview (Microsoft Store)
    os.path.expandvars(
        r"%LOCALAPPDATA%\Microsoft\WindowsApps\cdb.exe"
    ),
]

KD_SEARCH_PATHS = [
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
    r"C:\Program Files\Windows Kits\10\Debuggers\x64\kd.exe",
    os.path.expandvars(
        r"%LOCALAPPDATA%\Microsoft\WindowsApps\kd.exe"
    ),
]

DEFAULT_COMMAND_TIMEOUT = 30.0
MAX_SESSIONS = 10


class DebuggerType(str, Enum):
    USERMODE = "usermode"
    KERNEL = "kernel"


class SessionState(str, Enum):
    STARTING = "starting"
    RUNNING = "running"
    BROKEN = "broken"  # Debugger has control (at breakpoint/initial break)
    EXITED = "exited"
    ERROR = "error"


def find_debugger(debugger_type: DebuggerType) -> str | None:
    """Find the debugger executable on the system.

    Checks PATH first, then known installation directories.
    """
    exe_name = "cdb.exe" if debugger_type == DebuggerType.USERMODE else "kd.exe"
    search_paths = CDB_SEARCH_PATHS if debugger_type == DebuggerType.USERMODE else KD_SEARCH_PATHS

    # Check PATH first
    found = shutil.which(exe_name)
    if found:
        return found

    # Check known locations
    for path_str in search_paths:
        p = Path(path_str)
        if p.exists():
            return str(p)

    return None


class OutputReader:
    """Background thread that reads debugger stdout and buffers output.

    Uses a threading.Event to signal when a prompt is detected,
    allowing the caller to wait for command completion.
    """

    def __init__(self, stream, debugger_type: DebuggerType):
        self._stream = stream
        self._debugger_type = debugger_type
        self._buffer = ""
        self._lock = threading.Lock()
        self._prompt_event = threading.Event()
        self._closed = False
        self._thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._thread.start()

    @property
    def prompt_pattern(self) -> re.Pattern:
        if self._debugger_type == DebuggerType.KERNEL:
            return KERNEL_PROMPT
        return USERMODE_PROMPT

    def _reader_loop(self):
        """Continuously read from the stream and buffer output."""
        try:
            while not self._closed:
                # read1() returns available bytes without blocking for full buffer
                chunk = self._stream.read1(4096) if hasattr(self._stream, 'read1') else self._stream.read(1)
                if not chunk:
                    break
                try:
                    text = chunk.decode("utf-8", errors="replace")
                except Exception:
                    text = chunk.decode("latin-1", errors="replace")

                with self._lock:
                    self._buffer += text
                    # Check if we have a prompt
                    if self.prompt_pattern.search(self._buffer):
                        self._prompt_event.set()
        except Exception as e:
            logger.error(f"Reader thread error: {e}")
        finally:
            self._closed = True
            self._prompt_event.set()  # Unblock any waiters

    def wait_for_prompt(self, timeout: float = DEFAULT_COMMAND_TIMEOUT) -> str:
        """Wait for the debugger prompt and return accumulated output.

        Args:
            timeout: Maximum seconds to wait.

        Returns:
            The output text up to (and including) the prompt.

        Raises:
            TimeoutError: If prompt not detected within timeout.
        """
        if not self._prompt_event.wait(timeout=timeout):
            with self._lock:
                partial = self._buffer
                self._buffer = ""
                self._prompt_event.clear()
            raise TimeoutError(
                f"Debugger did not respond within {timeout}s. "
                f"Partial output:\n{partial[-500:]}"
            )

        with self._lock:
            output = self._buffer
            self._buffer = ""
            self._prompt_event.clear()

        # Detect EOF without a real prompt (process died)
        if self._closed and not self.prompt_pattern.search(output):
            raise RuntimeError(
                f"Debugger process exited unexpectedly. "
                f"Last output:\n{output[-500:]}"
            )

        return output

    def drain(self) -> str:
        """Return whatever is in the buffer without waiting."""
        with self._lock:
            output = self._buffer
            self._buffer = ""
            self._prompt_event.clear()
        return output

    def close(self):
        self._closed = True
        self._prompt_event.set()


@dataclass
class DebugSession:
    """Manages a single CDB/KD debugging session."""

    session_id: str
    debugger_type: DebuggerType
    target: str
    args: str = ""
    state: SessionState = SessionState.STARTING
    created_at: float = field(default_factory=time.time)
    pid: int | None = None

    _process: subprocess.Popen | None = field(default=None, repr=False, init=False)
    _reader: OutputReader | None = field(default=None, repr=False, init=False)
    _initial_output: str = field(default="", repr=False, init=False)

    async def start(self) -> str:
        """Start the debugger subprocess.

        Returns:
            The initial debugger output (banner + initial break).

        Raises:
            FileNotFoundError: If debugger executable not found.
            RuntimeError: If the debugger fails to start.
        """
        exe_path = find_debugger(self.debugger_type)
        if not exe_path:
            exe_name = "cdb.exe" if self.debugger_type == DebuggerType.USERMODE else "kd.exe"
            raise FileNotFoundError(
                f"Could not find {exe_name}. Install Windows Debugging Tools:\n"
                f"1. Install Windows SDK: https://developer.microsoft.com/windows/downloads/windows-sdk/\n"
                f"2. Select 'Debugging Tools for Windows' during install\n"
                f"3. Or install WinDbg Preview from Microsoft Store"
            )

        cmd = [exe_path]

        if self.debugger_type == DebuggerType.USERMODE:
            # Check if target is a PID (attach) or path (launch)
            if self.target.isdigit():
                cmd.extend(["-p", self.target])
                self.pid = int(self.target)
            else:
                cmd.extend(["-o", self.target])
                if self.args:
                    cmd.extend(self.args.split())
        else:
            # Kernel debugging - target is connection string or local
            if self.target.lower() == "local":
                cmd.append("-kl")
            else:
                cmd.extend(["-k", self.target])

        # Add common flags
        cmd.extend([
            "-lines",   # Enable source line info
            "-n",       # Enable noisy symbol loading
        ])

        env = build_symbol_environment()

        try:
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr into stdout
                env=env,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except OSError as e:
            self.state = SessionState.ERROR
            raise RuntimeError(f"Failed to start debugger: {e}")

        # Start the background reader
        self._reader = OutputReader(self._process.stdout, self.debugger_type)

        # Wait for the initial prompt
        try:
            self._initial_output = await asyncio.to_thread(
                self._reader.wait_for_prompt, 60.0  # Longer timeout for initial load
            )
            self.state = SessionState.BROKEN
        except TimeoutError as e:
            self.state = SessionState.ERROR
            raise RuntimeError(f"Debugger failed to reach initial break: {e}")

        return self._initial_output

    async def send_command(self, command: str, timeout: float = DEFAULT_COMMAND_TIMEOUT) -> str:
        """Send a command to the debugger and return the output.

        Args:
            command: The debugger command to execute.
            timeout: Maximum seconds to wait for response.

        Returns:
            The command output text.

        Raises:
            RuntimeError: If session is not active.
            TimeoutError: If command doesn't complete in time.
        """
        if not self._process or self._process.poll() is not None:
            self.state = SessionState.EXITED
            raise RuntimeError("Debug session has ended.")

        if not self._reader:
            raise RuntimeError("Session reader not initialized.")

        # Drain any leftover output
        self._reader.drain()

        # Send the command
        cmd_bytes = (command.strip() + "\n").encode("utf-8")
        try:
            self._process.stdin.write(cmd_bytes)
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            self.state = SessionState.EXITED
            raise RuntimeError(f"Debugger pipe broken: {e}")

        # Wait for prompt
        output = await asyncio.to_thread(self._reader.wait_for_prompt, timeout)

        # Strip the echoed command from the beginning if present
        lines = output.splitlines(keepends=True)
        if lines and command.strip() in lines[0]:
            output = "".join(lines[1:])

        # Strip the trailing prompt
        output = USERMODE_PROMPT.sub("", output)
        output = KERNEL_PROMPT.sub("", output)

        return output.strip()

    def send_raw(self, data: bytes) -> None:
        """Send raw bytes to the debugger stdin without waiting for prompt.

        Used for commands like 'g' that won't return a prompt immediately.
        """
        if not self._process or self._process.poll() is not None:
            self.state = SessionState.EXITED
            raise RuntimeError("Debug session has ended.")
        if self._reader:
            self._reader.drain()
        try:
            self._process.stdin.write(data)
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            self.state = SessionState.EXITED
            raise RuntimeError(f"Debugger pipe broken: {e}")

    async def send_break(self) -> str:
        """Send a break signal to the debugger (Ctrl+Break equivalent)."""
        if not self._process or self._process.poll() is not None:
            self.state = SessionState.EXITED
            raise RuntimeError("Debug session has ended.")

        import ctypes
        import signal

        try:
            # On Windows, send CTRL_BREAK_EVENT to the process group
            # This works because cdb is a console app
            os.kill(self._process.pid, signal.CTRL_BREAK_EVENT)
        except Exception:
            # Fallback: use DebugBreakProcess via ctypes
            try:
                kernel32 = ctypes.windll.kernel32
                kernel32.DebugBreakProcess(int(self._process._handle))
            except Exception as e:
                raise RuntimeError(f"Failed to break into debugger: {e}")

        try:
            output = await asyncio.to_thread(self._reader.wait_for_prompt, 10.0)
            self.state = SessionState.BROKEN
            return output
        except TimeoutError:
            return "(Break sent but no prompt received yet)"

    async def close(self):
        """Terminate the debug session and clean up."""
        if self._reader:
            self._reader.close()
            self._reader._thread.join(timeout=2.0)

        if self._process and self._process.poll() is None:
            try:
                # Try graceful quit first
                self._process.stdin.write(b"q\n")
                self._process.stdin.flush()
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass

        self.state = SessionState.EXITED

    @property
    def is_active(self) -> bool:
        return self.state in (SessionState.RUNNING, SessionState.BROKEN)

    def info_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "debugger_type": self.debugger_type.value,
            "target": self.target,
            "state": self.state.value,
            "pid": self.pid,
            "created_at": self.created_at,
        }


class SessionManager:
    """Manages multiple concurrent debug sessions."""

    def __init__(self, max_sessions: int = MAX_SESSIONS):
        self._sessions: dict[str, DebugSession] = {}
        self._max_sessions = max_sessions

    def _generate_id(self) -> str:
        return uuid.uuid4().hex[:8]

    async def create_session(
        self,
        target: str,
        debugger_type: str = "usermode",
        args: str = "",
    ) -> tuple[DebugSession, str]:
        """Create and start a new debug session.

        Returns:
            Tuple of (session, initial_output).
        """
        # Clean up dead sessions
        self._cleanup_dead()

        if len(self._sessions) >= self._max_sessions:
            raise RuntimeError(
                f"Maximum sessions ({self._max_sessions}) reached. "
                f"Close a session first with dbg_close_session."
            )

        session_id = self._generate_id()
        dtype = DebuggerType(debugger_type)

        session = DebugSession(
            session_id=session_id,
            debugger_type=dtype,
            target=target,
            args=args,
        )

        initial_output = await session.start()
        self._sessions[session_id] = session

        return session, initial_output

    def get_session(self, session_id: str) -> DebugSession:
        """Get session by ID."""
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(
                f"Session '{session_id}' not found. "
                f"Active sessions: {list(self._sessions.keys())}"
            )
        if not session.is_active:
            raise RuntimeError(f"Session '{session_id}' is no longer active (state: {session.state.value}).")
        return session

    def list_sessions(self) -> list[dict]:
        """List all sessions with their info."""
        self._cleanup_dead()
        return [s.info_dict() for s in self._sessions.values()]

    async def close_session(self, session_id: str):
        """Close and remove a session."""
        session = self._sessions.get(session_id)
        if session:
            await session.close()
            del self._sessions[session_id]

    async def close_all(self):
        """Close all sessions."""
        for session in list(self._sessions.values()):
            await session.close()
        self._sessions.clear()

    def _cleanup_dead(self):
        """Remove sessions whose processes have exited."""
        dead = []
        for sid, session in self._sessions.items():
            if session._process and session._process.poll() is not None:
                session.state = SessionState.EXITED
                if session._reader:
                    session._reader.close()
                dead.append(sid)
        for sid in dead:
            del self._sessions[sid]
