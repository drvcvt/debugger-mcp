"""Windows Debugger MCP Server.

A FastMCP server wrapping CDB/KD for interactive debugging of
user-mode processes and kernel targets. Designed for reverse
engineering and vulnerability research workflows.
"""

from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager

from fastmcp import FastMCP

from engines.session import SessionManager, DebuggerType, SessionState
from engines.commands import (
    build_breakpoint_set_cmd,
    build_memory_read_cmd,
    build_memory_write_cmd,
    build_memory_search_cmd,
    build_step_cmd,
    build_watchpoint_cmd,
    format_raw_output,
    parse_breakpoint_list,
    parse_memory_dump,
    parse_module_list,
    parse_registers,
    parse_stack_trace,
    parse_symbol_resolve,
)
from engines.symbols import (
    get_default_symbol_path,
    format_symbol_path_for_display,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("debugger-mcp")

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

manager = SessionManager()

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_HEX_ADDR = re.compile(r"^(0x)?[0-9a-fA-F`]+$")
_SYMBOL = re.compile(r"^[a-zA-Z_][\w.]*![a-zA-Z_~][\w:.<>*?~]*$")

CRITICAL_PIDS = {0, 4}  # System Idle Process, System
CRITICAL_NAMES = {"csrss.exe", "smss.exe", "wininit.exe", "services.exe", "lsass.exe"}


def validate_address(address: str) -> str:
    """Validate that an address is a hex value or symbol reference."""
    address = address.strip()
    if _HEX_ADDR.match(address) or _SYMBOL.match(address):
        return address
    # Allow poi(), @@, and other debugger expressions
    if any(address.startswith(p) for p in ["poi(", "@@(", "@@c++("]):
        return address
    raise ValueError(
        f"Invalid address format: '{address}'. "
        f"Use hex (0x...), symbol (module!func), or debugger expression."
    )


def sanitize_command(command: str) -> str:
    """Basic sanity check on raw debugger commands.

    This prevents accidentally sending shell metacharacters.
    The debugger itself is the security boundary - we just avoid
    obviously malformed input.
    """
    command = command.strip()
    if not command:
        raise ValueError("Empty command.")
    if len(command) > 4096:
        raise ValueError("Command too long (max 4096 chars).")
    # Block commands that could launch external processes
    blocked = [".shell", ".create", "!execute", ".restart"]
    # Normalize whitespace: collapse multiple spaces between dot-command parts
    cmd_lower = re.sub(r"\s+", " ", command.lower()).strip()
    for b in blocked:
        # Match at start or after semicolon (command separator)
        if re.search(rf"(?:^|;\s*){re.escape(b)}\b", cmd_lower):
            raise ValueError(
                f"Command contains blocked keyword '{b}'. "
                f"Use dbg_create_session to launch processes."
            )
    return command


# ---------------------------------------------------------------------------
# FastMCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "Windows Debugger",
    instructions=(
        "Interactive Windows debugging via CDB/KD. "
        "Supports user-mode and kernel debugging for RE and vuln research."
    ),
)


# ===========================================================================
# Session Management
# ===========================================================================

@mcp.tool()
async def dbg_create_session(
    target: str,
    debugger_type: str = "usermode",
    args: str = "",
) -> str:
    """Create a new debugging session.

    Args:
        target: Path to executable, PID (digits) for attach, or
                kernel connection string (e.g. "local" for local kernel).
        debugger_type: "usermode" (cdb.exe) or "kernel" (kd.exe).
        args: Additional arguments passed to the target executable.

    Returns:
        Session ID and initial debugger output.
    """
    if debugger_type not in ("usermode", "kernel"):
        return "**Error:** debugger_type must be 'usermode' or 'kernel'."

    # Warn about critical PIDs
    if target.isdigit():
        pid = int(target)
        if pid in CRITICAL_PIDS:
            return (
                f"**Warning:** PID {pid} is a critical system process. "
                f"Attaching could crash the system. Aborting."
            )

    try:
        session, initial_output = await manager.create_session(
            target=target,
            debugger_type=debugger_type,
            args=args,
        )
    except FileNotFoundError as e:
        return f"**Error:** {e}"
    except RuntimeError as e:
        return f"**Error:** {e}"

    # Format response
    sym_path = get_default_symbol_path()
    return (
        f"### Session Created\n\n"
        f"- **Session ID:** `{session.session_id}`\n"
        f"- **Type:** {debugger_type}\n"
        f"- **Target:** `{target}`\n"
        f"- **State:** {session.state.value}\n\n"
        f"**Symbol Path:**\n{format_symbol_path_for_display(sym_path)}\n\n"
        f"### Initial Output\n\n```\n{initial_output[:3000]}\n```"
    )


@mcp.tool()
async def dbg_list_sessions() -> str:
    """List all active debug sessions."""
    sessions = manager.list_sessions()
    if not sessions:
        return "No active debug sessions."

    lines = [
        "| Session ID | Type | Target | State |",
        "|------------|------|--------|-------|",
    ]
    for s in sessions:
        lines.append(
            f"| `{s['session_id']}` | {s['debugger_type']} | "
            f"`{s['target']}` | {s['state']} |"
        )
    return "\n".join(lines)


@mcp.tool()
async def dbg_close_session(session_id: str) -> str:
    """Terminate a debug session and clean up resources.

    Args:
        session_id: The session ID to close.
    """
    try:
        await manager.close_session(session_id)
        return f"Session `{session_id}` closed."
    except Exception as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_command(session_id: str, command: str, timeout: float = 30.0) -> str:
    """Send a raw debugger command and return the output.

    Args:
        session_id: Active session ID.
        command: Raw CDB/KD command to execute.
        timeout: Max seconds to wait for output (default 30).

    Returns:
        Raw debugger output in a code block.
    """
    try:
        command = sanitize_command(command)
        session = manager.get_session(session_id)
        output = await session.send_command(command, timeout=timeout)
        return format_raw_output(output, title=f"`{command}`")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


# ===========================================================================
# Process Control
# ===========================================================================

@mcp.tool()
async def dbg_attach(pid: int, session_id: str | None = None) -> str:
    """Attach to a running process by PID.

    If session_id is provided, sends .attach command to existing session.
    Otherwise creates a new session attached to the PID.

    Args:
        pid: Process ID to attach to.
        session_id: Optional existing session ID.
    """
    if pid in CRITICAL_PIDS:
        return f"**Error:** PID {pid} is a critical system process. Refusing to attach."

    # Check critical process names via tasklist
    try:
        import subprocess as _sp
        result = _sp.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.strip().strip('"').split('","')
            if parts and parts[0].lower() in CRITICAL_NAMES:
                return f"**Error:** PID {pid} is `{parts[0]}` (critical system process). Refusing to attach."
    except Exception:
        pass  # Best-effort check

    if session_id:
        try:
            session = manager.get_session(session_id)
            output = await session.send_command(f".attach {pid}")
            return format_raw_output(output, title=f"Attach to PID {pid}")
        except (ValueError, RuntimeError, TimeoutError) as e:
            return f"**Error:** {e}"

    return await dbg_create_session(target=str(pid), debugger_type="usermode")


@mcp.tool()
async def dbg_detach(session_id: str) -> str:
    """Detach from the debugged process without killing it.

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command(".detach")
        return f"Detached from process.\n\n```\n{output}\n```"
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_go(session_id: str) -> str:
    """Continue execution (equivalent to 'g' command).

    Note: This will let the target run. Use dbg_break to regain control,
    or set breakpoints first.

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        # g command won't return a prompt until a break event occurs
        # Send raw command without waiting for prompt
        session.send_raw(b"g\n")
        session.state = SessionState.RUNNING
        return (
            "Execution resumed. Target is running.\n\n"
            "Use `dbg_break` to break back into the debugger, "
            "or the debugger will break at the next breakpoint/exception."
        )
    except (ValueError, RuntimeError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_break(session_id: str) -> str:
    """Break into the debugger (Ctrl+Break equivalent).

    Use this to regain control after dbg_go.

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_break()
        return format_raw_output(output, title="Break")
    except (ValueError, RuntimeError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_step_into(session_id: str, count: int = 1) -> str:
    """Single-step into the next instruction(s) (trace / 't' command).

    Args:
        session_id: Active session ID.
        count: Number of instructions to step (default 1).
    """
    try:
        session = manager.get_session(session_id)
        cmd = build_step_cmd("into", count)
        output = await session.send_command(cmd)
        return format_raw_output(output, title=f"Step Into (x{count})")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_step_over(session_id: str, count: int = 1) -> str:
    """Step over the next instruction(s) ('p' command).

    Args:
        session_id: Active session ID.
        count: Number of instructions to step (default 1).
    """
    try:
        session = manager.get_session(session_id)
        cmd = build_step_cmd("over", count)
        output = await session.send_command(cmd)
        return format_raw_output(output, title=f"Step Over (x{count})")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_step_out(session_id: str) -> str:
    """Step out of the current function ('gu' command).

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        cmd = build_step_cmd("out")
        output = await session.send_command(cmd)
        return format_raw_output(output, title="Step Out")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


# ===========================================================================
# Breakpoints
# ===========================================================================

@mcp.tool()
async def dbg_breakpoint_set(
    session_id: str,
    address: str,
    condition: str = "",
    command: str = "",
) -> str:
    """Set a breakpoint at an address or symbol.

    Args:
        session_id: Active session ID.
        address: Hex address or symbol (e.g. "kernel32!CreateFileW").
        condition: Optional conditional expression for the breakpoint.
        command: Optional debugger command to run when breakpoint hits.

    Examples:
        dbg_breakpoint_set(sid, "kernel32!CreateFileW")
        dbg_breakpoint_set(sid, "ntdll!NtCreateFile", command=".echo HIT; kb")
        dbg_breakpoint_set(sid, "0x7ff812340000", condition="@rcx==0")
    """
    try:
        address = validate_address(address)
        session = manager.get_session(session_id)
        # Use bu (unresolved) for symbol references, bp for addresses
        unresolved = "!" in address and not address.startswith("0")
        cmd = build_breakpoint_set_cmd(
            address,
            condition=condition or None,
            command=command or None,
            unresolved=unresolved,
        )
        output = await session.send_command(cmd)

        # Also get the breakpoint list for confirmation
        bl_output = await session.send_command("bl")
        bp_list = parse_breakpoint_list(bl_output)

        return (
            f"### Breakpoint Set\n\n"
            f"Command: `{cmd}`\n\n"
            f"{output}\n\n"
            f"### Active Breakpoints\n\n{bp_list.to_markdown()}"
        )
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_breakpoint_list(session_id: str) -> str:
    """List all breakpoints in the session.

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command("bl")
        bp_list = parse_breakpoint_list(output)
        return f"### Breakpoints\n\n{bp_list.to_markdown()}"
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_breakpoint_delete(session_id: str, bp_id: int) -> str:
    """Delete a breakpoint by ID.

    Args:
        session_id: Active session ID.
        bp_id: Breakpoint ID (from dbg_breakpoint_list).
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command(f"bc {bp_id}")
        return f"Breakpoint {bp_id} deleted.\n\n{output}"
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_breakpoint_disable(session_id: str, bp_id: int) -> str:
    """Disable a breakpoint by ID.

    Args:
        session_id: Active session ID.
        bp_id: Breakpoint ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command(f"bd {bp_id}")
        return f"Breakpoint {bp_id} disabled.\n\n{output}"
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_breakpoint_enable(session_id: str, bp_id: int) -> str:
    """Enable a breakpoint by ID.

    Args:
        session_id: Active session ID.
        bp_id: Breakpoint ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command(f"be {bp_id}")
        return f"Breakpoint {bp_id} enabled.\n\n{output}"
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_watchpoint_set(
    session_id: str,
    address: str,
    size: int = 4,
    access_type: str = "w",
) -> str:
    """Set a data breakpoint (hardware watchpoint).

    Triggers when the specified memory is accessed.

    Args:
        session_id: Active session ID.
        address: Memory address to watch.
        size: Size in bytes to watch (1, 2, 4, or 8).
        access_type: "r" (read), "w" (write), "e" (execute), "rw" (read/write).
    """
    try:
        address = validate_address(address)
        if size not in (1, 2, 4, 8):
            return "**Error:** size must be 1, 2, 4, or 8."
        session = manager.get_session(session_id)
        cmd = build_watchpoint_cmd(address, size, access_type)
        output = await session.send_command(cmd)

        bl_output = await session.send_command("bl")
        bp_list = parse_breakpoint_list(bl_output)

        return (
            f"### Watchpoint Set\n\n"
            f"Command: `{cmd}`\n\n{output}\n\n"
            f"### Active Breakpoints\n\n{bp_list.to_markdown()}"
        )
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


# ===========================================================================
# Memory
# ===========================================================================

@mcp.tool()
async def dbg_memory_read(
    session_id: str,
    address: str,
    length: int = 128,
    format: str = "bytes",
) -> str:
    """Read memory at an address.

    Args:
        session_id: Active session ID.
        address: Hex address or symbol to read from.
        length: Number of elements to display (default 128).
        format: Display format - "bytes", "words", "dwords", "qwords",
                "ascii", "unicode", "pointers".
    """
    try:
        address = validate_address(address)
        session = manager.get_session(session_id)
        cmd = build_memory_read_cmd(address, length, format)
        output = await session.send_command(cmd)

        if format in ("ascii", "unicode"):
            return format_raw_output(output, title=f"Memory @ {address}")

        dump = parse_memory_dump(output)
        if dump.rows:
            return f"### Memory @ `{address}` ({format})\n\n{dump.to_markdown()}"
        return format_raw_output(output, title=f"Memory @ {address}")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_memory_write(
    session_id: str,
    address: str,
    data: str,
    format: str = "bytes",
) -> str:
    """Write data to memory.

    Args:
        session_id: Active session ID.
        address: Hex address to write to.
        data: Data to write (space-separated hex values, or string for ascii/unicode).
        format: Write format - "bytes", "words", "dwords", "qwords", "ascii", "unicode".
    """
    try:
        address = validate_address(address)
        session = manager.get_session(session_id)
        cmd = build_memory_write_cmd(address, data, format)
        output = await session.send_command(cmd)
        return f"Memory written at `{address}`.\n\n{output}"
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_memory_search(
    session_id: str,
    address: str,
    length: str,
    pattern: str,
) -> str:
    """Search memory for a byte pattern.

    Args:
        session_id: Active session ID.
        address: Start address for search.
        length: Search range (hex, e.g. "10000").
        pattern: Byte pattern to search for (space-separated hex, e.g. "4d 5a 90 00").
    """
    try:
        address = validate_address(address)
        session = manager.get_session(session_id)
        cmd = build_memory_search_cmd(address, length, pattern)
        output = await session.send_command(cmd, timeout=60.0)
        return format_raw_output(output, title=f"Search results for `{pattern}`")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_memory_map(session_id: str) -> str:
    """Show the virtual memory layout of the process (!address).

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command("!address", timeout=60.0)
        return format_raw_output(output, title="Memory Map")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_memory_protect(session_id: str, address: str) -> str:
    """Show memory protection for an address (!vprot).

    Args:
        session_id: Active session ID.
        address: Address to query.
    """
    try:
        address = validate_address(address)
        session = manager.get_session(session_id)
        output = await session.send_command(f"!vprot {address}")
        return format_raw_output(output, title=f"Memory Protection @ {address}")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


# ===========================================================================
# Registers
# ===========================================================================

@mcp.tool()
async def dbg_registers(session_id: str, register: str = "") -> str:
    """Read CPU registers.

    Args:
        session_id: Active session ID.
        register: Optional specific register name (e.g. "rax"). Empty = all registers.
    """
    try:
        session = manager.get_session(session_id)
        cmd = f"r {register}" if register else "r"
        output = await session.send_command(cmd)

        if not register:
            regs = parse_registers(output)
            return f"### Registers\n\n{regs.to_markdown()}"

        return format_raw_output(output, title=f"Register `{register}`")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_register_set(session_id: str, register: str, value: str) -> str:
    """Set a register value.

    Args:
        session_id: Active session ID.
        register: Register name (e.g. "rax", "rcx", "rip").
        value: New value in hex (e.g. "0x41414141").
    """
    try:
        session = manager.get_session(session_id)
        # Sanitize register name
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9]+$", register):
            return f"**Error:** Invalid register name: `{register}`"
        # Validate value — must be hex or simple debugger expression
        if not re.match(r"^(0x)?[0-9a-fA-F]+$", value):
            return f"**Error:** Invalid register value: `{value}`. Use hex (e.g. 0x41414141)."
        cmd = f"r @{register}={value}"
        output = await session.send_command(cmd)
        # Read back for confirmation
        verify = await session.send_command(f"r {register}")
        return f"Register set.\n\n{verify}"
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


# ===========================================================================
# Stack
# ===========================================================================

@mcp.tool()
async def dbg_stack_trace(session_id: str, frames: int = 20) -> str:
    """Get the call stack.

    Args:
        session_id: Active session ID.
        frames: Maximum number of frames to show (default 20).
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command(f"kn {frames}")
        trace = parse_stack_trace(output)
        if trace.frames:
            return f"### Call Stack\n\n{trace.to_markdown()}"
        return format_raw_output(output, title="Call Stack")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_stack_locals(session_id: str) -> str:
    """Show local variables for the current stack frame.

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command("dv /t /v")
        return format_raw_output(output, title="Local Variables")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


# ===========================================================================
# Symbols & Modules
# ===========================================================================

@mcp.tool()
async def dbg_modules(session_id: str) -> str:
    """List all loaded modules.

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command("lm", timeout=60.0)
        mod_list = parse_module_list(output)
        if mod_list.modules:
            return f"### Loaded Modules ({len(mod_list.modules)})\n\n{mod_list.to_markdown()}"
        return format_raw_output(output, title="Loaded Modules")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_symbols_resolve(session_id: str, pattern: str) -> str:
    """Resolve symbol names matching a pattern.

    Args:
        session_id: Active session ID.
        pattern: Symbol pattern with wildcards (e.g. "kernel32!Create*").
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command(f"x {pattern}", timeout=60.0)
        results = parse_symbol_resolve(output)
        if results:
            lines = [
                "| Address | Symbol | Type |",
                "|---------|--------|------|",
            ]
            for r in results[:100]:  # Limit output
                lines.append(f"| `{r['address']}` | `{r['symbol']}` | {r['type']} |")
            if len(results) > 100:
                lines.append(f"\n*...and {len(results) - 100} more*")
            return f"### Symbols matching `{pattern}`\n\n" + "\n".join(lines)
        return f"No symbols found matching `{pattern}`."
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_symbols_nearest(session_id: str, address: str) -> str:
    """Find the nearest symbol to an address.

    Args:
        session_id: Active session ID.
        address: Hex address to look up.
    """
    try:
        address = validate_address(address)
        session = manager.get_session(session_id)
        output = await session.send_command(f"ln {address}")
        return format_raw_output(output, title=f"Nearest symbols to `{address}`")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


# ===========================================================================
# Analysis
# ===========================================================================

@mcp.tool()
async def dbg_analyze_crash(session_id: str) -> str:
    """Run automated crash analysis (!analyze -v).

    Best used after an exception/crash occurs.

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command("!analyze -v", timeout=120.0)
        return format_raw_output(output, title="Crash Analysis")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_analyze_heap(session_id: str, address: str = "") -> str:
    """Analyze heap state or a specific heap address.

    Args:
        session_id: Active session ID.
        address: Optional heap address to inspect. Empty = overview of all heaps.
    """
    try:
        session = manager.get_session(session_id)
        if address:
            address = validate_address(address)
            cmd = f"!heap -a {address}"
        else:
            cmd = "!heap -s"
        output = await session.send_command(cmd, timeout=60.0)
        return format_raw_output(output, title="Heap Analysis")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_analyze_handles(session_id: str) -> str:
    """Show handle information for the process.

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command("!handle 0 f", timeout=60.0)
        return format_raw_output(output, title="Handle Information")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_analyze_threads(session_id: str) -> str:
    """Show all threads with their call stacks.

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command("~*kn", timeout=60.0)
        return format_raw_output(output, title="Thread Stacks")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


# ===========================================================================
# Kernel Debugging
# ===========================================================================

@mcp.tool()
async def dbg_kernel_modules(session_id: str) -> str:
    """List kernel modules (for kernel debug sessions).

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command("lm", timeout=60.0)
        mod_list = parse_module_list(output)
        if mod_list.modules:
            return f"### Kernel Modules ({len(mod_list.modules)})\n\n{mod_list.to_markdown()}"
        return format_raw_output(output, title="Kernel Modules")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_kernel_drivers(session_id: str) -> str:
    """List driver objects in the kernel.

    Args:
        session_id: Active session ID.
    """
    try:
        session = manager.get_session(session_id)
        output = await session.send_command("!object \\Driver", timeout=60.0)
        return format_raw_output(output, title="Driver Objects")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_kernel_device(session_id: str, driver_name: str) -> str:
    """Get device object information for a driver.

    Args:
        session_id: Active session ID.
        driver_name: Driver name (e.g. "\\Driver\\Tcpip" or just "Tcpip").
    """
    try:
        session = manager.get_session(session_id)
        # First get the driver object
        if not driver_name.startswith("\\"):
            driver_name = f"\\Driver\\{driver_name}"
        output = await session.send_command(f"!drvobj {driver_name} 7", timeout=30.0)
        return format_raw_output(output, title=f"Driver: {driver_name}")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_kernel_irp(session_id: str, address: str) -> str:
    """Analyze an I/O Request Packet (IRP).

    Args:
        session_id: Active session ID.
        address: Address of the IRP structure.
    """
    try:
        address = validate_address(address)
        session = manager.get_session(session_id)
        output = await session.send_command(f"!irp {address}", timeout=30.0)
        return format_raw_output(output, title=f"IRP @ {address}")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


@mcp.tool()
async def dbg_kernel_pool(session_id: str, tag: str = "") -> str:
    """Query kernel pool allocations.

    Args:
        session_id: Active session ID.
        tag: Optional pool tag (4 chars, e.g. "Proc"). Empty = summary.
    """
    try:
        session = manager.get_session(session_id)
        if tag:
            # Sanitize tag - must be 1-4 ASCII chars
            if not re.match(r"^[a-zA-Z0-9 ]{1,4}$", tag):
                return "**Error:** Pool tag must be 1-4 alphanumeric characters."
            cmd = f"!poolfind {tag}"
        else:
            cmd = "!pool"
        output = await session.send_command(cmd, timeout=60.0)
        return format_raw_output(output, title=f"Pool {'(tag: ' + tag + ')' if tag else 'Summary'}")
    except (ValueError, RuntimeError, TimeoutError) as e:
        return f"**Error:** {e}"


# ===========================================================================
# Entry Point
# ===========================================================================

if __name__ == "__main__":
    mcp.run()
