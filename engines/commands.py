"""Command builders and output parsers for CDB/KD debugger output.

Translates between structured Python parameters and raw debugger commands,
and parses debugger text output into structured data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data classes for parsed output
# ---------------------------------------------------------------------------

@dataclass
class RegisterSet:
    """Parsed register values."""
    values: dict[str, int]
    flags: str = ""

    def to_markdown(self) -> str:
        lines = ["| Register | Value |", "|----------|-------|"]
        for name, val in self.values.items():
            lines.append(f"| `{name}` | `0x{val:016x}` |")
        if self.flags:
            lines.append(f"\n**Flags:** `{self.flags}`")
        return "\n".join(lines)


@dataclass
class MemoryDump:
    """Parsed memory dump."""
    address: int
    rows: list[dict]  # each: {address, hex_bytes, ascii}

    def to_markdown(self) -> str:
        lines = ["```"]
        for row in self.rows:
            addr = f"{row['address']:016x}"
            hex_part = row.get("hex_str", " ".join(f"{b:02x}" for b in row.get("hex_bytes", [])))
            ascii_part = row.get("ascii", "")
            lines.append(f"{addr}  {hex_part}  {ascii_part}")
        lines.append("```")
        return "\n".join(lines)


@dataclass
class StackFrame:
    """A single stack frame."""
    frame_number: int
    child_sp: str
    ret_addr: str
    call_site: str
    args: list[str] = field(default_factory=list)

    def to_markdown_row(self) -> str:
        return f"| {self.frame_number} | `{self.child_sp}` | `{self.ret_addr}` | `{self.call_site}` |"


@dataclass
class StackTrace:
    """Parsed stack trace."""
    frames: list[StackFrame]

    def to_markdown(self) -> str:
        lines = [
            "| # | Child-SP | RetAddr | Call Site |",
            "|---|----------|---------|-----------|",
        ]
        for f in self.frames:
            lines.append(f.to_markdown_row())
        return "\n".join(lines)


@dataclass
class Module:
    """A loaded module."""
    start: str
    end: str
    name: str
    path: str = ""
    symbol_status: str = ""
    timestamp: str = ""

    def to_markdown_row(self) -> str:
        return f"| `{self.start}` | `{self.end}` | {self.name} | {self.symbol_status} |"


@dataclass
class ModuleList:
    """Parsed module list."""
    modules: list[Module]

    def to_markdown(self) -> str:
        lines = [
            "| Start | End | Module | Symbols |",
            "|-------|-----|--------|---------|",
        ]
        for m in self.modules:
            lines.append(m.to_markdown_row())
        return "\n".join(lines)


@dataclass
class Breakpoint:
    """A single breakpoint."""
    bp_id: int
    bp_type: str  # e/d (enabled/disabled)
    address: str
    resolve_status: str = ""
    hits: int = 0
    command: str = ""
    condition: str = ""
    symbol: str = ""

    def to_markdown_row(self) -> str:
        status = "enabled" if self.bp_type == "e" else "disabled"
        return f"| {self.bp_id} | {status} | `{self.address}` | {self.symbol} |"


@dataclass
class BreakpointList:
    """Parsed breakpoint list."""
    breakpoints: list[Breakpoint]

    def to_markdown(self) -> str:
        if not self.breakpoints:
            return "No breakpoints set."
        lines = [
            "| ID | Status | Address | Symbol |",
            "|----|--------|---------|--------|",
        ]
        for bp in self.breakpoints:
            lines.append(bp.to_markdown_row())
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------

def build_memory_read_cmd(address: str, length: int, fmt: str) -> str:
    """Build memory read command based on format."""
    fmt_map = {
        "bytes": "db",
        "words": "dw",
        "dwords": "dd",
        "qwords": "dq",
        "ascii": "da",
        "unicode": "du",
        "pointers": "dps",
    }
    cmd = fmt_map.get(fmt, "db")
    return f"{cmd} {address} L{length}"


def build_memory_write_cmd(address: str, data: str, fmt: str) -> str:
    """Build memory write command based on format."""
    fmt_map = {
        "bytes": "eb",
        "words": "ew",
        "dwords": "ed",
        "qwords": "eq",
        "ascii": "ea",
        "unicode": "eu",
    }
    cmd = fmt_map.get(fmt, "eb")
    return f"{cmd} {address} {data}"


def build_memory_search_cmd(address: str, length: str, pattern: str) -> str:
    """Build memory search command."""
    return f"s -b {address} L{length} {pattern}"


def build_breakpoint_set_cmd(
    address: str,
    condition: str | None = None,
    command: str | None = None,
    unresolved: bool = False,
) -> str:
    """Build breakpoint set command.

    Args:
        address: Symbol or hex address.
        condition: Optional conditional expression (j syntax).
        command: Optional command string to run on hit.
        unresolved: If True, use bu (unresolved) instead of bp.
    """
    bp_cmd = "bu" if unresolved else "bp"
    parts = [bp_cmd, address]

    if condition and command:
        parts.append(f'"/j ({condition}) \'{command}\'; \'gc\'"')
    elif condition:
        parts.append(f'"/j ({condition}) \'\'; \'gc\'"')
    elif command:
        parts.append(f'"{command}"')

    return " ".join(parts)


def build_watchpoint_cmd(address: str, size: int, access_type: str) -> str:
    """Build data breakpoint (ba) command.

    Args:
        address: Memory address to watch.
        size: Size in bytes (1, 2, 4, or 8).
        access_type: "r" (read), "w" (write), "e" (execute), "rw" (read/write).
    """
    access_map = {"read": "r", "write": "w", "execute": "e", "rw": "rw",
                  "r": "r", "w": "w", "e": "e"}
    access = access_map.get(access_type, "w")
    return f"ba {access}{size} {address}"


def build_step_cmd(step_type: str, count: int = 1) -> str:
    """Build step command."""
    cmd_map = {"into": "t", "over": "p", "out": "gu"}
    cmd = cmd_map.get(step_type, "t")
    if step_type == "out":
        return cmd
    return f"{cmd} {count}" if count > 1 else cmd


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def parse_registers(output: str) -> RegisterSet:
    """Parse register output from 'r' command."""
    values: dict[str, int] = {}
    flags = ""

    # Match patterns like "rax=00000000deadbeef" or "eax=deadbeef"
    reg_pattern = re.compile(r"([a-z][a-z0-9]+)=([0-9a-fA-F]+)")
    for match in reg_pattern.finditer(output):
        name = match.group(1)
        try:
            val = int(match.group(2), 16)
            values[name] = val
        except ValueError:
            continue

    # Extract flags line (iopl=... nv up ei pl nz na po nc)
    flags_match = re.search(r"(iopl=\d+\s+[a-z]{2}(?:\s+[a-z]{2})*)", output)
    if flags_match:
        flags = flags_match.group(1).strip()

    return RegisterSet(values=values, flags=flags)


def parse_memory_dump(output: str) -> MemoryDump:
    """Parse memory dump output (db/dd/dq etc)."""
    rows = []
    first_addr = 0

    # Pattern: address  hex_bytes  ascii
    # e.g. 00007ff8`12345678  41 42 43 44 45 46 47 48-49 4a 4b 4c 4d 4e 4f 50  ABCDEFGHIJKLMNOP
    line_pattern = re.compile(
        r"([0-9a-fA-F`]+)\s+((?:[0-9a-fA-F]{2}[\s\-]?)+)\s*(.*)"
    )

    for line in output.splitlines():
        line = line.strip()
        m = line_pattern.match(line)
        if m:
            addr_str = m.group(1).replace("`", "")
            try:
                addr = int(addr_str, 16)
            except ValueError:
                continue
            if not rows:
                first_addr = addr
            hex_str = m.group(2).strip()
            ascii_str = m.group(3).strip()
            rows.append({
                "address": addr,
                "hex_str": hex_str,
                "ascii": ascii_str,
            })

    return MemoryDump(address=first_addr, rows=rows)


def parse_stack_trace(output: str) -> StackTrace:
    """Parse stack trace output from 'k' command."""
    frames = []

    # Pattern: # Child-SP          RetAddr               Call Site
    # 00 00000000`0014f6b8 00007ff8`12345678 ntdll!LdrpInitialize+0x1234
    frame_pattern = re.compile(
        r"([0-9a-fA-F]{1,3})\s+([0-9a-fA-F`]+)\s+([0-9a-fA-F`]+)\s+(.+)"
    )

    for line in output.splitlines():
        line = line.strip()
        # Skip header line
        if line.startswith("#") or line.startswith("Child-SP") or not line:
            continue
        m = frame_pattern.match(line)
        if m:
            frames.append(StackFrame(
                frame_number=int(m.group(1), 16),
                child_sp=m.group(2),
                ret_addr=m.group(3),
                call_site=m.group(4).strip(),
            ))

    return StackTrace(frames=frames)


def parse_module_list(output: str) -> ModuleList:
    """Parse module list output from 'lm' command."""
    modules = []

    # Pattern: start    end        module name  (symbol status)
    # 00007ff8`12340000 00007ff8`12350000   ntdll    (pdb symbols) ...
    mod_pattern = re.compile(
        r"([0-9a-fA-F`]+)\s+([0-9a-fA-F`]+)\s+(\S+)\s*(.*)"
    )

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("start") or line.startswith("Browse"):
            continue
        m = mod_pattern.match(line)
        if m:
            sym_status = m.group(4).strip()
            # Extract just the symbol status in parens
            sym_match = re.search(r"\(([^)]+)\)", sym_status)
            modules.append(Module(
                start=m.group(1),
                end=m.group(2),
                name=m.group(3),
                symbol_status=sym_match.group(1) if sym_match else sym_status,
            ))

    return ModuleList(modules=modules)


def parse_breakpoint_list(output: str) -> BreakpointList:
    """Parse breakpoint list output from 'bl' command."""
    breakpoints = []

    # Pattern:  0 e Disable Clear  00007ff8`12345678     0001 (0001)  0:**** ntdll!DbgBreakPoint
    bp_pattern = re.compile(
        r"\s*(\d+)\s+([ed])\s+\S+\s+\S+\s+([0-9a-fA-F`]+)\s+.*?(\S+!.+|$)"
    )

    # Simpler pattern for basic bl output:
    # 0 e 00007ff8`12345678 [inline]  0001 (0001)  0:**** module!Function
    bp_simple = re.compile(
        r"\s*(\d+)\s+([ed])\s+([0-9a-fA-F`]+)\s+(.+)"
    )

    for line in output.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue

        m = bp_pattern.match(line) or bp_simple.match(line)
        if m:
            symbol = m.group(4).strip() if m.lastindex >= 4 else ""
            breakpoints.append(Breakpoint(
                bp_id=int(m.group(1)),
                bp_type=m.group(2),
                address=m.group(3),
                symbol=symbol,
            ))

    return BreakpointList(breakpoints=breakpoints)


def parse_symbol_resolve(output: str) -> list[dict[str, str]]:
    """Parse symbol resolution output from 'x' command."""
    results = []

    # Pattern: 00007ff8`12345678 module!SymbolName (type)
    sym_pattern = re.compile(
        r"([0-9a-fA-F`]+)\s+(\S+!?\S+)(?:\s+\((.+)\))?"
    )

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = sym_pattern.match(line)
        if m:
            results.append({
                "address": m.group(1),
                "symbol": m.group(2),
                "type": m.group(3) or "",
            })

    return results


def parse_handles(output: str) -> str:
    """Parse handle output - return cleaned markdown."""
    lines = output.strip().splitlines()
    cleaned = [l for l in lines if l.strip() and not l.strip().startswith("Handle")]
    if not cleaned:
        return "No handle information available."
    return "```\n" + "\n".join(lines) + "\n```"


def format_raw_output(output: str, title: str = "") -> str:
    """Wrap raw debugger output in markdown code block."""
    header = f"### {title}\n\n" if title else ""
    return f"{header}```\n{output.strip()}\n```"
