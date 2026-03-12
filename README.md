# debugger-mcp

MCP server for interactive Windows debugging through CDB and KD. Built for reverse engineering and vulnerability research workflows.

Wraps the Windows Debugging Tools (CDB for user-mode, KD for kernel-mode) behind the Model Context Protocol, allowing LLM-driven debugging sessions with full control over breakpoints, memory, registers, and process state.

## What it does

- **Session management** -- launch, attach, detach, and close debug sessions against user-mode processes or kernel targets
- **Process control** -- step into/over/out, continue execution, break into running targets
- **Breakpoints** -- software breakpoints at addresses or symbols, conditional breakpoints, hardware watchpoints (data breakpoints)
- **Memory operations** -- read/write/search memory in various formats (bytes, words, dwords, qwords, ASCII, Unicode, pointers), query memory protection and layout
- **Register access** -- read and write CPU registers
- **Stack inspection** -- call stack traces, local variable display
- **Symbol resolution** -- resolve symbols by pattern, find nearest symbol to address, list loaded modules
- **Analysis tools** -- automated crash analysis (`!analyze -v`), heap inspection, handle enumeration, thread stack dumps
- **Kernel debugging** -- kernel module listing, driver object enumeration, device object inspection, IRP analysis, pool tag queries

## Requirements

- Windows 10/11
- [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) or [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) installed (provides `cdb.exe` and `kd.exe`)
- Python 3.10+
- Dependencies: `pip install -r requirements.txt`

## Setup

```bash
pip install -r requirements.txt
python server.py
```

The server communicates over stdio using the MCP protocol. Point your MCP client at `python server.py`.

For kernel debugging, run with appropriate privileges and configure your kernel debug connection (local, serial, network) as you would for WinDbg/KD.

## Configuration

The server uses the default Microsoft symbol path. Set `_NT_SYMBOL_PATH` to customize symbol resolution.

## Architecture

```
debugger/
  server.py              # MCP server, tool definitions
  engines/
    session.py           # Session lifecycle, CDB/KD process management
    commands.py          # Command builders and output parsers
    symbols.py           # Symbol path configuration
  utils/                 # Shared helpers
```

All debugger interaction goes through subprocess pipes to CDB/KD. The server sanitizes commands to prevent shell injection and blocks dangerous operations (`.shell`, `.create`, etc.). Critical system processes (PID 0, 4, csrss, lsass, etc.) are protected from accidental attach.

## License

CC BY-NC-SA 4.0 -- see [LICENSE](LICENSE).
