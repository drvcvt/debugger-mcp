"""Symbol management for Windows debugging sessions.

Handles symbol path configuration, Microsoft Symbol Server integration,
and symbol resolution helpers.
"""

import os
from pathlib import Path

DEFAULT_SYMBOL_CACHE = r"C:\symbols"
MS_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"


def get_default_symbol_path() -> str:
    """Build the default _NT_SYMBOL_PATH value.

    Priority:
    1. Existing _NT_SYMBOL_PATH environment variable
    2. Constructed path with local cache + Microsoft Symbol Server
    """
    existing = os.environ.get("_NT_SYMBOL_PATH", "")
    if existing:
        return existing

    cache_dir = Path(DEFAULT_SYMBOL_CACHE)
    return f"srv*{cache_dir}*{MS_SYMBOL_SERVER}"


def build_symbol_environment(extra_paths: list[str] | None = None) -> dict[str, str]:
    """Build environment dict with proper symbol path configuration.

    Args:
        extra_paths: Additional symbol paths to prepend.

    Returns:
        Copy of os.environ with _NT_SYMBOL_PATH set.
    """
    env = os.environ.copy()
    base_path = get_default_symbol_path()

    if extra_paths:
        combined = ";".join(extra_paths) + ";" + base_path
        env["_NT_SYMBOL_PATH"] = combined
    else:
        env["_NT_SYMBOL_PATH"] = base_path

    return env


def parse_symbol_name(symbol: str) -> tuple[str | None, str]:
    """Parse a symbol string into module and function parts.

    Examples:
        "kernel32!CreateFileW" -> ("kernel32", "CreateFileW")
        "ntdll!RtlAllocateHeap" -> ("ntdll", "RtlAllocateHeap")
        "CreateFileW" -> (None, "CreateFileW")
        "0x7ff812345678" -> (None, "0x7ff812345678")

    Returns:
        Tuple of (module_name_or_None, symbol_or_address).
    """
    if "!" in symbol:
        parts = symbol.split("!", 1)
        return (parts[0], parts[1])
    return (None, symbol)


def format_symbol_path_for_display(symbol_path: str) -> str:
    """Format a symbol path string for readable display."""
    parts = symbol_path.split(";")
    lines = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if part.startswith("srv*"):
            components = part.split("*")
            if len(components) >= 3:
                lines.append(f"  Symbol Server: {components[-1]}")
                lines.append(f"  Local Cache:   {components[1]}")
            else:
                lines.append(f"  {part}")
        else:
            lines.append(f"  Local Path:    {part}")
    return "\n".join(lines) if lines else "  (none configured)"
