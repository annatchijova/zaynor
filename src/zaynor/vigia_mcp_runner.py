"""Run an existing VIGÍA MCP bridge with its asyncio stdio backend."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: vigia_mcp_runner.py BRIDGE_PATH")
    bridge_path = Path(sys.argv[1]).resolve()
    if not bridge_path.is_file() or bridge_path.is_symlink():
        raise SystemExit("bridge path must be a regular file")
    sys.path.insert(0, str(bridge_path.parent.parent))
    spec = importlib.util.spec_from_file_location("zaynor_vigia_bridge", bridge_path)
    if spec is None or spec.loader is None:
        raise SystemExit("could not load VIGÍA bridge")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    import anyio

    # The bridge's tools use asyncio.get_event_loop() and run_in_executor().
    # Keep the bridge on asyncio; ZAYNOR's own MCP server has a separate
    # runner because the SDK's asyncio stdio path has a different constraint.
    anyio.run(module.mcp.run_stdio_async, backend="asyncio")


if __name__ == "__main__":
    main()
