"""Opt-in, read-only XPipe smoke test.

Run with ``XPIPE_TO_SSH_LIVE_SMOKE=1 uv run python scripts/live_smoke.py``.
The script only queries stores and builds JSON-safe command metadata; it never
executes SSH or changes XPipe data.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import sys

from xpipe_to_ssh.cli import default_client
from xpipe_to_ssh.errors import ExportError, XPipeError
from xpipe_to_ssh.rendering import render
from xpipe_to_ssh.selection import exportable_connections
from xpipe_to_ssh.ssh import build_ssh_argv
from xpipe_to_ssh.xpipe import display_path


def main() -> int:
    if os.environ.get("XPIPE_TO_SSH_LIVE_SMOKE") != "1":
        print("Set XPIPE_TO_SSH_LIVE_SMOKE=1 to enable the read-only smoke test.")
        return 2
    try:
        client = default_client(False)
        # Filter by type at the daemon, the same way the CLI lists, so this
        # does not pull every store's detail across the API.
        infos = exportable_connections(client)
        generated: list[str] = []
        failures: list[dict[str, str]] = []
        for info in infos:
            name = display_path(info) or "<unnamed>"
            try:
                render(build_ssh_argv(client, info), "json")
            except ExportError as exc:
                # Report which connection failed; a bare counter is useless
                # when a real installation has a few broken stores.
                failures.append({"name": name, "error": str(exc)})
            else:
                generated.append(name)
        print(
            json.dumps(
                {
                    "xpipeApi": importlib.metadata.version("xpipe-api"),
                    "exportableStores": len(infos),
                    "generatedCommands": len(generated),
                    # Store names and validation messages only: no secrets, no
                    # identity payloads, nothing that could reach a log.
                    "failures": failures,
                },
                sort_keys=True,
                indent=2,
            )
        )
        return 0 if not failures else 1
    except XPipeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
