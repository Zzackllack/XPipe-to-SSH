"""Opt-in, read-only XPipe smoke test.

Run with ``XPIPE_TO_SSH_LIVE_SMOKE=1 uv run python scripts/live_smoke.py``.
The script only queries stores and builds JSON-safe command metadata; it never
executes SSH or changes XPipe data.
"""

from __future__ import annotations

import importlib.metadata
import json
import os

from xpipe_to_ssh.cli import default_client
from xpipe_to_ssh.errors import ExportError, XPipeError
from xpipe_to_ssh.rendering import render
from xpipe_to_ssh.selection import exportable
from xpipe_to_ssh.ssh import build_ssh_argv
from xpipe_to_ssh.xpipe import query_all


def main() -> int:
    if os.environ.get("XPIPE_TO_SSH_LIVE_SMOKE") != "1":
        print("Set XPIPE_TO_SSH_LIVE_SMOKE=1 to enable the read-only smoke test.")
        return 2
    try:
        client = default_client(False)
        infos = [info for info in query_all(client) if exportable(info)]
        generated = 0
        failures = 0
        for info in infos:
            try:
                render(build_ssh_argv(client, info), "json")
                generated += 1
            except ExportError:
                failures += 1
        print(
            json.dumps(
                {
                    "xpipeApi": importlib.metadata.version("xpipe-api"),
                    "exportableStores": len(infos),
                    "generatedCommands": generated,
                    "failures": failures,
                },
                sort_keys=True,
            )
        )
        return 0 if failures == 0 else 1
    except XPipeError as exc:
        print(f"error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
