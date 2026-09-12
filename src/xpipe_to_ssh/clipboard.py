"""Clipboard subprocess adapter with bounded execution."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

from .errors import ClipboardError


def copy_to_clipboard(text: str, *, timeout: float = 3) -> str:
    commands: list[list[str]] = []
    if os.name == "nt":
        commands.append(["clip"])
    elif sys.platform == "darwin":
        commands.append(["pbcopy"])
    else:
        if os.environ.get("WAYLAND_DISPLAY"):
            commands.append(["wl-copy"])
        commands.extend([["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]])

    failures: list[str] = []
    for command in commands:
        executable = shutil.which(command[0])
        if not executable:
            failures.append(f"{command[0]} is not installed")
            continue
        try:
            result = subprocess.run(
                [executable, *command[1:]],
                input=text,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            failures.append(f"{command[0]} timed out")
            continue
        except OSError as exc:
            failures.append(f"{command[0]} failed to start: {exc}")
            continue
        if result.returncode == 0:
            return command[0]
        detail = (result.stderr or "").strip()
        failures.append(
            f"{command[0]} exited {result.returncode}" + (f": {detail}" if detail else "")
        )
    detail = "; ".join(failures) if failures else "no clipboard backend is configured"
    raise ClipboardError(f"Could not copy to the clipboard: {detail}")
