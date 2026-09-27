# Contributing

## Setup

```bash
uv sync
```

## Quality gates

Run the full local checks before submitting a change:

```bash
uv run python -m unittest discover -v
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv lock --check
uv build
```

The test suite uses `unittest` deliberately to keep the runtime dependency
surface small. Keep pure XPipe parsing, validation, planning, and rendering
testable without a running daemon or a real network.

CI also runs the suite on Windows, and once with `rich` uninstalled, because
the PowerShell renderer, Windows agent discovery, `list2cmdline` quoting, and
the no-rich presentation fallbacks are all branches a single platform cannot
reach. Keep those paths covered rather than merely present.

Platform behavior is a contract: pass `platform_name` explicitly in tests
instead of relying on the host, and prefer a pure function over anything that
inspects the machine it runs on.

## Live smoke tests

Live validation is opt-in and read-only. It may list XPipe stores and generate
POSIX/PowerShell/JSON command representations, but must never start SSH,
modify XPipe data, copy secrets, or commit captured responses. Record the
XPipe and `xpipe-api` versions with the result. Do not put credentials or
decrypted identity payloads in fixtures or logs.

The repository includes the guarded smoke command:

```bash
XPIPE_TO_SSH_LIVE_SMOKE=1 uv run python scripts/live_smoke.py
```

## Change structure

Keep commits focused by responsibility. Prefer a small adapter or value
object over broad exception handling or another dictionary traversal in the
CLI. When adding an external field, validate it at the XPipe boundary and
cover malformed input as well as the happy path.

Every new error carries its own `code`, `exit_code`, and any extra JSON
`details()`. Do not add a branch to the CLI's error reporting: declaring a
subclass of `ExportError` is the whole mechanism, and the code and exit status
it reports are part of the documented output contract.
