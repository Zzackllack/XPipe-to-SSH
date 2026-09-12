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

## Live smoke tests

Live validation is opt-in and read-only. It may list XPipe stores and generate
POSIX/PowerShell/JSON command representations, but must never start SSH,
modify XPipe data, copy secrets, or commit captured responses. Record the
XPipe and `xpipe-api` versions with the result. Do not put credentials or
decrypted identity payloads in fixtures or logs.

## Change structure

Keep commits focused by responsibility. Prefer a small adapter or value
object over broad exception handling or another dictionary traversal in the
CLI. When adding an external field, validate it at the XPipe boundary and
cover malformed input as well as the happy path.

