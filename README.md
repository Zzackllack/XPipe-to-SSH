# XPipe to SSH

Convert an XPipe SSH connection into a standalone OpenSSH command.

The CLI reads connection metadata through XPipe's local HTTP API, validates
the values it exports, shows alternative target addresses, and can print,
copy, or execute the resulting command. It never exports XPipe-managed
passwords.

Discovery uses XPipe's store name and type filters before fetching details.
Lookup still ranks exact paths, unique leaf names, and partial matches locally;
XPipe UUIDs remain the most reliable selector for automation.

## Requirements

- macOS, Linux, or Windows
- Python 3.13 or newer
- XPipe running, unlocked, with **Settings → HTTP API** enabled
- `uv` for installation from source

The dependency `xpipe-api>=0.1.34` supports XPipe 24's store API. A local
client uses XPipe's local authentication file automatically. Remote XPipe
instances require the client to be configured with a token and base URL; this
CLI intentionally constructs the local client only.

## Installation

```bash
git clone https://github.com/Zzackllack/XPipe-to-SSH.git
cd XPipe-to-SSH
uv sync
uv run xpipe-to-ssh --help
```

To put `xpipe-to-ssh` on your PATH, run `uv tool install .` from the checkout.
`uv run python main.py` remains available as a compatibility entry point for
older scripts.

## Usage

List exportable connections:

```bash
xpipe-to-ssh --list
xpipe-to-ssh --list --shell json
```

Generate a command using a full connection path, unique leaf name, or XPipe
store UUID:

```bash
xpipe-to-ssh "oracle-oc1"
xpipe-to-ssh d0cd9b16-11b4-4c90-b1fc-391d8e4bf12f
```

Select an alternative address or provide one explicitly:

```bash
xpipe-to-ssh oracle-oc1 --pick-host
xpipe-to-ssh oracle-oc1 --host 130.61.33.189
```

Use `--plain` for command-only output, `--shell json` for structured output,
and `--copy` to copy the rendered command:

```bash
xpipe-to-ssh oracle-oc1 --plain
xpipe-to-ssh oracle-oc1 --shell json
xpipe-to-ssh oracle-oc1 --copy
xpipe-to-ssh oracle-oc1 --strict --shell json
```

`--connect` executes the local `ssh` program after preparing the command. It
cannot be combined with `--plain`, `--shell json`, `--list`, or interactive
selection modes that do not apply to the selected connection.

To run a command on the selected connection, pass one explicit remote-shell
command string:

```bash
xpipe-to-ssh oracle-oc1 --connect --remote-command 'uname -a'
```

OpenSSH passes this string to the remote shell. Shell operators and expansions
in it run remotely; the CLI does not promise separate, safely quoted remote
arguments. Use a fixed or deliberately constructed command string.

## Authentication and agents

Password values stored by XPipe are not placed in argv, JSON, environment
variables, or logs. SSH may prompt for a password if key authentication fails.

For a `passwordManagerAgent` identity, the CLI carries the provider/identifier
metadata into agent selection and sets `SSH_AUTH_SOCK` only when a usable
agent is found:

```bash
xpipe-to-ssh oracle-oc1 --agent-socket "$HOME/.bitwarden-ssh-agent.sock"
xpipe-to-ssh oracle-oc1 --agent-socket none
```

Automatic path discovery currently covers the common macOS Bitwarden and
1Password sockets, the Unix `SSH_AUTH_SOCK`, and explicit endpoints on
Windows. Named-pipe/Pageant environments should use `--agent-socket` and are
not claimed as automatic support until tested on that platform.
If a target and its gateway name different password-manager agents, the CLI
warns because one inherited `SSH_AUTH_SOCK` may not authenticate both hops.
Use `--strict` to reject such a command in automation.

## Output and safety contract

- Normal command output is written to stdout; warnings and text-mode errors go
  to stderr.
- JSON command output has `schemaVersion: 1`, `connection`, `env`, `argv`, and
  `warnings`. JSON listing has `schemaVersion: 1` and `connections` with names,
  UUIDs, types, hosts, alternative hosts, and ports.
- JSON failures have `schemaVersion: 1` and an `error` object with a stable
  `code` and `message`. Ambiguous selectors also include `candidates` with
  names and XPipe IDs. They are printed on stdout so agents can parse them.
- `--strict` exits with code `2` when command generation has warnings, before
  copying or connecting. JSON errors include the warning list.
- Exit code `0` means success, `1` means XPipe/local integration failure, and
  `2` means invalid input, selection, or export data.
- XPipe hosts, aliases, usernames, and additional options are treated as
  input to OpenSSH argument construction. Review generated commands before
  executing them, especially command-bearing options such as `ProxyCommand`
  and `LocalCommand`.
- `--connect` runs the local `ssh` executable from the current environment and
  can open a network session. Tests and the optional smoke workflow do not
  connect to SSH.

## Development

```bash
uv run python -m unittest discover -v
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv lock --check
uv build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the read-only XPipe smoke-test
policy and release notes.
