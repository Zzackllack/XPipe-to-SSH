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
The older `python main.py` entry point has been removed; scripts that used it
should call the installed `xpipe-to-ssh` command or
`python -m xpipe_to_ssh` instead.

## Usage

List exportable connections:

```bash
xpipe-to-ssh --list
xpipe-to-ssh --list --plain                  # tab separated: name, target, port, type, id
xpipe-to-ssh --list --shell json
xpipe-to-ssh --list --filter ggl             # name substring
xpipe-to-ssh --list --filter '**oracle*'     # glob, passed to the daemon as written
```

`--filter` is applied by the daemon before any store details are fetched, so a
narrow filter is much cheaper than listing everything.

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

`--pick-host` needs an interactive terminal and requires a number from the
listed menu. A stored port that is absent or null means the SSH default, and a
stored alternative address that cannot be used safely is reported as a warning
instead of failing the export.

Review where a command came from, and pass extra `ssh` arguments through:

```bash
xpipe-to-ssh oracle-oc1 --explain
xpipe-to-ssh oracle-oc1 --plain --explain      # provenance on stderr, command on stdout
xpipe-to-ssh oracle-oc1 -- -- -J jump.example  # extra ssh arguments, before the destination
```

`--explain` prints every argument next to the XPipe field that produced it,
which is the fastest way to confirm a command does what you expect before
running it. With `--shell json` the same information appears as a `provenance`
array; without `--explain` the JSON payload is unchanged.

Arguments after `--` are inserted before the destination, are **not** validated
against the ssh option grammar, and produce a warning. They cannot be combined
with `--list` or `--remote-command`.

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
A stored `passwordManagerAgent` identity names a key, not a product, so a
recognizable agent socket is used unless XPipe names a product that no
discovered socket matches.
If a target and its gateway name different password-manager agents, the CLI
warns because one inherited `SSH_AUTH_SOCK` may not authenticate both hops.
Use `--strict` to reject such a command in automation.

## Output and safety contract

- Normal command output is written to stdout; warnings and text-mode errors go
  to stderr. The `--pick-host` menu is terminal chrome and also goes to stderr,
  so `--shell json` output stays parseable while selecting an address.
- JSON command output has `schemaVersion: 1`, `connection`, `env`, `argv`, and
  `warnings`, plus `provenance` when `--explain` is given. JSON listing has
  `schemaVersion: 1` and `connections` with names, UUIDs, types, hosts,
  alternative hosts, and ports. A port is `null` when XPipe does not state one
  or when an `ssh config` host owns its own port.
- JSON failures have `schemaVersion: 1` and an `error` object with a stable
  `code` and `message`. Ambiguous selectors also include `candidates` with
  names and XPipe IDs. They are printed on stdout so agents can parse them.
- `--strict` exits with code `2` when command generation has warnings, before
  copying or connecting. JSON errors include the warning list.
- Exit code `0` means success, `1` means XPipe/local integration failure, `2`
  means invalid input, selection, or export data, and `130` means the
  interactive host menu was interrupted with Ctrl-C.
- XPipe hosts, aliases, usernames, and additional options are treated as
  input to OpenSSH argument construction. Review generated commands before
  executing them, especially command-bearing options such as `ProxyCommand`
  and `LocalCommand`. Untrusted field values are truncated in error messages,
  so a malformed field cannot flood the output.
- `--connect` runs the local `ssh` executable from the current environment and
  can open a network session. Tests and the optional smoke workflow do not
  connect to SSH.

## Configuration

Optional, at `$XDG_CONFIG_HOME/xpipe-to-ssh/config.toml`, falling back to
`~/.config/xpipe-to-ssh/config.toml`. Every key is optional:

```toml
shell = "posix"              # auto | posix | powershell | json
agent_socket = "none"        # a path, or "none" to skip agent discovery
ptb = false                  # talk to an XPipe PTB build
api_timeout = 10.0           # seconds to wait for one XPipe request
```

Precedence is command line, then environment, then this file, then the built-in
default. A missing file is not an error; a malformed one is, because silently
ignoring it hides why a setting did not apply. Set `XPIPE_TO_SSH_CONFIG` to
point elsewhere, or to `/dev/null` to bypass the file entirely.

Environment variables: `XPIPE_TO_SSH_SHELL`, `XPIPE_TO_SSH_AGENT_SOCKET`,
`XPIPE_API_TIMEOUT` (seconds, 0 < value <= 300), and `XPIPE_TO_SSH_CONFIG`.
The timeout only exists as a setting because the upstream client has no
timeout parameter, so this CLI bounds every request with a worker thread.

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
