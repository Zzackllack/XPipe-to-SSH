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
CLI intentionally constructs the local client only. `pyyaml` renders the YAML
and Ansible inventory exports.

## When XPipe is not running

If the CLI cannot reach the XPipe daemon, it offers to start it — on
interactive terminals only (stderr must be a terminal too), after the
connection check fails and before any work begins:

```text
XPipe is not running. Open it now with `xpipe open`? [Y/n]
```

Answering yes launches `xpipe open` (which starts the daemon and opens the
application) and the CLI waits up to 60 seconds for the local HTTP API to
answer before continuing; answering no prints the usual error. `--shell json`
and non-interactive terminals never see the prompt. The offer is also skipped
for `--ptb` and for `XPIPE_BEACON_PORT` overrides, because a plain
`xpipe open` starts the release build. When XPipe is running but rejects
authentication — the HTTP API is disabled or XPipe is locked — reopening
would not help, so the CLI reports that instead of offering a restart.

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
narrow filter is much cheaper than listing or exporting everything.

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

## Bulk export

Export every saved connection at once instead of one command at a time. A
`--filter` narrows the set at the daemon, exactly as with `--list`. On an
interactive terminal the export shows a summary on stderr while it runs and
after it finishes: a header, a table of exported connections with their
ports and agent bindings, a `Skipped` table for connections that could not
be exported, and the usual warnings. The document itself stays on stdout, so
`xpipe-to-ssh --export ssh-config > ssh.conf` works as before; the summary is
terminal chrome only. Non-interactive terminals and `--shell json` keep the
plain `warning:` lines, and `--pick-hosts` menus are shown instead of the
spinner while you answer.

```bash
xpipe-to-ssh --export ssh-config                              # OpenSSH config on stdout
xpipe-to-ssh --export ssh-config --output ~/.ssh/config.d/xpipe.conf
xpipe-to-ssh --export yaml --output hosts.yaml
xpipe-to-ssh --export ansible --output inventory.yml
xpipe-to-ssh --export json --filter '**prod**'
xpipe-to-ssh --export ssh-config --pick-hosts    # ask which address to use, per connection
```

Formats:

- `ssh-config` - an OpenSSH client config. Each connection becomes a
  `Host <alias>` block with `HostName`, `User`, `Port`, `IdentityFile`,
  `ForwardX11`, a `ProxyCommand` for a gateway hop, `IdentityAgent` for a
  password-manager-agent connection, and any `additionalOptions`. The alias
  is the full XPipe path with whitespace and glob characters folded to `-`,
  for example `Host default/oracle-oc1`. A connection whose ProxyCommand
  delegates to an exported gateway expands the gateway's `Host` line with
  the destination the command dials (for example `Host default/gateway
  gw.example`), so the inner ssh hop re-reading the config picks up the
  gateway's Port, User, IdentityFile, and IdentityAgent. Include the
  generated file from `~/.ssh/config`.
- `yaml` - the same fields as an ordered `hosts:` list, for tooling that reads
  a `hosts.yaml`/`hosts.yml`.
- `ansible` - an Ansible inventory (`all.hosts`) with `ansible_host`,
  `ansible_user`, `ansible_port`, `ansible_ssh_private_key_file`, and
  `ansible_ssh_common_args` for gateways and extra options.
- `json` - structured output with `schemaVersion` and `generator`.

Connections whose identity is a password-manager SSH agent cannot
authenticate without knowing the agent socket, so the export binds them the
same way the single-command path does: a machine-specific `IdentityAgent`
in `ssh-config`, an `IdentityAgent=...` in `ansible_ssh_common_args`, or an
`identityAgent` field in `yaml`/`json` records. If no matching socket is
found, the connection is exported with a warning instead of failing
silently; `--strict` turns that into a failure. `--agent-socket PATH` forces
one socket for the whole export instead of auto-discovering per connection,
and `--agent-socket none` disables agent binding entirely.

Connections that store several available addresses export the one XPipe has
selected. To choose per connection while exporting, pass `--pick-hosts`
(interactive terminals only): every connection with more than one available
address is offered the same numbered menu as `--pick-host`, and the chosen
address is written into the document. Your answer is kept per connection, so
a connection with a single address is never asked about. `--pick-hosts`
requires `--export` and an interactive terminal; with `--shell json` the
menus stay on stderr so stdout remains machine readable. An answer that is
out of range, empty of input, or an interrupt aborts the whole export with
exit code 2 and writes no file; the document is never half-written.

`--output PATH` writes the document to a file instead of stdout; `-` means
stdout. An existing file is never overwritten unless `--force` is given, and a
new file is written to a temporary name and moved into place with mode `0600`,
because it can name key files and carry a `ProxyCommand`.

XPipe stores of type `sshConfigHost` already resolve through `~/.ssh/config`,
so they are skipped with a warning rather than re-exported as a self-reference.
A connection with unusable data is skipped and reported as a warning, so one
broken store cannot sink the whole export; `--strict` turns any warning into a
failure. No password, passphrase, or decrypted identity payload is ever
written.

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
  so `--shell json` output stays parseable while selecting an address. On an
  interactive terminal, errors render as a red panel and status notes as
  one-liners instead of plain text; piped output, `--plain`, and `--shell
  json` never see panels. Machine-readable bytes are unchanged: JSON error
  payloads, exit codes, and `--plain` output are identical to before. The one
  exception is `--help`, which is rendered by rich-argparse (heading case and
  layout differ, colors on a tty); scripts that need a stable shape should
  parse JSON, not help text.
- JSON command output has `schemaVersion: 1`, `connection`, `env`, `argv`, and
  `warnings`, plus `provenance` when `--explain` is given. JSON listing has
  `schemaVersion: 1` and `connections` with names, UUIDs, types, hosts,
  alternative hosts, and ports. A port is `null` when XPipe does not state one
  or when an `ssh config` host owns its own port. `--export json` has its own
  `schemaVersion: 1` document with `generator` and a `hosts` array.
- Bulk export writes the document to stdout, or to `--output`; warnings and the
  `wrote ...` line go to stderr, so a redirected document stays clean. On a
  terminal, the summary panels go to stderr as well, so stdout never carries
  chrome either.
- JSON failures have `schemaVersion: 1` and an `error` object with a stable
  `code` and `message`. Ambiguous selectors also include `candidates` with
  names and XPipe IDs. They are printed on stdout so agents can parse them.
- `--strict` exits with code `2` when command generation has warnings, or when
  a bulk export skipped a connection, before copying, connecting, or writing.
  JSON errors include the warning list.
- Exit code `0` means success, `1` means XPipe/local integration failure
  (including an output file that could not be written or would be clobbered),
  `2` means invalid input, selection, or export data, and `130` means the
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
