# XPipe to SSH

Convert an XPipe SSH connection into a standalone OpenSSH command.

The script reads connection details through XPipe’s local API, displays available target addresses, detects password-manager SSH agents, and can print or run the resulting command.

## Requirements

* macOS, Linux, or Windows
* XPipe running and unlocked
* **Settings → HTTP API** enabled in XPipe
* `uv`
* Python 3.13 recommended

## Installation

Create the project and install the dependencies:

```bash
uv init
uv python pin 3.13
uv add xpipe-api rich
```

Save the script as `main.py`.

## Usage

List available SSH connections:

```bash
uv run python main.py --list
```

Generate a command using a connection name or XPipe UUID:

```bash
uv run python main.py "oracle-oc1"
uv run python main.py d0cd9b16-11b4-4c90-b1fc-391d8e4bf12f
```

Connect immediately:

```bash
uv run python main.py oracle-oc1 --connect
```

Choose from XPipe’s available IP addresses:

```bash
uv run python main.py oracle-oc1 --pick-host
```

Use a specific address:

```bash
uv run python main.py oracle-oc1 --host 130.61.33.189
```

Copy the command to the clipboard:

```bash
uv run python main.py oracle-oc1 --copy
```

Print only the command for scripts or aliases:

```bash
uv run python main.py oracle-oc1 --plain
```

Export structured JSON:

```bash
uv run python main.py oracle-oc1 --shell json
```

## Password-manager SSH agents

Bitwarden and 1Password agent sockets are detected automatically. When required, the generated command includes `SSH_AUTH_SOCK`:

```bash
SSH_AUTH_SOCK="$HOME/.bitwarden-ssh-agent.sock" ssh user@host
```

Override the detected socket:

```bash
uv run python main.py oracle-oc1 \
  --agent-socket "$HOME/.bitwarden-ssh-agent.sock"
```

Disable agent detection:

```bash
uv run python main.py oracle-oc1 --agent-socket none
```

## Common options

| Option                | Description                    |
| --------------------- | ------------------------------ |
| `--list`              | List XPipe SSH connections     |
| `--connect`           | Run SSH directly               |
| `--pick-host`         | Choose an available address    |
| `--host ADDRESS`      | Use a specific target address  |
| `--copy`              | Copy the generated command     |
| `--plain`             | Print only the command         |
| `--shell json`        | Output connection data as JSON |
| `--agent-socket PATH` | Select an SSH-agent socket     |
| `--no-color`          | Disable terminal colors        |
| `--ptb`               | Connect to an XPipe PTB build  |

## Notes

Passwords stored by XPipe are never placed in the generated command. A password warning means SSH may prompt for it only if key authentication fails.

XPipe must be running while the script reads connection data through its local API. The generated SSH command itself does not require XPipe.
