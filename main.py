#!/usr/bin/env python3
"""Turn an XPipe SSH connection into a usable OpenSSH command.

Features:
- Rich terminal dashboard with connection details and warning panels
- Displays XPipe's selected and alternative target addresses
- Auto-detects Bitwarden and 1Password SSH-agent sockets
- Interactive target selection with --pick-host
- Direct connection with --connect
- Script-friendly raw output with --plain or --shell json

Requirements:
    uv add xpipe-api rich

Examples:
    uv run python main.py --list
    uv run python main.py 632b70d2-43cf-46f1-a805-06525fc6ba02
    uv run python main.py 632b70d2-43cf-46f1-a805-06525fc6ba02 --pick-host
    uv run python main.py 632b70d2-43cf-46f1-a805-06525fc6ba02 --connect
    uv run python main.py 632b70d2-43cf-46f1-a805-06525fc6ba02 --plain
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# xpipe-api imports a dependency that expects an event loop at import time.
_XPIPE_IMPORT_LOOP = asyncio.new_event_loop()
asyncio.set_event_loop(_XPIPE_IMPORT_LOOP)
try:
    from xpipe_api import Client
except ImportError:
    sys.exit("Missing dependency. Run: uv add xpipe-api")

try:
    from rich import box
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class ExportError(RuntimeError):
    pass


@dataclass
class IdentityResult:
    argv: list[str] = field(default_factory=list)
    username: str | None = None
    auth_methods: list[str] = field(default_factory=list)
    needs_password_manager_agent: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass
class AgentSocket:
    path: str
    label: str
    identity_count: int


@dataclass
class SSHCommand:
    argv: list[str]
    env: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    needs_password_manager_agent: bool = False

    connection_name: str = ""
    connection_id: str = ""
    connection_type: str = "ssh"
    selected_host: str = ""
    available_hosts: list[str] = field(default_factory=list)
    username: str | None = None
    port: int = 22
    auth_methods: list[str] = field(default_factory=list)
    gateway_names: list[str] = field(default_factory=list)
    agent: AgentSocket | None = None


def unique_text(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = selected_text(value)
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def api_method(client: Client, *names: str) -> Any:
    """Return the first API method supported by the installed client."""
    for name in names:
        method = getattr(client, name, None)
        if callable(method):
            return method
    supported = ", ".join(names)
    raise ExportError(f"Installed xpipe-api does not provide any of: {supported}")


def store_id(info: dict[str, Any]) -> str:
    """Return the v24 store ID, with a v23 connection-ID fallback."""
    value = info.get("store") or info.get("connection")
    return str(value) if value else ""


def info_one(client: Client, ref: str) -> dict[str, Any]:
    values = api_method(client, "store_info", "connection_info")([ref])
    if not values:
        raise ExportError(f"XPipe returned no information for {ref}")
    return values[0]


def display_path(info: dict[str, Any]) -> str:
    names = info.get("name") or []
    if isinstance(names, str):
        return names
    return "/".join(str(part) for part in names)


def query_all(client: Client) -> list[dict[str, Any]]:
    if callable(getattr(client, "store_query", None)):
        refs = client.store_query(categories="**", stores="**", types="*")
    else:
        refs = api_method(client, "connection_query")(connections="**")

    if not refs:
        return []
    return api_method(client, "store_info", "connection_info")(
        list(dict.fromkeys(refs))
    )


def connection_config(info: dict[str, Any]) -> dict[str, Any]:
    """Return the store schema across XPipe API field-name versions."""
    keys = ("rawData", "config", "data")
    for key in keys:
        value = info.get(key)
        if isinstance(value, dict) and value:
            nested = value.get("config")
            if isinstance(nested, dict) and nested:
                return nested
            return value
    for key in keys:
        value = info.get(key)
        if isinstance(value, dict):
            return value
    return {}


def selected_value(value: Any) -> Any:
    """Unwrap XPipe values such as {value: ..., available: [...]} objects."""
    seen: set[int] = set()
    while isinstance(value, dict) and id(value) not in seen:
        seen.add(id(value))
        if "value" in value:
            value = value.get("value")
            continue
        if "selected" in value:
            value = value.get("selected")
            continue
        break
    return value


def selected_text(value: Any) -> str | None:
    value = selected_value(value)
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (str, int, float)):
        text = str(value).strip()
        return text or None
    return None


def selectable_texts(value: Any) -> tuple[str | None, list[str]]:
    """Return the selected value and all advertised alternatives."""
    selected = selected_text(value)
    available_raw: list[Any] = []

    if isinstance(value, dict):
        for key in ("available", "alternatives", "options", "values"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                available_raw.extend(candidate)

    available = unique_text(([selected] if selected else []) + available_raw)
    return selected, available


def choose_connection(client: Client, selector: str) -> dict[str, Any]:
    if UUID_RE.fullmatch(selector):
        return info_one(client, selector)

    all_infos = query_all(client)
    needle = selector.casefold().strip("/")

    exact = [
        info
        for info in all_infos
        if display_path(info).casefold().strip("/") == needle
        or display_path(info).split("/")[-1].casefold() == needle
    ]
    matches = exact or [
        info for info in all_infos if needle in display_path(info).casefold()
    ]
    matches = [
        info
        for info in matches
        if info.get("type") in {"ssh", "sshConfigHost"}
        or connection_config(info).get("type") in {"ssh", "sshConfigHost"}
    ]

    if not matches:
        raise ExportError(
            f"No SSH connection matched {selector!r}. Use --list to see names."
        )
    if len(matches) > 1:
        names = "\n  ".join(
            f"{display_path(info)}  [{store_id(info)}]" for info in matches[:20]
        )
        raise ExportError(
            f"Connection name is ambiguous. Use a full path or UUID:\n  {names}"
        )
    return matches[0]


def find_identity_store(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        if "username" in value and (
            "sshIdentity" in value
            or "password" in value
            or str(value.get("type", "")).lower().endswith("identity")
        ):
            return value
        for child in value.values():
            found = find_identity_store(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_identity_store(child)
            if found:
                return found
    return None


def resolve_identity(
    client: Client,
    identity: Any,
    warnings: list[str],
) -> dict[str, Any] | None:
    if not isinstance(identity, dict):
        return None

    kind = identity.get("type")
    if kind == "inPlace":
        return find_identity_store(identity.get("identityStore"))
    if kind == "ref" and identity.get("ref"):
        identity_info = info_one(client, str(identity["ref"]))
        store = find_identity_store(connection_config(identity_info))
        if not store:
            warnings.append(
                f"Could not understand the identity schema for {display_path(identity_info)}."
            )
        return store

    return find_identity_store(identity)


def decrypt_json(client: Client, encrypted: Any, warnings: list[str]) -> Any:
    if not encrypted:
        return None
    try:
        raw = client.secret_decrypt(encrypted)
    except Exception as exc:
        warnings.append(f"Could not decrypt SSH identity metadata: {exc}")
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return raw


def decode_identity_data(client: Client, value: Any, warnings: list[str]) -> Any:
    """Decode v23 encrypted identity data or return a v24 descriptor directly."""
    if isinstance(value, dict):
        descriptor_type = value.get("type")
        encrypted_keys = {"secrets", "encryptedValue", "encryptedToken"}
        if isinstance(descriptor_type, str) and not encrypted_keys.intersection(value):
            return value
    return decrypt_json(client, value, warnings)


def identity_options(client: Client, cfg: dict[str, Any]) -> IdentityResult:
    result = IdentityResult()
    store = resolve_identity(client, cfg.get("identity"), result.warnings)
    if not store:
        result.auth_methods.append("SSH defaults / config")
        return result

    result.username = selected_text(store.get("username"))
    if result.username:
        result.argv += ["-l", result.username]

    key_data = decode_identity_data(client, store.get("sshIdentity"), result.warnings)
    if isinstance(key_data, dict):
        key_type = selected_text(key_data.get("type"))
        key_file = selected_text(key_data.get("file"))
        normalized = key_type.casefold() if key_type else ""

        if normalized == "file" and key_file:
            expanded = os.path.expanduser(key_file)
            result.argv += ["-i", expanded]
            result.auth_methods.append(f"Key file: {expanded}")
        elif normalized == "passwordmanageragent":
            result.needs_password_manager_agent = True
            result.auth_methods.append("Password-manager SSH agent")
        elif normalized in {"", "none"}:
            pass
        elif normalized == "agent":
            result.auth_methods.append("SSH agent")
        else:
            result.auth_methods.append(f"XPipe key type: {key_type}")
            result.warnings.append(
                f"SSH key type {key_type!r} may depend on XPipe or local SSH configuration."
            )

    # Deliberately never put a password into argv or process listings.
    if store.get("password"):
        result.auth_methods.append("Password fallback")
        result.warnings.append(
            "XPipe-managed password was not exported; SSH may prompt for it if the key is rejected."
        )

    if not result.auth_methods:
        result.auth_methods.append("SSH defaults / config")
    return result


def additional_options(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        lines = raw.splitlines()
    elif isinstance(raw, list):
        lines = [str(item) for item in raw]
    elif isinstance(raw, dict):
        lines = [f"{key}={value}" for key, value in raw.items()]
    else:
        lines = [str(raw)]

    result: list[str] = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            result += ["-o", line]
    return result


def ssh_config_alias(info: dict[str, Any], cfg: dict[str, Any]) -> str:
    for key in ("alias", "host", "hostName", "name"):
        value = selected_text(cfg.get(key))
        if value:
            return value
    host_entry = cfg.get("hostEntry")
    if isinstance(host_entry, dict):
        for key in ("name", "alias", "host", "hostName"):
            value = selected_text(host_entry.get(key))
            if value:
                return value
    path = display_path(info)
    if path:
        return path.split("/")[-1]
    raise ExportError("Could not determine the SSH config alias")


def build_ssh_argv(
    client: Client,
    info: dict[str, Any],
    *,
    proxy_mode: bool = False,
    visited: set[str] | None = None,
    host_override: str | None = None,
) -> SSHCommand:
    visited = set() if visited is None else set(visited)
    ref = store_id(info)
    if ref:
        if ref in visited:
            raise ExportError("Gateway cycle detected in XPipe configuration")
        visited.add(ref)

    cfg = connection_config(info)
    connection_type = str(info.get("type") or cfg.get("type") or "")
    name = display_path(info)

    if connection_type == "sshConfigHost" or cfg.get("type") == "sshConfigHost":
        alias = ssh_config_alias(info, cfg)
        argv = ["ssh"]
        if proxy_mode:
            argv += ["-W", "%h:%p"]
        argv.append(alias)
        return SSHCommand(
            argv=argv,
            connection_name=name,
            connection_id=ref,
            connection_type="sshConfigHost",
            selected_host=alias,
            available_hosts=[alias],
            auth_methods=["~/.ssh/config"],
        )

    if cfg.get("type") != "ssh" and connection_type != "ssh":
        raise ExportError(
            f"{name!r} is type {connection_type!r}, not a directly exportable SSH connection"
        )

    selected_host, available_hosts = selectable_texts(cfg.get("host"))
    host = host_override or selected_host
    if not host:
        raise ExportError(
            f"{name!r} has no usable SSH host (raw value: {cfg.get('host')!r})"
        )

    warnings: list[str] = []
    if host_override and available_hosts and host_override not in available_hosts:
        warnings.append(
            f"The manually selected host {host_override!r} was not in XPipe's advertised alternatives."
        )
    if host not in available_hosts:
        available_hosts.insert(0, host)

    argv = ["ssh"]
    port_text = selected_text(cfg.get("port"))
    port = 22
    if port_text:
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ExportError(f"Invalid SSH port {port_text!r}") from exc
        if port != 22:
            argv += ["-p", str(port)]

    identity = identity_options(client, cfg)
    argv += identity.argv
    warnings.extend(identity.warnings)

    if cfg.get("forwardX11"):
        argv.append("-X")

    argv += additional_options(cfg.get("additionalOptions"))

    gateway_names: list[str] = []
    needs_agent = identity.needs_password_manager_agent
    gateway_ref = selected_text(cfg.get("gateway"))
    if gateway_ref:
        gateway_info = info_one(client, gateway_ref)
        gateway_command = build_ssh_argv(
            client,
            gateway_info,
            proxy_mode=True,
            visited=visited,
        )
        needs_agent = needs_agent or gateway_command.needs_password_manager_agent
        warnings.extend(gateway_command.warnings)
        gateway_names = [
            gateway_command.connection_name,
            *gateway_command.gateway_names,
        ]
        argv += ["-o", f"ProxyCommand={shlex.join(gateway_command.argv)}"]

    if proxy_mode:
        argv += ["-W", "%h:%p"]

    argv.append(host)
    return SSHCommand(
        argv=argv,
        warnings=unique_strings(warnings),
        needs_password_manager_agent=needs_agent,
        connection_name=name,
        connection_id=ref,
        connection_type="ssh",
        selected_host=host,
        available_hosts=available_hosts,
        username=identity.username,
        port=port,
        auth_methods=identity.auth_methods,
        gateway_names=gateway_names,
    )


def unique_strings(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def powershell_join(argv: list[str]) -> str:
    def quote(arg: str) -> str:
        if arg and not re.search(r"[\s'`$&|<>;(){}\[\]]", arg):
            return arg
        return "'" + arg.replace("'", "''") + "'"

    return " ".join(quote(arg) for arg in argv)


def candidate_agent_sockets() -> list[Path]:
    home = Path.home()
    candidates = [
        home / ".bitwarden-ssh-agent.sock",
        home
        / "Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock",
        home / "Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
    ]
    current = os.environ.get("SSH_AUTH_SOCK")
    if current:
        candidates.append(Path(os.path.expandvars(os.path.expanduser(current))))

    result: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        text = str(candidate)
        if text not in seen:
            seen.add(text)
            result.append(candidate)
    return result


def agent_label(path: Path) -> str:
    normalized = str(path).casefold()
    if "bitwarden" in normalized:
        return "Bitwarden"
    if "1password" in normalized:
        return "1Password"
    if "apple" in normalized or "launchd" in normalized:
        return "macOS SSH agent"
    return "SSH agent"


def agent_identity_count(socket_path: Path) -> int:
    try:
        result = subprocess.run(
            ["ssh-add", "-L"],
            env={**os.environ, "SSH_AUTH_SOCK": str(socket_path)},
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return 0
    if result.returncode != 0:
        return 0
    return len([line for line in result.stdout.splitlines() if line.strip()])


def resolve_agent_socket(requested: str) -> AgentSocket | None:
    if requested == "none":
        return None

    if requested != "auto":
        path = Path(os.path.expandvars(os.path.expanduser(requested)))
        if not path.exists():
            raise ExportError(f"SSH agent socket does not exist: {path}")
        return AgentSocket(str(path), agent_label(path), agent_identity_count(path))

    existing: list[AgentSocket] = []
    for candidate in candidate_agent_sockets():
        if candidate.exists():
            existing.append(
                AgentSocket(
                    str(candidate),
                    agent_label(candidate),
                    agent_identity_count(candidate),
                )
            )

    for agent in existing:
        if agent.identity_count > 0:
            return agent
    return existing[0] if existing else None


def render(command: SSHCommand, shell: str) -> str:
    if shell == "auto":
        shell = "powershell" if os.name == "nt" else "posix"
    if shell == "json":
        return json.dumps(
            {
                "connection": {
                    "name": command.connection_name,
                    "id": command.connection_id,
                    "host": command.selected_host,
                    "availableHosts": command.available_hosts,
                    "port": command.port,
                    "username": command.username,
                    "auth": command.auth_methods,
                    "gateways": command.gateway_names,
                },
                "env": command.env,
                "argv": command.argv,
                "warnings": command.warnings,
            },
            indent=2,
        )
    if shell == "powershell":
        rendered = powershell_join(command.argv)
        if command.env:
            prefix = "; ".join(
                f"$env:{key}={powershell_join([value])}"
                for key, value in command.env.items()
            )
            return f"{prefix}; {rendered}"
        return rendered

    rendered = shlex.join(command.argv)
    if command.env:
        prefix = " ".join(
            f"{key}={shlex.quote(value)}" for key, value in command.env.items()
        )
        return f"{prefix} {rendered}"
    return rendered


def address_kind(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
        return f"IPv{address.version}"
    except ValueError:
        return "Hostname"


def make_console(*, no_color: bool = False, stderr: bool = False) -> Any:
    if not RICH_AVAILABLE:
        return None
    return Console(no_color=no_color, stderr=stderr, highlight=False)


def render_address_table(command: SSHCommand) -> Any:
    table = Table(box=box.SIMPLE_HEAVY, expand=True, show_header=True)
    table.add_column("Status", width=10, no_wrap=True)
    table.add_column("Address", overflow="fold")
    table.add_column("Type", width=10, no_wrap=True)

    for host in command.available_hosts:
        if host == command.selected_host:
            table.add_row(
                "[bold green]Selected[/]", f"[bold]{host}[/]", address_kind(host)
            )
        else:
            table.add_row("[cyan]Available[/]", host, address_kind(host))
    return table


def render_dashboard(
    command: SSHCommand,
    command_text: str,
    *,
    no_color: bool = False,
    copied: bool = False,
    stderr: bool = False,
) -> None:
    if not RICH_AVAILABLE:
        for warning in command.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        print(command_text)
        return

    console = make_console(no_color=no_color, stderr=stderr)

    title = Text("XPipe  →  OpenSSH", style="bold")
    subtitle = Text(command.connection_name or command.selected_host, style="cyan")
    header = Group(title, subtitle)
    console.print(Panel.fit(header, border_style="cyan", padding=(0, 2)))

    details = Table.grid(padding=(0, 2), expand=True)
    details.add_column(style="bold", width=15, no_wrap=True)
    details.add_column(overflow="fold")
    details.add_row("Connection", command.connection_name or "—")
    details.add_row("XPipe ID", command.connection_id or "—")
    details.add_row("Target", command.selected_host)
    details.add_row("Port", str(command.port))
    details.add_row("User", command.username or "SSH default")
    details.add_row("Authentication", ", ".join(command.auth_methods) or "SSH default")
    if command.agent:
        details.add_row(
            "SSH agent",
            f"{command.agent.label} · {command.agent.identity_count} "
            f"identit{'y' if command.agent.identity_count == 1 else 'ies'}",
        )
        details.add_row("Agent socket", command.agent.path)
    elif command.needs_password_manager_agent:
        details.add_row("SSH agent", "Not found")
    if command.gateway_names:
        details.add_row("Gateway", " → ".join(command.gateway_names))

    console.print(Panel(details, title="Connection", border_style="blue"))

    console.print(
        Panel(
            render_address_table(command),
            title=f"Target addresses ({len(command.available_hosts)})",
            border_style="magenta",
            subtitle="Use --pick-host or --host ADDRESS",
        )
    )

    if command.warnings:
        warning_lines = []
        for warning in command.warnings:
            line = Text()
            line.append("! ", style="bold yellow")
            line.append(warning)
            warning_lines.append(line)
        console.print(
            Panel(
                Group(*warning_lines),
                title=f"Warnings ({len(command.warnings)})",
                border_style="yellow",
            )
        )

    language = "powershell" if command_text.lstrip().startswith("$env:") else "bash"
    syntax = Syntax(
        command_text,
        language,
        word_wrap=True,
        background_color="default",
        padding=(0, 1),
    )
    subtitle_text = "Copied to clipboard" if copied else "Use --copy or --connect"
    console.print(
        Panel(
            syntax,
            title="SSH command",
            subtitle=subtitle_text,
            border_style="green",
        )
    )


def render_list(infos: list[dict[str, Any]], *, plain: bool, no_color: bool) -> None:
    if plain or not RICH_AVAILABLE or not sys.stdout.isatty():
        for info in sorted(infos, key=lambda item: display_path(item).casefold()):
            print(f"{display_path(info)}\t{store_id(info)}")
        return

    console = make_console(no_color=no_color)
    table = Table(
        title="XPipe SSH connections",
        box=box.ROUNDED,
        expand=True,
        show_lines=False,
    )
    table.add_column("Name", ratio=3, overflow="fold")
    table.add_column("Target", ratio=2, overflow="fold")
    table.add_column("Port", width=6, justify="right")
    table.add_column("Type", width=14)
    table.add_column("XPipe ID", ratio=2, overflow="fold")

    for info in sorted(infos, key=lambda item: display_path(item).casefold()):
        cfg = connection_config(info)
        connection_type = str(info.get("type") or cfg.get("type") or "")
        if connection_type == "sshConfigHost":
            target = ssh_config_alias(info, cfg)
            port = "—"
        else:
            target = selected_text(cfg.get("host")) or "—"
            port = selected_text(cfg.get("port")) or "22"
        table.add_row(
            display_path(info),
            target,
            port,
            connection_type,
            store_id(info),
        )
    console.print(table)


def choose_host_interactively(
    current: str | None,
    available: list[str],
    *,
    no_color: bool,
) -> str | None:
    if len(available) <= 1:
        return current
    if not sys.stdin.isatty():
        raise ExportError("--pick-host requires an interactive terminal")

    if RICH_AVAILABLE:
        console = make_console(no_color=no_color)
        table = Table(title="Choose target address", box=box.ROUNDED)
        table.add_column("#", justify="right", width=4)
        table.add_column("Address")
        table.add_column("Type")
        table.add_column("Current", width=9)
        for index, host in enumerate(available, 1):
            table.add_row(
                str(index),
                host,
                address_kind(host),
                "[green]yes[/]" if host == current else "",
            )
        console.print(table)
        default_index = available.index(current) + 1 if current in available else 1
        choice = Prompt.ask(
            "Address number",
            choices=[str(index) for index in range(1, len(available) + 1)],
            default=str(default_index),
            console=console,
        )
        return available[int(choice) - 1]

    for index, host in enumerate(available, 1):
        marker = " (selected)" if host == current else ""
        print(f"{index}. {host}{marker}")
    raw = input("Address number: ").strip()
    try:
        return available[int(raw) - 1]
    except (ValueError, IndexError) as exc:
        raise ExportError("Invalid address selection") from exc


def copy_to_clipboard(text: str) -> str:
    commands: list[list[str]] = []
    if sys.platform == "darwin":
        commands.append(["pbcopy"])
    elif os.name == "nt":
        commands.append(["clip"])
    else:
        if os.environ.get("WAYLAND_DISPLAY"):
            commands.append(["wl-copy"])
        commands.extend(
            [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
        )

    for command in commands:
        if shutil.which(command[0]):
            result = subprocess.run(
                command,
                input=text,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
            )
            if result.returncode == 0:
                return command[0]
    raise ExportError("No supported clipboard command was found")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export an XPipe SSH connection as one OpenSSH command"
    )
    parser.add_argument(
        "connection", nargs="?", help="connection name/path or XPipe UUID"
    )
    parser.add_argument("--list", action="store_true", help="list SSH connections")
    parser.add_argument(
        "--shell",
        choices=("auto", "posix", "powershell", "json"),
        default="auto",
        help="command quoting format (default: auto)",
    )
    parser.add_argument(
        "--ptb", action="store_true", help="connect to an XPipe PTB build"
    )
    parser.add_argument(
        "--agent-socket",
        default="auto",
        metavar="PATH",
        help=(
            "SSH agent socket for passwordManagerAgent identities; "
            "default: auto-detect Bitwarden/1Password, or use 'none'"
        ),
    )
    parser.add_argument(
        "--host",
        metavar="ADDRESS",
        help="override XPipe's selected host with a specific address",
    )
    parser.add_argument(
        "--pick-host",
        action="store_true",
        help="interactively choose from XPipe's available target addresses",
    )
    parser.add_argument(
        "--connect",
        action="store_true",
        help="run SSH directly after showing the connection dashboard",
    )
    parser.add_argument(
        "--copy",
        action="store_true",
        help="copy the rendered SSH command to the system clipboard",
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="print only the command; useful for scripts and command substitution",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable terminal colors",
    )
    args = parser.parse_args()

    try:
        client = Client(ptb=args.ptb)
        if args.list:
            infos = query_all(client)
            ssh_infos = [
                info
                for info in infos
                if info.get("type") in {"ssh", "sshConfigHost"}
                or connection_config(info).get("type") in {"ssh", "sshConfigHost"}
            ]
            render_list(ssh_infos, plain=args.plain, no_color=args.no_color)
            return 0

        if not args.connection:
            parser.error("provide a connection name/UUID, or use --list")

        info = choose_connection(client, args.connection)
        cfg = connection_config(info)
        selected_host, available_hosts = selectable_texts(cfg.get("host"))
        host_override = args.host
        if args.pick_host:
            host_override = choose_host_interactively(
                selected_host,
                available_hosts,
                no_color=args.no_color,
            )

        command = build_ssh_argv(client, info, host_override=host_override)

        if command.needs_password_manager_agent:
            agent = resolve_agent_socket(args.agent_socket)
            if agent:
                command.agent = agent
                command.env["SSH_AUTH_SOCK"] = agent.path
                if agent.identity_count == 0:
                    command.warnings.append(
                        f"{agent.label} socket was found, but ssh-add reported no identities."
                    )
            else:
                command.warnings.append(
                    "This connection uses a password-manager SSH agent, but no usable "
                    "agent socket was found. Pass --agent-socket PATH."
                )

        command.warnings = unique_strings(command.warnings)
        command_text = render(command, args.shell)

        copied = False
        if args.copy:
            copy_to_clipboard(command_text)
            copied = True

        pretty = (
            not args.plain
            and args.shell != "json"
            and RICH_AVAILABLE
            and sys.stdout.isatty()
        )

        if args.connect:
            if pretty:
                render_dashboard(
                    command,
                    command_text,
                    no_color=args.no_color,
                    copied=copied,
                    stderr=True,
                )
            else:
                for warning in command.warnings:
                    print(f"warning: {warning}", file=sys.stderr)
            env = {**os.environ, **command.env}
            os.execvpe(command.argv[0], command.argv, env)

        if pretty:
            render_dashboard(
                command,
                command_text,
                no_color=args.no_color,
                copied=copied,
            )
        else:
            for warning in command.warnings:
                print(f"warning: {warning}", file=sys.stderr)
            print(command_text)
        return 0

    except ExportError as exc:
        if RICH_AVAILABLE and sys.stderr.isatty() and not args.plain:
            console = make_console(no_color=args.no_color, stderr=True)
            console.print(Panel(str(exc), title="Error", border_style="red"))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        message = (
            "Could not talk to XPipe. Ensure XPipe is running and "
            f"Settings → HTTP API is enabled.\n\nDetails: {exc}"
        )
        if RICH_AVAILABLE and sys.stderr.isatty() and not args.plain:
            console = make_console(no_color=args.no_color, stderr=True)
            console.print(Panel(message, title="XPipe API error", border_style="red"))
        else:
            print(f"error: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
