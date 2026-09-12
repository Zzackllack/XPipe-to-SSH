"""Human-facing Rich and plain terminal presentation."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from .errors import ExportError
from .models import SSHCommand
from .rendering import address_kind
from .ssh import ssh_config_alias
from .xpipe import WireRecord, connection_config, display_path, selected_text, store_id

if TYPE_CHECKING:
    from rich.console import Console
    from rich.table import Table

try:
    from rich import box
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised in minimal installations
    RICH_AVAILABLE = False


def make_console(*, no_color: bool = False, stderr: bool = False) -> Console | None:
    if not RICH_AVAILABLE:
        return None
    return Console(no_color=no_color, stderr=stderr, highlight=False)


def literal(value: object, *, style: str | None = None) -> Text:
    return Text(str(value), style=style or "", no_wrap=False)


def render_address_table(command: SSHCommand) -> Table | None:
    if not RICH_AVAILABLE:
        return None
    table = Table(box=box.SIMPLE_HEAVY, expand=True, show_header=True)
    table.add_column("Status", width=10, no_wrap=True)
    table.add_column("Address", overflow="fold")
    table.add_column("Type", width=10, no_wrap=True)
    for host in command.available_hosts:
        selected = host == command.selected_host
        table.add_row(
            literal(
                "Selected" if selected else "Available", style="bold green" if selected else "cyan"
            ),
            literal(host, style="bold" if selected else None),
            literal(address_kind(host)),
        )
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
    if console is None:
        print(command_text)
        return
    title = Text("XPipe  →  OpenSSH", style="bold")
    subtitle = literal(command.connection_name or command.selected_host, style="cyan")
    console.print(Panel.fit(Group(title, subtitle), border_style="cyan", padding=(0, 2)))

    details = Table.grid(padding=(0, 2), expand=True)
    details.add_column(style="bold", width=15, no_wrap=True)
    details.add_column(overflow="fold")
    for key, value in (
        ("Connection", command.connection_name or "—"),
        ("XPipe ID", command.connection_id or "—"),
        ("Target", command.selected_host),
        ("Port", command.port),
        ("User", command.username or "SSH default"),
        ("Authentication", ", ".join(command.auth_methods) or "SSH default"),
    ):
        details.add_row(literal(key, style="bold"), literal(value))
    if command.agent:
        count = command.agent.identity_count
        suffix = "identity" if count == 1 else "identities"
        details.add_row(
            literal("SSH agent", style="bold"), literal(f"{command.agent.label} · {count} {suffix}")
        )
        details.add_row(literal("Agent socket", style="bold"), literal(command.agent.path))
    elif command.needs_password_manager_agent:
        details.add_row(literal("SSH agent", style="bold"), literal("Not found"))
    if command.gateway_names:
        details.add_row(
            literal("Gateway", style="bold"), literal(" → ".join(command.gateway_names))
        )
    console.print(Panel(details, title="Connection", border_style="blue"))
    address_table = render_address_table(command)
    if address_table is not None:
        console.print(
            Panel(
                address_table,
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
    console.print(
        Panel(
            Syntax(
                command_text, language, word_wrap=True, background_color="default", padding=(0, 1)
            ),
            title="SSH command",
            subtitle="Copied to clipboard" if copied else "Use --copy or --connect",
            border_style="green",
        )
    )


def render_list(infos: list[WireRecord], *, plain: bool, no_color: bool) -> None:
    ordered = sorted(infos, key=lambda item: display_path(item).casefold())
    if plain or not RICH_AVAILABLE or not sys.stdout.isatty():
        for info in ordered:
            print(f"{display_path(info)}\t{store_id(info)}")
        return
    console = make_console(no_color=no_color)
    if console is None:
        return
    table = Table(title="XPipe SSH connections", box=box.ROUNDED, expand=True, show_lines=False)
    for name, ratio in (("Name", 3), ("Target", 2), ("Port", 0), ("Type", 0), ("XPipe ID", 2)):
        table.add_column(
            name,
            ratio=ratio or None,
            width=None if ratio else (6 if name == "Port" else 14),
            overflow="fold",
        )
    for info in ordered:
        cfg = connection_config(info)
        kind = str(info.get("type") or cfg.get("type") or "")
        target = (
            ssh_config_alias(info, cfg)
            if kind == "sshConfigHost"
            else selected_text(cfg.get("host")) or "—"
        )
        port = "—" if kind == "sshConfigHost" else selected_text(cfg.get("port")) or "22"
        table.add_row(
            *(literal(value) for value in (display_path(info), target, port, kind, store_id(info)))
        )
    console.print(table)


def choose_host_interactively(
    current: str | None, available: list[str], *, no_color: bool
) -> str | None:
    if len(available) <= 1:
        return current
    if not sys.stdin.isatty():
        raise ExportError("--pick-host requires an interactive terminal")
    if RICH_AVAILABLE:
        console = make_console(no_color=no_color)
        if console is None:
            raise ExportError("Interactive presentation is unavailable")
        table = Table(title="Choose target address", box=box.ROUNDED)
        table.add_column("#", justify="right", width=4)
        table.add_column("Address")
        table.add_column("Type")
        table.add_column("Current", width=9)
        for index, host in enumerate(available, 1):
            table.add_row(str(index), host, address_kind(host), "yes" if host == current else "")
        console.print(table)
        default_index = available.index(current) + 1 if current in available else 1
        choice = Prompt.ask(
            "Address number",
            choices=[str(i) for i in range(1, len(available) + 1)],
            default=str(default_index),
            console=console,
        )
        return available[int(choice) - 1]
    for index, host in enumerate(available, 1):
        print(f"{index}. {host}{' (selected)' if host == current else ''}")
    try:
        return available[int(input("Address number: ").strip()) - 1]
    except (ValueError, IndexError) as exc:
        raise ExportError("Invalid address selection") from exc
