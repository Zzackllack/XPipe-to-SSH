"""CLI composition root and user-facing error policy."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Never, cast

from . import __version__
from .agents import resolve_agent_socket
from .clipboard import copy_to_clipboard
from .errors import (
    AgentError,
    AmbiguousConnectionError,
    ClipboardError,
    ConnectionNotFoundError,
    ExecutionError,
    ExportError,
    SelectionError,
    XPipeConnectionError,
    XPipeError,
    XPipeSchemaError,
)
from .models import AgentSocket, SSHCommand
from .presentation import RICH_AVAILABLE, choose_host_interactively, render_dashboard, render_list
from .rendering import render
from .selection import choose_connection, exportable
from .ssh import build_ssh_argv
from .xpipe import connection_config, query_all, selectable_texts


@dataclass(frozen=True)
class CliOptions:
    connection: str | None
    list_mode: bool
    shell: str
    ptb: bool
    agent_socket: str
    host: str | None
    pick_host: bool
    connect: bool
    copy: bool
    plain: bool
    no_color: bool
    debug: bool


@dataclass
class AppDependencies:
    client_factory: Callable[[bool], object] | None = None
    clipboard: Callable[[str], str] = copy_to_clipboard
    executor: Callable[[list[str], dict[str, str]], None] | None = None
    agent_resolver: Callable[..., object] = resolve_agent_socket


def print_error(exc: Exception, *, json_mode: bool) -> None:
    if not json_mode:
        print(f"error: {exc}", file=sys.stderr)
        return
    if isinstance(exc, ConnectionNotFoundError):
        code = "connection_not_found"
    elif isinstance(exc, AmbiguousConnectionError):
        code = "ambiguous_connection"
    elif isinstance(exc, XPipeConnectionError):
        code = "xpipe_request_failed"
    elif isinstance(exc, XPipeSchemaError):
        code = "xpipe_schema_error"
    elif isinstance(exc, AgentError):
        code = "agent_unavailable"
    elif isinstance(exc, ClipboardError):
        code = "clipboard_failed"
    elif isinstance(exc, ExecutionError):
        code = "execution_failed"
    elif isinstance(exc, SelectionError):
        code = "selection_failed"
    elif isinstance(exc, ExportError):
        code = "invalid_export_data"
    elif isinstance(exc, OSError):
        code = "local_process_failed"
    else:
        code = "internal_error"
    detail: dict[str, object] = {"code": code, "message": str(exc)}
    if isinstance(exc, AmbiguousConnectionError):
        detail["candidates"] = exc.candidates
    print(json.dumps({"schemaVersion": 1, "error": detail}))


class CliArgumentParser(argparse.ArgumentParser):
    json_errors = False

    def error(self, message: str) -> Never:
        if self.json_errors:
            print(
                json.dumps(
                    {"schemaVersion": 1, "error": {"code": "invalid_arguments", "message": message}}
                )
            )
            raise SystemExit(2)
        super().error(message)


def build_parser() -> CliArgumentParser:
    parser = CliArgumentParser(description="Export an XPipe SSH connection as one OpenSSH command")
    parser.add_argument("connection", nargs="?", help="connection name/path or XPipe UUID")
    parser.add_argument("--list", action="store_true", help="list SSH connections")
    parser.add_argument(
        "--shell",
        choices=("auto", "posix", "powershell", "json"),
        default="auto",
        help="command quoting format (default: auto)",
    )
    parser.add_argument("--ptb", action="store_true", help="connect to an XPipe PTB build")
    parser.add_argument(
        "--agent-socket", default="auto", metavar="PATH", help="SSH agent socket, or 'none'"
    )
    parser.add_argument("--host", metavar="ADDRESS", help="override XPipe's selected host")
    parser.add_argument(
        "--pick-host", action="store_true", help="interactively choose an available target"
    )
    parser.add_argument("--connect", action="store_true", help="run SSH directly")
    parser.add_argument("--copy", action="store_true", help="copy the rendered command")
    parser.add_argument("--plain", action="store_true", help="print only the command")
    parser.add_argument("--no-color", action="store_true", help="disable terminal colors")
    parser.add_argument(
        "--debug", action="store_true", help="include a traceback for unexpected errors"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def parse_options(argv: Sequence[str] | None = None) -> tuple[CliArgumentParser, CliOptions]:
    parser = build_parser()
    tokens = list(sys.argv[1:] if argv is None else argv)
    parser.json_errors = any(
        token == "--shell=json"
        or (token == "--shell" and index + 1 < len(tokens) and tokens[index + 1] == "json")
        for index, token in enumerate(tokens)
    )
    args = parser.parse_args(tokens)
    if args.list and args.connection:
        parser.error("--list cannot be combined with a connection")
    if args.list and any(
        (args.connect, args.copy, args.host, args.pick_host, args.agent_socket != "auto")
    ):
        parser.error("--list cannot be combined with connection-only options")
    if args.host and args.pick_host:
        parser.error("--host and --pick-host are mutually exclusive")
    if args.connect and args.list:
        parser.error("--connect requires a connection")
    if args.connect and args.shell == "json":
        parser.error("--connect cannot be combined with --shell json")
    if args.connect and args.plain:
        parser.error("--connect cannot be combined with --plain")
    if not args.list and not args.connection:
        parser.error("provide a connection name/UUID, or use --list")
    return parser, CliOptions(
        connection=args.connection,
        list_mode=args.list,
        shell=args.shell,
        ptb=args.ptb,
        agent_socket=args.agent_socket,
        host=args.host,
        pick_host=args.pick_host,
        connect=args.connect,
        copy=args.copy,
        plain=args.plain,
        no_color=args.no_color,
        debug=args.debug,
    )


def default_client(ptb: bool) -> object:
    try:
        from xpipe_api import Client
    except ImportError as exc:
        raise XPipeError("Missing xpipe-api dependency. Run: uv sync") from exc
    return Client(ptb=ptb)


def _execvpe(argv: list[str], env: dict[str, str]) -> None:
    executable = shutil.which(argv[0], path=env.get("PATH"))
    if not executable:
        raise ExecutionError(f"SSH executable {argv[0]!r} was not found on PATH")
    os.execvpe(executable, argv, env)


def prepare_command(client: object, options: CliOptions, deps: AppDependencies) -> SSHCommand:
    if options.connection is None:
        raise ExportError("a connection is required")
    info = choose_connection(client, options.connection)
    cfg = connection_config(info)
    selected_host, available_hosts = selectable_texts(cfg.get("host"))
    if options.host and (str(info.get("type") or cfg.get("type")) == "sshConfigHost"):
        raise ExportError("--host cannot be used with an SSH config host")
    if options.pick_host and (str(info.get("type") or cfg.get("type")) == "sshConfigHost"):
        raise ExportError("--pick-host cannot be used with an SSH config host")
    host_override = options.host
    if options.pick_host:
        host_override = choose_host_interactively(
            selected_host, available_hosts, no_color=options.no_color
        )
    command = build_ssh_argv(client, info, host_override=host_override)
    if command.needs_password_manager_agent:
        agent = cast(
            AgentSocket | None,
            deps.agent_resolver(
                options.agent_socket,
                provider=command.agent_provider,
                identifier=command.agent_identifier,
            ),
        )
        if agent:
            command.agent = agent
            command.env["SSH_AUTH_SOCK"] = agent.path
            if agent.identity_count == 0:
                detail = f" ({agent.probe_error})" if agent.probe_error else ""
                command.warnings.append(
                    f"{agent.label} socket was found, but ssh-add reported no identities{detail}."
                )
        else:
            command.warnings.append(
                "This connection uses a password-manager SSH agent, but no matching usable agent socket was found. Pass --agent-socket PATH."
            )
    command.warnings = list(dict.fromkeys(command.warnings))
    return command


def run(options: CliOptions, deps: AppDependencies) -> int:
    client = (deps.client_factory or default_client)(options.ptb)
    if options.list_mode:
        infos = [info for info in query_all(client) if exportable(info)]
        render_list(
            infos, plain=options.plain, no_color=options.no_color, json_mode=options.shell == "json"
        )
        return 0
    command = prepare_command(client, options, deps)
    command_text = render(command, options.shell)
    copied = False
    if options.copy:
        deps.clipboard(command_text)
        copied = True
    pretty = (
        not options.plain and options.shell != "json" and RICH_AVAILABLE and sys.stdout.isatty()
    )
    if options.connect:
        if pretty:
            render_dashboard(
                command, command_text, no_color=options.no_color, copied=copied, stderr=True
            )
        else:
            for warning in command.warnings:
                print(f"warning: {warning}", file=sys.stderr)
        env = {**os.environ, **command.env}
        (deps.executor or _execvpe)(command.argv, env)
        return 0
    if pretty:
        render_dashboard(command, command_text, no_color=options.no_color, copied=copied)
    else:
        for warning in command.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        print(command_text)
    return 0


def main(argv: Sequence[str] | None = None, deps: AppDependencies | None = None) -> int:
    try:
        _parser, options = parse_options(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    try:
        return run(options, deps or AppDependencies())
    except (XPipeError, AgentError, ClipboardError, ExecutionError, ExportError) as exc:
        print_error(exc, json_mode=options.shell == "json")
        return 1 if isinstance(exc, (XPipeError, AgentError, ClipboardError, ExecutionError)) else 2
    except OSError as exc:
        print_error(exc, json_mode=options.shell == "json")
        return 1
    except Exception as exc:  # pragma: no cover - a final safety net for integration defects
        print_error(exc, json_mode=options.shell == "json")
        if options.debug:
            traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
