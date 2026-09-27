"""CLI composition root and user-facing error policy."""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Never

from . import __version__
from .agents import resolve_agent_socket
from .clipboard import copy_to_clipboard
from .errors import (
    EXIT_OK,
    ExecutionError,
    ExportError,
    InternalError,
    LocalProcessError,
    StrictWarningsError,
    XPipeConnectionError,
    XPipeError,
)
from .models import AgentSocket, SSHCommand
from .presentation import RICH_AVAILABLE, choose_host_interactively, render_dashboard, render_list
from .rendering import SHELL_CHOICES, Shell, render
from .selection import choose_connection, exportable_connections
from .ssh import build_ssh_argv, dedupe
from .xpipe import connection_config, connection_type, selectable_texts


@dataclass(frozen=True)
class CliOptions:
    connection: str | None
    list_mode: bool
    shell: Shell
    ptb: bool
    agent_socket: str
    host: str | None
    pick_host: bool
    connect: bool
    remote_command: str | None
    copy: bool
    plain: bool
    strict: bool
    no_color: bool
    debug: bool


@dataclass
class AppDependencies:
    """Injection points for tests; every default is the real implementation."""

    client_factory: Callable[[bool], object] | None = None
    clipboard: Callable[[str], str] = copy_to_clipboard
    executor: Callable[[list[str], dict[str, str]], None] | None = None
    agent_resolver: Callable[..., AgentSocket | None] = resolve_agent_socket


def error_code(exc: Exception) -> str:
    """Resolve the stable JSON code for a failure, without an ordered ladder."""
    if isinstance(exc, ExportError):
        return exc.code
    if isinstance(exc, OSError):
        return LocalProcessError.code
    return InternalError.code


def print_error(exc: Exception, *, json_mode: bool) -> None:
    if not json_mode:
        print(f"error: {exc}", file=sys.stderr)
        return
    detail: dict[str, object] = {"code": error_code(exc), "message": str(exc)}
    if isinstance(exc, ExportError):
        detail.update(exc.details())
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


SHELL_FLAG = "--shell"


def build_parser() -> CliArgumentParser:
    parser = CliArgumentParser(description="Export an XPipe SSH connection as one OpenSSH command")
    parser.add_argument("connection", nargs="?", help="connection name/path or XPipe UUID")
    parser.add_argument("--list", action="store_true", help="list SSH connections")
    parser.add_argument(
        SHELL_FLAG,
        choices=SHELL_CHOICES,
        default="auto",
        help="output format (default: auto)",
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
    parser.add_argument(
        "--remote-command",
        metavar="COMMAND",
        help="run one explicit command string through the remote shell (requires --connect)",
    )
    parser.add_argument("--copy", action="store_true", help="copy the rendered command")
    parser.add_argument("--plain", action="store_true", help="print only the command")
    parser.add_argument(
        "--strict", action="store_true", help="fail if command generation produces warnings"
    )
    parser.add_argument("--no-color", action="store_true", help="disable terminal colors")
    parser.add_argument(
        "--debug", action="store_true", help="include a traceback for unexpected errors"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def shell_wants_json(tokens: Sequence[str]) -> bool:
    """Detect a machine-output request before argparse reports a bad argument.

    argparse accepts unambiguous abbreviations such as ``--she json``, so an
    exact match on ``--shell`` is not enough: the first argument error must
    still be machine readable.
    """
    for index, token in enumerate(tokens):
        name, _, inline = token.partition("=")
        if not name.startswith("--") or not SHELL_FLAG.startswith(name):
            continue
        value = inline or (tokens[index + 1] if index + 1 < len(tokens) else "")
        if value == "json":
            return True
    return False


def parse_options(argv: Sequence[str] | None = None) -> tuple[CliArgumentParser, CliOptions]:
    parser = build_parser()
    tokens = list(sys.argv[1:] if argv is None else argv)
    parser.json_errors = shell_wants_json(tokens)
    args = parser.parse_args(tokens)
    # The parsed value is authoritative for the validation errors below.
    parser.json_errors = args.shell == "json"
    if args.list and args.connection:
        parser.error("--list cannot be combined with a connection")
    if args.list and any(
        (
            args.connect,
            args.remote_command is not None,
            args.copy,
            args.host,
            args.pick_host,
            args.agent_socket != "auto",
            args.strict,
        )
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
    if args.remote_command is not None:
        if not args.connect:
            parser.error("--remote-command requires --connect")
        if not args.remote_command.strip() or any(
            ord(char) < 32 or ord(char) == 127 for char in args.remote_command
        ):
            parser.error("--remote-command must be non-empty and contain no control characters")
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
        remote_command=args.remote_command,
        copy=args.copy,
        plain=args.plain,
        strict=args.strict,
        no_color=args.no_color,
        debug=args.debug,
    )


def default_client(ptb: bool) -> object:
    try:
        from xpipe_api import AuthFailedException, Client, NoTokenFoundException
    except ImportError as exc:
        raise XPipeError("Missing xpipe-api dependency. Run: uv sync") from exc
    try:
        return Client(ptb=ptb)
    except (NoTokenFoundException, AuthFailedException) as exc:
        # The daemon being down or the API being disabled is the single most
        # common setup failure; report it as such instead of an internal error.
        raise XPipeConnectionError(
            "Could not reach the XPipe daemon; check that XPipe is running, unlocked, "
            f"and that Settings -> HTTP API is enabled: {exc}"
        ) from exc


def _execvpe(argv: list[str], env: dict[str, str]) -> None:
    """Replace this process with ssh, resolving it from the command's own PATH.

    execvpe already looks up env["PATH"], and a failing lookup is a plain
    FileNotFoundError, so there is no separate which() pass to keep in sync.
    """
    try:
        sys.stdout.flush()
        sys.stderr.flush()
        os.execvpe(argv[0], argv, env)
    except OSError as exc:
        raise ExecutionError(f"Could not run {argv[0]!r} from PATH: {exc}") from exc


def prepare_command(client: object, options: CliOptions, deps: AppDependencies) -> SSHCommand:
    if options.connection is None:
        raise ExportError("a connection is required")
    info = choose_connection(client, options.connection)
    cfg = connection_config(info)
    selected_host, available_hosts = selectable_texts(cfg.get("host"))
    if connection_type(info) == "sshConfigHost":
        # An ssh config entry owns its own address resolution, so there is
        # nothing for --host or --pick-host to override.
        if options.host:
            raise ExportError("--host cannot be used with an SSH config host")
        if options.pick_host:
            raise ExportError("--pick-host cannot be used with an SSH config host")
    host_override = options.host
    if options.pick_host:
        host_override = choose_host_interactively(
            selected_host, available_hosts, no_color=options.no_color
        )
    command = build_ssh_argv(client, info, host_override=host_override)
    if command.needs_password_manager_agent:
        agent = deps.agent_resolver(
            options.agent_socket,
            provider=command.agent_provider,
            identifier=command.agent_identifier,
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
    command.warnings = dedupe(command.warnings)
    return command


def run(options: CliOptions, deps: AppDependencies) -> int:
    client = (deps.client_factory or default_client)(options.ptb)
    if options.list_mode:
        infos = exportable_connections(client)
        render_list(
            infos, plain=options.plain, no_color=options.no_color, json_mode=options.shell == "json"
        )
        return 0
    command = prepare_command(client, options, deps)
    if options.strict and command.warnings:
        raise StrictWarningsError(command.warnings)
    if options.remote_command is not None:
        # OpenSSH sends this as a remote shell command, not a preserved argv vector.
        command.argv.append(options.remote_command)
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
        return int(exc.code or EXIT_OK)
    try:
        return run(options, deps or AppDependencies())
    except ExportError as exc:
        print_error(exc, json_mode=options.shell == "json")
        return exc.exit_code
    except OSError as exc:
        print_error(exc, json_mode=options.shell == "json")
        return LocalProcessError.exit_code
    except KeyboardInterrupt:
        # Ctrl-C at the interactive host menu is a normal user abort, not a defect.
        print("aborted", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - a final safety net for integration defects
        print_error(exc, json_mode=options.shell == "json")
        if options.debug:
            traceback.print_exc(file=sys.stderr)
        return InternalError.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
