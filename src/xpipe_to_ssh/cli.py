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
from pathlib import Path
from subprocess import Popen
from typing import Never, cast

from . import __version__
from .agents import attach_agent, resolve_agent_socket
from .clipboard import copy_to_clipboard
from .config import load_settings
from .daemon import ensure_client
from .errors import (
    EXIT_OK,
    ConfigError,
    ExecutionError,
    ExportError,
    InternalError,
    LocalProcessError,
    StrictWarningsError,
    XPipeConnectionError,
    XPipeError,
)
from .export import (
    EXPORT_CHOICES,
    STDOUT_TARGET,
    ExportFormat,
    ExportResult,
    collect_export,
    render_export,
    write_document,
)
from .models import AgentSocket, SSHCommand
from .presentation import (
    RICH_AVAILABLE,
    choose_host_interactively,
    chrome_console,
    confirm_open,
    render_dashboard,
    render_error,
    render_export_summary,
    render_list,
    render_note,
    render_provenance,
)
from .rendering import SHELL_CHOICES, Shell, render
from .selection import choose_connection, exportable_connections, store_filter
from .ssh import build_ssh_argv, dedupe
from .xpipe import (
    TIMEOUT_ENV,
    connection_config,
    connection_type,
    selectable_texts,
    set_request_timeout,
)

_HELP_FORMATTER: type[argparse.HelpFormatter] = argparse.HelpFormatter
if RICH_AVAILABLE:
    # rich-argparse imports Rich lazily, so importing the formatter alone
    # can succeed even when using it to render help would fail.
    try:
        from rich_argparse import RichHelpFormatter
    except ImportError:
        pass
    else:

        class _HelpFormatter(RichHelpFormatter):
            # Bracket-heavy help texts must not be parsed as console markup.
            help_markup = False
            text_markup = False

        _HELP_FORMATTER = _HelpFormatter


@dataclass(frozen=True)
class CliOptions:
    connection: str | None
    list_mode: bool
    list_filter: str | None
    export: ExportFormat | None
    output: str | None
    force: bool
    shell: Shell
    ptb: bool
    agent_socket: str
    host: str | None
    pick_host: bool
    pick_hosts: bool
    connect: bool
    remote_command: str | None
    ssh_args: list[str]
    copy: bool
    plain: bool
    explain: bool
    api_timeout: float | None
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
    # Launches XPipe (defaults to `xpipe open`); injectable so tests never spawn it.
    opener: Callable[[], Popen[bytes] | None] | None = None


def error_code(exc: Exception) -> str:
    """Resolve the stable JSON code for a failure, without an ordered ladder."""
    if isinstance(exc, ExportError):
        return exc.code
    if isinstance(exc, OSError):
        return LocalProcessError.code
    return InternalError.code


def print_error(exc: Exception, *, json_mode: bool, no_color: bool = False) -> None:
    if not json_mode:
        if render_error(str(exc), no_color=no_color):
            return
        print(f"error: {exc}", file=sys.stderr)
        return
    detail: dict[str, object] = {"code": error_code(exc), "message": str(exc)}
    if isinstance(exc, ExportError):
        detail.update(exc.details())
    print(json.dumps({"schemaVersion": 1, "error": detail}))


class CliArgumentParser(argparse.ArgumentParser):
    json_errors = False

    # argparse binds self.formatter_class from its __init__ parameter, so a
    # class attribute would be shadowed everywhere it matters.
    def __init__(self, *args, **kwargs) -> None:  # argparse itself is dynamically typed
        kwargs.setdefault("formatter_class", _HELP_FORMATTER)
        super().__init__(*args, **kwargs)

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
SHELL_ENV = "XPIPE_TO_SSH_SHELL"
AGENT_SOCKET_ENV = "XPIPE_TO_SSH_AGENT_SOCKET"
DEFAULT_SHELL: Shell = "auto"
DEFAULT_AGENT_SOCKET = "auto"


def resolve_settings(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> argparse.Namespace:
    """Fill unset options from the environment and the optional config file.

    Precedence is command line, then environment, then config file, then the
    built-in default, so an explicit flag is never silently overridden.
    """
    settings = load_settings()
    args.shell = args.shell or os.environ.get(SHELL_ENV) or settings.shell or DEFAULT_SHELL
    if args.shell not in SHELL_CHOICES:
        parser.error(f"{SHELL_ENV} must be one of: {', '.join(SHELL_CHOICES)}")
    args.agent_socket = (
        args.agent_socket
        or os.environ.get(AGENT_SOCKET_ENV)
        or settings.agent_socket
        or DEFAULT_AGENT_SOCKET
    )
    if args.ptb is None:
        args.ptb = settings.ptb or False
    # The deadline has no flag. The environment wins over the file, and a bad
    # value is reported rather than silently falling back to the default.
    raw_timeout = os.environ.get(TIMEOUT_ENV)
    if raw_timeout is not None:
        args.api_timeout = parse_timeout(raw_timeout, TIMEOUT_ENV, parser)
    else:
        args.api_timeout = settings.api_timeout
    if args.api_timeout is not None:
        set_request_timeout(args.api_timeout)
    return args


def parse_timeout(value: str, origin: str, parser: argparse.ArgumentParser) -> float:
    try:
        seconds = float(value)
    except ValueError:
        parser.error(f"{origin} must be a number of seconds, got {value!r}")
    if not 0 < seconds <= 300:
        parser.error(f"{origin} must be greater than 0 and at most 300 seconds")
    return seconds


def build_parser() -> CliArgumentParser:
    parser = CliArgumentParser(
        description="Export an XPipe SSH connection as one OpenSSH command, or all of them as a config file"
    )
    parser.add_argument("connection", nargs="?", help="connection name/path or XPipe UUID")
    parser.add_argument(
        "ssh_args",
        nargs="*",
        help="extra ssh arguments after --, inserted before the destination",
    )
    parser.add_argument("--list", action="store_true", help="list SSH connections")
    parser.add_argument(
        "--filter",
        metavar="PATTERN",
        help="only list or export connections matching a name or glob (requires --list or --export)",
    )
    parser.add_argument(
        "--export",
        choices=EXPORT_CHOICES,
        default=None,
        metavar="FORMAT",
        help="export every connection as FORMAT (" + ", ".join(EXPORT_CHOICES) + ")",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        default=None,
        help="write --export output to PATH instead of stdout ('-' means stdout)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing --output file",
    )
    parser.add_argument(
        SHELL_FLAG,
        choices=SHELL_CHOICES,
        default=None,
        help=f"output format (default: {DEFAULT_SHELL})",
    )
    parser.add_argument(
        "--ptb", action="store_true", default=None, help="connect to an XPipe PTB build"
    )
    parser.add_argument(
        "--agent-socket", default=None, metavar="PATH", help="SSH agent socket, or 'none'"
    )
    parser.add_argument("--host", metavar="ADDRESS", help="override XPipe's selected host")
    parser.add_argument(
        "--pick-host", action="store_true", help="interactively choose an available target"
    )
    parser.add_argument(
        "--pick-hosts",
        action="store_true",
        help="with --export, ask which available target to use for each connection",
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
        "--explain",
        action="store_true",
        help="also show which XPipe field produced each argument",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail if command generation or export produces warnings",
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
    # The --list guard has to know what was typed, not what was resolved: a
    # configured agent socket is a standing default, not a request to connect.
    explicit_agent_socket = args.agent_socket
    # The resolved value is authoritative for the validation errors below.
    try:
        args = resolve_settings(args, parser)
    except ConfigError as exc:
        # The file couldn't supply a default, but the flag and environment still can.
        shell = args.shell or os.environ.get(SHELL_ENV)
        print_error(exc, json_mode=shell == "json", no_color=args.no_color)
        raise SystemExit(exc.exit_code) from exc
    parser.json_errors = args.shell == "json"
    if args.list and args.connection:
        parser.error("--list cannot be combined with a connection")
    if args.list and args.export:
        parser.error("--list and --export are mutually exclusive")
    if args.filter and not (args.list or args.export):
        parser.error("--filter requires --list or --export")
    if args.filter and any(char.isspace() for char in args.filter):
        parser.error("--filter cannot contain whitespace")
    if args.output and not args.export:
        parser.error("--output requires --export")
    if args.force and not (args.export and args.output):
        parser.error("--force requires --export and --output")
    if args.list and any(
        (
            args.connect,
            args.remote_command is not None,
            args.copy,
            args.host,
            args.pick_host,
            explicit_agent_socket is not None,
            args.strict,
        )
    ):
        parser.error("--list cannot be combined with connection-only options")
    if args.export and any(
        (
            args.connection,
            args.connect,
            args.remote_command is not None,
            args.copy,
            args.host,
            args.pick_host,
            args.plain,
            args.explain,
            args.ssh_args,
        )
    ):
        parser.error("--export cannot be combined with connection-only options")
    if args.pick_hosts and not args.export:
        parser.error("--pick-hosts requires --export")
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
    if args.ssh_args:
        if args.list or args.export:
            parser.error("-- cannot be combined with --list or --export")
        if args.remote_command is not None:
            parser.error("-- cannot be combined with --remote-command")
        if tokens[:1] == ["--"]:
            # argparse would bind the first argument after -- to the
            # connection and silently treat an ssh flag as a connection name.
            parser.error("-- requires a connection before it")
        if not args.connection:
            parser.error("-- requires a connection")
        for value in args.ssh_args:
            if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
                parser.error("arguments after -- must be non-empty and free of control characters")
    if not args.list and not args.export and not args.connection:
        parser.error("provide a connection name/UUID, use --list, or use --export")
    return parser, CliOptions(
        connection=args.connection,
        list_mode=args.list,
        list_filter=args.filter,
        export=cast(ExportFormat, args.export) if args.export else None,
        output=args.output,
        force=args.force,
        shell=args.shell,
        ptb=args.ptb,
        agent_socket=args.agent_socket,
        host=args.host,
        pick_host=args.pick_host,
        pick_hosts=args.pick_hosts,
        connect=args.connect,
        remote_command=args.remote_command,
        ssh_args=list(args.ssh_args),
        copy=args.copy,
        plain=args.plain,
        explain=args.explain,
        api_timeout=args.api_timeout,
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


def may_offer_open(options: CliOptions) -> bool:
    """Decide whether prompting to launch XPipe makes sense for this run.

    JSON output must stay machine readable, and a plain ``xpipe open`` starts
    the release build, so PTB builds and custom beacon ports must not be
    offered it either; those users start their build manually.
    """
    if options.shell == "json":
        return False
    if options.ptb or os.environ.get("XPIPE_BEACON_PORT"):
        return False
    if not sys.stdin.isatty():
        return False
    # The prompt goes to stderr; if stderr is a pipe, it lands in a log file.
    if not sys.stderr.isatty():
        return False
    # Never offer a launch we cannot perform.
    return shutil.which("xpipe") is not None


def connected_client(options: CliOptions, deps: AppDependencies) -> object:
    if deps.client_factory is not None:
        # Injected factories are trusted: no probe, no prompt, by design.
        return deps.client_factory(options.ptb)
    if may_offer_open(options):

        def confirm() -> bool:
            return confirm_open(no_color=options.no_color)
    else:
        confirm = None
    return ensure_client(
        ptb=options.ptb,
        client_maker=default_client,
        confirm=confirm,
        opener=deps.opener,
        no_color=options.no_color,
    )


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
    command = build_ssh_argv(client, info, host_override=host_override, extra_argv=options.ssh_args)
    attach_agent(command, options.agent_socket, deps.agent_resolver)
    command.warnings = dedupe(command.warnings)
    return command


def run_export(
    client: object, options: CliOptions, fmt: ExportFormat, deps: AppDependencies
) -> int:
    """Export every matching connection as one document or file."""
    infos = exportable_connections(client, name_pattern=store_filter(options.list_filter or ""))
    picker = None
    if options.pick_hosts:

        def picker(current: str | None, available: list[str]) -> str | None:
            return choose_host_interactively(
                current, available, no_color=options.no_color, flag_name="--pick-hosts"
            )

    stderr_rich = (
        chrome_console(no_color=options.no_color, stderr=True) if options.shell != "json" else None
    )

    def collect() -> ExportResult:
        return collect_export(
            client,
            infos,
            agent_resolver=deps.agent_resolver,
            agent_socket=options.agent_socket,
            host_picker=picker,
        )

    if stderr_rich is not None and not options.pick_hosts:
        # The user is away while the daemon is probed; menus would clash with
        # a live spinner, so interactive runs get no spinner.
        with stderr_rich.status("Exporting connections…", spinner="dots"):
            result = collect()
    else:
        result = collect()
    if options.strict and result.warnings:
        raise StrictWarningsError(result.warnings)
    if stderr_rich is not None:
        render_export_summary(result, fmt, no_color=options.no_color)
    else:
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)
    document = render_export(result, fmt)
    if options.output and options.output != STDOUT_TARGET:
        target = Path(options.output)
        write_document(document, target, force=options.force)
        if stderr_rich is not None:
            render_note(
                f"✓ wrote {target} ({len(result.hosts)} connection(s))",
                style="bold green",
                no_color=options.no_color,
            )
        else:
            print(f"wrote {target} ({len(result.hosts)} connection(s))", file=sys.stderr)
    else:
        sys.stdout.write(document)
    return 0


def run(options: CliOptions, deps: AppDependencies) -> int:
    client = connected_client(options, deps)
    if options.list_mode:
        infos = exportable_connections(client, name_pattern=store_filter(options.list_filter or ""))
        render_list(
            infos, plain=options.plain, no_color=options.no_color, json_mode=options.shell == "json"
        )
        return 0
    if options.export:
        return run_export(client, options, options.export, deps)
    command = prepare_command(client, options, deps)
    if options.strict and command.warnings:
        raise StrictWarningsError(command.warnings)
    if options.remote_command is not None:
        # OpenSSH sends this as a remote shell command, not a preserved argv vector.
        command.argv.append(options.remote_command)
    command_text = render(command, options.shell, explain=options.explain)
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
        if options.explain:
            # The session replaces this process, so explain before exec, never after.
            render_provenance(command, plain=not pretty, no_color=options.no_color)
        env = {**os.environ, **command.env}
        (deps.executor or _execvpe)(command.argv, env)
        return 0
    if pretty:
        render_dashboard(command, command_text, no_color=options.no_color, copied=copied)
    else:
        for warning in command.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        print(command_text)
    if options.explain and options.shell != "json":
        # JSON carries provenance inside the payload instead.
        render_provenance(command, plain=options.plain, no_color=options.no_color)
    return 0


def main(argv: Sequence[str] | None = None, deps: AppDependencies | None = None) -> int:
    try:
        _parser, options = parse_options(argv)
    except SystemExit as exc:
        return int(exc.code or EXIT_OK)
    try:
        return run(options, deps or AppDependencies())
    except ExportError as exc:
        print_error(exc, json_mode=options.shell == "json", no_color=options.no_color)
        return exc.exit_code
    except OSError as exc:
        print_error(exc, json_mode=options.shell == "json", no_color=options.no_color)
        return LocalProcessError.exit_code
    except KeyboardInterrupt:
        # Ctrl-C at the interactive host menu is a normal user abort, not a defect.
        print("aborted", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - a final safety net for integration defects
        print_error(exc, json_mode=options.shell == "json", no_color=options.no_color)
        if options.debug:
            traceback.print_exc(file=sys.stderr)
        return InternalError.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
