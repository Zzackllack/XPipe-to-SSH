"""Pure-ish conversion from normalized XPipe records to SSH arguments."""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from collections.abc import Iterable, Sequence

from .agents import provider_hint
from .errors import ExportError
from .models import GatewayPlan, IdentityResult, SSHCommand
from .selection import decode_identity_data, resolve_identity
from .xpipe import (
    WireRecord,
    connection_config,
    connection_type,
    display_path,
    info_one,
    selectable_texts,
    selected_text,
    store_id,
)

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
OPTION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
COMMAND_OPTIONS = {"proxycommand", "localcommand", "match", "include"}

#: A port is 1-65535, so five significant digits is the most that can be valid.
MAX_PORT_DIGITS = 5
MAX_ECHOED_INPUT = 40


def brief(value: str, limit: int = MAX_ECHOED_INPUT) -> str:
    """Shorten untrusted input before it reaches an error message or JSON.

    XPipe fields are echoed back in errors, and a malformed field can be
    megabytes long; the message should stay readable and the JSON bounded.
    """
    text = repr(value)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... ({len(value)} chars)"


def validate_destination(value: str, *, field: str = "SSH host") -> str:
    value = value.strip()
    if not value:
        raise ExportError(f"{field} must not be empty")
    if CONTROL_RE.search(value) or any(char.isspace() for char in value):
        raise ExportError(f"{field} contains whitespace or control characters")
    if value.startswith("-"):
        raise ExportError(f"{field} must not start with '-'")
    if value.startswith("[") or value.endswith("]"):
        if not (value.startswith("[") and value.endswith("]")):
            raise ExportError(f"Invalid bracketed {field.lower()}: {brief(value)}")
        inner = value[1:-1]
        try:
            ipaddress.ip_address(inner)
        except ValueError as exc:
            raise ExportError(f"Invalid bracketed {field.lower()}: {brief(value)}") from exc
        return inner
    return value


def parse_port(value: object, *, default: int = 22) -> int:
    """Read an XPipe port, treating an absent or null value as the SSH default.

    XPipe serializes an unset port as an explicit null rather than dropping the
    key, so a missing value must not be reported as malformed data. An empty or
    non-numeric string stays an error: that is bad data, not an absent default.
    """
    if value is None:
        return default
    text = selected_text(value)
    if text is None or not re.fullmatch(r"[0-9]+", text):
        raise ExportError(
            f"Invalid SSH port {brief(text or '')}; expected an integer from 1 to 65535"
        )
    # Reject on digit count before calling int(): a malformed field of thousands
    # of digits would otherwise raise the interpreter's integer-conversion
    # ValueError instead of an ExportError.
    digits = text.lstrip("0") or "0"
    if len(digits) > MAX_PORT_DIGITS:
        raise ExportError(f"Invalid SSH port {brief(text)}; expected an integer from 1 to 65535")
    port = int(digits)
    if not 1 <= port <= 65535:
        raise ExportError(f"Invalid SSH port {port}; expected an integer from 1 to 65535")
    return port


def usable_destinations(values: Iterable[str], warnings: list[str]) -> list[str]:
    """Validate advertised addresses, reporting the unusable ones as warnings."""
    result: list[str] = []
    for value in values:
        try:
            normalized = validate_destination(value)
        except ExportError:
            warnings.append(f"Ignored an unusable XPipe target address: {brief(value)}.")
            continue
        if normalized not in result:
            result.append(normalized)
    return result


def parse_bool(value: object, *, field: str) -> bool:
    if value is None:
        return False
    value = selected_text(value) if not isinstance(value, bool) else value
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.casefold() in {"true", "false"}:
        return value.casefold() == "true"
    raise ExportError(f"Invalid {field}; expected true or false")


def identity_options(client: object, cfg: dict[str, object]) -> IdentityResult:
    result = IdentityResult()
    store = resolve_identity(client, cfg.get("identity"), result.warnings)
    if not store:
        result.auth_methods.append("SSH defaults / config")
        return result

    username = selected_text(store.get("username"))
    if username:
        if CONTROL_RE.search(username) or any(char.isspace() for char in username):
            raise ExportError("SSH username contains whitespace or control characters")
        result.username = username
        result.argv += ["-l", username]
        result.arg_sources += ["XPipe identity username", "XPipe identity username"]

    key_data = decode_identity_data(client, store.get("sshIdentity"), result.warnings)
    offers_key_material = False
    if isinstance(key_data, dict):
        key_type = selected_text(key_data.get("type"))
        key_file = selected_text(key_data.get("file"))
        normalized = key_type.casefold() if key_type else ""
        if normalized == "file" and key_file:
            if CONTROL_RE.search(key_file):
                raise ExportError("SSH key-file path contains control characters")
            expanded = os.path.expanduser(key_file)
            result.argv += ["-i", expanded]
            result.arg_sources += ["XPipe identity key file", "XPipe identity key file"]
            result.auth_methods.append(f"Key file: {expanded}")
            offers_key_material = True
        elif normalized == "passwordmanageragent":
            result.needs_password_manager_agent = True
            result.agent_provider = selected_text(key_data.get("provider"))
            result.agent_identifier = selected_text(key_data.get("identifier"))
            result.auth_methods.append("Password-manager SSH agent")
            offers_key_material = True
        elif normalized in {"", "none"}:
            pass
        elif normalized == "agent":
            result.auth_methods.append("SSH agent")
            offers_key_material = True
        else:
            result.auth_methods.append(f"XPipe key type: {key_type}")
            result.warnings.append(
                f"SSH key type {key_type!r} may depend on XPipe or local SSH configuration."
            )

    if store.get("password"):
        result.auth_methods.append("Password fallback")
        # Without key material the password is the only method, so SSH will
        # always prompt for it; saying "if the key is rejected" would be wrong.
        result.warnings.append(
            "XPipe-managed password was not exported; SSH may prompt for it if the key is rejected."
            if offers_key_material
            else "XPipe-managed password was not exported; SSH will prompt for the password."
        )
    if not result.auth_methods:
        result.auth_methods.append("SSH defaults / config")
    return result


def parse_additional_options(raw: object) -> tuple[list[str], list[str]]:
    if not raw:
        return [], []
    if isinstance(raw, str):
        lines = raw.splitlines()
    elif isinstance(raw, list):
        lines = [str(item) for item in raw]
    elif isinstance(raw, dict):
        lines = [f"{key}={value}" for key, value in raw.items()]
    else:
        raise ExportError("SSH additionalOptions must be text, a list, or an object")

    result: list[str] = []
    warnings: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if CONTROL_RE.search(line):
            raise ExportError("SSH additional option contains control characters")
        key = line.split("=", 1)[0].split(None, 1)[0]
        if not OPTION_RE.fullmatch(key):
            raise ExportError(f"Invalid SSH additional option: {brief(line)}")
        if "=" not in line and not re.search(r"\s", line):
            raise ExportError(f"SSH additional option needs a value: {brief(line)}")
        result += ["-o", line]
        if key.casefold() in COMMAND_OPTIONS:
            warnings.append(
                f"SSH option {key} can execute local commands; inspect the generated command before use."
            )
    return result, warnings


def ssh_config_alias(info: WireRecord, cfg: dict[str, object]) -> str:
    for key in ("alias", "host", "hostName", "name"):
        value = selected_text(cfg.get(key))
        if value:
            return validate_destination(value, field="SSH config alias")
    host_entry = cfg.get("hostEntry")
    if isinstance(host_entry, dict):
        for key in ("name", "alias", "host", "hostName"):
            value = selected_text(host_entry.get(key))
            if value:
                return validate_destination(value, field="SSH config alias")
    path = display_path(info)
    if path:
        return validate_destination(path.split("/")[-1], field="SSH config alias")
    raise ExportError("Could not determine the SSH config alias")


#: Provenance labels for --explain, naming where each argv entry came from.
SSH_EXECUTABLE = "the ssh executable"
GATEWAY_FORWARDING = "gateway hop forwarding (generated)"
XPIPE_HOST = "XPipe selected host"


def build_ssh_argv(
    client: object,
    info: WireRecord,
    *,
    proxy_mode: bool = False,
    visited: set[str] | None = None,
    host_override: str | None = None,
    host_source: str = XPIPE_HOST,
    extra_argv: Sequence[str] = (),
    depth: int = 0,
    max_gateway_depth: int = 8,
    platform_name: str | None = None,
) -> SSHCommand:
    if depth > max_gateway_depth:
        raise ExportError(f"Gateway chain exceeds the maximum depth of {max_gateway_depth}")
    visited = set() if visited is None else set(visited)
    ref = store_id(info)
    if not ref:
        raise ExportError(f"{display_path(info)!r} has no valid XPipe store ID")
    if ref in visited:
        raise ExportError("Gateway cycle detected in XPipe configuration")
    visited.add(ref)

    cfg = connection_config(info)
    kind = connection_type(info)
    name = display_path(info)
    if kind == "sshConfigHost":
        return ssh_config_command(info, cfg, name=name, ref=ref, proxy_mode=proxy_mode)
    if kind != "ssh":
        raise ExportError(f"{name!r} is type {kind!r}, not an exportable SSH connection")

    warnings: list[str] = []
    host, available_hosts = resolve_hosts(cfg, host_override, warnings)
    port = parse_port(cfg.get("port"))
    identity = identity_options(client, cfg)
    warnings.extend(identity.warnings)

    argv = ["ssh"]
    sources = [SSH_EXECUTABLE]
    if port != 22:
        argv += ["-p", str(port)]
        sources += ["XPipe port", "XPipe port"]
    argv += identity.argv
    sources += identity.arg_sources
    if parse_bool(cfg.get("forwardX11"), field="forwardX11"):
        argv.append("-X")
        sources.append("XPipe forwardX11")
    extra, extra_warnings = parse_additional_options(cfg.get("additionalOptions"))
    argv += extra
    sources += ["XPipe additionalOptions"] * len(extra)
    warnings.extend(extra_warnings)

    gateway = plan_gateway(
        client,
        cfg,
        identity,
        visited=visited,
        depth=depth,
        max_gateway_depth=max_gateway_depth,
        platform_name=platform_name,
        warnings=warnings,
    )
    argv += gateway.argv
    sources += gateway.sources
    if proxy_mode:
        argv += ["-W", "%h:%p"]
        sources += [GATEWAY_FORWARDING, GATEWAY_FORWARDING]
    if extra_argv:
        # Not validated against the ssh option grammar: ssh itself is the
        # authority on which flags take a value, and a wrong guess here would
        # silently drop an argument.
        argv += list(extra_argv)
        sources += ["arguments after --"] * len(extra_argv)
        warnings.append(
            "Extra ssh arguments were inserted before the destination and were not "
            "validated: review them, since ssh executes what they enable."
        )
    argv.append(host)
    sources.append(host_source)
    return SSHCommand(
        argv=argv,
        arg_sources=sources,
        warnings=dedupe(warnings),
        needs_password_manager_agent=gateway.needs_agent,
        connection_name=name,
        connection_id=ref,
        connection_type="ssh",
        selected_host=host,
        available_hosts=available_hosts,
        username=identity.username,
        port=port,
        auth_methods=identity.auth_methods,
        gateway_names=gateway.names,
        agent_provider=gateway.provider,
        agent_identifier=gateway.identifier,
    )


def resolve_hosts(
    cfg: dict[str, object], host_override: str | None, warnings: list[str]
) -> tuple[str, list[str]]:
    """Pick the target address and keep the usable alternatives around it."""
    selected_host, advertised = selectable_texts(cfg.get("host"))
    host = validate_destination(host_override or selected_host or "")
    if host_override and advertised and host_override not in advertised:
        warnings.append(
            f"The manually selected host {host_override!r} was not in XPipe's advertised alternatives."
        )
    # One stale address in XPipe's alternatives must not break the whole export:
    # only the selected host is load-bearing for the generated command.
    available = usable_destinations(advertised, warnings)
    if host not in available:
        available.insert(0, host)
    return host, available


def plan_gateway(
    client: object,
    cfg: dict[str, object],
    identity: IdentityResult,
    *,
    visited: set[str],
    depth: int,
    max_gateway_depth: int,
    platform_name: str | None,
    warnings: list[str],
) -> GatewayPlan:
    """Build the ProxyCommand for a gateway hop, if the connection has one."""
    plan = GatewayPlan(
        argv=[],
        names=[],
        needs_agent=identity.needs_password_manager_agent,
        provider=identity.agent_provider,
        identifier=identity.agent_identifier,
    )
    gateway_ref = selected_text(cfg.get("gateway"))
    if not gateway_ref:
        return plan

    gateway_command = build_ssh_argv(
        client,
        info_one(client, gateway_ref),
        proxy_mode=True,
        visited=visited,
        depth=depth + 1,
        max_gateway_depth=max_gateway_depth,
        platform_name=platform_name,
    )
    if _agents_disagree(identity, gateway_command):
        # One inherited SSH_AUTH_SOCK cannot select different providers per hop.
        warnings.append(
            "Target and gateway require different password-manager SSH agents; "
            "one SSH_AUTH_SOCK may not authenticate both hops."
        )
    warnings.extend(gateway_command.warnings)
    nested = (
        windows_join(gateway_command.argv)
        if (platform_name or os.name) == "nt"
        else shlex.join(gateway_command.argv)
    )
    hop = f"XPipe gateway {gateway_command.connection_name}"
    return GatewayPlan(
        argv=["-o", f"ProxyCommand={nested}"],
        sources=[hop, hop],
        names=[gateway_command.connection_name, *gateway_command.gateway_names],
        needs_agent=plan.needs_agent or gateway_command.needs_password_manager_agent,
        provider=plan.provider or gateway_command.agent_provider,
        identifier=plan.identifier or gateway_command.agent_identifier,
    )


def _agents_disagree(identity: IdentityResult, gateway: SSHCommand) -> bool:
    if not (identity.needs_password_manager_agent and gateway.needs_password_manager_agent):
        return False
    target = provider_hint(identity.agent_provider, identity.agent_identifier)
    hop = provider_hint(gateway.agent_provider, gateway.agent_identifier)
    # An unrecognized provider on either side cannot prove a mismatch.
    return bool(target and hop and target != hop)


def ssh_config_command(
    info: WireRecord,
    cfg: dict[str, object],
    *,
    name: str,
    ref: str,
    proxy_mode: bool,
) -> SSHCommand:
    """Build the command for a connection that defers everything to ~/.ssh/config."""
    alias = ssh_config_alias(info, cfg)
    argv = ["ssh"]
    sources = [SSH_EXECUTABLE]
    if proxy_mode:
        argv += ["-W", "%h:%p"]
        sources += [GATEWAY_FORWARDING, GATEWAY_FORWARDING]
    argv.append(alias)
    sources.append("XPipe ssh config alias")
    return SSHCommand(
        argv=argv,
        arg_sources=sources,
        connection_name=name,
        connection_id=ref,
        connection_type="sshConfigHost",
        selected_host=alias,
        available_hosts=[alias],
        auth_methods=["~/.ssh/config"],
    )


def dedupe(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def windows_join(argv: list[str]) -> str:
    """Quote nested argv for Windows OpenSSH's command-line parser."""
    import subprocess

    return subprocess.list2cmdline(argv)
