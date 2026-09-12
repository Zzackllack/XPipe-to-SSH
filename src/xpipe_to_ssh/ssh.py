"""Pure-ish conversion from normalized XPipe records to SSH arguments."""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from collections.abc import Iterable

from .errors import ExportError
from .models import IdentityResult, SSHCommand
from .selection import resolve_identity
from .xpipe import (
    WireRecord,
    connection_config,
    display_path,
    info_one,
    selectable_texts,
    selected_text,
    store_id,
)

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
OPTION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
COMMAND_OPTIONS = {"proxycommand", "localcommand", "match", "include"}


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
            raise ExportError(f"Invalid bracketed {field.lower()}: {value!r}")
        inner = value[1:-1]
        try:
            ipaddress.ip_address(inner)
        except ValueError as exc:
            raise ExportError(f"Invalid bracketed {field.lower()}: {value!r}") from exc
        return inner
    return value


def parse_port(value: object) -> int:
    text = selected_text(value)
    if text is None or not re.fullmatch(r"[0-9]+", text):
        raise ExportError(f"Invalid SSH port {text!r}; expected an integer from 1 to 65535")
    port = int(text)
    if not 1 <= port <= 65535:
        raise ExportError(f"Invalid SSH port {port}; expected an integer from 1 to 65535")
    return port


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
            result.agent_provider = selected_text(key_data.get("provider"))
            result.agent_identifier = selected_text(key_data.get("identifier"))
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

    if store.get("password"):
        result.auth_methods.append("Password fallback")
        result.warnings.append(
            "XPipe-managed password was not exported; SSH may prompt for it if the key is rejected."
        )
    if not result.auth_methods:
        result.auth_methods.append("SSH defaults / config")
    return result


def decode_identity_data(client: object, value: object, warnings: list[str]) -> object:
    from .selection import decode_identity_data as decode

    return decode(client, value, warnings)


def additional_options(raw: object) -> list[str]:
    options, _ = parse_additional_options(raw)
    return options


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
            raise ExportError(f"Invalid SSH additional option: {line!r}")
        if "=" not in line and not re.search(r"\s", line):
            raise ExportError(f"SSH additional option needs a value: {line!r}")
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


def build_ssh_argv(
    client: object,
    info: WireRecord,
    *,
    proxy_mode: bool = False,
    visited: set[str] | None = None,
    host_override: str | None = None,
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
        raise ExportError(f"{name!r} is type {connection_type!r}, not an exportable SSH connection")

    selected_host, available_hosts = selectable_texts(cfg.get("host"))
    host = validate_destination(host_override or selected_host or "")
    warnings: list[str] = []
    if host_override and available_hosts and host_override not in available_hosts:
        warnings.append(
            f"The manually selected host {host_override!r} was not in XPipe's advertised alternatives."
        )
    available_hosts = [validate_destination(value) for value in available_hosts]
    if host not in available_hosts:
        available_hosts.insert(0, host)

    port = parse_port(cfg.get("port", 22))
    identity = identity_options(client, cfg)
    warnings.extend(identity.warnings)
    argv = ["ssh"]
    if port != 22:
        argv += ["-p", str(port)]
    argv += identity.argv
    if parse_bool(cfg.get("forwardX11"), field="forwardX11"):
        argv.append("-X")
    extra, extra_warnings = parse_additional_options(cfg.get("additionalOptions"))
    argv += extra
    warnings.extend(extra_warnings)

    gateway_names: list[str] = []
    needs_agent = identity.needs_password_manager_agent
    gateway_provider = identity.agent_provider
    gateway_identifier = identity.agent_identifier
    gateway_ref = selected_text(cfg.get("gateway"))
    if gateway_ref:
        gateway_info = info_one(client, gateway_ref)
        gateway_command = build_ssh_argv(
            client,
            gateway_info,
            proxy_mode=True,
            visited=visited,
            depth=depth + 1,
            max_gateway_depth=max_gateway_depth,
            platform_name=platform_name,
        )
        needs_agent = needs_agent or gateway_command.needs_password_manager_agent
        gateway_provider = gateway_provider or gateway_command.agent_provider
        gateway_identifier = gateway_identifier or gateway_command.agent_identifier
        warnings.extend(gateway_command.warnings)
        gateway_names = [gateway_command.connection_name, *gateway_command.gateway_names]
        proxy_shell = "windows" if (platform_name or os.name) == "nt" else "posix"
        nested = (
            windows_join(gateway_command.argv)
            if proxy_shell == "windows"
            else shlex.join(gateway_command.argv)
        )
        argv += ["-o", f"ProxyCommand={nested}"]
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
        agent_provider=gateway_provider,
        agent_identifier=gateway_identifier,
    )


def unique_strings(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def windows_join(argv: list[str]) -> str:
    """Quote nested argv for Windows OpenSSH's command-line parser."""
    import subprocess

    return subprocess.list2cmdline(argv)
