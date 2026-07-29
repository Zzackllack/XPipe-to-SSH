#!/usr/bin/env python3
"""Export an XPipe SSH connection as one OpenSSH command.

Requires:
  1. XPipe running with Settings -> HTTP API enabled.
  2. python -m pip install xpipe_api

Examples:
  python xpipe_to_ssh.py --list
  python xpipe_to_ssh.py "Production/Database"
  python xpipe_to_ssh.py 34c7ea9a-b00d-45e1-a324-78ef0750acc2
  python xpipe_to_ssh.py "Production/Database" --shell powershell
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from typing import Any

try:
    from xpipe_api import Client
except ImportError:
    sys.exit("Install the XPipe API client first: python -m pip install xpipe_api")

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class ExportError(RuntimeError):
    pass


def warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def info_one(client: Client, ref: str) -> dict[str, Any]:
    values = client.connection_info([ref])
    if not values:
        raise ExportError(f"XPipe returned no information for {ref}")
    return values[0]


def display_path(info: dict[str, Any]) -> str:
    names = info.get("name") or []
    if isinstance(names, str):
        return names
    return "/".join(str(part) for part in names)


def query_all(client: Client) -> list[dict[str, Any]]:
    refs: list[str] = []
    seen: set[str] = set()
    # XPipe's connection query uses glob patterns. Try broad patterns because
    # installations can organize their root categories differently.
    for pattern in ("**", "*", "**/*"):
        try:
            for ref in client.connection_query(connections=pattern):
                if ref not in seen:
                    seen.add(ref)
                    refs.append(ref)
        except Exception:
            pass
    return client.connection_info(refs) if refs else []


def connection_config(info: dict[str, Any]) -> dict[str, Any]:
    """Return the connection schema across XPipe API field-name versions."""
    keys = ("config", "rawData", "data")
    for key in keys:
        value = info.get(key)
        if isinstance(value, dict) and value:
            return value
    for key in keys:
        value = info.get(key)
        if isinstance(value, dict):
            return value
    return {}


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
            f"{display_path(info)}  [{info.get('connection')}]" for info in matches[:20]
        )
        raise ExportError(
            f"Connection name is ambiguous. Use a full path or UUID:\n  {names}"
        )
    return matches[0]


def find_identity_store(value: Any) -> dict[str, Any] | None:
    """Tolerate identity wrapper/schema changes by locating the useful store."""
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


def resolve_identity(client: Client, identity: Any) -> dict[str, Any] | None:
    if not isinstance(identity, dict):
        return None

    kind = identity.get("type")
    if kind == "inPlace":
        return find_identity_store(identity.get("identityStore"))
    if kind == "ref" and identity.get("ref"):
        identity_info = info_one(client, str(identity["ref"]))
        store = find_identity_store(connection_config(identity_info))
        if not store:
            warn(
                f"could not understand identity schema for {display_path(identity_info)}"
            )
        return store

    # Handles possible inline schema variants.
    return find_identity_store(identity)


def decrypt_json(client: Client, encrypted: Any) -> Any:
    if not encrypted:
        return None
    try:
        raw = client.secret_decrypt(encrypted)
    except Exception as exc:
        warn(f"could not decrypt SSH identity metadata: {exc}")
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return raw


def identity_options(client: Client, cfg: dict[str, Any]) -> list[str]:
    options: list[str] = []
    store = resolve_identity(client, cfg.get("identity"))
    if not store:
        return options

    username = store.get("username")
    if username:
        options += ["-l", str(username)]

    key_data = decrypt_json(client, store.get("sshIdentity"))
    if isinstance(key_data, dict):
        key_type = key_data.get("type")
        if key_type == "file" and key_data.get("file"):
            options += ["-i", os.path.expanduser(str(key_data["file"]))]
        elif key_type not in (None, "none", "agent"):
            warn(
                f"SSH key type {key_type!r} cannot always be represented by plain OpenSSH; "
                "the command will rely on your SSH agent/config"
            )

    # A normal OpenSSH command can prompt for a password, but it cannot safely
    # embed or auto-type XPipe-managed passwords. Deliberately do not decrypt it.
    if store.get("password"):
        warn("XPipe-managed password was not exported; ssh may prompt for it")

    return options


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
        value = cfg.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
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
) -> list[str]:
    visited = set() if visited is None else set(visited)
    ref = str(info.get("connection") or "")
    if ref:
        if ref in visited:
            raise ExportError("Gateway cycle detected in XPipe configuration")
        visited.add(ref)

    cfg = connection_config(info)
    connection_type = info.get("type") or cfg.get("type")

    if connection_type == "sshConfigHost" or cfg.get("type") == "sshConfigHost":
        argv = ["ssh"]
        if proxy_mode:
            argv += ["-W", "%h:%p"]
        argv.append(ssh_config_alias(info, cfg))
        return argv

    if cfg.get("type") != "ssh" and connection_type != "ssh":
        raise ExportError(
            f"{display_path(info)!r} is type {connection_type!r}, not a directly exportable SSH connection"
        )

    host = cfg.get("host")
    if not host:
        raise ExportError(f"{display_path(info)!r} has no SSH host")

    argv = ["ssh"]
    port = cfg.get("port")
    if port and int(port) != 22:
        argv += ["-p", str(port)]

    argv += identity_options(client, cfg)

    if cfg.get("forwardX11"):
        argv.append("-X")

    argv += additional_options(cfg.get("additionalOptions"))

    gateway_ref = cfg.get("gateway")
    if gateway_ref:
        gateway_info = info_one(client, str(gateway_ref))
        gateway_argv = build_ssh_argv(
            client, gateway_info, proxy_mode=True, visited=visited
        )
        # ProxyCommand rather than -J preserves per-gateway usernames, ports,
        # key files, extra options, and arbitrarily deep gateway chains.
        argv += ["-o", f"ProxyCommand={shlex.join(gateway_argv)}"]

    if proxy_mode:
        argv += ["-W", "%h:%p"]

    argv.append(str(host))
    return argv


def powershell_join(argv: list[str]) -> str:
    def quote(arg: str) -> str:
        if arg and not re.search(r"[\s'`$&|<>;(){}\[\]]", arg):
            return arg
        return "'" + arg.replace("'", "''") + "'"

    return " ".join(quote(arg) for arg in argv)


def render(argv: list[str], shell: str) -> str:
    if shell == "auto":
        shell = "powershell" if os.name == "nt" else "posix"
    if shell == "powershell":
        return powershell_join(argv)
    if shell == "json":
        return json.dumps(argv, indent=2)
    return shlex.join(argv)


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
        help="output quoting format (default: auto)",
    )
    parser.add_argument(
        "--ptb", action="store_true", help="connect to an XPipe PTB build"
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
            for info in sorted(
                ssh_infos, key=lambda item: display_path(item).casefold()
            ):
                print(f"{display_path(info)}\t{info.get('connection')}")
            return 0

        if not args.connection:
            parser.error("provide a connection name/UUID, or use --list")

        info = choose_connection(client, args.connection)
        argv = build_ssh_argv(client, info)
        print(render(argv, args.shell))
        return 0
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(
            "error: could not talk to XPipe. Ensure XPipe is running and "
            f"Settings -> HTTP API is enabled. Details: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
