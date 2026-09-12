"""Deterministic shell and machine-output renderers."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex

from .models import SSHCommand


def powershell_join(argv: list[str]) -> str:
    def quote(arg: str) -> str:
        if arg and not re.search(r"[\s'`$&|<>;(){}\[\]]", arg):
            return arg
        return "'" + arg.replace("'", "''") + "'"

    return " ".join(quote(arg) for arg in argv)


def render(command: SSHCommand, shell: str) -> str:
    if shell == "auto":
        shell = "powershell" if os.name == "nt" else "posix"
    if shell == "json":
        return json.dumps(
            {
                "schemaVersion": 1,
                "connection": {
                    "name": command.connection_name,
                    "id": command.connection_id,
                    "type": command.connection_type,
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
    if shell != "posix":
        raise ValueError(f"Unsupported shell renderer: {shell}")
    rendered = shlex.join(command.argv)
    if command.env:
        prefix = " ".join(
            f"{key}={shlex.quote(value)}" for key, value in command.env.items()
        )
        return f"{prefix} {rendered}"
    return rendered


def normalize_address(value: str) -> str:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        return value[1:-1]
    return value


def address_kind(value: str) -> str:
    try:
        address = ipaddress.ip_address(normalize_address(value))
        return f"IPv{address.version}"
    except ValueError:
        return "Hostname"

