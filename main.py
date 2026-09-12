#!/usr/bin/env python3
"""Compatibility entry point for the packaged ``xpipe-to-ssh`` CLI."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence

from xpipe_to_ssh.agents import (
    agent_identity_count,
    agent_label,
    candidate_agent_sockets,
    resolve_agent_socket,
)
from xpipe_to_ssh.cli import AppDependencies
from xpipe_to_ssh.cli import main as _main
from xpipe_to_ssh.errors import ExportError
from xpipe_to_ssh.models import AgentSocket, IdentityResult, SSHCommand
from xpipe_to_ssh.presentation import (
    RICH_AVAILABLE,
    choose_host_interactively,
    make_console,
    render_address_table,
    render_dashboard,
    render_list,
)
from xpipe_to_ssh.rendering import address_kind, powershell_join, render
from xpipe_to_ssh.selection import (
    choose_connection,
    decode_identity_data,
    find_identity_store,
    resolve_identity,
)
from xpipe_to_ssh.ssh import (
    additional_options,
    build_ssh_argv,
    identity_options,
    ssh_config_alias,
    unique_strings,
)
from xpipe_to_ssh.xpipe import (
    connection_config,
    display_path,
    info_one,
    query_all,
    selectable_texts,
    selected_text,
    selected_value,
    store_id,
)

__all__ = [
    "AgentSocket",
    "AppDependencies",
    "ExportError",
    "IdentityResult",
    "RICH_AVAILABLE",
    "SSHCommand",
    "additional_options",
    "address_kind",
    "agent_identity_count",
    "agent_label",
    "api_method",
    "build_ssh_argv",
    "candidate_agent_sockets",
    "choose_connection",
    "choose_host_interactively",
    "connection_config",
    "decode_identity_data",
    "decrypt_json",
    "display_path",
    "find_identity_store",
    "identity_options",
    "info_one",
    "main",
    "make_console",
    "powershell_join",
    "query_all",
    "render",
    "render_address_table",
    "render_dashboard",
    "render_list",
    "resolve_agent_socket",
    "resolve_identity",
    "selectable_texts",
    "selected_text",
    "selected_value",
    "ssh_config_alias",
    "store_id",
    "unique_strings",
    "unique_text",
]


def unique_text(values: Iterable[object]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = selected_text(value)
        if text and text not in result:
            result.append(text)
    return result


def api_method(client: object, *names: str) -> object:
    for name in names:
        method = getattr(client, name, None)
        if callable(method):
            return method
    supported = ", ".join(names)
    raise ExportError(f"Installed xpipe-api does not provide any of: {supported}")


def decrypt_json(client: object, encrypted: object, warnings: list[str]) -> object:
    if not encrypted:
        return None
    try:
        method = api_method(client, "secret_decrypt")
        raw = method(encrypted)  # type: ignore[operator]
    except (ValueError, TypeError, RuntimeError) as exc:
        warnings.append(f"Could not decrypt SSH identity metadata: {exc}")
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return raw


def main(argv: Sequence[str] | None = None, deps: AppDependencies | None = None) -> int:
    return _main(argv, deps)


if __name__ == "__main__":
    raise SystemExit(main())
