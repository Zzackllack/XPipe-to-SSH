"""Connection and identity selection rules."""

from __future__ import annotations

import re
from typing import cast

from .errors import SelectionError
from .xpipe import (
    WireRecord,
    XPipeAdapter,
    connection_config,
    display_path,
    info_one,
    query_all,
    store_id,
)

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def exportable(info: WireRecord) -> bool:
    cfg = connection_config(info)
    return info.get("type") in {"ssh", "sshConfigHost"} or cfg.get("type") in {
        "ssh",
        "sshConfigHost",
    }


def choose_connection(client: object, selector: str) -> WireRecord:
    if UUID_RE.fullmatch(selector):
        return info_one(client, selector)

    needle = selector.casefold().strip("/")
    infos = [info for info in query_all(client) if exportable(info)]
    ranked: list[tuple[int, WireRecord]] = []
    for info in infos:
        path = display_path(info).strip("/")
        folded = path.casefold()
        leaf = folded.rsplit("/", 1)[-1]
        if folded == needle:
            rank = 0
        elif leaf == needle:
            rank = 1
        elif needle in folded:
            rank = 2
        else:
            continue
        ranked.append((rank, info))

    if not ranked:
        raise SelectionError(f"No SSH connection matched {selector!r}. Use --list to see names.")
    best_rank = min(rank for rank, _ in ranked)
    matches = [info for rank, info in ranked if rank == best_rank]
    if best_rank == 1 and len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        shown = "\n  ".join(
            f"{display_path(info)}  [{store_id(info) or 'missing ID'}]" for info in matches[:20]
        )
        suffix = f"\n  ... and {len(matches) - 20} more" if len(matches) > 20 else ""
        raise SelectionError(
            "Connection name is ambiguous. Use a full path or UUID "
            f"({len(matches)} matches):\n  {shown}{suffix}"
        )
    return matches[0]


def find_identity_store(value: object, *, max_depth: int = 6) -> dict[str, object] | None:
    """Find a known identity store while bounding compatibility fallback traversal."""
    seen: set[int] = set()

    def walk(current: object, depth: int) -> dict[str, object] | None:
        if depth > max_depth or id(current) in seen:
            return None
        if isinstance(current, dict):
            seen.add(id(current))
            if "username" in current and (
                "sshIdentity" in current
                or "password" in current
                or str(current.get("type", "")).casefold().endswith("identity")
            ):
                return cast(dict[str, object], current)
            for child in current.values():
                found = walk(child, depth + 1)
                if found:
                    return found
        elif isinstance(current, list):
            seen.add(id(current))
            for child in current:
                found = walk(child, depth + 1)
                if found:
                    return found
        return None

    return walk(value, 0)


def resolve_identity(
    client: object,
    identity: object,
    warnings: list[str],
) -> dict[str, object] | None:
    if not isinstance(identity, dict):
        return None
    kind = identity.get("type")
    if kind == "inPlace":
        return find_identity_store(identity.get("identityStore"))
    if kind == "ref" and isinstance(identity.get("ref"), str):
        identity_info = info_one(client, identity["ref"])
        store = find_identity_store(connection_config(identity_info))
        if not store:
            warnings.append(
                f"Could not understand the identity schema for {display_path(identity_info)}."
            )
        return store
    return find_identity_store(identity)


def decode_identity_data(
    client: object,
    value: object,
    warnings: list[str],
) -> object:
    """Recognize documented v24 descriptors before decrypting v23 envelopes."""
    direct_types = {"none", "file", "agent", "passwordmanageragent"}
    encrypted_keys = {"secrets", "encryptedValue", "encryptedToken"}
    if isinstance(value, dict):
        descriptor_type = value.get("type")
        if isinstance(descriptor_type, str) and descriptor_type.casefold() in direct_types:
            return value
        if isinstance(descriptor_type, str) and not encrypted_keys.intersection(value):
            warnings.append(f"Unsupported XPipe SSH identity type {descriptor_type!r}.")
            return None
    if not value:
        return None
    try:
        decoded = XPipeAdapter(client).decrypt(value)
    except (ValueError, TypeError, RuntimeError) as exc:
        warnings.append(f"Could not decrypt SSH identity metadata: {exc}")
        return None
    if isinstance(decoded, (dict, list)):
        return decoded
    if isinstance(decoded, str):
        try:
            import json

            return json.loads(decoded)
        except json.JSONDecodeError:
            return decoded
    return decoded
