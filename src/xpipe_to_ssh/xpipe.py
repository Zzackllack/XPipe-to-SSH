"""XPipe API adaptation and wire-schema validation."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from typing import Protocol, cast

from .errors import XPipeConnectionError, XPipeSchemaError

WireRecord = dict[str, object]


class StoreClient(Protocol):
    """The small subset of an XPipe client used by this application."""


class XPipeAdapter:
    """Bind one API generation for the lifetime of a client."""

    def __init__(self, client: object) -> None:
        self.client = client
        if callable(getattr(client, "store_query", None)) or callable(
            getattr(client, "store_info", None)
        ):
            self.query_method = "store_query"
            self.info_method = "store_info" if callable(getattr(client, "store_info", None)) else "connection_info"
        elif callable(getattr(client, "connection_query", None)) or callable(
            getattr(client, "connection_info", None)
        ):
            self.query_method = "connection_query"
            self.info_method = "connection_info"
        else:
            raise XPipeSchemaError(
                "Installed xpipe-api does not provide a complete store or connection API"
            )

    def query(self) -> list[WireRecord]:
        if not callable(getattr(self.client, self.query_method, None)):
            raise XPipeSchemaError(f"XPipe client no longer provides {self.query_method}")
        method = self._method(self.query_method)
        try:
            if self.query_method == "store_query":
                refs = method(categories="**", stores="**", types="*")
            else:
                refs = method(connections="**")
        except Exception as exc:
            raise XPipeConnectionError(f"XPipe query failed: {exc}") from exc
        identifiers = _identifiers(refs, "query response")
        if not identifiers:
            return []
        return self._info(identifiers)

    def info(self, ref: str) -> WireRecord:
        return self._info([ref])[0]

    def decrypt(self, encrypted: object) -> object:
        method = getattr(self.client, "secret_decrypt", None)
        if not callable(method):
            raise XPipeSchemaError("Installed xpipe-api cannot decrypt identity metadata")
        try:
            return method(encrypted)
        except Exception as exc:
            raise XPipeConnectionError(f"XPipe identity decryption failed: {exc}") from exc

    def _info(self, identifiers: list[str]) -> list[WireRecord]:
        method = self._method(self.info_method)
        try:
            values = method(identifiers)
        except Exception as exc:
            raise XPipeConnectionError(f"XPipe store lookup failed: {exc}") from exc
        if not isinstance(values, list):
            raise XPipeSchemaError("XPipe info response must be a list")
        records: list[WireRecord] = []
        for index, value in enumerate(values):
            if not isinstance(value, dict):
                raise XPipeSchemaError(
                    f"XPipe info response item {index} must be an object"
                )
            records.append(cast(WireRecord, value))
        returned = {store_id(record) for record in records}
        missing = [ref for ref in identifiers if ref not in returned]
        if missing and len(identifiers) == 1:
            raise XPipeSchemaError(
                f"XPipe returned a different store ID for requested {missing[0]}"
            )
        return records

    def _method(self, name: str) -> Callable[..., object]:
        method = getattr(self.client, name, None)
        if not callable(method):
            raise XPipeSchemaError(f"XPipe client no longer provides {name}")
        return method


def _identifiers(value: object, path: str) -> list[str]:
    if not isinstance(value, list):
        raise XPipeSchemaError(f"{path} must be a list of store IDs")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise XPipeSchemaError(f"{path}[{index}] must be a non-empty string ID")
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result


def store_id(info: WireRecord) -> str:
    """Return a v24 store ID, retaining the v23 compatibility field."""
    value = info.get("store") or info.get("connection")
    if not isinstance(value, str) or not value.strip():
        return ""
    return value.strip()


def info_one(client: object, ref: str) -> WireRecord:
    if not isinstance(ref, str) or not ref.strip():
        raise XPipeSchemaError("XPipe store ID must be a non-empty string")
    return XPipeAdapter(client).info(ref)


def query_all(client: object) -> list[WireRecord]:
    return XPipeAdapter(client).query()


def display_path(info: WireRecord) -> str:
    names = info.get("name")
    if isinstance(names, str):
        return names.strip()
    if isinstance(names, list):
        return "/".join(str(part) for part in names if str(part).strip())
    return ""


def connection_config(info: WireRecord) -> dict[str, object]:
    """Extract a known XPipe config envelope without guessing arbitrary fields."""
    for key in ("rawData", "config", "data"):
        value = info.get(key)
        if not isinstance(value, dict):
            continue
        nested = value.get("config")
        if isinstance(nested, dict):
            return cast(dict[str, object], nested)
        return cast(dict[str, object], value)
    return {}


def selected_value(value: object) -> object:
    """Unwrap selected-value envelopes with cycle and depth protection."""
    seen: set[int] = set()
    for _ in range(8):
        if not isinstance(value, dict) or id(value) in seen:
            break
        seen.add(id(value))
        if "value" in value:
            value = value["value"]
        elif "selected" in value:
            value = value["selected"]
        else:
            break
    return value


def selected_text(value: object) -> str | None:
    value = selected_value(value)
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (str, int, float)):
        text = str(value).strip()
        return text or None
    return None


def selectable_texts(value: object) -> tuple[str | None, list[str]]:
    selected = selected_text(value)
    alternatives: list[object] = []
    if isinstance(value, dict):
        for key in ("available", "alternatives", "options", "values"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                alternatives.extend(candidate)
    result: list[str] = []
    for candidate in ([selected] if selected else []) + alternatives:
        text = selected_text(candidate)
        if text and text not in result:
            result.append(text)
    return selected, result


def decode_json(value: object) -> object:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value
