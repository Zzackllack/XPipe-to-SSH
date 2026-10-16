"""Errors that cross the application boundary.

Every error carries its own machine-readable ``code`` and process ``exit_code``
so that adding a new failure mode cannot silently inherit another one's
reporting. ``code`` is part of the JSON output contract; see the README.
"""

from __future__ import annotations

from typing import Any

#: Exit codes documented in the README's output contract.
EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_INVALID = 2


class ExportError(RuntimeError):
    """Base class for expected user-facing export failures."""

    code = "invalid_export_data"
    exit_code = EXIT_INVALID

    def details(self) -> dict[str, Any]:
        """Extra JSON fields specific to this failure."""
        return {}


class XPipeError(ExportError):
    """Base class for XPipe transport and schema failures."""

    code = "xpipe_error"
    exit_code = EXIT_FAILURE


class XPipeConnectionError(XPipeError):
    """The XPipe client could not complete a request."""

    code = "xpipe_request_failed"


class XPipeSchemaError(XPipeError):
    """XPipe returned a response that did not match a known shape."""

    code = "xpipe_schema_error"


class SelectionError(ExportError):
    """A connection or target could not be selected."""

    code = "selection_failed"


class ConnectionNotFoundError(SelectionError):
    """No exportable connection matched a selector."""

    code = "connection_not_found"


class AmbiguousConnectionError(SelectionError):
    """Several connections matched equally well."""

    code = "ambiguous_connection"

    def __init__(self, message: str, candidates: list[dict[str, str]]) -> None:
        super().__init__(message)
        self.candidates = candidates

    def details(self) -> dict[str, Any]:
        return {"candidates": self.candidates}


class StrictWarningsError(ExportError):
    """A warning-free command was requested but could not be produced."""

    code = "strict_warnings"

    def __init__(self, warnings: list[str]) -> None:
        super().__init__(f"Command has {len(warnings)} warning(s): " + "; ".join(warnings))
        self.warnings = warnings

    def details(self) -> dict[str, Any]:
        return {"warnings": self.warnings}


class AgentError(ExportError):
    """An explicitly requested SSH agent could not be used."""

    code = "agent_unavailable"
    exit_code = EXIT_FAILURE


class ClipboardError(ExportError):
    """Clipboard discovery or invocation failed."""

    code = "clipboard_failed"
    exit_code = EXIT_FAILURE


class ExecutionError(ExportError):
    """The local SSH executable could not be started."""

    code = "execution_failed"
    exit_code = EXIT_FAILURE


class LocalProcessError(ExportError):
    """A local process or filesystem call failed outside SSH itself."""

    code = "local_process_failed"
    exit_code = EXIT_FAILURE


class ConfigError(ExportError):
    """The optional configuration file exists but could not be used."""

    code = "invalid_configuration"
    exit_code = EXIT_FAILURE


class ExportOutputError(ExportError):
    """A bulk export file could not be written, or would clobber one."""

    code = "export_output_failed"
    exit_code = EXIT_FAILURE


class InternalError(ExportError):
    """An unexpected defect; only reachable through the top-level safety net."""

    code = "internal_error"
    exit_code = EXIT_FAILURE
