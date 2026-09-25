"""Errors that cross the application boundary."""


class ExportError(RuntimeError):
    """Base class for expected user-facing export failures."""


class XPipeError(ExportError):
    """Base class for XPipe transport and schema failures."""


class XPipeConnectionError(XPipeError):
    """The XPipe client could not complete a request."""


class XPipeSchemaError(XPipeError):
    """XPipe returned a response that did not match a known shape."""


class SelectionError(ExportError):
    """A connection or target could not be selected."""


class ConnectionNotFoundError(SelectionError):
    """No exportable connection matched a selector."""


class AmbiguousConnectionError(SelectionError):
    """Several connections matched equally well."""

    def __init__(self, message: str, candidates: list[dict[str, str]]) -> None:
        super().__init__(message)
        self.candidates = candidates


class AgentError(ExportError):
    """An explicitly requested SSH agent could not be used."""


class ClipboardError(ExportError):
    """Clipboard discovery or invocation failed."""


class ExecutionError(ExportError):
    """The local SSH executable could not be started."""
