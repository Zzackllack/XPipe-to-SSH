"""Best-effort detection and opt-in auto-start of the XPipe daemon/application.

The CLI can only reach XPipe through the local HTTP API, so "XPipe is not
running" shows up either while constructing the client (no beacon-auth file)
or on the first handshake (connection refused, reset, or blackholed). When
that happens on an interactive terminal, the user is offered to launch XPipe
with ``xpipe open`` and the operation is retried once. Anything short of that
(missing beacon-auth from another user's daemon, an HTTP API that rejects
authentication, a daemon that answers with garbage) gets the plain error
message, because relaunching would not fix it.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from collections.abc import Callable, Iterator
from enum import Enum

from .errors import XPipeConnectionError
from .presentation import render_note
from .xpipe import XPipeAdapter

#: Short deadline for the liveness probe; localhost should answer in milliseconds.
PROBE_TIMEOUT = 5.0
#: How long to wait for a freshly opened XPipe to become reachable.
STARTUP_TIMEOUT = 60.0
POLL_INTERVAL = 0.5

ConfirmPrompt = Callable[[], bool]
Launcher = Callable[[], subprocess.Popen[bytes] | None]


class Availability(Enum):
    """Why XPipe cannot be used right now, and whether `xpipe open` could help."""

    #: No daemon (or a wedged one) answered; opening the app starts the daemon.
    NOT_RUNNING = "not_running"
    #: The daemon answered but rejected authentication; a restart changes nothing.
    UNAUTHORIZED = "unauthorized"
    #: Anything else; the cause is reported, but opening XPipe is not offered.
    UNKNOWN = "unknown"


def _cause_chain(exc: BaseException, limit: int = 8) -> Iterator[BaseException]:
    seen: set[int] = set()
    current: BaseException | None = exc
    for _ in range(limit):
        if current is None or id(current) in seen:
            return
        seen.add(id(current))
        yield current
        # Look at both: the vendor client wraps transport errors with `from`,
        # but a raw handshake failure may only carry the context.
        current = current.__cause__ or current.__context__


def _is_unreachable(exc: BaseException) -> bool:
    try:
        import requests
    except ImportError:
        # requests is a hard dependency of xpipe-api, so this branch only
        # matters for exotic installs; OSError is what its errors subclass.
        return isinstance(exc, OSError)
    return isinstance(exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout))


def classify(exc: BaseException) -> tuple[Availability, str]:
    """Map a client-construction or probe failure onto a restart-or-not verdict.

    The vendor raises its own exception types, so match on type names instead of
    importing xpipe-api internals that are free to move; the names come from its
    public ``exceptions`` module.
    """
    for current in _cause_chain(exc):
        name = type(current).__name__
        text = str(current)
        if name == "NoTokenFoundException":
            if "Bad permissions" in text:
                # The beacon-auth file exists but belongs to another user's
                # daemon; opening the app as this user will not fix that.
                return Availability.UNKNOWN, text
            return Availability.NOT_RUNNING, text
        if name == "AuthFailedException":
            return Availability.UNAUTHORIZED, text
        if _is_unreachable(current):
            return Availability.NOT_RUNNING, text
    return Availability.UNKNOWN, str(exc)


def probe(client: object) -> None:
    """Check that the daemon answers, with a short deadline.

    Raises whatever the transport raised; classify with :func:`classify`.
    The adapter's bounded call returns the raw cause instead of wrapping it.
    """
    method = getattr(client, "daemon_version", None)
    if not callable(method):
        raise XPipeConnectionError(
            "Installed xpipe-api cannot probe the daemon (missing daemon_version)"
        )
    XPipeAdapter(client, timeout=PROBE_TIMEOUT)._call(method)


def open_xpipe() -> subprocess.Popen[bytes]:
    binary = shutil.which("xpipe")
    if binary is None:
        raise XPipeConnectionError(
            "Could not find the `xpipe` command on PATH; start XPipe manually, then retry"
        )
    # A GUI launcher: detach so this CLI never inherits its lifetime or its output.
    return subprocess.Popen(
        [binary, "open"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def wait_for_daemon(
    ptb: bool,
    client_maker: Callable[[bool], object],
    *,
    timeout: float = STARTUP_TIMEOUT,
    proc: subprocess.Popen[bytes] | None = None,
    no_color: bool = False,
) -> object:
    """Poll until the freshly opened XPipe answers, then return a verified client."""
    render_note("Waiting for XPipe to start…", style="cyan", no_color=no_color)
    deadline = time.monotonic() + timeout
    while True:
        try:
            client = client_maker(ptb)
            probe(client)
            render_note("✓ XPipe is ready.", style="bold green", no_color=no_color)
            return client
        except Exception as exc:
            if proc is not None and (rc := proc.poll()) is not None and rc != 0:
                raise XPipeConnectionError(
                    f"`xpipe open` exited with code {rc}; run `xpipe open` in a terminal to see why"
                ) from exc
            if time.monotonic() >= deadline:
                raise XPipeConnectionError(
                    f"XPipe was opened but did not become reachable within {int(timeout)} seconds; "
                    "check the XPipe application, then retry"
                ) from exc
            time.sleep(POLL_INTERVAL)


def _failure(status: Availability, detail: str) -> XPipeConnectionError:
    if status is Availability.UNAUTHORIZED:
        return XPipeConnectionError(
            "XPipe is running but rejected the API handshake; make sure Settings -> HTTP API "
            "is enabled and XPipe is unlocked, then try again"
        )
    return XPipeConnectionError(
        "Could not reach the XPipe daemon; check that XPipe is running, unlocked, "
        f"and that Settings -> HTTP API is enabled: {detail}"
    )


def ensure_client(
    *,
    ptb: bool,
    client_maker: Callable[[bool], object],
    confirm: ConfirmPrompt | None = None,
    opener: Launcher | None = None,
    timeout: float = STARTUP_TIMEOUT,
    no_color: bool = False,
) -> object:
    """Return a verified XPipe client, offering to launch XPipe when it is down.

    ``confirm`` gates the interactive offer; pass None on non-interactive
    terminals and for ``--shell json`` so machines never see a prompt.
    ``opener`` is injectable for tests; the default launches ``xpipe open``.
    """
    try:
        client = client_maker(ptb)
        probe(client)
        return client
    except Exception as exc:
        status, detail = classify(exc)
        if status is Availability.NOT_RUNNING and confirm is not None and confirm():
            proc = (opener or open_xpipe)()
            return wait_for_daemon(ptb, client_maker, timeout=timeout, proc=proc, no_color=no_color)
        raise _failure(status, detail) from exc
