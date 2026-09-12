"""Cross-platform SSH-agent discovery and bounded probing."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

from .errors import AgentError
from .models import AgentProbe, AgentSocket


def _provider_for(path: Path) -> tuple[str, str | None]:
    normalized = str(path).casefold()
    if "bitwarden" in normalized:
        return "Bitwarden", "bitwarden"
    if "1password" in normalized:
        return "1Password", "1password"
    if "pageant" in normalized:
        return "Pageant", "pageant"
    return "SSH agent", None


def candidate_agent_sockets(
    *,
    home: Path | None = None,
    environ: Mapping[str, str] | None = None,
    platform_name: str | None = None,
) -> list[Path]:
    home = Path.home() if home is None else home
    environ = os.environ if environ is None else environ
    platform_name = os.name if platform_name is None else platform_name
    candidates: list[Path] = []
    if platform_name == "nt":
        # Named-pipe/Pageant endpoints cannot be validated with Path.exists();
        # explicit --agent-socket remains the reliable Windows escape hatch.
        for key in ("SSH_AUTH_SOCK", "SSH_AGENT_PID"):
            value = environ.get(key)
            if value and key == "SSH_AUTH_SOCK":
                candidates.append(Path(value))
    else:
        candidates.extend(
            [
                home / ".bitwarden-ssh-agent.sock",
                home
                / "Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock",
                home / "Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
            ]
        )
        current = environ.get("SSH_AUTH_SOCK")
        if current:
            candidates.append(Path(os.path.expandvars(os.path.expanduser(current))))
    result: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        value = str(candidate)
        if value not in seen:
            result.append(candidate)
            seen.add(value)
    return result


def agent_label(path: Path) -> str:
    return _provider_for(path)[0]


def probe_agent(
    socket_path: Path,
    *,
    ssh_add: str | None = None,
    timeout: float = 3,
    platform_name: str | None = None,
) -> AgentProbe:
    platform_name = os.name if platform_name is None else platform_name
    if platform_name != "nt":
        try:
            if not stat.S_ISSOCK(socket_path.stat().st_mode):
                return AgentProbe(None, "path is not a Unix socket")
        except OSError as exc:
            return AgentProbe(None, f"socket is unavailable: {exc}")
    executable = ssh_add or shutil.which("ssh-add")
    if not executable:
        return AgentProbe(None, "ssh-add was not found on PATH")
    try:
        result = subprocess.run(
            [executable, "-L"],
            env={**os.environ, "SSH_AUTH_SOCK": str(socket_path)},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return AgentProbe(None, "ssh-add timed out")
    except OSError as exc:
        return AgentProbe(None, f"could not run ssh-add: {exc}")
    if result.returncode != 0:
        return AgentProbe(0, "ssh-add reported no usable identities")
    return AgentProbe(len([line for line in result.stdout.splitlines() if line.strip()]), None)


def agent_identity_count(socket_path: Path) -> int:
    """Compatibility helper returning zero for unavailable probes."""
    probe = probe_agent(socket_path)
    return probe.identity_count or 0


def _socket(path: Path, probe: AgentProbe) -> AgentSocket:
    label, provider = _provider_for(path)
    return AgentSocket(
        str(path),
        label,
        probe.identity_count or 0,
        provider=provider,
        identifier=provider,
        probe_error=probe.error,
    )


def resolve_agent_socket(
    requested: str,
    *,
    provider: str | None = None,
    identifier: str | None = None,
    candidates: Sequence[Path] | None = None,
    platform_name: str | None = None,
) -> AgentSocket | None:
    if requested == "none":
        return None
    platform_name = os.name if platform_name is None else platform_name
    if requested != "auto":
        path = Path(os.path.expandvars(os.path.expanduser(requested)))
        if not path.exists() and platform_name != "nt":
            raise AgentError(f"SSH agent socket does not exist: {path}")
        probe = probe_agent(path, platform_name=platform_name)
        if probe.error and probe.identity_count is None:
            raise AgentError(f"SSH agent at {path} is unavailable: {probe.error}")
        return _socket(path, probe)

    paths = list(candidates) if candidates is not None else candidate_agent_sockets(platform_name=platform_name)
    existing: list[AgentSocket] = []
    for path in paths:
        if platform_name != "nt" and not path.exists():
            continue
        current = _socket(path, probe_agent(path, platform_name=platform_name))
        existing.append(current)

    def matches(agent: AgentSocket) -> bool:
        requested_values = {value.casefold() for value in (provider, identifier) if value}
        actual_values = {value.casefold() for value in (agent.provider, agent.identifier, agent.label) if value}
        return not requested_values or bool(requested_values & actual_values)

    for agent in existing:
        if matches(agent) and agent.identity_count > 0:
            return agent
    for agent in existing:
        if matches(agent):
            return agent
    if provider or identifier:
        return None
    return existing[0] if existing else None

