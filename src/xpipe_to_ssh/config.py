"""Optional user configuration for defaults the CLI should not have to repeat.

Resolution order is command line, then environment, then this file, then the
built-in default. The file is optional: a missing file is not an error, but a
malformed one is, because silently ignoring it hides the reason a setting did
not take effect.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .rendering import SHELL_CHOICES

#: Overrides the location of the configuration file.
CONFIG_PATH_ENV = "XPIPE_TO_SSH_CONFIG"
CONFIG_RELATIVE = Path("xpipe-to-ssh") / "config.toml"

#: Recognized keys and how to read them. Anything else is a typo worth failing on.
SETTING_TYPES: dict[str, type] = {
    "shell": str,
    "agent_socket": str,
    "ptb": bool,
    "api_timeout": float,
}


@dataclass(frozen=True)
class Settings:
    shell: str | None = None
    agent_socket: str | None = None
    ptb: bool | None = None
    api_timeout: float | None = None

    def explicit(self) -> dict[str, Any]:
        return {key: value for key, value in vars(self).items() if value is not None}


def config_path() -> Path | None:
    """Locate the config file, or None when the environment disables it."""
    override = os.environ.get(CONFIG_PATH_ENV)
    if override is not None:
        return Path(override)
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / CONFIG_RELATIVE


def _coerce(key: str, kind: type, value: object) -> Any:
    """Check one TOML value against its declared type, with TOML's int/float gap.

    ``api_timeout = 4`` is an integer in TOML, and rejecting that would make the
    obvious spelling of a timeout an error. Booleans are not numbers here even
    though Python says ``bool`` is a subclass of ``int``.
    """
    if kind is bool:
        if not isinstance(value, bool):
            raise TypeError(f"bool, got {type(value).__name__}")
        return value
    if kind is float and isinstance(value, int):
        return float(value)
    # bool is a subclass of int, so a boolean must not satisfy a number.
    if isinstance(value, bool) or not isinstance(value, kind):
        raise TypeError(f"{kind.__name__}, got {type(value).__name__}")
    return value


def load_settings(path: Path | None = None) -> Settings:
    """Read the configuration file, ignoring a missing one."""
    target = config_path() if path is None else path
    if target is None or not target.exists():
        return Settings()
    try:
        with target.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Could not read {target}: {exc}") from exc

    unknown = sorted(set(document) - set(SETTING_TYPES))
    if unknown:
        valid = ", ".join(sorted(SETTING_TYPES))
        raise ConfigError(
            f"Unknown setting(s) in {target}: {', '.join(unknown)}. Valid keys: {valid}"
        )

    values: dict[str, Any] = {}
    for key, kind in SETTING_TYPES.items():
        if key not in document:
            continue
        try:
            values[key] = _coerce(key, kind, document[key])
        except TypeError as exc:
            raise ConfigError(f"{key} in {target} must be {exc}") from exc

    shell = values.get("shell")
    if shell is not None and shell not in SHELL_CHOICES:
        valid = ", ".join(SHELL_CHOICES)
        raise ConfigError(f"shell in {target} must be one of: {valid}")
    timeout = values.get("api_timeout")
    if timeout is not None and not 0 < timeout <= 300:
        raise ConfigError(f"api_timeout in {target} must be greater than 0 and at most 300 seconds")
    agent_socket = values.get("agent_socket")
    if agent_socket is not None and not agent_socket:
        raise ConfigError(f"agent_socket in {target} must not be empty")
    return Settings(**values)
