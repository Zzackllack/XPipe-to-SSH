"""Small domain objects shared by adapters, planning, and presentation."""

from dataclasses import dataclass, field


@dataclass
class IdentityResult:
    argv: list[str] = field(default_factory=list)
    username: str | None = None
    auth_methods: list[str] = field(default_factory=list)
    needs_password_manager_agent: bool = False
    agent_provider: str | None = None
    agent_identifier: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AgentProbe:
    identity_count: int | None
    error: str | None = None


@dataclass
class AgentSocket:
    path: str
    label: str
    identity_count: int
    provider: str | None = None
    identifier: str | None = None
    probe_error: str | None = None


@dataclass
class SSHCommand:
    argv: list[str]
    env: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    needs_password_manager_agent: bool = False

    connection_name: str = ""
    connection_id: str = ""
    connection_type: str = "ssh"
    selected_host: str = ""
    available_hosts: list[str] = field(default_factory=list)
    username: str | None = None
    port: int = 22
    auth_methods: list[str] = field(default_factory=list)
    gateway_names: list[str] = field(default_factory=list)
    agent_provider: str | None = None
    agent_identifier: str | None = None
    agent: AgentSocket | None = None

