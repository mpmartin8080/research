"""Pydantic models describing a honeypot. A spec is the single reviewable source of
truth: the planner writes it, the policy validator checks it, the renderer turns it
into images and a compose project."""

from __future__ import annotations

import secrets
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

SLUG = r"^[a-z][a-z0-9-]{1,40}$"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class Archetype(StrEnum):
    AI_TOOLS = "ai-tools"
    FINANCIAL = "financial"
    MFT_HUB = "mft-hub"
    CUSTOM = "custom"


class Protocol(StrEnum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    SFTP = "sftp"
    FTP = "ftp"
    FTPS = "ftps"
    SMTP = "smtp"
    FIX = "fix"
    POSTGRES = "postgres"
    TCP = "tcp"
    UDP = "udp"


class VulnKind(StrEnum):
    WEAK_CREDENTIALS = "weak-credentials"
    FAKE_SHELL = "fake-shell"
    PATH_TRAVERSAL = "path-traversal"
    SQL_INJECTION = "sql-injection"
    AUTH_BYPASS = "auth-bypass"
    INFO_DISCLOSURE = "info-disclosure"
    UNAUTHENTICATED_API = "unauthenticated-api"


class VulnSpec(_Model):
    """A deliberately exposed weakness. Always emulated: the emulator fabricates the
    result of exploitation, it never executes attacker input."""

    kind: VulnKind
    description: str = ""
    emulated: Literal[True] = True
    params: dict[str, Any] = Field(default_factory=dict)


class ServiceSpec(_Model):
    name: str = Field(pattern=SLUG)
    emulator: str = Field(description="Emulator id in runtime/decoy, e.g. 'openai_api'")
    protocol: Protocol
    listen_port: int = Field(ge=1, le=65535, description="Port inside the container")
    publish_port: int | None = Field(default=None, ge=1, le=65535)
    banner: str | None = None
    vulns: list[VulnSpec] = Field(default_factory=list)
    options: dict[str, Any] = Field(default_factory=dict)


class CompanionSpec(_Model):
    """A generated fake partner/upstream server that receives the decoy's outbound flows."""

    name: str = Field(pattern=SLUG)
    emulator: str
    protocol: Protocol
    listen_port: int = Field(ge=1024, le=65535)
    options: dict[str, Any] = Field(default_factory=dict)


class OutboundFlow(_Model):
    name: str = Field(pattern=SLUG)
    protocol: Protocol
    target: str = Field(description="Companion name or an allowlisted public host")
    port: int = Field(ge=1, le=65535)
    interval_seconds: int = Field(ge=10)
    jitter_pct: int = Field(default=20, ge=0, le=90)
    payload_profile: str = Field(description="Content generator id, e.g. 'model-pull'")
    signal: str | None = Field(default=None, description="Id of the signal this flow embodies")


class SignalScope(StrEnum):
    INTERNET = "internet"
    ON_PATH = "on-path"
    L2 = "L2"


class SignalKind(StrEnum):
    # internet-observable
    CT_CERTIFICATE = "ct-certificate"
    DNS_RECORDS = "dns-records"
    HONEYTOKEN_LEAK = "honeytoken-leak"
    P2P_NODE = "p2p-node"
    FEDERATION = "federation"
    INDEXED_ARTIFACT = "indexed-artifact"
    # on-path / network-wide
    CLEARTEXT_AUTH = "cleartext-auth"
    AI_TRAFFIC = "ai-traffic"
    FINANCE_TRAFFIC = "finance-traffic"
    HEALTHCARE_TRAFFIC = "healthcare-traffic"
    BACKUP_TRAFFIC = "backup-traffic"
    DEVOPS_TRAFFIC = "devops-traffic"
    IDENTITY_TRAFFIC = "identity-traffic"
    OPS_TELEMETRY = "ops-telemetry"
    ICS_TRAFFIC = "ics-traffic"
    # L2 broadcast / multicast
    NAME_RESOLUTION_BAIT = "name-resolution-bait"
    SERVICE_ADVERTISEMENT = "service-advertisement"
    IDENTITY_LEAK = "identity-leak"


SIGNAL_SCOPES: dict[SignalKind, frozenset[SignalScope]] = {
    SignalKind.CT_CERTIFICATE: frozenset({SignalScope.INTERNET}),
    SignalKind.DNS_RECORDS: frozenset({SignalScope.INTERNET, SignalScope.ON_PATH}),
    SignalKind.HONEYTOKEN_LEAK: frozenset({SignalScope.INTERNET, SignalScope.ON_PATH}),
    SignalKind.P2P_NODE: frozenset({SignalScope.INTERNET}),
    SignalKind.FEDERATION: frozenset({SignalScope.INTERNET}),
    SignalKind.INDEXED_ARTIFACT: frozenset({SignalScope.INTERNET}),
    SignalKind.CLEARTEXT_AUTH: frozenset({SignalScope.ON_PATH}),
    SignalKind.AI_TRAFFIC: frozenset({SignalScope.ON_PATH}),
    SignalKind.FINANCE_TRAFFIC: frozenset({SignalScope.ON_PATH}),
    SignalKind.HEALTHCARE_TRAFFIC: frozenset({SignalScope.ON_PATH}),
    SignalKind.BACKUP_TRAFFIC: frozenset({SignalScope.ON_PATH}),
    SignalKind.DEVOPS_TRAFFIC: frozenset({SignalScope.ON_PATH}),
    SignalKind.IDENTITY_TRAFFIC: frozenset({SignalScope.ON_PATH}),
    SignalKind.OPS_TELEMETRY: frozenset({SignalScope.ON_PATH}),
    SignalKind.ICS_TRAFFIC: frozenset({SignalScope.ON_PATH}),
    SignalKind.NAME_RESOLUTION_BAIT: frozenset({SignalScope.L2}),
    SignalKind.SERVICE_ADVERTISEMENT: frozenset({SignalScope.L2}),
    SignalKind.IDENTITY_LEAK: frozenset({SignalScope.L2}),
}


def new_tag() -> str:
    return "sig-" + secrets.token_hex(4)


class SignalSpec(_Model):
    """An active emission that advertises the honeypot's value. The tag is embedded in
    whatever the signal emits (hostname, canary, advertised name) so inbound contact can
    be attributed to the signal that drew it."""

    id: str = Field(pattern=SLUG)
    kind: SignalKind
    scope: SignalScope
    enabled: bool = True
    tag: str = Field(default_factory=new_tag, pattern=r"^sig-[a-z0-9]{4,32}$")
    params: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _scope_matches_kind(self) -> SignalSpec:
        allowed = SIGNAL_SCOPES[SignalKind(self.kind)]
        if SignalScope(self.scope) not in allowed:
            names = ", ".join(sorted(s.value for s in allowed))
            raise ValueError(f"signal kind {self.kind!r} cannot have scope {self.scope!r} (allowed: {names})")
        return self


class Persona(_Model):
    org_name: str = Field(description="Fictional organisation name; never a real brand")
    role: str = Field(description="What this host is, e.g. 'ML inference gateway'")
    description: str = ""
    hostname: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{0,252}$")
    public_hostnames: list[str] = Field(default_factory=list, description="Names used by internet-scope signals")
    os_fingerprint: str = "Ubuntu 22.04"


class EgressPolicy(_Model):
    decoy_allow: list[str] = Field(default_factory=list, description="Public hosts decoy flows may reach")
    controller_allow: list[str] = Field(default_factory=lambda: ["api.anthropic.com"])


class TelemetryMode(StrEnum):
    HTTPS = "https"
    SYSLOG = "syslog"


class TelemetrySpec(_Model):
    mode: TelemetryMode = TelemetryMode.HTTPS
    endpoint: str = Field(description="https://collector/... or syslog+tls://host:port")
    ca_secret: str = "collector_ca"
    client_cert_secret: str = "collector_client_cert"
    client_key_secret: str = "collector_client_key"
    heartbeat_seconds: int = Field(default=60, ge=10)


class Budget(_Model):
    daily_usd: float = Field(default=5.0, gt=0)
    daily_tokens: int = Field(default=2_000_000, gt=0)
    per_source_rpm: int = Field(default=20, gt=0)
    latency_ms: int = Field(default=2500, gt=0)


class ModelConfig(_Model):
    build: str = "claude-opus-5-5"
    runtime: str = "claude-haiku-5-5"
    director: str = "claude-sonnet-5-5"


class NetworkMode(StrEnum):
    BRIDGE = "bridge"
    MACVLAN = "macvlan"
    IPVLAN = "ipvlan"


class NetworkSpec(_Model):
    mode: NetworkMode = NetworkMode.BRIDGE
    parent_interface: str | None = None
    subnet: str | None = None
    gateway: str | None = None
    ip_address: str | None = None

    @model_validator(mode="after")
    def _l2_needs_parent(self) -> NetworkSpec:
        if self.mode != NetworkMode.BRIDGE and not (self.parent_interface and self.subnet):
            raise ValueError(f"network mode {self.mode!r} requires parent_interface and subnet")
        return self


class HoneypotSpec(_Model):
    version: Literal[1] = 1
    name: str = Field(pattern=SLUG)
    archetype: Archetype
    experiment_arm: Literal["active", "passive"] = "active"
    persona: Persona
    services: list[ServiceSpec] = Field(min_length=1)
    companions: list[CompanionSpec] = Field(default_factory=list)
    outbound: list[OutboundFlow] = Field(default_factory=list)
    signals: list[SignalSpec] = Field(default_factory=list)
    egress: EgressPolicy = Field(default_factory=EgressPolicy)
    telemetry: TelemetrySpec
    budget: Budget = Field(default_factory=Budget)
    models: ModelConfig = Field(default_factory=ModelConfig)
    network: NetworkSpec = Field(default_factory=NetworkSpec)

    def passive_twin(self) -> HoneypotSpec:
        """Identical honeypot with every active signal (and the flows embodying them)
        disabled: the control arm of the active-vs-passive experiment."""
        twin = self.model_copy(deep=True)
        twin.name = f"{self.name[:32]}-passive"
        twin.experiment_arm = "passive"
        for sig in twin.signals:
            sig.enabled = False
        twin.outbound = [f for f in twin.outbound if f.signal is None]
        return twin
