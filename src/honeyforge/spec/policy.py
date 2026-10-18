"""Policy checks a spec must pass before it can be rendered or built. Schema validation
(models.py) catches malformed specs; this module catches well-formed specs that would
produce an unsafe or unsound honeypot."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from honeyforge.canary.modules import MAX_TCPBANNERS, MODULES
from honeyforge.spec.models import HoneypotSpec, NetworkMode, SignalKind, SignalScope

# Option/param keys that would imply real execution or passthrough of attacker input.
FORBIDDEN_KEYS = {"exec", "command", "shell_path", "real_shell", "passthrough", "proxy_to", "eval", "subprocess"}

# Shapes of real credentials. Canaries are minted at build time, so none belong in a spec.
SECRET_PATTERNS = {
    "anthropic-key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "openai-key": re.compile(r"sk-(proj-)?[A-Za-z0-9]{32,}"),
    "aws-access-key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "private-key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "slack-token": re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b"),
}

# Public signals must not impersonate real organisations. Not exhaustive: a tripwire
# for obvious cases, reviewed by a human alongside the spec. Distinctive names match as
# substrings ("jpmorganchase"); short or dictionary-like names only as whole tokens, so
# "metadata" or "swiftly" don't trip.
BRAND_SUBSTRINGS = {
    "anthropic", "openai", "google", "microsoft", "nvidia", "huggingface", "jpmorgan",
    "goldman", "wellsfargo", "bankofamerica", "mastercard", "paypal", "coinbase", "binance",
    "moveit", "goanywhere", "kiteworks", "accellion", "citrix",
}
BRAND_TOKENS = {
    "amazon", "aws", "azure", "meta", "chase", "citi", "citibank", "swift", "visa", "stripe",
    "fortra", "okta", "progress",
}

HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PRIVILEGED_PORT = 1024
PLACEHOLDER_TLDS = {"example", "test", "invalid", "localhost"}


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class Finding:
    severity: Severity
    code: str
    message: str

    def __str__(self) -> str:
        return f"[{self.severity}] {self.code}: {self.message}"


def check_policy(spec: HoneypotSpec) -> list[Finding]:
    findings: list[Finding] = []
    for check in (_check_services, _check_modules, _check_egress, _check_outbound, _check_signals,
                  _check_secrets, _check_brands, _check_telemetry):
        findings.extend(check(spec))
    return findings


def has_errors(findings: list[Finding]) -> bool:
    return any(f.severity == Severity.ERROR for f in findings)


def _err(code: str, msg: str) -> Finding:
    return Finding(Severity.ERROR, code, msg)


def _warn(code: str, msg: str) -> Finding:
    return Finding(Severity.WARNING, code, msg)


def _walk_keys(obj: Any, path: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield f"{path}.{k}" if path else str(k), k
            yield from _walk_keys(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_keys(v, f"{path}[{i}]")


def _walk_strings(obj: Any, path: str = ""):
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")


def _check_services(spec: HoneypotSpec) -> list[Finding]:
    out: list[Finding] = []
    names = Counter(s.name for s in spec.services) + Counter(c.name for c in spec.companions)
    for name, n in names.items():
        if n > 1:
            out.append(_err("duplicate-name", f"service/companion name {name!r} used {n} times"))

    published = Counter(s.publish_port for s in spec.services if s.publish_port)
    for port, n in published.items():
        if n > 1:
            out.append(_err("duplicate-publish-port", f"publish port {port} used by {n} services"))
    listen = Counter(s.listen_port for s in spec.services)
    for port, n in listen.items():
        if n > 1:
            out.append(_err("duplicate-listen-port", f"listen port {port} used by {n} services"))

    for svc in spec.services:
        if svc.listen_port < PRIVILEGED_PORT:
            out.append(_err("privileged-listen-port",
                            f"{svc.name}: listen_port {svc.listen_port} needs CAP_NET_BIND_SERVICE; "
                            "listen high and set publish_port instead"))
        for path, key in _walk_keys({"options": svc.options, "vulns": [v.params for v in svc.vulns]}):
            if str(key).lower() in FORBIDDEN_KEYS:
                out.append(_err("real-execution", f"{svc.name}: {path} implies real execution/passthrough"))
    return out


def _check_modules(spec: HoneypotSpec) -> list[Finding]:
    out: list[Finding] = []
    used = Counter(s.emulator for s in spec.services)
    for svc in spec.services:
        module = MODULES.get(svc.emulator)
        if module is None:
            out.append(_err("unknown-emulator", f"{svc.name}: emulator {svc.emulator!r} is not a supported "
                            f"OpenCanary module ({', '.join(sorted(MODULES))})"))
            continue
        for key in sorted(set(svc.options) - module.options):
            out.append(_err("unknown-option", f"{svc.name}: option {key!r} is not valid for module {module.name!r}"))
        if svc.vulns:
            out.append(_warn("vulns-descriptive", f"{svc.name}: OpenCanary is low-interaction and logs attempts "
                             "without granting access; declared vulns are descriptive only"))
    for name, n in used.items():
        module = MODULES.get(name)
        if module and not module.multi and n > 1:
            out.append(_err("duplicate-module", f"module {name!r} can only back one service (used {n} times)"))
        if module and module.multi and n > MAX_TCPBANNERS:
            out.append(_err("too-many-tcpbanners", f"at most {MAX_TCPBANNERS} tcpbanner services (got {n})"))
    banners = [s for s in spec.services if s.emulator in ("http", "https") and s.banner]
    if len({s.banner for s in banners}) > 1:
        out.append(_warn("shared-http-banner", "http and https share one Server banner in OpenCanary; "
                         f"using {banners[0].banner!r}"))
    return out


def _is_bad_egress(host: str) -> str | None:
    if "*" in host:
        return "wildcards are not allowed"
    try:
        net = ipaddress.ip_network(host, strict=False)
    except ValueError:
        pass
    else:
        if net.num_addresses > 1:
            return "address ranges are not allowed"
        return None
    if not HOSTNAME.match(host):
        return "not a fully-qualified hostname"
    return None


def _check_egress(spec: HoneypotSpec) -> list[Finding]:
    out: list[Finding] = []
    for field, hosts in (("decoy_allow", spec.egress.decoy_allow), ("controller_allow", spec.egress.controller_allow)):
        for host in hosts:
            if reason := _is_bad_egress(host):
                out.append(_err("egress-too-broad", f"egress.{field}: {host!r}: {reason}"))
    extra = set(spec.egress.controller_allow) - {"api.anthropic.com"}
    if extra:
        out.append(_warn("controller-egress", f"controller may reach more than the Claude API: {sorted(extra)}"))
    return out


def _check_outbound(spec: HoneypotSpec) -> list[Finding]:
    out: list[Finding] = []
    companions = {c.name for c in spec.companions}
    allowed = set(spec.egress.decoy_allow)
    signal_ids = {s.id for s in spec.signals}
    for flow in spec.outbound:
        if flow.target not in companions and flow.target not in allowed:
            out.append(_err("outbound-not-allowed",
                            f"flow {flow.name!r} targets {flow.target!r}, which is neither a companion "
                            "nor in egress.decoy_allow"))
        if flow.signal and flow.signal not in signal_ids:
            out.append(_err("unknown-signal", f"flow {flow.name!r} references unknown signal {flow.signal!r}"))
    return out


def _check_signals(spec: HoneypotSpec) -> list[Finding]:
    out: list[Finding] = []
    for field in ("id", "tag"):
        counts = Counter(getattr(s, field) for s in spec.signals)
        for value, n in counts.items():
            if n > 1:
                out.append(_err(f"duplicate-signal-{field}", f"signal {field} {value!r} used {n} times"))

    enabled = [s for s in spec.signals if s.enabled]
    if spec.experiment_arm == "passive" and enabled:
        out.append(_err("passive-arm-signals", f"passive arm has enabled signals: {[s.id for s in enabled]}"))
    if spec.experiment_arm == "active" and spec.signals and not enabled:
        out.append(_warn("no-active-signals", "active arm has signals defined but none enabled"))

    for sig in enabled:
        if sig.scope == SignalScope.L2 and spec.network.mode == NetworkMode.BRIDGE:
            out.append(_err("l2-needs-macvlan",
                            f"signal {sig.id!r} is L2-scoped but network.mode is bridge; broadcasts "
                            "will not leave the Docker host (use macvlan/ipvlan on a Linux host)"))
        if sig.kind in (SignalKind.CT_CERTIFICATE, SignalKind.DNS_RECORDS) and not spec.persona.public_hostnames:
            out.append(_err("signal-needs-hostnames", f"signal {sig.id!r} needs persona.public_hostnames"))
        if sig.kind == SignalKind.HONEYTOKEN_LEAK and not sig.params.get("destinations"):
            out.append(_warn("honeytoken-no-destination", f"signal {sig.id!r} has no params.destinations"))
    return out


def _check_secrets(spec: HoneypotSpec) -> list[Finding]:
    out: list[Finding] = []
    for path, value in _walk_strings(spec.model_dump(mode="json")):
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(value):
                out.append(_err("secret-in-spec", f"{path} looks like a real {label}; specs must not contain "
                                "secrets (canaries are minted at build time)"))
    return out


def _check_brands(spec: HoneypotSpec) -> list[Finding]:
    out: list[Finding] = []
    p = spec.persona
    public = [("persona.org_name", p.org_name), ("persona.hostname", p.hostname)]
    public += [(f"persona.public_hostnames[{i}]", h) for i, h in enumerate(p.public_hostnames)]
    for path, value in public:
        lowered = value.lower()
        squashed = re.sub(r"[^a-z0-9]", "", lowered)
        tokens = set(re.split(r"[^a-z0-9]+", lowered))
        hits = sorted({b for b in BRAND_SUBSTRINGS if b in squashed} | (BRAND_TOKENS & tokens))
        if hits:
            out.append(_err("real-brand", f"{path} {value!r} resembles real organisation(s) {hits}; "
                            "personas must be fictional"))
    for i, h in enumerate(p.public_hostnames):
        if not HOSTNAME.match(h):
            out.append(_err("bad-hostname", f"persona.public_hostnames[{i}] {h!r} is not a valid FQDN"))

    needs_real_dns = any(s.enabled and s.kind in (SignalKind.CT_CERTIFICATE, SignalKind.DNS_RECORDS)
                         for s in spec.signals)
    placeholders = [h for h in p.public_hostnames if h.rsplit(".", 1)[-1] in PLACEHOLDER_TLDS]
    if needs_real_dns and placeholders:
        out.append(_warn("placeholder-domain", f"public hostnames {placeholders} use a reserved TLD; replace "
                         "with a domain you control before deploying CT/DNS signals"))
    return out


def _check_telemetry(spec: HoneypotSpec) -> list[Finding]:
    t = spec.telemetry
    want = "https://" if t.mode == "https" else "syslog+tls://"
    if not t.endpoint.startswith(want):
        return [_err("telemetry-insecure", f"telemetry.endpoint must start with {want!r} for mode {t.mode!r}")]
    return []
