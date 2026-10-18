"""Translate a HoneypotSpec into an opencanary.conf dictionary."""

from __future__ import annotations

from typing import Any

from honeyforge.canary.modules import MAX_TCPBANNERS, MODULES
from honeyforge.spec.models import HoneypotSpec, ServiceSpec

# Paths inside the decoy image (see render/project.py Dockerfile).
SSH_KEY_DIR = "/etc/honeyforge/ssh"
TLS_CERT = "/etc/honeyforge/tls/cert.pem"
TLS_KEY = "/etc/honeyforge/tls/key.pem"
EVENT_LOG = "/var/log/honeyforge/opencanary.jsonl"

# Modules never enabled by HoneyForge, explicitly disabled so OpenCanary defaults can't leak in.
ALWAYS_OFF = ("portscan", "smb", "snmp", "llmnr")


def skin_name(svc: ServiceSpec) -> str:
    return f"hf-{svc.name}"


def tls_hostname(spec: HoneypotSpec) -> str:
    return spec.persona.public_hostnames[0] if spec.persona.public_hostnames else spec.persona.hostname


def service_prefixes(spec: HoneypotSpec) -> dict[str, str]:
    """Service name -> OpenCanary key prefix (tcpbanner services get tcpbanner_N)."""
    out, n = {}, 0
    for svc in spec.services:
        if MODULES[svc.emulator].multi:
            n += 1
            out[svc.name] = f"tcpbanner_{n}"
        else:
            out[svc.name] = svc.emulator
    return out


def build_config(spec: HoneypotSpec) -> dict[str, Any]:
    conf: dict[str, Any] = {
        "device.node_id": spec.name,
        "device.listen_addr": "",
        "ip.ignorelist": [],
        "logtype.ignorelist": [],
    }
    for name in [*MODULES, *ALWAYS_OFF]:
        conf[f"{name}.enabled"] = False
    conf["tcpbanner.maxnum"] = MAX_TCPBANNERS

    prefixes = service_prefixes(spec)
    for svc in spec.services:
        module = MODULES[svc.emulator]
        prefix = prefixes[svc.name]
        if module.multi:
            conf["tcpbanner.enabled"] = True
        conf[f"{prefix}.enabled"] = True
        conf[f"{prefix}.port"] = svc.listen_port
        if svc.banner and module.banner_key:
            conf[f"{prefix}.{module.banner_key}"] = svc.banner

        if module.name in ("http", "https"):
            conf[f"{prefix}.skin"] = skin_name(svc)
            if svc.banner:
                conf.setdefault("http.banner", svc.banner)
        if module.name == "https":
            conf["https.domain_name"] = tls_hostname(spec)
            conf["https.certificate"] = TLS_CERT
            conf["https.key"] = TLS_KEY
        if module.name == "ssh":
            conf["ssh.key_path"] = SSH_KEY_DIR

        for key, value in svc.options.items():
            conf[f"{prefix}.{key}"] = value

    conf["logger"] = {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {"plain": {"format": "%(message)s"}},
            "handlers": {
                "console": {"class": "logging.StreamHandler", "stream": "ext://sys.stdout",
                            "formatter": "plain"},
                "file": {"class": "logging.FileHandler", "filename": EVENT_LOG, "formatter": "plain"},
            },
        },
    }
    return conf
