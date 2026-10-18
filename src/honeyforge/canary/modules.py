"""The OpenCanary modules a spec service may use, and the config keys each accepts.

Keys mirror opencanary/data/settings.json for the pinned OpenCanary version. Modules
that need root or raw sockets in the container (portscan, smb, snmp, llmnr) are not
offered as services."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class Module:
    name: str
    transport: Literal["tcp", "udp"]
    banner_key: str | None = None  # where ServiceSpec.banner is written
    options: frozenset[str] = field(default_factory=frozenset)
    multi: bool = False  # tcpbanner supports numbered instances


_MODULES = [
    Module("ftp", "tcp", "banner", frozenset({"log_auth_attempt_initiated"})),
    Module("http", "tcp", "banner", frozenset({"skin", "log_unimplemented_method_requests", "log_redirect_request"})),
    # https shares http.banner; the renderer handles that.
    Module("https", "tcp", None, frozenset({"skin", "domain_name"})),
    Module("httpproxy", "tcp", None, frozenset({"skin"})),
    Module("ssh", "tcp", "version", frozenset({"preauth_banner"})),
    Module("telnet", "tcp", "banner", frozenset({"honeycreds", "log_tcp_connection", "max_connections", "timeout"})),
    Module("mysql", "tcp", "banner", frozenset({"log_connection_made"})),
    Module("mssql", "tcp", "version"),
    Module("mongodb", "tcp", "version"),
    Module("redis", "tcp", None, frozenset({"max_arg_length", "timeout", "max_connections"})),
    Module("rdp", "tcp"),
    Module("vnc", "tcp"),
    Module("git", "tcp", None, frozenset({"max_connections", "timeout"})),
    Module("sip", "udp"),
    Module("ntp", "udp"),
    Module("tftp", "udp"),
    Module("tcpbanner", "tcp", "initbanner",
           frozenset({"initbanner", "datareceivedbanner", "alertstring", "alertstring.enabled",
                      "keep_alive.enabled", "keep_alive_secret", "keep_alive_probes",
                      "keep_alive_interval", "keep_alive_idle"}),
           multi=True),
]

MODULES: dict[str, Module] = {m.name: m for m in _MODULES}
MAX_TCPBANNERS = 10

# OpenCanary logtype codes (opencanary/logger.py) -> stable names for normalised events.
LOGTYPES: dict[int, str] = {
    1000: "boot", 1001: "msg", 1002: "debug", 1003: "error", 1004: "ping", 1005: "config-save",
    2000: "ftp.login-attempt", 2001: "ftp.auth-initiated",
    3000: "http.get", 3001: "http.login-attempt", 3002: "http.unimplemented-method", 3003: "http.redirect",
    4000: "ssh.new-connection", 4001: "ssh.remote-version", 4002: "ssh.login-attempt",
    5000: "smb.file-open", 5001: "portscan.syn", 5002: "portscan.nmap-os", 5003: "portscan.nmap-null",
    5004: "portscan.nmap-xmas", 5005: "portscan.nmap-fin",
    6001: "telnet.login-attempt", 6002: "telnet.connection",
    7001: "httpproxy.login-attempt",
    8001: "mysql.login-attempt", 9003: "mysql.connection",
    9001: "mssql.login-sql", 9002: "mssql.login-windows",
    10001: "tftp.request", 11001: "ntp.monlist", 12001: "vnc.auth", 13001: "snmp.command",
    14001: "rdp.connection", 15001: "sip.request", 16001: "git.clone",
    17001: "redis.command",
    18001: "tcpbanner.connection", 18002: "tcpbanner.keepalive-connection",
    18003: "tcpbanner.keepalive-secret", 18004: "tcpbanner.keepalive-data", 18005: "tcpbanner.data",
    19001: "llmnr.response", 20001: "mongodb.login-attempt",
}
