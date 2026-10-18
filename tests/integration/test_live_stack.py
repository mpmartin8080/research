"""Builds and runs a real honeypot stack. Opt-in: HONEYFORGE_INTEGRATION=1 pytest tests/integration

Uses the ai-tools archetype with publish ports shifted by +20000 to avoid clashing with
services on the host."""

import json
import os
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from honeyforge.builder import docker
from honeyforge.events import parse_line
from honeyforge.render import DEFAULT_NETGUARD_IMAGE, render_project
from honeyforge.spec.loader import load_archetype

pytestmark = pytest.mark.skipif(os.environ.get("HONEYFORGE_INTEGRATION") != "1",
                                reason="set HONEYFORGE_INTEGRATION=1 to run against local Docker")
OFFSET = 20000
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}  # stop Git Bash rewriting container paths


def _exec(container: str, code: str) -> str:
    out = subprocess.run(["docker", "exec", container, "/opt/venv/bin/python", "-c", code],
                         capture_output=True, text=True, env=ENV, timeout=60)
    return out.stdout + out.stderr


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    spec = load_archetype("ai-tools")
    spec.name = "hf-itest"
    for svc in spec.services:
        svc.publish_port += OFFSET
    out = tmp_path_factory.mktemp("stack")
    render_project(spec, out, base_image=docker.pin_digest("python:3.12-slim-bookworm"),
                   netguard_base=docker.pin_digest(DEFAULT_NETGUARD_IMAGE))
    docker.compose(out, "up", "--build", "--detach", "--wait")
    try:
        yield spec, out
    finally:
        docker.compose(out, "down", "--volumes")


def _port(spec, name):
    return next(s.publish_port for s in spec.services if s.name == name)


def test_services_answer(stack):
    spec, _ = stack
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with urllib.request.urlopen(f"https://127.0.0.1:{_port(spec, 'gateway')}/index.html", context=ctx) as r:
        assert r.status == 200 and r.headers["Server"] == "nginx/1.24.0"
        assert b"Corvane Labs" in r.read()
    with socket.create_connection(("127.0.0.1", _port(spec, "ssh")), 5) as s:
        assert s.recv(64).startswith(b"SSH-2.0-OpenSSH_8.9p1")


def test_cert_has_persona_subject(stack):
    spec, _ = stack
    pem = ssl.get_server_certificate(("127.0.0.1", _port(spec, "gateway")))
    out = subprocess.run(["openssl", "x509", "-noout", "-subject"], input=pem, capture_output=True, text=True)
    assert "Corvane Labs" in out.stdout and "Synology" not in out.stdout


def test_login_attempt_becomes_event(stack):
    spec, out = stack
    req = urllib.request.Request(f"http://127.0.0.1:{_port(spec, 'mlflow')}/index.html",
                                 data=b"username=itest&password=itest-pw", headers={"User-Agent": "itest/1"})
    urllib.request.urlopen(req).read()
    for _ in range(10):
        logs = docker.compose(out, "logs", "--no-color", "--no-log-prefix", "decoy", capture=True)
        events = [e for e in map(lambda l: parse_line(l, spec), logs.splitlines()) if e]
        hits = [e for e in events if e.kind == "http.login-attempt" and e.data.get("USERNAME") == "itest"]
        if hits:
            assert hits[0].service == "mlflow" and hits[0].arm == "active"
            return
        time.sleep(1)
    pytest.fail("login attempt never appeared in events")


def test_decoy_is_unprivileged_and_readonly(stack):
    out = _exec(f"hf-{stack[0].name}-decoy-1", """
import os
caps = [l.split()[1] for l in open('/proc/self/status') if l.startswith('CapEff')][0]
try:
    open('/opt/venv/x', 'w'); ro = False
except OSError:
    ro = True
print(os.getuid(), caps, ro)
""")
    assert out.split() == ["10001", "0000000000000000", "True"]


@pytest.mark.parametrize("host,port", [("1.1.1.1", 443), ("8.8.8.8", 53)])
def test_decoy_cannot_egress(stack, host, port):
    out = _exec(f"hf-{stack[0].name}-decoy-1", f"""
import socket
try:
    socket.create_connection(({host!r}, {port}), 4); print('OPEN')
except OSError:
    print('BLOCKED')
""")
    assert out.strip() == "BLOCKED"


def test_netguard_dropped_privileges(stack):
    out = subprocess.run(["docker", "exec", f"hf-{stack[0].name}-netguard-1", "grep", "-E",
                          "^(Uid|CapEff|CapBnd)", "/proc/1/status"], capture_output=True, text=True, env=ENV)
    fields = {line.split(":")[0]: line.split()[1] for line in out.stdout.splitlines()}
    assert fields == {"Uid": "65534", "CapEff": "0000000000000000", "CapBnd": "0000000000000000"}


def test_no_docker_socket_or_secrets(stack):
    inspect = json.loads(subprocess.run(["docker", "inspect", f"hf-{stack[0].name}-decoy-1"],
                                        capture_output=True, text=True).stdout)[0]
    assert not any("docker.sock" in m.get("Source", "") for m in inspect["Mounts"])
    assert not any(k.startswith(("ANTHROPIC", "AWS_", "OPENAI")) for k in
                   (e.split("=", 1)[0] for e in inspect["Config"]["Env"]))
