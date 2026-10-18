import json

import pytest
import yaml

from honeyforge.canary.config import SSH_KEY_DIR, TLS_CERT, build_config
from honeyforge.events import parse_line
from honeyforge.render import render_project
from honeyforge.spec.loader import load_archetype, load_spec


@pytest.fixture
def ai():
    return load_archetype("ai-tools")


def test_config_enables_only_spec_services(ai):
    conf = build_config(ai)
    enabled = {k.removesuffix(".enabled") for k, v in conf.items() if k.endswith(".enabled") and v}
    assert enabled == {"https", "http", "tcpbanner", "tcpbanner_1", "tcpbanner_2", "redis", "ssh"}
    for off in ("portscan", "smb", "snmp", "llmnr", "ftp", "telnet"):
        assert conf[f"{off}.enabled"] is False


def test_config_ports_banners_and_keys(ai):
    conf = build_config(ai)
    assert conf["https.port"] == 8443 and conf["ssh.port"] == 2222
    assert conf["tcpbanner_1.port"] == 11434 and conf["tcpbanner_2.port"] == 8888
    assert conf["tcpbanner_1.datareceivedbanner"].endswith("Ollama is running")
    assert conf["ssh.version"].startswith("SSH-2.0-OpenSSH_8.9p1")
    assert conf["http.banner"] == "nginx/1.24.0"
    assert conf["https.skin"] == "hf-gateway" and conf["http.skin"] == "hf-mlflow"
    assert conf["https.certificate"] == TLS_CERT and conf["ssh.key_path"] == SSH_KEY_DIR
    assert conf["https.domain_name"] == "infer.corvane-labs.example"
    assert conf["device.node_id"] == ai.name


def test_render_writes_context(ai, tmp_path):
    compose_file = render_project(ai, tmp_path)
    for name in ("Dockerfile", "opencanary.conf", "requirements.txt", "keygen.py", "spec.lock.yaml",
                 "netguard/Dockerfile", "netguard/netguard.sh",
                 *(f"skins/{s}/{p}" for s in ("hf-gateway", "hf-mlflow")
                   for p in ("index.html", "redirect.html", "400.html", "403.html", "404.html"))):
        assert (tmp_path / name).is_file(), name
    json.loads((tmp_path / "opencanary.conf").read_text())
    assert load_spec(tmp_path / "spec.lock.yaml").signals[0].tag == ai.signals[0].tag
    skin = (tmp_path / "skins/hf-gateway/index.html").read_text()
    assert "Inference Gateway Console" in skin and "Corvane Labs" in skin
    assert "<!--STARTERR-->" in skin and 'name="username"' in skin and 'name="password"' in skin
    assert compose_file.name == "compose.yaml"


def test_dockerfile_hardening(ai, tmp_path):
    render_project(ai, tmp_path, base_image="python@sha256:" + "0" * 64)
    df = (tmp_path / "Dockerfile").read_text()
    assert df.count("FROM python@sha256:") == 2
    assert "USER 10001:10001" in df
    assert "'Corvane Labs'" in df  # shell-quoted org for keygen
    assert "$PATH" in df and "$$" not in df


def test_compose_hardening(ai, tmp_path):
    compose = yaml.safe_load((render_project(ai, tmp_path)).read_text())
    decoy = compose["services"]["decoy"]
    assert decoy["read_only"] is True
    assert decoy["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in decoy["security_opt"]
    assert decoy["pids_limit"] and decoy["mem_limit"] and decoy["cpus"]
    assert "privileged" not in decoy and "cap_add" not in decoy
    assert not any("docker.sock" in v for v in decoy["volumes"])
    assert decoy["labels"]["io.honeyforge.arm"] == "active"
    # decoy shares netguard's namespace: no ports/networks of its own
    assert decoy["network_mode"] == "service:netguard"
    assert "ports" not in decoy and "networks" not in decoy

    guard = compose["services"]["netguard"]
    assert "443:8443/tcp" in guard["ports"] and "22:2222/tcp" in guard["ports"]
    assert guard["cap_drop"] == ["ALL"]
    assert set(guard["cap_add"]) == {"NET_ADMIN", "SETUID", "SETGID", "SETPCAP"}
    assert guard["read_only"] is True and "no-new-privileges:true" in guard["security_opt"]
    assert guard["hostname"] == ai.persona.hostname


def test_netguard_script(ai, tmp_path):
    render_project(ai, tmp_path)
    script = (tmp_path / "netguard" / "netguard.sh").read_bytes()
    assert b"\r\n" not in script
    assert b"-P OUTPUT DROP" in script and b"ESTABLISHED,RELATED" in script
    assert b"--bounding-set=-all" in script


def test_render_refuses_policy_failures(ai, tmp_path):
    ai.egress.decoy_allow.append("*")
    with pytest.raises(ValueError, match="egress-too-broad"):
        render_project(ai, tmp_path)


def test_render_udp_ports(ai, tmp_path):
    from honeyforge.spec.models import ServiceSpec
    ai.services.append(ServiceSpec(name="ntp", emulator="ntp", protocol="ntp", listen_port=1123, publish_port=123))
    compose = yaml.safe_load(render_project(ai, tmp_path).read_text())
    assert "123:1123/udp" in compose["services"]["netguard"]["ports"]


def test_passive_twin_renders_same_services(ai, tmp_path):
    a = build_config(ai)
    p = build_config(ai.passive_twin())
    a.pop("device.node_id"), p.pop("device.node_id")
    assert a == p


SSH_LINE = ('{"dst_host": "172.18.0.2", "dst_port": 2222, "local_time": "2026-10-17 12:00:00.123456", '
            '"local_time_adjusted": "2026-10-17 12:00:00.123456", "logdata": {"USERNAME": "root", '
            '"PASSWORD": "toor"}, "logtype": 4002, "node_id": "ai-gateway", "src_host": "203.0.113.9", '
            '"src_port": 51234, "utc_time": "2026-10-17 12:00:00.123456"}')


def test_parse_event(ai):
    ev = parse_line(SSH_LINE, ai)
    assert ev.kind == "ssh.login-attempt" and ev.service == "ssh"
    assert ev.src_host == "203.0.113.9" and ev.src_port == 51234
    assert ev.arm == "active" and ev.is_interaction
    assert ev.data["USERNAME"] == "root"
    assert ev.ts.year == 2026 and ev.ts.tzinfo is not None


@pytest.mark.parametrize("line", ["", "2026-10-17 [-] Loading opencanary.tac", "{not json", "[1, 2]", '{"a": 1}'])
def test_parse_ignores_noise(ai, line):
    assert parse_line(line, ai) is None
