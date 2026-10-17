import pytest
from pydantic import ValidationError

from honeyforge.spec import check_policy, dump_spec, load_spec
from honeyforge.spec.loader import archetype_names, load_archetype
from honeyforge.spec.models import SignalSpec
from honeyforge.spec.policy import Severity, has_errors


def codes(spec):
    return {f.code for f in check_policy(spec) if f.severity == Severity.ERROR}


@pytest.fixture
def ai():
    return load_archetype("ai-tools")


@pytest.mark.parametrize("name", archetype_names())
def test_archetypes_pass_policy(name):
    assert not has_errors(check_policy(load_archetype(name)))


def test_archetypes_present():
    assert {"ai-tools", "financial", "mft-hub"} <= set(archetype_names())


def test_tags_minted_unique_per_load():
    a, b = load_archetype("ai-tools"), load_archetype("ai-tools")
    tags_a = {s.tag for s in a.signals}
    assert len(tags_a) == len(a.signals)
    assert tags_a.isdisjoint({s.tag for s in b.signals})


def test_roundtrip_preserves_tags(ai, tmp_path):
    path = tmp_path / "spec.yaml"
    dump_spec(ai, path)
    again = load_spec(path)
    assert [s.tag for s in again.signals] == [s.tag for s in ai.signals]


def test_vuln_cannot_be_real():
    with pytest.raises(ValidationError):
        load_archetype("ai-tools").services[0].vulns[0].__class__(kind="fake-shell", emulated=False)


def test_forbidden_execution_keys(ai):
    ai.services[0].options["passthrough"] = True
    ai.services[1].vulns[0].params["exec"] = "/bin/sh"
    assert "real-execution" in codes(ai)


def test_privileged_listen_port(ai):
    ai.services[0].listen_port = 443
    assert "privileged-listen-port" in codes(ai)


def test_duplicate_publish_port(ai):
    ai.services[1].publish_port = ai.services[0].publish_port
    assert "duplicate-publish-port" in codes(ai)


@pytest.mark.parametrize("host", ["*", "*.example.com", "0.0.0.0/0", "10.0.0.0/8", "localhost"])
def test_broad_egress_rejected(ai, host):
    ai.egress.decoy_allow.append(host)
    assert "egress-too-broad" in codes(ai)


def test_outbound_must_be_allowlisted(ai):
    ai.outbound[0].target = "evil.example.org"
    assert "outbound-not-allowed" in codes(ai)


def test_outbound_unknown_signal(ai):
    ai.outbound[0].signal = "nope"
    assert "unknown-signal" in codes(ai)


def test_signal_scope_must_match_kind():
    with pytest.raises(ValidationError):
        SignalSpec(id="x1", kind="ct-certificate", scope="L2")


def test_l2_signal_needs_macvlan(ai):
    l2 = next(s for s in ai.signals if s.scope == "L2")
    l2.enabled = True
    assert "l2-needs-macvlan" in codes(ai)


def test_l2_network_requires_parent():
    from honeyforge.spec.models import NetworkSpec
    with pytest.raises(ValidationError):
        NetworkSpec(mode="macvlan")


@pytest.mark.parametrize("secret", [
    "sk-ant-api03-" + "a" * 40,
    "AKIAABCDEFGHIJKLMNOP",
    "ghp_" + "b" * 36,
    "-----BEGIN OPENSSH PRIVATE KEY-----",
])
def test_secrets_rejected(ai, secret):
    ai.services[0].options["note"] = secret
    assert "secret-in-spec" in codes(ai)


@pytest.mark.parametrize("value,bad", [
    ("OpenAI Research", True),
    ("jpmorganchase-ops", True),
    ("Meta Platforms", True),
    ("Metadata Systems", False),
    ("Swiftly Freight", False),
])
def test_brand_tripwire(ai, value, bad):
    ai.persona.org_name = value
    assert ("real-brand" in codes(ai)) is bad


def test_placeholder_domain_warns(ai):
    warnings = {f.code for f in check_policy(ai) if f.severity == Severity.WARNING}
    assert "placeholder-domain" in warnings


def test_insecure_telemetry(ai):
    ai.telemetry.endpoint = "http://collector.example/ingest"
    assert "telemetry-insecure" in codes(ai)


def test_passive_twin(ai):
    twin = ai.passive_twin()
    assert twin.experiment_arm == "passive"
    assert twin.name.endswith("-passive")
    assert not any(s.enabled for s in twin.signals)
    assert all(f.signal is None for f in twin.outbound)
    assert [s.model_dump(exclude={"enabled"}) for s in twin.services] == \
           [s.model_dump(exclude={"enabled"}) for s in ai.services]
    assert any(f.signal for f in ai.outbound), "original must be untouched"
    assert not has_errors(check_policy(twin))


def test_passive_arm_with_enabled_signal(ai):
    twin = ai.passive_twin()
    twin.signals[0].enabled = True
    assert "passive-arm-signals" in codes(twin)
