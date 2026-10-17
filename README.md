# HoneyForge

Generates hardened Docker honeypots that mimic high-value targets (AI tooling, financial
systems, file-transfer hubs). A sidecar Claude controller keeps the persona alive, and
the honeypot emits **active signals** (CT certificates, leaked honeytokens, protocol
traffic, LAN advertisements) to test whether active signal mimicry attracts more
attackers than passive exposure.

Status: phase 1 (spec models, policy validator, CLI, archetypes). Runtime, image
building, and the Claude controller are not implemented yet.

## Quick start

```sh
python -m venv .venv && .venv/Scripts/pip install -e ".[dev]"
honeyforge archetypes
honeyforge init-spec -a ai-tools -o my-gateway.yaml   # mints unique signal tags
honeyforge validate my-gateway.yaml
honeyforge twin my-gateway.yaml -o my-gateway-passive.yaml   # control arm, signals off
pytest
```

## Spec concepts

- **services**: emulated listeners. Vulnerabilities are always `emulated: true`; the
  policy rejects anything implying real execution or passthrough.
- **companions / outbound**: fake partner servers and the decoy's scheduled outbound
  flows. Every target must be a companion or in `egress.decoy_allow`.
- **signals**: active emissions, each with a `scope` (`internet`, `on-path`, `L2`) and a
  unique `tag` that is embedded in what it emits, so inbound contact can be attributed.
  L2 signals require `network.mode: macvlan|ipvlan` on a Linux host.
- **experiment_arm**: `active` or `passive`. `honeyforge twin` derives the passive
  control from an active spec.

Deploy only on networks you own or are authorised to monitor. Personas must be
fictional; the validator trips on obvious real brands.
