# HoneyForge

Generates hardened Docker honeypots that mimic high-value targets (AI tooling, financial
systems, file-transfer hubs). A sidecar Claude controller keeps the persona alive, and
the honeypot emits **active signals** (CT certificates, leaked honeytokens, protocol
traffic, LAN advertisements) to test whether active signal mimicry attracts more
attackers than passive exposure.

Status: phases 1–2. Specs, policy validation, and a hardened OpenCanary decoy you can
build and run. Telemetry shipping, egress allowlisting, the Claude controller, and
signal emission are not implemented yet.

## Quick start

```sh
python -m venv .venv && .venv/Scripts/pip install -e ".[dev]"
honeyforge archetypes
honeyforge init-spec -a ai-tools -o my-gateway.yaml   # mints unique signal tags
honeyforge validate my-gateway.yaml
honeyforge twin my-gateway.yaml -o my-gateway-passive.yaml   # control arm, signals off

honeyforge build my-gateway.yaml          # renders out/my-gateway and builds images
honeyforge up out/my-gateway
honeyforge events out/my-gateway          # normalised JSON events
honeyforge down out/my-gateway

pytest                                                  # unit tests
HONEYFORGE_INTEGRATION=1 pytest tests/integration       # builds and probes a live stack
```

## Runtime layout

Each honeypot is a compose project with two containers:

- **netguard** owns the network namespace (published ports, hostname). At startup it
  applies a default-deny OUTPUT policy (replies to inbound connections still flow),
  then drops to `nobody` with an empty capability bounding set.
- **decoy** runs [OpenCanary](https://github.com/thinkst/opencanary) (pinned) inside
  netguard's namespace: non-root, read-only rootfs, no capabilities,
  `no-new-privileges`, resource-limited. It cannot originate network connections or
  change the firewall rules. Per-image SSH host keys and a TLS certificate with the
  persona's subject are minted at build time, with persona-branded HTTP login skins.

Services map to OpenCanary modules (`ssh`, `https`, `http`, `ftp`, `redis`, `mssql`,
`tcpbanner`, and others; see `src/honeyforge/canary/modules.py`). OpenCanary is
low-interaction: it logs connections and credential attempts but never grants access.

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
