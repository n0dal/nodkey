<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/hero-dark.png">
  <img src="assets/readme/hero-light.png" width="100%" alt="Nodkey: human approval for the actions your AI agent takes, enforced outside the agent. A vertical line marks the trust boundary. On the workload side: no credentials, no network route, can only propose. On the authority side: credentials held by the broker only, execution needs a single-use grant, the grant comes from an approval or a mandate.">
</picture>

# Nodkey

**Human approval for the actions your AI agent takes, enforced outside the agent.**

[Why](#why) · [Demos](#demos) · [5-minute demo](#5-minute-demo-demo-a) · [Requirements](#requirements) · [Limits](#limits) · [Repository map](#repository-map) · [Security](#security-and-contributing) · [License](#license)

---

> [!WARNING]
> **Research prototype. Not for production.** All security reviews were performed by AI agents; no
> independent human audit has been done. See [LIMITATIONS.md](LIMITATIONS.md) and
> [DISCLAIMER.md](DISCLAIMER.md).

![Terminal recording: a prompt-injected support agent's tool calls and Nodkey's responses. A EUR 20.00 refund inside the approved mandate executes; a EUR 5,000.00 refund on another customer's order goes to the approver, is denied, and nothing runs; an email to x@evil.example is rejected; a message to the ticket's own customer executes, a stated limit.](assets/readme/demo.gif)

<sub>Recorded results of one local Demo A run on 2026-10-30 (simulated provider; the agent and the approver are scripted), replayed by [`assets/readme/demo.tape`](assets/readme/demo.tape); source: [`tests/demoa`](tests/demoa/run.sh), [`examples/agent-support`](examples/agent-support/README.md).</sub>

An AI agent or an app proposes consequential actions such as payments, refunds, or messages. An
action executes only after a human approves exactly that action, or when it fits a bounded mandate the
human set earlier. A separate broker holds the provider credentials; the app never does.

> **Compromise of computation must not imply compromise of authority.**

Nodkey separates an application's ability to compute from its authority to cause consequential
effects. An AI agent or an app (the *workload*) can only **propose** actions such as a refund or an
outbound message. A separate **broker**, which alone holds the provider credentials, executes an action
only if it carries a single-use grant signed by a separate **authority**, and the authority signs only
what a human approved, exactly as it was shown to them, or what fits a bounded **mandate** that human
delegated earlier.

## Why

Prompt injection or remote code execution in the workload gives an attacker everything the workload can
do. If the workload holds API keys or database credentials, the attacker holds them too. In Nodkey the
workload holds no credential and has no network route to the protected resource, so taking it over yields
proposals, not authority. Nodkey limits the *consequences* of compromise; it does not prevent
compromise or prompt injection ([VISION.md](docs/VISION.md), [THREAT_MODEL.md](docs/THREAT_MODEL.md)).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/diagram-dark.svg">
  <img src="assets/readme/diagram-light.svg" width="100%" alt="Propose, confirm, execute. 1: the workload (an app or AI agent; untrusted, no credentials, no network; it reaches only the broker socket) proposes an action to the broker, which holds the provider credentials. 2: the broker sends a pending record to the gateway. 3: a person approves the exact values, or a bounded mandate, on the gateway auth origin. 4: the gateway passes the approval to the authority (signing key, no network). 5: the authority returns a single-use signed grant to the broker. 6: the broker executes once at the provider (simulated in the demos).">
</picture>

<sub>Propose, confirm, execute: the workload proposes, a person approves, and the broker executes once with a single-use grant. PNG versions: [light](assets/readme/diagram-light.png), [dark](assets/readme/diagram-dark.png).</sub>

Simplified. The real flow has more checks, for example a payments adapter that verifies grants again
before contacting the provider. See [ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[effect-protocol-v2](docs/specs/effect-protocol-v2.md).

## Demos

Each demo runs locally in Docker. The apps are **intentionally vulnerable** (a remote-code-execution
endpoint models a compromised workload). They bind to `127.0.0.1` only and must never be exposed to a
network. Results are copied from [STATUS.md](STATUS.md) (last local runs, 2026-10-25 to 2026-10-28).

| Demo | Directory | Shows | Last result |
|---|---|---|---|
| 1. Containment | [`examples/php-ledger`](examples/php-ledger/README.md) | Arbitrary PHP in the app cannot reach the database or its credential; the same attack succeeds against an unprotected baseline | 65 PASS / 2 NOT APPLICABLE / 0 FAIL; baseline: 24 expected FAILs |
| 2. Confirmed transfer | [`examples/confirmed-transfer`](examples/confirmed-transfer/README.md) | A compromised app can propose a transfer but cannot alter, forge, or replay the approved one | 29/29 PASS |
| P. Confirmed refund | [`examples/confirmed-refund`](examples/confirmed-refund/compose.yaml) | Refunds through a simulated payment provider; the app never holds the provider key; no double refund | 92 PASS / 0 FAIL / 17 NOT TESTED |
| A. AI support agent | [`examples/agent-support`](examples/agent-support/README.md) | A prompt-injected agent's tool calls run only when approved or within a mandate | 75 PASS / 0 FAIL / 14 NOT TESTED |

## 5-minute demo (Demo A)

Demo A needs no model, API key, or account: a deterministic stand-in plays a fully prompt-injected agent.

```sh
tests/demoa/run.sh
```

The script builds the images, runs the scenario twice on fresh stacks, prints a results table, and
stops the stack. It exits with status 2 because 14 rows are NOT TESTED. The first run downloads base
images and compiles the Rust components; this build can take longer than five minutes (it has not been
timed). Step-by-step instructions, the
meaning of each result value, cleanup, and troubleshooting are in [QUICKSTART.md](QUICKSTART.md).

## Requirements

- Linux, or a Linux VM such as [Colima](https://github.com/abiosoft/colima) on macOS. The development
  runs used Colima 0.10.3 (Ubuntu 24.04, AppArmor, Docker default seccomp).
- Docker with Compose v2.
- `bash`, `python3`, `openssl` on the host (used by the run scripts).
- Network access for the first image build (base images, Rust crates).
- Rust (1.99 used) only to build and test the crates outside Docker. The demos compile inside Docker.
- `php` on the host only for the Demo 1 containment suite (`tests/containment/run.sh`).

## Limits

Nodkey does not prevent code execution or prompt injection, does not make permitted actions safe,
and does not protect against a compromised host, kernel, container runtime, broker, gateway, or
authority. Confirmed intent (SI-20) is **PARTIALLY MET**: approval is session-based with a test login,
without passkeys. All providers are simulators. Many rows are NOT TESTED. Details:
[LIMITATIONS.md](LIMITATIONS.md).

## Repository map

| Path | Contents |
|---|---|
| [`broker/`](broker/README.md) | Broker (Rust): verifies grants, owns effect state, executes declared operations |
| [`crates/`](crates/) | Authority, gateway, grant verifier, payments adapter, MCP front (Rust) |
| [`tools/`](tools/) | Simulated payment provider (`simpay`), mail sink, deterministic demo agent |
| [`examples/`](examples/) | The four demo stacks |
| [`tests/`](tests/) | Demo runners and harnesses, integration tests, test vectors |
| [`docs/`](docs/README.md) | Vision, invariants, threat model, architecture, specs, ADRs, research, reviews |
| [STATUS.md](STATUS.md) / [ROADMAP.md](ROADMAP.md) | What is verified; what is planned |

## Security and contributing

Report vulnerabilities as described in [SECURITY.md](SECURITY.md). Contributions: see
[CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party material is listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); see also [DISCLAIMER.md](DISCLAIMER.md).
