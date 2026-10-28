# Roadmap

Phases are gated by acceptance criteria, not dates. A phase is complete only when its acceptance
evidence is recorded in [STATUS.md](STATUS.md).

| Phase | Goal | Acceptance | State |
|---|---|---|---|
| 0 | Repository and project knowledge | A fresh session can reconstruct goals and state from the repo | Done |
| 1 | Research and architecture selection | Coherent security model; assumptions stated; initial ADRs accepted | Done |
| 2 | Minimal containment (PHP, local DB) | Arbitrary PHP execution cannot reach the protected resource under P0 | Done |
| 3 | Signed grants and confirmed intent | Forged, altered, expired, misdirected, reused, or unconfirmed grants produce no effect | **Done** (verified locally; see STATUS) |
| 4 | External effects (Demo P) | Simulated payment provider behind the broker: app holds no provider key; refunds bound to confirmation; no double refund on ambiguous outcomes; budgets/mandates | **Done** (verified locally; see STATUS) |
| 5 | AI agents (Demo A) | Agent tool calls (incl. prompt-injection scenario) execute only when confirmed or within a delegated mandate; agent-facing interface | **Done** (verified locally; see STATUS) |
| 6 | Developer experience | `nodkey` CLI incl. `verify`; a newcomer can run both demos from docs alone | Planned |
| 7 | Generalization | Second SDK language; more adapters; language-neutral protocol docs | Planned |
| 8 | Security hardening | Fuzzing, failure injection, formal model of grant/effect state, supply-chain hardening | Planned |
| 9 | Open-source preparation | Owner can evaluate a release candidate with known limits | Planned |
| 10 | Long-term evolution | Workflow receipts (ADR-0007), WASI-native execution, distributed brokers | Research |

Focus: [ADR-0010](docs/decisions/0010-project-focus.md).

Public release of any kind requires explicit approval from the project owner.
