# Research

Research notes rank below accepted ADRs and specifications (see [source-of-truth hierarchy](../README.md)).
Each note separates **established facts** (cited) from **hypotheses**. Notes are point-in-time
(2026-10-24) and were not hands-on evaluations unless stated.

> **Naming:** notes are kept as written. "PBE" / "Proof-Bound Execution" is the provisional working name of the project now called **Nodkey** (name chosen 2026-10-30).

| Note | Topic | Key finding |
|---|---|---|
| [01-prior-art.md](01-prior-art.md) | Prior art and competing systems | No surveyed open-source project combines credential-less containment, typed brokered effects, and per-effect authorization from trusted facts; each part has strong prior art (privsep, Chromium broker, credential injectors, PostgREST+RLS, BeyondProd). |
| [02-grant-protocol.md](02-grant-protocol.md) | Grant format, replay, keys | Grants are necessary but never sufficient. Restricted COSE_Sign1/Ed25519 profile; single-use consumption in the effect's transaction. |
| [03-runtime-isolation.md](03-runtime-isolation.md) | Runtime isolation | Architecture A with Deployment Profile P0 (`network_mode: none` + per-workload broker socket); gVisor as P1; WASI not viable for legacy PHP in 2026. |
| [04-authorization-policy.md](04-authorization-policy.md) | Identity and policy | Trusted gateway attests verified user + request digest; Cedar embedded in the broker; facts read in the effect's own transaction. |
| [05-governance-licensing-naming.md](05-governance-licensing-naming.md) | Licensing, naming, export, legal checklist | Apache-2.0 + DCO; retire the "Proof-Bound Execution" name before public release (conflicts found). |
| [06-payment-provider-and-http-adapter.md](06-payment-provider-and-http-adapter.md) | Payment providers, simulator, HTTP effect adapter | Provider restricted keys cannot bind amount/charge/user; idempotency only covers same-key retries. Stripe has overlapping approval rules; Nodkey adds end-user binding, ownership from trusted facts, user confirmation, key custody under containment, provider independence. Simulator + adapter design; 19 attack scenarios. |
| [07-ai-agents-and-tool-authorization.md](07-ai-agents-and-tool-authorization.md) | AI agents, MCP, mandates | Expose broker operations as MCP tools over per-agent sockets; MCP carries no security. In-process approval features of agent SDKs are not a boundary against prompt injection. Closest prior art: AWS AgentCore Policy (proprietary), AP2 signed mandates. Demo A scenario with prompt injection. |

## Orchestrator verification notes

- **2026-10-24 — Actenon (verified via GitHub API):** `github.com/Actenon/actenon-kernel`, Apache-2.0,
  created 2026-06-05, last push 2026-10-08, describes itself as "the open verifier for proof-bound
  consequential execution… issues no grants; runs no policy decisions." It overlaps Nodkey's grant
  *verification* layer only; it does not address workload credential custody or isolation. It is part
  of a vendor ecosystem with separate commercial components. Implications: (1) the name
  "proof-bound" is effectively taken; (2) its protocol should be evaluated for interoperability
  before Nodkey finalizes a grant format (OQ-07).
