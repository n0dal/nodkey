# ADR-0013: Agent interface (MCP tools) and mandates

- **Status:** Accepted (2026-10-28) with Revision 1 below, per
  [`docs/reviews/2026-10-28-agent-interface-review.md`](../reviews/2026-10-28-agent-interface-review.md)
  (verdict: accept after revising the spec; blocking AI-01, AI-02, AI-04, AI-08 resolved in Revision 1).
  Makes SECURITY_INVARIANTS v0.5 binding.
- **Date:** 2026-10-28
- **Invariants:** SI-01, SI-02, SI-05, SI-06, SI-07, SI-09, SI-10, SI-11, SI-16, SI-19, SI-20, SI-21
- **Resolves:** OQ-12
- **Specified in:** [`docs/specs/agent-interface-v1.md`](../specs/agent-interface-v1.md) Draft 2, with
  grant-v1 Draft 4, effect-protocol-v2 Draft 4 §12, payments-adapter-v1 Draft 4 §16, ADR-0006 Amendment 3

## Problem

Phase 5 (Demo A) puts an AI agent behind Nodkey. ADR-0011 already defines propose → confirm →
execute for any workload and says that MCP maps tool calls onto it, and that mandates (OQ-12) let a
proposal skip per-effect confirmation. Four things are undecided:

1. how agents reach the broker (protocol, transport, identity) without adding parsing to the TCB;
2. how asynchronous approval results reach an agent;
3. how a bounded pre-approval (a mandate) is represented, selected, tracked, and revoked, given
   ADR-0011 Revision 1 PC-06 (the broker selects; the workload cannot name a mandate) and
   effect-protocol-v2 EP-03 (mandates only for `enrolled` workloads, checked by the authority
   independently of broker state);
4. what Demo A must show, and what Nodkey may claim for agents.

A finding while designing: the existing `payments.refund` requires `order owner = approver`. A
merchant-side support agent's principal (a support operator) never owns the customer's order, so Demo
A cannot use that operation unchanged.

## Evaluation criteria

- No new code that parses agent input inside the TCB; no secret in any agent-side component.
- Works with unmodified MCP clients, today.
- Mandates: authority-signed; bounded totals that cannot be exceeded even by a compromised broker
  alone; unambiguous selection; revocable by the principal; minimal, versioned format change.
- Every claim testable (SI-17), with a positive-control baseline.

## Alternatives considered

**Agent interface.**

| Option | Assessment |
|---|---|
| A1. MCP front outside the TCB translating to socket W (**chosen**) | Any MCP client works; the broker keeps its strict protocol; front compromise = agent compromise = no gain |
| A2. Broker speaks MCP itself | Adds JSON-RPC/MCP parsing and version negotiation to the TCB. Rejected |
| A3. Only the native protocol v2 | Secure, but every agent framework needs custom glue. Kept as the underlying channel |
| A4. Streamable HTTP + MCP OAuth | Needed for remote agents later; introduces bearer tokens to Nodkey that need sender constraint. Out of v1 scope |

**Asynchronous results.** (a) pending result + `nodkey.effect_status` polling (**chosen**, works on
2025-11-25 and 2026-07-28); (b) MRTR URL-mode elicitation (deferred: client support is uneven, and it
is UX only — accepting it approves nothing); (c) Tasks extension (deferred: extension, not core).

**Mandate representation.**

| Option | Assessment |
|---|---|
| M1. A mandate is the confirmed `knd = 1` grant of a declared **template operation**; per-call grants carry `cfm = 2` and `mid` (**chosen**) | Reuses the pending record, digest, confirmation page, typed amounts, authority exactly-once store and revocation. Grant change: one value and one key |
| M2. New grant kind `knd = 3` (research 07 §3.3) | New key set, verification path and vectors; needs a predicate language for scope. More format, same security |
| M3. Separate signed mandate object (own `typ`, registry purpose) | Clean separation, but duplicates the confirm pipeline for no added property |
| M4. Biscuit or macaroon held by the agent | Attenuable bearer token in the agent's hands; budgets need server state anyway; new dependency. Rejected for v1 |
| M5. Broker DB row only | Violates EP-03: broker state alone would authorize. Rejected |
| M6. AP2 mandate formats | Payment-specific protocol (v0.2 per research 07); not studied in depth for this ADR. Interoperability deferred, not evaluated |

**Per-call grant marking.** Reusing `cfm = 1` would falsely state per-effect confirmation (audit
honesty) and would let the adapter not distinguish; a full grant v2 (new `typ`/aad) is heavier than
needed while v1 is an undeployed draft. Chosen: grant-v1 Draft 4 adds `cfm = 2` and key 20 `mid`;
Draft 3 verifiers reject such grants (unknown key), so old components fail closed. After v1 is final,
grant-v1 §13 (new fields = new version) applies without exception.

**Demo A refund operation.** Keep `payments.refund` and make the agent the customer's own assistant
(does not match a support-ticket scenario); or add `payments.support_refund` with a broker-resolved,
signed `customer_sub` (con3) and approver ∈ `support_principals` (**chosen**; requires a payments-adapter
amendment so its independent check becomes `owner_sub = con3`).

## Decision

1. **Interface.** A per-agent MCP front (`nodkey-mcp`), outside the TCB, holding nothing but that
   agent's socket W. Socket form on `/run/nodkey/agent/<name>/mcp.sock` with MCP stdio framing, plus
   the no-secret byte-copying shim `nodkey-mcp-stdio`. Identity is socket W (`SO_PEERCRED`), as for
   every workload. Target MCP **2026-07-28** only (Revision 1); **tools only**
   (`server/discover`, `tools/list`, `tools/call`, `ping`); no elicitation, Tasks, sampling, resources
   or OAuth in v1. Strict parsing that rejects ambiguity (spec §2.4). Write tools call
   `effect.propose`; results via `effect.status` and `nodkey.effect_status`.
2. **Mandates.** Approved on the auth origin as a pending effect of a template operation
   (`mandate.support_ticket`): customer scope, currency, count, per-call and total refund limits,
   message count, lifetime ≤ 1 h, all exact and below operator ceilings. Only for `enrolled` workloads;
   at most one active mandate per (workload, principal); the broker pre-selects, the authority decides
   with its own mandate record and durable counters, the broker re-checks under lock against current
   state, and the payments adapter re-checks scope. Both the authority's and the broker's mandate must
   permit an effect. Counters never release in v1. Identical repeats fall back to confirmation.
   Revocation by the principal (broker first, acknowledged; then authority; Revision 1), `revoked_before`, expiry,
   no replacement while one is active (Revision 1). Proposals outside a mandate use normal confirmation.
3. **Reads.** An agent's reads are permitted only under an active mandate, filtered by its customer
   scope; there is no other read path for agents in v1.
4. **Demo A** as in spec §5, with a scripted, fully obedient agent and a baseline positive control.
5. **Claims** limited to spec §6; residuals R-A1..R-A7 published.

## Evidence

- MCP revision and tool rules: MCP versioning page (current revision 2026-07-28) and the 2026-07-28
  tools page (name character set; `tools/list` must not vary per connection; `isError` for execution
  errors; "a handle is a name, not a capability"), both fetched 2026-10-28.
- Transport guidance, MRTR, elicitation and authorization facts: research 07 §2.1 and its references
  (not re-verified here beyond the two pages above).
- Mandates rely on mechanisms already specified and implemented for Phase 3/4: pending digest, authority
  issuance store, `grant.deliver`, execution transaction, adapter ownership check (effect-protocol-v2
  Draft 3.1, payments-adapter-v1 Draft 3.3). Nothing in this ADR has been implemented or tested.

## Consequences

- **Advantages:** no MCP code in the TCB; any MCP client works; mandates reuse the reviewed confirm
  pipeline; the scope and totals of mandated effects do not depend on the broker alone.
- **Drawbacks:** five dependent amendments (written 2026-10-28, not yet reviewed) (SI v0.5 for SI-06/20/21, grant-v1 Draft 4,
  effect-protocol-v2 Draft 4, payments-adapter-v1 Draft 4, ADR-0006 Amendment 3); one mandate per
  (workload, principal); failed mandated effects burn budget; agent reads require a mandate.
- **Security:** mandated effects execute without per-effect human review by design: misuse within
  bounds and exfiltration through allowed channels (message bodies to the in-scope customer, the model
  provider) are residuals, not defects. SI-20 remains PARTIALLY MET until passkeys; that now also covers
  mandate approval, which carries more authority than a single effect.
- **Performance:** mandated effects add the authority poll interval (≤ 500 ms) plus the normal
  execution path.
- **Compatibility:** Draft 3 grant verifiers reject `cfm = 2` grants (fail closed). Existing
  operations and `named` workloads are unchanged.

## Reversal / migration

Removing mandates leaves the interface intact: all agent writes fall back to confirmation and agent
reads become unavailable. The MCP front can be replaced by native protocol v2 clients without broker
changes. If `cfm = 2` proves insufficient, mandate grants move to grant v2 with a new `typ`.

## Revision 1 (2026-10-28): review changes

Decision items 1–3 are amended as follows; where they conflict, this revision wins.

1. **Revocation reaches the broker (AI-01).** The broker checks its own mandate row before delivering or
   executing any `cfm = 2` grant and before every mandate read. The gateway revokes at the broker first and
   reports success only on the broker's acknowledgement, retrying otherwise; then at the authority. After
   revocation both refuse. A `cfm = 2` delivery rejected for an inactive mandate ends the record `DENIED`.
2. **Support principals (AI-02).** `approver ∈ support_principals(ten)` is required for the template, for
   mandate reads and for coverage; loaders refuse templates and support operations for other enrolments,
   and refuse templates declared `mandate_eligible` or used as a template's covered operation (AI-08).
3. **No replacement (AI-04).** A template approval requires that no mandate is active for
   (workload, principal), checked by the gateway render, the authority and broker activation. A new mandate
   is a new human approval with fresh counters.
4. **Claims (AI-03, AI-05, AI-06, AI-10).** Refund bounds are independent of the broker; message bounds are
   broker-only (the authority keeps no message counter). The SI-09 claim is "no grant produces more than
   one effect; identical repeats under a mandate require confirmation". New residuals R-A8 (agent-chosen
   mandate scope), R-A9 (broker-only message bounds), R-A10 (authority-only revocation).
5. **Simplification (AI-12).** MCP 2026-07-28 only; two transport forms (per-agent socket, no-secret shim).
6. **Binding (AI-09, AI-11).** The customer's email is a resolved, signed mandate term and must equal `to`;
   mandates end when `config.digest` changes.
