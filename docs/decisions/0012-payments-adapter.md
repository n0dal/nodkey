# ADR-0012: Payments adapter for Demo P — separate process, broker-owned effect state, reconciler

- **Status:** Proposed
- **Date:** 2026-10-25
- **Invariants:** SI-01, SI-02, SI-03, SI-09, SI-10, SI-11, SI-15, SI-16, SI-19
- **Resolves (on acceptance):** OQ-10 (via ADR-0006 Amendment 2 below)
- **Specified in:** [`docs/specs/payments-adapter-v1.md`](../specs/payments-adapter-v1.md) Draft 1
- **Builds on:** ADR-0002 §5, ADR-0006 (incl. Amendment 1), ADR-0010, ADR-0011 (Revision 1, Amendment 1),
  effect-protocol-v2 Draft 3, research note 06 Part 2

## Problem

Demo P (ADR-0010): a customer of a self-service shop refunds part of their own order; they confirm on
the Nodkey confirmation page; the refund is executed against the **simulated** provider simpay, and the
shop never holds the provider key. effect-protocol-v2 already declares `payments.refund` and
`payments.get_order` and defines propose → confirm → execute up to the `RESERVED` insert. Not yet
decided: where the provider call runs, how external effect state and ambiguous outcomes are recorded and
resolved, where trusted order facts live, how egress is confined, what a malicious provider can and
cannot do, whether budgets ship, and whether webhooks are in scope. ADR-0006 §7 forbids retrying an
`UNKNOWN` effect without documented upstream deduplication, and OQ-10 asks whether a reconciler resend
is a grantless effect under SI-19.

## Evaluation criteria

1. No double refund under retries, crashes, timeouts and races (SI-09, SI-15).
2. Workload cannot reach the key or the provider (SI-01..03); the process that parses untrusted provider
   responses does not hold the DB credential or verify grants (ADR-0002 §5, attacker G).
3. Every value sent to the provider comes from the approved record or broker-owned rows (SI-10, SI-16).
4. Decision, trusted-fact checks and encumbrance are atomic (SI-11, ADR-0006).
5. Smallest new TCB and fewest moving parts that meet 1–4; fault semantics of simpay preserved in tests.

## Alternatives considered

### Process model

| Option | Assessment |
|---|---|
| **A. Adapter as a module inside the broker** | Least code. Rejected: the provider-response parser (attacker G's surface: malformed HTTP, hostile JSON) runs in the process that holds the DB credential, `K_idem` and the grant verifier; the broker would need egress. Contradicts ADR-0002 §5. |
| **B. Separate, stateless adapter process; broker owns all state and drives it** (chosen) | Adapter: own uid, holds only the simpay key and pinned CA, only network `pay-egress`, no DB. Broker keeps T1 atomic in its own DB. A G-exploited parser bug yields at most the restricted key, usable only from the adapter's address. |
| C. Adapter owns its own effect DB and state machine | Rejected: grant consumption (broker DB) and `RESERVED` (adapter DB) would no longer commit atomically; would need two-phase commit or an outbox, i.e. more states and more TCB. |
| D. Generic credential-injecting egress proxy (Envoy-style) | Rejected: an arbitrary-request proxy fails SI-16; the typed request construction and response filtering still need an adapter. |
| E. Adapter additionally verifies the grant | Deferred (hardening phase): `charge_id` comes from broker rows anyway, so a compromised broker could still aim a "valid" grant's amount at another charge; the gain is limited to amount bounding, at the cost of a second registry and revocation reader. |

**Channel.** Unix socket P, adapter listening, broker the only client; `SO_PEERCRED` both directions;
the effect-protocol-v2 §1.2 socket model and §1.3 strict JSON envelope. Alternatives: TCP with mTLS
(keys to manage, no gain on one host), gRPC/length-prefixed binary (new parser, no gain). An `ok:false`
from the adapter is normative proof that nothing was sent; anything else that is not a definite result is
ambiguous.

### Effect state and ambiguity

- **Chosen:** `payment_effect` rows in the broker DB, `RESERVED → DISPATCHED → SUCCEEDED | FAILED |
  UNKNOWN`, mirrored onto `pending_effect` (`EXECUTING`, `UNKNOWN`, final) in the same transaction. T1
  commits grant consumption, trusted-fact checks under the order lock, budget spend, the encumbrance and
  the **frozen** request (charge, amount, currency, derived idempotency key and reference) together. T2
  marks `DISPATCHED` before the first byte. No provider answer other than a socket-level "not sent"
  moves an effect directly to `FAILED`: the broker had already proved under lock that the refund is
  valid, so a refusal contradicts trusted facts and is resolved by the reconciler.
- Rejected: treating `4xx` refusals as `FAILED` immediately (research 06's table). simpay's
  `deny_but_commit` shows a provider can refuse and still refund; releasing the amount would then permit a
  second refund. Cost of the chosen rule: such cases need one reconciler round.
- **Idempotency key:** `HMAC-SHA256(K_idem, "nodkey.idem.v1" ‖ len-prefixed iss ‖ jti)`, as ADR-0006 §7,
  with an unambiguous length-prefixed encoding; `jti = pending_id`. Rejected: `pending_id` itself (the
  workload knows it from the confirm URL; an unguessable key costs nothing).
- **Remaining refundable** = captured − external refunds − every effect not `released`. In-flight,
  `UNKNOWN`, `SUCCEEDED` (even with failed settlement) and unresolved `FAILED` amounts encumber. One
  in-flight effect per order: any `RESERVED`/`DISPATCHED`/`UNKNOWN` row blocks new refunds (AR-10,
  tightened from "DISPATCHED/UNKNOWN" to include `RESERVED` for a simpler invariant).
- **Reconciliation:** same-key resend of the frozen request only before `resend_deadline` = first dispatch
  + provider retention − margin, at most `max_resends` times; then lookup by `(charge, reference)`; after
  the deadline lookup only, and "not found" never concludes anything; `FAILED` only on a definite business
  refusal of a same-key resend **and** an empty lookup **and** (simpay) a `done` idempotency state.

### Trusted facts

- **Chosen:** broker-DB `orders` table written only by a separate shop-operator DB role (the workload has
  no DB route); `charge_id`, `currency`, `captured_minor` immutable by trigger. Read at render (display,
  unlocked) and again under lock in T1; a change between approval and execution (owner, status) yields
  `FAILED/denied` with no provider call. After T1 the frozen values decide.
- Rejected: reading charge facts from the provider at execution (puts the untrusted party in the
  decision, adds a call a liar controls); accepting `charge_id` from the workload (SI-10).

### Egress and TLS

- **Chosen:** internal Docker network `pay-egress` with exactly the adapter and the simpay API; fixed IP
  literal, no DNS, no proxy env, no redirects, TLS 1.3 to a single pinned test CA with a fixed server name,
  early data off; response head 16 KiB, body 64 KiB, total 10 s; simpay key restricted with
  `allowed_cidrs` = the adapter's /32.
- **TLS front: a rustls listener inside simpay** (`api_tls`). Rejected: a reverse-proxy sidecar
  (nginx/Caddy) — it would replace `commit_then_drop` by a `502`, and reject or rewrite malformed
  responses (`header_injection`, `duplicate_content_length`), destroying the fault semantics the tests
  rely on. A byte relay (stunnel) would mostly preserve them but adds a process, a C dependency and
  half-close subtleties for no gain over a small `tokio-rustls` wrapper in a test tool (size estimate, not measured). Test PKI is
  generated per run into `var/`; the CA key is deleted after issuance; nothing is committed.

### Malicious provider (G)

The adapter rejects inconsistency: echo mismatch, create vs. confirming GET, refusal contradicting broker
facts, redirects, oversized/slow/ambiguous/malformed responses; provider text never reaches the workload,
logs or alarms (closed enums only). It **cannot** detect a consistently lying provider (fake success,
hidden refunds, ignored idempotency, invented settlement). Published, with the observation that a
malicious provider holds the merchant's funds anyway.

### Budgets

- **Chosen: specify now.** Per `(ten, customer, currency, UTC day)` locked counter rows (AR-05,
  ADR-0006 §2) with amount and count limits, spent in T1, never released; unconfigured currency denied.
  Reason: Demo P's workload is `named`, where a compromised shop can send real customers approval links
  they did not ask for (effect-protocol-v2 §6); a budget bounds that harm per customer per day, and T1
  already holds the locks, so the cost is one table and one guarded update.
- Rejected: deferring to mandates (OQ-12): mandates are for `enrolled` workloads only and do not cover
  `named` approvals. Rejected: SERIALIZABLE aggregate checks (AR-05 write skew).

### Webhooks

**Out of Phase 4.** No inbound listener on the adapter or broker; outcomes and settlement come from the
broker's own GETs. Webhooks would only ever be a hint to GET earlier (research 06 §2.2), and a receiver
adds an attacker-A-reachable parser. P-19 is NOT APPLICABLE in Phase 4, with a negative test.

## Decision

Adopt alternatives B, the broker-owned state machine with the conservative refusal rule, the derived
idempotency key and reference, the `orders` table and immutability triggers, the `pay-egress` network,
the simpay rustls listener with a pinned CA, per-customer daily budgets, and webhooks out of scope, as
specified in `payments-adapter-v1` Draft 1. The spec also lists six amendments (E1–E6) to
effect-protocol-v2, to be folded into its Draft 4.

### ADR-0006 Amendment 2 (proposed; appended to ADR-0006 on acceptance of this ADR; resolves OQ-10)

Decision 7 is extended:

> **7a. Reconciler resend.** For an external effect in `UNKNOWN` whose grant was consumed with outcome
> `ACCEPT`, the broker MAY resend the request decided in that grant's effect transaction if and only if:
> (1) the provider profile documents deduplication by idempotency key; (2) every request field, the key
> and the destination come from the effect row frozen in that transaction, so the fingerprint is
> identical; (3) the broker clock is before `resend_deadline` = first dispatch + documented retention −
> margin; (4) fewer than `max_resends` resends have been made. A resend is a retransmission of an
> already-decided effect: it creates no effect row, consumes no grant, and takes no value from the
> workload. Its authority is the consumed grant recorded on a broker-owned row, so it is not a grantless
> effect under SI-19. After the deadline the broker only looks the effect up; "not found" is never proof
> of no effect. `UNKNOWN → FAILED` requires positive evidence of no effect as defined by the adapter
> specification.

SI-19 needs no text change if "effect" is read as "one decided effect row"; a clarifying note to that
effect is proposed for SECURITY_INVARIANTS v0.5 (not made here).

## Evidence

- Research 06 Part 1 [F]: Stripe/Adyen idempotency semantics, cached `500`s, retention ≥ 24 h, "retry with
  the same key… after that, reconcile"; refunds can fail after creation.
- `tools/simpay` README and tests (64 passing per STATUS.md): fault and malicious catalogues used by the
  test plan; `idempotency_keys` endpoint is a **[sim]** extension.
- ADR-0002 §5 (per-adapter process required); ADR-0006 §1–2, §7, Amendment 1; effect-protocol-v2 §4.4
  (atomic execution transaction), §5 (refund checks); review AR-05, AR-10.
- Nothing in this ADR is implemented or tested.

## Consequences
- **Advantages:** provider parsing isolated from DB, grants and `K_idem`; one atomic decision; double
  refunds excluded by construction under honest-provider semantics; workload sees closed enums only.
- **Drawbacks:** two new processes in Demo P (adapter, simpay TLS); conservative liveness — refusals and
  ambiguity block the order until the reconciler or an operator resolves; budgets never refund; one
  in-flight refund per order; a confirming GET per success.
- **Security:** adapter compromise = restricted key compromise (bounded by provider access policy);
  broker compromise (J) can still refund any charge the key allows; consistent provider lies undetected;
  restore needs a stricter runbook (non-final rows → `UNKNOWN`, provider listing comparison).
- **Performance:** one extra UDS hop and one extra GET per refund; immaterial for a confirmed effect.
- **Compatibility:** Stripe-shaped; real providers lack simpay's idempotency-state endpoint, so there
  `FAILED` after `UNKNOWN` needs an operator. Retention and key length are profile parameters.

## Reversal / migration

The adapter protocol is internal: merging the adapter into the broker (A) or moving to an outbox model
(C) changes no workload, gateway or authority interface. Webhooks can be added later as GET triggers
without changing state rules. Budgets can be widened or removed by configuration.
