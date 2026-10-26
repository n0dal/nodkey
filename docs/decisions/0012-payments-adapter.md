# ADR-0012: Payments adapter for Demo P — grant-verifying adapter process, broker-owned effect state, reconciler (rev. 1)

- **Status:** Accepted (rev. 1, 2026-10-25). All blocking findings of
  [`2026-10-25-payments-adapter-review.md`](../reviews/2026-10-25-payments-adapter-review.md) (PA-01..PA-04)
  are addressed in rev. 1 and payments-adapter-v1 Draft 2 (resolution table in the review). Rev. 1 has not
  been re-reviewed; implementation must be independently reviewed.
- **Date:** 2026-10-25
- **Invariants:** SI-01, SI-02, SI-03, SI-05, SI-06, SI-09, SI-10, SI-11, SI-15, SI-16, SI-19
- **Resolves:** OQ-10 (ADR-0006 Amendment 2)
- **Specified in:** [`payments-adapter-v1.md`](../specs/payments-adapter-v1.md) Draft 2;
  [`effect-protocol-v2.md`](../specs/effect-protocol-v2.md) Draft 3.1 (`charge_id` in `payments.refund`)
- **Builds on:** ADR-0002 §5, ADR-0006 (incl. Amendment 1), ADR-0010, ADR-0011, research note 06 Part 2

## Problem

Demo P (ADR-0010): a customer of a self-service shop refunds part of their own order, confirms it on the
Nodkey confirmation page, and the refund is executed against the **simulated** provider simpay without
the shop ever holding the provider key. Open: where the provider call runs and what it trusts; how
external effect state and ambiguous outcomes are recorded and resolved; where trusted order facts live;
egress; the malicious provider; budgets; webhooks; and whether a reconciler resend is a grantless effect
(OQ-10).

## Evaluation criteria

1. No double refund under retries, crashes, timeouts, races and clock or configuration error
   (SI-09, SI-15).
2. Workload cannot reach the key or the provider (SI-01..03); the parser of provider responses does not
   share a process with the broker's DB write credential or its grant consumption (ADR-0002 §5).
3. Amount, currency and charge sent to the provider are the ones the user approved and the authority
   signed; the charge is a trusted fact (SI-06, SI-10, SI-16).
4. A compromised broker (J) is bounded by user approvals: at most one refund per signed grant.
5. Decision, trusted-fact checks and encumbrance are atomic (SI-11).
6. Smallest TCB that meets 1–5; simpay fault semantics preserved in tests.

## Alternatives considered

### Process model and trust

| Option | Assessment |
|---|---|
| A. Adapter inside the broker | Rejected: provider parsing (attacker G) in the process with the DB write credential; broker needs egress; ADR-0002 §5. |
| B. Separate adapter that trusts the broker's request | Draft 1 choice. Rejected by review PA-01: a compromised broker could aim any amount at any refundable charge, any number of times. |
| **B'. Separate adapter that verifies the authority-signed grant itself** (chosen) | The adapter builds every provider request from the grant only, re-checks order → charge → owner in its own read-only view, derives the idempotency key from the grant's `(iss, jti)` with its own key, and refuses grants older than `R_max`. Broker compromise yields at most one refund per signed grant. |
| C. Adapter owns its own effect DB | Rejected: grant consumption and `RESERVED` would no longer commit atomically. |
| D. Credential-injecting egress proxy | Rejected: fails SI-16; typed construction and filtering still needed. |

### How the charge becomes trusted and bound (PA-01)

- **Chosen:** `charge_id` is a signed `payments.refund` parameter (con2). The broker resolves it from
  `orders` at propose into the immutable pending record; the digest, the confirmation page ("Charge being
  refunded") and the grant cover it; the adapter re-checks it against its own `SELECT`-only view of
  `orders`. Cost: the adapter joins the internal `data` network and has a DB role.
- Rejected: an operator-signed mapping file in the adapter (a second copy of `orders` to keep in sync);
  the authority reading `orders` (widens the authority's inputs, which today has no network).

### Grant age instead of `exp` (PA-02)

Write grants live ≤ 30 s, but resends are needed for hours, and the adapter cannot tell a resend from a
first dispatch (the broker labels it). The adapter therefore ignores `exp` and enforces
`now − iat ≤ R_max` (default 12 h) on its own clock, with the start-up rule `R_max < provider retention
− margin`. Every request for a grant is the same request with the same key, so within `R_max` the
provider deduplicates, and after `R_max` the adapter refuses. Rejected: a stricter gate refusing creates
later than `exp + grace` unless the provider already knows the key — it would send every lost original
to an operator. **Accepted residual:** a compromised broker can execute an approved-but-never-executed
grant once while it is younger than `R_max`; the user approved that exact refund.
A new, separately typed `nodkey-grant` entry point (`verify_retransmission`) does this, so the
broker's consuming path can never skip `exp`.

### Broker-unwritable adapter inputs (PA-03)

Registry and config: root-owned `0444` read-only mounts into the adapter only, checked at start (owner ∉
{broker, adapter}, no group/other write, no symlinks). Operation declaration: compiled in. Orders view:
DB role with `SELECT` on five `orders` columns; the broker role cannot write `orders` or alter roles.
Clock: host `CLOCK_REALTIME`, no container has `CAP_SYS_TIME`. Secrets (`K_idem`, simpay key):
adapter-owned `0400`, never mounted into the broker. Revocation and consumption are not checked by the
adapter (stated residual).

### Effect state and ambiguity

- **Chosen:** broker-DB `payment_effect` (`RESERVED → DISPATCHED → SUCCEEDED | FAILED | UNKNOWN`) mirrored
  onto `pending_effect`; T1 commits consumption, ordered trusted-fact checks under the charge row lock,
  budget, encumbrance and frozen values together; only a socket-level "not sent" fails directly; a
  provider refusal becomes `UNKNOWN` (simpay `deny_but_commit` shows why).
- **Per-charge accounting (PA-04):** `UNIQUE(charge_id)` makes the order row the charge row; remaining
  and the in-flight block are computed per charge.
- **Reconciler (PA-05):** lookup first; same-key resend only within the broker deadline
  (`iat + R_max − 60 s`), only within `max_resends`, never after the provider reports the key unknown
  past the first round; after that lookups only, "not found" never concludes anything.
- **Leases (PA-06):** every adapter call on a row is made by the lease holder; recovery waits for lease
  expiry.
- **Workload-facing reasons (PA-07):** ownership checked first and reported uniformly as `not_permitted`;
  other reasons collapsed to a small enum.

### Trusted facts provenance (PA-04)

`orders` is written only by an operator role whose credential sits in a payment-capture integration
outside the workload's trust domain, verifying each charge with the provider before insert. The SI-10
claim for refunds rests on that path and is not made if the shop application writes `orders`.

### Egress and TLS

Internal networks: `pay-egress` (adapter, simpay API only) and `data` (broker, adapter, PostgreSQL); IP
literal, no DNS, no proxy, no redirects; TLS 1.3 to one pinned test CA; size and time limits; simpay key
restricted to the adapter's address. TLS front: a rustls listener inside simpay. Rejected: a reverse
proxy (would replace `commit_then_drop` and malformed responses, destroying the fault tests); stunnel
(extra process and C dependency for no gain in a test tool).

### Malicious provider, budgets, webhooks

- Adapter rejects inconsistent answers; a consistently lying provider is undetectable (published).
- **Budgets specified:** per `(ten, customer, currency, UTC day)` locked counters (AR-05) in T1, because
  `named` workloads can send customers approval links they did not ask for. Enforced by the broker only.
- **Webhooks out of Phase 4:** no inbound listener; outcomes from GETs only; P-19 NOT APPLICABLE.

## Decision

Adopt B' with the charge bound in the grant, the age rule, the broker-unwritable input set, the
broker-owned state machine with per-charge accounting, lookup-first reconciliation with leases, budgets,
the simpay rustls listener, and webhooks out of scope, as specified in payments-adapter-v1 Draft 2 and
effect-protocol-v2 Draft 3.1. Append Amendment 2 to ADR-0006 (done with this revision).

## Evidence

- Research 06 Part 1 [F]: provider idempotency semantics, cached `500`s, retention ≥ 24 h, reconcile
  after ambiguity.
- simpay README and source: `phantom_success` neither caches nor records the key (`src/api.rs`, create
  path), so a same-key resend executes (PA-12); `deny_but_commit` refunds and answers 400.
- `crates/nodkey-grant` public API: `verify(..)` then `decide(revoked)` assumes one replay store and one
  `revoked_before` table (`verify.rs`), hence the new entry point.
- Review PA-01..PA-14. Nothing in this ADR is implemented or tested.

## Consequences
- **Advantages:** broker compromise bounded by user approvals (one refund per signed grant, signed amount,
  currency and charge); provider parsing isolated from the broker's DB write credential and consumption;
  double refunds excluded under honest-provider semantics; closed-enum output to the workload.
- **Drawbacks:** the adapter now parses grants and holds a read-only DB credential; two networks on the
  adapter; conservative liveness (refusals and ambiguity block a charge); budgets never refund; one
  confirming GET per success; operator obligations for `orders` and `K_idem` rotation.
- **Security:** residuals: approved-but-unexecuted grant once within `R_max`; broker-only controls
  (revocation, budget, remaining, status) lost under broker compromise; consistent provider lies; host
  clock rollback (attacker I); adapter compromise yields the restricted key and a read-only view.
- **Performance:** one UDS hop, one grant verification and one DB read in the adapter, one extra GET.
- **Compatibility:** `payments.refund` declaration gains `charge_id` (operations file and
  `config.digest` change); real providers lack simpay's idempotency-state endpoint.

## Reversal / migration

The adapter protocol is internal. Dropping adapter-side verification returns to option B (weaker,
documented). Webhooks can be added later as GET triggers.

## Revision history

| Rev. | Change |
|---|---|
| Draft (Proposed) | Option B; broker held `K_idem`; per-order accounting |
| rev. 1 (Accepted) | Option B' per the orchestrator ruling and review PA-01..PA-14 |
