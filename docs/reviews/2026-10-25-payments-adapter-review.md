# Adversarial review: ADR-0012 (Proposed) and payments-adapter-v1 Draft 1

- **Date:** 2026-10-25
- **Scope:** `docs/decisions/0012-payments-adapter.md` (incl. its proposed ADR-0006 Amendment 2),
  `docs/specs/payments-adapter-v1.md` Draft 1. Context read: effect-protocol-v2 Draft 3 (§2.3, §2.4
  table, §4.4, §5 refund row, §6 `named`), ADR-0006 (Decision 7, Amendment 1), research 06 §2.4
  (P-01..P-19), `tools/simpay/README.md`, SECURITY_INVARIANTS SI-02/09/10/11/15/16/19,
  `crates/nodkey-grant/src/{verify,registry}.rs` (public API only).
- **Method:** design review under a time box. No code exists for the adapter; nothing was run. Claims
  about simpay behaviour come from its README only; simpay source was **not** read (see PA-12).
- **Also evaluated:** the orchestrator ruling that the adapter SHOULD verify the authority-signed grant
  itself (via `nodkey-grant`) and derive the provider idempotency key from the grant's `(iss, jti)`.

Severity scale: Critical / High / Medium / Low / Info. "Blocks" = blocks implementation of Demo P.

## Summary

The broker-side state machine is sound for an honest provider. These parts are correct: T2 as a
compare-and-set from `RESERVED`, the rule that a refusal is not `FAILED`, the frozen request, the
same-key resend gated by a deadline, the one-in-flight-per-order rule and the locked budget counter.
I found no double-refund path that works with an honest provider, a correct broker clock and a
correct `orders` table. The problems are in three areas:

1. **The adapter-verifies-grant ruling** is sound in direction but does not deliver its stated
   property as written. The grant does not bind `charge_id`. Grant `exp` (≤ 30 s TTL) cannot be the
   bound, because resends happen for up to ~22 h. And the adapter's registry and clock must come from
   somewhere the broker cannot write. (PA-01, PA-02, PA-03.)
2. **Trusted-fact provenance of `orders`.** There is no charge uniqueness, remaining-refundable is
   computed per order rather than per charge, and the production write path is unspecified (PA-04).
3. **Clock- and configuration-dependent resend after retention** (PA-05), plus a timing race between
   the live dispatcher and the reconciler (PA-06).

## Findings

| ID | Severity | Section | Blocks |
|---|---|---|---|
| PA-01 | High | ruling; spec §1.1, §9; ADR alt. E | yes (if ruling adopted) |
| PA-02 | High | ruling; ADR-0006 Amendment 2 | yes (if ruling adopted) |
| PA-03 | High | ruling (new adapter inputs) | yes (if ruling adopted) |
| PA-04 | High | spec §4.1 `orders`, §4.3 W14 | yes |
| PA-05 | Medium | spec §4.3 T2, §4.7; ADR-0006 Am. 2 (3) | no (cheap; do before PT-15) |
| PA-06 | Medium | spec §4.3 Dispatch/Recovery | no |
| PA-07 | Medium | spec §4.6, §5 | no |
| PA-08 | Medium | spec §10 | no (must land before claims) |
| PA-09 | Low | spec §4.2 | no |
| PA-10 | Low | spec §3.1, §2.3 | no |
| PA-11 | Low | spec §4.1, §4.7 | no |
| PA-12 | Low | spec §10 PT-16 | no |
| PA-13 | Low | spec §7 | no |
| PA-14 | Info | ADR-0012 criteria 3, alt. E, Security; spec §9 | no |

### PA-01 — High — A grant does not bind the charge: a compromised broker can redirect an approved amount to any charge

**Section:** ruling; spec §1.1 `refund.create` args, §9 "Broker compromise"; ADR-0012 alternative E;
effect-protocol-v2 §5 (`charge_id comes only from the broker's orders row`).

**Scenario (attacker J, then money out).** The `payments.refund` grant signs `order_id` (res0),
`amount_minor` (con0) and `currency` (con1). It does not sign `charge_id`. An adapter that verifies
the grant still takes `charge_id` from the broker. The attack:

1. Victim V approves a refund of 50.00 USD on order 17.
2. The compromised broker sends `refund.create{grant_V, charge_id = ch_ATTACKER}`. `ch_ATTACKER` is a
   charge the attacker paid, with at least 50.00 still refundable, on the same provider account.
3. The adapter verifies the grant: signature, `op`, amount and currency all pass.
4. simpay refunds 50.00 to the attacker's card.

Same-key deduplication does not help: this is the first use of that key. This is theft from the
merchant, not merely a wrong refund. ADR-0012 alternative E already observed this. The ruling's claim
("can only cause refunds that the authority signed") is true of amount and currency only.

**Fix (pick one, state it in the spec):**

- (a) **Adapter-side trusted mapping** `order_id → (ten, charge_id, currency)`. It comes from an
  operator-owned source the broker uid cannot write. Examples: a read-only mount of an operator-signed
  manifest, or (Demo P) a fixture file owned by the operator uid with mode 0444. The adapter requires
  that `charge_id` equals the mapping for the grant's `order_id` and `ten`.
- (b) **Bind `charge_id` into the grant.** The authority would source it from operator facts at
  issuance. That moves `orders` read access into the authority (it is not the broker), and needs a
  grant-v1 parameter and an effect-protocol-v2 change.
- In addition (defence in depth, not sufficient alone), `GET /v1/charges/{id}`: require the currency to
  equal the grant's currency, and `amount − amount_refunded ≥ amount_minor`.

Without (a) or (b), §9 must state that a compromised broker can still aim any signed amount at any
refundable charge of the account.

### PA-02 — High — Grant `exp` cannot bound reconciler resends. Without an explicit adapter age cap the ruling gives "once per retention window, repeatedly", not "once"

**Section:** ruling; ADR-0006 Amendment 2; spec §4.7; effect-protocol-v2 §4.2 (`exp = iat +
grant_ttl_secs`, 1–30 s; skew ≤ 5 s).

**Scenario.** Resends are legitimate up to `resend_deadline` (default 22 h after dispatch). The grant
expired after ≤ 35 s. If the adapter enforces `exp` through the normal `nodkey-grant` verify (its
`VerifyContext` takes `now`), every reconciler resend fails, and PT-06..PT-09 and PT-16 break. If it
skips `exp` for "resends", there is a problem: the broker alone says which calls are resends, so a
compromised broker labels everything a resend. Then:

- (i) A grant that was approved but never executed can be executed once at any later time. Its record
  is `EXPIRED`, and effect-protocol-v2 T34 promises "no effect after expiry".
- (ii) Once the provider has pruned the key (simpay: `created + retention ≤ now`, "the same key
  executes again"), the same grant executes again. That repeats every retention window and is bounded
  only by the provider's remaining-amount check on the charge.

So "at most once per provider retention window" is accurate, but the window repeats. It is not "at
most once".

**Fix.**

- Add an explicit adapter acceptance window measured on the **adapter's** clock:
  `now < iat + provider_retention_s − resend_margin_s`. Measure from `iat`, not `exp`: the first
  provider receipt of the key happens after `iat`, so this deadline is conservative. That turns
  (ii) into "at most once" for an honest provider.
- For (i), either publish it as a residual ("a compromised broker can execute an approved-but-expired
  grant once, within the window"), or tighten it. With cap `idem_status`, refuse any create later than
  `exp + skew + dispatch_grace` (for example 60 s) unless `idem.status` is `in_progress` or `done`.
  Without that capability, refuse when `refund.find` finds nothing and the grant is past
  `exp + skew + dispatch_grace`. Both rules fail toward "not sent". Their cost is liveness: an original
  that never arrived goes to an operator instead of being resent.
- Implement the window as a **separate, differently typed entry point** in `nodkey-grant`, for
  example `verify_retransmission(now, max_age)` returning a distinct type. That way the broker's
  consumption path can never accidentally skip `exp`.
- Amend ADR-0006 Amendment 2 with an adapter-side clause (4b) that mirrors (3).

### PA-03 — High — The adapter's verification is only as good as its registry, its `aud` and parameter checks, and its clock, and the spec gives none of them

**Section:** ruling (new inputs); spec §1, §7.

**Scenario.** The verification is void in any of these cases:

- The adapter's key registry (or the `order → charge` mapping of PA-01) is a file the broker uid can
  write, or is delivered over socket P.
- The adapter accepts any grant from the broker's `iss` without checking all of: `knd = write`,
  `op = payments.refund`, `opv`, `wid = shop`, `aud` = the broker id, `cfm = true`, con0 equal to
  `amount_minor`, con1 equal to `currency`.

For example, a `ledger.transfer` grant or a read grant would carry a valid signature.

The adapter also has no `revoked_before` table and no consumption store. The `nodkey-grant` verify
API assumes "exactly one replay store and one `revoked_before` table" (`verify.rs` l.21), so the
adapter will need an API mode without them.

**Fix.** Specify the following:

- Registry: an operator-owned read-only mount. The adapter checks owner and mode at start, as it does
  for `key_file`. Rotation is by restart.
- An exact list of checked claims.
- The adapter uses its own `CLOCK_REALTIME` for `nbf`/`iat`/`exp` and the window. It refuses to start
  if the clock is unsynchronised, where that can be detected; otherwise publish clock rollback as a
  residual, as SI-09 already does for the broker.
- Revocation is not enforced at the adapter (residual: a grant revoked after approval but executed by
  a compromised broker). That is acceptable because revocation is the broker's job, but it must be
  stated.
- `refund.create` args become `{grant, charge_id}`. Amount, currency, `idem_key` and `reference` are
  derived inside the adapter, not sent by the broker. The broker stores the `idem_key` and
  `reference` the adapter returns. The broker then no longer needs `K_idem` (see PA-09).

### PA-04 — High — `orders` allows two rows on one charge; remaining is computed per order; the production write path is unspecified (SI-10)

**Section:** spec §4.1 `orders`, §4.3 T1 W14; ADR-0012 "Trusted facts".

**Scenario.** `charge_id` is immutable but not UNIQUE.

- Two order rows (same or different owners, same or different `ten`) that reference `ch_X`, each with
  `captured_minor = 100`, give Nodkey a remaining amount of 200 on a charge worth 100. The
  one-in-flight lock is per order, so concurrent refunds on the two orders are not serialized against
  each other. Only the provider's `amount_too_large` stops the excess.
- A row in tenant A that points at tenant B's charge lets A's customer refund B's payment.
- "Seeding happens at payment time" by role `nodkey_shop_operator`. In a real shop the
  payment-capture code is part of the shop application. If that code (or anything the compromised
  workload influences, for example an order-sync job fed by app data) holds the operator role, the
  workload can manufacture facts: `owner_sub = attacker`, `charge_id = any`. That is exactly what
  SI-10 forbids. For Demo P the fixture plus a harness assertion is fine; the production claim is not.

**Fix.**

- `UNIQUE (charge_id)` (or a composite with the provider account).
- Compute remaining and the in-flight lock per charge, or prove the 1:1 mapping by constraint.
- Seed only through a path the workload cannot reach or influence. At insert, verify the charge with
  `GET /v1/charges/{id}`: account, amount, currency, `succeeded`.
- State in §4.1 that the SI-10 claim for refunds rests on the operator path being outside the
  workload's control, and add a test for it (PA-08).

### PA-05 — Medium — A resend after the provider's retention depends on the broker wall clock and on an unchecked retention configuration

**Section:** spec §4.3 T2 (`resend_deadline = now + provider_retention_s − resend_margin_s`), §4.7;
ADR-0006 Amendment 2 (3).

**Scenario.** If the broker clock is set back after a `DISPATCHED`/`UNKNOWN` row passed its real
deadline, or `provider_retention_s` is configured above the provider's real retention, a same-key
resend reaches a pruned key and executes a **second** refund. The reconciler resends **before** it
looks up the refund (step 2 before step 3), so even an honest provider listing that shows the first
refund is not consulted first. SI-09 excludes clock rollback only "unless ADR-0006 procedures are
followed", and those procedures do not cover the provider's clock.

**Fix.**

- Look up before every resend: `refund.find(charge, reference)`; if found and identical, go to
  `SUCCEEDED` without resending.
- With `idem_status`: state `none` for a key known to have been dispatched means the key is pruned or
  was never received. Stop resending and go to operator. Never resend on `none` after the first
  reconciler round.
- Validate at start that `resend_margin_s < provider_retention_s ≤` the profile's documented minimum.
- Under the ruling, the adapter's own window (PA-02) is a second, independent clock check.

### PA-06 — Medium — Race between the live dispatcher and the reconciler: the recovery threshold is about the same as the dispatcher's worst case

**Section:** spec §4.3 Dispatch and Recovery.

**Scenario.** The dispatcher may make 3 calls. Each can take up to `total_ms` plus the 2 s P timeout
(12 s), with waits of 1 s and 2 s between them: about 39 s, plus T2/T3 database latency. Recovery
moves `DISPATCHED → UNKNOWN` at `total_ms + 30 s` = 40 s. Under a slow database, the reconciler's
same-key resend can overlap the dispatcher's third call. For an honest provider this is safe (a `409`,
or a cached replay), and T3 is a compare-and-set, so the late dispatcher result is discarded. But the
case depends entirely on provider deduplication, it creates spurious `busy` and `anomaly` entries, and
it is untested.

**Fix.**

- Derive the recovery threshold from the configured loop maximum (`3 × (total_ms + 2 s) + Σwaits +
  margin`).
- The dispatcher re-checks `state = DISPATCHED` (a cheap SELECT) before each retry.
- Add a test (PA-08).

### PA-07 — Medium — `effect.status.reason` can act as a fact oracle; the order of the T1 checks is unspecified

**Section:** spec §4.3 W14 bullet list, §4.6, §5.

**Scenario.** W14 lists the owner, tenant, currency and status checks in one bullet and gives no
evaluation order. If `currency`, `order_status`, `order_busy`, `insufficient_refundable` or `budget`
is reported for an order the approver does not (or no longer) own, the workload learns another
customer's order state. This applies to PT-01/PT-20-style ownership changes, or any path to T1
without the render-time uniform error. `budget` also discloses a customer's daily refund activity to
the shop (low: the customer is the shop's own user). `provider_declined` versus
`pending_reconciliation` tells the workload how the provider behaved (low).

**Fix.** Normative order: tenant and owner first, with a uniform `not_owner_or_unknown` that
short-circuits everything else. Then status, currency, busy, remaining, budget. Add a test.

### PA-08 — Medium — Gaps in the test plan (PT-01..28)

Missing cases. Each is needed before the related claim is made:

1. Broker clock rollback or jump across `resend_deadline`; a retention configured above simpay's
   (PA-05).
2. Two `orders` rows on one charge; a cross-tenant charge; an operator-role insert attempted from any
   workload-reachable path (PA-04).
3. Live dispatcher versus reconciler overlap under an injected T3 delay (PA-06).
4. Reason-ordering oracle (PA-07).
5. If the ruling is adopted, a broker-compromise suite run against the adapter directly. Expected
   result in every case: nothing sent. Cases:
   - `create` without a grant, or with a grant for another op, a read grant, another `wid` or `aud`,
     `cfm = false`, or an amount or currency different from the args;
   - a valid grant aimed at another order's charge;
   - the same grant with a different charge (provider: `idempotency_params_mismatch`);
   - a grant older than the window;
   - an expired, never-executed grant (PA-02 (i));
   - registry or mapping file writable by the broker uid (the adapter refuses to start).
6. PT-13 covers only the shop. Add the broker, authority and gateway containers, which must have no
   route to `172.30.30.20` and no `pay-egress` membership. The ADR claims the broker has no egress.
7. HTTP edge cases beyond simpay's catalogue: `1xx` informational responses, header count above the
   hyper default, non-UTF-8 header bytes, `Content-Length` shorter than the body, chunked trailers, a
   list with 3 items or `has_more = true` (`too_many_matches`/ambiguous).
8. Budget across UTC midnight (the documented 2× window).
9. `K_idem` rotation refused while non-final rows exist.
10. `get_order.refunded_minor` excludes `UNKNOWN` and failed-settlement amounts as specified.

### PA-09 — Low — Domain separation of the idempotency and reference derivation

**Section:** spec §4.2.

The HMAC input is `label ‖ iss ‖ jti`. Provider idempotency scope is the **account**, shared across
all its keys (simpay README; Adyen company scope). A future operation (a capture, say) that reuses the
same derivation label, or a second Nodkey deployment on the same account with a copied `K_idem` and
the same `iss`, relies only on `jti` uniqueness. `jti` is the broker-chosen `pending_id`.

**Fix.** Add `op`, `opv` and a provider-account identifier to the HMAC input. Under the ruling, hold
the key in the adapter, not the broker. A broker-reused `jti` then yields at most a cached replay or a
`params_mismatch`, never a new key.

### PA-10 — Low — Response parsing: decoding 5xx bodies and relying on hyper defaults

**Section:** spec §3.1, §2.3.

Decoding `5xx` bodies has no use, because every `5xx` is `ambiguous`; decoding them only widens the
parser surface. The spec relies on hyper defaults that it does not pin: obs-fold rejection, maximum
header count, `1xx` handling, header bytes outside visible ASCII.

**Fix.** Do not decode `5xx` bodies. Pin the hyper builder options in the spec (header count, read
buffer = `max_head`, no obsolete multiline), and add PA-08 item 7.

### PA-11 — Low — Accounting gaps: external refunds and failed settlement

**Section:** spec §4.1, §4.7.

Refunds made outside Nodkey with other keys of the same account (an operator dashboard) are visible
only through the manually maintained `external_refunded_minor`. The provider then refuses, the row
goes to `UNKNOWN`, and either `FAILED/provider_declined` (simpay) or an operator (Stripe) follows.
There is no double refund (the provider bounds it), but there is a liveness and alarm cost.

A failed settlement returns the amount to the charge at the provider while Nodkey keeps it
encumbered. That direction is conservative.

**Fix.** Periodically reconcile `orders` against `GET /v1/charges/{id}.amount_refunded` (alarm only;
never raise remaining automatically).

### PA-12 — Low — PT-16 `phantom_success` expectation not verified

**Section:** spec §10 PT-16.

PT-16 expects "resend executes → one real refund". If simpay caches the phantom `200` under the key,
as it caches other business outcomes, the resend replays the phantom response, the GET returns `404`,
`find` returns not_found, and the row stays `UNKNOWN` until an operator resolves it. I did not check
simpay's source. Confirm the caching behaviour and correct the expectation.

### PA-13 — Low — Configuration validation

**Section:** spec §7.

PT-15 uses retention 120 s while the default `resend_margin_s` is 7200, which gives a negative
deadline. That is safe but silently disables resends. Budget limits are in minor units: `JPY 10000`
is ¥10,000, but `USD 10000` is $100.00, which is probably not what was meant.

**Fix.** Refuse to start when `margin ≥ retention`. Express limits per currency with the ISO 4217
exponent in the documentation.

### PA-14 — Info — Document consistency if the ruling is adopted

ADR-0012 needs these changes:

- Alternative E moves from "Deferred" to "Chosen".
- Criterion 3 changes to "every amount/currency sent comes from the signed grant; `charge_id` from an
  adapter-trusted mapping".
- The Security consequences and spec §9 "Broker compromise" need rewriting.
- ADR-0002 §5's statement that the adapter "does not verify grants" needs revisiting.
- Under PA-03, the broker no longer holds `K_idem`.
- ADR-0006 Amendment 2 needs the adapter-side window clause (PA-02).

## Assessment of the "adapter verifies the grant" ruling

**Direction: sound, and it should be adopted.** It turns a broker compromise from "refund any
refundable charge, any amount, any number of times" into a bound fixed by user approvals, but only if
the conditions below hold. The parser-isolation argument of ADR-0012 option B is unaffected: the
adapter still has no DB credential. It now also parses a CBOR/COSE grant, but only from the broker.

**What it achieves, with PA-01..03 fixed** (assuming an honest provider, an uncompromised adapter, a
correct adapter clock and a correct operator mapping):

- **Amount and currency** come only from the signed grant.
- **Charge** comes from the operator mapping for the signed `order_id` and `ten`.
- **Repetition:** the same grant always derives the same `(iss, jti)` key. Within retention, a replay
  is deduplicated, and a replay aimed at a different charge gets `idempotency_params_mismatch`.
- **Age:** the adapter's window (`iat + retention − margin`) stops any use after the provider could
  have pruned the key. The result is **at most one refund per signed grant in total**, not once per
  window.
- **Key confusion:** `op`/`knd`/`wid`/`aud`/`cfm` checks plus registry provenance prevent reuse of
  transfer or read grants and of keys the broker controls.

**Residuals that remain:**

1. A compromised broker can execute an approved grant that the honest system let expire, once,
   within the window (PA-02 (i)), unless the stricter `idem.status`/`find` gate is adopted.
2. A compromised broker can ignore every broker-side control: budgets, remaining-refundable,
   one-in-flight, revocation, ownership changes after approval. It is bounded only by what users
   approved and by the provider's per-charge remaining amount.
3. A compromised broker can still deny service: withhold dispatch, or report false outcomes to the
   workload.
4. A provider that ignores idempotency, or an adapter clock rollback, defeats the "once" property.
5. Adapter compromise (attacker G through a parser bug) yields the restricted key and with it all of
   the above, now combined with grant verification in the same process. This was already a residual.
6. Authority signing-key compromise is out of scope (attacker J at the authority).

**What the adapter then needs:**

- The authority's key registry (operator-owned read-only mount; startup owner and mode checks; no
  delivery over P).
- The operator `order → (ten, charge, currency)` mapping, from the same kind of source.
- Its own clock, with the age window.
- A `nodkey-grant` entry point that verifies signature and claims without a replay store or
  `revoked_before`, with a bounded-age rule that is typed differently from the broker's consumption
  verify.
- Its own derivation key for `idem_key` and `reference`.
- No state, and no consumption store: deduplication is delegated to the provider within the window,
  and the window bounds the rest.

## Verdict

**Changes required before implementation.** The broker-side design is good and needs only PA-04 and
the cheap fixes PA-05 and PA-13. If the ruling is adopted (recommended), PA-01, PA-02 and PA-03 must be
specified in Draft 2 before the adapter is written; otherwise the ruling's claim is false for the
charge and for grant age. PA-06..PA-12 can be fixed alongside implementation, but the tests in PA-08
must exist before the corresponding STATUS claims.
