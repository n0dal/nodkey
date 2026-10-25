# Research Note 06: Payment Provider Behaviour and the HTTP Effect Adapter (Demo P)

> [!NOTE]
> Status: **research note and design proposal, 2026-10-25**. Ranks below accepted ADRs and specs.
> Nothing here is decided or tested. Markers: **[F]** marks a fact with a cited primary source (provider
> documentation fetched on 2026-10-25; providers change their docs, so re-check before relying on
> them). **[H]** marks a hypothesis or design proposal.

Scope: Phase 4 / Demo P (ADR-0010). A web app issues refunds through a **simulated** payment provider.
The broker holds the provider key. Invariants in play: SI-01/02/03 (custody and reach), SI-06/09/10/11
(binding, at-most-once, trusted facts, current state), SI-15 (ambiguous outcomes), SI-16 (bounded
interface), SI-20 (confirmed intent). Builds on ADR-0006 §7 (`RESERVED → DISPATCHED → SUCCEEDED |
FAILED | UNKNOWN`, upstream key `HMAC(broker_key, "nodkey.idem.v1" ‖ iss ‖ jti)`, the AR-10 `UNKNOWN`
precondition), and on the ADR-0003 Phase 3 profile (confirmation on the auth origin, `cfm` marker).

---

## Part 1: How real providers behave

### 1.1 Authentication and key granularity

- **Stripe secret keys** (`sk_…`) have "unrestricted permissions on all Stripe APIs" [F,
  https://docs.stripe.com/keys].
- **Stripe restricted keys** (`rk_…`) let you set, per resource, one of **None, Read, or Write**. Write
  implies Read, and the HTTP method decides which permission is needed (GET = read; POST/DELETE =
  write) [F, https://docs.stripe.com/keys/restricted-api-keys]. The documentation describes no
  permission narrower than the resource level: nothing ties a key to a charge, a customer, or an amount.
- **Stripe access policies** limit a key to IPv4 addresses or CIDR ranges, or by ASN, country, or
  anonymiser category [F, https://docs.stripe.com/keys#access-policies].
- **Stripe approval rules** can require two-party approval when a refund is created. Conditions
  include an amount threshold, the actor (for example an agent-tagged key), and a request rate. An
  agent-tagged key that triggers a rule gets an `approval_required` error. A designated reviewer, who
  must be a different person from the requester, approves in the Dashboard. Requests expire after 14
  days [F, https://docs.stripe.com/account/approvals]. Default rules for agent-tagged keys cover
  "Refund is created" [F, ibid.].
- **Adyen** keeps idempotency keys at the **company account** level. Because all credentials under that
  account share the key space, Adyen tells you to use random keys so that "credentials can't access each
  other's stored responses". Lowering a credential's access does not stop it retrieving past responses
  for keys it already used [F, https://docs.adyen.com/development-resources/api-idempotency/].

### 1.2 Idempotency keys

| Property | Stripe (API v1) | Adyen | PayPal |
|---|---|---|---|
| Header | `Idempotency-Key`, up to 255 chars [F, https://docs.stripe.com/api/idempotent_requests] | `idempotency-key`, max 64 chars [F, Adyen idempotency page] | `PayPal-Request-Id`, 38 chars [F, https://developer.paypal.com/api/rest/reference/idempotency/] |
| Retention | "at least 24 hours"; reuse after pruning "can execute a new request" [F, https://docs.stripe.com/error-low-level] | 7–14 days [F] | "as long as the server stores the ID"; not stated [F] |
| Same key, different params | Error: the layer "compares incoming parameters … and errors if they're not the same" [F, idempotent_requests] | Not documented [F, absence] | Not documented; a reused ID "returns the latest status" of the earlier request [F] |
| In-flight duplicate | Not cached; `409` means another request with that key is still running; "wait and retry with that key" [F, error-low-level] | HTTP 422 or 409, error 704 "request already processed or in progress" [F] | Processes the first; "might fail the second" [F] |
| What is cached | Status and body once execution begins, **including `500`s**. Validation failures, auth failures, rate limits, and concurrency conflicts are not cached [F, idempotent_requests; error-low-level] | `transient-error: true` ⇒ retry with the same key; 503/703 if the idempotency store itself is down [F] | — |

Two consequences matter for Nodkey:

1. **A cached `500` does not resolve.** Retrying with the same key returns the same `500` while Stripe
   keeps the key. Stripe says to treat a `500` as indeterminate and to reconcile by retrieving the object,
   checking the Dashboard, and using webhooks [F, error-low-level].
2. **The client chooses the key.** Idempotency protects an honest client against its own retries. It does
   nothing against a key holder who wants a second effect: that holder just picks a fresh key.

### 1.3 Refund semantics

- **Stripe:** a refund names a charge or PaymentIntent. `amount` is optional and defaults to the full
  remaining amount. You can make several partial refunds "until the entire charge has been refunded".
  Asking for "more money than is left" raises an error [F,
  https://docs.stripe.com/api/refunds/create]. The create call has **no currency parameter**: the refund
  takes the charge's currency [F, ibid.; Refund object `currency`]. `reason=fraudulent` has a side
  effect: it adds the card and email to Radar block lists [F, ibid.]. Refunds go only to the original
  payment method [F, https://docs.stripe.com/refunds].
- **Stripe refund status** is one of `pending`, `requires_action`, `succeeded`, `failed`, `canceled`
  [F, https://docs.stripe.com/api/refunds/object]. A refund can fail **after** it was created. The
  return of funds "can take up to 30 days", and Stripe sends `refund.failed` [F, refunds page]. When the
  available balance is short, a card refund stays `pending` [F, ibid.].
- **Adyen:** refunds are asynchronous and the outcome arrives as a webhook. `success: true` means only
  that validation passed: `REFUND_FAILED` can follow days later. The currency "must match the currency
  used in the authorization". The sum of refunds cannot exceed the captured amount [F,
  https://docs.adyen.com/online-payments/refund/].

### 1.4 Errors, retries, and the "may have succeeded" window

Stripe's classes [F, error-low-level]:

- **Network error or timeout:** "Restoring connectivity doesn't tell you whether the original request
  succeeded." Retry with the same key and the same parameters within 24 hours. After that, stop and
  reconcile. Do not retry with a new key.
- **`4xx`:** `400`, `401`, `402` (valid parameters but the request failed), `403`, `409`, `424`, `429`.
  A `429` caused by a lock timeout means Stripe did not process the request.
- **`5xx`:** "the operation might have produced side effects".
- The `Stripe-Should-Retry` header can override the status code as a retry hint.
- "If the original outcome remains unknown, reconcile it before starting another operation."

### 1.5 Webhooks

- **Stripe** signs `timestamp + "." + raw_body` with HMAC-SHA256 into `Stripe-Signature: t=…,v1=…`. The
  libraries reject timestamps outside a default 5-minute tolerance, and docs say never to use tolerance
  `0`. Each delivery attempt gets a fresh timestamp. Events can arrive more than once and in any order:
  "Track event IDs to identify duplicate deliveries". Delivery retries continue for up to three days.
  Signing secrets are per endpoint and separate from API keys. Stripe also recommends an IP allowlist
  [F, https://docs.stripe.com/webhooks].
- **Adyen** HMAC signs eight fields (`pspReference` … `success`). The cited page puts **no timestamp**
  in the signed fields [F, https://docs.adyen.com/development-resources/webhooks/secure-webhooks/verify-hmac-signatures/].
  An Adyen receiver therefore has to stop replays by deduplicating events, not by checking freshness [H].

### 1.6 Rate limits

Stripe allows 100 req/s globally in live mode and 25 req/s per endpoint by default, with 50 concurrent
requests. Over-limit responses are `429` with `Stripe-Rate-Limited-Reason` [F,
https://docs.stripe.com/rate-limits].

### 1.7 Where provider controls help, and where they stop

| Control | Helps with | Stops short of |
|---|---|---|
| Restricted key, Refunds: Write | Stolen key cannot create charges, payouts, or read customers | It can refund **any** charge in the account, partially or fully, up to each charge's remaining amount. It knows nothing about end users, order ownership, or what the user agreed to [F, §1.1; inference H] |
| Access policy (IP/ASN) | A key exfiltrated from the broker host is useless from elsewhere | Does not stop misuse **through** the allowed host. That host is exactly what a compromised app abuses in a credential-injecting proxy design |
| Idempotency key | Safe retry of the *same* request within the retention window | Intentional duplicates under fresh keys; retries after 24 h (Stripe); cached `500`s; deduplicating business intent |
| Provider remaining-amount check | Total refunds ≤ charge | Refunds larger than the user asked for; refunds of another user's charge |
| Approval rules (Stripe) | Human review of agent refunds, amount thresholds, rate conditions | The reviewer is merchant staff in the Stripe Dashboard, not the affected end user. Rules cannot check order ownership in the merchant's system. Stripe-only. A compromised app could still request refunds, which then wait for review [H, from §1.1] |
| Webhook signatures | Forged events | Replayed events where there is no timestamp (Adyen). Signed but stale state, because events arrive unordered |

**Plain assessment [H].** For a Stripe merchant whose only worry is "an AI agent might issue refunds",
restricted keys, access policies, and approval rules together cover a real part of Demo P and Demo A.
Nodkey should say so publicly. It adds:

- **Per-effect authority bound to the end user's identity and ownership facts** in the merchant's own
  data. A provider sees charges, not who in the merchant's system owns them.
- **Confirmation by the affected user** of the exact values.
- **Key custody under containment**: a compromised app cannot reach the key or the provider (SI-01..03).
- **Provider-agnostic**, self-hosted, and testable with `verify`.

---

## Part 2: Design proposal

### 2.1 `simpay`: a self-hosted payment-provider simulator [H]

**Purpose.** Reproduce §1's security-relevant behaviour deterministically, with no external account
(ADR-0010 §4). Not a general Stripe mock.

**Data model.** Each account has:

- API keys with scopes (`refunds:write`, `charges:read`, `refunds:read`) and an optional source-CIDR
  access policy;
- charges `{id, amount_minor, currency, refunded_minor, status}` seeded from a fixture file;
- refunds `{id, charge, amount_minor, currency, status, reference, created}`;
- an idempotency table `(account, key) → {fingerprint, state: in_progress|done, status, body, created}`;
- webhook endpoints, each with its own signing secret.

The store is SQLite or in-memory with a seed file. It exposes a deterministic clock that the harness can
advance.

**API (Stripe-shaped, simplified).**

- `POST /v1/refunds`, form-encoded `charge`, `amount`, `reference`. Headers `Authorization: Bearer`
  and `Idempotency-Key` (required; at most 64 chars, to match Adyen's tighter limit).
- `GET /v1/refunds/{id}`
- `GET /v1/refunds?charge=…&reference=…`
- `GET /v1/charges/{id}`

**Faithful behaviours:**

- **Keys and scopes:**
  - wrong scope ⇒ `403`;
  - source address outside the access policy ⇒ `401`, even with a valid key. This gives a testable
    SI-03 analogue.
- **Idempotency** follows Stripe's semantics:
  - fingerprint = method, path, and canonical parameters;
  - same key with a different fingerprint ⇒ `400 idempotency_error`;
  - concurrent duplicate ⇒ `409`, not cached;
  - `400` validation errors, `401`, `403`, and `429` are not cached;
  - once execution starts, the result is cached, **including `500`**;
  - a configurable retention window (default 24 h) is checked against the deterministic clock. After
    pruning, the same key executes again, as Stripe documents.
- **Refunds:**
  - `amount` defaults to the remaining amount;
  - `amount > remaining` ⇒ `400 amount_too_large`;
  - fully refunded ⇒ `400 charge_already_refunded`;
  - no currency parameter (the refund inherits the charge's currency);
  - status starts `pending` or `succeeded` per fixture and can move to `failed` later through a
    scripted event that emits `refund.failed`.
- **Webhooks** Stripe-style (`t=…,v1=HMAC`), at-least-once, unordered; **rate limit** per key ⇒ `429`,
  nothing executed.

**Deterministic fault injection.** The fault plan is a list of rules. Each rule names a match (operation,
nth call, idempotency key, or charge) and a fault:

| Fault | Behaviour | Tests |
|---|---|---|
| `fail_before_commit(500)` | Return 500 with no state change. Not cached, so a same-key retry executes. | Retrying with the same key is safe |
| `commit_then_500` | Commit, cache 500, return 500 | Cached-500 path; reconciliation by GET |
| `commit_then_drop` | Commit, then close the TCP connection without a response | Classic timeout-after-commit ⇒ `UNKNOWN` |
| `commit_after_delay(ms)` | Hold `in_progress`, commit after the delay, respond late | Client timeout *before* commit; reconciliation must not conclude "not found ⇒ failed" while the key is in progress |
| `slow_response(ms)` | Commit promptly, delay the response | Timeout tuning; late `200` arriving after `UNKNOWN` was recorded |
| `inflight_409` | Hold the first request; a concurrent same-key request gets 409 | Concurrent retries |
| `webhook_duplicate(n)` | Deliver the same event id n times | Event dedupe |
| `webhook_replay(after_s)` | Re-send an old body with its old signature and timestamp | Freshness tolerance |
| `late_refund_failed` | Move `succeeded → failed` later | Settlement tracking |
| `rate_limit` | 429 with nothing executed | Bounded retry |

**Malicious-provider mode (attacker G)** is a separate profile:

- `200` with a different `amount`, `charge`, or `currency` than requested;
- `200` for a refund that was never stored;
- `3xx` redirect to another host;
- oversized bodies and headers;
- invalid or ambiguous JSON (duplicate keys, deep nesting, huge numbers);
- error messages containing markup or prompt-injection text;
- slow-drip responses;
- webhooks signed correctly whose content contradicts `GET`.

**Control plane.** Faults load from a file or a control socket mounted only into the test harness;
neither the broker nor the workload can reach it [H].

### 2.2 The broker's HTTP effect adapter [H]

**Process placement.** ADR-0002 §5 requires per-adapter processes "before the first adapter that calls an
external service". The payments adapter therefore runs as its own process, with its own Unix user and its
own network namespace. The broker core reaches it over a local socket using a length-prefixed structured
protocol. Only the adapter's namespace has a route to simpay (or to the real provider's IP ranges). The
workload stays `network_mode: none` (P0). The broker core does not need egress either.

**Fixed destination (SI-16).** Configuration fixes each of these at deploy time:

- the scheme, host, and port;
- the CA bundle, pinned to the simpay test CA in Demo P;
- the TLS server name;
- the exact path templates (`/v1/refunds`, `/v1/refunds/{id}`, `/v1/charges/{id}`).

Path segments are filled only with identifiers read from broker-owned rows and checked against a strict
pattern `^[a-z]{2,4}_[A-Za-z0-9]{8,64}$`. Further rules:

- Redirects are **disabled**: a `3xx` is classified as a provider anomaly (§2.4).
- No proxy environment variables are honoured.
- DNS: the hostname is resolved once at start-up, and its IP is pinned or checked against an allowlist.
  This blocks DNS-rebinding-style redirection.

**Secret custody (SI-02).**

- The API key and webhook signing secret are read from files readable only by the adapter's user.
  Docker/systemd secrets work; environment variables are not used, so C-01-style environment scans of
  sibling processes find nothing.
- The key is used only for the `Authorization` header, which every log path redacts.
- On the simpay side, an access policy accepts the key only from the adapter's address (SI-03).
- For real providers, the documentation should recommend:
  - a restricted key with `Refunds: Write` and `Charges: Read` only;
  - an access policy pinned to the broker's egress IP (§1.1).

**Request construction from typed values only.** The adapter receives a typed struct, never bytes from
the workload:

```
RefundDispatch { effect_id, charge_id /* trusted */, amount_minor: u64, idem_key /* derived */ }
```

It builds `charge=<charge_id>&amount=<amount_minor>&reference=<effect_id>` with fixed headers. The
workload controls no header, no path, no query parameter, and no free text. `reason` and `metadata` are
fixed by the adapter or omitted. `reason=fraudulent` is never sent, because it has provider-side side
effects (§1.3).

**Idempotency key.** The key is `base64url(HMAC-SHA256(broker_key, "nodkey.idem.v1" ‖ iss ‖ jti))`,
43 chars. That fits Stripe (255) and Adyen (64). PayPal (38 chars) would need truncation to 128 bits
(22 chars), and that profile should state the truncation [H]. The key reveals nothing about the grant
or the user, which follows Stripe's advice not to put personal data in keys. It is persisted in the
`RESERVED` row **before** dispatch, so every attempt reuses it.

**State machine (ADR-0006 §7, refined):**

1. **T1, one transaction.** The broker does the following, then commits synchronously:
   - verify the grant and consume its `jti`;
   - lock the order row;
   - check the trusted facts (§2.3);
   - check that the order has no pending `UNKNOWN` or `DISPATCHED` effect (AR-10);
   - lock the budget counters (when budgets ship);
   - insert `effect{id, state=RESERVED, op, order_id, charge_id, amount, currency, idem_key,
     fingerprint, dispatch_deadline}`.
2. **T2.** Set `RESERVED → DISPATCHED` and commit **before the first request byte is written**. After a
   crash, a `RESERVED` row was provably never sent and becomes `FAILED(not_dispatched)`. A `DISPATCHED`
   row is treated as `UNKNOWN`.
3. **Send.** Connect timeout 2 s, total timeout 10 s, response cap 64 KiB (all tunable).
4. **T3.** Classify the outcome (table below) and commit.

| Provider outcome | Nodkey state | Rationale |
|---|---|---|
| `200` and strict decode and `charge`, `amount`, `currency` all equal the request | `SUCCEEDED` (settlement = `pending`/`succeeded`) | Provider created the refund object |
| `400` with a known "no effect" code (`amount_too_large`, `charge_already_refunded`, invalid) | `FAILED` | Definite refusal [F §1.3] |
| `400 idempotency_error` (fingerprint mismatch) | `UNKNOWN` + alarm | Must not happen when the key is derived from a unique `jti`. Signals a broker bug or a lying provider |
| `401`/`403` | `FAILED` + operator alarm | Not executed; configuration fault |
| `409` in-progress, `429`, Adyen `transient-error: true` | stay `DISPATCHED`; bounded retry with the **same** key and parameters | Not executed or still running [F §1.2, §1.4] |
| `5xx`, timeout, reset after any request byte was written | `UNKNOWN` | "might have produced side effects" [F] |
| Connect refused, or TLS failure before any request byte | `FAILED(not_sent)` | Request never left [H: must be proven at the socket layer, not inferred from error strings] |
| `3xx`, malformed or oversized body, mismatched echo fields | `UNKNOWN` + alarm | Attacker G or bug. Never `SUCCEEDED`, never `FAILED` |

**Reconciliation of `UNKNOWN` [H].** ADR-0006 forbids retrying `UNKNOWN` "without documented upstream
deduplication". Stripe and simpay document that deduplication, so the reconciler follows these steps:

1. **Before `dispatch_deadline`** (= first send + retention − safety margin, e.g. 24 h − 2 h for Stripe),
   **resend the identical request with the same key**. The responses resolve as follows:
   - a cached `2xx` or `4xx` resolves the effect;
   - `409` means still in progress: wait;
   - a fresh execution means the first attempt never arrived, and is still at most once;
   - a cached `500` does not resolve, so go to step 2.
2. **Lookup.** `GET /v1/refunds?charge=…&reference=<effect_id>`. One match with equal amount ⇒
   `SUCCEEDED`. **"Not found" is never proof of no effect while the key could still be in progress**
   (`commit_after_delay`). `FAILED` requires both:
   - not found after the deadline;
   - a confirmed-final idempotency state, which simpay offers and real providers may not.

   Otherwise the effect stays `UNKNOWN`.
3. **After the deadline**, never resend. Use lookup only, then hand off to the operator. This matches
   Stripe's "don't retry with either the old key or a new one" [F].

The reconciler completes one already-consumed grant's effect under that grant's key; ADR-0006 must
state this is not a grantless effect (SI-19), see §3.

**Inbound webhooks.** Webhooks go to the adapter, never to the app.

- Verify the signature over the raw body, with a tolerance of ≤ 5 min and a non-zero clock check.
- Deduplicate on `event.id` in a table.
- **Treat the event as a hint only**: it triggers a `GET` of the referenced refund. That pattern mirrors
  Stripe's "thin events" approach (§1.5).

Replayed, duplicated, or unordered events then cause only redundant reads. `refund.failed` updates
settlement but never re-opens the refundable amount (§2.3).

**Response filtering.** The workload receives only:

```
{effect_id, state: succeeded|failed|unknown, settlement: pending|succeeded|failed|null,
 order_id, amount_minor, currency, failure_code: <closed enum>}
```

All values come from broker rows or a closed enum; provider bodies, headers, error text, and
references are never forwarded, which blocks response-borne injection (HTML, or prompt-injection text
aimed at Demo A's agent) [H]. For
`unknown`, the workload sees "outcome pending; do not retry". It can poll `payments.refund_status
{effect_id}` under a read grant scoped to the subject's own effects.

### 2.3 The typed operation `payments.refund{order_id, amount_minor, currency}` [H]

**Subject model.** The Demo P default is customer self-service: the subject refunds their own order.
A merchant-staff variant has the same tenant and an `orders.refund` role, and checks the tenant instead
of the owner. That variant is an open choice (§3).

| Parameter / fact | Class | Source | Check |
|---|---|---|---|
| `order_id` | `exact` | request body; shown on the confirmation page | must exist in tenant `ten` (from grant) |
| `amount_minor` | `exact` | request body; user-confirmed | integer, `1 ≤ amount ≤ remaining_refundable` (at T1, under lock) |
| `currency` | `exact` | request body; user-confirmed | must equal `order.currency` (trusted). Never sent to the provider |
| order owner | trusted fact | broker-owned `orders` row | `owner == sub` (grant-sourced) |
| `charge_id` | trusted fact | `orders.charge_id`, written at payment time by the broker | never accepted from the workload; strict decoding rejects unknown fields |
| charge amount, currency | trusted fact | `orders` row; cross-checked against `GET /v1/charges/{id}` at seeding | — |
| `remaining_refundable` | derived trusted fact | `charge_amount − Σ amount(effects in RESERVED, DISPATCHED, UNKNOWN, SUCCEEDED)` | in-flight and unknown amounts **encumber** |
| pending ambiguity | trusted fact | any `DISPATCHED`/`UNKNOWN` effect on this order | deny (AR-10) |
| order status | trusted fact | e.g. not `disputed` | deny (Stripe documents double-credit risk with disputes [F §1.3 refunds page]) |

**Notes:**

- **Confirmation summary.** The summary shows the amount formatted with the ISO 4217 exponent from a
  **broker-trusted table** (`1000 JPY` vs `10.00 USD`), not a workload-supplied label. That closes the
  currency-exponent confusion where "1000" displays differently than the user expects.
- **`currency`** is redundant with `order.currency` but is bound so the user approves an unambiguous
  amount; a mismatch is a denial, not a conversion.
- **A failed refund keeps its amount encumbered.** After `refund.failed` the amount stays encumbered
  until an operator action or a verified reconciliation releases it. That is conservative: liveness
  costs, not double refunds.
- **Double refund across two grants.** Two separate confirmations of the same refund produce two
  `jti`s, and so two upstream keys. The AR-10 precondition and the encumbering rule are what prevent a
  double refund while the first is unresolved. Once the first `SUCCEEDED`, a second confirmed refund is
  a second intended refund, bounded by `remaining_refundable`. A "business-intent key" (AR-10, second
  half) is therefore unnecessary for Demo P [H].

### 2.4 Attack scenarios Demo P must test [H]

Each scenario needs a positive control (the baseline profile, where the app holds the key and calls
simpay directly, shows the attack **succeeding**). It also needs a recorded simpay ledger assertion:
the count and sum of refunds per charge.

| ID | Attacker | Attack | Expected | Invariant |
|---|---|---|---|---|
| P-01 | C | Refund another user's order (valid session, forged `order_id`) | Denied at T1 (owner ≠ sub); simpay ledger unchanged | SI-10 |
| P-02 | C | Confirm 5.00, then submit 50.00 with the same grant | Denied: grant/request mismatch | SI-06, SI-20 |
| P-03 | C | Switch currency (confirm `JPY 1000` on a USD order, or submit a different currency than confirmed) | Denied: mismatch with grant or with `order.currency` | SI-06, SI-10 |
| P-04 | C, E | Replay a used grant (sequentially and 50× concurrently) | Exactly one refund; others return the stored outcome | SI-09 |
| P-05 | C, F | Two different confirmed grants on the same order race for the last 10.00 | One succeeds; the other is denied on `remaining_refundable` | SI-11 |
| P-06 | — | `commit_then_drop`; the app retries; the user re-confirms a new refund | First → `UNKNOWN`; new grant denied (AR-10); reconciler resolves to `SUCCEEDED`; ledger shows one refund | SI-15 |
| P-07 | — | `commit_after_delay` longer than the client timeout; reconciler lookup races the late commit | Stays `UNKNOWN` until the same-key retry resolves; never `FAILED` then duplicated | SI-15 |
| P-08 | — | `commit_then_500` (cached 500) | Same-key retry returns cached 500; GET-by-reference resolves | SI-15 |
| P-09 | — | `fail_before_commit` / `429` / `409` | Retry with the same key; exactly one refund | SI-09 |
| P-10 | C | `amount_minor` of 0, −1, 2^63, a float, a string, an exponent form, or a duplicate JSON key | Strict decoding denies | SI-08 |
| P-11 | C | Refund exceeding remaining (including after a partial refund, and while another is `UNKNOWN`) | Denied by broker before any dispatch (not merely by provider) | SI-10/11 |
| P-12 | C | Add `charge_id`, `reason`, `metadata`, `url` fields | Denied (unknown field) | SI-16 |
| P-13 | C | Workload connects to simpay (IP, DNS name, adapter socket, control socket) | No route (N-probes); with a stolen key from elsewhere, simpay's access policy rejects | SI-01, SI-03 |
| P-14 | C, D | Search for the API key or webhook secret (env, files, `/proc` of reachable processes, broker responses, error messages) | Not found; baseline control finds it | SI-02 |
| P-15 | C | Retention expiry: hold an `UNKNOWN` past the window, then try to force a re-dispatch | Reconciler does lookup only; no resend | SI-15 |
| P-16 | G | `200` with a mismatched amount/charge/currency; `200` for a non-existent refund | `UNKNOWN` + alarm; never `SUCCEEDED`; workload sees no provider text | SI-15 |
| P-17 | G | `3xx` to an attacker host | Not followed; `Authorization` never sent elsewhere | SI-02, SI-16 |
| P-18 | G | Oversized/slow/ambiguous JSON; error text with `<script>` or "ignore previous instructions" | Bounded resources; closed-enum response only | SI-16 (filtering) |
| P-19 | A, G | Forged webhook; replayed webhook (old `t`); duplicate event id | Rejected or no-op; state comes only from GET | — |

---

## 3. Open questions and residuals

1. **Provider honesty (G).** Reconciliation trusts the provider's GET. A provider that lies consistently
   cannot be detected from inside Nodkey (THREAT_MODEL, G "Partially"). The adapter only refuses to
   believe *inconsistent* answers.
2. **SI-19 vs reconciliation.** ADR-0006 needs an amendment stating that a same-key resend of a consumed
   grant's effect is not a new effect, together with its preconditions (deadline, identical
   fingerprint).
3. **Subject model.** Customer self-service versus staff refunds changes the ownership fact and the
   confirmer. Staff refunds make Stripe approval rules the closest overlap.
4. **Liveness and fidelity.** Encumbered `UNKNOWN`/failed amounts block refunds until an operator acts;
   simpay's "confirmed-final idempotency state" has no Stripe equivalent [H], so against Stripe a
   `FAILED` after `UNKNOWN` needs the operator.
5. **Budgets and mandates** (Phase 4) share T1; not designed here.
