# Nodkey payments adapter v1 — refunds against simpay (Demo P)

- **Status:** **Draft 1** (2026-10-25). Not reviewed. Nothing here is implemented or tested.
- **Implements:** [ADR-0012](../decisions/0012-payments-adapter.md) (Proposed), including its proposed
  ADR-0006 Amendment 2 (reconciler resend; OQ-10).
- **Builds on:** [effect-protocol-v2](effect-protocol-v2.md) Draft 3 (`payments.refund`,
  `payments.get_order`, §3.3, §4.4, §5); [grant-v1](grant-v1.md) Draft 3; ADR-0006 (incl. Amendment 1);
  ADR-0002 §5 (per-adapter process before the first external adapter).
- **Invariants:** SI-01, SI-02, SI-03, SI-09, SI-10, SI-11, SI-15, SI-16, SI-19.
- **Provider:** `tools/simpay` (SIMULATED; untrusted; attacker G in malicious mode). Facts about real
  providers are from research note 06 Part 1 and are cited there.

MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119 and RFC 8174.

**Scenario.** A customer of a self-service web shop (workload `shop`, `approver_source: named`) asks to
refund part of their own order. The shop proposes `payments.refund{order_id, amount_minor, currency}`
(effect-protocol-v2 §2.3). The customer approves on the auth origin. The broker decides in one
transaction and the payments adapter, a separate process that alone holds the simpay key and alone can
reach simpay, performs the provider call. The shop sees only a closed-enum outcome.

## 1. Components and channels

| Process | uid (example) | Holds | Network | Sockets |
|---|---|---|---|---|
| Workload `shop` | 10001 | nothing reusable | none | W (client) |
| Broker | 10002 | DB credential, `K_idem` | `data` only | W, G, A (listener); **P (client)** |
| Payments adapter | 10006 | simpay API key, pinned CA | `pay-egress` only | **P (listener)** |
| simpay | — | its own state | `pay-egress` (API, TLS), `harness` (admin) | none |

**Socket P** `/run/nodkey/br-pay/adapter.sock`. It follows the effect-protocol-v2 §1.2 socket model
with the roles reversed: the directory is owned by the **adapter** (listener), group = the broker's
group, setgid, mode `2750`; the socket is `0660`. The adapter checks `SO_PEERCRED` uid = `broker_uid` on
every connection; the broker checks uid = `adapter_uid`. Mismatch: close without response, alarm. The
directory is mounted into the broker and the adapter only, and is part of the control set (§1.2 manifest
rules). Start-up refusals of effect-protocol-v2 §1.2 extend to: adapter uid equal to any other role's
uid; P directory shared with or nested in another channel's directory.

**Framing and envelope:** exactly effect-protocol-v2 §1.2–§1.3 (strict JSON line ≤ 8 KiB, duplicate /
unknown / mistyped members rejected, `{"v":2,"id","op","args"}` and the response envelope). One request
per connection. The adapter serves at most `max_concurrent` (default 8) connections and closes idle
connections after 2 s.

**Meaning of errors on P (normative).** An `ok:false` response from the adapter MUST mean "no byte of a
provider request was written for this call". The broker MUST treat a lost response, a timeout
(`total_ms + 2 s`), a closed connection or an unparseable response on P as **ambiguous** (the adapter may
have sent).

### 1.1 Adapter operations

| `op` | `args` (exact) | `result` |
|---|---|---|
| `adapter.hello` | `{}` | `{"format":"nodkey.payments-adapter.v1","profile":"simpay","caps":[cap…]}`; `cap ∈ {idem_status, send_currency}` |
| `refund.create` | `{charge_id, amount_minor, currency, idem_key, reference}` | `Attempt` (§3.2) |
| `refund.get` | `{refund_id}` | `Lookup` |
| `refund.find` | `{charge_id, reference}` | `Lookup` |
| `idem.status` | `{idem_key}` (only if cap `idem_status`) | `{"state": "none"\|"in_progress"\|"done"}` or `{"state":"ambiguous","cause"}` |

Argument rules (else `invalid_argument`, nothing sent): `charge_id` `^ch_[A-Za-z0-9]{8,64}$`;
`refund_id` `^re_[A-Za-z0-9]{8,64}$`; `amount_minor` JSON integer `1 ..= max_amount_minor` (default
999 999 999 999, simpay's maximum); `currency` `^[A-Z]{3}$`; `idem_key`, `reference` exactly 43 chars of
base64url. The adapter holds no state about effects; every decision about state is the broker's.

```
Refund  = {"id": refund_id, "charge": charge_id, "amount_minor": uint, "currency": "[A-Z]{3}",
           "reference": text|null, "status": "pending"|"succeeded"|"failed"}
Attempt = {"class":"created","refund":Refund}
        | {"class":"refused","code":RefusalCode,"http":uint}
        | {"class":"busy","cause":"in_progress"|"rate_limited"}
        | {"class":"not_sent","cause":"connect"|"tls"|"local_limit"}
        | {"class":"ambiguous","cause":AmbCause}
Lookup  = {"class":"found","refunds":[Refund…] /* 1..2 */} | {"class":"not_found"}
        | {"class":"ambiguous","cause":AmbCause}
RefusalCode = amount_too_large | charge_already_refunded | charge_not_refundable | currency_mismatch
            | resource_missing | parameter_invalid | idempotency_params_mismatch | idempotency_key_invalid
            | auth_failed | permission_denied | other_4xx
AmbCause = timeout | reset_after_send | http_5xx | redirect | bad_status | bad_headers | oversized
         | bad_json | bad_content_type | echo_mismatch | schema | too_many_matches
```

Every result carries `"anomalies":[AnomalyCode…]` (possibly empty; closed enum equal to `AmbCause`
plus `contradicts_request`). Provider text (messages, `param`, headers, unknown fields) is never placed in
any result, log value, or alarm: only closed-enum codes and validated ids.

## 2. Egress, TLS and request construction

### 2.1 Network

- `pay-egress` is a Docker network with `internal: true`, subnet `172.30.30.0/24`, members **adapter**
  (`172.30.30.10`) and **simpay API** (`172.30.30.20`) only. The adapter is attached to no other network.
  The broker and the workload are not attached.
- simpay's admin listener binds only on `harness` (internal; members simpay and the test harness).
- The simpay key is restricted (`refunds: write`, `charges: read`) with `allowed_cidrs:
  ["172.30.30.10/32"]` (SI-03 analogue).
- The adapter connects to the IP literal and port in its configuration. It performs **no DNS**
  resolution, honours **no proxy** environment variables, and has no configurable destination other
  than this one.

### 2.2 TLS front: rustls listener in simpay

simpay gains an optional `api_tls: {cert_path, key_path}` configuration. When it is set, the API
listener speaks TLS only (rustls via `tokio-rustls`, TLS 1.3 only, ALPN `http/1.1`); the plain listener is
kept for simpay's own tests. The TLS layer wraps the same byte stream, so every fault (connection drop
after commit, malformed headers, slow drip) reaches the client unchanged. A reverse proxy is not used,
because it would normalize or replace exactly those responses (ADR-0012).

PKI for Demo P: `tests/demop/pki.sh` generates, into `var/demop/pki/` (Git-ignored), a test CA, a server
certificate for `simpay.test` (SAN DNS `simpay.test`, IP `172.30.30.20`, 7-day validity), and then
**deletes the CA private key**. No key material is committed.

Adapter TLS client (rustls): root store = the single pinned CA file (no system or webpki roots); TLS
1.3 only; SNI and name check = `server_name` (`simpay.test`); **early data disabled**; no session
resumption across requests; no client certificate.

### 2.3 HTTP

- HTTP/1.1, one request per connection (`Connection: close`), via `hyper` 1.x client connection over the
  TLS stream. Redirects are never followed (hyper does not follow them; any `3xx` is `ambiguous/redirect`).
- Limits (configuration, defaults): connect + TLS handshake 2 s; whole exchange `total_ms` 10 s; response
  head 16 KiB; body 64 KiB, read with a hard cap. Exceeding any limit after the request was written is
  `ambiguous` (`timeout` or `oversized`).
- **Sent / not sent (socket layer).** The adapter writes no request byte until the TLS handshake future
  has completed and the server certificate has verified. A failure up to that point is `not_sent`
  (`connect` or `tls`). Any failure after the first request byte is handed to the stream is `ambiguous`.
  Error strings are never inspected.
- Request (`POST /v1/refunds`), fixed headers only: `Host: simpay.test`, `Authorization: Bearer <key>`,
  `Idempotency-Key: <idem_key>`, `Content-Type: application/x-www-form-urlencoded`,
  `User-Agent: nodkey-payments-adapter/1`, `Content-Length`. Body built by `form_urlencoded` from typed
  values only: `charge=<charge_id>&amount=<amount_minor>&reference=<reference>` plus
  `&currency=<lowercase currency>` when cap `send_currency` is configured. No `reason`, no `metadata`, no
  other field.
- Lookups: `GET /v1/refunds/{refund_id}`; `GET /v1/refunds?charge=<charge_id>&reference=<reference>&limit=2`;
  `GET /v1/idempotency_keys?key=<idem_key>` (simpay **[sim]** extension). Paths are filled only from
  validated ids.

### 2.4 Secret custody (SI-02)

The API key is read once at start from `key_file` (owner adapter uid, mode `0400`; the adapter refuses
to start if the file is group- or world-readable, a symlink, or the key does not match `^rk_sim_` in the
`simpay` profile). The key is never in an environment variable, a command line, a log, an alarm or a
response. The `Authorization` value is held in a zeroizing buffer and redacted in every debug path.

## 3. Response handling (attacker G)

### 3.1 Parsing

A response body is decoded only if: status is `200`, `400`, `401`, `403`, `404`, `409`, `429` or `5xx`;
`Content-Type` is exactly `application/json` (parameters ignored); the body is valid UTF-8; strict JSON
with no duplicate keys (the broker's `strict_json` rules), nesting depth ≤ 8, integers only as `u64`
(no fraction, exponent or sign), total ≤ 64 KiB. hyper rejects malformed heads (CR/LF/NUL injection,
obs-fold, duplicate `Content-Length`, `Transfer-Encoding` with `Content-Length`); such a response is
`ambiguous/bad_headers`. Unknown JSON members are ignored, never forwarded.

A `Refund` is accepted only if `id` matches the refund-id pattern, `charge` the charge pattern, `amount`
is `1 ..= max_amount_minor`, `currency` is three ASCII letters (upper-cased for comparison), `status` is
one of the three values, `reference` is null or 1..128 of `[A-Za-z0-9_.:-]`. Otherwise `ambiguous/schema`.

### 3.2 Classification of `refund.create`

| Provider response | `Attempt` |
|---|---|
| `200`, valid `Refund`, `charge`, `amount_minor`, `currency` and `reference` equal to the request | `created` |
| `200` otherwise (mismatch or schema failure) | `ambiguous/echo_mismatch` or `/schema`, anomaly `contradicts_request` |
| `400` `invalid_request_error` with a code in `RefusalCode`; `401`; `403`; `404 resource_missing` | `refused` with that code |
| `400 idempotency_error / idempotency_params_mismatch` | `refused/idempotency_params_mismatch` + anomaly (cannot happen for a derived key; §4.2) |
| `409 idempotency_key_in_progress`; `429` | `busy` |
| any `5xx`; timeout or reset after send; `3xx`; other status; bad headers/JSON/size | `ambiguous` with the cause |

`refused` is **evidence, not a decision**: §4 decides what it means. `Lookup`: `200` list with 0 items →
`not_found`; 1–2 valid items → `found` (2 is an anomaly: `too_many_matches`); more → `ambiguous`;
`refund.get` `404 resource_missing` → `not_found`.

### 3.3 What Nodkey cannot detect

A provider that **lies consistently** — reports success for a refund it did not make, makes a refund it
reports as refused and hides it from lookups, ignores idempotency keys, or invents settlement — cannot be
detected from inside Nodkey. The adapter rejects only *inconsistent* answers (echo mismatch, create
vs. GET, refusal contradicting broker facts, malformed protocol). A malicious provider holds the
merchant's money anyway; duplicates it causes are not a capability Nodkey adds. Bounded by: the broker
asks for at most `remaining_refundable` per order and at most the daily budget per customer; the
reconciler resends at most `max_resends` times.

## 4. Effect state

### 4.1 Tables (broker DB, same database as `pending_effect` and `consumed_grant`)

**`orders`** — trusted facts, written only by the shop operator's DB role `nodkey_shop_operator`
(never by the broker, never by the workload, which has no DB route):

| Column | Type | Rule |
|---|---|---|
| `order_id` | bigint PK | `1 ..= 2^53 − 1` |
| `ten`, `owner_sub` | text | ID rules (grant-v1 §5.1) |
| `charge_id` | text | charge pattern; **immutable** |
| `currency` | text | `^[A-Z]{3}$`, in the broker's ISO 4217 table; **immutable** |
| `captured_minor` | bigint | ≥ 1; **immutable** |
| `external_refunded_minor` | bigint | refunds made outside Nodkey before seeding; ≥ 0; operator-updatable |
| `status` | text | `captured`, `partially_refunded`, `refunded`, `disputed`, `canceled`; operator-updatable |

A trigger rejects updates of immutable columns. Seeding happens at payment time (in Demo P: from a
fixture consistent with simpay's fixture; the harness asserts each `charge_id`, amount and currency
against simpay's admin ledger). The broker role has `SELECT` only. Operator updates take the row lock
and therefore serialize with T1 (SI-11).

**`payment_effect`** — one row per decided refund:

| Column | Notes |
|---|---|
| `pending_id` bytea(16) PK, FK `pending_effect` | one effect per grant (`jti = pending_id`) |
| `order_id`, `ten`, `sub`, `charge_id`, `amount_minor`, `currency` | **frozen at T1** from the record and the locked `orders` row |
| `idem_key`, `reference` | text(43), each UNIQUE; derived (§4.2); frozen |
| `state` | `RESERVED`, `DISPATCHED`, `SUCCEEDED`, `FAILED`, `UNKNOWN` |
| `reason` | closed enum (§4.6) |
| `released` | boolean; true only in `FAILED`; set in the transition that proves no effect |
| `provider_refund_id`, `settlement` | set only on `SUCCEEDED`; settlement `pending\|succeeded\|failed` |
| `reserved_at`, `dispatched_at`, `resend_deadline`, `resends`, `next_check_at`, `anomaly` | timing and bookkeeping |

The broker role may `INSERT` and update only `state`, `reason`, `released`, `provider_refund_id`,
`settlement`, timing and bookkeeping columns; a trigger enforces the transitions of §4.4 and the
immutability of frozen columns. **`refund_budget`** — §4.5.

### 4.2 Derived provider values

```
K_idem    = 32 bytes from broker_idem_key_file (broker uid, mode 0400; never leaves the broker)
idem_key  = b64url( HMAC-SHA256(K_idem, "nodkey.idem.v1" || 0x00 || u64be(len(iss)) || iss || u64be(16) || jti) )
reference = b64url( HMAC-SHA256(K_idem, "nodkey.ref.v1"  || 0x00 || u64be(len(iss)) || iss || u64be(16) || jti) )
```

`b64url` is unpadded (43 chars). `iss` and `jti` (= `pending_id`, 16 bytes) are those of the consumed
grant. This fixes the encoding of ADR-0006 §7's `HMAC(broker_key, "nodkey.idem.v1" ‖ iss ‖ jti)`
(length-prefixed, so unambiguous). Both values are unguessable to the workload, reveal nothing about the
user, and are computed once, in T1, and persisted before any send. Rotating `K_idem` is allowed only when
no row is in `RESERVED`, `DISPATCHED` or `UNKNOWN` (frozen values are never recomputed).

### 4.3 Transactions

**Lock order (refines ADR-0006 §1):** the transaction's own `pending_effect` row → `refund_budget` row →
`orders` row → `payment_effect` rows of that order. No transaction locks two `pending_effect` rows, so
taking the record first (effect-protocol-v2 §4.4 step 1) cannot deadlock.

**T1 — the execution transaction** (effect-protocol-v2 §4.4 steps 1–4 and 6; one transaction):

1. lock the record (`APPROVED`); window check; verify grant; W10 `consumed_grant` insert; savepoint;
   W11–W13;
2. W14 (execution checks, all under lock, all from trusted rows; §5 of effect-protocol-v2 as amended in
   §6 below):
   - lock and read `orders` row by `order_id`; require `ten` equal, `owner_sub = sub`,
     `currency = params.currency`, `status ∈ {captured, partially_refunded}`;
   - lock the order's `payment_effect` rows; require **none** in `RESERVED`, `DISPATCHED` or `UNKNOWN`;
   - `remaining = captured_minor − external_refunded_minor − Σ amount_minor(rows where NOT released)`;
     require `1 ≤ amount_minor ≤ remaining`;
   - budget (§4.5): locked conditional update succeeds;
3. on any failure: roll back to the savepoint (this also undoes the budget update), set `consumed_grant
   = DENIED`, record `FAILED` with `outcome_class = denied` and the reason, commit. **No `payment_effect`
   row, no adapter call.**
4. on success: `consumed_grant = ACCEPT`; insert `payment_effect` (`RESERVED`, frozen values, derived
   keys); record `APPROVED → EXECUTING`; deadline-at-commit check (grant-v1 D2-4: `now ≥ grant.exp +
   skew` ⇒ roll back everything); commit synchronously.

So the grant's single decision, the trusted-fact checks, the budget spend, the encumbrance of the
amount and the frozen request are one atomic commit. Facts that change **after** T1 commits do not affect
the decided effect; `charge_id`, `currency` and `captured_minor` cannot change at all.

**T2 — dispatch mark.** `UPDATE payment_effect SET state = DISPATCHED, dispatched_at = now,
resend_deadline = now + provider_retention_s − resend_margin_s WHERE pending_id = ? AND state =
RESERVED`; commit synchronously. Only if exactly one row changed does the dispatcher call
`refund.create`. Defaults: `provider_retention_s` 86 400 (simpay's and Stripe's minimum), margin 7 200.

**Dispatch.** At most 3 calls of `refund.create` with identical arguments, only while the previous result
is `busy` (waits 1 s, 2 s). Then **T3**, a compare-and-set from `DISPATCHED`:

| Last result (any earlier `ambiguous` makes the result `ambiguous`) | `payment_effect` | record |
|---|---|---|
| `created`, then `refund.get(id)` = `found` with an identical `Refund` | `SUCCEEDED`, `provider_refund_id`, `settlement` | `SUCCEEDED` |
| `not_sent` (first call; nothing was ever sent) | `FAILED/not_sent`, `released` | `FAILED` (`failed`) |
| `created` but the confirming GET is not identical; `refused`; `busy` after 3 calls; `not_sent` after an earlier call; `ambiguous`; P-channel failure | `UNKNOWN` with reason and anomaly | `UNKNOWN` |

A `refused` answer becomes `UNKNOWN`, not `FAILED`: the broker had already established under lock that
the refund is valid, so a refusal contradicts trusted facts (or reveals a provider lie such as simpay's
`deny_but_commit`); only the reconciler may conclude `FAILED`. `refused` with `auth_failed`,
`permission_denied` or `idempotency_params_mismatch` also raises an operator alarm.

**Recovery** (start-up, then every 5 s):
- `RESERVED` with `reserved_at + 30 s < now` → CAS to `FAILED/not_dispatched`, `released`; record `FAILED`.
  A dispatcher that loses this CAS race does not send (its T2 changes no row).
- `DISPATCHED` with `dispatched_at + total_ms + 30 s < now` → CAS to `UNKNOWN/lost_response`.

### 4.4 Transitions

| `payment_effect` | `pending_effect` (effect-protocol-v2 §3.3) |
|---|---|
| (insert) `RESERVED` → `DISPATCHED` | `EXECUTING` |
| `RESERVED` → `FAILED/not_dispatched`; `DISPATCHED` → `FAILED/not_sent` | `EXECUTING → FAILED` |
| `DISPATCHED` → `SUCCEEDED` / `UNKNOWN` | `EXECUTING → SUCCEEDED` / `UNKNOWN` |
| `UNKNOWN` → `SUCCEEDED` / `FAILED` (reconciler only) | `UNKNOWN → SUCCEEDED` / `FAILED` |
| `SUCCEEDED`: only `settlement` changes | unchanged |

Both rows change in the same transaction, which also takes the `orders` row lock whenever `released`
or the in-flight set changes (so T1's encumbrance read is current). There are no other transitions.

**Encumbrance.** Every `payment_effect` row encumbers its amount unless `released`. `released` is set
only where no provider effect is proven: `not_dispatched`, `not_sent`, and the reconciler's `FAILED`
(§4.7). A `SUCCEEDED` refund whose settlement later fails stays encumbered (alarm; operator action
outside v1). The order is blocked for new refunds while any of its rows is `RESERVED`, `DISPATCHED` or
`UNKNOWN` (AR-10).

### 4.5 Budget: per customer, per currency, per UTC day (AR-05)

`refund_budget(ten, sub, currency, day) → spent_minor, count`, primary key all four; `day` = UTC date of
the broker clock at T1. Limits come from broker configuration `payments.budget = {"per_customer_per_day":
{"<CUR>": limit_minor, …}, "max_refunds_per_customer_per_day": n}` (Demo P: USD 10000, EUR 10000,
JPY 10000, n = 3). In T1, after the savepoint: `INSERT … ON CONFLICT DO NOTHING`; `SELECT … FOR UPDATE`;
`UPDATE … SET spent_minor = spent_minor + $amt, count = count + 1 WHERE … AND spent_minor + $amt <= $limit
AND count + 1 <= $n`, which must change exactly one row. A currency without a configured limit is denied
(fail closed). Budget is spent at decision time and **never released** (also not for `released` effects):
liveness cost, never a double spend. Fixed windows allow up to 2× the limit across one midnight
(published). The budget limits what a compromised app can extract through users who approve unread
links (`named` residual, effect-protocol-v2 §6); it is not a mandate (OQ-12 stays open).

### 4.6 Reasons (closed enum; stored, and shown to the workload as `outcome.reason`)

T1 denials: `not_owner_or_unknown` (one code for missing, foreign tenant or not owner), `currency`,
`order_status`, `order_busy`, `insufficient_refundable`, `budget`. Effect outcomes: `not_dispatched`,
`not_sent`, `provider_declined`, `succeeded`, `pending_reconciliation`, `operator_required`.

### 4.7 Reconciler (`UNKNOWN`)

Runs in the broker for every `UNKNOWN` row whose `next_check_at ≤ now` (backoff 10 s, 1 min, 5 min,
30 min, then hourly). Each step uses the row's frozen values only.

**While `now < resend_deadline` and `resends < max_resends` (default 5):**
1. If cap `idem_status`: `idem.status`; `in_progress` → wait (no resend).
2. Same-key resend: `refund.create` with the frozen arguments (identical fingerprint); `resends += 1`.
   - `created` + confirming GET identical → `SUCCEEDED` (a cached success, or the first execution if the
     original never arrived — still at most once, by the provider's documented deduplication).
   - `busy` or `ambiguous` (including a cached `5xx`) → step 3.
   - `refused` → step 3; it may conclude `FAILED` only as below.
3. Lookup `refund.find(charge_id, reference)`:
   - `found`, one item, identical `charge`/`amount`/`currency`/`reference` → `refund.get` it → identical →
     `SUCCEEDED` (anomaly kept if a refusal or 5xx preceded it);
   - `not_found` **and** the step-2 result was `refused` with a business code (`amount_too_large`,
     `charge_already_refunded`, `charge_not_refundable`, `currency_mismatch`, `resource_missing`)
     **and** (cap `idem_status`: state `done`) → `FAILED/provider_declined`, `released`, alarm
     `provider_contradicts_facts`;
   - otherwise stay `UNKNOWN`.

**After `resend_deadline` (or `resends = max_resends`):** never send `refund.create` again. Lookups only
(daily, for 7 days): `found` + identical → `SUCCEEDED`. "Not found" never concludes anything. Then
`reason = operator_required`, alarm; the order stays blocked. Without a provider idempotency guarantee
(a profile lacking documented deduplication) resends are disabled and only this branch applies.

**Settlement.** For `SUCCEEDED` rows with `settlement = pending`: `refund.get` with the same backoff for
up to 30 days; `failed` → alarm, amount stays encumbered.

**Authority (ADR-0006 Amendment 2, proposed in ADR-0012; resolves OQ-10).** A reconciler resend is a
retransmission of the effect decided in T1, not a new effect: no new grant, no new `payment_effect` row,
no new key, no field taken from anywhere but the frozen row, only before `resend_deadline`, only for an
`UNKNOWN` row whose grant is consumed with `ACCEPT`. Its authority is that consumed grant recorded on a
broker-owned row; it is therefore not a grantless effect under SI-19. The workload has no way to trigger,
delay or shape it.

## 5. What the workload sees

- `effect.status` (effect-protocol-v2 §2.3) with `outcome = {class, receipt_id, reason}`; `reason` from
  §4.6, `null` while non-final except `pending_reconciliation` for `UNKNOWN` ("do not retry").
- `payments.get_order` (read grant) returns only broker values: `amount_minor = captured_minor`,
  `refunded_minor = external_refunded_minor + Σ amount(SUCCEEDED)`, `currency`, `status`.
- Never: provider ids, references, idempotency keys, provider status text, error messages, headers,
  settlement detail, anomaly codes.

**Confirmation page facts** (effect-protocol-v2 §5 "facts shown", plus): "Remaining refund allowance
today: <amount>" from `refund_budget` (read without lock; T1 decides), and "A refund on this order is
being processed" when any row is in flight.

## 6. Amendments to effect-protocol-v2 (to be folded into Draft 4)

| # | Section | Change |
|---|---|---|
| E1 | §1.2 | New socket P (adapter listener ← broker); start-up refusals extended (§1 above) |
| E2 | §2.3 | `outcome` gains `reason` (closed enum, §4.6); `reason` never carries provider text |
| E3 | §5 refund execution | "no `DISPATCHED`/`UNKNOWN`" becomes "no `RESERVED`, `DISPATCHED` or `UNKNOWN`"; adds the budget check; `charge_id` and the frozen values come from `orders` at T1 |
| E4 | §5 facts | remaining daily allowance; "being processed" notice |
| E5 | §4.4 step 6 | "the T1 `RESERVED` insert" is this spec's T1 step 4, including the budget update and derived keys |
| E6 | §3.3 | `UNKNOWN → FAILED` only by §4.7 rules, which set `released` |

## 7. Configuration (strict JSON, unknown members rejected)

Adapter: `{"format":"nodkey.payments-adapter.v1","socket_path","broker_uid","profile":"simpay",
"provider":{"addr":"172.30.30.20:8443","server_name":"simpay.test","ca_file","key_file",
"caps":["idem_status","send_currency"]},"limits":{"connect_ms":2000,"total_ms":10000,
"max_head":16384,"max_body":65536,"max_amount_minor":999999999999,"max_concurrent":8}}`. Refuses to
start: `addr` not an IP literal; CA file containing more than one certificate; key file mode or prefix
wrong; running as uid 0 or as `broker_uid`.

Broker (`nodkey.broker.v2`, new member): `"payments":{"adapter_socket","adapter_uid",
"idem_key_file","provider_retention_s":86400,"resend_margin_s":7200,"max_resends":5,"budget":{…}}`.
At start the broker calls `adapter.hello` and refuses to execute `payments.refund` (records stay
`APPROVED` and expire, BR-09 behaviour) while the adapter is unreachable or reports another format.

Workload registration: `shop`, `approver_source: named`, `write_ops: ["payments.refund"]`, `read_ops:
["payments.get_order"]`.

## 8. Webhooks: out of scope for Phase 4

The adapter and the broker expose **no inbound listener**. Outcomes and settlement come only from the
broker's own GETs (§4.7), which research 06 §2.2 already reduced webhooks to ("a hint only"); simpay's
`webhook_suppress` shows a receiver must not depend on them. An inbound listener would add an
attacker-A-reachable parser for no correctness gain. simpay's Demo P fixture has no webhook endpoints.
P-19 is therefore NOT APPLICABLE in Phase 4, with a negative test that no listener exists. A later spec
MAY add a receiver as a pure trigger for an early GET (signature over the raw body, tolerance ≤ 300 s,
`event.id` dedupe).

## 9. Residuals (published)

- **Consistent provider lies** (§3.3), including ignored idempotency on resend.
- **Adapter compromise** (via a parser bug exploited by G) yields the restricted simpay key, usable only
  from `172.30.30.10` (access policy) and only for refunds/charge reads; it yields no DB access, no grant,
  no other credential.
- **Broker compromise** (J) can call the adapter for any charge the key can refund; the adapter does not
  verify grants in v1 (ADR-0012, deferred).
- **Liveness:** `UNKNOWN`, failed settlement and unreleased amounts block an order until the reconciler
  or an operator resolves; the budget is never refunded; one in-flight refund per order.
- **Restore:** after a DB restore, every non-final `payment_effect` row MUST be set to `UNKNOWN` (never
  `FAILED/not_dispatched`), and every order with activity since the backup MUST be compared with
  `refund.find`/simpay listings before serving, in addition to ADR-0006 §9; a refund made after the
  backup is otherwise unknown to the broker (the provider's own remaining-amount check is the backstop).
- **Real providers:** the `idem_status` capability is a simpay **[sim]** extension; against Stripe the
  `FAILED/provider_declined` conclusion needs an operator.

## 10. Test plan

Every case needs an automated test reported PASS, FAIL or NOT TESTED. "Ledger" means simpay
`GET /admin/ledger` (count and sum of non-failed refunds per charge), read by the harness. Attack cases
need a **baseline positive control**: the baseline profile, where the shop holds `rk_sim_…` and reaches
simpay directly, MUST show the attack succeeding.

| # | Case | Expected | Maps to |
|---|---|---|---|
| PT-01 | Shop proposes a refund of another customer's order; that customer or the proposer approves | uniform error at render; if forced to execution (test fixture changes ownership after approval): `FAILED/denied`, `not_owner_or_unknown`; ledger unchanged | P-01, SI-10 |
| PT-02 | Approve 5.00; workload then tries to obtain or use a grant for 50.00 (new proposal, socket W grant, edited digest) | no grant on W (`grant_channel_invalid`); new proposal needs a new approval; digest mismatch → no grant; ledger: one 5.00 refund | P-02, SI-06 |
| PT-03 | `JPY 1000` proposed on a USD order; currency ≠ confirmed | `FAILED/denied` `currency` (or uniform error at render); nothing sent | P-03, SI-10 |
| PT-04 | Authority re-delivers one grant 50× concurrently while the recovery loop runs | one `payment_effect` row, one ledger refund | P-04, SI-09 |
| PT-05 | Two approved refunds race for the last 10.00 | one `SUCCEEDED`; other `FAILED/denied` (`order_busy` or `insufficient_refundable`); ledger sum ≤ captured | P-05, SI-11 |
| PT-06 | `commit_then_drop`; user approves a second refund on the same order | first `UNKNOWN`; second `FAILED/denied order_busy`; reconciler resend → cached 200 → `SUCCEEDED`; ledger 1 | P-06, SI-15 |
| PT-07 | `commit_after_delay` > `total_ms` | `UNKNOWN`; `idem.status in_progress` ⇒ no resend; then resolves `SUCCEEDED`; never `FAILED`; ledger 1 | P-07, SI-15 |
| PT-08 | `commit_then_500` | `UNKNOWN`; resend returns cached 500; `refund.find` resolves `SUCCEEDED`; ledger 1 | P-08 |
| PT-09 | `fail_before_commit`, `rate_limit`, `inflight_409`, `drop_before_commit` | busy: same-key retries; 5xx/drop: `UNKNOWN` then resend executes once → `SUCCEEDED`; ledger 1 | P-09, SI-09 |
| PT-10 | Proposals with `amount_minor` 0, −1, 2^63, 1.5, "5", 1e3, duplicate key | `invalid_argument` at propose | P-10, SI-08 |
| PT-11 | Refund > remaining: fresh, after a partial refund, while another is `UNKNOWN` | `FAILED/denied` before dispatch; adapter call count 0 | P-11, SI-11 |
| PT-12 | Propose with extra `charge_id`, `reason`, `metadata`, `url`; adapter `refund.create` with extra member | `invalid_argument`; adapter `malformed_request`, nothing sent | P-12, SI-16 |
| PT-13 | From the shop: connect to simpay IP/name, adapter socket, simpay admin; use the key from another `pay-egress` address | no route / path absent; simpay `401 source_address_not_allowed` | P-13, SI-01, SI-03 |
| PT-14 | Search for the simpay key in the shop (env, files, `/proc`, broker responses, error texts) and in the broker container | not found in either; baseline control finds it in the shop | P-14, SI-02 |
| PT-15 | `UNKNOWN` held past `resend_deadline` (test profile: retention 120 s, simpay `system` clock); then any workload action | no `refund.create` after the deadline (adapter call log); lookup only; `operator_required` | P-15, SI-15, SI-19 |
| PT-16 | Malicious: `lie_amount`, `lie_charge`, `lie_currency`, `lie_status`, `phantom_success`, `deny_but_commit` | never `SUCCEEDED` on a lie; `phantom_success` → resend executes → one real refund; `deny_but_commit` → lookup → `SUCCEEDED` + alarm; ledger ≤ 1 | P-16, SI-15 |
| PT-17 | `redirect` to a harness listener | `UNKNOWN/redirect`; harness listener sees 0 connections; no `Authorization` elsewhere | P-17, SI-02, SI-16 |
| PT-18 | `oversized_*`, `slow_drip`, every `malformed_json` and `header_injection` variant, `hostile_error_text` | bounded memory and time; `ambiguous` cause; `effect.status` and logs contain no provider text (byte search for the markers) | P-18, SI-16 |
| PT-19 | No inbound listener on adapter or broker (`ss -ltn` in both namespaces) | none | P-19 (N/A) |
| PT-20 | Ownership, status or (blocked) charge change between approval and execution | status/owner: `FAILED/denied`, no adapter call; immutable column update rejected by trigger | SI-10, SI-11 |
| PT-21 | Crash broker after T1 commit; after T2; after send before T3; crash adapter mid-request; stall DB at T3 | `FAILED/not_dispatched` (no ledger refund); `UNKNOWN` → resolved; never a duplicate; ledger matches final state | SI-09, SI-15 |
| PT-22 | Budget: 4th refund in a day; amount over limit; 32 concurrent T1s near the limit; currency without a limit | `FAILED/denied budget`; spent never exceeds limit | AR-05, SI-11 |
| PT-23 | `late_refund_failed` | settlement `failed`, alarm, amount stays encumbered | §4.7 |
| PT-24 | Wrong-uid peer on P (both directions); adapter config with DNS name, two CAs, readable key file | connection closed + alarm; adapter refuses to start | §1, SI-02 |
| PT-25 | TLS: wrong CA, wrong SAN, TLS 1.2-only server, plain HTTP server | `not_sent/tls`; `FAILED/not_sent`, `released`; ledger 0 | §2.2 |
| PT-26 | Reconciler resend inputs equal T1's frozen values byte for byte (simpay fingerprint never mismatches); `K_idem` derivation vectors | identical; vectors match | §4.2, OQ-10 |
| PT-27 | Proposal and `effect.status` traffic cannot trigger a resend or a dispatch (fuzz W while rows are `UNKNOWN`) | adapter call log unchanged | SI-19 |
| PT-28 | Restore drill (§9) | non-final rows → `UNKNOWN`; no refund duplicated | SI-09 |
