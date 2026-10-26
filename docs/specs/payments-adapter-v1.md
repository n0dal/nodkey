# Nodkey payments adapter v1 — refunds against simpay (Demo P)

- **Status:** **Draft 2** (2026-10-25). Supersedes Draft 1 (changes in §12). Not re-reviewed. Nothing
  here is implemented or tested.
- **Implements:** [ADR-0012](../decisions/0012-payments-adapter.md) (rev. 1) and
  [ADR-0006](../decisions/0006-replay-and-effect-state.md) Amendment 2 (reconciler resend; OQ-10).
- **Builds on:** [effect-protocol-v2](effect-protocol-v2.md) **Draft 3.1** (`payments.refund` now binds
  `charge_id`); [grant-v1](grant-v1.md) Draft 3; ADR-0002 §5; ADR-0006 (incl. Amendment 1).
- **Review:** [`2026-10-25-payments-adapter-review.md`](../reviews/2026-10-25-payments-adapter-review.md)
  (PA-xx; resolution table at its end).
- **Invariants:** SI-01, SI-02, SI-03, SI-05, SI-06, SI-09, SI-10, SI-11, SI-15, SI-16, SI-19.
- **Provider:** `tools/simpay` (SIMULATED; untrusted; attacker G in malicious mode).

MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119 and RFC 8174.

**Scenario.** A customer of a self-service shop (workload `shop`, `approver_source: named`) asks to
refund part of their own order. The shop proposes `payments.refund{order_id, amount_minor, currency}`;
the broker adds the order's `charge_id` from its trusted `orders` table into the immutable record; the
customer approves exactly that (including the charge) on the auth origin; the authority signs it. The
broker decides in one transaction. The **payments adapter** — a separate process that alone holds the
simpay key and alone can reach simpay — **verifies the signed grant itself**, re-checks the order →
charge → owner mapping in its own read-only view, and builds the provider request **only from the
grant**. The shop sees only a closed-enum outcome.

**What the adapter adds (with §2 inputs intact, an honest provider and a correct host clock):** a
compromised broker can cause at most **one refund per signed grant**, of exactly the signed amount and
currency, to exactly the signed charge, and only while the grant is younger than `R_max`.

## 1. Components, networks and channels

| Process | uid | Holds | Networks (exact) | Sockets |
|---|---|---|---|---|
| Workload `shop` | 10001 | nothing reusable | none | W (client) |
| Broker | 10002 | DB credential (`nodkey_broker`) | `data` 172.30.20.10 | W, G, A (listener); P (client) |
| Payments adapter | 10006 | simpay key, `K_idem`, DB credential (`nodkey_payments_adapter`, read-only) | `data` **172.30.20.30** and `pay-egress` **172.30.30.10** | P (listener) |
| PostgreSQL | — | — | `data` 172.30.20.20 | — |
| simpay | — | its own state | `pay-egress` 172.30.30.20 (API, TLS); `harness` (admin) | — |

- `data` and `pay-egress` are Docker networks with `internal: true`. `pay-egress` has exactly the adapter
  and the simpay API. The adapter has no other network. Neither the broker, the authority, the gateway
  nor the workload is attached to `pay-egress`.
- On `data` the only listener is PostgreSQL. The adapter and the broker expose **no** TCP listener.
  `pg_hba.conf` admits `nodkey_payments_adapter` only from 172.30.20.30 and `nodkey_broker` only
  from 172.30.20.10 (SCRAM).
- The adapter container has no `CAP_NET_ADMIN` and IP forwarding is off in its namespace, so it does not
  route between `data` and `pay-egress`.
- simpay's key is restricted (`refunds: write`, `charges: read`) with `allowed_cidrs:
  ["172.30.30.10/32"]` (SI-03 analogue).

**Socket P** `/run/nodkey/br-pay/adapter.sock`: the effect-protocol-v2 §1.2 socket model with the
adapter as listener (directory owned by the adapter, group = broker's group, setgid, `2750`; socket
`0660`). Both sides check the peer uid with `SO_PEERCRED` (adapter: `broker_uid`; broker: `adapter_uid`);
a mismatch closes without response and raises an alarm. The directory is part of the control set and is
mounted into the broker and the adapter only. Start-up refusals of §1.2 extend to the adapter uid
colliding with any other role, and to P's directory being shared or nested.

**Framing:** effect-protocol-v2 §1.2–§1.3 (strict JSON line ≤ 8 KiB; the grant travels as grant-v1 §2
transport text, ≤ 2 KiB of the line). One request per connection; at most `max_concurrent` (8)
connections; 2 s idle timeout.

**Meaning of errors on P (normative).** `ok:false` from the adapter MUST mean "no byte of a provider
request was written for this call". A lost response, a timeout (`total_ms + 2 s`), a closed connection
or an unparseable response is **ambiguous** to the broker.

## 2. Adapter inputs the broker cannot write (PA-03)

The adapter refuses to start unless every check in this table holds, and re-reads nothing at runtime
(rotation = restart).

| Input | Content | Enforcement |
|---|---|---|
| Key registry `/etc/nodkey-adapter/keys.json` | the authority's grant keys (grant-v1 §8 format) | operator-provisioned file, owner root, mode `0444`, parent directories root-owned and not group/other-writable; mounted read-only into the adapter only; start check: regular file, not a symlink, owner ∉ {broker uid, adapter uid}, no group/other write bit on file or parents |
| Config `/etc/nodkey-adapter/config.json` | `broker_id` (= grant `aud`), `wid` of `shop`, `R_max_s`, provider settings, limits | same as the registry |
| Operation declaration | `payments.refund` opv 1 placements (§3.1) | compiled into the adapter; not configurable |
| Orders view | `SELECT order_id, ten, owner_sub, charge_id, currency FROM orders` | DB role `nodkey_payments_adapter`: `SELECT` on those `orders` columns only, nothing else. `orders` is owned by `postgres`; only `nodkey_shop_operator` may write it; `nodkey_broker` has `SELECT` only and no `CREATEROLE`, ownership or `GRANT` option, so it can neither write `orders` nor alter the adapter's role. Password file owner adapter, `0400` |
| Clock | host `CLOCK_REALTIME` | no container has `CAP_SYS_TIME`; Linux time namespaces do not virtualize `CLOCK_REALTIME`; the adapter refuses to verify while the clock reads below 2024-01-01. Host clock rollback is attacker I (residual) |
| simpay key, `K_idem` | secrets | files owner adapter uid, mode `0400`, not symlinks; never mounted into the broker |
| Pinned CA | one certificate | owner root, `0444`, exactly one certificate |

The deployment test (PT-31) asserts that none of these paths is present in, or writable from, the broker
container.

## 3. Grant check in the adapter (PA-01, PA-02)

### 3.1 Checked claims

The adapter verifies the grant bytes the broker stored at `APPROVED` with a **new `nodkey-grant` entry
point**, `verify_retransmission(ctx, bytes, now, r_max) -> RetransmissionAuthorized`, typed differently
from the broker's consuming `verify(..).decide(..)`, so the broker's path can never skip `exp`. It
performs grant-v1 §7.2 steps 1–9 (structure, `typ`, algorithm, registry lookup by `kid`, key validity at
`iat`, signature, `iss`) and then requires, in order (any failure → `ok:false grant_refused`, nothing
sent):

| Claim | Requirement |
|---|---|
| `aud` | = configured `broker_id` |
| `wid` | = configured `wid` of `shop` |
| `knd`, `cfm`, `use` | `1`, `1`, `1` (confirmed single-use write) |
| `op`, `opv` | `payments.refund`, `1` |
| `res` | exactly `{0: order_id}` (uint) |
| `con` | exactly `{0: amount_minor (uint ≥ 1), 1: currency, 2: charge_id}`; nothing else |
| `nbf`, `iat` | `≤ now + skew` (skew 5 s) |
| **age** | `now − iat ≤ R_max_s` (default 43 200 s = 12 h) |
| `exp` | **not** checked (deliberately: resends happen after `exp`; the age rule replaces it) |

Not checked by the adapter: revocation (`revoked_before`) and consumption. Both are the broker's; their
loss under broker compromise is a residual (§10).

**`R_max` start-up rule.** `R_max_s < provider_retention_s − resend_margin_s`, and `resend_margin_s <
provider_retention_s ≤` the profile's documented minimum retention (simpay: its configured
`idempotency_retention_s`; Stripe: 86 400). Otherwise the adapter refuses to start. Defaults:
retention 86 400, margin 7 200, `R_max` 43 200.

### 3.2 Order check against the adapter's own view

For `refund.create` (initial and resend alike) the adapter reads `orders` by `order_id` (§2) and requires
a row with `ten` = grant `ten`, `owner_sub` = grant `sub`, `charge_id` = grant con2, `currency` = grant
con1. Otherwise `grant_refused`; DB unavailable → `unavailable`. Nothing is sent in either case. This
check does not cover status, remaining amount, budget or in-flight effects; those stay broker checks.

### 3.3 Derived provider values (PA-09)

```
D         = "nodkey.pay.v1" || 0x00 || lp(provider_account) || lp(op) || u64be(opv) || lp(iss) || lp(jti)
idem_key  = b64url( HMAC-SHA256(K_idem, "idem" || 0x00 || D) )
reference = b64url( HMAC-SHA256(K_idem, "ref"  || 0x00 || D) )
lp(x)     = u64be(len(x)) || x
```

`K_idem` is 32 bytes held only by the adapter. `provider_account` is the configured simpay account id.
`iss`, `jti` (16 bytes, = `pending_id`), `op`, `opv` are from the verified grant. b64url is unpadded
(43 chars). The broker never computes or supplies these values. Because they and every request field
derive from the grant, any replay of one grant within the provider's retention is a same-key,
same-fingerprint request (provider deduplicates), and a different grant cannot collide.

`adapter.hello` returns `idem_kid` = first 8 bytes (hex) of `HMAC-SHA256(K_idem, "kid")`. The broker
stores it on each `payment_effect` row and refuses to dispatch or resend a row whose `idem_kid` differs
from the current one (lookup-only, then operator). The operator MUST rotate `K_idem` only when no row is
non-final; the broker refuses to start payment processing (alarm) if non-final rows carry another kid.

## 4. Adapter operations

| `op` | `args` (exact) | `result` |
|---|---|---|
| `adapter.hello` | `{}` | `{"format":"nodkey.payments-adapter.v1","profile":"simpay","caps":[…],"idem_kid","r_max_s"}`; caps ⊆ `{idem_status, send_currency}` |
| `refund.create` | `{grant}` | `Attempt` |
| `refund.find` | `{grant}` | `Lookup` (by grant's charge and derived reference) |
| `refund.get` | `{grant, refund_id}` | `Lookup` (a found refund must match the grant's charge) |
| `idem.status` | `{grant}` (cap `idem_status`) | `{"state":"none"\|"in_progress"\|"done"}` or `{"state":"ambiguous","cause"}` |

Every op runs §3.1 first; `refund.create` also runs §3.2. Errors (`ok:false`, nothing sent):
`grant_refused`, `unavailable`, `invalid_argument`, plus the envelope errors.

```
Refund  = {"id","charge","amount_minor","currency":"[A-Z]{3}","reference","status":"pending"|"succeeded"|"failed"}
Attempt = {"class":"created","refund":Refund,"reference"}
        | {"class":"refused","code":RefusalCode,"http":uint,"reference"}
        | {"class":"busy","cause":"in_progress"|"rate_limited","reference"}
        | {"class":"not_sent","cause":"connect"|"tls"}
        | {"class":"ambiguous","cause":AmbCause,"reference"}
Lookup  = {"class":"found","refunds":[Refund]} | {"class":"not_found"} | {"class":"ambiguous","cause":AmbCause}
RefusalCode = amount_too_large | charge_already_refunded | charge_not_refundable | currency_mismatch
            | resource_missing | parameter_invalid | idempotency_params_mismatch | idempotency_key_invalid
            | auth_failed | permission_denied | other_4xx
AmbCause = timeout | reset_after_send | http_5xx | redirect | bad_status | bad_headers | oversized
         | bad_json | bad_content_type | echo_mismatch | schema | too_many_matches
```

Every result carries `"anomalies":[…]` (closed enum: `AmbCause` values plus `contradicts_request`).
Provider text (messages, `param`, headers, unknown members) never appears in any result, log or alarm.

## 5. Egress, TLS and HTTP

**TLS front: rustls listener in simpay.** simpay gains `api_tls: {cert_path, key_path}`; with it the API
listener is TLS-only (`tokio-rustls`, TLS 1.3, ALPN `http/1.1`). The TLS layer wraps the same byte
stream, so every fault (drop after commit, malformed heads, slow drip) reaches the client unchanged.
`tests/demop/pki.sh` generates into `var/demop/pki/` (Git-ignored) a test CA and a 7-day server
certificate (SAN DNS `simpay.test`, IP 172.30.30.20), then deletes the CA private key.

**Adapter TLS client:** root store = the pinned CA only; TLS 1.3 only; SNI and name check `simpay.test`;
early data off; no resumption; no client certificate. Destination = IP literal and port from config; no
DNS; no proxy environment variables.

**HTTP (pinned `hyper` 1.x client options, PA-10):** HTTP/1.1, one request per connection; maximum 64
response headers; read buffer = `max_head` (16 KiB); obsolete multiline headers in responses
**rejected** (set explicitly); header values must be visible ASCII or tab, else `bad_headers`; body read
with a hard 64 KiB cap; connect + handshake 2 s; whole exchange `total_ms` 10 s. Redirects are never
followed. `1xx` responses are skipped by hyper; any final status outside §6.1's list is `bad_status`.

**Sent / not sent (socket layer).** No request byte is written until the TLS handshake has completed
and the certificate verified; a failure up to there is `not_sent`. Any failure after the first request
byte is handed to the stream is `ambiguous`. Error strings are never inspected.

**Request.** `POST /v1/refunds` with fixed headers only: `Host: simpay.test`, `Authorization: Bearer
<key>`, `Idempotency-Key: <idem_key>`, `Content-Type: application/x-www-form-urlencoded`, `User-Agent:
nodkey-payments-adapter/1`, `Content-Length`. Body (`form_urlencoded`, from the grant only):
`charge=<con2>&amount=<con0>&reference=<reference>`, plus `&currency=<lowercase con1>` with cap
`send_currency`. Lookups: `GET /v1/refunds/{refund_id}` (id `^re_[A-Za-z0-9]{8,64}$`),
`GET /v1/refunds?charge=<con2>&reference=<reference>&limit=3`, `GET /v1/idempotency_keys?key=<idem_key>`
(simpay **[sim]**).

**Custody (SI-02).** Secrets are read once from the §2 files; never in environment, command line, logs,
alarms or responses; held in zeroizing buffers; redacted in every debug path.

## 6. Response handling (attacker G)

### 6.1 Parsing

Bodies are decoded only for status `200`, `400`, `401`, `403`, `404`, `409`, `429`; **`5xx` bodies are not
decoded** (`ambiguous/http_5xx`). Decoding requires `Content-Type` exactly `application/json`, valid
UTF-8, strict JSON without duplicate keys (broker `strict_json` rules), depth ≤ 8, integers only as `u64`,
≤ 64 KiB. Unknown members are ignored and never forwarded. A `Refund` is valid only if `id` matches the
refund-id pattern, `charge` = the grant's charge, `amount` in `1 ..= 999 999 999 999`, `currency` three
ASCII letters (upper-cased), `status` one of three, `reference` 1..128 of `[A-Za-z0-9_.:-]`.

### 6.2 Classification of `refund.create`

| Provider response | `Attempt` |
|---|---|
| `200`, valid `Refund`, `charge`/`amount`/`currency`/`reference` = grant-derived values | `created` |
| `200` otherwise | `ambiguous/echo_mismatch` or `/schema`, anomaly `contradicts_request` |
| `400` with a `RefusalCode`; `401`; `403`; `404 resource_missing` | `refused` |
| `409 idempotency_key_in_progress`; `429` | `busy` |
| `5xx`; timeout or reset after send; `3xx`; other status; bad heads/JSON/size | `ambiguous` |

`refused` is evidence, not a decision (§7.3). Lookups: list with 0 items → `not_found`; exactly 1 valid
item → `found`; 2 or more, or `has_more: true` → `ambiguous/too_many_matches`; `refund.get` `404` →
`not_found`.

### 6.3 What Nodkey cannot detect

A provider that **lies consistently** (fake success, a refund reported as refused and hidden from
lookups, ignored idempotency, invented settlement) cannot be detected. The adapter rejects only
*inconsistent* answers. A malicious provider holds the merchant's money anyway.

## 7. Effect state (broker)

### 7.1 Tables (broker DB)

**`orders`** — trusted facts. Columns: `order_id` bigint PK (`1 ..= 2^53 − 1`); `ten`, `owner_sub` (ID
rules); `charge_id` **UNIQUE**, `^ch_[A-Za-z0-9]{8,64}$`, immutable; `currency` `^[A-Z]{3}$` in the ISO
4217 table, immutable; `captured_minor` ≥ 1, immutable; `external_refunded_minor` ≥ 0; `status ∈
{captured, partially_refunded, refunded, disputed, canceled}`. A trigger rejects updates of immutable
columns. Because `charge_id` is UNIQUE, one order row **is** the charge row: every per-charge sum and
lock below is taken on it.

**Writer (PA-04).** Only the role `nodkey_shop_operator` may `INSERT`/`UPDATE` `orders`. Its credential
is held by the operator's payment-capture integration, which MUST run outside the workload's trust
domain and take no input from the workload; before inserting, it MUST verify the charge with
`GET /v1/charges/{id}` (same account, `succeeded`, amount = `captured_minor`, currency) using its own
`charges: read` key. **The SI-10 claim for refunds rests on that path.** If the shop application itself
writes `orders`, the claim is not made. In Demo P the writer is the harness seeding from a fixture and
asserting each row against simpay's admin ledger; the shop container has no DB route (PT-13). The
operator SHOULD run a periodic, alarm-only comparison of `captured_minor − external_refunded_minor` with
`GET /v1/charges/{id}.amount_refunded` (PA-11); it never raises a remaining amount automatically.

**`payment_effect`** — one row per decided refund: `pending_id` PK (FK `pending_effect`); `order_id`,
`charge_id`, `ten`, `sub`, `amount_minor`, `currency` frozen from the grant at T1; `idem_kid`;
`reference` (set from the first adapter result, audit only); `state ∈ {RESERVED, DISPATCHED, SUCCEEDED,
FAILED, UNKNOWN}`; internal `reason`; `released`; `provider_refund_id`, `settlement` (only on
`SUCCEEDED`); `lease_owner`, `lease_until`; `reserved_at`, `dispatched_at`, `resend_deadline`, `resends`,
`reconcile_rounds`, `next_check_at`, `anomaly`. Index on `charge_id`. A trigger enforces §7.4 and the
immutability of frozen columns.

### 7.2 Transactions

**Lock order:** own `pending_effect` row → `refund_budget` row → `orders` (charge) row → that charge's
`payment_effect` rows. No transaction locks two `pending_effect` rows.

**T1 — execution transaction** (effect-protocol-v2 §4.4): lock record; window; verify; W10; savepoint;
W11–W13; then W14 **in this order**, stopping at the first failure (PA-07):

1. lock `orders` by `order_id`; require it exists, `ten` = grant `ten`, `owner_sub` = grant `sub` —
   else reason `not_owner_or_unknown`;
2. `charge_id` = grant con2 (always true for an existing row; a mismatch is an alarm) and `currency` =
   grant con1 — else `currency`;
3. `status ∈ {captured, partially_refunded}` — else `order_status`;
4. no `payment_effect` row of this `charge_id` in `RESERVED`, `DISPATCHED` or `UNKNOWN` — else
   `order_busy`;
5. `remaining = captured_minor − external_refunded_minor − Σ amount_minor(rows of this charge_id
   NOT released)`; `1 ≤ amount_minor ≤ remaining` — else `insufficient_refundable`;
6. budget (§7.5) — else `budget`.

On failure: roll back to the savepoint, `consumed_grant = DENIED`, record `FAILED` (`denied`), commit; no
`payment_effect` row, no adapter call. On success: `consumed_grant = ACCEPT`; insert `payment_effect`
`RESERVED` with frozen values, `idem_kid`, `resend_deadline = grant.iat + R_max_s − 60`; record
`APPROVED → EXECUTING`; deadline-at-commit check (grant-v1 D2-4); commit synchronously.

**Leases (PA-06).** Every adapter call on a row is made by the holder of its lease. A lease is taken or
extended by `UPDATE … SET lease_owner = $me, lease_until = now + L WHERE pending_id = ? AND state = $s
AND (lease_owner = $me OR lease_until < now)` changing exactly one row, committed **before** the call.
`$me` is random per process start. `L_dispatch = 3 × (total_ms + 2 s) + 3 s + 10 s` (49 s by default);
`L_reconcile = total_ms + 2 s + 10 s` per call.

**T2 — dispatch.** In one statement: `RESERVED → DISPATCHED`, `dispatched_at = now`, lease
`L_dispatch`. Only if exactly one row changed is `refund.create` called. At most 3 calls, only while the
previous result is `busy` (waits 1 s, 2 s); before each retry the dispatcher re-asserts its lease (the
CAS above); if it fails, the dispatcher stops without writing.

**T3** (CAS from `DISPATCHED` under the dispatcher's lease; a lost lease discards the result):

| Result | `payment_effect` | record |
|---|---|---|
| `created`, then `refund.get` = `found`, identical | `SUCCEEDED` | `SUCCEEDED` |
| `not_sent` on the first call | `FAILED/not_sent`, `released` | `FAILED` |
| anything else (incl. `refused`, `busy` after 3 calls, `not_sent` after an earlier call, `grant_refused`, P failure) | `UNKNOWN` (+ alarm for `refused`/`grant_refused`) | `UNKNOWN` |

`refused` is not `FAILED`: the broker proved the refund valid under lock, so a refusal contradicts
trusted facts (or is a lie such as `deny_but_commit`).

**Recovery** (start-up, every 5 s): `RESERVED` with `reserved_at + 30 s < now` → CAS
`FAILED/not_dispatched`, `released` (a dispatcher losing this race sends nothing). `DISPATCHED` whose
lease has expired → CAS `UNKNOWN/lost_response`.

### 7.3 Reconciler (`UNKNOWN`) — lookup first (PA-05)

For each `UNKNOWN` row with `next_check_at ≤ now` and an expired lease, the reconciler takes the lease
and runs one **round** (backoff 10 s, 1 min, 5 min, 30 min, then hourly):

1. `refund.find`: `found` (one item, identical) → `refund.get` it → identical → `SUCCEEDED`. Stop.
2. Resend gate — all must hold, else go to step 4: `now < resend_deadline`; `resends < max_resends` (5);
   row `idem_kid` = current; provider profile documents deduplication; and with cap `idem_status`:
   `idem.status` is `done` or `in_progress` — or `none` **only in the first round** (`none` later means
   pruned or never received: stop resending, `operator_required`). `in_progress` → wait, no resend.
3. Same-key resend `refund.create{grant}`; `resends += 1`. `created` + identical GET → `SUCCEEDED`.
   `refused` with a business code (`amount_too_large`, `charge_already_refunded`,
   `charge_not_refundable`, `currency_mismatch`, `resource_missing`) **and** a following
   `refund.find` = `not_found` **and** (cap `idem_status`) state `done` → `FAILED/provider_declined`,
   `released`, alarm `provider_contradicts_facts`. Anything else → stay `UNKNOWN`.
4. Past the gate: lookups only (daily, 7 days); "not found" never concludes anything; then
   `operator_required`, alarm; the charge stays blocked.

The adapter enforces `R_max` independently (§3.1), so a broker clock rollback or a misconfigured
retention cannot produce a resend after the provider could have pruned the key.

**Settlement:** for `SUCCEEDED` with `settlement = pending`, `refund.get` on the same backoff for up to
30 days; `failed` → alarm, amount stays encumbered.

**Authority (ADR-0006 Amendment 2).** A resend retransmits the effect decided in T1: the same stored
grant, no new row, no value from the workload; the adapter re-verifies the grant and its age. It is not
a grantless effect under SI-19. The workload cannot trigger, delay or shape it.

### 7.4 Transitions

| `payment_effect` | `pending_effect` |
|---|---|
| (insert) `RESERVED` → `DISPATCHED` | `EXECUTING` |
| `RESERVED` → `FAILED/not_dispatched`; `DISPATCHED` → `FAILED/not_sent` | `EXECUTING → FAILED` |
| `DISPATCHED` → `SUCCEEDED` / `UNKNOWN` | `EXECUTING → SUCCEEDED` / `UNKNOWN` |
| `UNKNOWN` → `SUCCEEDED` / `FAILED` (reconciler only) | `UNKNOWN → SUCCEEDED` / `FAILED` |
| `SUCCEEDED`: only `settlement` | unchanged |

Both rows change in one transaction, which takes the charge row lock whenever `released` or the in-flight
set changes. **Encumbrance:** every row encumbers its amount unless `released`; `released` is set only for
`not_dispatched`, `not_sent` and the reconciler's `FAILED`.

### 7.5 Budget: per customer, per currency, per UTC day (AR-05)

`refund_budget(ten, sub, currency, day) → spent_minor, count`. Configuration in minor units, documented
with the ISO 4217 exponent (PA-13). Demo P: `USD 20000` (= 200.00 USD), `EUR 20000` (= 200.00 EUR),
`JPY 20000` (= ¥20,000; exponent 0), at most 3 refunds per day. In T1 step 6: `INSERT … ON CONFLICT DO
NOTHING`; `SELECT … FOR UPDATE`; `UPDATE … WHERE spent_minor + $amt <= $limit AND count + 1 <= $n` must
change one row. Unconfigured currency → denied. Never released. Fixed windows allow 2× across one
midnight (published). Not enforced by the adapter (residual under broker compromise).

## 8. What the workload sees (PA-07)

`effect.status` `outcome = {class, receipt_id, reason}` with the **workload-facing** reason enum:

| Internal reason | `reason` |
|---|---|
| `not_owner_or_unknown` | `not_permitted` |
| `currency`, `order_status`, `order_busy`, `insufficient_refundable` | `not_refundable` |
| `budget` | `limit` |
| `not_dispatched`, `not_sent`, `provider_declined` | `not_executed` |
| `SUCCEEDED`; `UNKNOWN` (any) | `null` (class `succeeded` / `unknown` = "do not retry") |

Because ownership is checked first and short-circuits, the shop learns nothing about an order the
approver does not own. `payments.get_order` returns `amount_minor = captured_minor`, `refunded_minor =
external_refunded_minor + Σ amount(SUCCEEDED)` (excludes `UNKNOWN`, in-flight and failed-settlement
nuances), `currency`, `status`. Never shown: provider ids, references, keys, provider text, settlement,
anomalies.

**Confirmation page facts** (in addition to effect-protocol-v2 §5): "Charge being refunded: `<charge_id>`"
(a signed parameter); "Remaining refund allowance today"; "A refund on this order is being processed"
when any row is in flight.

## 9. Configuration (strict JSON) and webhooks

Adapter: `{"format":"nodkey.payments-adapter.v1","socket_path","broker_uid","broker_id","wid",
"R_max_s":43200,"registry_path","db":{"host":"172.30.20.20","port":5432,"dbname","user":
"nodkey_payments_adapter","password_file"},"provider":{"profile":"simpay","account":
"acct_demomerchant01","addr":"172.30.30.20:8443","server_name":"simpay.test","ca_file","key_file",
"idem_key_file","retention_s":86400,"resend_margin_s":7200,"caps":[…]},"limits":{"connect_ms":2000,
"total_ms":10000,"max_head":16384,"max_body":65536,"max_concurrent":8}}`. Refusals: §2 checks; §3.1
`R_max` rule; `addr` not an IP literal; uid 0 or = `broker_uid`.

Broker: `"payments":{"adapter_socket","adapter_uid","R_max_s","max_resends":5,"budget":{…}}`. At start
the broker calls `adapter.hello`, requires the format and `r_max_s` = its own, and otherwise does not
execute `payments.refund` (records stay `APPROVED` and expire). Test profile (PT-15): simpay retention
300 s, margin 60 s, `R_max` 180 s, simpay `system` clock.

**Webhooks: out of Phase 4.** No inbound listener on adapter or broker; outcomes come only from GETs.
P-19 is NOT APPLICABLE in Phase 4 (negative test PT-19).

## 10. Residuals (published)

- **Approved-but-never-executed grant (ruling on PA-02).** A compromised broker can still execute an
  approved grant once while it is younger than `R_max`, even if the honest broker let the record expire
  (effect-protocol-v2 T34). The user approved exactly that refund. It cannot cause a second refund for
  that grant within `R_max`, because every request derives from the grant and the provider deduplicates
  on the jti-derived key; after `R_max` the adapter refuses.
- **Broker compromise (J)** bypasses broker-only controls: revocation, budgets, remaining-refundable,
  one-in-flight, order status; it can deny service and misreport outcomes. Bounded by user approvals, the
  adapter's ownership/charge check, and the provider's per-charge remaining amount.
- **Provider** lying consistently or ignoring idempotency; **host clock rollback** (attacker I) defeats
  the age rule.
- **Adapter compromise** (G via a parser bug) yields the restricted key (usable only from 172.30.30.10)
  and a read-only orders view; no grant key, no broker DB write.
- **Operator path** for `orders` (§7.1) is assumed outside workload control.
- **Liveness:** `UNKNOWN`, failed settlement and unreleased amounts block a charge; budget never refunds.
- **Restore:** after a DB restore, every non-final `payment_effect` row MUST be set to `UNKNOWN`, and every
  charge with activity since the backup compared with provider listings, before serving (plus ADR-0006 §9).
- **Real providers** lack simpay's `idem_status`; there `FAILED/provider_declined` needs an operator.

## 11. Test plan

PASS / FAIL / NOT TESTED per case. "Ledger" = simpay `GET /admin/ledger`. Attack cases need a **baseline
positive control** (shop holds `rk_sim_…`, reaches simpay directly; the attack succeeds).

| # | Case | Expected | Maps to |
|---|---|---|---|
| PT-01 | Refund of another customer's order (render; ownership changed after approval) | uniform error; `FAILED/denied`, `not_permitted`; ledger unchanged | P-01, SI-10 |
| PT-02 | Approve 5.00; workload tries 50.00 via new proposal, W-socket grant, edited digest | no grant on W; new approval needed; digest mismatch → no grant; ledger one 5.00 | P-02, SI-06 |
| PT-03 | `JPY 1000` on a USD order | `not_refundable`; nothing sent | P-03, SI-10 |
| PT-04 | Grant re-delivered 50× concurrently with recovery loop | one row; ledger 1 | P-04, SI-09 |
| PT-05 | Two approvals race for the last 10.00 | one `SUCCEEDED`; other `not_refundable`; ledger sum ≤ captured | P-05, SI-11 |
| PT-06 | `commit_then_drop`; second approval on the order | `UNKNOWN`; second denied; reconciler `find` → `SUCCEEDED` without resend; ledger 1 | P-06, SI-15 |
| PT-07 | `commit_after_delay` > `total_ms` | `in_progress` → no resend; resolves `SUCCEEDED`; ledger 1 | P-07 |
| PT-08 | `commit_then_500` | `find` resolves `SUCCEEDED`; ledger 1 | P-08 |
| PT-09 | `fail_before_commit`, `rate_limit`, `inflight_409`, `drop_before_commit` | `find` not_found → same-key resend → one refund | P-09, SI-09 |
| PT-10 | Bad `amount_minor` forms; duplicate key; `charge_id` supplied in propose | `invalid_argument` | P-10, P-12, SI-08 |
| PT-11 | Refund > remaining (fresh, after partial, while another `UNKNOWN`) | denied before dispatch; adapter call count 0 | P-11, SI-11 |
| PT-12 | Extra members in propose and in P requests | `invalid_argument` / `malformed_request`; nothing sent | P-12, SI-16 |
| PT-13 | From shop, **broker, authority, gateway**: route to 172.30.30.20, `pay-egress` membership, adapter socket, simpay admin; shop to DB; stolen key from another address | no route / not member / absent; simpay `401 source_address_not_allowed` | P-13, SI-01, SI-03 |
| PT-14 | Search for simpay key and `K_idem` in shop and broker | absent; baseline finds it in shop | P-14, SI-02 |
| PT-15 | `UNKNOWN` beyond `resend_deadline` / `R_max` (test profile) | no create sent (adapter log); `operator_required` | P-15, SI-15 |
| PT-16 | `lie_*`, `phantom_success`, `deny_but_commit` | never `SUCCEEDED` on a lie; `phantom_success` (not cached by simpay, `api.rs`) → `find` not_found → resend executes once; `deny_but_commit` → `find` → `SUCCEEDED` + alarm; ledger ≤ 1 | P-16, SI-15 |
| PT-17 | `redirect` to a harness listener | `UNKNOWN`; listener sees 0 connections | P-17, SI-02 |
| PT-18 | Oversized, slow drip, `malformed_json`, `header_injection`, `hostile_error_text` | bounded; `ambiguous`; no provider text anywhere (byte search) | P-18, SI-16 |
| PT-19 | Listening sockets in adapter and broker namespaces | none | P-19 (N/A) |
| PT-20 | Owner/status change after approval; update of an immutable `orders` column | denied, no adapter call; trigger rejects | SI-10, SI-11 |
| PT-21 | Crash broker after T1, after T2, after send; crash adapter mid-request; stall DB at T3 | no duplicate; ledger matches final state | SI-09, SI-15 |
| PT-22 | Budget: 4th refund; over limit; 32 concurrent T1s; unconfigured currency; **two refunds across UTC midnight** | spent ≤ limit per day; 2× across midnight only | AR-05 |
| PT-23 | `late_refund_failed` | settlement `failed`, alarm, encumbered | §7.3 |
| PT-24 | Wrong-uid peer on P both ways; adapter config with DNS name, two CAs, readable key file | closed + alarm; refuses start | §1, §2 |
| PT-25 | Wrong CA, wrong SAN, TLS 1.2-only, plain HTTP | `FAILED/not_sent`; ledger 0 | §5 |
| PT-26 | Derivation vectors for `idem_key`, `reference`, `idem_kid`; resend fingerprint equal to first | vectors match; no `params_mismatch` | §3.3, OQ-10 |
| PT-27 | Fuzz socket W while rows are `UNKNOWN` | adapter call log unchanged | SI-19 |
| PT-28 | Restore drill (§10) | non-final rows → `UNKNOWN`; no duplicate | SI-09 |
| PT-29 | **Broker-compromise suite** on P (test client with broker uid): no grant; grant for another op; read grant; other `wid`/`aud`; `cfm = 0`; foreign key; valid grant whose order now has another owner; same grant 20× (sequential and concurrent); grant older than `R_max`; expired never-executed grant younger than `R_max` | all refused, nothing sent — except: same grant 20× → ledger 1; expired-but-young grant → one refund (published residual) | PA-01..03, SI-05, SI-06 |
| PT-30 | `orders`: second row with an existing `charge_id`; cross-tenant charge; operator-role insert attempted from shop, broker and adapter | unique violation; rejected; no path (connection refused / permission denied) | PA-04, SI-10 |
| PT-31 | §2 inputs: registry, config, CA, key, `K_idem` writable by or present in the broker; broker attempts `UPDATE orders`, `ALTER ROLE`, `GRANT` | adapter refuses start; DB permission denied | PA-03 |
| PT-32 | Broker clock set back past a row's deadline; retention configured above simpay's; `margin ≥ retention`; `R_max` violating §3.1 | no resend after the real window (adapter refuses); refusals at start | PA-05, PA-13 |
| PT-33 | Dispatcher vs reconciler under an injected 60 s T3 delay | at most one adapter call in flight per row; late T3 discarded; ledger 1 | PA-06 |
| PT-34 | Reason oracle: proposals on a foreign order in each status, currency, busy and budget state | always `not_permitted` | PA-07 |
| PT-35 | HTTP edge: `1xx` then 200; 65 headers; non-ASCII header byte; short `Content-Length`; chunked trailers; list of 3 or `has_more` | classified `ambiguous`/as specified; never `created` from malformed input | PA-10 |
| PT-36 | `K_idem` rotated while a row is non-final | broker refuses payment processing; alarm | PA-09 |
| PT-37 | `get_order.refunded_minor` with `UNKNOWN`, in-flight and failed-settlement rows | equals external + Σ `SUCCEEDED` | §8 |

## 12. Changes from Draft 1

| Change | Source |
|---|---|
| The adapter verifies the grant itself (`verify_retransmission`, exact claims, age rule replacing `exp`); `refund.*` take only `{grant}`; all request fields derive from the grant | ruling, PA-01..03 |
| `charge_id` is a signed parameter (con2), resolved by the broker at propose (effect-protocol-v2 Draft 3.1); the adapter re-checks order → charge → owner in its own read-only view; adapter joins `data` | ruling, PA-01 |
| `R_max` (default 12 h) with start-up rule against retention and margin; residual for approved-but-unexecuted grants | ruling, PA-02, PA-13 |
| §2: broker-unwritable adapter inputs and their enforcement | PA-03 |
| `K_idem` moves to the adapter; derivation adds provider account, `op`, `opv`; `idem_kid` | PA-03, PA-09 |
| `UNIQUE(charge_id)`; per-charge sums and lock; operator-only writer and SI-10 dependency; alarm-only charge comparison | PA-04, PA-11 |
| Reconciler looks up first; `none` after round 1 stops resends; `resend_deadline` from `iat + R_max` | PA-05 |
| Row leases for dispatcher and reconciler; recovery waits for lease expiry | PA-06 |
| Normative T1 check order; workload-facing reason enum | PA-07 |
| No `5xx` body decoding; pinned hyper options; list `limit=3` | PA-10 |
| `phantom_success` expectation confirmed from simpay source | PA-12 |
| Budget values with exponents; test-profile values consistent | PA-13 |
| Tests PT-29..PT-37; PT-13, PT-22 extended | PA-08 |
