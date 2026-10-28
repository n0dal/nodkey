# Nodkey payments adapter v1 — refunds against simpay (Demo P)

- **Status:** **Draft 4** (2026-10-28): Draft 3.3 plus the operation `payments.support_refund` for
  merchant-side support agents (§16; [ADR-0013](../decisions/0013-agent-interface-and-mandates.md),
  [agent-interface-v1](agent-interface-v1.md) Draft 2). Nothing in §1–§15 changes for `payments.refund`.
  Not implemented. **Draft 3.3** (2026-10-28). Resolves the Demo P conformance findings DEMOP-F03..F08
  (`tests/demop/FINDINGS.md`); changes in §15. Draft 3.2 (2026-10-26) amended Draft 3 after the code reviews
  [`2026-10-26-payments-adapter-code-review.md`](../reviews/2026-10-26-payments-adapter-code-review.md) (PC-A-xx) and
  [`2026-10-26-broker-payments-review.md`](../reviews/2026-10-26-broker-payments-review.md) (BP-xx); changes in §14.
  Supersedes Draft 2 (changes in §13; Draft 1 → 2 in §12). Implemented as a prototype in
  `crates/nodkey-payments-adapter` and `broker/src/v2/payments.rs`; Drafts 3.2 and 3.3 are not yet re-reviewed.
- **Implements:** [ADR-0012](../decisions/0012-payments-adapter.md) (rev. 2, Proposed) and
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
| Payments adapter | 10006 | simpay key, `K_idem`, DB credential (`nodkey_payments_adapter`, read-only) | `pay-egress` **172.30.30.10** only; DB over the Unix socket in volume `pg-adapter` | P (listener); `pg-adapter` (client) |
| PostgreSQL | — | — | `data` 172.30.20.20 | TCP on `data`; Unix socket in `pg-adapter` |
| simpay | — | its own state | `pay-egress` 172.30.30.20 (API, TLS); `harness` (admin) | — |

- `data` and `pay-egress` are Docker networks with `internal: true`. `pay-egress` has exactly the adapter
  and the simpay API. The adapter has no other network. Neither the broker, the authority, the gateway
  nor the workload is attached to `pay-egress`.
- **Adapter DB channel (PA-16).** The adapter is **not** on `data`. It reaches PostgreSQL only through a
  Unix socket in the volume `pg-adapter`, which is mounted into the PostgreSQL and adapter containers
  **only** (never into the broker; part of the control set). PostgreSQL: `unix_socket_directories =
  '/var/run/postgresql, /run/pg-adapter'`, `unix_socket_group = <adapter gid>`,
  `unix_socket_permissions = 0770`; the directory is owned by the postgres uid, group = adapter gid,
  mode `2750`. The adapter connects the `UnixStream` itself, requires the server's `SO_PEERCRED` uid =
  configured `db_uid`, and only then runs the PostgreSQL protocol over it (`tokio-postgres`
  `connect_raw`). `pg_hba.conf`, in this order:

  ```
  local  ledger  nodkey_payments_adapter                 scram-sha-256
  host   all     nodkey_payments_adapter  0.0.0.0/0      reject
  host   all     nodkey_payments_adapter  ::/0           reject
  host   ledger  nodkey_broker            172.30.20.10/32 scram-sha-256
  ```

  The adapter role is therefore usable only over a channel the broker cannot reach, so the broker
  cannot observe or relay the adapter's session. TLS and channel binding are not needed on a Unix
  socket.
- On `data` the only listener is PostgreSQL. The adapter and the broker expose **no** TCP listener.
- **Capabilities.** Every Nodkey container (workloads, broker, authority, gateway, adapter) runs with
  `cap_drop: [ALL]` and `no-new-privileges`, so none has `CAP_NET_RAW` (no ARP spoofing or raw sockets),
  `CAP_NET_ADMIN` or `CAP_SYS_TIME` (PT-38). The adapter has one network, so it routes nothing.
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

**One deadline per request (PC-A-02, normative).** The adapter's deadline for a request is `total_ms`
after it accepts the connection. The order check (§3.2) gets at most `min(2 s, time left)` of it, as
one budget for connect, authentication and the query (exceeded → `unavailable`, nothing sent); the
provider exchange (§5) must finish by the same deadline. The broker waits `W = total_ms_broker + 2 s`
for a response. `adapter.hello` publishes the adapter's `deadline_ms`; the broker refuses payment
processing (alarm) unless `deadline_ms < W`, so the adapter has answered (or given up) before the
broker records a call as ambiguous. The adapter refuses to start unless `connect_ms < total_ms ≤
60 000`.

## 2. Adapter inputs the broker cannot write (PA-03)

The adapter refuses to start unless every check in this table holds, and re-reads nothing at runtime
(rotation = restart).

| Input | Content | Enforcement |
|---|---|---|
| Key registry `/etc/nodkey-adapter/keys.json` | the authority's grant keys (grant-v1 §8 format) | operator-provisioned file, owner root, mode `0444`, parent directories root-owned and not group/other-writable; mounted read-only into the adapter only; start check (PC-A-03): regular file, not a symlink, owner = root, every parent directory owned by root, no group/other write bit on file or parents; the bytes parsed are the bytes of the checked inode (one read) |
| Config `/etc/nodkey-adapter/config.json` | `broker_id` (= grant `aud`), `wid` of `shop`, `R_max_s`, provider settings incl. `idem_key_not_before` (§3.3), limits | same as the registry |
| Operation declaration | `payments.refund` opv 1 placements (§3.1) | compiled into the adapter; not configurable |
| Orders view: privileges | `SELECT order_id, ten, owner_sub, charge_id, currency FROM nodkey.orders WHERE order_id = $1` | DB role `nodkey_payments_adapter`: `SELECT` on those columns only, nothing else. `nodkey.orders` is owned by `postgres`; only `nodkey_shop_operator` may write it; `nodkey_broker` has `SELECT` only (no `UPDATE`, so it cannot even lock rows), no `CREATEROLE`, ownership or `GRANT` option. Password file owner adapter, `0400` |
| Orders view: transport | Unix socket in `pg-adapter` | mounted into PostgreSQL and the adapter only; server peer uid checked; `pg_hba` rejects the adapter role over TCP (§1) |
| Orders view: name resolution (PA-17) | schema-qualified names; nothing can be created | **The control (Draft 3.3):** (1) every statement issued by the broker and the adapter names every object schema-qualified (`nodkey.<table>`, `public.<table>`); (2) every function in schemas `nodkey` and `public` pins `search_path` (`SET search_path = ''` or `pg_catalog, public`); (3) no Nodkey role (`nodkey_broker`, `nodkey_payments_adapter`, `nodkey_shop_operator`) has `CREATE` on any schema, nor `CREATE` or `TEMPORARY` on any database of the cluster (`REVOKE CREATE, TEMPORARY ON DATABASE ledger, postgres, template1 FROM PUBLIC`; `REVOKE CREATE ON SCHEMA public FROM PUBLIC`; no `SUPERUSER`, `CREATEDB`, `CREATEROLE`). No object that could shadow a qualified name, or capture an unqualified one, can therefore exist. **Not a control:** the per-role default `ALTER ROLE … SET search_path = ''` is defence in depth only — PostgreSQL lets any role `ALTER ROLE` its own session defaults and `SET search_path` in its session, so a compromised broker can change its own `search_path` (DEMOP-F07); with (1)–(3) that changes nothing it resolves |
| Clock | host `CLOCK_REALTIME` | no container has `CAP_SYS_TIME`; Linux time namespaces do not virtualize `CLOCK_REALTIME`; the adapter refuses to verify while the clock reads below 2024-01-01. Host clock rollback is attacker I (residual) |
| simpay key, `K_idem` | secrets | files owner adapter uid, mode `0400`, not symlinks; never mounted into the broker |
| Pinned CA | one certificate | owner root, `0444`, exactly one certificate |

The deployment test (PT-31) asserts that none of these paths is present in, or writable from, the broker
container.

## 3. Grant check in the adapter (PA-01, PA-02)

### 3.1 Checked claims

The adapter verifies the grant bytes the broker stored at `APPROVED` with **two new `nodkey-grant`
entry points**, each typed differently from the broker's consuming `verify(..).decide(..)` and from each
other, so no path can skip a check by accident: `verify_retransmission(ctx, bytes, now, r_max) ->
RetransmissionAuthorized` (for `refund.create`: every row below, including age) and
`verify_binding(ctx, bytes, now) -> BindingVerified` (for `refund.find`, `refund.get`, `idem.status`:
every row except age; these ops cannot cause an effect). Each
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
| `con` | exactly `{0: amount_minor (uint ≥ 1), 1: currency, 2: charge_id}`; nothing else; con2 MUST match `^ch_[A-Za-z0-9]{8,61}$` on **every** op (PA-19) |
| `nbf`, `iat` | `≤ now + skew` (skew 5 s) |
| **age** (`refund.create` only, PA-18) | `now − iat ≤ R_max_s` (default 43 200 s = 12 h) |
| `exp` | **not** checked (deliberately: resends happen after `exp`; the age rule replaces it) |

Not checked by the adapter: revocation (`revoked_before`) and consumption. Both are the broker's; their
loss under broker compromise is a residual (§10). Lookups after `R_max` remain possible, so late
`UNKNOWN` resolution and settlement polling work (§7.3).

**Exact verification procedure (resolves grant-crate issues RX-1..RX-6, `crates/nodkey-grant/SPEC_ISSUES.md`).**
The steps below are normative; their order matters only for audit logs, because every failure is
`grant_refused` and nothing is sent.

1. Clock floor: refuse while the adapter clock reads below 2024-01-01.
2. grant-v1 §7.2 steps 1–7, including 4c (key `status: revoked` → refuse) and 5 (signature over the
   `external_aad`, which binds `aud`). Step 4d (key validity window) is evaluated **at `iat`**, not at
   `now` (RX-2).
3. Steps 8a–8d, including 8b (time order) and 8c (lifetime measured from `iat`). Step **8e (`exp`) is
   not run**; for `refund.create` it is replaced by the age rule `now − iat ≤ R_max_s`; `verify_binding`
   has no age rule (RX-2).
4. Steps 9a–9c, with 9c (`ten` ∈ the workload's tenants) checked against the adapter's **own configured
   `tenants` list** for `wid` (§9), passed to the crate as `workload_tenants`. An empty list is a start-up
   refusal. This is in addition to, not replaced by, §3.2 (RX-1; the crate's stricter reading).
5. The claim table above: `knd`, `cfm`, `use`, `op`, `opv`, `res`/`con` keys, classes and declared types.
   `aud` is checked again explicitly although step 5 already binds it (RX-4).
6. **Adapter rules on the crate's output** (`RetransmissionAuthorized::params()` /
   `BindingVerified::params()`), which the grant-v1 §6 declaration format cannot express: `amount_minor ≥
   1` (RX-3); con2 matches `^ch_[A-Za-z0-9]{8,61}$` (PA-19, RX-6); `currency` in the adapter's ISO 4217
   table.
7. For `refund.create` only: §3.2.

**`unresolved` is never signed (RX-6).** effect-protocol-v2 Draft 3.1 §2.3 requires the authority to
refuse approval of a `payments.refund` record whose `charge_id` does not match the charge pattern; step 6
and §3.2 are the adapter's independent checks.

**Crate status.** `verify_retransmission` exists in `crates/nodkey-grant` (commit 8668eb2) with the
behaviour above. `verify_binding` is **not yet implemented**; until it is, the adapter MUST refuse lookups
rather than call `verify_retransmission` with a widened age (that would merge the two types).

**`R_max` start-up rule.** With `retention_s` the configured provider retention: `R_max_s < retention_s −
resend_margin_s` and `resend_margin_s < retention_s`; otherwise the adapter refuses to start. Defaults:
retention 86 400, margin 7 200, `R_max` 43 200. **`retention_s` is an operator statement (Draft 3.3,
DEMOP-F03):** it MUST NOT exceed the provider's actual key retention (simpay: its configured
`idempotency_retention_s`; Stripe: documented 86 400), but the adapter has no source for that value and
cannot check it; a value set too high re-opens a resend after the provider pruned the key (§10).

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
stores it on each `payment_effect` row at T1 (frozen).

**Key binding on every call (PC-A-01, BP-01, normative).**

1. Every `refund.create`, `refund.find`, `refund.get` and `idem.status` carries `idem_kid` = the kid
   stored on the row the call is for. The adapter refuses any call whose `idem_kid` differs from its
   loaded key's kid with `ok:false idem_kid_mismatch` (static message), before verifying the grant and
   without any provider request. A resend can therefore never go out under a key other than the one the
   row was first dispatched with, whatever the broker believes about the adapter.
2. The broker re-runs `adapter.hello` before every dispatch and every reconciliation round (and every
   payments tick). It refuses payment processing (no T1, no dispatch, no reconciliation; alarm
   `idem_kid_rotated_with_open_rows`) while any non-final row (`RESERVED`, `DISPATCHED`, `UNKNOWN`)
   carries another kid. Such a row stays as it is (a `RESERVED` row becomes `FAILED/not_dispatched`,
   nothing having been sent) until the operator restores the key it was dispatched under; it is never
   resent under a new key. T2 dispatches only a row whose kid equals the adapter's current kid. An
   `idem_kid_mismatch` answer to a create leaves the row `UNKNOWN` (reason `key_mismatch`, alarm),
   never `FAILED`.
3. **Activation time.** The adapter configuration carries `provider.idem_key_not_before` (Unix
   seconds, ≥ 2024-01-01). The operator sets it to the time the current `K_idem` was installed, at every
   rotation or regeneration; the adapter refuses to start if it lies in the future, and refuses
   `refund.create` (`grant_refused`, nothing sent) for any grant with `iat < idem_key_not_before`.
   Lookups are unaffected. A grant executed under an earlier key therefore cannot be executed again under
   the new key, even by a compromised broker (J-lite) that resends it while it is younger than `R_max`.

The operator MUST still rotate `K_idem` only when no row is non-final; rule 2 makes a violation fail
closed, and rule 3 makes a rotation with final rows safe.

## 4. Adapter operations

| `op` | `args` (exact) | `result` |
|---|---|---|
| `adapter.hello` | `{}` | `{"format":"nodkey.payments-adapter.v1","profile":"simpay","caps":[…],"idem_kid","r_max_s","deadline_ms"}`; caps ⊆ `{idem_status, send_currency}`; `deadline_ms` = the adapter's `total_ms` (§1) |
| `refund.create` | `{grant, idem_kid}` | `Attempt` |
| `refund.find` | `{grant, idem_kid}` | `Lookup` (by grant's charge and derived reference) |
| `refund.get` | `{grant, refund_id, idem_kid}` | `Lookup` (a found refund must match the grant's charge) |
| `idem.status` | `{grant, idem_kid}` (cap `idem_status`) | `{"state":"none"\|"in_progress"\|"done"}` or `{"state":"ambiguous","cause"}` |

`refund.create` runs the `idem_kid` check (§3.3), `verify_retransmission`, the activation-time rule
(§3.3) and §3.2; the other ops run the `idem_kid` check and `verify_binding`. Errors (`ok:false`,
nothing sent): `idem_kid_mismatch`, `grant_refused`, `unavailable`, `invalid_argument`, plus the
envelope errors.

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
(simpay **[sim]**). Query strings are serialized with `form_urlencoded` (every byte outside
`[A-Za-z0-9*-._]` percent-encoded); path segments are only pattern-checked ids, inserted verbatim.

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

All tables are in schema `nodkey` (§2); prose below omits the prefix, statements MUST NOT.

**`nodkey.orders`** — trusted facts. Columns: `order_id` bigint PK (`1 ..= 2^53 − 1`); `ten`, `owner_sub` (ID
rules); `charge_id` **UNIQUE**, `^ch_[A-Za-z0-9]{8,61}$`, immutable; `currency` `^[A-Z]{3}$` in the ISO
4217 table, immutable; `captured_minor` ≥ 1, immutable; `external_refunded_minor` ≥ 0; `status ∈
{captured, partially_refunded, refunded, disputed, canceled}`. A trigger rejects updates of immutable
columns. `nodkey_broker` has `SELECT` only and never locks `orders` (PA-15).

**`nodkey.charge_refund_state`** — broker-owned, one row per charge (PA-15): `charge_id` PK
(`^ch_[A-Za-z0-9]{8,61}$`), `succeeded_minor`, `inflight_minor` (`RESERVED` + `DISPATCHED`),
`unknown_minor`, all ≥ 0. The broker has `SELECT`, `INSERT` and `UPDATE` on it. The rows are created by
the broker (`INSERT … ON CONFLICT DO NOTHING`) and are the **per-charge lock**. A deferred constraint
trigger checks at commit that the three counters equal the sums over that charge's `payment_effect`
rows by state, so they cannot drift. The check function is `SECURITY DEFINER`, `search_path = ''`,
`EXECUTE` revoked from PUBLIC, owned by the `NOLOGIN` role `nodkey_payments_checker` whose only
privileges are `SELECT` on those two tables (BP-02: a deferred trigger runs as the committing role,
which for an operator update is `nodkey_shop_operator`). It reads both tables in **one statement**
(one snapshot, BP-06) and fires on `charge_refund_state` inserts/updates and on `payment_effect`
inserts and updates `OF state, amount_minor, released` only. Every `FAILED` row is `released`, so encumbrance =
`succeeded_minor + inflight_minor + unknown_minor`. **Serialization with the operator:** a
`BEFORE UPDATE OR DELETE` trigger on `nodkey.orders` (`SECURITY DEFINER`, owner `postgres`,
`search_path = ''`) inserts-if-absent and locks the order's `charge_refund_state` row, so an operator
change of owner or status waits for, or blocks, any T1 on that charge (SI-11).

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
`SUCCEEDED`; **unique** when set, BP-08); `lease_owner`, `lease_until`; `reserved_at`, `dispatched_at`, `resend_deadline`, `resends`,
`reconcile_rounds`, `next_check_at`, `anomaly`. Index on `charge_id`. A trigger enforces §7.4 and the
immutability of frozen columns.

### 7.2 Transactions

**Lock order:** own `pending_effect` row → `refund_budget` row → `charge_refund_state` row → that
charge's `payment_effect` rows. No transaction locks two `pending_effect` rows. The operator trigger
takes only the `charge_refund_state` row (after its own `orders` row lock); T1 never locks `orders`, so
there is no cycle.

**T1 — execution transaction** (effect-protocol-v2 §4.4): lock record; window; verify; W10; savepoint;
W11–W13; then W14 **in this order**, stopping at the first failure (PA-07):

0. grant con2 matches the charge pattern — else `not_owner_or_unknown` (so `unresolved` creates no
   state row);
1. budget (§7.5) — lock taken here, evaluated at step 7;
2. insert-if-absent and lock `charge_refund_state` for con2;
3. **after** that lock, read `nodkey.orders` by `order_id` (a new statement, so it sees every operator
   change committed before the lock); require it exists, `ten` = grant `ten`, `owner_sub` = grant `sub`,
   `charge_id` = con2 — else `not_owner_or_unknown`;
4. `currency` = grant con1 — else `currency`; `status ∈ {captured, partially_refunded}` — else
   `order_status`;
5. `inflight_minor + unknown_minor = 0` — else `order_busy`;
6. `remaining = captured_minor − external_refunded_minor − (succeeded_minor + inflight_minor +
   unknown_minor)`; `1 ≤ amount_minor ≤ remaining` — else `insufficient_refundable`;
7. budget guarded update — else `budget`.

Steps are evaluated in this order and stop at the first failure (ownership before anything that
reveals order state). On failure: roll back to the savepoint, `consumed_grant = DENIED`, record `FAILED` (`denied`), commit; no
`payment_effect` row, no adapter call. On success: `consumed_grant = ACCEPT`; `inflight_minor += amount`; insert `payment_effect`
`RESERVED` with frozen values, `idem_kid`, `resend_deadline = grant.iat + R_max_s − 60`; record
`APPROVED → EXECUTING`; deadline-at-commit check (grant-v1 D2-4); commit synchronously.

**Leases (PA-06).** Every adapter call on a row is made by the holder of its lease. A lease is taken or
extended by `UPDATE … SET lease_owner = $me, lease_until = now + L WHERE pending_id = ? AND state = $s
AND (lease_owner = $me OR lease_until < now)` changing exactly one row, committed **before** the call.
`$me` is random per process start. `L_dispatch = 4 × (total_ms + 2 s) + 3 s + 10 s` (three creates and
the confirming `refund.get`; 61 s by default; BP-10); `L_reconcile = total_ms + 2 s + 10 s` per call.

**Before every adapter call (BP-03).** The caller waits for one of the broker's call slots for at most
`total_ms + 2 s`, then re-asserts its lease by the CAS above (committed), and only then calls. No slot →
no call (on a dispatch's first call: `FAILED/not_sent`, nothing having been sent). Lease lost → the
caller stops without writing. A lost lease discards the result: T3 and every reconciler write are CASes on
the row's `state` and `lease_owner`; the dispatcher and the reconciler of one process share `$me`, and
their mutual exclusion rests on the state (`DISPATCHED` vs `UNKNOWN`), which recovery moves only after
the dispatch lease has expired (BP-10).

**T2 — dispatch.** In one statement: `RESERVED → DISPATCHED`, `dispatched_at = now`, lease
`L_dispatch`. Only if exactly one row changed is `refund.create` called. At most 3 calls, only while the
previous result is `busy` (waits 1 s, 2 s); before each retry the dispatcher re-asserts its lease (the
CAS above); if it fails, the dispatcher stops without writing.

**T3** (CAS from `DISPATCHED` under the dispatcher's lease; a lost lease discards the result):

| Result | `payment_effect` | record |
|---|---|---|
| `created`, then `refund.get` = `found`, identical (incl. `reference`) | `SUCCEEDED` (settlement = the refund's status; `failed` → alarm, BP-09) | `SUCCEEDED` |
| `not_sent` on the first call | `FAILED/not_sent`, `released` | `FAILED` |
| anything else (incl. `refused`, `busy` after 3 calls, `not_sent` after an earlier call, `grant_refused`, `idem_kid_mismatch`, P failure) | `UNKNOWN` (+ alarm for `refused`/`grant_refused`/`idem_kid_mismatch`) | `UNKNOWN` |

`refused` is not `FAILED`: the broker proved the refund valid under lock, so a refusal contradicts
trusted facts (or is a lie such as `deny_but_commit`).

**Recovery** (start-up, every 5 s, in a payments loop of its own, separate from the effect-protocol-v2
recovery loop, which never awaits an adapter call; BP-04): `RESERVED` with `reserved_at + 30 s < now`
→ CAS `FAILED/not_dispatched`, `released` (a dispatcher losing this race sends nothing). `DISPATCHED`
whose lease has expired → CAS `UNKNOWN/lost_response`. Rows are worked on at most 4 at a time; an
error on one row is logged with an alarm and pushes that row's next check back by 60 s, without
stopping the others (BP-05).

### 7.3 Reconciler (`UNKNOWN`) — lookup first (PA-05)

For each `UNKNOWN` row with `next_check_at ≤ now` and an expired lease, the reconciler takes the lease
and runs one **round** (backoff 10 s, 1 min, 5 min, 30 min, then hourly):

0. Row `idem_kid` = the adapter's current kid (re-learnt by `adapter.hello` before the round, §3.3);
   otherwise no call at all for this row, alarm, row stays `UNKNOWN`.
1. `refund.find`: `found` (one item, identical) → `refund.get` it → identical → `SUCCEEDED`. Stop.
2. Resend gate — all must hold, else go to step 4: `now < resend_deadline`; `resends < max_resends` (5); provider profile documents deduplication; and with cap `idem_status`:
   `idem.status` is `done` or `in_progress` — or `none` **only in the first round** (`none` later means
   pruned or never received: stop resending, `operator_required`). `in_progress` → wait, no resend.
3. Same-key resend `refund.create{grant}`; `resends += 1`. `created` + identical GET → `SUCCEEDED`.
   `refused` with a business code (`amount_too_large`, `charge_already_refunded`,
   `charge_not_refundable`, `currency_mismatch`, `resource_missing`) **and** a following
   `refund.find` = `not_found` **and** (cap `idem_status`) state `done` → `FAILED/provider_declined`,
   `released`, alarm `provider_contradicts_facts`. Anything else → stay `UNKNOWN`.
4. Past the gate: lookups only (daily, 7 days); "not found" never concludes anything; then
   `operator_required`, alarm; the charge stays blocked.

The adapter enforces `R_max` on `refund.create` independently (§3.1), so a broker clock rollback or a
misconfigured retention cannot produce a resend after the provider could have pruned the key. Lookups
(steps 1 and 4, settlement) are not age-bounded.

**Settlement:** for `SUCCEEDED` with `settlement = pending`, `refund.get` on the same backoff for up to
30 days from `dispatched_at` (then alarm `settlement_unresolved`, polling stops); `failed` → alarm, amount
stays encumbered. **One rule for both paths (BP-09):** a refund that the provider confirms (identical
`refund.get`) is `SUCCEEDED`, with `settlement` = its status, whether the dispatcher or the reconciler
confirms it; `failed` raises the alarm. `payments.get_order.refunded_minor` therefore counts a refund
whose settlement failed (§8).

**Post-success watch (Draft 3.3, DEMOP-F06).** A provider can move a refund it reported `succeeded` to
`failed` later (simpay `late_refund_failed`; card refunds can fail after acceptance). For `SUCCEEDED` with
`settlement = succeeded` (whether set by the dispatcher, the reconciler or settlement polling) the broker
keeps calling `refund.get` (lookup only, same lease and kid rules as above; never `refund.create`, no
resend) at 10 s, 1 min, 5 min, 30 min after it became `succeeded`, then daily, until `dispatched_at +
settlement_watch_s` (broker config, §9; default 30 days, bounds 1 h ..= 90 days). If an identical
`refund.get` then reports `failed`: `settlement` → `failed`, `anomaly = settlement_reversed`, alarm
`refund_settlement_failed` (with `previous: succeeded`), and the row stays `SUCCEEDED` with its amount
encumbered (counted in `succeeded_minor`, never released; §7.4) — the same end state as a refund that
failed while `pending`. `failed` is final: no further checks. Any other answer (`pending`, `not_found`,
mismatch, adapter failure) changes nothing and the watch continues. A reversal reported after the window
is not observed (§10).

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
| `SUCCEEDED`: only `settlement`: `pending` → `succeeded` / `failed`; `succeeded` → `failed` (post-success watch, §7.3); `failed` is final | unchanged |

Both rows change in one transaction, which also locks the `charge_refund_state` row and moves the amount
between its counters (`inflight` → `succeeded` / `unknown`, `unknown` → `succeeded`, or out of all three
on `FAILED`). **Encumbrance:** every row encumbers its amount unless `released`; `released` is set only for
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
| `not_owner_or_unknown`; `grant` (W11–W13 failed at T1, e.g. revoked; BP-11) | `not_permitted` |
| `currency`, `order_status`, `order_busy`, `insufficient_refundable` | `not_refundable` |
| `budget` | `limit` |
| `not_dispatched`, `not_sent`, `provider_declined` | `not_executed` |
| `SUCCEEDED`; `UNKNOWN` (any) | `null` (class `succeeded` / `unknown` = "do not retry") |

Because ownership is checked first and short-circuits, the shop learns nothing about an order the
approver does not own. `payments.get_order` returns `amount_minor = captured_minor`, `refunded_minor =
external_refunded_minor + succeeded_minor` (excludes `UNKNOWN`, in-flight and failed-settlement
nuances), `currency`, `status`. Never shown: provider ids, references, keys, provider text, settlement,
anomalies.

**Confirmation page facts** (in addition to effect-protocol-v2 §5): "Charge being refunded: `<charge_id>`"
(a signed parameter); "Remaining refund allowance today"; "A refund on this order is being processed"
when any row is in flight.

## 9. Configuration (strict JSON) and webhooks

Adapter: `{"format":"nodkey.payments-adapter.v1","socket_path","broker_uid","broker_id","wid",
"tenants":["acme"],"R_max_s":43200,"registry_path","db":{"socket_dir":"/run/pg-adapter","db_uid","dbname","user":
"nodkey_payments_adapter","password_file"},"provider":{"profile":"simpay","account":
"acct_demomerchant01","addr":"172.30.30.20:8443","server_name":"simpay.test","ca_file","key_file",
"idem_key_file","idem_key_not_before","retention_s":86400,"resend_margin_s":7200,"caps":[…]},"limits":{"connect_ms":2000,
"total_ms":10000,"max_head":16384,"max_body":65536,"max_concurrent":8}}`. Refusals: §2 checks; §3.1
`R_max` rule; empty `tenants`; `addr` not an IP literal; uid 0 or = `broker_uid`;
`idem_key_not_before` before 2024-01-01 or in the future; not `connect_ms < total_ms ≤ 60 000`.

Broker: `"payments":{"adapter_socket","adapter_uid","R_max_s","max_resends":5,"adapter_total_ms":10000,
"settlement_watch_s":2592000,"budget":{…}}`; `settlement_watch_s` (post-success watch, §7.3) is optional
(default 2 592 000 = 30 days) and refused outside 3 600 ..= 7 776 000.
At start, and again before every dispatch, reconciliation round and payments tick (§3.3), the broker
calls `adapter.hello`, requires the format, `r_max_s` = its own, `deadline_ms < adapter_total_ms + 2 s`
(§1) and no non-final row under another kid, and otherwise does not execute `payments.refund` (records
stay `APPROVED` and expire). Test profile (PT-15): simpay retention
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
- **`K_idem` activation time is an operator statement (Draft 3.2).** The guarantee "at most one refund
  per signed grant within `R_max`" across a `K_idem` rotation or regeneration holds only if the operator
  sets `idem_key_not_before` to (at least) the time the new key was installed. The adapter can check that
  the value is not in the future, but not that it is not too early (as with `retention_s`, §3.1). A value
  set too early re-opens PC-A-01 for grants issued between it and the rotation. Setting it correctly
  costs liveness: an approved grant issued before the rotation and not yet executed can no longer be
  executed (it ends `FAILED/not_dispatched` or `UNKNOWN`). Host clock rollback (attacker I) also defeats
  this rule. A compromised authority (J, out of scope) could sign a later `iat`.
- **`retention_s` is an operator statement (Draft 3.3, DEMOP-F03).** The adapter checks `R_max_s <
  retention_s − resend_margin_s` against the configured value only (§3.1); it cannot learn the provider's
  actual retention. A value above it can allow a same-key resend after the provider pruned the key.
- **Settlement reversal after the watch (Draft 3.3, DEMOP-F06).** A provider that moves a refund from
  `succeeded` to `failed` after `dispatched_at + settlement_watch_s` is not observed by the broker; the
  row stays `succeeded`. The operator's alarm-only charge comparison (§7.1) is the remaining detector.
- **Own session defaults (Draft 3.3, DEMOP-F07).** A compromised broker (or adapter) can `ALTER ROLE` its
  own role's session defaults and `SET search_path`. This is not prevented; it is harmless because every
  statement is schema-qualified, every function pins `search_path`, and the role can create no object
  anywhere (§2, PA-17).
- **Rows under a lost key.** A non-final row whose `K_idem` is lost stays unresolved (no lookup or
  resend is possible under another key); the charge stays blocked and payment processing stays refused
  until the operator restores the key or resolves the row by hand against provider listings.
- **Provider id probing (PC-A-09).** `refund.get` takes any pattern-valid refund id from the broker; a
  compromised broker learns whether an id exists at the provider (`not_found` vs `echo_mismatch`), and
  nothing else about it.

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
| PT-10 | Bad `amount_minor` forms; duplicate key; `charge_id` supplied in propose | `invalid_argument`, except duplicate key → `malformed_request` (strict framing rejects the line before argument validation, effect-protocol-v2 §1.2; Draft 3.3, DEMOP-F04); no record in every case | P-10, P-12, SI-08 |
| PT-11 | Refund > remaining (fresh, after partial, while another `UNKNOWN`) | denied before dispatch; adapter call count 0 | P-11, SI-11 |
| PT-12 | Extra members in propose and in P requests | `invalid_argument` / `malformed_request`; nothing sent | P-12, SI-16 |
| PT-13 | From shop, **broker, authority, gateway**: route to 172.30.30.20, `pay-egress` membership, adapter socket, simpay admin; shop to DB; stolen key from another address | no route / not member / absent; simpay `401 source_address_not_allowed` | P-13, SI-01, SI-03 |
| PT-14 | Search for simpay key and `K_idem` in shop and broker | absent; baseline finds it in shop | P-14, SI-02 |
| PT-15 | `UNKNOWN` beyond `resend_deadline` / `R_max` (test profile) | no create sent (adapter log); `operator_required` | P-15, SI-15 |
| PT-16 | `lie_*`, `phantom_success`, `deny_but_commit` | never `SUCCEEDED` on a lie; `phantom_success` (not cached by simpay, `api.rs`) → `find` not_found → resend executes once; `deny_but_commit` → `find` → `SUCCEEDED` + alarm; ledger ≤ 1 | P-16, SI-15 |
| PT-17 | `redirect` to a harness listener | `UNKNOWN`; listener sees 0 connections | P-17, SI-02 |
| PT-18 | Oversized, slow drip, `malformed_json`, `header_injection`, `hostile_error_text` | bounded; `ambiguous` — except `header_injection/crlf_injection` (syntactically valid extra header fields on an exact 200, never read or followed) → `created`, confirmed by `refund.get` (PC-A-07); `hostile_error_text` (`400` with an unknown error code) → `refused/other_4xx` per §6.2, row `UNKNOWN` + alarm, resolved by lookup (Draft 3.3, DEMOP-F05); every other `header_injection` variant → `ambiguous` with any cause (`bare_cr` → `bad_headers`; `te_and_cl` may surface as `bad_headers` or `reset_after_send` depending on where the HTTP stack rejects it; Draft 3.3, DEMOP-F08); in every case one refund at most and no corrupted state (row resolves to the provider's outcome); no provider text anywhere (byte search) | P-18, SI-16 |
| PT-19 | Listening sockets in adapter and broker namespaces | none | P-19 (N/A) |
| PT-20 | Owner/status change after approval; update of an immutable `orders` column | denied, no adapter call; trigger rejects | SI-10, SI-11 |
| PT-21 | Crash broker after T1, after T2, after send; crash adapter mid-request; stall DB at T3 | no duplicate; ledger matches final state | SI-09, SI-15 |
| PT-22 | Budget: 4th refund; over limit; 32 concurrent T1s; unconfigured currency; **two refunds across UTC midnight** | spent ≤ limit per day; 2× across midnight only | AR-05 |
| PT-23 | `late_refund_failed` (refund `succeeded` at creation, `failed` afterwards); `failed` while `pending`; reversal after `settlement_watch_s` | post-success watch records settlement `failed`, anomaly `settlement_reversed`, alarm, amount encumbered, row `SUCCEEDED`, only `refund.get` calls (no create); `failed` final; no check after the window (Draft 3.3, DEMOP-F06) | §7.3 |
| PT-24 | Wrong-uid peer on P both ways; adapter config with DNS name, two CAs, readable key file | closed + alarm; refuses start | §1, §2 |
| PT-25 | Wrong CA, wrong SAN, TLS 1.2-only, plain HTTP | `FAILED/not_sent`; ledger 0 | §5 |
| PT-26 | Derivation vectors for `idem_key`, `reference`, `idem_kid`; resend fingerprint equal to first | vectors match; no `params_mismatch` | §3.3, OQ-10 |
| PT-27 | Fuzz socket W while rows are `UNKNOWN` | adapter call log unchanged | SI-19 |
| PT-28 | Restore drill (§10) | non-final rows → `UNKNOWN`; no duplicate | SI-09 |
| PT-29 | **Broker-compromise suite** on P (test client with broker uid): no grant; grant for another op; read grant; other `wid`/`aud`; `cfm = 0`; foreign key; valid grant whose order now has another owner; same grant 20× (sequential and concurrent); grant older than `R_max`; expired never-executed grant younger than `R_max` | all refused, nothing sent — except: same grant 20× → ledger 1; expired-but-young grant → one refund (published residual) | PA-01..03, SI-05, SI-06 |
| PT-30 | `orders`: second row with an existing `charge_id`; cross-tenant charge; operator-role insert attempted from shop, broker and adapter | unique violation; rejected; no path (connection refused / permission denied) | PA-04, SI-10 |
| PT-31 | §2 inputs: registry, config, CA, key, `K_idem` writable by or present in the broker; broker attempts `UPDATE`, `SELECT … FOR UPDATE` on `nodkey.orders`, `GRANT`, `CREATE` in any schema, `CREATE TEMP`, a shadowing `orders` view (also after `SET search_path = public, nodkey`); catalog check: no Nodkey role has `CREATE` on any schema or `CREATE`/`TEMPORARY` on any database, and every function in `nodkey`/`public` pins `search_path`; `pg-adapter` absent in the broker; adapter role over TCP | adapter refuses start; DB permission denied / catalog check empty / path absent / `pg_hba` reject. `ALTER ROLE` on the role's own session defaults is **not** expected to be refused (PostgreSQL permits it; §2, §10; Draft 3.3, DEMOP-F07) | PA-03, PA-15..17 |
| PT-32 | Broker clock set back past a row's deadline; `R_max_s ≥ retention_s − resend_margin_s` for the **configured** `retention_s`; `margin ≥ retention`; `R_max` violating §3.1 | no resend after the real window (adapter refuses); refusals at start. A `retention_s` above the provider's actual retention is an operator statement the adapter cannot verify and is not a test case (§3.1, §10; Draft 3.3, DEMOP-F03) | PA-05, PA-13 |
| PT-33 | Dispatcher vs reconciler under an injected 60 s T3 delay | at most one adapter call in flight per row; late T3 discarded; ledger 1 | PA-06 |
| PT-34 | Reason oracle: proposals on a foreign order in each status, currency, busy and budget state | always `not_permitted` | PA-07 |
| PT-35 | HTTP edge: `1xx` then 200; 65 headers; non-ASCII header byte; short `Content-Length`; chunked trailers; list of 3 or `has_more` | classified `ambiguous`/as specified; never `created` from malformed input | PA-10 |
| PT-36 | `K_idem` rotated while a row is non-final — at broker start **and** adapter-only restart while the broker runs (row `UNKNOWN`; row `RESERVED`; rotation between hello and create); `K_idem` rotated with `idem_key_not_before` = rotation time, then a young `SUCCEEDED` grant resent on P under the new and the old kid; baseline without the activation time | broker refuses payment processing, alarm, no call for the row under the new key, row resolves under the old key once restored; resend → `grant_refused` / `idem_kid_mismatch`, ledger 1; baseline ledger 2 | PA-09, PC-A-01, BP-01 |
| PT-37 | `get_order.refunded_minor` with `UNKNOWN`, in-flight and failed-settlement rows | equals external + `succeeded_minor` | §8 |
| PT-38 | Every Nodkey container: `CapEff` in `/proc/self/status`; from the broker: raw/packet socket, ARP send, connect to `pg-adapter` path | `CapEff = 0`; `EPERM`; path absent | PA-16 |
| PT-39 | `charge_refund_state` counters forced out of step with `payment_effect`; operator owner/status update racing T1 (both orders of arrival); operator updates **as `nodkey_shop_operator`** on a charge with and without a state row | commit rejected by the constraint trigger; T1 sees the update or the update waits; never an effect under a stale owner; operator updates commit, operator cannot touch broker tables | PA-15, SI-11, BP-02 |
| PT-40 | After `R_max`: `refund.create` vs `refund.find` / `refund.get` / `idem.status` with the same grant | create `grant_refused`, nothing sent; lookups served; late `UNKNOWN` resolves; settlement observed | PA-18 |
| PT-42 | Grant for a tenant not in the adapter's `tenants`; `amount_minor = 0` in a test-key grant; key `revoked` in the adapter registry; key window ending between `iat` and `now` | refused / refused / refused / accepted (window at `iat`); nothing sent where refused | RX-1..RX-3 |
| PT-43 | Every op on P with a missing or foreign `idem_kid` | `malformed_request` / `idem_kid_mismatch`; nothing sent | PC-A-01, BP-01 |
| PT-44 | Slow order view; stalled provider; `deadline_ms` in hello vs the broker's wait; slot wait beyond the dispatch lease | answer within `total_ms`; broker refuses an adapter whose deadline is not below its wait; late dispatcher sends nothing | PC-A-02, BP-03 |
| PT-41 | con2 malformed (`unresolved`, `ch_x`, path or query metacharacters) on every op | `grant_refused`, nothing sent; T1 denies `not_owner_or_unknown` without creating a state row | PA-19 |

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

## 13. Changes from Draft 2

| Change | Source |
|---|---|
| Adapter leaves `data`; DB only over a Unix socket in `pg-adapter` (PostgreSQL and adapter only), server peer uid checked, `pg_hba` rejects the adapter role over TCP; `cap_drop: [ALL]` and `no-new-privileges` on every Nodkey container | PA-16 (ruling) |
| Broker-owned `charge_refund_state` row is the per-charge lock with counters checked against `payment_effect` at commit; `orders` stays `SELECT`-only for the broker; operator updates lock the same row via a trigger; T1 reads `orders` after the lock | PA-15, PA-04 |
| Schema `nodkey`, qualified names, empty `search_path` per role, no `CREATE`/`TEMP` | PA-17, PA-03 |
| Age rule on `refund.create` only (`verify_retransmission`); lookups use `verify_binding` (signature and bindings, no age); ADR-0006 7b amended | PA-18 (ruling) |
| con2 pattern on every op; query percent-encoding stated | PA-19 |
| Exact grant-v1 step list for the adapter (4c, 4d at `iat`, 8b/8c, no 8e), configured `tenants` for 9c, adapter-side `amount_minor ≥ 1`, explicit `aud` check, normative order, authority refuses `unresolved` | grant crate RX-1..RX-6 |
| T1 step 0 (pattern) and reordered steps; tests PT-38..PT-41; PT-31 extended | PA-15..PA-19 |

## 14. Changes from Draft 3 (Draft 3.2)

| Change | Source |
|---|---|
| Every grant-carrying call on P carries the row's `idem_kid`; the adapter refuses another kid (`idem_kid_mismatch`, nothing sent); the broker re-runs `adapter.hello` before every dispatch and reconciliation round, never calls for a row under another kid, and refuses payment processing while non-final rows carry another kid | PC-A-01, BP-01 (ruling) |
| `provider.idem_key_not_before`: `refund.create` refused for `iat` below it; start refusal if in the future; residual published (§10) | PC-A-01 (ruling) |
| One deadline per request from receipt (`total_ms`), DB phase inside it; `deadline_ms` in `adapter.hello`; broker refuses unless `deadline_ms < total_ms_broker + 2 s`; `connect_ms < total_ms` | PC-A-02 (ruling) |
| Counter check `SECURITY DEFINER` with a minimal owner, one statement, fires only on amount/state changes | BP-02, BP-06 |
| Slot wait bounded; lease re-asserted after the slot and before every call; `L_dispatch` covers the confirming GET; exclusion rule stated | BP-03, BP-10 |
| Payments loop separate from the effect-protocol-v2 recovery loop; bounded per-row concurrency; per-row error isolation and back-off | BP-04, BP-05 |
| Confirmation compares the reference; `provider_refund_id` unique; one settlement rule for both paths; `grant` → `not_permitted` | BP-08, BP-09, BP-11 |
| Operator files: owner root, parents root-owned, one checked read | PC-A-03 |
| PT-18 `crlf_injection` → `created`; PT-36, PT-39 extended; PT-43, PT-44 added; §10 residuals (activation time, lost key, id probing) | PC-A-07, PC-A-09 |

## 15. Changes from Draft 3.2 (Draft 3.3)

Resolves the Demo P conformance findings in `tests/demop/FINDINGS.md`.

| Change | Source |
|---|---|
| `retention_s` stated as an operator statement the adapter cannot verify (§3.1, §10); PT-32 tests the start-up rule against the configured value only | DEMOP-F03 |
| PT-10: duplicate key → `malformed_request` (framing), not `invalid_argument` | DEMOP-F04 |
| PT-18: `hostile_error_text` → `refused/other_4xx` (as §6.2 already specified); `te_and_cl` → any `ambiguous` cause; one refund at most and no corrupted state in every case | DEMOP-F05, DEMOP-F08 |
| Post-success settlement watch: `succeeded` rows re-checked with `refund.get` (lookup only) until `dispatched_at + settlement_watch_s` (broker config, default 30 days, 1 h ..= 90 days); a reversal → `settlement = failed`, anomaly `settlement_reversed`, alarm, encumbered; §7.4 and the DB guard allow `succeeded → failed`; residual for reversals after the window; PT-23 extended | DEMOP-F06 |
| PA-17 restated: the control is schema-qualified SQL, pinned function `search_path`, and no `CREATE`/`TEMPORARY` for any Nodkey role on any schema or database (incl. `postgres`, `template1`); per-role `search_path = ''` is defence in depth, since a role can `ALTER ROLE` its own session defaults; PT-31 tests exactly that | DEMOP-F07 |

## 16. Draft 4 amendment: `payments.support_refund`

A support agent's principal never owns the customer's order, so `payments.refund`'s `owner_sub = sub`
cannot hold. `payments.support_refund` (declared in agent-interface-v1 §3) adds a fifth signed parameter,
`customer_sub` (con3, `text64`, broker-resolved from `orders.owner_sub` at propose), and moves the
ownership check onto it. Everything not listed here is as for `payments.refund` (same adapter operations,
idempotency-key derivation from the grant, age rule, provider request built only from the grant, broker
states, reconciler).

**16.1 Configuration.** The adapter configuration gains an optional member
`"support":{"wids":[ID…],"support_principals":{"<ten>":[ID…]}}` (strict JSON; every `ten` must be in
`tenants`; empty lists refused). Without it, the adapter refuses every `payments.support_refund` grant.
The broker's and authority's `support_principals` (agent-interface-v1 §3) MUST equal it; the adapter cannot
check that equality, so an operator error that adds a subject to the broker's copy only fails closed at
the adapter.

**16.2 Claims (§3.1) for `op = payments.support_refund`**, replacing the rows that differ:

| Claim | Requirement |
|---|---|
| `wid` | ∈ `support.wids` |
| `knd`, `use` | `1`, `1` |
| `cfm` | `1`, or `2` with key 20 `mid` present (grant-v1 Draft 4); the adapter does not evaluate the mandate (the authority and broker do) |
| `sub` | ∈ `support.support_principals[ten]` |
| `op`, `opv` | `payments.support_refund`, `1` |
| `con` | exactly `{0: amount_minor, 1: currency, 2: charge_id, 3: customer_sub}`; con3 is an ID (`0x21–0x7E`, 1–64 bytes, so the reserved `" "` fails) |

**16.3 Order check (§3.2).** For `payments.support_refund`: a row with `ten` = grant `ten`,
**`owner_sub` = grant con3**, `charge_id` = con2, `currency` = con1. Under broker compromise this bounds the
scope of mandated refunds: the broker cannot write `nodkey.orders` (§2), so a false con3 never matches.

**16.4 Broker T1 (§7.2).** Step 3 requires `owner_sub` = grant **con3** (instead of `sub`). For `cfm = 2`
grants, the mandate row lock and checks of agent-interface-v1 §4.5 come between the record lock and the
`refund_budget` lock: **record → mandate → `refund_budget` → `charge_refund_state` → `payment_effect`**.

**16.5 Budget (§7.5).** The per-customer budget row is keyed `(ten, con3, currency, day)` for
`payments.support_refund`, so refunds to one customer share one daily budget whichever operation or
principal produced them.

**16.6 Tests.**

| # | Case | Expected | Maps to |
|---|---|---|---|
| PT-45 | `support_refund` grant with `sub` ∉ `support_principals`, `wid` ∉ `support.wids`, no `support` config | `grant_refused`, nothing sent | SI-06 |
| PT-46 | con3 ≠ the order's `owner_sub` (broker-compromise client); con3 = `" "` | `grant_refused`, nothing sent | SI-10, EP-03 |
| PT-47 | `cfm = 2` without `mid`; `cfm = 0` | `grant_refused` (crate: `grant_payload_invalid` / adapter claim) | SI-08 |
| PT-48 | `payments.refund` and `support_refund` to one customer on one day | one shared budget | AR-05 |
| PT-49 | Owner changed between signing and T1 | T1 `not_owner_or_unknown`; adapter refuses on a resend | SI-11 |

**16.7 Changes from Draft 3.3**

| Change | Source |
|---|---|
| `payments.support_refund`: `support` configuration; claims (`wid`, `sub`, `cfm` 1/2, con3); order check on con3; T1 step 3 on con3; lock order with the mandate row; budget keyed by con3; PT-45..PT-49 | ADR-0013; agent-interface review AI-02 (support principals), EP-03 |
