# Nodkey effect protocol v2 — propose → confirm → execute

- **Status:** Draft 1 (2026-10-25). Not yet reviewed.
- **Implements:**
  - [ADR-0011](../decisions/0011-propose-confirm-execute.md) incl. Revision 1;
  - [ADR-0003](../decisions/0003-trusted-user-context-and-grant-issuance.md) Phase 3 profile items 2, 3, 5, 6, 8, plus the page hardening of item 4;
  - SECURITY_INVARIANTS v0.4 SI-06, SI-09, SI-10, SI-20, SI-21.
- **Uses:** [grant-v1](grant-v1.md) Draft 2 (format, verification, deterministic CBOR §4, declarations §6).
- **Review input:** [`docs/reviews/2026-10-25-adr-0011-review.md`](../reviews/2026-10-25-adr-0011-review.md) (PC-01..PC-13).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119/8174.

## 1. Components and channels

| Channel | Path (example) | Peers | Mounted into | Authentication |
|---|---|---|---|---|
| Workload | `/run/nodkey/wl/<wid>.sock` (one per workload, as v1) | workload → broker | that workload only | socket path identifies `wid`; `SO_PEERCRED` uid = the workload's configured uid |
| Gateway | `/run/nodkey/ctl/gateway.sock` | gateway-edge → broker | gateway-edge only | `SO_PEERCRED` uid = configured gateway uid |
| Authority | `/run/nodkey/ctl/authority.sock` | authority → broker | authority only | `SO_PEERCRED` uid = configured authority uid |
| Issue | `/run/nodkey/auth/issue.sock` | gateway-edge → authority | gateway-edge, authority | `SO_PEERCRED` uid = gateway uid (checked by the authority) |

The broker MUST refuse to start in any of these cases:
- two channels share a path or a uid;
- the gateway or authority uid equals any workload uid;
- a control socket's directory is listed in any workload's mounts (where the deployment manifest is
  available to the broker).

On every accepted connection the broker checks `SO_PEERCRED`, and closes the connection on a mismatch.

All four channels use the framing of the v1 broker protocol (`broker/src/protocol.rs`):
- one strict JSON object per line;
- duplicate members, unknown members and wrong types are rejected;
- lines are ≤ 8 KiB, and read/write timeouts are as in v1.

## 2. Workload protocol v2

### 2.1 Version decision

Protocol v1 (`"v":1`: `ledger.get_balance`, `ledger.transfer` with idempotency key, no grants) is kept
**only for Demo 1**. Each workload socket is configured for exactly one version. A message whose `v`
differs from the socket's version is answered with `unsupported_version`. A v2 socket never executes a
write without a confirmed grant (no grantless effects).

### 2.2 Envelope

```json
{"v":2,"id":"<1..64 of [A-Za-z0-9._-]>","op":"<method>","args":{...}}
{"v":2,"id":"…","correlation_id":"…","ok":true,"result":{...}}
{"v":2,"id":"…","correlation_id":"…","ok":false,"error":{"code":"…","message":"<static text>"}}
```

`grant`, when present, is a member of `args` and contains grant-v1 transport text (base64url, ≤ 2731
chars).

### 2.3 Methods

| Method | `args` | `result` |
|---|---|---|
| `effect.propose` | `{"op": string, "params": object, "approver": {"ten": ID, "sub": ID}}` | `{"pending_id", "confirm_url", "expires_at"}` |
| `effect.status` | `{"pending_id": string}` | `{"pending_id", "state", "expires_at", "outcome": null \| {"class", "receipt_id"}}` |
| `ledger.get_balance` | `{"account": account_id, "grant": string}` | `{"account", "balance_minor"}` |
| `payments.get_order` | `{"order_id": uint, "grant": string}` | `{"order_id", "currency", "amount_minor", "refunded_minor", "status"}` |

**`effect.propose`**
1. `op` MUST be declared as a write operation that requires confirmation (§5) and is allowed for this
   `wid`.
2. `params` MUST contain exactly the declared parameters, strictly typed (grant-v1 §6.2; integers in minor
   units ≤ 2^53 − 1). Phase 3/4 operations have no free-text parameters.
3. `approver`: see §2.4.
4. The broker validates **syntax, types and registration only**. It never consults trusted state
   (orders, accounts, balances), so propose is not an existence oracle (PC-10). Any failure →
   `invalid_argument`.
5. On success the broker creates an immutable pending record (§3), and returns:
   - `pending_id`: 16 bytes from the broker's CSPRNG, base64url (22 chars);
   - `confirm_url`: `https://<auth origin>/confirm/<pending_id>`, with no other component (PC-11);
   - `expires_at`: Unix seconds.

   Identical re-proposals create new records; they never update an existing one (PC-04).

**`effect.status`.** Answered only if the record's `wid` equals the caller's `wid`. For any other caller,
a malformed id, an unknown id, or a pruned id, the answer is `not_found` with identical timing and body
(PC-10). The result carries:
- `state`;
- `outcome.class` ∈ `succeeded | failed | unknown | denied | expired`;
- an opaque `receipt_id` (null until the effect is final, ADR-0007).

It never returns the approver, the trusted facts, the grant, or upstream error text.

**Read methods** take a grant-v1 **read** grant (`knd = 2`) whose `rop` contains the method. The broker
verifies it with `peer_wid` = this socket's `wid` (grant-v1 §7.2, §7.4), and the query filters by the
grant's `ten` and `sub` (`owner_scoped`). A non-owned or nonexistent resource yields `grant_denied`,
indistinguishable from other denials.

A grant with `knd = 1` presented on a workload socket is rejected with `grant_denied` (broker-facing
code `grant_channel_invalid`). Write grants are accepted only on the authority socket (PC-13).

### 2.4 Intended approver (PC-01, PC-06)

Each workload registration declares `approver_source`:

| `approver_source` | Rule at propose time | Page banner |
|---|---|---|
| `enrolled{ten, sub}` (agents, single-principal apps) | `approver` MUST equal the enrolment exactly | none |
| `named` (multi-user web apps) | `approver.ten` MUST be one of the workload's registered tenants; `sub` is any ID | "Requested by <workload display name>. It was not necessarily started by you." |

The broker stores the approver on the record. Only a session whose `(ten, sub)` equals it may view or
approve the record (§4). The operation's trusted-fact checks for that subject are also required (§5).
Mandates (specified separately) are looked up by `(wid, approver)` as stored, never by a proposal field.

### 2.5 Limits

| Limit | Default | Exceeded → |
|---|---|---|
| Outstanding `PENDING` records per `wid` | 32 | `limit_exceeded` |
| Outstanding `PENDING` records per `(wid, approver)` | 8 | `limit_exceeded` |
| Proposal rate per `wid` | token bucket: 10/min, burst 10 | `limit_exceeded` |
| `effect.status` rate per `wid` | 120/min | `limit_exceeded` |
| Pending expiry (`expires_at − created_at`) | 600 s (configurable 60–900 s) | record → `EXPIRED` |
| Approval-to-delivery deadline | 60 s | `APPROVED` → `EXPIRED` |

Limits are checked before any record is written, and the uniform error is used for all of them (PC-09).

### 2.6 Client-facing error codes (closed set, static messages)

`malformed_request`, `unsupported_version`, `request_too_large`, `unknown_operation`,
`operation_not_permitted`, `invalid_argument`, `limit_exceeded`, `not_found`, `grant_denied`,
`unavailable`.

Detailed reasons go only to the broker's audit log.

## 3. Pending-effect record

### 3.1 Fields

Stored in the broker database (table `pending_effect`). Only the broker reads or writes it. The gateway
and the authority see only what §4/§6 return.

| Field | Type | Mutable |
|---|---|---|
| `pending_id` | 16 bytes, primary key | no |
| `broker_id` | ID | no |
| `wid` | ID | no |
| `ten`, `approver_sub` | ID | no |
| `op`, `opv` | op name, uint | no |
| `params` | map name → uint \| tstr, as validated | no |
| `created_at`, `expires_at` | uint seconds | no |
| `digest` | 32 bytes (§3.2), computed at creation | no |
| `state` | §3.3 | CAS only |
| `state_changed_at` | uint | with `state` |
| `grant_jti` | = `pending_id` once delivered | set once |
| `outcome_class`, `receipt_id` | per §2.3 | set once, at a final state |

Immutability is enforced in the schema: the broker's database role has `UPDATE` only on the mutable
columns. An `UPDATE` trigger rejects changes to any other column.

### 3.2 Canonical digest (gateway and broker MUST compute identical bytes)

```
digest = SHA-256( "nodkey.pending.v1" || 0x00 || dcbor(M) )
M = { 0: pending_id (bstr 16), 1: broker_id (tstr), 2: wid (tstr), 3: ten (tstr),
      4: approver_sub (tstr), 5: op (tstr), 6: opv (uint),
      7: { param name (tstr): value (uint | tstr), ... },
      8: created_at (uint), 9: expires_at (uint) }
```

- `dcbor` is the core deterministic encoding of grant-v1 §4: shortest form, definite lengths, and map
  keys sorted by their encoded bytes, so text keys sort shorter first.
- No floats, tags, negative integers, or other types are allowed.
- The digest covers exactly the values the grant will bind, plus identity and expiry.
- Trusted facts are **not** part of it: they are shown for information and re-checked under lock at
  approval and at execution (§3.3, §5).
- The broker returns the record fields with the render response (§4.1). The gateway MUST recompute the
  digest from the fields it renders and MUST refuse to render (uniform error) if it differs from the
  broker's.

### 3.3 State machine (every transition is a single conditional `UPDATE … WHERE state = <from>`; affected rows = 1 or the transition fails)

| From → To | Actor (channel) | Additional conditions in the same statement/transaction |
|---|---|---|
| (new) → `PENDING` | broker (workload `effect.propose`) | the §2.5 limits hold |
| `PENDING` → `APPROVED` | gateway (`pending.approve`) | `digest` = the supplied digest; `now < expires_at`; supplied `(ten, sub)` = `(ten, approver_sub)`; the operation's approval checks (§5) pass under row locks |
| `PENDING` → `DENIED` | gateway (`pending.deny`) | as for approve, minus the fact checks |
| `PENDING` → `EXPIRED` | broker sweeper, or lazily on access | `now ≥ expires_at` |
| `APPROVED` → `EXPIRED` | broker sweeper | `now ≥ state_changed_at + 60` and `grant_jti` is null |
| `APPROVED` → `EXECUTING` | broker (authority `grant.deliver`) | the grant verifies and matches the record (§6); `grant_jti` is set |
| `EXECUTING` → `SUCCEEDED \| FAILED \| UNKNOWN` | broker effect transaction / adapter | grant-v1 §7.3 W10–W14, plus the adapter states of research 06 §2.2 (`RESERVED`/`DISPATCHED` are sub-states of `EXECUTING`). Denials at execution (for example remaining refundable now too low) → `FAILED`, `outcome.class = denied` |
| `UNKNOWN` → `SUCCEEDED \| FAILED` | reconciler only | research 06 §2.2; never by retry without upstream deduplication |

There are no other transitions. `DENIED`, `EXPIRED`, `SUCCEEDED` and `FAILED` are final.

## 4. Gateway ↔ broker (gateway socket)

The gateway can render and decide; it **cannot sign**. It holds no grant key, and the broker accepts no
grant on this socket. Every gateway request carries the session subject the gateway authenticated
(`{"ten","sub"}`).

### 4.1 `pending.render{pending_id, subject}`

The broker:
1. loads the record;
2. requires `subject = (ten, approver_sub)`;
3. requires the operation's approval checks (§5) to pass, read-only.

If any check fails, or the record does not exist, it returns `not_available`: one code, one body, the
same for every cause (PC-03).

Otherwise it returns:
- `record`: all §3.1 immutable fields, plus `state`;
- `digest`;
- `facts`: the per-operation trusted facts of §5, resolved now;
- `context`:
  - `pending_from_workload_for_subject`: count (PC-08);
  - `recent_identical`: records of the same `(wid, approver, op, params)` in the last 30 min, with state;
  - `workload_display_name`: from registration;
  - `approver_source`.

### 4.2 `pending.approve{pending_id, digest, subject}` / `pending.deny{pending_id, digest, subject}`

Each runs the §3.3 CAS. The result is `ok` or `not_available`; failure causes are uniform.

After `ok` on approve, the gateway sends `issue{pending_id}` on the issue socket (§6). This is the gateway's
only role in issuance. If that call fails, the record expires 60 s after approval (§2.5).

## 5. Operation declarations (Phase 3/4)

The grant-related members follow grant-v1 §6.1. The v2-only members (`approval_checks`, `facts`,
`display`) live in the broker's effects configuration. Every write below has `kind: write`,
`requires_confirmation: true`, `opv: 1`.

| Operation | Kind | Parameters (grant-v1 placement / class / type) | Approval checks (at render, at approve CAS, and again at execution under lock) | Facts shown on the page |
|---|---|---|---|---|
| `ledger.transfer` (continuity) | write | `from` res0 exact `account_id`; `to` con0 exact `account_id`, `destination: true`; `amount_minor` con1 exact `uint` (≥ 1) | `from` exists in `ten` and is owned by the approver | `from` owned by you: yes; current balance of `from`; `to` is "one of your accounts" or "an account not owned by you" (existence of others' accounts is not revealed); amount formatted with the ledger currency's ISO 4217 exponent |
| `payments.refund` | write | `order_id` res0 exact `uint`; `amount_minor` con0 exact `uint` (≥ 1); `currency` con1 exact `currency` | the order exists in `ten`; `owner = approver`; `currency = order.currency`; order status ≠ `disputed` | order id; captured amount; already refunded or encumbered (`RESERVED`, `DISPATCHED`, `UNKNOWN`, `SUCCEEDED`); `remaining_refundable`; warning if any `DISPATCHED`/`UNKNOWN` effect exists on the order; amount formatted with the **broker-trusted** ISO 4217 exponent table; "refund goes to the original payment method" |
| `ledger.get_balance` | read | `account`: `owner_scoped` `account_id` | owner = grant `sub` (in-query) | — |
| `payments.get_order` | read | `order_id`: `owner_scoped` `uint` | owner = grant `sub` (in-query) | — |

**Refund execution** (research 06 §2.3) re-checks, inside the effect transaction under the order lock:
- `1 ≤ amount_minor ≤ remaining_refundable`;
- no `DISPATCHED`/`UNKNOWN` effect on the order (AR-10);
- every approval check.

`charge_id` comes from the broker's `orders` row, never from the workload. A refund that later fails
keeps its amount encumbered until it is released.

`facts` are display-only. They never change what the grant binds.

## 6. Authority ↔ broker (authority socket) and issuance

1. The gateway sends `issue{pending_id}` to the authority on the issue socket. The authority ignores any
   other content.
2. The authority sends `pending.fetch_approved{pending_id}` on the authority socket. The broker returns
   the record's immutable fields and `digest` only if all of these hold:
   - `state = APPROVED`;
   - `grant_jti` is null;
   - the record is not past its delivery deadline.

   Otherwise it returns `not_available`.
3. The authority recomputes the digest (§3.2) and aborts on a mismatch. It then signs a grant-v1 write
   grant **from the fetched record only**:

   | Field | Value |
   |---|---|
   | `iss` | its issuer name |
   | `aud` | `broker_id` |
   | `jti` | `pending_id` |
   | `iat` | its own clock; `nbf = iat`; `exp = iat + 30` |
   | `wid`, `ten` | from the record |
   | `sub` | `approver_sub` |
   | `op`, `opv` | from the record |
   | `res`/`con` | from `params` per the declaration (all exact) |
   | `use` | 1 |
   | `knd` | 1 |
   | `cfm` | 1 |
4. The authority sends `grant.deliver{pending_id, grant}`. The broker:
   - (a) verifies the grant with grant-v1 §7.2 steps 1–9, using `peer_wid` := the record's `wid`;
   - (b) requires `jti = pending_id`, and requires `wid`, `ten`, `sub`, `op`, `opv` and every parameter
     to equal the record;
   - (c) runs the CAS `APPROVED → EXECUTING`, setting `grant_jti`;
   - (d) runs grant-v1 §7.3 (W10 consumption with `request_hash` over the record's params, through W14)
     and the effect.

   Results:

   | Outcome | Response |
   |---|---|
   | Delivery accepted | `accepted` |
   | A grant was already delivered for this record (`grant_jti` set) | `already_delivered` |
   | Any other failure | `not_available` (the cause goes to the audit log; a mismatch in (b) also raises an alarm) |

**Exactly-once.** `jti = pending_id` and the `APPROVED → EXECUTING` CAS together mean that at most one
grant per record is ever consumed. (This refines grant-v1 §9 "Authority generates `jti`": for this
flow `jti` is the broker's 128-bit CSPRNG pending id, unique per record.) If the authority retries after a lost response, it signs again and
gets `already_delivered`; the extra grant is inert. The authority keeps no issuance state.

## 7. Confirmation page contract (auth origin)

### 7.1 GET `/confirm/<pending_id>`

- `pending_id` MUST match the 22-char base64url grammar. Otherwise the uniform error.
- Without a session, the request redirects to login on the auth origin and returns to the **same path**
  afterwards. The page accepts no query parameters (PC-11).
- The gateway calls `pending.render` and verifies the digest (§3.2).
- If the record is final or `APPROVED`, its state is shown to the intended approver without an action
  form.

The page displays:
- operation label (static per-operation template);
- every parameter value in full: no truncation, monospace, escaped;
- formatted amounts;
- the `pending_id`;
- the workload display name, plus the banner of §2.4 when applicable;
- `created_at`, `expires_at`;
- the §5 facts;
- the §4.1 context;
- a form with "Approve" and "Deny".

The form carries `pending_id`, `digest` (hex) and an **approval token**.

### 7.2 Approval token

| Property | Rule |
|---|---|
| Value | 32 bytes from the gateway's CSPRNG, base64url (43 chars) |
| Storage | the gateway's server-side session store maps `token → {session_id, pending_id, digest, expires_at}` |
| `expires_at` | `min(render + 300 s, record.expires_at)` |
| Issuance | one token per render; a re-render issues a new token and invalidates the previous one for that `(session, pending_id)` |
| Use | single use: atomically deleted on first use, whatever the outcome |

### 7.3 POST `/confirm/<pending_id>/decision` — all checks, in order. Any failure → the uniform error, no state change

1. Method is POST and `Content-Type: application/x-www-form-urlencoded`. The form fields are exactly
   `token`, `digest`, `decision` (`approve` or `deny`).
2. Provenance (SI-21, PC-02):
   - If `Sec-Fetch-Site` is present, it MUST be `same-origin` relative to the auth origin, and
     `Sec-Fetch-Mode` MUST be `navigate`.
   - If `Sec-Fetch-Site` is absent, `Origin` MUST be present and exactly equal to the auth origin.
   - `same-site`, `cross-site` and `none` are rejected, as are an app-origin `Origin`, a missing `Origin`
     when `Sec-Fetch-Site` is missing, and `Origin: null`.
3. A valid session exists on the auth origin (`__Host-` cookie, ADR-0003 Phase 3 profile items 2–3).
4. The token exists, is unexpired, and is bound to this session, this `pending_id` and this `digest`. It is
   consumed at this point.
5. `pending.approve` or `pending.deny` with the session subject.

### 7.4 Headers on every auth-origin confirmation response

- `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self';
  frame-ancestors 'none'; base-uri 'none'`;
- no scripts;
- `Cross-Origin-Opener-Policy: same-origin`;
- `Cross-Origin-Resource-Policy: same-origin`;
- `X-Frame-Options: DENY`;
- `Cache-Control: no-store`;
- `Referrer-Policy: no-referrer`;
- `X-Content-Type-Options: nosniff`.

### 7.5 Uniform error

For every failure the response is identical:
- status 404;
- body "This request is not available.";
- the §7.4 headers.

This covers: unknown, expired or decided record (for non-approvers); wrong subject; failed facts; bad
token; bad provenance; digest mismatch.

**Residuals (published).**
- Approval is session-based in Phase 3 (test login), so SI-20 is **PARTIALLY MET**. With passkeys, the
  WebAuthn challenge MUST be `digest`.
- A compromised gateway can approve anything (attacker J, out of scope).
- The workload's proposed values are shown as proposed; only their equality with what executes is
  guaranteed (PC-12).
- Approval fatigue and look-alike phishing of the auth origin remain until passkeys exist (PC-08,
  PC-11).

## 8. Test plan (each case must have an automated test; results reported PASS / FAIL / NOT TESTED)

| # | Case | Expected | Maps to |
|---|---|---|---|
| T01 | Approve by a logged-in user who is not the intended approver (same and other tenant) | uniform error; state stays `PENDING` | PC-01, SI-20 |
| T02 | `enrolled` workload proposes with a different approver | `invalid_argument` | PC-01, PC-06 |
| T03 | `named` workload; approver does not own the order | page: uniform error; approve CAS fails | PC-01, PC-03, SI-10 |
| T04 | App-origin `fetch` POST to the decision endpoint with credentials (`Sec-Fetch-Site: same-site`) | uniform error | PC-02, SI-21 |
| T05 | App-origin HTML form POST (top-level navigation, `same-site`) | uniform error | PC-02, SI-21 |
| T06 | POST with no Fetch Metadata and no `Origin`; with `Origin: null`; with `Origin` = app origin | uniform error | PC-02, SI-21 |
| T07 | Valid POST with a missing, reused, other-session, other-pid, or expired token | uniform error; a reused token never succeeds twice | PC-02, PC-04 |
| T08 | Digest in the POST ≠ stored digest (record re-proposed, values changed) | CAS fails; uniform error | PC-04, SI-20 |
| T09 | Attempt to modify a pending record (repeat propose, direct DB update by the broker role) | new pid / rejected by the trigger | PC-04 |
| T10 | Render for nonexistent vs foreign vs expired pid: byte-identical responses, timing within tolerance | identical | PC-03, PC-10 |
| T11 | `effect.status` from another `wid` for a valid pid; for an unknown pid | `not_found`, identical | PC-10 |
| T12 | `effect.propose` for an existing vs nonexistent order | identical success (no fact lookup) | PC-10 |
| T13 | Confirmation page framed by the app origin; opened via `window.open` from the app | blocked by the headers; no opener access | PC-05 |
| T14 | Confirmation URL with extra query parameters or a path suffix | uniform error; no redirect | PC-11 |
| T15 | Write grant (`knd = 1`) presented on a workload socket | `grant_denied` (`grant_channel_invalid`) | PC-13, SI-05 |
| T16 | Grant delivered on the gateway socket; peer with the wrong uid on the authority socket | rejected; connection closed | PC-13, SI-05 |
| T17 | Authority asked to issue for a `PENDING`, `DENIED`, `EXPIRED`, or already-delivered record | no grant / `already_delivered` | SI-20, SI-09 |
| T18 | Delivered grant whose params differ from the record (forged by a test authority key) | `not_available` + alarm; no effect | SI-06 |
| T19 | Two concurrent deliveries for one record; N = 64 concurrent approves | one `EXECUTING`; one effect | SI-09 |
| T20 | Refund amount > remaining refundable at execution (a second refund executed in between) | `FAILED`/`denied`; no upstream call | SI-11, research 06 |
| T21 | Refund while another effect on the order is `UNKNOWN` | `FAILED`/`denied` | AR-10, SI-15 |
| T22 | Refund currency ≠ order currency | approval check fails (uniform) | SI-10 |
| T23 | Outstanding limits and rate limits exceeded; another `wid` unaffected | `limit_exceeded`; other `wid` proceeds | PC-09 |
| T24 | Approve after `expires_at`; approve after `APPROVED → EXPIRED` | uniform error; no grant | SI-20 |
| T25 | Duplicate identical proposals: the page shows `recent_identical` and the pending count | shown | PC-08 |
| T26 | Read grant for a non-owned account/order; read grant used for `effect.propose` or a write | `grant_denied` | SI-06, SI-10 |
| T27 | v1 message on a v2 socket and vice versa | `unsupported_version` | §2.1 |
| T28 | Gateway digest computation vs broker: shared vectors (field orderings, long and short param names) | identical bytes | §3.2 |
| T29 | Kill the authority between approve and deliver | record `EXPIRED` after 60 s; no effect | §2.5 |
| T30 | Crash at each state boundary (`EXECUTING`/`RESERVED`/`DISPATCHED`) | as research 06 §2.2; never a duplicate effect | SI-09, SI-15 |
