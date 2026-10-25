# Nodkey effect protocol v2 — propose → confirm → execute

- **Status:** **Draft 2** (2026-10-25). Not yet re-reviewed. Supersedes Draft 1 (changes in §9).
- **Implements:**
  - [ADR-0011](../decisions/0011-propose-confirm-execute.md), incl. Revision 1 and Amendment 1 (approval
    channel);
  - [ADR-0003](../decisions/0003-trusted-user-context-and-grant-issuance.md) Phase 3 profile items 2, 3, 5, 6
    and 8, plus the page hardening of item 4;
  - SECURITY_INVARIANTS v0.4 SI-05, SI-06, SI-09, SI-10, SI-15, SI-20 and SI-21.
- **Uses:** [grant-v1](grant-v1.md) Draft 2: format, verification, deterministic CBOR (§4) and
  declarations (§6).
- **Reviews:**
  - [`2026-10-25-adr-0011-review.md`](../reviews/2026-10-25-adr-0011-review.md) (PC-xx);
  - [`2026-10-25-effect-protocol-v2-review.md`](../reviews/2026-10-25-effect-protocol-v2-review.md) (EP-xx).
- **Vectors:** [`tests/vectors/effect-v2/`](../../tests/vectors/effect-v2/README.md) (pending-effect digest).

MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119 and RFC 8174.

## 1. Components, trust and channels

### 1.1 Trust

| Process | Holds | Trusted for | Compromise = |
|---|---|---|---|
| Workload | nothing reusable | nothing | attacker C (the design target) |
| gateway-edge | sessions, approval tokens; **no signing key** | the authenticated session subject (TCB) | attacker J: can approve as any logged-in user |
| Authority | the grant signing key; its own issuance store | signing only what a gateway approval and the broker record agree on | attacker J |
| Broker | DB credentials, provider credentials, pending records | executing verified grants | attacker J |

A write grant requires **two independent inputs**:
- an approval from the gateway, carrying the session-verified subject and the digest it displayed;
- a pending record read from the broker whose digest and approver match that approval.

So compromise of the broker's database or request parsing **alone** cannot produce a grant. Neither can a
compromised gateway alone: it can only approve records that exist, with the digest those records have. A
compromised gateway can still approve any record on behalf of any logged-in user (residual, attacker J;
reduced by passkeys, §7.6).

### 1.2 Channels

Every socket lives in its **own** directory, mode 0700, owned by the peer that connects to it. The socket
file is mode 0600, owned by that peer's uid, with the listener's uid given access through a group. Nothing
in any control directory is mounted into a workload.

| # | Socket | Listener ← client | Mounted into | Client authentication |
|---|---|---|---|---|
| W | `/run/nodkey/wl/<wid>/broker.sock` (one per workload) | broker ← workload | that workload | the path identifies `wid`; `SO_PEERCRED` uid = that workload's uid |
| G | `/run/nodkey/gw-broker/broker.sock` | broker ← gateway | gateway | `SO_PEERCRED` uid = gateway uid |
| A | `/run/nodkey/au-broker/broker.sock` | broker ← authority | authority | `SO_PEERCRED` uid = authority uid |
| I | `/run/nodkey/gw-authority/authority.sock` | authority ← gateway | gateway, authority | `SO_PEERCRED` uid = gateway uid (checked by the authority) |

The authority has no network interface. It holds one listening socket (I) and one client socket (A).

**Start-up refusals.** The broker and the authority MUST refuse to start if any of these hold:
- two roles share a uid;
- the gateway or authority uid equals a workload uid;
- a socket directory is shared between channels;
- the deployment manifest shows any control directory mounted into a workload.

If the manifest is unavailable, they MUST also refuse to start, unless the operator flag
`--mounts-verified-externally` is set. That flag is logged at every start (EP-09).

uids are compared as seen in the listener's user namespace. Deployments MUST map each role to a distinct
uid in that namespace. Every connection whose `SO_PEERCRED` uid differs from the expected one is closed.

**Framing** (all channels): the v1 broker framing (`broker/src/protocol.rs`):
- one strict JSON object per line;
- duplicate, unknown and wrongly typed members are rejected;
- lines are ≤ 8 KiB;
- the v1 timeouts apply.

## 2. Workload protocol v2 (socket W)

### 2.1 Versions

Protocol v1 (grantless `ledger.transfer`) exists **only** for Demo 1. A broker MUST refuse to start if:
- a v1 socket is configured and the deployment profile is not the explicit `demo1` profile;
- v1 and v2 sockets are configured on one broker;
- v1 and v2 sockets share one database (EP-10).

A message whose `v` differs from the socket's version gets `unsupported_version`.

### 2.2 Envelope

```json
{"v":2,"id":"<1..64 of [A-Za-z0-9._-]>","op":"<method>","args":{...}}
{"v":2,"id":"…","correlation_id":"…","ok":true,"result":{...}}
{"v":2,"id":"…","correlation_id":"…","ok":false,"error":{"code":"…","message":"<static text>"}}
```

### 2.3 Methods

| Method | `args` | `result` |
|---|---|---|
| `effect.propose` | `{"op", "params": {...}, "approver": {"ten": ID, "sub": ID}}` | `{"pending_id", "confirm_url", "expires_at"}` |
| `effect.status` | `{"pending_id"}` | `{"pending_id", "state", "expires_at", "outcome": null \| {"class", "receipt_id"}}` |
| `ledger.get_balance` | `{"account", "grant"}` | `{"account", "balance_minor"}` |
| `payments.get_order` | `{"order_id", "grant"}` | `{"order_id", "currency", "amount_minor", "refunded_minor", "status"}` |

**`effect.propose`**
- `op` MUST be declared `write` with `requires_confirmation`, and allowed for this `wid` (§5).
- `params` MUST contain exactly the declared parameters, typed per grant-v1 §6.2 (integers in minor
  units ≤ 2^53 − 1).
- `approver` follows §2.4.
- The broker checks **syntax, types and registration only**, never trusted state (PC-10). Any failure
  gives `invalid_argument`.
- On success it creates an immutable record (§3) and returns:
  - `pending_id`: 16 bytes from the broker CSPRNG, as canonical unpadded base64url (22 chars);
  - `confirm_url`: `https://<auth origin>/confirm/<pending_id>`, with nothing else in it;
  - `expires_at`.
- Re-proposals always create new records.

**`effect.status`**
- It is answered only for records whose `wid` is the caller's.
- In every other case (another workload's record, unknown, non-canonical or pruned id) it returns
  `not_found`, with an identical body and timing.
- `outcome.class` ∈ `succeeded | failed | unknown | denied | expired`.
- `receipt_id` is null until the record is in a final state. It is then 16 random bytes in base64url,
  never sequential.
- The response never contains the approver, facts, grant or upstream text.

**Read methods** need a grant-v1 **read** grant (`knd = 2`, signed by the authority, §4.3) whose `rop`
contains the method. The broker verifies it with `peer_wid` = this socket's `wid`. The query filters by the
grant's `ten`/`sub`. A missing or foreign resource is answered with `grant_denied`.

A `knd = 1` grant on socket W is answered with `grant_denied` (broker-facing code `grant_channel_invalid`).

### 2.4 Intended approver and mandates (PC-01, PC-06, EP-03, EP-08)

| Registration `approver_source` | Propose rule | Mandates | Operations allowed |
|---|---|---|---|
| `enrolled{ten, sub}`: agents and single-principal apps | `approver` MUST equal the enrolment | MAY apply (mandate spec), looked up by `(wid, enrolled principal)` | all declared |
| `named`: multi-user apps | `approver.ten` ∈ registered tenants; `sub` is any ID | **never**: every write needs explicit confirmation in v1 | only operations without `destination: true` parameters (for example `payments.refund`, not `ledger.transfer`) |

A mandate-based approval, when specified, MUST also go through the authority with a check that does not
depend on broker state alone.

### 2.5 Limits

| Limit | Default | When exceeded |
|---|---|---|
| `PENDING` records per `wid` / per `(wid, approver)` | 32 / 8 | `limit_exceeded` |
| Proposal rate per `wid` | 10/min, burst 10 | `limit_exceeded` |
| `effect.status` rate per `wid` | 120/min | `limit_exceeded` |
| Pending lifetime (`expires_at − created_at`) | 600 s (60–900) | `PENDING → EXPIRED` |
| Execution window after approval | the grant's `exp + skew` (≤ 35 s) | `APPROVED → EXPIRED` |

A `named` workload can exhaust its own per-`wid` quota by rotating `sub`. That denies service only to its
own users and is accepted.

### 2.6 Client-facing error codes

`malformed_request`, `unsupported_version`, `request_too_large`, `unknown_operation`,
`operation_not_permitted`, `invalid_argument`, `limit_exceeded`, `not_found`, `grant_denied`,
`unavailable`. Each has a static message. Details go to the audit log only.

## 3. Pending-effect record

### 3.1 Storage and fields

The record lives in the broker's database, in the **same** database as `consumed_grant`, the effect
tables and the adapter states (`RESERVED`/`DISPATCHED`). The ADR-0006 restore runbook covers them
together.

| Field | Type | Mutable |
|---|---|---|
| `pending_id` | 16 bytes, primary key | no |
| `broker_id`, `wid`, `ten`, `approver_sub`, `op` | text | no |
| `opv`, `created_at`, `expires_at` | uint | no |
| `params` | name → value | no |
| `param_types` | name → type | no |
| `display` | per §3.2 key 11 | no |
| `digest` | 32 bytes | no |
| `state`, `state_changed_at` | §3.3 | by conditional update only |
| `grant` | bytes, set at `APPROVED` | set once |
| `outcome_class`, `receipt_id` | | set once, in a final state |

The broker's DB role may update only the mutable columns. A trigger rejects any other update.

### 3.2 Digest (normative; the broker, gateway and authority MUST produce identical bytes)

```
digest = SHA-256( "nodkey.pending.v1" || 0x00 || dcbor(M) )
```

The tag versions the *record format*, not the protocol. `dcbor` is grant-v1 §4: shortest-form heads,
definite lengths, and map keys in bytewise order of their **encoded** bytes, so text keys sort shorter
first. No floats, tags, negative integers, booleans or nulls.

| Key | Field | CBOR type | Value rule |
|---|---|---|---|
| 0 | `pending_id` | bstr(16) | the 16 bytes from a **canonical** decode of the 22-char base64url text (grant-v1 §2 rules: alphabet, no padding, 4 trailing bits zero). Non-canonical text is rejected, not normalized |
| 1 | `broker_id` | tstr | ID (`0x21–0x7E`, 1–128 bytes) |
| 2 | `wid` | tstr | ID, 1–256 |
| 3 | `ten` | tstr | ID, 1–128 |
| 4 | `approver_sub` | tstr | ID, 1–256 |
| 5 | `op` | tstr | op name |
| 6 | `opv` | uint | |
| 7 | params | map tstr → uint \| tstr | **every** declared parameter (including `free` ones). The CBOR type comes from the **declared type** (key 10), never from the JSON value type: `uint` → CBOR uint (JSON integer, ≤ 2^53 − 1); any text type → tstr (JSON string). The value must satisfy the grant-v1 §6.2 grammar. A JSON value of the other kind is rejected |
| 8 | `created_at` | uint | Unix seconds |
| 9 | `expires_at` | uint | Unix seconds |
| 10 | param types | map tstr → tstr | declared type name for each parameter in key 7 |
| 11 | display | map tstr → uint \| tstr | broker-trusted presentation facts that change how values read: for amounts `{"amount_exponent": uint, "currency": tstr}` from the broker's ISO 4217 table; `{}` if none. Text 0–64 bytes of `0x20–0x7E` |

Further rules:
- **Text:** the exact UTF-8 bytes of the JSON string after standard JSON unescaping. There is no Unicode
  normalization, trimming or case folding. All allowed text is ASCII.
- **Hex digest** (in forms and messages): exactly 64 lowercase hex characters. It is decoded before
  comparison; uppercase or any other length is rejected.

Each party computes the digest **itself**:
- the broker, at creation, from its validated values;
- the gateway, from the render response it displays (it formats amounts **only** with key 11's exponent);
- the authority, from the record it fetches.

Vectors DG-01..DG-10 fix the bytes, including:
- a numeric-looking `account_id`;
- 2^53 − 1;
- escaped JSON text;
- the display exponent;
- a free-text parameter;
- rejections for an alias `pending_id`, a type mismatch, a missing parameter, and a non-ASCII ID.

### 3.3 State machine

Every transition is one conditional `UPDATE … WHERE pending_id = ? AND state = <from> AND <conditions>`.
It takes effect only if exactly one row is updated. Concurrent attempts are serialized with
`SELECT … FOR UPDATE` (PostgreSQL, ADR-0006 §1). Lazy expiry: every access to a non-final record first
applies the applicable expiry transition.

| From → To | Trigger | Conditions (same statement or transaction) |
|---|---|---|
| (new) → `PENDING` | `effect.propose` (W) | §2.5 limits |
| `PENDING` → `DENIED` | `pending.deny` (G) | digest equal; `(ten, sub)` = approver; `now < expires_at` |
| `PENDING` → `EXPIRED` | sweeper or lazily | `now ≥ expires_at` |
| `PENDING` → `APPROVED` | `grant.deliver` (A) | §4.2 checks; `now < expires_at`; approval checks (§5) under lock; stores `grant` |
| `APPROVED` → `SUCCEEDED \| FAILED` | execution transaction (§4.4), internal effects | grant-v1 W10–W14 in the same transaction |
| `APPROVED` → `EXECUTING` | execution transaction, external effects | W10–W13 and the ADR-0006 T1 `RESERVED` insert, in the same transaction |
| `APPROVED` → `EXPIRED` | execution attempt or sweeper | `now ≥ grant.exp + skew` (the grant can no longer verify; nothing was consumed) |
| `EXECUTING` → `SUCCEEDED \| FAILED \| UNKNOWN` | adapter T2/T3 (research 06 §2.2) | `RESERVED`/`DISPATCHED` are sub-states of `EXECUTING` |
| `UNKNOWN` → `SUCCEEDED \| FAILED` | reconciler only | research 06 §2.2 |

There are no other transitions. Final states: `DENIED`, `EXPIRED`, `SUCCEEDED`, `FAILED`.

A denial at execution time (for example, the remaining refundable amount is now too low) gives `FAILED`
with `outcome.class = denied`.

## 4. Approval, issuance and execution

### 4.1 Gateway → broker (socket G): render and deny

The gateway sends `{"subject": {"ten","sub"}}` from its verified session with every request.

**`pending.render{pending_id, subject}`**
- Requires `subject = (ten, approver_sub)` and the approval checks of §5 (read-only).
- On any failure or unknown id it returns `not_available`: one body for every cause (PC-03).
- Otherwise it returns:
  - the §3.2 fields;
  - `digest` (hex) and `state`;
  - `facts` (§5);
  - `context`:
    - `pending_from_workload_for_subject`;
    - `recent_identical` (same `wid`, approver, `op` and params in the last 30 min, with states);
    - `other_open_on_resource` (§5);
    - `workload_display_name`;
    - `approver_source`.
- The gateway recomputes the digest from these fields. On a mismatch it renders the uniform error.

**`pending.deny{pending_id, digest, subject}`** runs the §3.3 transition. It returns `ok` or `not_available`.

The gateway can neither approve on the broker nor sign anything. The broker accepts no grant on socket G.

### 4.2 Gateway → authority (socket I): `approve` and `read_grant`

**`approve{pending_id, digest_shown, subject}`.** It is sent after the §7.3 checks pass. The authority:

1. Validates the input: canonical `pending_id`, 64-char lowercase-hex `digest_shown`, ID-valid `subject`.
2. Sends `pending.get{pending_id}` on socket A. This call is read-only. It returns the §3.2 fields,
   `state` and `digest` for any record, or `not_found`.
3. Requires all of these:
   - `state = PENDING`;
   - `now < expires_at`;
   - its **own** recomputed digest = `digest_shown`, and also = the broker's `digest`;
   - `subject = (ten, approver_sub)`;
   - the workload's `approver_source` permits the operation (§2.4).

   It has the operation and workload registrations in its own configuration, as copies of the broker's.
   Their equality is checked at start-up through `config.digest` on socket A. Any failure → `not_available`.
4. **Exactly-once at the authority.** It inserts into its own durable store (synchronous commit or fsync):

   `issuance(jti = pending_id PRIMARY KEY, digest, ten, sub, wid, op, signed_at, grant, status)`

   - If a row exists with the same digest and subject, it does not sign again: it re-delivers the stored
     `grant` bytes (step 6).
   - If a row exists with a different digest or subject, it returns `not_available` and raises an alarm.
5. Signs a grant-v1 write grant from the fetched record only:

   | Field | Value |
   |---|---|
   | `iss` | its issuer |
   | `aud` | `broker_id` |
   | `jti` | `pending_id` |
   | `iat` | its own clock |
   | `nbf` | `iat` |
   | `exp` | `iat + 30` |
   | `wid`, `ten` | from the record |
   | `sub` | `approver_sub` |
   | `op`, `opv` | from the record |
   | `res` / `con` | from params per the declaration (all exact) |
   | `use` | 1 |
   | `knd` | 1 |
   | `cfm` | 1 |

   Stores the bytes, then sets `status = signed`.
6. Sends `grant.deliver{pending_id, grant}` on socket A (§4.3). It records the result as
   `status ∈ {accepted, rejected, expired}`:
   - `unavailable` or a lost response: retry with the **same bytes** until `exp`;
   - no `accepted` by `exp + skew`: mark `expired`. The broker can no longer execute that grant (§3.3).
7. Returns `ok` (on `accepted`) or `not_available` to the gateway. The gateway shows a neutral
   "submitted" page in both cases, plus the record state from a fresh render.

`jti = pending_id` overrides grant-v1 §9 ("Authority generates `jti`") for this flow:
- the value is the broker's 128-bit CSPRNG id;
- the authority never signs two different grants with one `jti` (step 4);
- read-grant `jti`s come from the authority's CSPRNG and share the `iss` namespace (collision probability
  negligible; read grants are not consumed).

**`read_grant{subject, wid, rop}`** (EP-05). Read grants are signed **only** by the authority, on request
from the gateway, for a same-origin or top-level document navigation (ADR-0003 Profile 1 for reads). The
authority:
- requires every `rop` entry to be a `read` operation allowed for `wid`;
- requires `subject.ten` to be among the tenants of `wid`;
- signs `knd = 2` with `sub`/`ten` from `subject`, `iat` from its clock and `exp = iat + 30`;
- returns it to the gateway, which attaches it to the forwarded request.

The gateway holds no key.

### 4.3 Authority → broker (socket A): `pending.get`, `grant.deliver`

**`grant.deliver{pending_id, grant}`.** In one transaction, the broker:
1. locks the record;
2. if `state = APPROVED` and the stored `grant` equals the delivered bytes, returns `accepted`
   (idempotent);
3. otherwise requires `state = PENDING` and `now < expires_at`, and then requires:
   - the grant to verify per grant-v1 §7.2 steps 1–9, with `peer_wid` := the record's `wid`;
   - `knd = 1` and `cfm = 1`;
   - `jti = pending_id`;
   - `wid`, `ten`, `sub = approver_sub`, `op`, `opv` and every parameter to equal the record;
   - the approval checks of §5 to pass under lock.
4. sets `APPROVED` and stores `grant`;
5. commits, and returns `accepted`.

Results:

| Result | Meaning |
|---|---|
| `accepted` | approval stored |
| `rejected` | verification or match failed; alarm on a match failure |
| `expired` | record no longer `PENDING`, or past `expires_at` |
| `unavailable` | DB failure; nothing changed; retry allowed |

### 4.4 Execution and recovery (EP-01)

After `accepted`, and in a **recovery loop** (at start-up, then every 5 s, for every `APPROVED` record),
the broker runs the **execution transaction**:

1. `SELECT … FOR UPDATE` the record with `state = APPROVED`. If it is no longer `APPROVED`, stop.
2. If `now ≥ grant.exp + skew`, set `APPROVED → EXPIRED` and commit. The grant was never used. Stop.
3. Verify the stored grant (grant-v1 §7.2 steps 1–9, `peer_wid` := the record's `wid`).
4. Run grant-v1 §7.3:
   - W10 consumption, with `request_hash` over the record's params;
   - savepoint;
   - W11–W13;
   - W14, including the §5 execution checks under lock.
5. For **internal effects** (ledger): perform the effect and set `SUCCEEDED`, or on denial roll back to
   the savepoint and set `FAILED/denied` with `consumed_grant.outcome = DENIED`. Then commit.
6. For **external effects**: insert the ADR-0006/research 06 T1 `RESERVED` row and set
   `APPROVED → EXECUTING`. Then commit. T2/T3 follow in their own transactions.

Every step above happens in **one** transaction. If anything fails before commit (crash, lock timeout,
recording failure), everything rolls back. The record stays `APPROVED`, nothing is consumed, and the
recovery loop retries until success or until step 2 expires it.

So there is no `EXECUTING` record without a consumed grant, and no consumed grant without a recorded
decision. The grant-v1 rule "a recording failure means no decision" holds, because the retry simply
decides later.

Restoring a database backup MUST follow ADR-0006 §9 (revoke or rotate before serving). Otherwise a
restored `APPROVED` row whose grant is still unexpired could execute again. With the 30 s grant TTL, this
risk lasts only 35 s after the backup was taken.

## 5. Operation declarations (Phase 3/4)

The grant-related members follow grant-v1 §6.1. The approval checks, facts and display members live in
the effects configuration. Every write has `requires_confirmation: true` and `opv: 1`. Approval checks run:
- at render (read-only);
- at `grant.deliver`, under lock;
- again during execution, under lock.

| Operation | Parameters | Approval checks | Facts shown |
|---|---|---|---|
| `ledger.transfer` (write; `enrolled` workloads only) | `from` res0 exact `account_id`; `to` con0 exact `account_id`, `destination: true`; `amount_minor` con1 exact `uint` ≥ 1 | `from` exists in `ten` and is owned by the approver | "from: your account"; balance of `from`; `to`: "one of your accounts" or "not owned by you" (existence is not revealed); amount with the ledger currency's exponent (display key 11) |
| `payments.refund` (write) | `order_id` res0 exact `uint`; `amount_minor` con0 exact `uint` ≥ 1; `currency` con1 exact `currency` | order exists in `ten`; `owner = approver`; `currency = order.currency`; **`order.status ∈ {captured, partially_refunded}`** (allow-list; any other or unknown status fails) | order id; captured amount; refunded and encumbered amounts (`RESERVED`, `DISPATCHED`, `UNKNOWN`, `SUCCEEDED`); `remaining_refundable`; `other_open_on_resource` = count and amounts of other `PENDING`/`APPROVED`/`EXECUTING` records on the order; warning on any `DISPATCHED`/`UNKNOWN`; amount with the broker's ISO 4217 exponent (key 11); "refunded to the original payment method" |
| `ledger.get_balance` (read) | `account` `owner_scoped` `account_id` | owner = grant `sub` (in query) | — |
| `payments.get_order` (read) | `order_id` `owner_scoped` `uint` | owner = grant `sub` (in query) | — |

**Refund execution** re-checks under the order lock:
- `1 ≤ amount_minor ≤ remaining_refundable`;
- no `DISPATCHED`/`UNKNOWN` effect on the order (AR-10);
- every approval check.

`charge_id` comes only from the broker's `orders` row.

An amount encumbered by a failed or unknown refund is released **only by the reconciler**, after the
provider confirms a final failure (research 06 §2.2).

Facts are informational and can be up to 300 s stale (the token lifetime). Execution re-checks decide.

## 6. Residuals (published)

- **Session approval.** Approval is session-based in Phase 3 (test login): SI-20 is **PARTIALLY MET**.
  With passkeys, the WebAuthn challenge MUST be the digest, and the authority MUST verify the assertion
  itself.
- **Compromised gateway** (J): approves any existing record as any logged-in user.
- **Compromised authority** (J): signs anything.
- **Compromised broker** (J): needs no grant for its own credentials, but cannot obtain grants without a
  gateway approval.
- **Proposed values.** Displayed values are the workload's proposal. Only their equality with what
  executes is guaranteed (PC-12).
- **Named approvers.** Under `named`, a compromised app can send users approval links for effects they
  never started. The banner and per-operation limits (§2.4) bound this; user vigilance remains a residual
  (EP-08, PC-08).
- **Execution oracle.** `outcome.class` after an approved `ledger.transfer` reveals whether `to` exists at
  execution (EP-12). Accepted: it requires a user approval.
- **Phishing.** Look-alike phishing of the auth origin remains until passkeys (PC-11).

## 7. Confirmation page contract (auth origin)

### 7.1 GET `/confirm/<pending_id>`

1. The path must be exactly `/confirm/` followed by a canonical 22-char id, with no query. Anything else
   gets the uniform error.
2. Without a session, the gateway stores the return path **server-side**, keyed by its login state, and
   redirects to login. After login it returns only to `/confirm/<that id>` (EP-13).
3. The gateway runs `pending.render` (§4.1) and the digest check.
4. If the record is not `PENDING`, its state is shown to the intended approver, with no form.

The page shows:
- the operation label (static template);
- every parameter in full: escaped, monospace, never truncated;
- amounts formatted only with display key 11;
- the `pending_id`;
- the workload display name;
- `created_at` and `expires_at`;
- the facts and context of §4.1;
- for `named` workloads, directly above the buttons: **"Approve only if you just asked <workload> to do
  this."**;
- a form with `token`, `digest` (lowercase hex) and two submit buttons, `decision=approve` and
  `decision=deny`.

### 7.2 Approval token

| Property | Rule |
|---|---|
| Value | 32 bytes from the gateway CSPRNG, base64url (43 chars) |
| Storage | `token → {session_id, pending_id (bytes), digest (bytes), expires_at = min(render + 300 s, record.expires_at)}` |
| Re-render | invalidates the previous token for that `(session, pending_id)` |
| Use | single use; deleted atomically at its first presentation, **even if a later step fails**, so a stale render cannot be retried |

### 7.3 POST `/confirm/<pending_id>/decision`

All checks run in order. Any failure gives the uniform error and causes no state change.

1. Path rules as in §7.1. Method POST, `Content-Type: application/x-www-form-urlencoded`, fields exactly
   `token`, `digest`, `decision`.
2. Provenance (SI-21):
   - if `Sec-Fetch-Site` is present, it MUST be `same-origin` and `Sec-Fetch-Mode` MUST be `navigate`;
   - otherwise `Origin` MUST exactly equal the auth origin;
   - `Origin: null` is rejected.
3. A valid auth-origin session (`__Host-` cookie, ADR-0003 Profile 2–3).
4. The token is valid and bound to this session, `pending_id` and digest. It is consumed here.
5. On `approve`: send `approve{pending_id, digest_shown, subject}` on socket I. On `deny`: send
   `pending.deny` on socket G. Either way, show a neutral result page.

### 7.4 Headers on every confirmation response

- `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`;
- no scripts;
- COOP `same-origin`;
- CORP `same-origin`;
- `X-Frame-Options: DENY`;
- `Cache-Control: no-store`;
- `Referrer-Policy: no-referrer`;
- `nosniff`.

### 7.5 Uniform error

The uniform error is status 404, body "This request is not available.", with the §7.4 headers. It is
identical for every cause: unknown, foreign, expired or decided id (for a non-approver); wrong subject;
failed check; bad token; bad provenance; digest mismatch.

### 7.6 Passkeys (future)

When passkeys land, the approve form carries a WebAuthn assertion with user verification and
`challenge = digest`. The authority verifies it against the approver's registered credential before
step 4 of §4.2. A compromised gateway can then no longer approve on a user's behalf.

## 8. Test plan

Every case needs an automated test, reported as PASS, FAIL or NOT TESTED.

| # | Case | Expected | Maps to |
|---|---|---|---|
| T01 | Approve by a logged-in non-approver (same and other tenant) | uniform error; stays `PENDING` | PC-01, SI-20 |
| T02 | `enrolled` workload names another approver | `invalid_argument` | PC-01 |
| T03 | `named`: the approver does not own the order | uniform error at render and approval | PC-01, PC-03, SI-10 |
| T04 | App-origin `fetch` POST with credentials (`same-site`) | uniform error | PC-02, SI-21 |
| T05 | App-origin form POST | uniform error | PC-02, SI-21 |
| T06 | No Fetch Metadata and no `Origin`; `Origin: null`; `Origin` = app origin | uniform error | PC-02 |
| T07 | Token missing, reused, from another session or pid, or expired | uniform error; never succeeds twice | PC-02, PC-04 |
| T08 | Submitted digest ≠ stored digest | no grant | PC-04, SI-20 |
| T09 | Re-propose; DB role update of an immutable column | new pid; the trigger rejects the update | PC-04 |
| T10 | Render of a nonexistent, foreign or expired pid | byte-identical responses | PC-03, PC-10 |
| T11 | `effect.status` from another `wid`; unknown or non-canonical pid | `not_found`, identical | PC-10 |
| T12 | Propose for an existing vs a nonexistent order | identical success | PC-10 |
| T13 | Page framed by, or opened from, the app origin | blocked; no opener access | PC-05 |
| T14 | Query or path suffix on the confirm URL | uniform error | PC-11 |
| T15 | `knd = 1` grant on socket W | `grant_channel_invalid` | PC-13 |
| T16 | Grant on socket G; wrong-uid peer on A | rejected; connection closed | PC-13 |
| T17 | `approve` for a `DENIED`, `EXPIRED` or `APPROVED` record | no new grant | SI-20, SI-09 |
| T18 | Delivered grant whose params differ from the record (test key) | `rejected` + alarm | SI-06 |
| T19 | 64 concurrent approves; approve racing deny | one decision; at most one effect | SI-09 |
| T20 | Refund exceeds `remaining_refundable` at execution | `FAILED/denied`; no upstream call | SI-11 |
| T21 | Refund while another effect on the order is `UNKNOWN` | `FAILED/denied` | AR-10, SI-15 |
| T22 | Refund currency ≠ order currency | uniform error | SI-10 |
| T23 | Limits exceeded; another `wid` unaffected | `limit_exceeded`; the other `wid` proceeds | PC-09 |
| T24 | Approve after `expires_at` | no grant | SI-20 |
| T25 | Duplicates: `recent_identical` and pending count shown | shown | PC-08 |
| T26 | Read grant for a foreign resource; read grant used for propose or a write | `grant_denied` | SI-06 |
| T27 | v1 message on a v2 socket and vice versa | `unsupported_version` | §2.1 |
| T28 | Digest vectors DG-01..10 in broker, gateway and authority code | identical bytes / rejections | EP-04 |
| T29 | Authority killed between `approve` and delivery; restarted | re-delivers stored bytes before `exp`; otherwise the record expires; no effect after expiry | EP-06 |
| T30 | Crash at each boundary (`APPROVED` before commit, `RESERVED`, `DISPATCHED`) | never a duplicate effect; research 06 states | SI-09, SI-15 |
| T31 | `named` workload proposes within another user's active mandate | confirmation still required | EP-03, PC-06 |
| T32 | v1 socket outside the `demo1` profile; v1 and v2 on one broker or DB | refuses to start | EP-10 |
| T33 | Forced failure in the execution transaction (W10 insert, savepoint record, commit) | record stays `APPROVED`; the recovery loop completes it or expires it; never stuck in `EXECUTING` | EP-01, SI-09 |
| T34 | Delivery after `expires_at`; execution after `grant.exp + skew` | `expired`; `APPROVED → EXPIRED`; nothing consumed | EP-06 |
| T35 | Broker row forced to `APPROVED` with no gateway approval; `approve` whose digest or subject ≠ record | no grant (the authority's checks and the broker's `PENDING` precondition) | EP-02, SI-20 |
| T36 | Write grant from a gateway-held or foreign key delivered on A | `rejected` (unknown kid / signature) | EP-05, SI-05 |
| T37 | Digest edge cases: alias pid, numeric-looking text, escaped JSON, uppercase hex, type mismatch | as DG vectors; uppercase hex rejected | EP-04 |
| T38 | Approve, deny and expiry racing at `expires_at ± 1 s` | exactly one transition | §3.3 |
| T39 | Revocation or key revocation between approval and execution | `FAILED/denied` (W13) or `rejected`; no effect | SI-08 |
| T40 | Ownership or order status changes between approval and execution (including an unknown status) | `FAILED/denied` | SI-10, SI-11, EP-07 |
| T41 | Two pending full-amount refunds on one order, both approved | first succeeds, second `FAILED/denied`; second page shows the first in `other_open_on_resource` | EP-07 |
| T42 | Start-up refusals of §1.2 (shared uid, uid collision, shared directory, manifest absent without the flag) | refuses | EP-09 |
| T43 | Wrong-uid peer on I; workload probing each control path | rejected / path absent | §1.2 |
| T44 | Crafted login return target; `same-origin` with `Sec-Fetch-Mode: cors` | uniform error; returns only to the canonical confirm path | EP-13, SI-21 |
| T45 | `effect.status` field set for `DENIED`, `EXPIRED`, `UNKNOWN`; `receipt_id` rules | as §2.3 | PC-10 |
| T46 | Authority retry after a lost `accepted`; authority restarted mid-issuance | the same bytes, `accepted` (idempotent); never a second signature for one `jti` | §4.2, SI-09 |

## 9. Changes from Draft 1

| Change | Reason |
|---|---|
| Approval goes gateway → authority (`approve` on socket I). The authority fetches the record read-only, checks the digest and subject, keeps a durable issuance store, signs, and delivers. The broker stores the grant at `PENDING → APPROVED`. New trust table (§1.1). | EP-02 |
| Execution in one transaction from `APPROVED` (consumption, effect or `RESERVED`, state). Recovery loop. `unavailable` deliver result. Idempotent re-delivery replaces `already_delivered`. | EP-01, EP-11 |
| Mandates only for `enrolled` workloads. `named` workloads cannot use mandates or destination operations. | EP-03, EP-08 |
| Digest fully normative (types from the declaration, canonical `pending_id`, text and hex rules, all parameters, display key 11, type key 10). Vectors in `tests/vectors/effect-v2/`. | EP-04 |
| Read grants signed only by the authority (`read_grant`). The gateway holds no key. | EP-05 |
| Delivery requires `PENDING` and `now < expires_at`. Execution expires at `grant.exp + skew`. Lazy expiry in all states. | EP-06 |
| Refund status allow-list; `other_open_on_resource`; reconciler-only release; staleness residual. | EP-07 |
| Banner next to the buttons. | EP-08 |
| Per-socket directories and modes; the manifest is required unless an explicit flag is set; uid namespace rule. | EP-09 |
| Start-up refusals for v1 outside `demo1`. | EP-10 |
| Opaque random `receipt_id`; execution-oracle residual. | EP-12 |
| Server-side login return; PostgreSQL locking; token consumed on failure; domain-tag note; quota note. | EP-13 |
| Tests T31–T46; T28–T30 extended. | review |
