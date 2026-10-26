# Nodkey effect protocol v2 — propose → confirm → execute

- **Status:** **Draft 3.1** (2026-10-25): Draft 3 plus one amendment for `payments.refund` (`charge_id` is a
  broker-resolved, signed parameter; §2.3, §5, §11), required by
  [payments-adapter-v1](payments-adapter-v1.md) Draft 2. Draft 3 (2026-10-25). Not yet re-reviewed. Supersedes Draft 2 (changes in §10; Draft
  1 → 2 in §9). Draft 3 makes no design change: it records what the reviewed implementation does
  (`broker/` v2, `crates/nodkey-authority`, `crates/nodkey-gateway`, `examples/confirmed-transfer`)
  and settles the gaps those implementers listed (AU-1..AU-7, GW-1..GW-7, BR-04, BR-05, BR-09).
- **Implements:**
  - [ADR-0011](../decisions/0011-propose-confirm-execute.md), incl. Revision 1 and Amendment 1 (approval
    channel);
  - [ADR-0003](../decisions/0003-trusted-user-context-and-grant-issuance.md) Phase 3 profile items 2, 3, 5, 6
    and 8, plus the page hardening of item 4;
  - SECURITY_INVARIANTS v0.4 SI-05, SI-06, SI-09, SI-10, SI-15, SI-20 and SI-21.
- **Uses:** [grant-v1](grant-v1.md) Draft 3: format, verification, deterministic CBOR (§4) and
  declarations (§6).
- **Reviews:**
  - [`2026-10-25-adr-0011-review.md`](../reviews/2026-10-25-adr-0011-review.md) (PC-xx);
  - [`2026-10-25-effect-protocol-v2-review.md`](../reviews/2026-10-25-effect-protocol-v2-review.md) (EP-xx);
  - implementation reviews: [authority](../reviews/2026-10-25-authority-review.md) (AU-R-xx),
    [gateway](../reviews/2026-10-25-gateway-review.md) (GW-R-xx),
    [broker v2](../reviews/2026-10-25-broker-v2-review.md) (BR-xx).
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

**Socket model (BR-05, AU-4; as deployed in `examples/confirmed-transfer/compose.yaml`).**
- Every socket lives in its **own** directory. The directory is owned by the **listener**, its group is
  the **one permitted client's** group, it is **setgid**, and it has no "other" bits (mode `2750`). In the
  example each directory is a separate tmpfs volume (`noexec,nosuid,nodev`).
- The listener creates the socket with mode **`0660`**. Because the directory is setgid, the socket
  inherits the client's group, so exactly the listener and the permitted client can connect.
- **`SO_PEERCRED` is the primary control** (`getpeereid` on macOS). File modes are defence in depth. On
  every accepted connection the listener compares the peer uid with the channel's expected uid. A
  mismatch closes the connection without a response and raises an alarm.
- The clients check the listener too: the gateway checks `expected_broker_uid` and
  `expected_authority_uid`; the authority checks `broker_uid`.
- Nothing in any control directory is mounted into a workload.

**Broker start-up checks of socket directories.**
- Each directory must be a real directory (not a symlink), with no "other" bits, owned by the broker or
  by that channel's peer.
- No socket directory may contain another one (nesting is refused).
- A stale *socket* at a socket path is removed. Anything else at a socket path is an error:
  - for the G and A channels the broker refuses to start;
  - for a workload channel the broker raises an alarm and serves every other workload but not that one,
    so a workload cannot stop the broker by planting a file in its own directory.

| # | Socket | Listener ← client | Mounted into | Client authentication |
|---|---|---|---|---|
| W | `/run/nodkey/wl/<name>/broker.sock` (one per workload) | broker ← workload | that workload | the path identifies `wid`; `SO_PEERCRED` uid = that workload's uid |
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

**Deployment manifest (AU-3, AU-R-05).**
- Format: `{"format":"nodkey.deployment-manifest.v1","workload_mounts":[{"wid","host_paths":[absolute path…]}]}`,
  strict JSON.
- Every registered `wid` MUST appear in it.
- The "control set" consists of:
  - the directories of sockets G, A and I;
  - for the authority, the directories of its key, its issuance store, its config, its operations and
    workloads files, and the manifest itself.
- A start-up refusal applies when any workload host path lexically contains, or is contained in, a path
  of the control set (comparison both ways).
- The Phase 3 broker has no manifest reader. It therefore always requires `--mounts-verified-externally`,
  and logs it at every start. The authority reads the manifest.

uids are compared as seen in the listener's user namespace. Deployments MUST map each role to a distinct
uid in that namespace. Every connection whose `SO_PEERCRED` uid differs from the expected one is closed.

**Framing** (all channels): the v1 broker framing (`broker/src/protocol.rs`):
- one strict JSON object per line;
- duplicate, unknown and wrongly typed members are rejected;
- lines are ≤ 8 KiB;
- the v1 timeouts apply. The broker closes a connection after 10 s idle.

### 1.3 Control-channel messages (normative; AU-1, AU-2, GW-1)

Every channel uses the §2.2 envelope:
- requests are `{"v":2,"id","op","args"}`;
- responses are `{"v":2,"id","correlation_id","ok","result"|"error":{"code","message"}}`;
- the response `id` MUST equal the request id;
- a response whose `id` is `null`, or not the request id, is treated by the client as a failure (fail
  closed).

| Socket | `op` | `args` (exact members) | `result` on success | error codes |
|---|---|---|---|---|
| G | `pending.render` | `{pending_id, subject:{ten,sub}}` | `{record, digest, state, facts, context}` (below) | `not_available` |
| G | `pending.deny` | `{pending_id, digest, subject:{ten,sub}}` | `{}` | `not_available` |
| I | `approve` | `{pending_id, digest_shown, subject:{ten,sub}}` | `{}` | `not_available` |
| I | `read_grant` | `{subject:{ten,sub}, wid, rop:[op…]}` | `{grant}` (grant-v1 §2 transport text) | `not_available` |
| A | `config.digest` | `{}` | `{digest}` (64 lowercase hex) | `unavailable` |
| A | `pending.get` | `{pending_id}` | the 12 §3.2 record fields plus `state` and `digest` | `not_found`, `unavailable` |
| A | `grant.deliver` | `{pending_id, grant}` | `{status}` with `status ∈ {accepted, rejected, expired}` | `unavailable` |

Further rules:
- `rejected` and `expired` are **results**; only `unavailable` is an error of `grant.deliver`.
- Envelope errors on every channel: `malformed_request`, `unsupported_version`, `request_too_large`,
  `unknown_operation`.
- An `op` sent on the wrong channel is `unknown_operation`.

**`pending.render` result (GW-1).**
- `record`: the 12 fields of §3.2, exactly as in `tests/vectors/effect-v2` records.
- `digest`: hex.
- `state`: a §3.3 state.
- `facts`: a list of `{"label": text, "value": text}`.
- `context`:
  - `pending_from_workload_for_subject`: uint;
  - `recent_identical`: list of `R`;
  - `other_open_on_resource`: list of `R`;
  - `workload_display_name`: text;
  - `approver_source`: `"named"` or `"enrolled"`.
- `R = {"pending_id", "state", "created_at", "amount_minor"?}`.
- All display text is printable ASCII with bounded length. The gateway escapes it and uses it for
  display only.

**Connections.**
- The gateway opens one connection per request on G and I.
- The authority keeps one connection on A. If a **reused** A connection proves stale (the write fails,
  or the broker closes it before any response byte), the authority reconnects, re-checks the broker
  uid and `config.digest`, and resends that request **once** (DEMO2-F02). This is safe because
  `config.digest` and `pending.get` are read-only, and `grant.deliver` resends identical durable bytes
  that the broker accepts idempotently.
- A failure on a fresh connection is not retried.

**`config.digest` (AU-2).**

```
SHA-256("nodkey.authority-config-digest.v1" || 0x00 ||
        u64be(len(O)) || O || u64be(len(W)) || W)
```

- `O` is the exact bytes of the operations file (grant-v1 §6.1) and `W` the exact bytes of the
  workloads file.
- The broker's and the authority's copies MUST be byte-identical.
- The authority checks this at start-up (retrying for 30 s, then refusing to start) and on every
  reconnect.

**Workloads file** `{"format":"nodkey.workloads.v1","workloads":[{wid, tenants, approver_source:
"named" | {"enrolled":{ten,sub}}, write_ops, read_ops}]}`. Loading it refuses:
- a `named` workload with a destination operation (§2.4);
- a confirmed write operation with a `bounded` parameter, because every confirmed value is exact
  (§4.2 step 5).

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
- **Broker-resolved parameters (Draft 3.1).** A parameter marked `resolved_by_broker` in §5 MUST be
  absent from `params` (present → `invalid_argument`). The broker sets it at creation, before the digest
  is computed, from its trusted tables, looking up by `(ten, <resource parameter>)` only (no ownership
  check, so the response stays identical, PC-10/T12). If no row exists the broker sets the reserved
  value `unresolved`, which matches no trusted row; render and execution then fail as for a foreign
  resource. The value is part of key 7 like any parameter, so the digest, the confirmation page and the
  signed grant cover it. The authority MUST refuse (`not_available`) to approve a `payments.refund` record whose
  `charge_id` does not match `^ch_[A-Za-z0-9]{8,64}$`, so the reserved value `unresolved` is never signed
  (grant crate issue RX-6).
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
- Otherwise it returns the result shape of §1.3. `recent_identical` lists records with the same `wid`,
  approver, `op` and params from the last 30 min.
- The gateway parses the result strictly, recomputes the digest from `record`, and requires the digest,
  `pending_id` and `(ten, approver_sub)` = session subject to match. On any mismatch it renders the
  uniform error.

**`pending.deny{pending_id, digest, subject}`** runs the §3.3 transition. It returns `{}` or
`not_available`.

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
   Their equality is checked with `config.digest` (§1.3). In addition:
   - the record must parse under every §3.2 rule;
   - `broker_id` must match;
   - `0 < expires_at − created_at ≤ 900` and `created_at ≤ now + skew` (AU-R-11);
   - the operation must be a confirmed write whose `opv` and `param_types` equal the declaration;
   - the workload must be registered for `ten` and the operation;
   - **display key 11 must equal the authority's own derivation** (AU-R-01).

   **Display derivation.** The authority does not take key 11 on the broker's word, because the gateway
   formats amounts only with it:
   - an operation with exactly one `currency`-typed parameter: `{amount_exponent: ISO 4217 exponent of
     that value, currency: that value}`;
   - an operation with an `amount_minor` parameter and no currency parameter: the same, using the
     authority's configured **`ledger_currency`**;
   - otherwise `{}`.

   The ISO 4217 table is the authority's own copy (the same values as the broker's) and is not part of
   `config.digest`. A mismatch fails that approval closed, with the alarm `broker_display_mismatch`.

   Any failure → `not_available`.
4. **Exactly-once at the authority (AU-5).** Under the store lock:
   - a row with the same digest and subject: re-use its stored `grant` bytes (step 6). If its status is
     already `rejected` or `expired`, return `not_available` instead; issuance for that `jti` is final;
   - a row with a different digest or subject: `not_available` and an alarm;
   - no row: sign (step 5), then append **one** durable row that already contains the grant bytes, and
     fsync it **before** any delivery:

     `issuance(jti = pending_id, digest, ten, sub, wid, op, signed_at = iat, grant, status = signed)`

   There is no "inserted but unsigned" state:
   - a crash before the fsync means the grant never left the process; a later approval signs again, and
     that grant is the first one observable;
   - a crash after the fsync means recovery re-delivers the identical bytes.

   The reference store is an append-only, checksummed, fsync'd log with an exclusive lock
   (`crates/nodkey-authority`). Any equivalent durable "insert if absent" store is acceptable.
5. Signs a grant-v1 write grant from the fetched record only:

   | Field | Value |
   |---|---|
   | `iss` | its issuer |
   | `aud` | `broker_id` |
   | `jti` | `pending_id` |
   | `iat` | its own clock |
   | `nbf` | `iat` |
   | `exp` | `iat + grant_ttl_secs` (configuration, 1–30) |
   | `wid`, `ten` | from the record |
   | `sub` | `approver_sub` |
   | `op`, `opv` | from the record |
   | `res` / `con` | from params per the declaration (all exact; `free` parameters omitted) |
   | `use` | 1 |
   | `knd` | 1 |
   | `cfm` | 1 |

   **Clock rules (AU-7 as corrected by AU-R-04).** The authority MUST refuse to sign:
   - while its clock reads below 2024-01-01 (a clock error);
   - while `now + skew` is below its high-water mark, which is the latest write-grant `iat` in the store
     plus any `iat` used since start.

   A clock rollback is fail-safe for revocation: an earlier `iat` is revoked by more `revoked_before`
   rows, and write grants simply expire. The unsafe direction is a **forward** jump: grants then carry a
   future `iat` that escapes a later `revoked_before` (grant-v1 REV-09). Detecting that needs the
   broker's time on socket A, which is **not specified in v2**; it is a published residual (§6).
6. Sends `grant.deliver{pending_id, grant}` on socket A (§4.3), in its own task, with at most one
   delivery loop per `jti`. It records the result as `status ∈ {accepted, rejected, expired}`:
   - `unavailable` or a lost response: retry with the **same bytes** while `now < exp`;
   - `rejected`: final for that `jti`, with an alarm. The bytes are never re-delivered and never
     re-signed;
   - no `accepted` by `exp + skew`, including after a restart: mark `expired`. The broker can no longer
     execute that grant (§3.3).
7. Answers the gateway `{}` if the broker answered `accepted` within `approve_reply_timeout_ms` (≤ 30 s),
   and `not_available` otherwise (AU-6). Delivery continues in the background either way. The gateway
   waits up to its own `approve_timeout_ms` (default 31 s), then shows a neutral "submitted" page plus
   the record state from a fresh render.

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
- requires 1–16 `rop` entries with no duplicates;
- for an `enrolled` workload, requires `subject` to equal the enrolment (AU-R-03);
- signs `knd = 2` with `sub`/`ten` from `subject`, `iat` from its clock, `exp = iat + grant_ttl_secs`,
  and `jti` from its CSPRNG;
- returns it to the gateway (§1.3).

The gateway attaches it to the forwarded app request as the header `Nodkey-Grant` (GW-2). It asks
only for configured read routes, only with a live app session, and only when `Sec-Fetch-Site:
same-origin` or (`Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`). Without Fetch Metadata no
read grant is requested (GW-3, fail closed). An inbound `Nodkey-*` header is never forwarded.

The gateway holds no key.

### 4.3 Authority → broker (socket A): `pending.get`, `grant.deliver`

**`grant.deliver{pending_id, grant}`.** In one transaction, the broker:
1. locks the record;
2. if the stored `grant` equals the delivered bytes, returns `accepted`. This is idempotent in **every**
   state, so an authority retrying after a lost `accepted` gets `accepted` again (T46). It changes no
   state and never causes a second execution. A *different* grant for a record that already holds one
   raises the alarm `second_grant_for_jti`;
3. if `state ≠ PENDING`, returns `expired`. If `now ≥ expires_at`, sets `PENDING → EXPIRED`, commits and
   returns `expired`;
4. requires all of these, else returns `rejected`:
   - the grant verifies per grant-v1 §7.2 steps 1–9, with `peer_wid` := the record's `wid`;
   - `knd = 1`, `cfm = 1` and `jti = pending_id`;
   - `wid`, `ten` and `sub = approver_sub` equal the record;
   - grant-v1 W11–W13 pass against the record's own params (`op`, `opv`, `cfm`, `res`/`con` equality,
     revocation);
   - the approval checks of §5 pass under lock;
5. sets `APPROVED` and stores `grant`;
6. commits, and returns `accepted`.

**Delivery is not a decision (BR-04).**
- `rejected` writes nothing: no `consumed_grant` row, and the record stays `PENDING`.
- The checks of step 4 are a pre-check. The grant's single decision (grant-v1 §7.3, SI-09) happens only
  in the execution transaction (§4.4), where it is consumed.
- A delivery rejection is re-evaluable within `exp`. The reference authority never re-delivers after
  `rejected` (§4.2 step 6), so in practice a rejected grant is never used.
- Even a re-delivery of the same bytes after the cause disappeared (for example, an operator removed a
  `revoked_before` row) could at most be accepted and then decided once at execution, under every
  execution-time check. It can never cause a second effect.

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
3. Verify the stored grant (grant-v1 §7.2 steps 1–9, `peer_wid` := the record's `wid`). If verification
   fails, roll back with nothing consumed. The record stays `APPROVED`, is retried by the recovery loop,
   and ends `EXPIRED` at step 2 (BR-09). This happens if the key was revoked after approval, the
   workload was unregistered, or the operation has no executor.
4. Run grant-v1 §7.3:
   - W10 consumption, with `request_hash` over the record's params;
   - savepoint;
   - W11–W13;
   - W14, including the §5 execution checks under lock.
5. For **internal effects** (ledger): perform the effect and set `SUCCEEDED`, or on denial roll back to
   the savepoint and set `FAILED/denied` with `consumed_grant.outcome = DENIED`. **Deadline at commit
   (grant-v1 D2-4):** immediately before committing a `SUCCEEDED` effect, the broker re-reads its clock.
   If `now ≥ grant.exp + skew`, it aborts the whole transaction (rollback; nothing consumed), and the
   record then expires at step 2. A denial may commit late. Then commit.
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
| `payments.refund` (write) | `order_id` res0 exact `uint`; `amount_minor` con0 exact `uint` ≥ 1; `currency` con1 exact `currency`; **`charge_id` con2 exact `text64`, `resolved_by_broker` from `orders.charge_id` (Draft 3.1)** | order exists in `ten`; `owner = approver`; `currency = order.currency`; **`order.status ∈ {captured, partially_refunded}`** (allow-list; any other or unknown status fails) | order id; captured amount; refunded and encumbered amounts (`RESERVED`, `DISPATCHED`, `UNKNOWN`, `SUCCEEDED`); `remaining_refundable`; `other_open_on_resource` = count and amounts of other `PENDING`/`APPROVED`/`EXECUTING` records on the order; warning on any `DISPATCHED`/`UNKNOWN`; amount with the broker's ISO 4217 exponent (key 11); "refunded to the original payment method" |
| `ledger.get_balance` (read) | `account` `owner_scoped` `account_id` | owner = grant `sub` (in query) | — |
| `payments.get_order` (read) | `order_id` `owner_scoped` `uint` | owner = grant `sub` (in query) | — |

**Refund execution** re-checks under the order lock:
- `1 ≤ amount_minor ≤ remaining_refundable`;
- no `DISPATCHED`/`UNKNOWN` effect on the order (AR-10);
- every approval check.

`charge_id` comes only from the broker's `orders` row: resolved at propose into the immutable record, signed in the grant (con2), shown on the page as "Charge being refunded", and re-checked at execution and by the payments adapter (payments-adapter-v1 Draft 2 §3.2, §7.2). Execution-time refund rules (in-flight set, per-charge remaining, budget, reasons) are those of payments-adapter-v1 §7–§8.

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
- **UI redress.** The inert period and typed amounts (§7.3) are mitigations, not a proof. There is no
  browser test of popup or timed-click attacks (T13 browser part NOT TESTED). The full fix is §7.6.
- **Authority clock jumping forward** (AU-R-04). It is not detected (§4.2 step 5).
- **App identity of the user** (GW-6). No header tells the app who the user is; the app can read `sub`
  and `ten` only from a read grant it receives. This is open for a later draft.
- **Logout does not revoke broker-side** (GW-7). Logout revokes gateway sessions only. Writing
  `revoked_before` on logout needs a gateway → broker revoke operation, which v2 does not define.

## 7. Confirmation page contract (auth origin)

### 7.1 GET `/confirm/<pending_id>`

1. The path must be exactly `/confirm/` followed by a canonical 22-char id, with no query (not even a bare
   `?`). `Sec-Fetch-Mode`, if present, must be `navigate` (GW-R-05). Anything else gets the uniform error.
2. Without a session, the gateway creates **no server-side state** (GW-R-02). It puts the canonical
   return target into the cookie `__Host-nodkey_return`, which only the auth origin sets, and redirects
   to login. The cookie is re-validated when the login form is rendered, so only
   `/confirm/<canonical id>` is ever followed (EP-13).
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
- a form with `token` and `digest` (lowercase hex);
- for a write approval, one text input `confirm_<param>` per **amount parameter** (§7.3);
- two submit buttons, **Deny first**, then Approve (`decision=deny`, `decision=approve`). The buttons are
  inert (hidden, no pointer events) for **1.5 s** after the page renders, using CSS only (the page has no
  scripts).

### 7.2 Approval token

| Property | Rule |
|---|---|
| Value | 32 bytes from the gateway CSPRNG, base64url (43 chars) |
| Storage | `token → {session_id, pending_id (bytes), digest (bytes), issued_at, amount fields [(name, expected text)], expires_at = min(render + 300 s, record.expires_at)}` |
| Re-render | invalidates the previous token for that `(session, pending_id)` |
| Use | single use, deleted atomically at its first presentation **even if a later step fails**, so a stale render cannot be retried. The **one** exception is a typed-amount mismatch (§7.3 step 5), which keeps the token. Exactly one concurrent presentation can consume it |

### 7.3 POST `/confirm/<pending_id>/decision`

All checks run in order. Any failure gives the uniform error and causes no state change.

1. Path rules as in §7.1. Method POST, `Content-Type: application/x-www-form-urlencoded` exactly. The
   fields are exactly:
   - `token`;
   - `digest` (64 lowercase hex);
   - `decision` ∈ {`approve`, `deny`};
   - one `confirm_<param>` for each **amount parameter** of the record, and no other field.

   An amount parameter is a parameter declared `uint` whose name ends in `_minor`. Operations without
   one have no typed field. The `confirm_*` fields replace Draft 2's "exactly `token`, `digest`,
   `decision`" rule (GW-R-01).
2. Provenance (SI-21):
   - if `Sec-Fetch-Site` is present, it MUST be `same-origin` and `Sec-Fetch-Mode` MUST be `navigate`;
   - otherwise `Origin` MUST exactly equal the auth origin;
   - `Origin: null` is rejected.
3. A valid auth-origin session (`__Host-` cookie, ADR-0003 Profile 2–3).
4. The token must be valid, unexpired, and bound to this session, this `pending_id`, this digest, and
   exactly the set of `confirm_*` field names it was issued with.
   - For `approve`, at least **1.5 s** must have passed since the token was issued. The server enforces
     this independently of the CSS delay (GW-R-01).
   - Any failure in this step consumes the token and gives the uniform error.
5. **Typed amounts (approve only).** Each `confirm_<param>` must equal the displayed amount, compared
   after trimming surrounding whitespace only:
   - with display key 11, the major-unit text formatted with `amount_exponent` (for example `12.50` for
     1250 with exponent 2);
   - without display data, the raw integer.

   On a mismatch, the gateway re-renders the page with a message and **keeps** the token, but only if
   a fresh render still has `state = PENDING` and the same digest; otherwise it gives the uniform error.
6. The gateway consumes the token. On `approve`, it sends `approve{pending_id, digest_shown, subject}` on
   socket I. On `deny` (no delay and no typed field required), it sends `pending.deny` on socket G.
   Either way, it shows a neutral "submitted" page plus the state from a fresh render.

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

The uniform error is status 404, `Content-Type: text/plain`, with exactly the body `This request is not
available.`, no banner, and the §7.4 headers (GW-4). It is byte-identical for every cause:
- unknown, foreign, expired or decided id (for a non-approver);
- wrong subject; failed check;
- bad token; bad provenance;
- digest mismatch.

Its **timing** is not equalized (a published residual).

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
| T13 | Page framed by, or opened from, the app origin; popup or timed click within 1.5 s of render | blocked; no opener access; early approve rejected by the server (browser part NOT TESTED) | PC-05, GW-R-01 |
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
| T39 | `revoked_before` set between approval and execution; signing key revoked after approval | `revoked_before`: `FAILED/denied` (W13, consumed as `DENIED`). Key revoked: verification fails, nothing is consumed, the record **stays `APPROVED` with no effect** and becomes `EXPIRED` at `grant.exp + skew` (BR-09) | SI-08, SI-09 |
| T40 | Ownership or order status changes between approval and execution (including an unknown status) | `FAILED/denied` | SI-10, SI-11, EP-07 |
| T41 | Two pending full-amount refunds on one order, both approved | first succeeds, second `FAILED/denied`; second page shows the first in `other_open_on_resource` | EP-07 |
| T42 | Start-up refusals of §1.2 (shared uid, uid collision, shared directory, manifest absent without the flag) | refuses | EP-09 |
| T43 | Wrong-uid peer on I; workload probing each control path | rejected / path absent | §1.2 |
| T44 | Crafted login return target; `same-origin` with `Sec-Fetch-Mode: cors` | uniform error; returns only to the canonical confirm path | EP-13, SI-21 |
| T45 | `effect.status` field set for `DENIED`, `EXPIRED`, `UNKNOWN`; `receipt_id` rules | as §2.3 | PC-10 |
| T46 | Authority retry after a lost `accepted`; authority restarted mid-issuance | the same bytes, `accepted` (idempotent); never a second signature for one `jti` | §4.2, SI-09 |
| T47 | Approve fewer than 1.5 s after the token was issued; deny within 1.5 s | approve: uniform error, token consumed; deny: allowed | GW-R-01 |
| T48 | Wrong or missing `confirm_<param>`; an extra unknown field | wrong value: re-render, token kept; missing or extra field: uniform error, token consumed | GW-R-01, §7.3 |
| T49 | `grant.deliver` of identical bytes after `SUCCEEDED`/`EXPIRED`; a different grant for a record holding one | `accepted`, no state change; `second_grant_for_jti` alarm | §4.3, T46 |
| T50 | Delivery `rejected` (for example W13), cause removed, same bytes delivered again before `exp` | nothing recorded at the first delivery; the reference authority does not re-deliver (status `rejected` final); if it were re-delivered and accepted, exactly one decision at execution | BR-04, SI-09 |
| T51 | Workload replaces its socket with a regular file; nested socket directories; a directory with "other" bits or a foreign owner | that workload is unserved (alarm), others are served; nesting and bad mode/owner refused at start | BR-05 |
| T52 | Execution transaction delayed past `grant.exp + skew` before commit | effect rolled back, nothing consumed, record `EXPIRED` | grant-v1 D2-4 |
| T53 | Broker `display` differs from the authority's derivation (for example a wrong exponent) | `not_available`, `broker_display_mismatch` alarm, no grant | AU-R-01 |
| T54 | Authority clock below 2024-01-01, or behind its high-water mark by more than `skew` | refuses to sign | AU-R-04 |

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

## 10. Changes from Draft 2

Draft 3 records the verified implementation; none of the security properties change.

| Change | Source |
|---|---|
| Socket model: the listener owns a setgid directory (mode 2750, group = the one client); sockets 0660; `SO_PEERCRED` primary; directory owner, mode, symlink and nesting checks; a bad workload socket path disables only that workload | BR-05, AU-4, `examples/confirmed-transfer/compose.yaml` |
| New §1.3: normative message table for sockets G, I and A; `pending.render` result shape; connection and reconnect-once rules; `config.digest` definition; workloads-file format | AU-1, AU-2, GW-1, DEMO2-F02 |
| Deployment-manifest format and control set; the broker has no manifest reader and always needs the operator flag | AU-3, AU-R-05 |
| §4.2: the authority derives display key 11 itself (`ledger_currency`); record lifetime and declaration checks | AU-R-01, AU-R-11 |
| §4.2: one durable issuance row containing the grant bytes, fsync'd before delivery; `rejected` and `expired` are final at the authority; `exp = iat + grant_ttl_secs` | AU-5 |
| §4.2: authority clock rules (minimum time, high-water mark); forward-jump residual | AU-7, AU-R-04 |
| §4.2: bounded wait for `accepted` (`approve_reply_timeout_ms`), with background delivery; gateway `approve_timeout_ms` | AU-6 |
| §4.2: read grants for `enrolled` workloads only for the enrolled principal; 1–16 unique `rop`; `Nodkey-Grant` header; no grant without Fetch Metadata | AU-R-03, GW-2, GW-3 |
| §4.3: idempotent `accepted` in every state; `second_grant_for_jti` alarm; delivery runs W11–W13 as a pre-check; **delivery is not a decision** | BR-04, BR-07 |
| §4.4: stored grant failing verification stays `APPROVED`, then `EXPIRED` (T39 updated); deadline re-checked before committing an effect | BR-09, grant-v1 D2-4 |
| §7: `Sec-Fetch-Mode` rule on GET; return target in `__Host-nodkey_return` instead of server-side state; Deny first; 1.5 s inert buttons plus a server check; typed `confirm_<param>` amount fields; token keeps the field names and survives only a typed-amount mismatch; `text/plain` uniform error | GW-R-01, GW-R-02, GW-R-05, GW-4 |
| §6 residuals: UI redress, authority clock jumping forward, no app identity header, logout not revoking broker-side | GW-R-01, AU-R-04, GW-6, GW-7 |
| Tests T13 and T39 revised; T47–T54 added | above |

## 11. Draft 3.1 amendment

| Change | Source |
|---|---|
| `payments.refund` gains `charge_id` (con2, exact, `text64`, broker-resolved from `orders` at propose; reserved value `unresolved`). It is absent from the workload's `params`, covered by the digest (key 7), displayed, and signed. Operation files (grant-v1 §6.1) and authority copies MUST add the parameter; `config.digest` changes accordingly. No other operation changes | payments-adapter review PA-01, orchestrator ruling |
| Digest vectors DG-11 (`payments.refund` with `charge_id`) and DG-12 (`unresolved`) in `tests/vectors/effect-v2/` (generated; Python cross-check agrees; the broker and authority vector tests still assert a count of 10) | PA-01 |
| Authority refuses to approve a `payments.refund` record whose `charge_id` is not a charge id (`unresolved` is never signed) | grant crate RX-6 |
| §5 refund execution rules are now specified in payments-adapter-v1 Draft 2 (per-charge accounting, `RESERVED` also blocks, budget, workload-facing reasons) | payments-adapter-v1 §7–§8 |
