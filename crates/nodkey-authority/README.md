# nodkey-authority

> **PROTOTYPE.** Not suitable for production use.

The authority process of [effect-protocol-v2](../../docs/specs/effect-protocol-v2.md) **Draft 2**
(ADR-0011 Amendment 1). It is the only grant signer. It has no network: one listening Unix socket for
the gateway (socket I) and one client connection to the broker (socket A).

A write grant needs two independent inputs: a gateway `approve` and a broker record that agree on
digest and intended approver (§1.1). Signing uses the `nodkey-grant` issuer (`GrantBuilder`); this
crate implements no cryptography.

## Commands

```sh
nodkey-authority keygen --out <path> --iss <issuer> [--not-before <unix>] [--not-after <unix>]
nodkey-authority run --config <path> [--mounts-verified-externally]
```

- `keygen` creates the key file exclusively (mode 0600, fsync'd). It refuses to overwrite. It prints
  a grant-v1 §8.2 registry document for the broker on stdout; the document is checked with
  `Registry::load`. Key file format: 64 lowercase hex characters (the Ed25519 seed) and an optional `\n`.
- `run` start-up order:
  1. Load the strict config, operations and workloads.
  2. Run the §1.2 refusals (`config::startup_checks`):
     - the process uid must equal `authority_uid`;
     - authority, gateway and broker uids must be distinct and differ from every workload uid;
     - the I and A socket directories must be neither shared nor nested;
     - a manifest must exist and show no control directory mounted into a workload, unless
       `--mounts-verified-externally` is passed. That flag is logged at every start.
  3. Load the key. The file must be regular (not a symlink), owned by the authority uid, with no
     group or other bits. Its derived `kid` must equal `signing_kid`.
  4. Open and lock the issuance store.
  5. Check the broker: peer uid and `config.digest`, retried for 30 s, otherwise refuse to start.
  6. Run recovery: re-deliver `signed` rows.
  7. Bind socket I (directory without "other" bits; socket mode 0660).

## Approval (`approve`, §4.2)

1. Validate the input: canonical 22-character `pending_id`, 64-character lowercase-hex
   `digest_shown`, and an ID-valid `subject`.
2. Fetch the record with `pending.get` (read-only).
3. Require all of these:
   - the record parses under every §3.2 rule;
   - `pending_id` and `broker_id` match;
   - `state = PENDING` and `now < expires_at`;
   - the authority's **own** recomputed digest equals both `digest_shown` and the broker's `digest`;
   - `subject = (ten, approver_sub)`;
   - the workload is registered for `ten` and the operation;
   - the operation is a confirmed write whose `opv` and `param_types` equal the declaration;
   - `approver_source` permits it (`enrolled` = the enrolment; `named` = no destination parameter).
4. Under the store lock:
   - a row with the same digest and subject: re-use the stored bytes;
   - a row with a different digest or subject: `not_available` plus an alarm;
   - no row: sign (`iat` from the authority's clock, `nbf = iat`, `exp = iat + grant_ttl_secs`,
     `jti = pending_id`, `cfm = 1`, every `res`/`con` value exact, `free` parameters omitted). Then
     insert the row **with the grant bytes** and fsync **before** any delivery.
5. Deliver with `grant.deliver`, retrying the same bytes while `now < exp`. A row without
   `accepted` by `exp + skew` is marked `expired`. Delivery runs in its own task. The gateway gets
   `ok` when the broker answers `accepted` within `approve_reply_timeout_ms`, and `not_available`
   otherwise. Every refusal is `not_available`, and the reason goes only to the log.

`read_grant{subject, wid, rop}` signs `knd = 2` when:
- every `rop` entry is a declared read operation in the workload's `read_ops`, with 1–16 entries and
  no duplicates;
- `subject.ten` is a tenant of `wid`.

The `jti` comes from the OS CSPRNG, and `exp = iat + grant_ttl_secs`.

## Issuance store: append-only fsync'd log

**Choice.** The store is one file of lines `<sha256-hex(json)> <json>\n`, opened `O_APPEND`, with
`sync_data` after every append. An exclusive `flock` stops a second process from opening it. At
start-up the log is replayed into a `HashMap`. SQLite (`rusqlite`) was rejected for this prototype:
- it would add a bundled C library to the TCB;
- it is not in the local crate cache;
- the store needs only "insert if absent", one status transition and a start-up scan. They fit in
  about 330 lines, documentation included (`src/store.rs`).

**Exactly-once argument.** A row is written once, already containing the signed bytes. Delivery
starts only after `insert` returned (write and fsync succeeded). So:
- a crash before the fsync: the grant never left the process, and a later approve signs again; that
  grant is the first one observable;
- a crash after the fsync: the row exists, and recovery or a retry re-delivers the identical bytes.

This deliberately merges spec steps 4 and 5 ("insert, sign, store bytes, set `signed`") into one
durable record. The result is the same guarantee, without an "inserted but unsigned" state.

**Recovery and failure handling.**
- A torn final line (no newline) is truncated, because that append never returned.
- Any complete corrupt line refuses to open: bad checksum, duplicate `jti`, status for an unknown
  `jti`, a transition out of a final status, or an empty line.
- A failed write poisons the store until restart (fail closed).

## Wire formats (this crate's reading; see "Spec gaps")

Both channels use the §1.2 framing: strict JSON, one object per line, at most 8 KiB, and the v1
timeouts. The §2.2 envelope is `{"v":2,"id","op","args"}`, answered by
`{"v":2,"id","correlation_id","ok","result"|"error":{"code","message"}}`.

| Socket | `op` | `args` | `result` |
|---|---|---|---|
| I | `approve` | `{pending_id, digest_shown, subject:{ten,sub}}` | `{}`; error `not_available` |
| I | `read_grant` | `{subject:{ten,sub}, wid, rop:[op…]}` | `{grant}` (base64url); error `not_available` |
| A | `config.digest` | `{}` | `{digest}` (hex) |
| A | `pending.get` | `{pending_id}` | the 12 §3.2 fields plus `state` and `digest`; error `not_found` |
| A | `grant.deliver` | `{pending_id, grant}` | `{status: accepted\|rejected\|expired}`; error `unavailable` |

On socket I, envelope errors are `malformed_request`, `unsupported_version`, `request_too_large` and
`unknown_operation`. A connection whose `SO_PEERCRED` uid is not `gateway_uid` is closed without a
response, and an alarm is logged. On socket A, the authority checks the broker's peer uid as well.

## Configuration files (admin-only; strict JSON)

- `nodkey.authority-config.v1`. Fields:
  - `issuer`, `broker_id`, `signing_key_path`, `signing_kid`, `store_path`;
  - `gateway_socket`, `broker_socket`;
  - `authority_uid`, `gateway_uid`, `broker_uid`, `workload_uids`;
  - `operations_path` (grant-v1 §6.1), `workloads_path`, `manifest_path` (nullable);
  - `grant_ttl_secs` (1–30), `skew_secs` (0–5), `approve_reply_timeout_ms`, `broker_call_timeout_ms`.
- `nodkey.workloads.v1`: `[{wid, tenants, approver_source: "named" | {"enrolled":{ten,sub}}, write_ops, read_ops}]`.
  Load refuses:
  - a `named` workload with a destination operation (§2.4);
  - a confirmed write with a `bounded` parameter (step 5, "all exact").
- `nodkey.deployment-manifest.v1`: `{workload_mounts:[{wid, host_paths}]}`.
- `config.digest = SHA-256("nodkey.authority-config-digest.v1" ‖ 0x00 ‖ u64be(len) ‖ operations bytes ‖ u64be(len) ‖ workloads bytes)`.
  The broker's copies must be byte-identical.

## Spec gaps found (for the spec owner)

| # | Where | Gap | Reading used |
|---|---|---|---|
| AU-1 | §4.2, §4.3 | Message envelopes and result shapes for sockets I and A are not specified. | The §2.2 envelope and the table above. |
| AU-2 | §4.2 step 3 | The canonical form of `config.digest` and the registration file format are undefined. | Digest over the exact file bytes (above). |
| AU-3 | §1.2 | The deployment-manifest format is undefined. | Minimal `host_paths` format; lexical containment both ways. |
| AU-4 | §1.2 | "Directory 0700 owned by the connecting peer" conflicts with the listener creating the socket in it. | The directory must have no "other" bits; the socket is 0660; `SO_PEERCRED` is authoritative. |
| AU-5 | §4.2 steps 4–5 | Insert-then-sign leaves an "inserted, unsigned" row whose restart behaviour is unspecified. | One durable record with the bytes (see the store section). |
| AU-6 | §4.2 step 7 | How long the gateway waits for a delivery result is unspecified (up to 30 s). | Bounded by `approve_reply_timeout_ms`; delivery continues in the background. |
| AU-7 | grant-v1 §7.6 / §9 | No clock high-water mark is required of the authority. A clock rollback could produce `iat` earlier than a `revoked_before` row. | Not implemented. |

## Limitations

- **SI-20 is PARTIALLY MET**: approval is session-based, with no WebAuthn yet (§6, §7.6).
- **Tests run as one uid.** uid-mismatch cases are tested by configuring a different expected uid.
  Distinct-uid deployment has not been tested.
- **Platform.** Tested on macOS only (`getpeereid`); Linux (`SO_PEERCRED`) has not been tested.
- **Store growth.** The store is never compacted: it is limited to 1 GiB at open and its index is
  held in memory.
- **Throughput.** There is one broker connection, and requests on it are serialized.
- **Read-grant origin.** `read_grant` trusts the gateway's same-origin/navigation check, which the
  authority cannot observe.

## Dependencies

| Crate | Why | License |
|---|---|---|
| `nodkey-grant` (path) | Issuer (`GrantBuilder`), canonical base64url, registry self-check | Apache-2.0 |
| `tokio` | Unix sockets, `peer_cred`, timers, signals (already used by the broker) | MIT |
| `serde`, `serde_json` | Strict config and wire parsing | MIT OR Apache-2.0 |
| `sha2` | Pending-effect digest, store checksums, config digest | MIT OR Apache-2.0 |
| `getrandom` | Key generation and read-grant `jti` (OS CSPRNG) | MIT OR Apache-2.0 |
| `zeroize` | Key-file buffers (`SigningKey` zeroizes itself on drop) | Apache-2.0 OR MIT |

## Tests

```sh
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

| Suite | Covers |
|---|---|
| `tests/digest_vectors.rs` | DG-01..DG-10: byte-exact CBOR and digest; 4 rejections (T28, T37) |
| `tests/approve.rs` | Happy path, with the grant verified by a fake broker using `nodkey_grant::verify` + `decide`; T01, T08, T16, T17, T19, T24, T34, T35, T37, T43, T46; enrolled and free-parameter operations; issuance conflict |
| `tests/read_grant.rs` | `knd = 2` verifies for reads and never for writes (T26); refusals |
| `tests/store.rs` | Reopen durability; one row per `jti` across restarts; torn tail; corruption refusals; `flock` |
| `tests/crash.rs` | T29/T46: **SIGKILL** of a child authority mid-delivery, restart, identical bytes re-delivered, no second signature; restart after `exp` marks the row expired; logs contain neither key nor grant |
| `tests/config.rs` | T42 start-up refusals; strict config; workload registration refusals |
| unit tests | CBOR heads and ordering, hex and pending-id rules, framing, key-file permission, owner and symlink refusals |
