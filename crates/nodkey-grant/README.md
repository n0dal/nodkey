# nodkey-grant

> **PROTOTYPE.** This crate is not suitable for production use.

This crate verifies and issues **Nodkey-Grant v1** grants. It implements **spec Draft 4**
([`docs/specs/grant-v1.md`](../../docs/specs/grant-v1.md)): restricted COSE_Sign1 with Ed25519 and a
deterministic-CBOR payload. Draft 4 adds mandate-issued write grants (`cfm = 2` with key 20 `mid`) and
the declaration member `mandate_eligible` (spec §17).

It is a second implementation, independent of the vector generator in
`tests/vectors/grant-v1/gen/`. It shares no code with the generator, and the generator was not read
while writing it up to Draft 3. The Draft 4 update was made by the author of the Draft 4 generator
changes, so it is not independent for Draft 4 (SPEC_ISSUES.md, "Independence note").

A valid grant is a necessary condition for an effect, never a sufficient one (SI-04).

## What it does

| Area | Spec | Notes |
|---|---|---|
| Strict CBOR decoder and encoder | §4 | Hand-written and bounded. Rejects non-shortest heads, indefinite lengths, major type 7, tags, invalid UTF-8, keys that are not in encoded-byte order (C8) or are duplicated, trailing bytes, and lengths beyond the input (checked before allocation). Depth limits: envelope 4, header 1, payload 3. |
| COSE_Sign1 profile | §3 | Requires the single-byte `0xd2` tag, the exact protected header, an empty unprotected map, and `verify_strict` over `Sig_structure` with `external_aad = "nodkey.grant.v1" ‖ 0x00 ‖ broker_id`. |
| Key registry | §8 | Strict JSON. Rejects unknown, missing or duplicate members, JSON string escapes, and integers that do not match `0\|[1-9][0-9]*` or exceed 2^53 − 1. Each key must have order exactly L and a derived `kid`, and duplicates are refused. |
| Operation declarations | §6 | `Operations::load` reads the reference JSON format with the same strictness, and applies the §6.3 refusals plus D2-3 (SPEC_ISSUES.md). |
| Request validation | §6.2, §7.1 | `Operations::parse_request` rejects undeclared, missing or ill-typed parameters, using the closed type grammars. It returns a `Request` that carries the normative §5.4 hash. |
| Verification | §7.2–§7.4 | `verify` runs steps 1c–9. `WriteGrant::decide` runs W11–W13. `ReadGrant::decide` runs R11 and R13. The first failing check sets the code. |
| Transport | §2 | Canonical unpadded base64url. |
| Issuer | §9 | `GrantBuilder` produces canonical grants. It checks its own payload with the verifier and refuses times outside `iat ≤ nbf ≤ iat + 5` and `nbf < exp ≤ iat + 30`. |

## API and caller obligations

```rust
let registry = Registry::load(&registry_json)?;          // at start-up; any error: refuse to start
let ops = Operations::load(&operations_json)?;            // ditto (ops_declaration_invalid)
let broker_id = BrokerId::new(configured_id).expect("ID"); // ditto

// Per request:
let request = ops.parse_request(op, params)?;             // RequestError: invalid_argument, nothing else happens
let bytes = decode_transport(header_or_member)?;          // None if absent; never trim the value
let ctx = VerifyContext { now, broker_id: &broker_id, workload: peer_wid,
                          workload_tenants: &registered_tenants, request: &request,
                          operations: &ops, limits: Limits::default() };
match verify(&bytes, &registry, &ctx) {
    Err(code) => deny(code),                              // unverified: consume and record nothing
    Ok(Verified::Write(w)) => {
        // BEGIN; W10 is the first statement:
        let c = w.consumption();                          // (iss, jti, exp, request_hash)
        // INSERT consumed_grant(c.iss, c.jti, c.exp, c.request_hash, 'PENDING')
        //   conflict, same hash      -> return the stored outcome (STORED_OUTCOME)
        //   conflict, different hash -> grant_replayed (row unchanged)
        // SAVEPOINT decision; SELECT revoked_before rows for the grant's tenant
        match w.decide(&rows) {                           // W11–W13
            Ok(a) => { /* W14 preconditions; effect using ONLY a.params(); outcome = ACCEPT; COMMIT */ }
            Err(code) => { /* ROLLBACK TO SAVEPOINT; outcome = DENIED; COMMIT; on any failure -> unavailable */ }
        }
    }
    Ok(Verified::Read(r)) => {
        // READ ONLY transaction; SELECT revoked_before rows for the grant's tenant
        let a = r.decide(&rows)?;                         // R11, R13; nothing is recorded
        // query filtered by a.tenant() and a.subject() (R14)
    }
}
```

The broker must meet these obligations. They cannot be enforced inside a library.

1. **Trusted context.**
   - `workload` comes from the socket or mTLS peer identity.
   - `workload_tenants` comes from the workload registry, and is empty if the workload is not
     registered.
   - `now` is the broker clock, floored, and checked against the persisted high-water mark (§7.6).
   - All instances that share a `broker_id` share one replay store and one revocation table (§7.1).
2. **W10 before anything else.**
   - The consumption insert, keyed uniquely on `(iss, jti)`, is the first statement of the effect
     transaction.
   - Every `Err` from `WriteGrant::decide`, and every W14 precondition failure, is recorded as
     DENIED in **the same** transaction (§7.3).
   - If that recording or the commit fails, or the commit outcome is unknown, answer `unavailable`,
     not `grant_denied`.
   - Nothing is recorded for read grants or for `verify` errors.
3. **Revocation rows** are read inside the deciding transaction and passed to `decide`.
4. **Execute only what was checked.** The effect reads parameters only from
   `Authorized::params()`, which are the same values that were validated, hashed, and compared
   with the grant. `Request`, `WriteGrant`, `ReadGrant` and `Authorized` are not `Clone`.
5. **Client responses.**
   - The workload sees only `grant_denied` or `unavailable`.
   - `GrantError::as_str()` is for the audit log.
   - Infrastructure failures (registry, replay store, revocation table, locks) mean `unavailable`.
6. **Configuration tests.** Check that `ledger.transfer` has `requires_confirmation: true` (D-2).
   - Registry reload must validate the whole file and swap it in atomically.
   - If the reload fails, stop serving: the failed file may have carried a revocation (§8.4).
   - The registry and declaration files must be writable by administrators only.
7. **Expiry at commit** (SPEC_ISSUES.md D2-4): re-check `now < exp + skew` inside the effect
   transaction, or bound the transaction time.
8. **Concurrency, restart and replay-store restore** must be covered by integration tests
   (§12.2).
9. **Mandate grants (`cfm = 2`, Draft 4).** The crate checks only the format (`mid` is exactly
   16 bytes and present iff `cfm = 2`) and W11d (`cfm = 2` only for a `mandate_eligible`
   operation). It does **not** know whether the mandate exists, is active, or has room in its
   terms and counters. For every write grant whose `WriteGrant::mandate_id()` /
   `Authorized::mandate_id()` is `Some(mid)`, the broker MUST, inside the effect transaction:
   - lock and check its own mandate row for that `mid` (agent-interface-v1 §4.5: active, bound to
     the grant's `wid`/`ten`/`sub`, terms, counters) as a **W14 precondition**, in the documented
     lock order (for payments: record → mandate → budget, payments-adapter-v1 §16.4);
   - treat a missing, revoked or exhausted mandate as a W14 denial: roll back to the savepoint,
     record DENIED, commit (§7.3), exactly like any other precondition failure;
   - update the mandate counters in the same transaction as the effect.
   `mandate_id()` is `None` for `cfm = 0` and `cfm = 1`; a `cfm = 1` grant touches no mandate.
   Declarations: set `mandate_eligible: true` only on operations the mandate design allows
   (agent-interface-v1 §3); `Operations::new` refuses it on reads and on writes without
   `requires_confirmation`.
10. **Issuers.** `GrantBuilder::mandated(mid)` sets `cfm = 2` and `mid`. The Authority may call it
    only after finding the effect within an active mandate on its **own** mandate record and
    counters, never on a caller's word (spec §9).

### Payments adapter: `verify_retransmission`

The payments adapter calls this to (re)send an effect the broker already decided
(payments-adapter-v1 Draft 2 §3.1). It is separate from `verify` and cannot be confused with it:

- it has its own context (`RetransmissionContext`), result (`RetransmissionAuthorized`) and error
  (`RetransmissionError`) types;
- it never yields a `WriteGrant` or `Authorized`, and has no consumption step;
- it does **not** check `exp`. It requires `now − iat ≤ R_max` instead, where `RMax::new` enforces
  the start-up rule against provider retention and resend margin;
- it evaluates the key window at `iat`;
- it refuses while the clock reads below 2024-01-01;
- it accepts `cfm = 1`, and `cfm = 2` (with `mid`) only when the adapter's declaration is
  `mandate_eligible` (payments-adapter-v1 §16.2 for `payments.support_refund`; SPEC_ISSUES.md
  D4-1). `confirmation()` / `mandate_id()` report it; the adapter does not evaluate the mandate.

`idempotency_identity()` returns the `(iss, jti)` pair for the provider idempotency key. Every
provider value comes from `params()`, the signed `res`/`con` values.

`verify_binding` (Draft 3, PA-18) is the lookup-only variant for `refund.find`, `refund.get` and
`idem.status`. It runs the same checks **without** the age cap. Its result, `BindingVerified`, has
no conversion to `RetransmissionAuthorized`, so it can never authorize a create. An empty tenant
list makes `RetransmissionContext::new` refuse.

Adapter obligations:
- check `amount_minor ≥ 1` (SPEC_ISSUES.md RX-3);
- check its own order view (§3.2);
- map every error to `grant_refused`;
- never use this function on the broker path.

Open spec points are RX-1..RX-6 in SPEC_ISSUES.md. The most important is RX-1: the tenant check
is enforced against a caller-supplied tenant list.

The feature `conformance-unvalidated-requests` exposes `Request::unvalidated_for_conformance`. It
exists only so that this crate's tests can reach W12b/W12c, and is enabled only through the
crate's own dev-dependency. **Never enable it in a broker.**

## Dependencies

Licenses were checked with the crates.io API (`/api/v1/crates/<name>/<version>`) on 2026-10-25.

| Crate | Version | License | Why |
|---|---|---|---|
| `ed25519-dalek` | =3.0.0 | BSD-3-Clause | `verify_strict`, signing, key decoding. §3.5 names this behaviour. Features: `fast`, `zeroize`. |
| `curve25519-dalek` (transitive) | 5.0.0 | BSD-3-Clause | `is_small_order` / `is_torsion_free`, used for the order-L check on keys. |
| `sha2` | 0.11 (0.11.0 locked) | MIT OR Apache-2.0 | SHA-256 for the kid (§8.1) and the request hash (§5.4). |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | Strict parsing of the registry and declarations (`deny_unknown_fields`, duplicate fields, borrowed strings). |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | JSON parsing. The `raw_value` feature supports per-entry parsing and integer-grammar checks. |

The only dev-dependency is this crate itself, which enables the test-only feature. The transitive
tree uses only MIT, Apache-2.0, BSD-3-Clause, Unlicense-or-MIT and Unicode-3.0 licenses.

## Tests

```sh
cargo test --release
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

| Suite | Covers |
|---|---|
| `tests/conformance.rs` | Every vector in the manifest (`spec_draft` 4):<br>• 292 grant vectors (305 steps), including MND-01..12<br>• 26 registry, 24 operation-declaration (incl. OPS-21..25) and 11 transport vectors<br>• 3 request-hash examples<br>W10 and the savepoint recording rule are simulated with an in-memory store. The test also asserts that only CON-20..24 bypass the strict request parser. |
| `tests/roundtrip.rs` | • Builder → verify → decide<br>• Byte-exact reproduction of ACC-01<br>• Strict request parsing (GC-01)<br>• The consumption hash and `Authorized::params` match the validated request (GC-02)<br>• Builder refusals<br>• 300 randomized `test.hold` grants<br>• Draft 4: byte-exact MND-01, `mandate_id()` on verified grants, W11d on `ledger.transfer`, strict `mandate_eligible` member |
| `tests/retransmission.rs` | `verify_retransmission` and `verify_binding`:<br>• age-cap boundaries, and an expired-but-young grant accepted while `verify` still says `grant_expired`<br>• future `iat`, and every binding or schema mismatch<br>• read grant, key revoked or unknown, key window at `iat`<br>• clock floor, the `R_max` start-up rule, and context refusals<br>• `verify_binding`: an old grant is accepted for lookup but refused for create; tampered, read and mismatched grants are rejected<br>• Draft 4: `cfm = 2` accepted only for a `mandate_eligible` declaration, with `mid` reported |
| `tests/robustness.rs` | • Over 1.4 million truncated, mutated, extended and random variants of every vector<br>• Re-signed mutated payloads<br>The checks are no panics, and no mutation of an accepted grant is ever accepted. |

Spec issues: [`SPEC_ISSUES.md`](SPEC_ISSUES.md).
