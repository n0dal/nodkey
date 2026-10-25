# nodkey-grant

> **PROTOTYPE.** This crate is not reviewed and not suitable for production use.

This crate verifies and issues **Nodkey-Grant v1** grants, as specified in
[`docs/specs/grant-v1.md`](../../docs/specs/grant-v1.md). Grants use a restricted COSE_Sign1
(Ed25519) profile with a deterministic-CBOR payload. The crate was written as a second
implementation, independent of the vector generator in `tests/vectors/grant-v1/gen/`. It shares no
code with the generator and was written without reading it.

A valid grant is a necessary condition for an effect, never a sufficient one (SI-04). The broker
still applies policy, current state and budgets.

## What it does

| Area | Spec | Notes |
|---|---|---|
| Strict CBOR decoder and encoder | §4 | Hand-written and bounded. Rejects non-shortest heads, indefinite lengths, major type 7, tags, invalid UTF-8, unsorted or duplicate map keys, trailing bytes, and lengths larger than the remaining input (checked before allocation). Depth limits are 4, 1 and 3. Negative integers are not allowed in the payload. |
| COSE_Sign1 profile | §3 | Requires the single-byte tag `0xd2`, the exact protected header `{1: alg, 4: kid, 16: typ}` and an empty unprotected map. The signature is checked with Ed25519 `verify_strict` over `Sig_structure`, with `external_aad = "nodkey.grant.v1" ‖ 0x00 ‖ broker_id`. |
| Key registry | §8 | Strict JSON: unknown, duplicate and missing members are rejected. Each key must be a canonical encoding of a curve point, must not be small-order or mixed-order, must have a derived kid, and must not be a duplicate. Checks run in file order. |
| Verification | §7.2 steps 1c–11 | The first failing step sets the error code. |
| Transport | §2, steps 0–1c | Canonical unpadded base64url. |
| Issuer | §9 | `GrantBuilder` emits canonical grants. It validates its own output with the verifier's decoder and schema, and refuses to sign anything nonconforming. |

The crate does **not** do step 12 (consumption) or step 13 (revocation). Both need the broker's
database and must run inside its effect transaction. The crate supplies the inputs for them.

## API

```rust
let registry = Registry::load(&json)?;                       // RegistryError { code, entry }
let ops = Operations::new(declarations)?;                    // spec §6 start-up checks
let bytes = decode_transport(header_value)?;                 // steps 0–1c
let ctx = VerifyContext { now, audience: broker_id, workload: peer_wid,
                          workload_tenants: &tenants, requested_op, requested_params: &params,
                          operations: &ops, skew: Skew::default() };
match verify(&bytes, &registry, &ctx) {
    Ok(g) if g.must_consume() => { /* step 12: insert (g.iss(), g.jti(), request_hash(..)); step 13 */ }
    Ok(g) => { /* read grant: step 13 (g.identity().is_revoked(..)), then READ ONLY query by (ten, sub) */ }
    Err(rej) => {
        // rej.code.as_str() goes to the audit log; the workload only gets "grant_denied".
        // If rej.verified is Some(write grant), record DENIED under (iss, jti) (spec §7.3).
    }
}

let grant = GrantBuilder::write("ledger.transfer", 1)
    .issuer(iss).audience(broker_id).jti(csprng_16_bytes).times(iat, nbf, exp)
    .workload(wid).tenant(ten).subject(sub)
    .resource(0, ParamValue::Text("alice".into()))
    .exact(0, ParamValue::Text("bob".into())).exact(1, ParamValue::Uint(12500))
    .confirmed(true)
    .sign(&signing_key)?;
```

- **`GrantError`** has one variant per §7.2 error code, and `as_str()` returns that code as a
  stable string. `verify` returns a `Rejection { code, verified }` rather than a bare
  `GrantError`. Spec §7.3 requires the broker to record a verified write grant that is denied at
  steps 10–11 under its `(iss, jti)`, so the identity has to come back with the error.
  `verified` is `Some` exactly when steps 1–9 passed.
- **`VerifiedGrant`** can only be constructed by `verify`. It exposes `kind`, `iss`, `jti`, the
  tenant, the subject, `op` and `opv`, and `must_consume()`.
- **Parameter types** are supplied by the broker as a `ParamType` (uint, or text with length
  bounds and an allowed-byte set), because the spec does not define them (SPEC_ISSUES.md SI-1).
- The crate never generates `jti`. The issuer must supply 16 bytes from a CSPRNG.

## Dependencies

Licenses were checked with the crates.io API (`/api/v1/crates/<name>/<version>`) on 2026-10-25.

| Crate | Version | License | Why |
|---|---|---|---|
| `ed25519-dalek` | =3.0.0 | BSD-3-Clause | Ed25519 `verify_strict`, signing, key decoding. The spec names this exact behaviour (§3.5). Pinned. Features: `fast`, `zeroize`. |
| `curve25519-dalek` (transitive) | 5.0.0 | BSD-3-Clause | Provides `is_small_order` and `is_torsion_free`, used for the registry weak-key check. |
| `sha2` | 0.11 (0.11.0 locked) | MIT OR Apache-2.0 | SHA-256 for kid derivation (§8.1) and `request_hash` (§5.4). |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | Strict registry parsing (`deny_unknown_fields`, duplicate-field detection). |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | Registry JSON. Uses `raw_value` so that duplicate members are detected within each entry. |

There are no dev-dependencies. Property and fuzz-style tests use a small in-file PRNG instead of
`proptest` or `cargo fuzz`. The full transitive tree (`cargo tree -e normal`) uses only the
MIT, Apache-2.0, BSD-3-Clause, Unlicense-or-MIT and Unicode-3.0 licenses.

## Tests

```sh
cargo test                                   # unit + conformance + round trip + robustness
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

| Suite | What it checks |
|---|---|
| `tests/conformance.rs` | Runs every vector in `tests/vectors/grant-v1/manifest.json`: 235 grant vectors with 246 steps, and 17 registry vectors. Each step must give the exact expected result. Steps 12 and 13 are simulated with an in-memory replay store, as the vectors README describes. |
| `tests/roundtrip.rs` | Builder → sign → verify for write and read grants. Byte-exact reproduction of vector ACC-01. Role separation. Builder refusals. 300 randomized `test.hold` grants checked for accept, bound, constraint and expiry. |
| `tests/robustness.rs` | Over 1.4 million truncated, bit-flipped, byte-substituted, inserted and random variants of every vector, plus random inputs and deep nesting. Also re-signed mutated payloads, which reach the post-signature decoder. The checks: no panics, and no mutation of an accepted grant is ever accepted. |

Not covered: concurrency, restart, replay-store failure (broker integration tests), and signatures
with a small-order `R` but an otherwise valid equation. `verify_strict` rejects that case, but
there is no vector for it (spec §12.2).

Spec ambiguities found during implementation: [`SPEC_ISSUES.md`](SPEC_ISSUES.md).
