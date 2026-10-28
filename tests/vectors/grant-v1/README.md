# Nodkey-Grant v1 test vectors (spec Draft 4)

> [!WARNING]
> **TEST-ONLY KEYS.** Every signing key used here is a published RFC 8032 test key, and its secret seed
> is public. The seeds are listed in `manifest.json`. A key registry containing any of these keys must
> never be deployed.

These are conformance vectors for [`docs/specs/grant-v1.md`](../../../docs/specs/grant-v1.md) Draft 4
(Draft 2 set plus the Draft 4 changes of spec §17: ENV-02 and PSCH-03 moved to key 21, MND-01..12,
OPS-21..25; `operations.json` gains `test.mandated`).
An implementation conforms if it produces exactly the expected result for every vector.

## Layout

| Path | Content |
|---|---|
| `manifest.json` | Constants, type grammars, test keys, workload registrations, request-hash examples, and every vector with its inputs and expected result |
| `registry.json` | The key registry (spec §8) used by every grant vector: keys A, C, D, E, F |
| `operations.json` | The operation declarations (spec §6) used by every grant vector |
| `grants/<id>.hex` | The grant bytes of one grant vector, as one line of lowercase hex |
| `registries/<id>.json` | Key registries for the registry-load vectors (some are deliberately not valid JSON or contain duplicate members) |
| `operations/<id>.json` | Declarations for the operation-load vectors |
| `gen/` | Rust generator and reference checker (`ed25519-dalek` 3.0.0, `curve25519-dalek` 5.0.0, `sha2`, `serde`, `serde_json`) |
| `crosscheck/openssl_verify.py` | Signature cross-check through a separate code path: a Python stdlib reader plus `openssl pkeyutl` |

## Test keys

| Name | Source | Registry entry | Used for |
|---|---|---|---|
| A | RFC 8032 §7.1 TEST 1 | `active`, iss `nodkey.authority.test` | every valid grant |
| B | RFC 8032 §7.1 TEST 2 | not registered | wrong-key and unknown-kid vectors; base for the mixed-order key |
| C | RFC 8032 §7.1 TEST 3 | `revoked` | revoked key |
| D | RFC 8032 §7.1 TEST 1024 | `active`, window 2025-01-01 to 2026-01-01 | key past its window; window-end boundary |
| E | RFC 8032 §7.1 TEST SHA(abc) | `active`, same iss as A | rotation overlap (ACC-08); kid swap (SIG-02) |
| F | RFC 8032 §7.2 Ed25519ctx key (used as plain Ed25519) | `active`, window from 2027-01-01 | key not yet valid |

The generator checks that each seed yields the public key given in the RFC.

## Manifest format

```jsonc
{
  "format": "nodkey.grant-v1.vectors", "spec_draft": 4,
  "constants": { "typ", "external_aad_tag", "kid_label", "request_hash_label", "max_grant_bytes": 2048,
                 "max_transport_chars": 2731, "skew_seconds": 5, "max_ttl_seconds": 30 },
  "types": { "uint", "account_id", "currency", "text64", "text256" },   // grammars (spec §6.2)
  "keys": [ { "name", "source", "secret_seed", "public_key", "kid", "in_registry", "purpose" } ],
  "workloads": [ { "wid", "tenants": [...] } ],             // workload registrations (spec step 9c)
  "request_hash_examples": [ { "request", "request_hash" } ], // spec §5.4
  "vectors": [ ... ]                                          // four kinds, below
}
```

| `kind` | Fields | Expected |
|---|---|---|
| `grant` | `registry`, `operations`, `grant` (hex file), `grant_len`, `steps[]` | per step |
| `registry` | `registry` (file) | `LOAD_OK` or a spec §8.3 code |
| `operations` | `operations` (file) | `LOAD_OK` or `ops_declaration_invalid` |
| `transport` | `text`, `text_len`, `decoded` (hex file, or `null` for zero bytes) | `DECODED` (the decoded bytes equal `decoded`) or a spec §2 / step 1 code |

**Running a grant vector.**

1. Load `registry` and `operations`, and start with an empty replay store.
2. Submit the grant once per step, in order, with that step's trusted context:
   - `now`: broker clock, in Unix seconds;
   - `broker_id`: used for `external_aad` and for the `aud` check;
   - `peer_wid`: the identity of the submitting workload;
   - `revoked_before`: rows of the form `{"ten"}`, `{"ten","wid"}` or `{"ten","sub"}`, each plus `"before"`.
3. Each step's `request` is the strictly parsed request: the operation name and arguments keyed by
   parameter name. Five constraint vectors deliberately carry requests outside the declaration, so a
   broker with a strict request parser must run them through an unvalidated path:
   - CON-20..23 pass a missing argument or one of the wrong type;
   - CON-24 passes `p0` of 257 bytes (`text256` allows 256) and omits `p1`..`p7`. Its grant fails
     earlier anyway, at step 7 (spec D2-1).
4. The replay store persists across the steps of one vector only.

**Expected results for a step.**

- `ACCEPT`: the grant passes every grant check. Step W14 / R14 preconditions are out of scope.
- `STORED_OUTCOME:ACCEPT` or `STORED_OUTCOME:DENIED`: spec step W10, same grant and same request hash.
- Otherwise, an exact broker-facing error code from spec §7.

Descriptions that contain **STRICT-ONLY** mark signatures that satisfy the cofactorless equation but must
be rejected by the strict rules of spec §3.5. A lax verifier such as OpenSSL accepts them.

## Operations

`ledger.transfer` is a write operation:
- it requires confirmation;
- `from` is its `res` parameter;
- `to` (the destination) and `amount_cents` are `exact` constraints.

`ledger.get_balance` is a read operation. These two match the ADR-0003 Phase 3 profile.

The other operations exist only to exercise the format:
- `test.hold`: bounded, exact and free parameters;
- `test.bulk`: eight `text256` parameters, used to reach the 2048-byte limit;
- `ledger.list_transfers` and `test.peek`: read operations; `test.peek` tests text-key ordering;
- `test.mandated` (Draft 4): a write with `requires_confirmation` and `mandate_eligible: true`, one exact
  `res` parameter. Mandate grants carry `cfm = 2` and a TEST-ONLY 16-byte `mid` (key 20). The vectors
  check only the grant format and W11d; whether the mandate is active and within its terms is a broker
  precondition (W14) that the vectors do not cover.

## Categories

| Prefix | Spec step | Count |
|---|---|---|
| ACC | positive controls | 12 |
| ENV | 1–2 size and envelope | 23 |
| HDR | 3–4b headers, `alg` | 23 |
| KEY | 4 key lookup, status, window (incl. boundaries) | 7 |
| SIG | 5 signatures; every field altered after signing (SIG-20..39); small-order and non-canonical R | 32 |
| PDEC | 6 strict payload decoding | 21 |
| PSCH | 7 payload schema, kinds, ID and value limits | 86 |
| ISS, TIME | 8 issuer, time window, lifetime from `iat` | 20 |
| BIND | 9 audience, workload, tenant | 6 |
| OP | W11 / R11 operation, kind, opv, confirmation | 12 |
| MND | Draft 4 mandate grants: `cfm = 2`, `mid` shape, W11d eligibility, `mid` under the signature | 12 |
| CON | W12 resource, constraints, declared types | 21 |
| RPL | W10 replay sequences | 8 |
| REV | W13 / R13 `revoked_before` | 9 |
| REG | key-registry load | 26 |
| OPS | operation-declaration load (OPS-01..19, OPS-21..25; OPS-20 reserved) | 24 |
| TRN | transport text | 11 |

## Regenerating and checking

You need a Rust toolchain (edition 2024). The cross-check also needs Python 3 and OpenSSL 3.0 or later.

```sh
cd tests/vectors/grant-v1/gen
cargo run -q -- generate ..        # rewrites manifest.json, registry.json, operations.json, grants/, registries/, operations/
cargo run -q -- check ..           # reference verifier: every result must match "expected"
python3 -I ../crosscheck/openssl_verify.py ..
```

The output is deterministic. Regeneration must reproduce the committed files byte for byte, because:
- Ed25519 signatures are deterministic;
- `jti` is the first 16 bytes of SHA-256(`"nodkey.test.jti"` ‖ 0x00 ‖ *seed*), where *seed* is a
  generator-internal string. Usually that is the vector id's short prefix (for example `ACC-01`), but
  not always (for example `ENV` for several envelope vectors).

An implementation that wants to reproduce a grant byte for byte should take `jti` from the grant itself.
`jti` has no other significance in the vectors.

**Limits of the reference checker.**
- It reads only the committed files. However, it shares the CBOR module, the kid, `external_aad` and
  `Sig_structure` helpers, and the `request_hash` function with the generator.
- It is therefore a consistency check by the same author, not an independent implementation. The
  OpenSSL cross-check is the independent code path for signatures, and the `nodkey-grant` crate is the
  independent second implementation.

## Not covered

- concurrency, restart, and failure injection into denial recording (integration tests, spec §12.2);
- registry reload;
- read ownership and W14 preconditions;
- the `broker_id` sharing rule;
- mandate state (active, terms, counters) for `cfm = 2` grants (a W14 precondition).
