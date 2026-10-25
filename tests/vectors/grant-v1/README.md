# Nodkey-Grant v1 test vectors

> [!WARNING]
> **TEST-ONLY KEYS.** Every signing key used here is a published test key from RFC 8032 §7.1. Their
> secret seeds are public (and listed in `manifest.json`). A key registry containing any of them must
> never be deployed.

Conformance vectors for [`docs/specs/grant-v1.md`](../../../docs/specs/grant-v1.md). An implementation
conforms if, for every vector, it produces exactly the expected result.

## Layout

| Path | Content |
|---|---|
| `manifest.json` | Constants, test keys, workload registrations, operation declarations, and every vector with its inputs and expected result |
| `registry.json` | The key registry (spec §8.2) used by every grant vector: keys A, C, D, E |
| `grants/<id>.hex` | The grant bytes of one vector: lowercase hex, one line (the decoded form; base64url transport is not exercised) |
| `registries/<id>.json` | Key registries for the load-time vectors |
| `gen/` | Rust generator and reference checker (`ed25519-dalek` 3.0.0, `curve25519-dalek` 5.0.0, `sha2`, `serde_json`) |
| `crosscheck/openssl_verify.py` | Signature cross-check using a separate code path: a Python stdlib reader plus `openssl pkeyutl` |

## Test keys

| Name | Source | Registry entry | Used for |
|---|---|---|---|
| A | RFC 8032 TEST 1 | `active`, role `user_authority`, iss `nodkey.authority.test` | every valid user grant |
| B | RFC 8032 TEST 2 | not registered | wrong-key and unknown-kid vectors |
| C | RFC 8032 TEST 3 | `revoked` | revoked key |
| D | RFC 8032 TEST 1024 | `active`, window 2025-01-01 to 2026-01-01 | key outside its validity window |
| E | RFC 8032 TEST SHA(abc) | `active`, role `scheduler`, iss `nodkey.scheduler.test` | scheduler grants (provisional, spec D-9) |

The generator asserts that each seed yields the RFC's public key.

## Manifest format

```jsonc
{
  "format": "nodkey.grant-v1.vectors",
  "constants": { "typ", "external_aad_tag", "kid_label", "max_grant_bytes": 2048, "skew_seconds": 5, "max_ttl_seconds": 30 },
  "keys": [ { "name", "source", "secret_seed", "public_key", "kid", "in_registry", "purpose" } ],
  "workloads": [ { "wid", "tenants": [...] } ],          // workload registrations (spec step 9c)
  "operations": [ { "op", "kind", "opv": [...], "authority", "requires_confirmation", "params": [...] } ],
  "vectors": [
    { "id", "kind": "grant", "category", "description",
      "registry": "registry.json", "grant": "grants/<id>.hex", "grant_len",
      "steps": [ { "now", "broker_id", "peer_wid", "revoked_before": [...], "request": { "op", "args" }, "expected" } ] },
    { "id", "kind": "registry", "category": "registry", "description", "registry": "registries/<id>.json", "expected" }
  ]
}
```

- **Grant vectors.** Load `registry`, start with an **empty replay store**, then submit the grant once per
  step, in order, with that step's trusted context: `now` (broker clock, Unix seconds), `broker_id` (the
  broker's own identifier, used for `external_aad` and the `aud` check), `peer_wid` (the workload identity
  of the submitting socket), and `revoked_before` rows (`{"ten"}`, `{"ten","wid"}`, or `{"ten","sub"}`
  plus `"before"`). The replay store persists across the steps of one vector only.
- **`request`** is the already strictly parsed request the broker is asked to authorize: operation name
  and typed arguments (strings or unsigned integers), keyed by parameter name from `operations`.
- **`expected`** is one of `ACCEPT`; `STORED_OUTCOME:ACCEPT` / `STORED_OUTCOME:DENIED` (spec §7.2 step 12:
  same grant, same request hash, no second effect); or an exact broker-facing error code from spec §7.2.
  Policy, state and budget checks (step 14) are out of scope: `ACCEPT` means "passes every grant check".
- **Registry vectors** expect `LOAD_OK` or a load error code from spec §8.3. A failing registry stops the
  broker; every non-valid registry here contains the four valid keys plus one bad entry (or no keys).

## Operations

`ledger.transfer` (write, confirmation required, `from` res, `to` and `amount_cents` exact) and
`ledger.get_balance` (read) match the ADR-0003 Phase 3 profile. `test.hold` (bounded amount, exact
currency, free memo) and `ledger.list_transfers` (read) exist only to exercise the format.
`orders.capture` (scheduler-signed) depends on ADR-0009, which is being revised.

## Categories

| Prefix | Spec step | Vectors |
|---|---|---|
| ACC | positive controls (write, read multi-use, inclusive bound, free param, other audience at its own broker, multi-tenant workload, scheduler) | 9 |
| ENV | 1–2 size and envelope structure (2048/2049 bytes, truncation, trailing bytes, tags, arity, indefinite and non-minimal encodings, signature length, nil payload, huge declared length) | 23 |
| HDR | 3–4b protected/unprotected header, `alg` disagreement (−8, −7, 0) | 23 |
| KEY | 4 unknown kid, revoked key, key outside window | 4 |
| SIG | 5 wrong key, kid swap, R/S bit flips, S + L malleability, wrong audience/domain tag/empty aad, wrong COSE context, and every payload field altered after signing (SIG-20..38) | 29 |
| PDEC | 6 non-canonical ints/lengths, unsorted and duplicate keys, indefinite lengths, floats, negative ints, tags, simple values, trailing bytes, truncation, invalid UTF-8, depth | 19 |
| PSCH | 7 unknown/reserved/text keys, each missing field, wrong types and ranges, version, kind and kind-specific key sets | 63 |
| ISS, TIME | 8 issuer, expiry/not-before with ±1 s skew boundaries, TTL, ordering | 14 |
| BIND | 9 audience field, workload, tenant | 6 |
| OP | 10 operation, kind (read grant for a write op, and the reverse), opv, issuer role, missing confirmation (OP-13) | 13 |
| CON | 11 resource, exact and bounded constraints, schema/class disagreement | 17 |
| RPL | 12 replay sequences (stored outcome, different request, consumed denial, unverified not consumed, revocation interplay) | 7 |
| REV | 13 `revoked_before` scopes and boundary, read grant revoked | 8 |
| REG | key registry load (small-order and non-canonical keys, kid mismatch, duplicates, shape) | 17 |

## Regenerating and checking

Requires a Rust toolchain (edition 2024) and, for the cross-check, Python 3 and OpenSSL ≥ 3.0.

```sh
cd tests/vectors/grant-v1/gen
cargo run -q -- generate ..        # rewrites manifest.json, registry.json, grants/, registries/
cargo run -q -- check ..           # reference verifier: every step must match "expected"
python3 -I ../crosscheck/openssl_verify.py ..
```

Output is deterministic (Ed25519 signatures are deterministic; `jti` = first 16 bytes of
SHA-256(`"nodkey.test.jti" ‖ 0x00 ‖ vector-id`)), so regeneration must reproduce the committed files
byte for byte.

The reference checker reads only the committed files, but it shares the CBOR module (the generator
uses its encoder, the checker its strict decoder) and the kid, `external_aad` and `Sig_structure`
helpers with the generator. It is a consistency check by the same author, not an independent
implementation; the OpenSSL cross-check is the only independent code path for signatures; the broker's
verifier is expected to be the second implementation run against these files. Its JSON parsing of
registries is not strict about duplicate members (the spec requires strict parsing).

## Not covered

Base64url transport encoding; concurrency, restart and replay-store failure (integration tests);
read-ownership and step-14 preconditions; signatures with a small-order `R`. See spec §12.2.
