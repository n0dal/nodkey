# Effect protocol v2: pending-effect digest vectors

These are conformance vectors for the pending-effect digest of
[`docs/specs/effect-protocol-v2.md`](../../../docs/specs/effect-protocol-v2.md) §3.2. The broker, the
gateway and the authority each compute this digest independently. All three must produce the same bytes.

## Files

| Path | Content |
|---|---|
| `digest-vectors.json` | the vectors |
| `gen/` | Rust generator (own minimal deterministic-CBOR encoder, `sha2`, `serde_json`) |
| `verify_digest.py` | second code path, Python stdlib only (`hashlib`, `base64`, `json`) |

## Format

Each vector has:
- `id` and `description`;
- `record`: the record as it appears in a broker JSON response, including `param_types` and `display`.

An accepting vector also has:
- `cbor_hex`: the deterministic CBOR encoding of `M`;
- `digest`: `SHA-256("nodkey.pending.v1" || 0x00 || cbor)`, as lowercase hex.

A rejecting vector instead has `"expected": "reject"` and a `reason`. Rejections cover:
- a non-canonical `pending_id` alias;
- a JSON value whose type differs from the declared type;
- a missing parameter;
- a non-ASCII ID.

## Regenerate and verify

```sh
cd tests/vectors/effect-v2/gen && cargo run -q -- ..   # rewrites ../digest-vectors.json (deterministic)
python3 -I ../verify_digest.py                          # re-encodes every record and re-hashes it
```

The Python checker shares no code with the generator. It re-encodes each record with its own encoder and
compares the result with `cbor_hex`. It then hashes the hex with `hashlib` and compares that with
`digest`. It also requires every rejection to be rejected again.
