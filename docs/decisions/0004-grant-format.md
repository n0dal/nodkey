# ADR-0004: Grant format — restricted COSE_Sign1 profile

- **Status:** Proposed
- **Date:** 2026-10-24
- **Invariants:** SI-05, SI-06, SI-07, SI-08
- **Open questions:** OQ-05 (addressed), OQ-07 (open)

## Problem

Choose a signed representation for grants that the workload carries but cannot forge, alter, or
reinterpret, and that the broker can verify strictly (OQ-05).

## Evaluation criteria

No algorithm confusion; no encoding ambiguity; small strict verifier; standard primitives only;
maintained Rust implementations; no features PBE does not need.

## Alternatives considered

From research 02 §3: **Biscuit** (attenuation via Datalog; no single-use; key-confusion advisory
CVE-2024-41949; slowed releases) — revisit if delegation is needed. **Macaroons** (HMAC: verifier can
mint) — rejected. **PASETO v4.public** (version-locked Ed25519, PAE, implicit assertion; JSON claims)
— acceptable runner-up. **JWS/JWT** (`alg` confusion classes, RFC 8725; CVE-2026-25537) — rejected.
**Fixed-field binary envelope** — fallback. **Actenon** protocol — not yet evaluated (OQ-07).

## Decision

**PBE-Grant v1** = a restricted COSE_Sign1 profile (research 02 §4):

- CBOR tag 18, 4-element definite array; protected header exactly `{1: -19, 4: kid(16 B), 16:
  "application/pbe-grant+cbor"}`; unprotected header empty; non-detached payload; 64-byte signature.
- **Ed25519** (COSE alg −19, RFC 9864), verified with `ed25519-dalek` `verify_strict`; keys checked
  for weakness and canonical encoding at load.
- **Algorithm fixed by the key entry** (`kid` → key, alg, issuer, purpose, validity); the header `alg`
  must merely equal it.
- Payload: **deterministic CBOR map with PBE-private integer keys** (02 §4.2); unknown keys rejected
  at every level; required keys mandatory; strict types.
- **Domain separation:** fixed protected `typ`, COSE `"Signature1"` context, broker-supplied
  `external_aad = "pbe.grant.v1" ‖ 0x00 ‖ aud`, one key per purpose.
- Verification order per 02 §4.3: length cap → bounded decode with re-encode byte-compare → header
  check → signature → payload decode → semantic checks against trusted facts. Any failure is a
  generic deny; detail goes to the audit log.
- No attenuation, delegation, or `cnf` in v1. New algorithms arrive only as protocol v2.
- The PHP SDK treats grants as opaque, length-capped strings.

## Evidence

RFC 9052 §3, §4.4; RFC 9596; RFC 9864; RFC 8949 §4.2; `ed25519-dalek` 3.0.0 docs (verify_strict,
ZIP-215); RFC 8725 §2–3 — all cited in research 02.

## Consequences
- **Advantages:** binary, integer-keyed payload; well-reviewed structure; `external_aad` makes
  wrong-audience grants fail cryptographically.
- **Drawbacks:** a hand-written strict verifier is TCB code that needs fuzzing and an independent
  second implementation for test vectors; `coset`/`ciborium` maturity on the verify path is undecided
  (02 §9).
- **Security:** the format guarantees integrity and binding, never authorization (SI-04); the
  broker still runs policy and state checks.
- **Performance:** one Ed25519 verification per effect [H, negligible vs the DB transaction].
- **Compatibility:** language-neutral; any COSE library can *produce* conforming grants.

## Architect notes

- **OQ-07 must be closed before v1**: evaluate Actenon's verifier protocol for interoperability or
  reuse. Adopting PBE's own profile first and switching later would be a breaking change.
- The 02 §8 test vectors (1–20) are acceptance criteria for this ADR, not optional.

## Reversal / migration

Switching to PASETO v4.public or a fixed-field envelope changes only the codec; payload fields and
semantic checks are format-independent. `ver`/`typ` distinguish versions; no downgrade fallback.
