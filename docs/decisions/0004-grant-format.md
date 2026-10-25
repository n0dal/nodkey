# ADR-0004: Grant format — restricted COSE_Sign1 profile (rev. 2)

- **Status:** Proposed — review conditions (AR-08, AR-09, AR-17) applied; stays Proposed because OQ-07
  (Actenon interop/reuse) could replace the format and must be evaluated first.
- **Date:** 2026-10-24
- **Invariants:** SI-05, SI-06, SI-07, SI-08
- **Open questions:** OQ-05 (addressed), OQ-07 (open, blocks acceptance)

## Problem

Choose a signed grant representation the workload carries but cannot forge, alter, or reinterpret,
and the broker verifies strictly.

## Evaluation criteria

No algorithm confusion; no encoding ambiguity; small strict verifier; standard primitives only;
maintained Rust libraries; no unneeded features.

## Alternatives considered

Research 02 §3: Biscuit (attenuation; no single-use; CVE-2024-41949) — revisit for delegation.
Macaroons (verifier can mint) — rejected. PASETO v4.public — runner-up. JWS/JWT (RFC 8725 classes;
CVE-2026-25537) — rejected. Fixed-field binary — fallback. Actenon — not evaluated (OQ-07).

## Decision

**Nodkey-Grant v1**, restricted COSE_Sign1 (research 02 §4), with these revisions:

- Envelope: tag 18, 4-element array; protected header exactly `{1: -19, 4: kid, 16:
  "application/nodkey-grant+cbor"}`; empty unprotected header; 64-byte signature.
- **Ed25519** (−19), `verify_strict`; algorithm fixed by the `kid` trust-store entry.
- Payload: deterministic CBOR, Nodkey-private integer keys, unknown keys rejected at every level.
- Domain separation: fixed `typ`, `"Signature1"`, `external_aad = "nodkey.grant.v1" ‖ 0x00 ‖ aud`, one
  key per purpose and issuer (the gateway's authority is the only issuer in v0). Read grants (ADR-0003 §7)
  require an amendment to this ADR: grant-kind field, `use` semantics, `ops` set.
- Verification order per 02 §4.3; any failure is a generic deny.
- **Payload changes vs 02 §4.2:**
  - `con` carries the **exact value** for every `exact` parameter and the ceiling for every `bounded`
    one (ADR-0003); a grant lacking a value for an `exact` parameter is denied.
  - Key 15 `epo` **removed**: revocation is a broker-side *revoked-before* timestamp per `(ten)`,
    `(ten, wid)`, `(ten, sub)`; deny if `iat < revoked_before`, checked in the consuming transaction
    (AR-09). Key 15 reserved.
  - Key 16 `rqh` **removed** in v1: redundant with exact `con` (AR-08). Key 16 reserved.
  - `max_ttl` default **30 s** (`exp − nbf`), per research 04 §10; a route may declare a longer TTL
    only with a written reason.
- **Sourced vs checked (AR-17):** `sub` and `ten` have no independent source at the broker; they are
  *sourced* from the verified grant (the signature is the trusted fact). *Checked* fields are: `aud`
  vs broker id, `wid` vs socket identity, `iss` vs kid, time vs broker clock, `op`/`opv` vs registry,
  `res`/`con` vs submitted params; `ten` is then enforced in every query.
- No attenuation, delegation, `cnf`. New algorithms only as protocol v2. PHP SDK treats grants as
  opaque.

## Evidence

RFC 9052, 9596, 9864, 8949 §4.2, 8725; `ed25519-dalek` 3.0.0 docs (research 02); review AR-08, AR-09,
AR-17, AR-20 (format closes known confusion classes).

## Consequences
- **Advantages:** wrong-audience grants fail cryptographically; no authority-side revocation state.
- **Drawbacks:** hand-written strict verifier needs fuzzing and a second implementation for vectors.
- **Security:** integrity and binding only, never authorization (SI-04).
- **Performance:** one Ed25519 verification per effect [H].
- **Compatibility:** any COSE library can produce conforming grants.

## Reversal / migration

Codec swap (PASETO, fixed-field, or an OQ-07 outcome) keeps payload semantics; `typ`/`ver` versioned,
no downgrade.
