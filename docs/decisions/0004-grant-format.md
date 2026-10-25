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

## Amendment 1 (2026-10-25)

Required by ADR-0003 rev. 3 (Accepted), Phase 3 implementation profile items 5–7, and specified in full
by [`docs/specs/grant-v1.md`](../specs/grant-v1.md) (Draft 1). The status of this ADR is unchanged
(Proposed; OQ-07 still open). Changes relative to the decision above:

1. **Grant kinds (new payload key 17 `knd`).** `1` = write: one write operation, single use, `jti`
   consumed in the effect transaction. `2` = read: a set of read operations in new key 19 `rop`
   (`{op name: opv}`, 1–16 entries), multi-use within the validity window, never consumed, never valid
   for a write operation; the broker checks ownership of every read resource by the grant's
   `(ten, sub)` against trusted state. Read grants omit keys 10–14 and 18. The kind is signed and the
   broker checks the operation's declared kind before dispatch.
2. **Confirmation marker (new payload key 18 `cfm`, write grants only).** `1` = the user approved the
   exact bound values on the auth origin; `0` otherwise. An operation may require it; `ledger.transfer`
   does. A grant for such an operation with `cfm = 0` is denied.
3. **`con` encoding.** Each entry is `[class, value]` with class `0` = exact, `1` = bounded (inclusive
   uint ceiling); the class must equal the broker's declaration. `free` parameters never appear in
   `con`.
4. **Sizes and limits.** Grant ≤ 2048 bytes (replacing research 02's 4096-byte envelope and 2048-byte
   payload caps); times ≤ 2^53 − 1; IDs printable ASCII without space; `max_ttl` = 30 s broker-wide for
   both kinds (the per-route longer TTL above is not supported in v1); skew ≤ 5 s.
5. **Verification order.** Research 02 §4.3 is superseded by spec §7, which fixes the order of checks
   and a broker-facing error code per step; the workload receives only `grant_denied`. A grant that
   passes the binding checks (step 9) is *verified*; denials of verified write grants are recorded so
   each grant receives one decision (ADR-0006 §4).
6. **Tenant check.** `ten` remains sourced from the grant and must additionally be one of the tenants in
   the presenting workload's registration.
7. **Key registry.** JSON file format with `kid = SHA-256("nodkey.kid.v1" ‖ 0x00 ‖ pk)[0..16]`,
   load-time rejection of weak, non-canonical, duplicate or mis-derived keys, and a `role` field
   (`user_authority` | `scheduler`) matched against the operation's authority class. The `scheduler`
   role is provisional until ADR-0009 is revised.
8. **No grantless operations** in v1: every operation requires a grant.

Unchanged: COSE_Sign1 with tag 18, the exact protected header, empty unprotected header, Ed25519 with
`verify_strict`, the `external_aad` construction, keys 0–14 and their meanings, reserved keys 15–16, and
`revoked_before` revocation.

## Amendment 2 (2026-10-25)

Specified by [`docs/specs/grant-v1.md`](../specs/grant-v1.md) **Draft 2** after the spec review
([`docs/reviews/2026-10-25-grant-v1-spec-review.md`](../reviews/2026-10-25-grant-v1-spec-review.md)) and
the independent implementer's issue list. Status unchanged (Proposed; OQ-07 open). Changes relative to
the decision and Amendment 1:

1. **Time (GS-01).** `nbf − iat ≤ skew`; lifetime measured from issuance, `exp − iat ≤ max_ttl`
   (replacing `exp − nbf`); `iat ≤ now + skew`. The Authority sets `iat`/`nbf`/`exp` from its own clock,
   never from caller-supplied values. `max_ttl` is configurable 1–30 s.
2. **One issuer role (GS-05).** Amendment 1 item 7's `role` field and the `scheduler` role are withdrawn:
   SECURITY_INVARIANTS v0.3 defines the Authority as the gateway signer only, and ADR-0009 is deferred to
   Phase 5. A second issuer role requires a new protocol version.
3. **Registry keys (GS-04).** A public key must be a canonical encoding of a point of order exactly L
   (not small order and torsion-free); mixed-order keys are rejected. Strict JSON with duplicate-member
   rejection; atomic reload that fails closed.
4. **One `opv` per operation; normative request hash (GS-06).** `request_hash` covers the requested
   operation and all request parameters, without `opv`.
5. **Write-grant decisions recorded atomically (GS-02).** Consumption is the first statement of the effect
   transaction and denials are recorded via a savepoint; see ADR-0006 Amendment 1.
6. **Operation declarations.** Closed parameter type set, explicit `destination` flag (destinations must
   be `exact`), `res` parameters must be `exact`, startup refusals enumerated.
7. **`broker_id`** is an ID, and one `broker_id` maps to exactly one replay store and revocation table.
