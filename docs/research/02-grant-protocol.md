# 02 — Grant representation and protocol mechanics (OQ-05)

> [!NOTE]
> Status: **research note** (2026-10-24). Ranks below accepted ADRs and specs. Nothing here is a
> decision until an ADR accepts it. Labels used throughout:
> **[F]** established fact, with a primary source in [References](#references);
> **[O]** observed by this note's author on the stated date (crates.io / GitHub API queries);
> **[H]** hypothesis or engineering judgement, not yet validated by a test or review.

## 1. Problem statement

A trusted **Authority** issues a grant. The untrusted **workload** carries it to a trusted
**Broker**, which runs a typed protected effect such as `ledger.refund{order, amount_cents <= X}`.
Before any effect, the Broker must check issuer, audience, workload binding, tenant, subject,
operation, resource, constraints, validity window, and single use. These checks implement SI-05
through SI-09, plus SI-10, SI-11 and SI-15. The workload, possibly running attacker code (actors C
and D), must not be able to forge, broaden, substitute or replay a grant. Broker and issuer are
written in Rust. The PHP SDK only carries the grant as opaque bytes.

## 2. Is a workload-held grant necessary? (critical analysis)

Start with a plain fact: **a signature proves integrity and origin. It does not prove
authorization** (owner directive; SI-04, SI-13). A grant only adds value when it carries a decision
the Broker cannot rebuild from its own trusted facts at the moment of the effect.

**The baseline without a grant [H].** The gateway authenticates the end user and forwards a
verified identity. The isolation layer gives the workload's identity at transport level (mTLS
SVID, or a per-workload Unix socket with `SO_PEERCRED`). The Broker evaluates policy over
(workload, subject, tenant, op, resource, request) against current state in its own transaction.
This satisfies SI-10/SI-11 directly, makes SI-05 trivial (nothing to forge), and needs no
signature format, key distribution or token-replay store (idempotency keys are still needed).

So **if the Authority and the Broker are the same process, or share a database, a bearer grant
is mostly ceremony.** It adds parsing attack surface and a second source of truth that can
disagree with policy.

**When signed grants do add value [H, argued]:**
1. **Authority separated from Broker.** The decision depends on facts the Broker lacks (end-user
   approval, step-up auth, human approval over a threshold); the grant carries it across the
   untrusted workload.
2. **Decision time ≠ effect time.** Approve now, execute later in a queue; the grant pins what was
   approved.
3. **Offline verification.** No Authority call per request.
4. **Attenuation/delegation** to sub-workers or agents.
5. **Audit.** Each effect ties to an Authority-signed record (which does not prove intent).

**Alternative: reference handles [H].** The Authority stores the decision and gives the workload
a random 128-bit handle; the Broker looks it up over a back channel and consumes it atomically.
Single use, instant revocation, no crypto parsing; but the Authority must be online (conflicts
with value 3). This is the OAuth reference-token vs self-contained-token trade-off
(RFC 7662 introspection) [F].

**Conclusion [H].** In PBE the grant must be **necessary, never sufficient**. The Broker computes
`effect_allowed = verify(grant) ∧ policy(trusted facts, request) ∧ state_preconditions`. The
grant sets an upper bound and the Broker's policy narrows it further; neither can widen the other.
For the containment PoC (Demo 1), use the baseline with no grant. Demo 2 explicitly requires signed
operation-specific authorization, which is justified by values 1, 2 and 5. Keep reference handles
as a documented deployment option. Do **not** add attenuation (value 4) in v1: no use case
currently needs it, and it is the main source of complexity in Biscuit and Macaroons.

## 3. Candidates

### 3.1 Comparison table

| Option | Integrity primitive | Attenuation | Workload binding | Replay | Ambiguity risk | Rust maturity (as of 2026-10-24) | Fit for PBE v1 |
|---|---|---|---|---|---|---|---|
| **Biscuit** v3 | Ed25519 or P-256 signature chain per block [F] | Yes: offline, Datalog checks; any holder can append blocks [F] | Through Datalog facts or third-party blocks; no native PoP [F/H] | Revocation IDs only; no single-use mechanism [F] | Low at the encoding level (protobuf, signed bytes). High at the semantic level (Datalog policy correctness) [H] | `biscuit-auth` 6.0.0, released 2025-07-16, no release in 15 months; repo moved to `eclipse-biscuit`, last push 2026-10-08; depends on `ed25519-dalek ^2`, `prost 0.10` [O]. Advisory GHSA-p9w4-585h-g3c7 / CVE-2024-41949 (third-party block key confusion) [F] | Strong if delegation is needed later. Too much for v1 |
| **Macaroons** | HMAC-SHA256 chain [F] | Yes: first- and third-party caveats [F] | Through caveats [F] | None built in [F] | Caveat language is application-defined and not standardized [F] | `macaroon` 0.3.0 (2022-10-13), repo last push 2023-01 [O] | **Reject.** The verifier must hold the root HMAC key, so whoever verifies can mint grants. That merges Broker and Authority keys [F/H] |
| **PASETO v4.public** | Ed25519 over PAE(header, msg, footer, implicit) [F] | No | The *implicit assertion* can bind the audience or workload ID without sending it [F] | `jti` claim only; store is up to the application [F] | Low: algorithm fixed per version, no `alg` header [F]. JSON claims (duplicate keys, number precision) [H] | `pasetors` 0.8.1 (2026-08-30), active; single maintainer [O] | **Acceptable runner-up** |
| **COSE_Sign1 / CWT** (RFC 9052, 8392) | Ed25519 (alg −19, RFC 9864) over `Sig_structure` [F] | No | `cnf` claim (RFC 8747) [F] | `cti` claim; store is up to the application [F] | Medium: header maps and protected/unprotected duplication need a strict profile [F/H] | `coset` 0.4.2 (2026-03-02, Google), pre-1.0, built on `ciborium` 0.2.2 (last release 2024-01) [O]. Ed25519 = −19 is in coset `main` [O] | **Recommended, with a restricted profile** |
| **JWS / JWT** | many algorithms [F] | No | `cnf` (RFC 7800), DPoP [F] | `jti` [F] | High: `alg` confusion, `none`, cross-JWT confusion (RFC 8725 §2) [F]; real Rust bug: `jsonwebtoken` < 10.3.0 skipped `nbf`/`exp` checks on mistyped claims, CVE-2026-25537 [F] | `jsonwebtoken` 11.1.0 (2026-09-16), active [O] | **Reject** for grants; too many ways to get verification wrong |
| **Custom envelope**: deterministic CBOR (RFC 8949 §4.2) or fixed-field binary + Ed25519 | Ed25519, `verify_strict` [F] | No | Field + transport identity [H] | `jti` + store [H] | Lowest if fixed-field. Everything is our own spec and needs review [H] | `ed25519-dalek` 3.0.0 (2026-07-06), active; RUSTSEC-2022-0093 fixed in ≥ 2 [O/F] | Viable fallback if the COSE profile is still too loose |
| **DPoP** (RFC 9449) | per-request JWS by a holder key [F] | n/a | Proof of possession of a holder key [F] | `jti` per proof, server-side store, nonces [F] | Inherits JWS pitfalls [F] | n/a | Not suitable for PBE workload binding (see §3.3) |
| **RFC 9421 HTTP Message Signatures** | signature over selected HTTP components [F] | n/a | Holder key [F] | `created`/`nonce` parameters; store is up to the application [F] | Component selection and canonicalization [F] | several young crates [H, not surveyed] | Not needed. Use it only if the Broker is reached over HTTP across a trust boundary without mTLS |
| **SPIFFE SVIDs** | X.509-SVID (mTLS), JWT-SVID [F] | n/a | **Transport identity**, which is the right layer [F/H] | JWT-SVIDs are bearer tokens and replayable; the spec advises audience restriction [F] | — | SPIRE is a CNCF graduated project [F] | **Use for workload identity**, not as the grant itself |

### 3.2 Notes per candidate

**Biscuit [F].** An authority block plus blocks the holder can append, each signed with the next
key in a chain. The spec defines Datalog checks and policies, revocation identifiers, sealed
tokens, and third-party blocks. Attenuation is cryptographically sound: appended blocks can only
add checks. Costs [H]: authorization logic in Datalog split between token and authorizer; delegation features
already produced a key-confusion bug (2024 advisory); no help with single use (SI-09); slowed
releases [O]. **Revisit if delegation becomes a requirement.**

**PASETO v4.public [F].** Version-locked Ed25519 with no algorithm negotiation, and
Pre-Authentication Encoding (PAE) that removes concatenation ambiguity. The optional footer is
authenticated but not encrypted; PASERK defines key IDs. The implicit assertion lets the verifier
supply a value, such as `aud || wid`, that is covered by the signature but not sent. That is a
neat binding mechanism. Drawbacks [H]: JSON claims (duplicate keys, 2^53 integer limit, Unicode IDs), so strictness
depends on correct `serde` configuration. Fully defensible if reviewers prefer it.

**COSE_Sign1 [F].** `COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr/nil,
signature: bstr]`, CBOR tag 18. The signature covers
`Sig_structure = ["Signature1", body_protected, external_aad, payload]` (RFC 9052 §4.4), and
`external_aad` adds application-chosen context without sending it. RFC 9052 §3 forbids a label
appearing in both the protected and unprotected headers. RFC 9596 defines the COSE `typ` header
(label 16) for explicit typing. RFC 9864 deprecates the polymorphic `EdDSA` (−8) and assigns
`Ed25519` = −19. CWT (RFC 8392) defines claim keys (iss 1, sub 2, aud 3, exp 4, nbf 5, iat 6,
cti 7). Main risk [H]: general COSE libraries accept far more than PBE needs, so the §4 profile accepts
**exactly one shape**.

**JWT [F].** RFC 8725 lists algorithm substitution, `none`, HMAC/public-key confusion and
cross-JWT substitution; the 2026 `jsonwebtoken` CVE is a fail-open claim check in Rust.

**Ed25519 details [F].** `ed25519-dalek` 3.0.0 `verify_strict` rejects non-canonical `s` (all
verify functions do), rejects `R` with small-order components, and rejects weak (low-order) public
keys. Plain `verify` does not reject `R` torsion. `VerifyingKey::from_bytes` follows ZIP-215
decoding, and the docs warn that non-canonically encoded keys compare unequal. RUSTSEC-2022-0093
(double public-key signing oracle) affected `ed25519-dalek` < 2. Ed25519 signatures are
deterministic, but **signature bytes must not be used as a unique ID** [H]: malleability is closed
only by strict verification, and `jti` is the defined identifier.

### 3.3 Workload binding: proof of possession does not help against the main attacker

DPoP (RFC 9449) and RFC 9421 bind a token to a key the *holder* controls. In PBE the holder is
the workload, and actors C and D own its memory. **A PoP private key held by a compromised
workload gives no protection against that workload [H, follows from the threat model].** PoP only
stops a *different* party from using a stolen grant (leaked logs, another workload, a network
observer). The binding that matters is **transport-level identity that the isolation layer
assigns and the workload cannot choose**:
- an mTLS X.509-SVID whose private key is held outside the workload (e.g. a sidecar) [H: needs a
  deployment profile]; or
- `SO_PEERCRED` / a dedicated per-workload Unix socket mounted only into its namespace [H].

The Broker requires `grant.wid == transport_identity`, blocking cross-workload use (SI-06) with no
key in the workload. An SVID key inside the workload is stealable by D: a weaker, DPoP-equivalent
profile that must be labeled as such.

## 4. Recommendation (v1 draft)

**Recommendation [H].** A **restricted COSE_Sign1 profile**, "PBE-Grant v1":
- signed with Ed25519 (COSE alg −19), verified with `ed25519-dalek` `verify_strict`;
- the payload is a **deterministic-CBOR map with small integer keys**, using PBE-private claim
  numbering. CWT claim numbers are not reused, to avoid partial CWT-library interpretation;
- issued by the Authority;
- verified by the Broker with a **hand-written strict validator**. `coset` may be used for
  encoding on the issuer side and for cross-checking in tests.

Preferred over PASETO for its integer-native binary payload, a structure reviewers know, and
`external_aad`. Fallback if the profile proves too loose: a fixed-field binary envelope signed over
`"PBE-GRANT-v1\0" || body`, same fields.

Rule: **the PHP SDK never parses grants**. It treats them as opaque base64url strings with a
length cap.

### 4.1 Envelope (wire)

`grant = base64url_nopad( CBOR tag 18 ( [ protected, {}, payload, signature ] ) )`

| Element | Rule |
|---|---|
| Tag | Exactly tag 18 (COSE_Sign1_Tagged); untagged input is rejected |
| Array | Definite length, exactly 4 elements |
| `protected` | bstr; decodes to a map with **exactly** keys `{1: -19, 4: kid (bstr, 16 bytes), 16: "application/pbe-grant+cbor"}` in deterministic order; no other labels (so no `crit`, no `x5chain`) |
| `unprotected` | Must be the empty map `{}` (0xA0) |
| `payload` | bstr, non-nil (no detached payload), ≤ 2048 bytes |
| `signature` | bstr, exactly 64 bytes |
| `external_aad` | Fixed `"pbe.grant.v1"` ‖ `0x00` ‖ broker audience ID (UTF-8). The Broker supplies it, so a grant for another audience fails *cryptographically*, in addition to the field check |

### 4.2 Payload fields (draft)

| Key | Name | Type | Rule |
|---|---|---|---|
| 0 | `ver` | uint | Must equal 1 |
| 1 | `iss` | tstr ≤ 128 | Must equal the issuer registered for `kid` (key-bound issuer) |
| 2 | `aud` | tstr ≤ 128 | Single value; must equal this Broker's ID |
| 3 | `jti` | bstr, 16 bytes | CSPRNG; consumption key `(iss, jti)` |
| 4 | `iat` | uint (s) | ≤ now + skew |
| 5 | `nbf` | uint (s) | ≤ now + skew |
| 6 | `exp` | uint (s) | > now − skew; `exp − nbf ≤ max_ttl` (Broker config, default 300 s); `nbf ≥ iat` |
| 7 | `wid` | tstr (SPIFFE ID) | Must equal the transport-authenticated workload identity |
| 8 | `ten` | tstr ≤ 128 | Must equal the tenant derived from trusted facts (gateway / workload registration) |
| 9 | `sub` | tstr ≤ 256 | Must equal the gateway-verified subject on the request context |
| 10 | `op` | tstr, ASCII `[a-z0-9_.]{1,64}` | Must name a registered typed operation |
| 11 | `opv` | uint | Operation schema version; must be supported |
| 12 | `res` | map (per-op schema) | Exact match against request resource fields (e.g. `{0: order_id}`) |
| 13 | `con` | map (per-op schema) | Constraints; e.g. `{0: amount_cents_max (uint), 1: currency (tstr, ISO 4217)}`. Every key required by the schema; unknown keys rejected |
| 14 | `use` | uint | 1 = single-use. **v1 accepts only 1** |
| 15 | `epo` | uint | Revocation epoch for (`ten`, `wid`); must be ≥ the Broker's current epoch |
| 16 | `rqh` | bstr 32, optional | SHA-256 of the canonical request, when the grant authorizes one exact request |

Reserved, and **rejected in v1**: `cnf` (PoP key) and delegation chains.

### 4.3 Parsing and verification order (all failures are a generic deny; detailed reason goes to the audit log only)

1. Enforce the length cap (≤ 4096 bytes encoded) **before** decoding. Use strict base64url
   (no padding, no whitespace, canonical final bits).
2. Run a **bounded structural decode** of the envelope. Reject indefinite lengths, nesting depth
   > 4 in the envelope, trailing bytes, any tag other than the outer 18, non-minimal integer or
   length encodings, duplicate map keys, and non-deterministic key order (RFC 8949 §4.2.1).
   Implementation: decode, re-encode deterministically, and **byte-compare to the input**; reject
   on any difference.
3. Check `protected` is exactly the allowed map. Look `kid` up in the trust store (§6). An unknown
   `kid` is denied. The trust-store entry fixes alg = Ed25519, `iss`, purpose = `grant`, and the
   key's validity window. **The algorithm comes from the key entry, never from the token**; the
   header `alg` must simply equal it.
4. Build `Sig_structure` from the **received** `protected` and `payload` bytes plus the
   Broker-supplied `external_aad`, then call `verify_strict`. The key was checked against `is_weak`
   at load time.
5. Only after the signature verifies, decode `payload` with the same strictness as step 2. Also
   reject floats, simple values other than none, tags, negative integers where uint is required,
   non-UTF-8 text, text outside the allowed character set, and unknown keys at any level.
   Required keys must be present.
6. Run the semantic checks in §4.2 against **trusted facts**: transport `wid`, gateway `sub`/`ten`,
   Broker `aud`, clock.
7. Check the request against the grant: `op`/`opv` equal; each `res` field equals the request
   field; the request satisfies `con` (e.g. `amount_cents ≤ amount_cents_max`, currency equal);
   `rqh` (if present) equals the hash of the canonical request.
8. Run Broker policy and state preconditions (SI-10, SI-11), then **consume `jti` and run the
   effect in one transaction** (§5).

Comparisons on identifiers are byte-exact. No case folding, trimming or Unicode normalization;
IDs are restricted to ASCII.

## 5. Replay prevention and at-most-once (SI-09, SI-15)

**Internal effects (Broker-owned DB, e.g. the simulated ledger) [H, standard practice]:**
- Table `consumed_grant(iss, jti PRIMARY KEY, exp, request_hash, outcome, receipt)`.
- In **one serializable DB transaction**: `INSERT` the consumption row (a unique violation means
  replay: deny, or return the stored outcome if `request_hash` matches; see idempotency below),
  re-check state preconditions, write the effect, then commit. Since consumption and effect commit
  together, a crash leaves both or neither.
- Durability: synchronous commit / fsync on. If the store is unavailable, deny (SI-15). Never keep
  the replay set in memory only. A restart must not reopen the replay window.
- Retention: rows may be pruned after `exp + skew` (the grant can no longer pass `exp`), assuming
  bounded `max_ttl` and a Broker clock that never jumps backwards (documented assumption) [H].
- Concurrency: the unique constraint is the arbiter; N parallel submissions yield one commit.

**Idempotency vs replay [H].** A legitimate client retry after a timeout looks like a replay.
Rule: the idempotency key is the `jti` (or a client key scoped to `(wid, jti)`). A resubmission
with the **same canonical request hash** returns the stored outcome without running the effect
again. A different request hash under the same key is denied and logged. This mirrors the IETF
`Idempotency-Key` draft (still an Internet-Draft as far as known).

**External effects (Q12: ambiguous outcomes) [H].** No transaction spans the Broker and an
external API. Use a durable state machine in the Broker DB:
`RESERVED → DISPATCHED → {SUCCEEDED | FAILED | UNKNOWN}`.
1. Commit `RESERVED` (this consumes `jti`) before any network call.
2. Commit `DISPATCHED` with an upstream idempotency key derived from `jti`, for example
   `HMAC(broker_key, "pbe.idem.v1" ‖ iss ‖ jti)`. That keeps the key stable without revealing the
   `jti` upstream.
3. On timeout, reset or 5xx: mark `UNKNOWN`. **Never** move UNKNOWN to FAILED, or retry, unless
   the upstream documents idempotency-key deduplication over a window longer than the retry
   horizon (SI-15). Otherwise resolve by **reconciliation**: query upstream state by the
   idempotency key or a reference, or escalate to an operator.
4. A crash recovered in `RESERVED` is safe to fail. A crash in `DISPATCHED` is `UNKNOWN`.
5. The workload sees `unknown`; a re-issue needs a fresh Authority decision, which should check
   for pending UNKNOWN operations on the resource [H, open].

## 6. Key management, rotation and revocation (Q11)

**Trust store [H].** The Broker loads, from an admin-only path (SI-13, SI-14), entries of the form
`kid → {public_key, alg=Ed25519, iss, purpose=grant, not_before, not_after, status}`.
`kid = SHA-256("pbe.kid.v1" ‖ 0x00 ‖ pubkey)[0..16]`. The kid is derived from the key and never
chosen by the issuer, so one kid cannot name two keys. Keys are rejected at load if they are weak,
non-canonically encoded, or duplicated.

**Separation [H].** One key per purpose (grant, receipt, admin) and per issuer; signing keys live
only in the Authority's trust domain (SI-05). HSM/KMS optional; a labeled file key suffices for the PoC.

**Rotation [H].** (1) Add the new public key to the Broker trust store; (2) switch the Authority to
sign with it; (3) keep the old key `verify-only` for ≥ `max_ttl + skew`; (4) remove it. Short TTLs
mean no in-flight grant outlives the overlap.

**Revocation [H].** Three levels: **short TTL** (default ≤ 300 s) bounds exposure; **epoch
counters** per `(ten, wid)` (optionally `sub`) revoke all outstanding grants in a scope with O(1)
state; **key revocation** (status `revoked`) handles issuer compromise. Per-`jti` denylists are
unnecessary because consumption already enforces single use.

**In-flight operations [H].** The consuming transaction is the decision point: revocation committed
before it denies; after it, the committed effect stands. Revocation and epoch checks therefore run
*inside* that transaction (SI-11). An external effect already DISPATCHED cannot be recalled; state
this publicly and leave compensation to workflow design (Demo 3).

## 7. Domain separation and algorithm agility (rules)

1. **Typed signing contexts [F/H].** COSE context `"Signature1"`, protected `typ`
   `application/pbe-grant+cbor`, `external_aad` `"pbe.grant.v1" ‖ 0x00 ‖ aud`, and per-purpose
   keys all apply. Any other PBE signed object differs in `typ` and aad and always uses another key.
2. **Version locks the algorithm (PASETO model) [F for PASETO; H for PBE].** v1 = Ed25519 only.
   A new algorithm (e.g. ML-DSA, once standardized COSE identifiers and maintained Rust crates
   exist) is introduced as **protocol v2** with its own `typ`/aad, never as a new value in v1.
3. **The key determines the algorithm.** The verifier never selects an algorithm from attacker
   input (RFC 8725 §3.1).
4. **No downgrade.** Accepted versions are an explicit config list; no "try the next" fallback.
5. **Hash and ID derivations carry labels.** Every hash or HMAC used for IDs is prefixed with a
   unique ASCII label and `0x00` (`pbe.kid.v1`, `pbe.idem.v1`, `pbe.rqh.v1`).

## 8. Required adversarial test vectors

Each vector is a committed file with expected `DENY:<reason-class>` or `ACCEPT`, cross-checked by
an independent second implementation where possible [H].

**Envelope / encoding**
1. Untagged COSE_Sign1; wrong tag (17, 98, 61); tag nested twice.
2. Array of length 3 or 5; indefinite-length array, map or bstr.
3. Non-empty unprotected header; `alg`, `kid` or `typ` placed in the unprotected header; a label
   in both headers.
4. Extra protected label (`crit`, `x5chain`, unknown int); missing `typ`; wrong `typ`; alg −8
   (polymorphic EdDSA), alg −7 (ES256), alg 0 / absent.
5. Detached payload (nil); payload > cap; envelope > cap; trailing bytes after the item.
6. Non-minimal integer or length encodings; non-deterministic key order; duplicate keys (first or
   last occurrence valid).
7. Base64 variants: padding, standard alphabet, whitespace, non-canonical trailing bits.
8. Deep nesting / CBOR bombs (huge declared lengths) must fail without allocating the declared size.

**Signature / key**
9. Valid signature with one bit flipped in each of: protected, payload, signature.
10. `s ≥ ℓ` (non-canonical scalar); `R` with a small-order component (passes `verify`, fails
    `verify_strict`); small-order public key; non-canonical public-key encoding.
11. Unknown `kid`; known `kid` with a different key's signature; `kid` from a `revoked` or
    `receipt` purpose key; key outside its validity window.
12. A grant signed for audience B presented to broker A (fails through `external_aad`).
13. Cross-type confusion: a receipt or other PBE object signed with the right key type but the
    wrong `typ`/aad.

**Payload / semantics** (each one valid-signed by the real issuer key unless noted)
14. Each required field missing, in turn; an unknown top-level key; an unknown key inside `res` or
    `con`.
15. Wrong types: `exp` as tstr or float (the CVE-2026-25537 class), negative ints, `jti` of 15 or
    17 bytes, non-UTF-8 strings, non-ASCII lookalike IDs (Unicode confusables), and NUL
    inside an ID.
16. `ver` = 0 or 2; `use` = 0 or 2; unsupported `opv`.
17. Time: expired; `nbf` in the future; `exp − nbf > max_ttl`; `nbf < iat`; skew boundary ±1 s;
    `exp` near 2^64 overflow.
18. Binding mismatches, each a separate vector: `iss` ≠ the issuer of the kid, `aud`, `wid`
    (grant for workload A presented over workload B's channel), `ten`, `sub`, `op`, `res.order`,
    `currency`.
19. Constraint broadening: `amount = max + 1`; amount exactly max (ACCEPT); amount overflowing
    u64 in the request; the request carries extra fields the schema does not define.
20. Stale epoch; epoch incremented between verification and commit (must deny inside the
    transaction).

**Replay / concurrency / failure** (integration tests, not static vectors)
21. Same grant submitted twice sequentially; N = 64 concurrently; exactly one commit.
22. Replay after a Broker restart; replay after the replay store is restored from backup (must
    document the result); replay store unavailable → deny.
23. Same idempotency key with a different request hash → deny; with the same hash → original
    outcome, no second effect.
24. External effect: timeout after dispatch → `UNKNOWN`, no automatic retry; crash in
    `RESERVED` vs `DISPATCHED`.
25. Revoked key / incremented epoch with an in-flight request (ordering both ways).
26. Clock moved backwards on the Broker (expected behavior must be specified, then tested).

**Positive controls**: at least one ACCEPT vector per operation schema; a rotated-key overlap
ACCEPT.

## 9. Open items for ADR

- ADR: COSE_Sign1 profile vs PASETO v4.public vs fixed-field binary (independent review of §4.3).
- ADR: grant required only for Native Effect Authorization mode; Legacy Containment uses broker
  policy without grants (§2).
- Whether `coset`/`ciborium` is used on the verify path at all, or only a minimal hand-written
  strict decoder. `ciborium` has had no release since 2024-01 [O]; `minicbor` is actively released
  [O]. Decide after a fuzzing spike.
- Workload-identity deployment profile: where the SVID key lives (§3.3).
- Delegation/attenuation: deferred. Biscuit is the candidate if it becomes needed.

## References

Primary standards (IETF, rfc-editor.org / datatracker.ietf.org):
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA).
- RFC 8392 — CBOR Web Token (CWT).
- RFC 8725 — JSON Web Token Best Current Practices.
- RFC 8747 — Proof-of-Possession Key Semantics for CWTs. RFC 7800 — PoP Key Semantics for JWTs.
- RFC 8949 — CBOR, §4.2 Deterministic Encoding.
- RFC 9052 — COSE: Structures and Process (§3 headers, §4.2 COSE_Sign1, §4.4 Sig_structure). RFC 9053 — COSE Initial Algorithms.
- RFC 9596 — CBOR Object Signing and Encryption "typ" Header Parameter.
- RFC 9864 (Oct 2025) — Fully-Specified Algorithms for JOSE and COSE (Ed25519 = −19; deprecates EdDSA −8). https://datatracker.ietf.org/doc/html/rfc9864
- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP).
- RFC 9421 — HTTP Message Signatures.
- RFC 7662 — OAuth 2.0 Token Introspection (reference tokens).
- draft-ietf-httpapi-idempotency-key-header — The Idempotency-Key HTTP Header Field (Internet-Draft; status to re-check).

Specifications and projects:
- Biscuit specification and docs: https://doc.biscuitsec.org ; repo https://github.com/eclipse-biscuit/biscuit-rust (redirected from `biscuit-auth/biscuit-rust`, observed 2026-10-25 UTC).
- Biscuit advisory GHSA-p9w4-585h-g3c7 / CVE-2024-41949, "Public key confusion in third party block".
- Birgisson et al., "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud", NDSS 2014.
- PASETO specification (v4, PAE, implicit assertions) and PASERK: https://github.com/paseto-standard/paseto-spec
- SPIFFE specifications (SPIFFE ID, X.509-SVID, JWT-SVID): https://github.com/spiffe/spiffe/tree/main/standards
- `jsonwebtoken` advisory GHSA-h395-gr6q-cpjc / CVE-2026-25537 (fixed in 10.3.0).
- `ed25519-dalek` 3.0.0 `VerifyingKey` docs (verify_strict, is_weak, ZIP-215): https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/struct.VerifyingKey.html ; RUSTSEC-2022-0093.

Observations [O]: crates.io API `/api/v1/crates/<name>/versions` and GitHub API, queried 2026-10-24/25 (values in §3.1). No RustSec entries found for biscuit-auth, coset, pasetors, jsonwebtoken, macaroon, ciborium.
