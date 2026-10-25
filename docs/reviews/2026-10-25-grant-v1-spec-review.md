# Review: Nodkey-Grant v1 spec (Draft 1) and vector set

- **Date:** 2026-10-25
- **Reviewer role:** adversarial reviewer (fresh context; not the author)
- **Scope:** `docs/specs/grant-v1.md` (Draft 1); `tests/vectors/grant-v1/README.md` and `manifest.json`
  (vector list, operations, constants). Context: ADR-0004 incl. Amendment 1, ADR-0003 Phase 3 profile,
  ADR-0006 §4, SECURITY_INVARIANTS SI-05..SI-09, SI-19, SI-20.
- **Not reviewed in depth:** the generator/checker code (two spot checks only, cited below). Nothing was
  executed; no test results are claimed.
- **Method:** time-boxed protocol review: I read the spec and looked for points where two independent
  implementers could disagree, where a role or audience could be confused, or where an invariant fails.

## Verdict

**Approve with changes.** The envelope, header, CBOR profile, algorithm pinning, audience-bound
`external_aad`, derived kid and strict signature rules are sound. The negative vectors for them are
thorough. I found no signature-substitution, algorithm-confusion or cross-audience bypass. Two
**High** findings must be resolved before the spec moves past Draft (owner rule: unresolved High
blocks the milestone):

- **GS-01:** the time window is not bounded from issuance.
- **GS-02:** the spec, inheriting ADR-0006 §4, lets a verified-and-denied write grant later produce an
  effect. That contradicts SI-09's falsification clause.

The Medium findings are mostly ambiguities that an independent implementer could resolve two ways.
Most of them need a new vector.

## Findings

Severity: Critical / High / Medium / Low. "Vector" = needs a new conformance vector.

### GS-01 — High — §5.1 keys 4–6, §7.2 step 8, §8.4, §9: validity window is unbounded relative to `iat` and `now`; future-dated grants evade TTL and revocation

**Issue.** The only time constraints are `nbf ≥ iat`, `exp > nbf`, `exp − nbf ≤ max_ttl`, and the
window check against `now`. Nothing bounds `nbf − iat`, `iat − now`, or `nbf − now`. An issuer can
therefore produce a grant with `iat = T`, `nbf = T + 1 year`, `exp = nbf + 30`. The broker accepts it
for 40 s one year later. ACC-05 already accepts `iat < nbf`. The issuer here could be a compromised
edge, if the authority signs times the edge supplies ("signs whatever the edge asks", ADR-0003 §1), or
an issuer with a clock error. Consequences:

1. ADR-0003's claim that edge compromise "ends when the edge is fixed (no key theft)" fails. Grants
   minted during the compromise for future windows stay valid after the fix, until each affected
   tenant or subject is revoked or the key is rotated.
2. Revocation can be evaded. Step 13 denies iff `iat < revoked_before`. A grant whose `iat` is also
   future-dated (`iat = nbf`) is not revoked by a `revoked_before` row written now. Only key
   revocation stops it.
3. §8.4's statement "Because TTLs are short, no in-flight grant outlives the overlap" is false as
   written. It holds only because the old key's `not_after` is enforced at 4d, not because of the TTL.
4. The Phase 3 profile item "write grant (TTL ≤ 30 s)" and ADR-0003 "TTL 30 s, from now" are measured
   from issuance. The spec measures `max_ttl` from `nbf`.

**Fix.** Add these checks to step 8, with vectors:

- (a) `iat ≤ now + skew`. A future-dated issuance → `grant_time_invalid` (or a new
  `grant_issued_in_future`).
- (b) `nbf − iat ≤ skew`, or equivalently require `exp − iat ≤ max_ttl + skew`, so the lifetime is
  measured from issuance.

Also state in §9 that the authority sets `iat`/`nbf`/`exp` from its own clock and never from values the
edge supplies. Correct §8.4's rationale.

**Vector:** yes (future `iat`; `nbf` far beyond `iat`; boundary `nbf − iat = skew` / `skew + 1`;
revocation of a future-`iat` grant).

### GS-02 — High — §7.3 (and ADR-0006 §4): denial recording outside the effect transaction violates SI-09

**Issue.** A verified write grant denied at step 10, 11 or 13, or by a step-14 precondition, is
recorded as `DENIED` "in a separate short transaction if no row exists yet. If that write fails, the
response is still a denial." SI-09 is falsified by "a verified-and-denied grant later producing an
effect". Two paths do exactly that:

1. **DENIED write fails.** For example, a lock timeout or a transient store error happens after the
   denial has been decided. The workload has received a denial, but no row exists. A later submission
   of the same grant (the workload is the attacker and holds it) can then reach ACCEPT, for example
   after state changes such as a deposit or a budget reset, within the TTL.
2. **Race at step 14.** The effect transaction rolls back on a precondition failure, which removes the
   step-12 consumption row with it. Before the separate DENIED insert runs, a concurrent submission of
   the same grant inserts its own row and commits an effect. The first caller has received a denial;
   the grant has produced an effect.

The spec allows both paths. Neither has a vector; §12.2 defers concurrency to integration tests, but
the rule itself is the defect.

**Fix.**

- Step-14 denials: never roll back the consumption row. Insert `consumed_grant` first, take a
  `SAVEPOINT`, and attempt the effect. On a precondition failure, roll back to the savepoint, set
  `outcome = DENIED`, and commit. The decision and the record are then atomic.
- Step 10/11/13 denials: use the already-permitted option (§7.3 last bullet) and make it mandatory. Run
  step 12 first and record DENIED in the same transaction as the decision.
- If recording is impossible, return `unavailable` ("nothing was executed"), not `grant_denied`. The
  grant has then received no decision, and SI-09 holds.

Update ADR-0006 §4 to match.

**Vector:** yes, as a scripted integration test: inject a failure into the DENIED write, then resubmit
with a request that passes. Expected: no ACCEPT ever follows a returned `grant_denied`.

### GS-03 — Medium — §3.4, §7.1, §7.2 step 12: `broker_id` uniqueness and replay-store scope not stated

**Issue.** Audience binding and consumption both assume that one `broker_id` corresponds to one replay
store. The spec does not say so. Two broker instances with the same `broker_id` and separate replay
stores (an HA pair, a blue/green deploy, a restored replica) each accept the same write grant once.
That is two effects, which breaks SI-09. Separately, `broker_id` has no syntax rule. The `aud` check
needs it to be an ID, but nothing says so.

**Fix.** State normatively: all instances configured with one `broker_id` MUST share one replay store
and `revoked_before` table, and distinct stores MUST have distinct `broker_id`s. Also: `broker_id` MUST
satisfy the ID rule, 1–128 bytes, and the broker refuses to start otherwise.

**Vector:** no (deployment rule). It needs an integration test.

### GS-04 — Medium — §3.5 item 3, §8.3: "small-order component" check is stricter than `verify_strict` and than the reference checker

**Issue.** §8.3 requires rejecting points "of small order (identity, order 2, 4, 8, or with a small-order
component)". A point with a small-order component is a mixed-order point, `P + T` with `T` a torsion
point. `ed25519-dalek` 3.0.0 `VerifyingKey::is_weak()` is only `self.point.is_small_order()` (crate
source `src/verifying.rs:200-202`). The reference checker applies only `pt.is_small_order()`
(`tests/vectors/grant-v1/gen/src/verify.rs:110`). Three readings are therefore in play:

- the spec text (reject torsion components, i.e. `!is_torsion_free()`);
- dalek's `is_weak` (accept mixed-order keys);
- the reference checker (accept them).

These disagree, and §3.5 claims the verifier is "equivalent to `verify_strict`". A mixed-order public key
makes cofactorless and cofactored verification differ. That is a known differential between Ed25519
verifiers.

**Fix.** Pick one rule. I recommend rejecting non-torsion-free keys at load (`registry_key_weak`), since
the broker never needs them. Implement it in the reference checker and state it as an explicit
`is_torsion_free()` requirement.

**Vector:** yes (a REG vector with `A + T8`, where A is a valid key and T8 a point of order 8).

### GS-05 — Medium — §1, §6 `authority`, §8.2 `role`, D-9, ACC-08: scheduler role conflicts with SI-05 v0.3

**Issue.** SECURITY_INVARIANTS v0.3's changelog reads: "Authority = gateway signer only (scheduler
removed)". SI-05 is falsified by "broker accepting any grant not produced by the Authority's key". ACC-08
requires a conforming broker to ACCEPT a grant signed by scheduler key E. As written, the conformance
suite therefore requires behavior that falsifies SI-05. ADR-0009 has been returned for revision, and
Phase 3 has no scheduler.

**Fix.** Choose one:

- (a) Remove the `scheduler` role and the related vectors (ACC-08, OP-05/06, CON-05) from v1.
- (b) Keep them behind an explicit, default-off broker configuration flag, and make a broker refuse to
  load a `role: scheduler` entry unless the flag is set.

In both cases, add a startup rule that a `scheduler_grant` operation cannot also be
`requires_confirmation`. A scheduler can set `cfm = 1` without any user.

**Vector:** yes (a REG vector: `role: scheduler` with the flag off → load error).

### GS-06 — Medium — §6, §7.1, §5.4: which `opv` governs request parsing and `request_hash` is undefined

**Issue.** The request carries no `opv`. §7.1 says the request is "already strictly parsed" before
verification, but each `opv` may have its own parameter schema. Two implementers will diverge:

- Parse with the newest version, or with the grant's `opv`. The latter requires parsing after step 7.
- §5.4 hashes `[op, opv, …]` without saying whether `opv` comes from the grant or from the request.

A hash disagreement turns an idempotent retry (STORED_OUTCOME) into `grant_replayed`, or the reverse.

**Fix.** Either:

- (a) require that a broker declares at most one `opv` per operation in v1; or
- (b) state that request parsing uses the grant's `opv` and therefore happens after step 10c, and that
  §5.4's `opv` is the grant's.

Make §5.4 normative (MUST), not RECOMMENDED. Implementations that disagree on it produce different
step-12 decisions.

**Vector:** yes (a two-`opv` declaration, or a `request_hash` vector with expected hash bytes).

### GS-07 — Medium — §7.2 read steps 10c–10f: inconsistent whole-grant vs requested-op semantics; step 10f untested

**Issue.** Step 10c validates every `rop` entry and rejects the whole grant if any entry is a write op.
Steps 10e (opv) and 10f (role) apply only to the requested operation. These cases are left to the
implementer:

- A read grant lists `ledger.get_balance:1` and `ledger.list_transfers:9`, and the request is
  get_balance. One implementer accepts; another, extending 10c's logic, rejects.
- A scheduler-signed read grant that lists a `user_grant` read op. Role is checked per request, not
  per grant.

No vector exercises step 10f (read-path role check) at all.

**Fix.** Make every `rop` entry subject to every per-op check (declared, kind `read`, opv supported,
role matches authority) before any requested-op check. A read grant is then valid or invalid as a
whole, independent of the request. This is also simpler to reason about for SI-07.

**Vector:** yes (scheduler key E signs a read grant → `grant_issuer_not_permitted`; a non-requested
`rop` entry with an unsupported opv).

### GS-08 — Medium — §5.3, §6: parameter types and "destination-like" undefined in the spec

**Issue.** CON-17/18/19 expect `grant_op_schema_invalid` for type violations of `account_id`,
`currency` and `text64`. These types are defined nowhere in the spec. The manifest names them but gives
no grammar. An independent implementer cannot reproduce CON-18 ("eur" is invalid). §6's startup rule
"a destination-like parameter is `free` → refuse" is unimplementable without a definition of
destination-like. It is the very rule that keeps `to` from being free.

**Fix.**

- Define a closed type set in §6, each with an exact grammar: `uint` (with a range), `account_id`,
  `currency` (`[A-Z]{3}`), and `textN`. Put the same grammars in the manifest `operations`.
- Replace "destination-like" with an explicit declaration flag (`destination: true` ⇒ class `exact`),
  or rule that `free` is allowed only for types marked display-only.
- Add a startup rule: placement `res` ⇒ class `exact`. Today a `res` parameter declared `bounded` or
  `free` is not refused.

**Vector:** yes (declaration-load vectors; there are none for any §6 startup rule).

### GS-09 — Medium — §8.2–§8.5: registry strict-JSON and reload semantics

**Issue.**

1. §8.2 requires strict JSON (no duplicate members), but the README says the reference checker is not
   strict about duplicates, and no vector covers them. A registry entry with
   `"status":"revoked", …, "status":"active"` is read as revoked by a first-wins parser and as active
   by a last-wins parser. Revocation then silently depends on the JSON library.
2. The type "integer" for `not_before`/`not_after` does not say whether `1.7e9`, `1767225600.0` or a
   negative value is acceptable.
3. §8.5 revokes a key by "set status revoked and reload", but §8.2/§8.3 define only startup loading.
   Reload is unspecified: is it atomic, and what happens if the new file fails validation? If a failed
   reload keeps the old registry, the revocation never takes effect.

**Fix.**

- Require rejecting duplicate members at any depth, and fix the reference checker to do so.
- Require that integers match `0|[1-9][0-9]*` with a value ≤ 2^53 − 1.
- Specify reload: it validates the new file completely and swaps it atomically. On failure, the broker
  stops serving grant-requiring operations (fail closed) and alarms. It does not keep the old
  registry.

**Vector:** yes (duplicate `status`; float and exponent times; `not_after` = 2^53).

### GS-10 — Medium — §4 C8, §5.1 `rop`, §5.4, §9: text-key ordering trap; no vector distinguishes it

**Issue.** C8 orders keys by their encoded bytes, which for text keys amounts to length first. An
issuer using a generic library that sorts by raw string order (for example a `BTreeMap<String>` or a
JSON-style canonicalizer) emits `rop` in a different order whenever a shorter name sorts later. One
example is `"b.x"` vs `"a.long"`. Such grants fail closed (`grant_payload_malformed`), so this is not a
broadening. It does contradict §9's claim that "a generic COSE library can produce conforming grants".
It also matters for the §5.4 `request_hash` map: two broker implementations that sort differently
compute different hashes, which feeds the step-12 differential in GS-06. In ACC-09,
`ledger.get_balance` and `ledger.list_transfers` sort the same way under both rules, so no vector
detects the difference.

**Fix.** Add a sentence to C8 with an example showing that length-first ordering applies to text keys,
and qualify §9's claim.

**Vector:** yes (a valid `rop` whose two op names sort differently by length and by raw bytes, in the
correct encoded order → ACCEPT; the same grant in raw order → `grant_payload_malformed`; a duplicate
`rop` key with different opv → `grant_payload_malformed`).

### GS-11 — Medium — §2, §12.2: transport encoding has no vectors although the workload controls it

**Issue.** The base64url layer is parsed from attacker input, and common decoders differ: they may
accept padding, accept `+/`, ignore non-zero trailing bits, or tolerate whitespace. The spec defines
strict rules and error codes 1a/1b, but none of them is covered by a vector. Lenient trailing bits give
several text forms per grant. Harmless for authorization, but it breaks "one byte sequence, one
meaning" at the text layer and any text-level deduplication or logging.

**Fix.** Add a small `transport` vector file:

- canonical text → ACCEPT;
- `=` padding, `+`/`/`, embedded LF, a length ≡ 1 mod 4, non-zero trailing bits → `grant_encoding_invalid`;
- 2731 vs 2732 characters → pass the size check vs `grant_too_large`.

**Vector:** yes.

### GS-12 — Low — §5.3, §6: uint values in `res`/`con` unbounded (up to 2^64 − 1)

**Issue.** Times are capped at 2^53 − 1, but `res` and `con` uints are not. Requests arrive as JSON, and
the PHP SDK or a JS layer may round values above 2^53. For `exact` this fails closed, but for `bounded`
a rounded request could compare differently from what the user saw.

**Fix.** Cap every uint in `res`/`con`, and the `uint` request type, at 2^53 − 1 (`grant_payload_invalid`).

**Vector:** yes.

### GS-13 — Low — §8.3: no consistency rule across entries sharing `iss`

**Issue.** Keys rotated under one `iss` share the `(iss, jti)` namespace, which is intended. Nothing
stops entries with the same `iss` from having different `role`s. That would let one issuer name hold
both authorities, which defeats the point of role separation in logs and revocation.

**Fix.** Add a load check: all entries with the same `iss` have the same `role` (`registry_entry_invalid`).
Also consider rejecting, at load, a public key that appears in any other Nodkey registry the process
loads, such as receipts. Today only per-file duplicates are caught, and kid derivation uses a label
shared across purposes.

**Vector:** yes (same `iss`, two roles).

### GS-14 — Low — §7.3, §7.4: probing with unverified grants; timing

**Issue.** Unverified grants are not consumed (step 9b, RPL-04), which is correct. However, failures
before and after the signature check take measurably different times. A workload can therefore learn
whether a grant it holds is signature-valid for this broker. The value of this is low, because the
workload cannot forge grants. The client-facing code is uniform.

**Fix.** Note it as a residual in §11. No constant-time requirement is needed.

**Vector:** no.

### GS-15 — Low — §7.2 step order vs idempotent retry

**Issue.** Steps 1–9 run before step 12, so a retry after `exp + skew` returns `grant_expired`, not the
stored outcome. That is acceptable, but nowhere stated. An implementer who checks the replay store
first (permitted only for steps 10–11) might return STORED_OUTCOME after expiry.

**Fix.** State it in §7.3 and add a vector: ACCEPT, then the identical request at `now = exp + skew` →
`grant_expired`.

**Vector:** yes.

### GS-16 — Low — §7.1, D-6: is `max_ttl` configurable?

**Issue.** §7.1 says `max_ttl` = 30 s. D-6 says "default and maximum 30 s", which implies it can be
lowered. If a broker lowers it while the issuer uses 30 s, every grant is denied (fail-closed, but an
availability trap).

**Fix.** State the allowed range, and require the issuer's TTL to be ≤ the smallest configured
broker `max_ttl`.

**Vector:** no.

### GS-17 — Low — §12.1: no positive vector at the size limit

**Issue.** ENV-02 (2048 bytes) fails at step 7 because of its padding key 20, so no vector shows a
2048-byte grant being accepted. An implementer who applies `≥` at step 1c would still pass the suite.

**Fix.** Add a 2048-byte ACCEPT vector, padded with long but valid `sub` and `wid` values and `rop`
entries.

**Vector:** yes.

## Areas checked with no finding

- **Algorithm confusion:** the registry selects the algorithm, and the header only has to agree (−8,
  −7 and 0 are rejected).
- **kid substitution:** the kid is derived from the key, and the role/`iss` checks bind it (SIG-02,
  ISS-01).
- **Cross-audience reuse:** the `external_aad` uses this broker's own id; SIG-07 and ACC-07 are paired.
- **Cross-protocol reuse:** the fixed `typ`, the `Signature1` context and the aad tag are each
  vectored.
- **`aud` vs aad concatenation:** `aud` sits inside a length-prefixed bstr after a fixed tag that
  contains no NUL, so the aad is unambiguous.
- **CBOR:**
  - shortest form, definite lengths only;
  - no floats, simple values or tags, so no negative zero and no bignums;
  - negative integers banned in the payload;
  - duplicate and unsorted keys rejected;
  - depth and length checked before allocation.
- **Kind interplay:**
  - a read grant cannot authorize a write (OP-01, OP-07, OP-08);
  - a write grant cannot authorize a read (OP-09);
  - `rop` cannot broaden: it is signed (but see the coverage gap for a SIG vector on key 19);
  - `cfm` is forbidden on read grants.
- **Constraint classes:**
  - the class is signed and must equal the declaration (CON-11/12);
  - `exact` requires the same type;
  - `bounded` is inclusive (ACC-03, CON-01);
  - `free` is absent from `con` (CON-13).
- **Consumption timing for denied write grants:** a workload that holds a grant can burn it by
  submitting a wrong request. That gives it nothing it lacked, since it could simply drop the grant.
  A stolen grant used over another socket is not burned (RPL-04). Correct apart from GS-02.
- **Error oracle:** detailed codes are broker-facing only (§7.4).

## Coverage gaps (spec rules with no vector)

1. Transport §2 entirely: padding, alphabet, trailing bits, length ≡ 1 mod 4, the 2731/2732 boundary
   (GS-11).
2. Future-dated `iat` / `nbf` far beyond `iat` (GS-01; needs the new rule first).
3. Read-path step 10f (role check for read grants); a scheduler-signed read grant (GS-07).
4. Read grant with an unsupported opv on a non-requested `rop` entry (GS-07).
5. **No SIG vector for altering key 19 `rop`**: the SIG series stops at knd/cfm (SIG-37/38). One should
   add an op to `rop` after signing → `grant_signature_invalid`.
6. Duplicate `rop` key; `rop` in raw-string order versus encoded order (GS-10); `rop` with 17 entries
   (> 16); `rop` op name 65 bytes.
7. Mixed-order (torsion-component) public key at registry load (GS-04).
8. Registry: duplicate JSON member, non-integer or exponent times, time > 2^53 − 1, the same `iss` under
   two roles, `not_before > not_after` (only equality is covered by REG-13), a `kid` in uppercase
   hex (GS-09, GS-13).
9. Key window: a not-yet-active key (`now < not_before`) and the boundary `now == not_after`; only a past
   window is covered (KEY-04).
10. §6 operation-declaration startup refusals: unclassified parameter, free destination, bounded
    non-uint, duplicate placement/number, `res` declared non-exact (GS-08). There are no vectors at all.
11. Request-side type mismatch for an `exact` parameter (request `"12500"` vs grant uint 12500); only
    grant-side type errors are covered (CON-17/19).
12. A 2048-byte grant that ACCEPTs (GS-17).
13. `request_hash` expected bytes (GS-06), and a retry after expiry (GS-15).
14. ID-alphabet boundaries: 0x7F and 0x20 in an ID field; `iss`/`aud`/`ten` at 128 and 129 bytes
    (only `sub` 257 is covered); tstr values in `res`/`con` at 256 and 257 bytes; `opv` 65536.
15. Read grant missing each of keys 0–2 and 4–9 (only `jti` and `rop` are covered for read grants), and
    read grants carrying keys 11, 12 or 14.
16. Denial recording under failure and concurrency (GS-02). This needs an integration test.
17. Small-order `R` (acknowledged in §12.2). A non-canonical `R` encoding (y ≥ p) is also not
    vectored.

## Evidence

- Spec text: `docs/specs/grant-v1.md` §§2–9, 12 (line references above by section).
- ADR-0006 §4 (`docs/decisions/0006-replay-and-effect-state.md:34-37`): "records `outcome = DENIED` in a
  separate short transaction; if that write fails, the response is still Deny."
- SI-09 (`docs/SECURITY_INVARIANTS.md:85-92`): falsified by "a verified-and-denied grant later producing
  an effect".
- SI-05 (`docs/SECURITY_INVARIANTS.md:58-60`) and the v0.3 changelog (line 216: "scheduler removed").
- `ed25519-dalek-3.0.0/src/verifying.rs:200-202`: `is_weak()` returns `self.point.is_small_order()`.
- `tests/vectors/grant-v1/gen/src/verify.rs:110`: the registry load check uses `is_small_order()` only.
- `tests/vectors/grant-v1/gen/src/generate.rs:604-605`: ACC-05 uses `iat = T0 − 1`, `nbf = T0 + 1`. Any
  positive `nbf − iat` is accepted.
