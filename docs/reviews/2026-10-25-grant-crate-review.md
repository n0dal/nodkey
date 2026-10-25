# Review: `crates/nodkey-grant` (commit 9851d0a) against Nodkey-Grant v1 Draft 1

- **Date:** 2026-10-25
- **Scope:** `crates/nodkey-grant/src/*.rs`, tests, `SPEC_ISSUES.md`, `README.md`, checked against
  `docs/specs/grant-v1.md` Draft 1. Spec-design findings already in
  `docs/reviews/2026-10-25-grant-v1-spec-review.md` (GS-nn) are cited, not repeated.
- **Method:** full read of the source; the existing suites run in release mode; seven extra
  adversarial tests written as a temporary integration test (kept outside the repo, file removed
  afterwards; the repo is unchanged except for this report).

## Verdict

**No Critical or High implementation defects found.** Before the signature check, the parser is
bounded and linear. It does not panic on any input tried. Signature verification uses `verify_strict`
over exactly the received `protected` and `payload` bytes. `Rejection.verified` is set only after
steps 1–9 pass. No error path returns success.

The remaining risk is at the API boundary. The crate trusts the request parameters it is given, and
it does not bind the verified grant to the request it was checked against (GC-01, GC-02, both
Medium). The broker must either get these changes or implement the obligations listed below.

The crate implements Draft 1 faithfully, so it inherits GS-01 (future-dated grants) and GS-02 (the
denial-recording race). Both need code changes when Draft 2 lands.

**Recommendation:** acceptable as the broker's verifier once GC-01 and GC-02 are fixed in the crate
(preferred) or covered by broker integration tests, and the Draft 2 deltas are applied.

## Evidence

Existing suites (`cargo test --release` in `crates/nodkey-grant`), all passing:

```
running 13 tests … test result: ok. 13 passed; 0 failed   (unit)
running 2 tests  … test result: ok. 2 passed; 0 failed    (conformance: 235 grant vectors / 246 steps, 17 registry)
running 4 tests  … test result: ok. 4 passed; 0 failed; finished in 16.05s (robustness)
running 6 tests  … test result: ok. 6 passed; 0 failed    (roundtrip)
```

The review tests (temporary file `tests/zz_review.rs`, now removed) were run with
`cargo test --release --test zz_review -- --nocapture`:

```
escaped status: Ok(1)
float not_after: Err(EntryInvalid)
exp not_after: Err(EntryInvalid)
BOM: Err(EntryInvalid)
test r7_registry_json_leniency ... ok
test r1_s_plus_l_rejected ... ok
test r4_time_extremes_no_panic ... ok
future-dated: Err(KeyInactive)
test r3_verified_grant_not_bound_to_params_for_hash ... ok
test r2_request_params_not_checked_against_declaration ... ok
test r5_future_dated_grant_accepted_later_gs01 ... ok
map-heavy envelope x10000: 88.567583ms
array-heavy envelope x10000: 76.004417ms
test r6_worst_case_pre_signature_parse_time ... ok
test result: ok. 7 passed; 0 failed
```

| Test | Asserts |
|---|---|
| r1 | Adding L to S of a valid `test.hold` grant gives `grant_signature_invalid` and `verified == None`. |
| r2 | A verified grant is **accepted** with an undeclared extra request parameter, with the declared free parameter missing, with that free parameter given the wrong type (uint for `text64`), and with a 5000-byte value full of control characters (GC-01). |
| r3 | `request_hash` can be computed over parameters other than the verified ones; nothing in the API prevents this (GC-02). |
| r4 | No panic at `now` ∈ {0, 2^53 − 1, 2^53, u64::MAX − 4, u64::MAX}, nor with all times at 2^53 − 1. |
| r5 | A grant with `iat = T`, `nbf = T + 3600` is accepted at `T + 3601` (GS-01, as Draft 1 specifies). The one-year case fails only because the test key's `not_after` has passed. |
| r6 | Worst-case envelopes of 2048 bytes before the signature check (a 1000-entry map, a 2040-element array, maximum depth with fan-out) take about 8–9 µs each and do not panic. |
| r7 | Registry: an uppercase kid gives `registry_kid_mismatch`; a duplicate key under a different `iss` gives `registry_duplicate_key`; a non-ID `iss` gives `entry_invalid`; floats, exponents and a BOM are rejected; a JSON escape in `status` is **accepted** (GC-06). |

## Checks with no finding

- **CBOR decoder** (`src/cbor.rs`).
  - Every length is checked against the remaining input before it is used (`take`, line 110). Element
    counts are checked with `saturating_mul` before `Vec::with_capacity` (`enter`, line 230), so
    allocation is at most about 40 bytes per input byte (2048-byte cap).
  - Depth is checked before recursion. Recursion is at most 4 frames.
  - Non-minimal heads, all 8-byte widths, AI 28–31, major 6 and 7, invalid UTF-8, and key order
    compared on the raw encoded key bytes are all rejected.
  - No integer arithmetic on attacker lengths can overflow. Work is linear: each key comparison is
    bounded by the key length, and each key is compared once.
- **Envelope and header** (`verify.rs:258–285`).
  - The single-byte tag `0xd2` is required, with exactly 4 items typed bstr/map/bstr/bstr and a
    64-byte signature.
  - The unprotected header must be the empty map (only `0xa0` can encode it under C2).
  - The protected header must be exactly `{1: int, 4: bstr16, 16: typ}`, matched by a slice pattern,
    with depth 1.
- **Signature binding** (`verify.rs:196–206, 305–309`).
  - `Sig_structure` is built from the received `protected` and `payload` slices. These are the same
    slices that are later parsed, so a parser differential is impossible: one byte string is both
    signed and interpreted.
  - `external_aad` uses `ctx.audience`, the same value as the `aud` check.
  - The algorithm comes from the registry entry; the header `alg` only has to match it.
  - The kid-to-key-to-iss/role binding comes from one registry entry (`entry`), so a token cannot
    choose its issuer or role.
- **Time** (`verify.rs:300–332`).
  - Payload times are capped at 2^53 − 1 in step 7b (`payload.rs:107`) before any arithmetic.
  - `exp − nbf` runs after the check `exp > nbf`.
  - `now + skew` saturates.
  - Key window: `not_before ≤ now < not_after`.
- **Payload** (`payload.rs`).
  - The key set is compared as an exact bitmask per `knd`, so reserved keys 15 and 16 and any
    key ≥ 20 are rejected.
  - 7a runs before 7b.
  - `res`/`con` keys are limited to 0..=15. Class and value types are enforced; bounded values must
    be uints.
  - `rop` must have 1–16 entries with valid op names and opv values.
- **Steps 10–11** (`verify.rs:380–502`).
  - Key sets of `res`/`con` are compared for exact equality with the declaration: both sides are
    sorted, the lengths must be equal, and keys are compared pairwise.
  - Declared types are checked for `res` and exact `con` values.
  - Comparison is type-strict (`Scalar::equals`), so uint `7` never equals text `"7"` and text is
    compared byte-exact.
  - A bounded check against a non-uint or missing request value denies.
  - Read grants reject any listed write op (10c) and check the role against the requested op.
- **`Rejection.verified`.**
  - Every failure in steps 1c–9 comes from `verify_binding` as a `GrantError`. It reaches
    `Rejection` only through `From`, so `verified` is `None` there (`verify.rs:172, 236`).
  - `Some` is set only in `authorize` failures.
  - An unverified grant cannot cause a jti to be recorded (vector RPL-04 passes).
- **Registry** (`registry.rs:122–190`).
  - `deny_unknown_fields`, with duplicate members rejected at both levels.
  - Canonical point check by re-compression. Small-order and mixed-order keys are rejected
    (`is_torsion_free`, covering GS-04 / SI-5).
  - The kid is derived and compared. A duplicate key is a duplicate kid.
  - Times are capped at 2^53 − 1 with `not_before < not_after`.
  - Revoked entries load and fail at step 4c.
- **Transport** (`transport.rs`).
  - The length cap is checked before decoding. Length ≡ 1 (mod 4) is rejected, unused bits must be
    zero, and there is no padding, whitespace or `+/`.

## Findings

### GC-01 — Medium — `src/verify.rs:416–468`, `src/ops.rs:167–175`: request parameters are not validated against the declaration

**Issue.** `verify` reads only the request parameters named by `res`/`con` declarations. It does
not check the following:

- (a) that the request contains no undeclared parameter;
- (b) that every declared `free` parameter is present;
- (c) that `free` values, and values of any parameter not compared against the grant, have the
  declared `ParamType`;
- (d) that request text is within any bound.

Draft 1 §7.1 assigns this to "the broker's strict request parser", but the crate gives the
broker no way to do it with the same `Operations` object: there is no `Operations::parse_request`.

If the broker's parser is lenient (for example, it accepts any JSON object), an attacker can send
extra or ill-typed parameters that a verified grant does not bind. Those parameters are then visible
to step 14 and the effect code. That breaks SI-06/SI-07 if the effect code reads any parameter by
name, or if the declaration and the effect code disagree about which names exist.

**Reproduction.** Review test r2: a `test.hold` grant is accepted with `to: "mallory"` added, with
`memo` missing, with `memo: 1` (uint), and with `memo` set to 5000 newlines.

**Fix.** Have `verify` (or a mandatory `Operations::validate_request(op, &Params)` whose output
type `ValidatedParams` is the only thing `VerifyContext` accepts) reject the following with a
request-level code, before step 10:

- any name not declared for `requested_op`;
- any declared name that is missing;
- any value whose type is not the declared `ParamType` (including free and owner-scoped ones).

Add negative tests for each case.

### GC-02 — Medium — `src/verify.rs:114–153, 155–161, 507–534`: the verified grant is not bound to the request it authorized

**Issue.** `VerifiedGrant` holds neither the parameters nor the request hash it was checked
against, and it is `Clone`.

- `request_hash(op, opv, params)` is a free function: the broker chooses what to hash and what to
  execute.
- For a denial, the broker must assemble the hash itself from `rej.verified.write_op`, choosing
  between the requested `op` and the grant's `op` (SI-2/GS-06).

A broker that re-parses the request, hashes a normalized copy, or executes from a different
structure than the one passed to `verify` gets a valid authorization for parameters that were never
compared. It can also compute a `request_hash` that turns a replay into `STORED_OUTCOME`, or the
reverse.

**Reproduction.** Review test r3: after `verify(&g, …, &p)` succeeds, `request_hash(v.op(),
v.opv(), &other)` with `amount_cents = 999999` is accepted by the API.

**Fix.**

- `verify` computes the request hash itself and stores it in `VerifiedGrant`, and in
  `Rejection.verified` for verified write denials.
- `VerifiedGrant` owns or borrows the validated `Params`. The effect code receives the parameters
  only from `VerifiedGrant::params()`.
- Remove `Clone` from `VerifiedGrant`.
- Add `Rejection::must_record() -> Option<(iss, jti, request_hash)>`, which returns `Some` only for
  write grants. Today `verified` is also `Some` for read-grant denials, and a broker that records
  every `Some` would write DENIED rows for read jtis (doc comment `verify.rs:155` vs behaviour).

### GC-03 — Low — `src/verify.rs:300, 327–332`: time is checked once, at verification, not at commit

**Issue.** `verify` takes `now` once. Step 12 (consumption) and step 14 (the effect) run later, in
the broker's transaction, and may wait on locks. A grant that verifies at `exp + skew − 1` can
commit its effect after expiry. Draft 1 does not say whether the time checks must hold at commit.

**Fix.** In the crate, add `VerifiedGrant::still_valid(now) -> bool`, which re-checks 4d, 8d and
8e, and document that the broker calls it inside the effect transaction. Alternatively, the broker
bounds the transaction time to under `skew`. Ask the Draft 2 author to state which is required.

### GC-04 — Low — `src/verify.rs:525`: `request_hash` ignores an encoder error

**Issue.** `let _ = cbor::encode(…)` discards `DuplicateKey`. This is unreachable today because the
keys come from a `BTreeMap<String, _>`. If the input type changes, a failed encode would hash a
partial buffer, and two different requests could share a hash, giving `STORED_OUTCOME` for a
different request. Parameter names are also not validated (empty, non-ASCII), either here or in
`Operations::new` (`ops.rs:118`).

**Fix.** `expect` with a stated invariant, or return `Result`. Validate parameter names as
`[a-z0-9_]{1,64}` in `Operations::new`.

### GC-05 — Low — `src/ops.rs:105–160`: declaration checks the crate could enforce but does not

**Issue.** `Operations::new` accepts:

- a write operation whose parameters are all `Free`, or that has none, so the grant binds only `op`;
- duplicate entries in `versions`;
- a `ledger.transfer` with `requires_confirmation: false`, although D-2 requires `cfm` for every
  `ledger.transfer`.

The "destination-like free" rule cannot be checked (SI-8 / GS-08).

**Fix.** Reject write operations with no `res`/`con` parameter unless they are explicitly marked.
Reject duplicate versions. Leave the D-2 rule to the broker's configuration test, but list it as a
caller obligation (below). Add a `destination` attribute when Draft 2 defines one.

### GC-06 — Low — `src/registry.rs:135–153`: registry strings are compared after JSON unescaping

**Issue.** `"status": "active"` loads as `active` (review test r7). This is semantically
harmless, but it contradicts "parsed strictly" (§8.2). It also means a text-level review of the
file (grep for `"revoked"`) can disagree with what the broker loads. The registry file size is
unbounded; it is an admin input, so that is informational only.

**Fix.** Reject any member value containing `\` escapes. In serde_json, deserialize the field as
`&str`: a borrowed string fails on escapes. Optionally cap the file size. GS-09 covers the rest of
the strict-JSON semantics.

### GC-07 — Informational — Draft 1 issues the crate inherits (no crate defect)

- **GS-01 (High, spec):** future-dated grants are accepted (review test r5: `nbf = iat + 3600`
  accepted). `verify.rs:319–332` implements Draft 1 exactly. When Draft 2 adds `iat ≤ now + skew`
  and `nbf − iat ≤ skew` (or `exp − iat ≤ max_ttl + skew`), update step 8 and `GrantBuilder::payload`
  (`issue.rs:185`).
- **GS-02 (High, spec):** recording DENIED outside the effect transaction. The crate gives no
  guidance beyond the README, and the test harness (`tests/common/mod.rs`, `Err(rej)` branch)
  records it separately, as Draft 1 says. The broker must follow the Draft 2 rule; see the
  obligations.
- **GS-06 / SI-2:** the `opv` and `op` used in the hash of a step-10a denial. GC-02's fix moves
  this decision into the crate.
- **GS-11:** there are no transport vectors. The crate's own unit tests (`transport.rs:99–122`)
  cover padding, `+/`, whitespace, non-zero trailing bits, length ≡ 1 (mod 4) and the 2731/2732
  boundary.
- There is no unit test for S + L malleability; review test r1 confirms it is rejected. Add r1 to
  `tests/robustness.rs`.

## Caller obligations (broker)

The broker must implement each of these. Each should have an integration test.

1. **Transport:** pass the header or JSON member to `decode_transport` as `None` when it is absent.
   Never trim or normalize the value first.
2. **Request parsing (until GC-01 is fixed):** reject undeclared, missing and ill-typed parameters
   for the requested op before calling `verify`. Effect code reads only the parameters passed in
   `VerifyContext.requested_params`.
3. **Trusted context:**
   - `workload` comes from the socket or mTLS peer identity, never from the request.
   - `workload_tenants` comes from the workload registry, and is empty when the workload is
     unregistered.
   - `audience` is this broker's configured `broker_id`, which must be an ID; GS-03 requires it to
     be unique per replay store.
   - `now` is the broker clock, floored, and checked against the persisted high-water mark (§7.5).
   - `skew` ≤ 5 is enforced by `Skew::new`.
4. **Step 12 (write grants):** before any effect, insert `(iss, jti, exp, request_hash, outcome)`
   with a unique key on `(iss, jti)` as the first statement of the effect transaction.
   - On conflict: if the hash is the same, return the stored outcome; otherwise
     `grant_replayed`.
   - Hash the exact parameters that will be executed (GC-02).
5. **Step 13 (both kinds):** fetch `revoked_before` rows for the grant's `ten` inside the same
   transaction, and call `identity().is_revoked(&rows)`. For writes, record DENIED on revocation.
6. **Denials of verified write grants** (`rej.verified` is `Some` and `kind == Write`): record
   DENIED atomically with the decision, per the Draft 2 / GS-02 fix. If the record cannot be written,
   return `unavailable`, not `grant_denied`. Never record for read grants or for `verified == None`.
7. **Step 14:** policy, state and budget preconditions. For read grants, a `READ ONLY` transaction
   filtered by `(ten, sub)`. Never treat `Ok(VerifiedGrant)` as sufficient (SI-04).
8. **Expiry at commit:** re-check `now < exp + skew` inside the effect transaction, or bound the
   transaction duration (GC-03).
9. **Client responses:** send only `grant_denied` / `unavailable` to the workload. Send
   `rej.code.as_str()` to the audit log only (§7.4).
10. **Infrastructure errors** (registry, replay store, revocation table, lock timeout, commit):
    deny with `unavailable`. Never fall through to the effect.
11. **Start-up:** refuse to start on any `RegistryError` or `DeclarationError`. The registry file
    must be readable and writable by administrators only (SI-13).
    - Configuration tests must check that `ledger.transfer` has `requires_confirmation = true` (D-2)
      and that no destination-like parameter is `Free` (SI-8).
    - If reload is supported, the new `Registry` replaces the old one atomically (GS-09).
12. **Concurrency:** N parallel submissions of one write grant yield exactly one effect. A
    restart, or a restore of the replay store, must not re-enable a consumed jti. Rows are pruned
    no earlier than `exp + skew + margin`.
