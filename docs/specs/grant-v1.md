# Nodkey-Grant v1 — format and verification specification

- **Status:** Draft 1 (2026-10-25). Not yet reviewed. Implements [ADR-0004](../decisions/0004-grant-format.md)
  (Proposed) as changed by its Amendment 1 ([§0](#0-adr-0004-amendment)), with the binding rules of
  [ADR-0003](../decisions/0003-trusted-user-context-and-grant-issuance.md) rev. 3 (Accepted, Phase 3
  implementation profile) and the replay rules of [ADR-0006](../decisions/0006-replay-and-effect-state.md)
  (Accepted). Every point that rests on a specific ADR-0003 or ADR-0009 detail is collected in
  [§10](#10-depends-on-adr-0003-and-adr-0009) and marked **[D-n]** where it is used.
- **Invariants:** SI-05, SI-06, SI-07, SI-08, SI-09 (mapping in [§11](#11-security-considerations)).
- **Test vectors:** [`tests/vectors/grant-v1/`](../../tests/vectors/grant-v1/README.md).

The key words MUST, MUST NOT, REQUIRED, SHOULD, and MAY are to be interpreted as described in RFC 2119 and
RFC 8174 when, and only when, they appear in all capitals.

## Contents

0. [ADR-0004 amendment](#0-adr-0004-amendment)
1. [Scope and model](#1-scope-and-model)
2. [Transport encoding](#2-transport-encoding)
3. [COSE_Sign1 profile](#3-cose_sign1-profile)
4. [CBOR decoding profile](#4-cbor-decoding-profile)
5. [Payload](#5-payload)
6. [Operation declarations](#6-operation-declarations)
7. [Verification procedure](#7-verification-procedure)
8. [Key registry](#8-key-registry)
9. [Issuer requirements](#9-issuer-requirements)
10. [Depends on ADR-0003 and ADR-0009](#10-depends-on-adr-0003-and-adr-0009)
11. [Security considerations](#11-security-considerations)
12. [Test vectors](#12-test-vectors)
13. [Versioning](#13-versioning)
14. [References](#14-references)

## 0. ADR-0004 amendment

This spec changes ADR-0004 as recorded in its **Amendment 1 (2026-10-25)**, which ADR-0003 rev. 3's Phase
3 profile (items 5–6) requires. In short, relative to ADR-0004:

| # | Change | Where |
|---|---|---|
| 1 | New signed key 17 `knd`: write (1) or read (2) grant; key sets differ by kind | §5.1, §5.2 |
| 2 | New key 18 `cfm` (write only): user confirmed the exact values on the auth origin; required where the operation demands it (`ledger.transfer`) | §5.1, step 10e |
| 3 | New key 19 `rop` (read only): set of read operations; read grants multi-use, never consumed, never valid for writes | §5.1, §7.2 read steps |
| 4 | `con` entries are `[class, value]`; class must equal the declaration; `free` params absent | §5.3, step 11a |
| 5 | Grant ≤ 2048 bytes; times ≤ 2^53 − 1; ID alphabet; `max_ttl` 30 s broker-wide (no per-route extension); skew ≤ 5 s | §3.1, §5.1, §7.1 |
| 6 | Verification order and per-step error codes replace research 02 §4.3; verified-grant boundary at step 9 | §7 |
| 7 | `ten` must also be in the presenting workload's registered tenants | step 9c |
| 8 | Key registry file format, kid derivation, load-time checks, `role` matched to operation authority (provisional, ADR-0009) | §8, steps 10d/10f |
| 9 | Every operation requires a grant (no grantless class) | step 0 |

Unchanged: the COSE_Sign1 envelope and exact protected header, Ed25519 `verify_strict`, `external_aad`,
keys 0–14, reserved 15–16, `revoked_before` revocation.

## 1. Scope and model

A **grant** is a signed, single-audience authorization record. The **issuer** (the gateway's signing
authority, or the trusted scheduler of ADR-0009 [D-9]) signs it; the untrusted **workload** carries it as
an opaque string; the **broker** verifies it and decides whether to execute one requested operation.

This document specifies the byte format, the key registry the broker loads, and the exact order of
checks the broker performs, with the error code each check produces. It does not specify the broker's
request protocol, its policy/state/budget preconditions (ADR-0005, ADR-0006), or how the gateway maps
HTTP requests to operations (ADR-0003).

A grant has one of two **kinds** [D-1]:

| Kind | `knd` | Authorizes | Use | Consumed |
|---|---|---|---|---|
| **write** | 1 | exactly one write operation, with every parameter bound per its class (§6) | single use | yes: `(iss, jti)` in the effect transaction |
| **read** | 2 | any operation in a declared set of read operations, each limited to resources the subject owns (ownership checked by the broker against trusted state) | multi-use within the validity window | no |

A read grant never authorizes a write operation, and a write grant never authorizes a read operation.

Integrity is not authorization (SI-04): a valid grant is a necessary condition for an effect, never a
sufficient one. The broker still applies policy, current state, and budgets.

## 2. Transport encoding

On every text channel (HTTP header `Nodkey-Grant`, the broker's JSON request member), the grant is the
**base64url encoding without padding** (RFC 4648 §5) of the grant bytes defined in §3.

- Alphabet `A–Z a–z 0–9 - _` only. No `=`, no whitespace, no line breaks, no `+` or `/`.
- Length of the text MUST be ≤ 2731 characters (= ⌈2048 × 4 / 3⌉); longer → `grant_too_large`, checked
  **before** decoding.
- Canonical form: a text length ≡ 1 (mod 4) is invalid, and the unused low bits of the final character
  MUST be zero. Any violation → `grant_encoding_invalid`.

Software that only forwards grants (the PHP SDK, the workload) MUST treat them as opaque strings and
MUST NOT parse them.

The test vectors are given as the decoded grant bytes; transport encoding is not covered by them
(§12.2).

## 3. COSE_Sign1 profile

### 3.1 Envelope

A grant is a **tagged COSE_Sign1** (RFC 9052 §4.2) with these restrictions:

```
grant = #6.18([                     ; tag 18 REQUIRED, encoded as the single byte 0xd2
          protected   : bstr,       ; exactly the header of §3.2, deterministically encoded
          unprotected : {},         ; MUST be the empty map, encoded 0xa0
          payload     : bstr,       ; deterministic CBOR map (§5); never nil (no detached payload)
          signature   : bstr .size 64
        ])
```

- **Tag 18 is REQUIRED.** Untagged input, any other tag (17, 98, 61, …), a second tag, or tag 18
  encoded non-minimally (`0xd8 0x12`) is rejected. Rationale: one accepted form removes the
  tagged/untagged ambiguity and makes a grant self-identifying in logs.
- The whole envelope MUST satisfy the decoding profile of §4 (envelope rules).
- **Maximum size:** the grant bytes MUST be ≤ **2048 bytes**. There is no separate payload limit; the
  field limits of §5 keep honest payloads well below it (a typical write grant is ~330 bytes).

### 3.2 Protected header

The protected header bstr MUST decode (§4, header rules) to a map with **exactly** these three labels:

| Label | Name | Value | Rule |
|---|---|---|---|
| 1 | `alg` | int | MUST equal the `alg` of the registry entry for `kid` (§7 step 4). For v1 this is **−19 (Ed25519)**, RFC 9864. |
| 4 | `kid` | bstr, exactly 16 bytes | Key identifier derived from the public key (§8.1). |
| 16 | `typ` | tstr | MUST equal `application/nodkey-grant+cbor` (RFC 9596). |

Every other label is forbidden, including `crit` (2), content type (3), IV (5, 6), `x5chain` (33), and
any private label. A conforming protected header therefore has the fixed layout (55 bytes):

```
a3                                   map(3)
   01 32                             1: -19
   04 50 <kid: 16 bytes>             4: h'…'
   10 78 1f                          16: text(31)
      6170706c69636174696f6e2f676c6569706e69722d6772616e742b63626f72   "application/nodkey-grant+cbor"
```

`alg` −8 (polymorphic EdDSA), −7, 0, or any other integer is **not** an alias: it is rejected with
`grant_alg_mismatch`. The algorithm is selected by the registry entry, never by the token (RFC 8725
§3.1); the header value only has to agree with it.

### 3.3 Unprotected header

MUST be the empty map (`0xa0`). Any entry — including a copy of a protected label — is rejected.

### 3.4 Signature input

The signature is Ed25519 (RFC 8032 §5.1, pure Ed25519, no context, no prehash) by the issuer's key over
the COSE `Sig_structure` (RFC 9052 §4.4) for COSE_Sign1:

```
Sig_structure = [ "Signature1", protected, external_aad, payload ]
```

encoded as a definite-length CBOR array of four elements with shortest-form heads:
`0x84 0x6a "Signature1"`, then `protected`, `external_aad` and `payload` each as a bstr. `protected` and
`payload` are the **exact bytes received** (not a re-encoding).

**external_aad** (domain separation and audience binding):

```
external_aad = "nodkey.grant.v1" || 0x00 || UTF-8(audience)
```

where `audience` is the verifying broker's own configured identifier (never a value from the grant). A
grant signed for broker B therefore fails *signature verification* at broker A, independently of the
`aud` field check (§7 step 9).

### 3.5 Signature verification (strict)

Verification MUST be equivalent to `ed25519-dalek` `VerifyingKey::verify_strict` (versions 2.x and
3.x), i.e. RFC 8032 §5.1.7 with these additional rules:

1. `S` (the last 32 bytes, little-endian) MUST be < L = 2^252 + 27742317777372353535851937790883648493.
   (`S + L` malleability is rejected.)
2. `R` MUST decode to a curve point and MUST NOT be of small order.
3. The public key `A` MUST NOT be of small order and MUST be canonically encoded (enforced at registry
   load, §8.3).
4. Accept iff the encoding of `[S]B − [k]A` equals the received `R` bytes, where
   `k = SHA-512(R || A || Sig_structure) mod L` (cofactorless equation).

Signature bytes MUST NOT be used as identifiers; `jti` is the identifier.

## 4. CBOR decoding profile

All three CBOR items (the envelope, the protected header, the payload) are decoded by a **strict
decoder** that rejects anything that is not the core deterministic encoding of RFC 8949 §4.2.1, plus
further restrictions. Implementations SHOULD decode with a hand-written bounded decoder; "decode, then
re-encode and byte-compare" is an acceptable equivalent only if the re-encoder enforces every rule below.

### 4.1 Rules common to all three items

| # | Rule | Rejects |
|---|---|---|
| C1 | Exactly one data item that consumes all input | trailing bytes, truncation, empty input |
| C2 | Every head uses the shortest form (arguments < 24 inline; 1/2/4/8-byte arguments only when needed) | `0x18 0x01`, `0x98 0x04`, `0x5b 00…`, `0x78 0x17` |
| C3 | Definite lengths only | additional information 31 on any major type |
| C4 | Reserved additional information 28–30 is malformed | |
| C5 | Major type 7 is forbidden entirely | floats of every width, `false`, `true`, `null`, `undefined`, simple values, `break` |
| C6 | Tags (major type 6) are forbidden (the outer tag 18 of §3.1 is consumed before C1–C10 apply) | tag 1, tag 24, nested tag 18 |
| C7 | Text strings MUST be valid UTF-8 | |
| C8 | Map keys MUST be in strictly increasing bytewise lexicographic order of their deterministic encodings | duplicate keys, unsorted keys |
| C9 | A declared length or element count larger than the remaining input is rejected **before** any allocation | "CBOR bombs" |
| C10 | Nesting depth limit (a top-level array/map is depth 1) | deeper nesting |

### 4.2 Per-item differences

| Item | Negative integers (major 1) | Max depth | Error code on violation |
|---|---|---|---|
| Envelope (the bytes after `0xd2`) | allowed | 4 | `grant_malformed` |
| Protected header (bstr contents) | allowed | 1 (no nested containers) | `grant_header_invalid` |
| Payload (bstr contents) | **forbidden** | 3 | `grant_payload_malformed` |

Negative integers are permitted in the envelope only so that a malformed unprotected header such as
`{1: -19}` is reported as `grant_header_invalid` rather than `grant_malformed`; it is rejected either way.

## 5. Payload

### 5.1 Field table

The payload is a CBOR map with unsigned-integer keys (Nodkey-private numbering; CWT claim numbers are
deliberately not reused). **Unknown keys are rejected**; the key set is fixed by `knd`.

| Key | Name | CBOR type | Constraint | Write | Read |
|---|---|---|---|---|---|
| 0 | `ver` | uint | MUST be 1 | REQUIRED | REQUIRED |
| 1 | `iss` | tstr | ID, 1–128 bytes; MUST equal the registry `iss` of `kid` | REQUIRED | REQUIRED |
| 2 | `aud` | tstr | ID, 1–128 bytes; MUST equal the broker's identifier | REQUIRED | REQUIRED |
| 3 | `jti` | bstr | exactly 16 bytes from a CSPRNG | REQUIRED (consumption key) | REQUIRED (audit only; never consumed) |
| 4 | `iat` | uint | seconds since the Unix epoch, ≤ 2^53 − 1 | REQUIRED | REQUIRED |
| 5 | `nbf` | uint | as `iat`; `nbf ≥ iat` | REQUIRED | REQUIRED |
| 6 | `exp` | uint | as `iat`; `nbf < exp ≤ nbf + max_ttl` | REQUIRED | REQUIRED |
| 7 | `wid` | tstr | ID, 1–256 bytes (a SPIFFE ID in the reference deployment) | REQUIRED | REQUIRED |
| 8 | `ten` | tstr | ID, 1–128 bytes | REQUIRED | REQUIRED |
| 9 | `sub` | tstr | ID, 1–256 bytes | REQUIRED | REQUIRED |
| 10 | `op` | tstr | `[a-z0-9_.]{1,64}` | REQUIRED | FORBIDDEN |
| 11 | `opv` | uint | 1–65535 | REQUIRED | FORBIDDEN |
| 12 | `res` | map | §5.3 | REQUIRED | FORBIDDEN |
| 13 | `con` | map | §5.3 | REQUIRED (may be `{}`) | FORBIDDEN |
| 14 | `use` | uint | MUST be 1 | REQUIRED | FORBIDDEN |
| 15 | — | — | reserved (was `epo`, removed by ADR-0004 rev. 2); MUST NOT appear | — | — |
| 16 | — | — | reserved (was `rqh`, removed by ADR-0004 rev. 2); MUST NOT appear | — | — |
| 17 | `knd` | uint | 1 = write, 2 = read [D-1] | REQUIRED | REQUIRED |
| 18 | `cfm` | uint | 0 = not confirmed, 1 = user confirmed the exact bound values on the auth origin [D-2] | REQUIRED | FORBIDDEN |
| 19 | `rop` | map tstr → uint | read operation set: 1–16 entries, key = op name (`[a-z0-9_.]{1,64}`), value = opv (1–65535) [D-1] | FORBIDDEN | REQUIRED |

Every key ≥ 20, and every non-uint key, is unknown and rejected. Reserved numbers are never reassigned.

An **ID** is a text string whose bytes are all in `0x21–0x7E` (printable ASCII, no space, no control
characters, no NUL). All comparisons are **byte-exact**: no case folding, trimming, or Unicode
normalization.

### 5.2 Version and kind

`ver` is checked before the key set: a payload whose key 0 is a uint other than 1 is rejected with
`grant_version_unsupported`. Then `knd` selects the exact key set (write: 0–14, 17, 18; read: 0–9, 17,
19). A missing, extra, or wrongly typed key → `grant_payload_invalid`.

### 5.3 `res` and `con` (write grants)

Both are maps with uint keys 0–15 and at most 16 entries. Keys are the parameter numbers from the
operation declaration (§6). The **class of each parameter comes from the broker's declaration**; the
encoding is self-describing so that an issuer/broker disagreement about a class is detected instead of
silently broadening (SI-07).

- `res` value: the exact resource identifier, a uint or a tstr. Resource parameters are always `exact`.
- `con` value: a two-element array `[class, value]`:

| `class` | Meaning | `value` | Request satisfies it iff |
|---|---|---|---|
| 0 | **exact** | uint or tstr | request value is identical (same type, byte-exact text, equal integer) |
| 1 | **bounded** (inclusive ceiling) | uint | request value is a uint and ≤ `value` |

- `free` parameters MUST NOT appear in `con` (they are unconstrained by definition and published as
  residuals, ADR-0003).
- tstr values in `res`/`con` are 0–256 bytes of `0x20–0x7E`. Per-parameter types (§6) narrow this further.
- Generic shape violations (wrong value types, class not 0/1, bounded with a non-uint, key > 15, > 16
  entries) → `grant_payload_invalid` (step 7). Disagreement with the operation's declaration (missing or
  extra key, class mismatch, type mismatch) → `grant_op_schema_invalid` (step 11).

### 5.4 Request hash (broker-internal)

The replay store records a hash of the request so that a retry can be distinguished from a replay
(ADR-0006 §5). It never appears on the wire; this construction is RECOMMENDED so that implementations and
logs agree:

```
request_hash = SHA-256( "nodkey.rqh.v1" || 0x00 ||
                        deterministic_cbor([ op, opv, { param_name (tstr) : value (uint|tstr) } ]) )
```

over every parameter of the request, including `free` ones.

## 6. Operation declarations

The broker's configuration declares each operation. The format of that configuration belongs to the
broker; the semantic content the verifier needs is:

| Element | Meaning |
|---|---|
| `op`, supported `opv` list | name and accepted schema versions |
| `kind` | `write` or `read` [D-1] |
| `authority` | which issuer role may sign grants for it: `user_grant` → registry role `user_authority`; `scheduler_grant` → role `scheduler` [D-9] |
| `requires_confirmation` | write only: the grant MUST carry `cfm = 1` [D-2] |
| parameters | for write ops: name, placement (`res` or `con`), number (0–15), class (`exact`, `bounded`, `free`), type. For read ops: each parameter is `owner_scoped` (the broker checks that `(ten, sub)` owns the referenced resource in the query) [D-3] |

The broker MUST refuse to start if any parameter is unclassified, if a destination-like parameter is
`free`, if a `bounded` parameter is not an unsigned integer, or if two parameters share a placement and
number. Every operation requires a grant: there is no grantless (`workload`) class in v1 [D-8].

## 7. Verification procedure

### 7.1 Inputs

- `G`: the grant bytes (after §2 decoding).
- The request: operation name and typed parameters, already strictly parsed by the broker's request
  parser (unknown/missing/duplicate parameters rejected before this procedure).
- Trusted context: `broker_id` (configuration), `peer_wid` (the workload identity of the socket or mTLS
  peer, assigned by the isolation layer), `now` (broker UTC clock, whole seconds, floor).
- Trusted configuration: key registry (§8), workload registrations (`wid` → set of tenants) [D-4],
  operation declarations (§6), `skew` = **5 s** (a deployment MAY configure 0–5 s; never more),
  `max_ttl` = **30 s** [D-6].
- Broker state: the replay store and the `revoked_before` table (ADR-0006).

### 7.2 Procedure

The steps run **in this order**; the first failing check determines the error code. All arithmetic is
checked (values are ≤ 2^53 − 1, so `exp + skew` and `now + skew` cannot overflow a u64).

| Step | Check | Error code |
|---|---|---|
| 0 | The operation requires a grant (all v1 operations do) and none was supplied | `grant_missing` |
| 1a | Transport text longer than 2731 characters | `grant_too_large` |
| 1b | Transport text is not canonical unpadded base64url (§2) | `grant_encoding_invalid` |
| 1c | `len(G) > 2048` | `grant_too_large` |
| 2 | **Structure.** `G[0] == 0xd2`; the remaining bytes satisfy §4 (envelope rules); the item is an array of exactly 4 elements typed bstr, map, bstr, bstr; the signature bstr is 64 bytes | `grant_malformed` |
| 3 | **Header.** Unprotected map is empty. Protected bytes satisfy §4 (header rules) and decode to a map with exactly labels {1, 4, 16}; label 1 is an integer; label 4 is a 16-byte bstr; label 16 equals `application/nodkey-grant+cbor` | `grant_header_invalid` |
| 4a | **Key.** `kid` is in the registry | `grant_unknown_kid` |
| 4b | header `alg` equals the entry's algorithm (−19) | `grant_alg_mismatch` |
| 4c | entry `status` is `active` | `grant_key_revoked` |
| 4d | `not_before ≤ now < not_after` for the entry | `grant_key_inactive` |
| 5 | **Signature.** Build `external_aad` from **this broker's** `broker_id` (§3.4) and `Sig_structure` from the received `protected` and `payload` bytes; strict verification (§3.5) with the entry's key | `grant_signature_invalid` |
| 6 | **Payload decoding.** Payload bytes satisfy §4 (payload rules) | `grant_payload_malformed` |
| 7a | Payload key 0 present as a uint ≠ 1 | `grant_version_unsupported` |
| 7b | **Payload schema.** Top level is a map; all keys are uints; `knd` ∈ {1, 2}; key set equals the set for `knd`; every field has its type and constraints (§5.1, §5.3 generic shape) | `grant_payload_invalid` |
| 8a | **Issuer.** `iss` equals the entry's `iss` | `grant_issuer_mismatch` |
| 8b | **Time.** `nbf ≥ iat` and `exp > nbf` | `grant_time_invalid` |
| 8c | `exp − nbf ≤ max_ttl` | `grant_ttl_exceeded` |
| 8d | `now + skew ≥ nbf` | `grant_not_yet_valid` |
| 8e | `now < exp + skew` | `grant_expired` |
| 9a | **Binding.** `aud == broker_id` | `grant_audience_mismatch` |
| 9b | `wid == peer_wid` | `grant_workload_mismatch` |
| 9c | `ten` ∈ tenants registered for `peer_wid` [D-4] | `grant_tenant_mismatch` |

A grant that passes steps 1–9 is **verified**. The remaining steps depend on the kind.

**Write grants (`knd = 1`)** — every denial from here on is a *decision* and is recorded (§7.3):

| Step | Check | Error code |
|---|---|---|
| 10a | `op` equals the requested operation and is declared | `grant_op_mismatch` |
| 10b | the declared kind of `op` is `write` | `grant_kind_mismatch` |
| 10c | `opv` is supported for `op` | `grant_opv_unsupported` |
| 10d | the entry's `role` matches the operation's `authority` | `grant_issuer_not_permitted` |
| 10e | if the operation `requires_confirmation`, `cfm == 1` | `grant_confirmation_required` |
| 11a | `res` and `con` match the declaration: same key sets (`free` parameters absent from `con`), each `con` class equals the declared class, each value has the declared type | `grant_op_schema_invalid` |
| 11b | each `res` value equals the request's value for that parameter | `grant_resource_mismatch` |
| 11c | for each `con` entry in ascending key order: exact → equal, else `grant_constraint_mismatch`; bounded → request ≤ ceiling, else `grant_bound_exceeded` | `grant_constraint_mismatch` / `grant_bound_exceeded` |
| 12 | **Consumption**, first statement of the effect transaction: insert `consumed_grant(iss, jti, exp, request_hash, outcome)`. If a row exists: same `request_hash` → return the stored outcome (`STORED_OUTCOME`), no effect; different hash → deny | `grant_replayed` |
| 13 | **Revocation**, in the same transaction: for each `revoked_before` row matching `(ten)`, `(ten, wid)` or `(ten, sub)`, deny if `iat < revoked_before` | `grant_revoked` |
| 14 | Policy, state, and budget preconditions (ADR-0005/0006); execute; record `ACCEPT`; commit | (outside this spec) |

**Read grants (`knd = 2`)** — nothing is consumed or recorded:

| Step | Check | Error code |
|---|---|---|
| 10a | the requested operation is declared | `grant_op_mismatch` |
| 10b | its declared kind is `read` | `grant_kind_mismatch` |
| 10c | for each `rop` entry in map order: the operation is not declared → `grant_op_mismatch`; it is declared but its kind is not `read` → `grant_kind_mismatch` (a read grant that lists any write operation is rejected entirely, whatever is requested) | `grant_op_mismatch` / `grant_kind_mismatch` |
| 10d | the requested operation is a key of `rop` | `grant_op_mismatch` |
| 10e | the `rop` opv for it is supported | `grant_opv_unsupported` |
| 10f | the entry's `role` matches the operation's `authority` | `grant_issuer_not_permitted` |
| 13 | revocation as for write grants, in the read transaction | `grant_revoked` |
| 14 | the read runs in a `READ ONLY` transaction whose query filters by the grant's `ten` and `sub`; a resource the subject does not own is not found, and that denial is indistinguishable from any other [D-3] | (outside this spec) |

Infrastructure failure at any step (replay store, revocation table, or registry unavailable; lock
timeout; commit failure) → deny with `replay_store_unavailable` (or the broker's equivalent internal code);
never proceed (SI-15).

### 7.3 One decision per write grant (ADR-0006 §4)

- **Unverified** grants (failing steps 1–9) consume nothing. A grant stolen and presented over another
  workload's socket (step 9b) is therefore not burned and its owner can still use it (vector RPL-04).
- A **verified** write grant denied at step 10, 11 or 13, or by a step-14 precondition, is recorded as
  `DENIED` with its `request_hash` in a separate short transaction if no row exists yet. If that write
  fails, the response is still a denial. Later submissions of the same `(iss, jti)` follow step 12:
  identical request → the stored denial; different request → `grant_replayed`.
- Steps 10–11 do not need the replay store; an implementation MAY run step 12 before them. The
  vectors assume the order above (only the error code of a request that is wrong in two ways differs).

### 7.4 Results and client-facing codes

Error codes above are **broker-facing**: they go to the audit log with the detail, never to the
workload. The workload receives exactly one of:

| Broker result | Client-facing |
|---|---|
| `ACCEPT` | the operation's normal result |
| `STORED_OUTCOME` | the response recorded for the first decision on that `(iss, jti)` (may itself be a denial) |
| any `grant_*` code | `grant_denied`, static message "authorization denied" |
| `replay_store_unavailable` / infrastructure failure | `unavailable` ("nothing was executed"), the existing broker code |

`grant_denied` is deliberately generic: the workload is the attacker in the threat model, and per-step
codes would be an oracle for crafting grants.

### 7.5 Clock

`now` is the broker's clock. The broker MUST persist a clock high-water mark and refuse to serve while
`now < mark − skew` (ADR-0006 §8). Consumed rows MUST NOT be pruned before `exp + skew + margin`.

## 8. Key registry

### 8.1 Key identifier

```
kid = first 16 bytes of SHA-256( "nodkey.kid.v1" || 0x00 || public_key )
```

where `public_key` is the 32-byte RFC 8032 encoding. The kid is derived, never chosen, so one kid cannot
name two keys.

### 8.2 File format

The broker loads the registry at startup from an administrator-only path that the workload cannot read
or write (SI-13). It is a UTF-8 JSON document parsed strictly (duplicate member names, unknown members,
missing members, and wrong types are errors):

```json
{
  "format": "nodkey.grant-keys.v1",
  "keys": [
    {
      "kid": "4fcf41a3bf742ec7db96e0aaa5047e3a",
      "alg": "Ed25519",
      "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "iss": "nodkey.authority.test",
      "role": "user_authority",
      "purpose": "grant",
      "not_before": 1767225600,
      "not_after": 1798761600,
      "status": "active"
    }
  ]
}
```

(The key shown is RFC 8032 TEST 1: **TEST-ONLY**, its secret is public.)

| Member | Type | Rule |
|---|---|---|
| `format` | string | exactly `nodkey.grant-keys.v1` |
| `keys` | array | non-empty |
| `kid` | string | 32 lowercase hex characters; MUST equal §8.1 applied to `public_key` |
| `alg` | string | exactly `Ed25519` (maps to COSE −19) |
| `public_key` | string | 64 lowercase hex characters |
| `iss` | string | ID, 1–128 bytes; grants under this key MUST carry this `iss` |
| `role` | string | `user_authority` or `scheduler` [D-9] |
| `purpose` | string | exactly `grant` (receipt and administrative keys live in other registries and never verify grants) |
| `not_before`, `not_after` | integer | Unix seconds, ≤ 2^53 − 1, `not_before < not_after` |
| `status` | string | `active` or `revoked` |

### 8.3 Load-time validation

The broker validates every entry in file order and **refuses to start** if any check fails (it never
skips a bad entry). Checks, in order per entry:

| Check | Error code |
|---|---|
| shape and member rules of §8.2 (other than `public_key` and `kid` values) | `registry_entry_invalid` |
| `public_key` is 64 lowercase hex, decodes to a curve point, and re-encodes to the same bytes (canonical: y < p) | `registry_key_invalid` |
| the point is not of small order (identity, order 2, 4, 8, or with a small-order component) | `registry_key_weak` |
| `kid` equals the derivation of §8.1 | `registry_kid_mismatch` |
| no earlier entry has the same `kid` or `public_key` | `registry_duplicate_key` |

### 8.4 Rotation

1. Generate the new key in the issuer's trust domain; add its public entry (`active`) to every broker
   registry and restart/reload the brokers.
2. Switch the issuer to the new key.
3. Keep the old entry `active` for at least `max_ttl + skew` (35 s at defaults) after the switch, then set
   its `not_after` to the switch time plus that overlap (or remove it).

Because TTLs are short, no in-flight grant outlives the overlap.

### 8.5 Revocation

| Scope | Mechanism | Effect |
|---|---|---|
| A key (issuer compromise) | set `status: "revoked"` and reload | every grant under that `kid` fails at step 4c, including unexpired ones |
| A tenant, workload, or subject | `revoked_before` row for `(ten)`, `(ten, wid)`, or `(ten, sub)` (ADR-0006 §6) | grants with `iat < revoked_before` fail at step 13, inside the effect transaction |
| One grant | not needed: write grants are single-use; read grants expire within `max_ttl` | |

Writers of `revoked_before` SHOULD store `floor(t) + 1` for a revocation at time `t`, so that a grant
issued earlier in the same second is also revoked (the comparison is strict `<`) [D-7].

## 9. Issuer requirements

The issuer (authority or scheduler) MUST:

- sign only with a key whose private half never enters the workload's trust domain (SI-05), one key per
  purpose and issuer;
- generate `jti` from a CSPRNG (16 bytes) and never reuse it;
- set `iss` to its registered issuer name, `aud` to the single target broker, `iat` to its current
  time, and `nbf`/`exp` so that `exp − nbf ≤ max_ttl`;
- for write grants: put every `exact` parameter's value and every `bounded` parameter's ceiling into
  `con`, every resource parameter into `res`, and omit `free` parameters; set `cfm = 1` only when the
  user approved exactly the values in `op`, `res`, and `con` on the auth origin [D-2];
- for read grants: list only operations declared `read` for the target broker;
- encode the payload and protected header with the core deterministic encoding (§4), with tag 18 and an
  empty unprotected header.

A generic COSE library can produce conforming grants if it is configured to emit exactly this profile.

## 10. Depends on ADR-0003 and ADR-0009

ADR-0003 rev. 3 was accepted on 2026-10-25 with a **Phase 3 implementation profile** (end of the ADR),
after the re-review in
[`docs/reviews/2026-10-25-adr-0003-0009-review.md`](../reviews/2026-10-25-adr-0003-0009-review.md).
ADR-0009 was returned for revision by the same review. The items below are where this spec relies on a
specific detail of those ADRs. Each is isolated so that a later change touches only the listed fields,
steps, and vectors. "Profile n" refers to item n of the ADR-0003 Phase 3 profile.

| Id | Dependency | What this spec assumes | Touches |
|---|---|---|---|
| D-1 | **Grant kinds** — settled by Profile 6 (R3B-06) | Two kinds: write (one op, single use, consumed) and read (a set of read ops, multi-use within TTL, never consumed, never valid for a write op). Encoded as `knd` (17); read set as `rop` (19). | §1, §5.1, §5.2, §7.2 steps 10R/13R; vectors ACC-02, ACC-09, OP-01, OP-07..OP-12, PSCH-60..71, TIME-12, REV-08 |
| D-2 | **Confirmation marker** — settled by Profiles 4–5 (R3B-01, R3B-02) | `cfm` (18) = 1 means the gateway's pending effect for exactly these values reached `APPROVED` on the auth origin, bound to the session's subject. Every `ledger.transfer` requires it (no threshold); other operations declare `requires_confirmation`. Phase 3 approval uses the local test login (Profile 3), so the strength of the approval is that of the test login. | §5.1, §6, step 10e; vectors OP-13, SIG-38 |
| D-3 | **Parameter classes** — ADR-0003 §5; Profile 7 | `exact` / `bounded` (inclusive uint ceiling) / `free` for write ops, encoded `[class, value]`. Phase 3 `ledger.transfer` binds `from` (res), `to` and `amount_cents` exactly, in integer minor units. Read-op parameters are `owner_scoped`: the broker checks ownership by the grant's `(ten, sub)` against its own state; the app never supplies ownership as a fact. `test.hold` in the vectors exists only to exercise `bounded` and `free`. | §5.3, §6, step 11, step 14R |
| D-4 | **Tenant check** | `ten` is *sourced* from the grant (ADR-0004 AR-17) and additionally MUST be one of the tenants in the presenting workload's registration (`wid` → tenants). If ADR-0003 changes how tenancy is registered, only step 9c changes. | step 9c; vectors BIND-04..06, ACC-06 |
| D-5 | **`sub` sourcing** | `sub` is sourced from the verified grant; there is no independent broker check. | §5.1 |
| D-6 | **TTL** — Profile 6 (write ≤ 30 s) | `max_ttl` is one broker-wide value, default and maximum 30 s, for both kinds (the profile does not fix a read TTL; 30 s is this spec's choice). Per-route longer TTLs (ADR-0004 allows them with a written reason) and scheduler queue latency (review R3-13) are not supported in v1. | step 8c; vectors TIME-07, TIME-11 |
| D-7 | **Revocation writers** | The gateway's revoke socket and the operator write `revoked_before`; same-second rounding per §8.5. | §8.5, step 13 |
| D-8 | **No grantless effects in Phase 3** (coordinator ruling 2026-10-25) | Every operation requires a grant (step 0). ADR-0009's `workload` class is not supported by this spec. | step 0, §6 |
| D-9 | **Scheduler issuer** (ADR-0009, returned for revision; review R3-12/R3-13) | A registry `role` of `scheduler` and an operation `authority` of `scheduler_grant` exist so that a scheduler key cannot sign user operations and vice versa. If ADR-0009 replaces the scheduler with broker-derived authority, remove the `scheduler` role and vectors ACC-08, OP-05, OP-06, CON-05; nothing else changes. | §8.2 `role`, step 10d (write) / 10f (read) |

## 11. Security considerations

| Invariant | How v1 supports it | Residual / limits |
|---|---|---|
| **SI-05 No self-minting** | Ed25519 signatures with keys that exist only in the issuer's trust domain; the broker holds public keys only. `kid` is derived from the key; the algorithm is fixed by the registry (no `alg` confusion, no `none`); weak and non-canonical keys rejected at load; strict verification rejects malleable signatures. Domain separation: fixed `typ`, `"Signature1"` context, `external_aad` tag `nodkey.grant.v1`, per-purpose keys, so a signature on any other Nodkey object cannot be replayed as a grant. | Compromise of an issuer key (attacker J) mints arbitrary grants until the key is revoked (§8.5). |
| **SI-06 Full binding** | Every bound field is checked: `ver`/`typ`/aad (version), `iss` vs kid, `aud` both cryptographically (aad) and by field, `wid` vs socket identity, `ten` vs workload registration, time vs broker clock, `op`/`opv`/`knd` vs declarations, `res`/`con` vs the request. Class is encoded in the grant and must equal the declaration. | `sub` and `ten` are sourced, not independently checked (D-4, D-5). `free` parameters are unbound by definition (published residuals). Read grants bind the operation set, not the resource; ownership is a state check (D-3). |
| **SI-07 No broadening** | Any change to the signed bytes invalidates the signature (vectors SIG-20..38); strict deterministic decoding means one byte sequence has one meaning (no duplicate keys, no alternative encodings, no ignored trailing data); unknown keys are rejected rather than ignored; no attenuation, delegation, or combination is defined; bounded constraints are ceilings checked against the request. | For operations with `bounded` parameters, one grant can be used for any value up to the ceiling, once (Phase 3 `ledger.transfer` has none). `free` parameters are unbound. |
| **SI-08 Default deny** | Every failure in §7 is a deny; malformed, unknown version, unknown algorithm, unknown key, unknown field, expired, not yet valid, revoked, and wrong-key grants each have a vector. Load errors in the registry stop the broker. | — |
| **SI-09 At-most-once** | Write grants: `(iss, jti)` consumption in the effect transaction (unique key); verified denials recorded; same-request retries get the stored outcome, other requests `grant_replayed`. Read grants are multi-use by design and produce no effect. | Not claimed across restore of the replay store or clock rollback unless ADR-0006 §8–9 procedures are followed. Concurrency and restart behavior require integration tests (§12.2). |

Further considerations:

- **Parser attack surface.** The verifier decodes untrusted CBOR before the signature check (envelope
  and protected header, steps 2–3). These decoders MUST be bounded (§4 C9, C10) and SHOULD be fuzzed. The
  payload is decoded only after the signature verifies.
- **Error oracle.** Detailed codes are logged, never returned to the workload (§7.4).
- **Time.** The ±5 s skew widens every validity window by up to 10 s. Broker clock correctness is a
  stated assumption (§7.5).
- **Algorithm agility** is by protocol version only (§13); there is no negotiation.
- **Size limits** (2048 bytes, ID lengths, 16 entries per map) bound verifier work per grant; one Ed25519
  verification per request is the dominant cost.

## 12. Test vectors

### 12.1 Provided

[`tests/vectors/grant-v1/`](../../tests/vectors/grant-v1/README.md) contains 235 grant vectors (246
checked steps, including multi-step replay and multi-use sequences) and 17 key-registry vectors, generated
deterministically from TEST-ONLY RFC 8032 keys by a committed generator, checked by a reference verifier
that implements §7, and cross-checked for signatures with OpenSSL. Expected results are `ACCEPT`,
`STORED_OUTCOME:<ACCEPT|DENIED>`, `LOAD_OK`, or an exact error code from §7.2 / §8.3.

### 12.2 Not covered by static vectors

Transport base64url encoding (§2); concurrency (N parallel submissions of one grant), broker restart,
replay-store unavailability and restore (integration tests, research 02 §8 items 21–26); ownership checks
of read operations and step-14 preconditions; small-order `R` in a signature with an otherwise valid
equation; `exp` near 2^64 (unrepresentable: times are capped at 2^53 − 1 by step 7b).

## 13. Versioning

- The version appears in three places that MUST agree: `typ` (`application/nodkey-grant+cbor`),
  the `external_aad` tag (`nodkey.grant.v1`), and payload `ver = 1`.
- v1 is Ed25519 only. A new algorithm or any incompatible change is protocol v2 with a new `typ`, a new
  aad tag (`nodkey.grant.v2`), and new registry entries. A broker accepts an explicit configured list
  of versions and never falls back.
- New payload fields require a new version; reserved numbers (15, 16) are never reused.

## 14. References

- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA).
- RFC 8949 — Concise Binary Object Representation (CBOR), §4.2.1 core deterministic encoding.
- RFC 9052 — CBOR Object Signing and Encryption (COSE): Structures and Process (§4.2 COSE_Sign1, §4.4
  Sig_structure).
- RFC 9596 — CBOR Object Signing and Encryption (COSE) "typ" (type) Header Parameter.
- RFC 9864 — Fully-Specified Algorithms for JOSE and COSE (Ed25519 = −19).
- RFC 8725 — JSON Web Token Best Current Practices (algorithm confusion classes).
- RFC 4648 — Base-N encodings (§5 base64url).
- RFC 8410 — Algorithm identifiers for Ed25519 (used by the OpenSSL cross-check only).
- `ed25519-dalek` 3.0.0, `VerifyingKey::verify_strict`.
- Nodkey: ADR-0003, ADR-0004, ADR-0006, ADR-0009; research note 02 §4–§8; SECURITY_INVARIANTS v0.2.
