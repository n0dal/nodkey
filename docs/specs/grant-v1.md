# Nodkey-Grant v1 — format and verification specification

- **Status:** **Draft 2** (2026-10-25). Not yet re-reviewed. Supersedes Draft 1 (changes in
  [§15](#15-changes-from-draft-1)). Implements [ADR-0004](../decisions/0004-grant-format.md) (Proposed) as
  changed by its Amendments 1 and 2 ([§0](#0-adr-0004-amendments)), with the binding rules of
  [ADR-0003](../decisions/0003-trusted-user-context-and-grant-issuance.md) rev. 3 (Accepted, Phase 3
  implementation profile) and the replay rules of [ADR-0006](../decisions/0006-replay-and-effect-state.md)
  (Accepted, with Amendment 1). Every point that rests on a specific ADR-0003 detail is collected in
  [§10](#10-depends-on-adr-0003) and marked **[D-n]** where it is used.
- **Invariants:** SI-05, SI-06, SI-07, SI-08, SI-09 (mapping in [§11](#11-security-considerations)).
- **Test vectors:** [`tests/vectors/grant-v1/`](../../tests/vectors/grant-v1/README.md).
- **Review:** [`docs/reviews/2026-10-25-grant-v1-spec-review.md`](../reviews/2026-10-25-grant-v1-spec-review.md)
  (Draft 1; findings GS-01..GS-17, resolution table appended there).

The key words MUST, MUST NOT, REQUIRED, SHOULD, and MAY are to be interpreted as described in RFC 2119 and
RFC 8174 when, and only when, they appear in all capitals.

## Contents

0. [ADR-0004 amendments](#0-adr-0004-amendments)
1. [Scope and model](#1-scope-and-model)
2. [Transport encoding](#2-transport-encoding)
3. [COSE_Sign1 profile](#3-cose_sign1-profile)
4. [CBOR decoding profile](#4-cbor-decoding-profile)
5. [Payload](#5-payload)
6. [Operation declarations](#6-operation-declarations)
7. [Verification procedure](#7-verification-procedure)
8. [Key registry](#8-key-registry)
9. [Issuer requirements](#9-issuer-requirements)
10. [Depends on ADR-0003](#10-depends-on-adr-0003)
11. [Security considerations](#11-security-considerations)
12. [Test vectors](#12-test-vectors)
13. [Versioning](#13-versioning)
14. [References](#14-references)
15. [Changes from Draft 1](#15-changes-from-draft-1)

## 0. ADR-0004 amendments

This spec changes ADR-0004 as recorded in its **Amendment 1** (grant kinds, confirmation; required by
the ADR-0003 rev. 3 Phase 3 profile, items 5–6) and **Amendment 2** (Draft 2 corrections). Relative to
ADR-0004:

| # | Change | Where |
|---|---|---|
| 1 | New signed key 17 `knd`: write (1) or read (2) grant; key sets differ by kind | §5.1, §5.2 |
| 2 | New key 18 `cfm` (write only): user confirmed the exact values on the auth origin; required where the operation demands it (`ledger.transfer`) | §5.1, step W11d |
| 3 | New key 19 `rop` (read only): set of read operations; read grants multi-use, never consumed, never valid for writes | §5.1, steps R11 |
| 4 | `con` entries are `[class, value]`; class must equal the declaration; `free` params absent | §5.3, step W12a |
| 5 | Grant ≤ 2048 bytes; times and uints ≤ 2^53 − 1; ID alphabet; `max_ttl` ≤ 30 s **measured from `iat`**; `nbf − iat ≤ skew`; skew ≤ 5 s | §3.1, §5, §7.1, step 8 |
| 6 | Verification order and per-step error codes replace research 02 §4.3; verified boundary at step 9; write-grant consumption **first** in the effect transaction, denials recorded atomically via a savepoint | §7 |
| 7 | `ten` must also be in the presenting workload's registered tenants | step 9c |
| 8 | Key registry file format, kid derivation, load-time checks (keys of order exactly L); no `role` member (one Authority) | §8 |
| 9 | Every operation requires a grant (no grantless class); exactly one `opv` per operation | step 0, §6 |

Unchanged: the COSE_Sign1 envelope and exact protected header, Ed25519 `verify_strict`, `external_aad`,
keys 0–14, reserved 15–16, `revoked_before` revocation.

## 1. Scope and model

A **grant** is a signed, single-audience authorization record. The **Authority** (the gateway's signing
process, ADR-0003 §1; SECURITY_INVARIANTS v0.3) signs it; the untrusted **workload** carries it as an
opaque string; the **broker** verifies it and decides whether to execute one requested operation. v1 has
exactly one issuer role. Scheduler-issued grants (ADR-0009) are **out of v1 scope**.

This document specifies the byte and text format, the key registry and the operation declarations the
broker loads, and the exact order of checks the broker performs, with the error code each check
produces. It does not specify the broker's request protocol, its policy/state/budget preconditions
(ADR-0005, ADR-0006), or how the gateway maps HTTP requests to operations (ADR-0003).

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

- Alphabet `A–Z a–z 0–9 - _` only: no `=`, no whitespace or line breaks, no `+` or `/`, no non-ASCII.
- Text length MUST be ≤ **2731** characters (the encoding of 2048 bytes); longer → `grant_too_large`,
  checked **before** decoding.
- Canonical form: a text length ≡ 1 (mod 4) is invalid, and the unused low bits of the final character
  MUST be zero (2 unused bits when length ≡ 3 mod 4, 4 when ≡ 2 mod 4).
- Any violation other than length → `grant_encoding_invalid`.
- **Absent vs empty.** A request without the grant member/header is "no grant supplied" (step 0,
  `grant_missing`). A present but empty string is a supplied grant of zero bytes: it decodes, then fails
  step 2 with `grant_malformed` (vectors TRN-09, ENV-03).

Software that only forwards grants (the PHP SDK, the workload) MUST treat them as opaque strings and
MUST NOT parse them.

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
  encoded non-minimally (`0xd8 0x12`) is rejected.
- The whole envelope MUST satisfy the decoding profile of §4 (envelope rules).
- **Maximum size:** the grant bytes MUST be ≤ **2048 bytes** (exactly 2048 is accepted, vector ACC-11).
  There is no separate payload limit.

### 3.2 Protected header

The protected header bstr MUST decode (§4, header rules) to a map with **exactly** these three labels:

| Label | Name | Value | Rule |
|---|---|---|---|
| 1 | `alg` | int | MUST equal the algorithm of the registry entry for `kid` (§7 step 4). For v1 this is **−19 (Ed25519)**, RFC 9864. |
| 4 | `kid` | bstr, exactly 16 bytes | Key identifier derived from the public key (§8.1). |
| 16 | `typ` | tstr | MUST equal `application/nodkey-grant+cbor` (RFC 9596). |

Every other label is forbidden, including `crit` (2), content type (3), IV (5, 6), `x5chain` (33), and
any private label. A conforming protected header therefore has the fixed 55-byte layout:

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
external_aad = "nodkey.grant.v1" || 0x00 || UTF-8(broker_id)
```

where `broker_id` is the verifying broker's own configured identifier (§7.1), never a value from the
grant. A grant signed for broker B therefore fails *signature verification* at broker A, independently
of the `aud` field check (step 9a).

### 3.5 Signature verification (strict)

Verification MUST give the same result as `ed25519-dalek` (2.x/3.x) `VerifyingKey::verify_strict`,
which is RFC 8032 §5.1.7 with these rules, applied in this order:

1. `S` (the last 32 bytes, little-endian) MUST be < L = 2^252 + 27742317777372353535851937790883648493.
   (`S + L` malleability is rejected, vector SIG-05.)
2. `R` (the first 32 bytes) MUST decode to a curve point (a non-decodable `R` is rejected) and that point
   MUST NOT be of small order, i.e. `[8]R` MUST NOT be the identity (vector SIG-40).
3. The public key `A` MUST NOT be of small order. (Registry loading, §8.3, already guarantees that `A`
   has order exactly L, which is stronger.)
4. Compute `k = SHA-512(R_bytes || A_bytes || Sig_structure) mod L` from the **received** `R` bytes and
   the registered `A` bytes; accept iff the canonical encoding of `[S]B − [k]A` equals the received
   `R_bytes` byte for byte (cofactorless equation). A non-canonical `R` encoding therefore never verifies
   (vector SIG-41).

Because `A` has order L, `[S]B − [k]A` lies in the prime-order subgroup, so an `R` with a torsion
component can never satisfy rule 4; rule 2 additionally rejects the identity `R`, which the equation
alone would accept when `S = k·a`. A general-purpose Ed25519 verifier that lacks rule 2 (for example
OpenSSL 3.x/4.x `pkeyutl -verify`, observed while producing the vectors) accepts SIG-40, so it MUST NOT be
used as the broker's verifier.

Signature bytes MUST NOT be used as identifiers; `jti` is the identifier.

## 4. CBOR decoding profile

All three CBOR items (the envelope, the protected header, the payload) are decoded by a **strict
decoder** that rejects anything that is not the core deterministic encoding of RFC 8949 §4.2.1, plus
further restrictions. Implementations SHOULD use a hand-written bounded decoder; "decode, then re-encode
and byte-compare" is acceptable only if the re-encoder enforces every rule below.

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
| C8 | Map keys MUST be in strictly increasing bytewise lexicographic order of their **encoded** bytes | duplicate keys, unsorted keys |
| C9 | A declared length or element count larger than the remaining input is rejected **before** any allocation | "CBOR bombs" |
| C10 | Nesting depth limit (a top-level array/map is depth 1) | deeper nesting |

**C8 and text keys.** The encoded bytes of a text key start with its length head, so text keys sort
**shorter first**, then bytewise: `"test.peek"` (`69 …`) sorts before `"ledger.get_balance"` (`72 …`)
although `"l" < "t"`. A library that sorts by raw string order produces non-conforming maps whenever a
shorter key is lexically later; such grants are rejected (vector PDEC-20; ACC-10 is the conforming
order). This applies to `rop` (§5.1) and to the request-hash map (§5.4).

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
| 2 | `aud` | tstr | ID, 1–128 bytes; MUST equal the broker's `broker_id` | REQUIRED | REQUIRED |
| 3 | `jti` | bstr | exactly 16 bytes from a CSPRNG | REQUIRED (consumption key) | REQUIRED (audit only; never consumed) |
| 4 | `iat` | uint | seconds since the Unix epoch, ≤ 2^53 − 1 | REQUIRED | REQUIRED |
| 5 | `nbf` | uint | as `iat`; `iat ≤ nbf ≤ iat + skew` | REQUIRED | REQUIRED |
| 6 | `exp` | uint | as `iat`; `nbf < exp ≤ iat + max_ttl` | REQUIRED | REQUIRED |
| 7 | `wid` | tstr | ID, 1–256 bytes (a SPIFFE ID in the reference deployment) | REQUIRED | REQUIRED |
| 8 | `ten` | tstr | ID, 1–128 bytes | REQUIRED | REQUIRED |
| 9 | `sub` | tstr | ID, 1–256 bytes | REQUIRED | REQUIRED |
| 10 | `op` | tstr | op name: `[a-z0-9_.]{1,64}` | REQUIRED | FORBIDDEN |
| 11 | `opv` | uint | 1–65535 | REQUIRED | FORBIDDEN |
| 12 | `res` | map | §5.3 | REQUIRED | FORBIDDEN |
| 13 | `con` | map | §5.3 | REQUIRED (may be `{}`) | FORBIDDEN |
| 14 | `use` | uint | MUST be 1 | REQUIRED | FORBIDDEN |
| 15 | — | — | reserved (was `epo`, removed by ADR-0004 rev. 2); MUST NOT appear | — | — |
| 16 | — | — | reserved (was `rqh`, removed by ADR-0004 rev. 2); MUST NOT appear | — | — |
| 17 | `knd` | uint | 1 = write, 2 = read [D-1] | REQUIRED | REQUIRED |
| 18 | `cfm` | uint | 0 = not confirmed, 1 = user confirmed the exact bound values on the auth origin [D-2] | REQUIRED | FORBIDDEN |
| 19 | `rop` | map tstr → uint | read operation set: 1–16 entries, key = op name, value = opv (1–65535), keys in C8 order [D-1] | FORBIDDEN | REQUIRED |

Every key ≥ 20, and every non-uint key, is unknown and rejected. Reserved numbers are never reassigned.

An **ID** is a text string whose bytes are all in `0x21–0x7E` (printable ASCII, no space `0x20`, no
`DEL 0x7F`, no control characters, no NUL). All comparisons are **byte-exact**: no case folding,
trimming, or Unicode normalization.

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
| 0 | **exact** | uint or tstr | the request value has the same CBOR type and is identical (byte-exact text, equal integer) |
| 1 | **bounded** (inclusive ceiling) | uint | the request value is a uint and ≤ `value` |

- `free` parameters MUST NOT appear in `con` (they are unconstrained by definition and published as
  residuals, ADR-0003).
- Generic value rules (step 7): every uint ≤ 2^53 − 1; every tstr 0–256 bytes of `0x20–0x7E`.
- Generic shape violations (wrong value types, class not 0/1, bounded with a non-uint, a value outside
  the generic rules, key > 15, > 16 entries) → `grant_payload_invalid` (step 7). Disagreement with the
  operation's declaration (missing or extra key, class mismatch, value not of the declared type, §6.2) →
  `grant_op_schema_invalid` (step W12a).

### 5.4 Request hash (normative)

The replay store records a hash of the request so that a retry can be distinguished from a replay
(ADR-0006 §5). It never appears on the wire, but implementations MUST compute it exactly as follows,
because it decides between `STORED_OUTCOME` and `grant_replayed`:

```
request_hash = SHA-256( "nodkey.rqh.v1" || 0x00 ||
                        dcbor([ op, { name: value, ... } ]) )
```

- `op` is the **requested** operation name (from the request, not the grant).
- The map holds **every** parameter of the request (including `free` ones), keyed by parameter name
  (tstr), with values as uint or tstr, ordered per C8 (shorter names first).
- `dcbor` is the core deterministic encoding of §4.
- There is no `opv` in the hash: each operation has exactly one `opv` in v1 (§6.1).

Example (vector manifest `request_hash_examples`): request `ledger.transfer {from: "alice", to: "bob",
amount_cents: 12500}` encodes as `["ledger.transfer", {"to": "bob", "from": "alice", "amount_cents":
12500}]` and hashes to
`7d58c02dce96c8c1f0a0e6225ed8c15f61873e6fb14d27900844832aa4209279`.

## 6. Operation declarations

### 6.1 Format

The broker loads its operation declarations at startup from an administrator-only file. The reference
format (used by the vectors and RECOMMENDED for brokers) is strict JSON (§8.2 rules: duplicate members,
unknown members, missing members and wrong types are errors):

```json
{ "format": "nodkey.operations.v1",
  "operations": [
    { "op": "ledger.transfer", "kind": "write", "opv": 1, "requires_confirmation": true,
      "params": [
        { "name": "from", "in": "res", "key": 0, "class": "exact", "type": "account_id", "destination": false },
        { "name": "to", "in": "con", "key": 0, "class": "exact", "type": "account_id", "destination": true },
        { "name": "amount_cents", "in": "con", "key": 1, "class": "exact", "type": "uint", "destination": false } ] } ] }
```

| Member | Rule |
|---|---|
| `op` | op name `[a-z0-9_.]{1,64}`; unique in the file |
| `kind` | `write` or `read` [D-1] |
| `opv` | one integer 1–65535 (**exactly one version per operation in v1**) |
| `requires_confirmation` | boolean; `true` only for `write` operations [D-2] |
| `params[].name` | `[a-z0-9_]{1,64}`; unique within the operation |
| `params[].in` | write: `res` or `con`; read: `request` |
| `params[].key` | write `res`, and write `con` with class `exact`/`bounded`: integer 0–15, unique per placement; `free` and read parameters: `null` |
| `params[].class` | write `res`: `exact`; write `con`: `exact`, `bounded` or `free`; read: `owner_scoped` [D-3] |
| `params[].type` | one of the closed set in §6.2 |
| `params[].destination` | boolean, REQUIRED. `true` marks a destination-like parameter (account, URL, recipient) [D-3] |
| `params[].justification` | non-empty string, REQUIRED for `free` parameters and forbidden otherwise; published in the residual table |

### 6.2 Parameter types (closed set)

| Type | Grant value | Grammar |
|---|---|---|
| `uint` | uint | 0 … 2^53 − 1 |
| `account_id` | tstr | 1–32 bytes of `[a-z0-9_]` |
| `currency` | tstr | exactly 3 bytes of `[A-Z]` |
| `text64` | tstr | 0–64 bytes of `0x20–0x7E` |
| `text256` | tstr | 0–256 bytes of `0x20–0x7E` |

The request parser MUST apply the same grammars to request values (a request value above 2^53 − 1 is
not a `uint`).

### 6.3 Startup refusals

The broker MUST refuse to start (`ops_declaration_invalid`) if any member rule of §6.1 fails, including:
an unclassified parameter; a `res` parameter that is not `exact`; a `bounded` parameter whose type is not
`uint`; a parameter with `destination: true` whose class is not `exact`; a `free` parameter with a key
or without a justification; duplicate operation names, parameter names, or placement/key pairs; more
than one `opv`; `requires_confirmation` on a read operation; a read operation with `res`/`con`
parameters; a write operation with `owner_scoped` parameters; an unknown type. Every operation requires a
grant: there is no grantless class in v1 [D-8]. Vectors OPS-01..OPS-19.

## 7. Verification procedure

### 7.1 Inputs and deployment rules

- `G`: the grant bytes (after §2 decoding).
- The request: operation name and typed parameters, strictly parsed by the broker's request parser
  against the single declared schema of the requested operation (unknown, duplicate, or ill-typed
  parameters are rejected before this procedure).
- Trusted context: `broker_id`, `peer_wid` (the workload identity of the socket or mTLS peer, assigned by
  the isolation layer), `now` (broker UTC clock, whole seconds, floor).
- Trusted configuration: key registry (§8), workload registrations (`wid` → set of tenants) [D-4],
  operation declarations (§6), `skew` (0–5 s, default **5 s**), `max_ttl` (1–30 s, default **30 s**).
- Broker state: the replay store and the `revoked_before` table (ADR-0006).

**`broker_id` rules (GS-03).** `broker_id` MUST be an ID of 1–128 bytes; the broker refuses to start
otherwise. All broker instances configured with the same `broker_id` MUST share one replay store and one
`revoked_before` table; instances with separate stores MUST have distinct `broker_id`s (otherwise a write
grant could be consumed once per store).

**Time configuration (GS-16).** The Authority's TTL (`exp − iat`) MUST be ≤ the smallest `max_ttl`
configured on any broker it issues for; a broker with a smaller `max_ttl` denies every such grant
(`grant_ttl_exceeded`, fail-closed).

### 7.2 Common steps

The steps run **in this order**; the first failing check determines the error code. All arithmetic is
checked (values are ≤ 2^53 − 1, so `exp + skew` and `now + skew` cannot overflow a u64).

| Step | Check | Error code |
|---|---|---|
| 0 | The operation requires a grant (all v1 operations do) and none was supplied (member/header absent) | `grant_missing` |
| 1a | Transport text longer than 2731 characters | `grant_too_large` |
| 1b | Transport text is not canonical unpadded base64url (§2) | `grant_encoding_invalid` |
| 1c | `len(G) > 2048` | `grant_too_large` |
| 2 | **Structure.** `G[0] == 0xd2`; the remaining bytes satisfy §4 (envelope rules); the item is an array of exactly 4 elements typed bstr, map, bstr, bstr; the signature bstr is 64 bytes | `grant_malformed` |
| 3 | **Header.** Unprotected map is empty. Protected bytes satisfy §4 (header rules) and decode to a map with exactly labels {1, 4, 16}; label 1 is an integer; label 4 is a 16-byte bstr; label 16 equals `application/nodkey-grant+cbor` | `grant_header_invalid` |
| 4a | **Key.** `kid` is in the registry | `grant_unknown_kid` |
| 4b | header `alg` equals −19 (the entry's algorithm) | `grant_alg_mismatch` |
| 4c | entry `status` is `active` | `grant_key_revoked` |
| 4d | `not_before ≤ now < not_after` for the entry (half-open) | `grant_key_inactive` |
| 5 | **Signature.** `external_aad` from **this broker's** `broker_id` (§3.4); `Sig_structure` from the received `protected` and `payload` bytes; strict verification (§3.5) | `grant_signature_invalid` |
| 6 | **Payload decoding.** Payload bytes satisfy §4 (payload rules) | `grant_payload_malformed` |
| 7a | Payload key 0 present as a uint ≠ 1 | `grant_version_unsupported` |
| 7b | **Payload schema.** Top level is a map; all keys are uints; `knd` ∈ {1, 2}; key set equals the set for `knd`; every field has its type and constraints (§5.1; §5.3 generic rules) | `grant_payload_invalid` |
| 8a | **Issuer.** `iss` equals the entry's `iss` | `grant_issuer_mismatch` |
| 8b | **Time order.** `iat ≤ nbf`, `nbf < exp`, and `nbf − iat ≤ skew` | `grant_time_invalid` |
| 8c | **Lifetime from issuance.** `exp − iat ≤ max_ttl` | `grant_ttl_exceeded` |
| 8d | `iat ≤ now + skew` and `nbf ≤ now + skew` | `grant_not_yet_valid` |
| 8e | `now < exp + skew` | `grant_expired` |
| 9a | **Binding.** `aud == broker_id` | `grant_audience_mismatch` |
| 9b | `wid == peer_wid` | `grant_workload_mismatch` |
| 9c | `ten` ∈ tenants registered for `peer_wid` [D-4] | `grant_tenant_mismatch` |

A grant that passes steps 1–9 is **verified**. Unverified grants consume and record nothing (a grant
stolen and presented over another workload's socket is not burned, vector RPL-04).

Because steps 1–9 always run first, a retry of an accepted grant after `exp + skew` gets
`grant_expired`, not the stored outcome (vector RPL-08).

### 7.3 Write grants (`knd = 1`): one decision per grant, recorded atomically

After step 9 the broker opens the **effect transaction** and runs:

| Step | Check | Error code |
|---|---|---|
| W10 | **Consumption**, the first statement: compute `request_hash` (§5.4) and insert `consumed_grant(iss, jti, exp, request_hash, outcome = PENDING)`. If a row for `(iss, jti)` exists: same hash → return the stored outcome (`STORED_OUTCOME`), no effect; different hash → deny without changing the row. Then take `SAVEPOINT decision`. | `grant_replayed` |
| W11a | `op` equals the requested operation and is declared | `grant_op_mismatch` |
| W11b | the declared kind of `op` is `write` | `grant_kind_mismatch` |
| W11c | `opv` equals the declared `opv` | `grant_opv_unsupported` |
| W11d | if the operation `requires_confirmation`, `cfm == 1` | `grant_confirmation_required` |
| W12a | `res` and `con` match the declaration: same key sets (`free` parameters absent from `con`), each `con` class equals the declared class, each `res` value and each exact `con` value has the declared type (§6.2) | `grant_op_schema_invalid` |
| W12b | for each `res` entry: the request has that parameter with an identical value (§5.3) | `grant_resource_mismatch` |
| W12c | for each `con` entry in ascending key order: exact → the request value is identical, else `grant_constraint_mismatch`; bounded → the request value is a uint, else `grant_constraint_mismatch`, and ≤ ceiling, else `grant_bound_exceeded` | `grant_constraint_mismatch` / `grant_bound_exceeded` |
| W13 | **Revocation**: for each `revoked_before` row matching `(ten)`, `(ten, wid)` or `(ten, sub)`, deny if `iat < revoked_before` | `grant_revoked` |
| W14 | Policy, state, and budget preconditions (ADR-0005/0006); execute the effect; set `outcome = ACCEPT`; commit | (outside this spec) |

A missing request parameter or a request value of the wrong type cannot normally reach W12 (the request
parser rejects it), but if it does, W12b/W12c give the codes above (vectors CON-20..23).

**Recording rule (GS-02; ADR-0006 Amendment 1).** On any denial at W10 (`grant_replayed` excepted), W11,
W12, W13 or a W14 precondition, the broker MUST `ROLLBACK TO SAVEPOINT decision`, set the row's
`outcome = DENIED`, and **commit the same transaction**. The consumption row is never rolled back, so no
concurrent submission can insert a fresh row between the denial and its record. If the savepoint
rollback, the update, or the commit fails, or the commit outcome is unknown, the response MUST be
`unavailable` ("nothing was executed"), never `grant_denied`: in that case the grant has received no
decision, and a later submission may still be decided. Thus every `grant_denied` returned for a verified
write grant is backed by a committed `DENIED` row, and SI-09's "verified-and-denied grant later producing
an effect" cannot occur. Later submissions of the same `(iss, jti)` follow W10: identical request → the
stored denial (`STORED_OUTCOME:DENIED`, vector RPL-03); different request → `grant_replayed`.

### 7.4 Read grants (`knd = 2`)

Nothing is consumed or recorded. The read runs in a `READ ONLY` transaction.

| Step | Check | Error code |
|---|---|---|
| R11a | **Whole grant**, for each `rop` entry in map order: undeclared → `grant_op_mismatch`; declared but not `read` → `grant_kind_mismatch`; opv ≠ declared opv → `grant_opv_unsupported`. A read grant is valid or invalid as a whole, independent of the request (vectors OP-07, OP-08, OP-11, OP-14) | as listed |
| R11b | the requested operation is declared | `grant_op_mismatch` |
| R11c | its declared kind is `read` (a read grant never authorizes a write, vector OP-01) | `grant_kind_mismatch` |
| R11d | the requested operation is a key of `rop` | `grant_op_mismatch` |
| R13 | revocation as in W13 | `grant_revoked` |
| R14 | the read query filters by the grant's `ten` and `sub`; a resource the subject does not own is not found, and that result is indistinguishable from any other denial [D-3] | (outside this spec) |

### 7.5 Results and client-facing codes

Error codes are **broker-facing**: they go to the audit log with the detail, never to the workload. The
workload receives exactly one of:

| Broker result | Client-facing |
|---|---|
| `ACCEPT` | the operation's normal result |
| `STORED_OUTCOME` | the response recorded for the first decision on that `(iss, jti)` (may itself be a denial) |
| any `grant_*` code | `grant_denied`, static message "authorization denied" |
| replay store / revocation table / registry unavailable, lock timeout, savepoint or commit failure, unknown commit outcome while recording a denial | `unavailable` ("nothing was executed"), the existing broker code |

### 7.6 Clock

`now` is the broker's clock. The broker MUST persist a clock high-water mark and refuse to serve while
`now < mark − skew` (ADR-0006 §8). Consumed rows MUST NOT be pruned before `exp + skew + margin`.

## 8. Key registry

### 8.1 Key identifier

```
kid = first 16 bytes of SHA-256( "nodkey.kid.v1" || 0x00 || public_key )
```

where `public_key` is the 32-byte RFC 8032 encoding. The kid is derived, never chosen.

### 8.2 File format

The broker loads the registry from an administrator-only path that the workload cannot read or write
(SI-13). It is UTF-8 JSON parsed **strictly**: duplicate member names at any depth, unknown members,
missing members and wrong types are errors. Integers MUST be written as `0|[1-9][0-9]*` (no sign,
fraction, or exponent) with a value ≤ 2^53 − 1.

```json
{
  "format": "nodkey.grant-keys.v1",
  "keys": [
    {
      "kid": "4fcf41a3bf742ec7db96e0aaa5047e3a",
      "alg": "Ed25519",
      "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "iss": "nodkey.authority.test",
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
| `alg` | string | exactly `Ed25519` (COSE −19) |
| `public_key` | string | 64 lowercase hex characters |
| `iss` | string | ID, 1–128 bytes; grants under this key MUST carry this `iss` |
| `purpose` | string | exactly `grant` |
| `not_before`, `not_after` | integer | Unix seconds, `not_before < not_after`; the key is usable for `not_before ≤ now < not_after` |
| `status` | string | `active` or `revoked` |

Draft 1's `role` member is removed; a registry carrying it is rejected as an unknown member.

### 8.3 Load-time validation

The broker validates the whole document and every entry in file order and **refuses to start** (or, on
reload, stops serving — §8.4) if any check fails. Checks, in order:

| Check | Error code |
|---|---|
| The file is strict JSON (§8.2) with exactly the members `format` and `keys`, the right `format`, and a non-empty `keys` array | `registry_entry_invalid` |
| Per entry: exactly the members of §8.2 with their types and value rules, including the `kid` **format** (32 lowercase hex) and the integer rules; `alg`, `purpose`, `status`, `iss`; `not_before < not_after` | `registry_entry_invalid` |
| `public_key` is 64 lowercase hex, decodes to a curve point, and re-encodes to the same bytes (canonical: y < p) | `registry_key_invalid` |
| The point has **order exactly L**: it is not of small order (`[8]A ≠ identity`) **and** is torsion-free (`[L]A = identity`). This rejects the identity, every point of order 2, 4 or 8, and every mixed-order point `P + T` with a non-trivial torsion component `T`. With `curve25519-dalek`: reject if `is_small_order() || !is_torsion_free()`. (`ed25519-dalek`'s `VerifyingKey::is_weak()` checks only the first condition and is therefore not sufficient.) | `registry_key_weak` |
| `kid` equals the derivation of §8.1 | `registry_kid_mismatch` |
| No earlier entry has the same `kid` or `public_key` | `registry_duplicate_key` |

A grant key MUST NOT also appear in any other key registry the process loads (receipt or administrative
keys); a broker that loads several registries MUST check this at load (`registry_duplicate_key`).

### 8.4 Reload

A broker MAY reload the registry at runtime (for key revocation, §8.6). A reload MUST validate the new
file completely (§8.3) and swap it in atomically. If validation fails, the broker MUST stop serving every
grant-requiring operation (fail closed, `unavailable`) and raise an alarm until a valid file is loaded; it
MUST NOT keep serving with the previous registry, because the failed file may have carried a
revocation.

### 8.5 Rotation

1. Generate the new key in the Authority's trust domain; add its public entry (`active`) to every broker
   registry and reload.
2. Switch the Authority to the new key.
3. Keep the old entry `active` for at least `max_ttl + 2 × skew` after the switch (the latest grant signed
   with the old key has `exp ≤ iat + max_ttl` and is accepted until `exp + skew`; `iat` may lead the
   broker clock by up to `skew`), then set its `not_after` (or remove it).

The overlap is bounded by step 8c (lifetime from `iat`) together with the issuer clock rule of §9, and
enforced at the end by step 4d.

### 8.6 Revocation

| Scope | Mechanism | Effect |
|---|---|---|
| A key (Authority compromise) | set `status: "revoked"` and reload (§8.4) | every grant under that `kid` fails at step 4c |
| A tenant, workload, or subject | `revoked_before` row for `(ten)`, `(ten, wid)`, or `(ten, sub)` (ADR-0006 §6) | grants with `iat < revoked_before` fail at W13 / R13 |
| One grant | not needed: write grants are single-use; read grants expire within `max_ttl` | |

Writers of `revoked_before` SHOULD store `floor(t) + 1` for a revocation at time `t`, so that a grant
issued earlier in the same second is also revoked (the comparison is strict `<`) [D-7]. A grant whose
`iat` is later than a `revoked_before` row is not revoked by it (vector REV-09); with steps 8b–8d such a
grant can only exist if the Authority itself future-dates `iat`, which §9 forbids (§11, residual).

## 9. Issuer requirements

The Authority MUST:

- sign only with a key whose private half never enters the workload's trust domain (SI-05), one key per
  purpose;
- set `iat` from **its own clock** at signing time, `nbf = iat`, and `exp = iat + TTL` with TTL ≤ the
  smallest `max_ttl` of the target brokers; it MUST NOT take `iat`, `nbf`, or `exp` from the edge or any
  other caller;
- generate `jti` from a CSPRNG (16 bytes) and never reuse it;
- set `iss` to its registered issuer name and `aud` to the single target broker's `broker_id`;
- for write grants: put every `exact` parameter's value and every `bounded` parameter's ceiling into
  `con`, every resource parameter into `res`, and omit `free` parameters; set `cfm = 1` only when the
  user approved exactly the values in `op`, `res`, and `con` on the auth origin [D-2];
- for read grants: list only operations declared `read` for the target broker, with their declared opv;
- encode the payload and protected header with the core deterministic encoding of §4 (note C8 for text
  keys), with tag 18 and an empty unprotected header.

A general-purpose COSE library can produce conforming grants only if it emits deterministic CBOR with
encoded-byte key order (C8) and is configured for exactly this profile; libraries that sort text keys by
raw string order do not conform.

## 10. Depends on ADR-0003

ADR-0003 rev. 3 was accepted on 2026-10-25 with a **Phase 3 implementation profile** ("Profile n" below
refers to its item n). The items below are where this spec relies on a specific detail of it. Each is
isolated so that a later change touches only the listed fields, steps, and vectors.

| Id | Dependency | What this spec assumes | Touches |
|---|---|---|---|
| D-1 | **Grant kinds** — Profile 6 (R3B-06) | Write (one op, single use, consumed) and read (a set of read ops, multi-use within TTL, never consumed, never valid for a write op); `knd` (17), `rop` (19). | §1, §5, §7.4; ACC-02, ACC-09, ACC-10, OP-01, OP-07..OP-14, PSCH-60..98, TIME-12, REV-08, SIG-39 |
| D-2 | **Confirmation marker** — Profiles 4–5 (R3B-01, R3B-02) | `cfm` (18) = 1 means the gateway's pending effect for exactly these values reached `APPROVED` on the auth origin, bound to the session's subject. Every `ledger.transfer` requires it. Phase 3 approval uses the local test login (Profile 3). | §5.1, §6.1, W11d; OP-13, SIG-38 |
| D-3 | **Parameter classes and destinations** — ADR-0003 §5; Profile 7 | `exact` / `bounded` / `free` for write ops; destination-like parameters are marked `destination: true` and must be `exact`. Phase 3 `ledger.transfer` binds `from` (res), `to` (destination) and `amount_cents` exactly. Read parameters are `owner_scoped`. `test.hold`, `test.bulk`, `test.peek` and `ledger.list_transfers` in the vectors exist only to exercise the format. | §5.3, §6, W12, R14 |
| D-4 | **Tenant check** | `ten` is sourced from the grant and MUST also be one of the presenting workload's registered tenants. | step 9c; BIND-04..06, ACC-06, ACC-12 |
| D-5 | **`sub` sourcing** | `sub` is sourced from the verified grant; there is no independent broker check. | §5.1 |
| D-6 | **TTL** — Profile 6 (write ≤ 30 s) | `max_ttl` ≤ 30 s for both kinds, measured from `iat`; the profile does not fix a read TTL. | step 8c |
| D-7 | **Revocation writers** | The gateway's revoke socket and the operator write `revoked_before`; same-second rounding per §8.6. | §8.6, W13/R13 |
| D-8 | **No grantless effects in Phase 3** | Every operation requires a grant (step 0). | step 0, §6.3 |

ADR-0009 (scheduler / background authority) is deferred to Phase 5 and is **not** part of v1: there is one
issuer role, and Draft 1's `role` / `authority` mechanism and its vectors (ACC-08 scheduler, OP-05, OP-06,
CON-05) were removed (GS-05). A future version that adds a second issuer role must add it as a new
protocol version or an explicitly versioned registry format.

## 11. Security considerations

| Invariant | How v1 supports it | Residual / limits |
|---|---|---|
| **SI-05 No self-minting** | Ed25519 signatures with keys that exist only in the Authority's trust domain; the broker holds public keys only. One issuer role (the Authority). `kid` is derived from the key; the algorithm is fixed by the registry; keys of order other than L are rejected at load; strict verification rejects malleable signatures and small-order `R`. Domain separation: fixed `typ`, `"Signature1"` context, `external_aad` tag `nodkey.grant.v1`, per-purpose keys and a cross-registry duplicate check. | Compromise of the Authority key (attacker J) mints arbitrary grants until the key is revoked (§8.6). |
| **SI-06 Full binding** | Every bound field is checked: `ver`/`typ`/aad (version), `iss` vs kid, `aud` both cryptographically (aad) and by field, `wid` vs socket identity, `ten` vs workload registration, time vs broker clock and vs `iat`, `op`/`opv`/`knd` vs declarations, `res`/`con` vs the request with closed types. Class is encoded in the grant and must equal the declaration; destinations must be exact. | `sub` and `ten` are sourced (D-4, D-5). `free` parameters are unbound by definition (published residuals). Read grants bind the operation set, not the resource; ownership is a state check (D-3). |
| **SI-07 No broadening** | Any change to the signed bytes invalidates the signature (SIG-20..39); strict deterministic decoding means one byte sequence has one meaning (no duplicate keys, no alternative encodings, no ignored trailing data); canonical transport text; unknown keys rejected; no attenuation or delegation; lifetime bounded from `iat`. | For `bounded` parameters, one grant can be used for any value up to the ceiling, once (Phase 3 `ledger.transfer` has none). |
| **SI-08 Default deny** | Every failure in §7 is a deny; registry and declaration errors stop the broker; a failed registry reload fails closed. | — |
| **SI-09 At-most-once** (write grants) | `(iss, jti)` consumption is the first statement of the effect transaction (unique key); every denial of a verified write grant is recorded in the **same** transaction via a savepoint; if recording fails the response is `unavailable`, not a denial (§7.3). One `broker_id` ↔ one replay store (§7.1). | Not claimed across restore of the replay store or clock rollback unless ADR-0006 §8–9 procedures are followed. Concurrency, restart and failure injection require integration tests (§12.2). |

Further considerations:

- **Future-dated issuance.** Steps 8b–8d bound a grant's lifetime to `max_ttl` from `iat` and forbid
  `iat`/`nbf` in the broker's future beyond `skew`. They cannot detect an issuer that sets `iat` itself to
  a future time and lets the grant be presented later (vector REV-09); that is excluded by §9 (the
  Authority's own clock, never caller-supplied times). If the Authority's time source is compromised,
  rotate the key (§8.6).
- **Parser attack surface.** The verifier decodes untrusted CBOR before the signature check (envelope and
  protected header, steps 2–3) and untrusted base64url text (step 1). These decoders MUST be bounded and
  SHOULD be fuzzed. The payload is decoded only after the signature verifies.
- **Error oracle and timing.** Detailed codes are logged, never returned to the workload (§7.5). Failures
  before and after the signature check take measurably different times, so a workload can learn whether a
  grant it holds verifies at this broker. It cannot forge grants, so this is accepted as a residual; no
  constant-time requirement is made (GS-14).
- **Clock.** The ±5 s skew widens every validity window by up to 10 s. Broker and Authority clock
  correctness are stated assumptions (§7.6, §9).
- **Algorithm agility** is by protocol version only (§13); there is no negotiation.
- **Size limits** (2048 bytes, ID lengths, 16 entries per map) bound verifier work per grant.

## 12. Test vectors

### 12.1 Provided

[`tests/vectors/grant-v1/`](../../tests/vectors/grant-v1/README.md) contains 280 grant vectors (293
checked steps, including multi-step replay and multi-use sequences), 26 key-registry vectors, 19
operation-declaration vectors, 11 transport vectors, and 3 request-hash examples. They are generated
deterministically from TEST-ONLY RFC 8032 keys by a committed generator, checked by a reference verifier
that implements this Draft, and cross-checked for signatures with OpenSSL. Expected results are
`ACCEPT`, `STORED_OUTCOME:<ACCEPT|DENIED>`, `LOAD_OK`, `DECODED`, or an exact error code from §7, §8.3 or
§6.3.

### 12.2 Not covered by static vectors

Concurrency (N parallel submissions of one grant), broker restart, replay-store unavailability and
restore, and failure injection into the DENIED recording of §7.3 (integration tests, research 02 §8 items
21–26; review GS-02); registry reload (§8.4); ownership checks of read operations and W14 preconditions;
the `broker_id` sharing rule (§7.1); `exp` near 2^64 (unrepresentable: times are capped at 2^53 − 1 by
step 7b).

## 13. Versioning

- The version appears in three places that MUST agree: `typ` (`application/nodkey-grant+cbor`), the
  `external_aad` tag (`nodkey.grant.v1`), and payload `ver = 1`.
- v1 is Ed25519 only. A new algorithm, a second issuer role, or any incompatible change is protocol v2
  with a new `typ`, a new aad tag (`nodkey.grant.v2`), and new registry entries. A broker accepts an
  explicit configured list of versions and never falls back.
- New payload fields require a new version; reserved numbers (15, 16) are never reused.
- Draft 2 changes v1 semantics relative to Draft 1 (§15). Draft 1 was never deployed; no Draft-1
  compatibility is provided.

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
- `ed25519-dalek` 3.0.0 `VerifyingKey::verify_strict`, `is_weak`; `curve25519-dalek` 5.0.0
  `EdwardsPoint::is_small_order`, `is_torsion_free`.
- Nodkey: ADR-0003, ADR-0004, ADR-0006; research note 02 §4–§8; SECURITY_INVARIANTS v0.3.

## 15. Changes from Draft 1

| Change | Reason |
|---|---|
| Step 8: `nbf − iat ≤ skew` (8b), lifetime `exp − iat ≤ max_ttl` (8c, was `exp − nbf`), `iat ≤ now + skew` (8d); §9 requires Authority-clock times; §8.5 rotation rationale corrected | GS-01 |
| Write grants: consumption (W10) moved before the operation and constraint checks and made the first statement of the effect transaction; every denial recorded atomically via `SAVEPOINT`; recording failure → `unavailable`. RPL-03 step 3 is now `STORED_OUTCOME:DENIED` | GS-02; ADR-0006 Amendment 1 |
| `broker_id` is an ID; one `broker_id` ↔ one replay store and revocation table | GS-03 |
| Registry keys must have order exactly L (`!is_small_order() && is_torsion_free()`); §3.5 states the exact signature rules, including small-order and non-canonical `R` | GS-04, SPEC_ISSUES SI-5 |
| Scheduler role removed: no registry `role`, no operation `authority`, no `grant_issuer_not_permitted`; ACC-08 is now a rotation-overlap ACCEPT; OP-05, OP-06, CON-05 removed | GS-05, SI-05 v0.3 |
| Exactly one `opv` per operation; `request_hash` is normative, uses the requested `op`, no `opv`; expected hashes in the manifest | GS-06, SPEC_ISSUES SI-2 |
| Read grants: every `rop` entry checked (declared, read, opv) before the requested-operation checks | GS-07 |
| Closed parameter type set with grammars (§6.2); `destination` flag; startup refusals listed; reference declaration format; OPS vectors | GS-08, SPEC_ISSUES SI-1, SI-8 |
| Registry: strict JSON with duplicate-member rejection at any depth, integer grammar, reload semantics (fail closed); `kid` format errors and document-level errors are `registry_entry_invalid` | GS-09, SPEC_ISSUES SI-4 |
| C8 text-key ordering stated with an example; §9 COSE-library claim qualified | GS-10 |
| Transport vectors; empty string vs absent defined | GS-11, SPEC_ISSUES SI-3 |
| Every uint in `res`/`con` and the `uint` request type ≤ 2^53 − 1 | GS-12 |
| Cross-registry duplicate key rule (GS-13's role rule is moot without roles) | GS-13 |
| Timing residual stated | GS-14 |
| Retry after expiry gets `grant_expired` | GS-15 |
| `max_ttl` range 1–30 s and the Authority TTL rule | GS-16 |
| 2048-byte ACCEPT vector (ACC-11) and 2731-character transport vector | GS-17 |
| W12b/W12c codes for missing or wrong-type request values stated | SPEC_ISSUES SI-7 |
| README: `jti` derivation described correctly | SPEC_ISSUES SI-6 |
| New key F (not yet valid) and key-window boundary vectors; read-grant missing/extra keys; ID-length boundaries; `rop` limits, ordering and duplicates; SIG-39 (altered `rop`), SIG-40/41 (small-order and non-canonical `R`); REV-09 (future-`iat` residual) | review coverage gaps 1–17 |
| Step numbering: write path W10–W14, read path R11–R14 | consumption-first ordering |
