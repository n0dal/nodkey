# Spec issues found while implementing `nodkey-grant`

These were found while building this crate as an independent second implementation of
[`docs/specs/grant-v1.md`](../../docs/specs/grant-v1.md). The vector generator was not read. The
crate now implements **Draft 2**.

## Draft 1 issues: all resolved in Draft 2

| Id | Issue | Resolution in Draft 2 | Implemented |
|---|---|---|---|
| SI-1 | Parameter types were undefined. | §6.2: closed type set with grammars (manifest `types`). | `ParamType` (closed enum) |
| SI-2 | The `op`/`opv` inputs to `request_hash` were unclear. | §5.4 (normative): hash the requested `op`, with no `opv`. | `Request::request_hash` |
| SI-3 | It was unclear whether an empty transport string counts as missing. | §2: absent means `grant_missing`; `""` decodes to zero bytes and then fails as `grant_malformed`. | `decode_transport` |
| SI-4 | Error codes for a malformed `kid` format and for document-level registry errors were unstated. | §8.3: both are `registry_entry_invalid`. | `Registry::load` |
| SI-5 | Mixed-order keys had no vector. | §8.3: keys must have order exactly L (vector REG-18). | `is_small_order() \|\| !is_torsion_free()` |
| SI-6 | The README described the `jti` derivation incorrectly. | The README now describes it correctly. | ACC-01 test takes `jti` from the grant |
| SI-7 | The W12 error codes for a missing or wrong-type request value were unstated. | §7.3, W12b/W12c (vectors CON-20..23). | `WriteGrant::decide` |
| SI-8 | "Destination-like" parameters could not be checked. | §6.1: a `destination` flag, which requires the parameter to be exact. | `Operations::new` |

## Open items against Draft 2

| Id | Severity | Where | Issue | Reading used here | Proposed fix |
|---|---|---|---|---|---|
| D2-1 | Low (vectors) | CON-24, vectors README | The README says only CON-20..23 carry ill-formed requests. CON-24's request also violates the declaration: `p0` is 257 bytes (`text256` allows at most 256) and `p1`..`p7` are missing. The expected result (`grant_payload_invalid` at step 7) is unaffected, but a broker that parses requests strictly rejects CON-24 before verification. | The harness runs CON-24 through the test-only unvalidated request path, as it does CON-20..23, and asserts that exactly these five vectors take that path. | Give CON-24 a valid request (for example `p0` of 256 bytes and `p1`..`p7`), or list it in the README. |
| D2-2 | Low | §2, TRN-11 | §2 limits the text to 2731 "characters", but the manifest's `text_len` counts UTF-8 bytes (TRN-11 has a non-ASCII character). The verdict is the same either way, because non-ASCII text is invalid. | The limit is checked in bytes. | Say "bytes" (or "ASCII characters") in §2. |
| D2-3 | Low | §6.3 | The crate also refuses a write operation that binds no `res` or `con` parameter, because a grant for it would bind only the operation name (review GC-05). §6.3 does not list this refusal; OPS-01 is unaffected. | Refused (`ops_declaration_invalid`). | Ratify the rule in §6.3 (and add an OPS vector), or drop it from the crate. |
| D2-4 | Low | §7.3, W14 | The spec does not say whether the time checks (4d, 8d, 8e) must still hold at commit. A transaction that waits on locks can commit after `exp + skew` (review GC-03). | Not enforced by the crate. Listed as a caller obligation in the README. | State the rule: re-check `now < exp + skew` at commit, or bound transaction time. |

## `verify_retransmission` / `verify_binding` (payments-adapter-v1 §3.1)

RX-1 to RX-6 are **resolved** by payments-adapter-v1 Draft 3 §3.1 ("Exact verification procedure"). The crate
already matched the resolution: the tenant list is the adapter's configured `tenants`, and an empty list is
now a start-up refusal. RX-3 and RX-6 remain adapter rules on `params()`. Draft 3 adds `verify_binding`
(PA-18): the same checks without the age cap, for lookups only, with its own result type. The table below
is kept for history.

| Id | Severity | Where | Issue | Reading used here | Proposed fix |
|---|---|---|---|---|---|
| RX-1 | Medium | payments-adapter §3.1, §9 | §3.1 says the adapter "performs grant-v1 §7.2 steps 1–9", which includes 9c (`ten` ∈ the workload's registered tenants). But the claim table omits `ten`, and the adapter config (§9) has no tenant registration; `ten` is checked only against the orders view (§3.2). | **Stricter reading:** 9c is enforced against a caller-supplied `workload_tenants` list; an empty list refuses everything. | Either add `tenants` to the adapter config, or state that 9c is replaced by §3.2. |
| RX-2 | Low | §3.1 | "Steps 1–9" includes 8e (`exp`), which the table says is not checked. It is also unclear whether 4c (key `status: revoked`) applies, and whether 8b/8c (time order, lifetime from `iat`) apply. | 8e omitted. 4c, 8b and 8c applied. 4d (key window) is evaluated at `iat`, as §3.1 says ("key validity at `iat`"). | List the exact grant-v1 steps that run, with 4d at `iat` and 8e replaced by the age rule. |
| RX-3 | Low | §3.1, effect-protocol-v2 op table | `amount_minor` must be a uint ≥ 1. The grant-v1 §6 declaration format cannot express "≥ 1", so a generic verifier cannot check it. | The crate checks keys, classes and declared types only (`amount_minor` is `uint`). The adapter MUST check `amount_minor ≥ 1` on `RetransmissionAuthorized::params()`. | Add a `min` attribute to §6.1, or keep the rule in the adapter and say so in §3.1. |
| RX-4 | Low | §3.1 | The table lists `aud` as a separate claim check. With grant-v1 the audience is also bound in `external_aad`, so a grant for another `aud` fails at signature verification (step 5), before any claim check. The outcome is the same (`grant_refused`). | Both checks run. | None needed; consider noting it. |
| RX-5 | Low | §3.1 | The order of the age check relative to 9a–9c, and the error codes used, are unspecified. Every failure maps to `grant_refused`, so the order only affects audit logs. | Order: clock floor, 1c–7, 4d at `iat`, 8a–8d, age, 9a–9c, kind, `cfm`, `op`, `opv`, `res`/`con`. | State the order, or explicitly leave it unspecified. |
| RX-6 | Low | §3.1 | `charge_id` is declared `text64`, and the broker may store the reserved value `unresolved` (effect-protocol-v2 Draft 3.1). The grammar `^ch_[A-Za-z0-9]{8,64}$` (§7.1) is not part of the declaration, so the verifier accepts any `text64`. | The adapter's order-view check (§3.2) catches it (`charge_id` must equal the `orders` row). | Give `charge_id` a closed type, or require that `unresolved` is never signed. |
