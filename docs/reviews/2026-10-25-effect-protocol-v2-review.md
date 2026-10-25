# Review: effect protocol v2 (Draft 1)

- **Subject:** `docs/specs/effect-protocol-v2.md` Draft 1 (2026-10-25).
- **Context read:** ADR-0011 incl. Revision 1; `docs/reviews/2026-10-25-adr-0011-review.md`; SECURITY_INVARIANTS
  SI-05/06/09/10/15/20/21; grant-v1 §4, §5.3–5.4, §7.1–7.3, §8.2, §9.
- **Method:** specification review only, time-boxed. No code exists for this spec; nothing was run. Every
  finding is a reading of the text, with the cited section. Reproductions are described as test procedures.
- **Severity:** Critical / High / Medium / Low. "Blocks" = must be fixed in the spec before implementation starts.

## Verdict

**Revise before implementation (Draft 2).** The structure is sound: the workload never holds a write
grant, the CAS state machine and `jti = pending_id` give a credible exactly-once story, and the page
contract closes PC-02/03/05/11. But four High findings block implementation:

- EP-01: a crash or failure between `APPROVED → EXECUTING` and grant consumption leaves records stuck with
  no defined recovery, and the deliver results cannot express grant-v1's `unavailable`;
- EP-02: the authority signs whatever the broker reports as `APPROVED`, so the signature adds no check
  independent of the broker's database, which contradicts ADR-0011's "Signed grants still matter" claim;
- EP-03: under `approver_source: named`, mandate lookup by `(wid, approver)` lets a compromised workload
  spend any user's mandate with no confirmation;
- EP-04: the digest is not guaranteed to be byte-identical between gateway and broker, because the spec
  does not fix the type source, the `pending_id` form, or the text rules.

EP-05 (who signs read grants) and EP-06 (the delivery deadline is not in the CAS) also block. They are
small text fixes.

**Answer to the digest question:** *not as written*. The CBOR rules are adequate, since they reuse grant-v1
§4. The inputs are not: the spec does not say whether value types come from JSON or from the declaration,
whether the `pending_id` bytes come from a canonical decode, how text is restricted or escaped, or how
the hex digest is cased. Two independent implementations could disagree. Fixing EP-04 and extending
T28's vectors closes this.

## Findings

### EP-01 — `EXECUTING` without consumption: no atomicity, no recovery, and the `unavailable` outcome is unmapped (High, blocks: yes)

**Section:** §6 step 4 (c)/(d); §3.3 `APPROVED → EXECUTING`; grant-v1 §7.3 recording rule.

**Issue.** Step (c) runs the CAS `APPROVED → EXECUTING` and sets `grant_jti`. Step (d) then runs W10–W14.
The spec does not say whether (c) and (d) run in one database transaction, or whether `pending_effect` and
`consumed_grant` are in the same store. If (c) commits on its own, and then the broker crashes, W10's
insert fails, or W13 denies before the savepoint is recorded:
- the record stays `EXECUTING` forever. §3.3 gives no transition out of a bare `EXECUTING`; the reconciler
  handles only `UNKNOWN`;
- the authority's retry gets `already_delivered`, so nothing can ever finish the effect;
- `effect.status` reports `EXECUTING` indefinitely.

grant-v1 §7.3 also requires `unavailable` ("nothing was executed, a later submission may still be
decided") when recording fails. The §6 result table has no such outcome. It collapses into `not_available`,
and the retry then hits `already_delivered`. That violates grant-v1's own rule that such a grant "has
received no decision".

Conversely, if (c) and (d) are in one transaction but the pending-record final state is written in a
separate commit, `consumed_grant.outcome` and `pending_effect.state` can disagree after a crash.

**Fix.**
- Require one database, and one transaction, for (c), W10–W14 and the `EXECUTING` → final transition
  (or `RESERVED`/`DISPATCHED` per research 06 §2.2). On a recording failure, the whole transaction rolls
  back and the record stays `APPROVED`.
- Add `unavailable` to the deliver results. The authority MAY retry only while the delivery deadline holds.
- Add a recovery rule: on start-up and in the sweeper, an `EXECUTING` record with no `consumed_grant` row
  for `(iss, grant_jti)` past `exp + skew` → `FAILED` with `outcome.class = failed`. This is safe because
  no consumption means no effect.
- State that the adapter sub-states persist in the same store.

### EP-02 — The authority adds no independent check: it signs on the broker's word alone (High, blocks: yes, either fix or narrow the claim)

**Section:** §6 steps 1–3 ("The authority ignores any other content"); ADR-0011 Consequences, "Signed grants
still matter".

**Issue.** The authority's only input is `pending.fetch_approved` from the broker, and the broker later
verifies the grant. Anyone who can set `state = APPROVED` in the broker database gets a grant. That
includes a bug or injection in the broker's workload-socket parsing, and any write path to
`pending_effect`; the schema trigger guards the immutable columns, not `state`. ADR-0011 claims that
"compromise of … the broker's request parsing does not let either mint authority". Under this spec, the
signature attests only "the broker's DB said APPROVED", and the broker is also the verifier. SI-20
("no write grant is issued unless the intended approver … approved it") then rests entirely on broker
DB integrity.

**Fix (cheap, Phase 3).**
- Make `issue` carry `{pending_id, digest, subject, decided_at}` from the gateway.
- The authority MUST require it to equal the fetched record's `(digest, ten, approver_sub)`. Issuance then
  needs the gateway and the broker to agree, two processes instead of one.
- Better: the gateway MACs or signs this approval statement with an approval key held only by the gateway.
  With passkeys, this becomes the WebAuthn assertion over `digest`, verified by the authority.
- Otherwise, narrow the ADR-0011 claim to "a compromised broker can obtain grants for any record it marks
  `APPROVED`". Publish that as a residual next to attacker J.

### EP-03 — `named` approver + mandates = workload-chosen mandate spending (High, blocks: yes, one sentence)

**Section:** §2.4, last sentence ("Mandates … are looked up by `(wid, approver)` as stored").

**Issue.** Under `named`, the workload chooses `approver.sub` freely within its tenants. The stored approver
is therefore workload-chosen, and PC-06's fix ("the broker selects the mandate from the intended approver")
does not hold for multi-user apps. The attack: a compromised Demo P workload proposes effects naming each
user who holds an active mandate for that `wid`. Each proposal falls within that user's mandate, so it
skips confirmation. No user is involved at any point. This is the PC-06 attack restored.

**Fix.** "Mandates MUST NOT apply to records whose workload has `approver_source = named`." The mandate
spec may later define a per-use proof of the user's presence. Add test T31.

### EP-04 — Digest inputs under-specified: gateway and broker can compute different bytes (Medium, blocks: yes)

**Section:** §3.2, §4.1, §7.1, §7.2.

**Issue.** The CBOR encoding is fixed (grant-v1 §4), but the mapping from the render response, which is
JSON, to `M` is not. The spec does not say:
1. **Type source.** Is a parameter's CBOR type (uint vs tstr) taken from the JSON value type or from the
   operation declaration? An `account_id` such as `"12345"` would digest as tstr through one path and as
   uint through another. Does the gateway even hold the declarations? §5 places them in "the broker's
   effects configuration".
2. **`pending_id` bytes.** Are they from a canonical base64url decode? A 22-char base64url string carries
   4 spare bits. A lenient decoder accepts 16 spellings of one id, and §7.1's grammar check does not
   require canonical form. The approval token binds "this `pending_id`" without saying whether that means
   the string or the bytes.
3. **Text.** Which character set? grant-v1 §5.3 limits text to `0x20–0x7E` and 256 bytes, but §3.2 does not
   cite that. Is JSON `\u` escape decoding required before encoding?
4. **`digest` (hex) in the form.** Lowercase only? Compared as bytes or as text?
5. **The key-7 map.** It uses parameter *names*, while the grant uses numbers 0–15, which is fine. But it
   must hold **every** declared parameter, including `free` ones (none exist in Phase 3/4). Is that
   stated? The `request_hash` rule (grant-v1 §5.4) says so; §3.2 does not.
6. **Display.** The amount exponent (from the "ledger currency" or the "broker-trusted table") is not in
   the digest, and §7 does not say where the gateway gets it. A gateway/broker table mismatch displays
   `1000.00` vs `10.00` under the same digest. SI-20 requires "a digest of exactly the values displayed".

**Fix.**
- Types come from the broker-supplied declaration, carried in the render response and itself digested
  (add key 10: `opv`'s parameter type list), or from a declaration copy the gateway holds, checked for
  equality at start-up.
- `pending_id` is canonical unpadded base64url (grant-v1 §2 rules), decoded to exactly 16 bytes; everything
  is compared as bytes.
- Text follows grant-v1 §5.3 generic rules.
- The digest is lowercase hex, 64 chars, compared after decoding.
- Exponents and currency come from `facts` supplied by the broker. Either digest the currency and exponent
  used for display, or require the gateway to format from broker-supplied exponents only.
- Publish shared vectors covering each of these points (extend T28).

### EP-05 — Who signs read grants? "The gateway cannot sign" vs ADR-0011 "read grants … issued by the gateway" (Medium, blocks: yes)

**Section:** §4 opening; §2.3 read methods; ADR-0011 "Read operations"; grant-v1 §8.2 (`purpose` is exactly
`grant`, with no restriction on `knd`).

**Issue.** If the gateway holds a read-grant key, that key is in a registry whose entries are not restricted
by `knd`, so it can also sign `knd = 1` write grants. Those are accepted on the authority socket by anyone
holding the authority uid. They are also accepted by any later channel that relaxes PC-13. If the gateway
holds no key, the spec does not say how read grants reach the workload. In both cases SI-05's boundary is
undefined.

**Fix.**
- Specify the read-grant issuance path (for example, the authority signs on an `issue_read` request over
  the issue socket).
- Or add `knd` (or `kinds`) to the key-registry entry, so the broker rejects a write grant under a
  read-only `kid`.
- Restate in §4 which process holds which key.

### EP-06 — Delivery deadline is not part of the `APPROVED → EXECUTING` CAS (Medium, blocks: yes, text)

**Section:** §3.3, §6 step 2 vs step 4(c), §2.5.

**Issue.** Only `fetch_approved` checks the 60 s deadline. The deliver CAS checks just `state = APPROVED`.
The sweeper is periodic, and the "lazily on access" rule is listed only for `PENDING`. So a fetch at
t = 59 s followed by a deliver at t ≈ 89 s (grant TTL 30 s) executes after the deadline. The bound is
loose but real, and T29 assumes it does not happen. The `grant_jti is null` condition on
`APPROVED → EXPIRED` is redundant, because `grant_jti` is set in the same CAS that leaves `APPROVED`.
Readers may take it as meaningful.

**Fix.** Add `now < state_changed_at + deadline` to the deliver CAS. Expire lazily on every access in every
non-final state. Drop the redundant condition or explain it.

### EP-07 — Refund approval check is a deny-list on status; pending siblings not shown (Medium, blocks: no)

**Section:** §5 `payments.refund`.

**Issue.**
1. "order status ≠ `disputed`" admits every other status, including future ones: `pending` or not yet
   captured, `voided`, `fully_refunded`, `chargeback`. This fails open on unknown statuses, against SI-15
   and owner rule 8.
2. TOCTOU between display and execution is handled correctly for the amount: execution re-checks
   `1 ≤ amount ≤ remaining_refundable` under lock, and denial → `FAILED/denied`. But the page's
   encumbrance list omits **other non-final records on the same order** (`PENDING`, `APPROVED`,
   `EXECUTING` before `RESERVED`). Example: a user is shown three proposals, each for the full remaining
   amount. They read as independent and all approvable. Two fail later, with only `effect.status` to
   explain why, and the user is never told.
3. If the remaining amount *rises* after approval (a reservation is released), the effect still executes
   for the approved amount. That is correct, but the shown `remaining_refundable` is stale for up to 300 s
   (the token lifetime).
4. "A refund that later fails keeps its amount encumbered until it is released": the releaser and its
   trigger are unspecified.

**Fix.**
- Use an allow-list (`status ∈ {captured, partially_refunded}`). An unknown status → the check fails.
- Show the count and amounts of other non-final effects on the order.
- Specify the release (reconciler only, after upstream confirms failure).
- Publish the staleness as a residual.

### EP-08 — `named` banner: honest but weak, and destination operations should not be `named` (Medium, blocks: no)

**Section:** §2.4, §7.1.

**Issue.** The banner text is accurate. But it appears on *every* request from a multi-user app, so users
learn to ignore it (PC-08). It also does not say what the user should check. For `payments.refund` the
harm is bounded, because the money goes to the original payment method of the approver's own order. For
`ledger.transfer` with a workload-chosen `to`, a compromised multi-user app can send a phishing link to
each user ("confirm your transfer") at volume. The only defence is the fact line "an account not owned by
you".

**Fix.**
- Banner: "Approve only if you just asked <app> to do this." Show it next to the action buttons, not only
  at the top.
- Forbid `named` for operations with a `destination: true` parameter in Phase 3, or require that such a
  destination is owned by the approver.
- Publish the residual.

### EP-09 — Channel isolation depends on mounts; the start-up check fails open (Medium, blocks: no)

**Section:** §1.

**Issue.**
1. The gateway and authority sockets share `/run/nodkey/ctl/`. If the directory is bind-mounted, the
   gateway also sees `authority.sock`. The uid check rejects it, but that leaves a single layer of
   defence.
2. "(where the deployment manifest is available to the broker)": when it is not, the mount check is
   silently skipped. That is a fail-open start-up check.
3. Socket file mode and ownership are not specified.
4. `SO_PEERCRED` uids are translated into the broker's user namespace. Workload and gateway uids that are
   distinct inside their containers but map to the same host uid (or the reverse) are not addressed.
5. Anyone holding the authority uid can call `fetch_approved` and read every approved record's params and
   approver. That is a minor disclosure; delivering a grant still needs the key.

A workload cannot impersonate the authority without both the authority uid **and** a mount of `ctl/`,
and a forged grant still fails the signature check. So the risk is defence-in-depth, not a bypass.

**Fix.**
- Use separate directories per control socket, with modes 0700 and 0600 owned by the peer uid.
- If the manifest is unavailable, refuse to start unless an explicit operator flag (logged) says the
  check was done externally.
- Compare uids in the broker's namespace and document the mapping requirement.

### EP-10 — Demo 1 v1 (grantless writes) can coexist with v2 in one broker (Medium, blocks: no)

**Section:** §2.1.

**Issue.** "Each workload socket is configured for exactly one version." A production deployment could
still configure one socket as v1, which gives grantless `ledger.transfer` and bypasses every guarantee in
this spec. Nothing stops this except configuration.

**Fix.** The broker refuses to start if any v1 socket is configured and the profile is not the explicit
Demo 1 profile, or if v1 and v2 sockets share a broker or database. Add test T32.

### EP-11 — `jti = pending_id`: sound, with three caveats to state (Low, blocks: no)

**Section:** §6 "Exactly-once"; grant-v1 §9.

**Assessment.** There is no practical collision risk:
- `pending_id` is a 128-bit broker CSPRNG value and the primary key;
- `aud = broker_id`, and grant-v1 §7.1 requires one replay store per `broker_id`, so ids from other brokers
  or tenants never share a consumption namespace;
- the workload knowing the `jti` grants nothing.

**Caveats.**
1. The authority re-signs the same `jti` on retry. That literally violates grant-v1 §9 "never reuse it",
   so amend §9 rather than "refine" it silently.
2. The authority's own CSPRNG `jti`s for read grants share the `(iss)` namespace with broker ids.
   Collisions are negligible at 128 bits, and read grants are not consumed, but say so.
3. The guarantee depends on the broker's CSPRNG and on `pending_effect` + `consumed_grant` being restored
   together (ADR-0006 §8–9). Restoring `pending_effect` alone, with a row back in `APPROVED`, could
   re-execute it. Tie this to EP-01's single-store rule.

### EP-12 — `effect.status` and execution outcomes leak a small amount (Low, blocks: no)

**Section:** §2.3, §3.3, §5.

**Issue.** After a user approves, `outcome.class` tells the workload whether execution-time checks passed.
For `ledger.transfer`, the approval checks cover only `from`. A nonexistent `to` therefore fails at
execution, and the workload learns whether another tenant's account exists. This needs a user approval,
so the leak is small. It is otherwise well contained: there is a uniform `not_found`, and approver,
facts and upstream text are excluded.

**Fix.** Check that `to` exists at approval; the page already says "not owned by you" without revealing
existence. Or publish this as a residual. Pin `receipt_id` as opaque and non-sequential.

### EP-13 — Minor ambiguities (Low, blocks: no)

- **§7.1 login return.** How is the "same path" carried through login? If it travels in a query parameter,
  it must be validated against `^/confirm/<canonical id>$` or stored server-side. Otherwise PC-11 returns
  through the login page.
- **§3.3 "under row locks".** The database is unspecified. On SQLite, there are no row locks; say
  `BEGIN IMMEDIATE`, or the equivalent serialization.
- **§7.3 step 4 / §7.2.** The token is consumed even when the CAS later fails. State this deliberately so
  that a stale render cannot be retried with a new token.
- **§3.2 domain tag.** The `"nodkey.pending.v1"` domain tag sits inside protocol v2. That is fine, but
  say it versions the record format, not the protocol.
- **§2.5.** A `named` workload can fill its 32-record quota by rotating `sub`. That only denies service to
  its own users, but note it.

## Missing tests (add to §8)

| # | Case | Expected | Maps to |
|---|---|---|---|
| T31 | `named` workload proposes within another user's active mandate | confirmation still required; no grant | EP-03, PC-06 |
| T32 | Broker started with a v1 socket outside the Demo 1 profile; v1 and v2 on one DB | refuses to start | EP-10 |
| T33 | Crash or forced error after the `APPROVED → EXECUTING` CAS and before W10 commits; W10 insert fails; savepoint record fails | record not stuck: returns to `APPROVED` or → `FAILED` by the recovery rule; deliver returns `unavailable`, never `not_available` + `already_delivered` with no decision | EP-01, SI-09, SI-15 |
| T34 | Fetch at the deadline − 1 s, deliver after the deadline | CAS fails; no effect | EP-06 |
| T35 | Authority given an `issue` whose digest or subject ≠ record; broker DB row forced to `APPROVED` without a gateway approval | no grant (after EP-02 fix) | EP-02, SI-20 |
| T36 | Write grant signed under a read-only `kid` (or by a gateway key) delivered on the authority socket | rejected | EP-05, SI-05 |
| T37 | Digest vectors: numeric-looking tstr id; uint 2^53−1; JSON-escaped text; non-canonical base64url `pending_id` (alias spellings); uppercase hex digest | identical bytes, or a defined rejection, in both implementations | EP-04 |
| T38 | Concurrent approve + deny + sweeper-expire at `expires_at` ± 1 s | exactly one transition wins; no grant if not `APPROVED` | §3.3, SI-20 |
| T39 | `revoked_before` set, or signing key revoked, between approve and deliver | `FAILED`/`denied` (W13) or `not_available`; no effect | SI-08, W13 |
| T40 | Ownership change between approve and execute (`from` account or order owner changes; order status → `voided`/unknown) | `FAILED`/`denied` | SI-10, SI-11, EP-07 |
| T41 | Two pending refunds, each for the full remaining amount, both approved | the first succeeds, the second `FAILED`/`denied`; the page for the second shows the first as non-final | EP-07, SI-11 |
| T42 | Broker start-up refusals of §1 (shared uid, gateway uid = workload uid, `ctl/` mounted, manifest absent) | refuses (after EP-09 fix, including manifest absent) | §1, EP-09 |
| T43 | Wrong-uid peer on the **issue** socket; workload attempts to connect to each control socket path | rejected / path not present | §1, PC-13 |
| T44 | Login with a crafted return target; `Sec-Fetch-Site: same-origin` with `Sec-Fetch-Mode: cors` | uniform error / return only to the canonical confirm path | EP-13, SI-21, PC-11 |
| T45 | `effect.status` for `DENIED`, `EXPIRED`, `UNKNOWN`: field set and `receipt_id` null rules; no approver or facts | as §2.3 | PC-10 |
| T46 | Authority retry after a lost `accepted` response: the second grant is inert on every channel | `already_delivered`; on the workload socket `grant_channel_invalid` | §6, SI-09 |

Existing-test notes:
- T19 should also cover concurrent approve vs deny.
- T28 should list its vectors (see T37).
- T29 should assert the `EXPIRED` transition *and* that a late delivery fails (T34).
- T30 should include the `EXECUTING`-before-`RESERVED` boundary (T33).

## Blocking summary

EP-01, EP-02, EP-03, EP-04, EP-05, EP-06. All are specification changes; EP-02 can alternatively be
resolved by narrowing the ADR-0011 claim and publishing the residual.

## Resolution (Draft 2, 2026-10-25)

Recorded by the spec author. Blocking findings EP-01..EP-06 are resolved per the orchestrator's rulings, in [`docs/specs/effect-protocol-v2.md`](../specs/effect-protocol-v2.md) Draft 2 (§9 lists every change). No finding is rejected. Re-review is requested.

| Id | Severity | Disposition | Where |
|---|---|---|---|
| EP-01 | High | **Fixed.** The broker stores the grant at `PENDING → APPROVED`. Verification, W10 consumption, savepoint, W11–W14, and the effect (or the `RESERVED` insert) all run in one transaction. A failure rolls back to `APPROVED`. A recovery loop retries at start-up and every 5 s, and expires the record at `grant.exp + skew`. `grant.deliver` can return `unavailable`. Re-delivery of the same grant bytes is idempotent, which removes the `already_delivered` dead end. The single-store rule is stated. | §3.1, §3.3, §4.3, §4.4 |
| EP-02 | High | **Fixed.** New gateway → authority `approve{pending_id, digest_shown, subject}`. The authority fetches the record read-only, recomputes the digest, and checks the subject. It records `jti = pending_id` in its own durable store before signing, then delivers. Broker state alone no longer yields a grant. The gateway is stated to be in the TCB for the subject; a compromised gateway is a published residual until passkeys. ADR-0011 Amendment 1. | §1.1, §4.2, §6, §7.6 |
| EP-03 | High | **Fixed.** Mandates apply only to `enrolled` workloads. `named` workloads need explicit confirmation for every write. | §2.4 |
| EP-04 | Medium | **Fixed.** The digest input is fully normative: declared types (key 10), canonical `pending_id` bytes, exact text bytes with no normalization, every parameter, display exponent and currency (key 11), lowercase 64-char hex decoded before comparison. Vectors DG-01..10 are in `tests/vectors/effect-v2/`, checked by a Rust generator and a Python stdlib re-encoder and hasher. | §3.2; T28, T37 |
| EP-05 | Medium | **Fixed.** Read grants are signed only by the authority (`read_grant` over socket I). The gateway holds no key. | §4.2 |
| EP-06 | Medium | **Fixed.** Delivery requires `PENDING` and `now < expires_at`. Execution expires at `grant.exp + skew` and the grant is never used. The authority marks the issuance `expired`. Records expire lazily on every access. The redundant `grant_jti` condition is removed. | §3.3, §4.2 step 6, §4.4 |
| EP-07 | Medium | **Fixed.** Refund status is an allow-list. `other_open_on_resource` is shown. Only the reconciler releases encumbered amounts. Fact staleness is a published residual. | §5 |
| EP-08 | Medium | **Fixed.** The banner sits next to the buttons. `named` workloads may not use operations that have destination parameters. | §2.4, §7.1 |
| EP-09 | Medium | **Fixed.** Each socket has its own directory with modes and ownership. A missing manifest means refusal unless an explicit, logged operator flag is set. The uid namespace rule is stated. | §1.2 |
| EP-10 | Medium | **Fixed.** Start-up refusals for v1 outside `demo1`, and for v1 and v2 sharing one broker or one database. | §2.1 |
| EP-11 | Low | **Fixed.** The `jti = pending_id` override of grant-v1 §9 is stated. The authority never signs two grants for one `jti`. The read-grant `jti` namespace is noted. The restore requirement is tied to the single store. | §4.2, §4.4 |
| EP-12 | Low | **Accepted as a residual** (the execution oracle requires a user approval). `receipt_id` is opaque and random. | §2.3, §6 |
| EP-13 | Low | **Fixed.** Login return is stored server-side. PostgreSQL `FOR UPDATE` is named. The token is consumed even when a later step fails. The domain-tag note and the quota note are added. | §7.1, §3.3, §7.2, §3.2, §2.5 |
| Missing tests | — | T31–T46 added. T28–T30 extended. | §8 |
