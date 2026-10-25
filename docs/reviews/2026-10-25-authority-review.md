# Review: nodkey-authority (commit 8400135)

- **Date:** 2026-10-25
- **Scope:** `crates/nodkey-authority/` at commit 8400135. Every file in `src/` was read in full, and the
  test list was checked.
- **Contract:**
  - effect-protocol-v2 Draft 2: §1.1, §1.2, §2.4, §3.2, §4.2, §4.3 and §8;
  - grant-v1: §7.2, §7.6, §8, §9 and §11;
  - `crates/nodkey-grant/README.md` (issuer);
  - ADR-0011 and its Amendment 1;
  - SI-05, SI-09, SI-13, SI-14 and SI-20.
- **Method:** adversarial source review against the contract. No Docker was run and no code was changed.
  This file is the only file written.

## Test evidence

Command: `cargo test` in `crates/nodkey-authority` on macOS. The output, trimmed to the result lines:

```
unittests src/lib.rs        test result: ok. 10 passed; 0 failed; 0 ignored
unittests src/main.rs       test result: ok. 0 passed; 0 failed; 0 ignored
tests/approve.rs            test result: ok. 15 passed; 0 failed; 0 ignored
tests/config.rs             test result: ok. 5 passed; 0 failed; 0 ignored
tests/crash.rs              test result: ok. 2 passed; 0 failed; 1 ignored
tests/digest_vectors.rs     test result: ok. 1 passed; 0 failed; 0 ignored
tests/read_grant.rs         test result: ok. 2 passed; 0 failed; 0 ignored
tests/store.rs              test result: ok. 6 passed; 0 failed; 0 ignored
```

That is 41 passed and 0 failed. The one ignored test is `child_authority`, a helper that the SIGKILL test
re-executes as a child process; it is ignored by design.

These configurations were **NOT TESTED**, here or by the implementer:
- Linux (`SO_PEERCRED`);
- distinct-uid deployment;
- a real broker (all tests use a fake broker).

## What holds (verified in source)

### Signing only what was approved

- The authority recomputes the §3.2 digest itself from the fetched record and requires it to equal **both**
  the broker's `digest` and `digest_shown` (`server.rs:190-200`).
- The record is parsed strictly. CBOR types come from the declared type, the `pending_id` must be
  canonical, and every declared parameter must be present (`digest.rs:155-251`).
- The fetched `pending_id` and `broker_id` must match (`server.rs:173-182`).
- The record must be `PENDING`, and `now < expires_at` must hold (`server.rs:183-189`).
- The subject must equal `(ten, approver_sub)` (`server.rs:201`).
- The workload's tenant and write-op registration are checked (`server.rs:204-213`).
- The operation must be a confirmed write, and `opv` and `param_types` must equal the declaration
  (`server.rs:214-231`).
- `approver_source` is enforced: `enrolled` must equal the enrolment, and `named` may not use a
  destination operation (`server.rs:232-243`).
- The grant takes every value from the record, and the times come from the authority's own clock
  (`server.rs:266-288`). `bounded` and `owner_scoped` bindings are refused, both at load and at signing.

### Exactly-once issuance

- The store mutex is held from the existence check through signing and the fsync'd insert
  (`server.rs:246-322`).
- Delivery starts only after `insert` returns.
- A row that exists with a different digest or subject raises an alarm and is never signed again.
- Final rows are never re-signed.
- An exclusive `flock` stops a second process (`store.rs:153`).
- Any complete line that is corrupt refuses to open. This covers a bad checksum, a duplicate `jti`, a
  status for an unknown `jti`, and a transition out of a final status (`store.rs:201-235`).
- A failed write poisons the store (`store.rs:272-290`).
- The README's AU-5 argument is sound: at most one grant per `jti` can ever leave the process.

### Keys

- The key file must be regular, not a symlink, and its dev/ino must be unchanged after opening.
- It must be owned by the authority uid, with no group or other bits.
- Its size is bounded, and its content must be lowercase hex. The buffers are `Zeroizing`.
- The derived `kid` must equal `signing_kid` (`key.rs:40-73`, `main.rs:146-150`).
- `keygen` uses `create_new` (O_EXCL, which also refuses a symlink), mode 0600, and fsyncs both the file
  and its directory. It self-checks the registry with `Registry::load` (`key.rs:81-151`).
- No log line contains key material or grant bytes; all call sites were reviewed.

### Channels

- Socket I closes any peer whose uid is not `gateway_uid` without sending a response
  (`server.rs:530-545`).
- Socket A checks the broker's peer uid and `config.digest` on **every** new connection
  (`broker_client.rs:90-124`).
- After any failure, the socket A connection is discarded and never reused (`broker_client.rs:187-190`).
- Framing: lines are at most 8 KiB, JSON is strict with duplicate keys rejected at any depth, member sets
  must be exact, and the response `id` must match.

## Findings

No Critical or High finding.

| ID | Severity | Blocks |
|---|---|---|
| AU-R-01 | Medium | no |
| AU-R-02 | Medium | no (yes before any non-local deployment) |
| AU-R-03 | Medium | no (spec-owner decision) |
| AU-R-04 | Low | no |
| AU-R-05 | Low | no |
| AU-R-06 | Low | no |
| AU-R-07 | Low | no |
| AU-R-08 | Low | no |
| AU-R-09 | Low | no |
| AU-R-10 | Low | no |
| AU-R-11 | Info | no |
| AU-R-12 | Info | no |

### AU-R-01 (Medium): the `display` member (key 11) comes from the broker and is never validated

- **Where:** `src/digest.rs:221-235`; `src/server.rs:172-243` (no check on `rec.display`).
- **Scenario:**
  1. An attacker with write access to the broker database, which §1.1 says "alone cannot produce a
     grant", inserts a `PENDING` `payments.refund` record for a real order owner with
     `amount_minor = 1000000` and `display = {"amount_exponent": 6, "currency": "USD"}`.
  2. The gateway formats amounts **only** with key 11 (§3.2). The user sees "1.000000 USD" and approves.
  3. The digest matches everywhere, because it covers the falsified `display`.
  4. The authority signs a grant for 1,000,000 minor units, which is USD 10,000.
- **Impact:** the user approved a value whose meaning was misrepresented. This is the SI-20 phrase "exactly
  the values displayed" being honoured in bytes but not in meaning. One click turns a broker-DB compromise
  into a grant, which weakens the two-independent-inputs property of §1.1 and ADR-0011 Amendment 1.
- **Related gap:** for `payments.refund`, nothing requires `display.currency` to equal `params.currency`
  either.
- **Fix:** give the authority, and the gateway, their own copy of the display rules: per operation, which
  display keys are allowed and the ISO 4217 exponent table. Then either recompute key 11 from the record's
  parameters or reject a mismatch. Include that table in `config.digest`. If the spec owner declines,
  publish this as a §6 residual.

### AU-R-02 (Medium): configuration and store files are read without any owner or mode check (SI-13)

- **Where:** `src/config.rs:22-33` and `src/config.rs:220-289`, which cover the config, operations,
  workloads and manifest files; `src/store.rs:146-151` (the store file).
- **Scenario:** a principal other than the administrator can write the config file. This includes the
  gateway uid, through a misdeployed directory or a group bit. That principal then:
  1. sets `broker_socket` to a path it listens on, and `broker_uid` to its own uid;
  2. its fake "broker" answers `config.digest` with the right digest, which is public, and serves
     `PENDING` records with any values;
  3. the gateway approves them as any logged-in user;
  4. the authority signs whatever it is shown.

  The key file is protected, but the file that decides **who the authority trusts** is not. The store file
  is created or opened without `O_NOFOLLOW` or owner/mode checks. An existing 0644 store discloses every
  grant and subject, and a writable store can be truncated to erase issuance history; the broker's
  `PENDING` precondition still bounds the effect of that.
- **Fix:** apply the key-file checks to every configuration path and its parent directories:
  - a regular file, not a symlink, with the dev/ino re-checked;
  - owned by root or the authority uid;
  - not writable by group or other.

  For the store file, require owner = the authority uid and mode 0600 at open, and open it with
  `O_NOFOLLOW`. Add negative tests.
- **Blocks:** not for a local prototype, but this must be fixed before any non-local deployment.

### AU-R-03 (Medium): `read_grant` for an `enrolled` workload accepts any subject in the tenant

- **Where:** `src/server.rs:423-440`.
- **Scenario:**
  1. Agent workload `A` is enrolled for principal `P` in tenant `t`.
  2. The compromised `A` sends user `Q` of tenant `t` a link to its origin.
  3. `Q` clicks it. A top-level navigation is allowed by SI-21.
  4. The gateway requests `read_grant{subject: (t, Q), wid: A, rop: [...]}`, and the authority signs it.
  5. `A` now holds a 30-second, multi-use read grant over `Q`'s owner-scoped data.

  §4.2 only requires `subject.ten ∈ tenants(wid)`, so the implementation conforms to the spec. The gap is
  in the spec: §2.4 defines `enrolled` as single-principal, but reads do not follow that rule.
- **Fix (spec owner):** for an `enrolled` workload, require `subject == enrolment` in `read_grant`, and add
  a test.

### AU-R-04 (Low): AU-7, the clock, is framed in the wrong direction, and no sanity check exists

- **Where:** `src/server.rs:32-39`, `266` and `459`; `src/main.rs:39-44`.
- **Assessment of AU-7:**
  - A clock **rollback** produces an earlier `iat`. That revokes more, so it is fail-safe for
    `revoked_before`. For write grants it produces at worst a grant that is already expired (denial of
    service), because the broker re-checks `expires_at` and verifies at delivery.
  - The unsafe direction is a **forward** jump. The authority then signs **read** grants with a future
    `iat`. The workload receives them, holds them, and presents them once the broker's clock catches up.
    A `revoked_before` set in between does not revoke them, because their `iat` is later (REV-09, grant-v1
    §11 "Future-dated issuance").
  - Write grants are safe from this, because delivery-time step 8d rejects them.
  - `unwrap_or(0)` turns a clock error into `iat = 0` instead of a refusal.
- **Fix:**
  - Have the broker return its time on socket A (for example in the `config.digest` or `pending.get`
    result), and refuse to sign when the two clocks differ by more than `skew`.
  - Persist a high-water mark, and refuse to sign while `now < mark`.
  - Treat a clock error as a refusal.
  - Correct the AU-7 text.

### AU-R-05 (Low): the manifest check covers only the two socket directories (AU-3)

- **Where:** `src/config.rs:373-397`.
- **Gaps:**
  - The directories of the key, the store and the configuration files are not checked against the
    workload mounts.
  - A manifest does not have to list every registered `wid`, so `"workload_mounts": []` passes.
  - `manifest_path` may be a relative path, and a missing member is accepted as `null`
    (`Option` without `deny`).
- **Fix:** include every authority path in the control set. Require one entry per registered `wid`.
  Require an absolute path and an explicit member.

### AU-R-06 (Low): logging panics on a closed stdout; the process hangs and fails closed silently

- **Where:** `src/log.rs:16`.
- **Scenario:**
  1. The log collector dies and stdout becomes EPIPE. Rust ignores SIGPIPE, so `println!` panics.
  2. A panic right after a durable insert (`server.rs:311`) kills the task before delivery is spawned. The
     row stays `signed` until a restart.
  3. A panic in `serve` (`server.rs:591` or `597`) ends the accept loop. The process keeps running, and the
     socket stays bound but is dead.
- **Impact:** availability only; nothing is signed wrongly.
- **Fix:** write with `writeln!` to a locked stdout and ignore the error, or abort the process so that the
  supervisor restarts it and recovery runs.

### AU-R-07 (Low): the store is unbounded at runtime and limited to 1 GiB only at open

- **Where:** `src/store.rs:36` and `174`.
- **Scenario:** the log grows past 1 GiB while the authority runs, and the next start refuses to open.
  Without compaction, the outage lasts until an operator intervenes manually. The in-memory index also
  keeps every grant's bytes forever.
- **Fix:**
  - Raise an alarm and refuse new inserts above a threshold below the open limit.
  - Specify compaction of final rows older than `exp + skew + margin`.

### AU-R-08 (Low): the torn-tail heuristic can discard a complete durable record

- **Where:** `src/store.rs:182-194`.
- **Scenario:** any final bytes without a newline are truncated, and only an *event* is logged, not an
  alarm. A tail that is a complete, valid `issue` record missing only its final `\n` would be dropped.
  This can happen through partial persistence of the last page, or a one-byte corruption. If that grant had
  already been delivered, the next approve signs a **second, different** grant for the same `jti`.
- **Impact:** the broker's `PENDING` precondition, together with consumption keyed on `(iss, jti)`, still
  allows at most one acceptance and one effect. Even so, this violates the authority's own "never two
  signatures per `jti`" (§4.2, T46).
- **Fix:**
  - If the tail parses and its checksum verifies, keep it: append the `\n` and fsync.
  - Truncate only a tail that is genuinely partial.
  - Log the truncation as an alarm.

### AU-R-09 (Low): socket A is a single serialized connection, and every re-approve spawns another delivery task

- **Where:** `src/broker_client.rs:180-192`; `src/server.rs:330-331`.
- **Scenario:**
  - Every `approve` of a row that is still `signed` spawns an extra `deliver_until_deadline` loop. Each loop
    retries every 500 ms through the one broker mutex.
  - With a slow broker, each call can take up to `broker_call_timeout_ms` (30 s at most), and
    `pending.get` for new approvals queues behind deliveries.
- **Mitigations:** the gateway is trusted, and approval tokens are single-use.
- **Fix:** keep at most one in-flight delivery per `jti`, joining the existing one, and bound the number of
  delivery tasks.

### AU-R-10 (Low): the key is not protected against core dumps or swap

- **Where:** `src/key.rs:72`, where the `SigningKey` lives for the life of the process.
- **Problem:** nothing sets `RLIMIT_CORE = 0` or `PR_SET_DUMPABLE = 0`, and the key is not `mlock`ed.
  `unsafe` is forbidden in this crate, so this needs a safe wrapper crate or deployment configuration
  (`LimitCORE=0`).
- **Fix:** do one of those, and document it in the README limitations.

### AU-R-11 (Info): the authority does not bound the pending lifetime

- **Where:** `src/server.rs:186-189`.
- **Problem:** neither `created_at ≤ now` nor `expires_at − created_at ≤ 900` (§2.5) is checked, so the
  broker's word is taken.
- **Fix:** check both. The cost is low, and it limits a compromised broker's ability to keep a record open
  for long.

### AU-R-12 (Info): re-approve semantics differ from the spec's idempotency wording

- **Where:** `src/server.rs:183` and `325-326`.
- **Behaviour:**
  - A gateway retry after the broker has stored `APPROVED` gets `not_available`, because the state is not
    `PENDING`. T46 describes it as idempotent, `accepted`. The gateway shows a neutral page either way, so
    there is no security impact.
  - A row that is `accepted` while the broker shows `PENDING` (after a broker restore) returns `ok`
    without re-delivering. That is safe, but it should be logged as an alarm, because it signals a
    restore inconsistency (ADR-0006 §9).

## The implementer's spec-gap resolutions (AU-1..AU-7)

| Gap | Safe? | Note |
|---|---|---|
| AU-1 envelopes | Yes | Strict, and consistent with §2.2. Fold the table into the spec. |
| AU-2 `config.digest` over exact bytes | Yes | Stricter than needed. It operationally requires byte-identical files on the broker and the authority. The digest omits AU-R-01's display table (none exists yet). |
| AU-3 manifest | Partly | See AU-R-05. |
| AU-4 directory without "other" bits, socket 0660 | Yes | `SO_PEERCRED` is authoritative on both sockets. The directory owner and group are not checked. Correct the spec text. |
| AU-5 one durable record with the bytes | Yes | Sound, because delivery follows the fsync. See AU-R-08 for the torn-tail edge case. |
| AU-6 reply timeout | Yes | Delivery continues in the background, and the gateway always shows a neutral page. |
| AU-7 clock | Not implemented, and the framing is wrong | See AU-R-04. The real risk is forward-dated read grants. |

## Verdict

**PASS WITH FINDINGS.** I found no way to get a signature for values the intended approver did not approve,
other than the documented compromised-gateway residual. I found no path to double issuance that the broker
would accept, and no key leak.

Three Medium findings narrow claimed properties:
- AU-R-01: the broker-supplied `display` member;
- AU-R-02: configuration files are trusted without owner or mode checks;
- AU-R-03: read grants are not bound to the enrolled principal.

Address them, or publish them as residuals, before the effect-protocol-v2 milestone is declared. None of
them blocks the prototype commit.

Linux, distinct-uid deployment and a real broker remain **NOT TESTED**.
