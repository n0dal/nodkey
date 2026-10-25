# Adversarial review: broker protocol v2 (uncommitted working tree)

- **Date:** 2026-10-25
- **Target:** `broker/src/v2/*`; v2-related changes in `broker/src/{lib,main,config,ledger}.rs`;
  `examples/php-ledger/docker/postgres/initdb/02-effects-v2.sh`. Read directly from the working tree.
- **Contract:** `docs/specs/effect-protocol-v2.md` Draft 2; `docs/specs/grant-v1.md` §7;
  `crates/nodkey-grant/README.md` caller obligations; ADR-0006 (incl. Amendment 1); ADR-0011
  (Revision 1, Amendment 1); SECURITY_INVARIANTS v0.4 SI-05..SI-11, SI-15, SI-16, SI-19, SI-20.
- **Reviewer context:** fresh. I did not write any of this code.

## Evidence

- `cargo test` in `broker/`, run 2026-10-25: lib unit tests **61 passed, 0 failed**; `feature_guard`
  **1 passed**; `pg_integration` **26 ignored**.
- The PostgreSQL integration suite (`tests/run-pg-integration.sh`) was **NOT TESTED** by this review,
  because Docker was in use by another process. Every finding about database behaviour below comes
  from reading the code and SQL, using standard PostgreSQL READ COMMITTED and `SELECT … FOR UPDATE`
  semantics. None of it was observed.
- I wrote no new tests. I modified no files except this one.

## What I tried to break, and why it held

These are the attack paths from the brief. For each I checked the code path end to end. None of them
produced a finding.

| Attack | Result | Where |
|---|---|---|
| Effect without APPROVED + verified, consumed, exactly matching grant | Held. The only effect path is `execute`. It needs `state = APPROVED` under `FOR UPDATE`. It re-verifies the stored grant with `peer_wid` set to the record's `wid`. It then runs W10 → savepoint → `decide` (W11–W13), and the effect uses only `Authorized::params()`. The request is rebuilt from the immutable, digest-checked record. | service.rs:1268-1395 |
| Write via socket W, or read grant reaching a write | Held. Socket W has no write method other than `effect.propose`. `read()` refuses non-`read` declarations, and a `knd = 1` grant gets `grant_channel_invalid`. `deliver` and `execute` refuse `Verified::Read`. | service.rs:845, 880, 1210, 1317 |
| Double execution: delivery-spawned execution racing the recovery loop | Held. Both paths serialize on `SELECT … FOR UPDATE`. In READ COMMITTED, the waiter gets the updated row version (`SUCCEEDED`) and stops. Further backstops: `consumed_grant` PK `(iss, jti = pending_id)`, and `transfers` `UNIQUE (workload, idempotency_key = pending_id)`. | service.rs:1278-1283; 02-effects-v2.sh:138; 01-ledger.sh:31 |
| Crash or unknown commit outcome | Held. Consumption, effect, `consumed_grant.outcome` and the state change commit in one transaction. If the outcome is unknown, the next pass sees the committed state or retries. A deadline timeout discards the connection. | service.rs:544-562, 1381-1386 |
| Denial not atomic | Held. Rollback to the savepoint, `outcome = DENIED` and `FAILED/denied` happen in the same transaction. A failure to record gives `Err`, so everything rolls back and nothing is consumed. | service.rs:1364-1379 |
| Grant consumed in a different transaction than the effect | Held. The W10 insert is the first write in the execution transaction. | service.rs:1320-1336 |
| TOCTOU on ownership or funds | Held. `accounts` rows are locked `FOR UPDATE` in id order, then `account_owner` is read in a new READ COMMITTED statement. The `account_owner` UPDATE/DELETE trigger takes the same account lock first. An INSERT race can only turn an allow into a deny. | service.rs:406-463; 02-effects-v2.sh:34-44 |
| Cross-workload / cross-tenant access to records | Held. `effect.status` filters on `wid` and returns the same `not_found` for unknown, foreign and non-canonical ids. `render` and `deny` require `(ten, approver_sub)` equal to the gateway subject, plus ownership of `from`. Delivery binds `wid`, `ten`, `sub` and `jti`. | service.rs:777-820, 947-962, 1086, 1213-1217 |
| Workload data treated as fact | Held. Display facts come from broker configuration. Facts and checks come from `accounts` and `account_owner`. `approver` is only a request, constrained by `approver_source`. | service.rs:617-773 |
| Immutable columns or illegal transitions via the broker role | Held for the immutable columns and §3.3 transitions. Triggers belong to the table owner, and the broker role has column-level `UPDATE` only and no `DELETE`. See BR-08 for the gap this leaves. | 02-effects-v2.sh:83-127 |
| Strict parsing | Held. Line-level duplicate-key rejection; exact envelope member set; `v` must be an integer; exact `args` keys; typed params from the declared type (`1.0`, `-1` and `1e3` are rejected); canonical 22-character ids; lowercase-only hex. | wire.rs:102-152; digest.rs:345-; ids.rs |
| nodkey-grant API misuse | Held. `decide()` is called in both `deliver` and `execute`. The consumption row comes from `w.consumption()`. Revocation rows are read inside the deciding transaction. The test-only feature is guarded. | service.rs:1221, 1321, 1337-1338; tests/feature_guard.rs |
| Error and log leaks | Held. Client messages are static per code. DB error text goes only to `log_event`. | wire.rs:49-64; server.rs:119-131 |

**Result: no Critical or High findings.**

## Findings

| ID | Severity | Location | Blocks |
|---|---|---|---|
| BR-01 | Medium | service.rs:824-919; server.rs:220 + server.rs:22 (32 conns); config.rs:126 (pool 8) | no |
| BR-02 | Medium | broker/src/config.rs:18-21, 67-69 | no |
| BR-03 | Low | broker/src/ledger.rs:215-250; main.rs:143-147 | no |
| BR-04 | Low | service.rs:1219-1240 | no |
| BR-05 | Low | v2/server.rs:258-270; v2/config.rs:248-256, 319-339 | no |
| BR-06 | Low | 02-effects-v2.sh:48-81, 132-139; service.rs:1005-1032 | no |
| BR-07 | Low | service.rs:1166-1171 | no |
| BR-08 | Low | 02-effects-v2.sh:112-120 | no |
| BR-09 | Low | service.rs:1295-1319 | no |
| BR-10 | Info | service.rs:1462-1472, 567-612 | no |
| BR-11 | Info | service.rs:715-761 | no |

### BR-01 (Medium): one workload can starve the shared DB pool, so other workloads' approved effects expire

- **Scenario:** All three sockets and the recovery loop share one pool. Its default size is 8 and the
  maximum is 32. Each workload socket accepts 32 connections, each allowed 256 requests.
  - `effect.propose` and `effect.status` are rate-limited per `wid`.
  - Read operations (`ledger.get_balance`) are **not** rate-limited, and each one takes a pool
    connection.
- **Attack:** A compromised workload holding any valid read grant (30 s TTL; the gateway issues one
  whenever a user navigates) sends reads in a loop on up to 32 connections. That keeps all 8 pool
  slots busy, and `Pool::get` times out after 3 s (`unavailable`).
- **Effect:**
  - Gateway render and deny calls, and authority `pending.get` and `grant.deliver` calls, fail.
  - `execute` for **other** workloads' APPROVED records fails. Those records pass `grant.exp + skew`
    (≤ 35 s) and become `EXPIRED`, so their effects are lost.
  - This is a cross-workload denial of service, which contradicts the T23 expectation that "another
    `wid` proceeds" and the per-workload fairness gap D1-07.
- **Fix:**
  - Add a per-`wid` rate limit for reads, as for status.
  - Cap concurrent DB use per workload, e.g. a per-`wid` semaphore smaller than the pool.
  - Reserve pool capacity for sockets A and G and for execution, e.g. a separate small pool or
    reserved permits.
  - Add an integration test: workload X floods reads while workload Y's approved transfer executes.

### BR-02 (Medium): a v1 configuration with no `profile` still starts protocol v1

- **Rule:** Spec §2.1 says a broker MUST refuse to start if a v1 socket is configured "and the
  deployment profile is not the **explicit** `demo1` profile".
- **Code:** `profile` is `Option`. It is rejected only if present and different from `demo1`, so a
  v1 configuration without the member runs grantless `ledger.transfer` (SI-19 exists to forbid that
  outside Demo 1).
- **Test gap:** The repository's own `broker.json` sets `"profile": "demo1"`, so the compatibility
  default is unnecessary. The test `v1_profile_must_be_demo1` checks only the positive case.
- **Fix:** Make `profile` required and equal to `"demo1"`. Add a negative test for the absent member.

### BR-03 (Low): v1 skips the database claim when `broker_claim` is missing (EP-10 hole by ordering)

- **Code:** `claim_protocol_v1` returns `Ok(false)` on `UNDEFINED_TABLE`, and `run_v1` continues.
- **Scenario:**
  1. A v1 broker starts on a Demo-1-only database.
  2. The operator later applies `02-effects-v2.sh`.
  3. A v2 broker claims the database (`protocol = 2`) while the v1 broker keeps serving grantless
     transfers on the same ledger.
- This needs an operator ordering mistake, but EP-10 exists to make that mistake fail closed.
- **Fix:** Either refuse v1 start-up when the table is absent and create `broker_claim` in
  `01-ledger.sh`, or have `02-effects-v2.sh` refuse if any v1 broker connection is active and insert
  the claim row itself.

### BR-04 (Low): verified grants rejected at `grant.deliver` are not recorded

- **Code:** `deliver` runs `verify` and `decide` (W11–W13), plus the ownership check, and returns
  `rejected` without writing `consumed_grant`. The record stays `PENDING`, and the authority keeps
  re-delivering the **same bytes** until `exp` (§4.2 step 6).
- **Scenario:** If the failure was W13 (revocation) and the operator removes the `revoked_before` row
  within the 30 s grant life, a later re-delivery is accepted and executes.
- **Why it matters:** SI-09 says "a grant that passed verification receives exactly one decision; a
  denied grant is consumed".
  - Practical impact is small, because the operator controls revocation.
  - The spec text treats delivery as approval, not decision, and does not resolve this.
- **Fix (choose one):**
  - Record a `DENIED` consumption at delivery for W11–W13 failures (in the same transaction, as at
    execution).
  - State in the spec that `grant.deliver` is not a decision, and that a delivery rejection is
    re-evaluable within `exp`.

### BR-05 (Low): socket and directory hardening is weaker than §1.2

- **Socket mode:** Sockets are chmod 0666; §1.2 says 0600, owned by the peer, with group access. The
  `SO_PEERCRED` uid check (server.rs:163-183) is the only effective barrier.
- **Directory checks:** Directories are checked only for being distinct (`HashSet`).
  - Nesting is not checked. Example: gateway socket `/run/x/g/broker.sock` and a workload socket
    `/run/x/broker.sock`; mounting the workload's directory exposes the gateway directory.
  - Mode and owner are not checked.
- **Start-up DoS:** `bind_socket` is fatal if a non-socket exists at a socket path. Under §1.2 the
  workload owns its own directory, so it can replace its socket with a file and stop the **whole**
  broker from restarting.
- **Fix:**
  - Use mode 0660 or 0600 with a group, as specified.
  - Refuse nested or overlapping socket directories.
  - Check the mode and owner of each directory at start.
  - Have the broker own each socket directory (peer access through a group) instead of the peer, or
    stop treating a stale non-socket at a workload path as fatal for the other channels.

### BR-06 (Low): unbounded tables, and render queries that scan them

- **Growth:** The broker role has no `DELETE`, and no pruning job exists for `pending_effect` or
  `consumed_grant`. One workload at 10 proposals/min adds about 14,400 rows/day.
  - Spec §2.3 assumes ids can be pruned.
  - grant-v1 §7.6 requires pruning to respect `exp + skew + margin`.
- **Render cost:** Every render runs two queries on this growing table:
  - `recent_identical` (`params = $5` text equality);
  - `other_open_on_resource` (`params::jsonb ->> 'from'`, `ten`, `op`), with only partial index
    support.
- **Fix:**
  - Document and implement an operator pruning job (final states older than a retention period;
    `consumed_grant` after `exp + skew + margin`).
  - Add an expression index on `(op, ten, (params::jsonb ->> 'from')) WHERE state IN (…)`.

### BR-07 (Low): a second, different grant for an already approved or final record raises no alarm

- **Code:** If the stored `grant` differs from the delivered bytes and the state is not `PENDING`,
  `deliver` returns `expired` silently.
- **Why it matters:** Under §4.2 step 4 the authority never signs two grants for one `jti`. A
  different grant for an `APPROVED` or executed record therefore indicates a compromised or buggy
  authority. That is exactly the case where the broker's independent check should alarm.
- **Fix:** When `rec.grant.is_some()` and the bytes differ, log `alarm` (`second_grant_for_jti`).

### BR-08 (Low, defense in depth against attacker J): the DB does not tie final states to consumption

- **Code:** The `pending_effect_guard` trigger allows `APPROVED → SUCCEEDED/FAILED` (and
  `→ EXECUTING → …`) with no matching `consumed_grant` row.
- **Effect:** A broker-role SQL session can mark a record executed without a consumed grant. Effects
  themselves (`accounts`, `transfers`) are not tied to records either.
- This is within the published broker-compromise residual (§6), so it does not block.
- **Cheap hardening:** A deferred constraint trigger requiring, for `APPROVED → SUCCEEDED/FAILED`, a
  `consumed_grant` row with `jti = pending_id` and outcome `ACCEPT` or `DENIED`.

### BR-09 (Low): unverifiable stored grants end as `EXPIRED`, not `FAILED/denied`

- **Code:** The record stays `APPROVED` and is re-verified every 5 s until expiry, then reported as
  `expired`, when:
  - the key was revoked after approval;
  - the workload was unregistered;
  - the op has no executor.
- **Spec gap:** T39 expects `FAILED/denied` or `rejected`. The grant-v1 rule that unverified grants
  consume nothing makes this outcome defensible, but the test plan and the code disagree.
- **Fix:** Align T39 with the code (the outcome is `expired`) or record the failure. Add a one-shot
  alarm instead of re-logging every 5 s.

### BR-10 (Info): clock high-water mark persistence

- **Code:** The mark is persisted only by `recovery_tick` (every 5 s), and `startup_checks` does not
  advance it.
- **Effect:** After a crash, rollback detection tolerates up to about skew + 5 s. The replay guards
  (`jti = pending_id` and the record state) make this non-exploitable, but ADR-0006 §8 reads stricter.
- **Fix:** Persist `max(mark, now)` at start-up.

### BR-11 (Info): misleading `unavailable` from `effect.propose`

- **Code:** If the deadline or commit outcome is lost after the insert committed, `effect.propose`
  returns `unavailable` ("nothing was executed"), but a `PENDING` record exists and counts toward the
  limits.
- **Impact:** Harmless for authority, since a proposal is not an effect. Mention it in the client
  documentation.

## Verdict

The core v2 authorization properties hold on code reading:
- **No grantless effect:** every effect needs `APPROVED` plus a verified, consumed grant that matches
  the immutable, digest-checked record exactly.
- **At most one execution:** row lock, `consumed_grant` PK and `transfers` unique key.
- **Denials are recorded atomically.**
- **Execution re-checks under lock:** ownership and funds are re-checked inside the effect
  transaction.
- **Workload and tenant isolation** holds for `status`, `render` and `deny`.

No Critical or High finding, so nothing blocks on severity.

- **Before Phase 3 is claimed:** fix BR-01 (cross-workload availability) and BR-02 (spec MUST).
- **Condition on that claim:** run the PostgreSQL integration suite and record its result. This review
  did not run it (NOT TESTED), so the database-semantics conclusions above rest on reading only.

**Status: PASS WITH FINDINGS (no blocking findings; integration suite NOT TESTED by reviewer).**
