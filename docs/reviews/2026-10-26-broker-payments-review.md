# Review: broker payments code (commit 24aeb40)

- **Date:** 2026-10-26
- **Target:** commit `24aeb40`: `broker/src/v2/payments.rs`, `broker/src/v2/adapter.rs`, and the related changes in
  `broker/src/v2/{service,server,config,decls}.rs`, `broker/src/ledger.rs`,
  `examples/php-ledger/docker/postgres/initdb/03-payments.sh`, `broker/tests/pg_payments.rs`.
- **Contract:** payments-adapter-v1 Draft 3 (§1, §2, §7, §8), ADR-0012 rev. 2, ADR-0006 Amendment 2,
  effect-protocol-v2 Draft 3.1 (`payments.refund` with a broker-resolved `charge_id`).
- **Method:** source reading against the spec. I ran the unit tests. I did **not** run the PostgreSQL
  integration tests (`#[ignore]`, they need Docker, which another agent was using), so every DB-behaviour
  claim below is NOT TESTED unless it says otherwise.
- **Evidence (unit tests):** `cd broker && cargo test` gave `test result: ok. 70 passed; 0 failed` (lib) plus
  `1 passed` in one more binary. The integration binaries reported `28 ignored` and `21 ignored`.

Severity uses Critical / High / Medium / Low. "Blocks" means the finding blocks the Demo P milestone under the
owner rule that unresolved High findings block.

## Findings

### BP-01: the `idem_kid` guard is only checked once, at broker start-up, so an adapter restart with a new `K_idem` allows a second refund (High; blocks: yes)

- **Where:** `broker/src/v2/payments.rs:573-623` (`ensure_adapter`: after the first success, `ready` is never
  cleared and `hello` is never refreshed; line 577 returns early); line 1003 (resend gate compares
  `row.idem_kid` with the **cached** `h.idem_kid`); line 811/816 (T2 CAS uses the cached kid).
- **Scenario:**
  1. A row is dispatched under `K_idem` = K1, the response is lost, and the row becomes `UNKNOWN`.
  2. The operator rotates `K_idem` against the §3.3 rule (non-final rows exist) and restarts **only the
     adapter**. This is exactly the operator error the kid guard exists to catch.
  3. The broker still holds the hello from K1. The reconciler runs `refund.find`: the reference is now
     derived from K2, so the lookup returns `not_found`.
  4. `idem.status` for the K2 key returns `none` in round 0, which counts as "go".
  5. The broker resends. The adapter derives a new `Idempotency-Key`, so the provider executes a **second
     refund** of the same grant.
  The adapter cannot catch this, because it does not know which kid the row was decided under.
  PT-36 (`pt24_pt36_adapter_identity`) covers only a *new broker* meeting a changed adapter.
- **Fix:** bind the kid on every call. Send `idem_kid` in `refund.create`/`refund.find`/`refund.get`/
  `idem.status` args and have the adapter refuse (`ok:false`, nothing sent) on a mismatch. As an
  alternative or in addition, have the adapter echo `idem_kid` in every result, and have the broker re-run
  `adapter.hello` and the open-row kid check before each dispatch and each reconciliation round, clearing
  `ready` on any mismatch. Apply the same to `r_max_s`, which is also cached. Add a test where the adapter
  is restarted with another key while the broker keeps running.

### BP-02: the deferred counter check runs as the operator role, which cannot read the tables, so operator updates of a fresh charge fail (High if confirmed; NOT TESTED; blocks: yes until tested)

- **Where:** `03-payments.sh:97-108` (`orders_lock_charge`, `SECURITY DEFINER`, inserts the
  `charge_refund_state` row); `03-payments.sh:195-220` (`charge_counters_check`, **not** `SECURITY DEFINER`,
  fired by the deferred constraint trigger `charge_refund_state_counters`). `nodkey_shop_operator` has
  no privilege on `charge_refund_state` or `payment_effect`.
- **Scenario (hypothesis):** in PostgreSQL 17 (the pinned image, `compose.protected.yaml:74`), a deferred
  AFTER trigger runs at COMMIT with the privileges of the role that is current at commit time. That role is
  the operator, not `postgres`, which owns the definer function that queued the event. The steps are:
  1. The operator runs `UPDATE nodkey.orders SET status='disputed'` (or `owner_sub`, or
     `external_refunded_minor`) on an order whose charge has no state row yet. That is any order never
     delivered or approved through Nodkey.
  2. The trigger inserts the row, and `charge_counters_check` fires at commit.
  3. It hits `permission denied for table charge_refund_state`, and the operator's update is rolled back.
  The trusted facts then cannot be updated, so later proposals are decided against stale facts (SI-10,
  SI-11): a disputed or canceled order stays `captured`, and an external refund is not counted in the
  remaining amount. (The provider's per-charge cap still bounds the total.) PT-39
  (`pt39_counters_and_operator_race`) uses the **superuser** as the operator, on a charge whose row already
  exists, so it cannot see this.
- **Reproduce:** connect as `nodkey_shop_operator` and update an order with no `charge_refund_state` row.
- **Fix:** make `charge_counters_check` `SECURITY DEFINER` (owner `postgres`, `search_path = ''`), or do
  the check without a deferred trigger. Re-run PT-39 as `nodkey_shop_operator` on a fresh charge and on an
  existing one.

### BP-03: the dispatcher's first call has no lease re-check after an unbounded wait for a call slot, which breaks the PA-06 exclusion (Medium; blocks: no)

- **Where:** `payments.rs:652-655` (`call_create` waits on `rt.calls.acquire()` with no timeout);
  `payments.rs:834-845` (only attempts 1 and 2 re-assert the lease).
- **Scenario:** 8 calls are slow (provider attacker G, `Slow` responses) and many refunds are queued. The
  dispatcher's T2 lease (49 s) runs out while it waits for a slot. Recovery moves the row to `UNKNOWN/lost_response`,
  and the reconciler resends or even concludes `FAILED/provider_declined` and releases the amount. Then the
  original dispatcher's first `refund.create` still goes out. This violates "at most one adapter call in
  flight per row" (PT-33) and leaves the protection resting only on the provider replaying a cached answer
  for that key. That holds for an honest provider within retention. Whether simpay replays cached 4xx
  answers was not checked.
- **Fix:** acquire the slot **before** T2, or re-run `take_lease(.., "DISPATCHED", ..)` after acquiring it
  and before every call (attempt 0 included). Also bound the wait with a timeout.

### BP-04: the payments recovery runs inline and serially in the Phase 3 recovery loop (Medium; blocks: no)

- **Where:** `service.rs:1777` (`recovery_tick` awaits `dispatch` inline for each re-executed refund);
  `server.rs:251-255` (`recovery_tick` and `payments_tick` share one loop task); `payments_tick` awaits up
  to 64 reconciliation rounds in sequence, each up to about 6 calls × 12 s.
- **Scenario:** a slow or malicious provider (G) makes each dispatch take about 50 s and each round
  minutes. Meanwhile `ledger.transfer` recovery is starved: approved records whose spawned execution failed
  are not executed, and PENDING records are not expired. Those approved transfers can pass `exp` and
  expire. Stale `RESERVED` and lost `DISPATCHED` handling is delayed in the same way. This is a liveness
  loss, not a safety loss, but it weakens the Phase 3 path the brief asked about.
- **Fix:** run the payments tick in its own task, spawn per-row work with a bound, and have
  `recovery_tick` spawn `dispatch` instead of awaiting it.

### BP-05: one failing row stops the whole payments tick (Medium; blocks: no)

- **Where:** `payments.rs:1188-1252`: `?` on every `apply`, `reconcile` and `poll_settlement`.
  `apply` returns `Err` when the record CAS touches no row (line 794), on the counter check, or on the
  "reference is set once" guard.
- **Scenario:** any persistent error on one row aborts every tick at that row. All later rows are then
  starved: stale `RESERVED`, lost `DISPATCHED`, `UNKNOWN` reconciliation and settlement. Every charge with
  an open row stays blocked.
- **Fix:** log and alarm per row and continue. Skip the row (back off its `next_check_at`) after repeated
  failures.

### BP-06: the counter check can fail spuriously because its two reads see different snapshots (Medium; NOT TESTED; blocks: no)

- **Where:** `03-payments.sh:195-215`. The function reads `charge_refund_state`, then `payment_effect`, in
  two statements. Under READ COMMITTED each statement gets a new snapshot. The trigger fires on **every**
  `payment_effect` update, including ones made without the charge lock: `take_lease`, the T2 CAS,
  `end_round`, `poll_settlement`.
- **Scenario:** a `poll_settlement` update on row A commits while a T1 or `apply` for row B on the same
  charge commits between the trigger's two SELECTs. The check sees mismatched counters, raises, and the
  update fails. Then:
  - A failure in T2 leaves the row `RESERVED`, which fails as `not_dispatched`: the user's refund is lost.
  - A failure in `take_lease` or `end_round` aborts the tick (BP-05).
- **Fix:** read both in one statement, or take `FOR SHARE` on the `charge_refund_state` row first. Fire
  the trigger only on changes to `state` or `amount_minor`
  (`AFTER UPDATE OF state, amount_minor, released`).

### BP-07: the broker's charge-id pattern still allows 8 to 64 characters after the prefix (Low; blocks: no)

- **Where:** `adapter.rs:155-162`, used for T1 step 0, `deliver_checks`, `render_facts` and response
  parsing. The spec, the DB check (`03-payments.sh:62`) and commit 3efafba use `{8,61}`. 3efafba did not
  touch `broker/`.
- **Impact:** today this cannot be reached, because `charge_id` comes only from `orders` and `text64`
  bounds it. If it were reached, the DB check would fail T1 as an infrastructure error, leaving a poison
  `APPROVED` record that is retried every tick.
- **Fix:** use `8..=61` and add a boundary test.

### BP-08: the `refund.get` confirmation does not check the reference, and `provider_refund_id` is not unique (Low; blocks: no)

- **Where:** `payments.rs:480-486` (`EffectRow::matches` compares charge, amount and currency only);
  `03-payments.sh:142` (no `UNIQUE` on `provider_refund_id`).
- **Scenario:** a provider (G) can return the id of an earlier refund of the same charge and amount. The
  broker then marks a second row `SUCCEEDED` with the same `re_…`. The user is told the refund succeeded,
  but nothing was refunded. Over-counting the encumbrance is safe, so this is an integrity and reporting
  gap, not a double refund.
- **Fix:** compare `reference` with the row's `reference` once that is known, and add a `UNIQUE` index on
  `provider_refund_id`.

### BP-09: the reconciler marks `SUCCEEDED` with settlement `failed`, while the dispatcher treats the same answer as `UNKNOWN` (Low; blocks: no)

- **Where:** `payments.rs:853` (dispatch: a refund with `status == Failed` gives `UNKNOWN`) versus
  `payments.rs:987` and `1080` (reconcile: `SUCCEEDED` with settlement `failed`).
- **Impact:** both choices are conservative, because the amount stays encumbered. But
  `payments.get_order.refunded_minor` then counts a refund that failed to settle. That is consistent
  with §8, but the two paths disagree. The spec (§7.3 settlement) should say which rule applies.

### BP-10: the dispatch lease does not cover the confirming `refund.get`, and the T3 CAS checks the lease owner but not its expiry (Low; blocks: no)

- **Where:** `config.rs` `lease_dispatch_s` (49 s) against the worst case of 3 × 12 s + 3 s + 12 s for
  the confirmation, which is 51 s. `payments.rs:752` (`lease_owner = $me` only).
- **Impact:** the only effect is a discarded result followed by a later lookup. That is safe, but
  §7.2's "a lost lease discards the result" is implemented as "a changed state or owner discards it".
  The dispatcher and reconciler in one process share `$me`, so their exclusion rests on the state
  (`DISPATCHED` versus `UNKNOWN`) alone. That is sound today, but the PA-06 text should say so.

### BP-11: the internal reason `grant` maps to `not_executed`, which §8 does not list (Low; blocks: no)

- **Where:** `payments.rs:70`.
- **Impact:** a revocation or another W11–W13 failure is shown as `not_executed`. That is not an
  ownership oracle, because the grant is the approver's own, but §8 is a closed table. Either add the row
  to the spec or map it to `not_permitted`.

## Checked and not found

- **Double refund from T1 versus dispatch versus recovery:** RESERVED→DISPATCHED and RESERVED→FAILED are
  single-row CASes under the row lock. A late T3 on an `UNKNOWN` row is discarded. `FAILED/not_sent` is
  applied only from `DISPATCHED`, and only when the first call of this dispatch was `not_sent`. `FAILED`
  is final in both tables. A crash after T1, after T2 or after the send behaves as §7.2 says. The
  remaining exceptions are BP-01 and BP-03.
- **Over-refund through concurrent records on one charge:** the per-charge row lock (with insert-if-absent)
  is followed by a new-statement read of `orders`. In-flight and `UNKNOWN` amounts block the charge (step 5)
  and are counted in step 6. Two orders cannot share a charge (`UNIQUE`).
- **Budget write skew:** the budget row is locked `FOR UPDATE` before the guarded `UPDATE`, and a denial
  rolls back to the savepoint. Lock order is the same in T1, `deliver_checks`, `apply` and the operator
  trigger, so no lock cycle was found.
- **Trusted-fact provenance:** the broker has `SELECT` only on `orders`. The app has no role in `nodkey`.
  The baseline `ledger_app` grant predates the schema. `charge_id` is resolved by `(ten, order_id)` from
  `orders` and is never taken from the workload (`typed_params` rejects extra keys). The value is immutable
  in `pending_effect.params`, and T1, `deliver_checks` and `render` re-check that `orders.charge_id` equals
  con2. Except for BP-02, the definer function is pinned (`search_path = ''`), uses qualified names, and
  `EXECUTE` is revoked from PUBLIC.
- **SQL privileges and name resolution:** the broker has no `CREATE` or `TEMP` and owns nothing, so it
  cannot `GRANT`. It cannot disable triggers or set `session_replication_role`. Every statement is
  schema-qualified, and the six `02-effects-v2.sh` functions are pinned. A `SET search_path` by the
  session is harmless without `CREATE`.
- **Leaks to the workload:**
  - `effect.status` returns only state, class, receipt and the §8 enum, for the workload's own records.
  - `propose` returns no params.
  - `payments.get_order` is filtered by the read grant's tenant and subject, and a foreign order and a
    missing order give the same denial.
  - Provider ids, references and the charge id appear only in render, which goes to the approver.
    Render returns `None` unless the approver owns the order.
- **Socket P:** the `SO_PEERCRED` uid is checked before any byte is written. A mismatch raises an alarm and
  sends nothing. Responses are parsed strictly with closed enums, so no provider text gets through.
  `ok:false` is mapped conservatively to `UNKNOWN`, never to `FAILED`.
- **`ledger.transfer`:** this commit makes no semantic change to the transfer path. The changes are
  schema qualification, executor dispatch and deadline-at-commit extended to `Reserved`. BP-04 is the one
  regression.

## Verdict

**Not ready.**
- **BP-01 (High)** is a real double-refund path: the kid guard is ineffective while the broker keeps
  running.
- **BP-02 (High if confirmed)** may stop the operator from updating the trusted facts.

Both block until they are fixed, and BP-02 until it is tested as `nodkey_shop_operator`. The Medium
findings (BP-03 to BP-06) should be fixed before the Demo P adversarial run (PT-33, PT-39). The rest of
the T1, state-machine and privilege design matches Draft 3. The PostgreSQL integration suite
(`pg_payments.rs`) must still be run and its output quoted, since that was NOT TESTED here.
