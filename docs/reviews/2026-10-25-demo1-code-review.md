# Demo 1 code review: minimal containment (Phase 2)

- **Date:** 2026-10-25
- **Type:** Independent adversarial code review. The reviewer did not write the code.
- **Target (uncommitted):** `broker/` (Rust broker), `examples/php-ledger/` (P0 =
  `compose.protected.yaml`, baseline = `compose.baseline.yaml`, nginx/php-fpm/postgres config,
  intentionally vulnerable PHP app), `tests/containment/probes.php`, `tests/containment/run.sh`.
- **Specs checked against:** research 03 §6 (Deployment Profile P0), SECURITY_INVARIANTS v0.2
  (SI-01..03, SI-08, SI-13, SI-15, SI-16, plus SI-19 where relevant), ADR-0002 rev. 2, architecture
  review findings AR-12 and AR-15.
- **Environment:** the same local Colima VM the suite uses (Docker 29.5.2, default seccomp, AppArmor
  `docker-default`). Every "Reproduced" item below was run against the live protected stack. Items
  marked "Analytical" come from reading the code and were not executed.

## Summary

The basic containment holds under the attacks I tried. The workload has only loopback, no
credential, and no path to the DB. The broker's parser is strict. `SO_PEERCRED` rejects other uids.
nginx ignores the app's X-Accel headers and does not treat `Location` as an internal redirect. Under
24 parallel clients, transfers kept the total balance constant and no balance went negative.

Two problems block committing Demo 1 as "verified under P0":

1. **D1-01 (High).** A transfer can commit while both the client and the user are told it failed.
   The demo UI shows `TRANSFER DENIED`, which invites a retry and so a second debit. This falsifies
   SI-15 as worded.
2. **D1-02 (High).** Probe F-02 ("no exec from writable mounts") cannot fail. The baseline run
   already shows it passing when exec actually succeeds. The property does hold today, but the
   suite does not show it.

Several Medium findings make specific STATUS.md claims false or overstated: persistence across
recreation, "every probe has a positive control", and "verified under P0" while P0 assumptions 2
and 3 are not met. These need code or wording changes before the commit.

| ID | Severity | Title | Blocks Demo 1 commit |
|---|---|---|---|
| D1-01 | High | Committed transfer reported as failure; UI says DENIED; no idempotency | **Yes**, unless SI-15 is marked NOT MET and the UI/client wording is fixed |
| D1-02 | High | F-02 exec probe is vacuous (busybox applet name gives rc=127) | **Yes** |
| D1-03 | Medium | Workload files survive app recreation; planted directory makes the redeployed app fail | **Yes** for the "no persistence across recreate" claim (fix, or reword plus a probe) |
| D1-04 | Medium | Compromised app wipes the broker's audit log in under 2 s | No, if documented as a residual |
| D1-05 | Medium | Harness false-PASS paths; missing positive controls; STATUS over-claims | **Yes** for the STATUS sentence; harness fixes recommended |
| D1-06 | Medium | Workload authority unbounded in aggregate (no budget, any source account) | No, but it must be stated in the Demo 1 claims |
| D1-07 | Medium | One DB connection behind one mutex: no per-workload fairness (ADR-0002 §4) | No (not claimed), document it |
| D1-08 | Medium | "Verified under P0" while P0 assumptions 2 and 3 are unmet; no configuration probes | **Yes** for the label (reword or add checks) |
| D1-09 | Low | C-03 places the real broker DB password in the workload's process list | No |
| D1-10 | Low | Broker keeps reading after malformed lines; app can point nginx's FastCGI connect anywhere | No |
| D1-11 | Low | Config accepts duplicate workload uids or the broker's own uid; README referenced but missing | No |
| D1-12 | Low | `peer_pid` is always 0 in logs; refusal response has `id:null`, so the client reports `bad_response` | No |
| D1-13 | Info | Smaller notes (see below) | No |

---

## Findings

### D1-01: Committed transfer reported as failure (High)

- **Files:**
  - `examples/php-ledger/app/lib/BrokerClient.php:26,73-84`: 5 s client timeout; every transport
    failure becomes `unavailable`.
  - `examples/php-ledger/app/public/index.php:58-62`: every `BrokerError` is rendered as
    `TRANSFER DENIED` with HTTP 403.
  - `broker/src/server.rs:283`: the broker never checks whether the peer is still connected before
    it executes.
  - `broker/src/ledger.rs:80,87-90,190`: the mutex wait has no bound. `OP_TIMEOUT` (10 s) wraps
    `tx.commit()`, and a timeout is mapped to `Unavailable`, not `OutcomeUnknown`.
- **Reproduced:**

  ```
  before: 100000                                   # alice, via BrokerClient
  docker compose -f compose.protected.yaml pause db
  php xfer.php  ->  ERROR code=unavailable msg=no complete response after 4.9s
  (1 s later) docker compose ... unpause db
  after: 99900                                     # the transfer committed
  broker log: {"decision":"allow","op":"ledger.transfer","amount_cents":100,"duration_us":6153026,...}
  ```

  Through the web UI, the same sequence returns `TRANSFER DENIED: unavailable` (403) for a transfer
  that committed. A user who retries is debited twice. The protocol has no idempotency key, so the
  broker cannot tell a retry from a new transfer.
- **Second path (Analytical):** `with_client` applies `tokio::time::timeout(OP_TIMEOUT, f(client))`
  to the whole closure, including `tx.commit()`.
  - The statement budget is `lock_timeout` 3 s and `statement_timeout` 5 s per statement, across
    six statements, so the 10 s outer timeout can fire while COMMIT is in flight.
  - The broker then returns `unavailable`, which the code documents as "before any commit was
    attempted" (`ledger.rs:24-25`). The real outcome is unknown, and the server may have committed.
  - Separately, the mutex wait is not covered by any timeout. With the DB stalled, queued requests
    from clients that have already given up execute later.
- **Why it matters:** SI-15 requires that ambiguous outcomes are recorded as *unknown* and never
  retried as if they had failed. Here the broker has an `OutcomeUnknown` code, but:
  - the timeout path does not use it;
  - the client collapses "sent, no answer" into `unavailable`;
  - the app tells the user "DENIED".

  The broker's audit says `allow` and the user sees `DENIED`.
- **Fix:**
  1. Map the outer timeout to `OutcomeUnknown` once COMMIT has been issued. Simplest: time out
     each statement separately and give COMMIT its own branch.
  2. Bound the mutex wait with a timeout that returns `unavailable` *before* any statement is sent.
  3. Make the broker's total deadline shorter than the client's, or have the client send its
     deadline and the broker refuse to start work it cannot finish in time.
  4. In `BrokerClient`, report any failure after the request bytes were written as `outcome_unknown`.
  5. In the demo UI, distinguish DENIED, UNAVAILABLE (nothing happened) and UNKNOWN (check before
     retrying).
  6. Add a client idempotency key (or defer to the ADR-0006 replay store) before claiming SI-15.
  7. Add a probe: pause the DB, transfer, unpause, then assert "client says failed" implies "no
     journal row".
- **Blocks:** Yes, unless STATUS lists SI-15 as NOT MET for Demo 1 and the UI and client stop
  calling an unknown outcome "denied".

### D1-02: F-02 exec probe is vacuous (High, test validity)

- **File:** `tests/containment/probes.php:138-158`.
- **Detail:** the probe copies `/bin/busybox` to `$dir/probe-exec-<pid>`, runs it with `true`, and
  passes when `rc !== 0`. Busybox is a multi-call binary that dispatches on `argv[0]`, and
  `probe-exec-<pid>` is not an applet name. When exec *succeeds*, it prints `applet not found` and
  exits with 127.
- **Reproduced:**

  ```
  docker run --rm --user 10001 --entrypoint sh nodkey/php-ledger-app:dev -c \
    'cp /bin/busybox /tmp/probe-exec-1; chmod 755 /tmp/probe-exec-1; /tmp/probe-exec-1 true; echo rc=$?'
  probe-exec-1: applet not found
  rc=127
  ```

  The last baseline run already shows this. Baseline F-02 is `PASS` with `/tmp: rc=127; /run/fcgi:
  rc=127`, even though baseline `/tmp` is writable and executable. The protected run shows rc=126
  (EACCES), and `/proc/mounts` confirms `noexec` on `/tmp`, `/run/fcgi`, `/dev/shm` and
  `/dev/mqueue`. So the property holds today, but the probe would still report PASS if `noexec`
  were removed, which is the AR-12 regression it exists to catch.
- **Fix:**
  - Copy to `$dir/true` (a valid applet name), or use a tiny script with a shebang.
  - Pass only on rc 126 (or an `EACCES` from `proc_open`). Treat rc 0 as FAIL and anything else as
    INCONCLUSIVE.
  - Include `/dev/shm` and `/dev/mqueue`.
  - Require baseline F-02 to FAIL as the sensitivity control, which needs a baseline `/tmp` without
    noexec.
  - Separately, the docs should not suggest that `noexec` stops native code: attacker C can already
    reach syscalls through PHP (for example by writing to `/proc/self/mem`; not tried here). F-02
    only shows that dropped binaries cannot be exec'd.
- **Blocks:** Yes. A Phase-2-blocking AR-12 claim rests on it.

### D1-03: Persistence across app recreation, and persistent DoS (Medium)

- **Files:** `examples/php-ledger/compose.protected.yaml:26,47,103`; `tests/containment/run.sh:94-98`.
- **Detail:**
  - The tmpfs-backed `fcgi` volume stays mounted as long as *any* container uses it. `web` keeps
    it mounted.
  - Recreating only `app` (crash restart, `up --no-deps app`, or redeploying a patched app image)
    therefore keeps every file the attacker wrote.
  - F-03 recreates `app` *and* `web` together, which is the one case where the volume is unmounted.
  - F-03 also never checks that the marker was written before the recreation, so a failed write
    also reads as PASS.
- **Reproduced:**

  ```
  app$ echo planted > /run/fcgi/persist-marker; echo '<?php system($_GET[c]);' > /run/fcgi/x.php
  docker compose -f compose.protected.yaml up -d --force-recreate --no-deps --wait app
  app$ cat /run/fcgi/persist-marker   ->  planted        (x.php also present)

  app$ rm /run/fcgi/php.sock && mkdir /run/fcgi/php.sock
  docker compose ... up -d --force-recreate --no-deps --wait app
  -> container exited (78): "unable to bind listening socket for address '/run/fcgi/php.sock':
     Address in use (98)"; curl http://127.0.0.1:8080/ -> 502
  ```

  The attacker's change outlives the redeploy, and the patched app does not start until an
  operator removes `web` as well. The planted files are not executable (`noexec`), and nothing
  `include`s from `/run/fcgi` today, so this is persistence of data and of a DoS, not of code.
- **Fix:**
  - Give the app a socket directory that only it can write and that is re-created with the app:
    for example, the app's own `tmpfs` at `/run/fcgi`, shared to nginx through a separate
    per-app-lifetime volume, or a pre-start step that empties the volume.
  - Mount `fcgi` read-only in `web` (connecting to a socket does not need rw).
  - F-03 should write and verify the markers, recreate **only `app`**, and also check for a planted
    directory at the socket path.
  - Reword STATUS "no persistence across recreate" until then.
- **Blocks:** Yes for the claim as written.

### D1-04: Audit trail can be erased by the workload (Medium)

- **Files:** `broker/src/server.rs:51-61,161-166`; `examples/php-ledger/compose.protected.yaml:13-15`
  (json-file, `max-size 1m`, `max-file 3`).
- **Reproduced:**
  - In the app, 200 connections × 256 `{"op":"nope"}` requests produced
    `51200 requests in 1.9s`.
  - Afterwards, `docker compose logs broker` begins with a `decision` line for one of those
    requests. The `listening` lines and the earlier `ledger.transfer` allow line are gone:
    `grep -c '"op":"ledger.transfer"'` returns `0`.
- **Why it matters:** the only record of denied attempts, `unknown` outcomes, and peer
  identity is broker stdout, and the workload can rotate it away at will. Committed transfers
  survive in `transfers` (with `workload` and `correlation_id`), but denials and unknowns do not.
  AR-19 already says audit must come from the broker DB, not container logs.
- **Fix:**
  - Rate-limit and aggregate deny logging per workload (for example one line per N identical
    denials per second).
  - Write security decisions (at least denials of authenticated peers and all unknowns) to an
    append-only table or a separate log sink with its own quota.
  - Document that container logs are not an audit trail.
- **Blocks:** No, provided it is listed as a residual.

### D1-05: Harness false-PASS paths and over-claimed controls (Medium)

- **Files:** `tests/containment/run.sh:63-67,71-83,104-135`; `STATUS.md` (uncommitted diff).
- **Detail:**
  1. **Silent loss of the HTTP run.** `curl ... | grep '^{' | sed ... >> "$res" || true`. If
     the RCE endpoint times out, returns 502, or emits nothing, no `via:http` rows are written and
     the summary still exits 0. `summarize` never checks that the expected set of probe IDs is
     present for each `via`. The same applies to any single probe that throws before `emit`
     (a PHP fatal in the exec run aborts the remaining probes silently, because exec's exit status
     is lost to the pipe when the earlier lines succeeded). (Analytical.)
  2. **No positive control for R-01, C-03, F-03, S-01, S-02, B-\*.** All of these PASS in the
     baseline too. In particular:
     - R-01 records PASS on *any* `psql` failure (DNS, timeout, wrong password), not specifically
       on a `pg_hba` rejection, yet the detail field says "pg_hba".
     - C-03 is never shown to find a secret that *is* present. The baseline app's own password
       is in its environment and would make a good control.
  3. **Sensitivity rule is narrow.** Only baseline `A-01` via exec gates `N-01..N-03` and `A-01`.
     In the protected profile:
     - N-03 targets the baseline subnet, which does not exist, so it is vacuous;
     - A-01 uses a non-existent role and an empty password and fails at DNS, so it is a duplicate
       of N-01.
  4. **STATUS over-claims.** STATUS.md says "Every probe has a positive control or a baseline
     counterpart, so 'blocked' cannot be confused with 'target down'". That is false for the items
     in (2), and for F-02 (D1-02).
- **Fix:**
  - Make `summarize` require the full ID set per `via` and mark missing IDs NOT TESTED.
  - Drop `|| true` on the HTTP run, or record a single INCONCLUSIVE row when it yields nothing.
  - R-01: match `no pg_hba.conf entry` in stderr, and add a control that the same command succeeds
    with the *app* role in baseline.
  - C-03: run it in baseline against `db_app_password` and expect FAIL.
  - Fix the STATUS sentence.
- **Blocks:** Yes for the STATUS sentence; the harness changes are strongly recommended.

### D1-06: Workload authority is unbounded in aggregate (Medium, claims gap)

- **Files:** `broker/src/config.rs:132-155`; `examples/php-ledger/docker/broker/broker.json`;
  ADR-0002 §1; SI-19.
- **Reproduced:** 24 parallel in-workload clients, 40 transfers each, emptied `alice` from
  99 900 to 1 900 and moved the money to `dave`, all `allow`, in a few seconds:

  ```
  before: alice=99900 bob=50100 carol=1000 dave=0  sum=151000
  after:  alice=1900  bob=50100 carol=300  dave=98700 sum=151000
  ```

  The only bound is `max_transfer_cents` *per call*. The workload can name any `from` account. It
  has no cumulative budget, no rate limit, and no account ownership.
- **Why it matters:** this is the expected Demo 1 shape: no grants until Phase 3. However:
  - ADR-0002 §1 requires a declared authority class (`workload`) per operation, with unlisted
    grantless operations as startup errors. `config.rs` has no authority class at all.
  - SI-19 (pending ADR-0009 acceptance) requires a locked budget for grantless effects.

  Without an explicit statement, readers will take "unauthorized op denied" to mean more than it
  does.
- **Fix:**
  - In STATUS and any Demo 1 write-up, state the residual: a compromised P0 workload can perform
    any number of transfers of up to 50 000 cents between any two existing accounts.
  - Add `authority: "workload"` to the config schema with a startup error when it is missing.
  - Track the locked budget as Phase 3/4 work.
- **Blocks:** No, if stated.

### D1-07: Single DB connection; no per-workload fairness (Medium)

- **Files:** `broker/src/ledger.rs:4-7,35-38,80`; `broker/src/server.rs:22,306`; ADR-0002 §4.
- **Detail (Analytical):**
  - Every operation from every workload takes one `tokio::sync::Mutex` around one Postgres
    connection, for up to `CONNECT_TIMEOUT` plus `OP_TIMEOUT` (15 s).
  - The per-workload connection cap (32) bounds connections, not in-flight work: each connection
    can pipeline up to 256 requests.
  - With app1 holding 32 busy connections, app2 gets about 1/33 of broker throughput.
  - If the DB stalls, every workload queues behind app1's requests for up to 15 s each.
  - The module comment also says correctness under concurrency "does not depend on" the mutex. It
    is true for the SQL as written, but the mutex means the `FOR UPDATE` path has never run
    concurrently. The 24-client test above exercised the broker, not concurrent DB transactions.
- **Fix:**
  - Use a small pool with per-workload in-flight semaphores (ADR-0002 §4) and a bounded wait.
  - Add a concurrency test that runs with at least two DB connections.
  - Document that the fairness property is NOT TESTED.
- **Blocks:** No (STATUS already lists resource exhaustion and concurrency as not tested).

### D1-08: "Verified under P0" while P0 assumptions are unmet; no configuration probes (Medium)

- **Files:** `examples/php-ledger/compose.protected.yaml:20,41,54,74`; research 03 §6.1 items 2-3,
  §6.4 item 4.
- **Detail:**
  - P0 assumption 3 requires every image pinned by digest. The compose file uses tags:
    `postgres:17-alpine`, `nginxinc/nginx-unprivileged:1.28-alpine`, locally built `:dev` images,
    and `rust:1.99-slim-trixie` / `debian:trixie-slim` in `broker/Dockerfile`.
  - Assumption 2 requires that `verify` reports no FAIL, *including configuration checks*.
  - The suite probes only effects. No probe checks:
    - `NoNewPrivs: 1` and `Seccomp: 2` in `/proc/self/status`;
    - the AppArmor profile (`/proc/self/attr/current`);
    - `CapEff/CapBnd = 0`;
    - a read-only rootfs (only one path under `/var/www` is written);
    - `docker inspect` for `privileged`, extra mounts, `network_mode` or `pid: host`.
  - I confirmed by hand that these are correct today (CapEff 0, NoNewPrivs 1, Seccomp 2,
    `docker-default (enforce)`, rootfs `ro`). However, a drift such as
    `security_opt: [seccomp=unconfined]` or `cap_add: [SYS_PTRACE]` would leave all 56 rows PASS.
- **Fix:**
  - Pin the images by digest, or label the result "P0 except assumption 3".
  - Add C-xx configuration probes (the in-container `/proc` checks above, plus an out-of-workload
    `docker inspect` check against an allowlist).
- **Blocks:** Yes for the label "verified under P0" (rewording is enough).

### D1-09: C-03 places the secret it searches for in the workload (Low)

- **File:** `tests/containment/run.sh:71-72`.
- **Detail:**
  - The real broker DB password is piped into the app container.
  - It is then passed as an argument: `grep -lF "$s" "$f"`, once per `/proc/*` file.
  - While the check runs, any resident uid-10001 process in the workload (for example a
    daemon the attacker left behind) can read it from `/proc/<grep-pid>/cmdline`; `hidepid` is not
    set.

  The test of SI-02 thus briefly violates SI-02 (Analytical; standard procfs behaviour).
- **Fix:** search for a *hash* or an unrelated canary, or run the search from outside the
  workload (`docker cp`/`nsenter` from the host, reading `/proc/<pid>/environ` of the container's
  processes host-side). Do not pass the secret as argv.

### D1-10: Broker resynchronises after malformed lines; app controls nginx's connect target (Low)

- **Files:** `broker/src/server.rs:281-301` (only `TooLarge` and `Incomplete` close the
  connection; a malformed line returns an error and reading continues);
  `compose.protected.yaml:26,47`.
- **Detail (Analytical):**
  - The app owns `/run/fcgi` (mode 0755, uid 10001) and can replace `php.sock` with a symlink.
    nginx's `connect()` follows symlinks inside the *web* container's mount namespace (standard
    `AF_UNIX` path resolution).
  - Today `web` mounts no other socket, so there is no target.
  - If a later topology mounts any broker or gateway socket into the nginx/gateway container, the
    app could aim nginx at it. nginx would then forward client-controlled request bodies.
  - Because the broker skips the garbage FastCGI lines and parses any later line that is valid
    JSON, it would execute requests under the identity of whichever peer uid nginx has.
- **Fix:**
  - Close the connection after the first malformed frame; there is no legitimate reason to
    resynchronise.
  - Mount `fcgi` read-only in `web`.
  - Prefer a socket directory the app cannot rename entries in, for example created by nginx with
    the sticky bit, or a FastCGI listener on a path created before the app starts.

### D1-11: Config validation gaps; missing README (Low)

- **File:** `broker/src/config.rs:75-123`.
- **Detail:**
  - Two workloads with the same `uid` are accepted, which reduces the `SO_PEERCRED` second factor
    to the mount alone. ADR-0002 §3 states that workloads have distinct UIDs.
  - A workload uid equal to the broker's own uid (`getuid()`) is also accepted.
  - `Cargo.toml:11` says "Each dependency is justified in README.md", but `broker/README.md` does
    not exist.
- **Fix:** reject duplicate uids and the broker's own uid at startup, add unit tests, and add the
  README or remove the reference.

### D1-12: Misleading audit and client fields (Low)

- **Reproduced:** every decision line has `"peer_pid":0`. The workload is in another PID
  namespace, so `SO_PEERCRED` translates its pid to 0.
- **Reproduced:** with the connection limit exhausted, the refusal response carries `"id":null`,
  so `BrokerClient` reports `bad_response: response does not match request` instead of
  `unavailable`.
- **Fix:** log `peer_pid` as null when it is 0 (or drop it). Have the client accept an `id:null`
  error response on a fresh connection as `unavailable`.

### D1-13: Info

- **AR-15 partial.** `Set-Cookie` from the app passes through. Reproduced:
  `Set-Cookie: __Host-session=attacker` reached the client. This is harmless until gateway cookies
  exist, but AR-15 lists it.
- **Not followed:** `Location: /_internal/x` with status 200 was not followed as an internal
  redirect (checked).
- **Host-readable secrets.** `gen_secrets` sets the secrets to 0644 on the host. Acceptable for a
  local demo; it should be stated.
- **Healthcheck.** The broker healthcheck does not check DB reachability. It still fails closed.
- **Address-based `pg_hba`.** `pg_hba` trusts the source IP 172.30.10.10 plus SCRAM. Another
  container could take that address only while the broker is absent, and only with host access
  (out of scope).

---

## What held (attempted and not broken)

- **No path out of the app:**
  - Network: only `lo` in `/proc/net/dev`; DB, internet and DNS unreachable.
  - Visibility: no `/run/secrets` or `/etc/nodkey`; the app2 socket is not visible.
  - Privilege: CapEff 0, NoNewPrivs 1, seccomp filter mode, AppArmor `docker-default`.
  - Filesystem: rootfs read-only.
  - Extensions: FFI is not loaded.
- **`SO_PEERCRED`:** a container with the app1 socket volume mounted, running as uid 10003, 10002
  or 0, received `unauthenticated`. Only uid 10001 was served. (The suite does not test this; see
  below.)
- **Transfers:** 24 parallel clients × 40 transfers (with insufficient-funds contention) kept the
  sum at 151 000 and no balance went negative.
  - Lock order (`ORDER BY id FOR UPDATE`) and the in-transaction funds check are correct as SQL.
  - Debit, credit and journal commit together or not at all.
- **Parser:** the strict JSON pre-check (duplicates at any depth), `deny_unknown_fields`, i64
  amount with float and string rejected, and bounded frame reading all hold. I found no
  differential between the duplicate check and the typed parse (both use `serde_json`).
- **Connection limit:** 40 held connections exhaust the per-workload permits (self-DoS only). The
  refusal tasks finish immediately, so broker file descriptors are not exhausted (soft `nofile`
  is 1024).

## What the suite does not test

- **`SO_PEERCRED`:** no probe connects to a workload socket as the wrong uid.
- **Configuration drift:** seccomp, AppArmor, no-new-privileges, capabilities, privileged,
  extra mounts, and image digests are not checked (D1-08).
- **Ambiguous outcomes and fail-closed behaviour (SI-15):** DB paused or killed mid-transfer,
  broker restart, client timeout (D1-01). The unknown-outcome path has no test at any level.
- **Broker concurrency:** no concurrent DB transactions, because of the single mutex (D1-07). There
  is also no cross-workload fairness or starvation test, and no slowloris or connection flood
  against the broker.
- **Persistence:** app-only recreation, a planted socket-path directory, and markers verified as
  written (D1-03). Exec is tested from no writable mount effectively (D1-02).
- **Log and audit integrity:** log flooding (D1-04).
- **Ledger semantics end to end:**
  - unknown account, insufficient funds, overflow, and `from == to`;
  - the exact limit boundary (`50000`);
  - op-not-permitted for a second workload (app2 is configured but no app2 workload runs);
  - cumulative drain (D1-06).
- **Broker reach:** egress from the broker container (P0 residual 7), and reachability of the
  data-network gateway 172.30.10.1 from the broker or DB.
- **Response-side deputy behaviour beyond `X-Accel-Redirect`:** `X-Accel-Limit-Rate`, `Set-Cookie`,
  `Location`, `Status`. Checked by hand only.
- **Kernel attack surface:** io_uring, user namespaces, `/proc/self/mem` native code, ptrace
  between workload processes. These are residual risk 1 and should at least be listed as NOT
  TESTED.
- **Suite completeness:** no check that every expected probe ID was produced for each `via`
  (D1-05).

## Evidence notes

Reproduction scripts were run from the reviewer's scratch space against
`nodkey-protected` started with `docker compose -f examples/php-ledger/compose.protected.yaml up
-d --build --wait`. Outputs are quoted above. The stack was torn down (`down -v`) afterwards, and
`tests/containment/run.sh both` was re-run so the repository's result files reflect an unmodified
run. That re-run (2026-10-25) gave: protected `56 PASS, 2 NOT APPLICABLE`, exit status 0. Baseline
F-02 was again `PASS` (vacuous, D1-02) and baseline F-03 was again `PASS` (no positive control,
D1-03/D1-05). None of the issues above changed any suite result.

## Resolution (orchestrator, 2026-10-25)

| Finding | Disposition | Where |
|---|---|---|
| D1-01 High | Fixed. Failures after the first write are `outcome_unknown`; required idempotency key with `UNIQUE (workload, idempotency_key)`; client and UI never report a possibly committed transfer as failed. Independently re-reviewed (`2026-10-25-idempotency-review.md`). | `broker/src/ledger.rs`, `BrokerClient.php`, `index.php`, `tests/integration/idempotency.sh` |
| D1-02 High | Fixed. Exec probe uses a real applet name; rc 0 = FAIL, 126 = PASS, else INCONCLUSIVE; covers `/dev/shm`, `/dev/mqueue`; protected PASS requires the baseline to FAIL. | `tests/containment/probes.php` F-02 |
| D1-03 Medium | Fixed. App empties its socket directory before starting php-fpm; F-03 recreates only `app` and requires marker precondition F-00. | `docker/php/Dockerfile`, `run.sh` |
| D1-04 Medium | Accepted residual for Demo 1; documented. Durable decision audit planned with the evidence layer. | `examples/php-ledger/README.md` |
| D1-05 Medium | Fixed. Required-ID completeness (missing = NOT TESTED); generic baseline sensitivity map; R-01 requires the `pg_hba` rejection; C-03 requires control C-03K; STATUS wording corrected. | `run.sh`, `STATUS.md` |
| D1-06 Medium | Accepted residual for Demo 1 (no per-user authority yet); addressed by Phase 3 grants and Phase 4 budgets; documented. | README |
| D1-07 Medium | Accepted residual; documented. | README |
| D1-08 Medium | Fixed. All images pinned by digest; configuration-drift probes P-01..P-05 (in-workload `/proc` checks and out-of-workload `docker inspect`). | compose files, Dockerfiles, `probes.php`, `run.sh` |
| D1-09..D1-13 | Low/Info: tracked for the hardening phase. | — |
