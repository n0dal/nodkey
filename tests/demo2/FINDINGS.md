# Demo 2 — integration findings

Issues found while assembling Demo 2 (`examples/confirmed-transfer/`) and its harness
(`tests/demo2/`). Per the brief, defects in `broker/`, `crates/*` or the specs are **recorded here,
not fixed**. Items fixed in the demo/harness themselves are listed at the end.

Environment: Docker 29.5.2 (Colima VM), macOS; images pinned by digest; effect-protocol-v2 Draft 2.

---

## DEMO2-F02 (component defect — `crates/nodkey-authority`) — authority does not reconnect a stale socket-A connection; the first approval after >10 s of idleness fails

**Severity:** medium (availability / correctness of a single approval; fails *closed*, so no
security-invariant violation — it denies, it does not double-execute).

**Where:** `crates/nodkey-authority/src/broker_client.rs`, `BrokerClient::call`.

The authority keeps **one** pooled connection to the broker (socket A) and, on a write/read error,
drops it and returns `Unavailable` **without reconnecting and retrying**:

    let r = self.exchange(conn, op, args).await;
    if matches!(r, Err(CallError::Unavailable(_))) {
        *guard = None;      // dropped, but this call still returns Unavailable
    }
    r

The broker closes idle control connections after `READ_TIMEOUT = 10 s`
(`broker/src/server.rs:19`). So whenever an `approve` arrives more than ~10 s after the previous
socket-A activity (the common case — approvals are human-paced), the authority writes
`pending.get` into a half-closed socket, the write fails, and the gateway shows the uniform error
("This request is not available."). The **next** approval reconnects and succeeds.

**Repro (observed):**
1. `tests/demo2/run.sh` (stack fresh); wait >10 s after start-up (the authority's last A activity
   is the start-up `config.digest`).
2. Sign in as Alice, propose a transfer, open the confirm page, click **Approve** once.
3. The approval fails. Broker/authority logs:

       authority | {"call":"pending.get","detail":"write","event":"broker_unavailable"}
       authority | {"event":"approve_refused","reason":"pending.get: unavailable"}
       gateway   | nodkey-gateway: approve not accepted: Refused("not_available")

   The pending record stays `PENDING`.
4. Re-render the page (fresh token) and approve again → succeeds; record → `APPROVED` → `SUCCEEDED`.

**Impact on the demo:** every human approval that follows an idle period fails on the first click.
Fail-closed is preserved (SI-15): the record is not approved, nothing is consumed, no double
effect. But it is a self-inflicted denial of the first approval and would be very confusing in use.

**Suggested fix (for the component owner, not applied here):** in `BrokerClient::call`, on an
`Unavailable` write/connection error, reconnect once and retry the request idempotently
(`config.digest`, `pending.get` and `grant.deliver` are all safe to retry — `grant.deliver` is
already idempotent by `jti`). Alternatively keep the A connection warm with a periodic
`config.digest` ping shorter than the broker's `READ_TIMEOUT`, or have the broker not time out the
authority connection.

**Harness accommodation:** `approve_with_retry()` re-renders a fresh token and re-approves (up to
5 attempts). It is documented in the code and does not hide the defect — it exists precisely
because a single approval is unreliable. Attack groups that test *rejection* do **not** retry.

---

## DEMO2-F01 (packaging observation — `crates/nodkey-gateway`) — no way to expose the gateway on a container-internal interface for a reverse-proxied dev deployment

**Severity:** low (ergonomics; the loopback requirement is a deliberate security control, R3B-11).

`config::check()` refuses dev TLS / test-login unless `listen` is loopback
(`crates/nodkey-gateway/src/config.rs`). In Compose, a published port
(`127.0.0.1:8443:8443`) arrives on the container's `eth0`, not loopback, so the gateway cannot be
reached directly from the host while dev TLS + test login are on.

This is **working as designed** (the restriction prevents accidentally exposing the credential-less
test login). It is recorded only to explain the demo's `gateway-port` service: a tiny stream-mode
nginx relay that runs in the gateway's own network namespace (`network_mode: service:gateway`) and
forwards the published port to the gateway's `127.0.0.1:8444` listener. TLS is end-to-end (the
relay only sees ciphertext). No component change is warranted.

---

## DEMO2-F03 (harness/deployment note — not a component defect) — full containment sweep over `/debug/eval` can exceed the gateway upstream timeout

The complete containment probe set issues several `connect()` calls whose OS timeouts can add up to
more than the gateway's `upstream_timeout_ms` (15 s), so serving the whole sweep through the app's
`/debug/eval` endpoint sometimes returns `502 Bad gateway`. The individual broker-socket attacks
(A1, A8, A10) run through `/debug/eval` fine and still model attacker C with code execution in the
workload; the **full** sweep (A9) is run through `docker compose exec app php` (identical
namespaces, uid and mounts), and the harness separately confirms the `/debug/eval` RCE endpoint is
live. No component defect.

---

## Fixed in the demo/harness (in scope)

- **db healthcheck:** an initial healthcheck used `psql` over the local socket as user `postgres`,
  which `pg_hba` maps to peer auth as the container's `root` → "Peer authentication failed". Changed
  to TCP `pg_isready -h 127.0.0.1` (the init-time socket-only server keeps it failing until every
  initdb script, including the Demo 2 seed, has run). All operator `psql` calls in the harness run
  as the `postgres` OS user (`docker compose exec --user postgres`).
- **gateway image build:** `gateway.Dockerfile` must also `COPY crates/nodkey-gateway/static`
  (the CSS is `include_str!`'d at compile time).
- **socket directory permissions:** each control socket is a tmpfs volume whose root is owned by the
  listener with group = the single permitted client and mode `0750` (the I directory is `2750`
  setgid so the authority's `0660` socket inherits the gateway group); the untrusted app web server
  runs `umask 000` so the gateway can connect to its `app-http` socket. The socket *directory*, not
  the socket mode, is the access boundary (matches spec §1.2 and the authority's AU-4 reading).
- **cross-workload propose params:** a `from == to` transfer is rejected at `effect.propose`
  (`invalid_argument`); the A8 probe proposes `carol → alice` so the proposal is accepted and the
  cross-workload `effect.status` denial is what is actually tested.
