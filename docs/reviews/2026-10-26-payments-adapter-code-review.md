# Code review: `crates/nodkey-payments-adapter` (commit 25c45ac)

- **Date:** 2026-10-26
- **Reviewer role:** adversarial reviewer. Fresh context; the reviewer wrote none of this code.
- **Target:** `crates/nodkey-payments-adapter/` at commit `25c45ac`.
- **Contract:** `docs/specs/payments-adapter-v1.md` Draft 3; ADR-0012 rev. 2; ADR-0006 Amendment 2;
  `crates/nodkey-grant` README and `src/retransmit.rs` (`verify_retransmission`, `verify_binding`);
  `tools/simpay/README.md` and `tools/simpay/src/api.rs`. Prior design review:
  `docs/reviews/2026-10-25-payments-adapter-review.md` (PA-01..PA-19).
- **Attacker model:** J-lite, a compromised broker that controls every byte on socket P. Secondary:
  G, a malicious provider.
- **Scope note:** this is a code review. Deployment properties (Docker networks, `pg_hba`, volumes,
  `cap_drop`) were not examined. No Docker was run, so `tests/postgres.rs` was not run.

## Tests run

`cargo test` (it starts a local simpay process):

- First run: unit tests 30/30 passed. Then `tests/http_edge.rs::stall_after_head_times_out` FAILED
  (`assertion failed: t.elapsed() < Duration::from_secs(3)`, `tests/http_edge.rs:113`), and cargo
  stopped at that binary.
- The same test run on its own 3 times: failed once (3.98 s), passed twice (2.22 s, 2.18 s).
- `cargo test --no-fail-fast`: every suite passed. Unit 30, http_edge 10, process 2, simpay 19,
  socket_p 9, tls 8. `postgres` had 1 test ignored (needs Docker).

So the suite is green apart from one timing-flaky test (PC-A-08).

## Findings

| ID | Severity | Location | Blocks |
|---|---|---|---|
| PC-A-01 | **High** | `src/derive.rs:70-82`, `src/server.rs:164-167`, `src/lib.rs:80`; spec §3.3 (l. 192-194) | **yes** |
| PC-A-02 | Medium | `src/lib.rs:88`, `src/orders.rs:97,120,138`, `src/provider.rs:190-231`, `src/server.rs:187-227` | no |
| PC-A-03 | Low | `src/lib.rs:52-62`, `src/config.rs:349-381` | no |
| PC-A-04 | Low | `src/provider.rs:110-116` | no |
| PC-A-05 | Low (unverified hypothesis) | `src/provider.rs:216-231` | no |
| PC-A-06 | Low | `src/orders.rs:114-118` | no |
| PC-A-07 | Low (spec consistency) | `tests/simpay.rs:463-469`; README "Decisions"; spec §11 PT-18 | no |
| PC-A-08 | Low (test) | `tests/http_edge.rs:106-114` | no |
| PC-A-09 | Info | `src/server.rs:251-252`, `src/result.rs:472-494` | no |
| PC-A-10 | Info | `src/config.rs:460-482` | no |

### PC-A-01 — High — Rotating, losing or regenerating `K_idem` lets a compromised broker get a second refund for every grant younger than `R_max`

**Where.** `idem_key` and `reference` are `HMAC(K_idem, …)` over `(account, op, opv, iss, jti)`
(`src/derive.rs:70-82`, called at `src/server.rs:164-167`). `K_idem` is read at start-up with no
activation time (`src/lib.rs:80`). Nothing on the create path ties a grant to the `K_idem` that was
current when the grant was first sent. The only rotation rule is an operator obligation in spec §3.3:
"rotate `K_idem` only when no row is non-final". The other half of that rule is the broker's
`idem_kid` check, and the broker is the attacker here.

**Scenario (J-lite plus a documented operator action).**

1. At T0 a grant G (amount 50.00 on charge C, `iat` = T0) is executed. simpay stores the record
   under `idem_key_1` and the refund is `SUCCEEDED`. No row is non-final.
2. At T0 + 1 h the operator rotates `K_idem`, following §3.3. The trigger may also be a lost secret
   being regenerated, or a re-deployment. The adapter restarts with `K_idem'`.
3. At T0 + 2 h the broker is compromised. It sends `refund.create{G}` on P.
4. `verify_retransmission` accepts G (age 2 h < `R_max` 12 h), and the order check passes (owner
   and charge are unchanged). The adapter derives `idem_key_2 ≠ idem_key_1` and a new `reference`.
   simpay has no record for `idem_key_2`, so it executes a **second** refund of 50.00, provided C
   still has 50.00 refundable.
5. The broker repeats this for every grant with `iat` in the last `R_max`.

This breaks the spec's headline claim: "at most one refund per signed grant … while the grant is
younger than `R_max`". §10 does not publish it as a residual. The fingerprint does not help, because
the key differs, so simpay sees a new request. Only the provider's per-charge remaining amount bounds
the loss.

**Fix (pick one, and state it in spec §3.3 and §10).**

- (a) Add a config value `idem_key_not_before` (Unix seconds, set by the operator at rotation; start
  check `≤ now`). Refuse `refund.create` with `grant_refused` when `iat < idem_key_not_before`.
  Lookups are unaffected.
- (b) Make "rotation = stop the adapter for at least `R_max` + skew before starting with the new key"
  normative. This is weaker, because nothing enforces it.

Either way, add a PT-36 variant: rotate `K_idem`, then resend a young `SUCCEEDED` grant on P.
Expected: `grant_refused`, ledger unchanged. Today the ledger would show 2.

### PC-A-02 — Medium — The adapter's time per request is not bounded by the broker's timeout, and work continues after the broker gives up

**Where.** The order check uses three separate 2 s timeouts: `UnixStream::connect`, `connect_raw` and
`query_opt` (`src/orders.rs:97,120,138`, with `Duration::from_secs(2)` at `src/lib.rs:88`). Only
after that does the provider exchange start, with its own `total_ms` deadline (`src/provider.rs:191`).
The worst case is ≈ 6 s + 10 s = 16 s. The broker's timeout is `total_ms + 2 s` = 12 s (spec §1), and
its lease formula `L_dispatch = 3 × (total_ms + 2 s) + 13 s` assumes each call takes at most that.
The adapter does not abort when P is closed, so `handle_line` runs to completion (`src/server.rs:187-227`).

**Scenario.** The DB is slow (≈5 s), whether naturally or by load. The broker times out at 12 s and
records the call as ambiguous, then `UNKNOWN`. The adapter writes the POST at about 5 s and may get its
answer as late as 15 s. The reconciler's first `refund.find` can therefore run while the adapter's
POST is still in flight. With an honest provider this is safe, because the same key gives a 409 or a
cached replay. But PT-33's assumption, "at most one adapter call in flight per row", does not hold on
the adapter side, and `not_found` from an early `find` can unlock a first-round resend.

**Fix.** Use one deadline per request, started when the request line arrives. Give the DB phase a
single budget (for example 2 s in total) and the provider phase the rest of `total_ms`. Alternatively,
specify the broker's timeout as `db_budget + total_ms + 2 s` and recompute `L_dispatch`. Add a test
with a slow fake `OrderView` that asserts the response arrives within the broker's budget.

### PC-A-03 — Low — The owner check on the config file is circular and weaker than §2's "owner root"

**Where.** `src/lib.rs:52-62` checks the config file first with `broker = own_uid`, parses it, and
only then re-checks it with `cfg.broker_uid`, a value **read from that same file**. The second read's
bytes are discarded; the first read's bytes are the ones used. `read_operator_file`
(`src/config.rs:349-381`) excludes only the adapter and broker uids as owners of the file and its
parents. A file owned by any other non-root uid passes, for example the shop workload's 10001 or
PostgreSQL's uid, although the §2 table says "owner root".

**Scenario.** This is not exploitable by J-lite alone. A broker-written config must name
`broker_uid = 10002` for P to accept the broker, and the second check then rejects a file owned by
10002. It becomes exploitable when another uid is compromised or misconfigured, for example a
workload-owned `/etc/nodkey-adapter`.

**Fix.** Require owner uid 0 for the registry, config, CA and their parents, as the §2 table says. Do
one `open_checked` read, and check and parse those same bytes.

### PC-A-04 — Low — `Call` derives `Debug` and would print the `Idempotency-Key`

**Where.** `src/provider.rs:110-116`: `#[derive(Debug, Clone)] pub enum Call { Create { idem_key, form }, … }`.
Nothing formats a `Call` today, so this is a latent leak. The spec says the broker never sees
`idem_key` and logs never carry it. `Derived` is redacted (`src/derive.rs:34-41`); `Call` is not.

**Fix.** Write a manual `Debug` for `Call` that redacts `idem_key`.

### PC-A-05 — Low (hypothesis, not verified) — The hyper connection task is not aborted when the exchange times out

**Where.** `src/provider.rs:216-231`. `driver.abort()` runs only when `run` returns. When
`timeout_at(deadline, work)` fires, `work` is dropped, but the spawned `driver` task (it owns the TLS
stream) is not aborted. Whether hyper 1.x's `Connection` future ends on its own once `SendRequest` and
the response future are dropped was **not verified** in this review.

**Scenario, if it does not end.** A malicious provider (G) stalls every response after the head. Each
timed-out exchange then leaks one task and one TCP/TLS socket. The broker, or simply load, keeps
creating exchanges until the adapter hits its fd limit, and every later exchange fails at `connect`,
which is `not_sent`. That is a DoS, not a safety failure.

**Fix.** Wrap the `JoinHandle` in a guard that aborts on `Drop`, or `select!` the connection future
inside `work`. Add a test that runs N stalled exchanges and counts open fds or live tasks.

### PC-A-06 — Low — The adapter does not pin its own DB session settings

**Where.** `src/orders.rs:114-118`. Name resolution is protected only by
`ALTER ROLE … SET search_path = ''` on the server side (spec §2, PA-17). The statement is
schema-qualified (`ORDER_SQL`, `src/orders.rs:20-21`), but the `=` operator still resolves through
`search_path`. `pg_catalog` comes first unless the path lists it explicitly later.

**Fix (defence in depth).** Set `cfg.options("-c search_path=")` on the connection, so a role-level
misconfiguration cannot reopen PA-17. Optionally run `SHOW search_path` once at start-up and refuse to
start if it is non-empty.

What was verified: the `SO_PEERCRED` check is done on the connected fd before `connect_raw`
(`src/orders.rs:97-113`). That leaves no TOCTOU between the check and the protocol, and the unit test
`refuses_db_socket_with_wrong_peer_uid` shows that no byte is sent to a peer with the wrong uid.

### PC-A-07 — Low (spec consistency) — `crlf_injection` → `created`: an assessment of the implementer's decision

**What simpay sends.** simpay pushes a header value
`ok\r\nSet-Cookie: simpay_injected=1\r\nLocation: http://attacker.invalid/`
(`tools/simpay/src/api.rs:780-783`). On the wire, that is three well-formed header fields. They cannot
be told apart from a provider that really sends `Set-Cookie` and `Location` on a 200.

**What the adapter does with them.** It reads only `Content-Type` (it requires exactly one, with value
exactly `application/json`) and the body. It never follows `Location`, never stores cookies, and
never forwards a header value. The ledger confirms that the refund happened, and the broker requires
an identical `refund.get` before it records `SUCCEEDED`. So **`created` is correct, and I agree with
the decision.** Reporting `ambiguous` would push a refund that truly exists into `UNKNOWN` for no
safety gain.

**The inconsistency.** Spec §11 PT-18 still expects `ambiguous` for `header_injection` as a whole.

**Fix.** Amend PT-18 so that `crlf_injection` (syntactically valid extra fields) gives `created` and
the other variants give `ambiguous/bad_headers`. Optionally, add an anomaly (for example
`unexpected_header`) when a non-3xx response carries `Location` or `Set-Cookie`. That would need a
new `anomalies` enum value in §4.

### PC-A-08 — Low (test) — `stall_after_head_times_out` is timing-flaky and measures the wrong interval

**Where.** `tests/http_edge.rs:106-114`. `t` starts before `FakeServer::start` and `start_p`, so the
assertion `< 3 s` covers test setup plus an exchange with `total_ms = 1200`. Observed results:

- one failure in the first full run;
- one failure in three runs of the test on its own (3.98 s);
- passing runs took about 2.2 s, which leaves little headroom.

Because setup is included, the test neither proves the `total_ms` bound nor passes reliably.

**Fix.** Start the timer right before `p.create(...)` and assert `< total_ms + 500 ms`.

### PC-A-09 — Info — `refund.get` lets the broker probe provider refund ids

`refund.get` takes any `re_` id the broker chooses (`src/server.rs:251-252`).

- An id that does not exist gives `not_found`.
- An id that exists but belongs to another charge, amount or reference gives
  `ambiguous/echo_mismatch` with `contradicts_request` (`src/result.rs:472-494`).

So the broker learns whether an id exists, and nothing else. The broker already holds provider refund
ids, so this is acceptable. Note it in §10 or ignore it.

### PC-A-10 — Info — The group of socket P's directory is not checked

`check_socket_dir` (`src/config.rs:460-482`) checks the owner and mode `2750`. It does not check the
group, which §1 says must be the broker's group. The `SO_PEERCRED` check on every connection
(`src/server.rs:406-425`) still rejects other uids, so the only effect is on liveness and
diagnostics.

## Hunt items with no finding (verified)

- **`verify_retransmission` vs `verify_binding`.**
  - `refund.create` reaches the provider only through `grant::verify_create` →
    `verify_retransmission`, with the age cap (`src/grant.rs:195-210`, `src/server.rs:187-227`).
  - Lookups use `verify_binding` (`src/grant.rs:215-230`) and only ever build a `Call::Get`
    (`src/server.rs:251-265`). No lookup path can issue a POST.
  - The two crate result types are distinct, and `BindingVerified` has no conversion to
    `RetransmissionAuthorized`.
  - The adapter rules (amount `1..=999 999 999 999`, the charge pattern, the ISO table) run on both
    paths (`src/grant.rs:233-250`).
- **A resend cannot reuse a different key, apart from PC-A-01.**
  - The key derives only from `cfg.account`, the compiled `op`/`opv` and the signed `iss`/`jti`.
    These come from the verified payload, not from the grant bytes, so transport or signature
    malleability cannot change the key.
  - The derivation matches §3.3 (length-prefixed, domain-separated `idem\0` / `ref\0`), with Python
    vectors (`src/derive.rs:93-108`).
  - The form body is built only from grant values (`src/server.rs:204-217`), so a resend has the same
    fingerprint. A change to `send_currency` changes the fingerprint and fails closed
    (`idempotency_params_mismatch`).
- **Tenants, charge, amount and currency.**
  - The tenant comes from the configured `tenants` in the crate's 9c check (`retransmit.rs:294-300`)
    and from the order row (`src/orders.rs:53-70`).
  - `created` requires the charge, amount, upper-cased currency and derived reference to equal the
    grant's values (`src/result.rs:363-368, 403-407`).
- **"Not sent" classification.**
  - `NotSent` arises only before or during TCP connect and the TLS handshake (`src/provider.rs:194-204`).
  - The hyper handshake, and any failure after it, is `ambiguous`.
  - `ok:false` is returned only before the exchange (create) or on `NotSent` (lookups,
    `src/server.rs:267-271`).
- **TLS.**
  - Only TLS 1.3 is allowed, and the pinned CA is the only root.
  - `ServerName` must be a DNS name, so the hostname is checked.
  - Resumption and early data are off, and ALPN is `http/1.1` (`src/provider.rs:71-86`).
- **Proxies, redirects and DNS.**
  - `src/` has no `std::env::var`.
  - hyper is used at the `client::conn` level, so there is no proxy, redirect handling or DNS.
  - The destination is an IP literal (`src/config.rs:193-199`).
- **Response limits.**
  - 64 headers; `max_header_size` = `max_head`; obsolete folding and invalid headers are rejected; no
    HTTP/0.9 (`src/provider.rs:207-215`).
  - Header values must be ASCII with SP/HTAB.
  - The body goes through `Limited`, and 5xx/3xx bodies are not read.
  - Strict JSON (duplicate keys, depth, u64 only) is checked before typed reading.
  - The whole exchange is under one deadline.
- **Log and response injection.**
  - Logs are serialized with `serde_json`, which escapes control characters.
  - The `op` echoed into logs is truncated to 32 characters.
  - Responses contain only enums, pattern-checked ids, integers and grant-derived values.
  - Error messages are static.
- **Secrets.**
  - `ApiKey`, `IdemKey`, `Derived` and `PgUnixView` all redact their `Debug` output.
  - The `Authorization` header value is marked sensitive.
  - Start-up errors do not echo config content (`classify_str`).
  - The remaining copies inside hyper and tokio-postgres are published as residuals in the README.
- **Socket P.**
  - The peer uid is checked before any read.
  - The line is at most 8 KiB, with a 2 s idle timeout and a 2 s write timeout.
  - Connections beyond `max_concurrent` are closed at once. A compromised broker can exhaust the
    permits, but that is only DoS, which §10 accepts.
- **`R_max`.**
  - `RMax::new` enforces `R_max < retention − margin` and `margin < retention` at start-up
    (`src/config.rs:205-209`).
  - `retention_s` remains an operator assertion that cannot be checked against simpay (spec §3.1).

## Verdict

**Changes required.** PC-A-01 (High) blocks: under J-lite, a `K_idem` rotation that follows the
documented procedure re-enables one extra provider refund per young grant. The spec's central claim
does not hold until the adapter refuses creates for grants issued before the current key's activation
(option (a)), or the residual is published and the rotation procedure made enforceable. PC-A-02
should be fixed together with the broker's timeout and lease constants. The remaining items do not
block.

The core of the implementation holds against every other hunt item:

- the separation between the verification types;
- deriving every value from the grant;
- the peer-uid-before-protocol DB channel;
- TLS pinning;
- the sent/not-sent boundary;
- response bounding.
