# nodkey-payments-adapter

> **PROTOTYPE.** Not suitable for production use. It talks only to `tools/simpay`, a
> **simulated** payment provider.

The payments adapter of Demo P. It implements
[`docs/specs/payments-adapter-v1.md`](../../docs/specs/payments-adapter-v1.md) **Draft 3.2**
(ADR-0012 rev. 2, ADR-0006 Amendment 2).

It is a stateless process with its own uid. It alone holds the simpay key and `K_idem`, and it
alone can reach simpay. It listens on socket P for the broker and checks the peer with
`SO_PEERCRED`. For every request it:

1. verifies the authority-signed grant itself;
2. re-checks order → charge → owner in its own read-only view of `nodkey.orders`;
3. derives the idempotency key and reference from the grant's `(iss, jti)`;
4. builds the provider request from the grant only;
5. returns a bounded, closed-enum result.

```sh
nodkey-payments-adapter --config /etc/nodkey-adapter/config.json
```

## What it does

| Area | Spec | Implementation |
|---|---|---|
| Start-up inputs | §2, §9 | Config, registry and pinned CA are operator files. Each must be a regular file and not a symlink (the opened inode must equal the checked path), owned by root, with every parent directory owned by root and no group/other write bit on the file or any parent; the config is read once and the checked bytes are parsed. Secrets (simpay key, `K_idem`, DB password) must be owned by the adapter uid with mode exactly `0400`. Socket P's directory must be owned by the adapter with mode exactly `2750`. Refusals: uid 0, or a uid equal to `broker_uid` or `db_uid`; empty `tenants`; `addr` not an IP literal; `server_name` not a DNS name; the `R_max` rule; unknown or duplicate caps; P's directory nested with `db.socket_dir`; a CA file with anything other than exactly one certificate; a key that is not a restricted `rk_sim_` key; `idem_key_not_before` before 2024-01-01 or in the future; not `connect_ms < total_ms`. Config is strict JSON (no duplicate keys, `deny_unknown_fields`, integers only). Nothing is re-read at runtime. |
| Grant check, creates | §3.1 | `nodkey_grant::verify_retransmission`: clock floor, steps 1–7 (4c revoked key, 4d window at `iat`), 8a–8d, no 8e, age `now − iat ≤ R_max`, 9a–9c (with 9c against the configured `tenants`, RX-1), kind, `cfm`, `op`/`opv`, and the exact `res`/`con` shape. The declaration is compiled in. Then the adapter rules (step 6): `amount_minor ≥ 1` (RX-3) and ≤ 999 999 999 999; con2 matches `^ch_[A-Za-z0-9]{8,61}$`; `currency` is in the ISO 4217 table, which is the same table as the broker's. |
| Grant check, lookups | §3.1, PA-18 | `nodkey_grant::verify_binding`: the same checks without the age rule, then the same adapter rules (con2 pattern on every op, PA-19). There is no order check, because lookups cannot cause an effect. |
| Order view | §2, §3.2, PA-16 | `PgUnixView` connects `<socket_dir>/.s.PGSQL.5432` itself and requires the server's `SO_PEERCRED` uid to equal `db_uid` before it sends any byte. Only then does it run `tokio-postgres` `connect_raw` (SCRAM, no TLS on a Unix socket). It sends one schema-qualified statement. Row mismatch → `grant_refused`; DB failure → `unavailable`. |
| Key binding | §3.3 (PC-A-01, BP-01) | Every grant-carrying op takes `idem_kid`; another value → `ok:false idem_kid_mismatch`, checked before the grant, nothing sent. `refund.create` is refused (`grant_refused`) for `iat < provider.idem_key_not_before`. |
| Deadline | §1 (PC-A-02) | One deadline per request, `total_ms` after the connection is accepted; the order check gets at most `min(2 s, time left)`; the provider exchange ends by the same deadline. `adapter.hello` reports it as `deadline_ms`. The DB session also pins `search_path` to empty in its start-up options (PC-A-06). |
| Derivation | §3.3 | HMAC-SHA256 (`hmac`/`sha2`) over the length-prefixed `D`; b64url unpadded (43 characters); `idem_kid` = first 8 bytes of `HMAC(K_idem, "kid")` as hex. Vectors were computed independently with Python. |
| TLS | §5 | rustls/ring, TLS 1.3 only, with the pinned CA as the only root. SNI and the name check use `server_name`. Resumption is disabled (no tickets, no early data); there is no client certificate; ALPN is `http/1.1`. The destination is the configured IP:port: no DNS, no proxy. |
| HTTP | §5 | hyper 1.x `http1` client, one request per connection. Options: `max_headers(64)`, `max_header_size` = `max_head`, obsolete line folding rejected, invalid headers not ignored, no HTTP/0.9. Header values must be visible ASCII, SP or HTAB. Body cap is `max_body` (`Limited`); connect + handshake must finish within `connect_ms`; the whole exchange within `total_ms`. Redirects are never followed. Headers are fixed (`Host`, `Authorization`, `Idempotency-Key`, `Content-Type`, `User-Agent: nodkey-payments-adapter/1`, `Content-Length`). The body is form-encoded and built from the grant only. |
| Sent / not sent | §1, §5 | `not_sent` is returned only for a failure before the handshake completes (`connect`, `tls`). Every failure after that is `ambiguous`. Error strings are never inspected. On lookups, `not_sent` becomes `ok:false unavailable`, because `ok:false` must mean "nothing written". |
| Classification | §4, §6 | Bodies are decoded only for 200/400/401/403/404/409/429. Decoding requires `Content-Type` to be exactly one `application/json`, strict JSON, depth ≤ 8 and `u64`-only numbers. A `created` result requires `charge`, `amount`, `currency` and `reference` all equal to the grant-derived values. Lookups require the same, plus the requested id on `refund.get`. A `find` that returns 2 or more items, or `has_more`, is `too_many_matches`. Results contain only closed enums, pattern-checked ids, integers and grant-derived values, with `anomalies` on every result. |
| Socket P | §1, §4 | The effect-protocol-v2 envelope (`v: 2`), strict JSON, line ≤ 8 KiB, one request per connection, a 2 s idle timeout, and at most `max_concurrent` connections (more are closed at once). A wrong peer uid gets no response and raises an alarm. Error messages are static per code. |
| Logs | §5 custody | JSON lines on stdout. They carry closed-enum values, uids, the `jti` and correlation ids. They never carry keys, `Idempotency-Key`, provider text or headers (byte-searched in tests). `Debug` output of secrets is redacted, and secrets live in zeroizing buffers. |

## Decisions and deviations (for review)

- **Lookup equality.** Lookups require the found refund's amount, currency and reference to equal the
  grant-derived values, not only the charge (§4 says "a found refund must match the grant's charge").
  A mismatch is `ambiguous/echo_mismatch` + `contradicts_request`. Every request for one grant
  derives from that grant, so any other value is an inconsistent answer.
- **`crlf_injection`** (now spec PT-18, Draft 3.2). simpay's variant smuggles syntactically *valid* extra header lines
  (`Set-Cookie`, `Location`) into an otherwise exact 200. Those headers are never read or forwarded,
  so the result is `created`. The ledger confirms the refund really happened. The broker
  still confirms by `refund.get` before `SUCCEEDED`.
- **Oversized head / 65 headers → `bad_headers`.** hyper's `is_parse_too_large` exists only with
  its `server` feature, which the adapter does not enable.
- **"Visible ASCII" header values** admit SP (0x20), because simpay's own headers contain spaces.
- **File formats** (not fixed by the spec):
  - `K_idem`: 64 lowercase hex characters;
  - simpay key: `rk_sim_[A-Za-z0-9_]+` only, because the spec requires a restricted key;
  - DB password: 1..1024 visible ASCII;
  - each file may end in one trailing newline.
- **`idem.status` without cap `idem_status`** → `unknown_operation`. Members wrong or missing →
  `malformed_request`. Bad `refund_id` → `invalid_argument`.
- **`nodkey_payments_adapter::build`** constructs the adapter from parsed values without the file checks. The
  binary only ever calls `load`, which runs every §2 check with the real uid. Tests use `build`,
  because unprivileged test files cannot be owned by another uid.
- **`log::set_sink`** redirects log lines (tests byte-search them). The binary never calls it.
- **Residuals.**
  - The `Authorization` header value and the PostgreSQL password copy inside `tokio-postgres` are
    not zeroized.
  - `tokio-postgres` depends on `whoami`. It is unused here, because `user` is always set.

## `payments.support_refund` (Draft 4 §16)

Minimal change for Demo A: an optional `"support":{"wids":[…],"support_principals":{"<ten>":[…]}}`
configuration member (strict; tenants must be configured; no empty lists). Without it every
`payments.support_refund` grant is refused. The compiled-in declarations add `payments.support_refund`
(con3 `customer_sub`, `mandate_eligible`). A grant is verified against the `payments.refund` context for
`wid` and the `payments.support_refund` context for each `support.wids` entry; the first that verifies
wins (the crate checks the grant's own `op` and `wid`). Then: `sub` ∈ `support_principals[ten]`; con3
in the ID grammar (so `" "` fails); `cfm` 1 or 2 (+`mid`, grant-v1 W11d); the order check uses
`owner_sub = con3` (§16.3). Tests: `tests/support_refund.rs` (PT-45, PT-46, PT-47, PT-49, config
refusals). PT-48 (shared budget) is broker-side and not tested here.

## Tests

```sh
cargo test                                          # unit + integration (builds tools/simpay)
cargo test --test postgres -- --ignored             # needs Docker (postgres:17-alpine, pinned digest)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The integration tests run a **real simpay process**, built from `tools/simpay` and using TLS
certificates from its `gen-test-ca` with `--dns-name simpay.test --malicious-certs`. They also
use an in-process adapter on a socket P, a fake broker client, and scripted TLS servers for
byte-level cases. Ground truth is simpay's `/admin/ledger`.

| Suite | Covers (spec §11) |
|---|---|
| `src/*` unit | strict JSON, derivation vectors (PT-26), id patterns (PT-41), adapter rules (RX-3), classification tables (§6.2), config refusals and file/uid/socket-directory checks (PT-24, PT-32 start-up), order check, DB server peer-uid refusal before any byte (PA-16) |
| `tests/simpay.rs` | Happy path and resend (PT-26). Same grant 20× sequential and concurrent (PT-04, PT-29). Faults: `commit_then_drop` (PT-06), `commit_after_delay` (PT-07), `commit_then_500` (PT-08), `fail_before_commit` / `drop_before_commit` / `rate_limit` / `inflight_409` (PT-09), `slow_response`, `slow_drip`. Malicious: `lie_*`, `phantom_success`, `deny_but_commit` (PT-16); `redirect` with a listener seeing 0 connections (PT-17); `oversized_*`, every `header_injection` and `malformed_json` variant, `hostile_error_text` with a byte search of responses and logs (PT-18). Key outside `allowed_cidrs` (PT-13 analogue). Provider business refusals. Lookups through P; reconciliation after ambiguous creates; `in_progress` key state; lookups after `R_max` (PT-40); `late_refund_failed` (PT-23); lies on GET and list |
| `tests/tls.rs` | Foreign CA, wrong SAN, expired certificate, plain HTTP, TLS 1.2-only server, refused connect, stalled handshake → `not_sent`, ledger 0 (PT-25) |
| `tests/http_edge.rs` | `1xx` then 200; 64 vs 65 headers; non-ASCII header byte; short `Content-Length`; chunked with trailers; exact single content type; stall after head; garbage status line; close without response; number forms and depth (PT-35) |
| `tests/socket_p.rs` | Broker-compromise suite: other op, opv, read grant, other `wid`/`aud`/`iss`, `cfm = 0`, foreign or revoked key, future `iat`, older than `R_max`, transport errors, order-view mutations, DB down (PT-29, PT-40, PT-42). Malformed con2 on every op (PT-41). Accepted edges: expired-but-young, key window at `iat` (PT-42). Uniform errors. Strict framing (PT-12). One request per connection, idle timeout, connection limit. Wrong peer uid closed with an alarm (PT-24). Exact request bytes and headers; the idempotency key never in a response or log |
| `tests/process.rs` | The binary refuses to start (exit 2) on usage errors, a missing config, a config owned by the adapter uid, or a symlinked config (PT-24) |
| `tests/postgres.rs` (ignored) | Real PostgreSQL 17 through the production connector (relayed Unix socket). Row checks; wrong password → `unavailable`. The role is denied other columns, `UPDATE`, `FOR UPDATE`, `INSERT`, `CREATE`, `TEMP` and unqualified names (part of PT-31). End to end P → PG → simpay; DB gone → `unavailable` |

**Not covered here:**

- deployment properties: Docker networks, `pg_hba`, the `pg-adapter` volume, `cap_drop`, uid
  separation, and paths absent from the broker (PT-13, PT-19, PT-31 deployment part, PT-38);
- broker-side behaviour (PT-01..03, 05, 10, 11, 15, 20..22, 27, 28, 30, 32 broker part, 33, 34,
  36, 37, 39).

## Dependencies

Licenses were checked with the crates.io API (`/api/v1/crates/<name>/<version>`) on 2026-10-25,
using a generic User-Agent.

| Crate | Locked | License | Why |
|---|---|---|---|
| `nodkey-grant` | path | Apache-2.0 | Grant verification (`verify_retransmission`, `verify_binding`), transport decoding, b64url |
| `tokio` | 1.54.1 | MIT | Unix and TCP sockets, timers, signals |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | Strict config parsing (`deny_unknown_fields`) |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | JSON on socket P and provider bodies |
| `hyper` | 1.12.0 | MIT | HTTP/1.1 client with the limits §5 pins (`client`, `http1` only) |
| `hyper-util` | 0.1.21 | MIT | `TokioIo` adapter only (`tokio` feature) |
| `http-body-util` | 0.1.5 | MIT | `Full` request body, `Limited` response body |
| `rustls` | 0.23.46 | Apache-2.0 OR ISC OR MIT | TLS 1.3 client (`ring`, `std`; no `tls12` in the binary) |
| `tokio-rustls` | 0.26.6 | MIT OR Apache-2.0 | Async TLS connector |
| `rustls-pki-types` | 1.15.1 | MIT OR Apache-2.0 | PEM parsing of the pinned CA |
| `tokio-postgres` | 0.7.18 | MIT OR Apache-2.0 | `connect_raw` over the adapter's own Unix stream, no default features (already used by the broker) |
| `hmac` | 0.13.0 | MIT OR Apache-2.0 | HMAC-SHA256 for §3.3 (no custom crypto) |
| `sha2` | 0.11.1 | MIT OR Apache-2.0 | SHA-256 for HMAC |
| `zeroize` | 1.9.1 | Apache-2.0 OR MIT | Zeroizing buffers for secrets |
| `form_urlencoded` | 1.2.2 | MIT OR Apache-2.0 | Request bodies and query strings |

Dev-dependency: `rustls` with `tls12` (for the TLS 1.2-only fake server). This feature is unified
into test builds only.

Transitive crates (`cargo tree -e normal`, all checked on crates.io):

- **MIT OR Apache-2.0:** async-trait, atomic-waker, base64, bitflags, block-buffer, cfg-if,
  chacha20, cmov, const-oid, cpufeatures, crypto-common, ctutils, digest, ed25519, errno,
  fallible-iterator, futures-channel, futures-core, futures-sink, futures-task, futures-util,
  getrandom (0.2, 0.4), http, httparse, hybrid-array, itoa, libc, lock_api, log, md-5, once_cell,
  parking_lot, parking_lot_core, percent-encoding, pin-project-lite, postgres-protocol,
  postgres-types, proc-macro2, quote, rand, rand_core, scopeguard, serde_core, serde_derive,
  signal-hook-registry, signature, siphasher, smallvec, socket2, stringprep, syn,
  typenum, unicode-bidi, unicode-properties.
- **MIT:** bytes, http-body, mio, phf, phf_shared, tokio-macros, tokio-util, try-lock, want, zmij.
- **Zlib OR Apache-2.0 OR MIT:** objc2-core-foundation, objc2-system-configuration (macOS only),
  tinyvec.
- **Apache-2.0 OR BSL-1.0 OR MIT:** whoami.
- **Unlicense OR MIT:** byteorder, memchr.
- **Apache-2.0 AND ISC:** ring.
- **ISC:** rustls-webpki, untrusted.
- **BSD-3-Clause:** curve25519-dalek, ed25519-dalek, subtle.
- **(MIT OR Apache-2.0) AND Unicode-3.0:** unicode-ident, unicode-normalization.
