# nodkey-gateway

**Status:** PROTOTYPE (Phase 3). Not suitable for production. Not yet independently reviewed.

The gateway is the only public HTTP listener and is part of the TCB. It holds sessions and approval
tokens, and **no signing key**. It implements:

- [`docs/specs/effect-protocol-v2.md`](../../docs/specs/effect-protocol-v2.md) Draft 2: §4.1 (socket G
  client: `pending.render`, `pending.deny`), §4.2 (socket I client: `approve`, `read_grant`), §7
  (confirmation page contract);
- [ADR-0003](../../docs/decisions/0003-trusted-user-context-and-grant-issuance.md) Phase 3 profile items
  2 (request/response filtering), 3 (sessions, test login), and the page hardening of item 4;
- [ADR-0011](../../docs/decisions/0011-propose-confirm-execute.md) Revision 1 and Amendment 1;
- SI-18, SI-20 (**PARTIALLY MET**: session-based approval, no WebAuthn), SI-21.

## Origins

The gateway routes on `Host` only. With TLS, the SNI name must agree with `Host` (else `421`). An
unknown `Host` gets `421`. Both origins reject (before anything else): a `Service-Worker` header (any
case, any value), `Upgrade`, methods other than GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS, more than one
cookie whose name equals a gateway cookie name ignoring case, repeated `Host`/`Content-Length`, and
bodies above `limits.max_request_body`.

### App origin (`app_origin`)

Reverse proxy to the untrusted app web server (TCP or Unix socket; one request per upstream connection;
bodies buffered and bounded; timeout).

| Request to the app | Rule |
|---|---|
| Headers | Rebuilt from an allowlist: `accept`, `accept-language`, `content-type`, `origin`, `referer`, `user-agent`, `sec-fetch-{site,mode,dest,user}`, `x-requested-with`. A repeated allowlisted header → `400`. Everything else (`Authorization`, `Nodkey-*`, `X-Forwarded-*`, …) is dropped. `Host` is set to the app origin's authority |
| Cookies | Only names listed in `app_cookies` (exact). Gateway cookies are never forwarded |
| Gateway context | Only `Nodkey-Grant` (a read grant, grant-v1 §2 transport text). The client cannot forge it: no inbound `Nodkey-*` header is ever forwarded |

| Response to the browser | Rule |
|---|---|
| Headers | Allowlist: `content-type`, `content-language`, `content-disposition`, `content-encoding`, `location`, `vary`, `content-security-policy(-report-only)`, `referrer-policy`, `permissions-policy`, `retry-after`. Dropped among others: `Service-Worker-Allowed`, `Access-Control-*`, `Cache-Control`/`Expires`/`Age`, `Clear-Site-Data`, `Link`, `WWW-Authenticate`, any `Nodkey-*` |
| `Set-Cookie` | Only for a name in `app_cookies`, never a gateway-like name (contains `nodkey`, any case), and never with a `Domain` attribute (host-only, so it cannot be tossed to the auth origin) |
| Added | `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Cross-Origin-Resource-Policy: same-origin`, and a separate `Content-Security-Policy: frame-ancestors 'self'` (enforced in addition to any app policy) |
| Not forwarded | 1xx / `101` |

**Read grants** (§4.2 `read_grant`, ADR-0011 "Read operations"). For a request whose path matches a
configured `read_routes` entry (exact, or prefix ending in `/`; only plain paths: no `%`, no `.`/`..`/
empty segments), with a live **app** session, and with `Sec-Fetch-Site: same-origin` **or**
(`Sec-Fetch-Mode: navigate` **and** `Sec-Fetch-Dest: document`), the gateway asks the authority for a
read grant for `(session subject, app_wid, rop)` and attaches it as `Nodkey-Grant`. Without Fetch
Metadata no read grant is issued (fail closed). A failed request is logged and the request is
forwarded without a grant.

**Reserved paths** (never forwarded): `GET /.nodkey/login`, `GET /.nodkey/callback?code=…`,
`POST /.nodkey/logout` (same-origin provenance). Anything else under `/.nodkey` is `404`.

### Auth origin (`auth_origin`)

Every response carries the §7.4 headers (CSP `default-src 'none'; style-src 'self'; img-src 'self';
form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, COOP and CORP `same-origin`,
`X-Frame-Options: DENY`, `no-store`, `Referrer-Policy: no-referrer`, `nosniff`). Pages are
server-rendered HTML with no scripts; every dynamic value is escaped; the stylesheet is served from the
auth origin (`/static/nodkey.css`).

| Route | Behaviour |
|---|---|
| `GET /confirm/<pid>` | §7.1. Canonical 22-char id, no query (even a bare `?`), else uniform error. Without a session: the return target is stored server-side under the login state (`__Host-nodkey_preauth`) and the browser goes to `/login` (EP-13). With a session: `pending.render` with the session subject; the gateway parses the answer strictly, recomputes the §3.2 digest itself, and requires it to equal the broker's, plus `pending_id` and `(ten, approver_sub)` = session. Any failure → uniform error. `PENDING` and unexpired → page with form and a fresh token; otherwise the state without a form |
| `POST /confirm/<pid>/decision` | §7.3 checks in order: path; `Content-Type: application/x-www-form-urlencoded` exactly; fields exactly `token`, `digest` (64 lowercase hex), `decision` ∈ {approve, deny}; provenance; session; token (consumed at first presentation, then bound to session, pid, digest, expiry). Approve → `approve` on socket I; deny → `pending.deny` on socket G. Neutral "submitted" page plus the state from a fresh render |
| `GET /login`, `POST /login` | Test login only (below) |
| `GET /login/app?h=<sha256 hex>` | Start of an app-session hand-off: always requires a login ceremony on this origin (no silent re-issue) |
| `POST /logout` | Provenance as §7.3 step 2; revokes the auth session and every app session from the same login |
| anything else | Uniform error (`404`, body `This request is not available.`, byte-identical for every cause) |

**Provenance** (SI-21): if `Sec-Fetch-Site` is present it must be `same-origin` and `Sec-Fetch-Mode`
must be `navigate`; otherwise `Origin` must equal the auth origin exactly (`null` and absence are
rejected). Repeated headers are rejected.

**Approval token** (§7.2): 32 CSPRNG bytes, base64url (43 chars); stored as `token → {session id,
pending id, digest, expires = min(render + 300 s, record.expires_at)}`; a re-render invalidates the
previous token for that `(session, pending id)`.

## Sessions and login

- Cookies: `__Host-nodkey_session` (`Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=<absolute>`),
  plus the short-lived `__Host-nodkey_preauth` (auth origin) and `__Host-nodkey_login` (app origin,
  5 min). Sessions are per origin: an app session is not accepted on the auth origin and vice versa.
- Fresh id at every login (a presented old id is revoked); absolute lifetime (default 12 h, max 24 h);
  idle timeout (default 30 min); logout revokes all sessions of the login.
- **App-session hand-off** (simplified ADR-0003 §2 code flow): app `/.nodkey/login` sets a random
  state in `__Host-nodkey_login` and sends only `SHA-256(state)` to the auth origin; after the login
  ceremony the auth origin issues a single-use code (60 s) bound to that hash and the subject; the app
  callback consumes the code, requires the state cookie to hash to it, and mints a fresh app session.
  PKCE and the OIDC parts are not implemented.
- **Server-side store: in memory** (Phase 3 limitation). A restart logs everyone out and invalidates
  every rendered form (fail closed). Each map is capped (`limits.max_store_entries`); when full after
  purging expired entries, new entries are refused, never evicted.

### Test login (R3B-11)

The **only** login method. It exists only when **both**:
1. the binary is built with the Cargo feature `test-login`; and
2. the configuration sets `test_login.enabled = true` (with 1–64 configured users).

It also requires a loopback listen address. Every auth-origin HTML page then carries a visible
**TEST LOGIN** banner, and start-up logs a warning. The login form takes a user index and a per-ceremony
CSRF token bound to the login-state cookie, under the same provenance rule as §7.3.

Without the feature, the binary has no login at all: `GET /login` says so (`503`), `POST /login` is the
uniform error, and a configuration that enables the test login is refused at start-up. SI-18's
credential-entry claim is therefore **NOT TESTED** in Phase 3.

## TLS (local approach)

| `tls.mode` | Use |
|---|---|
| `files` | `cert_pem` + `key_pem` (PEM). The production path |
| `dev_self_signed` | **DEV ONLY.** A self-signed certificate for the two host names is generated with `rcgen` at every start and its PEM written to `cert_out`, so a local browser or client can be told to trust it. Loopback listen address required |
| `plain_http_loopback_insecure` | **TESTS/curl ONLY.** Plain HTTP, loopback listen address required, origins must be `http://`. The gateway still marks cookies `Secure`; browsers may refuse `Secure`/`__Host-` cookies over plain HTTP, so use `dev_self_signed` for a browser demo |

TLS uses `rustls` with the `ring` provider, safe default protocol versions, ALPN `http/1.1`. HTTP/2 is
not offered. For a local demo, `app.localhost` and `auth.localhost` resolve to loopback in current
Chrome and Firefox. They are same-site siblings (R-18): only the provenance checks separate them.

## Configuration (strict JSON; unknown members are errors)

```json
{
  "listen": "127.0.0.1:8443",
  "tls": {"mode": "dev_self_signed", "cert_out": "var/gateway-dev-cert.pem"},
  "app_origin": "https://app.localhost:8443",
  "auth_origin": "https://auth.localhost:8443",
  "upstream": {"unix": "/run/nodkey/app/nginx.sock"},
  "app_wid": "spiffe://nodkey.test/workload/shop",
  "read_routes": [{"path": "/orders/", "rop": ["payments.get_order"]}],
  "app_cookies": ["PHPSESSID"],
  "broker_socket": "/run/nodkey/gw-broker/broker.sock",
  "authority_socket": "/run/nodkey/gw-authority/authority.sock",
  "expected_broker_uid": 1002,
  "expected_authority_uid": 1003,
  "session": {"absolute_lifetime_s": 43200, "idle_timeout_s": 1800},
  "limits": {"max_request_body": 1048576, "max_response_body": 8388608, "upstream_timeout_ms": 15000,
             "ipc_timeout_ms": 5000, "approve_timeout_ms": 31000, "max_store_entries": 10000},
  "test_login": {"enabled": true, "users": [{"ten": "acme", "sub": "user:u-17", "label": "Alice"}]}
}
```

`expected_*_uid`, when set, is checked against the socket peer (`SO_PEERCRED`/`getpeereid`) before
anything is sent. Run: `nodkey-gateway --config <path>`.

## Socket formats

Framing per §1.2: one JSON object per line, ≤ 8 KiB, one request per connection, timeout. Envelope
`{"v":2,"id","op","args"}` → `{"v":2,"id","correlation_id","ok","result"|"error":{"code","message"}}`;
the response `id` must equal the request id, members are strict, maps reject duplicate keys.

| Socket | `op` | `args` | `result` | Source |
|---|---|---|---|---|
| I | `approve` | `{pending_id, digest_shown, subject:{ten,sub}}` | `{}`; error `not_available` | `crates/nodkey-authority` README (AU-1) |
| I | `read_grant` | `{subject:{ten,sub}, wid, rop:[op…]}` | `{grant}`; error `not_available` | same |
| G | `pending.render` | `{pending_id, subject:{ten,sub}}` | see below; error `not_available` | **this crate's reading (GW-1)** |
| G | `pending.deny` | `{pending_id, digest, subject:{ten,sub}}` | `{}`; error `not_available` | GW-1 |

`pending.render` result: `{"record": <the 12 §3.2 fields, as in tests/vectors/effect-v2>, "digest":
<hex>, "state": <§3.3 state>, "facts": [{"label","value"}], "context":
{"pending_from_workload_for_subject": uint, "recent_identical": [R], "other_open_on_resource": [R],
"workload_display_name": text, "approver_source": "named"|"enrolled"}}` with `R = {"pending_id",
"state", "created_at", "amount_minor"?}`. Display text is printable ASCII with length bounds.

`approve` uses its own timeout (`approve_timeout_ms`, default 31 s) because the authority may wait up to
its `approve_reply_timeout_ms` (≤ 30 s) for the broker's `accepted` (authority AU-6).

## Spec gaps (this crate's readings)

| # | Spec | Gap | Reading here |
|---|---|---|---|
| GW-1 | §4.1 | Socket G message and result shapes (facts, context) are not specified | The table above; the broker must match or the spec must fix it |
| GW-2 | §4.2 `read_grant` | How the grant is "attached to the forwarded request" | `Nodkey-Grant` header (grant-v1 §2 names this header) |
| GW-3 | §4.2, ADR-0003 §3 | Read-grant provenance without Fetch Metadata | No grant (fail closed) |
| GW-4 | §7.5 | Uniform error body format | `text/plain`, exactly `This request is not available.`, no banner |
| GW-5 | ADR-0003 §2 | Phase 3 has no IdP; how an app-origin session is established | Simplified code flow above (no PKCE/OIDC) |
| GW-6 | — | No spec tells the app who the user is | The app gets no identity header; it can read `sub`/`ten` only from the read grant it receives. Open question for the spec |
| GW-7 | ADR-0003 §2 "Logout" | Logout should write `revoked_before` through a broker socket that §1.2 does not define | Not implemented; logout revokes gateway sessions only |

## Limitations and residuals

- SI-20 is **PARTIALLY MET**: approval is session-based. A compromised gateway can approve any existing
  record as any logged-in user (spec §6).
- SI-18 credential entry: **NOT TESTED** (test login only). App-origin script can plant a gateway-named
  cookie when none exists (published session-swap residual).
- Uniform-error **timing** is not equalised (a render failure may answer faster than a success).
- In-memory sessions/tokens (above). Single process; no idle-connection reaping beyond hyper's header
  timeout; at most 1024 concurrent connections.
- No HTTP/2; no `Upgrade`; multipart and streaming bodies are buffered up to the limits.
- The gateway trusts broker-supplied facts and context only for display; they are escaped and bounded.

## Dependencies

Licenses checked on crates.io for the resolved versions (2026-10-25).

| Crate | Version | License | Why |
|---|---|---|---|
| `tokio` | 1.54 | MIT | Async runtime, TCP/Unix sockets, timeouts |
| `hyper` | 1.12 | MIT | HTTP/1.1 server and upstream client (no framework) |
| `hyper-util` | 0.1.21 | MIT | Tokio I/O and timer adapters for hyper 1 |
| `http-body-util` | 0.1.5 | MIT | `Full` bodies and size-limited body collection |
| `bytes` | 1.12 | MIT | Body buffers (hyper's type) |
| `rustls` | 0.23.46 | Apache-2.0 OR ISC OR MIT | TLS server (no OpenSSL) |
| `tokio-rustls` | 0.26.6 | MIT OR Apache-2.0 | rustls on tokio streams |
| `ring` (via rustls) | 0.17.14 | Apache-2.0 AND ISC | Crypto provider for rustls and rcgen |
| `rcgen` | 0.14.7 | MIT OR Apache-2.0 | Dev-only self-signed certificate (`dev_self_signed`) |
| `serde`, `serde_json` | 1.0 | MIT OR Apache-2.0 | Strict config and socket messages |
| `sha2` | 0.11 | MIT OR Apache-2.0 | §3.2 digest; login-state hash |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 | OS CSPRNG for ids and tokens |
| `form_urlencoded` | 1.2.2 | MIT OR Apache-2.0 | Form body decoding (strictness checks are ours) |
| `nodkey-grant` | path | Apache-2.0 | grant-v1 §6.2 parameter grammars (single definition) |

`axum` was not used: the router is a handful of exact matches, and a framework would add extractors
and middleware to the TCB. The CBOR needed for the digest (uint, bstr, tstr, map) is encoded here
(no crypto primitive is implemented).

## Tests

```sh
cargo test                        # no login compiled: app origin, uniform errors, digest vectors, TLS, no-login
cargo test --features test-login  # adds sessions, confirmation, tokens, provenance, read grants
cargo clippy --all-targets -- -D warnings && cargo clippy --all-targets --features test-login -- -D warnings
cargo fmt --check
```

Integration tests run the real gateway on `127.0.0.1:0` against a fake upstream app (hyper), a fake
broker (socket G) and a fake authority (socket I).

| File | Covers |
|---|---|
| `tests/app_origin.rs` | Header allowlist; forged `Nodkey-Grant`/`Authorization`/`X-Forwarded-*` dropped; cookie allowlist; `Set-Cookie` filter (gateway names, case variants, `Domain`); dropped response headers; `no-store`/`nosniff`/`frame-ancestors`; `Service-Worker` rejected on both origins; duplicate gateway cookies; Host routing/`421`; reserved paths; `Upgrade`/`TRACE`; body cap; no read grant without a session |
| `tests/auth_origin.rs` | Uniform error byte-identical and hardened (unknown path, bad/alias pid, T14 query and suffix); confirm without session → server-side return |
| `tests/confirm.rs` (feature) | Banner; cookie attributes; single-use login state; login CSRF/provenance; fresh id; T01/T10 identical 404s; T07 token from another session/pid, reuse, re-render; T08 digest mismatch; T37 uppercase hex; exactly one approval; T04/T05/T06/T44 provenance (app-origin fetch and form POST rejected); exact form fields; deny → broker; broker digest lie → uniform; escaping; return path and logout; app hand-off (code without state, replay); read-grant delivery and provenance; path-traversal read routes; session origin separation |
| `tests/authority_wire.rs` | Socket I messages in the authority's exact format (strict fake); refusals; `id: null` error fails closed; approve timeout vs AU-6 |
| `tests/digest_vectors.rs` | T28/T37: DG-01..DG-10 (gateway part) |
| `tests/no_login.rs` (no feature) | Login absent; config enabling it refused |
| `tests/tls_and_config.rs` | Dev self-signed TLS end to end; SNI/Host mismatch `421`; start-up refusals; wrong peer uid on socket I fails closed |

Not tested here: anything that needs the real broker (T09, T11–T13 browser framing, T15–T46 broker and
authority sides); browser behaviour (Fetch Metadata, cookie prefixes) is modelled by headers only.
