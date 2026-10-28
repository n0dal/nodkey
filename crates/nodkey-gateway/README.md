# nodkey-gateway

**Status:** PROTOTYPE (Phase 3). Not suitable for production. Reviewed in
[`docs/reviews/2026-10-25-gateway-review.md`](../../docs/reviews/2026-10-25-gateway-review.md); the fixes
are listed under "Review dispositions" and have not been re-reviewed.

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
cookie whose name equals a gateway cookie name ignoring case, a repeated `Host`, and bodies above
`limits.max_request_body`. Differing `Content-Length` values are rejected by hyper; identical
duplicates are folded, and `Transfer-Encoding: chunked` wins over `Content-Length` (RFC 9112 §6.3). The
upstream request is always rebuilt with one recomputed length on a fresh connection, so neither case
can smuggle a request to the app (tested).

**Connections and deadlines** (GW-R-03): one request per connection (no keep-alive). Headers within
10 s; body within `request_body_timeout_ms` (default 15 s, else `408`); the response must be written
within `response_write_timeout_ms` (default 10 s) once ready, else the connection is dropped.
Connections that are not yet routed (TLS handshake, headers) share `unrouted_connections` (512; when
full, new connections are closed at once). Routed connections hold a permit of their origin:
`app_connections` (768) and `auth_connections` (256) are separate budgets, so app-origin traffic cannot
starve confirmations (`503` when an origin is full). Residuals: no per-source-address limit; the
unrouted pool can still be filled by many slow handshakes; buffered memory is bounded only by
connections × body limits.

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
| Duplicates | A repeated single-valued header (`content-type`, `content-language`, `content-disposition`, `content-encoding`, `location`, `referrer-policy`, `retry-after`) → `502` (GW-R-06) |
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
| `GET /confirm/<pid>` | §7.1. Canonical 22-char id, no query (even a bare `?`), and `Sec-Fetch-Mode` absent or `navigate` (GW-R-05), else uniform error. Without a session: **no server-side state** is created; the canonical return target goes into `__Host-nodkey_return` (set only by this origin, re-validated when the login form is rendered, so only `/confirm/<canonical id>` is ever followed, EP-13) and the browser goes to `/login`. With a session: `pending.render` with the session subject; the gateway parses the answer strictly, recomputes the §3.2 digest itself, and requires it to equal the broker's, plus `pending_id` and `(ten, approver_sub)` = session. Any failure → uniform error. `PENDING` and unexpired → page with form and a fresh token; otherwise the state without a form |
| `POST /confirm/<pid>/decision` | §7.3 checks in order: path; `Content-Type: application/x-www-form-urlencoded` exactly; fields `token`, `digest` (64 lowercase hex), `decision` ∈ {approve, deny}, plus exactly one `confirm_<param>` per amount parameter (see below); provenance; session; token bound to session, pid, digest, expiry and the amount field names; for approve, at least **1.5 s** since the token was issued. Any failure here consumes the token and gives the uniform error. Approve then requires every typed amount to equal the displayed amount; a mismatch re-renders the page with a message and **keeps** the token. Then the token is consumed (one concurrent winner). Approve → `approve` on socket I; deny → `pending.deny` on socket G. Neutral "submitted" page plus the state from a fresh render |
| `GET /login`, `POST /login` | Test login only (below) |
| `GET /login/app?h=<sha256 hex>` | Start of an app-session hand-off: always requires a login ceremony on this origin (no silent re-issue) |
| `POST /logout` | Provenance as §7.3 step 2; revokes the auth session and every app session from the same login |
| anything else | Uniform error (`404`, body `This request is not available.`, byte-identical for every cause) |

**Provenance** (SI-21): if `Sec-Fetch-Site` is present it must be `same-origin` and `Sec-Fetch-Mode`
must be `navigate`; otherwise `Origin` must equal the auth origin exactly (`null` and absence are
rejected). Repeated headers are rejected.

**UI redress (GW-R-01, orchestrator ruling), no JavaScript:**
- The Deny/Approve buttons (Deny first) are hidden and receive no clicks for 1.5 s after the page
  renders (`animation: nodkey-reveal 0s 1.5s both` toggling `visibility` and `pointer-events`); the
  server independently rejects an approval that arrives less than 1.5 s after the token was issued.
- To approve, the user types each amount parameter (declared `uint`, name ending `_minor`) exactly as
  displayed: the major-unit value from display key 11 (for example `12.50`), or the raw integer when
  there is no display data. Surrounding whitespace is ignored; nothing else is normalised. Operations
  without an amount parameter have no typed field.
- **Deviation from §7.3 step 1** ("fields exactly `token`, `digest`, `decision`"): the `confirm_*`
  fields are added by this ruling. A browser T13 test (popup + timed double-click) is **NOT TESTED**;
  the full fix remains §7.6 (WebAuthn over the digest).

**Approval token** (§7.2): 32 CSPRNG bytes, base64url (43 chars); stored as `token → {session id,
pending id, digest, expires = min(render + 300 s, record.expires_at)}`; a re-render invalidates the
previous token for that `(session, pending id)`.

### Mandate pages (effect-protocol-v2 Draft 4 §12.6)

| Route | Behaviour |
|---|---|
| `GET /pending` | The session subject's `PENDING` records (`pending.list`), each linking to `/confirm/<id>` |
| `GET /mandates` | The subject's mandates (`mandate.list`); each active one has a Revoke form with a fresh single-use token bound to session, `mid` and the revoke action (5 min) |
| `POST /mandates/<mid>/revoke` | §7.3 steps 1–4 (exactly the `token` field; provenance; session; token). `mandate.revoke` to the broker (G) **first**: "Mandate revoked" only on its `{}`; a broker refusal is the uniform error; no answer → "Revocation not confirmed — retrying" and background retries every 5 s until acknowledged or the mandate's `exp`. Then the authority (I), retried likewise |

Template confirmation pages show the AI §4.2 static text (amounts via key 11; both `_minor` amounts
typed). A `messages.send` body is shown in full, escaped, in a `<pre>`, labelled "Written by the agent —
unverified". Residual: background revoke retries are in memory and stop if the gateway restarts.

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
- **Login states** (GW-R-02) are created only when the login form is rendered, at most
  `preauth_per_client` (8) per client address and `max_store_entries` in total; the oldest entry (of
  that client, then globally) is evicted, so a flood displaces login states but never blocks new ones.
  Behind a proxy every client shares one address.
- **Idle timer** (GW-R-05): refreshed only by top-level navigations with `Sec-Fetch-Site:
  same-origin|none`, so app-origin subresource requests cannot keep an auth session alive. The
  absolute lifetime remains the real bound against attacker C.
- **Server-side store: in memory** (Phase 3 limitation). A restart logs everyone out and invalidates
  every rendered form (fail closed). Each map is capped (`limits.max_store_entries`); when full after
  purging expired entries, new entries are refused, never evicted.

### Test login (R3B-11)

The **only** login method. It exists only when **both**:
1. the binary is built with the Cargo feature `test-login`; and
2. the configuration sets `test_login.enabled = true` (with 1–64 configured users).

Like every dev-only mode it also requires `dev_local_only: true`, a loopback listen address,
`localhost`/`*.localhost` host names for both origins, and no `trusted_proxies`. Every auth-origin HTML
page then carries a visible
**TEST LOGIN** banner, and start-up logs a warning. The login form takes a user index and a per-ceremony
CSRF token bound to the login-state cookie, under the same provenance rule as §7.3.

Without the feature, the binary has no login at all: `GET /login` says so (`503`), `POST /login` is the
uniform error, and a configuration that enables the test login is refused at start-up. SI-18's
credential-entry claim is therefore **NOT TESTED** in Phase 3.

## TLS (local approach)

| `tls.mode` | Use |
|---|---|
| `files` | `cert_pem` + `key_pem` (PEM). The production path, and the mode the test suite runs in (with a test certificate) |
| `dev_self_signed` | **DEV ONLY.** Needs the Cargo feature `dev-tls` **and** `dev_local_only: true`. A self-signed certificate for the two host names is generated with `rcgen` at every start and its PEM written to `cert_out`, so a local browser can be told to trust it |
| `plain_http_loopback_insecure` | **DEV ONLY.** Same gating. Plain HTTP; origins must be `http://`. Cookies stay `Secure`; browsers may refuse them over plain HTTP, so use `dev_self_signed` for a browser demo |

**Dev-mode gating (GW-R-04).** The test login and both dev TLS modes each require their build-time
feature (`test-login`, `dev-tls`; neither is a default) **and** `dev_local_only: true` **and** a loopback
listen address **and** `localhost`/`*.localhost` origins (browsers resolve these to loopback). The gateway
refuses to start otherwise, and refuses any `trusted_proxies` entry in Phase 3. **Residual:** loopback
gating cannot prove the gateway is unexposed. A same-host reverse proxy that forwards to the loopback
listener and rewrites `Host` to the configured `*.localhost` names defeats it, and would expose the
credential-less test login. Never put a proxy in front of a dev-mode gateway.

TLS uses `rustls` with the `ring` provider, safe default protocol versions, ALPN `http/1.1`. HTTP/2 is
not offered. `app.localhost` and `auth.localhost` are same-site siblings (R-18): only the provenance
checks separate them.

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
  "dev_local_only": true,
  "session": {"absolute_lifetime_s": 43200, "idle_timeout_s": 1800},
  "limits": {"max_request_body": 1048576, "max_response_body": 8388608, "upstream_timeout_ms": 15000,
             "ipc_timeout_ms": 5000, "approve_timeout_ms": 31000, "max_store_entries": 10000,
             "preauth_per_client": 8, "request_body_timeout_ms": 15000, "response_write_timeout_ms": 10000,
             "unrouted_connections": 512, "app_connections": 768, "auth_connections": 256},
  "test_login": {"enabled": true, "users": [{"ten": "acme", "sub": "user:u-17", "label": "Alice"}]}
}
```

`expected_broker_uid` and `expected_authority_uid` are **required** (GW-R-08) and checked against the
socket peer (`SO_PEERCRED`/`getpeereid`) before anything is sent. The example uses `dev_self_signed`,
so it needs `--features dev-tls,test-login`. Run: `nodkey-gateway --config <path>`.

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
- In-memory sessions/tokens (above). Single process. Connection budgets and deadlines as above.
- UI redress: the 1.5 s activation delay and the typed amount are mitigations, not a proof; no browser
  test exists (T13 NOT TESTED).
- App-origin `POST /.nodkey/logout` ends the whole login, including the auth session (availability
  only). Cookie tossing of a case-variant gateway cookie from a sibling host can make auth requests fail
  the duplicate-cookie check (denial of service; required by SI-18).
- No HTTP/2; no `Upgrade`; multipart and streaming bodies are buffered up to the limits.
- The gateway trusts broker-supplied facts and context only for display; they are escaped and bounded.

## Review dispositions (2026-10-25 gateway review)

| # | Disposition |
|---|---|
| GW-R-01 | Fixed per ruling: 1.5 s CSS activation delay + server-side check; typed amount; Deny first. Browser T13 test NOT TESTED |
| GW-R-02 | Fixed: no state for cookie-less `GET /confirm` or `/login/app` (return cookie); login states bounded per client and globally with oldest-first eviction |
| GW-R-03 | Fixed: body and write deadlines, one request per connection, unrouted and per-origin connection budgets. Per-IP limits not added (residual) |
| GW-R-04 | Fixed: `dev-tls` feature, `dev_local_only` flag, `*.localhost` names, `trusted_proxies` refused; proxy residual documented. Not adopted: `compile_error!` in release builds (local demos run release builds) |
| GW-R-05 | Fixed: idle refresh and confirm rendering only for navigations |
| GW-R-06 | Fixed: duplicate single-valued response headers → `502` |
| GW-R-07 | README corrected; TE+CL behaviour tested (no smuggling). Not rejected explicitly: hyper drops `Content-Length` before the gateway sees it |
| GW-R-08 | Fixed: both uids required |
| GW-R-09 | Fixed: `white-space: pre-wrap` on values; raw minor units labelled. Leading/trailing-space markers not added (no Phase 3 text parameters) |
| GW-R-10 | Documented as residuals |

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
| `rcgen` | 0.14.7 | MIT OR Apache-2.0 | Optional (`dev-tls`): dev self-signed certificate. Also a dev-dependency (test certificate) |
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
cargo test                                   # no login, no dev TLS compiled in
cargo test --features test-login             # adds sessions, confirmation, tokens, provenance, read grants
cargo test --features dev-tls                # adds dev self-signed TLS end to end
cargo test --features test-login,dev-tls
cargo clippy --all-targets [--features …] -- -D warnings
cargo fmt --check
```

Integration tests run the real gateway on `127.0.0.1:0` over TLS (`files` mode, a test certificate
generated once per test process) against a fake upstream app (hyper), a fake
broker (socket G) and a fake authority (socket I).

| File | Covers |
|---|---|
| `tests/app_origin.rs` | GW-R-03 body deadline (`408`), write deadline (non-reading client cut off), app-origin flood cannot starve the auth origin; GW-R-06 duplicate `Content-Type` → `502`; GW-R-07 TE+CL not smuggled; header allowlist; forged `Nodkey-Grant`/`Authorization`/`X-Forwarded-*` dropped; cookie allowlist; `Set-Cookie` filter (gateway names, case variants, `Domain`); dropped response headers; `no-store`/`nosniff`/`frame-ancestors`; `Service-Worker` rejected on both origins; duplicate gateway cookies; Host routing/`421`; reserved paths; `Upgrade`/`TRACE`; body cap; no read grant without a session |
| `tests/auth_origin.rs` | Uniform error byte-identical and hardened (unknown path, bad/alias pid, T14 query and suffix); confirm without session → server-side return |
| `tests/confirm.rs` (feature) | GW-R-01 delayed controls, early approve rejected (token consumed), wrong typed amounts re-render with the token kept, missing field rejected, correct amount accepted; GW-R-02 flood of cookie-less `/confirm` and of `/login` with a 16-entry store cannot block login; GW-R-05 app-origin no-cors render cannot reset the token; banner; cookie attributes; single-use login state; login CSRF/provenance; fresh id; T01/T10 identical 404s; T07 token from another session/pid, reuse, re-render; T08 digest mismatch; T37 uppercase hex; exactly one approval; T04/T05/T06/T44 provenance (app-origin fetch and form POST rejected); exact form fields; deny → broker; broker digest lie → uniform; escaping; return path and logout; app hand-off (code without state, replay); read-grant delivery and provenance; path-traversal read routes; session origin separation |
| `tests/authority_wire.rs` | Socket I messages in the authority's exact format (strict fake); refusals; `id: null` error fails closed; approve timeout vs AU-6 |
| `tests/digest_vectors.rs` | T28/T37: DG-01..DG-10 (gateway part) |
| `tests/no_login.rs` (no feature) | Login absent; config enabling it refused |
| `tests/tls_and_config.rs` | TLS; SNI/Host mismatch `421`; start-up refusals; GW-R-04 gating of dev TLS (feature, flag, loopback, `*.localhost`) and test login; `trusted_proxies` refused; dev self-signed end to end (`dev-tls`); wrong peer uid fails closed |

Not tested here: anything that needs the real broker (T09, T11–T13 browser framing, T15–T46 broker and
authority sides); browser behaviour (Fetch Metadata, cookie prefixes) is modelled by headers only.
