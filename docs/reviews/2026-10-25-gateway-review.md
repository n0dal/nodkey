# Review: `crates/nodkey-gateway` (commit a839187)

- **Date:** 2026-10-25
- **Scope:** `crates/nodkey-gateway/` (all of `src/`, `static/`, `tests/`, `README.md`, `Cargo.toml`).
- **Contract checked:** `docs/specs/effect-protocol-v2.md` Draft 2 §1.2, §3.2, §4.1, §4.2, §7; ADR-0003
  Phase 3 profile items 2, 3, 5, 6, 8 (plus item 4 page hardening); ADR-0011 Revision 1 and Amendment 1;
  SECURITY_INVARIANTS v0.4 SI-18, SI-20, SI-21; earlier findings R3-01, R3-02, R3-06, R3-07, R3-11
  (`2026-10-25-adr-0003-0009-review.md`) and PC-02..PC-05 (`2026-10-25-adr-0011-review.md`).
- **Attackers:** C (controls every upstream app response and all script on the app origin) and A
  (unauthenticated, external).
- **Method:** I read the source and ran the crate's tests. I then wrote probe tests in a scratch crate
  outside the repository. They reuse the crate's own harness (`tests/common/mod.rs`), with the real
  gateway on 127.0.0.1, a fake upstream, a fake broker and a fake authority. I did not run Docker or a
  browser. Results that depend on browser behaviour are marked **[H]** (hypothesis, not reproduced here).

## Summary

| # | Severity | Title | Blocks |
|---|---|---|---|
| GW-R-01 | **High** [H] | Approval can be click-hijacked from an app-opened popup (double-click redress). No frame is needed, so `frame-ancestors`/COOP do not help | **Yes** (cheap fix; T13 "opened from the app origin" is untested) |
| GW-R-02 | Medium | 10 000 unauthenticated requests fill the login-state store and block **every** login for 10 min (reproduced) | No (yes before any non-local exposure) |
| GW-R-03 | Medium | Connection exhaustion: no body/write deadline, one 1024-slot pool for both origins (reproduced) | No (yes before any non-local exposure) |
| GW-R-04 | Medium | Test login and dev TLS modes are gated only by a loopback *listen* address, which does not prove the gateway is unexposed | No |
| GW-R-05 | Low | App-origin script keeps the auth session alive (the idle timeout is ineffective against C) and can reset the user's approval token | No |
| GW-R-06 | Low | Duplicate `Content-Type` (and other single-valued headers) from the app are forwarded; R3-06 asked for collapse or reject (reproduced) | No |
| GW-R-07 | Low | The README claims a repeated `Content-Length` is rejected; identical duplicates are accepted (no smuggling results; reproduced) | No |
| GW-R-08 | Low | Gateway-side peer-uid checks on sockets G/I are optional and off by default | No |
| GW-R-09 | Low | Display robustness: whitespace collapses in text values; an `*_minor` amount without display data is shown as a bare integer | No |
| GW-R-10 | Info | Uniform-error timing; app-origin logout ends the auth session; cookie-tossing denial of service | No |

No finding gives C or A a write grant without a matching approval by the intended approver, or lets
either one forge `Nodkey-*` context, plant a gateway cookie through a response, or approve from the app
origin. The approval core (§7.2/§7.3) matches the spec. The most serious gap, GW-R-01, is UI redress
against the approving user.

---

## Findings

### GW-R-01 — Approval click-hijacking from an app-opened popup (High, [H])

- **Where:** `src/html.rs:195-216` (the decision form: Approve is the first button, at a fixed position,
  clickable from the first paint); `static/nodkey.css:24-27`; spec §7.4 (the only anti-redress controls
  are `frame-ancestors 'none'`, XFO and COOP).
- **Scenario (attacker C, `enrolled` or `named` workload):**
  1. C proposes `ledger.transfer{from: victim, to: attacker, amount_minor: N}`. The victim is the
     intended approver.
  2. The victim is signed in on the auth origin (sessions live up to 12 h; GW-R-05 keeps them alive).
  3. An app page asks for a double-click ("double-click to continue"). On the first `mousedown`, script
     runs `window.open('https://auth…/confirm/<pid>', '', 'left=X,top=Y,width=W,height=H')`. C knows
     the page content (it chose the parameters), so it can place the popup with the Approve button
     under the cursor.
  4. The second click lands on Approve in a top-level, same-origin auth document. The request then
     carries `Sec-Fetch-Site: same-origin`, `Sec-Fetch-Mode: navigate`, the valid token and the digest,
     so every §7.3 check passes. SI-20 records an "approval" the user never read.
- **Why the existing controls do not stop it:**
  - `frame-ancestors 'none'`/XFO only stop framing.
  - COOP only cuts the opener reference. The popup still opens and takes the click.
  - A URL fragment (`#…`, including a text fragment) is not sent to the server, so the "no query"
    rule does not limit client-side scrolling either.
- **Background:** This is the publicly described "double-clickjacking" class (window-swap on the second
  click of a double-click; public research, December 2024). **I did not reproduce it in a browser.**
  Spec test T13 lists "opened from the app origin", and the README marks it as not tested.
- **Fix (no script needed, keeps the CSP):**
  - Keep the decision buttons unclickable for about 1 s after the page renders. For example, give them
    `visibility:hidden` with a CSS animation that makes them visible after a delay
    (`animation: reveal 0s 1s both`). Hidden elements receive no clicks.
  - Add a required checkbox, away from the buttons, that the user must tick ("I checked the amount and
    the destination").
  - Put Deny first, or vary the layout.
  - Add a browser test for T13 (popup plus timed click).
  - The full fix is §7.6: a WebAuthn user-verification assertion over the digest.
- **Blocks:** Yes. The fix is cheap, and it should land before SI-20 is reported even as PARTIALLY MET
  with T13.

### GW-R-02 — Unauthenticated exhaustion of the login-state store (Medium, reproduced)

- **Where:**
  - `src/auth.rs:377-388`: `GET /confirm/<pid>` without a session creates a preauth for **any**
    canonical pid, with no lookup.
  - `src/auth.rs:99-117`: `GET /login/app?h=` creates a preauth.
  - `src/auth.rs:157`: `GET /login` creates a preauth.
  - `src/store.rs:121-129, 241-258`: one cap (`max_store_entries`, default 10 000) and a 600 s TTL. When
    the store is full, new entries are refused, never evicted.
- **Reproduction:** probe `p1_preauth_exhaustion_blocks_login`. 64 tasks sent 10 000 cookie-less
  requests to `GET /confirm/<random canonical pid>` on the auth origin.
  ```
  P1 10k unauthenticated GET /confirm in 297.987375ms
  P1 GET /login after flood: status 404 body "This request is not available."
  P1 GET /confirm (no session) after flood: status 404
  ```
  Nobody can log in for 10 minutes, and the attacker can repeat this indefinitely. With no auth
  session, no effect can be approved. A needs nothing but network access.
- **Fix:**
  - Do not allocate server-side state for an unauthenticated GET. The return target is a canonical pid
    and not secret, so it can live in the `__Host-` preauth cookie and be re-validated when used.
    Create the preauth (CSRF) entry only when the login form is rendered.
  - Evict the oldest preauth entries; losing one only costs a fresh login.
  - Add per-client rate limits.
- **Blocks:** No for a local demo; yes before any non-loopback exposure.

### GW-R-03 — Connection and memory exhaustion (Medium, reproduced)

- **Where:**
  - `src/server.rs:23-25, 143-169`: one global `Semaphore(1024)` shared by the app and auth origins. The
    permit is acquired *before* `accept`.
  - `src/server.rs:182-187`: only `header_read_timeout(10 s)`.
  - `src/server.rs:311-321`: the body is collected with no deadline.
  - `src/app.rs:254-277`: the upstream may hold every request for 15 s and return up to 8 MiB.
- **Reproduction** (probes `p2`, `p3`):
  ```
  P2a after 25 s stalled body: Ok(Ok("HTTP/1.1 200 OK…"))      # a body stalled for 25 s is still accepted
  P2b after 25 s idle: write true read Ok(Ok(""))                # idle keep-alive IS closed (header timeout works)
  P3 auth-origin GET with 1030 stalled uploads held for 12 s: TIMEOUT (no answer in 10 s)
  ```
  1 030 connections, each holding a partial `POST` body, make the auth origin (confirmations, login)
  unreachable for as long as they are held.
- **Other paths:**
  - There is no response-write timeout, so a client that never reads holds its slot.
  - C can make every app response take 15 s, or answer 8 MiB per request: up to 1 024 × (1 MiB request
    + 8 MiB response) buffered.
  - Because sessions are in memory, an out-of-memory crash also logs everyone out.
- **Fix:**
  - Add a whole-request deadline (headers plus body) and a response-write deadline.
  - Cap connections per source address.
  - Give the auth origin its own connection budget (or its own listener), so app traffic cannot starve
    confirmations.
  - Bound total buffered bytes.
  - Note this residual in the README.
- **Blocks:** No for a local demo; yes before any non-loopback exposure.

### GW-R-04 — Dev-only modes are gated by a loopback listen address only (Medium)

- **Where:** `src/config.rs:190-196` (`dev_self_signed`, `plain_http_loopback_insecure`) and
  `src/config.rs:233-256` (test login: feature, then `enabled`, then loopback).
- **What holds:**
  - Without the `test-login` feature, no login path exists. `POST /login` returns the uniform error,
    and `/.nodkey/callback` can only consume codes that `login_submit` (feature-only) creates.
  - A configuration that enables the test login is refused at start-up. `tests/no_login.rs` passes.
  - Plain HTTP and dev TLS on a non-loopback listen address are refused.
- **Gap:**
  - "Listens on 127.0.0.1" does not mean "not exposed". A same-host TLS-terminating reverse proxy or
    load-balancer sidecar forwarding to `127.0.0.1:8443` is a normal production layout. The gateway
    then serves a credential-less login (any configured user) to the Internet, and every check passes.
  - Builds with `--all-features` (packaging, CI) compile the feature in. The config flag is then the
    only remaining switch.
  - The owner directive requires dev bypasses to be "impossible to enable accidentally in production".
- **Fix:**
  - When the test login or a dev TLS mode is active, require both origins' hosts to be `localhost` or
    end in `.localhost`. Browsers resolve these names to loopback, so a remote user's browser cannot
    reach such a gateway through a proxy.
  - Refuse `test-login` in release builds (`compile_error!` under `not(debug_assertions)`), or build it
    as a differently named binary.
  - Also show the TEST LOGIN banner on app-origin pages served through `/.nodkey/`.
- **Blocks:** No.

### GW-R-05 — App script keeps the auth session alive and can reset tokens (Low)

- **Where:** `src/auth.rs:48-54` together with `src/store.rs:157-176`. Every auth-origin request that
  carries the session refreshes `last_seen`. The confirm handler `src/auth.rs:392-399` mints a token for
  each render, and a re-render invalidates the previous one.
- **Scenario:**
  - App and auth are same-site, so `SameSite=Lax` cookies go with same-site subresource requests. App
    script running `fetch('https://auth…/', {credentials:'include', mode:'no-cors'})` every few minutes
    keeps the auth session alive up to the absolute lifetime. The 30-minute idle timeout is therefore
    no bound against C, and it widens GW-R-01's window. The response stays opaque (CORP), so nothing
    leaks.
  - The same request to `/confirm/<pid>` re-renders the page and silently invalidates the token in the
    form the user has open (approval denial of service; C can only target its own proposals).
- **Fix:**
  - Refresh `last_seen`, and mint tokens, only for `Sec-Fetch-Site: same-origin|none` with
    `Sec-Fetch-Mode: navigate` (no Fetch Metadata: do not refresh).
  - Document the absolute lifetime as the real bound.
- **Blocks:** No.

### GW-R-06 — Duplicate single-valued response headers forwarded (Low, reproduced)

- **Where:** `src/app.rs:283-288`. Every value of every allowlisted header is appended.
- **Reproduction:** the upstream `/dupct` answers with two `Content-Type` headers.
  `P4 dup content-type from app forwarded: ["text/html", "text/plain"]`.
- **Impact:** R3-06 asked to "collapse or reject duplicate `Content-Type`". With `nosniff` set, the
  impact is limited to browser-specific MIME choice on C's own origin. Duplicate `Location`,
  `Content-Disposition` and `Content-Encoding` are forwarded the same way.
- **Fix:** For single-valued headers, forward at most one value, and return 502 on duplicates.
- **Blocks:** No.

### GW-R-07 — README over-claims rejection of a repeated `Content-Length` (Low, reproduced)

- **Where:** `README.md` ("repeated `Host`/`Content-Length`"); `src/server.rs:298-300`.
- **Reproduction** (probes `p4`, `p6`):
  - A repeated `Host` is rejected (400).
  - A differing duplicate `Content-Length`, and `Content-Length: 5, 5`, are rejected (400).
  - An **identical** duplicate `Content-Length` is accepted (200); hyper folds it.
  - `Transfer-Encoding: chunked` together with `Content-Length` is accepted and decoded as chunked.
- **What the upstream saw:** a single recomputed `content-length: 5`, no `transfer-encoding`, body
  `hello`. This is a rebuilt request on a fresh connection per request, so **no request smuggling** to
  the app was possible in any case tried. Pipelined requests to different hosts were each routed by
  their own `Host`.
- **Fix:** Correct the README (SI-17), or reject TE+CL and duplicate CL explicitly.
- **Blocks:** No.

### GW-R-08 — Gateway-side peer-uid checks are optional (Low)

- **Where:** `src/config.rs:34-38` (`expected_broker_uid`, `expected_authority_uid` default `None`);
  `src/ipc.rs:110-117`.
- **Impact:** Spec §1.2 puts the uid check on the listener side, and the authority recomputes every
  digest, so a spoofed broker or authority socket cannot by itself produce a grant. It could still
  feed the confirmation page false values or facts (the approval would then fail at the authority),
  and it would receive approvals and read-grant requests.
- **Fix:** Make both settings mandatory except with the loopback dev TLS modes.
- **Blocks:** No.

### GW-R-09 — Display robustness (Low)

- **Where:** `src/html.rs:123-142`; `static/nodkey.css:18-19`.
- **Escaping and character set:** `esc` covers `& < > " '`, and every displayed value is checked for
  ASCII first:
  - IDs: 0x21–0x7E;
  - text grammars, display text, facts and the workload name: 0x20–0x7E;
  - `account_id`: `[a-z0-9_]`.

  So bidi controls and non-ASCII homoglyphs cannot reach the page. ASCII confusables (`l`/`1`, `o`/`0`)
  remain. A monospace font and the "not owned by you" fact for `to` mitigate them.
- **Problem (a), whitespace:** `.value` has no `white-space: pre-wrap`. A `text64`/`text256` value with
  doubled, leading or trailing spaces therefore looks identical to a different value. No Phase 3
  operation has a text parameter, and ADR-0011 Rev. 1 item 8 excludes free text in Phase 3.
- **Problem (b), unlabelled amounts:** if a `*_minor` uint has no `amount_exponent`/`currency` display
  data, it is shown as a bare integer (`html.rs:130`), with no "minor units" label. `related_list` does
  label it. A user could read `1250` as 1 250 currency units.
- **Fix:**
  - Use `white-space: pre-wrap` plus visible markers for leading and trailing spaces.
  - Label raw minor units, or treat a missing display entry for a `*_minor` parameter as a render
    failure.
- **Blocks:** No.

### GW-R-10 — Informational

- **Timing:** the uniform error's timing is not equalised (already documented). A cookie-less
  `/confirm/<canonical pid>` answers 303 whatever the pid, so it reveals nothing.
- **Logout:** an app-origin `POST /.nodkey/logout` (app-origin script passes the same-origin check)
  revokes the whole login, including the auth session. C can sign users out (availability only).
- **Cookie tossing:** C can toss a case-variant gateway cookie with `Domain=<parent>` in browsers that
  match `__Host-` case-sensitively. This turns the victim's auth requests into duplicate-cookie
  rejections (denial of service). The behaviour is required by SI-18; list it as a residual.

---

## Checked and holding

The facts in this section come from code reading plus the probes and crate tests quoted below.

- **Host routing and parsing:**
  - The gateway routes on `Host` only and lowercases it.
  - The absolute-form authority must equal `Host`: `GET http://auth.localhost/` with `Host: app` → 400.
  - A trailing-dot host, a wrong port and `CONNECT` all → 421.
  - `OPTIONS *` → 400, HTTP/1.0 without `Host` → 400.
  - `Upgrade: h2c` → 400, obs-fold → 400 (httparse).
  - With TLS, SNI must match `Host` (tested in `tls_and_config.rs`). No HTTP/2, so no connection
    coalescing (R3-02.5).
- **Service workers (SI-18):** a `Service-Worker` header is rejected by presence, in any case, on both
  origins. `Service-Worker-Allowed` is dropped.
- **Request rebuilding:** requests to the app are rebuilt from an allowlist. Any repeated allowlisted
  header → 400. `Authorization`, `X-Forwarded-*` and every `Nodkey-*` are dropped, so `Nodkey-Grant`
  can only come from the gateway. Gateway cookies are never forwarded. App cookies are forwarded only by
  exact allowlisted name.
- **Response filtering:**
  - Responses are rebuilt from an allowlist. Any `Nodkey-*`, `Cache-Control`/`Expires`/`Age`,
    `Clear-Site-Data`, `Link` and `Access-Control-*` header is dropped.
  - `no-store`, `nosniff`, XFO and CORP are always set, plus a separate `frame-ancestors 'self'` policy.
  - 1xx/101 → 502.
  - `Set-Cookie` passes only for an allowlisted name that does not contain "nodkey" and has no
    `Domain` attribute. Nameless and no-`=` forms are rejected. This fixes R3-07's response-side
    finding.
- **Duplicate gateway cookies:** two instances of one gateway name in any case → reject. A single
  case-variant instance is ignored.
- **Approval provenance:** the code is exactly §7.3 step 2:
  - if `Sec-Fetch-Site` is present, it must be `same-origin` and `Sec-Fetch-Mode` must be `navigate`;
  - otherwise `Origin` must equal the auth origin exactly;
  - `null` is rejected, a missing `Origin` is rejected, and repeated headers are rejected.

  App-origin fetch and form POSTs are rejected (tests T04–T06, T44).
- **Token:** 32 CSPRNG bytes. It is consumed under the store mutex at its first presentation, so
  concurrent presentations give one winner. It is bound to the session id, the pid bytes and the digest,
  and it expires at `min(render + 300 s, record.expires_at)`. A re-render invalidates the previous token.
  Logout and expiry purge tokens.
- **Digest:** the gateway recomputes it from the strictly parsed render, under the declared-type rules
  and the canonical pid, and compares it to the broker's in constant time. It also requires the pid to
  equal the path and `(ten, approver_sub)` to equal the session. The page renders `checked.rec`, the
  same object that was hashed. The approve call sends the token-bound digest.
- **Uniform error:** byte-identical across causes on the auth origin, with the §7.4 headers on every
  auth-origin response.
- **Sessions:** `__Host-`, `Secure`, `HttpOnly`, `Lax`. A fresh id at every login, with the presented id
  revoked. Absolute and idle lifetimes are enforced server-side. App and auth sessions are not
  interchangeable. Logout revokes the login.
- **App hand-off:** the code is single-use, lasts 60 s, and is bound to `SHA-256(state)` held in a
  host-only `__Host-` cookie on the app origin. The code is consumed before the state is checked, so it
  cannot be retried. The return target is server-side and canonical-only (EP-13). This closes R3-02.1
  for A. C's session swap remains a published residual.
- **TLS:** rustls with safe defaults and ALPN `http/1.1`. Plain HTTP is impossible on a non-loopback
  listen address (but see GW-R-04).

## Tests run

The crate, at commit a839187:
```
cargo test                          → all suites "test result: ok" (12+8+3+4+2+2+3 unit/integration tests, 0 failed)
cargo test --features test-login    → all suites "test result: ok" (adds confirm.rs: 10 passed; authority_wire 4 passed), 0 failed
```

The probes are in a scratch crate outside the repository. They use the crate's own harness. The
outputs are quoted in the findings.
- `p1_preauth_exhaustion_blocks_login` (GW-R-02);
- `p2_body_never_completes_and_idle_keepalive` and `p3_connection_exhaustion` (GW-R-03), run with
  `ulimit -n 10240`;
- `p4_parsing`, `p5_pipeline` and `p6` (GW-R-06, GW-R-07, and the "checked" list).

The probes are not committed. GW-R-02, GW-R-03, GW-R-06 and GW-R-07 should become regression tests in
the crate.

**Not tested:**
- any browser behaviour: GW-R-01; Fetch Metadata and cookie-prefix behaviour (the crate's tests model
  them with headers only); T13;
- anything that needs the real broker or authority.

## Verdict

**Accept with changes.**

- **What holds:** I found no authority bypass. Write grants still need an auth-origin, same-origin,
  token-bound approval by the session subject, with a digest the gateway recomputed. The authority checks
  that approval again independently. Header and cookie filtering, request rebuilding and test-login
  compilation gating are sound against C and A for the cases tried.
- **Before the Phase 3 milestone:** **GW-R-01 (High)** must be fixed (CSS activation delay and a
  required confirmation checkbox) and tested with a browser T13 case. Until then, report SI-20 as
  **PARTIALLY MET with an open UI-redress gap**.
- **Before any non-loopback or shared deployment:** fix GW-R-02 and GW-R-03, the two reproduced
  unauthenticated availability failures of the only public listener, and GW-R-04.
