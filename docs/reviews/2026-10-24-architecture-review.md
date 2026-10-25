# Architecture Review — ADR-0001…0008, Threat Model, Architecture (DRAFT v0.1)

> Historical review record. "PBE" refers to the project now named **Nodkey**.

- **Date:** 2026-10-24
- **Type:** Independent adversarial design review (fresh context; reviewer did not author the design)
- **Scope:** `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`,
  `docs/decisions/0001`–`0008`; supporting: `docs/research/02`, `03`, `04`.
- **Method:** Paper review only. **Nothing was executed; no finding below is a test result.** Every
  attack is a design-level scenario. Facts are marked **[F]** (established, primary source named),
  **[F\*]** (established from memory of a primary source, not re-fetched in this review; verify before
  relying on it), **[H]** (reviewer hypothesis to be confirmed by a spike or test).
- **Severity scale:** *Critical*: under the documented profile, attacker C (or A/B) gains authority the
  security goal (THREAT_MODEL §1) says it must not, with no stated residual covering it. *High*: a stated
  bound or invariant does not hold as designed, or the residual is materially larger than published.
  *Medium*: an undesigned or inconsistent mechanism that will produce a bypass or false claim if built
  as written. *Low/Info*: hardening, wording, simplification.

## Summary

| ID | Sev | Title | Affects | Blocks |
|---|---|---|---|---|
| AR-01 | **Critical** | Shared origin lets the compromised app capture user credentials at login | ADR-0003, SI-02, TM §1 | Phase 3 |
| AR-02 | **High** | Browser-side persistence (service worker, HTTP cache) outlives the compromise; R-3 understated | ADR-0003, TM R-3 | Phase 3 |
| AR-03 | **High** | nginx parses app output *and* holds every user's session credential; ADR-0001 objection 1 is necessary but not sufficient | ADR-0001, ADR-0003, TB-2, SI-02 | Phase 3 (topology decision before Phase 2 Compose is frozen) |
| AR-04 | **High** | Ceilings and unbound parameters violate "full binding"; agree with ADR-0003 objection 1 and extend it | ADR-0003, ADR-0004, SI-06, SI-07 | Phase 3 |
| AR-05 | **High** | Budgets (the stated bound for R-2/R-3) are subject to write skew under "row-locked" mode | ADR-0005, ADR-0006, SI-11 | Phase 4 |
| AR-06 | **High** | Workload-only operations and background workflow steps are an undesigned, grantless path | ADR-0002, ADR-0003, ADR-0007, SI-05, SI-10, SI-12 | Phase 3 (design) / Phase 5 |
| AR-07 | Medium | nginx ↔ authority subrequest: body visibility and response association unspecified | ADR-0003, R-8 | Phase 3 |
| AR-08 | Medium | `rqh` cannot be verified by the broker (agree with ADR-0003 objection 2) | ADR-0003, ADR-0004, SI-06 | Phase 3 |
| AR-09 | Medium | Epoch revocation needs state the stateless authority does not have; logout does not revoke; TTL 300 s | ADR-0004, ADR-0006, SI-08 | Phase 3 |
| AR-10 | Medium | "Refuse re-issue after UNKNOWN" is placed in the authority, which cannot see UNKNOWN | ADR-0006, SI-15 | Phase with first external effect |
| AR-11 | Medium | Denied attempts roll back consumption; grants are retryable and probe-able | ADR-0006, SI-09 | Phase 3 |
| AR-12 | Medium | Shared rw `fcgi` volume and container logs: writable+exec+persistent path and TCB-wide disk exhaustion | ADR-0001, P0, R-14 | **Phase 2** |
| AR-13 | Medium | Multi-effect requests / multiple grants per route unspecified | ADR-0003, ADR-0007 | Phase 3 |
| AR-14 | Medium | No comparison against the simplest alternative (PostgREST RPC-only + RLS); OQ-01 open | ADR-0001, ADR-0002, ADR-0004 | Before accepting ADRs |
| AR-15 | Low | nginx response-header filtering incomplete (Set-Cookie, other X-Accel-*, error interception) | TB-2 | Phase 2 |
| AR-16 | Low | SI-02 as worded is violated by design (grants are bearer credentials in the workload); response channel is an exfiltration path | SI-02, TM §1, TM row A | Phase 3 (wording) |
| AR-17 | Low | Broker `sub`/`ten` "checks" are circular; research 02 §4.2 rules describe checks that cannot occur | ADR-0004, SI-06 | Phase 3 |
| AR-18 | Low | Clock high-water mark and restore procedure still open; SI-09 cannot be claimed | ADR-0006, R-12 | Phase 3 claim |
| AR-19 | Low | Signed receipts add a key and a format with no v0 consumer; audit must be read from the broker DB, not container logs | ADR-0007, SI-12 | Phase 5 |
| AR-20 | Info | Points examined that hold under the design | — | — |

---

## Findings

### AR-01 — Shared origin lets the compromised app capture user credentials at login (Critical)

- **Affected:** ADR-0003 decision 1; SI-02 (intent); THREAT_MODEL §1 and §3 ("User session
  credentials … Gateway only").
- **Scenario (attacker C, then A at scale):**
  1. The design has one public origin: nginx serves both the app's pages (FastCGI) and whatever login
     flow establishes the session the authority later "verifies in its session store". The login flow
     itself is not specified anywhere.
  2. If login is handled by the PHP app (the default for every legacy PHP app), the compromised app
     receives every password in cleartext. Done.
  3. If login is rendered by the authority on the **same origin**, the app still wins: (a) app script on
     any page opens `/login` in a same-origin iframe and reads the password field from the DOM
     (same-origin policy grants full DOM access) [F\*: HTML/DOM same-origin rules]; (b) the app registers
     a service worker with scope `/` that intercepts the navigation to `/login` and returns a look-alike
     form (see AR-02); (c) the app simply links to its own fake login page (UI deception, R-4, but
     indistinguishable to the user because it is the same origin and URL bar).
  4. With passwords (or a same-origin `navigator.credentials.get()` call for the origin's RP ID, which
     still needs a user gesture), the attacker logs in from its own browser at any time, for any route,
     indefinitely.
- **Why the design does not stop it:** The design removes the *session cookie* from the app's view but
  never removes the *credential that creates sessions*. R-3 assumes the attacker's reach ends with the
  user's open pages; with captured credentials it is P(u) for every user who logs in, forever, without
  per-request grants mattering at all. No residual in §6 covers this.
- **Fix:** (1) Make it an invariant (or a P0/P1 profile requirement) that **credential entry and
  session establishment happen on an origin the app cannot serve content on** (separate host, e.g. an
  OIDC IdP or `auth.<domain>`, with the session cookie scoped to the app host only as an opaque handle
  the authority validates). (2) Session cookie `__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax|Strict`.
  (3) Route-map lint: no app-served route may accept a field named like a credential. (4) State in
  ARCHITECTURE §6 that a legacy app that keeps its own login form is **not** in Native mode.
- **Blocks:** Phase 3 (no grant demo is meaningful while credentials are capturable).

### AR-02 — Browser-side persistence outlives the compromise; R-3 understated (High)

- **Affected:** THREAT_MODEL R-3 ("for as long as a page is open"), ADR-0003 residual section.
- **Scenario (C):**
  1. Compromised app serves `/sw.js` with `Content-Type: text/javascript` and injects
     `navigator.serviceWorker.register('/sw.js', {scope: '/'})`.
  2. The service worker persists in every visiting browser after the app is patched and redeployed.
     On each later visit it intercepts requests, injects script, and issues real requests to mapped
     routes with the user's session (gateway issues grants as normal) [F\*: Service Workers spec;
     registration persists until unregistered or site data cleared].
  3. Alternatively, the app serves its main JS bundle with `Cache-Control: max-age=31536000,
     immutable`; the malicious bundle is served from the browser cache for a year [F\*: RFC 9111,
     RFC 8246].
- **Why not stopped:** TB-2 filters only `X-Accel-Redirect`; nginx passes every other response header
  and body. R-3's time bound is false; remediation of the app does not end the attack.
- **Fix:** Gateway (not app) policy, all enforceable at the trusted front without parsing HTML:
  reject requests carrying `Service-Worker: script` unless the path is allowlisted in the route map
  [F\*: browsers send this request header on SW script fetches — verify]; strip/override
  `Cache-Control`/`Expires` on app responses for script and HTML types; enforce a gateway-added CSP
  (multiple CSP policies are all enforced, so the app cannot loosen a gateway policy [F\*: CSP3
  §"multiple policies"]) with hash/nonce-pinned `script-src` from a deploy-time manifest; document a
  remediation runbook using `Clear-Site-Data: "cache", "storage"` [F\*: W3C Clear Site Data]. Rewrite
  R-3 to say the bound is P(u) ∩ budgets for every user whose browser loads the origin, **until
  browser-side state is cleared**, not "while a page is open".
- **Blocks:** Phase 3.

### AR-03 — nginx parses app output and holds every session credential (High)

- **Affected:** ADR-0001 (TCB list; objection 1), ADR-0003 decision 1, TB-1/TB-2, THREAT_MODEL row J
  and §3 asset "User session credentials".
- **Scenario (C → nginx):**
  1. nginx parses FastCGI records, response headers, and bodies produced by attacker C (TB-2).
  2. Any memory-safety or logic bug in that path (nginx is C; its FastCGI/HTTP parsers have had
     CVEs historically [F\*]) gives C code execution in nginx, which is **in the TCB and declared out of
     scope as J** — yet the attacker reaching it is C, which is in scope.
  3. nginx sees every inbound request **before** the session credential is stripped. A compromised
     nginx collects live session cookies of all users and replays them to the authority (reachable from
     nginx by design) to obtain grants for any route, any number of times, until session expiry. This
     is exactly option (a) that ADR-0003 rejected.
- **On ADR-0001 objection 1:** Correct and should be adopted (a signer co-resident with nginx would turn
  this into offline minting). But the objection's claim that nginx compromise "yields only the sessions
  and grants of requests in flight" understates the result: sessions are reusable bearer credentials,
  not in-flight artefacts.
- **Also:** "strips the session credential" is specified as a removal (denylist). Variants (second
  `Cookie` header, cookie-name case, `Authorization`, query-string token) that the authority accepts
  but the strip misses land in the app, which can exfiltrate them via its responses (AR-16).
- **Fix (also a simplification):** The component that speaks to the app must never see session
  credentials or the signing key. Preferred topology: a single Rust **front** (the authority, or a
  hyper-based proxy in the authority's trust domain with the signer in a separate process) terminates
  TLS and sessions, builds the forwarded request from an **allowlist** of headers/cookies, attaches the
  grant, and forwards over UDS to nginx/PHP-FPM, which are then placed **outside** the TCB (nginx
  compromise ≡ C, already modelled). This removes nginx from the TCB, removes the subrequest (AR-07),
  and puts the only attacker-facing parser of app output in a memory-safe component.
- **Blocks:** Phase 3; decide topology before the Phase 2 Compose file is frozen.

### AR-04 — Ceilings and unbound parameters break full binding (High)

- **Affected:** ADR-0003 decisions 2 and 4, residual section, objection 1; ADR-0004 `con`; SI-06,
  SI-07; ADR-0005 architect note on ceilings.
- **On ADR-0003 objection 1:** Agree. Research 04 §2.2 recommended b2 (exact derivation); the ADR
  silently degraded it to a ceiling, raising the per-request residual from "the effect the user sent" to
  "anything up to the policy max" ($25 → up to $80 in the ADR's own example). Nothing in the design
  needs the weaker form for the PoC routes.
- **Extension (not covered by the objection):** The grant has `res` (exact) and `con` (constraints). An
  operation parameter that is in neither is unconstrained by the grant. Scenario: `ledger.refund` gains
  `refund_method` or `destination_account`; `account.transfer` on a resource-less route
  (`POST /account/transfer`, resource = subject's account) has `to_account` and `amount`. If
  `to_account` is not declared in `con`, a compromised app (or an honest app fed a different body; see
  AR-07) sends the money anywhere, within budgets. "Unknown fields are rejected" (ADR-0002) protects
  only against *undeclared* fields, not declared-but-unbound ones.
- **Fix:** In the operation registry, **every** parameter is classified `exact` (default, value taken
  from the route-mapped request and placed in the grant), `bounded` (ceiling, explicitly marked
  `app_computed` in the route map), or `free` (must be justified and listed in published residuals).
  Broker rejects at startup any operation whose schema contains an unclassified parameter, and rejects
  any grant whose `con` lacks a value for an `exact` parameter. Publish the per-route residual table
  generated from that registry (SI-17).
- **Blocks:** Phase 3.

### AR-05 — Budgets are subject to write skew (High)

- **Affected:** ADR-0005 (forbids on `window_total + amount`), ADR-0006 decision 1 ("serializable (or
  row-locked)"), ARCHITECTURE §3 step 8 ("load budgets"), THREAT_MODEL F, R-2, R-3, R-7.
- **Scenario (C, with grants from many users or from R-3-driven requests):** Budget for user u is
  $200/24 h; current window total $190. The app submits 20 concurrent refunds of $10 on **different**
  orders. Each transaction locks its own `orders` row `FOR UPDATE`, reads `window_total = 190` from the
  ledger aggregate (not locked), Cedar allows, each commits. Total $390. Under PostgreSQL READ
  COMMITTED, and even REPEATABLE READ, this is classic write skew; only SERIALIZABLE or an explicitly
  locked counter row prevents it [F\*: PostgreSQL docs, "Transaction Isolation", serializable
  examples].
- **Why it matters:** Budgets are the only bound the design offers for its "Major" residual R-3 and for
  workload-only operations (R-7). A bound that a concurrent caller can exceed by N× is not a bound.
- **Fix:** Mandate one of: (a) SERIALIZABLE for every effect transaction, with serialization failure
  ⇒ Deny (and no automatic retry without re-reading facts); or (b) a budget counter row per
  `(scope, window)` locked `FOR UPDATE` and updated with a guarded write
  (`WHERE spent + $amt <= limit`, rows = 1). Remove "or row-locked" as a blanket alternative. Add N=64
  concurrent cross-resource budget tests.
- **Blocks:** Phase 4.

### AR-06 — Workload-only operations and background workflow steps are undesigned (High)

- **Affected:** ADR-0003 decision 5, ADR-0002, ADR-0007 decisions 2 and 4, THREAT_MODEL R-7, SI-05,
  SI-10, SI-12.
- **Scenario:** Demo 3 (order → reserve → authorize → capture → confirm) contains steps that real apps
  run from jobs, not from a user HTTP request. The authority only issues grants for requests arriving
  via nginx. So either (a) the broker accepts these operations **without a grant** (then SI-05..SI-09
  do not apply to them and the app can drive any declared transition whose guard holds, for any
  workflow), or (b) the operation is reached through some other grant source that does not exist yet.
  For a multi-tenant workload, "tenant derived from workload registration" (research 02 §4.2 key 8) is
  undefined: the workload serves many tenants, so a grantless operation has no trusted tenant and every
  tenant's workflows are in reach (confused deputy).
- **Why not stopped:** "Separate, budgeted class" is the whole specification. Budgets are themselves
  bypassable (AR-05). A transition operation marked workload-only by mistake is callable with no grant
  at all, and nothing in the design detects that misclassification.
- **Fix:** Before Phase 3, specify: workload-only operations must be explicitly enumerated in broker
  config, must carry a fixed tenant per workload (or be forbidden for multi-tenant workloads), must be
  limited to transitions whose guard references state created by a prior **user-granted** effect on the
  same resource (e.g. `capture` only if `authorize` committed under a grant for the same
  `(ten, sub, order)`), and must be budgeted with locked counters. Publish the list as residuals.
  Default: an operation with no grant requirement is a startup error unless listed.
- **Blocks:** Phase 3 (design), Phase 5 (implementation).

### AR-07 — nginx ↔ authority subrequest underspecified (Medium)

- **Affected:** ADR-0003 consequences ("authority is the single HTTP parser"), ARCHITECTURE §2 diagram
  ("subrequest: method, path, body digest, session"), R-8, OQ-08.
- **Issues:**
  1. *Body visibility.* Exact binding of body parameters (AR-04) requires the authority to see the body.
     Stock nginx `auth_request` runs in the access phase; whether and how the request body is available to
     the subrequest, and what produces a "body digest", is not specified. Stock nginx has no body-digest
     primitive [H: confirm with a spike; workarounds use njs/Lua, which add a scripting runtime to the
     TCB]. If nginx forwards one body to the authority and a re-read body to FastCGI, there are two body
     streams whose equality nobody checks.
  2. *Response association.* With upstream keepalive between nginx and the authority, a desync bug
     associates user V's grant with attacker B's request [H]. On a resource-less route with an unbound
     parameter (AR-04), an *honest* app then executes B's parameters under V's grant (cross-user mix-up
     without code execution).
  3. *Path canonicalization.* nginx `location` matching (merge_slashes, percent-decoding) decides whether
     `auth_request` runs at all; the authority parses the raw path. Mismatch is fail-closed for effects
     (no grant ⇒ no effect, a good property; see AR-20) but can attach a grant for route X to a request
     nginx dispatches to script Y.
- **Fix:** Adopting AR-03's front topology removes all three (one hop, one parser, the body the
  authority binds is the body it forwards). Otherwise: no keepalive to the authority; the authority echoes
  nginx `$request_id` and nginx rejects mismatches; specify body handling and test it differentially.
- **Blocks:** Phase 3.

### AR-08 — `rqh` cannot be verified at the broker (Medium)

- **Affected:** ADR-0003 decision 3 and objection 2; ADR-0004 payload key 16; research 02 §4.3 step 7.
- **Assessment:** Agree with objection 2. The broker never sees the HTTP request, so `rqh` over it is
  audit data that looks like a binding. Worse, research 04 §8 had the app forward "the original body" for
  re-digesting; if an implementer follows that note, the broker gains a second HTTP/JSON parser and the
  canonicalization problem returns.
- **Fix:** Define `rqh = SHA-256("pbe.rqh.v1" ‖ 0x00 ‖ deterministic-CBOR(typed broker request))`
  computed by the authority from route-extracted values, verified by the broker. With AR-04's `exact`
  classification this is redundant with `con`; pick one mechanism and delete the other.
- **Blocks:** Phase 3.

### AR-09 — Epoch revocation, logout, and TTL (Medium)

- **Affected:** ADR-0004 (`epo`), ADR-0006 decision 5, research 02 §6.
- **Issues:**
  1. The broker requires `epo ≥ current_epoch(ten, wid)`. The authority is stateless (route map + key)
     and has no channel to learn the broker's epoch. If it always emits a fixed value, the first
     revocation permanently denies every future grant; if it learns the epoch from config, revocation
     requires redeploying the authority. Neither is designed.
  2. Revocation is scoped `(ten, wid)`; user logout or session revocation does not invalidate that user's
     outstanding grants. The app keeps using them after logout for up to `max_ttl`.
  3. `max_ttl` default 300 s, while research 04 §10 recommended ≤ 30 s; no rationale is given for the
     tenfold increase, which multiplies the hoarding window in R-2.
- **Fix:** Replace epochs with a broker-side **revoked-before** timestamp per `(ten)`, `(ten, wid)`,
  `(ten, sub)`: deny if `iat < revoked_before`, checked inside the consuming transaction. No authority
  state required. The authority calls (or the operator writes) the broker's revocation table on logout.
  Default `max_ttl` 30 s unless a route declares otherwise.
- **Blocks:** Phase 3.

### AR-10 — UNKNOWN re-issue check is in the wrong component (Medium)

- **Affected:** ADR-0006 open risk 3; research 02 §5 item 5; SI-15.
- **Scenario:** External refund → timeout → `UNKNOWN`. The user (or app script via R-3) clicks
  "refund" again; the authority, which has no access to broker state, issues a fresh grant with a new
  `jti`; the broker dispatches a second upstream call with a **different** idempotency key (derived from
  the new `jti`). Duplicate external effect, falsifying SI-15.
- **Fix:** The broker must deny any effect on a resource with a pending `UNKNOWN` operation of a
  conflicting type, as a precondition inside the transaction. Upstream idempotency keys should derive
  from the *business* intent where possible (`(ten, op, res, exact params)`), not only `jti`.
- **Blocks:** the phase that introduces the first external effect (not v0's simulated ledger).

### AR-11 — Denied attempts do not consume the grant (Medium)

- **Affected:** ADR-0006 decisions 1–2 (`consumed_grant(… outcome)`), SI-09.
- **Scenario:** The consumption row is inserted inside the effect transaction; any deny rolls the
  transaction back, removing the row. The app can therefore (a) resubmit the same grant with different
  parameters until one passes (with ceilings, binary-search the refundable amount; with free parameters,
  try values freely), and (b) hold a denied grant and retry when state changes (e.g. wait for `captured`)
  until `exp`. The `outcome` column and "same hash returns stored outcome" imply denials are recorded;
  the transaction design means they cannot be.
- **Fix:** Decide explicitly. Recommended: on deny after successful grant verification, record
  consumption with outcome `DENIED` in a separate short transaction (fail-closed if that write fails), so
  each grant gets one decision. Add a test vector.
- **Blocks:** Phase 3.

### AR-12 — Shared rw `fcgi` volume and logs: writable+exec+persistent path, TCB disk exhaustion (Medium)

- **Affected:** ADR-0001 P0; research 03 §6.3; THREAT_MODEL R-14; "read-only rootfs removes persistence".
- **Scenario (C):** `/run/fcgi` is a named Docker volume mounted rw (php-fpm must bind there). It is not
  `noexec` and persists across container recreation. The attacker (a) writes and `execve`s binaries there
  despite `read_only: true` and the `noexec` `/tmp`; (b) leaves files that survive a redeploy; (c) fills
  it, and/or floods stdout into the default `json-file` log driver, until the Docker data root is full.
  Postgres in the same VM then cannot write WAL; the broker fails closed for **all** workloads and the
  audit trail stops.
- **Why not stopped:** `mem_limit`/`pids_limit` are set; disk and log quotas are not. R-14 frames DoS as
  "against co-tenants", but here a single compromised app takes down the TCB. Fail-closed holds; the
  availability claim and "no persistence" claim do not.
- **Fix:** Make `fcgi` a tmpfs-backed volume (`driver_opts: {type: tmpfs, device: tmpfs, o:
  "size=1m,noexec,nosuid,nodev"}`), or put the FastCGI socket in a tmpfs only the app writes and nginx
  only reads; set log driver `max-size`/`max-file` for `app`; put DB storage on a separate filesystem or
  quota. Add probes: exec from every writable mount (expect EACCES), file persists across recreate
  (expect absent). Amend research 03 §2.2's persistence statement.
- **Blocks:** **Phase 2.**

### AR-13 — Multi-effect requests unspecified (Medium)

- **Affected:** ADR-0003 drawbacks ("multiple scopes/grants (open)"), ADR-0007.
- **Scenario:** One user action needs several effects (refund + workflow transition + notification). If a
  route yields several independent grants, the app can execute any subset and in any order, leaving
  partial state that no grant forbids; the user's single intent becomes N independently usable
  authorizations.
- **Fix:** One route ⇒ one grant ⇒ one broker operation; composite effects are a single typed broker
  operation that runs all writes in one transaction (or a declared workflow transition). Forbid
  multi-grant routes in v1.
- **Blocks:** Phase 3.

### AR-14 — No comparison against the simplest alternative (Medium)

- **Affected:** ADR-0001, ADR-0002 (PostgREST dismissed in one line), ADR-0004; OQ-01 still open.
- **The alternative:** App under the same P0 isolation, reaching only PostgREST over a UDS. PostgREST
  exposes **only** an API schema of `SECURITY DEFINER` functions (no table privileges), Postgres RLS on
  tenant, and a gateway-signed **asymmetric** JWT carrying `sub`, `ten`, `op`, exact parameters and
  `jti`. Each function checks the claims against its arguments and inserts `jti` into a unique-keyed
  table in the same transaction.
- **What it matches:** SI-01..03 (same isolation), SI-05 (asymmetric key outside the workload), SI-06
  (claims compared in SQL), SI-09 (same-transaction unique insert), SI-10/11 (in-transaction SQL),
  SI-16 (RPC only). It also inherits AR-01..03 and AR-05 unchanged, because those are gateway and
  isolation issues, not broker issues.
- **Where PBE is materially better:** a memory-safe, single-shape grant verifier instead of a general
  JOSE stack (RFC 8725 classes); per-socket workload identity across several workloads; the external-effect
  state machine (Postgres cannot do idempotent external calls transactionally); analyzable policy
  (Cedar/symcc) separate from effect code.
- **Where it is not:** for internal-DB-only effects the guarantee is essentially the same, and the
  alternative has less new TCB code.
- **Fix:** Add this comparison to ADR-0002 explicitly, state that PBE's distinct value is concentrated in
  the gateway binding, external effects and multi-workload identity, and close OQ-01 before accepting
  ADR-0001/0002. Consider using the alternative as the Phase 2/3 baseline in tests.
- **Blocks:** acceptance of ADR-0001/0002 (documentation), not implementation.

### AR-15 — nginx response-header filtering incomplete (Low)

- **Affected:** TB-2; research 03 §6.3 nginx notes.
- **Detail:** `fastcgi_ignore_headers` can also ignore `X-Accel-Expires`, `X-Accel-Limit-Rate`,
  `X-Accel-Buffering`, `X-Accel-Charset`, `Expires`, `Cache-Control`, `Set-Cookie`, `Vary` [F\*: nginx
  `ngx_http_fastcgi_module` docs]; only `X-Accel-Redirect` is ignored. The app can set a `Set-Cookie`
  for the session cookie's name (session fixation / logout-forcing), influence any configured cache, and
  trigger `error_page` internal redirects if `fastcgi_intercept_errors` is on. Any client header that
  normalizes to the FastCGI parameter name used for the grant (e.g. `HTTP_PBE_GRANT` vs `PBE_GRANT`)
  must be impossible by construction.
- **Fix:** Ignore all X-Accel-* headers; `fastcgi_intercept_errors off`; no `fastcgi_cache`; strip any
  `Set-Cookie` naming gateway-owned cookies (easier in the AR-03 front); grant passed under a name that
  no `HTTP_*` header can produce; probe each.
- **Blocks:** Phase 2 (config hygiene).

### AR-16 — SI-02 wording, exfiltration channel, and threat-model over-claims (Low)

- **Affected:** SI-02, THREAT_MODEL §1, row A, §3.
- **Detail:**
  1. SI-02 says no credential granting access to a protected resource is present in the workload. A grant
     *is* such a credential (bearer, within `wid`), present by design. SI-17 requires the invariant to
     say what it means: "no **reusable or standing** credential; single-use grants are present by design
     and bounded by SI-06..09".
  2. `network_mode: none` removes network routes, not exfiltration: the app returns arbitrary bytes to
     any client, including attacker B. Every secret that reaches the app (stray session variants,
     AR-03; passwords, AR-01; grants; broker responses) is exfiltrable. TM §1 should say so.
  3. Row A: "no user-scoped effect is possible" is true only until A becomes C (then R-3 applies).
  4. TM §3: "User session credentials … Gateway only" is false while nginx (attacker-facing) holds them
     (AR-03).
  5. Research 03 §8 "four containers" is now five; ARCHITECTURE should not cite it as the minimum
     unchanged.
- **Blocks:** Phase 3 (documentation).

### AR-17 — Broker `sub`/`ten` checks are circular (Low)

- **Affected:** research 02 §4.2 keys 8–9, §4.3 step 6; ADR-0004 "semantic checks against trusted facts";
  SI-06.
- **Detail:** The broker has no source for subject or tenant other than the grant. "Must equal the
  gateway-verified subject on the request context" describes a check against nothing. This is fine if
  stated (the grant signature *is* the trusted fact), but a reviewer or implementer reading the rule
  will believe two independent sources agree. The SI-06 falsifier ("any bound field differs from the
  request") similarly has no request-side `sub`/`ten`.
- **Fix:** State that `sub`/`ten` are *sourced* from the verified grant, not *checked*; keep the real
  checks (`wid` vs socket, `aud`, clock, `res`/`con` vs params, tenant in every query).
- **Blocks:** Phase 3 (spec).

### AR-18 — Clock and restore still open (Low)

- **Affected:** ADR-0006 open risks 1–2; R-12; THREAT_MODEL assumptions 5–6.
- **Detail:** Already listed by the authors; recorded here because SI-09 is claimed in ARCHITECTURE §5
  without the qualifier. A grant pruned at `exp + skew + margin` and replayed after a backward clock step,
  or after DB restore, executes twice.
- **Fix:** Implement the persisted high-water mark (refuse to serve below it) and the restore runbook
  (rotate grant key or bump revoked-before) before any SI-09 claim; mark SI-09 "not claimed across
  restore/clock rollback" until then.
- **Blocks:** Phase 3 claim.

### AR-19 — Signed receipts and log-sourced evidence (Low)

- **Affected:** ADR-0007 decision 3; SI-12; THREAT_MODEL §3 audit row.
- **Detail:** Receipts are handed to the untrusted app and never accepted as input. In v0 nobody verifies
  them; they add a broker signing key, a second COSE type (cross-type confusion vector 13), and privacy
  surface. Separately, the app controls its own stdout; if auditors read aggregated container logs, the
  app can forge lines resembling broker audit records.
- **Fix:** v0 returns an unsigned outcome plus an audit row id; add signed receipts only with a named
  external verifier. Document that evidence is the broker DB audit table (or an append-only log only the
  broker writes), never aggregated container logs.
- **Blocks:** Phase 5.

### AR-20 — Points examined that hold (Info)

Recorded so they are not re-litigated; all remain NOT TESTED.

- **No grant ⇒ no effect** makes nginx/authority fail-open (authority down, path mismatch, missing
  `auth_request`) degrade to denial rather than bypass, *for grant-requiring operations* (not AR-06's).
- **Per-workload pathname UDS** with read-only mount: the app cannot unlink or pre-create the socket;
  connect on a ro mount should work because the read-only check applies to regular files, directories and
  symlinks [H: B-03]. `SO_PEERCRED` as secondary check is sound given distinct UIDs.
- **`/proc`, ptrace, signals:** private PID namespace removes visibility of broker/nginx processes;
  timing of tenant-scoped lookups gives no cross-tenant oracle because grants bind `res`.
- **Grant format (ADR-0004):** single accepted shape, key-fixed algorithm, `external_aad` audience,
  re-encode compare, and `verify_strict` close the known JOSE/COSE confusion classes; the vectors in
  research 02 §8 are adequate acceptance criteria.
- **Cedar adapter (ADR-0005):** diagnostics-as-deny closes the error-skip fail-open; guarded SQL writes
  duplicate the critical guardrails, which is correct defence in depth.
- **Receipts never authorize (ADR-0007):** with broker-owned state there is no laundering path through
  receipts.
- **R-8 severity:** route divergence between nginx and authority gives attacker B nothing beyond P(u)
  when parameters are exactly bound, because the honest app's divergent parameters fail the grant check;
  it matters mainly through AR-04 and AR-07(2).

---

## Verdict per ADR

| ADR | Verdict | Conditions |
|---|---|---|
| 0001 Architecture A + TCB | **Accept with changes** | Adopt objection 1 (separate signer); adopt AR-03 front topology so nginx leaves the TCB and never sees session credentials; AR-12 tmpfs FastCGI volume and log/disk quotas; objection 2 wording on Legacy Containment; AR-14 comparison recorded. |
| 0002 Broker execution model | **Accept with changes** | AR-06 workload-only operation rules (startup error for unlisted grantless ops); AR-14 PostgREST comparison; per-workload resource fairness noted (one workload can starve the shared broker). |
| 0003 Trusted user context & issuance | **Reject (revise and resubmit)** | The residual quantification is materially wrong: AR-01 (credential capture on shared origin), AR-02 (browser persistence), AR-03 (nginx holds sessions), AR-04 (ceilings; adopt objection 1 plus parameter classification), AR-07, AR-08 (adopt objection 2), AR-13. The b2 direction is right; the ADR as written does not deliver it. |
| 0004 Grant format | **Accept with changes** | `rqh` redefined or removed (AR-08); epoch replaced by revoked-before (AR-09); `max_ttl` 30 s default; `sub`/`ten` sourcing stated (AR-17). OQ-07 (Actenon) not evaluated by this review. |
| 0005 Policy engine | **Accept with changes** | Budget facts must come from locked counters or SERIALIZABLE (AR-05); CI check that every operation parameter used in policy is grant-bound or explicitly `free` (AR-04). |
| 0006 Replay & effect state | **Accept with changes** | AR-05 isolation rule; AR-10 broker-side UNKNOWN precondition; AR-11 denial consumption semantics; AR-18 high-water mark and restore runbook before any SI-09 claim. |
| 0007 Receipts & workflows | **Accept with changes** | AR-06 rules for transitions without a user request; AR-19 defer signed receipts. |
| 0008 Rust / thin PHP SDK | **Accept** | Note that `#![forbid(unsafe_code)]` does not cover dependencies; the dependency tree is TCB (already stated). |

**Overall:** The core broker design (typed operations, grant necessary-not-sufficient, in-transaction
consumption and state checks, broker-owned workflow state) is sound in structure. The weaknesses are at
the **browser/gateway edge**, where the design keeps the app on the same origin as the user's credentials
and puts an attacker-facing C parser in the TCB, and at **budgets**, which are the only bound on the
largest residual and are not concurrency-safe as specified. Phase 2 may proceed once AR-12 and AR-15 are
addressed and the AR-03 topology is decided; Phase 3 is blocked by AR-01..04, AR-06 and the Medium
findings marked Phase 3.

---

## Resolution (2026-10-24, architecture revision rev. 2)

Rulings by the orchestrator; changes drafted by the design author. The project is now named
**Nodkey**: revised documents use the new name and `nodkey` identifier prefixes. Nothing below has
been tested.

| Finding | Disposition | Where addressed |
|---|---|---|
| AR-01 | **Accepted.** Separate auth origin served only by the gateway; passkeys (RP ID = auth host) for P0; password login is a weaker, labelled profile; `__Host-` HttpOnly Secure session cookie set via a gateway-reserved callback. Route-map lint for credential-named fields adopted. | ADR-0003 §2; SI-18; THREAT_MODEL §3, assumption 9, R-4; ARCHITECTURE §3 step 1, §6 |
| AR-02 | **Accepted.** `Service-Worker: script` requests rejected; `Service-Worker-Allowed` dropped; HTML/JS forced `no-cache`; `Clear-Site-Data` runbook. R-3 rewritten and quantified. **Partially deferred:** a gateway-pinned CSP with hash-pinned `script-src` breaks most legacy apps (inline scripts), so it is an optional hardening, not a P0 requirement. Whether browsers send `Service-Worker: script` must be confirmed in a spike. | ADR-0003 §4; SI-18; THREAT_MODEL §6 R-3 |
| AR-03 | **Accepted.** A Rust gateway is the only public listener and terminates TLS and sessions. Signing runs in a separate `authority` container with no network and no workload traffic. nginx, if used, is part of the untrusted workload. Request headers and cookies are forwarded from an allowlist. | ADR-0001; ADR-0003 §1, §3; THREAT_MODEL row J, R-8 |
| AR-04 | **Accepted.** Every parameter is classified `exact` / `bounded` (only where the route map marks it `app_computed`) / `free` (justified and published). Destination-like parameters are never free. Unclassified parameters are a startup error. CI binding check against policy. | ADR-0003 §5; ADR-0002 §1; ADR-0004 (`con`); ADR-0005; SI-06 |
| AR-05 | **Accepted.** Locked counter rows (`FOR UPDATE`, guarded write) under READ COMMITTED with a fixed lock order. SERIALIZABLE is not required. Fixed windows give a published 2× worst case at a boundary. | ADR-0006 §1–2; ADR-0005; THREAT_MODEL R-3 |
| AR-06 | **Accepted.** New ADR-0009: authority classes `user_grant` / `scheduler_grant` / `workload`; trusted scheduler issues grants derived from prior user-granted state; grantless only in single-tenant workloads, with fixed ceilings. | ADR-0009; ADR-0002; ADR-0007 §3; SI-19 |
| AR-07 | **Accepted, resolved by topology.** The subrequest is gone: one hop and one parser, and the body forwarded is the bytes that were parsed. | ADR-0003 §1, §5; ARCHITECTURE §3 |
| AR-08 | **Accepted.** `rqh` removed in v1 (exact `con` replaces it); key 16 reserved. | ADR-0004; ADR-0003 §6 |
| AR-09 | **Accepted.** `epo` replaced by broker-side `revoked_before` per `(ten)`, `(ten, wid)`, `(ten, sub)`; gateway revoke-only socket on logout; `max_ttl` 30 s. | ADR-0004; ADR-0006 §6; ADR-0002 §3 |
| AR-10 | **Accepted (first half).** In-transaction precondition: deny effects on a resource with a pending conflicting `UNKNOWN`. **Deferred:** business-intent upstream idempotency keys, until the first external adapter, because they depend on upstream semantics. | ADR-0006 §7, Open |
| AR-11 | **Accepted.** A verified-and-denied grant records `DENIED` in a separate transaction; one decision per grant. | ADR-0006 §4; SI-09 |
| AR-12 | **Accepted.** All writable workload mounts, including socket volumes, are tmpfs `noexec,nosuid,nodev` with size caps; log rotation limits; DB storage on a separate filesystem; new exec and persistence probes. The research 03 §2.2 statement is superseded here; the research note itself was not edited. | ADR-0001; ARCHITECTURE §4; THREAT_MODEL TB-7, R-14 |
| AR-13 | **Accepted.** One route ⇒ at most one grant ⇒ one operation. Composite effects are a single typed operation or a workflow transition. | ADR-0003 §5 |
| AR-14 | **Accepted.** PostgREST RPC-only + RLS comparison recorded; it is to be built as a test comparator. ADR-0001/0002 stay Proposed until OQ-01 is closed. | ADR-0002 Alternatives; ADR-0001; ARCHITECTURE §6 |
| AR-15 | **Accepted, mostly made moot.** nginx is untrusted, so X-Accel and error interception affect only the workload. The gateway drops app `Set-Cookie` for gateway-owned names. `Nodkey-Grant` can be set only by the gateway, because inbound `Nodkey-*` headers are not on the allowlist. | ADR-0003 §3–4; THREAT_MODEL TB-2 |
| AR-16 | **Accepted.** SI-02 reworded (reusable/standing credentials, end-user credentials; grants present by design). Exfiltration stated in THREAT_MODEL §1. Row A and the §3 session-credential row corrected. Five-container P0 stated. | SI-02; THREAT_MODEL §1–3; ARCHITECTURE §4 |
| AR-17 | **Accepted.** `sub`/`ten` are stated as *sourced* from the verified grant; the checked fields are listed. | ADR-0004; SI-06 |
| AR-18 | **Accepted.** Clock high-water mark and restore runbook specified. SI-09 is not claimed across restore or clock rollback until these are tested. | ADR-0006 §8–9; SI-09; ARCHITECTURE §5 |
| AR-19 | **Accepted.** v0 returns an unsigned outcome plus an audit row id; signed receipts wait for a named verifier. Evidence is the broker DB audit table, never container logs. | ADR-0007 §4–5; ADR-0001 |
| AR-20 | Noted; no change. | — |

**Rejected findings:** none. **Status after revision:**
- **Accepted:** ADR-0005, ADR-0006, ADR-0008.
- **Proposed:**
  - ADR-0001 and ADR-0002, pending OQ-01.
  - ADR-0003, rewritten; needs re-review.
  - ADR-0004, pending OQ-07.
  - ADR-0007, to be accepted together with ADR-0009.
  - ADR-0009, new and unreviewed.
