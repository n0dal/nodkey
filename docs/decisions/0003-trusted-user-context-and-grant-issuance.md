# ADR-0003: Trusted user context and grant issuance (rev. 3)

- **Status:** Proposed. Rev. 3 addresses every R3 item that blocks Phase 3 (R3-01, 02, 04, 05) and every
  item the 2026-10-25 review set as a condition for acceptance. It stays Proposed because rev. 3 adds
  unreviewed mechanisms: confirmation flow, edge/proxy split, and read grants. Read grants also need an
  ADR-0004 amendment (§7). A focused re-review is needed before acceptance.
- **Date:** 2026-10-25
- **Invariants:** SI-02, SI-05, SI-06, SI-07, SI-09, SI-10, SI-18, SI-20, SI-21
- **Open questions:** OQ-04 (addressed), OQ-08 (see §5)

## Problem

The broker must know which user is behind an effect, and what that user asked for, without trusting
the workload that relays the request. The workload must never hold a reusable user credential.

## Evaluation criteria

- No reusable credential reaches workload code.
- The effect is bound to the request the browser sent.
- Intent is bound wherever it is claimed.
- One trusted parser.
- Published residuals.
- Existing components preferred.

## Alternatives considered

- (a) Cookie forwarding: rejected.
- (b1) Identity-only attestation: rejected.
- (c) DPoP: rejected.
- Rev. 1 (nginx + subrequest): rejected.
- Rev. 2: accepted with changes.
- **Existing OIDC IdP + identity-aware-proxy pattern (R3-10).** The auth origin, passkey ceremonies,
  enrollment, recovery and the code flow are commodity IdP functions. Only the route map, binding,
  confirmation and the signer are Nodkey-specific.
  - **Verdict:** login, enrollment and recovery **should be delegated** to a maintained OIDC IdP with
    WebAuthn where one is available. The gateway then acts as an OIDC RP, using code flow + PKCE + state
    + nonce, with `prompt=login`/`max_age=0` on every session establishment. Any IdP must meet the §2
    conditions.
  - The gateway still serves the confirmation pages (§6), because no standard IdP renders a
    gateway-held effect summary bound to a pending effect [H].
  - The Phase 3 PoC picks between built-in passkey login (a maintained WebAuthn library, no custom
    crypto) and an IdP. The selection criterion is smaller TCB code; the comparison is recorded in
    STATUS.

## Decision

### 1. Topology (R3-08)

- **`gateway-edge`** (Rust, TCB) is the only public listener. It holds the TLS keys, the session store,
  the route map and the pending-effect store. It serves the app host and `auth.<domain>`, and routes on
  `Host`/`:authority`, never on SNI (`421` on mismatch).
- **`gateway-proxy`** (Rust, *outside the TCB*, no secrets, `network_mode: none`) is the only process that
  speaks HTTP to the workload. Its profile:
  - HTTP/1.1 over UDS, one request per connection.
  - No `Upgrade`/`101`, no 1xx forwarding, no trailers.
  - Strict framing: rejects CL+TE, duplicate CL, obs-fold and duplicate `Content-Type`.
  - Header, body and time caps.
  - It returns a length-prefixed structured response to the edge.
- The edge applies all response policy (§4) to that structure. Its compromise is equivalent to C.
- R-8 thereby shrinks from "all live sessions" to "requests in flight".
- **`authority`** signs grants only for the edge. It has no network and no workload traffic. It signs
  whatever the edge asks, so it gives **no** protection for live sessions while the edge is compromised.
  It ensures that compromise ends when the edge is fixed (no key theft).

### 2. Auth origin and sessions (R3-02, R3-09, SI-18)

Separate **origin** is not separate **site**: `auth.<domain>` and same-site siblings can send
credentialed requests to each other. Recommendation: the app origin uses its **own registrable
domain**. Otherwise, every same-site sibling is a forgery source that only §3 stops (R-18).

**Login code flow:**
1. The edge, on the app host, creates `state` and `verifier`. It sets `__Host-nodkey_login`
   (HttpOnly, 5 min) holding them, and redirects to `auth.<domain>` with `H(state)` and
   `challenge = SHA-256(verifier)`.
2. The auth origin sets its own pre-auth cookie `__Host-nodkey_preauth`, binding the ceremony to this
   browser. It then requires a **WebAuthn assertion with user verification** (no silent re-issue: the
   auth origin keeps no session that can mint app sessions without a ceremony).
3. It issues a code that is single-use, valid ≤ 60 s, and bound to `H(state)`, `challenge` and the
   pre-auth cookie. The browser is sent to `/.nodkey/callback` on the app host.
4. The callback rejects the code unless `__Host-nodkey_login` is present and its state and verifier
   match.
5. The callback mints a **fresh** session id (it ignores and deletes any existing gateway-named cookie)
   and sets `__Host-nodkey_session` (HttpOnly, Secure, SameSite=Lax).
6. `return_to` must be an app-origin path from an allowlist.

**Session lifetime:**
- Absolute *L* = 12 h by default; idle timeout 30 min.
- App script can keep the idle timer alive, so only *L* bounds C.
- Renewal requires a user ceremony on the auth origin.

**Auth-origin page headers:** `frame-ancestors 'none'`, `Cross-Origin-Opener-Policy: same-origin`, and a
strict CSP with no app-origin sources.

**RP ID and verification:**
- RP ID = the auth host exactly, never the registrable domain.
- No `/.well-known/webauthn` related-origins list that includes the app.
- The server verifies `C.origin` and rejects `crossOrigin`/`topOrigin`.

**Enrollment and recovery:**
- Both complete only on the auth origin.
- First enrollment uses an invitation link opened there.
- Recovery codes are accepted only there.
- Completing recovery sets `revoked_before = now` for the subject (ADR-0006) and notifies the user out
  of band.
- Phishing of recovery codes on the app origin is published in R-4.

**Logout:** writes `revoked_before` for `(ten, sub)` through the revoke-only broker socket.

### 3. Request provenance (R3-01, SI-21)

- **Write-grant routes** use non-safe methods only (`POST`, `PUT`, `PATCH`, `DELETE`), and the edge
  checks the request's origin:
  - The edge issues a write grant only if `Sec-Fetch-Site: same-origin`.
  - If that header is absent, `Origin` must equal the app origin exactly.
  - If both are absent, deny.
- **Read-grant routes** (§7) may use `GET`. Any request that is not `Sec-Fetch-Site: same-origin`
  (or `none`) must be `Sec-Fetch-Mode: navigate`; otherwise the edge issues no read grant. Responses carry `Cross-Origin-Resource-Policy:
  same-origin`, and the edge drops app-set `Access-Control-*` headers on read routes. Rationale: a
  cross-site navigation renders the data only to the victim's own browser.
- **State-changing auth-origin endpoints** apply the same check against the auth origin, plus a
  per-ceremony token.
- **Architect clarification:** the orchestrator ruling "grant-issuing routes must use non-safe methods"
  is applied to **write** grants. Applied to read grants, it would make GET page rendering impossible
  (ruling 4). This needs confirmation.

### 4. Request and response filtering (R3-06, R3-07, AR-01)

**Request side:**
- Requests are built from a header and app-cookie allowlist. Gateway-named cookies, `Authorization`
  and `Nodkey-*` headers are never forwarded.
- A request carrying more than one cookie whose name matches `__host-nodkey` (case-insensitive) is
  rejected.
- Any request with a `Service-Worker` header is rejected (presence check, any case).

**Response side:**
- App `Set-Cookie` is forwarded only for allowlisted app cookie names. Gateway-prefixed names are
  dropped (case-insensitive).
- `Service-Worker-Allowed` and `Access-Control-*` (on read routes) are dropped.
- `X-Content-Type-Options: nosniff` is always set.
- **Every** app response gets `Cache-Control: no-store`, and `Expires`/`Age` are removed. The only
  exception is deploy-manifest static paths whose SHA-256 the edge verifies before allowing a long max-age.
- Remediation runbook: `Clear-Site-Data: "cache", "storage", "cookies"`, then revoke sessions (forces
  re-login).

**Credential-field lint (AR-01):** route-map build fails if a mapped route has a parameter named like
a credential (`password`, `passcode`, `otp`, `pin`, `recovery*`, `secret`). This cannot cover unmapped
routes: an app that renders its own login form is not in Native mode (ARCHITECTURE §6).

### 5. Parsing and binding (R3-05, R3-11)

**Encodings:**
- `application/json`: strict; duplicate keys rejected.
- `application/x-www-form-urlencoded` with a strict grammar:
  - UTF-8 only.
  - Names must match `[a-z0-9_]{1,64}`, so brackets, `.` and space are excluded (no PHP name mangling).
  - Duplicate names are rejected.
  - Values are percent-decoded once, with `+` read as space.
- `multipart/form-data` is unsupported on mapped routes in v1.

**Conversions** are declared per parameter:
- `int`
- `minor_units(exp)` with grammar `^[0-9]{1,12}(\.[0-9]{1,exp})?$`: no separators and no comma decimal.
  The client formats locale input.
- `enum`
- `id`: ASCII `[A-Za-z0-9_-]{1,64}`

A non-matching value returns 400 and no grant is issued.

**Binding sources:** `request:path:<name>` | `request:query:<name>` | `request:body:<pointer>` |
`route:<constant>` | `state:<broker check>` (the broker enforces equality with a trusted value, e.g.
currency = the order's currency). These combine with classes `exact` | `bounded` | `free` (ADR-0002).

The edge forwards the **canonical** path it mapped, the exact query string and the exact body bytes it
parsed.

**OQ-08:** the workload re-parses with PHP. For `exact` parameters, any divergence makes an honest app
submit different values, which the broker denies (fail-closed). For `bounded`/`free` parameters,
divergence is not detected.

**Patterns that cannot be exactly bound:**

| Pattern | Treatment | Residual |
|---|---|---|
| Server-computed amounts (cart total, tax, pro-rata refund) | `bounded` ceiling in the grant **and** the broker recomputes the amount from trusted state; the params must equal the recomputation | None beyond inputs to the computation |
| App-resolved destination ("pay alice@…" → account id) | **Unsupported.** The resolution moves into a broker operation that takes the user-entered identifier as `exact` | — |
| App-generated identifiers (new order id, idempotency key) | The broker generates ids; `jti` is the idempotency key | — |
| Multi-step wizard whose final POST carries no values | Unsupported unless the final POST carries every value (then bound like any request) or the state is a broker workflow (ADR-0007) | Values are app-shown (R-3); use `confirm` |
| Form-encoded bodies | Strict grammar above; multipart unsupported | — |
| Free text, file content | `free` with justification, or `exact` by SHA-256 of the field | As published |
| Batches / lists | Unsupported in v1 | — |
| Values not in the request (currency) | `route:` constant or `state:` check | — |

### 6. Intent confirmation (R3-03, SI-20)

**What exact binding gives, and what it does not.** Exact binding prevents widening, redirection and
reuse of a grant after issue. It also gives correctness for honest apps. It does **not** bind intent:
under C, "the request the browser sent" is whatever app script sent. On routes without `confirm`, the
residual equals R-3.

**Which routes confirm.** Route-map operations marked `confirm: true` (or `confirm: {when: <predicate
over exact values>}`) require it. The demo uses `ledger.transfer` with `confirm` when
`amount_cents > threshold`. Below the threshold, the transfer destination is not intent-bound (R-3).
Recommendation, not yet decided: confirm every transfer to a destination this user has not previously
confirmed.

**Confirmation flow:**
1. The app page sends `POST /transfer`. The edge passes §3 and §5 and derives `(op, res, con)`.
2. The edge stores a **pending effect** `P{pid (128-bit random), ten, sub, wid, op, res, con, body,
   created, exp = 5 min}`. It does **not** forward the request yet. It answers `303` to
   `https://auth.<domain>/confirm/<pid>`; for `fetch` callers, it answers a JSON pointer to that URL,
   which the SDK opens as a top-level navigation or popup.
3. The confirm page on the auth origin renders the summary **from P only**:
   - operation, resource, amount with currency, destination identifier, and the account the user is
     acting as;
   - free text is escaped.

   The app cannot script or frame the page (separate origin, `frame-ancestors 'none'`, COOP, CSP).
4. On **Approve**, the edge requires a WebAuthn assertion with user verification. The challenge is
   `SHA-256("nodkey.confirm.v1" ‖ 0x00 ‖ pid ‖ canonical(op, res, con))`, and the credential must
   belong to `P.sub`. If the assertion fails, or the credential belongs to anyone else, the edge denies.
   This also defeats a session swap through a pre-set cookie (R3-07): the summary shows the swapped
   account, and the victim's passkey does not match it. The edge then marks P `CONFIRMED`.
5. The browser is redirected to `/.nodkey/continue/<pid>` on the app host, a gateway-reserved path
   that is not a mapped route. The edge requires:
   - the session's `sub` = `P.sub`;
   - P is `CONFIRMED`, unexpired and unused.

   The edge then asks the authority to sign a grant from P's values (TTL 30 s, from now), and forwards
   P's original request bytes plus `Nodkey-Grant` to the app. The app's response is the continuation
   page. P becomes `USED`.
6. Rejections: on **Reject** or expiry, P is deleted. Pending effects are rate-limited per subject.

**Display names** of destinations are not shown in v1 (identifiers only). A broker read for them is
open.

### 7. Grants (R3-04, AR-13)

- **Write grant:** single-use, one write operation, 30 s (ADR-0004). One write per request; **multi-effect
  writes per request are not supported in v1** (composites are a single typed operation or a workflow
  transition).
- **Read grant:** at most one per request, in addition to at most one write grant. It is bound to `(ten,
  sub, wid)` and a **route-declared set** of read operations, and is multi-use within 30 s. Each read
  operation is declared `read` and filters by grant-sourced `ten`, with ownership = `sub` evaluated by
  the broker on trusted rows. A read grant is never accepted by a write operation. Tenant-shared reads
  are future work.
- **Required ADR-0004 amendment** (not made here): a grant-kind field, `use` semantics for read grants,
  and an `ops` set.

### 8. Broker side

The broker sources `sub`/`ten` from the grant (AR-17) and checks `wid`, `aud`, time, `op` and params
against `res`/`con`. It then derives ownership, state and budgets in the transaction. Unmapped routes
get no grant. Phase 3 has **no grantless effects** (ADR-0009).

## Evidence

- Review 2026-10-25 (R3-01..11, fact-checks (a)–(c)).
- WebAuthn L3 RP ID and related-origins rules [F, per review].
- draft-ietf-httpbis-rfc6265bis-22 §4.1.3.2 and §5.7 (Internet-Draft).
- W3C Service Workers, Appendix A/B: `Service-Worker` request header [F; WebKit not confirmed].
- RFC 9113 §9.1.1 (connection coalescing).
- Research 04 §2.

## Consequences

- **Advantages:**
  - No reusable credential reaches the workload.
  - Grants cannot be widened or reused.
  - Intent is bound where `confirm` is set.
  - Attacker-byte parsing runs in a process that holds no secrets.
- **Drawbacks:**
  - Apps give up login, multipart on mapped routes, and app-side destination resolution.
  - Confirmation adds a user step.
  - The gateway is split into two processes.
- **Security:** residuals R-2..R-5, R-17 and R-18 (THREAT_MODEL).
- **Performance:** extra local hop; one signature per mapped request; a WebAuthn ceremony per
  confirmation [H, unmeasured].
- **Compatibility:**
  - Apps that rely on service workers are unsupported in v1.
  - The same-registrable-domain deployments carry R-18.

## Reversal / migration

- The IdP and built-in login are interchangeable behind the code flow in §2.
- `confirm` predicates and binding sources are route-map changes.
