# Threat Model

> [!IMPORTANT]
> Status: **DRAFT v0.3** (2026-10-25), revised after the
> [architecture review](reviews/2026-10-24-architecture-review.md) and the
> [ADR-0003/0009 review](reviews/2026-10-25-adr-0003-0009-review.md). Reflects ADR-0001…0009
> (ADR-0003 rev. 3, ADR-0009 rev. 2) and SECURITY_INVARIANTS v0.3. Nothing here is tested; every claim is **NOT TESTED** until evidence
> appears in [`STATUS.md`](../STATUS.md#test-evidence) (SI-17). Claims apply only under P0/P1.

## 1. Security goal

> Compromise of computation must not imply compromise of authority.

An attacker with arbitrary code execution in the workload gains **at most** the authority in §6. It
does not gain DB credentials, signing keys, user credentials or sessions, a network path to protected
resources, the ability to mint or broaden grants, or the ability to change policy.

What it keeps: `network_mode: none` removes routes, **not exfiltration**. The workload returns
arbitrary bytes to any client (including attacker B), so everything that reaches it — request data,
single-use grants, broker responses — can be leaked. This is containment of authority, not prevention
of compromise or of data disclosure.

## 2. Attackers

| ID | Attacker | Scope (v0) | Rationale |
|---|---|---|---|
| A | Unauthenticated external party | **In scope** | Reaches only the gateway. Without a session there is no grant. Cross-site forgery against a victim's session is blocked by non-safe methods + fetch-metadata/Origin checks on write routes (SI-21) and by the bound login code flow (no login CSRF). Once A has code execution in the app, A becomes C. |
| B | Authenticated malicious user | **In scope** | Can tamper with every field; `sub`/`ten` come from the grant, ownership/state from the broker transaction (SI-10, SI-11). Limited to P(B). |
| C | Arbitrary code execution in the workload (PHP-FPM, nginx if used; equivalently a compromised `gateway-proxy`) | **In scope (primary)** | Bounded by P0 isolation, the gateway edge's origin/cookie/cache controls (SI-18, SI-21), confirmation on `confirm` routes (SI-20), and the broker interface (SI-05..16, 19). C also controls a same-site sibling app if one shares the registrable domain (R-18). |
| D | Read/write of workload environment and memory | **In scope** | Subsumed by C; sees in-flight grants (bounded, R-2), never reusable credentials (SI-02). |
| E | Forge, replay, substitute, escalate authorization | **In scope** | Keys outside the workload; strict verification; exact binding; one decision per grant. |
| F | Races and concurrency | **In scope** | Consumption, locked budget counters, state checks, and effect in one transaction; fixed lock order (ADR-0006). |
| G | Malicious external service | **Partially** | v0 has no external adapter. The state machine and UNKNOWN precondition prevent duplicates; upstream lies about outcomes are not preventable. Per-adapter processes required first (ADR-0002). |
| H | Compromised dependency/artifact | **Partially** | In the workload: in scope (≡ C). In TCB crates/images: out of scope for enforcement; pinning, review, SI-04. |
| I | Host / kernel / runtime / orchestration compromise | **Out of scope** | Breaks every invariant. Kernel exploits *from* C are residual R-1. |
| J | Gateway edge, authority, or broker compromise | **Out of scope** | TCB. Damage limitation is designed but not claimed: workload HTTP is parsed only by the secret-less `gateway-proxy`; the signer is separate, so a fixed edge ends the compromise (no key theft), though the authority signs whatever a compromised edge asks. |

## 3. Protected assets

| Asset | Where (P0) | Who can access | Mechanism preventing workload access |
|---|---|---|---|
| DB credential | Secret mounted into `broker`, `db` | Broker | Not mounted in `app`; empty env; probe F-01 |
| Grant signing key | `authority` container | Authority | No network, no app traffic; UDS from gateway only (SI-05) |
| User credentials, enrollment invitations, recovery codes | Browser ↔ auth origin (gateway edge or delegated IdP) | Edge / IdP | Separate origin; `frame-ancestors 'none'`, COOP, strict CSP; RP ID = auth host; workload cannot serve content there (SI-18) |
| Session cookie `__Host-nodkey_session`; login cookies | Browser; edge session store | Edge | HttpOnly; never forwarded; app `Set-Cookie` with gateway prefix dropped; duplicate gateway-named cookies rejected; fresh id at login |
| Pending effects (confirmation) | Edge store | Edge; approval needs the subject's passkey | Never forwarded until confirmed; 128-bit id; 5 min expiry (SI-20) |
| Trust store, Cedar policy, route map | Broker / gateway images or admin-only volumes | Read by TCB; written by operator | Not mounted in `app`; read-only rootfs; F-04 (SI-13) |
| Protected data, consumption, budgets, workflow state, audit rows | Postgres on internal `data` | Broker role | `network_mode: none`; `pg_hba` broker-only (SI-01, SI-03) |
| Container control plane | Host / VM | Operator | Never mounted; F-02 (exposure = I) |
| Broker socket inode | Per-workload tmpfs volume | That workload (connect only) | Read-only mount; F-03 |

## 4. Trust boundaries

| ID | Boundary | Enforcement |
|---|---|---|
| TB-1 | Internet ↔ gateway (app origin and auth origin) | TLS; sessions; SI-18 controls |
| TB-2 | Edge ↔ `gateway-proxy` ↔ workload | Proxy (no secrets) does strict HTTP/1.1 framing, one request per connection, no upgrades/1xx/trailers; edge applies request allowlist, `Service-Worker` rejection, app-cookie `Set-Cookie` allowlist, `no-store` on every response (hash-verified static exceptions), `nosniff` |
| TB-3 | Workload ↔ broker (per-workload UDS) | Socket = identity; `SO_PEERCRED`; strict verification; typed operations |
| TB-4 | Gateway ↔ authority (UDS) | Authority accepts only the gateway socket |
| TB-5 | Broker ↔ DB | `pg_hba` + SCRAM |
| TB-6 | Operator ↔ config/keys/policy | Deployment only; no runtime admin interface (SI-14 v0 note) |
| TB-7 | Containers ↔ host | Namespaces, caps, seccomp, LSM; P1 gVisor; tmpfs `noexec` writable mounts; log and disk quotas |

## 5. Assumptions

1. Single Linux host/VM; kernel and runtime uncompromised.
2. Exactly the P0 Compose file is deployed and `verify` reports no FAIL.
3. Images digest-pinned; the workload image may be malicious.
4. Gateway edge, authority, broker, DB, and their config uncompromised (J).
5. Authority/broker clocks within skew; broker high-water mark implemented before any SI-09 claim
   across clock rollback (ADR-0006).
6. DB restores follow the ADR-0006 runbook.
7. Every protected effect the app needs is a declared broker operation.
8. Distinct UID per workload; no other workload shares networks/volumes with TCB containers.
9. The app is not hosted on a subdomain of the auth host; the passkey RP ID is exactly the auth host;
   no related-origins list includes the app. Recommended: the app origin has its own registrable
   domain (otherwise R-18).
10. Browsers send `Service-Worker` on service-worker script fetches (verified for Chromium and Firefox
    per review; **WebKit not confirmed**) and honour `__Host-`, `SameSite`, and fetch metadata.

## 6. Residual risks

**R-3 quantified (in-page abuse while a user is active).** A user *u* loads a page from the app
origin while the workload is compromised. Injected script makes the browser send real requests; the
edge issues grants for any non-`confirm` mapped route. Exact binding does **not** help here: the
"request" is whatever script sent (ADR-0003 §6). Bound:

- *Who:* users who load an app page during the compromise window. No service worker can be
  registered and every app response is `no-store`, so script stops when tabs close or the app is
  fixed [H, NOT TESTED; WebKit unverified]. Persistence via storage the patched app reads ends with
  the `Clear-Site-Data` runbook (cache, storage, cookies, plus session revocation).
- *How long:* while a tab is open, extended slightly by popunders opened on a user click and
  `keepalive` requests at unload, and never beyond the session's absolute lifetime *L* (default 12 h).
  The idle timeout (30 min) does not bound C, because script keeps it alive. Script cannot renew or
  re-establish a session: every establishment needs a user-verifying passkey ceremony on the auth
  origin.
- *How much:* any non-`confirm` effect in P(u), each once per induced request, capped by locked budget
  counters (2× the limit across one fixed-window boundary). Example: $200/user/day and
  $5,000/tenant/day ⇒ ≤ $400 per user, ≤ $10,000 per tenant for a compromise spanning one boundary.
  `confirm` effects need the user to approve an auth-origin summary with their passkey; C can only
  *request* them (and deceive the user into approving, R-4).
- *Reads:* everything u's read grants cover (R-5).
- *What it is not:* no credential capture under passkeys, no use after the session ends, no other
  user's authority, no unmapped or undeclared operation.

| ID | Risk | Status |
|---|---|---|
| R-1 | Host-kernel exploit from the workload (runc) | Accepted for P0; P1 reduces |
| R-2 | In-flight grant: the app executes the request the browser sent, once, within 30 s, or drops/delays it; `bounded`/`free` params per published table. Under C this is a subset of R-3 | Accepted |
| R-3 | In-page abuse while a user is active (quantified above) | **Major, accepted**; budgets; `confirm` for high-value ops |
| R-4 | UI deception, including deceiving the user into approving a `confirm` summary; phishing of recovery codes (and of passwords under the password profile) on the app origin | Accepted; recovery only on auth origin, revocation and notification on recovery |
| R-5 | Exfiltration of all data reaching the workload, including everything the active user's read grants cover | Not claimed |
| R-6 | App lies, drops, delays (output integrity, DoS) | Not claimed |
| R-7 | Phase 5: `workload` operations affect any non-user-owned in-scope row of the fixed tenant up to ceilings and count budget; `derived` transitions run at a time and choice the workload selects among declared follow-ons | Accepted; enumerated (ADR-0009). Phase 3: none exist |
| R-8 | Edge logic bug reachable through the proxy's structured responses ⇒ live sessions; a proxy compromise ≡ C | Accepted; secret-less proxy parses HTTP, edge parses only length-prefixed structure, fuzzing |
| R-9 | No runtime admin path; SI-14 met only via deployment access | Open |
| R-10 | Broker defect bypasses policy (single process in v0) | Accepted for v0 |
| R-11 | Policy proofs do not cover fact derivation | Tests required |
| R-12 | Replay across DB restore / clock rollback | Not claimed until ADR-0006 §8–9 implemented |
| R-13 | Dispatched external effect cannot be recalled | Accepted |
| R-14 | Side channels; residual resource exhaustion (CPU, broker fairness) | Partially bounded by cgroups, tmpfs caps, log quotas, per-workload broker limits |
| R-15 | Configuration drift voids P0 | `verify` C-xx checks |
| R-16 | Below-threshold `ledger.transfer` (no `confirm`): destination is not intent-bound | Accepted; recommendation to confirm new destinations is open |
| R-17 | Session swap: when the victim has no session, app script plants a `__Host-nodkey_session` value the attacker holds; the victim acts in the attacker's account | Accepted; low authority gain; confirm pages show the account and require the subject's passkey |
| R-18 | Same-site sibling (shared registrable domain) compromised: can send credentialed requests; write grants still blocked by SI-21; read grants only for its top-level navigations, whose output goes to the victim's own browser | Accepted; recommend a dedicated registrable domain |
| R-19 | WebKit `Service-Worker` header and HTTP-cache satisfaction of SW updates unverified | Open; browser spike before any SI-18 claim |
