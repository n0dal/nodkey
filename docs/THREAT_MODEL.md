# Threat Model

> [!IMPORTANT]
> Status: **DRAFT v0.2** (2026-10-24), revised after the
> [architecture review](reviews/2026-10-24-architecture-review.md). Reflects ADR-0001…0009 and
> SECURITY_INVARIANTS v0.2. Nothing here is tested; every claim is **NOT TESTED** until evidence
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
| A | Unauthenticated external party | **In scope** | Reaches only the gateway; no session ⇒ no grant ⇒ no user-scoped effect. Once A achieves code execution in the app, A becomes C and R-3 applies. |
| B | Authenticated malicious user | **In scope** | Can tamper with every field; `sub`/`ten` come from the grant, ownership/state from the broker transaction (SI-10, SI-11). Limited to P(B). |
| C | Arbitrary code execution in the workload (PHP-FPM and nginx if used) | **In scope (primary)** | Bounded by P0 isolation, the gateway's origin/header controls (SI-18), and the broker interface (SI-05..16, 19). |
| D | Read/write of workload environment and memory | **In scope** | Subsumed by C; sees in-flight grants (bounded, R-2), never reusable credentials (SI-02). |
| E | Forge, replay, substitute, escalate authorization | **In scope** | Keys outside the workload; strict verification; exact binding; one decision per grant. |
| F | Races and concurrency | **In scope** | Consumption, locked budget counters, state checks, and effect in one transaction; fixed lock order (ADR-0006). |
| G | Malicious external service | **Partially** | v0 has no external adapter. The state machine and UNKNOWN precondition prevent duplicates; upstream lies about outcomes are not preventable. Per-adapter processes required first (ADR-0002). |
| H | Compromised dependency/artifact | **Partially** | In the workload: in scope (≡ C). In TCB crates/images: out of scope for enforcement; pinning, review, SI-04. |
| I | Host / kernel / runtime / orchestration compromise | **Out of scope** | Breaks every invariant. Kernel exploits *from* C are residual R-1. |
| J | Gateway, authority, scheduler, or broker compromise | **Out of scope** | TCB. Damage limitation (signer apart from parsers; per-adapter roles) is designed but not claimed. Note: the gateway parses workload responses, so C can *attack* it; a gateway bug reachable from the app yields live sessions (not the signing key). |

## 3. Protected assets

| Asset | Where (P0) | Who can access | Mechanism preventing workload access |
|---|---|---|---|
| DB credential | Secret mounted into `broker`, `db` | Broker | Not mounted in `app`; empty env; probe F-01 |
| Grant signing key | `authority` container | Authority | No network, no app traffic; UDS from gateway only (SI-05) |
| Scheduler signing key (ADR-0009) | `scheduler` container | Scheduler | As above |
| User credentials (passkeys/passwords) | Browser ↔ auth origin served by gateway | Gateway | Separate origin; `frame-ancestors 'none'`; workload cannot serve content there (SI-18) |
| Session cookie `__Host-nodkey_session` | Browser; gateway session store | Gateway | HttpOnly; never forwarded (header allowlist); app `Set-Cookie` for it dropped |
| Trust store, Cedar policy, route map | Broker / gateway images or admin-only volumes | Read by TCB; written by operator | Not mounted in `app`; read-only rootfs; F-04 (SI-13) |
| Protected data, consumption, budgets, workflow state, audit rows | Postgres on internal `data` | Broker role | `network_mode: none`; `pg_hba` broker-only (SI-01, SI-03) |
| Container control plane | Host / VM | Operator | Never mounted; F-02 (exposure = I) |
| Broker socket inode | Per-workload tmpfs volume | That workload (connect only) | Read-only mount; F-03 |

## 4. Trust boundaries

| ID | Boundary | Enforcement |
|---|---|---|
| TB-1 | Internet ↔ gateway (app origin and auth origin) | TLS; sessions; SI-18 controls |
| TB-2 | Gateway ↔ workload (HTTP over UDS) | Request header/cookie **allowlist**; grant only as `Nodkey-Grant`; response filtering (gateway-owned `Set-Cookie`, `Service-Worker-Allowed` dropped; HTML/JS `no-cache`); memory-safe parser |
| TB-3 | Workload ↔ broker (per-workload UDS) | Socket = identity; `SO_PEERCRED`; strict verification; typed operations |
| TB-4 | Gateway ↔ authority (UDS) | Authority accepts only the gateway socket |
| TB-5 | Broker ↔ DB | `pg_hba` + SCRAM |
| TB-6 | Operator ↔ config/keys/policy | Deployment only; no runtime admin interface (SI-14 v0 note) |
| TB-7 | Containers ↔ host | Namespaces, caps, seccomp, LSM; P1 gVisor; tmpfs `noexec` writable mounts; log and disk quotas |

## 5. Assumptions

1. Single Linux host/VM; kernel and runtime uncompromised.
2. Exactly the P0 Compose file is deployed and `verify` reports no FAIL.
3. Images digest-pinned; the workload image may be malicious.
4. Gateway, authority, scheduler, broker, DB, and their config uncompromised (J).
5. Authority/broker clocks within skew; broker high-water mark implemented before any SI-09 claim
   across clock rollback (ADR-0006).
6. DB restores follow the ADR-0006 runbook.
7. Every protected effect the app needs is a declared broker operation.
8. Distinct UID per workload; no other workload shares networks/volumes with TCB containers.
9. The app is not hosted on a subdomain of the auth host, and the passkey RP ID is the auth host.

## 6. Residual risks

**R-3 quantified (in-page abuse while a user is active).** Let a user *u* have a tab from the app
origin open while the workload is compromised. Injected script can make the browser send real
requests to any mapped route; the gateway issues grants as normal. Bound:

- *Who:* only users who load an app page during the compromise window. Service-worker registration is
  blocked and HTML/JS is served `no-cache`, so script stops when the tabs close or the app is fixed
  [H, NOT TESTED]. Residual persistence via storage the patched app itself reads (localStorage,
  IndexedDB) ends only after the `Clear-Site-Data` runbook.
- *How long:* while a tab is open, within the absolute session lifetime *L*. Script cannot renew a
  session: re-authentication needs the user on the auth origin.
- *How much:* any effect in P(u), each at most once per induced request, capped by locked budget
  counters. With fixed windows the worst case is 2× the limit across one boundary. Example: limits of
  $200/user/day and $5,000/tenant/day ⇒ at most $400 per user and $10,000 per tenant for a compromise
  spanning one day boundary; (k + 1) × limit over k boundaries.
- *What it is not:* no credential capture under passkeys, no use after the session ends, no other
  user's authority, no unmapped or undeclared operation.

| ID | Risk | Status |
|---|---|---|
| R-1 | Host-kernel exploit from the workload (runc) | Accepted for P0; P1 reduces |
| R-2 | In-flight grant: app executes exactly the user's request once within 30 s, or drops/delays it; `bounded`/`free` params per published table | Accepted |
| R-3 | In-page abuse while a user is active (quantified above) | **Major, accepted**; budgets + future gateway-origin approval for high-value ops |
| R-4 | UI deception; under the password profile, phishing on the app origin | Accepted; passkey profile removes credential phishing only |
| R-5 | Exfiltration of all data reaching the workload | Not claimed |
| R-6 | App lies, drops, delays (output integrity, DoS) | Not claimed |
| R-7 | `workload` operations in single-tenant workloads, up to declared ceilings | Accepted; enumerated (ADR-0009) |
| R-8 | Gateway parsing bug reachable from workload responses ⇒ live sessions | Accepted; memory-safe parser, fuzzing |
| R-9 | No runtime admin path; SI-14 met only via deployment access | Open |
| R-10 | Broker defect bypasses policy (single process in v0) | Accepted for v0 |
| R-11 | Policy proofs do not cover fact derivation | Tests required |
| R-12 | Replay across DB restore / clock rollback | Not claimed until ADR-0006 §8–9 implemented |
| R-13 | Dispatched external effect cannot be recalled | Accepted |
| R-14 | Side channels; residual resource exhaustion (CPU, broker fairness) | Partially bounded by cgroups, tmpfs caps, log quotas, per-workload broker limits |
| R-15 | Configuration drift voids P0 | `verify` C-xx checks |
| R-16 | Scheduler-issued grants for transitions whose precondition a user already created | Accepted (ADR-0009) |
