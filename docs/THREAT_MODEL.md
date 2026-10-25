# Threat Model

> [!IMPORTANT]
> Status: **DRAFT v0.1** (2026-10-24), derived from ADR-0001…0008 (all *Proposed*). Nothing here is
> tested. Every claim is **NOT TESTED** until the corresponding evidence appears in
> [`STATUS.md`](../STATUS.md#test-evidence) (SI-17). Claims apply only under Deployment Profile P0
> or P1 ([ARCHITECTURE.md](ARCHITECTURE.md#deployment-profile-p0)).

## 1. Security goal

> Compromise of computation must not imply compromise of authority.

An attacker who achieves arbitrary code execution in the application workload gains **at most** the
authority described in §6 (residual risks). It does not gain database credentials, signing keys, a
network path to protected resources, the ability to mint or broaden grants, or the ability to change
policy. This is *containment of authority*, not prevention of compromise.

## 2. Attackers

| ID | Attacker | Scope (v0) | Rationale |
|---|---|---|---|
| A | Unauthenticated external party | **In scope** | Reaches only the gateway. Without a verified session the gateway issues no grant, so no user-scoped effect is possible. Their input still reaches the app, which is how they become C. |
| B | Authenticated malicious user | **In scope** | Can tamper with every request field (IDs, amounts, tenant). The broker derives subject/tenant from the grant and ownership/state from its own transaction (SI-10, SI-11), so tampering cannot exceed the user's policy. B *can* do anything policy permits them; that is not a PBE failure. |
| C | Arbitrary code execution in the app | **In scope (primary)** | Modelled as attacker-controlled PHP. Bounded by P0 isolation (SI-01..03, SI-13) and the broker interface (SI-05..16). |
| D | Read/write of app environment and memory | **In scope** | Subsumed by C. Implies D sees every grant, request body, and broker response passing through the app; P0 ensures no protected credential is there to find (SI-02). |
| E | Forge, replay, substitute, or escalate authorization | **In scope** | Signing keys are outside the workload (SI-05); strict verification and full binding (SI-06..08); single-use consumption (SI-09). |
| F | Races and concurrency | **In scope** | Consumption, state checks, and the effect share one DB transaction (SI-09, SI-11). Concurrency tests are required (02 §8 vectors 21–25). |
| G | Malicious or faulty external service | **Partially** | v0 uses a simulated ledger only. The external-effect state machine (ADR-0006) prevents duplicate effects from ambiguous responses; PBE cannot prevent an upstream from lying about an outcome, and broker-side parsing of upstream responses is TCB attack surface. |
| H | Compromised dependency or artifact | **Partially** | *In the app image:* in scope, equivalent to C (P0 assumes the app image may be malicious). *In TCB components* (broker crates, Cedar, nginx, Postgres images): out of scope for enforcement; mitigated only by digest pinning, dependency review, and SI-04 (a signature never grants authority). |
| I | Host, kernel, container runtime, or orchestration compromise | **Out of scope** | Breaks every invariant by construction (e.g. Docker socket access is host root). Kernel exploits *from* C are the main residual (§6, R-1); P1 (gVisor) reduces but does not remove this. |
| J | Broker or Authority (gateway) compromise | **Out of scope** | These are the TCB. Partial damage limitation is designed in (signer separated from HTTP parsing, per-operation DB roles) but not claimed. |

## 3. Protected assets

| Asset | Where it lives (P0) | Who can access | Mechanism preventing workload access |
|---|---|---|---|
| DB credentials (`pbe_broker` role) | Docker secret mounted only into `broker` and `db` | Broker process | Not mounted into `app`; app env empty; probe F-01 (canary search) |
| Grant signing key (Ed25519) | `authority` container only | Authority process | Separate container; no shared volume or network with `app`; SI-05 |
| Broker trust store (gateway public keys, kid → issuer) | Broker image or admin-only volume | Broker (read), operator (write) | Not mounted into `app`; read-only rootfs; probe F-04; SI-13 |
| Cedar policy set and schema | Broker image or admin-only volume | Broker (read), operator (write) | As above; SI-13, SI-14 |
| Route map (route → operation scope) | Authority config | Authority (read), operator (write) | Not mounted into `app`; SI-13 |
| User session credentials (cookies / tokens) | Browser; gateway session store | Gateway only | Gateway strips the session credential before forwarding to `app` (ADR-0003) |
| Protected data (orders, ledger, refunds) | Postgres on internal `data` network | Broker via `pbe_broker` role | `app` has `network_mode: none` (SI-01); `pg_hba` admits only the broker role (SI-03); probes N-02, D-01 |
| Replay / consumption store (`consumed_grant`) | Same Postgres DB as the effect | Broker | As protected data; written in the effect transaction (SI-09) |
| Workflow state | Broker-owned tables | Broker | As protected data; SI-12 |
| Audit log and receipts | Broker-owned tables / append-only log | Broker (write), auditor (read) | As protected data; receipts handed to the app are copies, never authority |
| Container control plane (`docker.sock`, containerd, Colima/Lima sockets) | Host / VM | Operator | Never mounted; probe F-02. Exposure = attacker I |
| Broker socket inode (`/run/pbe/broker.sock`) | Per-workload volume | That workload (connect only) | Mounted read-only into `app` so it cannot be unlinked or replaced; probe F-03 |

## 4. Trust boundaries

| ID | Boundary | Direction of distrust | Enforcement |
|---|---|---|---|
| TB-1 | Internet ↔ gateway | Client untrusted | TLS, session verification in the authority |
| TB-2 | Gateway ↔ app (FastCGI over UDS) | **Both ways**: app output (headers, bodies) is untrusted input to nginx | `fastcgi_ignore_headers X-Accel-Redirect`, no `proxy_pass` locations; nginx never holds the signing key |
| TB-3 | App ↔ broker (per-workload UDS) | App untrusted | Socket mount = workload identity; `SO_PEERCRED` UID check; strict grant verification; typed operations only |
| TB-4 | Broker ↔ DB (internal network) | DB trusts only the broker role | `pg_hba` + SCRAM; no other principal on `data` |
| TB-5 | Operator ↔ config/keys/policy | Workload and end users untrusted | Files not reachable from `app`; changes via deployment only (SI-14 gap, §6 R-9) |
| TB-6 | Containers ↔ host kernel/runtime | Containers untrusted | Namespaces, `cap_drop: ALL`, `no-new-privileges`, default seccomp, LSM; P1 adds gVisor |
| TB-7 | Broker ↔ external service (future) | Upstream untrusted | Typed adapter, configured destinations only (SI-16), UNKNOWN state (SI-15) |

## 5. Assumptions

1. Single Linux host or VM; kernel, `dockerd`/`containerd`/`runc` (or `runsc` for P1) uncompromised.
2. The operator deploys exactly the P0 Compose file and `verify` reports no FAIL.
3. Images are pinned by digest; the app image may be attacker-controlled.
4. Gateway (nginx + authority), broker, DB, and their keys/config are uncompromised (J out of scope).
5. Clocks on authority and broker are within the configured skew and the broker clock does not move
   backwards across the replay-retention window (ADR-0006, open).
6. The replay store is never restored from an older backup without the rotation procedure in ADR-0006.
7. Every protected effect the app needs is exposed as a typed broker operation; an app that keeps a
   direct DB credential is not contained (see Legacy Containment limits in ARCHITECTURE.md).
8. No other workload shares networks or volumes with `broker` or `db`; each workload runs under a
   distinct UID.

## 6. Residual risks

| ID | Risk | Status |
|---|---|---|
| R-1 | Host-kernel exploit from the app (shared kernel under runc) | Accepted for P0; P1 (gVisor) reduces |
| R-2 | **In-flight grant use.** A compromised app may use any grant issued for a request passing through it, once, within that grant's scope and constraint ceiling, before expiry (quantified in ADR-0003) | Accepted; bounded by TTL, ceiling, policy, budgets |
| R-3 | **Compromised origin drives the browser.** The app serves the HTML/JS that authenticated users run, so injected script can make a logged-in browser send *real* requests to any mapped route. The gateway sees a valid session and issues grants. Effective bound: anything in the user's policy, limited by budgets, for as long as a page is open | **Major.** Mitigated only by budgets and gateway-origin approval for high-value operations (not in v0) |
| R-4 | UI deception (user tricked into sending a real request) | Accepted; same mitigation as R-3 |
| R-5 | Read-side exfiltration of everything the broker returns to the app, and of all request data | Not claimed |
| R-6 | App lies to users, drops or delays requests (integrity of app output, DoS) | Not claimed |
| R-7 | Workload-only operations (no user subject) usable up to their budgets | Accepted; must be enumerated per deployment |
| R-8 | Route-map / canonicalization divergence between nginx and authority (OQ-08) | Open; strict single parser in authority, differential tests |
| R-9 | Administrative path is "operator edits files and redeploys"; SI-14 is satisfied only in the sense that host access is distinct from workload credentials | Open |
| R-10 | Broker defect bypasses policy (all adapters share one process and its credentials in v0) | Accepted for v0; per-operation DB roles, review, path to per-adapter processes (ADR-0002) |
| R-11 | Cedar error-skip semantics fail open if diagnostics are ignored | Mitigated by ADR-0005 adapter; must be tested |
| R-12 | Replay after replay-store restore or clock rollback | Open (ADR-0006) |
| R-13 | External effect already dispatched cannot be recalled on revocation | Accepted; compensation is workflow design |
| R-14 | Side channels and resource exhaustion against co-tenants | Not claimed; cgroups only |
| R-15 | Configuration drift (one added network, volume, or `privileged`) silently voids P0 | Mitigated by `verify` configuration checks (C-xx) |
