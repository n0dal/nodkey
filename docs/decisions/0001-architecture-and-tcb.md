# ADR-0001: Architecture A (OS isolation + external broker) and the v0 TCB

- **Status:** Proposed
- **Date:** 2026-10-24
- **Invariants:** SI-01, SI-02, SI-03, SI-13, SI-17

## Problem

Choose the execution architecture for the PoC and Legacy Containment, and name the trusted computing
base (TCB) under which invariants are claimed.

## Evaluation criteria

Path containment (SI-01) for unmodified PHP; credential custody (SI-02); TCB size and scrutiny;
bypass resistance; operability on Colima and production Linux; verifiability by external probes.

## Alternatives considered

- **A. Conventional workload under OS isolation + separate broker.** Unmodified PHP-FPM in a
  hardened container; effects via a broker in another container.
- **B. Capability-native WASI/Wasmtime.** No ambient authority by construction, but no maintained
  PHP-on-WASI distribution with PDO and common extensions exists in 2026 (research 03 §3.1).
- **C. Hybrid** (A outside, Wasm inside). Two independent layers; highest operational cost.

## Decision

Adopt **Architecture A**, delivered as **Deployment Profile P0** (research 03 §6): PHP-FPM with
`network_mode: none`, read-only rootfs, `cap_drop: [ALL]`, `no-new-privileges`, default seccomp/LSM,
private IPC/PID, non-root UID. The workload's only channels are the FastCGI UDS to nginx and a
per-workload broker UDS (mounted read-only). The DB is on an internal network and accepts only the
broker role. **P1** = P0 + gVisor (`runsc`). Architecture B is a research track (Phase 7+), not a
PoC dependency.

**TCB (v0):** host kernel; container runtime (`dockerd`/`containerd`/`runc`, or `runsc` in P1);
gateway (nginx + authority logic); broker; protected DB; key, policy, and route-map files.

**Outside the TCB:** the app workload and everything it executes (PHP runtime, extensions, Composer
dependencies, PHP SDK); the browser and client code; any workflow orchestrator; logs and receipt
consumers; `verify` tooling (it reports, it does not enforce); image signatures (SI-04).

## Evidence

- `network_mode: none` removes gateway, DNS, ICC, and metadata reachability at once; `internal: true`
  networks do not (Docker docs; CVE-2024-29018) — research 03 §2.1.
- Per-workload pathname UDS mount authenticates by construction; abstract sockets have no permission
  model (`unix(7)`) — 03 §2.6.
- gVisor's threat model targets host-kernel exploits and states network policy must still be applied
  at the container level — 03 §2.4.

## Consequences
- **Advantages:** runs unmodified PHP; each P0 element maps to a falsifying probe; uses mature parts.
- **Drawbacks:** many configuration knobs; one Compose edit voids the profile (R-15).
- **Security:** shared-kernel escape under runc is the main residual (R-1). Any path to the container
  control plane breaks everything.
- **Performance:** runc ≈ native [H]; gVisor adds syscall/I/O overhead (unmeasured here).
- **Compatibility:** Linux only; Colima for macOS development; Kubernetes mapping deferred (03 §10).

## Architect objection

**1. The signing key must not live in the process that parses workload output.** "Gateway (nginx +
gateway/authority logic)" leaves the layout open. nginx parses FastCGI response headers and bodies
produced by the app (TB-2, attacker C). If grant signing runs inside nginx (module or script) or
shares its container, an nginx parsing bug reachable from the app yields the signing key, which lets
the attacker mint grants for **any** user, offline, until rotation. If the signer is a separate
process/container reachable only from nginx, an nginx compromise yields only the sessions and grants
of requests in flight. Evidence: privilege-separation lineage (OpenSSH privsep, Chromium broker;
research 01 §1) and 03's P0 sketch, which has no authority container at all. **Request:** amend the
decision to require a separate `authority` container that never receives traffic from the app.

**2. P0 does not deliver Legacy Containment for apps that need their DB.** With `network_mode: none`
the app has no DB route; a legacy app either moves effects behind the broker (Native mode) or needs a
different profile. This is not a reason to change A, but ARCHITECTURE.md must not claim P0 contains
unmodified legacy apps.

## Reversal / migration

Move to C by adding Wasm inside the P0 container for new modules; P1 is an additive runtime change.
