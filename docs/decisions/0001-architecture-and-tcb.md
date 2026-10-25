# ADR-0001: Architecture A (OS isolation + external broker) and the v0 TCB (rev. 2)

- **Status:** Proposed — review verdict "accept with changes"; changes applied, but AR-14 requires
  OQ-01 (is the PostgREST RPC-only + RLS baseline sufficient?) to be closed before acceptance.
- **Date:** 2026-10-24
- **Invariants:** SI-01, SI-02, SI-03, SI-13, SI-17, SI-18

## Problem

Choose the execution architecture for the PoC and name the trusted computing base (TCB) under which
invariants are claimed.

## Evaluation criteria

Path containment (SI-01) for unmodified PHP; credential custody (SI-02); TCB size and memory safety
of attacker-facing parsers; bypass resistance; operability on Colima and Linux; verifiability.

## Alternatives considered

- **A.** Conventional workload under OS isolation + separate broker.
- **B.** Capability-native WASI — no maintained PHP-on-WASI distribution (research 03 §3.1).
- **C.** Hybrid — two layers, highest cost.
- **Baseline for comparison (AR-14):** A's isolation + PostgREST RPC-only + RLS with a gateway-signed
  asymmetric JWT. Compared in ADR-0002.

## Decision

Adopt **Architecture A** as **Deployment Profile P0**, five trusted/untrusted roles:

| Container | Domain | Network | Holds |
|---|---|---|---|
| `gateway` (Rust) | Trusted | `edge` only (published port) | TLS key, session store, route map |
| `authority` (Rust) | Trusted | none; UDS from gateway only | Grant signing key |
| `app` (PHP-FPM; optional untrusted nginx in a second container) | **Untrusted** | `network_mode: none` | nothing |
| `broker` (Rust) | Trusted | internal `data` | DB credential, trust store, policy |
| `db` (Postgres) | Trusted resource | internal `data` | data; accepts only the broker role |

Workload hardening per research 03 §6: read-only rootfs, `cap_drop: [ALL]`, `no-new-privileges`,
default seccomp/LSM, private IPC/PID, distinct non-root UID, empty environment. The workload's only
channels: the gateway→app UDS and its per-workload broker UDS (read-only mount). All writable
workload mounts are tmpfs with `noexec,nosuid,nodev` and a size cap, including the socket volumes
(AR-12); `app` uses a log driver with `max-size`/`max-file`; DB storage is on a filesystem the workload
cannot fill. **P1** = P0 + gVisor for `app`. WASI is a research track.

**TCB (v0):** host kernel; container runtime; gateway; authority; broker; DB; key, policy, and
route-map files.

**Outside the TCB:** the workload and everything in it (PHP, extensions, Composer packages, PHP SDK,
nginx if used); browser and client code; any workflow orchestrator; container logs (never audit
evidence, AR-19); `verify` tooling; image signatures (SI-04).

## Evidence

- `network_mode: none` vs `internal: true` (Docker docs; CVE-2024-29018) — research 03 §2.1.
- Pathname UDS mount as identity; abstract sockets lack permissions (`unix(7)`) — 03 §2.6.
- gVisor targets host-kernel exploits; network rules still apply — 03 §2.4.
- Review AR-03: removing nginx from the TCB leaves only memory-safe code parsing app output.

## Consequences
- **Advantages:** unmodified PHP; every element maps to a falsifying probe.
- **Drawbacks:** five containers (research 03 §8's "four" is superseded); configuration drift voids
  the profile (R-15).
- **Security:** shared-kernel escape is the main residual (R-1); gateway parses app responses
  (memory-safe) and holds sessions.
- **Performance:** one extra proxy hop [H, unmeasured].
- **Compatibility:** Linux only; Colima for development.

## Resolved objections (rev. 1)

1. *Separate signer* — adopted (authority container). 2. *Legacy Containment* — P0 does not contain
an unmodified app that needs its own DB; stated in ARCHITECTURE §6.

## Reversal / migration

C by adding Wasm inside `app`; P1 is additive.
