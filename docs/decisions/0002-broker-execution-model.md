# ADR-0002: Broker execution model

- **Status:** Proposed
- **Date:** 2026-10-24
- **Invariants:** SI-02, SI-03, SI-06, SI-15, SI-16

## Problem

Define what the broker exposes, how it identifies its caller, and its process structure.

## Evaluation criteria

Bounded interface (SI-16); caller identity the workload cannot choose; credential custody;
reviewable size; a path to stronger internal separation.

## Alternatives considered

- **Credential injector / protocol passthrough** (Secretless, PgBouncer/ProxySQL, Envoy injector):
  forwards SQL or HTTP; fails SI-16 (research 01 §2).
- **Generic query API** (PostgREST): violates SI-16 unless restricted to RPC functions; caller
  typically mints or forwards the JWT.
- **Typed-operation broker** (Chromium/privsep model): declared operations with schemas.
- Caller identity via **mTLS/SPIFFE SVID** vs **per-workload UDS**: an in-workload key is stealable by
  attacker D and adds PKI to the TCB with no single-host gain (03 §2.6, 02 §3.3).

## Decision

1. A Rust broker exposes **only typed, declared operations** (operation id + schema version →
   typed request struct, resource-binding rules, preconditions, idempotency semantics). No arbitrary
   SQL, paths, destinations, or caller-selected credentials (SI-16). Unknown operations, unknown
   fields, and schema mismatches are denied.
2. The broker **holds all DB credentials**; none enter the workload.
3. **Workload identity = the per-workload socket the connection arrived on** (one listener per
   socket, mapped in broker config to a `wid`). `SO_PEERCRED` UID is a secondary check and must equal
   the UID registered for that `wid`; mismatch ⇒ deny.
4. **v0: single process**, adapters as Rust modules behind one operation registry. Documented path to
   **per-adapter processes**: each adapter becomes a separate process with its own DB role and
   credentials, the front process keeping only verification, policy, and dispatch.

## Evidence

- Chromium sandbox: "assume sandboxed code is malicious"; broker evaluates forwarded calls against
  policy (01 §1). OpenSSH privsep narrow monitor RPC.
- `SO_PEERCRED` returns credentials at `connect` time and is translated through user namespaces; it
  cannot name the container (unix(7); 03 §2.6). Hence socket-as-identity is primary.

## Consequences
- **Advantages:** small, auditable interface; identity without keys in the workload.
- **Drawbacks:** each new effect needs an adapter and schema (deliberate friction).
- **Security:** in v0 a memory-safety or logic bug in any adapter exposes every credential the
  process holds (R-10). Per-operation DB roles limit logic bugs only.
- **Performance:** one UDS round trip plus one DB transaction per effect.
- **Compatibility:** UDS identity is single-host; multi-host needs mTLS with keys held outside the
  workload (sidecar), a separate profile.

## Architect notes (not objections)

- `SO_PEERCRED` adds value only if **each workload runs under a distinct UID**; P0 must require it
  (THREAT_MODEL assumption 8). Without user-namespace remapping, container UIDs are host UIDs and
  could collide with other host processes.
- The broker must create each socket in a volume the matching workload mounts read-only, and must
  refuse to start if the socket path already exists with unexpected ownership.
- The per-adapter split should be triggered by the first adapter that talks to an external service
  (attacker G parsing surface), not deferred to Phase 8.

## Reversal / migration

Splitting adapters into processes changes internal IPC only; the workload-facing protocol is
unchanged.
