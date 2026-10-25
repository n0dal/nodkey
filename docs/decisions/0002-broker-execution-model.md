# ADR-0002: Broker execution model (rev. 2)

- **Status:** Proposed — review verdict "accept with changes"; changes applied, but AR-14 requires
  OQ-01 to be closed (decision on whether the PostgREST baseline suffices for internal-DB effects).
- **Date:** 2026-10-24
- **Invariants:** SI-02, SI-03, SI-06, SI-15, SI-16, SI-19

## Problem

Define what the broker exposes, how it identifies its caller, and its process structure.

## Evaluation criteria

Bounded interface (SI-16); caller identity the workload cannot choose; credential custody;
reviewable size; path to stronger internal separation.

## Alternatives considered

- **Credential injector / passthrough** (Secretless, ProxySQL, Envoy injector): fails SI-16.
- **PostgREST RPC-only + RLS baseline (AR-14).** App under P0 reaches only PostgREST; API schema
  exposes only `SECURITY DEFINER` functions; RLS on tenant; gateway-signed asymmetric JWT with `sub`,
  `ten`, `op`, exact parameters, `jti`; functions compare claims to arguments and insert `jti` in the
  same transaction. **Matches** SI-01..03, 05, 06, 09, 10, 11, 16 for internal-DB effects, with less new
  TCB code. **Nodkey is materially better only in:** a single-shape memory-safe grant verifier instead of
  a general JOSE stack (RFC 8725 classes); per-socket workload identity across several workloads; the
  external-effect state machine (no transactional idempotent external calls in Postgres); analyzable
  policy (Cedar/symcc) separate from effect code. It shares AR-01..03 and AR-05 unchanged (gateway and
  budget issues). **Consequence:** Nodkey's distinct value is in the gateway binding, external effects,
  and multi-workload identity; the baseline is to be built as a Phase 2/3 test comparator.
- **Caller identity via mTLS/SPIFFE:** in-workload key stealable by D; no single-host gain.

## Decision

1. A Rust broker exposes **only typed, declared operations**: operation id + schema version, typed
   request, per-parameter binding class `exact | bounded | free` (ADR-0003), required authority
   (`user_grant | read | derived | workload`, ADR-0003 §7, ADR-0009), preconditions, idempotency semantics.
   Unknown operations or fields ⇒ deny. Unclassified parameters, or a non-`user_grant` operation not
   listed in config, are **startup errors** (SI-19).
2. The broker holds all DB credentials.
3. **Workload identity = the per-workload socket** the connection arrived on; `SO_PEERCRED` UID must
   equal the UID registered for that `wid` (workloads have distinct UIDs). The gateway gets a separate
   socket whose only operation is `revoke(scope, before)` (ADR-0006).
4. **Fairness:** per-workload connection and in-flight limits so one workload cannot starve others.
5. **v0: single process**, adapters as modules. Per-adapter processes (own DB role/credential) are
   required before the first adapter that calls an external service (attacker G parsing surface).

## Evidence

Chromium sandbox and OpenSSH privsep (research 01 §1); `unix(7)` `SO_PEERCRED` semantics (03 §2.6);
PostgREST authorization docs (01 §6); review AR-06, AR-14, AR-20.

## Consequences
- **Advantages:** small, auditable interface; identity without keys in the workload.
- **Drawbacks:** every effect needs a declared adapter; overlap with the PostgREST baseline for
  internal-DB effects must be justified by tests, not asserted.
- **Security:** in v0 any adapter bug exposes every credential the process holds (R-10).
- **Performance:** one UDS round trip plus one transaction per effect.
- **Compatibility:** UDS identity is single-host; multi-host needs a separate mTLS profile with keys
  held outside the workload.

## Reversal / migration

Adapter split changes internal IPC only. If OQ-01 concludes the baseline suffices for internal
effects, the broker may delegate those to it while keeping external-effect adapters.
