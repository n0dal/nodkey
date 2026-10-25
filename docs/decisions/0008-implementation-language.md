# ADR-0008: Rust for trusted components; thin untrusted PHP SDK

- **Status:** Proposed
- **Date:** 2026-10-24
- **Invariants:** SI-02, SI-05, SI-08, SI-16

## Problem

Choose implementation languages for TCB components (authority, broker, `verify` tooling) and the
first application integration.

## Evaluation criteria

Memory safety in parsers of untrusted input; availability of maintained crypto, CBOR, Cedar, and
Postgres libraries; reviewability; small runtime; language-neutral protocol.

## Alternatives considered

- **Go:** memory-safe, mature ecosystem (OPA, SPIRE); Cedar is not native; GC runtime.
- **C/C++:** no memory safety for parsers of attacker input; rejected for new TCB code.
- **PHP for broker logic:** shares the language and possibly libraries of the untrusted workload;
  no benefit; rejected.
- **Rust:** memory-safe without GC; native `cedar-policy`, `ed25519-dalek`, CBOR crates, Postgres
  drivers.

## Decision

1. **Authority and broker in Rust.** `unsafe` forbidden in PBE crates (`#![forbid(unsafe_code)]`)
   except in a reviewed, isolated module if ever required. Dependencies pinned via `Cargo.lock`,
   reviewed with `cargo audit`/`cargo deny`; minimal feature sets.
2. **PHP SDK is a thin, untrusted client:** connects to `/run/pbe/broker.sock`, serializes typed
   requests, passes grants as opaque length-capped strings, never parses or validates grants, holds
   no keys. Nothing the SDK does counts toward any invariant.
3. The wire protocol is specified independently of both languages; a second-language SDK (Phase 7)
   must need no broker change.

## Evidence

Research 02 §3.1 (crate maturity observations); research 04 §3.2 (`cedar-policy` native Rust);
research 01 §5 item 5 (same-process permissions are not a boundary).

## Consequences
- **Advantages:** memory safety for every parser of untrusted bytes in the TCB; direct use of the
  chosen libraries.
- **Drawbacks:** async runtime and dependency tree enter the TCB (attacker H on TCB is out of scope
  but real); some crates are pre-1.0 (`coset`) or slow-moving (`ciborium`).
- **Security:** memory safety does not prevent logic errors; review and adversarial tests remain the
  primary assurance.
- **Performance:** native code; no GC pauses.
- **Compatibility:** PHP integration is a client library only; the framework does not depend on PHP.

## Reversal / migration

Components communicate over specified protocols; any component can be reimplemented in another
memory-safe language without changing the others.
