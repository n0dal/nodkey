# Security Invariants

> [!IMPORTANT]
> Status: **DRAFT v0.1** (2026-10-24). These invariants are the project's non-negotiable security
> requirements. Changing one requires an accepted ADR. Implementation that cannot satisfy an
> invariant blocks the affected milestone; it does not justify reinterpreting the invariant.

## Terms

| Term | Meaning |
|---|---|
| **Workload** | The untrusted application process(es) and everything they can execute — including attacker code after compromise. |
| **Protected resource** | A resource whose access or mutation is a *protected effect* (database rows, ledger entries, secrets, external API calls with consequence). |
| **Enforcement boundary** | A mechanism the workload cannot alter: kernel-enforced isolation, or a separate process in a separate trust domain. |
| **Broker** | The trusted component that executes protected effects on the workload's behalf. |
| **Authority** | The trusted component(s) that issue authorization. May be co-located with the broker (see ADRs). |
| **Grant** | A signed, versioned authorization record issued by the Authority. |
| **Trusted fact** | A value the broker obtains from a trusted source (verified identity, broker-owned state), never from the workload. |
| **Deployment profile** | A documented configuration under which these invariants are claimed. Claims outside a profile are not made. |

## Scope assumption

All invariants are claimed **only** under a documented deployment profile and the threat model in
[`THREAT_MODEL.md`](THREAT_MODEL.md). They assume the host kernel, the container/VM runtime, the
broker, and the Authority are not compromised (attackers I and J are out of scope for v0).

## Invariants

Each invariant states the property and the observation that would **falsify** it. Every
invariant must eventually map to at least one automated test in [`TEST_EVIDENCE`](../STATUS.md#test-evidence).

### Containment

**SI-01 — No direct reach.** The workload has no network route, socket, file, or IPC path to any
protected resource except the broker's request interface.
*Falsified by:* any successful connection, read, or write from inside the workload to a protected
resource endpoint (DB port, secret file, metadata service, upstream API) other than via the broker.

**SI-02 — No credential custody.** No credential that grants access to a protected resource is
present in the workload's filesystem, environment, process memory, or reachable IPC.
*Falsified by:* recovering any such credential from inside the workload.

**SI-03 — No alternate path.** Every protected resource rejects connections that do not originate
from the broker (defense in depth beyond SI-01: network policy *and* resource-side authentication).
*Falsified by:* a protected resource accepting a request from any principal other than the broker.

**SI-04 — Signed is not trusted.** Artifact signature verification may gate *what runs*, but never
expands *what it may do*. A validly signed workload has exactly the authority of an unsigned one
under the same profile.
*Falsified by:* any capability that is conditioned on artifact signature validity alone.

### Authorization integrity

**SI-05 — No self-minting.** The workload cannot produce a grant the broker accepts. Signing keys
for grants never enter the workload's trust domain.
*Falsified by:* broker accepting any grant not produced by the Authority's key.

**SI-06 — Full binding.** A grant is accepted only for the exact (protocol version, issuer, audience,
workload identity, tenant, subject, operation, resource, constraints, validity window) it encodes.
*Falsified by:* a grant producing an effect where any bound field differs from the request.

**SI-07 — No broadening.** No transformation available to the workload (editing, re-encoding,
combining, attenuating) yields a grant authorizing a strictly larger set of effects.
*Falsified by:* any accepted grant whose effect set exceeds that of the grant(s) it was derived from.

**SI-08 — Default deny.** Missing, malformed, unparseable, unknown-version, unknown-algorithm,
unknown-critical-field, expired, not-yet-valid, revoked, or wrong-key grants are denied.
*Falsified by:* any effect executed under such a grant.

**SI-09 — At-most-once consumption.** A single-use grant or idempotency key produces its effect at
most once, including under concurrent submission, retries, broker restart, and replay.
*Falsified by:* two committed effects attributable to one single-use grant.

**SI-10 — Trusted facts only.** Authorization decisions use only trusted facts for ownership,
tenancy, and resource state. Values supplied by the workload are treated as *requests*, never as
*facts*.
*Falsified by:* a decision outcome that changes when the workload alters a claimed fact (e.g. an
`owner_id` field) without the underlying trusted state changing.

**SI-11 — Current state.** State-dependent preconditions are evaluated against current trusted state
atomically with effect execution (no time-of-check/time-of-use gap within the broker's transaction).
*Falsified by:* an effect committing while its precondition is false at commit time.

**SI-12 — Receipts are evidence, not authority.** An execution receipt never authorizes an effect by
itself; any workflow precondition it satisfies is re-checked against current trusted state.
*Falsified by:* an effect executed on receipt possession alone, or a receipt reused across workflow,
tenant, or resource.

### Policy and administration

**SI-13 — Policy is out of reach.** The workload cannot read secrets from, write to, or reload the
policy, key, or configuration stores used by the broker/Authority.
*Falsified by:* any workload-initiated change in policy, keys, or broker configuration.

**SI-14 — Independent administration.** Policy and key changes require an administrative credential
that is distinct from, and not derivable from, any workload or end-user credential.
*Falsified by:* an administrative change performed with workload or end-user authority.

### Failure behavior

**SI-15 — Fail closed.** If any component required for a decision (policy, key material, replay
store, state store) is unavailable, inconsistent, or errors, the effect is denied. Ambiguous outcomes
of external effects are recorded as *unknown* and are never retried as if they had failed without an
idempotency guarantee.
*Falsified by:* an effect executed while a required component was unavailable, or a duplicate external
effect caused by blind retry.

**SI-16 — Bounded broker interface.** The broker exposes only typed, declared operations. It never
accepts arbitrary SQL, arbitrary filesystem paths, arbitrary network destinations, or a
caller-selected credential.
*Falsified by:* any broker operation whose effect is determined by unconstrained caller-provided code,
query text, path, destination, or credential reference.

### Honesty

**SI-17 — Claims are tested.** Every security claim in public documentation names its deployment
profile and assumptions and links to a test or explicitly says *NOT TESTED*.
*Falsified by:* a public security claim without either.

## What these invariants do **not** promise

- They do not prevent code execution in the workload, nor make a compromised workload harmless.
- A compromised workload can still invoke every operation its current grants and policy allow, return
  false data to users, leak data it legitimately holds, and exhaust its own resources.
- They do not hold if the host kernel, container runtime, broker, or Authority is compromised.

## Traceability to the owner's initial invariants

| Owner # | Covered by |
|---|---|
| 1 | SI-01, SI-16 | 
| 2 | SI-05 |
| 3 | SI-13 |
| 4 | SI-02 |
| 5 | SI-01, SI-03 |
| 6 | SI-06 |
| 7 | SI-07 |
| 8 | SI-08 |
| 9 | SI-09 |
| 10 | SI-10, SI-11 |
| 11 | SI-15 |
| 12 | SI-03 |
| 13 | SI-04 |
| 14 | SI-14 |
| 15 | SI-17 |
| (new) | SI-12 receipts ≠ authority |
