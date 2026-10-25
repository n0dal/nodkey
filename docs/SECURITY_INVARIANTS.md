# Security Invariants

> [!IMPORTANT]
> Status: **DRAFT v0.2** (2026-10-24; see [Changelog](#changelog)). These invariants are the project's non-negotiable security
> requirements. Changing one requires an accepted ADR. Implementation that cannot satisfy an
> invariant blocks the affected milestone; it does not justify reinterpreting the invariant.

## Terms

| Term | Meaning |
|---|---|
| **Workload** | The untrusted application process(es) and everything they can execute — including attacker code after compromise. |
| **Protected resource** | A resource whose access or mutation is a *protected effect* (database rows, ledger entries, secrets, external API calls with consequence). |
| **Enforcement boundary** | A mechanism the workload cannot alter: kernel-enforced isolation, or a separate process in a separate trust domain. |
| **Broker** | The trusted component that executes protected effects on the workload's behalf. |
| **Gateway** | The trusted front that terminates TLS and user sessions, serves the auth origin, and parses each request once (ADR-0003). |
| **Authority** | The trusted component(s) that sign grants: the gateway's signing authority process and, for background steps, the trusted scheduler (ADR-0003, ADR-0009). Never co-located with code that parses workload output. |
| **Grant** | A signed, versioned authorization record issued by the Authority. |
| **Trusted fact** | A value the broker obtains from a trusted source (verified identity, broker-owned state), never from the workload. |
| **Deployment profile** | A documented configuration under which these invariants are claimed. Claims outside a profile are not made. |

## Scope assumption

All invariants are claimed **only** under a documented deployment profile and the threat model in
[`THREAT_MODEL.md`](THREAT_MODEL.md). They assume the host kernel, the container/VM runtime, the
gateway, the broker, and the Authority are not compromised (attackers I and J are out of scope for v0).

## Invariants

Each invariant states the property and the observation that would **falsify** it. Every
invariant must eventually map to at least one automated test in [`TEST_EVIDENCE`](../STATUS.md#test-evidence).

### Containment

**SI-01 — No direct reach.** The workload has no network route, socket, file, or IPC path to any
protected resource except the broker's request interface.
*Falsified by:* any successful connection, read, or write from inside the workload to a protected
resource endpoint (DB port, secret file, metadata service, upstream API) other than via the broker.

**SI-02 — No credential custody.** No *reusable or standing* credential that grants access to a
protected resource — including resource credentials (DB passwords, API keys), end-user credentials
(passwords, passkey assertions), session cookies, and refresh tokens — is present in the workload's
filesystem, environment, process memory, or reachable IPC. Single-use grants are present by design;
their authority is bounded by SI-06..SI-09.
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
Every operation parameter is classified `exact`, `bounded`, or `free` in its declaration; `exact`
parameters are bound to a value in the grant, `bounded` to a ceiling, and `free` parameters are
justified and published as residuals (destination-like parameters are never `free`). Subject and
tenant are *sourced* from the verified grant; every other bound field is compared with an
independent trusted value (socket identity, broker id, clock, registry) or with the submitted request.
*Falsified by:* a grant producing an effect where any bound field differs from the request, or an
operation with an unclassified parameter being served.

**SI-07 — No broadening.** No transformation available to the workload (editing, re-encoding,
combining, attenuating) yields a grant authorizing a strictly larger set of effects.
*Falsified by:* any accepted grant whose effect set exceeds that of the grant(s) it was derived from.

**SI-08 — Default deny.** Missing, malformed, unparseable, unknown-version, unknown-algorithm,
unknown-critical-field, expired, not-yet-valid, revoked, or wrong-key grants are denied.
*Falsified by:* any effect executed under such a grant.

**SI-09 — At-most-once consumption.** A single-use grant or idempotency key produces its effect at
most once, including under concurrent submission, retries, broker restart, and replay. A grant that
passed verification receives exactly one decision; a denied grant is consumed. Not claimed across a
restore of the replay store from backup or a broker clock rollback unless the restore and clock
procedures of ADR-0006 are followed.
*Falsified by:* two committed effects attributable to one single-use grant, or a verified-and-denied
grant later producing an effect.

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
*v0 note:* there is no runtime administrative interface; changes are made only through deployment
configuration by the operator (host access). The gateway's revoke-only broker socket can only narrow
authority.

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

### Edge and authority sources

**SI-18 — Credentials never enter the app origin.** End-user credential entry and session
establishment happen only on an origin the workload cannot serve content on. Gateway-owned cookies
are `__Host-`, `HttpOnly`, `Secure`; workload responses cannot set them, and the workload cannot
register a service worker on the app origin.
*Falsified by:* any end-user credential or session-establishing artifact being observable by
workload code (server-side or script on the app origin), or a workload response setting a
gateway-owned cookie or registering a service worker.

**SI-19 — No undeclared grantless effect.** The broker executes an effect without a verified grant
only for operations explicitly declared `workload` in its configuration, only for single-tenant
workloads, and only within a fixed declared ceiling and locked budget. Background steps use grants
from the trusted scheduler derived from broker state (ADR-0009).
*Falsified by:* an effect without a verified grant for any other operation, or any grantless effect
in a multi-tenant workload.

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
| (new) | SI-18 credentials off the app origin (review AR-01/02) |
| (new) | SI-19 no undeclared grantless effect (review AR-06) |

## Changelog

- **v0.2 (2026-10-24):** Added Gateway term; Authority redefined; scope assumption includes the
  gateway; SI-02 reworded (reusable/standing credentials, end-user credentials; grants by design);
  SI-06 parameter classification and sourced-vs-checked fields; SI-09 one decision per grant and
  restore/clock scope; SI-14 v0 note; new SI-18 and SI-19. Source: architecture review
  2026-10-24 (AR-01, 02, 04, 06, 11, 16, 17, 18). Rests on ADR-0003 rev. 2 and ADR-0009, which are
  still *Proposed*; per this document's rule these changes become binding when those ADRs are accepted.
- **v0.1 (2026-10-24):** Initial draft.
