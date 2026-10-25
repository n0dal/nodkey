# Security Invariants

> [!IMPORTANT]
> Status: **DRAFT v0.3** (2026-10-25; see [Changelog](#changelog)). These invariants are the project's non-negotiable security
> requirements. Changing one requires an accepted ADR. Implementation that cannot satisfy an
> invariant blocks the affected milestone; it does not justify reinterpreting the invariant.

## Terms

| Term | Meaning |
|---|---|
| **Workload** | The untrusted application process(es) and everything they can execute — including attacker code after compromise. |
| **Protected resource** | A resource whose access or mutation is a *protected effect* (database rows, ledger entries, secrets, external API calls with consequence). |
| **Enforcement boundary** | A mechanism the workload cannot alter: kernel-enforced isolation, or a separate process in a separate trust domain. |
| **Broker** | The trusted component that executes protected effects on the workload's behalf. |
| **Gateway** | The trusted front (`gateway-edge`) that terminates TLS and user sessions, serves the auth origin, and maps each request once (ADR-0003). The `gateway-proxy` that speaks HTTP to the workload holds no secrets and is outside the TCB. |
| **Authority** | The trusted component(s) that sign grants: the gateway's signing authority process (ADR-0003). There is no other grant issuer in v0. Never co-located with code that parses workload output. |
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
parameters are bound to a value in the grant from a declared binding source (request path, query,
or body; route constant; or broker-checked trusted state), `bounded` to a ceiling, and `free` parameters are
justified and published as residuals (destination-like parameters are never `free`). Subject and
tenant are *sourced* from the verified grant; every other bound field is compared with an
independent trusted value (socket identity, broker id, clock, registry) or with the submitted request.
A *read grant* binds (tenant, subject, workload, declared set of read operations, validity window);
read operations filter by the grant's tenant and by subject ownership evaluated on trusted rows, and a
read grant is never accepted for a write operation.
*Falsified by:* a grant producing an effect where any bound field differs from the request, an
operation with an unclassified parameter being served, or a read grant authorizing a write or a read
of a row not owned by its subject.

**SI-07 — No broadening.** No transformation available to the workload (editing, re-encoding,
combining, attenuating) yields a grant authorizing a strictly larger set of effects.
*Falsified by:* any accepted grant whose effect set exceeds that of the grant(s) it was derived from.

**SI-08 — Default deny.** Missing, malformed, unparseable, unknown-version, unknown-algorithm,
unknown-critical-field, expired, not-yet-valid, revoked, or wrong-key grants are denied.
*Falsified by:* any effect executed under such a grant.

**SI-09 — At-most-once consumption.** A single-use (write) grant or idempotency key produces its
effect at most once, including under concurrent submission, retries, broker restart, and replay. A grant that
passed verification receives exactly one decision; a denied grant is consumed. Not claimed across a
restore of the replay store from backup or a broker clock rollback unless the restore and clock
procedures of ADR-0006 are followed. Read grants are multi-use within their validity window and are
outside this invariant (SI-06 bounds them).
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

**SI-18 — Credentials never enter the app origin.** End-user credential entry, enrollment,
recovery, and session establishment happen only on an origin the workload cannot serve content on,
and every session establishment requires a user ceremony there (no silent re-issue). Gateway-owned
cookies are `__Host-`, `HttpOnly`, `Secure`. Workload responses cannot set them; requests carrying more
than one gateway-named cookie are rejected; the workload cannot register a service worker on the app
origin. App-origin script *can* create a gateway-named cookie when none exists, so it can plant a
session the attacker already holds (session swap); this is a published residual, and confirmation
(SI-20) is bound to the subject's own passkey.
*Falsified by:* any end-user credential or session-establishing artifact being observable by
workload code (server-side or app-origin script); a session established without a user ceremony on
the auth origin; a workload response setting a gateway-owned cookie; a request with two gateway-named
cookies being accepted; or a service worker registered on the app origin.

**SI-19 — No undeclared grantless effect.** An effect without a verified grant presented at the time
is executed only for (a) `derived` workflow transitions whose authority is a consumed user grant
recorded on a broker-owned workflow row, with tenant, subject, resource, and parameters taken from
that row; or (b) `workload` operations of a workload whose tenant is fixed by configuration (broker
and gateway enforced), within a declared resource scope excluding user-owned rows, a fixed per-call
ceiling, and a locked count budget. Class (b) is forbidden for multi-tenant workloads. Phase 3
permits neither (ADR-0009).
*Falsified by:* any other effect without a verified grant; a `workload` operation in a multi-tenant
workload or touching a user-owned row; a `derived` transition taking any value from the workload.

**SI-20 — Confirmed intent.** For an operation the route map marks `confirm`, no grant is issued
unless the subject approved a summary of the exact bound values, rendered by the gateway on the auth
origin, with a user-verifying WebAuthn assertion whose challenge commits to those values; the grant
binds exactly the confirmed values.
*Falsified by:* a grant for a `confirm` operation without such an approval, or with any bound value
differing from the approved summary.

**SI-21 — Request provenance.** A write grant is issued only for a non-safe HTTP method with
`Sec-Fetch-Site: same-origin`, or, when that header is absent, an `Origin` exactly equal to the app
origin; requests with neither are denied. Read grants are never issued for non-same-origin requests other than
top-level navigations.
*Falsified by:* a write grant issued for a safe method, a cross-origin or same-site-sibling request,
or a request lacking both provenance headers.

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
| (new) | SI-20 confirmed intent (review R3-03) |
| (new) | SI-21 request provenance (review R3-01) |

## Changelog

- **v0.3 (2026-10-25):** Gateway term (edge/proxy); Authority = gateway signer only (scheduler
  removed); SI-06 binding sources and read grants; SI-09 limited to write grants; SI-18 reworded
  (enrollment/recovery, no silent re-issue, duplicate-cookie rejection, session-swap residual); SI-19
  rewritten (`derived` class, config-enforced tenancy, resource scope); new SI-20 (confirmed intent)
  and SI-21 (request provenance). Source: review 2026-10-25 (R3-01..07, R3-12..14). Rests on ADR-0003
  rev. 3 and ADR-0009 rev. 2, both *Proposed*; binding once accepted.

- **v0.2 (2026-10-24):** Added Gateway term; Authority redefined; scope assumption includes the
  gateway; SI-02 reworded (reusable/standing credentials, end-user credentials; grants by design);
  SI-06 parameter classification and sourced-vs-checked fields; SI-09 one decision per grant and
  restore/clock scope; SI-14 v0 note; new SI-18 and SI-19. Source: architecture review
  2026-10-24 (AR-01, 02, 04, 06, 11, 16, 17, 18). Rests on ADR-0003 rev. 2 and ADR-0009, which are
  still *Proposed*; per this document's rule these changes become binding when those ADRs are accepted.
- **v0.1 (2026-10-24):** Initial draft.
