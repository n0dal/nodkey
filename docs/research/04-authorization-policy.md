# Research Note 04 — Authorization and Policy

> [!NOTE]
> Status: **research note, 2026-10-24**. Ranks below accepted ADRs and specs. No ADR has been
> accepted yet, so nothing here is a decision. Markers: **[F]** means an established fact with a
> cited primary source. **[H]** means a hypothesis or design proposal, untested in PBE. **[A]** means
> an assumption that a deployment profile has to state.

Scope: open question OQ-04 and research questions Q3, Q7, Q8, Q9 and Q13 from the owner directive.
Invariants in play: SI-05, SI-06, SI-08, SI-09, SI-10, SI-11, SI-13, SI-14, SI-15, SI-16.

## 1. The core problem

The broker must decide whether to run a protected effect that a possibly compromised workload
(attackers C and D) asks for. The workload can lie about who the user is, who owns a resource,
what state the resource is in, and what the user meant to do. SI-10 says a decision may use only
**trusted facts**. Any field the workload supplies is a *request* and never a *fact*.

That leaves three separate questions, and each needs its own trusted source:

1. **Subject.** Which end user (if any) is behind this request, and how strongly were they
   authenticated? See section 2.
2. **Permission.** Given trusted facts about the subject, resource and state, does policy permit
   the operation? See sections 3 and 4.
3. **Atomicity.** Do those facts still hold when the effect commits? See section 4.

## 2. Where trusted end-user identity comes from (OQ-04, Q3)

### 2.1 Options evaluated

**(a) The app forwards the user's session cookie or OIDC token to the broker, and the broker
verifies it.** The broker can check the signature and expiry of an OIDC ID or access token
[F: OpenID Connect Core 1.0 §3.1.3.7], or look up an opaque session in a session store. The
weakness is that the app *holds a bearer credential*. A bearer token lets anyone who has it use it
[F: RFC 6750 §1.2]. A compromised app can therefore replay the token with any parameters, as often
as it likes, until the token expires or is revoked, and that includes after the user has left. This
proves identity and says nothing about intent. **Rejected as the primary design.** It is still
useful as a fallback inside a profile that states this residual openly.

**(b) A trusted gateway terminates TLS and the session, then attests to the broker.** The gateway
is a separate trust domain that the workload cannot alter. It verifies the session or OIDC login,
**strips the cookie or token before forwarding**, and attaches a short-lived signed attestation
(audience: the broker) holding:

- `sub`, `tenant`, `sid`, `auth_time`, `acr`
- a unique `req_id` and an expiry measured in seconds
- a **digest of the user's actual HTTP request**: method, normalized path, and a body digest
  (RFC 9530 `Content-Digest` [F])

The app forwards this attestation alongside its effect request. The app never sees a reusable user
credential.

This is close to the IETF OAuth **Transaction Tokens** draft. That draft propagates
user identity and request context inside a trust domain as short-lived signed tokens
[F: draft-ietf-oauth-transaction-tokens-11, WG consensus, not yet an RFC]. The token format should
reuse that draft, or another standard JWS/COSE envelope chosen under OQ-05. No custom primitives.

The variant matters:

- **(b1) Identity only.** The app can trigger *any* operation the user is permitted, but only
  while the attestation is live.
- **(b2) Identity plus request digest, with a declarative route-to-operation mapping held by the
  broker.** The broker derives the operation and its parameters *from the attested request* and
  rejects any effect request that does not match. Example: `POST /orders/{id}/refund`, body field
  `amount_cents`, maps to `Refund{order_id, amount_cents}`. **[H] b2 is the strongest option that
  needs no client keys.**

**(c) Per-request user-bound tokens.** These are proof-of-possession schemes where the client signs
each request, as in DPoP [F: RFC 9449]. A browser can hold a non-extractable WebCrypto key, and the
user never manages it. But the key lives in the same origin the compromised app serves its
JavaScript from. Code injected through the app can therefore ask the browser to sign arbitrary
requests. **[H]** Proof of possession defeats token *theft*, and that matters under (a). It does
not defeat a *compromised origin*. It adds little over (b2) and costs client complexity.

**(d) RFC 9421 HTTP Message Signatures** [F: RFC 9421]. This needs a signing key at the
signer. It suits **gateway→broker** and **workload→broker** authentication well, because those
are server-side keys outside the workload (for the gateway) or bound to workload identity. It does
not suit browser users, for the same reasons as (c), and there must be no shared secrets in public
JavaScript.

### 2.2 Recommendation

**[H]** The primary design is (b2): a trusted gateway attestation bound to the request digest,
signed with a standard algorithm and a gateway key that never enters the workload's trust domain
(SI-05). The broker verifies:

- the signature, `aud`, and expiry;
- `req_id` single-use consumption (SI-09);
- that the requested effect equals the effect derived from the attested request through the
  broker-held mapping (SI-06, SI-10).

Use RFC 9421 or mTLS for gateway↔broker and workload↔broker *channel* authentication. The
attestation itself must be verifiable on its own, so that the app cannot strip it or swap it.

**Costs of (b2):**

- The gateway must see request bodies, and they must be canonicalized. That is a parsing surface
  in the TCB.
- Routes must be declared, which is an SDK or manifest burden.
- Not every effect maps 1:1 to a user request. Background jobs and fan-out need a separate path:
  workload-only authority under tight policy and budgets, with no user subject.
- **[H]** Requests with no route mapping fall back to (b1) semantics, and the profile must say so.

### 2.3 Residual: what a compromised app can still do with a live user session

Let `W` be the set of user requests passing through the app in a time window, and `P(u)` the set
of effects policy permits for user `u`.

| Design | What the app can cause | Duration |
|---|---|---|
| (a) cookie forwarded | any effect in `P(u)`, any number of times (only budgets limit it), for every `u` whose credential it saw | until session or token expiry or revocation, even after the user leaves |
| (b1) identity attestation | any effect in `P(u)`, up to the per-attestation consumption limit, for each request in `W` | attestation TTL (seconds) |
| (b2) digest-bound attestation | **only the effect the user's own HTTP request maps to**, at most once | attestation TTL |

The following residual remains under every design, b2 included, and the profile must state it:

- **UI deception.** The app controls the pages the user sees. It can trick the user into
  submitting a real request: a button labeled "view" that posts a refund. b2 binds the effect to
  what the user *sent*, not to what the user *understood*. Only an approval screen rendered by the
  gateway on a separate origin narrows this (section 5).
- **Withholding and lying.** The app can drop, delay or fail requests and show false results.
  This is a denial-of-service and integrity problem for app output, which SI-* does not cover.
- **Reading.** Any data the broker returns to the app for a user, the app can exfiltrate.
- **Unmapped routes** fall to the (b1) residual.
- **Workload-only operations** (no user subject) are available to the app up to their budgets.

## 3. Policy engine choice (Q3, Q13)

### 3.1 Criteria

- Embeddable in-process in a Rust broker, with no extra network hop that could fail open.
- Deterministic with no I/O, so decisions depend only on inputs (SI-10).
- Default deny (SI-08).
- Formally analyzable, so we can ask "can anyone ever refund more than X" before deploying.
- Schema validation and a way to test policies.
- Permissive OSS license.
- Maturity in 2026.

### 3.2 Comparison

| Criterion | **Cedar** | **OPA / Rego** | **OpenFGA / SpiceDB** (Zanzibar ReBAC) | **Casbin** (casbin-rs) | **Hand-written typed Rust** |
|---|---|---|---|---|---|
| Rust embedding | Native crate `cedar-policy` 4.14.0, Oct 2026 [F: docs.rs] | OPA is Go (sidecar or Wasm). `regorus` is a Rust interpreter; it passes OPA's non-builtin tests but lacks some builtins, and crypto builtins are excluded by design [F: regorus README] | Servers (Go) with their own datastore. Rust gets only gRPC clients. Not embeddable | Native crate | Native |
| Determinism / no I/O | No I/O. The caller supplies all entity data [F: Cedar docs] | Builtins such as `http.send` and `time.now_ns` exist. They must be removed by a capabilities restriction [F: OPA docs, capabilities] | Decision depends on the server's relationship store and consistency token [F: Zanzibar §2.2, zookies] | Deterministic, but custom matcher functions can do anything | Whatever we write |
| Default deny | Yes. `forbid` overrides `permit` [F: Cedar docs] | Only if written so. An undefined result must be handled as deny by the caller | Yes (no tuple means no access) | Depends on the model's `policy_effect` | Whatever we write |
| Formal analysis | Lean-modeled semantics and a verified validator. `cedar-policy-symcc` compiles policies to SMT for never-errors, always-allows/denies, implies, equivalent and disjoint checks, and returns counterexamples. Needs an external cvc5 binary [F: Cutler et al. OOPSLA 2024; docs.rs cedar-policy-symcc] | None beyond tests and type checking | Model-level reasoning only. No SMT analysis | None | None (could use Kani or proptest on code) |
| Schema validation | Strict validator against a schema [F] | Optional JSON-schema type checking | Typed model DSL | Weak (string model) | Rust type system |
| Testing | CLI and test harness. Differential testing against the Lean model [F: OOPSLA 2024] | `opa test`, mature | Assertion test files (OpenFGA) | Unit tests | Rust tests |
| License | Apache-2.0 [F] | Apache-2.0 (OPA). regorus: check before adoption, the README excerpt did not state it | Apache-2.0 (both) | Apache-2.0 | n/a |
| Maturity 2026 | CNCF Sandbox since Oct 2025 [F: CNCF]. Used in AWS Verified Permissions | CNCF Graduated (2021). Very wide use | OpenFGA CNCF Incubating, Oct 2025 [F: CNCF blog]. SpiceDB commercial-backed OSS | Long-lived, smaller security community | n/a |
| ReBAC at scale | Yes, if entity hierarchy data is supplied | Yes, via data | **Best fit** | Partial | Manual |

### 3.3 Recommendation

**[H] For the PoC and the long term: Cedar, embedded in the broker, with typed Rust in front of
it and transactional checks behind it.**

- **Typed Rust layer.** It parses the broker's declared operations (SI-16) into a typed request.
  It constructs the Cedar `principal`, `action`, `resource` and `context` **only from trusted
  facts**. It owns the at-most-once and atomic state checks, because those are transaction
  semantics and not policy (section 4).
- **Cedar layer.** It answers "permitted given these facts?". It is pure, cannot do I/O, and its
  semantics are default-deny with forbid-overrides. Before deployment, `symcc` can prove
  guardrails such as "no policy permits `Refund` when `context.amount_cents > resource.refundable_cents`"
  and "no permit crosses tenant". **[H]** These proofs are about *policy given the schema*. They
  say nothing about whether the facts fed in are true. That stays the job of the Rust and
  transaction layers, and tests must cover it.

**Required fail-closed adapter [F/H].** Cedar *skips* a policy whose evaluation errors and reports
the error in diagnostics [F: Cedar authorization docs]. An erroring `forbid` could therefore let a
`permit` through. The broker must:

- treat **any** diagnostic error as Deny (SI-08, SI-15);
- refuse to load a policy set that fails strict validation;
- in CI, run `symcc check_never_errors` on every guardrail `forbid`.

**When to bring in the others:**

- **OpenFGA or SpiceDB** later, as a *fact source* for large relationship graphs. They would not
  be the decision point. Their store is separate from the protected resource, which creates a
  cross-store staleness gap (see the Zanzibar "new enemy" discussion and zookies [F: Pang et al.
  2019 §2.2]).
- **OPA** if adopters already standardize on Rego. Not recommended as core, because it lacks
  analyzability and needs builtin restrictions.
- **Casbin** offers nothing over Cedar here.

## 4. Trusted state, TOCTOU and tenant isolation (SI-10, SI-11)

**Option A: the broker queries the protected resource inside the same transaction.** Preferred
**[H]**. The broker holds the only credential to the DB (SI-02, SI-03). For one effect it:

1. `BEGIN` (ideally `SERIALIZABLE`, or `READ COMMITTED` with explicit row locks).
2. `SELECT … FOR UPDATE` loads the resource and every row that policy facts derive from, filtered
   by the **trusted** tenant.
3. Builds the Cedar entities and context from those rows, then evaluates.
4. Runs the effect as a typed, parameterized statement and records the consumption of `req_id` or
   the idempotency key in the same transaction (unique constraint, SI-09).
5. `COMMIT`. Any error or serialization failure means rollback and Deny (SI-15).

A row lock or serializable isolation keeps the checked facts true at commit
[F: PostgreSQL docs, "Transaction Isolation" and "Explicit Locking"]. That is SI-11 by
construction. As belt-and-braces, guard the write itself:
`UPDATE … WHERE state='captured' AND refunded_cents + $amt <= total_cents` and require rows-affected = 1.

**Option B: broker-owned state store.** Use this when the resource is external (a payment API).
The broker keeps its own ledger of what it has authorized and executed. Facts about the external
resource then are only as current as the broker's mirror. **[H]** This is acceptable only when the
broker is the *sole writer* (SI-03). Otherwise state can change underneath it. For external effects
use the provider's idempotency keys, and record ambiguous outcomes as *unknown* (SI-15).

**Tenant isolation:**

- `tenant` comes **only** from the gateway attestation (or workload identity for workload-only
  operations).
- Each resource's owning tenant comes **only** from the DB row.
- Policy has a top-level guardrail: `forbid … unless resource.tenant == principal.tenant`.
- Every broker query carries the trusted tenant in its `WHERE` clause. Composite keys
  `(tenant_id, id)` prevent cross-tenant ID guessing.
- Defense in depth: PostgreSQL row-level security, with the broker running
  `SET LOCAL app.tenant = …` per transaction and connecting as a non-owner role, because table
  owners bypass RLS unless `FORCE ROW LEVEL SECURITY` is set [F: PostgreSQL docs, "Row Security
  Policies"].
- Per-operation DB roles that hold only the column grants that operation needs. This limits
  damage from broker bugs.

## 5. Confused deputy (Q7) and abuse of still-valid capabilities (Q8)

### 5.1 Confused deputy

The broker is, by design, a deputy holding authority for every tenant. That is the textbook setup
[F: Hardy 1988, "The Confused Deputy"]. The failure looks like this: the app names a resource
(order 9821 of tenant B), and the broker acts on it using its *own* ambient authority while
believing it acts for tenant-A user U. Mitigations:

- **Authority travels with the request.** The subject comes from the attestation. The broker
  *never* decides using its own credentials as the principal. The decision principal is always the
  attested user or the attested workload.
- **Names are resolved inside the subject's scope.** Resource IDs are looked up under the trusted
  tenant. A failed lookup is reported as Deny, and the response does not reveal whether the
  resource exists.
- **Bounded interface (SI-16).** There are no caller-chosen destinations, credentials, SQL or
  paths. Outbound effects (webhooks, URLs) use destinations from configuration, never from the
  request.
- **No authority amplification through chains.** A receipt from step N never authorizes step N+1
  (SI-12). Each step re-derives facts.
- **[H]** Write property tests where the app substitutes every ID field with another tenant's IDs.
  These tests are falsification checks for SI-06 and SI-10.

### 5.2 Abuse of still-valid authority

A compromised app with a stream of live user requests stays inside policy and still causes harm.

| Control | Enforceable at broker? | Notes |
|---|---|---|
| Per-user, per-session, per-tenant, per-workload **rate limits** | **Yes [H]** | The broker is on the only path (SI-01). Counters are rows updated in the effect transaction, so they are atomic with the effect |
| **Amount budgets** (for example ≤ $200 refunded per user per 24h, ≤ $5k per tenant) | **Yes [H]** | Same transaction. Expose `context.window_total_cents` to Cedar and enforce the cap as a `forbid` |
| Per-resource invariants (refund ≤ captured − refunded) | **Yes** | State check, section 4 |
| **Step-up** above a threshold | **Yes, if the proof comes from the gateway [H]** | The policy requires `context.acr`, or an `auth_time` within N minutes, or a **gateway-hosted approval**: a WebAuthn assertion whose challenge equals the hash of the operation, collected on a gateway origin the app cannot script [F: WebAuthn L2, challenge semantics]. Even then the authenticator does not *display* the operation. The approval page has to, and it must be served by the gateway |
| Out-of-band human approval (second person) | Yes | The approver's identity comes through the gateway. Required for high-value operations and admin changes (SI-14) |
| Deterministic anomaly limits (sudden spikes, many distinct resources) | Yes, as thresholds | These are the rate limits written as policy |
| ML or behavioral anomaly detection | **Not a security boundary** | Useful as evidence and alerting. Must not be claimed as enforcement |
| Kill switch, revocation | Yes for future requests | Requests already committed stay committed (in-flight semantics are Q11) |

**Quantified residual [H]:** Over window `W`, the maximum effect is bounded by the minimum of what
the live requests permit (section 2.3) and the configured budgets. A deployment profile must
publish these numbers, for example "a compromised app can refund at most $200 per user and $5,000
per tenant per day, and only for requests users actually sent".

## 6. Q9 — What Legacy Containment can honestly offer without SDK integration

Without an SDK or route manifest, the broker cannot see user intent, and the app still issues its
own queries. SI-16 forbids running arbitrary SQL through the broker. **Legacy mode therefore offers
no per-user or per-effect authorization.** What it can offer is listed below. **[H]** Each item
needs its own test under a profile.

1. **Credential removal for HTTP egress.** An egress proxy injects API keys for allowlisted
   upstream (host, method, path-prefix) tuples. The app can still *use* those upstreams as before,
   but it can no longer *steal* the keys (SI-02) or reach other hosts.
2. **Network and OS isolation.** No route to the metadata service, other services or the
   internet, and no lateral movement (SI-01).
3. **Coarse operation allowlists at the proxy.** For example, "no `DELETE` on `/v1/customers`". A
   coarse rate or amount ceiling where the protocol exposes amounts.
4. **Evidence.** A tamper-evident log of every outbound protected call that the app cannot erase.
5. **DB access is not contained** if the app keeps a direct DB credential. The best honest
   statement: "a compromised app retains all authority of its DB role". Narrowing that role (a
   least-privilege DB user) is ordinary hygiene and not PBE.

**Claim to publish:** Legacy mode reduces the blast radius of compromise from "everything reachable
plus every secret" to "what the app's existing channels allow". It does **not** prevent misuse of
those channels. Moving from legacy to native means moving routes one at a time behind the broker.

## 7. Q13 — Dividing work between cryptography, policy and OS enforcement

| Layer | Answers | Must not be asked to |
|---|---|---|
| **Cryptographic verification** | *Who asserted what, and has it been altered?* Gateway attestation signature, request digest binding, grant signature and fields (SI-05, SI-06), workload channel identity (mTLS or RFC 9421). | Decide permission. A signed request is not a legitimate request. |
| **Fact derivation and transaction (typed Rust)** | *What is true now?* Load the resource, tenant, state, budgets and `req_id` consumption under lock. Build the typed request from trusted inputs only (SI-09, SI-10, SI-11). | Embed business permission rules ad hoc. |
| **Policy evaluation (Cedar)** | *Given these facts, is it permitted?* A pure function, default deny, analyzable. | Fetch facts, enforce atomicity, or trust context it did not get from the fact layer. |
| **OS and network enforcement** | *Is the broker the only path?* Isolation, no credentials in the workload, resource-side authentication (SI-01 to SI-03). | Understand operations or users. |

Every layer fails closed on its own. No layer can make up for a missing one. A perfect policy
behind a bypassable network path gives no security, and perfect isolation in front of a broker that
trusts `owner_id` gives none either. **[H]** The TCB for a decision is: the gateway (identity and
digest), the broker binary (parsing, fact derivation, Cedar), the policy and key stores (SI-13,
SI-14), the DB, and the kernel and container runtime.

## 8. End-to-end sketch: "refund $25 on order 9821"

**T** means trusted, **U** means untrusted (a request only, never a fact).

1. The browser sends `POST /orders/9821/refund {"amount_cents":2500}` to the **gateway**.
2. **The gateway (T domain)**:
   - verifies the session cookie against its session store (T) and strips the cookie;
   - computes `Content-Digest` over the body;
   - signs an attestation: `{sub:"u-17", tenant:"acme", sid, acr:"pwd", auth_time, req_id:"r-5f2",
     exp:+30s, aud:"broker", method:"POST", path:"/orders/9821/refund", content_digest}`;
   - forwards the body and attestation to the app.
3. **The app (U)** runs its own logic, which may be compromised. It calls the broker with
   `Refund{order_id: 9821, amount_cents: 2500, user:"u-17", tenant:"acme", owner:"u-17"}` (all
   fields **U**), the attestation, and the original body.
4. **The broker, crypto step:**
   - verifies the attestation with the gateway public key (T, from a config store out of the app's
     reach) and checks `aud` and `exp`;
   - recomputes the digest of the supplied body and compares it with the attested `content_digest`;
   - authenticates the app's channel as workload `shop-php` (T, mTLS).
   - Any failure means Deny.
5. **The broker, derivation step:** the broker-held route map turns the attested method and path
   plus the digest-checked body into `Refund{order_id: 9821, amount_cents: 2500}` (T, derived). It
   compares this with the app's request. Any mismatch means Deny. The app's `user`, `tenant` and
   `owner` fields are **ignored**. The subject is `u-17@acme`, taken from the attestation.
6. **The broker, transaction:**
   - `BEGIN`.
   - `INSERT consumed_requests(req_id)`. A unique violation means Deny (replay).
   - `SELECT tenant_id, customer_id, state, total_cents, refunded_cents FROM orders WHERE
     tenant_id='acme' AND id=9821 FOR UPDATE`. This is a T fact. If no row, Deny.
   - `SELECT sum(amount) FROM refunds WHERE tenant_id='acme' AND actor='u-17' AND at > now()-24h`
     gives the budget (T).
   - Loads u-17's roles (T, from the broker-owned or IdP-synchronized roles table).
7. **Cedar** is evaluated with principal `User::"u-17"` (roles, tenant), action `Refund`, resource
   `Order::"9821"` (tenant, owner, state, refundable = total − refunded), and context
   `{amount_cents:2500, window_total_cents, acr, auth_time}`. These are all T or T-derived.
   - Example permits: an order owner may refund if `state=="captured"`; a support role may refund
     within the tenant.
   - Example forbids: cross-tenant; `amount > refundable`; `window_total + amount > 20000`;
     `amount > 10000 && acr != "webauthn"`.
   - Allow requires the decision to be Allow **and** zero diagnostic errors.
8. **The effect:** `UPDATE orders SET refunded_cents = refunded_cents + 2500 WHERE … AND state='captured'
   AND refunded_cents + 2500 <= total_cents`, require rows = 1, then insert the ledger and refund
   rows, then `COMMIT`. For an external payment API, the provider idempotency key is `req_id`, and
   an ambiguous response is recorded as *unknown* (SI-15).
9. **The receipt** (evidence only, SI-12) is returned to the app and logged.

**What a compromised app can and cannot change here:** it cannot change the amount, order, user or
tenant, replay the request, or invent an order state. It can refuse to send the request, show a
false result, or trick the user into submitting a real refund request in the first place.

## 9. Residual risks

1. **UI deception and induced requests (b2 included).** Only gateway-origin approval screens
   mitigate this. [H]
2. **Unmapped routes and background jobs** fall to identity-only or workload-only authority. Must
   be enumerated and budgeted per profile.
3. **Gateway compromise or gateway key theft** gives forged attestations for any user. The gateway
   is in the TCB, outside the v0 scope of attacker J only if the profile says so. Needs key
   isolation and rotation.
4. **Canonicalization bugs** between the gateway digest and the broker's route parsing (path
   normalization, JSON duplicate keys) could let the two disagree about the operation. Needs
   differential tests and strict parsers that reject duplicate keys.
5. **Cedar error-skip semantics** fail open if the adapter ignores diagnostics. Mitigated by the
   adapter, strict validation and `symcc` never-errors checks.
6. **Policy proofs cover policy, not facts.** Wrong fact derivation makes proofs meaningless. Tests
   must cover the derivation layer.
7. **Stale external facts** (Option B, ReBAC stores) open TOCTOU gaps that do not exist with
   Option A.
8. **Budgets are tuned by people.** Set too high, they bound nothing useful. Their numbers must be
   published.
9. **Read-side exfiltration** of everything the broker returns to the app.
10. **Broker defects** bypass policy. Mitigated by per-operation DB roles and independent review.
11. **Supply chain** of Cedar (attacker H): pin and audit. cvc5 is used at analysis time only.

## 10. Recommendations for the ADR

ADR candidates: (1) end-user subject source = b2 gateway attestation, standard envelope, single-use
`req_id`, TTL of 30s or less, with cookie forwarding barred in any profile claiming SI-10;
(2) Cedar embedded with strict validation, diagnostics-as-Deny and `symcc` checks in CI;
(3) facts, budgets and replay consumption handled in the effect's own transaction. Required deny
tests: forged attestation, body or route mismatch, cross-tenant IDs, wrong owner, over-refund,
budget exceeded, replay, Cedar error, DB unavailable.

## References

- Cutler, J. et al. "Cedar: A New Language for Expressive, Fast, Safe, and Analyzable
  Authorization." OOPSLA 2024. Extended version arXiv:2403.04651. https://arxiv.org/abs/2403.04651
- Cedar documentation, authorization semantics. https://docs.cedarpolicy.com/auth/authorization.html
- `cedar-policy` crate (4.14.0, Apache-2.0). https://docs.rs/crate/cedar-policy/latest
- `cedar-policy-symcc` (Symbolic Cedar Compiler). https://docs.rs/cedar-policy-symcc
- CNCF project page, Cedar (Sandbox, Oct 2025). https://www.cncf.io/projects/cedar/
- Pang, R. et al. "Zanzibar: Google's Consistent, Global Authorization System." USENIX ATC 2019.
- OpenFGA becomes a CNCF incubating project (2025-11-11).
  https://www.cncf.io/blog/2025/11/11/openfga-becomes-a-cncf-incubating-project/
- Open Policy Agent documentation (policy language, capabilities). https://www.openpolicyagent.org/docs
- microsoft/regorus. https://github.com/microsoft/regorus
- draft-ietf-oauth-transaction-tokens-11 (Internet-Draft, work in progress).
  https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/
- RFC 6750 (Bearer Token Usage), RFC 9449 (DPoP), RFC 9421 (HTTP Message Signatures), RFC 9530
  (Digest Fields).
- OpenID Connect Core 1.0. https://openid.net/specs/openid-connect-core-1_0.html
- W3C Web Authentication Level 2. https://www.w3.org/TR/webauthn-2/
- Hardy, N. "The Confused Deputy." ACM SIGOPS OSR 22(4), 1988.
- PostgreSQL documentation: Transaction Isolation, Explicit Locking, Row Security Policies.
  https://www.postgresql.org/docs/current/

**Verification notes:** Cedar's crate version, license, CNCF status, error-skip semantics and
`symcc` capabilities were checked against the sources above on 2026-10-24. The regorus license was
not confirmed. The RFC, PostgreSQL, WebAuthn and Zanzibar citations come from known published text
and were not re-fetched in this session. Nothing in this note has been tested in code.
