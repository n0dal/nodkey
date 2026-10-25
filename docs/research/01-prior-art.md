# 01 — Prior Art and Competitive Landscape

> Status: research note (ranks below accepted ADRs and specifications). Date: 2026-10-24.
> Answers: OQ-01 (directly), research questions Q5 (do receipts help) and Q6 (closest prior art to
> effect chains), and partially OQ-06.
>
> **Labels.** **[F]** = fact, with a reference in §6. **[H]** = hypothesis or judgment by the
> author of this note. Neither label means the item was tested; no code was run for this note.
> Where a source is a vendor page or secondary write-up, that is stated.

## 1. Executive finding (OQ-01)

**Question.** Does an existing open-source project or well-documented product already provide,
together:
(a) a workload that holds no credentials and has no network path to protected resources;
(b) a separate broker that executes *typed* protected operations while holding the credentials; and
(c) per-effect authorization that the broker verifies independently of the possibly compromised
application?

**Answer.** We found **no single open-source project that provides all three as a packaged,
documented, testable unit** for ordinary server-side applications. That result is weaker than it
sounds, though. Each part, and each *pair* of parts, has strong, mature prior art. The
architecture as a whole is a well-known pattern, not an invention:

- **The pattern itself is old and proven.** Privilege-separated systems such as OpenSSH privsep,
  qmail, Postfix and the Chromium sandbox already split an unprivileged worker that has no authority
  from a privileged broker that checks a policy before acting [F: Provos et al. 2003; Bernstein
  2007; Postfix SECURITY_README; Chromium sandbox design]. Chromium's design doc tells implementers
  to "assume sandboxed code is malicious code" and to evaluate forwarded calls "against the policy"
  in the broker [F]. This is (a)+(b)+(c) inside one host and one product.
- **Google's BeyondProd covers (c) between services.** Backends check *end-user context tickets*:
  "integrity-protected, centrally issued, forwardable credentials" issued by an end-user
  authentication service. The backend checks that the user in the ticket is authorized for the
  requested data, so it does not have to trust the calling frontend [F: BeyondProd]. This is
  proprietary internal infrastructure, documented only at whitepaper level.
- **(a)+(b) is commodity.** Credential-injecting proxies keep secrets out of the workload: CyberArk
  Secretless Broker, HashiCorp Boundary credential injection, the Envoy credential-injector filter,
  and a 2025–2026 wave of agent tools (Infisical Agent Vault, nono, AgentCordon) [F]. Secretless
  says it "performs no client authentication by design" and treats network isolation as a hard
  requirement [F]. These are credential *injectors*, not effect *brokers*. They authorize at the
  level of a connection, host or URL, not a typed effect bound to trusted state.
- **(b)+(c) exists for agent tool calls.** AWS Bedrock AgentCore Policy evaluates every tool call
  against Cedar at a gateway "outside of agent's code" [F]. This is proprietary and AWS-hosted.
  Open-source MCP gateways with Cedar or OPA decisions are appearing (Cerbos/agentgateway, Keycard,
  Gravitee), but those sources are mostly vendor material [F, vendor]. These systems usually decide
  on *agent identity + tool name + arguments*. Unless the tool server re-checks ownership and state
  against its own records, they do not derive authority from trusted resource state (SI-10) [H].
- **(b)+(c) for databases: PostgREST/Supabase-style.** A typed-ish HTTP API holds the DB
  credentials. The caller presents a JWT from a separate issuer. Row-level security evaluates the
  claims against *current database state* [F: PostgREST docs]. This is the closest open-source
  match to (b)+(c) with trusted facts. Two gaps remain. The interface is a generic query surface,
  which conflicts with SI-16 unless it is restricted to RPC functions. And when a server-side app
  sits in front of it, that app usually mints or forwards the JWT, so it can still act as any user
  whose token passes through it [H].
- **Parallel work.** A reference architecture with almost the same goals, "Verified Compute Fabric"
  (Apache-2.0, v2.0 dated 2026-10-24), was published this month. It describes workloads with no
  standing authority, a credential broker, and leases scoped to resource, action, tenant and
  audience [F, self-published; not reviewed in depth]. It is a document, not an enforcement
  implementation.

**Should Nodkey exist?** [H] Only as a **composition and verification project**, not as a new
security mechanism. Nodkey could add:
1. a packaged, reproducible *deployment profile* that enforces (a) at the OS and network level,
   for legacy server apps (PHP first), not just agents;
2. a broker with *narrowly typed effect adapters* (SI-16), instead of credential injection into
   generic protocols;
3. authorization derived from **trusted facts**, meaning a gateway-verified user and broker-owned
   state, never from the app's claims (SI-10, OQ-04), using existing token and policy formats;
4. **falsifiable invariants with an adversarial test harness** (SI-17). We found no existing
   project that ships "assume RCE in the app; here are the tests showing what the attacker still
   cannot do" as its main artifact.

If Nodkey cannot keep its novelty to these four points while reusing established parts, it should
not exist as a separate framework. In that case it should become documentation and test suites for
a PostgREST/Envoy/SPIFFE/Linux-isolation composition [H]. **Recommendation:** before committing to
a custom broker, run a spike that builds Demo 1 from off-the-shelf parts (network-namespace
isolation + Envoy ext_authz + Cedar + PostgREST RPC-only + RLS). Measure exactly which invariants
it cannot meet.

## 2. Comparative matrix

Columns a/b/c refer to the Nodkey goals above. ✔ = provided, ◐ = partial or conditional, ✘ = not
provided. Maturity is our assessment [H] unless cited.

| System | Purpose | Enforcement boundary | Trust assumptions | a | b | c | License | Maturity |
|---|---|---|---|---|---|---|---|---|
| CyberArk Secretless Broker | Inject DB/SSH/HTTP creds so app holds none | Separate process (sidecar); needs network isolation | Anyone who reaches its port gets an authenticated session [F] | ◐ creds yes; network path to broker = full DB session | ✘ protocol passthrough (Postgres, MySQL, SSH, HTTP) | ✘ | Apache-2.0 | Maintained by CyberArk; actively developed [F] |
| HashiCorp Vault (DB secrets, transit) | Dynamic creds; crypto-as-a-service | Vault server | App holds a Vault token | ✘ DB creds handed to app; ◐ transit keys never leave Vault [F] | ◐ transit = typed crypto ops | ◐ path ACLs, not per-effect state | BUSL-1.1 (since 2023) [F] | Mature |
| HashiCorp Boundary | Session broker for humans | Worker proxies session | User never sees injected cred [F] | ◐ for humans | ✘ session-level | ◐ per-target RBAC | BUSL-1.1 | Mature |
| Teleport | Identity-aware access to infra | Proxy + agent | Short-lived certs in client | ◐ | ✘ session/protocol-level | ◐ RBAC, DB object permissions | AGPL-3.0 source (verify) | Mature |
| Pomerium / Envoy ext_authz | Per-request authz at L7 proxy | Proxy process | Proxy trusted; app behind it | ◐ if network-isolated | ✘ generic HTTP | ◐ per-request policy on request attributes [F] | Apache-2.0 | Mature |
| Envoy credential injector | Add workload creds to outbound requests | Proxy | Workload identity only, "does not handle end user authentication" [F] | ◐ | ✘ | ✘ | Apache-2.0 | Mature |
| SPIFFE/SPIRE | Workload identity (SVIDs) | Agent + server, attestation | Node/kernel trusted | ✘ SVID *is* a credential in the workload | ✘ | ✘ identity only | Apache-2.0 | CNCF graduated |
| Stripe Smokescreen | Egress allow-list proxy | Proxy | Role-based host ACLs | ◐ restricts egress | ✘ | ✘ | MIT | Production at Stripe |
| AWS IAM / Roles Anywhere | Temporary cloud creds | AWS APIs | Creds issued *to* workload [F] | ✘ | ✘ | ◐ IAM policy, not per-effect | Proprietary | Mature |
| Google BeyondProd (ALTS, EUC) | Service identity + end-user context | RPC layer, backend checks | Central EUC issuer trusted [F] | n/a internal | ◐ | ✔ backend verifies user independently of frontend [F] | Proprietary, whitepaper | Production (Google) |
| PgBouncer / ProxySQL | Connection pooling/routing | Proxy | Clients authenticate to proxy | ◐ | ✘ SQL passthrough | ◐ ProxySQL query rules (pattern-based) | ISC / GPL-3.0 | Mature |
| PostgREST / Hasura + RLS | API over DB with row policies | API server + DB RLS | JWT issuer trusted; DB enforces | ◐ client holds no DB creds | ◐ generic query API; RPC can be typed | ✔ claims evaluated against DB state [F] | MIT / Apache-2.0 | Mature |
| AWS AgentCore Policy | Cedar on agent tool calls | Gateway outside agent [F] | AWS-hosted | ◐ | ✔ tool calls | ◐ Cedar on principal/action/resource/context | Proprietary | GA product (2025–26) |
| MCP authorization spec | OAuth for MCP servers | MCP server as resource server | AS trusted | ✘ | ✘ | ◐ audience-bound tokens; no token passthrough (secondary sources) | Open spec | Evolving |
| Infisical Agent Vault | HTTP MITM cred proxy for agents | Proxy; routing via `HTTPS_PROXY` [F] | Agent cooperates unless the network enforces | ◐ | ✘ | ◐ host rules; default forwards unmatched [F] | MIT (+ `ee`) | "Preview" [F] |
| nono | Kernel sandbox + phantom creds for agents | Landlock / Seatbelt + proxy [F] | Kernel trusted | ✔ (per profile) | ✘ generic HTTP | ◐ per-action policy | Open source (license unconfirmed) | Growing adoption [F, press] |
| AgentCordon | Self-hosted cred broker, Cedar per request | Local broker daemon + server [F] | Network isolation not stated [F] | ◐ | ◐ broker executes calls | ◐ Cedar per request, URL scoping [F] | AGPL-3.0 | Pre-1.0, small [F] |
| CaMeL (DeepMind) | Prompt-injection defense via capabilities | Custom interpreter around LLM [F] | Interpreter trusted | n/a | ◐ tool calls via interpreter | ✔ data-flow policies on tool calls [F] | Research code | Research (2025) |
| Chromium sandbox | Renderer has no authority | OS process + restricted token; broker [F] | Kernel + broker trusted | ✔ | ✔ typed IPC | ✔ broker policy [F] | BSD-3 | Very mature |
| OpenSSH privsep / Postfix / qmail | Privilege separation | Process / UID boundaries [F] | Monitor trusted | ✔ | ✔ narrow monitor RPC | ✔ monitor state machine [F] | BSD / IPL-EPL / PD | Very mature |
| Capsicum / CHERI / seL4 / Fuchsia | Capability OS/hardware | Kernel / hardware | Kernel/HW trusted | ✔ mechanism | ✘ (substrate) | ✘ (substrate) | BSD / various / GPL-2 / BSD | Mature–research |
| WASI component model | Capability-scoped Wasm imports | Wasm runtime | Runtime trusted | ✔ mechanism (no ambient imports) | ◐ host functions can be typed effects | ✘ | Apache-2.0 | 0.3.0 released 2026-06-11 [F] |
| Deno / Node permissions | Runtime permission flags | Same process | Node: "does not protect against malicious code" [F] | ✘ not a boundary for RCE | ✘ | ✘ | MIT | Stable |
| Verified Compute Fabric | Reference architecture, same goals | Described, not implemented [F] | — | (design) | (design) | (design) | Apache-2.0 | Document v2.0 [F] |

## 3. Reuse / integrate / adapt / genuinely new

**Reuse as is (do not rebuild)** [H, informed by F above]
- Linux isolation: network namespaces, cgroups, seccomp (as a filter, not user-notify policy, per
  owner rule), Landlock, and optionally gVisor or microVMs. These provide goal (a).
- Workload identity: SPIFFE/SPIRE SVIDs or plain mTLS, for authenticating workload→broker. The
  workload *does* hold its own SVID. That is a credential to the broker, not to a resource, so it is
  compatible with SI-02.
- Policy evaluation: Cedar or OPA. Cedar is a closer fit for analyzable principal/action/resource
  decisions.
- Grant/token formats: Biscuit (attenuation, Datalog checks) or Macaroons, or JWT/COSE with RFC 9396
  `authorization_details`. Do not build a custom envelope unless OQ-05 shows the existing ones fail.
- Resource-side defense (SI-03): DB roles/`pg_hba` restricted to the broker's identity; RLS as a
  second layer.
- Evidence: an append-only log plus, if needed, a transparency-log library (Trillian or Sigstore
  Rekor style). Do not build new Merkle code.

**Integrate (Nodkey calls them or sits beside them)**
- An Envoy (or Pomerium) gateway in front of the app that verifies the user session and issues
  *gateway-attested user context* to the broker. This is the BeyondProd EUC pattern, and it answers
  OQ-04. The OAuth Transaction Tokens draft (`draft-ietf-oauth-transaction-tokens-11`, WG consensus,
  IESG submission milestone Dec 2026 [F]) is the standards-track format for exactly this: an
  immutable `tctx` carried down a call chain. Nodkey should adopt it, or stay compatible with it,
  rather than invent one [H].
- Temporal or plain DB state machines for workflow orchestration, *outside* the TCB. They provide
  durability and retries. They do not provide authority (see §4).

**Adapt (concept borrowed, implementation narrowed)**
- The Chromium/OpenSSH broker model, applied across a network/process boundary to application
  effects (ledger debit, order transition) instead of OS handles.
- PostgREST RPC-only mode as one possible "typed adapter" backend, with gateway-issued, not
  app-issued, user context.
- PSD2 dynamic linking: bind authorization to the exact amount and payee, so any change invalidates
  it [F: RTS Art. 5]. Generalize to SI-06 full binding.

**Genuinely new (thin)** [H]
- A *packaged* deployment profile for **legacy server apps assumed compromised**, plus a published
  adversarial test suite that maps each SI-xx to PASS/FAIL/NOT TESTED evidence. We found this
  nowhere, though the parts exist.
- Making SI-10 ("trusted facts only") and SI-12 ("receipts are evidence, not authority") explicit,
  testable broker-contract rules across adopters. These are disciplines, not mechanisms.
- A language-neutral **typed-effect adapter contract**: a declared operation, input schema,
  resource-binding rules, preconditions on broker-owned state, an idempotency key, and an
  unknown-outcome state. Each element has prior art. We have not found them combined into a
  reusable broker SDK [H, moderate confidence].

## 4. Effect chains and receipts (Q5, Q6; informs OQ-06)

### Closest prior art

| Prior art | What it already gives | Relation to Nodkey effect chains |
|---|---|---|
| **Privsep monitors** (OpenSSH) | Monitor keeps a state machine; the unprivileged child can only request transitions valid in the current state [F: Provos et al.] | The essential mechanism: a trusted state machine gating transitions requested by an untrusted caller |
| **Workflow authorization constraints** (Bertino, Ferrari & Atluri 1999) | Formal specification and enforcement of who may execute which task in a workflow, including separation-of-duty constraints [F] | Academic precedent for authorizing *state transitions*, not just accesses |
| **Typestate** (Strom & Yemini 1986) | Operations valid only in specific object states, checked statically [F] | The type-level version of "can't capture before authorize" |
| **Sagas** (Garcia-Molina & Salem 1987), **Temporal/Cadence** | Long-lived transactions as steps with compensations; durable, retried execution [F] | Gives orchestration and compensation. It gives no authority: the workflow code is trusted [H] |
| **Idempotency keys** (Stripe; IETF `Idempotency-Key` header draft) | Server-side at-most-once semantics for retried mutations [F] | Exactly SI-09. Not novel |
| **PSD2 dynamic linking** (Reg. (EU) 2018/389 Art. 5) | Auth code specific to amount and payee; any change invalidates it [F] | Exactly SI-06 for payments. Not novel |
| **OAuth RAR (RFC 9396), GNAP (RFC 9635)** | Structured, fine-grained, transaction-specific authorization requests [F] | Standard carrier for per-effect grant content |
| **OAuth Transaction Tokens (draft)** | Immutable transaction context propagated and verified across a call chain [F] | Closest standard to a "chain context". It carries context, not step receipts |
| **AP2 (Agent Payments Protocol)** | Signed Intent → Cart → Payment "mandates" chaining user intent to a concrete transaction [F, secondary sources] | Very close to "receipt/mandate chain" for agent payments; launched by Google in Sept 2025 |
| **in-toto** | Signed per-step link metadata verified against a layout of required steps and functionaries [F] | Closest to *receipts* for multi-step processes (supply chain). It shows a receipt chain works as **evidence** to a verifier, not as authority |
| **Zanzibar zookies** | Consistency tokens so ACL checks are evaluated at least as fresh as a given snapshot [F] | Precedent for the stale-state problem (SI-11) |
| **Proof-carrying authorization** (Appel & Felten 1999; Bauer et al. "Grey") | The requester supplies a proof; the guard only *checks* it [F] | Precedent for "the broker verifies, it does not trust". Also a caution: the proofs are of *logical authorization*, not of state freshness |
| **IFC/DIFC** (Jif, Flume, HiStar, Laminar) | Labels on data; declassification only by trusted gates [F] | The broker is a "trusted gate"; IFC also tackles the *laundering* concern formally |
| **Smart contracts** | State-transition functions with authorization checked by a replicated verifier [H: general knowledge] | Shows the cost of decentralizing the state machine. Nodkey does not need that cost: the broker owns state |
| **CaMeL** | Capabilities (provenance metadata) on values; policies checked at tool-call time by a trusted interpreter [F] | The agent analogue: untrusted computation, trusted mediator. Shows the "laundering via data flow" problem is real |

### Explicitly NOT novel in Nodkey's effect-chain idea [H, based on above]
- Gating workflow transitions on a trusted, server-owned state machine.
- At-most-once effects via idempotency keys or single-use grants.
- Binding authorization to exact operation parameters (amount, payee, resource).
- Propagating an immutable transaction context through a call chain.
- Signed step attestations verified against an expected sequence (in-toto).
- Fail-closed handling of ambiguous outcomes. Payment processors already model "pending/unknown"
  and reconcile instead of retrying blindly.

### Do receipts help? (Q5 / OQ-06) [H]
If **one broker owns the workflow state**, a receipt held by the workload adds no *authorization*
value. The broker re-reads its own state anyway (SI-11, SI-12). A receipt only creates new attack
surface: replay, cross-tenant reuse, and laundering. Receipts help only in three cases:
1. **Cross-trust-domain chains**, where broker B must learn that broker A committed step N and they
   share no database. Even then, B should verify A's signed statement *and* a binding to the
   current transaction context, as in in-toto or Txn-Tokens, rather than accept possession.
2. **Evidence and audit**: tamper-evident records given to users and auditors. This is useful, and
   it is SI-12's "evidence" role.
3. **Offline or partitioned verification**, at the cost of freshness.

Recommendation: v0 should use broker-owned state machines only. Treat receipts as an *evidence*
output, and defer cross-broker receipt chains until a concrete multi-broker deployment needs them.

## 5. Implications for Nodkey architecture [H]

1. **Position Nodkey as "privilege separation for application effects," and credit its lineage
   openly** (OpenSSH privsep, Chromium broker, BeyondProd EUC). Do not claim the pattern as new.
   Also revisit the name with OQ-02: "proof" suggests PCC/PCA formal proofs, which PBE does not
   provide.
2. **Goal (c) is the differentiator, and its hard part is OQ-04.** Every credential-injector
   reviewed fails (c), because the broker cannot tell a legitimate request from an
   attacker-initiated one made through the same compromised app. User context must come from a
   gateway the app cannot forge (EUC / Txn-Token pattern). Without it, Nodkey degrades to "Secretless
   with typed operations": still useful (it limits blast radius to the declared operations, per the
   SI "does not promise" section) but no longer meeting (c) for user-scoped effects.
3. **Typed adapters are what separates Nodkey from L7 proxies.** Generic HTTP/SQL passthrough (Envoy,
   Secretless, ProxySQL, Agent Vault) cannot meet SI-16. The adapter contract (§3) is where most of
   the real engineering goes. Keep it small.
4. **Do not build** a policy language, token format, signature scheme, workload identity system,
   sandbox, or workflow engine. Each has a mature open-source option listed in §2/§3.
5. **Use runtime permission models only as a seat belt.** Node's own docs say its permission model
   "does not protect against malicious code" [F]. Same-process permissions (Node, Deno, PHP
   `disable_functions`) must never count toward SI-01/SI-02. WASI components are a credible
   architecture-B substrate for *native* adopters, since WASI 0.3.0 has been released [F]. They do
   not help legacy PHP.
6. **Agents are the market with momentum.** Most 2025–2026 activity (Agent Vault, nono,
   AgentCordon, AgentCore Policy, MCP gateways, CaMeL) targets agents. Those projects mostly stop
   at credential injection plus host/tool allow-lists. Nodkey's trusted-facts and typed-effect
   discipline would add value there. Keep the protocol language-neutral so an MCP-gateway adapter is
   possible later (research Q15).
7. **Licensing landscape.** Several close neighbours are not Apache-2.0-compatible for embedding:
   Vault/Boundary (BUSL-1.1), AgentCordon and Teleport (AGPL). Nodkey can *interoperate* with them over
   the network but should not vendor them. The licensing workstream needs to confirm this.
8. **Next step (falsification spike).** Build Demo 1 from off-the-shelf parts: netns isolation,
   Envoy ext_authz + Cedar, PostgREST RPC-only + RLS, and DB auth restricted to the API's role. Run
   the SI-01…SI-16 tests against it. Every invariant it meets is one Nodkey should *not* reimplement.
   The invariants it fails define Nodkey's real scope.

### Gaps in this note
- Teleport's current licence and DB-permission features, nono's licence, and the exact MCP
  authorization spec text (2025-11-25 vs a reported 2026-07-28 revision) were **not verified from
  primary sources**.
- The AuthZEN Authorization API was reported "final" in January 2026 by a vendor blog; we did not
  verify this.
- No hands-on evaluation of any listed system was performed.

## 6. References

Privilege separation and broker models
- Provos, Friedl, Honeyman, "Preventing Privilege Escalation," USENIX Security 2003 — https://www.usenix.org/legacy/events/sec03/tech/full_papers/provos_et_al/provos_et_al.pdf
- Bernstein, "Some thoughts on security after ten years of qmail 1.0," 2007 — https://cr.yp.to/qmail/qmailsec-20071101.pdf
- Postfix security architecture — https://www.postfix.org/SECURITY_README.html
- Chromium sandbox design — https://chromium.googlesource.com/chromium/src/+/main/docs/design/sandbox.md
- Google BeyondProd (ALTS, end-user context tickets) — https://docs.cloud.google.com/docs/security/beyondprod
- Hardy, "The Confused Deputy," 1988 — https://dl.acm.org/doi/10.1145/54289.871709

Credential brokers, proxies, identity
- CyberArk Secretless Broker — https://github.com/cyberark/secretless-broker
- HashiCorp Vault database secrets — https://developer.hashicorp.com/vault/docs/secrets/databases ; transit — https://developer.hashicorp.com/vault/docs/secrets/transit
- HashiCorp licence change (BUSL) — https://www.hashicorp.com/en/blog/hashicorp-adopts-business-source-license
- HashiCorp Boundary credential injection — https://developer.hashicorp.com/boundary/tutorials/credential-management/hcp-private-vault-cred-injection
- Teleport — https://github.com/gravitational/teleport
- Pomerium — https://github.com/pomerium/pomerium
- Envoy ext_authz — https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter
- Envoy credential injector — https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/credential_injector_filter
- SPIFFE/SPIRE — https://spiffe.io/docs/latest/spiffe-about/overview/
- Stripe Smokescreen — https://github.com/stripe/smokescreen
- AWS IAM Roles Anywhere — https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html
- PgBouncer — https://www.pgbouncer.org/ ; ProxySQL — https://proxysql.com/
- PostgREST authorization — https://postgrest.org/en/latest/schema_structure.html ; https://docs.postgrest.org/en/v12/_sources/explanations/db_authz.rst.txt
- Hasura GraphQL Engine — https://github.com/hasura/graphql-engine

Agent security
- Debenedetti et al., "Defeating Prompt Injections by Design" (CaMeL), 2025 — https://arxiv.org/abs/2503.18813 ; code — https://github.com/google-research/camel-prompt-injection
- Willison, "The Dual LLM pattern," 2023 — https://simonwillison.net/2023/Apr/25/dual-llm-pattern/
- MCP authorization (2025-11-25) — https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization ; Keycloak MCP compliance notes — https://www.keycloak.org/securing-apps/mcp-authz-server
- AWS Bedrock AgentCore Policy — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
- Infisical Agent Vault — https://github.com/Infisical/agent-vault
- nono — https://github.com/nolabs-ai/nono ; Help Net Security, 2026-07-27 — https://www.helpnetsecurity.com/2026/07/27/nono-open-source-ai-agent-sandboxing/
- AgentCordon — https://github.com/agentcordon/agentcordon
- Cerbos, MCP tool-call authorization (vendor) — https://www.cerbos.dev/blog/authorizing-mcp-tool-calls-at-the-gateway-or-inside-the-proxy
- Keycard per-tool authorization (vendor) — https://docs.keycard.ai/use-cases/per-tool-authorization/
- Verified Compute Fabric — https://verifiedcomputefabric.netlify.app/ ; https://github.com/gfsaaser24/verified-compute-fabric
- Agent Payments Protocol (AP2) — https://ap2-protocol.org/
- awesome-agent-runtime-security — https://github.com/bureado/awesome-agent-runtime-security

Authorization standards
- OAuth Transaction Tokens draft — https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/
- RFC 9396 OAuth Rich Authorization Requests — https://www.rfc-editor.org/rfc/rfc9396
- RFC 9635 GNAP — https://www.rfc-editor.org/rfc/rfc9635
- RFC 8707 Resource Indicators — https://www.rfc-editor.org/rfc/rfc8707
- Commission Delegated Regulation (EU) 2018/389 (PSD2 RTS) — https://eur-lex.europa.eu/eli/reg_del/2018/389/oj ; EBA Q&A 2018_4414 — https://www.eba.europa.eu/single-rule-book-qa/qna/view/publicId/2018_4414
- OpenID AuthZEN WG — https://openid.net/wg/authzen/
- Biscuit — https://www.biscuitsec.org/ ; Birgisson et al., "Macaroons," NDSS 2014 — https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/
- Pang et al., "Zanzibar," USENIX ATC 2019 — https://www.usenix.org/conference/atc19/presentation/pang
- Cedar — https://www.cedarpolicy.com/

Capability systems
- Watson et al., "Capsicum," USENIX Security 2010 — https://www.usenix.org/legacy/event/sec10/tech/full_papers/Watson.pdf
- CHERI — https://www.cl.cam.ac.uk/research/security/ctsrd/cheri/
- Miller, "Robust Composition" (E, ocap), 2006 — http://www.erights.org/talks/thesis/
- seL4 — https://sel4.systems/ ; KeyKOS — https://www.cis.upenn.edu/~KeyKOS/
- Fuchsia capabilities — https://fuchsia.dev/fuchsia-src/concepts/components/v2/capabilities
- WASI 0.3 release — https://wasi.dev/releases/wasi-p3
- Deno security — https://docs.deno.com/runtime/fundamentals/security/
- Node.js permission model — https://nodejs.org/api/permissions.html

Workflow, effects, verification, IFC
- Garcia-Molina & Salem, "Sagas," SIGMOD 1987 — https://dl.acm.org/doi/10.1145/38713.38742
- Temporal — https://github.com/temporalio/temporal
- Stripe idempotent requests — https://docs.stripe.com/api/idempotent_requests ; IETF Idempotency-Key draft — https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/
- Strom & Yemini, "Typestate," IEEE TSE 1986 — https://doi.org/10.1109/TSE.1986.6312929
- Bertino, Ferrari, Atluri, "Specification and enforcement of authorization constraints in workflow management systems," ACM TISSEC 1999 — https://dl.acm.org/doi/10.1145/300830.300837
- Appel & Felten, "Proof-Carrying Authentication," CCS 1999 — https://dl.acm.org/doi/10.1145/319709.319718
- Necula, "Proof-Carrying Code," POPL 1997 — https://dl.acm.org/doi/10.1145/263699.263712
- Bauer, Garriss, Reiter, "Distributed proving in access-control systems" (Grey), IEEE S&P 2005 — https://doi.org/10.1109/SP.2005.9
- in-toto — https://in-toto.io/ ; Torres-Arias et al., USENIX Security 2019 — https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias
- Jif — https://www.cs.cornell.edu/jif/ ; Krohn et al., "Flume," SOSP 2007 — https://dl.acm.org/doi/10.1145/1294261.1294293 ; Zeldovich et al., "HiStar," OSDI 2006 — https://www.usenix.org/conference/osdi-06/making-information-flow-explicit-histar ; Roy et al., "Laminar," PLDI 2009 — https://dl.acm.org/doi/10.1145/1542476.1542484
