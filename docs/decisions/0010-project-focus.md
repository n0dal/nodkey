# ADR-0010: Project focus — authority control for consequential external actions

- **Status:** Accepted (owner decision, 2026-10-25)
- **Date:** 2026-10-25
- **Invariants:** all; especially SI-02 (credential custody), SI-09 (at-most-once), SI-15 (ambiguous
  outcomes), SI-20 (confirmed intent)

## Problem

Research note 01 and review finding AR-14 showed that for applications whose only protected resource is
their own database, an existing composition — PostgREST in RPC-only mode, PostgreSQL row-level
security, and a network-isolated application — provides roughly the same containment as Nodkey.
A general "protect every application resource" framework would therefore duplicate existing tools in its
most common case and dilute effort.

## Decision

Nodkey focuses on **authority control for applications and AI agents that perform consequential
external actions** — payments, refunds, outbound messages, and third-party API calls — with
**user-confirmed intent**.

Concretely:

1. **External effects first.** The broker holds third-party credentials (API keys, signing secrets) and
   executes typed operations against fixed upstream destinations. Workloads never hold those
   credentials. Ambiguous upstream outcomes (timeouts after the provider may have acted) are first-class
   (SI-15) and use provider idempotency keys.
2. **Confirmed intent.** Consequential operations require the user's approval of the exact effect on a
   surface the workload cannot script (ADR-0003 Phase 3 profile), or a pre-approved, budgeted mandate.
3. **AI agents as a first-class workload.** An agent's tool calls are treated exactly like code from a
   compromised application: the model, its prompt, and its tools' outputs are untrusted. A prompt
   injection is modelled as attacker C. Agents request effects; humans confirm them or delegate a
   bounded mandate.
4. **Two flagship demos:**
   - **Demo P (payments):** a web app issues refunds through a *simulated* payment provider. The app
     never holds the provider key; each refund is bound to the user's confirmation; a compromised app
     cannot refund other orders, change amounts, or replay; ambiguous provider outcomes never cause a
     double refund.
   - **Demo A (AI agent):** an agent with tools for payments and outbound messages, driven by a script
     that includes a prompt-injection scenario. The agent can propose any effect; only effects confirmed
     by the human, or within a delegated mandate, execute. The demo must not require a paid model or an
     external account: it runs with a scripted (deterministic) agent, and may optionally run a local or
     user-supplied model.
5. **Kept, not expanded:** Demo 1 (PHP containment of a local database) remains as the containment
   baseline and test-suite showcase. The local-database adapter is not developed further.

## Alternatives considered

- **Keep the broad scope** (all resources, all languages, workflows first). Rejected: duplicates existing
  tools for the most common case; spreads a small project thin.
- **Stop.** Rejected by the owner after weighing the prior-art findings.
- **Containment verification tool only.** Retained as a component (`nodkey verify`), not the whole
  project.

## Consequences

- **Roadmap** re-sequenced (see `ROADMAP.md`): Phase 3 completes signed grants and confirmation; Phase 4
  builds the external HTTP effect adapter, the payment-provider simulator, and budgets/mandates;
  Phase 5 builds the agent demo (including an agent-facing interface); workflow receipts (ADR-0007)
  move later.
- **Positioning:** public descriptions lead with external consequential actions and AI agents, not
  general application security.
- **Competition:** this space includes proprietary agent-policy products, credential-injecting proxies,
  and Actenon (research note 01, OQ-07). Nodkey's distinguishing combination must be shown by
  evidence: credential custody + per-effect signed grants derived from trusted facts + confirmed intent
  + containment verification, all self-hostable.
- **Validation:** the owner intends to sanity-check the refocus with practising developers.

## Reversal

Reversible by a later owner decision; the broker, grant format, and test suites are scope-agnostic.
