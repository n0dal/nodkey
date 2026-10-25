# Vision and Project Context

> **Compromise of computation must not imply compromise of authority.**

## Problem

Internet-facing applications routinely run with *ambient authority*: the process that parses
untrusted input also holds database credentials, API keys, filesystem permissions, and open network
egress. One remote-code-execution bug in that process converts into everything the process can reach.

Existing controls each address part of this:

- **Isolation** (containers, namespaces, seccomp, Landlock, gVisor, microVMs) limits *where* code can
  reach, but a legitimately connected app still holds full database credentials.
- **Authorization systems** (Cedar, OPA, Zanzibar-style ReBAC) decide *whether* an action is allowed,
  but are usually called *by the application*, which a compromised app can skip.
- **Credential brokers and secret managers** keep secrets out of config files, but typically hand the
  secret (or a long-lived token) back to the application.
- **Capability tokens** (Biscuit, Macaroons) bound authority cryptographically, but the token is often
  held and presented by the very process we are trying to distrust.

## Hypothesis

A useful framework would *compose* these so that:

1. The application process holds no credentials and has no network path to protected resources
   (OS-enforced).
2. Protected effects are typed operations executed by a separate **broker** that holds the
   credentials.
3. The broker executes an operation only with authorization it can verify independently of the
   application — derived from trusted facts (verified identity, broker-owned state, policy) rather
   than application claims.
4. Every decision produces tamper-evident evidence.

The research phase must establish whether this composition already exists, what is genuinely new,
and what guarantees are achievable. See [`research/`](research/).

## Scope

**Focus ([ADR-0010](decisions/0010-project-focus.md), 2026-10-25):** authority control for applications
and AI agents that perform **consequential external actions** — payments, refunds, outbound messages,
third-party API calls — with **user-confirmed intent**. The workload (an app or an agent) can propose
any effect; the broker, which alone holds the third-party credentials, executes only effects backed by a
signed grant for exactly that effect.

**In scope (v0):** Linux deployments; a broker with a small number of typed external-API adapters;
cryptographically verifiable grants; user confirmation and bounded mandates; containment verification;
two flagship demos — a web app issuing refunds through a simulated payment provider, and an AI agent
whose tool calls are subject to the same controls; reproducible adversarial tests.

**Not a focus:** protecting an application's own database in general. For that case, existing tools
(e.g. PostgREST with row-level security and a network-isolated app) already provide comparable
containment.

**Explicitly not claimed:** preventing code execution; protecting against host, kernel, runtime,
broker, or Authority compromise; making permitted operations safe to abuse; regulatory compliance.

## Principles

- Prefer established technology; build only what composition requires.
- Small, reviewable trusted computing base.
- Security claims are testable properties with stated assumptions ([SI-17](SECURITY_INVARIANTS.md)).
- Free and open source (Apache-2.0); no hosted service, account, or proprietary dependency required.
- Language-neutral protocol; PHP is the first integration, not a dependency.

## Long-term outcome

A reusable substrate that lets developers — and operators of background workers and autonomous
agents — run useful code without entrusting it with unrestricted authority over sensitive systems.
