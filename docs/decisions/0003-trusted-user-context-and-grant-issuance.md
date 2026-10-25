# ADR-0003: Trusted user context and grant issuance

- **Status:** Proposed
- **Date:** 2026-10-24
- **Invariants:** SI-02, SI-05, SI-06, SI-07, SI-09, SI-10
- **Open questions:** OQ-04 (addressed), OQ-08 (partially)

## Problem

The broker must know which user is behind an effect and what that user asked for, without trusting
the app that relays the request (OQ-04).

## Evaluation criteria

No reusable user credential in the workload; binding to the user's actual request; residual
authority of a compromised app; no client-side keys; standard formats.

## Alternatives considered

From research 04 §2: (a) app forwards the session cookie/token — the app holds a bearer credential
and can act as the user until expiry: **rejected**. (b1) gateway identity attestation — app can
trigger any permitted operation during TTL. (b2) gateway attestation + request digest, with the
**broker** deriving operation and parameters from the attested request. (c) DPoP-style client keys —
do not defeat a compromised origin. (d) RFC 9421 — suits server channels, not browsers.

## Decision

1. The gateway (authority component) verifies the user session and **removes the session credential
   before forwarding** the request to the app.
2. The authority maps the user's HTTP request through an **authority-held route map** to an
   **operation scope**: operation, resource, and a constraint ceiling (e.g. `ledger.refund` on order
   9821, `amount_cents ≤ policy max`).
3. It issues a **short-lived, single-use signed grant** (ADR-0004) bound to: issuer, audience =
   broker, workload, tenant, subject, operation, resource, constraints, request digest, `nbf`/`exp`,
   `jti`.
4. The app receives the grant, may compute concrete parameters, and submits `{grant, params}` to the
   broker. The broker **re-derives everything it can from trusted state** (ownership, tenant, state,
   budgets) and treats the grant as an upper bound only (necessary, never sufficient).
5. Unmapped routes produce no user-scoped grant. Workload-only operations (no subject) are a separate,
   budgeted class.

## Residual authority of a compromised app (quantified)

For each user request *r* that passes through the app and maps to scope *s(r)*, the app can cause
**at most one** effect with `op = s(r).op`, `resource = s(r).res`, subject/tenant = r's verified
user, and parameters anywhere in `ceiling(r) ∩ policy(u, state) ∩ budgets`, before `exp`
(TTL ≤ `max_ttl`, default 300 s). Example: user asks to refund $25; ceiling = per-refund policy max
$100; order refundable $80 ⇒ the app can refund **up to $80**, i.e. $55 more than intended, once.
It cannot touch another order, operation, user, tenant, or workload, or reuse the grant. Additionally
(THREAT_MODEL R-3) the app serves the page, so injected script can make the logged-in browser send
further real requests; the true bound across a session is then *P(u) limited by budgets*.

## Evidence

Research 04 §2.3 residual table; BeyondProd end-user context tickets and OAuth Transaction Tokens
draft-11 (01 §3); PSD2 RTS Art. 5 dynamic linking (01 §3).

## Consequences
- **Advantages:** no reusable user credential in the workload; the authority is the single HTTP
  parser, which removes broker-side re-parsing and narrows OQ-08 to nginx ↔ authority.
- **Drawbacks:** route map is a manifest burden; multi-effect requests need multiple scopes/grants
  (open); policy knowledge is split between route-map ceilings and broker Cedar.
- **Security:** authority and its key are TCB (attacker J); see ADR-0001 objection 1.
- **Performance:** one authority call and one signature per mapped request.
- **Compatibility:** requires the authority to see the request body when a ceiling depends on it.

## Architect objection

**1. A ceiling is weaker than b2 without need.** When the route map can read a parameter from the
user's own request (here `amount_cents = 2500` in the body), the grant should bind it **exactly**
(`amount_cents == 2500`, or the `rqh` exact-request mode), not as a ceiling. Then the residual for
that request is "the effect the user sent, at most once" instead of "up to $80". Ceilings should be
used only for parameters the route map explicitly declares as *app-computed*, and each such
declaration should be listed in the deployment's published residuals. Evidence: 04 §2.3 (b2 vs b1),
PSD2 dynamic linking binds the exact amount.

**2. The request digest is not a binding unless the broker checks it.** The broker receives
`{grant, params}`, not the user's HTTP request, so `rqh` over the HTTP request cannot be verified at
the broker and is audit evidence only. Either define `rqh` over the canonical *broker request*
(computed by the authority from route-extracted parameters) or document it as evidence only.

## Reversal / migration

Moving to strict b2 (exact binding everywhere) is a route-map change; grant format is unchanged.
