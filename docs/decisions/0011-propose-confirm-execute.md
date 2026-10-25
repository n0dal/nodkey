# ADR-0011: Propose → confirm → execute for consequential effects

- **Status:** Accepted (2026-10-25) with Revision 1 below, per `docs/reviews/2026-10-25-adr-0011-review.md`
  (verdict: accept with changes). Supersedes ADR-0003 Phase 3 profile items 1 (write-grant provenance),
  4 (grant delivery to the workload and the `ISSUED` state — page hardening is retained), and 7 (HTTP
  body binding). Items 2, 3, 5, 6, 8 remain in force.
- **Invariants:** SI-05, SI-06, SI-09, SI-10, SI-20, SI-21
- **Resolves:** OQ-11

## Problem

ADR-0003 (Phase 3 profile) delivers a confirmed write grant to the workload, which then presents it
to the broker. This has three costs:

1. The workload holds a live grant, so a compromised workload chooses *when* (and whether) to use it.
2. The gateway must derive the operation and exact parameters from the user's HTTP request (route map,
   canonical form parsing, exact-binding rules). Review R3 showed many operations cannot be exactly
   bound this way, and the mapping is itself attack surface.
3. It does not fit AI agents (ADR-0010, research 07): an agent's tool call is not an HTTP request from
   the user's browser.

## Decision

For every operation that requires confirmation, Nodkey uses one flow:

1. **Propose.** The workload (application or agent) sends `effect.propose{op, params}` to the broker over
   its workload socket. The broker validates the operation and parameter types, records a **pending
   effect** bound to the workload identity, and returns a pending id and a confirmation URL on the auth
   origin. Proposals have no authority; they are requests.
2. **Confirm.** The user opens the confirmation URL (the workload may redirect or link to it; it cannot
   render it). The gateway authenticates the user's session on the auth origin. The page shows the
   pending effect's exact values as stored by the broker (which are still workload-*proposed* values: the guarantee is that what executes equals what the user saw, not that the workload chose well), plus broker-resolved trusted facts (for
   example the order's owner and remaining refundable amount). The approving session's subject is the
   trusted subject; any subject the workload named in the proposal is ignored.
3. **Authorize.** On approval, the authority signs a single-use write grant (grant-v1, `cfm` set) bound to
   the pending id, workload, tenant, subject, operation, and exact parameter values, and delivers it to
   the broker over a channel the workload cannot reach.
4. **Execute.** The broker verifies the grant, re-checks trusted state (ownership, remaining amount,
   budgets) inside the effect transaction, consumes the grant, and executes. Pending effects follow
   `PENDING → APPROVED → EXECUTING → SUCCEEDED | FAILED | UNKNOWN`, or `DENIED | EXPIRED`, with
   compare-and-set transitions.
5. **Observe.** The workload learns the outcome with `effect.status{pending_id}`; it never receives the
   grant.

**Mandates (OQ-12)** plug into step 2: a proposal that falls entirely within an active, broker-tracked
mandate previously approved by the user skips per-effect confirmation. Mandates are specified separately.

**Read operations** are unchanged: read grants (ADR-0003 Phase 3 profile item 6) continue to be issued
by the gateway for same-origin or top-level navigation requests and presented by the workload.

## Consequences

- **Smaller workload authority.** A compromised workload can propose anything, but cannot hold, delay,
  replay, or redirect an approved grant. It can only spam proposals (rate-limited per workload) and try
  to mislead the user about what to approve — the confirmation page shows broker-stored values, not
  workload-supplied descriptions.
- **Simpler gateway.** No route map or exact binding from HTTP request bodies for writes; SI-21
  provenance checks remain for read grants and for the confirmation endpoints themselves.
- **Same flow for apps and agents.** Demo P and Demo A share it; the MCP interface (research 07) maps
  tool calls to `effect.propose` and `effect.status`.
- **Latency.** Effects are asynchronous with respect to the workload. Acceptable for consequential
  operations; not intended for high-frequency low-value calls (use mandates).
- **Residuals.** The user can still be persuaded to approve a harmful effect (UI deception through the
  app's own pages before the redirect); the confirmation page mitigates by showing trusted facts.
  Display names of destinations are not verified in Phase 3 (R3B-08).
- **Signed grants still matter.** The authority and broker are separate processes; the broker executes
  only effects backed by an authority-signed grant, so compromise of the gateway's HTTP handling or of
  the broker's request parsing does not let either mint authority (SI-05).

## Reversal

If asynchronous execution proves unworkable for an integration, the ADR-0003 delivery path can be
re-enabled per operation; the grant format is unchanged.


## Revision 1 (2026-10-25) — review changes (all blocking findings)

1. **Intended approver (PC-01).** Every proposal names its intended approver. Only that subject may
   approve, and the broker additionally requires the operation's trusted-fact checks for that subject
   (Demo P: the approver owns the order; Demo A: the approver is the agent's registered principal in
   broker configuration). An approval by any other logged-in user is rejected.
2. **Approval CSRF (PC-02).** The approve endpoint is on the auth origin and accepts only POST with
   `Sec-Fetch-Site: same-origin` relative to the auth origin (or exact auth-origin `Origin` when the header
   is absent) and a single-use approval token embedded in the rendered page, bound to the session, the
   pending id, and the displayed-values digest. Same-site siblings, including the app origin, are rejected.
3. **No cross-user disclosure (PC-03).** The confirmation page renders details only after the session's
   subject is verified as the intended approver and passes the trusted-fact checks; otherwise it returns a
   generic, uniform error.
4. **Immutability and digest commitment (PC-04).** Pending effects are immutable after creation.
   Approval carries the digest of the displayed values; the transition `PENDING → APPROVED` is a
   compare-and-set that succeeds only if the digest equals the stored record's digest and the record is
   still `PENDING` and unexpired. The authority signs only for an `APPROVED` record, exactly once.
5. **Page hardening retained (PC-05).** `frame-ancestors 'none'`, COOP `same-origin`, restrictive CSP,
   `no-store` on the confirmation page. Invariants SI-06/20/21 updated (v0.4) to match this flow.
6. **Mandate selection (PC-06).** Mandates are bound to (workload, principal). The broker selects the
   applicable mandate itself from the proposal's intended approver; the workload cannot name or choose a
   mandate.
7. **Wording (PC-12).** Claims narrowed: displayed values are the workload's proposal as stored; the
   guarantee is equality between what is approved and what executes, plus trusted facts shown alongside.
8. **Non-blocking, adopted for Phase 3:** per-workload limits on outstanding pending effects and
   proposal rate; pending effects expire (default 10 minutes); duplicate proposals with identical values
   are shown as such; free-text parameters are not displayed in Phase 3 operations; the confirmation
   URL contains only the pending id (no redirect parameter). Phase 3 approval is session-based, so SI-20
   is reported **PARTIALLY MET** until WebAuthn approval is implemented.
