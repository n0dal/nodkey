# ADR-0011: Propose → confirm → execute for consequential effects

- **Status:** Proposed (2026-10-25) — supersedes the write-grant delivery path of the ADR-0003 Phase 3
  profile (items 4 and 7) once accepted; requires a focused review.
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
   pending effect's exact values **as stored by the broker**, plus broker-resolved trusted facts (for
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
