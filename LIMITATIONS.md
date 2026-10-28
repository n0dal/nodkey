# Limitations

Nodkey is a **research prototype**. Nothing in this repository is suitable for production use.
This page consolidates limits stated in [STATUS.md](STATUS.md), the
[threat model](docs/THREAT_MODEL.md) (§5 assumptions, §6 residual risks), the
[security invariants](docs/SECURITY_INVARIANTS.md), and the published residuals of the specs. Where this
page and those documents differ, those documents are authoritative.

## Assurance

- **No independent human audit.** Every design and code review in [`docs/reviews/`](docs/reviews/) was
  performed by AI agents. Reviews found and fixed defects; they do not establish absence of defects.
- **Tests are not proofs.** Results come from local runs of the demo suites and unit tests on one
  development machine (macOS host, Colima VM with Ubuntu 24.04, AppArmor, Docker default seccomp). No
  production host, cloud host, or rootless Docker has been tested.
- **No formal model, no mutation testing.** Fuzzing so far: about 1.7 M mutated inputs against the grant
  verifier (STATUS.md).

## What Nodkey does not protect against

- **Code execution and prompt injection themselves.** Nodkey limits consequences, not occurrence
  (agent-interface-v1 R-A3).
- **Misuse within granted authority.** A compromised workload can still invoke every operation its
  current grants, mandates, and policy allow; an agent can misuse a mandate within its bounds (R-A1).
- **Exfiltration through allowed channels** and of any data that reaches the workload (THREAT_MODEL R-5,
  R-A2). Demo A row S8 shows a "card details" message to the in-scope customer executing.
- **False output, dropped or delayed requests, denial of service** by the workload (R-6), and side
  channels or residual resource exhaustion (R-14).
- **Deceiving the approver.** Displayed values are the workload's proposal; only their equality with what
  executes is guaranteed. UI deception, phishing of the auth origin before passkeys, and an approver who
  does not read the page remain (R-4; effect-protocol-v2 §6; R-A6, R-A8).
- **In-page abuse while a user is active** on a compromised app origin: non-confirmed effects up to the
  budgets (R-3, quantified in the threat model).
- **External effects cannot be recalled** once dispatched (R-13). A provider that lies consistently is
  not detectable (payments-adapter-v1 §10).

## Out of scope: compromised trusted components and host

The invariants assume the host kernel, container runtime, gateway, authority, and broker are not
compromised (attackers I and J). In particular:

- a kernel or runtime escape from the workload (R-1) voids containment;
- a compromised gateway can approve any existing pending record as any logged-in user;
- a compromised authority can sign anything;
- a compromised broker bypasses broker-only controls (revocation, budgets, message bounds), though for
  refunds it is still bounded by user approvals and the payments adapter's own checks
  (payments-adapter-v1 §10; R-A9);
- host clock rollback defeats age and key-rotation rules; replay across a database restore is not claimed
  until ADR-0006 §8–9 is implemented (R-12).

## Depends on deployment

All claims hold only under the documented deployment profile (P0 and the demo compose files) and the
threat-model assumptions: single Linux host or VM, uncompromised kernel and runtime, exactly the
documented compose configuration, digest-pinned images, distinct uid per workload. Configuration drift
voids the profile (R-15); the planned `verify` command does not exist yet. gVisor (profile P1) is not
tested. Cloud metadata exposure must be re-tested on a cloud host (N-06 is NOT APPLICABLE locally).

## Partially met or not tested

- **SI-20 (confirmed intent): PARTIALLY MET.** Approval is session-based with a credential-less test
  login; there is no WebAuthn/passkey binding yet.
- **SI-18 (credential entry never on the app origin): NOT TESTED** (test login only).
- **Click-hijacking defences:** unit-tested only; no real-browser popup or timed-click test (T13). WebKit
  behaviour for service-worker headers is unverified (R-19).
- **Demo P: 17 NOT TESTED rows**, for example concurrency of 32 refunds on one budget row, refunds across
  UTC midnight, crafted signed grants, broker clock set back, `K_idem` rotation with non-final rows, TLS
  1.2-only or plain-HTTP providers, exact crash points, restore drill, HTTP edge cases.
- **Demo A: 14 NOT TESTED rows**, for example retry after a dropped response, the baseline positive
  control, changes between signing and execution, approval racing the mandate loop, revocation races,
  the broker-compromise suite, authority crash points, the grant-v1 Draft 4 mandate vectors, and the
  optional real-model mode.
- **Demo 1:** broker resistance to resource exhaustion and per-workload fairness (D1-07); the idempotency
  unique-violation branch under real database concurrency; durable audit of denials (D1-04); the ID-02
  fix has no automated test.
- **Mandate grant vectors** (grant-v1 Draft 4) were generated and verified by the same author; readings
  D4-1..5 are flagged for review.

## Simulators only

No real payment provider, mail service, or AI model has been connected. `simpay` and `mailsink` are
simulators; the Demo A agent is a deterministic program. Real providers lack simpay's idempotency status
query, so some failure cases there need an operator (payments-adapter-v1 §10).

## Other

- The project name "Nodkey" has not been cleared as a trademark.
- Several ADRs are still Proposed ([index](docs/decisions/README.md)); open questions are in
  [OPEN_QUESTIONS.md](docs/OPEN_QUESTIONS.md).
