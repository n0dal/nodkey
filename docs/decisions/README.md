# Architecture Decision Records

Each ADR is a file `NNNN-short-title.md` using [TEMPLATE.md](TEMPLATE.md).
Statuses: `Proposed` → `Accepted` | `Rejected`; later `Superseded by ADR-NNNN`.

| ID | Title | Status |
|---|---|---|
| [0001](0001-architecture-and-tcb.md) | Architecture A (OS isolation + external broker) and the v0 TCB | Proposed (OQ-01 open) |
| [0002](0002-broker-execution-model.md) | Broker execution model | Proposed (OQ-01 open) |
| [0003](0003-trusted-user-context-and-grant-issuance.md) | Trusted user context and grant issuance (rev. 3) | Accepted with Phase 3 profile; items 1, 4 (delivery), 7 superseded by ADR-0011 |
| [0004](0004-grant-format.md) | Grant format — restricted COSE_Sign1 profile | Proposed (OQ-07 open) |
| [0005](0005-policy-engine.md) | Policy evaluation — Cedar embedded in the broker | Accepted |
| [0006](0006-replay-and-effect-state.md) | Replay prevention, budgets, and effect state | Accepted |
| [0007](0007-receipts-and-workflows.md) | Outcomes are evidence; workflow state is broker-owned | Proposed (with ADR-0009) |
| [0008](0008-implementation-language.md) | Rust for trusted components; thin untrusted PHP SDK | Accepted |
| [0009](0009-workload-authority-and-background-operations.md) | Workload-authority and background operations (rev. 2) | Proposed (Phase 5 scope) |
| [0010](0010-project-focus.md) | Project focus: authority control for consequential external actions | Accepted (owner) |
| [0011](0011-propose-confirm-execute.md) | Propose → confirm → execute for consequential effects | Accepted (rev. 1) |
