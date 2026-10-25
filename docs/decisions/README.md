# Architecture Decision Records

Each ADR is a file `NNNN-short-title.md` using [TEMPLATE.md](TEMPLATE.md).
Statuses: `Proposed` → `Accepted` | `Rejected`; later `Superseded by ADR-NNNN`.

| ID | Title | Status |
|---|---|---|
| [0001](0001-architecture-and-tcb.md) | Architecture A (OS isolation + external broker) and the v0 TCB | Proposed |
| [0002](0002-broker-execution-model.md) | Broker execution model | Proposed |
| [0003](0003-trusted-user-context-and-grant-issuance.md) | Trusted user context and grant issuance | Proposed |
| [0004](0004-grant-format.md) | Grant format — restricted COSE_Sign1 profile | Proposed |
| [0005](0005-policy-engine.md) | Policy evaluation — Cedar embedded in the broker | Proposed |
| [0006](0006-replay-and-effect-state.md) | Replay prevention and effect state | Proposed |
| [0007](0007-receipts-and-workflows.md) | Receipts are evidence; workflow state is broker-owned | Proposed |
| [0008](0008-implementation-language.md) | Rust for trusted components; thin untrusted PHP SDK | Proposed |
