# Roadmap

Phases are gated by acceptance criteria, not dates. A phase is complete only when its acceptance
evidence is recorded in [STATUS.md](STATUS.md).

| Phase | Goal | Acceptance | State |
|---|---|---|---|
| 0 | Repository and project knowledge | A fresh session can reconstruct goals and state from the repo | Done |
| 1 | Research and architecture selection | Coherent security model; assumptions stated; initial ADRs accepted | **Active** |
| 2 | Minimal containment (PHP) | Arbitrary PHP execution cannot reach the protected resource under the documented profile | Planned |
| 3 | Cryptographic authorization | Forged, altered, expired, misdirected, or reused grants produce no effect | Planned |
| 4 | Policy engine and effect broker | Approved effects without unrestricted resource authority | Planned |
| 5 | Workflow authorization | Unauthorized workflow transitions rejected; concurrency/retry tested | Planned |
| 6 | Developer experience | A newcomer can run the demo from docs alone | Planned |
| 7 | Generalization | Second language integration; language-neutral protocol | Planned |
| 8 | Security hardening | Fuzzing, failure injection, independent review, supply-chain hardening | Planned |
| 9 | Open-source preparation | Owner can evaluate a release candidate with known limits | Planned |
| 10 | Long-term evolution | WASI-native execution, more adapters, distributed brokers | Research |

Public release of any kind requires explicit approval from the project owner.
