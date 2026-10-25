# Documentation Index

| Document | Purpose |
|---|---|
| [VISION.md](VISION.md) | Problem, hypothesis, scope, principles |
| [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) | Non-negotiable, falsifiable security properties |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Attackers, assets, trust boundaries, out-of-scope threats |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Selected architecture and component relationships |
| [decisions/](decisions/README.md) | Architecture Decision Records (ADRs) |
| [research/](research/README.md) | Prior art, comparisons, research questions |
| [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md) | Unresolved research and engineering questions |
| [../ROADMAP.md](../ROADMAP.md) | Milestones and phases |
| [../STATUS.md](../STATUS.md) | What is implemented and verified; checkpoints; test evidence |

## Source-of-truth hierarchy

When documents conflict, the higher-ranked source wins and the conflict must be recorded in
[OPEN_QUESTIONS.md](OPEN_QUESTIONS.md) — never silently resolved.

1. Explicit instructions from the project owner
2. [Security invariants](SECURITY_INVARIANTS.md)
3. Accepted ADRs
4. Approved specifications (`docs/specs/`)
5. Verified implementation behavior (tests in `STATUS.md`)
6. Current plans (`ROADMAP.md`)
7. Research notes (`docs/research/`)
8. Historical discussion and speculative ideas
