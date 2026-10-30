# Documentation Index

New here? Start with the [README](../README.md), [QUICKSTART](../QUICKSTART.md), and
[LIMITATIONS](../LIMITATIONS.md).

## Current design

| Document | Purpose |
|---|---|
| [VISION.md](VISION.md) | Problem, hypothesis, scope, principles |
| [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) | Non-negotiable, falsifiable security properties (SI-xx) |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Attackers, assets, trust boundaries, assumptions, residual risks |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture and component relationships (draft) |
| [specs/](specs/README.md) | Normative specifications: grant format, effect protocol, payments adapter, agent interface |
| [decisions/](decisions/README.md) | Architecture Decision Records (ADRs) and their status |
| [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md) | Unresolved research and engineering questions |

## Project state

| Document | Purpose |
|---|---|
| [../STATUS.md](../STATUS.md) | What is implemented and verified; checkpoints; test evidence |
| [../ROADMAP.md](../ROADMAP.md) | Phases and acceptance criteria |
| [../LIMITATIONS.md](../LIMITATIONS.md) | Consolidated limits, residuals, and NOT TESTED items |

## Historical records

These are point-in-time records. They are kept for traceability and are not updated when the design
changes; current specs, ADRs, and invariants take precedence.

| Directory | Contents |
|---|---|
| [research/](research/README.md) | Research notes (2026-10-24 onward): prior art, comparisons, research questions |
| [reviews/](reviews/) | Design and code reviews with finding IDs and dispositions. All were performed by AI agents; none is an independent human audit. Research notes and reviews are dated records kept as written: they use the earlier project names (including "Proof-Bound Execution" and the name used before 2026-10-30), and their crate, path, and protocol identifiers correspond to today's `nodkey-*` / `nodkey.*` names |

## Source-of-truth hierarchy

When documents conflict, the higher-ranked source wins and the conflict must be recorded in
[OPEN_QUESTIONS.md](OPEN_QUESTIONS.md), never silently resolved.

1. Explicit instructions from the project owner
2. [Security invariants](SECURITY_INVARIANTS.md)
3. Accepted ADRs
4. Approved specifications (`docs/specs/`)
5. Verified implementation behavior (tests in `STATUS.md`)
6. Current plans (`ROADMAP.md`)
7. Research notes (`docs/research/`)
8. Historical discussion and speculative ideas
