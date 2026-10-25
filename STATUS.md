# Implementation Status

**Project:** Nodkey (renamed from the provisional "Proof-Bound Execution" on 2026-10-25).

**Maturity:** PROTOTYPE. Nothing in this repository is suitable for production use.

**Active milestone:** Phase 3 — Cryptographic authorization (next). Phase 2 (Demo 1, minimal
containment) is complete: EXPERIMENTAL, verified locally under Deployment Profile P0, independently
reviewed, with documented limitations.

## Verified functionality

| Capability | Profile | Evidence | Status |
|---|---|---|---|
| Workload has no network route, DNS, egress, or interface other than loopback | P0 | N-01..N-07 | PASS (local Colima VM) |
| Workload holds no DB credential (env, filesystem, other processes' env/cmdline) | P0 | C-01..C-03 | PASS |
| DB rejects the broker's own credential from any non-broker address | P0 | R-01 | PASS |
| Attacker code cannot modify the ledger directly | P0 | A-01 (baseline: attack succeeds) | PASS |
| App code read-only; no exec from writable mounts; no persistence across recreate | P0 | F-01..F-03 | PASS |
| No container-runtime or other-workload sockets reachable | P0 | S-01, S-02 | PASS |
| Broker accepts only declared, typed operations; strict parsing; per-op limits | P0 | B-01..B-11 | PASS |
| Transfers are idempotent per (workload, key); ambiguous outcomes reported as `outcome_unknown`, never as failure | P0 | B-12; `tests/integration/idempotency.sh` cases A–F | PASS (independently reviewed; ID-02 fix has no automated test yet) |
| Workload confinement configuration matches P0 (no_new_privs, seccomp, zero capabilities, AppArmor enforce, read-only rootfs, network none, mount allowlist) | P0 | P-01..P-05 | PASS |
| nginx ignores app-controlled X-Accel-* headers | P0 | X-01 (baseline: redirect followed) | PASS |
| Cloud metadata endpoint unreachable | P0 | N-06 | NOT APPLICABLE locally (no metadata service); must be re-tested on a cloud host |

How results are qualified (`tests/containment/run.sh both`): reachability probes require a passing
positive control (K-DB, K-NET); probes listed as SENSITIVE count as PASS in the protected profile only
if the same probe detected the breach in the baseline; the secret search (C-03) requires its baseline
control (C-03K) to find a secret that is present; R-01 requires the server's own `pg_hba` rejection;
any probe that does not report is NOT TESTED. Probes without a breach counterpart (S-01, S-02, B-*,
P-03, F-01, F-03) rest on direct observation only.

## Test evidence

| Test / suite | Invariants | Last run | Result | Evidence |
|---|---|---|---|---|
| `cargo test` (broker unit tests) | SI-08, SI-09, SI-15, SI-16 | 2026-10-25 | 40 passed | local run, macOS host |
| `cargo clippy --all-targets` | — | 2026-10-25 | no warnings | local run |
| `tests/containment/run.sh both` — protected (P0) | SI-01, SI-02, SI-03, SI-08, SI-09, SI-13, SI-16 | 2026-10-25 | 65 PASS, 2 NOT APPLICABLE, 0 FAIL, 0 INCONCLUSIVE | `var/containment/results-protected.json` (local, Git-ignored) |
| `tests/containment/run.sh both` — baseline (positive control) | — | 2026-10-25 | 24 FAIL as expected: every SENSITIVE probe detected its breach; C-03K found the planted-in-env secret | `var/containment/results-baseline.json` |
| `tests/integration/idempotency.sh` | SI-09, SI-15 | 2026-10-25 | 6/6 PASS (incl. D1-01 reproduction: paused DB → `outcome_unknown`, retry replays, one debit) | local run |

Environment: macOS 26.5.1 arm64 host; Colima 0.10.3 VM (Ubuntu 24.04.4, kernel 6.8.0-117, AppArmor,
Docker default seccomp); Docker 29.5.2; Compose 5.6.1; Rust 1.99.1; PHP 8.4 (image).

**Not tested:** gVisor (P1); production Linux hosts; cloud metadata exposure; rootless Docker;
broker resistance to resource exhaustion and per-workload fairness (D1-07); the idempotency unique-violation branch under real DB concurrency (the broker currently serializes on one connection); durable audit of denials (D1-04); business-level limits (D1-06, Phase 3/4); anything in Phases 3+.

## Checkpoints

### 2026-10-25 — Phase 2 / Demo 1 implemented
- **Done:** Rust broker (`broker/`), intentionally vulnerable PHP ledger demo with P0 and baseline
  profiles (`examples/php-ledger/`), containment suite (`tests/containment/`).
- **Defects found and fixed during verification:** broker DB role lacked `SELECT (id)` on `transfers`
  required by `INSERT … RETURNING id` (the broker failed closed: nothing committed, generic
  `unavailable` returned); C-01 false positive on the upstream image's public `GPG_KEYS` (exact-name
  allowlist with justification; C-03 still searches for the actual secret value).
- **Process note:** the first implementation agent stopped when a safety classifier withheld a
  response while it was writing the attack probes; the orchestrator wrote the probes, scoped to fixed
  checks against the demo's own local services.
- **Independent review** (`docs/reviews/2026-10-25-demo1-code-review.md`): 2 High fixed (D1-01 ambiguous
  outcomes + idempotency; D1-02 vacuous exec probe), Mediums D1-03/D1-05/D1-08 fixed, D1-04/D1-06/D1-07
  documented as Demo 1 limitations in `examples/php-ledger/README.md`.
- **Idempotency re-review** (`docs/reviews/2026-10-25-idempotency-review.md`): ID-01 High (UI claimed
  "nothing was charged" during a stalled double-submit) fixed with regression case G; ID-02 Medium
  (lookup before lock) fixed, no automated test yet.
- **Final run:** protected 65 PASS / 2 NOT APPLICABLE / 0 FAIL / 0 INCONCLUSIVE; baseline 24 FAIL as
  expected; idempotency 7/7 PASS; 40 unit tests; clippy clean.
- **Next:** Phase 3 (Rust gateway, separate
  authority, signed grants per ADR-0003/0004).
- **Open:** ADR-0001/0002/0003/0004/0007/0009 Proposed (see `docs/decisions/README.md`); OQ-01
  closure needs the PostgREST RPC+RLS comparison (AR-14).

### 2026-10-24/25 — Phase 1: research and architecture
- Five research notes, threat model, architecture, ADR-0001..0009, adversarial architecture review
  (20 findings, all dispositioned), invariants v0.2. Owner decisions: copyright holder "Henry Cuevas";
  project name "Nodkey" (trademark clearance by counsel still required).

### 2026-10-24 — Phase 0: repository initialization
- Repository, knowledge base, internal (Git-ignored) agent orchestration, attribution disabled.
