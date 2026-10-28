# Implementation Status

**Project:** Nodkey (renamed from the provisional "Proof-Bound Execution" on 2026-10-25).

**Maturity:** PROTOTYPE. Nothing in this repository is suitable for production use.

**Focus:** authority control for apps and AI agents performing consequential external actions,
with user-confirmed intent ([ADR-0010](docs/decisions/0010-project-focus.md)).

**Active milestone:** Phase 4 — External effects (Demo P): **complete, verified locally**.
Next: Phase 5 — AI agents (Demo A). Phases 2–3 complete. Next: Phase 4 — Demo P (payments).
Phase 2 (Demo 1, containment) complete.

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

### Phase 3 — confirmed effects (Demo 2, `examples/confirmed-transfer/`)

| Capability | Evidence | Status |
|---|---|---|
| A compromised app can propose but cannot execute any transfer the intended approver did not approve with exactly the displayed values | Demo 2 L-01..03, A1, A2, A10 | PASS (local) |
| Approval cannot be forged from the app origin, a sibling, or cross-site; tokens are single-use and bound to session, pending id, digest | A3, A4 | PASS |
| Only the intended approver can see or approve; others get a uniform 404 | A5, A8 | PASS |
| Replay, re-approval, and expiry produce no extra or late effect | A6, A7 | PASS |
| Authority or broker crash mid-flow → exactly one effect | A11, A12 | PASS |
| App container cannot reach the DB, the authority key, or any control socket | A9 (14 probes) | PASS |
| Grants verified by an independent implementation of the spec | `crates/nodkey-grant`: 280 grant / 26 registry / 19 declaration / 11 transport vectors | PASS |
| Confirmed intent (SI-20) | session-based approval; no WebAuthn yet | **PARTIALLY MET** |
| Credential entry never on the app origin (SI-18) | test login only | **NOT TESTED** |
| Approve-button click-hijacking defences (GW-R-01) | gateway unit tests (inert period, typed amount); no real-browser popup test (T13) | PASS (unit) / NOT TESTED (browser) |

### Phase 4 — confirmed refunds via a simulated payment provider (Demo P, `examples/confirmed-refund/`)

| Capability | Evidence | Status |
|---|---|---|
| The shop app never holds the provider key; only the payments adapter can reach the provider (TLS 1.3, pinned test CA) | Demo P containment + network rows | PASS (local) |
| A refund executes only for the intended customer's own order, with the exact amount, currency, and charge they confirmed | L-01..L-06, PT rows on ownership and binding | PASS |
| No double refund under any simulated ambiguous provider outcome, crash, replay, or key rotation | PT fault/crash/replay rows, PT-43 | PASS |
| Remaining-refundable amount and per-customer daily budgets hold under concurrency | PT rows on races and budgets | PASS |
| A compromised broker cannot obtain a refund the authority did not sign (adapter verifies grants) | adapter tests + PT rows | PASS |
| A refund reversed at the provider after success is detected and alarmed | PT-23 | PASS |
| Rows needing crafted signed grants, clock control, restore drills, key-rotation drills, exact crash points, or HTTP edge cases the simulator cannot emit | 17 rows | **NOT TESTED** |
| A provider that lies consistently | spec §10 residual | not detectable by design |

## Test evidence

| Test / suite | Invariants | Last run | Result | Evidence |
|---|---|---|---|---|
| `tests/demop/run.sh` | SI-01, SI-02, SI-09, SI-10, SI-11, SI-15, SI-16, SI-20 | 2026-10-28 | 92 PASS / 0 FAIL / 17 NOT TESTED | `var/demop/results.json` |
| `crates/nodkey-payments-adapter` (incl. PostgreSQL test) | SI-02, SI-09, SI-16 | 2026-10-27 | 85 passed | local |
| `broker` unit + PostgreSQL (incl. payments) | SI-09, SI-10, SI-11, SI-15 | 2026-10-28 | 73 unit; 28 + 30 PG | local + Docker |
| `crates/nodkey-grant` conformance + robustness | SI-05..SI-09 | 2026-10-25 | 27 tests; all vector categories 0 failures; 1.7 M mutated inputs, no panic, no false accept | local |
| `crates/nodkey-authority` | SI-05, SI-09, SI-20 | 2026-10-25 | 51 passed (incl. crash/restart exactly-once) | local, macOS |
| `crates/nodkey-gateway` (default / features) | SI-18, SI-20, SI-21 | 2026-10-25 | 40 / 54 passed | local, macOS |
| `broker` unit + PostgreSQL integration | SI-06, SI-09, SI-11, SI-15, SI-16 | 2026-10-25 | 64 unit; 28/28 PG | local + Docker |
| `tools/simpay` | — (untrusted simulator) | 2026-10-25 | 64 passed | local |
| `tests/demo2/run.sh` (no retries) | SI-01, SI-02, SI-05, SI-06, SI-09, SI-13, SI-15, SI-20, SI-21 | 2026-10-25 | 29/29 PASS | `var/demo2/results.json` |
| Demo 1 regression after Phase 3 changes | SI-01..SI-03, SI-08, SI-09, SI-13, SI-16 | 2026-10-25 | protected 65 PASS / 2 N/A; idempotency 7/7 | local |
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

### 2026-10-28 — Phase 4 complete (Demo P)
- **Decisions:** ADR-0012 rev. 2 (separate grant-verifying payments adapter; broker-owned refund
  state; adapter-only provider egress and database channel). Specs: payments-adapter-v1 Draft 3.3,
  effect-protocol-v2 Draft 3.1 (charge_id).
- **Reviews:** design review + re-check; code reviews of adapter and broker payments found three
  High issues (key-rotation double refund ×2, operator-role permission) — all fixed and tested.
- **Integration:** Demo P suite 109 rows; six failures found and resolved (one real broker defect:
  post-success reversal not detected; one spec overclaim; four test-plan rows corrected to the spec).
- **Process:** a safety classifier stopped two agents writing attack tests; the owner chose a fresh
  agent with a narrow conformance brief, which completed the suite.
- **Next:** Phase 5 — Demo A (AI agent; MCP tool interface; mandates).

### 2026-10-25 — Phase 3 implementation verified
- **Decisions:** ADR-0010 (refocus on external consequential actions, owner decision), ADR-0011
  (propose → confirm → execute; workloads never hold write grants), ADR-0003 Phase 3 profile.
- **Specs:** grant-v1 Draft 2 (336 vectors), effect-protocol-v2 Draft 2 (digest vectors).
- **Built:** nodkey-grant (clean-room), broker v2, nodkey-authority, nodkey-gateway, simpay,
  Demo 2. Each security-critical component independently reviewed; no Critical findings; one High
  (gateway popup click-hijack) fixed; all Medium findings fixed or dispositioned.
- **Integration found:** DEMO2-F02 (authority stale connection) — fixed; harness retry removed.
- **Incident:** an agent once sent the owner's email in a User-Agent header to crates.io; reported;
  rule added to all agent definitions; no repository content affected.
- **Not tested:** real-browser popup/clickjack test (T13), WebAuthn, Linux multi-uid for unit tests
  (covered in Demo 2 containers), production hosts, payments (Phase 4), mandates (Phase 4/5).
- **Next:** spec Draft 3 alignment; then Phase 4 Demo P (payments adapter for simpay, TLS front,
  budgets/mandates, attacks P-01..P-19).

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
