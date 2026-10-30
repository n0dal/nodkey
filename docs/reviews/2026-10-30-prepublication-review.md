# Pre-publication review: full Git history and working tree (2026-10-30)

- **Scope:** all 73 commits reachable from any ref (only `refs/heads/main`; no tags, stash, notes or
  remotes), HEAD `59e3718`, and the working tree (clean apart from Git-ignored files).
- **Method:** secret scanners in containers, `git ls-files`, path inventory of every blob ever
  committed, `git log --all -p` pattern searches, a raw scan of every blob in history (binaries
  included), and manual reading of every scanner hit.
- **Tools:** `zricethezav/gitleaks:v8.21.2` (`detect --source /repo --log-opts=--all`, plus
  `--no-git` on a `git archive HEAD` snapshot) and `trufflesecurity/trufflehog:3.88.0` (`git
  file:///repo` and `filesystem` on the HEAD snapshot, `--no-verification`, so nothing was sent to
  third-party APIs).
- **Limits:** scanners match patterns. A clean result does not show that no secrets exist. Items
  marked NOT CHECKED were not verified.

## Checklist

| # | Item | Result |
|---|---|---|
| 1 | Secrets in any commit (gitleaks + trufflehog) | **PASS**: 16 gitleaks hits, all test-only or false positives; trufflehog 0 |
| 2a | `var/`, `.claude/`, `CLAUDE.md`, `*.env`, keys/certs tracked now or in history | **PASS** |
| 2b | Local paths of the owner's machine | **FAIL** (F-01) |
| 2c | Personal emails, session links, AI co-author trailers in commits | **PASS** |
| 2d | Internal agent instructions / AI-process notes in public files | **FAIL, needs an owner decision** (F-02) |
| 2e | Large binaries | **PASS**: largest blob 270 KB (`tests/vectors/grant-v1/manifest.json`); 4 PNGs ≤ 55 KB, no metadata text chunks |
| 2f | Generated build artefacts tracked | **FAIL** (F-01: `__pycache__/*.pyc`) |
| 3 | Intentionally vulnerable demos: warning, loopback only, no non-loopback published port (HEAD and history) | **PASS**, one Low (F-03) |
| 4 | Committed test keys/certs labelled TEST-ONLY, unusable for real | **PASS**, one Low (F-04) |
| 5 | SECURITY.md contact | **PASS** after this review's edit (see "SECURITY.md change") |
| 6a | LICENSE is canonical Apache-2.0 | **PASS**: byte-identical to apache.org `LICENSE-2.0.txt`, sha256 `cfc7749b…3d30` |
| 6b | NOTICE reads "Nodkey / Copyright 2026 Henry Cuevas" | **PASS** |
| 6c | No third-party code copied without attribution | **PASS (pattern search only)**: no foreign copyright/SPDX headers, no "adapted/copied/ported from" code; all 14 Cargo manifests declare `Apache-2.0`. A provenance audit of every line was not done |
| 7 | `.github/workflows` permissions and secrets | **NOT APPLICABLE**: no `.github/` directory in HEAD or in history |

## Findings

### F-01 (High for public release): committed `.pyc` reveals the owner's local path

- **Files:**
  - `tests/demop/__pycache__/harness.cpython-314.pyc`: in HEAD. Added in `eb0785d`, modified in
    `c4c8473` and `e60eed5`. Blobs `554474aa`, `124e67fa` and `eb951e22` all embed the string
    an absolute local path to `tests/demop/harness.py` (removed from all history before publication).
  - `tests/demoa/__pycache__/harness.cpython-314.pyc`: in HEAD. Added in `59a679b`. Blob `98ae5d5d`
    stores only a relative path, so it reveals nothing, but it is still a build artefact.
- **Why it matters:** the owner's macOS username and directory layout become public, and compiled
  bytecode is committed next to its source.
- **Root cause:** `.gitignore` has no `__pycache__/` or `*.pyc` rule. `git check-ignore` confirms
  the path is not ignored.
- **Reproduction:**
  ```
  git cat-file -p eb951e22 | strings | grep /Users/
  git log --all --format=%h -- tests/demop/__pycache__
  ```
- **Fix:**
  1. `git rm --cached` both files.
  2. Add `__pycache__/` and `*.pyc` to `.gitignore`.
  3. The path also lives in 3 historical commits. Before the repository goes public, either rewrite
     history (for example `git filter-repo --path-glob '*.pyc' --invert-paths`) or have the owner
     explicitly accept the exposure.
- **Private push:** this does not block pushing to a private repository.

### F-02 (Medium, owner decision): AI-process notes in public documents

- **AI-review disclosures:**
  - `README.md:19`, `SECURITY.md:5`, `LIMITATIONS.md:12`, `docs/README.md:34`: "security reviews …
    performed by AI agents".
  - These read as a deliberate disclosure about the reviews, not as authorship attribution. Keep or
    remove them by owner decision.
- **Internal process notes:**
  - `STATUS.md:131` and `STATUS.md:157`: "a safety classifier stopped two agents writing attack
    tests"; "the first implementation agent stopped when a safety classifier withheld a response".
  - These are internal process notes about AI-agent implementation.
- **"Orchestrator" wording** appears in 17 tracked files, for example:
  - "orchestrator ruling": `crates/nodkey-gateway/README.md:90`,
    `docs/decisions/0003-trusted-user-context-and-grant-issuance.md:287`.
  - "Orchestrator verification notes": `docs/research/README.md:19`.
  - Resolution sections in `docs/reviews/*`.
- **`.gitignore:1` comment:** "Internal AI-assistant orchestration (never published …)".
- **Directive tension:** the owner directive says public docs are tool-neutral and that no AI
  attribution may appear anywhere. These lines sit in tension with that. No tool or vendor is named.
  The only "Claude" and "OpenAI" mentions are prior-art citations in
  `docs/research/07-ai-agents-and-tool-authorization.md:102,378` and
  `docs/research/05-governance-licensing-naming.md:166`.
- **Legal review:** `docs/research/05-governance-licensing-naming.md` §5 discusses AI-assisted
  authorship and DCO clause (a). The directive requires that question to go to legal review before
  publication.
- **Reproduction:**
  ```
  git grep -n -i -E 'by AI agents|implementation agent|safety classifier|orchestrator'
  ```

### F-03 (Low): Demo P has no README warning

- **What exists:** `examples/confirmed-refund/` has no README. Its warning is present in other places:
  - the header of `compose.yaml`, lines 1–6;
  - `app/public/index.php:6`;
  - the in-app banner at `index.php:24`.
- **Why it matters:** the top-level `README.md:63` links straight to `compose.yaml`. A visitor who
  browses the directory sees no warning.
- **The other three demos** carry a prominent README warning:
  - `examples/php-ledger/README.md:4`
  - `examples/confirmed-transfer/README.md:4`
  - `examples/agent-support/README.md:3`
- **Published ports, HEAD:** all 5 compose files publish ports only as `127.0.0.1:…`
  (`php-ledger` 8080/8081, the others 8443). Every other service is `network_mode: "none"` or
  `service:gateway`.
- **Published ports, history:** no added compose line in any commit publishes a non-loopback port.
- **Other bind addresses:**
  - `0.0.0.0` inside containers for simpay/mailsink requires the explicit `--container-bind` flag.
  - Public addresses are refused (`tools/simpay/tests/process.rs`).
  - `broker/tests/run-pg-integration.sh:23` uses `-p 127.0.0.1::5432`.

### F-04 (Low): simpay fixture keys are not labelled inside the file

- **File:** `tools/simpay/fixtures/demo-fixture.json:6,8` contains `sk_sim_DEMO…` / `rk_sim_DEMO…`
  with no TEST-ONLY note (JSON has no comments).
- **Why they are harmless:**
  - They are keys for a local simulator only.
  - simpay rejects any key not prefixed `sk_sim_`/`rk_sim_` (test `refuses_bad_configuration`).
  - `tools/simpay/README.md:5` states it holds no real provider keys.
- **Fix:** a `"_note": "TEST-ONLY"` field would make the label explicit.
- **Other committed keys:**
  - `tests/vectors/grant-v1/manifest.json`: only published RFC 8032 test seeds, labelled
    `"warning": "TEST-ONLY …"`, with the README banner at `tests/vectors/grant-v1/README.md:4`.
  - No PEM private keys or certificates are tracked, now or in history.
  - simpay TLS material is generated at run time into the Git-ignored `var/`.

### F-05 (Info): the old project name is in history and docs

- **Where:** "Nodkey" (and earlier "Proof-Bound Execution") appears:
  - in crate paths in history before `e60eed5`;
  - in 22 tracked files at HEAD (`docs/research/*`, `docs/reviews/*`), as dated records.
- **Risk:** none for security. The owner should confirm that keeping the old name public is acceptable.

## Classification of secret-scanner hits (gitleaks, history; HEAD snapshot gives the same 16)

| Rule | Location (first commit) | Classification |
|---|---|---|
| private-key ×2 | `crates/{nodkey,nodkey}-payments-adapter/src/config.rs` test `ca_parsing` (`b9e84d55`) | False positive: literal `AAAA` body used in a negative parser test |
| stripe-access-token | `tools/simpay/tests/process.rs:118` (`37649e67`) | False positive: `sk_live_0123456789abcdef` used to check that simpay *rejects* live-format keys |
| generic-api-key | `tools/simpay/tests/process.rs:122` (`37649e67`) | Test-only: `rk_sim_0123456789abcdef` |
| generic-api-key ×6 | `broker/src/protocol.rs:397…641` (`4f0ec295`) | False positive: example idempotency keys `kAbc_0…` |
| generic-api-key ×6 | `tests/vectors/grant-v1/manifest.json` (`61a944bd`, `8ebfc774`) | Labelled test-only: RFC 8032 §7.1/§7.2 published test seeds |

**Real secrets: none found.**

## SECURITY.md change

The placeholder contact line was replaced with GitHub private vulnerability reporting: the
repository's Security tab → "Report a vulnerability",
<https://github.com/n0dal/nodkey/security/advisories/new>.

The owner must enable "Private vulnerability reporting" in the repository settings, or the link will
not accept reports.

## Before publication

1. F-01: untrack the `.pyc` files, ignore `__pycache__/`, and rewrite history or record the owner's
   acceptance.
2. F-02: owner decision on the AI-process wording, plus legal review of AI-assisted authorship as the
   directive requires.
3. Enable private vulnerability reporting on the GitHub repository.

Publication blocked: yes (public release only, until F-01 is resolved and F-02 is decided; F-01 and F-02 do not block a push to the private repository)
