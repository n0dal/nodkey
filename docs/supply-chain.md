# Supply chain: advisories, licenses, short fuzzing pass

Snapshot taken 2026-10-28. PROTOTYPE project; this is an inventory and a short automated check,
not an audit. Nothing here changes a `Cargo.toml` or `Cargo.lock`; actions are recommendations.

## Method

All tools ran inside one throw-away container (nothing installed on the host):

```
docker run -d --name nodkey-fuzz -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/build/target \
  rust:1.99-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb sleep infinity
# inside: apt-get install g++ git python3; rustup toolchain install nightly --profile minimal
# cargo install --locked cargo-audit cargo-deny cargo-fuzz
```

| Tool | Version |
|---|---|
| rustc / cargo (stable, image) | 1.99.1 (58cf8f9c3 2026-10-13) / 1.99.1 |
| rustc nightly (fuzzing only) | 1.101.0-nightly (41089d07a 2026-10-27) |
| cargo-audit | 0.22.2 |
| cargo-fuzz | 0.13.2 |
| RustSec advisory DB | git `40f5be6fb12ed93fc591bf4ab23b7d793b3f2239`, committed 2026-10-28T09:50:03+01:00 |

Commands, per lockfile directory `$d`:

```
cargo audit --json                                     # (first run fetches the DB; later runs --no-fetch)
cargo metadata -q --locked --format-version 1          # dependency graph + license fields
cargo tree -q --locked -i <crate> -e normal,build      # paths to advisory crates (-e all for dev edges)
```

SHA-256 of all 22 `Cargo.toml`/`Cargo.lock` files was recorded before and after the work and
compared (see "Integrity of manifests" below).

Counting rules (from `cargo metadata`, all target platforms, so Windows/WASM/Redox-only crates
are included): **direct** = entries in the package's `[dependencies]` / `[dev-dependencies]`;
**production closure** = third-party packages reachable from the package over normal and build
edges; **with dev** = the same, also following the package's own dev-dependencies. Path-local
Nodkey crates are excluded from the third-party counts. `cargo audit` counts every package in
the lockfile including the root and local crates.

## Per crate

| Lockfile | Direct (normal / dev) | Third-party, production | Third-party, with dev | `cargo audit` packages | Advisories |
|---|---|---|---|---|---|
| `broker/` | 6 / 2 | 100 | 131 | 135 | 1: RUSTSEC-2026-0385 (ctutils 0.4.2) |
| `crates/nodkey-grant/` | 4 / 1 | 31 | 31 | 32 | 0 |
| `crates/nodkey-authority/` | 7 / 0 | 44 | 44 | 46 | 0 |
| `crates/nodkey-gateway/` | 14 / 1 | 79 | 108 | 110 | 1: RUSTSEC-2026-0009 (time 0.3.45, dev-only) |
| `crates/nodkey-payments-adapter/` | 15 / 1 | 130 | 130 | 132 | 1: RUSTSEC-2026-0385 (ctutils 0.4.2) |
| `crates/nodkey-mcp-front/` | 2 / 1 | 23 | 23 | 24 | 0 |
| `tools/mailsink/` | 4 / 0 | 90 | 90 | 91 | 1: RUSTSEC-2026-0385 (ctutils 0.4.2) |
| `tools/simpay/` | 11 / 0 | 91 | 91 | 92 | 2: RUSTSEC-2026-0385 (ctutils 0.4.2), RUSTSEC-2026-0009 (time 0.3.45) |
| `tools/demo-agent/` | 2 / 1 | 23 | 24 | 25 | 0 |
| `tests/vectors/grant-v1/gen/` | 5 / 0 | 36 | 36 | 37 | 0 |
| `tests/vectors/effect-v2/gen/` | 2 / 0 | 25 | 25 | 26 | 0 |

`cargo audit` reported no "unmaintained", "unsound" or "yanked" warnings for any lockfile.
Exit codes: 1 for broker, gateway, payments-adapter, mailsink, simpay (vulnerability found); 0 for
the rest.

## Advisories

Two distinct advisories, six occurrences.

### RUSTSEC-2026-0385 — ctutils 0.4.2: non-constant-time mask generation and `u128` comparisons

- Source: RustSec advisory DB `crates/ctutils/RUSTSEC-2026-0385.md` (dated 2026-10-23, category
  `crypto-failure`, no CVSS score assigned); upstream fix https://github.com/RustCrypto/utils/pull/1569.
  Patched: `>= 0.4.4`.
- What it says: `ctutils::Choice` mask generation could compile to a branch on common platforms,
  and `u128` comparisons branched on 32-bit targets; branches on secret values can leak them through
  timing side channels.
- Where it is: `ctutils` is pulled in only by `digest 0.11.3` with its `mac` feature
  (`cargo tree -i ctutils`; `digest-0.11.3/Cargo.toml`: `mac = ["dep:ctutils"]`). In
  `digest-0.11.3/src/mac.rs`, `ctutils::CtEq` is used only by `Mac::verify*` (tag comparison) and
  by `CtOutput`'s equality.
- Reachability (established by grep of this repository and of the vendored crate sources in the
  container; not by dynamic analysis):
  - Nodkey code never calls `verify_slice`/`verify`/`CtOutput ==`: the payments adapter
    (`src/derive.rs`) and simpay (`src/webhook.rs`) only compute HMACs (`finalize().into_bytes()`);
    the gateway has its own `util::ct_eq` and does not depend on ctutils.
  - Reachable path: `tokio-postgres` → `postgres-protocol 0.6.12`
    `src/authentication/sasl.rs:300` `hmac.verify_slice(&verifier)` — the SCRAM-SHA-256 client's
    check of the **server** signature. Used by the broker, the payments adapter and mailsink when
    they authenticate to PostgreSQL with SCRAM.
- Relevance (hypothesis, not tested): low. Exploiting it would require an attacker who already
  impersonates the database server on the broker/adapter's DB network and can measure fine-grained
  timing of a byte-wise comparison against a per-connection value (fresh nonces each connection).
  `ed25519-dalek`/`curve25519-dalek` also depend on `digest`, but without the `mac` path.
- Severity assigned here: **Low** (no CVSS published).
- Recommended action: `cargo update -p ctutils --precise 0.4.4` (or newer 0.4.x; 0.4.6 is current
  on crates.io as resolved during the fuzz build) in `broker/`, `crates/nodkey-payments-adapter/`,
  `tools/mailsink/`, `tools/simpay/`. Semver-compatible; lockfile-only change. Re-run the crates'
  test suites afterwards.

### RUSTSEC-2026-0009 — time 0.3.45: denial of service via stack exhaustion (CVE-2026-25727, GHSA-r6v5-fh4h-64xc)

- Source: RustSec DB `crates/time/RUSTSEC-2026-0009.md` (2026-02-05); CVSS 4.0
  `AV:N/AC:H/AT:N/PR:L/UI:A/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H`. Patched: `>= 0.3.47`.
- What it says: parsing attacker-supplied input with the RFC 2822 format (`Date::parse`,
  `OffsetDateTime::parse`, ... `parsing::Parsed::parse_item`) can exhaust the stack.
- Where it is: only via `rcgen 0.14.7` (and its `yasna`/`x509-parser` stack):
  - `crates/nodkey-gateway`: `rcgen` is a **dev-dependency** (`cargo tree -i time -e all` shows
    only `[dev-dependencies]` edges) — not in the gateway binary.
  - `tools/simpay` (test-only payment simulator): normal dependency, used to generate test
    certificates.
- Reachability: no Nodkey code parses RFC 2822 dates (grep finds no `time::` parse calls);
  rcgen uses `time` to format certificate validity, not to parse untrusted RFC 2822 text
  (established for our call sites by grep; not verified inside rcgen).
- Severity assigned here: **Informational** for Nodkey (not reachable from any shipped component).
- Recommended action: `cargo update -p time` (to `>= 0.3.47`) in `crates/nodkey-gateway/` and
  `tools/simpay/` to clear the finding; check rust-version (MSRV) compatibility of the resolved
  `time` release against each crate's `rust-version`.

### General recommendations

- Add `cargo audit` (with a pinned advisory-DB revision recorded in the evidence) to the
  verification script so new advisories surface on every run.
- Consider a `deny.toml` with `cargo deny check advisories licenses bans sources` to enforce the
  license allowlist below and to forbid non-crates.io sources mechanically. Not done in this pass.

## License inventory

Source: the `license` field of every package in each lockfile's resolved graph (`cargo metadata`).
These are the crates' self-declared SPDX expressions; LICENSE files were **not** inspected.
No package lacked a `license` field (none fell back to `license-file`). 166 unique third-party
packages (name + version) across the 11 lockfiles. Every package that is dev-only in one lockfile
is a production dependency in another, so no group below is purely dev-only.

**Flags: none.** Every expression is permissive and compatible with distributing Nodkey under
Apache-2.0. No package is licensed only under a copyleft licence. Notes:

- `r-efi 6.0.0` offers LGPL-2.1-or-later as one alternative; MIT/Apache-2.0 can be elected. It is
  a UEFI-target-only dependency of `getrandom` and is never compiled for Linux.
- `ring 0.17.14` declares `Apache-2.0 AND ISC` (both must be honoured; both are permissive).
- `unicode-ident` / `unicode-normalization` add `Unicode-3.0` (permissive, attribution).
- MIT, BSD-3-Clause, ISC, Zlib and BSL-1.0 require keeping copyright/licence notices when binaries
  are redistributed. Recommendation: generate a third-party notices file for any binary release
  (e.g. `cargo about`) — a release task, not needed for local use.
- Legal review is still the owner's call; this is an engineering inventory, not legal advice.

| License expression | Count | Packages |
|---|---|---|
| MIT OR Apache-2.0 | 102 | asn1-rs 0.7.2, asn1-rs-derive 0.6.0, async-trait 0.1.92, base64 0.22.1, bitflags 2.13.2, block-buffer 0.12.1, bumpalo 3.20.3, cc 1.10.0, cfg-if 1.0.5, chacha20 0.10.2, cpufeatures 0.3.1, crypto-common 0.2.2, der-parser 10.0.0, deranged 0.5.9, digest 0.11.3, displaydoc 0.2.7, errno 0.3.14, find-msvc-tools 0.1.15, form_urlencoded 1.2.2, futures-channel 0.3.34, futures-core 0.3.34, futures-sink 0.3.34, futures-task 0.3.34, futures-util 0.3.34, getrandom 0.2.17, getrandom 0.4.3, hashbrown 0.17.1, hmac 0.13.0, http 1.5.0, httparse 1.10.1, httpdate 1.0.3, hybrid-array 0.4.15, itoa 1.0.18, js-sys 0.3.106, lazy_static 1.5.1, libc 0.2.191, lock_api 0.4.14, log 0.4.34, md-5 0.11.0, num-bigint 0.4.8, num-conv 0.1.0, num-integer 0.1.47, num-traits 0.2.19, oid-registry 0.8.1, once_cell 1.21.4, parking_lot 0.12.5, parking_lot_core 0.9.12, percent-encoding 2.3.2, postgres-protocol 0.6.12, postgres-types 0.2.14, powerfmt 0.2.1, proc-macro2 1.0.107, quote 1.0.47, rand 0.10.3, rand_core 0.10.1, rcgen 0.14.7, rustc_version 0.4.1, rustls-pki-types 1.15.1, rustversion 1.0.23, scopeguard 1.2.0, semver 1.0.28, serde 1.0.229, serde_core 1.0.229, serde_derive 1.0.229, serde_json 1.0.154, sha2 0.11.0, sha2 0.11.1, shlex 2.0.1, signal-hook-registry 1.4.8, siphasher 1.0.4, smallvec 1.16.4, socket2 0.6.5, syn 2.0.119, syn 3.0.9, thiserror 2.0.21, thiserror-impl 2.0.21, time 0.3.45, time-core 0.1.7, time-macros 0.2.25, tokio-postgres 0.7.18, tokio-rustls 0.26.6, typenum 1.20.1, unicode-bidi 0.3.18, wasm-bindgen 0.2.129, wasm-bindgen-macro 0.2.129, wasm-bindgen-macro-support 0.2.129, wasm-bindgen-shared 0.2.129, web-sys 0.3.106, windows-link 0.2.1, windows-sys 0.52.0, windows-sys 0.61.2, windows-targets 0.52.6, windows_aarch64_gnullvm 0.52.6, windows_aarch64_msvc 0.52.6, windows_i686_gnu 0.52.6, windows_i686_gnullvm 0.52.6, windows_i686_msvc 0.52.6, windows_x86_64_gnu 0.52.6, windows_x86_64_gnullvm 0.52.6, windows_x86_64_msvc 0.52.6, x509-parser 0.18.1, yasna 0.5.2 |
| MIT | 21 | bytes 1.12.1, data-encoding 2.11.1, http-body 1.1.0, http-body-util 0.1.5, hyper 1.12.0, hyper-util 0.1.21, libredox 0.1.25, mio 1.2.4, nom 7.1.3, pem 3.0.6, phf 0.13.1, phf_shared 0.13.1, redox_syscall 0.5.18, slab 0.4.12, synstructure 0.13.2, tokio 1.54.1, tokio-macros 2.7.2, tokio-util 0.7.20, try-lock 0.2.5, want 0.3.2, zmij 1.0.23 |
| Apache-2.0 OR MIT | 11 | atomic-waker 1.1.2, autocfg 1.5.1, cmov 0.5.4, const-oid 0.10.2, ctutils 0.4.2, ed25519 3.0.0, equivalent 1.0.3, indexmap 2.14.2, pin-project-lite 0.2.17, signature 3.0.0, zeroize 1.9.1 |
| MIT/Apache-2.0 (legacy syntax) | 7 | asn1-rs-impl 0.2.0, curve25519-dalek-derive 0.1.1, fallible-iterator 0.2.0, minimal-lexical 0.2.1, rusticata-macros 4.1.0, stringprep 0.1.5, unicode-properties 0.1.4 |
| Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 6 | wasi 0.11.1+wasi-snapshot-preview1, wasi 0.14.7+wasi-0.2.4, wasip2 1.0.1+wasi-0.2.4, wasip2 1.0.4+wasi-0.2.12, wit-bindgen 0.46.0, wit-bindgen 0.57.1 |
| BSD-3-Clause | 3 | curve25519-dalek 5.0.0, ed25519-dalek 3.0.0, subtle 2.6.1 |
| Zlib OR Apache-2.0 OR MIT | 3 | objc2-core-foundation 0.3.2, objc2-system-configuration 0.3.2, tinyvec 1.13.3 |
| Unlicense OR MIT | 2 | byteorder 1.5.0, memchr 2.8.3 |
| ISC | 2 | rustls-webpki 0.103.16, untrusted 0.9.0 |
| (MIT OR Apache-2.0) AND Unicode-3.0 | 2 | unicode-ident 1.0.27, unicode-normalization 0.1.26 |
| Apache-2.0 OR BSL-1.0 OR MIT | 2 | wasite 1.0.2, whoami 2.1.3 |
| MIT OR Apache-2.0 OR BSD-1-Clause | 1 | fiat-crypto 0.3.0 |
| Zlib | 1 | foldhash 0.2.0 |
| MIT OR Apache-2.0 OR LGPL-2.1-or-later | 1 | r-efi 6.0.0 |
| Apache-2.0 AND ISC | 1 | ring 0.17.14 |
| Apache-2.0 OR ISC OR MIT | 1 | rustls 0.23.46 |

## Fuzzing (short pass)

**A short, single-run pass on one machine. It found nothing, which is weak evidence; it is not a
security guarantee and does not replace review, the conformance vectors, or longer campaigns.**

### Targets

Each harness is its own cargo package (with `[workspace]`, so the crate's `Cargo.toml`/`Cargo.lock`
are untouched) under the crate's `fuzz/` directory. Each `fuzz/Cargo.lock` was started from a copy
of the crate's own `Cargo.lock`, so the fuzzed dependency versions are the shipped ones; cargo only
added harness packages (`libfuzzer-sys 0.4.13`, `arbitrary 1.5.0`, `jobserver`, and for the grant
harness `cc`/`getrandom 0.4.3`/`r-efi`/`shlex`/`find-msvc-tools`).

| Target | Entry points | Oracle (besides panic / timeout / OOM) | Seeds |
|---|---|---|---|
| `crates/nodkey-grant/fuzz` `verify_raw` | `decode_transport` (byte 1 bit 0) then `verify` → `WriteGrant::consumption`/`decide` or `ReadGrant::decide`, against the grant-v1 vector registry/operations, broker id, `app1` workload, `now = 1792886410`; byte 0 picks one of the 23 manifest requests | SI-07: an authorized grant must be byte-identical to a published vector (the fuzzer has no key; `verify_strict` is non-malleable). Start-up control: ACC-01 must be authorized, else the harness aborts | all 292 `tests/vectors/grant-v1/grants/*.hex` vectors, raw and as transport text (584 files) |
| `crates/nodkey-grant/fuzz` `verify_resigned` | input = COSE payload, wrapped in the fixed protected header and signed with published RFC 8032 test key A (same construction as `tests/robustness.rs`), so mutations reach steps 6–9 and W12/W13 | none (re-signed grants are genuinely signed; acceptance is not a finding) | payloads extracted from the vectors (276 files) |
| `broker/fuzz` `v2_request_line` | `v2::wire::parse_envelope` (incl. `strict_json::check_strict`), `check_keys`, `str_arg`, `subject_arg`, `digest::typed_params` with `decls::expected(op)` types, `PendingFields::from_json`/`validate`/`digest`, `adapter::parse_refund/parse_attempt/parse_lookup/parse_idem` | none | 6 hand-written request lines |
| `crates/nodkey-payments-adapter/fuzz` `provider_response` | `result::classify_create`, `classify_find`, `classify_get`, `classify_idem` on a synthetic `Exchange::Response` (status, content-type flag, body / body-read error), plus `to_json` of each result | §6.2 echo check: `Created`/`Found` must carry exactly the expected charge, amount, currency, reference (and requested id for `get`); §4: a `<LEAK>` marker in the body must never appear in a rendered result | 9 hand-written provider responses |

Not covered: `Registry::load`, `Operations::load`, `verify_retransmission`/`verify_binding`, the
broker's socket framing and database-backed handlers, the adapter's HTTP/TLS layer (hyper/rustls),
the authority, the gateway, the MCP front.

### Commands

Container as in "Method" (nightly 1.101.0-nightly 41089d07a, cargo-fuzz 0.13.2, aarch64 Colima VM,
4 vCPU, 4 GiB). `tools/fuzz.sh` holds the exact steps:

```
docker exec nodkey-fuzz sh tools/fuzz.sh seeds   # writes fuzz/seeds/<target> (git-ignored, regenerable)
docker exec nodkey-fuzz sh tools/fuzz.sh build   # cargo +nightly fuzz build -O <target>, per crate
docker exec nodkey-fuzz sh tools/fuzz.sh run 600 # the four targets in parallel, one process each:
#   cargo +nightly fuzz run -O <target> /build/fuzzwork/corpus/<target> fuzz/seeds/<target> -- \
#     -max_total_time=600 -rss_limit_mb=2048 -timeout=10 -max_len=8192 -print_final_stats=1 \
#     -artifact_prefix=<crate>/fuzz/artifacts/<target>/
docker rm -f -v nodkey-fuzz
```

Run window: 2026-10-28 22:24:16Z to about 22:43Z (UTC). Working corpora stayed in the container
and were discarded with it.

### Results

| Target | Executions | Avg exec/s | Edge cov at start → end (`cov`) | Features (`ft`) end | Corpus end | Peak RSS | Crashes | Timeouts | OOM | Oracle failures |
|---|---|---|---|---|---|---|---|---|---|---|
| `verify_raw` | 33,982,924 | 30,153 | 1257 → 1327 | 2629 | 459 / 94 KB | 520 MB | 0 | 0 | 0 | 0 |
| `verify_resigned` | 2,970,773 | 2,636 | 1681 → 1788 | 2921 | 442 / 110 KB | 463 MB | 0 | 0 | 0 | — |
| `v2_request_line` | 19,288,900 | 17,115 | 676 → 2145 | 8952 | 2512 / 1011 KB | 670 MB | 0 | 0 | 0 | — |
| `provider_response` | 11,628,664 | 10,318 | 755 → 1698 | 6758 | 1963 / 145 KB | 534 MB | 0 | 0 | 0 | 0 |

`cov` is libFuzzer's count of instrumented edges reached (includes dependency code; it is not a
line-coverage percentage, and no source-level coverage report was produced).

**Duration caveat.** libFuzzer reported `Done ... in 1127 second(s)` for every target although
`-max_total_time=600`. All four processes recorded `slowest_unit_time_sec: 568` and wrote
`slow-unit-*` files at the same two moments (≈22:32Z and 22:43Z). Re-running every one of those
eight inputs alone took 2–60 ms (including fixture start-up), so they were not slow inputs: the
whole VM was stalled for roughly 568 s (cause not determined; a host sleep is the likely but
unverified explanation). Effective fuzzing time is therefore about 1127 − 568 ≈ 560 s (≈ 9.3 min)
per target, about 37 min in total; the execution counts above are exact. The eight `slow-unit-*`
files were deleted as non-findings.

### Findings

**None.** No crash, panic, timeout, OOM, or oracle failure in any target, so no reproducers are
stored. Observations:

- `verify_resigned` runs ~11× slower than `verify_raw` because every execution performs an
  Ed25519 signature and verification; it received the fewest executions.
- Seeds are deliberately small for the broker and adapter targets; the coverage growth there
  (676 → 2145 and 755 → 1698 edges) suggests the corpora were still expanding when the run ended.

### Recommendations for a longer campaign

Run each target for hours with `-jobs`/`-workers`, keep the corpora between runs, add
`cargo fuzz coverage` reports, and add targets for `Registry::load`/`Operations::load`, the
retransmission verifiers, and the broker's line framing. Consider structure-aware input
(`arbitrary`) for the broker envelope and CBOR payloads.

## Integrity of manifests

SHA-256 of all 22 pre-existing `Cargo.toml`/`Cargo.lock` files (outside `fuzz/`) were identical
before and after this work (`shasum -a 256` + `diff`: no output, `MANIFESTS_UNCHANGED`).

## Remediation (2026-10-28)

- **RUSTSEC-2026-0385 (ctutils):** fixed. `ctutils` updated to 0.4.6 in broker, payments-adapter, mailsink, and simpay; `rust-version` raised from 1.85 to 1.89 in broker, mailsink, and simpay to allow the fixed release (all builds already use Rust 1.99). Broker unit 77, PostgreSQL 28/11/30, adapter 89, mailsink 4, simpay 74 tests pass after the update.
- **RUSTSEC-2026-0009 (time via rcgen):** not reachable in production paths (gateway dev-only TLS, simulator); left as is and re-checked at the next audit.
