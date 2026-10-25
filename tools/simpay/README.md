# simpay: a SIMULATED payment provider

> [!WARNING]
> **simpay is a SIMULATOR. It is not a real payment API and it moves no money.** Never point it at
> real card data, real customer data, or real provider keys. Never expose it on a public network.
> Every response carries `Simpay-Simulator: SIMULATED payment provider - not a real payment API`,
> every JSON body carries `"simulator": true` and `"livemode": false`, and every log line starts
> with `[simpay SIMULATOR]`.

simpay supports Nodkey's Demo P and its tests (ADR-0010; research note 06 §2.1). It reproduces
the parts of a Stripe-like refund API that matter for security, and it does so deterministically.
It includes a fault plan and a malicious-provider mode (attacker G).

**Trust:** Nodkey does **not** trust simpay. simpay stands in for an external party, and in
malicious mode it lies on purpose. It is not part of any trusted computing base.

Status: prototype test tool. Design source: `docs/research/06-payment-provider-and-http-adapter.md`
Part 2 §2.1. Behaviour marked **[sim]** is a simulator choice that has no documented provider
equivalent.

## Running

```sh
cargo run --release -- --config fixtures/local-config.json      # 127.0.0.1:12111 api, :12112 admin
docker build -t nodkey/simpay:dev tools/simpay/
docker run --rm -p 127.0.0.1:12111:8080 -p 127.0.0.1:12112:8081 nodkey/simpay:dev
```

Flags: `--config <file>` (required), `--container-bind`, `--restore`.

**Bind policy.** simpay refuses to start (exit code 2) when it would listen on a public address:

| Address | Behaviour |
|---|---|
| Loopback, RFC 1918, link-local, 100.64/10, IPv6 ULA (`fc00::/7`), IPv6 link-local | allowed |
| `0.0.0.0` or `::` | refused unless `--container-bind` is given. The image passes this flag, because inside a container the unspecified address is the only way for sibling containers to reach it |
| Any other (public) address | always refused, with no override |

The bind check covers the address simpay binds to. It cannot see Docker port publishing. Publish
container ports only to `127.0.0.1`, and publish the admin port only to the test harness.

## Configuration

The config file is strict JSON: unknown fields are rejected. See `fixtures/local-config.json`.

| Field | Default | Meaning |
|---|---|---|
| `api_listen`, `admin_listen` | — | Two **separate** listeners. Port 0 picks an ephemeral port |
| `admin_token` | none | If set (≥16 chars), the admin listener requires `Authorization: Bearer <token>` |
| `seed` | — | Seed for deterministic ids |
| `clock.mode` | `manual` | `manual`: time changes only through `POST /admin/clock/advance`. `system`: wall clock plus an offset that can be advanced |
| `clock.start` | 1761350400 | Initial Unix time in manual mode |
| `idempotency_retention_s` | 86400 | Retention window for idempotency records, measured on the simulated clock |
| `idempotency_key_max_len` | 64 | Maximum `Idempotency-Key` length (1..=255) |
| `rate_limit` | none | `{max_requests, window_s}`: a fixed window per key on the simulated clock |
| `webhook_delivery` | 5 attempts, 200 ms base, 2 s timeout | `{max_attempts, retry_base_ms, timeout_ms}`. Backoff doubles each attempt |
| `snapshot_path` | none | Where snapshots are written (admin call, SIGTERM/SIGINT) and read (`--restore`) |
| `malicious_mode` | false | Allows malicious faults from the start |
| `fixture_path` / `fixture` | — | The seed data (exactly one of the two). A relative `fixture_path` resolves against the config file's directory |

**Fixture** (see `fixtures/demo-fixture.json`):

- **Accounts**, each with:
  - **API keys**:
    - `sk_sim_…` keys are unrestricted;
    - `rk_sim_…` keys are restricted and need a `permissions` map `{charges|refunds: none|read|write}`;
    - either kind can have optional `allowed_cidrs`.
  - **Webhook endpoints** `{url: "http://host:port/path", secret: "whsec_sim_…"}`.
- **Charges** `{id: "ch_…", account, amount_minor, currency, status, refunded_minor,
  refund_initial_status: succeeded|pending}`.

The `_sim_` infix is mandatory, so a simulator key never has the shape of a real `sk_live_` or
`sk_test_` key. A config holding a `sk_live_…` key is refused.

## Payment API (API listener)

Every request needs `Authorization: Bearer <key>`. The request uses HTTP/1.1, one request per
connection; the server always replies `Connection: close`. Bodies are form-encoded, the head is
limited to 16 KiB, and the body to 16 KiB.

| Method and path | Permission | Purpose |
|---|---|---|
| `POST /v1/refunds` | refunds: write | Create a refund. Params: `charge` (required), `amount`, `currency`, `reference`, `reason`. The `Idempotency-Key` header is **required** |
| `GET /v1/refunds/{id}` | refunds: read | Retrieve one refund |
| `GET /v1/refunds?charge=&reference=&limit=&starting_after=` | refunds: read | List refunds for reconciliation, newest first. `limit` is 1..=100 (default 10); the response includes `has_more` |
| `GET /v1/charges/{id}` | charges: read | Retrieve a charge (`amount`, `amount_refunded`, `refunded`) |
| `GET /v1/idempotency_keys?key=` | refunds: read | **[sim] extension.** Returns the key's state: `none`, `in_progress`, or `done` (with `expires_at`). This is the "confirmed-final idempotency state" in research 06 §2.2; real providers may have no equivalent |

**Permissions** follow Stripe's restricted keys: GET needs read, POST needs write, and write
implies read. A key outside its `allowed_cidrs` gets `401 source_address_not_allowed` even though
the key itself is valid. Objects in other accounts look like `404`.

**Refunds:**

- `amount` is a strict positive integer in minor units: no sign, no leading zero, no decimal point
  or exponent, and at most 999 999 999 999. If omitted, it defaults to the remaining amount.
- `amount > remaining` → `400 amount_too_large`.
- Fully refunded charge → `400 charge_already_refunded`.
- Non-`succeeded` charge → `400 charge_not_refundable`.
- Currency:
  - The refund always takes the charge's currency.
  - `currency` is optional. **[sim]:** if you send it, it must match the charge (Adyen's rule); a
    mismatch gives `400 currency_mismatch`. Stripe has no such parameter.
- Unknown parameters (`metadata`, `url`, …) give `400 parameter_unknown`. Duplicate parameters give
  `400 parameter_duplicate`.
- Status starts as `pending` or `succeeded`, as the fixture sets. Allowed transitions are
  `pending → succeeded|failed` and `succeeded → failed`, through the admin API or the
  `late_refund_failed` fault. A failed refund gives its amount back to the charge, as on Stripe.

**Idempotency** (Stripe semantics, research 06 §1.2):

- **Scope:** records are keyed by (account, key). All keys of one account share the key space, as
  with Adyen's company-level scope; a test covers this.
- **Fingerprint:** SHA-256 of the method, the path, and the sorted, re-encoded parameters.
  Parameter order does not matter.
- **Same key, same fingerprint, done:** the cached status and body are replayed, **including a
  cached 500**, with `Idempotent-Replayed: true`.
- **Same key, different fingerprint:** `400 idempotency_error / idempotency_params_mismatch`.
- **Same key while the first request is in progress:** `409 idempotency_error /
  idempotency_key_in_progress`. This response is not cached.
- **Not cached:** syntactic validation failures (400), 401, 403, 409, 429, and
  `fail_before_commit`.
- **Cached:** business outcomes once execution starts, whether 200, `amount_too_large`,
  `charge_already_refunded`, `currency_mismatch`, or `404` for an unknown charge. **[sim]:** where
  to draw this line is a simulator choice.
- **Retention:** a record expires once `created + idempotency_retention_s ≤ now`. After that, the
  same key executes again, which Stripe documents.

**Errors** have the shape `{"error": {type, code, message, param, should_retry}, "simulator": true}`.
They also carry the header `Simpay-Should-Retry: true|false`, simpay's analogue of
`Stripe-Should-Retry`:

| Status | `type` | Typical `code` | Retry guidance |
|---|---|---|---|
| 400 | `invalid_request_error` | `parameter_*`, `amount_too_large`, `charge_already_refunded`, `currency_mismatch`, `charge_not_refundable`, `idempotency_key_missing`, `idempotency_key_invalid` | Do not retry. These are definite refusals |
| 400 | `idempotency_error` | `idempotency_params_mismatch` | Do not retry. This signals a client bug |
| 401 | `authentication_error` | `missing_api_key`, `invalid_api_key`, `source_address_not_allowed` | Do not retry. Configuration fault |
| 403 | `permission_error` | `insufficient_permissions` | Do not retry. Configuration fault |
| 404 | `invalid_request_error` | `resource_missing` | Do not retry |
| 409 | `idempotency_error` | `idempotency_key_in_progress` | Retry with the **same** key after a wait |
| 429 | `rate_limit_error` | `rate_limit` (+ `Simpay-Rate-Limited-Reason`) | Nothing was executed. Retry with the same key |
| 500 | `api_error` | `internal_error` | `should_retry: true` only for `fail_before_commit`. A cached 500 says `false` and means *outcome unknown: reconcile* |

## Webhooks

- **Events:**
  - `refund.created`;
  - `refund.updated` on every status change;
  - `refund.failed` as well when a refund fails.
- **Event body:**
  `{"id": "evt_…", "object": "event", "type", "created", "livemode": false, "simulator": true,
  "data": {"object": <refund>}}`.
- **Signature:** `Simpay-Signature: t=<unix>,v1=<hex HMAC-SHA256(endpoint_secret, "<t>." ‖ raw_body)>`.
  This follows the same scheme as Stripe's `Stripe-Signature`. Each attempt is signed with a fresh
  `t` from the simulated clock. The event id is also sent in `Simpay-Event-Id`.
- **Receivers** must verify over the raw body, compare in constant time, apply a non-zero freshness
  tolerance (for example 300 s), and deduplicate on `id`.
- **Delivery** is at least once and unordered: one task per event and endpoint. Any non-2xx answer
  or connection error is retried up to `max_attempts` times, with backoff `retry_base_ms·2^(n-1)`.
  Only `http://` URLs are supported.
- **Delivery log:** `GET /admin/webhooks/deliveries` records each attempt with its signature header,
  result, and body.

## Admin API (admin listener only)

| Method and path | Purpose |
|---|---|
| `GET /admin/health` | Liveness |
| `GET /admin/ledger` | Ground truth for each charge: `refund_count`, `refund_sum`, `*_not_failed`, `amount_refunded`, plus every refund in creation order |
| `GET /admin/state` | The full store as JSON (the same as a snapshot) |
| `GET` / `PUT` / `DELETE /admin/faults` | Show the fault plan with each rule's `matched` and `fired` counters, replace the plan (`{"rules": [...]}`), or clear it |
| `PUT /admin/malicious` | `{"enabled": bool}`. Disabling also removes installed malicious rules |
| `GET /admin/clock`, `POST /admin/clock/advance` | `{"seconds": n}`. Advancing applies scheduled transitions that have come due |
| `POST /admin/refunds/{id}/status` | `{"status": "succeeded"|"failed"}` (settlement transition and webhooks) |
| `PUT /admin/accounts/{acct}/webhook_endpoints` | `{"endpoints": [{url, secret}]}` |
| `GET /admin/webhooks/deliveries`, `POST /admin/webhooks/resend` | `{"index": n}` re-sends a logged delivery byte for byte, with its old signature (a manual replay) |
| `POST /admin/snapshot`, `POST /admin/reset` | Write a snapshot to `snapshot_path`, or reload the fixture and clear the plan |

Neither the broker nor the workload must be able to reach the admin listener (research 06 §2.1,
"Control plane").

## Fault catalogue

A rule has the form `{"id"?, "match": {"op"?, "idempotency_key"?, "charge"?, "event_type"?},
"fault": {"kind", …}, "nth": 1, "times": 1}`:

- `op` is one of `create_refund`, `get_refund`, `list_refunds`, `get_charge`,
  `get_idempotency_key`, `webhook`.
- `match.charge` is compared with the request's `charge` parameter, or with the event's refund
  charge.

Each fault kind belongs to a **stage**. When a request reaches a stage, simpay evaluates that
stage's rules in order:

- A rule whose `match` conditions hold counts one match.
- The rule fires once its count is at least `nth` and it has fired fewer than `times` times
  (`times: 0` means unlimited).
- The first rule that fires ends evaluation for that stage.

Counting happens under the store lock, so given the same arrival order the outcome is
deterministic.

| Kind | Stage | Behaviour | Research 06 |
|---|---|---|---|
| `fail_before_commit {status=500}` | execute | Returns 5xx with no state change. The key is released, so a same-key retry executes | §2.1, P-09 |
| `commit_then_500` | execute | Commits, caches a 500 for the key, and returns 500 | P-08 |
| `commit_then_drop` | execute | Commits and caches the real 200, then closes the connection with no response | P-06 |
| `commit_after_delay {ms}` | execute | Holds the key `in_progress`, then commits after `ms` even if the client has left, then responds. Meanwhile a lookup finds nothing and a same-key request gets 409 | P-07 |
| `slow_response {ms}` | respond | Commits at once and delays the response | §2.1 |
| `inflight_409 {hold_ms=1000}` | execute | Holds the first request so that a concurrent same-key request gets 409 | §2.1 |
| `rate_limit` | pre | 429, with nothing executed or cached | P-09 |
| `drop_before_commit` | pre | Closes the connection with no response, and nothing executed | (contrast for P-06) |
| `late_refund_failed {after_s=0}` | post-commit | The committed refund moves `succeeded → failed` at `now + after_s` and emits `refund.updated` and `refund.failed` | §2.1 |
| `webhook_duplicate {n}` | webhook | Delivers the same event id `n` times | P-19 |
| `webhook_replay {after_ms}` | webhook | After a successful delivery, re-sends the identical bytes with the **old** `t` and signature | P-19 |
| `webhook_suppress` | webhook | Does not deliver the event, so receivers must not depend on webhooks | §2.2 |

**Malicious-provider mode (attacker G).** These kinds are refused unless malicious mode is enabled.
Most change only what goes over the wire; the ledger stays truthful, so tests can show the lie.

| Kind | Stage | Behaviour |
|---|---|---|
| `lie_amount {amount}`, `lie_charge {charge}`, `lie_currency {currency}`, `lie_status {status}` | respond | Echoes a value other than the stored one (also on GET and list) |
| `phantom_success` | execute | Returns 200 with a refund that was never stored (GET → 404) |
| `deny_but_commit` | execute | Commits the refund but answers `400 charge_already_refunded` |
| `redirect {location, status=307}` | pre | Returns a 3xx to another host, with nothing executed |
| `oversized_body {bytes}`, `oversized_header {bytes}` | respond | Pads the body or one header to `bytes` (limit 64 MiB) |
| `header_injection {variant}` | respond | `crlf_injection` (smuggled `Set-Cookie`/`Location` lines), `bare_cr`, `nul_byte`, `obs_fold`, `duplicate_content_length`, `te_and_cl` |
| `malformed_json {variant}` | respond | `truncated`, `duplicate_keys` (the first `amount` is a lie), `deep_nesting` (depth 100 000), `huge_number` (`1e400…`), `trailing_garbage`, `not_json`, `wrong_content_type`, `invalid_utf8` |
| `hostile_error_text` | respond | A 400 whose `message`, `code` and `param` hold HTML/JS markup and prompt-injection text. The operation underneath already ran |
| `slow_drip {chunk, interval_ms}` | respond | Writes the response `chunk` bytes at a time |
| `webhook_contradict` | webhook | A correctly signed event whose `status` and `amount` contradict GET |

## Persistence and determinism

- **Storage:** state lives in memory behind one mutex. An operation and its idempotency record
  commit under the same lock.
- **Snapshots:**
  - written by `POST /admin/snapshot` and on SIGTERM/SIGINT, when `snapshot_path` is set;
  - JSON, written to a temp file and renamed into place, with mode 0600;
  - `--restore` loads the snapshot;
  - in-progress idempotency records are dropped on restore, because they never committed;
  - the fault plan is not included.
- **Ids:** `prefix_` followed by 24 base62 characters derived from SHA-256(seed, prefix, counter).
  The same seed and the same order of operations give the same ids, and they match the adapter's
  pattern `^[a-z]{2,4}_[A-Za-z0-9]{8,64}$`.
- **Determinism limits:** timing faults (`*_ms`) use real sleeps. Determinism holds over the order
  of rules and requests, not over wall-clock races that a test sets up itself.

## Limitations and deviations

- **No TLS.** Research 06 §2.2 has the adapter pin a simpay test CA. That needs a TLS front, such
  as a reverse proxy with a test CA, or a later rustls listener. Plain HTTP is enough for the fault
  semantics.
- One request per connection, with no keep-alive and no chunked request bodies (`501`).
- Rate limiting uses a simple fixed window per key. There are no global or concurrency limits.
- Through the admin API, the webhook URL can point at any `http://host:port`. The admin listener
  is assumed to be reachable only by the test harness.
- There is no `reason=fraudulent` side effect (Radar block lists). The reason is only stored.
- Stripe returns no `currency` parameter on refunds and has no idempotency-state endpoint. Both are
  marked **[sim]** above.

## Dependencies

Licenses were checked with the crates.io API (`/api/v1/crates/<name>/<version>`) on 2026-10-25.

| Crate | Locked version | License | Why |
|---|---|---|---|
| `tokio` | 1.54.1 | MIT | Async TCP listeners, timers, signals. Features are limited to `rt-multi-thread, net, io-util, macros, time, sync, signal` |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | Strict config, fixture, and rule parsing (`deny_unknown_fields`) |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | JSON bodies, snapshots |
| `httparse` | 1.10.1 | MIT OR Apache-2.0 | Strict, bounded HTTP/1.1 request-head parsing. simpay writes responses itself, because server frameworks (hyper/axum) would refuse to emit the malformed responses that malicious mode needs |
| `form_urlencoded` | 1.2.2 | MIT OR Apache-2.0 | Form and query decoding, and the canonical re-encoding for fingerprints |
| `hmac` | 0.13.0 | MIT OR Apache-2.0 | HMAC-SHA256 webhook signatures (no custom crypto) |
| `sha2` | 0.11.0 | MIT OR Apache-2.0 | SHA-256 for webhook HMACs, idempotency fingerprints, and deterministic ids |

Transitive crates (`cargo tree -e normal`) were also checked on crates.io:

- MIT OR Apache-2.0: block-buffer, cfg-if, cmov, const-oid, cpufeatures, crypto-common, ctutils,
  digest, errno, hybrid-array, itoa, libc, percent-encoding, pin-project-lite, proc-macro2, quote,
  serde_core, serde_derive, signal-hook-registry, socket2, syn, typenum.
- MIT: bytes, mio, tokio-macros, zmij.
- Unlicense OR MIT: memchr.
- (MIT OR Apache-2.0) AND Unicode-3.0: unicode-ident.

There are no dev-dependencies. The tests use the crates above plus a raw TCP client, which can
observe dropped connections and malformed responses.

## Tests

```sh
cargo test                                  # 12 unit + 52 integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
docker build --target test --progress=plain tools/simpay/
```

| Suite | Covers |
|---|---|
| `src/*` unit tests | CIDR matching, bind policy, id syntax, URL parsing, fault-rule counting and parsing, strict amount parsing, fingerprints, HMAC (RFC 4231 case 2) |
| `tests/api.rs` | Simulator labelling, authentication, restricted keys (none/read/write, write ⇒ read), source-CIDR policy, partial and full refunds, remaining-amount checks, currency rule, parameter strictness, pending/failed transitions, lookup/list/pagination, idempotency (replay, mismatch, per-account scope, shared across keys, what is and is not cached, retention expiry, key-length rules), configured rate limit, HTTP strictness (404/405/413/431/501, duplicate `Content-Length`), listener separation, deterministic ids, admin token |
| `tests/faults.rs` | Every fault in the catalogue against the ledger. `nth`, `times`, and the match filters. Webhook signing, independent verification (wrong secret, tampering, staleness), retries, duplicates, replay with old signature, manual resend, suppression, late `refund.failed`, system-clock ticker |
| `tests/malicious.rs` | Mode gating, every malicious kind, plus ledger proof of what really happened |
| `tests/process.rs` | The binary refuses `0.0.0.0`/`::` without `--container-bind`, refuses public addresses always, refuses bad configs (`sk_live_` keys, unknown fields, …). Log prefix. Shipped configs validate. Relative `fixture_path`. Snapshot round trip (0600 mode, replay after restore). Reset. SIGTERM writes a snapshot |
