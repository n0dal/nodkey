# Demo A integration findings

Defects and deviations found while assembling `examples/agent-support/`. Component and specification
defects are recorded here, not patched in the demo or the harness.

| ID | Severity | Where | Finding | Disposition |
|---|---|---|---|---|
| DEMOA-F01 | Low (spec inconsistency) | `docs/specs/agent-interface-v1.md` §5 S10 vs §2.5 | S10 (the prompt-injected refund) expects MCP status `failed`. The broker refuses it before dispatch (`insufficient_refundable`; record `FAILED`, class `denied`), and §2.5 maps that class to `denied`. Nothing reaches the provider. Repro: `tests/demoa/run.sh` → S10, both passes. | **Resolved:** §5 S10 now expects `denied` (spec text fix; behaviour unchanged). |
| DEMOA-F02 | Low (spec / implementation mismatch) | `crates/nodkey-mcp-front` vs §2.4 | A tool call with a malformed number (`01`) in `arguments` is rejected as JSON-RPC `-32700` (parse error), not `invalid_argument` as §2.4 states. No record is created. Repro: AT-04. | **Resolved:** §2.4 now classifies invalid JSON (incl. `01`) as `-32700` (RFC 8259); behaviour unchanged. |
| DEMOA-N01 | Info (residual confirmed) | authority budget, R-A5 | `order_busy` denials under AT-12 still consume the authority's mandate budget. | Matches published residual R-A5. |
| DEMOA-N02 | Info (spec gap MD-8) | authority mandate state | An operator `revoked_before` row leaves the authority's view of the mandate "active" until its expiry; the broker refuses, so no effect occurs. | Tracked as MD-8. |
| DEMOA-N03 | Info (deployment) | mailsink DB role | The mailsink role needed `USAGE` on schema `public` to poll. | Fixed in `examples/agent-support/docker/postgres/05-mailsink.sh`. |

## Status of the suite

`tests/demoa/run.sh`: 75 PASS / 0 FAIL / 14 NOT TESTED after the two spec corrections (first run: 72 / 3 / 14).
NOT TESTED rows, each with its reason in the output: AT-02, 07, 08, 10c, 12b, 13b, 14, 15c, 16c, 17b,
18, 19, 21, 27. The scripted run's final state matches the specification in both passes (AT-26).
