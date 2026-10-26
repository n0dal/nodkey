# Demo P integration findings

Defects and deviations found while assembling `examples/confirmed-refund/`. Component defects are
recorded here, not patched in the demo.

| ID | Severity | Where | Finding | Disposition |
|---|---|---|---|---|
| DEMOP-F01 | Medium (design gap) | `crates/nodkey-gateway` (spec gap GW-6) | A multi-user app that names the approver has no Nodkey-provided way to learn the signed-in subject, so the demo shop uses an untrusted customer hint when proposing. The broker and authority still bind approval to the intended approver and check ownership, so a wrong hint can only produce a proposal nobody can approve. | Open: specify an identity hint the gateway supplies to the app (non-authoritative), or document the hint as untrusted UX only. |
| DEMOP-F02 | Low (environment) | Colima virtiofs bind mounts | Bind-mounted files do not keep their host ownership inside the VM. The adapter correctly refused to start (`config.json owned by the adapter or broker uid`). | Fixed in the demo: adapter inputs are copied into named volumes by a one-shot `adapter-init` service with the required owners and modes. |
| DEMOP-D01 | Info (deviation) | `tests/demop/run.sh` test PKI | simpay certificates are valid 2025–2035 rather than 7 days, and carry no IP SAN. | Test-only PKI; the CA private key is deleted after issuance. Shorten validity when the harness gains a certificate-expiry test. |

## Status of the suite

The stack and the legitimate refund flow pass (S-00, L-01..L-06). The attack groups (PT-01..PT-42,
P-01..P-19), fault and malicious-provider modes, budgets, containment, R_max, and crash tests are
**NOT TESTED** yet: the integration agent stopped when a safety classifier withheld a response while
it was writing the attack tests. Helpers for them (`p_client`, `set_faults`, `consistent`,
`creates_sent`, containment probes) exist but are not yet called.
