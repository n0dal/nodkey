# Open Questions

| ID | Question | Owner area | Status |
|---|---|---|---|
| OQ-01 | Does an existing open-source project already provide credential-less workload + typed effect broker + independently verified per-effect authorization? | Research | **Resolved 2026-10-25:** not as a combination; for own-database effects, PostgREST+RLS+isolation is roughly equivalent, so the project refocused on external consequential actions and AI agents (ADR-0010). |
| OQ-02 | Project name. | Owner | **Resolved 2026-10-25, revised 2026-10-30:** "Nodkey" (owner decision; replaces the earlier working names, including the provisional "Proof-Bound Execution"/"PBE"). Trademark clearance by counsel still required before public release. |
| OQ-03 | Copyright holder for LICENSE/NOTICE. | Owner | **Resolved 2026-10-24:** "Henry Cuevas" (owner decision) |
| OQ-04 | How can the broker derive operation-specific authority for browser users without trusting the app's description of the user? (Gateway-verified session vs. app claim.) | Protocol | Open |
| OQ-05 | Grant format: reuse Biscuit / COSE / PASETO, or a minimal custom envelope over a standard signature? | Protocol | Open |
| OQ-06 | Do workflow receipts add security beyond broker-owned state machines? | Research | Open |
| OQ-07 | Should Nodkey's grant format interoperate with or reuse an existing execution-edge proof protocol (e.g. Actenon) instead of defining its own COSE profile? | Protocol | Open |
| OQ-08 | Gateway and broker may parse the same HTTP request differently (route-mapping divergence). How is a single canonical request representation guaranteed? | Protocol | Open |
| OQ-09 | Demo P refund initiator: customer self-service or staff? | Owner/Orchestrator | **Resolved 2026-10-25:** Demo P = customer self-service (ownership + user confirmation); staff-side refunds are covered by Demo A (support agent under a staff-delegated mandate). |
| OQ-10 | ADR-0006 amendment: a reconciler resend with the same provider idempotency key is not a new effect and not a grantless path (SI-19). | Protocol | Open (Phase 4) |
| OQ-11 | For confirmed effects, should the broker execute the approved effect itself (grant delivered authority→broker, never to the workload) instead of the workload presenting the grant? Simpler and smaller workload authority; applies to Demo A and possibly Demo P. | Architecture | Open (decide at start of Phase 4) |
| OQ-12 | Mandate grant type (delegated, budgeted, signed; broker-tracked spend) — ADR-0004/0006 amendments. Prior art: AP2 mandates. | Protocol | **Resolved 2026-10-28:** ADR-0013 rev. 1 (mandates approved as confirmed effects; per-call signed grants; broker-side revocation; no replacement). |
