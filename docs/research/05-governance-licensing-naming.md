# Research 05 — Governance, Licensing, Naming, Export, Authorship, Privacy

> Written before the project name was chosen: "PBE" / "Proof-Bound Execution" refers to the project now called **Nodkey** (name chosen 2026-10-30). The name analysis below is kept as a historical record.

> [!NOTE]
> Status: research note (2026-10-24). This ranks below accepted ADRs (see the
> [source-of-truth hierarchy](../README.md)). **This is not legal advice.** It collects
> primary-source facts and turns open points into questions for counsel (§7). Each section keeps
> **Facts** (cited) apart from **Assessment** (hypotheses and recommendations).

Related open questions: OQ-02 (name), OQ-03 (copyright holder — resolved, see §1.5).

---

## 1. Apache License 2.0: what it requires

### 1.1 LICENSE file

**Facts**
- The canonical plain text is at `https://www.apache.org/licenses/LICENSE-2.0.txt` [A1]. Fetched
  2026-10-24: 202 lines, SHA-256
  `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.
- ASF guidance: put "one copy of the license text" in a top-level file named `LICENSE`, copying
  the contents of LICENSE-2.0.txt. `LICENSE` and `NOTICE` are preferred over `.txt` names [A2].
- Section 4(a) requires giving recipients a copy of the License. Section 4(b) requires modified
  files to carry prominent change notices. Section 4(c) requires keeping existing copyright,
  patent, trademark and attribution notices. Section 4(d) requires carrying forward the
  attribution notices in a NOTICE file, if the Work has one [A1].

**Assessment.** Copy the text byte for byte, appendix and brackets included. The repository's committed `LICENSE` has the same
SHA-256 as the canonical text, checked 2026-10-24. A CI check that compares this hash would stop
it drifting by accident.

### 1.2 The appendix boilerplate

**Facts.** The appendix ("How to apply the Apache License to your work") is part of the
license text. It tells authors to attach a boilerplate notice to their files, "with the fields
enclosed by brackets "[]" replaced with your own identifying information", using the file's
comment syntax [A1]:

```
Copyright [yyyy] [name of copyright owner]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
...
limitations under the License.
```

**Assessment.** The brackets are filled in per **source file**, not in LICENSE. In LICENSE the
brackets stay as they are.

### 1.3 NOTICE for a project with no bundled third-party code

**Facts**
- ASF: the NOTICE file is "reserved for a certain subset of legally required notifications". It
  should be kept "as brief and simple as possible". "Do not add anything to NOTICE which is not
  legally required." Do not change LICENSE or NOTICE for dependencies that are not bundled [A3].
- Apache-2.0 itself does not require a NOTICE file. Section 4(d) only applies "if the Work
  includes a NOTICE text file" [A1]. ASF policy requires one for ASF projects only [A2].
- After §4(d) applies, downstream redistributors must keep the NOTICE attributions [A1].

**Assessment.** With nothing bundled, NOTICE needs only the product name and the copyright
line. The committed NOTICE has three lines: product name, `Copyright 2026 n0dal`, and
"This product is licensed under the Apache License, Version 2.0 (see LICENSE)." The third line
is harmless but not legally required. Under the ASF minimalism guidance [A3], it could be
dropped, because every downstream redistributor must reproduce it. The NOTICE also contains the
provisional name "Proof-Bound Execution", so a rename (§3) needs a NOTICE edit. Entries are
added only when third-party material is **bundled** (vendored code, binaries, container images).

### 1.4 Per-file headers vs SPDX short identifiers

**Facts**
- ASF policy: each original source file "should include a short license header". One full copy
  of the license per distribution is enough [A2][A4].
- SPDX: a single line `SPDX-License-Identifier: Apache-2.0` inside the file's comment syntax.
  SPDX says copyright notices are outside the scope of the identifier, and existing copyright
  notices should not be removed or changed when an ID is added [S1]. `Apache-2.0` is the SPDX
  ID [S2].
- OpenSSF Best Practices: the **passing** level requires a FLOSS license (`floss_license`) in a
  standard location (`license_location`). The **gold** level adds `copyright_per_file` ("MUST
  include a copyright statement in each source file, identifying the copyright holder") and
  `license_per_file` [O1][O3].
- REUSE (FSFE) is a widely used convention for combining SPDX lines with copyright text, with
  `SPDX-FileCopyrightText` [S3]. It is a convention, not a legal requirement.

**Assessment / recommendation.** Use a two-line header in every source file:

```
// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0
```

This satisfies OpenSSF gold and is machine-checkable (`reuse lint`). The full appendix boilerplate is also valid. Whether the short
form is "enough" is a style choice, since Apache-2.0 does not make headers a condition. Counsel
can confirm this (§7, Q3). Contributor copyright: under DCO (§2) contributors keep their
copyright. Decide whether headers name only "n0dal", say "n0dal and contributors",
or point to an AUTHORS/git-history convention. The ASF asks committers not to add personal
copyright lines [A2]. That is ASF policy, not a requirement of the license.

### 1.5 Copyright holder (owner decision)

The owner decided on 2026-10-24 that the copyright holder is **n0dal**. LICENSE (the
canonical text) and NOTICE (`Copyright 2026 n0dal`) were committed in `718dd8f`. OQ-03
can close. The remaining open item is AI-assisted authorship (§5), which affects what the notice
*covers*, not who it names.

---

## 2. DCO vs CLA

**Facts**
- The Developer Certificate of Origin 1.1 is a short attestation published by the Linux
  Foundation. Clause (a) covers the contributor's own work, (b) work based on prior open-source
  work, and (c) work passed through from someone who certified it. Clause (d) says the
  contribution and a record of it, *including personal information and the sign-off*, are public
  and kept indefinitely [D1]. In practice it is attested with a `Signed-off-by:` trailer
  (`git commit -s`).
- OpenSSF Best Practices **silver** `dco` (SHOULD) asks for a legal mechanism by which
  contributors assert they are authorized. A DCO is "the most common and easily-implemented
  approach". A CLA also satisfies it [O2].
- Apache-2.0 §5 already says contributions intentionally submitted for inclusion are under the
  License's terms, unless explicitly stated otherwise ("inbound = outbound") [A1].

**Assessment / recommendation: DCO.** For a small new project with one copyright holder:

DCO costs contributors one flag and needs no infrastructure beyond an optional CI check. Apache-2.0 §3 already provides a patent grant. A CLA is only worth its cost if the owner wants rights to relicense contributions (for example
dual licensing). That would be a legally consequential ownership decision, so it needs explicit
owner approval and counsel. DCO + Apache-2.0 §5 fits the "fully open source, no proprietary
dependency" directive.

**Interaction with the no-AI-attribution rule.** DCO sign-off is a human certification by the
committer. Signing off with the owner's identity is consistent with the directive. Whether a
human can truthfully certify clause (a) ("created in whole or in part by me") for AI-assisted
material is a question for counsel (§7, Q11).

**CONTRIBUTING.md outline (sign-off section only; not created by this note):**
1. All commits must carry `Signed-off-by: Name <email>` matching the commit author, which
   certifies DCO 1.1 (link to full text).
2. How to sign off (`git commit -s`) and how to fix a missing sign-off (`git commit --amend -s`,
   `git rebase --signoff`).
3. Use your real or consistently used identity. Anonymous or pseudonymous contributions: policy
   to be decided (§7, Q10).
4. Contributions are licensed under Apache-2.0 per §5. No separate CLA.
5. Do not submit code you lack rights to (employer IP, incompatible licenses). Third-party code
   needs a license-compatibility review and a NOTICE/LICENSE update if bundled.
6. Privacy notice: sign-off name and email become permanent public record (DCO clause (d)).
7. Enforcement: a CI check rejects PRs with unsigned commits. Maintainers do not add sign-offs
   on contributors' behalf.

---

## 3. Name research

Observations from 2026-10-24 only. **Nothing here establishes legal availability.** Nothing was
registered or reserved.

### 3.1 "Proof-Bound Execution" / "ProofBound" / "proofbound"

**Observed**

| Check | Result |
|---|---|
| GitHub org `Proofbound` | **Exists**, Organization, created 2025-06-21, 13 public repos, website `proofbound.com`. Repos are unrelated (books, Claude Code plugins/skills, consulting sites) [N1] |
| GitHub repo search "proofbound" | 15 repos, incl. `cloudthinker-ai/proofbound` (MIT, created 2026-10-05): "Rust proof contracts with Python bindings for value-bound authorization" — **same problem domain** [N2] |
| GitHub search "proof bound execution" | 34 repos. `Actenon/actenon-kernel` (Apache-2.0, 2026-06-05): "The open verifier for **proof-bound consequential execution** ... before any side effect — payments, deletes, deploys, access changes". Also `rudycelekli/gradia-guard` ("proof-bound evidence recorder and verifier for ... execution boundaries"), `shr145129421/proofrail` ("policy-bounded, receipt-driven execution") [N2] |
| crates.io / PyPI / npm `proofbound`, `proof-bound`, `proof-bound-execution` | Not found (HTTP 404) [N3] |
| Packagist `proofbound/*` | Not found [N3] |
| `proofbound.com` | Resolves (Cloudflare NS), used by the GitHub org above |
| `proofbound.io` | Resolves (registrar-servers NS) |
| `proofbound.org` | Has NS records (AWS) |
| `proofbound.dev`, `proof-bound.com`, `proofboundexecution.com` | No DNS records. *No DNS ≠ unregistered*; WHOIS/RDAP not checked |

**Assessment.** "Proof-bound" is already used as a **descriptive phrase** by at least two
projects in the same niche (gating side effects on cryptographic proof). One of them is
Apache-2.0 and uses nearly the same phrase as PBE's tagline. The `proofbound` handle and
`.com`/`.io` are held by an unrelated party. The likely result is a crowded name with poor
distinctiveness and adopter confusion.

### 3.2 Acronym "PBE"

- "PBE" is long-standing cryptographic jargon for **Password-Based Encryption**: PKCS #5
  (RFC 8018 defines PBES1/PBES2), with JCA algorithm names such as `PBEWithHmacSHA256AndAES_256`
  [N4]. In a security project, "PBE" will be confused with this in search results, in code
  (`pbe` modules), and in reviewers' heads.
- GitHub user `pbe` exists (created 2011, 0 repos). `pbe` is free on crates.io, PyPI and npm.
  `pbe.dev` has Cloudflare NS (likely registered).

### 3.3 Does "proof" over-claim?

**Assessment.** Yes, it is a risk. "Proof" suggests formal verification ("proof-carrying code"
[N5], "provably secure"). PBE gives cryptographic **evidence** (signed grants) and tested claims
under deployment profiles (SI-17), not machine-checked proofs. The name also invites the
"signed ≠ authorized" confusion the project rejects (SI-04, SI-12). Keeping it would need a
prominent disclaimer.

### 3.4 Alternatives (lighter checks, same date)

| Candidate | crates / PyPI / npm | GitHub user/org | Packagist search | Repo search | `.dev` / `.com` NS | Notes |
|---|---|---|---|---|---|---|
| **EffectWarrant** (`effectwarrant`) | free / free / free | free | 0 | 0 | none / none | "Warrant" = a specific, limited authorization. Caveat: Warrant (`warrant-dev`, Zanzibar-style authz service, 1.3k★) is in the authz space [N6] |
| **Warrantgate** (`warrantgate`) | free / free / free | free | 0 | 0 | none / none | Same Warrant caveat |
| **EffectWrit** (`effectwrit`) | free / free / free | free | 0 | 0 | none / none | "Writ" = an order issued by an authority; no "proof" claim |
| **Writgate** (`writgate`) | free / free / free | free | (fuzzy noise) | 0 | none / **.com registered** | |
| EffectGate | free on registries | free | — | 3 repos, two MCP "verified tool effects" gateways (2026) | none | **Rejected**: crowded niche |
| Castellan / Seneschal | taken | taken | — | `openstack/castellan` is a key-manager library | taken | **Rejected** |

Note: names starting with "Effect" sit next to Effect-TS (`effect` on npm, "the missing
standard library for TypeScript") [N6]. That is low-to-moderate confusion, worth mentioning to
counsel.

**Recommendation.** Drop "Proof-Bound Execution" / "PBE" before any public release. Prefer
**EffectWrit** (most distinctive, describes "authority to produce an effect", no "proof"
claim, all observed namespaces free). **EffectWarrant** is the runner-up, pending a view on the
Warrant mark. Keep the old name internally until the owner decides. Any rename is an owner
decision and needs a USPTO/EUIPO clearance search by counsel.

### 3.5 USPTO search: NOT CHECKED

The USPTO Trademark Search system (`tmsearch.uspto.gov`) is a JavaScript application. Its
backing API refused a scripted query (HTTP 405), so no results are reported. Manual procedure:

1. Open https://tmsearch.uspto.gov/ → "Search trademarks".
2. Search each candidate as a wordmark and with wildcards: `proofbound`, `proof bound`,
   `effectwrit*`, `effect writ`, `*warrant*` combined with classes **009** (downloadable
   software) and **042** (SaaS/software design), plus **045** if security services.
3. Look at live *and* dead records, phonetic equivalents ("rit", "warant"), and design marks.
4. Repeat in EUIPO eSearch / WIPO Global Brand Database if non-US use is expected.
5. Record date, query, and hits in this note. Treat it as a screening search; counsel does
   clearance.

---

## 4. Export controls (US EAR)

**Facts** (eCFR, Title 15 up to date as of 2026-10-22 [E0])
- **§734.3(b)(3)**: information and "software" that "are published, as described in § 734.7"
  are not subject to the EAR. Note: "Publicly available encryption object code 'software'
  classified under ECCN 5D002 is not subject to the EAR when the corresponding source code meets
  the criteria specified in § 742.15(b)" [E1].
- **§734.7(a)(4)**: "published" includes "posting on the Internet on sites available to the
  public". **§734.7(b)**: published encryption software classified under 5D002 remains subject
  to the EAR unless it meets the §742.15(b) path [E2].
- **§740.13(e)** is now "**[Reserved]**" [E3]. The former License Exception TSU provision for
  publicly available encryption source code was moved into §742.15(b) by the March 2021 rule
  (86 FR 16482; listed in §742.15's amendment history as 86 FR 16488) [E4].
- **§742.15(b)(1)**: "publicly available ... encryption source code classified under ECCN 5D002
  is not subject to the EAR", subject to (b)(2). **§742.15(b)(2)**: notification (email to
  `crypt@bis.doc.gov` and `enc@nsa.gov` with the URL) is required **only** for source code that
  "provides or performs 'non-standard cryptography'" [E4].
- **§772.1** "Non-standard cryptography": "proprietary or unpublished cryptographic
  functionality, including encryption algorithms or protocols that have not been adopted or
  approved by a duly recognized international standards body (e.g., IEEE, IETF, ISO ...) and
  have not otherwise been published" [E5].
- **5A002 Technical Note 1** (Supp. 1 to Part 774): "cryptography for data confidentiality"
  excludes cryptography whose functions are "Authentication", "Digital signature", "Data
  integrity", "Non-repudiation", and key management in support of those [E6].

**Assessment**
- Ed25519 is standardized (RFC 8032, FIPS 186-5 [E7]), so it is not "non-standard cryptography".
- If PBE only *signs and verifies* grants, that is digital signature / authentication / integrity.
  So it is likely outside "cryptography for data confidentiality", and therefore likely not 5D002
  at all. Published source would then be outside the EAR under §734.3(b)(3)/§734.7.
- If PBE later includes confidentiality crypto (for example mTLS via rustls/OpenSSL, or
  encrypted receipts), it may be 5D002. Publicly available **source** is still not subject to the
  EAR under §742.15(b)(1). **No BIS notification** is needed as long as only standard
  cryptography is used.
- **Hypothesis to confirm**: release **binaries/container images** that bundle crypto libraries
  are "publicly available encryption object code" and follow the source under the §734.3(b)(3)
  note. OFAC sanctions are a separate regime (§7, Q17).

---

## 5. AI-assisted authorship

**Facts**
- **Registration guidance (Mar. 16, 2023)**, 88 FR 16190: copyright protects only human
  authorship. Applicants must disclose AI-generated content that is more than de minimis in a
  registration application and disclaim it, claiming only the human contribution [C1].
- **Copyright and AI, Part 2: Copyrightability (Jan. 29, 2025)** [C2]: existing law is
  adequate. Using AI as an *assistive tool* does not by itself affect copyrightability. Prompts
  alone generally do not give enough control to make the user the author of the output. Human
  expressive contributions that are perceptible in the output, and creative selection,
  coordination, arrangement or modification of AI output, can be protected. Decisions are case by
  case. (Paraphrase; the PDF could not be text-extracted in this environment. Verify against the
  report's conclusions section.)
- *Thaler v. Perlmutter*: the D.C. Circuit (Mar. 2025) affirmed the human-authorship requirement.
  The Supreme Court **denied certiorari on March 2, 2026** (No. 25-449) [C3].

**Implications for copyright notices**
1. `Copyright 2026 n0dal` is a notice, not a registration. It is not false merely
   because some material is not protectable. Any portions that are purely AI-generated, with no
   human creative contribution, may not be protected by copyright at all. The notice does not
   create rights where none exist.
2. The Apache-2.0 grant (§2) licenses whatever copyright exists. The practical exposure is
   narrower enforceability, not invalidity of the license.
3. Contributor sign-offs and the DCO clause (a) wording are affected (§2).

**Disclosure requirements found (stated without editorial comment)**
- **US Copyright Office registration**: if the owner ever *registers* the code, the 2023 guidance
  requires disclosing more-than-de-minimis AI-generated material in the application [C1].
  Inaccurate applications risk the registration. This applies only to registration filings,
  not to notices in the repository.
- **Linux kernel** `Documentation/process/coding-assistants.rst` asks for an `Assisted-by:` tag
  on kernel patches and forbids AI agents from adding `Signed-off-by` [C4]. It applies only to
  contributions *to the Linux kernel*, for example if PBE work were upstreamed there. Other
  upstream projects have their own contribution policies. Check them before upstreaming.
- **EU AI Act Art. 50** transparency duties target AI-system providers/deployers and certain
  published AI-generated content. Whether they reach repository source code is for counsel.
- **Platform terms** (GitHub, crates.io, PyPI, npm, Packagist): **NOT CHECKED** for AI-disclosure
  clauses in this pass. Re-check before publishing (§7, Q13).

No source reviewed requires AI attribution inside source files, commits, LICENSE or NOTICE of a
self-hosted open-source project.

---

## 6. Privacy: audit logs and receipts

PBE receipts and decision logs will likely contain subject identifiers, tenant IDs, resource
IDs, IP addresses and timestamps. The **deployer** is likely the GDPR controller. The PBE project
ships software and is not a controller of deployers' data, but the project's defaults determine
how hard compliance is.

**Facts (GDPR, Regulation (EU) 2016/679)** [P1]
- Art. 4(1) and Recital 26: identifiers, including pseudonymised ones, are personal data.
- Relevant articles: 5(1)(c) minimisation and 5(1)(e) storage limitation; 6(1)(f) legitimate
  interests (Recital 49 names network and information security); 15 access; 17 erasure;
  25 by design/default; 30 records; 32 security.

**Considerations to document (design hypotheses, not decisions)**
1. **Minimise by default**: receipts should carry opaque IDs, not names, emails or free text.
   Request parameters (amounts, addresses) should be logged only if a profile requires it.
2. **Keyed pseudonymisation** using a *standard* construction (HMAC-SHA-256 with a
   deployer-held key), so log readers cannot reverse IDs. This is still personal data (Recital
   26).
3. **Erasure vs tamper-evidence**: append-only or hash-chained receipts conflict with Art. 17.
   Options: keep personal data outside the chained record (store a commitment/pointer), or
   per-subject encryption keys destroyed on erasure ("crypto-shredding"). Both must use standard
   primitives only. Ask counsel whether retention for security/legal claims overrides erasure
   (Art. 17(3)).
4. **Retention**: configurable, with a documented default. No indefinite retention by default.
5. **Access control on evidence stores**: audit logs are a sensitive dataset in their own right
   (Art. 32). The workload must not be able to read them (consistent with SI-13).
6. **Deployer documentation**: list every field written, its purpose, and retention/redaction
   settings, to support deployers' Art. 30 records and DPIAs.
7. **Contributor data**: DCO sign-offs publish names and emails permanently (DCO clause (d)).
   Disclose this in CONTRIBUTING.
8. Other regimes (CCPA/CPRA, PCI DSS) not analysed here.

---

## 7. Legal-review checklist (questions for counsel)

**Licensing**
1. Is the committed NOTICE adequate? Should the non-required "This product is licensed..." line
   be removed to minimise downstream obligations?
2. Is "Copyright 2026 n0dal" the correct form? Should year ranges or "and contributors"
   be used as contributions arrive?
3. Is an SPDX two-line header enough, or should the full Apache appendix boilerplate be used in
   each file?
4. What process is needed before bundling third-party code or shipping binaries/containers
   (license compatibility, NOTICE propagation, dependency licence inventory)?
5. Are there patent risks in the authorization/receipt design (prior patents on
   capability-based authorization, proof-carrying requests) that warrant a search before
   release?

**Trademark/naming**
6. Clearance search for the chosen name (US classes 9 and 42; EU; WIPO). Is "Proof-Bound
   Execution" too descriptive or crowded, given `Actenon` and other uses of "proof-bound"?
7. Does "Warrant" (Warrant/WorkOS authz service) or "Effect" (Effect-TS) create a confusion
   risk for EffectWarrant or EffectWrit?
8. Should the mark be filed, in whose name, and is a fork/trademark policy needed?
9. Do disclaimers mitigate the risk that "proof" implies formal verification the project does
   not provide (consumer protection / misrepresentation)?

**Contributions/governance**
10. Is DCO 1.1 sufficient for this project? Policy on pseudonymous contributors?
11. Can a human contributor truthfully certify DCO clause (a) for AI-assisted code? Does
    project wording need adjusting?
12. Owner employment: does any employment or contractor agreement give an employer claims over
    this work (IP assignment clauses, moonlighting policies)?

**AI authorship/disclosure**
13. Do GitHub, crates.io, PyPI, npm or Packagist terms, or the EU AI Act, require disclosure of
    AI-assisted code in repositories or package metadata?
14. Practical effect of potentially unprotectable AI-generated portions on enforcement of
    Apache-2.0 terms (attribution, NOTICE) against downstream users.

**Export/sanctions**
15. Confirm classification: is signature-only functionality outside 5A002/5D002 (Technical Note
    1)? If TLS/encryption is added, confirm §742.15(b)(1) applies and no notification is needed.
16. Do public release binaries/container images follow the source code's status under the
    §734.3(b)(3) note?
17. OFAC/sanctions: any obligations for hosting downloads or accepting contributions from
    sanctioned jurisdictions?

**Privacy**
18. Could the project itself become a controller/processor (hosted demo, telemetry)?
19. Can hash-chained receipts containing pseudonymous IDs be retained against Art. 17
    requests? What documentation should deployers receive?
20. Is a privacy notice needed for contributor data (DCO sign-offs, issue tracker)?

**Liability**
21. Is the Apache-2.0 warranty disclaimer enough given security claims in docs (SI-17 phrasing)?

---

## References

- [A1] Apache License 2.0, canonical text — https://www.apache.org/licenses/LICENSE-2.0.txt (fetched 2026-10-24; SHA-256 above)
- [A2] ASF, "Applying the Apache License, Version 2.0" — https://www.apache.org/legal/apply-license.html
- [A3] ASF Infra, "Licensing How-To" (NOTICE guidance) — https://infra.apache.org/licensing-howto.html
- [A4] ASF, "Source Header and Copyright Notice Policy" — https://www.apache.org/legal/src-headers.html
- [S1] SPDX, "Handling License Info" — https://spdx.dev/learn/handling-license-info/
- [S2] SPDX License List, Apache-2.0 — https://spdx.org/licenses/Apache-2.0.html
- [S3] FSFE REUSE specification — https://reuse.software/spec/
- [D1] Developer Certificate of Origin 1.1 — https://developercertificate.org/
- [O1] OpenSSF Best Practices, passing criteria — https://www.bestpractices.dev/en/criteria/0
- [O2] OpenSSF Best Practices, silver criteria (`dco`) — https://www.bestpractices.dev/en/criteria/1
- [O3] OpenSSF Best Practices, gold criteria (`copyright_per_file`, `license_per_file`) — https://www.bestpractices.dev/en/criteria/2
- [N1] GitHub API, org `Proofbound` — https://api.github.com/users/Proofbound (queried 2026-10-24)
- [N2] GitHub repository search API (queries: proofbound; proof bound execution; effectgate) and repos `Actenon/actenon-kernel`, `cloudthinker-ai/proofbound`, `rudycelekli/gradia-guard`, `shr145129421/proofrail` (queried 2026-10-24)
- [N3] crates.io API, PyPI JSON API, npm registry, Packagist (`repo.packagist.org/p2/`, `packagist.org/search.json`) (queried 2026-10-24)
- [N4] RFC 8018, PKCS #5: Password-Based Cryptography Specification v2.1 — https://www.rfc-editor.org/rfc/rfc8018
- [N5] G. Necula, "Proof-Carrying Code", POPL 1997
- [N6] GitHub `warrant-dev/warrant`; npm `effect` (queried 2026-10-24)
- [E0] eCFR API title currency (Title 15 up to date as of 2026-10-22) — https://www.ecfr.gov/api/versioner/v1/titles.json
- [E1] 15 CFR 734.3 — https://www.ecfr.gov/current/title-15/section-734.3
- [E2] 15 CFR 734.7 — https://www.ecfr.gov/current/title-15/section-734.7
- [E3] 15 CFR 740.13 — https://www.ecfr.gov/current/title-15/section-740.13
- [E4] 15 CFR 742.15 — https://www.ecfr.gov/current/title-15/section-742.15 ; 86 FR 16482 (Mar. 29, 2021)
- [E5] 15 CFR 772.1, "Non-standard cryptography" — https://www.ecfr.gov/current/title-15/section-772.1
- [E6] 15 CFR Part 774 Supp. 1, ECCN 5A002 Technical Note 1 — https://www.ecfr.gov/current/title-15/part-774
- [E7] RFC 8032 (EdDSA) — https://www.rfc-editor.org/rfc/rfc8032 ; NIST FIPS 186-5 — https://doi.org/10.6028/NIST.FIPS.186-5
- [C1] US Copyright Office, Registration Guidance for Works Containing AI-Generated Material, 88 FR 16190 (Mar. 16, 2023) — https://www.copyright.gov/ai/
- [C2] US Copyright Office, Copyright and Artificial Intelligence, Part 2: Copyrightability (Jan. 29, 2025) — https://www.copyright.gov/ai/Copyright-and-Artificial-Intelligence-Part-2-Copyrightability-Report.pdf
- [C3] *Thaler v. Perlmutter*, No. 23-5233 (D.C. Cir. Mar. 18, 2025); cert. denied, No. 25-449 (U.S. Mar. 2, 2026) — https://www.scotusblog.com/cases/case-files/thaler-v-perlmutter
- [C4] Linux kernel, "AI Coding Assistants" — https://www.kernel.org/doc/Documentation/process/coding-assistants.rst
- [P1] Regulation (EU) 2016/679 (GDPR) — https://eur-lex.europa.eu/eli/reg/2016/679/oj
