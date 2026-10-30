# Disclaimer

**Please read this before you use Nodkey.**

This page explains, in plain language, what Nodkey is and is not. It does not change, replace, or add
to the terms of the [Apache License 2.0](LICENSE) under which Nodkey is distributed. Where this page
and the licence differ, the licence applies; see in particular section 7 (Disclaimer of Warranty) and
section 8 (Limitation of Liability) of [LICENSE](LICENSE).

## A research prototype

- **Not for production.** Nodkey is a research prototype. Nothing in this repository is suitable for
  production use ([STATUS.md](STATUS.md)).
- **No warranty.** Nodkey is provided "as is", without warranty of any kind, as stated in the licence.
  You use it at your own risk.
- **No security guarantee and no certification.** Nodkey limits the consequences of some kinds of
  compromise under a documented threat model and deployment profile. It does not prevent compromise,
  and it does not make an application or an AI agent safe. The limits are listed in
  [LIMITATIONS.md](LIMITATIONS.md) and [THREAT_MODEL.md](docs/THREAT_MODEL.md). Test results are
  results of local runs on one development machine; they are not proofs, and many rows are NOT TESTED.
  No body has certified Nodkey for anything.
- **No independent human audit.** Every design and code review recorded in
  [`docs/reviews/`](docs/reviews/) was performed by AI agents. No independent human security audit
  has been done.

## Not a compliance product, not advice

- Nodkey is not a compliance product. Using it does not make a system compliant with any standard or
  regulation, for example PCI DSS or SOC 2, and nothing in this repository claims that it does.
- Nothing in this repository is legal, financial, or compliance advice.

## The demos are intentionally vulnerable

- The demo applications contain a remote-code-execution endpoint on purpose, to model a compromised
  workload. Run them **only on your own machine**. They bind to `127.0.0.1`; never change that, and
  never expose a demo stack to a network or to the internet.
- The demo gateway image (used by Demos 2, P and A) is built with a test login that needs no
  credentials. It exists for local testing only.
- The signing keys used in tests and test vectors are published RFC 8032 test keys; their secrets are
  public. Never use them, or any key or certificate a demo generates, for anything real.

## Simulators, not real services

- `simpay` ([`tools/simpay`](tools/simpay/)) is a **simulated** payment provider. It is not a real
  payment service and moves no money. The mail sink ([`tools/mailsink`](tools/mailsink/)) is a
  **simulated** mail service and delivers no mail. The demo agent
  ([`tools/demo-agent`](tools/demo-agent/)) is a deterministic program, not an AI model.
- **Never enter real payment credentials** (card numbers, bank details, provider API keys) or other
  real personal data into Nodkey, its demos, or its simulators.
- No real payment provider, mail service, or AI model has been connected to Nodkey.

## No affiliation, trademarks

- Nodkey is not affiliated with, endorsed by, or sponsored by any company, project, or product named
  in this repository, for example Stripe, Adyen, PayPal, Amazon Web Services (AWS), Google, Microsoft,
  OpenAI, Anthropic, or the Model Context Protocol project. Such names are used only to describe prior
  art, compatibility, or comparisons.
- All trademarks belong to their respective owners.
- The name "Nodkey" and its mark have not been cleared as trademarks. The licence does not grant
  permission to use them to imply endorsement (Apache-2.0, section 6).

## Third-party material

Material that the project uses but did not write is listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

*This page is not legal advice.*
