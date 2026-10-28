# Contributing

Nodkey is a research prototype. Read [README.md](README.md), [STATUS.md](STATUS.md), and
[SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md) before proposing changes.

## Sign-off (DCO)

Contributions are accepted under the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Sign off every commit:

```sh
git commit -s
```

This adds `Signed-off-by: Your Name <your.email@example.org>`, certifying that you have the right to
submit the work under the project's license ([Apache-2.0](LICENSE)).

## Expectations

- **Tests.** Changes come with tests, and the affected suites are run with their output reported. Unit
  tests: `cargo test` in the changed crate. Demos: the runners in [`tests/`](tests/) (see
  [QUICKSTART.md](QUICKSTART.md)). Results use PASS / FAIL / NOT TESTED / NOT APPLICABLE / INCONCLUSIVE;
  do not drop or relabel a row to make a run pass.
- **Security-sensitive changes need a review** by someone other than the author. This covers the
  broker, authority, gateway, payments adapter, grant format and verification, specs, deployment
  profiles, and anything touching a security invariant. Changing an invariant requires an accepted ADR
  ([docs/decisions/](docs/decisions/README.md)).
- **No custom cryptographic primitives.** Use established libraries and formats.
- **Claims must be tested.** Documentation states the deployment profile and assumptions behind a
  security claim and links to a test, or says NOT TESTED (SI-17).
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in issues or pull
  requests.
