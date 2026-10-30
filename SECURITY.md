# Security Policy

> [!WARNING]
> Nodkey is a research prototype and is not intended for production use. All security reviews so far
> were performed by AI agents; no independent human audit has been done. See
> [DISCLAIMER.md](DISCLAIMER.md).

## Reporting a vulnerability

Report suspected vulnerabilities **privately**. Do not open a public issue.

Use GitHub private vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**, or go directly to
<https://github.com/n0dal/nodkey/security/advisories/new>.

Please include the affected component and version (commit), the deployment profile or demo, steps to
reproduce, and the security invariant ([SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md)) you
believe is violated, if any.

## Supported versions

None. There are no releases. Fixes, if any, are made on the main development line only.

## Scope

In scope: a violation of a security invariant under its documented deployment profile and threat model
([THREAT_MODEL.md](docs/THREAT_MODEL.md)), for example a workload executing an effect nobody approved,
an approved effect executing with different values or more than once, or a workload obtaining a
credential, a grant, or a route to a protected resource. A security claim in the documentation that is
not supported by a test is also a valid report (SI-17).

Out of scope:

- the intentionally vulnerable demo endpoints themselves (for example `POST /debug/eval`) and the
  credential-less test login; they exist to model a compromised workload on a local test stack;
- limitations already listed in [LIMITATIONS.md](LIMITATIONS.md), including compromise of the host,
  kernel, container runtime, gateway, authority, or broker;
- the simulators (`tools/simpay`, `tools/mailsink`, `tools/demo-agent`), except where a flaw affects
  what the demos claim to show.
