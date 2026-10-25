# ADR-0003: Trusted user context and grant issuance (rev. 2)

- **Status:** Proposed — rewritten after review AR-01..04, AR-07, AR-08, AR-13 (rev. 1 verdict:
  reject and resubmit). Needs re-review before acceptance.
- **Date:** 2026-10-24
- **Invariants:** SI-02, SI-05, SI-06, SI-07, SI-09, SI-10, SI-18
- **Open questions:** OQ-04 (addressed), OQ-08 (addressed by single-parser topology)

## Problem

The broker must know which user is behind an effect and exactly what that user asked for, without
trusting the app that relays the request, and without the app ever holding a reusable user
credential (OQ-04).

## Evaluation criteria

No reusable user credential reaches workload code, server- or client-side; the effect is bound to
the user's actual request; one parser decides what the request means; the residual of a compromised
app is published and small; standard primitives only.

## Alternatives considered

(a) app forwards the session cookie — rejected (bearer credential in the app). (b1) identity-only
attestation — app can trigger any permitted operation. (b2) attestation bound to the request,
operation derived by a trusted parser — chosen. (c) DPoP client keys — do not defeat a compromised
origin. Rev. 1 (nginx + auth subrequest, ceiling binding) — rejected by review: nginx parses app
output while holding all session cookies (AR-03), the subrequest has no body and no reliable response
association (AR-07), ceilings widen the residual (AR-04), and a shared origin lets the app capture
credentials at login (AR-01).

## Decision

1. **Topology.** A Rust **gateway** is the only public listener. It terminates TLS and sessions,
   parses each request once, and forwards it over a UDS to the workload (nginx, if used, is part of
   the untrusted workload). Grant **signing** happens in a separate **authority** process/container
   that receives requests only from the gateway, never from the app.
2. **Separate auth origin (SI-18).** Credential entry and session establishment happen only on
   `auth.<domain>`, served solely by the gateway, with `frame-ancestors 'none'`. Passkeys/WebAuthn
   with RP ID = the auth host are the P0 login method; password login is a weaker, separately
   labelled profile. After login the gateway sets `__Host-nodkey_session` (HttpOnly, Secure,
   SameSite=Lax) on the app host through a gateway-reserved, one-time-code callback path.
3. **Request allowlist.** The gateway builds the forwarded request from an **allowlist** of headers
   and app-owned cookies; everything else, including every gateway-owned cookie, `Authorization`, and
   any client-supplied `Nodkey-*` header, is dropped. The grant is attached under `Nodkey-Grant`, which only
   the gateway can set.
4. **Browser persistence controls.** The gateway rejects requests carrying `Service-Worker: script`
   (no service-worker registration on the app origin), sets `Cache-Control: no-cache` on HTML and
   JavaScript responses, drops app `Set-Cookie` headers naming gateway-owned cookies, and drops
   `Service-Worker-Allowed`. It supports an operator-triggered `Clear-Site-Data: "cache", "storage"`
   for remediation.
5. **Route map → exact binding.** The gateway maps method + canonical path + strictly parsed body
   (JSON with duplicate keys rejected, size-capped) to **at most one operation** per request
   (AR-13). Each operation parameter is classified in its broker declaration as **exact** (default:
   the value comes from the request and is placed in the grant), **bounded** (ceiling, allowed only
   where the route map marks it `app_computed`), or **free** (requires a written justification and
   appears in the published residual table). Destination-like parameters (accounts, URLs, recipients)
   are never free. The broker refuses to start if any parameter is unclassified.
6. **Grant.** The authority signs a single-use grant (ADR-0004): `iss, aud, wid, ten, sub, op, opv,
   res, con, iat, nbf, exp (≤ 30 s), jti`. No `rqh`: exact binding in `con` replaces it (AR-08).
7. **Broker.** Sources `sub`/`ten` from the verified grant (AR-17), checks `wid` against the socket,
   checks params against `res`/`con`, then re-derives ownership, state and budgets in-transaction.
8. Unmapped routes get no grant. Background and workload-authority operations follow ADR-0009.

## Residual authority of a compromised app

- **In-flight grant:** per mapped request, the app can execute **exactly the user's request, once,
  within 30 s**, or drop it. For `bounded` params: anything up to the declared ceiling; for `free`
  params: anything, as listed in the residual table.
- **In-page abuse while the user is active** (quantified in THREAT_MODEL R-3): any route in P(u),
  limited by budgets, while a tab from the app origin is open within the session lifetime.
- **No credential capture** under passkeys; under passwords, phishing on the app origin remains (R-4).

## Evidence

Research 04 §2 (b2); review AR-01..04, AR-07, AR-08, AR-13; WebAuthn L2 RP ID rules [F\*]; Service
Workers spec `Service-Worker: script` request header [F\*, to verify in a spike]; RFC 6265bis cookie
prefixes [F\*].

## Consequences
- **Advantages:** one memory-safe parser; no reusable credential in the workload; residual equals the
  user's own request for exact routes.
- **Drawbacks:** apps must give up their own login and declare routes; gateway is new TCB code.
- **Security:** the gateway still parses app responses and holds sessions — a gateway bug reachable
  from the app yields live sessions (not the signing key). Authority compromise = attacker J.
- **Performance:** one extra hop plus one signature per mapped request [H].
- **Compatibility:** apps relying on service workers need an explicit allowlisted path (none in v0).

## Reversal / migration

Moving bounded params to exact is a route-map change. Replacing the gateway with an IdP + another
trusted proxy is possible if both keep decisions 2–5.
