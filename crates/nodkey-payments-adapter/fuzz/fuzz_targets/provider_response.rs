// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: provider-response decoding and classification (payments-adapter-v1 §6).
//!
//! Input layout: bytes 0-1 = HTTP status (big-endian u16); byte 2 flags: bit 0 = exactly one
//! `Content-Type: application/json`, bit 1 = body present, bit 2 = body read failed (cause
//! selected by byte 3 when set); the rest is the response body.
//!
//! Properties checked:
//! - no panic / timeout / OOM in `classify_create`, `classify_find`, `classify_get`,
//!   `classify_idem` and the `to_json` renderings of their results;
//! - echo check (§6.2): a `Created`/`Found` result always carries exactly the grant-derived
//!   charge, amount, currency and reference (and, for `refund.get`, the requested id);
//! - provider text never reaches the rendered result (§4): a marker string planted by the
//!   fuzzer in the body must not appear in any rendered result.
#![no_main]

use nodkey_payments_adapter::result::{
    AmbCause, Attempt, Exchange, Expected, Lookup, classify_create, classify_find, classify_get,
    classify_idem,
};
use libfuzzer_sys::fuzz_target;

const CAUSES: [AmbCause; 12] = [
    AmbCause::Timeout,
    AmbCause::ResetAfterSend,
    AmbCause::Http5xx,
    AmbCause::Redirect,
    AmbCause::BadStatus,
    AmbCause::BadHeaders,
    AmbCause::Oversized,
    AmbCause::BadJson,
    AmbCause::BadContentType,
    AmbCause::EchoMismatch,
    AmbCause::Schema,
    AmbCause::TooManyMatches,
];

const REFUND_ID: &str = "re_ABCDEFGH1234";
const IDEM_KEY: &str = "idem_key_fixture";
/// Contains `<`, which no pattern-checked provider value (ids, reference, enums) may contain, and
/// which no fixed/grant-derived value here contains; if it reaches a rendered result, free-form
/// provider text leaked.
const MARKER: &str = "<LEAK>";

fn expected() -> Expected {
    Expected {
        charge: "ch_demoorder0001".into(),
        amount_minor: 500,
        currency: "USD".into(),
        reference: "REFabc_-".into(),
    }
}

fn check_refund(r: &nodkey_payments_adapter::result::Refund, e: &Expected) {
    assert_eq!(r.charge, e.charge);
    assert_eq!(r.amount_minor, e.amount_minor);
    assert_eq!(r.currency, e.currency);
    assert_eq!(r.reference, e.reference);
}

fuzz_target!(|data: &[u8]| {
    let [s0, s1, flags, rest @ ..] = data else { return };
    let status = u16::from_be_bytes([*s0, *s1]);
    let body = if flags & 0b10 == 0 {
        None
    } else if flags & 0b100 != 0 {
        let c = rest.first().copied().unwrap_or(0);
        Some(Err(CAUSES[usize::from(c) % CAUSES.len()]))
    } else {
        Some(Ok(rest.to_vec()))
    };
    let x = Exchange::Response {
        status,
        json_content_type: flags & 1 == 1,
        body,
    };
    let e = expected();
    let body_has_marker = rest.windows(MARKER.len()).any(|w| w == MARKER.as_bytes());
    let no_leak = |s: String| {
        if body_has_marker {
            assert!(!s.contains(MARKER), "provider text reached a result: {s}");
        }
    };

    let a = classify_create(&x, &e);
    if let Attempt::Created(r) = &a {
        check_refund(r, &e);
    }
    no_leak(a.to_json(&e.reference).to_string());
    let _ = (a.class(), a.cause());

    let f = classify_find(&x, &e);
    if let Lookup::Found(r) = &f {
        check_refund(r, &e);
    }
    no_leak(f.to_json().to_string());

    let g = classify_get(&x, &e, REFUND_ID);
    if let Lookup::Found(r) = &g {
        check_refund(r, &e);
        assert_eq!(r.id, REFUND_ID);
    }
    no_leak(g.to_json().to_string());

    let i = classify_idem(&x, IDEM_KEY);
    no_leak(i.to_json().to_string());
});
