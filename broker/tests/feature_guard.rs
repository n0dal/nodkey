// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Guard: the broker must never be built with nodkey-grant's test-only feature
//! `conformance-unvalidated-requests` (it exposes `Request::unvalidated_for_conformance`, which
//! bypasses strict request validation). Fails if any build of this package (normal or dev)
//! resolves nodkey-grant with that feature.

use std::process::Command;

#[test]
fn conformance_feature_not_enabled() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let out = Command::new(cargo)
        .args([
            "tree",
            "--offline",
            "--manifest-path",
            manifest,
            "-e",
            "features,normal,dev,build",
            "-i",
            "nodkey-grant",
            "--prefix",
            "none",
        ])
        .output()
        .expect("run cargo tree");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("nodkey-grant"),
        "unexpected cargo tree output: {text}"
    );
    assert!(
        !text.contains("conformance-unvalidated-requests"),
        "nodkey-grant's test-only feature is enabled in the broker build:\n{text}"
    );
}
