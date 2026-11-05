// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Charge-id pattern boundaries (payments-adapter-v1 PA-19, RX-6): `^ch_[A-Za-z0-9]{8,61}$`, so the
//! whole id never exceeds the grant parameter type `text64`.

use nodkey_authority::server::is_charge_id;

#[test]
fn charge_id_length_boundaries() {
    let id = |n: usize| format!("ch_{}", "a".repeat(n));
    assert!(!is_charge_id(&id(7)));
    assert!(is_charge_id(&id(8)));
    assert!(is_charge_id(&id(61)));
    assert_eq!(id(61).len(), 64, "longest accepted id must fit text64");
    assert!(!is_charge_id(&id(62)));
}

#[test]
fn charge_id_rejects_reserved_and_malformed() {
    assert!(!is_charge_id("unresolved"));
    assert!(!is_charge_id("ch_"));
    assert!(!is_charge_id("ch_abcdefg-"));
    assert!(!is_charge_id("CH_abcdefgh"));
    assert!(!is_charge_id("ch_abcdéfgh"));
}
