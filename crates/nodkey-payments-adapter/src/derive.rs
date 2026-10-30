// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Provider values derived from the verified grant with `K_idem` (payments-adapter-v1 §3.3):
//!
//! ```text
//! D         = "nodkey.pay.v1" || 0x00 || lp(provider_account) || lp(op) || u64be(opv) || lp(iss) || lp(jti)
//! idem_key  = b64url( HMAC-SHA256(K_idem, "idem" || 0x00 || D) )
//! reference = b64url( HMAC-SHA256(K_idem, "ref"  || 0x00 || D) )
//! idem_kid  = hex( HMAC-SHA256(K_idem, "kid")[..8] )
//! lp(x)     = u64be(len(x)) || x
//! ```
//!
//! HMAC-SHA256 comes from the `hmac`/`sha2` crates (no custom primitive); b64url is the grant
//! crate's canonical unpadded encoder.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// `K_idem`: 32 bytes held only by the adapter. Zeroized on drop; never printed.
pub struct IdemKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for IdemKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdemKey(<redacted>)")
    }
}

/// The values the adapter sends to the provider for one grant. The broker never sees `idem_key`.
#[derive(Clone, PartialEq, Eq)]
pub struct Derived {
    pub idem_key: String,
    pub reference: String,
}

impl std::fmt::Debug for Derived {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Derived")
            .field("idem_key", &"<redacted>")
            .field("reference", &self.reference)
            .finish()
    }
}

fn lp(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice(&(x.len() as u64).to_be_bytes());
    out.extend_from_slice(x);
}

impl IdemKey {
    pub fn new(bytes: [u8; 32]) -> IdemKey {
        IdemKey(Zeroizing::new(bytes))
    }

    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.0[..])
            .expect("HMAC accepts any key length");
        for p in parts {
            m.update(p);
        }
        m.finalize().into_bytes().into()
    }

    /// `idem_kid` for `adapter.hello` (16 lowercase hex characters).
    pub fn kid(&self) -> String {
        self.mac(&[b"kid"])[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub fn derive(&self, account: &str, op: &str, opv: u64, iss: &str, jti: &[u8; 16]) -> Derived {
        let mut d = Vec::with_capacity(96);
        d.extend_from_slice(b"nodkey.pay.v1\0");
        lp(&mut d, account.as_bytes());
        lp(&mut d, op.as_bytes());
        d.extend_from_slice(&opv.to_be_bytes());
        lp(&mut d, iss.as_bytes());
        lp(&mut d, jti);
        Derived {
            idem_key: nodkey_grant::encode_transport(&self.mac(&[b"idem\0", &d])),
            reference: nodkey_grant::encode_transport(&self.mac(&[b"ref\0", &d])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors computed independently with Python's `hmac`/`hashlib`/`base64` modules
    /// (`base64.urlsafe_b64encode(...).rstrip(b"=")`), not with this code (PT-26).
    /// K_idem = 0x00..0x1f, account "acct_demomerchant01", op "payments.refund", opv 1,
    /// iss "nodkey.authority.test", jti = 0x09 × 16.
    #[test]
    fn derivation_vectors() {
        let k = IdemKey::new(core::array::from_fn(|i| i as u8));
        let d = k.derive(
            "acct_demomerchant01",
            "payments.refund",
            1,
            "nodkey.authority.test",
            &[9; 16],
        );
        assert_eq!(d.idem_key, VEC_IDEM);
        assert_eq!(d.reference, VEC_REF);
        assert_eq!(k.kid(), VEC_KID);
        assert_eq!(d.idem_key.len(), 43);
        assert_eq!(d.reference.len(), 43);
    }

    #[test]
    fn every_input_separates() {
        let k = IdemKey::new([7; 32]);
        let base = k.derive("a", "payments.refund", 1, "iss", &[1; 16]);
        assert_ne!(base.idem_key, base.reference);
        for other in [
            k.derive("b", "payments.refund", 1, "iss", &[1; 16]),
            k.derive("a", "payments.refunc", 1, "iss", &[1; 16]),
            k.derive("a", "payments.refund", 2, "iss", &[1; 16]),
            k.derive("a", "payments.refund", 1, "isr", &[1; 16]),
            k.derive("a", "payments.refund", 1, "iss", &[2; 16]),
            IdemKey::new([8; 32]).derive("a", "payments.refund", 1, "iss", &[1; 16]),
        ] {
            assert_ne!(other.idem_key, base.idem_key);
            assert_ne!(other.reference, base.reference);
        }
        // Length prefixes: moving a byte between fields changes the result.
        assert_ne!(
            k.derive("ab", "c", 1, "iss", &[1; 16]).idem_key,
            k.derive("a", "bc", 1, "iss", &[1; 16]).idem_key
        );
        // Deterministic: a resend derives the same values.
        assert_eq!(k.derive("a", "payments.refund", 1, "iss", &[1; 16]), base);
    }

    #[test]
    fn debug_redacts() {
        let k = IdemKey::new([7; 32]);
        assert_eq!(format!("{k:?}"), "IdemKey(<redacted>)");
        let d = k.derive("a", "b", 1, "c", &[0; 16]);
        assert!(!format!("{d:?}").contains(&d.idem_key));
    }

    const VEC_IDEM: &str = "uWnB81G9llZOd4WnLHlkO50_DE9PJNIJ6O5CXMrsJBY";
    const VEC_REF: &str = "D6gacfRHuyXb61PPfEHdg3-dbxXO5__4qCv1q5nm3Uk";
    const VEC_KID: &str = "933007a5314c9534";
}
