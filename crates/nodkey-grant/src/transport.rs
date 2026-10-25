//! Transport encoding (spec §2, steps 0–1c): canonical unpadded base64url (RFC 4648 §5).

use crate::error::GrantError;
use crate::{MAX_GRANT_BYTES, MAX_TRANSPORT_CHARS};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Steps 0, 1a, 1b, 1c: decodes the transport text of a grant into grant bytes.
///
/// `None` (no grant supplied) is `grant_missing`. An empty string is treated as supplied and
/// decodes to zero bytes, which then fails structure checks (`grant_malformed`).
pub fn decode_transport(text: Option<&str>) -> Result<Vec<u8>, GrantError> {
    let text = text.ok_or(GrantError::Missing)?;
    let t = text.as_bytes();
    if t.len() > MAX_TRANSPORT_CHARS {
        return Err(GrantError::TooLarge);
    }
    if t.len() % 4 == 1 {
        return Err(GrantError::EncodingInvalid);
    }
    let mut out = Vec::with_capacity(t.len() * 3 / 4);
    for chunk in t.chunks(4) {
        let mut acc: u32 = 0;
        for &c in chunk {
            acc = (acc << 6) | u32::from(sextet(c).ok_or(GrantError::EncodingInvalid)?);
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]),
            3 => {
                // 18 bits: 16 data + 2 unused, which must be zero.
                if acc & 0x3 != 0 {
                    return Err(GrantError::EncodingInvalid);
                }
                out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]);
            }
            2 => {
                // 12 bits: 8 data + 4 unused, which must be zero.
                if acc & 0xf != 0 {
                    return Err(GrantError::EncodingInvalid);
                }
                out.push((acc >> 4) as u8);
            }
            _ => return Err(GrantError::EncodingInvalid),
        }
    }
    if out.len() > MAX_GRANT_BYTES {
        return Err(GrantError::TooLarge);
    }
    Ok(out)
}

/// Encodes grant bytes as unpadded base64url.
pub fn encode_transport(grant: &[u8]) -> String {
    let mut s = String::with_capacity(grant.len().div_ceil(3) * 4);
    for chunk in grant.chunks(3) {
        let mut b = [0u8; 3];
        b[..chunk.len()].copy_from_slice(chunk);
        let acc = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let n = chunk.len() + 1;
        for i in 0..n {
            s.push(ALPHABET[((acc >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors_unpadded() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode_transport(plain.as_bytes()), enc);
            assert_eq!(decode_transport(Some(enc)).unwrap(), plain.as_bytes());
        }
        assert_eq!(encode_transport(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn non_canonical_rejected() {
        use GrantError::*;
        assert_eq!(decode_transport(None), Err(Missing));
        // "Zh" and "Zm9" decode to the same bytes as "Zg" and "Zm8" but have nonzero unused bits.
        for bad in [
            "Zg==", "Zm9v\n", "Zm+v", "Zm/v", "Z", "Zh", "Zm9", "Zm 9v", "Zm9vY",
        ] {
            assert_eq!(decode_transport(Some(bad)), Err(EncodingInvalid), "{bad:?}");
        }
        assert_eq!(decode_transport(Some("Zm-")), Err(EncodingInvalid));
    }

    #[test]
    fn size_limits() {
        let max = encode_transport(&[0u8; MAX_GRANT_BYTES]);
        assert_eq!(max.len(), MAX_TRANSPORT_CHARS);
        assert_eq!(decode_transport(Some(&max)).unwrap().len(), MAX_GRANT_BYTES);
        let over = "A".repeat(MAX_TRANSPORT_CHARS + 1);
        assert_eq!(decode_transport(Some(&over)), Err(GrantError::TooLarge));
        // 2732 chars would be rejected at 1a; 2730 chars of "A" with len%4==2 decode to 2047 bytes.
        let ok = "A".repeat(2730);
        assert_eq!(decode_transport(Some(&ok)).unwrap().len(), 2047);
    }
}
