// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Signing-key file handling and dev key generation.
//!
//! Key file format: exactly 64 lowercase hex characters (the 32-byte Ed25519 secret seed of
//! RFC 8032), optionally followed by one `\n`. The file must be a regular file (not a symlink),
//! owned by the authority's uid, with no group or other permission bits. Secret bytes are held in
//! `Zeroizing` buffers and `SigningKey` zeroizes itself on drop (`ed25519-dalek` `zeroize`).
//! Nothing here logs or formats the secret.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use nodkey_grant::{Registry, SigningKey, derive_kid};
use serde_json::json;
use zeroize::Zeroizing;

use crate::digest::{hex, is_id};

const KEY_HEX_LEN: usize = 64;

fn unhex_secret(b: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if b.len() != KEY_HEX_LEN {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        out[i] = nib(b[2 * i])? << 4 | nib(b[2 * i + 1])?;
    }
    Some(out)
}

/// Loads the signing key. `owner_uid` is the authority's own uid. Error strings never contain
/// key material.
pub fn load_signing_key(path: &Path, owner_uid: u32) -> Result<SigningKey, String> {
    let link = std::fs::symlink_metadata(path).map_err(|e| format!("signing key: {e}"))?;
    if !link.file_type().is_file() {
        return Err("signing key: not a regular file (symlinks are refused)".into());
    }
    let mut f = File::open(path).map_err(|e| format!("signing key: {e}"))?;
    let meta = f.metadata().map_err(|e| format!("signing key: {e}"))?;
    if meta.dev() != link.dev() || meta.ino() != link.ino() {
        return Err("signing key: file changed while opening".into());
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "signing key: mode {:o} grants group/other access; require 0600 or 0400",
            meta.mode() & 0o777
        ));
    }
    if meta.uid() != owner_uid {
        return Err("signing key: not owned by the authority uid".into());
    }
    if meta.len() > (KEY_HEX_LEN + 1) as u64 {
        return Err("signing key: wrong size".into());
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(KEY_HEX_LEN + 2));
    Read::by_ref(&mut f)
        .take((KEY_HEX_LEN + 2) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("signing key: {e}"))?;
    let body: &[u8] = match buf.as_slice() {
        [rest @ .., b'\n'] => rest,
        all => all,
    };
    let seed = unhex_secret(body).ok_or("signing key: expected 64 lowercase hex characters")?;
    Ok(SigningKey::from_bytes(&seed))
}

/// The registry `kid` (§8.1) of a signing key, as lowercase hex.
pub fn kid_hex(key: &SigningKey) -> String {
    hex(&derive_kid(&key.verifying_key().to_bytes()))
}

/// A grant-v1 §8.2 registry document with one `active` entry for `key`.
pub fn registry_json(
    key: &SigningKey,
    iss: &str,
    not_before: u64,
    not_after: u64,
) -> Result<String, String> {
    if !is_id(iss, 128) {
        return Err("iss must be an ID of 1-128 bytes of 0x21-0x7E".into());
    }
    if not_before >= not_after || not_after > crate::digest::MAX_UINT {
        return Err("require not_before < not_after <= 2^53-1".into());
    }
    let pk = key.verifying_key().to_bytes();
    let doc = json!({
        "format": "nodkey.grant-keys.v1",
        "keys": [{
            "kid": kid_hex(key),
            "alg": "Ed25519",
            "public_key": hex(&pk),
            "iss": iss,
            "purpose": "grant",
            "not_before": not_before,
            "not_after": not_after,
            "status": "active"
        }]
    });
    let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    // Self-check with the broker's own loader (§8.3).
    Registry::load(&text).map_err(|e| format!("generated registry rejected: {e:?}"))?;
    Ok(text)
}

/// Generates a new key, writes it to `out` (created exclusively, mode 0600, fsync'd), and
/// returns the registry document for the broker. Refuses to overwrite an existing file.
pub fn keygen(out: &Path, iss: &str, not_before: u64, not_after: u64) -> Result<String, String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).map_err(|e| format!("CSPRNG: {e}"))?;
    let key = SigningKey::from_bytes(&seed);
    let registry = registry_json(&key, iss, not_before, not_after)?;

    let mut text = Zeroizing::new(String::with_capacity(KEY_HEX_LEN + 1));
    for b in seed.iter() {
        let hi = b >> 4;
        let lo = b & 0xf;
        for n in [hi, lo] {
            text.push(char::from(if n < 10 { b'0' + n } else { b'a' + n - 10 }));
        }
    }
    text.push('\n');

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|e| format!("{}: {e}", out.display()))?;
    f.write_all(text.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("{}: {e}", out.display()))?;
    if let Some(dir) = out.parent() {
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).unwrap();
        let d = std::env::temp_dir().join(format!("gla-key-{name}-{}", hex(&b)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn my_uid(dir: &Path) -> u32 {
        std::fs::metadata(dir).unwrap().uid()
    }

    #[test]
    fn keygen_roundtrip_and_registry_loads() {
        let d = tmpdir("rt");
        let p = d.join("k");
        let reg = keygen(&p, "nodkey.authority.test", 1, 2_000_000_000).unwrap();
        let mode = std::fs::metadata(&p).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let key = load_signing_key(&p, my_uid(&d)).unwrap();
        let r = Registry::load(&reg).unwrap();
        assert_eq!(r.len(), 1);
        assert!(reg.contains(&kid_hex(&key)));
        // The registry never contains the secret.
        let secret = std::fs::read_to_string(&p).unwrap();
        assert!(!reg.contains(secret.trim()));
        // No overwrite.
        assert!(keygen(&p, "nodkey.authority.test", 1, 2).is_err());
    }

    #[test]
    fn refuses_group_or_world_readable() {
        let d = tmpdir("perm");
        let p = d.join("k");
        keygen(&p, "iss.test", 1, 2).unwrap();
        for mode in [0o640, 0o604, 0o644, 0o660] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            let e = load_signing_key(&p, my_uid(&d)).unwrap_err();
            assert!(e.contains("group/other"), "{e}");
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(load_signing_key(&p, my_uid(&d)).is_ok());
    }

    #[test]
    fn refuses_wrong_owner_symlink_and_bad_content() {
        let d = tmpdir("own");
        let p = d.join("k");
        keygen(&p, "iss.test", 1, 2).unwrap();
        assert!(load_signing_key(&p, my_uid(&d).wrapping_add(1)).is_err());
        let l = d.join("link");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(load_signing_key(&l, my_uid(&d)).is_err());
        for bad in [
            &b"ABCD"[..],
            &[b'A'; 64][..],
            &[b'a'; 63][..],
            &[b'a'; 66][..],
        ] {
            let q = d.join(format!("bad{}", bad.len()));
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&q)
                .unwrap();
            f.write_all(bad).unwrap();
            let e = load_signing_key(&q, my_uid(&d)).unwrap_err();
            assert!(!e.contains("aaaa"), "error must not echo content: {e}");
        }
    }

    #[test]
    fn registry_rejects_bad_iss() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        assert!(registry_json(&key, "has space", 1, 2).is_err());
        assert!(registry_json(&key, "ok", 2, 2).is_err());
    }
}
