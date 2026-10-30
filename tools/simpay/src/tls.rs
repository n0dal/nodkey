// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Optional TLS for the API listener (rustls with the ring provider; no OpenSSL), and
//! generation of a TEST-ONLY certificate authority for pinning in tests.
//!
//! Protocol: TLS 1.3 only. Nodkey's payments adapter is the only intended client and
//! supports TLS 1.3, so there is no reason to keep TLS 1.2's larger negotiation surface.
//! No client authentication: simpay identifies callers by API key and source address.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, date_time_ymd,
};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Label placed in every generated certificate's subject.
pub const TEST_LABEL: &str = "simpay TEST-ONLY";

pub const CA_CERT: &str = "simpay-TEST-ONLY-ca.crt";
pub const CA_KEY: &str = "simpay-TEST-ONLY-ca.key";
pub const SERVER_CERT: &str = "simpay-TEST-ONLY-server.crt";
pub const SERVER_KEY: &str = "simpay-TEST-ONLY-server.key";
/// Opt-in malicious certificates (attacker G at the TLS layer).
pub const WRONG_HOST_CERT: &str = "simpay-TEST-ONLY-MALICIOUS-wrong-host.crt";
pub const WRONG_HOST_KEY: &str = "simpay-TEST-ONLY-MALICIOUS-wrong-host.key";
pub const EXPIRED_CERT: &str = "simpay-TEST-ONLY-MALICIOUS-expired.crt";
pub const EXPIRED_KEY: &str = "simpay-TEST-ONLY-MALICIOUS-expired.key";
/// The SAN used by the wrong-host certificate.
pub const WRONG_HOST_NAME: &str = "wrong-host.simpay.invalid";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Builds a TLS 1.3-only server configuration from PEM files.
pub fn server_config(files: &TlsFiles) -> Result<Arc<ServerConfig>, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&files.cert)
        .map_err(|e| format!("tls cert {}: {e}", files.cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("tls cert {}: {e}", files.cert.display()))?;
    if certs.is_empty() {
        return Err(format!(
            "tls cert {}: no certificates",
            files.cert.display()
        ));
    }
    let key = PrivateKeyDer::from_pem_file(&files.key)
        .map_err(|e| format!("tls key {}: {e}", files.key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls: {e}"))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn valid_dns_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn write_new(path: &Path, contents: &str, secret: bool) -> Result<(), String> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(if secret { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut f = o.open(path).map_err(|e| {
        format!(
            "{}: {e} (existing files are never overwritten)",
            path.display()
        )
    })?;
    f.write_all(contents.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn leaf_params(name: &str, cn: &str) -> Result<CertificateParams, String> {
    let mut p = CertificateParams::new(vec![name.to_string()]).map_err(|e| e.to_string())?;
    p.distinguished_name.push(DnType::CommonName, cn);
    p.distinguished_name
        .push(DnType::OrganizationName, "simpay SIMULATOR - TEST ONLY");
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.not_before = date_time_ymd(2025, 1, 1);
    p.not_after = date_time_ymd(2035, 1, 1);
    Ok(p)
}

/// Writes a TEST-ONLY CA and a server certificate for `dns_name` signed by it into `out`.
/// With `malicious`, also writes a wrong-hostname certificate and an expired certificate,
/// both signed by the same CA. Refuses to overwrite existing files. Keys are mode 0600.
pub fn generate_test_ca(
    out: &Path,
    dns_name: &str,
    malicious: bool,
) -> Result<Vec<PathBuf>, String> {
    if !valid_dns_name(dns_name) {
        return Err(format!("invalid DNS name {dns_name:?}"));
    }
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;

    let mut ca_params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    ca_params.distinguished_name.push(
        DnType::CommonName,
        format!("{TEST_LABEL} CA - DO NOT TRUST OUTSIDE TESTS"),
    );
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "simpay SIMULATOR - TEST ONLY");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = date_time_ymd(2025, 1, 1);
    ca_params.not_after = date_time_ymd(2035, 1, 1);
    let ca_key = KeyPair::generate().map_err(|e| e.to_string())?;
    let ca_cert = ca_params.self_signed(&ca_key).map_err(|e| e.to_string())?;
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let mut files: Vec<(String, String, bool)> = vec![
        (CA_CERT.into(), ca_cert.pem(), false),
        (CA_KEY.into(), ca_key.serialize_pem(), true),
    ];
    let mut leaf =
        |name: &str, cn: &str, expired: bool, cf: &str, kf: &str| -> Result<(), String> {
            let mut p = leaf_params(name, cn)?;
            if expired {
                p.not_before = date_time_ymd(2000, 1, 1);
                p.not_after = date_time_ymd(2001, 1, 1);
            }
            let k = KeyPair::generate().map_err(|e| e.to_string())?;
            let c = p.signed_by(&k, &issuer).map_err(|e| e.to_string())?;
            files.push((cf.into(), c.pem(), false));
            files.push((kf.into(), k.serialize_pem(), true));
            Ok(())
        };
    leaf(
        dns_name,
        &format!("{TEST_LABEL} server {dns_name}"),
        false,
        SERVER_CERT,
        SERVER_KEY,
    )?;
    if malicious {
        leaf(
            WRONG_HOST_NAME,
            &format!("{TEST_LABEL} MALICIOUS wrong-host"),
            false,
            WRONG_HOST_CERT,
            WRONG_HOST_KEY,
        )?;
        leaf(
            dns_name,
            &format!("{TEST_LABEL} MALICIOUS expired {dns_name}"),
            true,
            EXPIRED_CERT,
            EXPIRED_KEY,
        )?;
    }
    let notice = format!(
        "TEST-ONLY certificates generated by simpay (a SIMULATED payment provider).\n\
         Never trust {CA_CERT} outside tests. Server name: {dns_name}.\n\
         Files marked MALICIOUS are deliberately invalid (wrong hostname, expired) for\n\
         attacker-G tests and must make any correct client fail the handshake.\n"
    );
    files.push(("TEST-ONLY-README.txt".into(), notice, false));
    let mut written = vec![];
    for (name, contents, secret) in files {
        let p = out.join(name);
        write_new(&p, &contents, secret)?;
        written.push(p);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_names() {
        assert!(valid_dns_name("simpay.internal"));
        assert!(valid_dns_name("a-b.c1"));
        assert!(!valid_dns_name(""));
        assert!(!valid_dns_name("Simpay.internal"));
        assert!(!valid_dns_name("a..b"));
        assert!(!valid_dns_name("-a.b"));
        assert!(!valid_dns_name("a b"));
        assert!(!valid_dns_name("*.x"));
    }
}
