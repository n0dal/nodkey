// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! TLS (files mode; dev self-signed with `dev-tls`), SNI/Host agreement, start-up refusals
//! including the dev-mode gating of GW-R-04, IPC peer-uid checks.

mod common;
use common::*;

use nodkey_gateway::config::{TlsConfig, check};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn get_with_sni(addr: std::net::SocketAddr, sni: &str, host: &str) -> Resp {
    let mut s = tls_connect(addr, sni).await;
    s.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    parse(&out)
}

#[tokio::test]
async fn files_tls_and_sni_host_agreement() {
    let h = start().await;
    let r = get_with_sni(h.addr, APP, APP).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.text(), "hello from app");
    assert_eq!(get_with_sni(h.addr, AUTH, AUTH).await.status, 200);
    assert_eq!(
        get_with_sni(h.addr, AUTH, APP).await.status,
        421,
        "SNI and Host must agree"
    );
}

fn dev_ok(c: &mut nodkey_gateway::config::Config) {
    c.dev_local_only = true;
}

#[test]
fn startup_refusals() {
    let dir = tmpdir();
    let up = "127.0.0.1:1".parse().unwrap();
    let base = || base_config(&dir, up);

    let mut c = base();
    c.auth_origin = "https://app.localhost:8080".into();
    assert!(check(c).is_err(), "same host for both origins");

    let mut c = base();
    c.app_origin = "http://app.localhost".into();
    assert!(check(c).is_err(), "scheme must match the TLS mode");

    for bad in ["__Host-nodkey_session", "my_nodkey", "__Secure-x", "a b"] {
        let mut c = base();
        c.app_cookies = vec![bad.into()];
        assert!(check(c).is_err(), "app cookie {bad}");
    }

    let mut c = base();
    c.trusted_proxies = vec!["127.0.0.1".into()];
    assert!(check(c).unwrap_err().contains("trusted_proxies"));

    let mut c = base();
    c.limits.auth_connections = 0;
    assert!(check(c).is_err());

    // Dev TLS modes.
    for tls in [
        TlsConfig::PlainHttpLoopbackInsecure,
        TlsConfig::DevSelfSigned {
            cert_out: dir.join("x.pem"),
        },
    ] {
        let plain = matches!(tls, TlsConfig::PlainHttpLoopbackInsecure);
        let scheme = if plain { "http" } else { "https" };
        let mk = |tls: TlsConfig| {
            let mut c = base();
            c.tls = tls;
            c.app_origin = format!("{scheme}://app.localhost");
            c.auth_origin = format!("{scheme}://auth.localhost");
            c
        };
        let err = check(mk(tls.clone())).unwrap_err();
        if cfg!(feature = "dev-tls") {
            assert!(err.contains("dev_local_only"), "{err}");
            let mut c = mk(tls.clone());
            dev_ok(&mut c);
            assert!(check(c).is_ok());
            let mut c = mk(tls.clone());
            dev_ok(&mut c);
            c.listen = "0.0.0.0:8443".parse().unwrap();
            assert!(check(c).unwrap_err().contains("loopback"));
            let mut c = mk(tls.clone());
            dev_ok(&mut c);
            c.app_origin = format!("{scheme}://app.example.com");
            assert!(check(c).unwrap_err().contains("localhost"));
        } else {
            assert!(err.contains("`dev-tls` feature"), "{err}");
            let mut c = mk(tls.clone());
            dev_ok(&mut c);
            assert!(check(c).is_err(), "the config flag alone is not enough");
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(feature = "test-login")]
#[test]
fn test_login_gating() {
    use nodkey_gateway::config::{TestLoginConfig, TestUser};
    let dir = tmpdir();
    let mk = || {
        let mut c = base_config(&dir, "127.0.0.1:1".parse().unwrap());
        c.test_login = Some(TestLoginConfig {
            enabled: true,
            users: vec![TestUser {
                ten: "acme".into(),
                sub: "u".into(),
                label: "U".into(),
            }],
        });
        c
    };
    assert!(check(mk()).unwrap_err().contains("dev_local_only"));
    let mut c = mk();
    c.dev_local_only = true;
    assert!(check(c).unwrap().test_login_active);
    let mut c = mk();
    c.dev_local_only = true;
    c.listen = "0.0.0.0:8443".parse().unwrap();
    assert!(check(c).unwrap_err().contains("loopback"));
    let mut c = mk();
    c.dev_local_only = true;
    c.auth_origin = "https://login.example.com".into();
    assert!(check(c).unwrap_err().contains("localhost"));
    let mut c = mk();
    c.dev_local_only = true;
    c.trusted_proxies = vec!["10.0.0.1".into()];
    assert!(check(c).is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(feature = "dev-tls")]
#[tokio::test]
async fn dev_self_signed_end_to_end() {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};
    let certdir = tmpdir();
    let cert_out = certdir.join("dev-cert.pem");
    let co = cert_out.clone();
    let h = start_with(move |c| {
        c.tls = TlsConfig::DevSelfSigned { cert_out: co };
        c.dev_local_only = true;
    })
    .await;
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(&cert_out).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let cc = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let mut s = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cc))
        .connect(ServerName::try_from(APP.to_owned()).unwrap(), tcp)
        .await
        .unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: app.localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    assert_eq!(parse(&out).status, 200);
    let _ = std::fs::remove_dir_all(certdir);
}

#[tokio::test]
async fn wrong_peer_uid_fails_closed() {
    let h = start().await;
    let me = my_uid();
    let peer = nodkey_gateway::ipc::Peer {
        path: h.dir.join("i.sock"),
        expected_uid: Some(me.wrapping_add(4242)),
        timeout: std::time::Duration::from_secs(2),
    };
    let subj = nodkey_gateway::ipc::Subject {
        ten: "acme",
        sub: "u",
    };
    let r = nodkey_gateway::ipc::read_grant(&peer, subj, WID, &["payments.get_order".into()]).await;
    assert_eq!(
        r,
        Err(nodkey_gateway::ipc::IpcError::Transport(
            "peer uid mismatch"
        ))
    );
    assert!(h.world.lock().unwrap().authority_calls.is_empty());
    let ok = nodkey_gateway::ipc::Peer {
        expected_uid: Some(me),
        ..peer
    };
    assert_eq!(
        nodkey_gateway::ipc::read_grant(&ok, subj, WID, &["payments.get_order".into()]).await,
        Ok(FAKE_GRANT.to_owned())
    );
}
