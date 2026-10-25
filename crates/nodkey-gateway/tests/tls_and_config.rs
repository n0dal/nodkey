//! Dev self-signed TLS, SNI/Host agreement, start-up refusals, IPC peer-uid check.

mod common;
use common::*;
use std::sync::Arc;

use nodkey_gateway::config::{TlsConfig, check};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn tls_get(
    addr: std::net::SocketAddr,
    roots: &rustls::RootCertStore,
    sni: &str,
    host: &str,
) -> Resp {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cc = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    let conn = tokio_rustls::TlsConnector::from(Arc::new(cc));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut s = conn
        .connect(ServerName::try_from(sni.to_owned()).unwrap(), tcp)
        .await
        .unwrap();
    s.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    parse(&out)
}

#[tokio::test]
async fn dev_self_signed_tls_and_sni_host_agreement() {
    let certdir = tmpdir();
    let cert_out = certdir.join("dev-cert.pem");
    let co = cert_out.clone();
    let h = start_with(move |c| {
        c.tls = TlsConfig::DevSelfSigned { cert_out: co };
        c.app_origin = "https://app.localhost".into();
        c.auth_origin = "https://auth.localhost".into();
    })
    .await;
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(&cert_out).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let r = tls_get(h.addr, &roots, APP, APP).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.text(), "hello from app");
    let r = tls_get(h.addr, &roots, AUTH, AUTH).await;
    assert_eq!(r.status, 200);
    let r = tls_get(h.addr, &roots, AUTH, APP).await;
    assert_eq!(r.status, 421, "SNI and Host must agree");
    let _ = std::fs::remove_dir_all(certdir);
}

#[test]
fn startup_refusals() {
    let dir = tmpdir();
    let up = "127.0.0.1:1".parse().unwrap();
    let mut c = base_config(&dir, up);
    c.listen = "0.0.0.0:8443".parse().unwrap();
    assert!(
        check(c).unwrap_err().contains("loopback"),
        "plain HTTP off loopback"
    );

    let mut c = base_config(&dir, up);
    c.listen = "0.0.0.0:8443".parse().unwrap();
    c.tls = TlsConfig::DevSelfSigned {
        cert_out: dir.join("x.pem"),
    };
    c.app_origin = "https://app.localhost".into();
    c.auth_origin = "https://auth.localhost".into();
    assert!(
        check(c).unwrap_err().contains("loopback"),
        "dev cert off loopback"
    );

    let mut c = base_config(&dir, up);
    c.auth_origin = "http://app.localhost:8080".into();
    assert!(check(c).is_err(), "same host for both origins");

    let mut c = base_config(&dir, up);
    c.app_origin = "https://app.localhost".into();
    assert!(check(c).is_err(), "scheme must match the TLS mode");

    for bad in [
        "__Host-nodkey_session",
        "my_nodkey",
        "__Secure-x",
        "a b",
    ] {
        let mut c = base_config(&dir, up);
        c.app_cookies = vec![bad.into()];
        assert!(check(c).is_err(), "app cookie {bad}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(feature = "test-login")]
#[test]
fn test_login_refused_off_loopback() {
    use nodkey_gateway::config::{TestLoginConfig, TestUser};
    let dir = tmpdir();
    let mut c = base_config(&dir, "127.0.0.1:1".parse().unwrap());
    c.listen = "0.0.0.0:8443".parse().unwrap();
    c.tls = TlsConfig::Files {
        cert_pem: dir.join("c"),
        key_pem: dir.join("k"),
    };
    c.app_origin = "https://app.localhost".into();
    c.auth_origin = "https://auth.localhost".into();
    c.test_login = Some(TestLoginConfig {
        enabled: true,
        users: vec![TestUser {
            ten: "acme".into(),
            sub: "u".into(),
            label: "U".into(),
        }],
    });
    assert!(check(c).unwrap_err().contains("loopback"));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn wrong_peer_uid_on_authority_socket_means_no_read_grant_call_succeeds() {
    use std::os::unix::fs::MetadataExt;
    let h = start().await;
    // Socket I is answered by a process with our uid; expecting a different uid must fail closed.
    let me = std::fs::metadata(h.dir.join("i.sock")).unwrap().uid();
    let peer = nodkey_gateway::ipc::Peer {
        path: h.dir.join("i.sock"),
        expected_uid: Some(me.wrapping_add(4242)),
        timeout: std::time::Duration::from_secs(2),
    };
    let subj = nodkey_gateway::ipc::Subject {
        ten: "acme",
        sub: "u",
    };
    let r =
        nodkey_gateway::ipc::read_grant(&peer, subj, WID, &["payments.get_order".into()]).await;
    assert_eq!(
        r,
        Err(nodkey_gateway::ipc::IpcError::Transport(
            "peer uid mismatch"
        ))
    );
    assert!(
        h.world.lock().unwrap().authority_calls.is_empty(),
        "nothing was sent"
    );
    // With the right uid the call goes through.
    let ok = nodkey_gateway::ipc::Peer {
        expected_uid: Some(me),
        ..peer
    };
    assert_eq!(
        nodkey_gateway::ipc::read_grant(&ok, subj, WID, &["payments.get_order".into()]).await,
        Ok(FAKE_GRANT.to_owned())
    );
}
