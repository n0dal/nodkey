//! Without the `test-login` feature the binary has no login at all (R3B-11), and a configuration
//! that asks for the test login is refused at start-up.
#![cfg(not(feature = "test-login"))]

mod common;
use common::*;
use nodkey_gateway::config::{TestLoginConfig, TestUser, check};

// Compile-time check: this build has no test login.
const _: () = assert!(!nodkey_gateway::TEST_LOGIN_COMPILED);

#[tokio::test]
async fn login_absent() {
    let h = start().await;
    let r = get(h.addr, AUTH, "/login", &[]).await;
    assert_eq!(r.status, 503);
    assert!(
        r.text()
            .contains("compiled without the <code>test-login</code> feature")
    );
    assert!(!r.text().contains("TEST LOGIN"));
    assert!(r.cookie("__Host-nodkey_preauth").is_none());
    let r = post_form(h.addr, AUTH, "/login", &NAV_SAME_ORIGIN, "user=0&csrf=x").await;
    assert_eq!(r.status, 404);
    assert_eq!(r.text(), "This request is not available.");
    assert!(r.cookie("__Host-nodkey_session").is_none());
}

#[test]
fn config_with_test_login_refused() {
    let dir = tmpdir();
    let mut cfg = base_config(&dir, "127.0.0.1:1".parse().unwrap());
    cfg.test_login = Some(TestLoginConfig {
        enabled: true,
        users: vec![TestUser {
            ten: "acme".into(),
            sub: "user:u-17".into(),
            label: "Alice".into(),
        }],
    });
    let err = check(cfg).unwrap_err();
    assert!(err.contains("without the `test-login` feature"), "{err}");
    let _ = std::fs::remove_dir_all(dir);
}
