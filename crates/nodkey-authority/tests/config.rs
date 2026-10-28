//! Configuration loading and the §1.2 start-up refusals (T42).

mod common;

use std::path::Path;

use common::{OPERATIONS, WORKLOADS, tmpdir};
use nodkey_authority::config::{Config, Workloads, startup_checks};
use nodkey_grant::Operations;
use serde_json::{Value, json};

type Patch = Box<dyn FnOnce(&mut Value)>;

fn my_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(env!("CARGO_MANIFEST_DIR")).unwrap().uid()
}

fn load(p: &Path) -> Result<Config, String> {
    Config::load(p, my_uid())
}

fn write_config(dir: &Path, patch: impl FnOnce(&mut Value)) -> std::path::PathBuf {
    std::fs::write(dir.join("operations.json"), OPERATIONS).unwrap();
    std::fs::write(dir.join("workloads.json"), WORKLOADS).unwrap();
    let mut c = json!({
        "format": "nodkey.authority-config.v1",
        "issuer": "nodkey.authority.test",
        "broker_id": "nodkey.broker.payments-test",
        "signing_key_path": dir.join("k"),
        "signing_kid": "00112233445566778899aabbccddeeff",
        "store_path": dir.join("issuance.log"),
        "gateway_socket": "/run/nodkey/gw-authority/authority.sock",
        "broker_socket": "/run/nodkey/au-broker/broker.sock",
        "authority_uid": 2001, "gateway_uid": 2002, "broker_uid": 2003,
        "workload_uids": [3001, 3002],
        "operations_path": dir.join("operations.json"),
        "workloads_path": dir.join("workloads.json"),
        "manifest_path": dir.join("manifest.json"),
        "ledger_currency": "EUR",
        "grant_ttl_secs": 30, "skew_secs": 5,
        "approve_reply_timeout_ms": 5000, "broker_call_timeout_ms": 2000
    });
    patch(&mut c);
    let p = dir.join("config.json");
    std::fs::write(&p, c.to_string()).unwrap();
    p
}

fn manifest(dir: &Path, paths: &[&str]) {
    let m = json!({"format":"nodkey.deployment-manifest.v1","workload_mounts":[
        {"wid":"spiffe://nodkey.test/workload/shop","host_paths": paths},
        {"wid":"spiffe://nodkey.test/workload/agent","host_paths": []},
        {"wid":"spiffe://nodkey.test/workload/support","host_paths": []}]});
    std::fs::write(dir.join("manifest.json"), m.to_string()).unwrap();
}

#[test]
fn valid_config_passes_startup_checks() {
    let d = tmpdir("cfg-ok");
    manifest(&d, &["/run/nodkey/wl/shop", "/srv/app"]);
    let cfg = load(&write_config(&d, |_| {})).unwrap();
    startup_checks(&cfg, 2001, false).unwrap();
    // Not running as the configured authority uid.
    assert!(startup_checks(&cfg, 2002, false).is_err());
}

#[test]
fn t42_refusals() {
    let d = tmpdir("cfg-refuse");
    manifest(&d, &["/srv/app"]);
    let cases: Vec<(&str, Patch)> = vec![
        (
            "gateway shares authority uid",
            Box::new(|c| c["gateway_uid"] = json!(2001)),
        ),
        (
            "broker shares gateway uid",
            Box::new(|c| c["broker_uid"] = json!(2002)),
        ),
        (
            "authority uid is a workload uid",
            Box::new(|c| c["workload_uids"] = json!([2001])),
        ),
        (
            "gateway uid is a workload uid",
            Box::new(|c| c["workload_uids"] = json!([2002])),
        ),
        (
            "shared socket dir",
            Box::new(|c| c["broker_socket"] = json!("/run/nodkey/gw-authority/broker.sock")),
        ),
        (
            "nested socket dir",
            Box::new(|c| c["broker_socket"] = json!("/run/nodkey/gw-authority/x/broker.sock")),
        ),
    ];
    for (name, patch) in cases {
        let cfg = load(&write_config(&d, patch)).unwrap();
        assert!(startup_checks(&cfg, 2001, true).is_err(), "{name}");
    }
}

#[test]
fn t42_manifest_rules() {
    let d = tmpdir("cfg-manifest");
    let cfg = load(&write_config(&d, |_| {})).unwrap();
    // Manifest absent: refuse unless the explicit operator flag is set.
    assert!(startup_checks(&cfg, 2001, false).is_err());
    assert!(startup_checks(&cfg, 2001, true).is_ok());
    // A control directory (or a parent of one) mounted into a workload.
    for bad in [
        "/run/nodkey/gw-authority",
        "/run/nodkey",
        "/run/nodkey/au-broker/../au-broker",
        "/run/nodkey/au-broker/sub",
    ] {
        manifest(&d, &[bad]);
        let cfg = load(&d.join("config.json")).unwrap();
        assert!(startup_checks(&cfg, 2001, true).is_err(), "{bad}");
    }
    manifest(&d, &["relative/path"]);
    let cfg = load(&d.join("config.json")).unwrap();
    assert!(startup_checks(&cfg, 2001, false).is_err());
}

#[test]
fn config_parsing_is_strict() {
    let d = tmpdir("cfg-strict");
    let bad: Vec<Patch> = vec![
        Box::new(|c| c["extra"] = json!(1)),
        Box::new(|c| c["grant_ttl_secs"] = json!(31)),
        Box::new(|c| c["skew_secs"] = json!(6)),
        Box::new(|c| c["issuer"] = json!("has space")),
        Box::new(|c| c["signing_kid"] = json!("ABCD")),
        Box::new(|c| c["store_path"] = json!("relative.log")),
        Box::new(|c| c["manifest_path"] = json!("relative/manifest.json")),
        Box::new(|c| c["ledger_currency"] = json!("XXX")),
        Box::new(|c| {
            c.as_object_mut().unwrap().remove("manifest_path");
        }),
        Box::new(|c| {
            c.as_object_mut().unwrap().remove("ledger_currency");
        }),
        Box::new(|c| {
            c.as_object_mut().unwrap().remove("broker_uid");
        }),
    ];
    for (i, patch) in bad.into_iter().enumerate() {
        assert!(load(&write_config(&d, patch)).is_err(), "case {i}");
    }
    // Duplicate member.
    let p = write_config(&d, |_| {});
    let text = std::fs::read_to_string(&p).unwrap();
    std::fs::write(&p, text.replacen("{", r#"{"issuer":"x","#, 1)).unwrap();
    assert!(load(&p).is_err());
}

#[test]
fn workload_registration_refusals() {
    let ops = Operations::load(OPERATIONS).unwrap();
    let wl = |w: Value| {
        Workloads::load(
            json!({"format":"nodkey.workloads.v1","workloads":[w]})
                .to_string()
                .as_bytes(),
            &ops,
        )
    };
    let base = json!({"wid":"w1","tenants":["acme"],"approver_source":"named",
                      "write_ops":["payments.refund"],"read_ops":["payments.get_order"]});
    assert!(wl(base.clone()).is_ok());
    let mut cases = vec![];
    // §2.4: named workloads cannot use destination operations.
    let mut c = base.clone();
    c["write_ops"] = json!(["ledger.transfer"]);
    cases.push(c);
    // enrolled approver outside the registered tenants
    let mut c = base.clone();
    c["approver_source"] = json!({"enrolled":{"ten":"globex","sub":"u"}});
    cases.push(c);
    // read op listed as write, write op listed as read, undeclared op
    let mut c = base.clone();
    c["write_ops"] = json!(["payments.get_order"]);
    cases.push(c);
    let mut c = base.clone();
    c["read_ops"] = json!(["payments.refund"]);
    cases.push(c);
    let mut c = base.clone();
    c["write_ops"] = json!(["nope"]);
    cases.push(c);
    let mut c = base.clone();
    c["tenants"] = json!([]);
    cases.push(c);
    let mut c = base.clone();
    c["unknown"] = json!(1);
    cases.push(c);
    for c in cases {
        assert!(wl(c.clone()).is_err(), "{c}");
    }
}

#[test]
fn au_r_05_manifest_must_cover_every_workload_and_every_authority_path() {
    let d = tmpdir("cfg-manifest2");
    write_config(&d, |_| {});
    // A registered workload missing from the manifest.
    let m = json!({"format":"nodkey.deployment-manifest.v1","workload_mounts":[
        {"wid":"spiffe://nodkey.test/workload/shop","host_paths": []}]});
    std::fs::write(d.join("manifest.json"), m.to_string()).unwrap();
    let cfg = load(&d.join("config.json")).unwrap();
    assert!(startup_checks(&cfg, 2001, false).is_err());
    // The key/store/config directory mounted into a workload.
    manifest(&d, &[d.to_str().unwrap()]);
    let cfg = load(&d.join("config.json")).unwrap();
    let e = startup_checks(&cfg, 2001, false).unwrap_err();
    assert!(e.contains("mounted into workload"), "{e}");
}

#[test]
fn au_r_02_admin_file_ownership_and_mode() {
    use std::os::unix::fs::PermissionsExt;
    let set =
        |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    for target in ["config.json", "operations.json", "workloads.json"] {
        let d = tmpdir("cfg-perm");
        let p = write_config(&d, |_| {});
        assert!(load(&p).is_ok());
        let f = d.join(target);
        for mode in [0o664, 0o646, 0o666] {
            set(&f, mode);
            assert!(load(&p).is_err(), "{target} {mode:o}");
        }
        set(&f, 0o644);
        // Wrong owner: the check is against the authority uid (root is also accepted).
        assert!(Config::load(&p, my_uid() + 1).is_err());
        // A symlinked file.
        let real = d.join("real.json");
        std::fs::rename(&f, &real).unwrap();
        std::os::unix::fs::symlink(&real, &f).unwrap();
        assert!(load(&p).is_err(), "{target} symlink");
    }
    // A group/other-writable parent directory.
    let d = tmpdir("cfg-perm-dir");
    let p = write_config(&d, |_| {});
    set(&d, 0o777);
    assert!(load(&p).is_err());
    set(&d, 0o755);
    assert!(load(&p).is_ok());
}
