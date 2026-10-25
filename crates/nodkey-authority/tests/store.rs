//! Issuance store: durability, exactly-once and corruption handling across reopen (restart).

mod common;

use std::io::Write;

use common::tmpdir;
use nodkey_authority::digest::PendingId;
use nodkey_authority::store::{Issuance, Status, Store, StoreError};

fn row(n: u8) -> Issuance {
    Issuance {
        jti: PendingId([n; 16]),
        digest: [n; 32],
        ten: "acme".into(),
        sub: "user:u-17".into(),
        wid: "spiffe://w".into(),
        op: "payments.refund".into(),
        signed_at: 100,
        exp: 130,
        grant: vec![0xd2, n, 1, 2, 3],
        status: Status::Signed,
    }
}

#[test]
fn rows_and_statuses_survive_reopen() {
    let d = tmpdir("st-reopen");
    let p = d.join("issuance.log");
    {
        let mut s = Store::open(&p).unwrap();
        s.insert(row(1)).unwrap();
        s.insert(row(2)).unwrap();
        s.set_status(&PendingId([1; 16]), Status::Accepted).unwrap();
    } // "crash": dropped without any shutdown step
    let s = Store::open(&p).unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s.get(&PendingId([1; 16])).unwrap().status, Status::Accepted);
    let r2 = s.get(&PendingId([2; 16])).unwrap();
    assert_eq!(r2.status, Status::Signed);
    assert_eq!(*r2, row(2));
    assert_eq!(s.unfinished(), vec![row(2)]);
}

#[test]
fn at_most_one_row_per_jti_across_restarts() {
    let d = tmpdir("st-once");
    let p = d.join("issuance.log");
    {
        let mut s = Store::open(&p).unwrap();
        s.insert(row(1)).unwrap();
        let mut other = row(1);
        other.digest = [9; 32];
        other.grant = vec![0xd2, 9];
        assert_eq!(s.insert(other), Err(StoreError::Exists));
    }
    for _ in 0..3 {
        let mut s = Store::open(&p).unwrap();
        let mut other = row(1);
        other.grant = vec![0xd2, 8];
        assert_eq!(s.insert(other), Err(StoreError::Exists));
        assert_eq!(s.get(&PendingId([1; 16])).unwrap().grant, row(1).grant);
    }
    let text = std::fs::read_to_string(&p).unwrap();
    assert_eq!(text.lines().count(), 1);
}

#[test]
fn final_status_is_final() {
    let d = tmpdir("st-final");
    let p = d.join("issuance.log");
    let mut s = Store::open(&p).unwrap();
    s.insert(row(1)).unwrap();
    s.set_status(&PendingId([1; 16]), Status::Expired).unwrap();
    assert_eq!(
        s.set_status(&PendingId([1; 16]), Status::Accepted),
        Err(StoreError::AlreadyFinal)
    );
    assert_eq!(
        s.set_status(&PendingId([7; 16]), Status::Accepted),
        Err(StoreError::Unknown)
    );
}

#[test]
fn torn_tail_is_truncated_and_earlier_rows_kept() {
    let d = tmpdir("st-torn");
    let p = d.join("issuance.log");
    {
        let mut s = Store::open(&p).unwrap();
        s.insert(row(1)).unwrap();
    }
    let good = std::fs::read(&p).unwrap();
    // Simulate a crash in the middle of appending the second record.
    let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
    f.write_all(b"0123abcd {\"k\":\"issue\",\"jti\":\"AgICAgICAg")
        .unwrap();
    drop(f);
    let mut s = Store::open(&p).unwrap();
    assert_eq!(s.len(), 1);
    assert_eq!(std::fs::read(&p).unwrap(), good);
    // The torn row was never acknowledged; inserting it now works.
    s.insert(row(2)).unwrap();
    drop(s);
    assert_eq!(Store::open(&p).unwrap().len(), 2);
}

#[test]
fn corruption_refuses_to_open() {
    let d = tmpdir("st-corrupt");
    let base = d.join("base.log");
    {
        let mut s = Store::open(&base).unwrap();
        s.insert(row(1)).unwrap();
        s.insert(row(2)).unwrap();
    }
    let good = std::fs::read_to_string(&base).unwrap();
    let lines: Vec<&str> = good.lines().collect();
    let bad_cases = [
        // flipped byte in a complete line (checksum)
        good.replacen("acme", "acmf", 1),
        // duplicate jti
        format!("{}\n{}\n", lines[0], lines[0]),
        // empty line in the middle
        format!("{}\n\n{}\n", lines[0], lines[1]),
        // status for an unknown jti
        {
            let body = r#"{"jti":"BwcHBwcHBwcHBwcHBwcHBw","k":"status","status":"accepted"}"#;
            let sum = nodkey_authority::digest::hex(&sha(body));
            format!("{good}{sum} {body}\n")
        },
    ];
    for (i, content) in bad_cases.iter().enumerate() {
        let p = d.join(format!("bad{i}.log"));
        std::fs::write(&p, content).unwrap();
        assert!(
            matches!(Store::open(&p), Err(StoreError::Corrupt(_))),
            "case {i}"
        );
    }
}

fn sha(s: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(s.as_bytes()).into()
}

#[test]
fn second_process_cannot_open_the_same_store() {
    let d = tmpdir("st-lock");
    let p = d.join("issuance.log");
    let _s = Store::open(&p).unwrap();
    assert!(matches!(Store::open(&p), Err(StoreError::Corrupt(_))));
}
