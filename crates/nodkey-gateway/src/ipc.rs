// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Clients for socket G (gateway → broker) and socket I (gateway → authority).
//!
//! Framing (spec §1.2): one strict JSON object per line, ≤ 8 KiB, one request per connection here.
//! Envelope: the §2.2 v2 envelope. On socket I this is exactly the format defined by
//! `crates/nodkey-authority` (its README "Wire formats", spec gap AU-1):
//! `{"v":2,"id":…,"op":…,"args":{…}}` → `{"v":2,"id":…,"correlation_id":…,"ok":…,"result"|"error":…}`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::digest::PendingRecord;
use crate::json::de_uint;
use crate::util::{b64url, random_bytes};

pub const MAX_LINE: usize = 8 * 1024;
/// grant-v1 §2: maximum transport text length.
pub const MAX_GRANT_TEXT: usize = 2731;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    /// The peer answered `ok:false` (code is kept for the audit log only).
    Refused(String),
    /// Connection, timeout, framing, peer uid or parse failure.
    Transport(&'static str),
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub path: PathBuf,
    pub expected_uid: Option<u32>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subject<'a> {
    pub ten: &'a str,
    pub sub: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    v: u8,
    id: String,
    #[allow(dead_code)]
    correlation_id: String,
    ok: bool,
    #[serde(default)]
    result: Option<Box<serde_json::value::RawValue>>,
    #[serde(default)]
    error: Option<ErrorBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorBody {
    code: String,
    #[allow(dead_code)]
    message: String,
}

async fn call_raw(peer: &Peer, op: &str, args: Value) -> Result<String, IpcError> {
    let id = b64url(&random_bytes::<12>().ok_or(IpcError::Transport("rng"))?);
    let mut line = serde_json::to_vec(&json!({"v": 2, "id": id, "op": op, "args": args}))
        .map_err(|_| IpcError::Transport("encode"))?;
    if line.len() >= MAX_LINE {
        return Err(IpcError::Transport("request too large"));
    }
    line.push(b'\n');
    let fut = async {
        let mut s = connect(&peer.path, peer.expected_uid).await?;
        s.write_all(&line)
            .await
            .map_err(|_| IpcError::Transport("write"))?;
        let mut r = BufReader::new(s).take((MAX_LINE + 1) as u64);
        let mut buf = Vec::new();
        r.read_until(b'\n', &mut buf)
            .await
            .map_err(|_| IpcError::Transport("read"))?;
        if buf.last() != Some(&b'\n') || buf.len() > MAX_LINE {
            return Err(IpcError::Transport("framing"));
        }
        buf.pop();
        String::from_utf8(buf).map_err(|_| IpcError::Transport("utf8"))
    };
    let text = tokio::time::timeout(peer.timeout, fut)
        .await
        .map_err(|_| IpcError::Transport("timeout"))??;
    let env: Envelope = serde_json::from_str(&text).map_err(|_| IpcError::Transport("envelope"))?;
    if env.v != 2 || env.id != id {
        return Err(IpcError::Transport("envelope id/version"));
    }
    match (env.ok, env.result, env.error) {
        (true, Some(r), None) => Ok(r.get().to_owned()),
        (false, None, Some(e)) => Err(IpcError::Refused(e.code)),
        _ => Err(IpcError::Transport("envelope shape")),
    }
}

async fn connect(path: &Path, expected_uid: Option<u32>) -> Result<UnixStream, IpcError> {
    let s = UnixStream::connect(path)
        .await
        .map_err(|_| IpcError::Transport("connect"))?;
    if let Some(uid) = expected_uid {
        let cred = s
            .peer_cred()
            .map_err(|_| IpcError::Transport("peer_cred"))?;
        if cred.uid() != uid {
            return Err(IpcError::Transport("peer uid mismatch"));
        }
    }
    Ok(s)
}

async fn call<T: DeserializeOwned>(peer: &Peer, op: &str, args: Value) -> Result<T, IpcError> {
    let raw = call_raw(peer, op, args).await?;
    serde_json::from_str(&raw).map_err(|_| IpcError::Transport("result schema"))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Related {
    pub pending_id: String,
    pub state: String,
    #[serde(deserialize_with = "de_uint")]
    pub created_at: u64,
    #[serde(default)]
    pub amount_minor: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    #[serde(deserialize_with = "de_uint")]
    pub pending_from_workload_for_subject: u64,
    pub recent_identical: Vec<Related>,
    pub other_open_on_resource: Vec<Related>,
    pub workload_display_name: String,
    pub approver_source: String,
}

/// `pending.render` result (spec §4.1).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Render {
    pub record: PendingRecord,
    pub digest: String,
    pub state: String,
    pub facts: Vec<Fact>,
    pub context: Context,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantResult {
    grant: String,
}

pub async fn render(broker: &Peer, pending_id: &str, s: Subject<'_>) -> Result<Render, IpcError> {
    call(
        broker,
        "pending.render",
        json!({"pending_id": pending_id, "subject": {"ten": s.ten, "sub": s.sub}}),
    )
    .await
}

pub async fn deny(
    broker: &Peer,
    pending_id: &str,
    digest_hex: &str,
    s: Subject<'_>,
) -> Result<(), IpcError> {
    call::<Empty>(
        broker,
        "pending.deny",
        json!({"pending_id": pending_id, "digest": digest_hex, "subject": {"ten": s.ten, "sub": s.sub}}),
    )
    .await
    .map(|_| ())
}

pub async fn approve(
    authority: &Peer,
    pending_id: &str,
    digest_hex: &str,
    s: Subject<'_>,
) -> Result<(), IpcError> {
    call::<Empty>(
        authority,
        "approve",
        json!({"pending_id": pending_id, "digest_shown": digest_hex, "subject": {"ten": s.ten, "sub": s.sub}}),
    )
    .await
    .map(|_| ())
}

/// `pending.list` item (effect-protocol-v2 §12.3).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingItem {
    pub pending_id: String,
    pub op: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingList {
    pending: Vec<PendingItem>,
}

/// Mandate terms as listed by the broker (`mandate.list`, §12.3; member names: spec gap MD-6).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MandateTerms {
    pub customer_sub: String,
    pub customer_email: String,
    pub currency: String,
    pub refund_max_count: u64,
    pub refund_max_per_call_minor: u64,
    pub refund_max_total_minor: u64,
    pub message_max_count: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MandateCounters {
    pub refund_count: u64,
    pub refund_total_minor: u64,
    pub message_count: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MandateItem {
    pub mid: String,
    pub workload_display_name: String,
    pub terms: MandateTerms,
    pub counters: MandateCounters,
    pub nbf: u64,
    pub exp: u64,
    pub state: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MandateList {
    mandates: Vec<MandateItem>,
}

/// Bounds and grammar of broker-supplied list text (escaped anyway).
fn printable(s: &str, max: usize) -> bool {
    s.len() <= max && s.bytes().all(|c| (0x20..=0x7e).contains(&c))
}

/// `pending.list{subject}` on socket G.
pub async fn pending_list(broker: &Peer, s: Subject<'_>) -> Result<Vec<PendingItem>, IpcError> {
    let r: PendingList = call(
        broker,
        "pending.list",
        json!({"subject": {"ten": s.ten, "sub": s.sub}}),
    )
    .await?;
    let ok = r.pending.len() <= 64
        && r.pending.iter().all(|p| {
            crate::util::decode_pending_id(&p.pending_id).is_some() && printable(&p.op, 64)
        });
    if !ok {
        return Err(IpcError::Transport("pending.list schema"));
    }
    Ok(r.pending)
}

/// `mandate.list{subject}` on socket G.
pub async fn mandate_list(broker: &Peer, s: Subject<'_>) -> Result<Vec<MandateItem>, IpcError> {
    let r: MandateList = call(
        broker,
        "mandate.list",
        json!({"subject": {"ten": s.ten, "sub": s.sub}}),
    )
    .await?;
    let ok = r.mandates.len() <= 64
        && r.mandates.iter().all(|m| {
            crate::util::decode_pending_id(&m.mid).is_some()
                && printable(&m.workload_display_name, 128)
                && printable(&m.terms.customer_sub, 64)
                && printable(&m.terms.customer_email, 256)
                && m.terms.currency.len() == 3
                && m.terms.currency.bytes().all(|c| c.is_ascii_uppercase())
                && matches!(m.state.as_str(), "active" | "revoked" | "expired")
        });
    if !ok {
        return Err(IpcError::Transport("mandate.list schema"));
    }
    Ok(r.mandates)
}

/// `mandate.revoke{mid, subject}`: the same message on socket G (broker) and socket I (authority).
pub async fn mandate_revoke(peer: &Peer, mid: &str, s: Subject<'_>) -> Result<(), IpcError> {
    call::<Empty>(
        peer,
        "mandate.revoke",
        json!({"mid": mid, "subject": {"ten": s.ten, "sub": s.sub}}),
    )
    .await
    .map(|_| ())
}

/// Requests a read grant; returns its transport text (canonical base64url, ≤ 2731 chars).
pub async fn read_grant(
    authority: &Peer,
    s: Subject<'_>,
    wid: &str,
    rop: &[String],
) -> Result<String, IpcError> {
    let r: GrantResult = call(
        authority,
        "read_grant",
        json!({"subject": {"ten": s.ten, "sub": s.sub}, "wid": wid, "rop": rop}),
    )
    .await?;
    if r.grant.is_empty()
        || r.grant.len() > MAX_GRANT_TEXT
        || crate::util::b64url_decode_canonical(&r.grant).is_none()
    {
        return Err(IpcError::Transport("grant text"));
    }
    Ok(r.grant)
}
