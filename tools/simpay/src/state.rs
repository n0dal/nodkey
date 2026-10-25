//! In-memory store. Every mutation happens under one mutex, so an operation and its
//! idempotency record commit atomically.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::{
    AccountFixture, ChargeFixture, ChargeStatus, Cidr, ClockMode, Config, EndpointFixture,
    InitialRefundStatus, KeyFixture, Permission, Resource,
};
use crate::faults::FaultPlan;

pub type Charge = ChargeFixture;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Clock {
    pub mode: ClockMode,
    /// Manual: the absolute Unix time. System: an offset added to wall-clock time.
    pub value: i64,
}

impl Clock {
    pub fn now(&self) -> u64 {
        match self.mode {
            ClockMode::Manual => self.value.max(0) as u64,
            ClockMode::System => {
                let wall = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                wall.saturating_add(self.value).max(0) as u64
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundStatus {
    Pending,
    Succeeded,
    Failed,
}

impl RefundStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refund {
    pub id: String,
    pub account: String,
    pub charge: String,
    pub amount_minor: u64,
    pub currency: String,
    pub status: RefundStatus,
    pub reference: Option<String>,
    pub reason: Option<String>,
    pub created: u64,
    /// Creation order, used for list ordering.
    pub seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdemState {
    InProgress,
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdemRecord {
    pub fingerprint: String,
    pub state: IdemState,
    pub status: u16,
    pub body: String,
    pub should_retry: bool,
    pub created: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub account: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub created: u64,
    pub object: Value,
}

impl Event {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "object": "event",
            "type": self.event_type,
            "created": self.created,
            "livemode": false,
            "simulator": true,
            "data": {"object": self.object},
        })
    }

    pub fn charge(&self) -> Option<&str> {
        self.object.get("charge").and_then(Value::as_str)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delivery {
    pub index: usize,
    pub event_id: String,
    pub event_type: String,
    pub url: String,
    /// normal | duplicate | replay | resend
    pub kind: String,
    pub attempt: u32,
    pub timestamp: u64,
    pub signature_header: String,
    /// `"200"` etc., or `"error: …"`.
    pub result: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scheduled {
    pub refund_id: String,
    pub due: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub keys: Vec<KeyFixture>,
    pub webhook_endpoints: Vec<EndpointFixture>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RateWindow {
    pub window: u64,
    pub count: u64,
}

pub const MAX_DELIVERY_LOG: usize = 10_000;
pub const MAX_EVENT_LOG: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    pub simulator: bool,
    pub seed: String,
    pub clock: Clock,
    pub id_counter: u64,
    pub refund_seq: u64,
    pub accounts: BTreeMap<String, Account>,
    pub charges: BTreeMap<String, Charge>,
    pub refunds: BTreeMap<String, Refund>,
    /// account → idempotency key → record (keys are scoped per account).
    pub idempotency: BTreeMap<String, BTreeMap<String, IdemRecord>>,
    pub events: Vec<Event>,
    pub deliveries: Vec<Delivery>,
    pub scheduled: Vec<Scheduled>,
    /// "account/key-index" → current window.
    pub rate: BTreeMap<String, RateWindow>,
    #[serde(skip)]
    pub faults: FaultPlan,
    #[serde(skip)]
    pub malicious_mode: bool,
}

/// An API error in Stripe's shape, plus a retry hint.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub etype: &'static str,
    pub code: &'static str,
    pub message: String,
    pub param: Option<&'static str>,
    pub should_retry: bool,
}

impl ApiError {
    pub fn new(status: u16, etype: &'static str, code: &'static str, message: &str) -> Self {
        Self {
            status,
            etype,
            code,
            message: message.to_string(),
            param: None,
            should_retry: false,
        }
    }
    pub fn param(mut self, p: &'static str) -> Self {
        self.param = Some(p);
        self
    }
    pub fn retry(mut self, r: bool) -> Self {
        self.should_retry = r;
        self
    }
    pub fn body(&self) -> Value {
        json!({
            "error": {
                "type": self.etype,
                "code": self.code,
                "message": self.message,
                "param": self.param,
                "should_retry": self.should_retry,
            },
            "simulator": true,
        })
    }
    pub fn invalid(code: &'static str, message: &str) -> Self {
        Self::new(400, "invalid_request_error", code, message)
    }
}

/// The authenticated caller.
#[derive(Debug, Clone)]
pub struct Caller {
    pub account: String,
    pub key_index: usize,
    pub permissions: Option<BTreeMap<Resource, Permission>>,
}

impl Caller {
    pub fn allows(&self, res: Resource, need: Permission) -> bool {
        match &self.permissions {
            None => true,
            Some(map) => {
                let have = map.get(&res).copied().unwrap_or(Permission::None);
                match need {
                    Permission::None => true,
                    Permission::Read => matches!(have, Permission::Read | Permission::Write),
                    Permission::Write => have == Permission::Write,
                }
            }
        }
    }
}

pub fn charge_object(c: &Charge) -> Value {
    json!({
        "id": c.id,
        "object": "charge",
        "amount": c.amount_minor,
        "amount_refunded": c.refunded_minor,
        "currency": c.currency,
        "refunded": c.refunded_minor == c.amount_minor,
        "status": match c.status {
            ChargeStatus::Succeeded => "succeeded",
            ChargeStatus::Pending => "pending",
            ChargeStatus::Failed => "failed",
        },
        "livemode": false,
        "simulator": true,
    })
}

pub fn refund_object(r: &Refund) -> Value {
    json!({
        "id": r.id,
        "object": "refund",
        "amount": r.amount_minor,
        "charge": r.charge,
        "currency": r.currency,
        "status": r.status.as_str(),
        "reference": r.reference,
        "reason": r.reason,
        "created": r.created,
        "livemode": false,
        "simulator": true,
    })
}

/// Validated parameters of `POST /v1/refunds`.
#[derive(Debug, Clone)]
pub struct RefundParams {
    pub charge: String,
    pub amount: Option<u64>,
    pub currency: Option<String>,
    pub reference: Option<String>,
    pub reason: Option<String>,
}

const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

impl Store {
    pub fn from_config(cfg: &Config) -> Self {
        let fx = cfg.fixture.clone().unwrap_or(crate::config::Fixture {
            accounts: vec![],
            charges: vec![],
        });
        let accounts = fx
            .accounts
            .into_iter()
            .map(|a: AccountFixture| {
                (
                    a.id.clone(),
                    Account {
                        id: a.id,
                        keys: a.keys,
                        webhook_endpoints: a.webhook_endpoints,
                    },
                )
            })
            .collect();
        let charges = fx.charges.into_iter().map(|c| (c.id.clone(), c)).collect();
        let value = match cfg.clock.mode {
            ClockMode::Manual => cfg.clock.start.min(i64::MAX as u64) as i64,
            ClockMode::System => 0,
        };
        Self {
            simulator: true,
            seed: cfg.seed.clone(),
            clock: Clock {
                mode: cfg.clock.mode,
                value,
            },
            id_counter: 0,
            refund_seq: 0,
            accounts,
            charges,
            refunds: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            events: vec![],
            deliveries: vec![],
            scheduled: vec![],
            rate: BTreeMap::new(),
            faults: FaultPlan::default(),
            malicious_mode: cfg.malicious_mode,
        }
    }

    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Deterministic identifier: `prefix_` + 24 base62 characters derived from
    /// SHA-256(seed, prefix, counter). Same seed and same operation order ⇒ same ids.
    pub fn next_id(&mut self, prefix: &str) -> String {
        self.id_counter += 1;
        let mut h = Sha256::new();
        h.update(self.seed.as_bytes());
        h.update([0]);
        h.update(prefix.as_bytes());
        h.update([0]);
        h.update(self.id_counter.to_be_bytes());
        let d = h.finalize();
        let mut s = String::with_capacity(prefix.len() + 25);
        s.push_str(prefix);
        s.push('_');
        for b in d.iter().take(24) {
            s.push(ALPHABET[(*b as usize) % 62] as char);
        }
        s
    }

    /// Authenticates a bearer secret from `peer`. Unknown key and disallowed source
    /// address both yield 401, as with a provider access policy.
    pub fn authenticate(&self, secret: &str, peer: IpAddr) -> Result<Caller, ApiError> {
        for acct in self.accounts.values() {
            for (i, k) in acct.keys.iter().enumerate() {
                if constant_time_eq(k.secret.as_bytes(), secret.as_bytes()) {
                    if let Some(cidrs) = &k.allowed_cidrs {
                        let allowed = cidrs
                            .iter()
                            .filter_map(|c| Cidr::parse(c).ok())
                            .any(|c| c.contains(peer));
                        if !allowed {
                            return Err(ApiError::new(
                                401,
                                "authentication_error",
                                "source_address_not_allowed",
                                "This API key is not allowed from this source address.",
                            ));
                        }
                    }
                    return Ok(Caller {
                        account: acct.id.clone(),
                        key_index: i,
                        permissions: k.permissions.clone(),
                    });
                }
            }
        }
        Err(ApiError::new(
            401,
            "authentication_error",
            "invalid_api_key",
            "Invalid API key provided.",
        ))
    }

    /// Fixed-window per-key rate limit on the simulated clock.
    pub fn rate_check(&mut self, caller: &Caller, max: u64, window_s: u64) -> bool {
        let w = self.now() / window_s;
        let k = format!("{}/{}", caller.account, caller.key_index);
        let e = self.rate.entry(k).or_insert(RateWindow {
            window: w,
            count: 0,
        });
        if e.window != w {
            *e = RateWindow {
                window: w,
                count: 0,
            };
        }
        if e.count >= max {
            return false;
        }
        e.count += 1;
        true
    }

    pub fn prune_idempotency(&mut self, retention_s: u64) {
        let now = self.now();
        for recs in self.idempotency.values_mut() {
            recs.retain(|_, r| r.state == IdemState::InProgress || r.created + retention_s > now);
        }
    }

    pub fn emit(&mut self, account: &str, event_type: &str, object: Value) -> Event {
        let ev = Event {
            id: self.next_id("evt"),
            account: account.to_string(),
            event_type: event_type.to_string(),
            created: self.now(),
            object,
        };
        if self.events.len() >= MAX_EVENT_LOG {
            self.events.remove(0);
        }
        self.events.push(ev.clone());
        ev
    }

    /// Executes a refund. Business-rule failures are returned as errors; on success the
    /// refund is stored, the charge's refunded amount grows, and `refund.created` is emitted.
    pub fn create_refund(
        &mut self,
        account: &str,
        p: &RefundParams,
    ) -> Result<(Refund, Vec<Event>), ApiError> {
        let Some(charge) = self.charges.get(&p.charge).filter(|c| c.account == account) else {
            return Err(ApiError::invalid(
                "resource_missing",
                &format!("No such charge: '{}'", p.charge),
            )
            .param("charge")
            .with_status(404));
        };
        if charge.status != ChargeStatus::Succeeded {
            return Err(ApiError::invalid(
                "charge_not_refundable",
                "This charge cannot be refunded.",
            )
            .param("charge"));
        }
        if let Some(cur) = &p.currency
            && cur != &charge.currency
        {
            return Err(ApiError::invalid(
                "currency_mismatch",
                "The refund currency must match the charge currency.",
            )
            .param("currency"));
        }
        let remaining = charge.amount_minor - charge.refunded_minor;
        if remaining == 0 {
            return Err(ApiError::invalid(
                "charge_already_refunded",
                "This charge has already been refunded.",
            )
            .param("charge"));
        }
        let amount = p.amount.unwrap_or(remaining);
        if amount > remaining {
            return Err(ApiError::invalid(
                "amount_too_large",
                "Refund amount is greater than the remaining unrefunded amount.",
            )
            .param("amount"));
        }
        let status = match charge.refund_initial_status {
            InitialRefundStatus::Succeeded => RefundStatus::Succeeded,
            InitialRefundStatus::Pending => RefundStatus::Pending,
        };
        let currency = charge.currency.clone();
        let id = self.next_id("re");
        self.refund_seq += 1;
        let refund = Refund {
            id: id.clone(),
            account: account.to_string(),
            charge: p.charge.clone(),
            amount_minor: amount,
            currency,
            status,
            reference: p.reference.clone(),
            reason: p.reason.clone(),
            created: self.now(),
            seq: self.refund_seq,
        };
        if let Some(c) = self.charges.get_mut(&p.charge) {
            c.refunded_minor += amount;
        }
        self.refunds.insert(id, refund.clone());
        let ev = self.emit(account, "refund.created", refund_object(&refund));
        Ok((refund, vec![ev]))
    }

    /// Settlement transition: pending → succeeded | failed, succeeded → failed.
    /// A failed refund returns its amount to the charge, as on Stripe.
    pub fn set_refund_status(&mut self, id: &str, new: RefundStatus) -> Result<Vec<Event>, String> {
        let r = self.refunds.get_mut(id).ok_or("no such refund")?;
        let ok = matches!(
            (r.status, new),
            (RefundStatus::Pending, RefundStatus::Succeeded)
                | (RefundStatus::Pending, RefundStatus::Failed)
                | (RefundStatus::Succeeded, RefundStatus::Failed)
        );
        if !ok {
            return Err(format!(
                "transition {} -> {} not allowed",
                r.status.as_str(),
                new.as_str()
            ));
        }
        r.status = new;
        let r = r.clone();
        if new == RefundStatus::Failed
            && let Some(c) = self.charges.get_mut(&r.charge)
        {
            c.refunded_minor = c.refunded_minor.saturating_sub(r.amount_minor);
        }
        let obj = refund_object(&r);
        let mut evs = vec![self.emit(&r.account, "refund.updated", obj.clone())];
        if new == RefundStatus::Failed {
            evs.push(self.emit(&r.account, "refund.failed", obj));
        }
        Ok(evs)
    }

    /// Applies scheduled transitions whose due time has passed.
    pub fn process_due(&mut self) -> Vec<Event> {
        let now = self.now();
        let (due, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.scheduled)
            .into_iter()
            .partition(|s| s.due <= now);
        self.scheduled = rest;
        let mut evs = vec![];
        for s in due {
            if let Ok(mut e) = self.set_refund_status(&s.refund_id, RefundStatus::Failed) {
                evs.append(&mut e);
            }
        }
        evs
    }

    pub fn push_delivery(&mut self, mut d: Delivery) -> usize {
        if self.deliveries.len() >= MAX_DELIVERY_LOG {
            self.deliveries.remove(0);
        }
        d.index = self
            .deliveries
            .last()
            .map(|l| l.index + 1)
            .unwrap_or_default();
        let i = d.index;
        self.deliveries.push(d);
        i
    }

    /// Writes the store atomically (temp file + rename) with owner-only permissions.
    pub fn write_snapshot(&self, path: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp).map_err(|e| format!("snapshot: {e}"))?;
            f.write_all(&bytes).map_err(|e| format!("snapshot: {e}"))?;
            f.sync_all().map_err(|e| format!("snapshot: {e}"))?;
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("snapshot: {e}"))
    }

    /// Restores a snapshot. In-progress idempotency records are dropped: their request
    /// never committed (commit and record finalisation are atomic).
    pub fn read_snapshot(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("snapshot: {e}"))?;
        let mut s: Store = serde_json::from_str(&text).map_err(|e| format!("snapshot: {e}"))?;
        if !s.simulator {
            return Err("snapshot is not a simpay snapshot".into());
        }
        for recs in s.idempotency.values_mut() {
            recs.retain(|_, r| r.state == IdemState::Done);
        }
        Ok(s)
    }
}

impl ApiError {
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
