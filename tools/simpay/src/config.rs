// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Configuration, fixture loading, and the bind-address policy.
//!
//! Everything here is parsed strictly: unknown fields are rejected and every
//! value is range-checked before the simulator starts.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Largest amount (minor units) a charge or refund may carry.
pub const MAX_AMOUNT_MINOR: u64 = 999_999_999_999;

/// Top-level configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address of the payment API listener.
    pub api_listen: SocketAddr,
    /// Address of the admin (fault-control) listener. Must differ from `api_listen`.
    pub admin_listen: SocketAddr,
    /// Optional bearer token required on the admin listener.
    #[serde(default)]
    pub admin_token: Option<String>,
    /// Seed for deterministic identifiers.
    pub seed: String,
    #[serde(default)]
    pub clock: ClockConfig,
    /// Idempotency-record retention in simulated seconds (Stripe: "at least 24 hours").
    #[serde(default = "default_retention")]
    pub idempotency_retention_s: u64,
    /// Maximum `Idempotency-Key` length (default 64, Adyen's tighter limit).
    #[serde(default = "default_key_len")]
    pub idempotency_key_max_len: usize,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub webhook_delivery: WebhookDeliveryConfig,
    /// Where `POST /admin/snapshot` and shutdown write the JSON snapshot.
    #[serde(default)]
    pub snapshot_path: Option<PathBuf>,
    /// Whether attacker-G (malicious provider) faults may be installed at start.
    #[serde(default)]
    pub malicious_mode: bool,
    /// Path of the fixture file (relative paths resolve against the config file's directory).
    #[serde(default)]
    pub fixture_path: Option<PathBuf>,
    /// Inline fixture; mutually exclusive with `fixture_path`.
    #[serde(default)]
    pub fixture: Option<Fixture>,
}

fn default_retention() -> u64 {
    86_400
}
fn default_key_len() -> usize {
    64
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClockMode {
    /// Time stands still until the admin API advances it. Fully deterministic.
    #[default]
    Manual,
    /// Wall-clock time plus an offset the admin API can advance.
    System,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockConfig {
    #[serde(default)]
    pub mode: ClockMode,
    /// Manual mode: the initial Unix time. System mode: ignored.
    #[serde(default = "default_clock_start")]
    pub start: u64,
}

impl Default for ClockConfig {
    fn default() -> Self {
        Self {
            mode: ClockMode::Manual,
            start: default_clock_start(),
        }
    }
}

fn default_clock_start() -> u64 {
    1_761_350_400 // 2025-10-25T00:00:00Z
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Requests allowed per key per window.
    pub max_requests: u64,
    /// Window length in simulated seconds.
    pub window_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookDeliveryConfig {
    #[serde(default = "d_attempts")]
    pub max_attempts: u32,
    #[serde(default = "d_backoff")]
    pub retry_base_ms: u64,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
}

fn d_attempts() -> u32 {
    5
}
fn d_backoff() -> u64 {
    200
}
fn d_timeout() -> u64 {
    2_000
}

impl Default for WebhookDeliveryConfig {
    fn default() -> Self {
        Self {
            max_attempts: d_attempts(),
            retry_base_ms: d_backoff(),
            timeout_ms: d_timeout(),
        }
    }
}

/// Seed data: accounts, keys, webhook endpoints, charges.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub accounts: Vec<AccountFixture>,
    #[serde(default)]
    pub charges: Vec<ChargeFixture>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountFixture {
    pub id: String,
    pub keys: Vec<KeyFixture>,
    #[serde(default)]
    pub webhook_endpoints: Vec<EndpointFixture>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    Charges,
    Refunds,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    None,
    Read,
    Write,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyFixture {
    /// `sk_sim_…` (unrestricted) or `rk_sim_…` (restricted).
    pub secret: String,
    /// Required for restricted keys, forbidden for secret keys. Missing resources mean `none`.
    #[serde(default)]
    pub permissions: Option<BTreeMap<Resource, Permission>>,
    /// Source-address access policy. Absent means "any source".
    #[serde(default)]
    pub allowed_cidrs: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointFixture {
    /// `http://host:port/path` only.
    pub url: String,
    /// Per-endpoint signing secret, `whsec_sim_…`.
    pub secret: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChargeStatus {
    #[default]
    Succeeded,
    Pending,
    Failed,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InitialRefundStatus {
    #[default]
    Succeeded,
    Pending,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChargeFixture {
    pub id: String,
    pub account: String,
    pub amount_minor: u64,
    /// ISO 4217, three lowercase letters.
    pub currency: String,
    #[serde(default)]
    pub status: ChargeStatus,
    #[serde(default)]
    pub refunded_minor: u64,
    /// Status a new refund on this charge starts in.
    #[serde(default)]
    pub refund_initial_status: InitialRefundStatus,
}

/// Identifier syntax shared with the Nodkey adapter: `^[a-z]{2,4}_[A-Za-z0-9]{8,64}$`.
pub fn valid_object_id(s: &str) -> bool {
    let Some((prefix, rest)) = s.split_once('_') else {
        return false;
    };
    (2..=4).contains(&prefix.len())
        && prefix.bytes().all(|b| b.is_ascii_lowercase())
        && (8..=64).contains(&rest.len())
        && rest.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn valid_currency(c: &str) -> bool {
    c.len() == 3 && c.bytes().all(|b| b.is_ascii_lowercase())
}

/// A parsed `addr/prefix` range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (a, p) = s
            .split_once('/')
            .ok_or_else(|| format!("CIDR {s:?} lacks '/prefix'"))?;
        let net: IpAddr = a.parse().map_err(|_| format!("CIDR {s:?}: bad address"))?;
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.len() > 3 {
            return Err(format!("CIDR {s:?}: bad prefix"));
        }
        let prefix: u8 = p.parse().map_err(|_| format!("CIDR {s:?}: bad prefix"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("CIDR {s:?}: prefix > {max}"));
        }
        Ok(Self { net, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                u32::from(n) & mask == u32::from(i) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                u128::from(n) & mask == u128::from(i) & mask
            }
            _ => false,
        }
    }
}

/// Maps IPv4-mapped IPv6 addresses to IPv4.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn is_non_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 shared address space
}

fn is_non_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    ip.is_loopback() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
}

/// Bind policy: loopback and private addresses are always allowed. The unspecified
/// address (`0.0.0.0`, `::`) is allowed only with the explicit container flag, because
/// inside a container that is the only way to be reachable from sibling containers.
/// Public unicast addresses are always refused.
pub fn check_bind(addr: SocketAddr, container_bind: bool) -> Result<(), String> {
    let ip = canonical_ip(addr.ip());
    if ip.is_unspecified() {
        if container_bind {
            return Ok(());
        }
        return Err(format!(
            "refusing to bind {addr}: the unspecified address listens on every interface. \
             simpay is a SIMULATOR and must not be reachable from public networks. \
             Pass --container-bind only inside an isolated container network."
        ));
    }
    let ok = match ip {
        IpAddr::V4(v4) => is_non_public_v4(v4),
        IpAddr::V6(v6) => is_non_public_v6(v6),
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "refusing to bind {addr}: public address. simpay is a SIMULATOR and must never be \
             exposed to public networks (there is no override for public addresses)"
        ))
    }
}

impl Config {
    pub fn from_json(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|e| format!("config: {e}"))
    }

    /// Reads the config file and resolves `fixture_path` relative to it.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("config {}: {e}", path.display()))?;
        let mut cfg = Self::from_json(&text)?;
        if let Some(fp) = cfg.fixture_path.take() {
            if cfg.fixture.is_some() {
                return Err("config: set either fixture_path or fixture, not both".into());
            }
            let full = if fp.is_relative() {
                path.parent().unwrap_or(Path::new(".")).join(fp)
            } else {
                fp
            };
            let ftext = std::fs::read_to_string(&full)
                .map_err(|e| format!("fixture {}: {e}", full.display()))?;
            let fx: Fixture = serde_json::from_str(&ftext).map_err(|e| format!("fixture: {e}"))?;
            cfg.fixture = Some(fx);
        }
        Ok(cfg)
    }

    /// Validates everything that cannot be expressed in the type system.
    pub fn validate(&self) -> Result<(), String> {
        if self.api_listen == self.admin_listen && self.api_listen.port() != 0 {
            return Err("api_listen and admin_listen must differ".into());
        }
        if self.seed.is_empty() {
            return Err("seed must not be empty".into());
        }
        if !(1..=255).contains(&self.idempotency_key_max_len) {
            return Err("idempotency_key_max_len must be 1..=255".into());
        }
        if self.idempotency_retention_s == 0 {
            return Err("idempotency_retention_s must be > 0".into());
        }
        if let Some(rl) = &self.rate_limit
            && (rl.max_requests == 0 || rl.window_s == 0)
        {
            return Err("rate_limit values must be > 0".into());
        }
        if self.webhook_delivery.max_attempts == 0 || self.webhook_delivery.max_attempts > 20 {
            return Err("webhook_delivery.max_attempts must be 1..=20".into());
        }
        if let Some(t) = &self.admin_token
            && t.len() < 16
        {
            return Err("admin_token must be at least 16 characters".into());
        }
        let fx = self
            .fixture
            .as_ref()
            .ok_or("config: a fixture (fixture or fixture_path) is required")?;
        fx.validate()
    }
}

impl Fixture {
    pub fn validate(&self) -> Result<(), String> {
        let mut accounts = std::collections::BTreeSet::new();
        let mut secrets = std::collections::BTreeSet::new();
        for a in &self.accounts {
            if !valid_object_id(&a.id) || !a.id.starts_with("acct_") {
                return Err(format!("account id {:?} invalid", a.id));
            }
            if !accounts.insert(a.id.clone()) {
                return Err(format!("duplicate account {}", a.id));
            }
            for k in &a.keys {
                validate_key(k)?;
                if !secrets.insert(k.secret.clone()) {
                    return Err("duplicate API key secret".into());
                }
            }
            for e in &a.webhook_endpoints {
                validate_endpoint(e)?;
            }
        }
        let mut charges = std::collections::BTreeSet::new();
        for c in &self.charges {
            if !valid_object_id(&c.id) || !c.id.starts_with("ch_") {
                return Err(format!("charge id {:?} invalid", c.id));
            }
            if !charges.insert(c.id.clone()) {
                return Err(format!("duplicate charge {}", c.id));
            }
            if !accounts.contains(&c.account) {
                return Err(format!("charge {} names unknown account", c.id));
            }
            if c.amount_minor == 0 || c.amount_minor > MAX_AMOUNT_MINOR {
                return Err(format!("charge {} amount out of range", c.id));
            }
            if c.refunded_minor > c.amount_minor {
                return Err(format!("charge {} refunded > amount", c.id));
            }
            if !valid_currency(&c.currency) {
                return Err(format!("charge {} currency invalid", c.id));
            }
        }
        Ok(())
    }
}

fn validate_key(k: &KeyFixture) -> Result<(), String> {
    let tail_ok = |t: &str| t.len() >= 16 && t.bytes().all(|b| b.is_ascii_alphanumeric());
    // The `_sim_` infix keeps simulator keys from ever looking like real provider keys.
    if let Some(t) = k.secret.strip_prefix("sk_sim_") {
        if !tail_ok(t) {
            return Err("secret key must be sk_sim_ + >=16 alphanumerics".into());
        }
        if k.permissions.is_some() {
            return Err("sk_sim_ keys are unrestricted; use rk_sim_ for permissions".into());
        }
    } else if let Some(t) = k.secret.strip_prefix("rk_sim_") {
        if !tail_ok(t) {
            return Err("restricted key must be rk_sim_ + >=16 alphanumerics".into());
        }
        if k.permissions.is_none() {
            return Err("rk_sim_ keys need a permissions map".into());
        }
    } else {
        return Err("API keys must start with sk_sim_ or rk_sim_".into());
    }
    if let Some(cidrs) = &k.allowed_cidrs {
        for c in cidrs {
            Cidr::parse(c)?;
        }
    }
    Ok(())
}

pub fn validate_endpoint(e: &EndpointFixture) -> Result<(), String> {
    crate::http::parse_http_url(&e.url)?;
    let Some(t) = e.secret.strip_prefix("whsec_sim_") else {
        return Err("webhook secrets must start with whsec_sim_".into());
    };
    if t.len() < 16 || !t.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("webhook secret must be whsec_sim_ + >=16 alphanumerics".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(valid_object_id("ch_abcdefgh"));
        assert!(!valid_object_id("ch_abc"));
        assert!(!valid_object_id("CH_abcdefgh"));
        assert!(!valid_object_id("ch_abcdefg/"));
        assert!(!valid_object_id("abcde_abcdefgh"));
    }

    #[test]
    fn cidr() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(c.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        assert!(
            Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("10.0.0.0").is_err());
        assert!(Cidr::parse("10.0.0.0/+8").is_err());
        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn bind_policy() {
        let ok = |s: &str| check_bind(s.parse().unwrap(), false).is_ok();
        assert!(ok("127.0.0.1:1"));
        assert!(ok("10.1.1.1:1"));
        assert!(ok("172.20.0.2:1"));
        assert!(ok("192.168.1.1:1"));
        assert!(ok("[::1]:1"));
        assert!(ok("[fd00::1]:1"));
        assert!(!ok("0.0.0.0:1"));
        assert!(!ok("[::]:1"));
        assert!(!ok("8.8.8.8:1"));
        assert!(!ok("[2001:db8::1]:1"));
        assert!(check_bind("0.0.0.0:1".parse().unwrap(), true).is_ok());
        assert!(check_bind("8.8.8.8:1".parse().unwrap(), true).is_err());
    }
}
