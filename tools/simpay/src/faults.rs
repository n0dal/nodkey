//! Deterministic fault plan.
//!
//! A plan is an ordered list of rules. Each fault kind belongs to one *stage* of request
//! handling. When a request reaches a stage, the rules of that stage are evaluated in
//! order; a rule whose `match` conditions hold counts one match, and fires if its match
//! count has reached `nth` and it has fired fewer than `times` times (`times = 0` means
//! unlimited). The first rule that fires ends evaluation for that stage. Counting happens
//! under the store lock, so the outcome depends only on the order of arrivals.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    CreateRefund,
    GetRefund,
    ListRefunds,
    GetCharge,
    GetIdempotencyKey,
    Webhook,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// After authentication and permission checks, before idempotency handling.
    Pre,
    /// Only for `create_refund` requests that actually execute (not replays).
    Execute,
    /// After a refund has been committed.
    PostCommit,
    /// On the response about to be written (including idempotent replays).
    Respond,
    /// When an event is about to be delivered.
    Webhook,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderVariant {
    /// CR LF inside a header value, smuggling `Set-Cookie` and `Location` lines.
    CrlfInjection,
    /// A lone CR inside a header value.
    BareCr,
    /// A NUL byte inside a header value.
    NulByte,
    /// An obsolete line-folded header continuation.
    ObsFold,
    /// Two different `Content-Length` headers.
    DuplicateContentLength,
    /// `Transfer-Encoding: chunked` together with `Content-Length` and a non-chunked body.
    TeAndCl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonVariant {
    Truncated,
    /// `amount` appears twice; the first occurrence carries a lie.
    DuplicateKeys,
    DeepNesting,
    /// `amount` replaced with a number beyond 2^64 and beyond f64 range.
    HugeNumber,
    TrailingGarbage,
    NotJson,
    /// Valid JSON labelled `text/html`.
    WrongContentType,
    InvalidUtf8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Fault {
    // ---- Pre stage ----
    /// 429 with nothing executed and nothing cached.
    RateLimit,
    /// Close the connection without a response; nothing executed.
    DropBeforeCommit,
    /// (malicious) 3xx redirect to another host; nothing executed.
    Redirect {
        location: String,
        #[serde(default = "d307")]
        status: u16,
    },
    // ---- Execute stage ----
    /// Return a 5xx with no state change; the idempotency key is released (not cached).
    FailBeforeCommit {
        #[serde(default = "d500")]
        status: u16,
    },
    /// Commit, cache a 500 for the key, return 500.
    #[serde(rename = "commit_then_500")]
    CommitThen500,
    /// Commit (caching the real response), then close the connection without a response.
    CommitThenDrop,
    /// Hold the key `in_progress`, commit after `ms`, then respond.
    CommitAfterDelay { ms: u64 },
    /// Hold the first request `in_progress` for `hold_ms` so a concurrent duplicate gets 409.
    #[serde(rename = "inflight_409")]
    Inflight409 {
        #[serde(default = "d_hold")]
        hold_ms: u64,
    },
    /// (malicious) Return 200 with a refund object that was never stored.
    PhantomSuccess,
    /// (malicious) Commit the refund but answer 400 `charge_already_refunded`.
    DenyButCommit,
    // ---- PostCommit stage ----
    /// The committed refund moves to `failed` `after_s` simulated seconds later.
    LateRefundFailed {
        #[serde(default)]
        after_s: u64,
    },
    // ---- Respond stage ----
    /// Delay the (already committed) response by `ms`.
    SlowResponse { ms: u64 },
    /// (malicious) Report a different amount than the stored one.
    LieAmount { amount: u64 },
    /// (malicious) Report a different charge id.
    LieCharge { charge: String },
    /// (malicious) Report a different currency.
    LieCurrency { currency: String },
    /// (malicious) Report a different status.
    LieStatus { status: String },
    /// (malicious) Pad the JSON body to `bytes`.
    OversizedBody { bytes: usize },
    /// (malicious) Add one header of `bytes` length.
    OversizedHeader { bytes: usize },
    /// (malicious) Emit an invalid or smuggling header construction.
    HeaderInjection { variant: HeaderVariant },
    /// (malicious) Emit an invalid or ambiguous JSON body.
    MalformedJson { variant: JsonVariant },
    /// (malicious) Replace the response with a 400 whose text carries markup and prompt-injection text.
    HostileErrorText,
    /// (malicious) Send the response `chunk` bytes at a time every `interval_ms`.
    SlowDrip { chunk: usize, interval_ms: u64 },
    // ---- Webhook stage ----
    /// Deliver the same event id `n` times (each with a fresh timestamp).
    WebhookDuplicate { n: u32 },
    /// After a successful delivery, resend the identical bytes and old signature after `after_ms`.
    WebhookReplay { after_ms: u64 },
    /// (malicious) Correctly signed event whose content contradicts the stored object.
    WebhookContradict,
    /// Do not deliver the event at all.
    WebhookSuppress,
}

fn d307() -> u16 {
    307
}
fn d500() -> u16 {
    500
}
fn d_hold() -> u64 {
    1_000
}

/// Upper bounds that keep a fault plan from exhausting the simulator's own memory.
pub const MAX_OVERSIZE: usize = 64 * 1024 * 1024;
pub const MAX_DELAY_MS: u64 = 600_000;

impl Fault {
    pub fn stage(&self) -> Stage {
        use Fault::*;
        match self {
            RateLimit | DropBeforeCommit | Redirect { .. } => Stage::Pre,
            FailBeforeCommit { .. }
            | CommitThen500
            | CommitThenDrop
            | CommitAfterDelay { .. }
            | Inflight409 { .. }
            | PhantomSuccess
            | DenyButCommit => Stage::Execute,
            LateRefundFailed { .. } => Stage::PostCommit,
            SlowResponse { .. }
            | LieAmount { .. }
            | LieCharge { .. }
            | LieCurrency { .. }
            | LieStatus { .. }
            | OversizedBody { .. }
            | OversizedHeader { .. }
            | HeaderInjection { .. }
            | MalformedJson { .. }
            | HostileErrorText
            | SlowDrip { .. } => Stage::Respond,
            WebhookDuplicate { .. }
            | WebhookReplay { .. }
            | WebhookContradict
            | WebhookSuppress => Stage::Webhook,
        }
    }

    /// Attacker-G behaviours; installable only in malicious mode.
    pub fn is_malicious(&self) -> bool {
        use Fault::*;
        matches!(
            self,
            Redirect { .. }
                | PhantomSuccess
                | DenyButCommit
                | LieAmount { .. }
                | LieCharge { .. }
                | LieCurrency { .. }
                | LieStatus { .. }
                | OversizedBody { .. }
                | OversizedHeader { .. }
                | HeaderInjection { .. }
                | MalformedJson { .. }
                | HostileErrorText
                | SlowDrip { .. }
                | WebhookContradict
        )
    }

    fn validate(&self) -> Result<(), String> {
        use Fault::*;
        match self {
            Redirect { status, location } => {
                if !(300..=399).contains(status) {
                    return Err("redirect status must be 3xx".into());
                }
                if location.bytes().any(|b| !(0x20..0x7f).contains(&b)) {
                    return Err("redirect location must be visible ASCII".into());
                }
            }
            FailBeforeCommit { status } if !(500..=599).contains(status) => {
                return Err("fail_before_commit status must be 5xx".into());
            }
            CommitAfterDelay { ms } | SlowResponse { ms } if *ms > MAX_DELAY_MS => {
                return Err("delay too large".into());
            }
            Inflight409 { hold_ms } if *hold_ms > MAX_DELAY_MS => {
                return Err("delay too large".into());
            }
            WebhookReplay { after_ms } if *after_ms > MAX_DELAY_MS => {
                return Err("delay too large".into());
            }
            OversizedBody { bytes } | OversizedHeader { bytes } if *bytes > MAX_OVERSIZE => {
                return Err("oversize limit is 64 MiB".into());
            }
            SlowDrip { chunk, interval_ms } if *chunk == 0 || *interval_ms > 10_000 => {
                return Err("slow_drip needs chunk >= 1 and interval_ms <= 10000".into());
            }
            WebhookDuplicate { n } if *n == 0 || *n > 100 => {
                return Err("webhook_duplicate n must be 1..=100".into());
            }
            LieCharge { charge } if charge.len() > 128 => {
                return Err("lie value too long".into());
            }
            LieCurrency { currency } if currency.len() > 128 => {
                return Err("lie value too long".into());
            }
            LieStatus { status } if status.len() > 128 => {
                return Err("lie value too long".into());
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    #[serde(default)]
    pub op: Option<Op>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// Compared with the request's `charge` parameter, or the event's refund charge.
    #[serde(default)]
    pub charge: Option<String>,
    /// Webhook stage only, e.g. `refund.created`.
    #[serde(default)]
    pub event_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, rename = "match")]
    pub matcher: Match,
    pub fault: Fault,
    /// Fire starting at the nth match (1-based). Default 1.
    #[serde(default = "d_one")]
    pub nth: u64,
    /// How many times the rule fires. Default 1; 0 = unlimited.
    #[serde(default = "d_one")]
    pub times: u64,
}

fn d_one() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleState {
    pub rule: Rule,
    pub matched: u64,
    pub fired: u64,
}

/// What a stage knows about the current request or event.
#[derive(Debug, Clone, Copy)]
pub struct Ctx<'a> {
    pub op: Op,
    pub idempotency_key: Option<&'a str>,
    pub charge: Option<&'a str>,
    pub event_type: Option<&'a str>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct FaultPlan {
    pub rules: Vec<RuleState>,
}

impl FaultPlan {
    pub fn install(&mut self, rules: Vec<Rule>, malicious_mode: bool) -> Result<(), String> {
        if rules.len() > 256 {
            return Err("at most 256 rules".into());
        }
        for r in &rules {
            if r.nth == 0 {
                return Err("nth is 1-based".into());
            }
            if r.fault.is_malicious() && !malicious_mode {
                return Err(format!(
                    "fault {:?} is a malicious-provider behaviour; enable malicious mode first",
                    r.fault
                ));
            }
            r.fault.validate()?;
        }
        self.rules = rules
            .into_iter()
            .map(|rule| RuleState {
                rule,
                matched: 0,
                fired: 0,
            })
            .collect();
        Ok(())
    }

    pub fn take(&mut self, stage: Stage, ctx: Ctx<'_>) -> Option<Fault> {
        for rs in self.rules.iter_mut() {
            if rs.rule.fault.stage() != stage || !matches(&rs.rule.matcher, ctx) {
                continue;
            }
            rs.matched += 1;
            if rs.matched >= rs.rule.nth && (rs.rule.times == 0 || rs.fired < rs.rule.times) {
                rs.fired += 1;
                return Some(rs.rule.fault.clone());
            }
        }
        None
    }
}

fn matches(m: &Match, ctx: Ctx<'_>) -> bool {
    if let Some(op) = m.op
        && op != ctx.op
    {
        return false;
    }
    let eq = |want: &Option<String>, have: Option<&str>| match want {
        None => true,
        Some(w) => have == Some(w.as_str()),
    };
    eq(&m.idempotency_key, ctx.idempotency_key)
        && eq(&m.charge, ctx.charge)
        && eq(&m.event_type, ctx.event_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(op: Op) -> Ctx<'static> {
        Ctx {
            op,
            idempotency_key: None,
            charge: None,
            event_type: None,
        }
    }

    #[test]
    fn nth_and_times() {
        let mut p = FaultPlan::default();
        p.install(
            vec![Rule {
                id: None,
                matcher: Match {
                    op: Some(Op::CreateRefund),
                    ..Default::default()
                },
                fault: Fault::RateLimit,
                nth: 2,
                times: 2,
            }],
            false,
        )
        .unwrap();
        let seq: Vec<bool> = (0..5)
            .map(|_| p.take(Stage::Pre, ctx(Op::CreateRefund)).is_some())
            .collect();
        assert_eq!(seq, [false, true, true, false, false]);
        assert!(p.take(Stage::Pre, ctx(Op::GetCharge)).is_none());
        assert!(p.take(Stage::Execute, ctx(Op::CreateRefund)).is_none());
    }

    #[test]
    fn malicious_gate() {
        let mut p = FaultPlan::default();
        let r = Rule {
            id: None,
            matcher: Match::default(),
            fault: Fault::PhantomSuccess,
            nth: 1,
            times: 1,
        };
        assert!(p.install(vec![r.clone()], false).is_err());
        assert!(p.install(vec![r], true).is_ok());
    }

    #[test]
    fn parse_rules_strictly() {
        let ok: Result<Rule, _> =
            serde_json::from_str(r#"{"fault":{"kind":"commit_after_delay","ms":5}}"#);
        assert!(ok.is_ok());
        let bad: Result<Rule, _> =
            serde_json::from_str(r#"{"fault":{"kind":"commit_after_delay","ms":5,"x":1}}"#);
        assert!(bad.is_err());
        let bad: Result<Rule, _> = serde_json::from_str(r#"{"fault":{"kind":"nope"}}"#);
        assert!(bad.is_err());
    }
}
