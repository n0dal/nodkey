//! In-memory server-side state: sessions, approval tokens, login states and app hand-off codes.
//!
//! **Phase 3 limitation:** everything here is lost on restart (every user is logged out and every
//! rendered approval form becomes invalid, which fails closed). Each map is capped. Sessions,
//! tokens and codes are refused (`Full`) when their map is full after purging expired entries; login
//! states instead evict the oldest entry (per client, then globally), because they are created by
//! unauthenticated requests (GW-R-02).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use crate::util::{b64url, random_bytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOrigin {
    App,
    Auth,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub origin: SessionOrigin,
    pub ten: String,
    pub sub: String,
    /// Shared by the auth session and the app sessions minted from it; logout revokes all of them.
    pub login_id: [u8; 16],
    pub created: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub session_id: String,
    pub pending_id: [u8; 16],
    pub digest: [u8; 32],
    pub expires: u64,
    /// When the page carrying this token was rendered (GW-R-01 activation delay).
    pub issued: Instant,
    /// Amounts the user must type to approve: `(form field, exact expected text)`.
    pub amounts: Vec<(String, String)>,
}

/// A `/mandates` revoke-form token (effect-protocol-v2 §12.6): bound to the session, the
/// mandate id and the action; single-use.
#[derive(Debug, Clone)]
pub struct RevokeToken {
    pub session_id: String,
    /// Canonical mandate id text.
    pub mid: String,
    /// The mandate's `exp` (background retries stop there).
    pub mandate_exp: u64,
    pub expires: u64,
}

/// The only action a revoke token authorizes.
pub const REVOKE_ACTION: &str = "mandate.revoke";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Return {
    Home,
    /// Canonical pending id text (validated before it is stored).
    Confirm(String),
    /// SHA-256 of the app-origin login state.
    AppHandoff([u8; 32]),
}

#[derive(Debug, Clone)]
pub struct Preauth {
    pub csrf: String,
    pub ret: Return,
    pub expires: u64,
    pub client: IpAddr,
    seq: u64,
}

#[derive(Debug, Clone)]
pub struct Code {
    pub state_hash: [u8; 32],
    pub ten: String,
    pub sub: String,
    pub login_id: [u8; 16],
    pub expires: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Full,
    Rng,
}

#[derive(Debug)]
pub struct Store {
    cap: usize,
    abs_lifetime: u64,
    idle: u64,
    sessions: HashMap<String, Session>,
    tokens: HashMap<String, Token>,
    token_index: HashMap<(String, [u8; 16]), String>,
    preauth: HashMap<String, Preauth>,
    codes: HashMap<String, Code>,
    revoke_tokens: HashMap<String, RevokeToken>,
    preauth_per_client: usize,
    seq: u64,
}

pub const TOKEN_TTL: u64 = 300;
pub const PREAUTH_TTL: u64 = 600;
pub const CODE_TTL: u64 = 60;

fn new_id() -> Result<String, StoreError> {
    Ok(b64url(&random_bytes::<32>().ok_or(StoreError::Rng)?))
}

impl Store {
    pub fn with_preauth_per_client(mut self, n: usize) -> Store {
        self.preauth_per_client = n.max(1);
        self
    }

    pub fn preauth_len(&self) -> usize {
        self.preauth.len()
    }

    pub fn new(cap: usize, abs_lifetime: u64, idle: u64) -> Store {
        Store {
            cap,
            abs_lifetime,
            idle,
            sessions: HashMap::new(),
            tokens: HashMap::new(),
            token_index: HashMap::new(),
            preauth: HashMap::new(),
            codes: HashMap::new(),
            revoke_tokens: HashMap::new(),
            preauth_per_client: 8,
            seq: 0,
        }
    }

    fn session_live(&self, s: &Session, now: u64) -> bool {
        now < s.created.saturating_add(self.abs_lifetime)
            && now < s.last_seen.saturating_add(self.idle)
    }

    fn purge(&mut self, now: u64) {
        let (abs, idle) = (self.abs_lifetime, self.idle);
        self.sessions.retain(|_, s| {
            now < s.created.saturating_add(abs) && now < s.last_seen.saturating_add(idle)
        });
        let sessions = &self.sessions;
        self.tokens
            .retain(|_, t| now < t.expires && sessions.contains_key(&t.session_id));
        let tokens = &self.tokens;
        self.token_index.retain(|_, tok| tokens.contains_key(tok));
        self.preauth.retain(|_, p| now < p.expires);
        self.codes.retain(|_, c| now < c.expires);
        let sessions = &self.sessions;
        self.revoke_tokens
            .retain(|_, t| now < t.expires && sessions.contains_key(&t.session_id));
    }

    /// Mints a single-use revoke token for `(session, mid)` (§12.6).
    pub fn mint_revoke_token(
        &mut self,
        session_id: &str,
        mid: &str,
        mandate_exp: u64,
        now: u64,
    ) -> Result<String, StoreError> {
        self.room(|s| s.revoke_tokens.len(), now)?;
        let tok = new_id()?;
        self.revoke_tokens.insert(
            tok.clone(),
            RevokeToken {
                session_id: session_id.to_owned(),
                mid: mid.to_owned(),
                mandate_exp,
                expires: now + TOKEN_TTL,
            },
        );
        Ok(tok)
    }

    /// Removes a revoke token at its first presentation (checks are the caller's).
    pub fn take_revoke_token(&mut self, tok: &str) -> Option<RevokeToken> {
        self.revoke_tokens.remove(tok)
    }

    fn room(&mut self, len: impl Fn(&Store) -> usize, now: u64) -> Result<(), StoreError> {
        if len(self) >= self.cap {
            self.purge(now);
            if len(self) >= self.cap {
                return Err(StoreError::Full);
            }
        }
        Ok(())
    }

    /// Creates a session with a fresh id. The caller revokes any session the browser presented.
    pub fn create_session(
        &mut self,
        origin: SessionOrigin,
        ten: &str,
        sub: &str,
        login_id: [u8; 16],
        now: u64,
    ) -> Result<String, StoreError> {
        self.room(|s| s.sessions.len(), now)?;
        let id = new_id()?;
        self.sessions.insert(
            id.clone(),
            Session {
                origin,
                ten: ten.to_owned(),
                sub: sub.to_owned(),
                login_id,
                created: now,
                last_seen: now,
            },
        );
        Ok(id)
    }

    /// Returns the live session of the given origin and refreshes its idle timer.
    /// Returns the live session of the given origin. `refresh` restarts its idle timer; callers pass
    /// it only for top-level same-origin (or user-initiated) navigations (GW-R-05).
    pub fn session(
        &mut self,
        id: &str,
        origin: SessionOrigin,
        now: u64,
        refresh: bool,
    ) -> Option<Session> {
        let live = {
            let s = self.sessions.get(id)?;
            s.origin == origin && self.session_live(s, now)
        };
        if !live {
            // An expired session is removed; a session of the other origin is left untouched.
            if self
                .sessions
                .get(id)
                .is_some_and(|s| !self.session_live(s, now))
            {
                self.remove_session(id);
            }
            return None;
        }
        let s = self.sessions.get_mut(id)?;
        if refresh {
            s.last_seen = now;
        }
        Some(s.clone())
    }

    fn remove_session(&mut self, id: &str) {
        self.sessions.remove(id);
        self.tokens.retain(|_, t| t.session_id != id);
        self.token_index.retain(|(sid, _), _| sid != id);
    }

    /// Revokes the given session and every session that shares its login.
    pub fn revoke_login_of(&mut self, id: &str) {
        let Some(login) = self.sessions.get(id).map(|s| s.login_id) else {
            return;
        };
        let ids: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.login_id == login)
            .map(|(k, _)| k.clone())
            .collect();
        for k in ids {
            self.remove_session(&k);
        }
    }

    /// Revokes exactly one session (used when a browser presents an old id at login).
    pub fn revoke_session(&mut self, id: &str) {
        self.remove_session(id);
    }

    /// Mints an approval token; invalidates the previous one for `(session, pending_id)` (§7.2).
    pub fn mint_token(
        &mut self,
        session_id: &str,
        pending_id: [u8; 16],
        digest: [u8; 32],
        record_expires: u64,
        now: u64,
        amounts: Vec<(String, String)>,
    ) -> Result<String, StoreError> {
        let key = (session_id.to_owned(), pending_id);
        if let Some(old) = self.token_index.remove(&key) {
            self.tokens.remove(&old);
        }
        self.room(|s| s.tokens.len(), now)?;
        let tok = new_id()?;
        self.tokens.insert(
            tok.clone(),
            Token {
                session_id: session_id.to_owned(),
                pending_id,
                digest,
                expires: (now + TOKEN_TTL).min(record_expires),
                issued: Instant::now(),
                amounts,
            },
        );
        self.token_index.insert(key, tok.clone());
        Ok(tok)
    }

    /// Reads a token without consuming it.
    pub fn peek_token(&self, tok: &str) -> Option<Token> {
        self.tokens.get(tok).cloned()
    }

    /// Removes the token at its first presentation and returns it (checks are the caller's).
    pub fn take_token(&mut self, tok: &str) -> Option<Token> {
        let t = self.tokens.remove(tok)?;
        self.token_index
            .remove(&(t.session_id.clone(), t.pending_id));
        Some(t)
    }

    /// Creates a login state for `client`. At most `preauth_per_client` per client address and
    /// `cap` in total: the oldest entry (of that client, then globally) is evicted, so a flood can
    /// only displace login states, never block new ones (GW-R-02).
    pub fn create_preauth(
        &mut self,
        ret: Return,
        client: IpAddr,
        now: u64,
    ) -> Result<(String, String), StoreError> {
        self.preauth.retain(|_, p| now < p.expires);
        let mine: Vec<(&String, u64)> = self
            .preauth
            .iter()
            .filter(|(_, p)| p.client == client)
            .map(|(k, p)| (k, p.seq))
            .collect();
        if mine.len() >= self.preauth_per_client {
            if let Some(k) = mine
                .iter()
                .min_by_key(|(_, s)| *s)
                .map(|(k, _)| (*k).clone())
            {
                self.preauth.remove(&k);
            }
        }
        if self.preauth.len() >= self.cap {
            if let Some(k) = self
                .preauth
                .iter()
                .min_by_key(|(_, p)| p.seq)
                .map(|(k, _)| k.clone())
            {
                self.preauth.remove(&k);
            }
        }
        let id = new_id()?;
        let csrf = new_id()?;
        self.seq += 1;
        self.preauth.insert(
            id.clone(),
            Preauth {
                csrf: csrf.clone(),
                ret,
                expires: now + PREAUTH_TTL,
                client,
                seq: self.seq,
            },
        );
        Ok((id, csrf))
    }

    pub fn preauth(&self, id: &str, now: u64) -> Option<Preauth> {
        self.preauth.get(id).filter(|p| now < p.expires).cloned()
    }

    pub fn take_preauth(&mut self, id: &str, now: u64) -> Option<Preauth> {
        self.preauth.remove(id).filter(|p| now < p.expires)
    }

    pub fn create_code(&mut self, code: Code, now: u64) -> Result<String, StoreError> {
        self.room(|s| s.codes.len(), now)?;
        let id = new_id()?;
        self.codes.insert(id.clone(), code);
        Ok(id)
    }

    pub fn take_code(&mut self, id: &str, now: u64) -> Option<Code> {
        self.codes.remove(id).filter(|c| now < c.expires)
    }

    pub fn new_login_id() -> Result<[u8; 16], StoreError> {
        random_bytes::<16>().ok_or(StoreError::Rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_single_use_and_rerender_invalidates() {
        let mut s = Store::new(100, 3600, 600);
        let lid = [1u8; 16];
        let sid = s
            .create_session(SessionOrigin::Auth, "t", "u", lid, 1000)
            .unwrap();
        let t1 = s
            .mint_token(&sid, [2; 16], [3; 32], 5000, 1000, vec![])
            .unwrap();
        let t2 = s
            .mint_token(&sid, [2; 16], [3; 32], 5000, 1001, vec![])
            .unwrap();
        assert!(
            s.take_token(&t1).is_none(),
            "re-render invalidates the previous token"
        );
        let t = s.take_token(&t2).unwrap();
        assert_eq!(t.expires, 1301);
        assert!(s.take_token(&t2).is_none(), "single use");
        let t3 = s
            .mint_token(&sid, [2; 16], [3; 32], 1100, 1000, vec![])
            .unwrap();
        assert_eq!(
            s.take_token(&t3).unwrap().expires,
            1100,
            "capped at record expiry"
        );
    }

    #[test]
    fn session_lifetimes_and_origin() {
        let mut s = Store::new(100, 100, 50);
        let sid = s
            .create_session(SessionOrigin::App, "t", "u", [0; 16], 0)
            .unwrap();
        assert!(
            s.session(&sid, SessionOrigin::Auth, 1, true).is_none(),
            "app session not valid on auth"
        );
        assert!(s.session(&sid, SessionOrigin::App, 40, true).is_some());
        assert!(s.session(&sid, SessionOrigin::App, 89, true).is_some());
        assert!(
            s.session(&sid, SessionOrigin::App, 100, true).is_none(),
            "absolute lifetime"
        );
        let sid2 = s
            .create_session(SessionOrigin::App, "t", "u", [0; 16], 0)
            .unwrap();
        assert!(
            s.session(&sid2, SessionOrigin::App, 50, true).is_none(),
            "idle timeout"
        );
    }

    #[test]
    fn logout_revokes_linked_sessions_and_tokens() {
        let mut s = Store::new(100, 1000, 1000);
        let a = s
            .create_session(SessionOrigin::Auth, "t", "u", [7; 16], 0)
            .unwrap();
        let b = s
            .create_session(SessionOrigin::App, "t", "u", [7; 16], 0)
            .unwrap();
        let c = s
            .create_session(SessionOrigin::App, "t", "v", [8; 16], 0)
            .unwrap();
        let tok = s.mint_token(&a, [1; 16], [1; 32], 500, 0, vec![]).unwrap();
        s.revoke_login_of(&b);
        assert!(s.session(&a, SessionOrigin::Auth, 1, true).is_none());
        assert!(s.session(&b, SessionOrigin::App, 1, true).is_none());
        assert!(s.session(&c, SessionOrigin::App, 1, true).is_some());
        assert!(s.take_token(&tok).is_none());
    }

    #[test]
    fn preauth_evicts_oldest_per_client_and_globally() {
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let mut s = Store::new(5, 1000, 1000).with_preauth_per_client(2);
        let (b1, _) = s.create_preauth(Return::Home, b, 0).unwrap();
        let (a1, _) = s.create_preauth(Return::Home, a, 0).unwrap();
        let (a2, _) = s.create_preauth(Return::Home, a, 0).unwrap();
        let (a3, _) = s.create_preauth(Return::Home, a, 0).unwrap();
        assert!(s.preauth(&a1, 1).is_none(), "oldest of client a evicted");
        assert!(s.preauth(&a2, 1).is_some() && s.preauth(&a3, 1).is_some());
        assert!(
            s.preauth(&b1, 1).is_some(),
            "other clients untouched by a's flood"
        );
        for i in 0..100u8 {
            let c = IpAddr::from([10, 1, 0, i]);
            s.create_preauth(Return::Home, c, 0).unwrap();
        }
        assert_eq!(s.preauth_len(), 5, "global cap holds; never refuses");
    }

    #[test]
    fn caps_refuse_rather_than_evict() {
        let mut s = Store::new(2, 1000, 1000);
        s.create_session(SessionOrigin::App, "t", "u", [0; 16], 0)
            .unwrap();
        s.create_session(SessionOrigin::App, "t", "u", [0; 16], 0)
            .unwrap();
        assert_eq!(
            s.create_session(SessionOrigin::App, "t", "u", [0; 16], 0),
            Err(StoreError::Full)
        );
        // After expiry, room is made by purging.
        assert!(
            s.create_session(SessionOrigin::App, "t", "u", [0; 16], 2000)
                .is_ok()
        );
    }
}
