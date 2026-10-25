//! In-memory server-side state: sessions, approval tokens, login states and app hand-off codes.
//!
//! **Phase 3 limitation:** everything here is lost on restart (every user is logged out and every
//! rendered approval form becomes invalid, which fails closed). Each map is capped; when a map is
//! full after purging expired entries, new entries are refused (`Full`) rather than evicting live
//! ones.

use std::collections::HashMap;

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
}

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
}

pub const TOKEN_TTL: u64 = 300;
pub const PREAUTH_TTL: u64 = 600;
pub const CODE_TTL: u64 = 60;

fn new_id() -> Result<String, StoreError> {
    Ok(b64url(&random_bytes::<32>().ok_or(StoreError::Rng)?))
}

impl Store {
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
    pub fn session(&mut self, id: &str, origin: SessionOrigin, now: u64) -> Option<Session> {
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
        s.last_seen = now;
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
            },
        );
        self.token_index.insert(key, tok.clone());
        Ok(tok)
    }

    /// Removes the token at its first presentation and returns it (checks are the caller's).
    pub fn take_token(&mut self, tok: &str) -> Option<Token> {
        let t = self.tokens.remove(tok)?;
        self.token_index
            .remove(&(t.session_id.clone(), t.pending_id));
        Some(t)
    }

    pub fn create_preauth(
        &mut self,
        ret: Return,
        now: u64,
    ) -> Result<(String, String), StoreError> {
        self.room(|s| s.preauth.len(), now)?;
        let id = new_id()?;
        let csrf = new_id()?;
        self.preauth.insert(
            id.clone(),
            Preauth {
                csrf: csrf.clone(),
                ret,
                expires: now + PREAUTH_TTL,
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
        let t1 = s.mint_token(&sid, [2; 16], [3; 32], 5000, 1000).unwrap();
        let t2 = s.mint_token(&sid, [2; 16], [3; 32], 5000, 1001).unwrap();
        assert!(
            s.take_token(&t1).is_none(),
            "re-render invalidates the previous token"
        );
        let t = s.take_token(&t2).unwrap();
        assert_eq!(t.expires, 1301);
        assert!(s.take_token(&t2).is_none(), "single use");
        let t3 = s.mint_token(&sid, [2; 16], [3; 32], 1100, 1000).unwrap();
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
            s.session(&sid, SessionOrigin::Auth, 1).is_none(),
            "app session not valid on auth"
        );
        assert!(s.session(&sid, SessionOrigin::App, 40).is_some());
        assert!(s.session(&sid, SessionOrigin::App, 89).is_some());
        assert!(
            s.session(&sid, SessionOrigin::App, 100).is_none(),
            "absolute lifetime"
        );
        let sid2 = s
            .create_session(SessionOrigin::App, "t", "u", [0; 16], 0)
            .unwrap();
        assert!(
            s.session(&sid2, SessionOrigin::App, 50).is_none(),
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
        let tok = s.mint_token(&a, [1; 16], [1; 32], 500, 0).unwrap();
        s.revoke_login_of(&b);
        assert!(s.session(&a, SessionOrigin::Auth, 1).is_none());
        assert!(s.session(&b, SessionOrigin::App, 1).is_none());
        assert!(s.session(&c, SessionOrigin::App, 1).is_some());
        assert!(s.take_token(&tok).is_none());
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
