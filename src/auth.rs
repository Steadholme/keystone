//! Login primitives: cookies, signed sessions, CSRF (double-submit), Argon2 passwords.
//!
//! All cookies use the `__Host-` prefix (Secure + Path=/ + no Domain) so they are
//! only ever sent back over TLS to this exact host. The session cookie carries an
//! opaque, server-stored session id HMAC-signed with `SESSION_SECRET`, so a tampered
//! cookie is rejected before any store lookup.

use argon2::password_hash::rand_core::OsRng as PwOsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::http::{header, HeaderMap};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::store::{new_opaque_code, Session};
use crate::{now_secs, AppState};

type HmacSha256 = Hmac<Sha256>;

/// Server-stored session, HMAC-signed (HttpOnly).
pub const SESSION_COOKIE: &str = "__Host-session";
/// Double-submit CSRF token (readable by JS so it can echo into `X-CSRF-Token`).
pub const CSRF_COOKIE: &str = "__Host-csrf";
/// Short-lived id of the in-flight WebAuthn ceremony state (HttpOnly).
pub const WA_STATE_COOKIE: &str = "__Host-wa";
/// CSRF cookie lifetime, seconds.
const CSRF_TTL: u64 = 3600;
/// WebAuthn ceremony-state lifetime, seconds.
pub const WA_STATE_TTL: u64 = 300;

// ---------------------------------------------------------------------------
// Cookie parsing / building
// ---------------------------------------------------------------------------

/// Read a single cookie value from the request's `Cookie` header(s).
pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::COOKIE).iter() {
        let Ok(raw) = hv.to_str() else { continue };
        for pair in raw.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// `Set-Cookie` value for the signed session cookie.
pub fn session_cookie(value: &str, ttl: u64) -> String {
    format!("{SESSION_COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={ttl}")
}

/// `Set-Cookie` value for the (JS-readable) CSRF cookie.
pub fn csrf_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; Path=/; Secure; SameSite=Lax; Max-Age={CSRF_TTL}")
}

/// `Set-Cookie` value for the short-lived WebAuthn ceremony-state cookie.
pub fn wa_state_cookie(value: &str) -> String {
    format!(
        "{WA_STATE_COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={WA_STATE_TTL}"
    )
}

/// `Set-Cookie` value that immediately expires `name`.
pub fn clear_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

// ---------------------------------------------------------------------------
// HMAC signing of the opaque session id
// ---------------------------------------------------------------------------

fn sign(secret: &str, msg: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(msg.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Wrap an opaque id as `id.mac` for cookie transport.
pub fn signed_value(secret: &str, id: &str) -> String {
    format!("{id}.{}", sign(secret, id))
}

/// Verify an `id.mac` cookie value and return the id (constant-time MAC check).
pub fn verify_signed(secret: &str, value: &str) -> Option<String> {
    let (id, sig_b64) = value.rsplit_once('.')?;
    let sig = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(id.as_bytes());
    mac.verify_slice(&sig).ok()?;
    Some(id.to_string())
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/// Create + persist a session for `user_sub`; returns the signed cookie value.
pub async fn create_session(state: &AppState, user_sub: &str) -> String {
    let id = new_opaque_code();
    let now = now_secs();
    state
        .store
        .put_session(Session {
            id: id.clone(),
            user_sub: user_sub.to_string(),
            created_at: now,
            expires_at: now + state.config.session_ttl,
        })
        .await;
    signed_value(&state.config.session_secret, &id)
}

/// Resolve the current (unexpired) session from the request cookies, if any.
/// Expired sessions are deleted as a side effect.
pub async fn current_session(state: &AppState, headers: &HeaderMap) -> Option<Session> {
    let raw = get_cookie(headers, SESSION_COOKIE)?;
    let id = verify_signed(&state.config.session_secret, &raw)?;
    let session = state.store.get_session(&id).await?;
    if now_secs() > session.expires_at {
        state.store.delete_session(&id).await;
        return None;
    }
    Some(session)
}

/// Destroy the session referenced by the request cookie (logout). Best-effort.
pub async fn destroy_session(state: &AppState, headers: &HeaderMap) {
    if let Some(raw) = get_cookie(headers, SESSION_COOKIE) {
        if let Some(id) = verify_signed(&state.config.session_secret, &raw) {
            state.store.delete_session(&id).await;
        }
    }
}

// ---------------------------------------------------------------------------
// CSRF (double-submit)
// ---------------------------------------------------------------------------

/// Mint a fresh CSRF token (same value goes in the cookie and the form/header).
pub fn new_csrf_token() -> String {
    new_opaque_code()
}

/// Read the submitted CSRF token from the `X-CSRF-Token` header (used by fetch POSTs).
pub fn header_csrf(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-csrf-token")?
        .to_str()
        .ok()
        .map(str::to_string)
}

/// Double-submit check: the `submitted` token must equal the `__Host-csrf` cookie.
pub fn verify_csrf(headers: &HeaderMap, submitted: &str) -> bool {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(cookie) if !cookie.is_empty() => ct_eq(cookie.as_bytes(), submitted.as_bytes()),
        _ => false,
    }
}

/// Length-checked constant-time byte comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Argon2 password hashing
// ---------------------------------------------------------------------------

/// Hash a password with Argon2id, returning a self-describing PHC string.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut PwOsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("argon2 hash failed: {e}"))
}

/// Verify a password against a stored PHC hash (constant-time inside Argon2).
pub fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_round_trip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2"), "PHC string, got {hash}");
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn session_signature_round_trip() {
        let secret = "unit-test-secret";
        let signed = signed_value(secret, "session-abc");
        assert_eq!(
            verify_signed(secret, &signed).as_deref(),
            Some("session-abc")
        );
        // Tampered id is rejected.
        let tampered = signed.replacen("session-abc", "session-xyz", 1);
        assert!(verify_signed(secret, &tampered).is_none());
        // Wrong secret is rejected.
        assert!(verify_signed("other-secret", &signed).is_none());
    }

    #[test]
    fn csrf_double_submit() {
        let token = new_csrf_token();
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            format!("{CSRF_COOKIE}={token}").parse().unwrap(),
        );
        assert!(verify_csrf(&headers, &token));
        assert!(!verify_csrf(&headers, "not-the-token"));
    }
}
