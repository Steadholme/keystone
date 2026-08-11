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
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::store::{new_opaque_code, AssuranceLevel, Session};
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

/// Create + persist a session for `user_sub`; returns the signed cookie value only while
/// the authoritative user still exists and is enabled.
///
/// `user_agent`/`ip` are captured for the session-management UI (best-effort device labels);
/// pass empty strings when unavailable. `last_seen` starts at the creation time.
pub async fn try_create_session(
    state: &AppState,
    user_sub: &str,
    user_agent: &str,
    ip: &str,
) -> Option<String> {
    try_create_session_with_assurance(
        state,
        user_sub,
        user_agent,
        ip,
        AssuranceLevel::AalNone,
        false,
        "",
    )
    .await
}

/// Create a session carrying server-proven assurance. Callers may request
/// `MFA_STRONG` only immediately after a qualifying ceremony.
pub async fn try_create_session_with_assurance(
    state: &AppState,
    user_sub: &str,
    user_agent: &str,
    ip: &str,
    aal: AssuranceLevel,
    uv: bool,
    amr: &str,
) -> Option<String> {
    try_create_session_with_assurance_inner(
        state,
        user_sub,
        user_agent,
        ip,
        AssuranceGrant {
            aal,
            uv,
            amr,
            expected_factor_epoch: None,
        },
    )
    .await
}

/// Create a strong session only if the subject is still on the exact factor generation at
/// which a qualifying ceremony was atomically accepted. This closes the reset-between-verify-
/// and-session race for TOTP without holding a database transaction across handler work.
pub async fn try_create_strong_session_at_epoch(
    state: &AppState,
    user_sub: &str,
    user_agent: &str,
    ip: &str,
    uv: bool,
    amr: &str,
    expected_factor_epoch: u64,
) -> Option<String> {
    try_create_session_with_assurance_inner(
        state,
        user_sub,
        user_agent,
        ip,
        AssuranceGrant {
            aal: AssuranceLevel::MfaStrong,
            uv,
            amr,
            expected_factor_epoch: Some(expected_factor_epoch),
        },
    )
    .await
}

struct AssuranceGrant<'a> {
    aal: AssuranceLevel,
    uv: bool,
    amr: &'a str,
    expected_factor_epoch: Option<u64>,
}

async fn try_create_session_with_assurance_inner(
    state: &AppState,
    user_sub: &str,
    user_agent: &str,
    ip: &str,
    grant: AssuranceGrant<'_>,
) -> Option<String> {
    let AssuranceGrant {
        aal,
        uv,
        amr,
        expected_factor_epoch,
    } = grant;
    let user = state.store.get_user(user_sub).await?;
    if user.disabled || expected_factor_epoch.is_some_and(|expected| expected != user.factor_epoch)
    {
        return None;
    }
    let valid_assurance = match aal {
        AssuranceLevel::AalNone => !uv && amr.is_empty(),
        AssuranceLevel::MfaStrong => matches!(amr, "pwd,otp" | "hwk,user"),
    };
    if !valid_assurance {
        return None;
    }
    let id = new_opaque_code();
    let now = now_secs();
    let auth_time = if aal == AssuranceLevel::MfaStrong {
        now
    } else {
        0
    };
    let persisted = state
        .store
        .put_session_if_active(Session {
            id: id.clone(),
            user_sub: user_sub.to_string(),
            created_at: now,
            expires_at: now + state.config.session_ttl,
            user_agent: user_agent.to_string(),
            ip: ip.to_string(),
            last_seen: now,
            session_binding: Some(session_binding(&id)),
            aal,
            uv,
            auth_time,
            amr: amr.to_string(),
            factor_epoch: expected_factor_epoch.unwrap_or(user.factor_epoch),
        })
        .await
        .ok()?;
    if !persisted {
        return None;
    }
    Some(signed_value(&state.config.session_secret, &id))
}

/// Public, non-bearer identifier used to bind assurance to one server-side session.
pub fn session_binding(session_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"holdfast.keystone.session-binding.v1\n");
    digest.update(session_id.as_bytes());
    lower_hex(&digest.finalize())
}

/// Backward-compatible test/helper seam. A rejected write returns an empty, unusable cookie;
/// request handlers use [`try_create_session`] so they can surface the denial explicitly.
pub async fn create_session(
    state: &AppState,
    user_sub: &str,
    user_agent: &str,
    ip: &str,
) -> String {
    try_create_session(state, user_sub, user_agent, ip)
        .await
        .unwrap_or_default()
}

/// Resolve the current (unexpired) session from the request cookies, if any.
/// Expired sessions are deleted as a side effect.
pub async fn current_session(state: &AppState, headers: &HeaderMap) -> Option<Session> {
    let raw = get_cookie(headers, SESSION_COOKIE)?;
    let id = verify_signed(&state.config.session_secret, &raw)?;
    let session = state.store.get_session(&id).await?;
    let now = now_secs();
    if now > session.expires_at {
        state.store.delete_session(&id).await;
        return None;
    }
    // A session row is never sufficient authority by itself. Re-resolve the owner on every
    // request so account disablement, deletion, and store failures fail closed immediately.
    let active_user = state
        .store
        .get_user(&session.user_sub)
        .await
        .is_some_and(|user| !user.disabled);
    if !active_user {
        state.store.delete_session(&id).await;
        return None;
    }
    // Best-effort activity tracking: bump `last_seen` at most once a minute so the account
    // page can surface "last active" without a write on every OIDC hop.
    if now.saturating_sub(session.last_seen) >= 60 {
        state.store.touch_session(&id, now).await;
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
        Some(cookie) if !cookie.is_empty() => {
            constant_time_eq(cookie.as_bytes(), submitted.as_bytes())
        }
        _ => false,
    }
}

/// Length-checked constant-time byte comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Parse one `Authorization: Basic base64(client_id:client_secret)` credential.
/// Missing, repeated, non-Basic, oversized, or malformed headers are rejected.
pub fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() || value.len() > 1024 {
        return None;
    }
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded = BASE64_STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

/// SHA-256 hash used for opaque, high-entropy server-side secrets such as PATs and
/// recovery codes. The returned lowercase hex string is safe to persist; callers must
/// never log either the plaintext or this hash.
pub fn secret_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    lower_hex(&digest)
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{b:02x}").expect("writing to String cannot fail");
    }
    out
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
    fn session_binding_matches_cross_language_golden_vector() {
        assert_eq!(
            session_binding("sess_TESTVECTOR_0001"),
            "1e0007c3bba79f5c4f0c6f61e4081ed08ed2e1698268a86eaf96ebe903dd4b7f"
        );
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
