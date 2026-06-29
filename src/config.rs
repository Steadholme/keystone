//! Server configuration and v0 seed data.
//!
//! `issuer` and the derived endpoint URLs live here so the discovery document,
//! JWT `iss` claim, and JWKS `jwks_uri` can never drift apart. The login layer adds
//! WebAuthn (rp_id / rp_origin), the session secret, the session TTL, and the optional
//! bootstrap admin password — all env-overridable with working dev defaults.

use crate::store::{Client, User};

/// Seed public client id (shared integration contract).
pub const SEED_CLIENT_ID: &str = "sluice-dev";
/// Seed client's legacy exact-match redirect URI (kept for the existing contract tests).
pub const SEED_REDIRECT_URI: &str = "http://127.0.0.1:9090/callback";
/// Public redirect URI for the deployed single-entrypoint Sluice (https://id.w33d.xyz).
pub const SEED_REDIRECT_URI_PUBLIC: &str = "https://id.w33d.xyz/callback";
/// Seed admin subject id.
pub const SEED_USER_SUB: &str = "u_admin";
/// Seed admin email (doubles as a login username).
pub const SEED_USER_EMAIL: &str = "admin@holdfast.local";

/// Default WebAuthn relying-party id — the PARENT domain so passkeys work across
/// future `*.w33d.xyz` services.
pub const DEFAULT_RP_ID: &str = "w33d.xyz";
/// Default WebAuthn relying-party origin — the single public entrypoint.
pub const DEFAULT_RP_ORIGIN: &str = "https://id.w33d.xyz";
/// Dev/test default session secret. Production MUST override via `SESSION_SECRET`.
pub const DEFAULT_SESSION_SECRET: &str = "keystone-dev-session-secret-change-me";

/// Runtime configuration. `bind_addr` and `issuer` follow the shared dev contract.
#[derive(Clone, Debug)]
pub struct Config {
    pub issuer: String,
    pub bind_addr: String,
    /// access_token lifetime, seconds.
    pub access_ttl: u64,
    /// id_token lifetime, seconds.
    pub id_ttl: u64,
    /// authorization code lifetime, seconds.
    pub code_ttl: u64,
    /// Legacy dev seam: subject that the pre-login v0 auto-approved at `/authorize`.
    /// Retained for compatibility; `/authorize` now gates on a real session instead.
    pub dev_user_sub: String,
    /// Optional PEM path for the persisted RSA signing key. When `Some`, the key is
    /// loaded from (or generated into) this file so the `kid` is STABLE across restarts.
    /// When `None`, an ephemeral key is generated each startup (dev/test default).
    pub signing_key_path: Option<String>,
    /// WebAuthn relying-party id (`WEBAUTHN_RP_ID`). Parent domain `w33d.xyz` by default.
    pub webauthn_rp_id: String,
    /// WebAuthn relying-party origin (`WEBAUTHN_RP_ORIGIN`), e.g. `https://id.w33d.xyz`.
    pub webauthn_rp_origin: String,
    /// HMAC key for the `__Host-session` cookie (`SESSION_SECRET`).
    pub session_secret: String,
    /// Session lifetime, seconds (default 8h).
    pub session_ttl: u64,
    /// Optional bootstrap password for the seeded admin (`BOOTSTRAP_ADMIN_PASSWORD`).
    /// Applied once at startup if the admin has no password hash yet.
    pub bootstrap_admin_password: Option<String>,
}

impl Config {
    /// Default development configuration (matches the shared integration contract).
    pub fn dev() -> Self {
        Config {
            issuer: "http://127.0.0.1:8080".to_string(),
            bind_addr: "127.0.0.1:8080".to_string(),
            access_ttl: 3600,
            id_ttl: 3600,
            code_ttl: 60,
            dev_user_sub: SEED_USER_SUB.to_string(),
            signing_key_path: None,
            webauthn_rp_id: DEFAULT_RP_ID.to_string(),
            webauthn_rp_origin: DEFAULT_RP_ORIGIN.to_string(),
            session_secret: DEFAULT_SESSION_SECRET.to_string(),
            session_ttl: 8 * 60 * 60,
            bootstrap_admin_password: None,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    ///
    /// Every value keeps its dev default when the env var is unset/empty, so the dev
    /// contract is unchanged out of the box.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("ISSUER") {
            config.issuer = v;
        }
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("SIGNING_KEY_PATH") {
            config.signing_key_path = Some(v);
        }
        if let Some(v) = env_nonempty("WEBAUTHN_RP_ID") {
            config.webauthn_rp_id = v;
        }
        if let Some(v) = env_nonempty("WEBAUTHN_RP_ORIGIN") {
            config.webauthn_rp_origin = v;
        }
        if let Some(v) = env_nonempty("SESSION_SECRET") {
            config.session_secret = v;
        }
        // BOOTSTRAP_ADMIN_PASSWORD is intentionally NOT trimmed/validated here beyond
        // non-empty; it is applied once at seed time and never logged.
        config.bootstrap_admin_password = env_nonempty("BOOTSTRAP_ADMIN_PASSWORD");
        config
    }

    pub fn authorization_endpoint(&self) -> String {
        format!("{}/authorize", self.issuer)
    }
    pub fn token_endpoint(&self) -> String {
        format!("{}/token", self.issuer)
    }
    pub fn userinfo_endpoint(&self) -> String {
        format!("{}/userinfo", self.issuer)
    }
    pub fn jwks_uri(&self) -> String {
        format!("{}/jwks.json", self.issuer)
    }
}

/// Read an env var, returning `None` when unset OR empty (so empty never clobbers a default).
fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// The v0 seeded public client. Both the legacy loopback redirect (contract tests) and
/// the public `https://id.w33d.xyz/callback` are registered.
pub fn seed_client() -> Client {
    Client {
        client_id: SEED_CLIENT_ID.to_string(),
        redirect_uris: vec![
            SEED_REDIRECT_URI.to_string(),
            SEED_REDIRECT_URI_PUBLIC.to_string(),
        ],
        name: "Sluice (dev)".to_string(),
    }
}

/// The v0 seeded admin user. Password hash is seeded separately from
/// `BOOTSTRAP_ADMIN_PASSWORD` at startup (when set and not already present).
pub fn seed_user() -> User {
    User {
        sub: SEED_USER_SUB.to_string(),
        email: SEED_USER_EMAIL.to_string(),
        password_hash: None,
    }
}
