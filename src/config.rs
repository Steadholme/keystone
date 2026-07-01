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

/// Default confidential gateway client id — Sluice acting as an OIDC RP with a secret.
pub const DEFAULT_GW_CLIENT_ID: &str = "sluice-gw";
/// Default redirect URI for the confidential gateway's OIDC callback.
pub const DEFAULT_GW_REDIRECT_URI: &str = "https://id.w33d.xyz/_gw/auth/callback";
/// Display name for the confidential gateway client.
pub const GW_CLIENT_NAME: &str = "Sluice Gateway (confidential)";

/// Default WebAuthn relying-party id — the PARENT domain so passkeys work across
/// future `*.w33d.xyz` services.
pub const DEFAULT_RP_ID: &str = "w33d.xyz";
/// Default WebAuthn relying-party origin — the single public entrypoint.
pub const DEFAULT_RP_ORIGIN: &str = "https://id.w33d.xyz";
/// Dev/test default session secret. Production MUST override via `SESSION_SECRET`.
pub const DEFAULT_SESSION_SECRET: &str = "keystone-dev-session-secret-change-me";

/// Default internal mTLS listen address (`INTERNAL_TLS_ADDR`) when `INTERNAL_TLS=on`.
pub const DEFAULT_INTERNAL_TLS_ADDR: &str = "0.0.0.0:8443";
/// Default plaintext loopback health listener (`INTERNAL_HEALTH_ADDR`) used by the
/// docker HEALTHCHECK when internal mTLS is on (so the probe needs no client cert).
pub const DEFAULT_INTERNAL_HEALTH_ADDR: &str = "127.0.0.1:8081";

/// Default Watchtower audit-ingest base URL (`WATCHTOWER_URL`). Internal-only plaintext
/// hop for v0; `/events` is appended by the emitter.
pub const DEFAULT_WATCHTOWER_URL: &str = "http://watchtower:8500";

/// Default public issuer origin (`PUBLIC_ISSUER`) used to build the verification/reset
/// links emailed to users — the browser-facing origin, NOT the internal `issuer`.
pub const DEFAULT_PUBLIC_ISSUER: &str = "https://sso.w33d.xyz";

/// `From` address stamped on every transactional email Keystone sends.
pub const MAIL_FROM: &str = "no-reply@w33d.xyz";

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
    /// Confidential gateway client id (`GW_CLIENT_ID`, default `sluice-gw`).
    pub gw_client_id: String,
    /// Confidential gateway client secret (`GW_CLIENT_SECRET`). When `Some`, the gateway
    /// client is Argon2id-hashed + seeded at startup; when `None`, no gateway client is
    /// seeded (default — unchanged behavior).
    pub gw_client_secret: Option<String>,
    /// Gateway client redirect URI (`GW_REDIRECT_URI`).
    pub gw_redirect_uri: String,
    /// Internal mTLS toggle (`INTERNAL_TLS=on`). Default OFF — plain HTTP on `bind_addr`
    /// exactly as today. When ON, Keystone serves the app over mTLS on
    /// `internal_tls_addr` and a plaintext health listener on `internal_health_addr`.
    pub internal_tls: bool,
    /// mTLS listen address (`INTERNAL_TLS_ADDR`, default `0.0.0.0:8443`).
    pub internal_tls_addr: String,
    /// Server certificate PEM path (`INTERNAL_TLS_CERT`, Keyward-issued, CN/SAN=keystone).
    pub internal_tls_cert: Option<String>,
    /// Server private key PEM path (`INTERNAL_TLS_KEY`).
    pub internal_tls_key: Option<String>,
    /// Client-CA PEM path (`INTERNAL_TLS_CLIENT_CA`, Keyward `root.crt`) used to verify
    /// the client certificate presented by Sluice.
    pub internal_tls_client_ca: Option<String>,
    /// Plaintext loopback health listen address (`INTERNAL_HEALTH_ADDR`,
    /// default `127.0.0.1:8081`) for the docker HEALTHCHECK when mTLS is on.
    pub internal_health_addr: String,
    /// Audit emitter toggle (`AUDIT_ENABLED`). Default OFF — the audit sink is a no-op and
    /// behavior is unchanged. When ON (with a token + URL) auth events are fire-and-forget
    /// emitted to Watchtower.
    pub audit_enabled: bool,
    /// Watchtower audit-ingest base URL (`WATCHTOWER_URL`, default `http://watchtower:8500`).
    pub watchtower_url: String,
    /// Watchtower ingest bearer token (`AUDIT_INGEST_TOKEN`). When `None`, audit stays
    /// disabled even if `AUDIT_ENABLED=on`. Never logged.
    pub audit_ingest_token: Option<String>,
    /// Public issuer origin (`PUBLIC_ISSUER`, default `https://sso.w33d.xyz`) — the base for
    /// the verification/reset links emailed to users (browser-facing, not the internal issuer).
    pub public_issuer: String,
    /// Corvid mail-send endpoint URL (`CORVID_SEND_URL`, e.g. `http://corvid:8800/api/send`).
    /// When `None`, transactional email is logged + skipped (never fails the request path).
    pub corvid_send_url: Option<String>,
    /// Corvid send bearer token (`MAIL_SEND_TOKEN`). When `None`, email stays disabled. Never logged.
    pub mail_send_token: Option<String>,
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
            gw_client_id: DEFAULT_GW_CLIENT_ID.to_string(),
            gw_client_secret: None,
            gw_redirect_uri: DEFAULT_GW_REDIRECT_URI.to_string(),
            internal_tls: false,
            internal_tls_addr: DEFAULT_INTERNAL_TLS_ADDR.to_string(),
            internal_tls_cert: None,
            internal_tls_key: None,
            internal_tls_client_ca: None,
            internal_health_addr: DEFAULT_INTERNAL_HEALTH_ADDR.to_string(),
            audit_enabled: false,
            watchtower_url: DEFAULT_WATCHTOWER_URL.to_string(),
            audit_ingest_token: None,
            public_issuer: DEFAULT_PUBLIC_ISSUER.to_string(),
            corvid_send_url: None,
            mail_send_token: None,
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
        // Confidential gateway client (Sluice as an OIDC RP). Seeded only when a secret
        // is set; the secret is never logged.
        if let Some(v) = env_nonempty("GW_CLIENT_ID") {
            config.gw_client_id = v;
        }
        config.gw_client_secret = env_nonempty("GW_CLIENT_SECRET");
        if let Some(v) = env_nonempty("GW_REDIRECT_URI") {
            config.gw_redirect_uri = v;
        }
        // Internal mTLS (default OFF). Only `on` (case-insensitive) enables it.
        config.internal_tls = std::env::var("INTERNAL_TLS")
            .map(|v| v.eq_ignore_ascii_case("on"))
            .unwrap_or(false);
        if let Some(v) = env_nonempty("INTERNAL_TLS_ADDR") {
            config.internal_tls_addr = v;
        }
        config.internal_tls_cert = env_nonempty("INTERNAL_TLS_CERT");
        config.internal_tls_key = env_nonempty("INTERNAL_TLS_KEY");
        config.internal_tls_client_ca = env_nonempty("INTERNAL_TLS_CLIENT_CA");
        if let Some(v) = env_nonempty("INTERNAL_HEALTH_ADDR") {
            config.internal_health_addr = v;
        }
        // Audit emitter (default OFF). Enabled by `on`/`true`/`1`/`yes` (case-insensitive);
        // anything else (incl. unset) keeps it off so existing tests/dev are unchanged.
        config.audit_enabled = std::env::var("AUDIT_ENABLED")
            .map(|v| {
                let v = v.trim();
                v.eq_ignore_ascii_case("on")
                    || v.eq_ignore_ascii_case("true")
                    || v == "1"
                    || v.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        if let Some(v) = env_nonempty("WATCHTOWER_URL") {
            config.watchtower_url = v;
        }
        // Never logged; only the bearer header to Watchtower carries it.
        config.audit_ingest_token = env_nonempty("AUDIT_INGEST_TOKEN");
        // Public self-service identity lifecycle: browser-facing link base + Corvid mail hop.
        if let Some(v) = env_nonempty("PUBLIC_ISSUER") {
            config.public_issuer = v;
        }
        config.corvid_send_url = env_nonempty("CORVID_SEND_URL");
        // Never logged; only the bearer header to Corvid carries it.
        config.mail_send_token = env_nonempty("MAIL_SEND_TOKEN");
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
        // Public client (PKCE-only) — no secret.
        client_secret_hash: None,
        // First-party: the gateway itself — never prompt for consent.
        first_party: true,
    }
}

/// Build the CONFIDENTIAL gateway client record from config, carrying an
/// already-hashed (Argon2id) client secret. Scopes (openid/email/profile) are not
/// persisted on the client — they flow through `/authorize` and are echoed back —
/// so the record only needs the id, redirect URI, name, and secret hash.
pub fn gw_client(config: &Config, client_secret_hash: String) -> Client {
    Client {
        client_id: config.gw_client_id.clone(),
        redirect_uris: vec![config.gw_redirect_uri.clone()],
        name: GW_CLIENT_NAME.to_string(),
        client_secret_hash: Some(client_secret_hash),
        // First-party: the platform gateway RP — skips the consent screen.
        first_party: true,
    }
}

/// The v0 seeded admin user. Password hash is seeded separately from
/// `BOOTSTRAP_ADMIN_PASSWORD` at startup (when set and not already present).
pub fn seed_user() -> User {
    User {
        sub: SEED_USER_SUB.to_string(),
        email: SEED_USER_EMAIL.to_string(),
        password_hash: None,
        // Trusted pre-provisioned admin: verified so it can log in even before any migration
        // backfill runs. `created_at=0` marks it as predating the self-service lifecycle.
        email_verified: true,
        created_at: 0,
        // Operator account: admin out of the box so `/admin` is reachable from day one.
        is_admin: true,
        disabled: false,
    }
}
