//! Server configuration and v0 seed data.
//!
//! `issuer` and the derived endpoint URLs live here so the discovery document,
//! JWT `iss` claim, and JWKS `jwks_uri` can never drift apart.

use crate::store::{Client, User};

/// Seed public client id (shared integration contract).
pub const SEED_CLIENT_ID: &str = "sluice-dev";
/// Seed client's single exact-match redirect URI.
pub const SEED_REDIRECT_URI: &str = "http://127.0.0.1:9090/callback";
/// Seed test user subject id (auto-approved at `/authorize` in v0).
pub const SEED_USER_SUB: &str = "u_admin";
/// Seed test user email.
pub const SEED_USER_EMAIL: &str = "admin@holdfast.local";

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
    /// v0 dev-only: subject auto-approved at `/authorize` (no login UI yet — seam).
    pub dev_user_sub: String,
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
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    ///
    /// `ISSUER` and `BIND_ADDR` are overridable; every other value keeps its dev
    /// default when the env var is unset, so the dev contract is unchanged out of
    /// the box. In docker-compose the canonical issuer is the in-network service
    /// name, e.g. `ISSUER=http://keystone:8080` with `BIND_ADDR=0.0.0.0:8080`.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Ok(issuer) = std::env::var("ISSUER") {
            if !issuer.is_empty() {
                config.issuer = issuer;
            }
        }
        if let Ok(bind_addr) = std::env::var("BIND_ADDR") {
            if !bind_addr.is_empty() {
                config.bind_addr = bind_addr;
            }
        }
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

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// The v0 seeded public client.
pub fn seed_client() -> Client {
    Client {
        client_id: SEED_CLIENT_ID.to_string(),
        redirect_uris: vec![SEED_REDIRECT_URI.to_string()],
        name: "Sluice (dev)".to_string(),
    }
}

/// The v0 seeded test user.
pub fn seed_user() -> User {
    User {
        sub: SEED_USER_SUB.to_string(),
        email: SEED_USER_EMAIL.to_string(),
    }
}
