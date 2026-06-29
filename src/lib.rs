//! Keystone v0 — OIDC/OAuth2 authorization server (authorization_code + PKCE S256).
//!
//! Library root: defines [`AppState`], wires all six routes via [`app`], and
//! provides [`build_dev_state`] (seeded store + generated signing key). The
//! integration test consumes [`app`] directly via `tower::oneshot`.

pub mod config;
pub mod error;
pub mod handlers;
pub mod jwt;
pub mod keys;
pub mod pkce;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;

use crate::config::Config;
use crate::keys::SigningKey;
use crate::store::{InMemoryStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub keys: Arc<SigningKey>,
}

/// Build the router wiring all six contract endpoints onto `state`.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::discovery::healthz))
        .route(
            "/.well-known/openid-configuration",
            get(handlers::discovery::openid_configuration),
        )
        .route("/jwks.json", get(handlers::discovery::jwks))
        .route("/authorize", get(handlers::authorize::authorize))
        .route("/token", post(handlers::token::token))
        .route("/userinfo", get(handlers::userinfo::userinfo))
        .with_state(state)
}

/// Construct dev state: dev [`Config`], a seeded [`InMemoryStore`], and a freshly
/// generated [`SigningKey`]. Used by `main` and by the integration test.
pub fn build_dev_state() -> AppState {
    let config = Config::dev();
    let store = InMemoryStore::new();
    store.put_client(config::seed_client());
    store.put_user(config::seed_user());

    AppState {
        config: Arc::new(config),
        store: Arc::new(store),
        keys: Arc::new(SigningKey::generate()),
    }
}

/// Current wall-clock time in epoch seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}
