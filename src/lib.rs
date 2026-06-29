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
use crate::store::{InMemoryStore, PgStore, Store};

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

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by
/// `KEYSTONE_STORE`:
/// - `memory` (default): seeded [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run idempotent migrations, UPSERT-seed the
///   dev client + user, and wire the [`PgStore`] behind `Arc<dyn Store>`.
///
/// Returns an error string on misconfiguration (missing `DATABASE_URL`, connect /
/// migrate / seed failure) so `main` can fail loudly instead of serving a broken store.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();
    let store_kind = std::env::var("KEYSTONE_STORE").unwrap_or_else(|_| "memory".to_string());

    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "KEYSTONE_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("KEYSTONE_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migrations: {e}"))?;
            pg.seed(&config::seed_client(), &config::seed_user())
                .await
                .map_err(|e| format!("seed dev client/user: {e}"))?;
            tracing::info!("postgres store ready (migrated + seeded)");
            Arc::new(pg)
        }
        "memory" => {
            let mem = InMemoryStore::new();
            mem.put_client(config::seed_client());
            mem.put_user(config::seed_user());
            Arc::new(mem)
        }
        other => return Err(format!("unknown KEYSTONE_STORE={other} (use memory|postgres)")),
    };

    // SIGNING_KEY_PATH set -> persist/reload the key so the `kid` is stable across
    // restarts (prevents the Sluice 401 gap on a Keystone restart). Unset -> ephemeral
    // key, unchanged dev/test behavior.
    let keys = match config.signing_key_path.as_deref() {
        Some(path) => {
            let key = SigningKey::load_or_generate(std::path::Path::new(path))
                .map_err(|e| format!("load/persist signing key at {path}: {e}"))?;
            tracing::info!(%path, kid = %key.kid, "persisted signing key ready");
            key
        }
        None => {
            tracing::warn!("SIGNING_KEY_PATH unset — using EPHEMERAL signing key (kid rotates on restart)");
            SigningKey::generate()
        }
    };

    Ok(AppState {
        config: Arc::new(config),
        store,
        keys: Arc::new(keys),
    })
}

/// Current wall-clock time in epoch seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}
