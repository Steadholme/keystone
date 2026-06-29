//! Keystone v0 — OIDC/OAuth2 authorization server (authorization_code + PKCE S256).
//!
//! Library root: defines [`AppState`], wires all six routes via [`app`], and
//! provides [`build_dev_state`] (seeded store + generated signing key). The
//! integration test consumes [`app`] directly via `tower::oneshot`.

pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod jwt;
pub mod keys;
pub mod pkce;
pub mod store;
pub mod webauthn;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;
use webauthn_rs::Webauthn;

use crate::config::Config;
use crate::keys::SigningKey;
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub keys: Arc<SigningKey>,
    /// WebAuthn relying party (rp_id / rp_origin), shared read-only.
    pub webauthn: Arc<Webauthn>,
}

/// Build the router wiring the OIDC contract endpoints + the login surface onto `state`.
pub fn app(state: AppState) -> Router {
    Router::new()
        // --- OIDC / OAuth2 contract (unchanged wire behavior) ---
        .route("/healthz", get(handlers::discovery::healthz))
        .route(
            "/.well-known/openid-configuration",
            get(handlers::discovery::openid_configuration),
        )
        .route("/jwks.json", get(handlers::discovery::jwks))
        .route("/authorize", get(handlers::authorize::authorize))
        .route("/token", post(handlers::token::token))
        .route("/userinfo", get(handlers::userinfo::userinfo))
        // --- Login surface ---
        .route(
            "/login",
            get(handlers::login::login_page).post(handlers::login::login_submit),
        )
        .route("/account", get(handlers::login::account_page))
        .route("/logout", post(handlers::login::logout))
        .route("/static/{file}", get(handlers::static_assets::serve))
        // --- WebAuthn ceremonies ---
        .route(
            "/webauthn/register/begin",
            post(handlers::webauthn::register_begin),
        )
        .route(
            "/webauthn/register/finish",
            post(handlers::webauthn::register_finish),
        )
        .route(
            "/webauthn/authenticate/begin",
            post(handlers::webauthn::authenticate_begin),
        )
        .route(
            "/webauthn/authenticate/finish",
            post(handlers::webauthn::authenticate_finish),
        )
        .with_state(state)
}

/// Construct dev state: dev [`Config`], a seeded [`InMemoryStore`], and a freshly
/// generated [`SigningKey`]. Used by `main` and by the integration test.
pub fn build_dev_state() -> AppState {
    let config = Config::dev();
    let store = InMemoryStore::new();
    store.put_client(config::seed_client());
    store.put_user(config::seed_user());

    let webauthn = webauthn::build(&config.webauthn_rp_id, &config.webauthn_rp_origin)
        .expect("dev WebAuthn config is valid");

    AppState {
        config: Arc::new(config),
        store: Arc::new(store),
        keys: Arc::new(SigningKey::generate()),
        webauthn: Arc::new(webauthn),
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
        other => {
            return Err(format!(
                "unknown KEYSTONE_STORE={other} (use memory|postgres)"
            ))
        }
    };

    // Bootstrap admin password: if BOOTSTRAP_ADMIN_PASSWORD is set and the seeded admin
    // has no password hash yet, hash it (Argon2id) and UPSERT it. Idempotent across
    // restarts — once a hash exists we never overwrite it from the env.
    if let Some(password) = config.bootstrap_admin_password.as_deref() {
        match store.get_user(config::SEED_USER_SUB) {
            Some(user) if user.password_hash.is_none() => {
                let hash = auth::hash_password(password)
                    .map_err(|e| format!("hash bootstrap admin password: {e}"))?;
                store.set_password_hash(config::SEED_USER_SUB, &hash);
                tracing::info!(sub = %config::SEED_USER_SUB, "bootstrap admin password applied");
            }
            Some(_) => {
                tracing::info!("admin already has a password hash — bootstrap password ignored")
            }
            None => tracing::warn!("seeded admin missing — cannot apply bootstrap password"),
        }
    }

    // Confidential gateway client (Sluice as an OIDC RP). Seeded ONLY when
    // GW_CLIENT_SECRET is set: the secret is Argon2id-hashed and UPSERTed (idempotent
    // across restarts — the env plaintext keeps verifying, and changing it in the env
    // takes effect on the next restart). When unset, no gateway client is seeded so
    // default behavior is unchanged.
    if let Some(secret) = config.gw_client_secret.as_deref() {
        let hash = auth::hash_password(secret)
            .map_err(|e| format!("hash gateway client secret: {e}"))?;
        store.put_client(config::gw_client(&config, hash));
        tracing::info!(
            client_id = %config.gw_client_id,
            redirect_uri = %config.gw_redirect_uri,
            "confidential gateway client seeded"
        );
    }

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
            tracing::warn!(
                "SIGNING_KEY_PATH unset — using EPHEMERAL signing key (kid rotates on restart)"
            );
            SigningKey::generate()
        }
    };

    // WebAuthn relying party — fail loudly on a bad rp_id/origin pairing.
    let webauthn = webauthn::build(&config.webauthn_rp_id, &config.webauthn_rp_origin)
        .map_err(|e| format!("build WebAuthn: {e}"))?;
    tracing::info!(
        rp_id = %config.webauthn_rp_id,
        rp_origin = %config.webauthn_rp_origin,
        "WebAuthn relying party ready"
    );

    Ok(AppState {
        config: Arc::new(config),
        store,
        keys: Arc::new(keys),
        webauthn: Arc::new(webauthn),
    })
}

/// Current wall-clock time in epoch seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}
