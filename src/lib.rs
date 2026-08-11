//! Keystone v0 — OIDC/OAuth2 authorization server (authorization_code + PKCE S256).
//!
//! Library root: defines [`AppState`], wires all six routes via [`app`], and
//! provides [`build_dev_state`] (seeded store + generated signing key). The
//! integration test consumes [`app`] directly via `tower::oneshot`.

pub mod audit;
pub mod auth;
pub mod config;
pub mod email;
pub mod error;
pub mod handlers;
pub mod jwt;
pub mod keys;
pub mod pkce;
pub mod ratelimit;
pub mod store;
pub mod tls;
pub mod totp;
pub mod webauthn;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use webauthn_rs::Webauthn;

use crate::audit::AuditSink;
use crate::config::Config;
use crate::email::EmailSink;
use crate::keys::SigningKey;
use crate::ratelimit::RateLimiter;
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub keys: Arc<SigningKey>,
    /// WebAuthn relying party (rp_id / rp_origin), shared read-only.
    pub webauthn: Arc<Webauthn>,
    /// Non-blocking, fire-and-forget audit emitter -> Watchtower. Disabled (no-op) by
    /// default; enabled when `AUDIT_ENABLED` is on with a `WATCHTOWER_URL` + ingest token.
    pub audit: AuditSink,
    /// Non-blocking, fire-and-forget transactional email emitter -> Corvid. Disabled
    /// (log + skip) by default; enabled when `CORVID_SEND_URL` + `MAIL_SEND_TOKEN` are set.
    pub email: EmailSink,
    /// Per-IP token bucket throttling abuse-prone public POSTs (register / forgot).
    pub rate_limiter: Arc<RateLimiter>,
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
        .route(
            "/authorize/consent",
            post(handlers::authorize::consent_submit),
        )
        .route("/token", post(handlers::token::token))
        .route("/userinfo", get(handlers::userinfo::userinfo))
        .route(
            "/internal/v1/pats/introspect",
            post(handlers::introspect::introspect)
                .layer(DefaultBodyLimit::max(
                    handlers::introspect::MAX_INTROSPECTION_FORM_LEN,
                ))
                .layer(axum::middleware::from_fn(
                    handlers::introspect::privacy_headers,
                )),
        )
        .route(
            "/internal/v1/jml/subjects/lifecycle",
            post(handlers::lifecycle::apply_lifecycle)
                .layer(DefaultBodyLimit::max(
                    handlers::lifecycle::MAX_LIFECYCLE_JSON_LEN,
                ))
                .layer(axum::middleware::from_fn(
                    handlers::lifecycle::privacy_headers,
                )),
        )
        .route(
            "/internal/v1/session-assurance",
            post(handlers::assurance::lookup)
                .layer(DefaultBodyLimit::max(
                    handlers::assurance::MAX_ASSURANCE_JSON_LEN,
                ))
                .layer(axum::middleware::from_fn(
                    handlers::lifecycle::privacy_headers,
                )),
        )
        .route(
            "/internal/v1/identity/registration/snapshot",
            post(handlers::registration::create_snapshot)
                .layer(DefaultBodyLimit::max(
                    handlers::registration::MAX_REGISTRATION_JSON_LEN,
                ))
                .layer(axum::middleware::from_fn(
                    handlers::registration::privacy_headers,
                )),
        )
        .route(
            "/internal/v1/identity/registration/snapshot/{snapshot_id}",
            get(handlers::registration::snapshot_page).layer(axum::middleware::from_fn(
                handlers::registration::privacy_headers,
            )),
        )
        .route(
            "/internal/v1/identity/registration/changes",
            get(handlers::registration::changes).layer(axum::middleware::from_fn(
                handlers::registration::privacy_headers,
            )),
        )
        .route(
            "/internal/v1/identity/registration/ack",
            post(handlers::registration::acknowledge)
                .layer(DefaultBodyLimit::max(
                    handlers::registration::MAX_REGISTRATION_JSON_LEN,
                ))
                .layer(axum::middleware::from_fn(
                    handlers::registration::privacy_headers,
                )),
        )
        // --- Login surface ---
        .route("/", get(handlers::login::root_redirect))
        .route(
            "/login",
            get(handlers::login::login_page).post(handlers::login::login_submit),
        )
        .route("/login/totp", post(handlers::login::totp_login_submit))
        .route("/account", get(handlers::login::account_page))
        .route(
            "/account/mfa/totp/enroll",
            post(handlers::login::totp_enroll),
        )
        .route(
            "/account/mfa/totp/verify",
            post(handlers::login::totp_verify),
        )
        .route(
            "/account/mfa/totp/disable",
            post(handlers::login::totp_disable),
        )
        .route("/account/tokens/create", post(handlers::login::pat_create))
        .route("/account/tokens/revoke", post(handlers::login::pat_revoke))
        .route(
            "/account/password",
            post(handlers::register::change_password),
        )
        .route("/logout", post(handlers::login::logout))
        .route(
            "/account/sessions/revoke",
            post(handlers::login::revoke_session),
        )
        .route(
            "/account/sessions/revoke-all",
            post(handlers::login::revoke_other_sessions),
        )
        // --- Operator admin console (session + is_admin gated) ---
        .route("/admin", get(handlers::admin::admin_page))
        .route("/admin/users/disable", post(handlers::admin::disable_user))
        .route("/admin/users/enable", post(handlers::admin::enable_user))
        .route("/admin/users/reset", post(handlers::admin::force_reset))
        .route(
            "/admin/users/revoke-sessions",
            post(handlers::admin::revoke_user_sessions),
        )
        .route(
            "/admin/users/toggle-admin",
            post(handlers::admin::toggle_admin),
        )
        // --- Public self-service identity lifecycle ---
        .route(
            "/register",
            get(handlers::register::register_page).post(handlers::register::register_submit),
        )
        .route("/verify", get(handlers::register::verify))
        .route(
            "/forgot",
            get(handlers::register::forgot_page).post(handlers::register::forgot_submit),
        )
        .route(
            "/reset",
            get(handlers::register::reset_page).post(handlers::register::reset_submit),
        )
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

/// Loopback-only liveness router. The plaintext health listener deliberately does not mount
/// any OIDC or `/internal` route, so registration-feed requests can only reach the mTLS app.
pub fn health_app() -> Router {
    Router::new().route("/healthz", get(handlers::discovery::healthz))
}

/// Construct dev state: dev [`Config`], a seeded [`InMemoryStore`], and a freshly
/// generated [`SigningKey`]. Used by `main` and by the integration test.
pub fn build_dev_state() -> AppState {
    let config = Config::dev();
    let store = InMemoryStore::new();
    store.seed_client(config::seed_client());
    store.put_user(config::seed_user());

    let webauthn = webauthn::build(&config.webauthn_rp_id, &config.webauthn_rp_origin)
        .expect("dev WebAuthn config is valid");

    AppState {
        config: Arc::new(config),
        store: Arc::new(store),
        keys: Arc::new(SigningKey::generate()),
        webauthn: Arc::new(webauthn),
        // Dev/test default: audit OFF (no-op sink) — unchanged behavior.
        audit: AuditSink::disabled(),
        // Dev/test default: email OFF (log + skip) — registration/reset still succeed.
        email: EmailSink::disabled(),
        // Register/forgot throttle: 5 requests per IP per hour.
        rate_limiter: Arc::new(RateLimiter::new(5, 3600)),
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
                // SQLx constraint errors can include the complete failing row. Migration
                // repair touches PAT rows, so never propagate database details to startup
                // logs where a token lookup hash could be disclosed.
                .map_err(|_| "run migrations: database error".to_string())?;
            pg.seed(&config::seed_client(), &config::seed_user())
                .await
                .map_err(|e| format!("seed dev client/user: {e}"))?;
            tracing::info!("postgres store ready (migrated + seeded)");
            Arc::new(pg)
        }
        "memory" => {
            let mem = InMemoryStore::new();
            mem.seed_client(config::seed_client());
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
        match store.get_user(config::SEED_USER_SUB).await {
            Some(user) if user.password_hash.is_none() => {
                let hash = auth::hash_password(password)
                    .map_err(|e| format!("hash bootstrap admin password: {e}"))?;
                store.set_password_hash(config::SEED_USER_SUB, &hash).await;
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
        let hash =
            auth::hash_password(secret).map_err(|e| format!("hash gateway client secret: {e}"))?;
        store.put_client(config::gw_client(&config, hash)).await;
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

    // Non-blocking audit emitter. Built from config BEFORE `config` is moved into the Arc.
    // When AUDIT_ENABLED is off (default) this is a no-op sink and nothing is spawned.
    let audit = AuditSink::start(
        config.audit_enabled,
        &config.watchtower_url,
        config.audit_ingest_token.as_deref(),
    );

    // Non-blocking transactional email emitter. Built before `config` is moved into the Arc.
    // Disabled (log + skip) unless both CORVID_SEND_URL and MAIL_SEND_TOKEN are set.
    let email = EmailSink::start(
        config.corvid_send_url.as_deref(),
        config.mail_send_token.as_deref(),
    );

    Ok(AppState {
        config: Arc::new(config),
        store,
        keys: Arc::new(keys),
        webauthn: Arc::new(webauthn),
        audit,
        email,
        rate_limiter: Arc::new(RateLimiter::new(5, 3600)),
    })
}

/// Current wall-clock time in epoch seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}
