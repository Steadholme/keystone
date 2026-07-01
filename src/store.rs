//! Storage abstraction + models.
//!
//! `Store` is a small trait with an in-memory and a PostgreSQL implementation.
//! Handlers depend only on the trait, never on a concrete store type, so a
//! FusionDB-backed implementation can drop in later without touching handlers.
//!
//! The login layer adds four persisted concerns behind the same seam: a nullable
//! `password_hash` on the user, server-side `sessions`, WebAuthn `credentials`
//! (serialised Passkeys), and short-lived WebAuthn ceremony `states`. All use the
//! same portable-SQL discipline as the v0 OAuth tables.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::now_secs;

/// Registered client. `redirect_uris` is an EXACT-match list. `client_secret_hash`
/// distinguishes the two client kinds:
/// - `None`  -> PUBLIC client (PKCE-only, no secret) — e.g. `sluice-dev`. Unchanged.
/// - `Some(_)` -> CONFIDENTIAL client: `/token` MUST verify a presented client secret
///   against this Argon2id hash (constant-time) — e.g. the `sluice-gw` gateway RP.
#[derive(Clone, Debug)]
pub struct Client {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub name: String,
    /// Argon2id PHC hash of the client secret. `None` = public client (no secret).
    pub client_secret_hash: Option<String>,
}

impl Client {
    /// EXACT (not prefix) redirect_uri match — never redirect to an untrusted URI.
    pub fn allows_redirect(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }

    /// A confidential client carries a secret hash and must authenticate at `/token`.
    pub fn is_confidential(&self) -> bool {
        self.client_secret_hash.is_some()
    }
}

/// End user. Stable subject id + email, plus an optional Argon2 password hash
/// (PHC string; `None` until a password is set).
///
/// `email_verified` gates password login for the public self-service lifecycle: a user
/// created via `POST /register` starts unverified and cannot complete a password login
/// until they click the emailed verification link. `created_at` is the epoch-seconds
/// registration time (`0` for rows that predate the column — those are backfilled to
/// verified on migration so seeded/manual accounts are never locked out).
#[derive(Clone, Debug)]
pub struct User {
    pub sub: String,
    pub email: String,
    pub password_hash: Option<String>,
    pub email_verified: bool,
    pub created_at: u64,
}

/// A single-use email verification / password-reset token. `kind` is `"verify"` (email
/// confirmation) or `"reset"` (password reset). Consumed by delete-on-take, mirroring the
/// authorization-code single-use pattern; `expires_at` is enforced inside the take.
#[derive(Clone, Debug)]
pub struct VerificationToken {
    pub token: String,
    pub sub: String,
    pub kind: String,
    pub expires_at: u64,
}

/// Outcome of a self-service `create_user`. The `EmailTaken` variant surfaces the
/// `UNIQUE(email)` conflict as a typed value so the handler can render a friendly error
/// (without leaking hard existence) instead of a generic 500.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateUserError {
    /// The email is already registered.
    EmailTaken,
    /// A storage backend failure (logged at the store layer).
    Backend,
}

/// A server-side login session. The opaque `id` is what the signed `__Host-session`
/// cookie carries; everything else is authoritative state held here.
#[derive(Clone, Debug)]
pub struct Session {
    pub id: String,
    pub user_sub: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// `User-Agent` captured at sign-in (best-effort device label). Empty when unknown.
    pub user_agent: String,
    /// Forwarded client IP captured at sign-in. Empty/`unknown` when not resolvable.
    pub ip: String,
    /// Unix seconds of the last time this session was seen active. `0` = never touched.
    pub last_seen: u64,
}

/// A registered WebAuthn passkey. `passkey` is the serde-JSON of webauthn-rs' `Passkey`
/// (the authoritative credential, including the signature counter we bump on each auth).
#[derive(Clone, Debug)]
pub struct Credential {
    pub cred_id: String,
    pub user_sub: String,
    pub passkey: String,
    pub created_at: u64,
}

/// Short-lived server-side state for an in-flight WebAuthn ceremony. `state` is the
/// serde-JSON of `PasskeyRegistration` or `PasskeyAuthentication`; `kind` is `"reg"`/`"auth"`.
#[derive(Clone, Debug)]
pub struct WebauthnState {
    pub id: String,
    pub kind: String,
    pub state: String,
    pub expires_at: u64,
}

/// A bound, single-use authorization code. Minted at `/authorize`, consumed at `/token`.
#[derive(Clone, Debug)]
pub struct AuthCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    /// PKCE S256 challenge — always present in v0.
    pub code_challenge: String,
    pub sub: String,
    /// Absolute expiry, epoch seconds (~60s TTL).
    pub expires_at: u64,
    /// Single-use marker (consumption is enforced by atomic removal in `take_code`).
    pub used: bool,
}

/// Pluggable storage. Methods are `async`: the axum handlers `.await` them directly on the
/// serving runtime, so a DB round-trip never blocks a worker thread. The in-memory impl holds
/// its `std::sync::Mutex` guards only across synchronous critical sections (no `.await` inside),
/// so a guard is never held across a yield point.
#[async_trait]
pub trait Store: Send + Sync {
    async fn get_client(&self, client_id: &str) -> Option<Client>;
    /// Insert or replace a client (incl. its redirect URIs + optional secret hash).
    /// Idempotent UPSERT — used to seed the confidential gateway client at startup.
    async fn put_client(&self, client: Client);
    async fn get_user(&self, sub: &str) -> Option<User>;
    /// Resolve a user by login name: matches the subject id OR the email (exact).
    async fn get_user_by_username(&self, username: &str) -> Option<User>;
    /// Set (or replace) a user's Argon2 password hash.
    async fn set_password_hash(&self, sub: &str, hash: &str);
    /// Create a self-service user (`email_verified=false`). Returns [`CreateUserError::EmailTaken`]
    /// on the `UNIQUE(email)` conflict so registration can render a friendly, non-leaking error.
    async fn create_user(
        &self,
        sub: &str,
        email: &str,
        password_hash: &str,
        created_at: u64,
    ) -> Result<(), CreateUserError>;
    /// Mark a user's email as verified (idempotent).
    async fn set_email_verified(&self, sub: &str);

    /// Store a single-use verification/reset token.
    async fn put_verification_token(&self, token: VerificationToken);
    /// Atomically remove and return `(sub, kind)` for a still-valid token; `None` when the
    /// token is absent, already consumed, or expired (single-use, mirrors [`Store::take_code`]).
    async fn take_verification_token(&self, token: &str) -> Option<(String, String)>;

    async fn put_code(&self, code: AuthCode);
    /// Atomically remove and return the code (single-use consume); `None` if absent.
    async fn take_code(&self, code: &str) -> Option<AuthCode>;

    async fn put_session(&self, session: Session);
    async fn get_session(&self, id: &str) -> Option<Session>;
    async fn delete_session(&self, id: &str);
    /// All non-expired sessions for a user, newest first (drives the account page).
    async fn list_sessions(&self, user_sub: &str) -> Vec<Session>;
    /// Delete session `id` only if it belongs to `user_sub` (revoke one device).
    async fn revoke_session(&self, user_sub: &str, id: &str);
    /// Delete every session for `user_sub` except `keep_id` (log out all other devices).
    async fn revoke_other_sessions(&self, user_sub: &str, keep_id: &str);
    /// Bump `last_seen` for an active session (best-effort activity tracking).
    async fn touch_session(&self, id: &str, last_seen: u64);

    async fn put_credential(&self, cred: Credential);
    /// All passkeys registered to a user (for authentication + exclude lists).
    async fn list_credentials(&self, user_sub: &str) -> Vec<Credential>;
    /// One credential by its id (resolves the owning user during passwordless auth).
    async fn get_credential(&self, cred_id: &str) -> Option<Credential>;
    /// Replace a credential's serialised passkey (counter update after each auth).
    async fn update_credential_passkey(&self, cred_id: &str, passkey: &str);

    async fn put_state(&self, state: WebauthnState);
    /// Atomically remove and return ceremony state (single-use); `None` if absent.
    async fn take_state(&self, id: &str) -> Option<WebauthnState>;
}

/// In-memory `Store`. `std::sync::Mutex<HashMap>` — no async lock needed.
#[derive(Default)]
pub struct InMemoryStore {
    clients: Mutex<HashMap<String, Client>>,
    users: Mutex<HashMap<String, User>>,
    codes: Mutex<HashMap<String, AuthCode>>,
    sessions: Mutex<HashMap<String, Session>>,
    credentials: Mutex<HashMap<String, Credential>>,
    states: Mutex<HashMap<String, WebauthnState>>,
    verification_tokens: Mutex<HashMap<String, VerificationToken>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a user (startup only).
    pub fn put_user(&self, user: User) {
        self.users
            .lock()
            .expect("users lock poisoned")
            .insert(user.sub.clone(), user);
    }

    /// Seed a client (startup only). Inherent + synchronous (parallel to [`Self::put_user`])
    /// so the sync `build_dev_state` constructor can populate the in-memory store without
    /// entering the async `Store` trait. Runtime / `Arc<dyn Store>` paths use the trait method.
    pub fn seed_client(&self, client: Client) {
        self.clients
            .lock()
            .expect("clients lock poisoned")
            .insert(client.client_id.clone(), client);
    }
}

// The `std::sync::Mutex` guards below are fine under `#[async_trait]`: every critical section
// is fully synchronous (no `.await` inside), so a guard is never held across a yield point and
// the generated futures stay `Send`.
#[async_trait]
impl Store for InMemoryStore {
    async fn get_client(&self, client_id: &str) -> Option<Client> {
        self.clients
            .lock()
            .expect("clients lock poisoned")
            .get(client_id)
            .cloned()
    }

    async fn put_client(&self, client: Client) {
        self.clients
            .lock()
            .expect("clients lock poisoned")
            .insert(client.client_id.clone(), client);
    }

    async fn get_user(&self, sub: &str) -> Option<User> {
        self.users
            .lock()
            .expect("users lock poisoned")
            .get(sub)
            .cloned()
    }

    async fn get_user_by_username(&self, username: &str) -> Option<User> {
        self.users
            .lock()
            .expect("users lock poisoned")
            .values()
            .find(|u| u.sub == username || u.email == username)
            .cloned()
    }

    async fn set_password_hash(&self, sub: &str, hash: &str) {
        if let Some(user) = self.users.lock().expect("users lock poisoned").get_mut(sub) {
            user.password_hash = Some(hash.to_string());
        }
    }

    async fn create_user(
        &self,
        sub: &str,
        email: &str,
        password_hash: &str,
        created_at: u64,
    ) -> Result<(), CreateUserError> {
        let mut users = self.users.lock().expect("users lock poisoned");
        if users.values().any(|u| u.email == email) {
            return Err(CreateUserError::EmailTaken);
        }
        users.insert(
            sub.to_string(),
            User {
                sub: sub.to_string(),
                email: email.to_string(),
                password_hash: Some(password_hash.to_string()),
                email_verified: false,
                created_at,
            },
        );
        Ok(())
    }

    async fn set_email_verified(&self, sub: &str) {
        if let Some(user) = self.users.lock().expect("users lock poisoned").get_mut(sub) {
            user.email_verified = true;
        }
    }

    async fn put_verification_token(&self, token: VerificationToken) {
        self.verification_tokens
            .lock()
            .expect("verification_tokens lock poisoned")
            .insert(token.token.clone(), token);
    }

    async fn take_verification_token(&self, token: &str) -> Option<(String, String)> {
        let rec = self
            .verification_tokens
            .lock()
            .expect("verification_tokens lock poisoned")
            .remove(token)?;
        if now_secs() > rec.expires_at {
            return None;
        }
        Some((rec.sub, rec.kind))
    }

    async fn put_code(&self, code: AuthCode) {
        self.codes
            .lock()
            .expect("codes lock poisoned")
            .insert(code.code.clone(), code);
    }

    async fn take_code(&self, code: &str) -> Option<AuthCode> {
        self.codes.lock().expect("codes lock poisoned").remove(code)
    }

    async fn put_session(&self, session: Session) {
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .insert(session.id.clone(), session);
    }

    async fn get_session(&self, id: &str) -> Option<Session> {
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .get(id)
            .cloned()
    }

    async fn delete_session(&self, id: &str) {
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .remove(id);
    }

    async fn list_sessions(&self, user_sub: &str) -> Vec<Session> {
        let now = now_secs();
        let mut v: Vec<Session> = self
            .sessions
            .lock()
            .expect("sessions lock poisoned")
            .values()
            .filter(|s| s.user_sub == user_sub && s.expires_at > now)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        v
    }

    async fn revoke_session(&self, user_sub: &str, id: &str) {
        let mut g = self.sessions.lock().expect("sessions lock poisoned");
        // Ownership check: never let one user delete another user's session id.
        if g.get(id).is_some_and(|s| s.user_sub == user_sub) {
            g.remove(id);
        }
    }

    async fn revoke_other_sessions(&self, user_sub: &str, keep_id: &str) {
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .retain(|id, s| s.user_sub != user_sub || id == keep_id);
    }

    async fn touch_session(&self, id: &str, last_seen: u64) {
        if let Some(s) = self
            .sessions
            .lock()
            .expect("sessions lock poisoned")
            .get_mut(id)
        {
            s.last_seen = last_seen;
        }
    }

    async fn put_credential(&self, cred: Credential) {
        self.credentials
            .lock()
            .expect("credentials lock poisoned")
            .insert(cred.cred_id.clone(), cred);
    }

    async fn list_credentials(&self, user_sub: &str) -> Vec<Credential> {
        self.credentials
            .lock()
            .expect("credentials lock poisoned")
            .values()
            .filter(|c| c.user_sub == user_sub)
            .cloned()
            .collect()
    }

    async fn get_credential(&self, cred_id: &str) -> Option<Credential> {
        self.credentials
            .lock()
            .expect("credentials lock poisoned")
            .get(cred_id)
            .cloned()
    }

    async fn update_credential_passkey(&self, cred_id: &str, passkey: &str) {
        if let Some(cred) = self
            .credentials
            .lock()
            .expect("credentials lock poisoned")
            .get_mut(cred_id)
        {
            cred.passkey = passkey.to_string();
        }
    }

    async fn put_state(&self, state: WebauthnState) {
        self.states
            .lock()
            .expect("states lock poisoned")
            .insert(state.id.clone(), state);
    }

    async fn take_state(&self, id: &str) -> Option<WebauthnState> {
        self.states.lock().expect("states lock poisoned").remove(id)
    }
}

// ----------------------------------------------------------------------------
// PostgreSQL-backed `Store` (portable: standard SQL, runtime queries, no macros).
// ----------------------------------------------------------------------------
//
// Selected at runtime by `KEYSTONE_STORE=postgres`. Uses ONLY portable SQL so the
// same layer later runs unchanged on FusionDB over pgwire: TEXT/BIGINT columns,
// plain PRIMARY KEY/UNIQUE/NOT NULL constraints, parameterized queries, UPSERT via
// `INSERT ... ON CONFLICT`, and a child table (`client_redirect_uris`) instead of an
// array/JSON column. Single-use codes/states are enforced by delete-on-consume.
//
// The `Store` trait is async, so each method drives sqlx natively and the handlers `.await`
// it on the serving runtime — there is NO `block_in_place` and NO sync-over-async bridge, so a
// DB round-trip never blocks a worker thread.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds a `PgPool`; the async trait methods drive sqlx natively,
/// so no worker thread is ever blocked on a DB round-trip.
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Idempotent, portable migrations. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS oauth_clients (\
                 client_id TEXT PRIMARY KEY, \
                 name TEXT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Additive, idempotent column for confidential clients (Argon2id secret hash).
        // NULL = public client (PKCE-only); older DBs predate this column.
        sqlx::query("ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS client_secret_hash TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS client_redirect_uris (\
                 client_id TEXT NOT NULL, \
                 redirect_uri TEXT NOT NULL, \
                 PRIMARY KEY (client_id, redirect_uri)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (\
                 sub TEXT PRIMARY KEY, \
                 email TEXT NOT NULL UNIQUE\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Additive, idempotent column for the password fallback (older DBs predate it).
        sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT")
            .execute(&self.pool)
            .await?;
        // Additive, idempotent columns for the public self-service identity lifecycle.
        sqlx::query(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at BIGINT NOT NULL DEFAULT 0")
            .execute(&self.pool)
            .await?;
        // CRITICAL backfill: rows that predate `email_verified` (created_at still 0 — seeded or
        // manually provisioned accounts like u_admin/w33d) are trusted and MUST stay able to log
        // in. Flip them to verified once, right after the ALTERs. Idempotent: re-running only
        // re-touches those same legacy rows (self-service users carry a real created_at > 0).
        sqlx::query("UPDATE users SET email_verified = true WHERE created_at = 0")
            .execute(&self.pool)
            .await?;
        // Single-use verification/reset tokens (delete-on-consume, mirrors auth_codes).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS verification_tokens (\
                 token TEXT PRIMARY KEY, \
                 sub TEXT NOT NULL, \
                 kind TEXT NOT NULL, \
                 expires_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS auth_codes (\
                 code TEXT PRIMARY KEY, \
                 client_id TEXT NOT NULL, \
                 redirect_uri TEXT NOT NULL, \
                 code_challenge TEXT NOT NULL, \
                 sub TEXT NOT NULL, \
                 nonce TEXT, \
                 scope TEXT NOT NULL, \
                 expires_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sessions (\
                 id TEXT PRIMARY KEY, \
                 user_sub TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 expires_at BIGINT NOT NULL, \
                 user_agent TEXT NOT NULL DEFAULT '', \
                 ip TEXT NOT NULL DEFAULT '', \
                 last_seen BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Session metadata columns are additive: back-fill onto pre-existing tables so the
        // account page can render device/IP/last-seen for sessions minted before this change.
        sqlx::query("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT ''")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip TEXT NOT NULL DEFAULT ''")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen BIGINT NOT NULL DEFAULT 0")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS webauthn_credentials (\
                 cred_id TEXT PRIMARY KEY, \
                 user_sub TEXT NOT NULL, \
                 passkey TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS webauthn_states (\
                 id TEXT PRIMARY KEY, \
                 kind TEXT NOT NULL, \
                 state TEXT NOT NULL, \
                 expires_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Idempotent UPSERT seed of the dev client (+ its redirect URIs) and user.
    /// Password hash is intentionally NOT touched here (seeded separately, once).
    pub async fn seed(&self, client: &Client, user: &User) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, name) VALUES ($1, $2) \
             ON CONFLICT (client_id) DO UPDATE SET name = EXCLUDED.name",
        )
        .bind(&client.client_id)
        .bind(&client.name)
        .execute(&self.pool)
        .await?;
        for uri in &client.redirect_uris {
            sqlx::query(
                "INSERT INTO client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2) \
                 ON CONFLICT (client_id, redirect_uri) DO NOTHING",
            )
            .bind(&client.client_id)
            .bind(uri)
            .execute(&self.pool)
            .await?;
        }
        // Seed the admin as verified (created_at=0) — a trusted, pre-provisioned account that
        // must be able to log in on a brand-new database, before any backfill has rows to touch.
        sqlx::query(
            "INSERT INTO users (sub, email, email_verified, created_at) VALUES ($1, $2, true, 0) \
             ON CONFLICT (sub) DO UPDATE SET email = EXCLUDED.email",
        )
        .bind(&user.sub)
        .bind(&user.email)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_client_async(&self, client_id: &str) -> Result<Option<Client>, sqlx::Error> {
        let row = sqlx::query("SELECT name, client_secret_hash FROM oauth_clients WHERE client_id = $1")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else { return Ok(None) };
        let name: String = row.try_get("name")?;
        let client_secret_hash: Option<String> = row.try_get("client_secret_hash")?;
        let uri_rows = sqlx::query(
            "SELECT redirect_uri FROM client_redirect_uris WHERE client_id = $1 \
             ORDER BY redirect_uri",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await?;
        let mut redirect_uris = Vec::with_capacity(uri_rows.len());
        for r in &uri_rows {
            redirect_uris.push(r.try_get::<String, _>("redirect_uri")?);
        }
        Ok(Some(Client {
            client_id: client_id.to_string(),
            redirect_uris,
            name,
            client_secret_hash,
        }))
    }

    /// Idempotent UPSERT of a client (name + secret hash) and its redirect URIs.
    async fn put_client_async(&self, c: &Client) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, name, client_secret_hash) VALUES ($1, $2, $3) \
             ON CONFLICT (client_id) DO UPDATE SET name = EXCLUDED.name, \
             client_secret_hash = EXCLUDED.client_secret_hash",
        )
        .bind(&c.client_id)
        .bind(&c.name)
        .bind(c.client_secret_hash.as_deref())
        .execute(&self.pool)
        .await?;
        for uri in &c.redirect_uris {
            sqlx::query(
                "INSERT INTO client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2) \
                 ON CONFLICT (client_id, redirect_uri) DO NOTHING",
            )
            .bind(&c.client_id)
            .bind(uri)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    fn user_from_row(row: &sqlx::postgres::PgRow) -> Result<User, sqlx::Error> {
        let created_at: i64 = row.try_get("created_at")?;
        Ok(User {
            sub: row.try_get("sub")?,
            email: row.try_get("email")?,
            password_hash: row.try_get("password_hash")?,
            email_verified: row.try_get("email_verified")?,
            created_at: created_at as u64,
        })
    }

    fn session_from_row(row: &sqlx::postgres::PgRow) -> Result<Session, sqlx::Error> {
        let created_at: i64 = row.try_get("created_at")?;
        let expires_at: i64 = row.try_get("expires_at")?;
        let last_seen: i64 = row.try_get("last_seen")?;
        Ok(Session {
            id: row.try_get("id")?,
            user_sub: row.try_get("user_sub")?,
            created_at: created_at as u64,
            expires_at: expires_at as u64,
            user_agent: row.try_get("user_agent")?,
            ip: row.try_get("ip")?,
            last_seen: last_seen as u64,
        })
    }

    async fn get_user_async(&self, sub: &str) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT sub, email, password_hash, email_verified, created_at FROM users WHERE sub = $1",
        )
        .bind(sub)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::user_from_row).transpose()
    }

    async fn get_user_by_username_async(
        &self,
        username: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT sub, email, password_hash, email_verified, created_at FROM users \
             WHERE sub = $1 OR email = $1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::user_from_row).transpose()
    }

    async fn set_password_hash_async(&self, sub: &str, hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET password_hash = $2 WHERE sub = $1")
            .bind(sub)
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Insert a self-service user (`email_verified=false`). A `UNIQUE(email)` violation is
    /// mapped to [`CreateUserError::EmailTaken`]; any other failure is `Backend` (logged).
    async fn create_user_async(
        &self,
        sub: &str,
        email: &str,
        password_hash: &str,
        created_at: u64,
    ) -> Result<(), CreateUserError> {
        let res = sqlx::query(
            "INSERT INTO users (sub, email, password_hash, email_verified, created_at) \
             VALUES ($1, $2, $3, false, $4)",
        )
        .bind(sub)
        .bind(email)
        .bind(password_hash)
        .bind(created_at as i64)
        .execute(&self.pool)
        .await;
        match res {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.as_database_error()
                    .map(|db| db.is_unique_violation())
                    .unwrap_or(false)
                {
                    Err(CreateUserError::EmailTaken)
                } else {
                    tracing::error!(error = %e, "pg create_user failed");
                    Err(CreateUserError::Backend)
                }
            }
        }
    }

    async fn set_email_verified_async(&self, sub: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET email_verified = true WHERE sub = $1")
            .bind(sub)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn put_verification_token_async(
        &self,
        t: &VerificationToken,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO verification_tokens (token, sub, kind, expires_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (token) DO UPDATE SET sub = EXCLUDED.sub, kind = EXCLUDED.kind, \
             expires_at = EXCLUDED.expires_at",
        )
        .bind(&t.token)
        .bind(&t.sub)
        .bind(&t.kind)
        .bind(t.expires_at as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomic single-use consume of a verification token (read + DELETE in one transaction),
    /// then an expiry check so an expired token is both discarded and reported absent.
    async fn take_verification_token_async(
        &self,
        token: &str,
    ) -> Result<Option<(String, String)>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT sub, kind, expires_at FROM verification_tokens WHERE token = $1",
        )
        .bind(token)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let deleted = sqlx::query("DELETE FROM verification_tokens WHERE token = $1")
            .bind(token)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        if deleted.rows_affected() != 1 {
            return Ok(None);
        }
        let expires_at: i64 = row.try_get("expires_at")?;
        if now_secs() > expires_at as u64 {
            return Ok(None);
        }
        Ok(Some((row.try_get("sub")?, row.try_get("kind")?)))
    }

    async fn put_code_async(&self, code: &AuthCode) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO auth_codes \
                 (code, client_id, redirect_uri, code_challenge, sub, nonce, scope, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&code.code)
        .bind(&code.client_id)
        .bind(&code.redirect_uri)
        .bind(&code.code_challenge)
        .bind(&code.sub)
        .bind(code.nonce.as_deref())
        .bind(&code.scope)
        .bind(code.expires_at as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomic single-use consume: read the row, then DELETE inside one transaction.
    /// If a concurrent consumer won the race the DELETE affects 0 rows and we return
    /// `None`, so a code can be redeemed at most once. No RETURNING / no `FOR UPDATE`
    /// is used, keeping the statement portable across pgwire backends.
    async fn take_code_async(&self, code: &str) -> Result<Option<AuthCode>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT code, client_id, redirect_uri, code_challenge, sub, nonce, scope, expires_at \
             FROM auth_codes WHERE code = $1",
        )
        .bind(code)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let deleted = sqlx::query("DELETE FROM auth_codes WHERE code = $1")
            .bind(code)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        if deleted.rows_affected() != 1 {
            return Ok(None);
        }
        let expires_at: i64 = row.try_get("expires_at")?;
        let nonce: Option<String> = row.try_get("nonce")?;
        Ok(Some(AuthCode {
            code: row.try_get("code")?,
            client_id: row.try_get("client_id")?,
            redirect_uri: row.try_get("redirect_uri")?,
            code_challenge: row.try_get("code_challenge")?,
            sub: row.try_get("sub")?,
            nonce,
            scope: row.try_get("scope")?,
            expires_at: expires_at as u64,
            used: false,
        }))
    }

    async fn put_session_async(&self, s: &Session) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO sessions (id, user_sub, created_at, expires_at, user_agent, ip, last_seen) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (id) DO UPDATE SET user_sub = EXCLUDED.user_sub, \
             created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at, \
             user_agent = EXCLUDED.user_agent, ip = EXCLUDED.ip, last_seen = EXCLUDED.last_seen",
        )
        .bind(&s.id)
        .bind(&s.user_sub)
        .bind(s.created_at as i64)
        .bind(s.expires_at as i64)
        .bind(&s.user_agent)
        .bind(&s.ip)
        .bind(s.last_seen as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_session_async(&self, id: &str) -> Result<Option<Session>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, user_sub, created_at, expires_at, user_agent, ip, last_seen \
             FROM sessions WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(Self::session_from_row(&row)?))
    }

    async fn delete_session_async(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_sessions_async(&self, user_sub: &str) -> Result<Vec<Session>, sqlx::Error> {
        let now = now_secs() as i64;
        let rows = sqlx::query(
            "SELECT id, user_sub, created_at, expires_at, user_agent, ip, last_seen \
             FROM sessions WHERE user_sub = $1 AND expires_at > $2 ORDER BY created_at DESC",
        )
        .bind(user_sub)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::session_from_row).collect()
    }

    async fn revoke_session_async(&self, user_sub: &str, id: &str) -> Result<(), sqlx::Error> {
        // Ownership is enforced in SQL: the row is deleted only when both id and owner match.
        sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_sub = $2")
            .bind(id)
            .bind(user_sub)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn revoke_other_sessions_async(
        &self,
        user_sub: &str,
        keep_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM sessions WHERE user_sub = $1 AND id <> $2")
            .bind(user_sub)
            .bind(keep_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn touch_session_async(&self, id: &str, last_seen: u64) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE sessions SET last_seen = $1 WHERE id = $2")
            .bind(last_seen as i64)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn put_credential_async(&self, c: &Credential) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO webauthn_credentials (cred_id, user_sub, passkey, created_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (cred_id) DO UPDATE SET passkey = EXCLUDED.passkey",
        )
        .bind(&c.cred_id)
        .bind(&c.user_sub)
        .bind(&c.passkey)
        .bind(c.created_at as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn credential_from_row(row: &sqlx::postgres::PgRow) -> Result<Credential, sqlx::Error> {
        let created_at: i64 = row.try_get("created_at")?;
        Ok(Credential {
            cred_id: row.try_get("cred_id")?,
            user_sub: row.try_get("user_sub")?,
            passkey: row.try_get("passkey")?,
            created_at: created_at as u64,
        })
    }

    async fn list_credentials_async(&self, user_sub: &str) -> Result<Vec<Credential>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT cred_id, user_sub, passkey, created_at FROM webauthn_credentials \
             WHERE user_sub = $1 ORDER BY created_at",
        )
        .bind(user_sub)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::credential_from_row).collect()
    }

    async fn get_credential_async(&self, cred_id: &str) -> Result<Option<Credential>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT cred_id, user_sub, passkey, created_at FROM webauthn_credentials \
             WHERE cred_id = $1",
        )
        .bind(cred_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::credential_from_row).transpose()
    }

    async fn update_credential_passkey_async(
        &self,
        cred_id: &str,
        passkey: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE webauthn_credentials SET passkey = $2 WHERE cred_id = $1")
            .bind(cred_id)
            .bind(passkey)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn put_state_async(&self, s: &WebauthnState) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO webauthn_states (id, kind, state, expires_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, state = EXCLUDED.state, \
             expires_at = EXCLUDED.expires_at",
        )
        .bind(&s.id)
        .bind(&s.kind)
        .bind(&s.state)
        .bind(s.expires_at as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomic single-use consume of ceremony state (read + DELETE in one transaction).
    async fn take_state_async(&self, id: &str) -> Result<Option<WebauthnState>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let row =
            sqlx::query("SELECT id, kind, state, expires_at FROM webauthn_states WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let deleted = sqlx::query("DELETE FROM webauthn_states WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        if deleted.rows_affected() != 1 {
            return Ok(None);
        }
        let expires_at: i64 = row.try_get("expires_at")?;
        Ok(Some(WebauthnState {
            id: row.try_get("id")?,
            kind: row.try_get("kind")?,
            state: row.try_get("state")?,
            expires_at: expires_at as u64,
        }))
    }
}

#[async_trait]
impl Store for PgStore {
    async fn get_client(&self, client_id: &str) -> Option<Client> {
        self.get_client_async(client_id)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg get_client failed");
                None
            })
    }

    async fn put_client(&self, client: Client) {
        if let Err(e) = self.put_client_async(&client).await {
            tracing::error!(error = %e, "pg put_client failed");
        }
    }

    async fn get_user(&self, sub: &str) -> Option<User> {
        self.get_user_async(sub).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_user failed");
            None
        })
    }

    async fn get_user_by_username(&self, username: &str) -> Option<User> {
        self.get_user_by_username_async(username)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg get_user_by_username failed");
                None
            })
    }

    async fn set_password_hash(&self, sub: &str, hash: &str) {
        if let Err(e) = self.set_password_hash_async(sub, hash).await {
            tracing::error!(error = %e, "pg set_password_hash failed");
        }
    }

    async fn create_user(
        &self,
        sub: &str,
        email: &str,
        password_hash: &str,
        created_at: u64,
    ) -> Result<(), CreateUserError> {
        self.create_user_async(sub, email, password_hash, created_at)
            .await
    }

    async fn set_email_verified(&self, sub: &str) {
        if let Err(e) = self.set_email_verified_async(sub).await {
            tracing::error!(error = %e, "pg set_email_verified failed");
        }
    }

    async fn put_verification_token(&self, token: VerificationToken) {
        if let Err(e) = self.put_verification_token_async(&token).await {
            tracing::error!(error = %e, "pg put_verification_token failed");
        }
    }

    async fn take_verification_token(&self, token: &str) -> Option<(String, String)> {
        self.take_verification_token_async(token)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg take_verification_token failed");
                None
            })
    }

    async fn put_code(&self, code: AuthCode) {
        if let Err(e) = self.put_code_async(&code).await {
            tracing::error!(error = %e, "pg put_code failed");
        }
    }

    async fn take_code(&self, code: &str) -> Option<AuthCode> {
        self.take_code_async(code).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg take_code failed");
            None
        })
    }

    async fn put_session(&self, session: Session) {
        if let Err(e) = self.put_session_async(&session).await {
            tracing::error!(error = %e, "pg put_session failed");
        }
    }

    async fn get_session(&self, id: &str) -> Option<Session> {
        self.get_session_async(id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_session failed");
            None
        })
    }

    async fn delete_session(&self, id: &str) {
        if let Err(e) = self.delete_session_async(id).await {
            tracing::error!(error = %e, "pg delete_session failed");
        }
    }

    async fn list_sessions(&self, user_sub: &str) -> Vec<Session> {
        self.list_sessions_async(user_sub).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_sessions failed");
            Vec::new()
        })
    }

    async fn revoke_session(&self, user_sub: &str, id: &str) {
        if let Err(e) = self.revoke_session_async(user_sub, id).await {
            tracing::error!(error = %e, "pg revoke_session failed");
        }
    }

    async fn revoke_other_sessions(&self, user_sub: &str, keep_id: &str) {
        if let Err(e) = self.revoke_other_sessions_async(user_sub, keep_id).await {
            tracing::error!(error = %e, "pg revoke_other_sessions failed");
        }
    }

    async fn touch_session(&self, id: &str, last_seen: u64) {
        if let Err(e) = self.touch_session_async(id, last_seen).await {
            tracing::error!(error = %e, "pg touch_session failed");
        }
    }

    async fn put_credential(&self, cred: Credential) {
        if let Err(e) = self.put_credential_async(&cred).await {
            tracing::error!(error = %e, "pg put_credential failed");
        }
    }

    async fn list_credentials(&self, user_sub: &str) -> Vec<Credential> {
        self.list_credentials_async(user_sub)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg list_credentials failed");
                Vec::new()
            })
    }

    async fn get_credential(&self, cred_id: &str) -> Option<Credential> {
        self.get_credential_async(cred_id)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg get_credential failed");
                None
            })
    }

    async fn update_credential_passkey(&self, cred_id: &str, passkey: &str) {
        if let Err(e) = self.update_credential_passkey_async(cred_id, passkey).await {
            tracing::error!(error = %e, "pg update_credential_passkey failed");
        }
    }

    async fn put_state(&self, state: WebauthnState) {
        if let Err(e) = self.put_state_async(&state).await {
            tracing::error!(error = %e, "pg put_state failed");
        }
    }

    async fn take_state(&self, id: &str) -> Option<WebauthnState> {
        self.take_state_async(id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg take_state failed");
            None
        })
    }
}

/// Generate an opaque 32-byte CSPRNG token, base64url-no-pad encoded. Used for
/// authorization codes, session ids, CSRF tokens, and ceremony-state ids.
pub fn new_opaque_code() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
