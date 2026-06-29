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

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;

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
#[derive(Clone, Debug)]
pub struct User {
    pub sub: String,
    pub email: String,
    pub password_hash: Option<String>,
}

/// A server-side login session. The opaque `id` is what the signed `__Host-session`
/// cookie carries; everything else is authoritative state held here.
#[derive(Clone, Debug)]
pub struct Session {
    pub id: String,
    pub user_sub: String,
    pub created_at: u64,
    pub expires_at: u64,
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

/// Pluggable storage. No `.await` is ever held across the internal lock.
pub trait Store: Send + Sync {
    fn get_client(&self, client_id: &str) -> Option<Client>;
    /// Insert or replace a client (incl. its redirect URIs + optional secret hash).
    /// Idempotent UPSERT — used to seed the confidential gateway client at startup.
    fn put_client(&self, client: Client);
    fn get_user(&self, sub: &str) -> Option<User>;
    /// Resolve a user by login name: matches the subject id OR the email (exact).
    fn get_user_by_username(&self, username: &str) -> Option<User>;
    /// Set (or replace) a user's Argon2 password hash.
    fn set_password_hash(&self, sub: &str, hash: &str);

    fn put_code(&self, code: AuthCode);
    /// Atomically remove and return the code (single-use consume); `None` if absent.
    fn take_code(&self, code: &str) -> Option<AuthCode>;

    fn put_session(&self, session: Session);
    fn get_session(&self, id: &str) -> Option<Session>;
    fn delete_session(&self, id: &str);

    fn put_credential(&self, cred: Credential);
    /// All passkeys registered to a user (for authentication + exclude lists).
    fn list_credentials(&self, user_sub: &str) -> Vec<Credential>;
    /// One credential by its id (resolves the owning user during passwordless auth).
    fn get_credential(&self, cred_id: &str) -> Option<Credential>;
    /// Replace a credential's serialised passkey (counter update after each auth).
    fn update_credential_passkey(&self, cred_id: &str, passkey: &str);

    fn put_state(&self, state: WebauthnState);
    /// Atomically remove and return ceremony state (single-use); `None` if absent.
    fn take_state(&self, id: &str) -> Option<WebauthnState>;
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
}

impl Store for InMemoryStore {
    fn get_client(&self, client_id: &str) -> Option<Client> {
        self.clients
            .lock()
            .expect("clients lock poisoned")
            .get(client_id)
            .cloned()
    }

    fn put_client(&self, client: Client) {
        self.clients
            .lock()
            .expect("clients lock poisoned")
            .insert(client.client_id.clone(), client);
    }

    fn get_user(&self, sub: &str) -> Option<User> {
        self.users
            .lock()
            .expect("users lock poisoned")
            .get(sub)
            .cloned()
    }

    fn get_user_by_username(&self, username: &str) -> Option<User> {
        self.users
            .lock()
            .expect("users lock poisoned")
            .values()
            .find(|u| u.sub == username || u.email == username)
            .cloned()
    }

    fn set_password_hash(&self, sub: &str, hash: &str) {
        if let Some(user) = self.users.lock().expect("users lock poisoned").get_mut(sub) {
            user.password_hash = Some(hash.to_string());
        }
    }

    fn put_code(&self, code: AuthCode) {
        self.codes
            .lock()
            .expect("codes lock poisoned")
            .insert(code.code.clone(), code);
    }

    fn take_code(&self, code: &str) -> Option<AuthCode> {
        self.codes.lock().expect("codes lock poisoned").remove(code)
    }

    fn put_session(&self, session: Session) {
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .insert(session.id.clone(), session);
    }

    fn get_session(&self, id: &str) -> Option<Session> {
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .get(id)
            .cloned()
    }

    fn delete_session(&self, id: &str) {
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .remove(id);
    }

    fn put_credential(&self, cred: Credential) {
        self.credentials
            .lock()
            .expect("credentials lock poisoned")
            .insert(cred.cred_id.clone(), cred);
    }

    fn list_credentials(&self, user_sub: &str) -> Vec<Credential> {
        self.credentials
            .lock()
            .expect("credentials lock poisoned")
            .values()
            .filter(|c| c.user_sub == user_sub)
            .cloned()
            .collect()
    }

    fn get_credential(&self, cred_id: &str) -> Option<Credential> {
        self.credentials
            .lock()
            .expect("credentials lock poisoned")
            .get(cred_id)
            .cloned()
    }

    fn update_credential_passkey(&self, cred_id: &str, passkey: &str) {
        if let Some(cred) = self
            .credentials
            .lock()
            .expect("credentials lock poisoned")
            .get_mut(cred_id)
        {
            cred.passkey = passkey.to_string();
        }
    }

    fn put_state(&self, state: WebauthnState) {
        self.states
            .lock()
            .expect("states lock poisoned")
            .insert(state.id.clone(), state);
    }

    fn take_state(&self, id: &str) -> Option<WebauthnState> {
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
// The `Store` trait is intentionally synchronous (handlers never `.await` the store),
// so each method bridges to async sqlx via `block_in_place` + the runtime `Handle`.
// This requires a multi-threaded Tokio runtime, which production (`#[tokio::main]`)
// and the `multi_thread` integration tests both provide.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds a `PgPool` plus the runtime [`Handle`] used to
/// drive async queries to completion from the synchronous trait methods.
///
/// [`Handle`]: tokio::runtime::Handle
pub struct PgStore {
    pool: PgPool,
    handle: tokio::runtime::Handle,
}

impl PgStore {
    /// Open a pooled connection. Captures the current runtime handle for the
    /// sync→async bridge; must be called from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self {
            pool,
            handle: tokio::runtime::Handle::current(),
        })
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            pool,
            handle: tokio::runtime::Handle::current(),
        }
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
                 expires_at BIGINT NOT NULL\
             )",
        )
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
        sqlx::query(
            "INSERT INTO users (sub, email) VALUES ($1, $2) \
             ON CONFLICT (sub) DO UPDATE SET email = EXCLUDED.email",
        )
        .bind(&user.sub)
        .bind(&user.email)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Drive an async DB op to completion from a synchronous trait method.
    /// `block_in_place` releases the worker so the runtime keeps making progress.
    fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        tokio::task::block_in_place(|| self.handle.block_on(fut))
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
        Ok(User {
            sub: row.try_get("sub")?,
            email: row.try_get("email")?,
            password_hash: row.try_get("password_hash")?,
        })
    }

    async fn get_user_async(&self, sub: &str) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query("SELECT sub, email, password_hash FROM users WHERE sub = $1")
            .bind(sub)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::user_from_row).transpose()
    }

    async fn get_user_by_username_async(
        &self,
        username: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        let row =
            sqlx::query("SELECT sub, email, password_hash FROM users WHERE sub = $1 OR email = $1")
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
            "INSERT INTO sessions (id, user_sub, created_at, expires_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (id) DO UPDATE SET user_sub = EXCLUDED.user_sub, \
             created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at",
        )
        .bind(&s.id)
        .bind(&s.user_sub)
        .bind(s.created_at as i64)
        .bind(s.expires_at as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_session_async(&self, id: &str) -> Result<Option<Session>, sqlx::Error> {
        let row =
            sqlx::query("SELECT id, user_sub, created_at, expires_at FROM sessions WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        let Some(row) = row else { return Ok(None) };
        let created_at: i64 = row.try_get("created_at")?;
        let expires_at: i64 = row.try_get("expires_at")?;
        Ok(Some(Session {
            id: row.try_get("id")?,
            user_sub: row.try_get("user_sub")?,
            created_at: created_at as u64,
            expires_at: expires_at as u64,
        }))
    }

    async fn delete_session_async(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM sessions WHERE id = $1")
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

impl Store for PgStore {
    fn get_client(&self, client_id: &str) -> Option<Client> {
        self.block_on(self.get_client_async(client_id))
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg get_client failed");
                None
            })
    }

    fn put_client(&self, client: Client) {
        if let Err(e) = self.block_on(self.put_client_async(&client)) {
            tracing::error!(error = %e, "pg put_client failed");
        }
    }

    fn get_user(&self, sub: &str) -> Option<User> {
        self.block_on(self.get_user_async(sub)).unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_user failed");
            None
        })
    }

    fn get_user_by_username(&self, username: &str) -> Option<User> {
        self.block_on(self.get_user_by_username_async(username))
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg get_user_by_username failed");
                None
            })
    }

    fn set_password_hash(&self, sub: &str, hash: &str) {
        if let Err(e) = self.block_on(self.set_password_hash_async(sub, hash)) {
            tracing::error!(error = %e, "pg set_password_hash failed");
        }
    }

    fn put_code(&self, code: AuthCode) {
        if let Err(e) = self.block_on(self.put_code_async(&code)) {
            tracing::error!(error = %e, "pg put_code failed");
        }
    }

    fn take_code(&self, code: &str) -> Option<AuthCode> {
        self.block_on(self.take_code_async(code))
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg take_code failed");
                None
            })
    }

    fn put_session(&self, session: Session) {
        if let Err(e) = self.block_on(self.put_session_async(&session)) {
            tracing::error!(error = %e, "pg put_session failed");
        }
    }

    fn get_session(&self, id: &str) -> Option<Session> {
        self.block_on(self.get_session_async(id))
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg get_session failed");
                None
            })
    }

    fn delete_session(&self, id: &str) {
        if let Err(e) = self.block_on(self.delete_session_async(id)) {
            tracing::error!(error = %e, "pg delete_session failed");
        }
    }

    fn put_credential(&self, cred: Credential) {
        if let Err(e) = self.block_on(self.put_credential_async(&cred)) {
            tracing::error!(error = %e, "pg put_credential failed");
        }
    }

    fn list_credentials(&self, user_sub: &str) -> Vec<Credential> {
        self.block_on(self.list_credentials_async(user_sub))
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg list_credentials failed");
                Vec::new()
            })
    }

    fn get_credential(&self, cred_id: &str) -> Option<Credential> {
        self.block_on(self.get_credential_async(cred_id))
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg get_credential failed");
                None
            })
    }

    fn update_credential_passkey(&self, cred_id: &str, passkey: &str) {
        if let Err(e) = self.block_on(self.update_credential_passkey_async(cred_id, passkey)) {
            tracing::error!(error = %e, "pg update_credential_passkey failed");
        }
    }

    fn put_state(&self, state: WebauthnState) {
        if let Err(e) = self.block_on(self.put_state_async(&state)) {
            tracing::error!(error = %e, "pg put_state failed");
        }
    }

    fn take_state(&self, id: &str) -> Option<WebauthnState> {
        self.block_on(self.take_state_async(id))
            .unwrap_or_else(|e| {
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
