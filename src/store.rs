//! Storage abstraction + models.
//!
//! `Store` is a small trait with a single in-memory implementation for v0.
//! Handlers depend only on the trait, never on a concrete store type, so a
//! FusionDB-backed implementation can drop in later without touching handlers.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;

/// Registered client. Public client (no secret); `redirect_uris` is an EXACT-match list.
#[derive(Clone, Debug)]
pub struct Client {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub name: String,
}

impl Client {
    /// EXACT (not prefix) redirect_uri match — never redirect to an untrusted URI.
    pub fn allows_redirect(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }
}

/// End user. Stable subject id + email. Future: passkey credentials/profile attach here (seam).
#[derive(Clone, Debug)]
pub struct User {
    pub sub: String,
    pub email: String,
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
    fn get_user(&self, sub: &str) -> Option<User>;
    fn put_code(&self, code: AuthCode);
    /// Atomically remove and return the code (single-use consume); `None` if absent.
    fn take_code(&self, code: &str) -> Option<AuthCode>;
}

/// In-memory `Store` for v0. `std::sync::Mutex<HashMap>` — no async lock needed.
#[derive(Default)]
pub struct InMemoryStore {
    clients: Mutex<HashMap<String, Client>>,
    users: Mutex<HashMap<String, User>>,
    codes: Mutex<HashMap<String, AuthCode>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a client (startup only — concrete-type access is fine outside handlers).
    pub fn put_client(&self, client: Client) {
        self.clients
            .lock()
            .expect("clients lock poisoned")
            .insert(client.client_id.clone(), client);
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

    fn get_user(&self, sub: &str) -> Option<User> {
        self.users
            .lock()
            .expect("users lock poisoned")
            .get(sub)
            .cloned()
    }

    fn put_code(&self, code: AuthCode) {
        self.codes
            .lock()
            .expect("codes lock poisoned")
            .insert(code.code.clone(), code);
    }

    fn take_code(&self, code: &str) -> Option<AuthCode> {
        self.codes
            .lock()
            .expect("codes lock poisoned")
            .remove(code)
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
// array/JSON column. Single-use codes are enforced by delete-on-consume.
//
// The `Store` trait is intentionally synchronous (handlers never `.await` the store),
// so each method bridges to async sqlx via `block_in_place` + the runtime `Handle`.
// This requires a multi-threaded Tokio runtime, which production (`#[tokio::main]`)
// and the `multi_thread` integration test both provide.

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
        Ok(())
    }

    /// Idempotent UPSERT seed of the dev client (+ its redirect URIs) and user.
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
        let row = sqlx::query("SELECT name FROM oauth_clients WHERE client_id = $1")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else { return Ok(None) };
        let name: String = row.try_get("name")?;
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
        }))
    }

    async fn get_user_async(&self, sub: &str) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query("SELECT sub, email FROM users WHERE sub = $1")
            .bind(sub)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(User {
                sub: r.try_get("sub")?,
                email: r.try_get("email")?,
            })),
            None => Ok(None),
        }
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
}

impl Store for PgStore {
    fn get_client(&self, client_id: &str) -> Option<Client> {
        match self.block_on(self.get_client_async(client_id)) {
            Ok(client) => client,
            Err(e) => {
                tracing::error!(error = %e, "pg get_client failed");
                None
            }
        }
    }

    fn get_user(&self, sub: &str) -> Option<User> {
        match self.block_on(self.get_user_async(sub)) {
            Ok(user) => user,
            Err(e) => {
                tracing::error!(error = %e, "pg get_user failed");
                None
            }
        }
    }

    fn put_code(&self, code: AuthCode) {
        if let Err(e) = self.block_on(self.put_code_async(&code)) {
            tracing::error!(error = %e, "pg put_code failed");
        }
    }

    fn take_code(&self, code: &str) -> Option<AuthCode> {
        match self.block_on(self.take_code_async(code)) {
            Ok(code) => code,
            Err(e) => {
                tracing::error!(error = %e, "pg take_code failed");
                None
            }
        }
    }
}

/// Generate an opaque 32-byte CSPRNG authorization code, base64url-no-pad encoded.
pub fn new_opaque_code() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
