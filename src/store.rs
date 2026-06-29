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

// TODO seam: `FusionDbStore` implementing `Store` against the future FusionDB data plane.
// FusionDB is NOT running for v0 and must NOT be required. The trait boundary above is the seam.

/// Generate an opaque 32-byte CSPRNG authorization code, base64url-no-pad encoded.
pub fn new_opaque_code() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
