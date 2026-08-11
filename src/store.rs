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

use std::cmp::Reverse;
use std::collections::HashMap;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::now_secs;

const REGISTRATION_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

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
    /// First-party (platform-owned) clients skip the consent screen — they *are* the
    /// platform (Sluice gateway). Third-party clients (default `false`) must obtain the
    /// user's consent for the requested scopes before a code is issued.
    pub first_party: bool,
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
///
/// `is_admin` gates the `/admin` operator console; rows with `created_at=0` (seeded /
/// pre-provisioned accounts) are backfilled to admin on migration so the operator is never
/// locked out. `disabled` blocks new password logins with an explicit 403 — an admin
/// switch, self-service users always start enabled.
#[derive(Clone, Debug)]
pub struct User {
    pub sub: String,
    pub email: String,
    pub password_hash: Option<String>,
    pub email_verified: bool,
    pub created_at: u64,
    pub is_admin: bool,
    pub disabled: bool,
    /// Monotonic identity-factor generation. Any factor reset or recovery event bumps it,
    /// invalidating assurance on sessions minted under an older generation.
    pub factor_epoch: u64,
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

/// Failure to obtain or persist authoritative state in the configured storage backend.
/// Callers must fail closed instead of treating this as a missing record or success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Backend,
}

/// Registration state exported by Keystone to Access Governance. This is identity-source
/// truth only: an Access lifecycle fence may still block login without changing this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationState {
    Registered,
    Unverified,
    Disabled,
    Deleted,
}

impl RegistrationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Unverified => "unverified",
            Self::Disabled => "disabled",
            Self::Deleted => "deleted",
        }
    }

    fn from_db(value: &str) -> Option<Self> {
        match value {
            "registered" => Some(Self::Registered),
            "unverified" => Some(Self::Unverified),
            "disabled" => Some(Self::Disabled),
            "deleted" => Some(Self::Deleted),
            _ => None,
        }
    }
}

/// Result of an explicit operator enable/disable mutation. `login_disabled` includes the
/// independent lifecycle fence; `registration_state` deliberately does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManualDisabledOutcome {
    pub changed: bool,
    pub account_version: u64,
    pub registration_state: RegistrationState,
    pub login_disabled: bool,
    pub lifecycle_blocked: bool,
}

/// One immutable full-state event in the registration changefeed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationEvent {
    pub cursor: u64,
    pub event_id: String,
    pub subject: String,
    pub account_version: u64,
    pub registration_state: RegistrationState,
    pub email_verified: bool,
    pub enabled: bool,
    pub payload_hash: String,
    pub occurred_at: u64,
}

/// Immutable registration snapshot manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationSnapshotManifest {
    pub snapshot_id: String,
    /// Durable Keystone feed epoch. Consumers echo this value in every ACK so stale
    /// writers from an earlier authority epoch cannot advance the cursor.
    pub generation: u64,
    pub high_watermark: u64,
    pub high_watermark_event_id: String,
    pub high_watermark_payload_hash: String,
    pub count: u64,
    pub digest: String,
}

/// One row in an immutable registration snapshot. Ordinals start at one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationSnapshotRow {
    pub ordinal: u64,
    pub subject: String,
    pub account_version: u64,
    pub registration_state: RegistrationState,
    pub email_verified: bool,
    pub enabled: bool,
    pub payload_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationSnapshotPage {
    pub snapshot_id: String,
    pub generation: u64,
    pub high_watermark: u64,
    pub high_watermark_event_id: String,
    pub high_watermark_payload_hash: String,
    pub digest: String,
    pub rows: Vec<RegistrationSnapshotRow>,
    pub next_after_ordinal: u64,
    pub done: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationChangesPage {
    pub generation: u64,
    pub events: Vec<RegistrationEvent>,
    pub head_cursor: u64,
    pub retention_floor_cursor: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationAckCommand {
    pub consumer: String,
    pub generation: u64,
    pub acked_cursor: u64,
    pub event_id: String,
    pub payload_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationAckOutcome {
    pub consumer: String,
    pub generation: u64,
    pub stored_cursor: u64,
}

/// Stable store-layer outcomes mapped one-for-one to the registration feed HTTP contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationFeedError {
    SnapshotIncomplete,
    ResnapshotRequired,
    AckRegression,
    AckGenerationConflict,
    AckAhead,
    AckEventMismatch,
    FeedGap,
    Replay,
    Backend,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn canonical_registration_subject(raw_sub: &str) -> String {
    format!("user:{raw_sub}")
}

fn registration_state(
    email_verified: bool,
    login_disabled: bool,
    disabled_by_lifecycle: bool,
) -> (RegistrationState, bool) {
    let identity_disabled = login_disabled && !disabled_by_lifecycle;
    if identity_disabled {
        (RegistrationState::Disabled, false)
    } else if !email_verified {
        (RegistrationState::Unverified, true)
    } else {
        (RegistrationState::Registered, true)
    }
}

fn registration_payload_hash(
    subject: &str,
    account_version: u64,
    state: RegistrationState,
    email_verified: bool,
    enabled: bool,
) -> String {
    let canonical = format!(
        "registration-payload-v1\n{subject}\n{account_version}\n{}\n{}\n{}",
        state.as_str(),
        u8::from(email_verified),
        u8::from(enabled)
    );
    sha256_hex(canonical.as_bytes())
}

fn registration_snapshot_digest(high_watermark: u64, rows: &[RegistrationSnapshotRow]) -> String {
    let mut canonical = format!("registration-snapshot-v1\n{high_watermark}");
    for row in rows {
        use std::fmt::Write as _;
        let _ = write!(
            canonical,
            "\nR\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.ordinal,
            row.subject,
            row.account_version,
            row.registration_state.as_str(),
            u8::from(row.email_verified),
            u8::from(row.enabled),
            row.payload_hash
        );
    }
    sha256_hex(canonical.as_bytes())
}

fn valid_registration_watermark_evidence(
    high_watermark: u64,
    event_id: &str,
    payload_hash: &str,
) -> bool {
    if high_watermark == 0 {
        return event_id.is_empty() && payload_hash.is_empty();
    }
    payload_hash.len() == 64
        && payload_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && event_id == format!("ire_{high_watermark:016x}_{}", &payload_hash[..16])
}

/// Authoritative workforce lifecycle state applied by the internal JML endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectLifecycleState {
    Active,
    Frozen,
    Terminated,
}

impl SubjectLifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Terminated => "terminated",
        }
    }

    fn from_db(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "frozen" => Some(Self::Frozen),
            "terminated" => Some(Self::Terminated),
            _ => None,
        }
    }

    fn disables_login(self) -> bool {
        !matches!(self, Self::Active)
    }
}

/// One version-fenced lifecycle command from the authoritative workforce source.
#[derive(Clone, Debug)]
pub struct SubjectLifecycleCommand {
    pub subject: String,
    pub state: SubjectLifecycleState,
    pub source_event_id: String,
    pub source_version: u64,
    pub correlation_id: String,
}

/// Durable result returned for both a newly-applied command and an exact replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectLifecycleOutcome {
    pub state: SubjectLifecycleState,
    pub replayed: bool,
    pub user_found: bool,
    pub revoked_sessions: u64,
}

/// A lifecycle fence conflict is caller-visible (409); backend failures fail closed (503).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectLifecycleError {
    Conflict,
    Backend,
}

#[derive(Clone, Debug)]
struct SubjectLifecycleRecord {
    state: SubjectLifecycleState,
    source_event_id: String,
    source_version: u64,
    user_found: bool,
    revoked_sessions: u64,
    disabled_by_lifecycle: bool,
}

/// A server-side login session. The opaque `id` is what the signed `__Host-session`
/// cookie carries; everything else is authoritative state held here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssuranceLevel {
    AalNone,
    MfaStrong,
}

impl AssuranceLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AalNone => "AAL_NONE",
            Self::MfaStrong => "MFA_STRONG",
        }
    }

    fn from_db(value: &str) -> Option<Self> {
        match value {
            "AAL_NONE" => Some(Self::AalNone),
            "MFA_STRONG" => Some(Self::MfaStrong),
            _ => None,
        }
    }
}

/// The authoritative assurance facts stored on a live Keystone session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionAssurance {
    pub session_binding: String,
    pub aal: AssuranceLevel,
    pub uv: bool,
    pub auth_time: u64,
    /// Canonical comma-separated AMR values from the closed set `pwd,otp,hwk,user,rcv`.
    pub amr: String,
    pub factor_epoch: u64,
}

/// Frozen subset copied from a session into a single-use authorization code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthCodeBinding {
    pub session_binding: String,
    pub aal: AssuranceLevel,
    pub uv: bool,
    pub auth_time: u64,
    pub factor_epoch: u64,
}

impl AuthCodeBinding {
    pub fn from_session(session: &Session) -> Option<Self> {
        Some(Self {
            session_binding: session.session_binding.clone()?,
            aal: session.aal,
            uv: session.uv,
            auth_time: session.auth_time,
            factor_epoch: session.factor_epoch,
        })
    }

    fn matches_session(&self, session: &Session) -> bool {
        session.session_binding.as_deref() == Some(self.session_binding.as_str())
            && session.aal == self.aal
            && session.uv == self.uv
            && session.auth_time == self.auth_time
            && session.factor_epoch == self.factor_epoch
    }
}

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
    /// Public, non-bearer binding identifier. Legacy rows remain `None` and can never assert MFA.
    pub session_binding: Option<String>,
    pub aal: AssuranceLevel,
    pub uv: bool,
    pub auth_time: u64,
    pub amr: String,
    pub factor_epoch: u64,
}

impl Session {
    pub fn assurance(&self) -> Option<SessionAssurance> {
        Some(SessionAssurance {
            session_binding: self.session_binding.clone()?,
            aal: self.aal,
            uv: self.uv,
            auth_time: self.auth_time,
            amr: self.amr.clone(),
            factor_epoch: self.factor_epoch,
        })
    }
}

/// Result of consuming an authorization code at the store linearization point.
#[derive(Clone, Debug)]
pub struct RedeemedAuthCode {
    pub code: AuthCode,
    pub user: User,
    /// `None` is permitted only for an authorization code created before session binding existed.
    pub assurance: Option<SessionAssurance>,
    /// Wall-clock lower bound sampled after all authoritative lifecycle/session locks were held.
    /// Callers must use at least this value for their final expiry and freshness decision.
    pub validated_at: u64,
    /// Expiry of the bound authoritative session, when the code carries a session binding.
    pub session_expires_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionAssuranceLookup {
    Live(SessionAssurance),
    Absent { factor_epoch: u64 },
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

/// Optional TOTP second-factor configuration. `enabled=false` means enrollment has
/// started but the first authenticator code has not been verified yet.
#[derive(Clone, Debug)]
pub struct TotpConfig {
    pub user_sub: String,
    pub secret: String,
    pub enabled: bool,
    pub created_at: u64,
    pub verified_at: u64,
    /// Greatest RFC 6238 counter accepted for authentication or enrollment. `None` is the
    /// additive legacy value; acceptance must advance it monotonically before session minting.
    pub last_accepted_counter: Option<u64>,
}

/// One hashed, single-use recovery code for TOTP account recovery.
#[derive(Clone, Debug)]
pub struct TotpRecoveryCode {
    pub user_sub: String,
    pub code_hash: String,
    pub created_at: u64,
}

/// Short-lived password-accepted, TOTP-pending login challenge.
#[derive(Clone, Debug)]
pub struct TotpChallenge {
    pub id: String,
    pub user_sub: String,
    pub return_to: String,
    pub user_agent: String,
    pub ip: String,
    pub expires_at: u64,
    /// Present for an on-demand step-up that must remain tied to the session which requested it.
    pub source_session_binding: Option<String>,
    /// Factor generation observed before the password/TOTP ceremony began.
    pub expected_factor_epoch: Option<u64>,
    /// Closed requested ACR. `None` is the ordinary login compatibility path.
    pub required_acr: Option<String>,
    /// Server-side evidence that the password was checked for this exact challenge flow.
    pub password_verified: bool,
}

/// Per-account login history row. `result` is `"success"`, `"failure"`, or `"challenge"`.
#[derive(Clone, Debug)]
pub struct LoginEvent {
    pub id: String,
    pub user_sub: String,
    pub username: String,
    pub occurred_at: u64,
    pub ip: String,
    pub user_agent: String,
    pub method: String,
    pub result: String,
    pub detail: String,
}

/// Personal access token metadata. Only `token_hash` is persisted; plaintext is shown once.
#[derive(Clone, Debug)]
pub struct PersonalAccessToken {
    pub id: String,
    pub user_sub: String,
    pub name: String,
    pub token_hash: String,
    pub scopes: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// `0` = active/not revoked.
    pub revoked_at: u64,
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
    /// `None` is the explicit legacy compatibility path and can only mint AAL_NONE.
    pub binding: Option<AuthCodeBinding>,
    /// Closed ACR requirement copied from `/authorize`; `None` preserves ordinary OIDC.
    pub required_acr: Option<String>,
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
    /// The scope string a user previously consented to for `client_id`, or `None`.
    async fn get_consent(&self, user_sub: &str, client_id: &str) -> Option<String>;
    /// Record (replace) the granted scope set for (user, client).
    async fn put_consent(&self, user_sub: &str, client_id: &str, scope: &str, granted_at: u64);
    async fn get_user(&self, sub: &str) -> Option<User>;
    /// Resolve a user by login name: matches the subject id OR the email (exact).
    async fn get_user_by_username(&self, username: &str) -> Option<User>;
    /// Set (or replace) a user's Argon2 password hash.
    async fn set_password_hash(&self, sub: &str, hash: &str);
    /// Rotate a password and bump the subject factor generation at one linearization point.
    /// Used by password reset/change; startup seeding continues to use `set_password_hash`.
    async fn set_password_hash_and_bump_factor(
        &self,
        sub: &str,
        hash: &str,
    ) -> Result<u64, StoreError>;
    /// Create a self-service user (`email_verified=false`). Returns [`CreateUserError::EmailTaken`]
    /// on the `UNIQUE(email)` conflict so registration can render a friendly, non-leaking error.
    async fn create_user(
        &self,
        sub: &str,
        email: &str,
        password_hash: &str,
        created_at: u64,
    ) -> Result<(), CreateUserError>;
    /// Registration handler variant that also persists the initial verification token in the
    /// same transaction as the user, account version, and outbox event.
    async fn create_user_with_verification_token(
        &self,
        sub: &str,
        email: &str,
        password_hash: &str,
        created_at: u64,
        token: VerificationToken,
    ) -> Result<(), CreateUserError>;
    /// Mark a user's email as verified and append the resulting registration snapshot at the
    /// same linearization point. Returns whether identity-source state changed.
    async fn set_email_verified(&self, sub: &str) -> Result<bool, StoreError>;
    /// Revoke email verification and append the resulting registration snapshot atomically.
    async fn set_email_unverified(&self, sub: &str) -> Result<bool, StoreError>;
    /// All users, oldest first (drives the `/admin` console user table).
    async fn list_users(&self) -> Vec<User>;
    /// Set (or clear) the identity-authority disabled flag. The independent lifecycle fence
    /// remains effective, and the full-state registration event is committed atomically.
    async fn set_disabled(
        &self,
        sub: &str,
        disabled: bool,
    ) -> Result<ManualDisabledOutcome, StoreError>;
    /// Delete a user while retaining a versioned registration tombstone and outbox event.
    async fn delete_user(&self, sub: &str) -> Result<bool, StoreError>;
    /// Apply one authoritative, monotonically-versioned JML state transition. Exact
    /// `(version, state, event)` replay is idempotent; stale or conflicting commands fail.
    async fn apply_subject_lifecycle(
        &self,
        command: SubjectLifecycleCommand,
    ) -> Result<SubjectLifecycleOutcome, SubjectLifecycleError>;
    /// Set (or clear) a user's admin flag (admin action; gates the `/admin` console).
    async fn set_is_admin(&self, sub: &str, is_admin: bool);
    /// All registered clients, ordered by client_id (read-only `/admin` clients table).
    async fn list_clients(&self) -> Vec<Client>;

    /// Store a single-use verification/reset token.
    async fn put_verification_token(&self, token: VerificationToken) -> Result<(), StoreError>;
    /// Atomically remove and return `(sub, kind)` for a still-valid token; `None` when the
    /// token is absent, already consumed, or expired (single-use, mirrors [`Store::take_code`]).
    async fn take_verification_token(
        &self,
        token: &str,
    ) -> Result<Option<(String, String)>, StoreError>;
    /// Atomically consume a live `verify` token, mark the user verified, increment the account
    /// version when needed, and append the full-state registration event.
    async fn consume_verification_token_and_verify(
        &self,
        token: &str,
    ) -> Result<Option<String>, StoreError>;
    /// Atomically consume a live `reset` token, rotate the password/factor generation, verify
    /// the mailbox when needed, and append the corresponding registration event.
    async fn consume_reset_token_and_rotate_password(
        &self,
        token: &str,
        password_hash: &str,
    ) -> Result<Option<(String, u64)>, StoreError>;

    /// Materialize one immutable cross-page snapshot at a fixed outbox watermark.
    async fn create_registration_snapshot(
        &self,
    ) -> Result<RegistrationSnapshotManifest, RegistrationFeedError>;
    async fn get_registration_snapshot_page(
        &self,
        snapshot_id: &str,
        after_ordinal: u64,
        limit: u16,
    ) -> Result<RegistrationSnapshotPage, RegistrationFeedError>;
    async fn get_registration_changes(
        &self,
        after: u64,
        limit: u16,
    ) -> Result<RegistrationChangesPage, RegistrationFeedError>;
    async fn acknowledge_registration(
        &self,
        command: RegistrationAckCommand,
    ) -> Result<RegistrationAckOutcome, RegistrationFeedError>;
    /// Durably claim a verified request nonce. A duplicate must fail before serving data.
    async fn claim_registration_nonce(
        &self,
        nonce_hash: &str,
        kid: &str,
        audience: &str,
        seen_at: u64,
        expires_at: u64,
    ) -> Result<(), RegistrationFeedError>;

    async fn put_code(&self, code: AuthCode);
    /// Atomically remove and return the code (single-use consume); `None` if absent.
    async fn take_code(&self, code: &str) -> Option<AuthCode>;
    /// Atomically consume one authorization code and validate its bound session/user tuple.
    /// A bound mismatch is returned as `Ok(None)` after the code has been burned; backend
    /// uncertainty is `Err` and callers must fail closed.
    async fn redeem_code(
        &self,
        code: &str,
        now: u64,
    ) -> Result<Option<RedeemedAuthCode>, StoreError>;

    /// Persist a session only while its owning user exists and is enabled. This operation
    /// serializes with [`Store::apply_subject_lifecycle`] for the same subject.
    async fn put_session_if_active(&self, session: Session) -> Result<bool, StoreError>;
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
    /// Authoritative lookup by the public session binding. Absence/revocation/stale epoch is
    /// deterministic AAL_NONE; backend failure is indeterminate.
    async fn lookup_session_assurance(
        &self,
        subject: &str,
        session_binding: &str,
        now: u64,
    ) -> Result<SessionAssuranceLookup, StoreError>;
    /// Monotonically invalidate all previously minted session assurance for this identity.
    async fn bump_factor_epoch(&self, user_sub: &str) -> Result<u64, StoreError>;

    async fn put_credential(&self, cred: Credential);
    /// Persist a newly registered passkey and invalidate prior assurance atomically.
    async fn put_credential_and_bump_factor(&self, cred: Credential) -> Result<u64, StoreError>;
    /// All passkeys registered to a user (for authentication + exclude lists).
    async fn list_credentials(&self, user_sub: &str) -> Vec<Credential>;
    /// One credential by its id (resolves the owning user during passwordless auth).
    async fn get_credential(&self, cred_id: &str) -> Option<Credential>;
    /// Replace a credential's serialised passkey (counter update after each auth).
    async fn update_credential_passkey(&self, cred_id: &str, passkey: &str);

    /// Optional TOTP configuration for a user.
    async fn get_totp(&self, user_sub: &str) -> Option<TotpConfig>;
    /// Insert or replace a TOTP configuration (pending or enabled).
    async fn put_totp(&self, config: TotpConfig);
    /// Replace any current TOTP factor with a pending enrollment, remove recovery codes, and
    /// bump the factor generation in one operation. The bump happens at enrollment start because
    /// the old factor has already stopped being authoritative at that point.
    async fn begin_totp_enrollment(&self, config: TotpConfig) -> Result<u64, StoreError>;
    /// Enable the exact pending TOTP secret, persist its first accepted counter, and replace all
    /// recovery codes atomically. Returns false if the pending factor changed concurrently.
    async fn enable_totp(
        &self,
        user_sub: &str,
        expected_secret: &str,
        accepted_counter: u64,
        verified_at: u64,
        code_hashes: Vec<String>,
    ) -> Result<bool, StoreError>;
    /// Monotonically accept a TOTP counter for the exact current enabled secret. The returned
    /// epoch is the factor generation that the qualifying strong session must snapshot.
    async fn accept_totp_counter(
        &self,
        user_sub: &str,
        expected_secret: &str,
        counter: u64,
    ) -> Result<Option<u64>, StoreError>;
    /// Remove TOTP and all recovery codes for a user.
    async fn delete_totp(&self, user_sub: &str);
    /// Remove TOTP/recovery codes and bump the factor generation atomically.
    async fn disable_totp_and_bump_factor(&self, user_sub: &str) -> Result<u64, StoreError>;
    /// Replace all recovery codes for a user with fresh hashed codes.
    async fn put_recovery_codes(&self, user_sub: &str, code_hashes: Vec<String>, created_at: u64);
    /// Number of unused recovery codes left for a user.
    async fn recovery_code_count(&self, user_sub: &str) -> usize;
    /// Consume one recovery code by hash. Returns true only when it existed for this user.
    async fn take_recovery_code(&self, user_sub: &str, code_hash: &str) -> bool;
    /// Consume one recovery code and bump the factor generation at the same linearization point.
    /// `None` means the code was absent; backend uncertainty is an error and fails closed.
    async fn take_recovery_code_and_bump_factor(
        &self,
        user_sub: &str,
        code_hash: &str,
    ) -> Result<Option<u64>, StoreError>;

    /// Store a short-lived password-accepted TOTP challenge.
    async fn put_totp_challenge(&self, challenge: TotpChallenge);
    /// Atomically consume a TOTP challenge.
    async fn take_totp_challenge(&self, id: &str) -> Option<TotpChallenge>;

    /// Append a per-account login history event.
    async fn put_login_event(&self, event: LoginEvent);
    /// Newest login events for a user, bounded by `limit`.
    async fn list_login_events(&self, user_sub: &str, limit: usize) -> Vec<LoginEvent>;

    /// Store a hashed personal access token only while its owner exists and is enabled.
    /// This operation serializes with [`Store::apply_subject_lifecycle`] for the same
    /// subject. A backend failure is returned so the caller never reveals plaintext for
    /// a token that was not durably persisted.
    async fn put_personal_token(&self, token: PersonalAccessToken) -> Result<(), StoreError>;
    /// Tokens for a user, newest first. Revoked tokens are not returned.
    async fn list_personal_tokens(&self, user_sub: &str) -> Vec<PersonalAccessToken>;
    /// Resolve one currently active PAT by its SHA-256 hash. This is an authoritative
    /// lookup: revoked/expired tokens and tokens owned by disabled/missing users return
    /// `Ok(None)`, while a backend failure returns `Err` and must fail closed.
    async fn find_active_personal_token(
        &self,
        token_hash: &str,
        now: u64,
    ) -> Result<Option<PersonalAccessToken>, StoreError>;
    /// Revoke one token only if it belongs to `user_sub`. A backend failure is
    /// authoritative and must not be presented to the user as a successful revocation.
    async fn revoke_personal_token(
        &self,
        user_sub: &str,
        id: &str,
        revoked_at: u64,
    ) -> Result<(), StoreError>;

    async fn put_state(&self, state: WebauthnState);
    /// Atomically remove and return ceremony state (single-use); `None` if absent.
    async fn take_state(&self, id: &str) -> Option<WebauthnState>;
}

#[derive(Clone, Debug)]
struct InMemoryRegistrationSnapshot {
    manifest: RegistrationSnapshotManifest,
    rows: Vec<RegistrationSnapshotRow>,
}

#[derive(Clone, Debug)]
struct InMemoryRegistrationAck {
    generation: u64,
    cursor: u64,
    event_id: String,
    payload_hash: String,
}

struct InMemoryRegistrationAuthority {
    generation: u64,
    clock: u64,
    retention_floor_cursor: u64,
    versions: HashMap<String, u64>,
    outbox: Vec<RegistrationEvent>,
    tombstones: HashMap<String, RegistrationSnapshotRow>,
    snapshots: HashMap<String, InMemoryRegistrationSnapshot>,
    acknowledgements: HashMap<String, InMemoryRegistrationAck>,
    replay_nonces: HashMap<String, u64>,
}

impl Default for InMemoryRegistrationAuthority {
    fn default() -> Self {
        Self {
            generation: 1,
            clock: 0,
            retention_floor_cursor: 0,
            versions: HashMap::new(),
            outbox: Vec::new(),
            tombstones: HashMap::new(),
            snapshots: HashMap::new(),
            acknowledgements: HashMap::new(),
            replay_nonces: HashMap::new(),
        }
    }
}

/// In-memory `Store`. `std::sync::Mutex<HashMap>` — no async lock needed.
#[derive(Default)]
pub struct InMemoryStore {
    clients: Mutex<HashMap<String, Client>>,
    users: Mutex<HashMap<String, User>>,
    codes: Mutex<HashMap<String, AuthCode>>,
    sessions: Mutex<HashMap<String, Session>>,
    /// Serializes user disabled transitions with session creation. The PostgreSQL store
    /// uses the equivalent per-subject advisory transaction lock.
    lifecycle_guard: Mutex<()>,
    subject_lifecycle: Mutex<HashMap<String, SubjectLifecycleRecord>>,
    credentials: Mutex<HashMap<String, Credential>>,
    totp: Mutex<HashMap<String, TotpConfig>>,
    recovery_codes: Mutex<HashMap<(String, String), TotpRecoveryCode>>,
    totp_challenges: Mutex<HashMap<String, TotpChallenge>>,
    login_events: Mutex<Vec<LoginEvent>>,
    personal_tokens: Mutex<HashMap<String, PersonalAccessToken>>,
    #[cfg(test)]
    fail_personal_token_put: AtomicBool,
    #[cfg(test)]
    fail_personal_token_revoke: AtomicBool,
    states: Mutex<HashMap<String, WebauthnState>>,
    verification_tokens: Mutex<HashMap<String, VerificationToken>>,
    registration: Mutex<InMemoryRegistrationAuthority>,
    /// Consent record keyed by `(user_sub, client_id)` -> (granted scope, granted_at).
    consents: Mutex<HashMap<(String, String), (String, u64)>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a user (startup only).
    pub fn put_user(&self, mut user: User) {
        let _guard = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle_guard lock poisoned");
        if let Some(fence) = self
            .subject_lifecycle
            .lock()
            .expect("subject_lifecycle lock poisoned")
            .get_mut(&user.sub)
        {
            if fence.state.disables_login() && !user.disabled {
                user.disabled = true;
                fence.disabled_by_lifecycle = true;
            }
        }
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

    /// Unit-test fault injection for the PAT persistence boundary. These switches do
    /// not exist in production builds and let handler tests prove fail-closed responses.
    #[cfg(test)]
    pub(crate) fn set_personal_token_write_failures(&self, put: bool, revoke: bool) {
        self.fail_personal_token_put.store(put, Ordering::SeqCst);
        self.fail_personal_token_revoke
            .store(revoke, Ordering::SeqCst);
    }

    fn create_user_memory(
        &self,
        sub: &str,
        email: &str,
        password_hash: &str,
        created_at: u64,
        verification_token: Option<VerificationToken>,
    ) -> Result<(), CreateUserError> {
        if verification_token
            .as_ref()
            .is_some_and(|token| token.sub != sub || token.kind != "verify")
        {
            return Err(CreateUserError::Backend);
        }
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| CreateUserError::Backend)?;
        let mut lifecycle = self
            .subject_lifecycle
            .lock()
            .map_err(|_| CreateUserError::Backend)?;
        let disabled = lifecycle
            .get(sub)
            .is_some_and(|fence| fence.state.disables_login());
        let mut users = self.users.lock().map_err(|_| CreateUserError::Backend)?;
        if users.values().any(|user| user.email == email) {
            return Err(CreateUserError::EmailTaken);
        }
        let mut registration = self
            .registration
            .lock()
            .map_err(|_| CreateUserError::Backend)?;
        let mut tokens = self
            .verification_tokens
            .lock()
            .map_err(|_| CreateUserError::Backend)?;
        if verification_token
            .as_ref()
            .is_some_and(|token| tokens.contains_key(&token.token))
        {
            return Err(CreateUserError::Backend);
        }
        let account_version = Self::next_registration_version_memory(&registration, sub)
            .map_err(|_| CreateUserError::Backend)?;
        registration
            .clock
            .checked_add(1)
            .ok_or(CreateUserError::Backend)?;
        users.insert(
            sub.to_string(),
            User {
                sub: sub.to_string(),
                email: email.to_string(),
                password_hash: Some(password_hash.to_string()),
                email_verified: false,
                created_at,
                is_admin: false,
                disabled,
                factor_epoch: 0,
            },
        );
        if disabled {
            if let Some(fence) = lifecycle.get_mut(sub) {
                fence.disabled_by_lifecycle = true;
            }
        }
        registration.tombstones.remove(sub);
        Self::append_registration_event_memory(
            &mut registration,
            sub,
            account_version,
            RegistrationState::Unverified,
            false,
            true,
            created_at,
        )
        .map_err(|_| CreateUserError::Backend)?;
        if let Some(token) = verification_token {
            tokens.insert(token.token.clone(), token);
        }
        Ok(())
    }

    fn set_email_verification_memory(&self, sub: &str, verified: bool) -> Result<bool, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let lifecycle = self
            .subject_lifecycle
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut users = self.users.lock().map_err(|_| StoreError::Backend)?;
        let user = users.get_mut(sub).ok_or(StoreError::Backend)?;
        if user.email_verified == verified {
            return Ok(false);
        }
        let mut registration = self.registration.lock().map_err(|_| StoreError::Backend)?;
        let account_version = Self::next_registration_version_memory(&registration, sub)?;
        registration
            .clock
            .checked_add(1)
            .ok_or(StoreError::Backend)?;
        user.email_verified = verified;
        let disabled_by_lifecycle = lifecycle
            .get(sub)
            .is_some_and(|fence| fence.disabled_by_lifecycle);
        let (state, enabled) = registration_state(verified, user.disabled, disabled_by_lifecycle);
        Self::append_registration_event_memory(
            &mut registration,
            sub,
            account_version,
            state,
            verified,
            enabled,
            now_secs(),
        )?;
        Ok(true)
    }

    fn append_registration_event_memory(
        authority: &mut InMemoryRegistrationAuthority,
        raw_sub: &str,
        account_version: u64,
        state: RegistrationState,
        email_verified: bool,
        enabled: bool,
        occurred_at: u64,
    ) -> Result<RegistrationEvent, StoreError> {
        authority.clock = authority.clock.checked_add(1).ok_or(StoreError::Backend)?;
        let subject = canonical_registration_subject(raw_sub);
        let payload_hash =
            registration_payload_hash(&subject, account_version, state, email_verified, enabled);
        let event_id = format!("ire_{:016x}_{}", authority.clock, &payload_hash[..16]);
        let event = RegistrationEvent {
            cursor: authority.clock,
            event_id,
            subject,
            account_version,
            registration_state: state,
            email_verified,
            enabled,
            payload_hash,
            occurred_at,
        };
        authority.outbox.push(event.clone());
        authority
            .versions
            .insert(raw_sub.to_string(), account_version);
        Ok(event)
    }

    fn next_registration_version_memory(
        authority: &InMemoryRegistrationAuthority,
        raw_sub: &str,
    ) -> Result<u64, StoreError> {
        authority
            .versions
            .get(raw_sub)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StoreError::Backend)
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

    async fn get_consent(&self, user_sub: &str, client_id: &str) -> Option<String> {
        self.consents
            .lock()
            .expect("consents lock poisoned")
            .get(&(user_sub.to_string(), client_id.to_string()))
            .map(|(scope, _)| scope.clone())
    }

    async fn put_consent(&self, user_sub: &str, client_id: &str, scope: &str, granted_at: u64) {
        self.consents
            .lock()
            .expect("consents lock poisoned")
            .insert(
                (user_sub.to_string(), client_id.to_string()),
                (scope.to_string(), granted_at),
            );
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

    async fn set_password_hash_and_bump_factor(
        &self,
        sub: &str,
        hash: &str,
    ) -> Result<u64, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut users = self.users.lock().map_err(|_| StoreError::Backend)?;
        let user = users.get_mut(sub).ok_or(StoreError::Backend)?;
        let next = user
            .factor_epoch
            .checked_add(1)
            .ok_or(StoreError::Backend)?;
        user.password_hash = Some(hash.to_string());
        user.factor_epoch = next;
        Ok(next)
    }

    async fn create_user(
        &self,
        sub: &str,
        email: &str,
        password_hash: &str,
        created_at: u64,
    ) -> Result<(), CreateUserError> {
        self.create_user_memory(sub, email, password_hash, created_at, None)
    }

    async fn create_user_with_verification_token(
        &self,
        sub: &str,
        email: &str,
        password_hash: &str,
        created_at: u64,
        token: VerificationToken,
    ) -> Result<(), CreateUserError> {
        self.create_user_memory(sub, email, password_hash, created_at, Some(token))
    }

    async fn set_email_verified(&self, sub: &str) -> Result<bool, StoreError> {
        self.set_email_verification_memory(sub, true)
    }

    async fn set_email_unverified(&self, sub: &str) -> Result<bool, StoreError> {
        self.set_email_verification_memory(sub, false)
    }

    async fn list_users(&self) -> Vec<User> {
        let mut v: Vec<User> = self
            .users
            .lock()
            .expect("users lock poisoned")
            .values()
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.sub.cmp(&b.sub))
        });
        v
    }

    async fn set_disabled(
        &self,
        sub: &str,
        disabled: bool,
    ) -> Result<ManualDisabledOutcome, StoreError> {
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut lifecycle = self
            .subject_lifecycle
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut users = self.users.lock().map_err(|_| StoreError::Backend)?;
        let user = users.get_mut(sub).ok_or(StoreError::Backend)?;
        let lifecycle_blocked = lifecycle
            .get(sub)
            .is_some_and(|fence| fence.state.disables_login());
        let disabled_by_lifecycle = lifecycle
            .get(sub)
            .is_some_and(|fence| fence.disabled_by_lifecycle);
        let identity_disabled = user.disabled && !disabled_by_lifecycle;
        let mut registration = self.registration.lock().map_err(|_| StoreError::Backend)?;
        // Acquire consequence stores before mutating identity/outbox so a poisoned lock can
        // never yield an error after the authority transition has already become visible.
        let mut sessions = self.sessions.lock().map_err(|_| StoreError::Backend)?;
        let mut personal_tokens = self
            .personal_tokens
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let current_version = registration.versions.get(sub).copied().unwrap_or(0);
        if identity_disabled == disabled {
            let (state, _) =
                registration_state(user.email_verified, user.disabled, disabled_by_lifecycle);
            return Ok(ManualDisabledOutcome {
                changed: false,
                account_version: current_version,
                registration_state: state,
                login_disabled: user.disabled,
                lifecycle_blocked,
            });
        }

        let account_version = current_version.checked_add(1).ok_or(StoreError::Backend)?;
        registration
            .clock
            .checked_add(1)
            .ok_or(StoreError::Backend)?;
        if disabled {
            user.disabled = true;
            if let Some(fence) = lifecycle.get_mut(sub) {
                // Manual disable takes ownership of the aggregate disabled bit.
                fence.disabled_by_lifecycle = false;
            }
        } else if lifecycle_blocked {
            // Registration authority is enabled, while the independent effective lifecycle
            // fence continues to block login until Access clears it.
            user.disabled = true;
            if let Some(fence) = lifecycle.get_mut(sub) {
                fence.disabled_by_lifecycle = true;
            }
        } else {
            user.disabled = false;
            if let Some(fence) = lifecycle.get_mut(sub) {
                fence.disabled_by_lifecycle = false;
            }
        }

        let disabled_by_lifecycle = lifecycle
            .get(sub)
            .is_some_and(|fence| fence.disabled_by_lifecycle);
        let (state, enabled) =
            registration_state(user.email_verified, user.disabled, disabled_by_lifecycle);
        Self::append_registration_event_memory(
            &mut registration,
            sub,
            account_version,
            state,
            user.email_verified,
            enabled,
            now_secs(),
        )?;

        if disabled {
            sessions.retain(|_, session| session.user_sub != sub);
            let revoked_at = now_secs();
            for token in personal_tokens
                .values_mut()
                .filter(|token| token.user_sub == sub && token.revoked_at == 0)
            {
                token.revoked_at = revoked_at;
            }
        }

        Ok(ManualDisabledOutcome {
            changed: true,
            account_version,
            registration_state: state,
            login_disabled: user.disabled,
            lifecycle_blocked,
        })
    }

    async fn delete_user(&self, sub: &str) -> Result<bool, StoreError> {
        let _lifecycle = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut users = self.users.lock().map_err(|_| StoreError::Backend)?;
        if !users.contains_key(sub) {
            return Ok(false);
        }
        let mut registration = self.registration.lock().map_err(|_| StoreError::Backend)?;
        let mut sessions = self.sessions.lock().map_err(|_| StoreError::Backend)?;
        let mut personal_tokens = self
            .personal_tokens
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut credentials = self.credentials.lock().map_err(|_| StoreError::Backend)?;
        let mut verification_tokens = self
            .verification_tokens
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut totp = self.totp.lock().map_err(|_| StoreError::Backend)?;
        let mut recovery_codes = self
            .recovery_codes
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut totp_challenges = self
            .totp_challenges
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut login_events = self.login_events.lock().map_err(|_| StoreError::Backend)?;
        let mut consents = self.consents.lock().map_err(|_| StoreError::Backend)?;
        let mut codes = self.codes.lock().map_err(|_| StoreError::Backend)?;
        let account_version = Self::next_registration_version_memory(&registration, sub)?;
        registration
            .clock
            .checked_add(1)
            .ok_or(StoreError::Backend)?;
        users.remove(sub);
        let event = Self::append_registration_event_memory(
            &mut registration,
            sub,
            account_version,
            RegistrationState::Deleted,
            false,
            false,
            now_secs(),
        )?;
        registration.tombstones.insert(
            sub.to_string(),
            RegistrationSnapshotRow {
                ordinal: 0,
                subject: event.subject,
                account_version,
                registration_state: RegistrationState::Deleted,
                email_verified: false,
                enabled: false,
                payload_hash: event.payload_hash,
            },
        );
        sessions.retain(|_, value| value.user_sub != sub);
        personal_tokens.retain(|_, value| value.user_sub != sub);
        credentials.retain(|_, value| value.user_sub != sub);
        verification_tokens.retain(|_, value| value.sub != sub);
        totp.retain(|_, value| value.user_sub != sub);
        recovery_codes.retain(|(user_sub, _), _| user_sub != sub);
        totp_challenges.retain(|_, value| value.user_sub != sub);
        login_events.retain(|value| value.user_sub != sub);
        consents.retain(|(user_sub, _), _| user_sub != sub);
        codes.retain(|_, value| value.sub != sub);
        Ok(true)
    }

    async fn apply_subject_lifecycle(
        &self,
        command: SubjectLifecycleCommand,
    ) -> Result<SubjectLifecycleOutcome, SubjectLifecycleError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| SubjectLifecycleError::Backend)?;
        let mut lifecycle = self
            .subject_lifecycle
            .lock()
            .map_err(|_| SubjectLifecycleError::Backend)?;

        if let Some(current) = lifecycle.get(&command.subject).cloned() {
            if command.source_version < current.source_version {
                return Err(SubjectLifecycleError::Conflict);
            }
            if command.source_version == current.source_version {
                if command.state == current.state
                    && command.source_event_id == current.source_event_id
                {
                    let mut disabled_by_replay = false;
                    if current.state.disables_login() {
                        if let Some(user) = self
                            .users
                            .lock()
                            .map_err(|_| SubjectLifecycleError::Backend)?
                            .get_mut(&command.subject)
                        {
                            disabled_by_replay = !user.disabled;
                            user.disabled = true;
                        }
                        self.sessions
                            .lock()
                            .map_err(|_| SubjectLifecycleError::Backend)?
                            .retain(|_, session| session.user_sub != command.subject);
                        let revoked_at = now_secs();
                        for token in self
                            .personal_tokens
                            .lock()
                            .map_err(|_| SubjectLifecycleError::Backend)?
                            .values_mut()
                            .filter(|token| {
                                token.user_sub == command.subject && token.revoked_at == 0
                            })
                        {
                            token.revoked_at = revoked_at;
                        }
                    }
                    if disabled_by_replay {
                        if let Some(fence) = lifecycle.get_mut(&command.subject) {
                            fence.disabled_by_lifecycle = true;
                        }
                    }
                    return Ok(SubjectLifecycleOutcome {
                        state: current.state,
                        replayed: true,
                        user_found: current.user_found,
                        revoked_sessions: current.revoked_sessions,
                    });
                }
                return Err(SubjectLifecycleError::Conflict);
            }
        }

        let previous_disabled_by_lifecycle = lifecycle
            .get(&command.subject)
            .is_some_and(|fence| fence.disabled_by_lifecycle);
        let mut disabled_by_lifecycle = false;
        let user_found = {
            let mut users = self
                .users
                .lock()
                .map_err(|_| SubjectLifecycleError::Backend)?;
            match users.get_mut(&command.subject) {
                Some(user) => {
                    if command.state.disables_login() {
                        disabled_by_lifecycle = previous_disabled_by_lifecycle || !user.disabled;
                        user.disabled = true;
                    } else if previous_disabled_by_lifecycle {
                        user.disabled = false;
                    }
                    true
                }
                None => false,
            }
        };

        let revoked_sessions = if command.state.disables_login() {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| SubjectLifecycleError::Backend)?;
            let before = sessions.len();
            sessions.retain(|_, session| session.user_sub != command.subject);
            before.saturating_sub(sessions.len()) as u64
        } else {
            0
        };

        if command.state.disables_login() {
            let revoked_at = now_secs();
            let mut personal_tokens = self
                .personal_tokens
                .lock()
                .map_err(|_| SubjectLifecycleError::Backend)?;
            for token in personal_tokens
                .values_mut()
                .filter(|token| token.user_sub == command.subject && token.revoked_at == 0)
            {
                token.revoked_at = revoked_at;
            }
        }

        lifecycle.insert(
            command.subject,
            SubjectLifecycleRecord {
                state: command.state,
                source_event_id: command.source_event_id,
                source_version: command.source_version,
                user_found,
                revoked_sessions,
                disabled_by_lifecycle,
            },
        );

        Ok(SubjectLifecycleOutcome {
            state: command.state,
            replayed: false,
            user_found,
            revoked_sessions,
        })
    }

    async fn set_is_admin(&self, sub: &str, is_admin: bool) {
        if let Some(user) = self.users.lock().expect("users lock poisoned").get_mut(sub) {
            user.is_admin = is_admin;
        }
    }

    async fn list_clients(&self) -> Vec<Client> {
        let mut v: Vec<Client> = self
            .clients
            .lock()
            .expect("clients lock poisoned")
            .values()
            .cloned()
            .collect();
        v.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        v
    }

    async fn put_verification_token(&self, token: VerificationToken) -> Result<(), StoreError> {
        self.verification_tokens
            .lock()
            .map_err(|_| StoreError::Backend)?
            .insert(token.token.clone(), token);
        Ok(())
    }

    async fn take_verification_token(
        &self,
        token: &str,
    ) -> Result<Option<(String, String)>, StoreError> {
        let Some(rec) = self
            .verification_tokens
            .lock()
            .map_err(|_| StoreError::Backend)?
            .remove(token)
        else {
            return Ok(None);
        };
        if now_secs() > rec.expires_at {
            return Ok(None);
        }
        Ok(Some((rec.sub, rec.kind)))
    }

    async fn consume_verification_token_and_verify(
        &self,
        token: &str,
    ) -> Result<Option<String>, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut tokens = self
            .verification_tokens
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let Some(record) = tokens.get(token).cloned() else {
            return Ok(None);
        };
        if record.kind != "verify" || now_secs() > record.expires_at {
            tokens.remove(token);
            return Ok(None);
        }
        let lifecycle = self
            .subject_lifecycle
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut users = self.users.lock().map_err(|_| StoreError::Backend)?;
        let Some(user) = users.get_mut(&record.sub) else {
            tokens.remove(token);
            return Ok(None);
        };
        let mut registration = self.registration.lock().map_err(|_| StoreError::Backend)?;
        if !user.email_verified {
            let account_version =
                Self::next_registration_version_memory(&registration, &record.sub)?;
            registration
                .clock
                .checked_add(1)
                .ok_or(StoreError::Backend)?;
            user.email_verified = true;
            let disabled_by_lifecycle = lifecycle
                .get(&record.sub)
                .is_some_and(|fence| fence.disabled_by_lifecycle);
            let (state, enabled) = registration_state(true, user.disabled, disabled_by_lifecycle);
            Self::append_registration_event_memory(
                &mut registration,
                &record.sub,
                account_version,
                state,
                true,
                enabled,
                now_secs(),
            )?;
        }
        tokens.remove(token);
        Ok(Some(record.sub))
    }

    async fn consume_reset_token_and_rotate_password(
        &self,
        token: &str,
        password_hash: &str,
    ) -> Result<Option<(String, u64)>, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut tokens = self
            .verification_tokens
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let Some(record) = tokens.get(token).cloned() else {
            return Ok(None);
        };
        if record.kind != "reset" || now_secs() > record.expires_at {
            tokens.remove(token);
            return Ok(None);
        }
        let lifecycle = self
            .subject_lifecycle
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut users = self.users.lock().map_err(|_| StoreError::Backend)?;
        let Some(user) = users.get_mut(&record.sub) else {
            tokens.remove(token);
            return Ok(None);
        };
        let next_factor_epoch = user
            .factor_epoch
            .checked_add(1)
            .ok_or(StoreError::Backend)?;
        let mut registration = self.registration.lock().map_err(|_| StoreError::Backend)?;
        let next_registration_version = if user.email_verified {
            None
        } else {
            registration
                .clock
                .checked_add(1)
                .ok_or(StoreError::Backend)?;
            Some(Self::next_registration_version_memory(
                &registration,
                &record.sub,
            )?)
        };
        user.password_hash = Some(password_hash.to_string());
        user.factor_epoch = next_factor_epoch;
        if let Some(account_version) = next_registration_version {
            user.email_verified = true;
            let disabled_by_lifecycle = lifecycle
                .get(&record.sub)
                .is_some_and(|fence| fence.disabled_by_lifecycle);
            let (state, enabled) = registration_state(true, user.disabled, disabled_by_lifecycle);
            Self::append_registration_event_memory(
                &mut registration,
                &record.sub,
                account_version,
                state,
                true,
                enabled,
                now_secs(),
            )?;
        }
        tokens.remove(token);
        Ok(Some((record.sub, next_factor_epoch)))
    }

    async fn create_registration_snapshot(
        &self,
    ) -> Result<RegistrationSnapshotManifest, RegistrationFeedError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| RegistrationFeedError::Backend)?;
        let lifecycle = self
            .subject_lifecycle
            .lock()
            .map_err(|_| RegistrationFeedError::Backend)?;
        let users = self
            .users
            .lock()
            .map_err(|_| RegistrationFeedError::Backend)?;
        let mut authority = self
            .registration
            .lock()
            .map_err(|_| RegistrationFeedError::Backend)?;
        let mut rows = Vec::with_capacity(users.len() + authority.tombstones.len());
        for (raw_sub, user) in users.iter() {
            let disabled_by_lifecycle = lifecycle
                .get(raw_sub)
                .is_some_and(|fence| fence.disabled_by_lifecycle);
            let (state, enabled) =
                registration_state(user.email_verified, user.disabled, disabled_by_lifecycle);
            let subject = canonical_registration_subject(raw_sub);
            let account_version = authority.versions.get(raw_sub).copied().unwrap_or(0);
            rows.push(RegistrationSnapshotRow {
                ordinal: 0,
                payload_hash: registration_payload_hash(
                    &subject,
                    account_version,
                    state,
                    user.email_verified,
                    enabled,
                ),
                subject,
                account_version,
                registration_state: state,
                email_verified: user.email_verified,
                enabled,
            });
        }
        for (raw_sub, tombstone) in &authority.tombstones {
            if !users.contains_key(raw_sub) {
                rows.push(tombstone.clone());
            }
        }
        rows.sort_by(|left, right| left.subject.cmp(&right.subject));
        for (index, row) in rows.iter_mut().enumerate() {
            row.ordinal = u64::try_from(index + 1).map_err(|_| RegistrationFeedError::Backend)?;
        }
        let snapshot_id = format!("irs_{}", uuid::Uuid::new_v4().simple());
        let high_watermark = authority.clock;
        let (high_watermark_event_id, high_watermark_payload_hash) = if high_watermark == 0 {
            (String::new(), String::new())
        } else {
            let evidence = authority
                .outbox
                .iter()
                .find(|event| event.cursor == high_watermark)
                .map(|event| (event.event_id.clone(), event.payload_hash.clone()))
                .or_else(|| {
                    authority
                        .acknowledgements
                        .values()
                        .find(|ack| ack.cursor == high_watermark)
                        .map(|ack| (ack.event_id.clone(), ack.payload_hash.clone()))
                })
                .ok_or(RegistrationFeedError::Backend)?;
            if !valid_registration_watermark_evidence(high_watermark, &evidence.0, &evidence.1) {
                return Err(RegistrationFeedError::Backend);
            }
            evidence
        };
        let digest = registration_snapshot_digest(high_watermark, &rows);
        let manifest = RegistrationSnapshotManifest {
            snapshot_id: snapshot_id.clone(),
            generation: authority.generation,
            high_watermark,
            high_watermark_event_id,
            high_watermark_payload_hash,
            count: rows.len() as u64,
            digest,
        };
        authority.snapshots.insert(
            snapshot_id,
            InMemoryRegistrationSnapshot {
                manifest: manifest.clone(),
                rows,
            },
        );
        Ok(manifest)
    }

    async fn get_registration_snapshot_page(
        &self,
        snapshot_id: &str,
        after_ordinal: u64,
        limit: u16,
    ) -> Result<RegistrationSnapshotPage, RegistrationFeedError> {
        let authority = self
            .registration
            .lock()
            .map_err(|_| RegistrationFeedError::Backend)?;
        let snapshot = authority
            .snapshots
            .get(snapshot_id)
            .ok_or(RegistrationFeedError::SnapshotIncomplete)?;
        let rows: Vec<_> = snapshot
            .rows
            .iter()
            .filter(|row| row.ordinal > after_ordinal)
            .take(limit as usize)
            .cloned()
            .collect();
        let next_after_ordinal = rows.last().map(|row| row.ordinal).unwrap_or(after_ordinal);
        Ok(RegistrationSnapshotPage {
            snapshot_id: snapshot.manifest.snapshot_id.clone(),
            generation: snapshot.manifest.generation,
            high_watermark: snapshot.manifest.high_watermark,
            high_watermark_event_id: snapshot.manifest.high_watermark_event_id.clone(),
            high_watermark_payload_hash: snapshot.manifest.high_watermark_payload_hash.clone(),
            digest: snapshot.manifest.digest.clone(),
            done: next_after_ordinal >= snapshot.manifest.count,
            rows,
            next_after_ordinal,
        })
    }

    async fn get_registration_changes(
        &self,
        after: u64,
        limit: u16,
    ) -> Result<RegistrationChangesPage, RegistrationFeedError> {
        let authority = self
            .registration
            .lock()
            .map_err(|_| RegistrationFeedError::Backend)?;
        let head_cursor = authority.clock;
        let retention_floor_cursor = authority.retention_floor_cursor;
        if after < retention_floor_cursor {
            return Err(RegistrationFeedError::ResnapshotRequired);
        }
        if after > head_cursor {
            return Err(RegistrationFeedError::FeedGap);
        }
        let events: Vec<_> = authority
            .outbox
            .iter()
            .filter(|event| event.cursor > after)
            .take(limit as usize)
            .cloned()
            .collect();
        if after < head_cursor
            && events
                .first()
                .is_none_or(|event| event.cursor != after.saturating_add(1))
        {
            return Err(RegistrationFeedError::FeedGap);
        }
        Ok(RegistrationChangesPage {
            generation: authority.generation,
            events,
            head_cursor,
            retention_floor_cursor,
        })
    }

    async fn acknowledge_registration(
        &self,
        command: RegistrationAckCommand,
    ) -> Result<RegistrationAckOutcome, RegistrationFeedError> {
        let mut authority = self
            .registration
            .lock()
            .map_err(|_| RegistrationFeedError::Backend)?;
        if command.generation == 0 || command.generation != authority.generation {
            return Err(RegistrationFeedError::AckGenerationConflict);
        }
        if command.acked_cursor > authority.clock {
            return Err(RegistrationFeedError::AckAhead);
        }
        let mut event_verified_from_ack = false;
        if let Some(current) = authority.acknowledgements.get(&command.consumer) {
            if current.generation > command.generation {
                return Err(RegistrationFeedError::AckGenerationConflict);
            }
            if command.acked_cursor < current.cursor {
                return Err(RegistrationFeedError::AckRegression);
            }
            if command.acked_cursor == current.cursor
                && (command.event_id != current.event_id
                    || command.payload_hash != current.payload_hash)
            {
                return Err(RegistrationFeedError::AckEventMismatch);
            }
            if command.acked_cursor == current.cursor {
                if current.generation == command.generation {
                    return Ok(RegistrationAckOutcome {
                        consumer: command.consumer,
                        generation: command.generation,
                        stored_cursor: command.acked_cursor,
                    });
                }
                event_verified_from_ack = true;
            }
        }
        if !event_verified_from_ack {
            let event = authority
                .outbox
                .iter()
                .find(|event| event.cursor == command.acked_cursor)
                .ok_or(RegistrationFeedError::AckEventMismatch)?;
            if event.event_id != command.event_id || event.payload_hash != command.payload_hash {
                return Err(RegistrationFeedError::AckEventMismatch);
            }
        }
        authority.acknowledgements.insert(
            command.consumer.clone(),
            InMemoryRegistrationAck {
                generation: command.generation,
                cursor: command.acked_cursor,
                event_id: command.event_id,
                payload_hash: command.payload_hash,
            },
        );
        let minimum_ack = authority
            .acknowledgements
            .values()
            .map(|ack| ack.cursor)
            .min()
            .unwrap_or(0);
        let cutoff = now_secs().saturating_sub(REGISTRATION_RETENTION_SECONDS);
        let time_floor = authority
            .outbox
            .iter()
            .find(|event| event.occurred_at >= cutoff)
            .map(|event| event.cursor.saturating_sub(1))
            .unwrap_or(authority.clock);
        let next_floor = authority
            .retention_floor_cursor
            .max(minimum_ack.min(time_floor));
        if next_floor > authority.retention_floor_cursor {
            authority.outbox.retain(|event| event.cursor > next_floor);
            authority.retention_floor_cursor = next_floor;
        }
        Ok(RegistrationAckOutcome {
            consumer: command.consumer,
            generation: command.generation,
            stored_cursor: command.acked_cursor,
        })
    }

    async fn claim_registration_nonce(
        &self,
        nonce_hash: &str,
        _kid: &str,
        _audience: &str,
        seen_at: u64,
        expires_at: u64,
    ) -> Result<(), RegistrationFeedError> {
        let mut authority = self
            .registration
            .lock()
            .map_err(|_| RegistrationFeedError::Backend)?;
        authority
            .replay_nonces
            .retain(|_, expires| *expires >= seen_at);
        if authority.replay_nonces.contains_key(nonce_hash) {
            return Err(RegistrationFeedError::Replay);
        }
        authority
            .replay_nonces
            .insert(nonce_hash.to_string(), expires_at);
        Ok(())
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

    async fn redeem_code(
        &self,
        code: &str,
        now: u64,
    ) -> Result<Option<RedeemedAuthCode>, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let Some(code) = self
            .codes
            .lock()
            .map_err(|_| StoreError::Backend)?
            .remove(code)
        else {
            return Ok(None);
        };
        let Some(user) = self
            .users
            .lock()
            .map_err(|_| StoreError::Backend)?
            .get(&code.sub)
            .cloned()
            .filter(|user| !user.disabled)
        else {
            return Ok(None);
        };

        let (assurance, session_expires_at) = match code.binding.as_ref() {
            None => (None, None),
            Some(binding) => {
                let session = self
                    .sessions
                    .lock()
                    .map_err(|_| StoreError::Backend)?
                    .values()
                    .find(|session| {
                        session.session_binding.as_deref() == Some(binding.session_binding.as_str())
                    })
                    .cloned();
                let Some(session) = session.filter(|session| {
                    session.user_sub == code.sub
                        && user.factor_epoch == binding.factor_epoch
                        && binding.matches_session(session)
                }) else {
                    return Ok(None);
                };
                let assurance = session.assurance().ok_or(StoreError::Backend)?;
                (Some(assurance), Some(session.expires_at))
            }
        };
        // `now` is only a caller-supplied lower bound. Re-sample after every in-memory
        // lifecycle/session lock has been acquired so lock contention cannot extend a code or
        // session lifetime.
        let validated_at = now.max(now_secs());
        if validated_at > code.expires_at
            || session_expires_at.is_some_and(|expires_at| validated_at > expires_at)
        {
            return Ok(None);
        }
        Ok(Some(RedeemedAuthCode {
            code,
            user,
            assurance,
            validated_at,
            session_expires_at,
        }))
    }

    async fn put_session_if_active(&self, session: Session) -> Result<bool, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let active = self
            .users
            .lock()
            .map_err(|_| StoreError::Backend)?
            .get(&session.user_sub)
            .is_some_and(|user| !user.disabled && user.factor_epoch == session.factor_epoch);
        if !active {
            return Ok(false);
        }
        self.sessions
            .lock()
            .map_err(|_| StoreError::Backend)?
            .insert(session.id.clone(), session);
        Ok(true)
    }

    async fn get_session(&self, id: &str) -> Option<Session> {
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .get(id)
            .cloned()
    }

    async fn delete_session(&self, id: &str) {
        let _guard = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle_guard lock poisoned");
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
        v.sort_by_key(|session| Reverse(session.created_at));
        v
    }

    async fn revoke_session(&self, user_sub: &str, id: &str) {
        let _guard = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle_guard lock poisoned");
        let mut g = self.sessions.lock().expect("sessions lock poisoned");
        // Ownership check: never let one user delete another user's session id.
        if g.get(id).is_some_and(|s| s.user_sub == user_sub) {
            g.remove(id);
        }
    }

    async fn revoke_other_sessions(&self, user_sub: &str, keep_id: &str) {
        let _guard = self
            .lifecycle_guard
            .lock()
            .expect("lifecycle_guard lock poisoned");
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

    async fn lookup_session_assurance(
        &self,
        subject: &str,
        session_binding: &str,
        now: u64,
    ) -> Result<SessionAssuranceLookup, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let user = self
            .users
            .lock()
            .map_err(|_| StoreError::Backend)?
            .get(subject)
            .cloned();
        let factor_epoch = user.as_ref().map_or(0, |user| user.factor_epoch);
        let Some(user) = user.filter(|user| !user.disabled) else {
            return Ok(SessionAssuranceLookup::Absent { factor_epoch });
        };
        let session = self
            .sessions
            .lock()
            .map_err(|_| StoreError::Backend)?
            .values()
            .find(|session| session.session_binding.as_deref() == Some(session_binding))
            .cloned();
        let Some(session) = session.filter(|session| {
            session.user_sub == subject
                && now <= session.expires_at
                && session.factor_epoch == user.factor_epoch
        }) else {
            return Ok(SessionAssuranceLookup::Absent { factor_epoch });
        };
        match session.assurance() {
            Some(assurance) => Ok(SessionAssuranceLookup::Live(assurance)),
            None => Ok(SessionAssuranceLookup::Absent { factor_epoch }),
        }
    }

    async fn bump_factor_epoch(&self, user_sub: &str) -> Result<u64, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut users = self.users.lock().map_err(|_| StoreError::Backend)?;
        let user = users.get_mut(user_sub).ok_or(StoreError::Backend)?;
        user.factor_epoch = user
            .factor_epoch
            .checked_add(1)
            .ok_or(StoreError::Backend)?;
        Ok(user.factor_epoch)
    }

    async fn put_credential(&self, cred: Credential) {
        self.credentials
            .lock()
            .expect("credentials lock poisoned")
            .insert(cred.cred_id.clone(), cred);
    }

    async fn put_credential_and_bump_factor(&self, cred: Credential) -> Result<u64, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut users = self.users.lock().map_err(|_| StoreError::Backend)?;
        let user = users
            .get_mut(&cred.user_sub)
            .filter(|user| !user.disabled)
            .ok_or(StoreError::Backend)?;
        let next = user
            .factor_epoch
            .checked_add(1)
            .ok_or(StoreError::Backend)?;
        self.credentials
            .lock()
            .map_err(|_| StoreError::Backend)?
            .insert(cred.cred_id.clone(), cred);
        user.factor_epoch = next;
        Ok(next)
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

    async fn get_totp(&self, user_sub: &str) -> Option<TotpConfig> {
        self.totp
            .lock()
            .expect("totp lock poisoned")
            .get(user_sub)
            .cloned()
    }

    async fn put_totp(&self, config: TotpConfig) {
        self.totp
            .lock()
            .expect("totp lock poisoned")
            .insert(config.user_sub.clone(), config);
    }

    async fn begin_totp_enrollment(&self, config: TotpConfig) -> Result<u64, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut users = self.users.lock().map_err(|_| StoreError::Backend)?;
        let user = users
            .get_mut(&config.user_sub)
            .filter(|user| !user.disabled)
            .ok_or(StoreError::Backend)?;
        let next = user
            .factor_epoch
            .checked_add(1)
            .ok_or(StoreError::Backend)?;
        self.totp
            .lock()
            .map_err(|_| StoreError::Backend)?
            .insert(config.user_sub.clone(), config.clone());
        self.recovery_codes
            .lock()
            .map_err(|_| StoreError::Backend)?
            .retain(|(sub, _), _| sub != &config.user_sub);
        user.factor_epoch = next;
        Ok(next)
    }

    async fn enable_totp(
        &self,
        user_sub: &str,
        expected_secret: &str,
        accepted_counter: u64,
        verified_at: u64,
        code_hashes: Vec<String>,
    ) -> Result<bool, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let active = self
            .users
            .lock()
            .map_err(|_| StoreError::Backend)?
            .get(user_sub)
            .is_some_and(|user| !user.disabled);
        if !active {
            return Ok(false);
        }
        let mut configs = self.totp.lock().map_err(|_| StoreError::Backend)?;
        let Some(config) = configs.get_mut(user_sub).filter(|config| {
            !config.enabled
                && config.secret == expected_secret
                && config
                    .last_accepted_counter
                    .is_none_or(|last| last < accepted_counter)
        }) else {
            return Ok(false);
        };
        config.enabled = true;
        config.verified_at = verified_at;
        config.last_accepted_counter = Some(accepted_counter);
        let mut recovery = self
            .recovery_codes
            .lock()
            .map_err(|_| StoreError::Backend)?;
        recovery.retain(|(sub, _), _| sub != user_sub);
        for code_hash in code_hashes {
            recovery.insert(
                (user_sub.to_string(), code_hash.clone()),
                TotpRecoveryCode {
                    user_sub: user_sub.to_string(),
                    code_hash,
                    created_at: verified_at,
                },
            );
        }
        Ok(true)
    }

    async fn accept_totp_counter(
        &self,
        user_sub: &str,
        expected_secret: &str,
        counter: u64,
    ) -> Result<Option<u64>, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let epoch = self
            .users
            .lock()
            .map_err(|_| StoreError::Backend)?
            .get(user_sub)
            .filter(|user| !user.disabled)
            .map(|user| user.factor_epoch);
        let Some(epoch) = epoch else {
            return Ok(None);
        };
        let mut configs = self.totp.lock().map_err(|_| StoreError::Backend)?;
        let Some(config) = configs.get_mut(user_sub).filter(|config| {
            config.enabled
                && config.secret == expected_secret
                && config
                    .last_accepted_counter
                    .is_none_or(|last| last < counter)
        }) else {
            return Ok(None);
        };
        config.last_accepted_counter = Some(counter);
        Ok(Some(epoch))
    }

    async fn delete_totp(&self, user_sub: &str) {
        self.totp
            .lock()
            .expect("totp lock poisoned")
            .remove(user_sub);
        self.recovery_codes
            .lock()
            .expect("recovery_codes lock poisoned")
            .retain(|(sub, _), _| sub != user_sub);
    }

    async fn disable_totp_and_bump_factor(&self, user_sub: &str) -> Result<u64, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut users = self.users.lock().map_err(|_| StoreError::Backend)?;
        let user = users.get_mut(user_sub).ok_or(StoreError::Backend)?;
        let next = user
            .factor_epoch
            .checked_add(1)
            .ok_or(StoreError::Backend)?;
        self.totp
            .lock()
            .map_err(|_| StoreError::Backend)?
            .remove(user_sub);
        self.recovery_codes
            .lock()
            .map_err(|_| StoreError::Backend)?
            .retain(|(sub, _), _| sub != user_sub);
        user.factor_epoch = next;
        Ok(next)
    }

    async fn put_recovery_codes(&self, user_sub: &str, code_hashes: Vec<String>, created_at: u64) {
        let mut g = self
            .recovery_codes
            .lock()
            .expect("recovery_codes lock poisoned");
        g.retain(|(sub, _), _| sub != user_sub);
        for code_hash in code_hashes {
            g.insert(
                (user_sub.to_string(), code_hash.clone()),
                TotpRecoveryCode {
                    user_sub: user_sub.to_string(),
                    code_hash,
                    created_at,
                },
            );
        }
    }

    async fn recovery_code_count(&self, user_sub: &str) -> usize {
        self.recovery_codes
            .lock()
            .expect("recovery_codes lock poisoned")
            .values()
            .filter(|c| c.user_sub == user_sub)
            .count()
    }

    async fn take_recovery_code(&self, user_sub: &str, code_hash: &str) -> bool {
        self.recovery_codes
            .lock()
            .expect("recovery_codes lock poisoned")
            .remove(&(user_sub.to_string(), code_hash.to_string()))
            .is_some()
    }

    async fn take_recovery_code_and_bump_factor(
        &self,
        user_sub: &str,
        code_hash: &str,
    ) -> Result<Option<u64>, StoreError> {
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let mut users = self.users.lock().map_err(|_| StoreError::Backend)?;
        let Some(user) = users.get_mut(user_sub).filter(|user| !user.disabled) else {
            return Ok(None);
        };
        let next = user
            .factor_epoch
            .checked_add(1)
            .ok_or(StoreError::Backend)?;
        let removed = self
            .recovery_codes
            .lock()
            .map_err(|_| StoreError::Backend)?
            .remove(&(user_sub.to_string(), code_hash.to_string()))
            .is_some();
        if !removed {
            return Ok(None);
        }
        user.factor_epoch = next;
        Ok(Some(next))
    }

    async fn put_totp_challenge(&self, challenge: TotpChallenge) {
        self.totp_challenges
            .lock()
            .expect("totp_challenges lock poisoned")
            .insert(challenge.id.clone(), challenge);
    }

    async fn take_totp_challenge(&self, id: &str) -> Option<TotpChallenge> {
        let challenge = self
            .totp_challenges
            .lock()
            .expect("totp_challenges lock poisoned")
            .remove(id)?;
        if now_secs() > challenge.expires_at {
            return None;
        }
        Some(challenge)
    }

    async fn put_login_event(&self, event: LoginEvent) {
        self.login_events
            .lock()
            .expect("login_events lock poisoned")
            .push(event);
    }

    async fn list_login_events(&self, user_sub: &str, limit: usize) -> Vec<LoginEvent> {
        let mut v: Vec<LoginEvent> = self
            .login_events
            .lock()
            .expect("login_events lock poisoned")
            .iter()
            .filter(|e| e.user_sub == user_sub)
            .cloned()
            .collect();
        v.sort_by_key(|event| Reverse(event.occurred_at));
        v.truncate(limit);
        v
    }

    async fn put_personal_token(&self, token: PersonalAccessToken) -> Result<(), StoreError> {
        #[cfg(test)]
        if self.fail_personal_token_put.load(Ordering::SeqCst) {
            return Err(StoreError::Backend);
        }
        let _guard = self
            .lifecycle_guard
            .lock()
            .map_err(|_| StoreError::Backend)?;
        let active = self
            .users
            .lock()
            .map_err(|_| StoreError::Backend)?
            .get(&token.user_sub)
            .is_some_and(|user| !user.disabled);
        if !active {
            return Err(StoreError::Backend);
        }
        let mut personal_tokens = self
            .personal_tokens
            .lock()
            .map_err(|_| StoreError::Backend)?;
        if personal_tokens.contains_key(&token.id)
            || personal_tokens
                .values()
                .any(|existing| existing.token_hash == token.token_hash)
        {
            return Err(StoreError::Backend);
        }
        personal_tokens.insert(token.id.clone(), token);
        Ok(())
    }

    async fn list_personal_tokens(&self, user_sub: &str) -> Vec<PersonalAccessToken> {
        let mut v: Vec<PersonalAccessToken> = self
            .personal_tokens
            .lock()
            .expect("personal_tokens lock poisoned")
            .values()
            .filter(|t| t.user_sub == user_sub && t.revoked_at == 0)
            .cloned()
            .collect();
        v.sort_by_key(|token| Reverse(token.created_at));
        v
    }

    async fn find_active_personal_token(
        &self,
        token_hash: &str,
        now: u64,
    ) -> Result<Option<PersonalAccessToken>, StoreError> {
        let token = self
            .personal_tokens
            .lock()
            .expect("personal_tokens lock poisoned")
            .values()
            .find(|token| {
                token.token_hash == token_hash && token.revoked_at == 0 && token.expires_at > now
            })
            .cloned();
        let Some(token) = token else {
            return Ok(None);
        };
        let enabled_owner = self
            .users
            .lock()
            .expect("users lock poisoned")
            .get(&token.user_sub)
            .is_some_and(|user| !user.disabled);
        Ok(enabled_owner.then_some(token))
    }

    async fn revoke_personal_token(
        &self,
        user_sub: &str,
        id: &str,
        revoked_at: u64,
    ) -> Result<(), StoreError> {
        #[cfg(test)]
        if self.fail_personal_token_revoke.load(Ordering::SeqCst) {
            return Err(StoreError::Backend);
        }
        if revoked_at == 0 {
            return Err(StoreError::Backend);
        }
        if let Some(token) = self
            .personal_tokens
            .lock()
            .expect("personal_tokens lock poisoned")
            .get_mut(id)
        {
            if token.user_sub == user_sub && token.revoked_at == 0 {
                token.revoked_at = revoked_at;
            }
        }
        Ok(())
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
use sqlx::{Postgres, Row, Transaction};

/// PostgreSQL-backed [`Store`]. Holds a `PgPool`; the async trait methods drive sqlx natively,
/// so no worker thread is ever blocked on a DB round-trip.
pub struct PgStore {
    pool: PgPool,
}

#[derive(Debug)]
enum PgSubjectLifecycleError {
    Conflict,
    Backend(sqlx::Error),
}

impl From<sqlx::Error> for PgSubjectLifecycleError {
    fn from(value: sqlx::Error) -> Self {
        Self::Backend(value)
    }
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
        // First-party flag: platform-owned clients skip the consent screen. Default false so
        // any newly-registered third-party client requires consent; the seeded first-party
        // clients (Sluice) re-upsert with true on every startup.
        sqlx::query("ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS first_party BOOLEAN NOT NULL DEFAULT false")
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
        // Recorded user consent per (user, client): the granted scope set + when. Presence of a
        // covering row lets a third-party client skip the consent screen on subsequent authorizes.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS consents (\
                 user_sub TEXT NOT NULL, \
                 client_id TEXT NOT NULL, \
                 scope TEXT NOT NULL, \
                 granted_at BIGINT NOT NULL, \
                 PRIMARY KEY (user_sub, client_id)\
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
        sqlx::query(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at BIGINT NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await?;
        // Additive, idempotent columns for the `/admin` operator console.
        sqlx::query(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT false",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT false",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS factor_epoch BIGINT NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS account_version BIGINT NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_factor_epoch_nonnegative",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE users ADD CONSTRAINT ck_users_factor_epoch_nonnegative \
             CHECK (factor_epoch >= 0) NOT VALID",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE users VALIDATE CONSTRAINT ck_users_factor_epoch_nonnegative")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_account_version_nonnegative",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE users ADD CONSTRAINT ck_users_account_version_nonnegative \
             CHECK (account_version >= 0) NOT VALID",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE users VALIDATE CONSTRAINT ck_users_account_version_nonnegative")
            .execute(&self.pool)
            .await?;
        // CRITICAL backfill: rows that predate `email_verified` (created_at still 0 — seeded or
        // manually provisioned accounts like u_admin/w33d) are trusted and MUST stay able to log
        // in. Flip them to verified once, right after the ALTERs. Idempotent: re-running only
        // re-touches those same legacy rows (self-service users carry a real created_at > 0).
        sqlx::query("UPDATE users SET email_verified = true WHERE created_at = 0")
            .execute(&self.pool)
            .await?;
        // Same trick for the admin bit: pre-existing seeded/provisioned accounts (created_at=0,
        // i.e. the operator) are admins out of the box, so `/admin` can never lock everyone out.
        sqlx::query("UPDATE users SET is_admin = true WHERE created_at = 0")
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
        for statement in [
            "ALTER TABLE auth_codes ADD COLUMN IF NOT EXISTS snap_session_binding TEXT",
            "ALTER TABLE auth_codes ADD COLUMN IF NOT EXISTS snap_aal TEXT",
            "ALTER TABLE auth_codes ADD COLUMN IF NOT EXISTS snap_uv BOOLEAN",
            "ALTER TABLE auth_codes ADD COLUMN IF NOT EXISTS snap_auth_time BIGINT",
            "ALTER TABLE auth_codes ADD COLUMN IF NOT EXISTS snap_factor_epoch BIGINT",
            "ALTER TABLE auth_codes ADD COLUMN IF NOT EXISTS required_acr TEXT",
        ] {
            sqlx::query(statement).execute(&self.pool).await?;
        }
        sqlx::query(
            "ALTER TABLE auth_codes DROP CONSTRAINT IF EXISTS ck_auth_codes_assurance_snapshot",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE auth_codes ADD CONSTRAINT ck_auth_codes_assurance_snapshot CHECK (\
                 (snap_session_binding IS NULL AND snap_aal IS NULL AND snap_uv IS NULL AND \
                  snap_auth_time IS NULL AND snap_factor_epoch IS NULL) OR \
                 (snap_session_binding ~ '^[0-9a-f]{64}$' AND \
                  snap_aal IN ('AAL_NONE','MFA_STRONG') AND snap_uv IS NOT NULL AND \
                  snap_auth_time >= 0 AND snap_factor_epoch >= 0)\
             ) NOT VALID",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE auth_codes VALIDATE CONSTRAINT ck_auth_codes_assurance_snapshot")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE auth_codes DROP CONSTRAINT IF EXISTS ck_auth_codes_required_acr")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE auth_codes ADD CONSTRAINT ck_auth_codes_required_acr \
             CHECK (required_acr IS NULL OR \
                    (required_acr='hf-aal-strong' AND snap_session_binding IS NOT NULL AND \
                     snap_aal='MFA_STRONG' AND snap_uv=TRUE AND snap_auth_time>0)) \
             NOT VALID",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE auth_codes VALIDATE CONSTRAINT ck_auth_codes_required_acr")
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
        sqlx::query(
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip TEXT NOT NULL DEFAULT ''")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen BIGINT NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await?;
        for statement in [
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS session_binding TEXT",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS aal TEXT NOT NULL DEFAULT 'AAL_NONE'",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS uv BOOLEAN NOT NULL DEFAULT false",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_time BIGINT NOT NULL DEFAULT 0",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS amr TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS factor_epoch BIGINT NOT NULL DEFAULT 0",
        ] {
            sqlx::query(statement).execute(&self.pool).await?;
        }
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS sessions_binding_uidx ON sessions(session_binding) \
             WHERE session_binding IS NOT NULL",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE sessions DROP CONSTRAINT IF EXISTS ck_sessions_assurance")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE sessions ADD CONSTRAINT ck_sessions_assurance CHECK (\
                 (session_binding IS NULL OR session_binding ~ '^[0-9a-f]{64}$') AND \
                 aal IN ('AAL_NONE','MFA_STRONG') AND auth_time >= 0 AND factor_epoch >= 0 AND \
                 amr IN ('','pwd,otp','hwk,user') AND \
                 ((aal='AAL_NONE' AND uv=false AND auth_time=0 AND amr='') OR \
                  (aal='MFA_STRONG' AND auth_time>0 AND amr<>''))\
             ) NOT VALID",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE sessions VALIDATE CONSTRAINT ck_sessions_assurance")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS sessions_user_sub_idx ON sessions (user_sub)")
            .execute(&self.pool)
            .await?;
        // Durable per-subject JML fence. There is deliberately no FK to users: leaver events
        // for an identity not yet (or no longer) present in Keystone remain tombstoned.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS subject_lifecycle_fences (\
                 subject TEXT PRIMARY KEY, \
                 state TEXT NOT NULL CHECK (state IN ('active', 'frozen', 'terminated')), \
                 source_event_id TEXT NOT NULL, \
                 source_version BIGINT NOT NULL \
                     CONSTRAINT ck_subject_lifecycle_source_version_positive \
                     CHECK (source_version > 0), \
                 correlation_id TEXT NOT NULL, \
                 user_found BOOLEAN NOT NULL, \
                 revoked_sessions BIGINT NOT NULL CHECK (revoked_sessions >= 0), \
                 disabled_by_lifecycle BOOLEAN NOT NULL DEFAULT FALSE, \
                 updated_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        let invalid_lifecycle_versions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM subject_lifecycle_fences WHERE source_version <= 0",
        )
        .fetch_one(&self.pool)
        .await?;
        if invalid_lifecycle_versions != 0 {
            return Err(sqlx::Error::Protocol(format!(
                "subject_lifecycle_fences contains {invalid_lifecycle_versions} non-positive \
                 source_version row(s); remediate authoritative JML versions before migration"
            )));
        }
        // Older deployments used an unnamed `>= 0` check. Replace it only after the
        // explicit preflight above, then validate the stronger invariant before startup.
        sqlx::query(
            "ALTER TABLE subject_lifecycle_fences DROP CONSTRAINT IF EXISTS \
             subject_lifecycle_fences_source_version_check",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "DO $$ BEGIN \
                 IF NOT EXISTS (\
                     SELECT 1 FROM pg_constraint \
                     WHERE conrelid='subject_lifecycle_fences'::regclass \
                       AND conname='ck_subject_lifecycle_source_version_positive'\
                 ) THEN \
                     ALTER TABLE subject_lifecycle_fences ADD CONSTRAINT \
                         ck_subject_lifecycle_source_version_positive \
                         CHECK (source_version > 0) NOT VALID; \
                 END IF; \
             END $$",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE subject_lifecycle_fences VALIDATE CONSTRAINT \
             ck_subject_lifecycle_source_version_positive",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE subject_lifecycle_fences \
             ADD COLUMN IF NOT EXISTS disabled_by_lifecycle BOOLEAN NOT NULL DEFAULT FALSE",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS subject_lifecycle_source_event_idx \
             ON subject_lifecycle_fences (source_event_id)",
        )
        .execute(&self.pool)
        .await?;
        // Keystone is the registration authority. The clock row is updated in the same
        // transaction as every identity mutation, so a rollback never consumes a cursor.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS identity_outbox_clock (\
                 id SMALLINT PRIMARY KEY CHECK (id = 1), \
                 next_cursor BIGINT NOT NULL CHECK (next_cursor >= 0), \
                 generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0), \
                 retention_floor_cursor BIGINT NOT NULL DEFAULT 0 \
                     CHECK (retention_floor_cursor >= 0)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE identity_outbox_clock ADD COLUMN IF NOT EXISTS \
             generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE identity_outbox_clock ADD COLUMN IF NOT EXISTS \
             retention_floor_cursor BIGINT NOT NULL DEFAULT 0 \
             CHECK (retention_floor_cursor >= 0)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "INSERT INTO identity_outbox_clock (id, next_cursor, generation) VALUES (1, 0, 1) \
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS identity_registration_outbox (\
                 cursor BIGINT PRIMARY KEY CHECK (cursor > 0), \
                 event_id TEXT NOT NULL UNIQUE, \
                 subject TEXT NOT NULL CHECK (subject ~ '^user:[^[:space:]]+$'), \
                 account_version BIGINT NOT NULL CHECK (account_version > 0), \
                 registration_state TEXT NOT NULL \
                     CHECK (registration_state IN ('registered','unverified','disabled','deleted')), \
                 enabled BOOLEAN NOT NULL, \
                 email_verified BOOLEAN NOT NULL, \
                 payload_hash TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'), \
                 occurred_at BIGINT NOT NULL CHECK (occurred_at >= 0), \
                 UNIQUE (subject, account_version)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS identity_registration_outbox_subject_idx \
             ON identity_registration_outbox (subject, account_version)",
        )
        .execute(&self.pool)
        .await?;
        // Recover a durable floor if a previous binary or operator already pruned a prefix.
        // This makes lagging consumers receive 410 instead of treating a known prefix as a gap.
        sqlx::query(
            "UPDATE identity_outbox_clock SET retention_floor_cursor=GREATEST(\
                 retention_floor_cursor,COALESCE(\
                   (SELECT MIN(cursor)-1 FROM identity_registration_outbox),next_cursor)) \
             WHERE id=1",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS identity_registration_tombstone (\
                 subject TEXT PRIMARY KEY CHECK (subject ~ '^user:[^[:space:]]+$'), \
                 account_version BIGINT NOT NULL CHECK (account_version > 0), \
                 payload_hash TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'), \
                 occurred_at BIGINT NOT NULL CHECK (occurred_at >= 0)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS identity_registration_snapshot (\
                 snapshot_id TEXT PRIMARY KEY, \
                 generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0), \
                 high_watermark BIGINT NOT NULL CHECK (high_watermark >= 0), \
                 high_watermark_event_id TEXT, \
                 high_watermark_payload_hash TEXT, \
                 row_count BIGINT NOT NULL CHECK (row_count >= 0), \
                 digest TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'), \
                 complete BOOLEAN NOT NULL DEFAULT FALSE, \
                 created_at BIGINT NOT NULL CHECK (created_at >= 0)\
             )",
        )
        .execute(&self.pool)
        .await?;
        // The nullable columns distinguish snapshots sealed by a legacy binary. Such a
        // manifest remains immutable but is rejected by page reads, forcing a fresh snapshot.
        sqlx::query(
            "ALTER TABLE identity_registration_snapshot ADD COLUMN IF NOT EXISTS \
             high_watermark_event_id TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE identity_registration_snapshot ADD COLUMN IF NOT EXISTS \
             high_watermark_payload_hash TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE identity_registration_snapshot DROP CONSTRAINT IF EXISTS \
             identity_reg_snapshot_hwm_ack_check",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE identity_registration_snapshot ADD CONSTRAINT \
             identity_reg_snapshot_hwm_ack_check CHECK (\
                 (high_watermark_event_id IS NULL AND high_watermark_payload_hash IS NULL) OR \
                 (high_watermark_event_id IS NOT NULL AND \
                  high_watermark_payload_hash IS NOT NULL AND (\
                     (high_watermark=0 AND high_watermark_event_id='' AND \
                         high_watermark_payload_hash='') OR \
                     (high_watermark>0 AND \
                         high_watermark_payload_hash ~ '^[0-9a-f]{64}$' AND \
                         high_watermark_event_id = 'ire_' || \
                             lpad(to_hex(high_watermark),16,'0') || '_' || \
                             left(high_watermark_payload_hash,16))\
                 ))\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE identity_registration_snapshot ADD COLUMN IF NOT EXISTS \
             generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS identity_registration_snapshot_row (\
                 snapshot_id TEXT NOT NULL REFERENCES identity_registration_snapshot(snapshot_id) \
                     ON DELETE RESTRICT, \
                 ordinal BIGINT NOT NULL CHECK (ordinal > 0), \
                 subject TEXT NOT NULL CHECK (subject ~ '^user:[^[:space:]]+$'), \
                 account_version BIGINT NOT NULL CHECK (account_version >= 0), \
                 registration_state TEXT NOT NULL \
                     CHECK (registration_state IN ('registered','unverified','disabled','deleted')), \
                 email_verified BOOLEAN NOT NULL, \
                 enabled BOOLEAN NOT NULL, \
                 payload_hash TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'), \
                 PRIMARY KEY (snapshot_id, subject), \
                 UNIQUE (snapshot_id, ordinal)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS identity_registration_consumer_ack (\
                 consumer TEXT PRIMARY KEY, \
                 acked_cursor BIGINT NOT NULL CHECK (acked_cursor > 0), \
                 generation BIGINT NOT NULL CHECK (generation > 0), \
                 event_id TEXT NOT NULL, \
                 payload_hash TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'), \
                 updated_at BIGINT NOT NULL CHECK (updated_at >= 0)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS identity_registration_replay (\
                 nonce_hash TEXT PRIMARY KEY CHECK (nonce_hash ~ '^[0-9a-f]{64}$'), \
                 kid TEXT NOT NULL, \
                 audience TEXT NOT NULL, \
                 seen_at BIGINT NOT NULL CHECK (seen_at >= 0), \
                 expires_at BIGINT NOT NULL CHECK (expires_at >= seen_at)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS identity_registration_replay_expiry_idx \
             ON identity_registration_replay (expires_at)",
        )
        .execute(&self.pool)
        .await?;
        // Completed manifests and every materialized row are immutable across page reads.
        sqlx::query(
            "CREATE OR REPLACE FUNCTION protect_identity_registration_snapshot_manifest() \
             RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
                 IF TG_OP = 'DELETE' THEN \
                     IF OLD.complete THEN RAISE EXCEPTION 'registration_snapshot_immutable'; END IF; \
                     RETURN OLD; \
                 END IF; \
                 IF OLD.complete OR NEW.snapshot_id <> OLD.snapshot_id \
                    OR NEW.generation <> OLD.generation \
                    OR NEW.high_watermark <> OLD.high_watermark \
                    OR NEW.high_watermark_event_id IS DISTINCT FROM \
                       OLD.high_watermark_event_id \
                    OR NEW.high_watermark_payload_hash IS DISTINCT FROM \
                       OLD.high_watermark_payload_hash \
                    OR NEW.row_count <> OLD.row_count OR NEW.digest <> OLD.digest \
                    OR NEW.created_at <> OLD.created_at OR NEW.complete = FALSE THEN \
                     RAISE EXCEPTION 'registration_snapshot_immutable'; \
                 END IF; \
                 RETURN NEW; \
             END $$",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "DROP TRIGGER IF EXISTS trg_protect_identity_registration_snapshot_manifest \
             ON identity_registration_snapshot",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TRIGGER trg_protect_identity_registration_snapshot_manifest \
             BEFORE UPDATE OR DELETE ON identity_registration_snapshot FOR EACH ROW \
             EXECUTE FUNCTION protect_identity_registration_snapshot_manifest()",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE OR REPLACE FUNCTION protect_identity_registration_snapshot_row() \
             RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE sealed BOOLEAN; BEGIN \
                 IF TG_OP <> 'INSERT' THEN \
                     RAISE EXCEPTION 'registration_snapshot_row_immutable'; \
                 END IF; \
                 SELECT complete INTO sealed FROM identity_registration_snapshot \
                     WHERE snapshot_id = NEW.snapshot_id FOR SHARE; \
                 IF sealed IS DISTINCT FROM FALSE THEN \
                     RAISE EXCEPTION 'registration_snapshot_immutable'; \
                 END IF; \
                 RETURN NEW; \
             END $$",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "DROP TRIGGER IF EXISTS trg_protect_identity_registration_snapshot_row \
             ON identity_registration_snapshot_row",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TRIGGER trg_protect_identity_registration_snapshot_row \
             BEFORE INSERT OR UPDATE OR DELETE ON identity_registration_snapshot_row \
             FOR EACH ROW EXECUTE FUNCTION protect_identity_registration_snapshot_row()",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mfa_totp (\
                 user_sub TEXT PRIMARY KEY, \
                 secret TEXT NOT NULL, \
                 enabled BOOLEAN NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 verified_at BIGINT NOT NULL, \
                 last_accepted_counter BIGINT\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE mfa_totp ADD COLUMN IF NOT EXISTS last_accepted_counter BIGINT")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE mfa_totp DROP CONSTRAINT IF EXISTS \
             ck_mfa_totp_last_accepted_counter_nonnegative",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE mfa_totp ADD CONSTRAINT \
             ck_mfa_totp_last_accepted_counter_nonnegative \
             CHECK (last_accepted_counter IS NULL OR last_accepted_counter >= 0) NOT VALID",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE mfa_totp VALIDATE CONSTRAINT \
             ck_mfa_totp_last_accepted_counter_nonnegative",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mfa_recovery_codes (\
                 user_sub TEXT NOT NULL, \
                 code_hash TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 PRIMARY KEY (user_sub, code_hash)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mfa_login_challenges (\
                 id TEXT PRIMARY KEY, \
                 user_sub TEXT NOT NULL, \
                 return_to TEXT NOT NULL, \
                 user_agent TEXT NOT NULL, \
                 ip TEXT NOT NULL, \
                 expires_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        for statement in [
            "ALTER TABLE mfa_login_challenges ADD COLUMN IF NOT EXISTS source_session_binding TEXT",
            "ALTER TABLE mfa_login_challenges ADD COLUMN IF NOT EXISTS expected_factor_epoch BIGINT",
            "ALTER TABLE mfa_login_challenges ADD COLUMN IF NOT EXISTS required_acr TEXT",
            "ALTER TABLE mfa_login_challenges ADD COLUMN IF NOT EXISTS password_verified BOOLEAN NOT NULL DEFAULT FALSE",
        ] {
            sqlx::query(statement).execute(&self.pool).await?;
        }
        sqlx::query(
            "ALTER TABLE mfa_login_challenges DROP CONSTRAINT IF EXISTS \
             ck_mfa_login_challenges_step_up",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE mfa_login_challenges ADD CONSTRAINT \
             ck_mfa_login_challenges_step_up CHECK (\
                 (source_session_binding IS NULL OR source_session_binding ~ '^[0-9a-f]{64}$') AND \
                 (expected_factor_epoch IS NULL OR expected_factor_epoch >= 0) AND \
                 (required_acr IS NULL OR \
                  (required_acr='hf-aal-strong' AND expected_factor_epoch IS NOT NULL))\
             ) NOT VALID",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE mfa_login_challenges VALIDATE CONSTRAINT \
             ck_mfa_login_challenges_step_up",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS login_events (\
                 id TEXT PRIMARY KEY, \
                 user_sub TEXT NOT NULL, \
                 username TEXT NOT NULL, \
                 occurred_at BIGINT NOT NULL, \
                 ip TEXT NOT NULL, \
                 user_agent TEXT NOT NULL, \
                 method TEXT NOT NULL, \
                 result TEXT NOT NULL, \
                 detail TEXT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS personal_access_tokens (\
                 id TEXT PRIMARY KEY, \
                 user_sub TEXT NOT NULL, \
                 name TEXT NOT NULL, \
                 token_hash TEXT NOT NULL, \
                 scopes TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 expires_at BIGINT NOT NULL, \
                 revoked_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;
        // PAT plaintext is never persisted. Its SHA-256 lookup key must identify at most
        // one row so introspection cannot produce ambiguous authority.
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS personal_access_tokens_token_hash_uq \
             ON personal_access_tokens (token_hash)",
        )
        .execute(&self.pool)
        .await?;
        // Forward-converge data written before lifecycle/PAT revocation became atomic.
        // One transaction ensures a non-active authoritative fence cannot survive startup
        // alongside an enabled user, a session, or an active PAT.
        let lifecycle_now = now_secs() as i64;
        let mut lifecycle_tx = self.pool.begin().await?;
        // Current-version writers take these same per-subject locks, in a stable order.
        // They close same-version startup races, but cannot constrain an older binary that
        // predates the locking contract. Production migration therefore remains gated by
        // `stop-old -> drain -> migrate/start-new` (see deploy/README.md); do not use a
        // mixed-version rolling deployment for this schema transition.
        let fenced_subjects: Vec<String> = sqlx::query_scalar(
            "SELECT subject FROM subject_lifecycle_fences \
             WHERE state<>'active' ORDER BY subject",
        )
        .fetch_all(&mut *lifecycle_tx)
        .await?;
        for subject in &fenced_subjects {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(subject)
                .fetch_one(&mut *lifecycle_tx)
                .await?;
        }
        // If startup is repairing an enabled user behind an existing fence, the
        // lifecycle process now owns that disabled bit. Record the provenance before
        // flipping the user so a later authoritative rehire can enable the account.
        sqlx::query(
            "UPDATE subject_lifecycle_fences AS f SET disabled_by_lifecycle=TRUE \
             FROM users AS u WHERE u.sub=f.subject AND f.state<>'active' \
             AND u.disabled=FALSE",
        )
        .execute(&mut *lifecycle_tx)
        .await?;
        sqlx::query(
            "UPDATE users AS u SET disabled=TRUE \
             FROM subject_lifecycle_fences AS f \
             WHERE u.sub=f.subject AND f.state<>'active'",
        )
        .execute(&mut *lifecycle_tx)
        .await?;
        sqlx::query(
            "DELETE FROM sessions AS s USING subject_lifecycle_fences AS f \
             WHERE s.user_sub=f.subject AND f.state<>'active'",
        )
        .execute(&mut *lifecycle_tx)
        .await?;
        sqlx::query(
            "UPDATE personal_access_tokens AS p SET revoked_at=$1 \
             FROM subject_lifecycle_fences AS f \
             WHERE p.user_sub=f.subject AND f.state<>'active' AND p.revoked_at=0",
        )
        .bind(lifecycle_now)
        .execute(&mut *lifecycle_tx)
        .await?;
        lifecycle_tx.commit().await?;
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
            "INSERT INTO oauth_clients (client_id, name, first_party) VALUES ($1, $2, $3) \
             ON CONFLICT (client_id) DO UPDATE SET name = EXCLUDED.name, \
             first_party = EXCLUDED.first_party",
        )
        .bind(&client.client_id)
        .bind(&client.name)
        .bind(client.first_party)
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
        // Serialize user creation with a possibly-earlier JML tombstone. A terminated/frozen
        // identity must not become enabled merely because Keystone starts after the event.
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&user.sub)
            .fetch_one(&mut *tx)
            .await?;
        let user_existed: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE sub = $1)")
                .bind(&user.sub)
                .fetch_one(&mut *tx)
                .await?;
        let disabled = sqlx::query("SELECT state FROM subject_lifecycle_fences WHERE subject = $1")
            .bind(&user.sub)
            .fetch_optional(&mut *tx)
            .await?
            .is_some_and(|row| row.get::<String, _>("state") != "active");
        // Seed the admin as verified + admin (created_at=0). Existing rows retain their
        // authoritative disabled bit; a newly-created row inherits the lifecycle tombstone.
        sqlx::query(
            "INSERT INTO users (sub, email, email_verified, created_at, is_admin, disabled) \
             VALUES ($1, $2, true, 0, true, $3) \
             ON CONFLICT (sub) DO UPDATE SET email = EXCLUDED.email",
        )
        .bind(&user.sub)
        .bind(&user.email)
        .bind(disabled)
        .execute(&mut *tx)
        .await?;
        if disabled && !user_existed {
            sqlx::query(
                "UPDATE subject_lifecycle_fences SET disabled_by_lifecycle = TRUE \
                 WHERE subject = $1",
            )
            .bind(&user.sub)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn get_client_async(&self, client_id: &str) -> Result<Option<Client>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT name, client_secret_hash, first_party FROM oauth_clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let name: String = row.try_get("name")?;
        let client_secret_hash: Option<String> = row.try_get("client_secret_hash")?;
        let first_party: bool = row.try_get("first_party")?;
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
            first_party,
        }))
    }

    /// Idempotent UPSERT of a client (name + secret hash) and its redirect URIs.
    async fn put_client_async(&self, c: &Client) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, name, client_secret_hash, first_party) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (client_id) DO UPDATE SET name = EXCLUDED.name, \
             client_secret_hash = EXCLUDED.client_secret_hash, first_party = EXCLUDED.first_party",
        )
        .bind(&c.client_id)
        .bind(&c.name)
        .bind(c.client_secret_hash.as_deref())
        .bind(c.first_party)
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

    async fn get_consent_async(
        &self,
        user_sub: &str,
        client_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query("SELECT scope FROM consents WHERE user_sub = $1 AND client_id = $2")
            .bind(user_sub)
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(r.try_get("scope")?)),
            None => Ok(None),
        }
    }

    async fn put_consent_async(
        &self,
        user_sub: &str,
        client_id: &str,
        scope: &str,
        granted_at: u64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO consents (user_sub, client_id, scope, granted_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (user_sub, client_id) DO UPDATE SET scope = EXCLUDED.scope, \
             granted_at = EXCLUDED.granted_at",
        )
        .bind(user_sub)
        .bind(client_id)
        .bind(scope)
        .bind(granted_at as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn user_from_row(row: &sqlx::postgres::PgRow) -> Result<User, sqlx::Error> {
        let created_at: i64 = row.try_get("created_at")?;
        let factor_epoch: i64 = row.try_get("factor_epoch")?;
        Ok(User {
            sub: row.try_get("sub")?,
            email: row.try_get("email")?,
            password_hash: row.try_get("password_hash")?,
            email_verified: row.try_get("email_verified")?,
            created_at: created_at as u64,
            is_admin: row.try_get("is_admin")?,
            disabled: row.try_get("disabled")?,
            factor_epoch: factor_epoch as u64,
        })
    }

    fn session_from_row(row: &sqlx::postgres::PgRow) -> Result<Session, sqlx::Error> {
        let created_at: i64 = row.try_get("created_at")?;
        let expires_at: i64 = row.try_get("expires_at")?;
        let last_seen: i64 = row.try_get("last_seen")?;
        let auth_time: i64 = row.try_get("auth_time")?;
        let factor_epoch: i64 = row.try_get("factor_epoch")?;
        let aal_value: String = row.try_get("aal")?;
        let aal = AssuranceLevel::from_db(&aal_value).ok_or_else(|| {
            sqlx::Error::Protocol(format!("invalid persisted assurance level: {aal_value}"))
        })?;
        Ok(Session {
            id: row.try_get("id")?,
            user_sub: row.try_get("user_sub")?,
            created_at: created_at as u64,
            expires_at: expires_at as u64,
            user_agent: row.try_get("user_agent")?,
            ip: row.try_get("ip")?,
            last_seen: last_seen as u64,
            session_binding: row.try_get("session_binding")?,
            aal,
            uv: row.try_get("uv")?,
            auth_time: auth_time as u64,
            amr: row.try_get("amr")?,
            factor_epoch: factor_epoch as u64,
        })
    }

    fn auth_code_from_row(row: &sqlx::postgres::PgRow) -> Result<AuthCode, sqlx::Error> {
        let expires_at: i64 = row.try_get("expires_at")?;
        let session_binding: Option<String> = row.try_get("snap_session_binding")?;
        let binding = match session_binding {
            None => None,
            Some(session_binding) => {
                let aal_value: String =
                    row.try_get::<Option<String>, _>("snap_aal")?
                        .ok_or_else(|| {
                            sqlx::Error::Protocol(
                                "partial auth-code assurance snapshot".to_string(),
                            )
                        })?;
                let aal = AssuranceLevel::from_db(&aal_value).ok_or_else(|| {
                    sqlx::Error::Protocol(format!(
                        "invalid persisted auth-code assurance level: {aal_value}"
                    ))
                })?;
                let auth_time = row
                    .try_get::<Option<i64>, _>("snap_auth_time")?
                    .ok_or_else(|| {
                        sqlx::Error::Protocol("partial auth-code assurance snapshot".to_string())
                    })?;
                let factor_epoch = row
                    .try_get::<Option<i64>, _>("snap_factor_epoch")?
                    .ok_or_else(|| {
                        sqlx::Error::Protocol("partial auth-code assurance snapshot".to_string())
                    })?;
                Some(AuthCodeBinding {
                    session_binding,
                    aal,
                    uv: row.try_get::<Option<bool>, _>("snap_uv")?.ok_or_else(|| {
                        sqlx::Error::Protocol("partial auth-code assurance snapshot".to_string())
                    })?,
                    auth_time: auth_time as u64,
                    factor_epoch: factor_epoch as u64,
                })
            }
        };
        Ok(AuthCode {
            code: row.try_get("code")?,
            client_id: row.try_get("client_id")?,
            redirect_uri: row.try_get("redirect_uri")?,
            code_challenge: row.try_get("code_challenge")?,
            sub: row.try_get("sub")?,
            nonce: row.try_get("nonce")?,
            scope: row.try_get("scope")?,
            expires_at: expires_at as u64,
            used: false,
            binding,
            required_acr: row.try_get("required_acr")?,
        })
    }

    async fn get_user_async(&self, sub: &str) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT sub, email, password_hash, email_verified, created_at, is_admin, disabled, \
                    factor_epoch \
             FROM users WHERE sub = $1",
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
            "SELECT sub, email, password_hash, email_verified, created_at, is_admin, disabled, \
                    factor_epoch \
             FROM users WHERE sub = $1 OR email = $1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::user_from_row).transpose()
    }

    async fn list_users_async(&self) -> Result<Vec<User>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT sub, email, password_hash, email_verified, created_at, is_admin, disabled, \
                    factor_epoch \
             FROM users ORDER BY created_at, sub",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::user_from_row).collect()
    }

    async fn append_registration_event_tx(
        tx: &mut Transaction<'_, Postgres>,
        raw_sub: &str,
        account_version: i64,
        state: RegistrationState,
        email_verified: bool,
        enabled: bool,
        occurred_at: i64,
    ) -> Result<RegistrationEvent, sqlx::Error> {
        if account_version <= 0 || occurred_at < 0 {
            return Err(sqlx::Error::Protocol(
                "invalid registration event version or timestamp".to_string(),
            ));
        }
        let cursor: i64 = sqlx::query_scalar(
            "UPDATE identity_outbox_clock SET next_cursor = next_cursor + 1 \
             WHERE id = 1 RETURNING next_cursor",
        )
        .fetch_one(&mut **tx)
        .await?;
        let cursor_u64 = u64::try_from(cursor).map_err(|_| {
            sqlx::Error::Protocol("registration cursor exceeded unsigned range".to_string())
        })?;
        let account_version_u64 = u64::try_from(account_version).map_err(|_| {
            sqlx::Error::Protocol("registration version exceeded unsigned range".to_string())
        })?;
        let subject = canonical_registration_subject(raw_sub);
        let payload_hash = registration_payload_hash(
            &subject,
            account_version_u64,
            state,
            email_verified,
            enabled,
        );
        let event_id = format!("ire_{cursor_u64:016x}_{}", &payload_hash[..16]);
        sqlx::query(
            "INSERT INTO identity_registration_outbox \
                 (cursor,event_id,subject,account_version,registration_state,enabled,\
                  email_verified,payload_hash,occurred_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(cursor)
        .bind(&event_id)
        .bind(&subject)
        .bind(account_version)
        .bind(state.as_str())
        .bind(enabled)
        .bind(email_verified)
        .bind(&payload_hash)
        .bind(occurred_at)
        .execute(&mut **tx)
        .await?;
        Ok(RegistrationEvent {
            cursor: cursor_u64,
            event_id,
            subject,
            account_version: account_version_u64,
            registration_state: state,
            email_verified,
            enabled,
            payload_hash,
            occurred_at: occurred_at as u64,
        })
    }

    fn registration_event_from_row(
        row: &sqlx::postgres::PgRow,
    ) -> Result<RegistrationEvent, sqlx::Error> {
        let cursor: i64 = row.try_get("cursor")?;
        let account_version: i64 = row.try_get("account_version")?;
        let occurred_at: i64 = row.try_get("occurred_at")?;
        let state_raw: String = row.try_get("registration_state")?;
        let state = RegistrationState::from_db(&state_raw).ok_or_else(|| {
            sqlx::Error::Protocol("invalid persisted registration state".to_string())
        })?;
        Ok(RegistrationEvent {
            cursor: u64::try_from(cursor)
                .map_err(|_| sqlx::Error::Protocol("negative registration cursor".to_string()))?,
            event_id: row.try_get("event_id")?,
            subject: row.try_get("subject")?,
            account_version: u64::try_from(account_version).map_err(|_| {
                sqlx::Error::Protocol("negative registration account version".to_string())
            })?,
            registration_state: state,
            email_verified: row.try_get("email_verified")?,
            enabled: row.try_get("enabled")?,
            payload_hash: row.try_get("payload_hash")?,
            occurred_at: u64::try_from(occurred_at).map_err(|_| {
                sqlx::Error::Protocol("negative registration timestamp".to_string())
            })?,
        })
    }

    async fn set_email_verification_async(
        &self,
        sub: &str,
        verified: bool,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(sub)
            .fetch_one(&mut *tx)
            .await?;
        let current = sqlx::query(
            "SELECT u.email_verified,u.disabled,u.account_version,\
                    COALESCE(f.disabled_by_lifecycle,FALSE) AS disabled_by_lifecycle \
             FROM users u LEFT JOIN subject_lifecycle_fences f ON f.subject=u.sub \
             WHERE u.sub=$1 FOR UPDATE OF u",
        )
        .bind(sub)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(current) = current else {
            tx.rollback().await?;
            return Err(sqlx::Error::RowNotFound);
        };
        let was_verified: bool = current.try_get("email_verified")?;
        if was_verified == verified {
            tx.commit().await?;
            return Ok(false);
        }
        let login_disabled: bool = current.try_get("disabled")?;
        let disabled_by_lifecycle: bool = current.try_get("disabled_by_lifecycle")?;
        let account_version: i64 = sqlx::query_scalar(
            "UPDATE users SET email_verified=$2,account_version=account_version+1 \
             WHERE sub=$1 RETURNING account_version",
        )
        .bind(sub)
        .bind(verified)
        .fetch_one(&mut *tx)
        .await?;
        let (state, enabled) = registration_state(verified, login_disabled, disabled_by_lifecycle);
        Self::append_registration_event_tx(
            &mut tx,
            sub,
            account_version,
            state,
            verified,
            enabled,
            now_secs() as i64,
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn set_disabled_async(
        &self,
        sub: &str,
        disabled: bool,
    ) -> Result<ManualDisabledOutcome, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(sub)
            .fetch_one(&mut *tx)
            .await?;
        let current = sqlx::query(
            "SELECT u.email_verified,u.disabled,u.account_version,\
                    COALESCE(f.state<>'active',FALSE) AS lifecycle_blocked,\
                    COALESCE(f.disabled_by_lifecycle,FALSE) AS disabled_by_lifecycle \
             FROM users u LEFT JOIN subject_lifecycle_fences f ON f.subject=u.sub \
             WHERE u.sub=$1 FOR UPDATE OF u",
        )
        .bind(sub)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(current) = current else {
            tx.rollback().await?;
            return Err(sqlx::Error::RowNotFound);
        };
        let email_verified: bool = current.try_get("email_verified")?;
        let current_login_disabled: bool = current.try_get("disabled")?;
        let current_version: i64 = current.try_get("account_version")?;
        let lifecycle_blocked: bool = current.try_get("lifecycle_blocked")?;
        let disabled_by_lifecycle: bool = current.try_get("disabled_by_lifecycle")?;
        let identity_disabled = current_login_disabled && !disabled_by_lifecycle;
        if identity_disabled == disabled {
            let (state, _) = registration_state(
                email_verified,
                current_login_disabled,
                disabled_by_lifecycle,
            );
            tx.commit().await?;
            return Ok(ManualDisabledOutcome {
                changed: false,
                account_version: u64::try_from(current_version)
                    .map_err(|_| sqlx::Error::Protocol("negative account_version".to_string()))?,
                registration_state: state,
                login_disabled: current_login_disabled,
                lifecycle_blocked,
            });
        }

        let login_disabled = disabled || lifecycle_blocked;
        let new_disabled_by_lifecycle = !disabled && lifecycle_blocked;
        let account_version: i64 = sqlx::query_scalar(
            "UPDATE users SET disabled=$2,account_version=account_version+1 \
             WHERE sub=$1 RETURNING account_version",
        )
        .bind(sub)
        .bind(login_disabled)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE subject_lifecycle_fences SET disabled_by_lifecycle=$2 WHERE subject=$1",
        )
        .bind(sub)
        .bind(new_disabled_by_lifecycle)
        .execute(&mut *tx)
        .await?;
        if disabled {
            sqlx::query("DELETE FROM sessions WHERE user_sub=$1")
                .bind(sub)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE personal_access_tokens SET revoked_at=$2 \
                 WHERE user_sub=$1 AND revoked_at=0",
            )
            .bind(sub)
            .bind(now_secs() as i64)
            .execute(&mut *tx)
            .await?;
        }
        let (state, enabled) =
            registration_state(email_verified, login_disabled, new_disabled_by_lifecycle);
        Self::append_registration_event_tx(
            &mut tx,
            sub,
            account_version,
            state,
            email_verified,
            enabled,
            now_secs() as i64,
        )
        .await?;
        tx.commit().await?;
        Ok(ManualDisabledOutcome {
            changed: true,
            account_version: u64::try_from(account_version)
                .map_err(|_| sqlx::Error::Protocol("negative account_version".to_string()))?,
            registration_state: state,
            login_disabled,
            lifecycle_blocked,
        })
    }

    async fn delete_user_async(&self, sub: &str) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(sub)
            .fetch_one(&mut *tx)
            .await?;
        let current_version: Option<i64> =
            sqlx::query_scalar("SELECT account_version FROM users WHERE sub=$1 FOR UPDATE")
                .bind(sub)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(current_version) = current_version else {
            tx.commit().await?;
            return Ok(false);
        };
        let account_version = current_version.checked_add(1).ok_or_else(|| {
            sqlx::Error::Protocol("registration account version exhausted".to_string())
        })?;
        let occurred_at = now_secs() as i64;
        let event = Self::append_registration_event_tx(
            &mut tx,
            sub,
            account_version,
            RegistrationState::Deleted,
            false,
            false,
            occurred_at,
        )
        .await?;
        sqlx::query(
            "INSERT INTO identity_registration_tombstone \
                 (subject,account_version,payload_hash,occurred_at) VALUES ($1,$2,$3,$4) \
             ON CONFLICT (subject) DO UPDATE SET account_version=EXCLUDED.account_version,\
                 payload_hash=EXCLUDED.payload_hash,occurred_at=EXCLUDED.occurred_at",
        )
        .bind(&event.subject)
        .bind(account_version)
        .bind(&event.payload_hash)
        .bind(occurred_at)
        .execute(&mut *tx)
        .await?;
        for statement in [
            "DELETE FROM sessions WHERE user_sub=$1",
            "DELETE FROM personal_access_tokens WHERE user_sub=$1",
            "DELETE FROM verification_tokens WHERE sub=$1",
            "DELETE FROM webauthn_credentials WHERE user_sub=$1",
            "DELETE FROM mfa_totp WHERE user_sub=$1",
            "DELETE FROM mfa_recovery_codes WHERE user_sub=$1",
            "DELETE FROM mfa_login_challenges WHERE user_sub=$1",
            "DELETE FROM login_events WHERE user_sub=$1",
            "DELETE FROM consents WHERE user_sub=$1",
            "DELETE FROM auth_codes WHERE sub=$1",
        ] {
            sqlx::query(statement).bind(sub).execute(&mut *tx).await?;
        }
        sqlx::query("DELETE FROM users WHERE sub=$1")
            .bind(sub)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn apply_subject_lifecycle_async(
        &self,
        command: &SubjectLifecycleCommand,
    ) -> Result<SubjectLifecycleOutcome, PgSubjectLifecycleError> {
        let source_version = i64::try_from(command.source_version).map_err(|_| {
            PgSubjectLifecycleError::Backend(sqlx::Error::Protocol(
                "source_version exceeds PostgreSQL BIGINT".to_string(),
            ))
        })?;
        let mut tx = self.pool.begin().await?;

        // Both lifecycle transitions and guarded session creation take this exact lock.
        // A transaction finishing second must therefore observe the first one's committed state.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&command.subject)
            .fetch_one(&mut *tx)
            .await?;

        let current = sqlx::query(
            "SELECT state, source_event_id, source_version, user_found, revoked_sessions, \
                    disabled_by_lifecycle \
             FROM subject_lifecycle_fences WHERE subject = $1 FOR UPDATE",
        )
        .bind(&command.subject)
        .fetch_optional(&mut *tx)
        .await?;

        let mut previous_disabled_by_lifecycle = false;
        if let Some(row) = current {
            previous_disabled_by_lifecycle = row.try_get("disabled_by_lifecycle")?;
            let current_version: i64 = row.try_get("source_version")?;
            if source_version < current_version {
                return Err(PgSubjectLifecycleError::Conflict);
            }
            if source_version == current_version {
                let current_state_raw: String = row.try_get("state")?;
                let current_state =
                    SubjectLifecycleState::from_db(&current_state_raw).ok_or_else(|| {
                        PgSubjectLifecycleError::Backend(sqlx::Error::Protocol(
                            "invalid persisted subject lifecycle state".to_string(),
                        ))
                    })?;
                let current_event: String = row.try_get("source_event_id")?;
                if current_state == command.state && current_event == command.source_event_id {
                    let user_found: bool = row.try_get("user_found")?;
                    let revoked_sessions: i64 = row.try_get("revoked_sessions")?;
                    if current_state.disables_login() {
                        let replay_now = now_secs() as i64;
                        let disabled_by_replay = sqlx::query(
                            "UPDATE users SET disabled=TRUE \
                             WHERE sub=$1 AND disabled=FALSE",
                        )
                        .bind(&command.subject)
                        .execute(&mut *tx)
                        .await?
                        .rows_affected()
                            == 1;
                        if disabled_by_replay {
                            sqlx::query(
                                "UPDATE subject_lifecycle_fences \
                                 SET disabled_by_lifecycle=TRUE WHERE subject=$1",
                            )
                            .bind(&command.subject)
                            .execute(&mut *tx)
                            .await?;
                        }
                        sqlx::query("DELETE FROM sessions WHERE user_sub=$1")
                            .bind(&command.subject)
                            .execute(&mut *tx)
                            .await?;
                        sqlx::query(
                            "UPDATE personal_access_tokens SET revoked_at=$2 \
                             WHERE user_sub=$1 AND revoked_at=0",
                        )
                        .bind(&command.subject)
                        .bind(replay_now)
                        .execute(&mut *tx)
                        .await?;
                    }
                    tx.commit().await?;
                    return Ok(SubjectLifecycleOutcome {
                        state: current_state,
                        replayed: true,
                        user_found,
                        revoked_sessions: revoked_sessions as u64,
                    });
                }
                return Err(PgSubjectLifecycleError::Conflict);
            }
        }

        let user = sqlx::query("SELECT disabled FROM users WHERE sub = $1 FOR UPDATE")
            .bind(&command.subject)
            .fetch_optional(&mut *tx)
            .await?;
        let user_found = user.is_some();
        let mut disabled_by_lifecycle = false;
        if let Some(user) = user {
            let currently_disabled: bool = user.try_get("disabled")?;
            if command.state.disables_login() {
                disabled_by_lifecycle = previous_disabled_by_lifecycle || !currently_disabled;
                sqlx::query("UPDATE users SET disabled = TRUE WHERE sub = $1")
                    .bind(&command.subject)
                    .execute(&mut *tx)
                    .await?;
            } else if previous_disabled_by_lifecycle {
                sqlx::query("UPDATE users SET disabled = FALSE WHERE sub = $1")
                    .bind(&command.subject)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        let revoked_sessions = if command.state.disables_login() {
            sqlx::query("DELETE FROM sessions WHERE user_sub = $1")
                .bind(&command.subject)
                .execute(&mut *tx)
                .await?
                .rows_affected()
        } else {
            0
        };

        let lifecycle_now = now_secs();
        if command.state.disables_login() {
            sqlx::query(
                "UPDATE personal_access_tokens SET revoked_at = $2 \
                 WHERE user_sub = $1 AND revoked_at = 0",
            )
            .bind(&command.subject)
            .bind(lifecycle_now as i64)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            "INSERT INTO subject_lifecycle_fences \
                 (subject, state, source_event_id, source_version, correlation_id, \
                  user_found, revoked_sessions, disabled_by_lifecycle, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (subject) DO UPDATE SET \
                 state = EXCLUDED.state, source_event_id = EXCLUDED.source_event_id, \
                 source_version = EXCLUDED.source_version, \
                 correlation_id = EXCLUDED.correlation_id, \
                 user_found = EXCLUDED.user_found, \
                 revoked_sessions = EXCLUDED.revoked_sessions, \
                 disabled_by_lifecycle = EXCLUDED.disabled_by_lifecycle, \
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(&command.subject)
        .bind(command.state.as_str())
        .bind(&command.source_event_id)
        .bind(source_version)
        .bind(&command.correlation_id)
        .bind(user_found)
        .bind(revoked_sessions as i64)
        .bind(disabled_by_lifecycle)
        .bind(lifecycle_now as i64)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(SubjectLifecycleOutcome {
            state: command.state,
            replayed: false,
            user_found,
            revoked_sessions,
        })
    }

    async fn set_is_admin_async(&self, sub: &str, is_admin: bool) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET is_admin = $2 WHERE sub = $1")
            .bind(sub)
            .bind(is_admin)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// All clients + their redirect URIs in two fixed queries (no N+1), merged in memory.
    async fn list_clients_async(&self) -> Result<Vec<Client>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT client_id, name, client_secret_hash, first_party FROM oauth_clients \
             ORDER BY client_id",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut clients = Vec::with_capacity(rows.len());
        for row in &rows {
            clients.push(Client {
                client_id: row.try_get("client_id")?,
                redirect_uris: Vec::new(),
                name: row.try_get("name")?,
                client_secret_hash: row.try_get("client_secret_hash")?,
                first_party: row.try_get("first_party")?,
            });
        }
        let uri_rows = sqlx::query(
            "SELECT client_id, redirect_uri FROM client_redirect_uris \
             ORDER BY client_id, redirect_uri",
        )
        .fetch_all(&self.pool)
        .await?;
        for row in &uri_rows {
            let client_id: String = row.try_get("client_id")?;
            let uri: String = row.try_get("redirect_uri")?;
            if let Some(c) = clients.iter_mut().find(|c| c.client_id == client_id) {
                c.redirect_uris.push(uri);
            }
        }
        Ok(clients)
    }

    async fn set_password_hash_async(&self, sub: &str, hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET password_hash = $2 WHERE sub = $1")
            .bind(sub)
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_password_hash_and_bump_factor_async(
        &self,
        sub: &str,
        hash: &str,
    ) -> Result<Option<u64>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(sub)
            .fetch_one(&mut *tx)
            .await?;
        let epoch: Option<i64> = sqlx::query_scalar(
            "UPDATE users SET password_hash = $2, factor_epoch = factor_epoch + 1 \
             WHERE sub = $1 RETURNING factor_epoch",
        )
        .bind(sub)
        .bind(hash)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(epoch.map(|value| value as u64))
    }

    /// Insert a self-service user (`email_verified=false`). A `UNIQUE(email)` violation is
    /// mapped to [`CreateUserError::EmailTaken`]; any other failure is `Backend` (logged).
    async fn create_user_async(
        &self,
        sub: &str,
        email: &str,
        password_hash: &str,
        created_at: u64,
        verification_token: Option<&VerificationToken>,
    ) -> Result<(), CreateUserError> {
        if verification_token.is_some_and(|token| token.sub != sub || token.kind != "verify") {
            return Err(CreateUserError::Backend);
        }
        let res: Result<(), sqlx::Error> = async {
            let mut tx = self.pool.begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(sub)
                .fetch_one(&mut *tx)
                .await?;
            let disabled =
                sqlx::query("SELECT state FROM subject_lifecycle_fences WHERE subject = $1")
                    .bind(sub)
                    .fetch_optional(&mut *tx)
                    .await?
                    .is_some_and(|row| row.get::<String, _>("state") != "active");
            let subject = canonical_registration_subject(sub);
            let previous_version: i64 = sqlx::query_scalar(
                "SELECT COALESCE((SELECT account_version FROM identity_registration_tombstone \
                  WHERE subject=$1 FOR UPDATE),0)",
            )
            .bind(&subject)
            .fetch_one(&mut *tx)
            .await?;
            let account_version = previous_version.checked_add(1).ok_or_else(|| {
                sqlx::Error::Protocol("registration account version exhausted".to_string())
            })?;
            sqlx::query(
                "INSERT INTO users \
                     (sub, email, password_hash, email_verified, created_at, disabled,account_version) \
                 VALUES ($1, $2, $3, false, $4, $5,$6)",
            )
            .bind(sub)
            .bind(email)
            .bind(password_hash)
            .bind(created_at as i64)
            .bind(disabled)
            .bind(account_version)
            .execute(&mut *tx)
            .await?;
            if disabled {
                sqlx::query(
                    "UPDATE subject_lifecycle_fences SET disabled_by_lifecycle = TRUE \
                     WHERE subject = $1",
                )
                .bind(sub)
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query("DELETE FROM identity_registration_tombstone WHERE subject=$1")
                .bind(&subject)
                .execute(&mut *tx)
                .await?;
            Self::append_registration_event_tx(
                &mut tx,
                sub,
                account_version,
                RegistrationState::Unverified,
                false,
                true,
                created_at as i64,
            )
            .await?;
            if let Some(token) = verification_token {
                sqlx::query(
                    "INSERT INTO verification_tokens (token,sub,kind,expires_at) \
                     VALUES ($1,$2,$3,$4)",
                )
                .bind(&token.token)
                .bind(&token.sub)
                .bind(&token.kind)
                .bind(token.expires_at as i64)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            Ok(())
        }
        .await;
        match res {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.as_database_error().is_some_and(|db| {
                    db.is_unique_violation() && db.constraint() == Some("users_email_key")
                }) {
                    Err(CreateUserError::EmailTaken)
                } else {
                    tracing::error!(error = %e, "pg create_user failed");
                    Err(CreateUserError::Backend)
                }
            }
        }
    }

    async fn put_verification_token_async(&self, t: &VerificationToken) -> Result<(), sqlx::Error> {
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
            "SELECT sub, kind, expires_at FROM verification_tokens WHERE token = $1 FOR UPDATE",
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

    async fn consume_verification_token_and_verify_async(
        &self,
        token: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let record = sqlx::query(
            "SELECT sub,kind,expires_at FROM verification_tokens WHERE token=$1 FOR UPDATE",
        )
        .bind(token)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(record) = record else {
            tx.rollback().await?;
            return Ok(None);
        };
        let sub: String = record.try_get("sub")?;
        let kind: String = record.try_get("kind")?;
        let expires_at: i64 = record.try_get("expires_at")?;
        if kind != "verify" || expires_at < 0 || now_secs() > expires_at as u64 {
            sqlx::query("DELETE FROM verification_tokens WHERE token=$1")
                .bind(token)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(None);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&sub)
            .fetch_one(&mut *tx)
            .await?;
        let user = sqlx::query(
            "SELECT u.email_verified,u.disabled,\
                    COALESCE(f.disabled_by_lifecycle,FALSE) AS disabled_by_lifecycle \
             FROM users u LEFT JOIN subject_lifecycle_fences f ON f.subject=u.sub \
             WHERE u.sub=$1 FOR UPDATE OF u",
        )
        .bind(&sub)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(user) = user else {
            sqlx::query("DELETE FROM verification_tokens WHERE token=$1")
                .bind(token)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(None);
        };
        let email_verified: bool = user.try_get("email_verified")?;
        if !email_verified {
            let account_version: i64 = sqlx::query_scalar(
                "UPDATE users SET email_verified=TRUE,account_version=account_version+1 \
                 WHERE sub=$1 RETURNING account_version",
            )
            .bind(&sub)
            .fetch_one(&mut *tx)
            .await?;
            let login_disabled: bool = user.try_get("disabled")?;
            let disabled_by_lifecycle: bool = user.try_get("disabled_by_lifecycle")?;
            let (state, enabled) = registration_state(true, login_disabled, disabled_by_lifecycle);
            Self::append_registration_event_tx(
                &mut tx,
                &sub,
                account_version,
                state,
                true,
                enabled,
                now_secs() as i64,
            )
            .await?;
        }
        sqlx::query("DELETE FROM verification_tokens WHERE token=$1")
            .bind(token)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(sub))
    }

    async fn consume_reset_token_and_rotate_password_async(
        &self,
        token: &str,
        password_hash: &str,
    ) -> Result<Option<(String, u64)>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let record = sqlx::query(
            "SELECT sub,kind,expires_at FROM verification_tokens WHERE token=$1 FOR UPDATE",
        )
        .bind(token)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(record) = record else {
            tx.rollback().await?;
            return Ok(None);
        };
        let sub: String = record.try_get("sub")?;
        let kind: String = record.try_get("kind")?;
        let expires_at: i64 = record.try_get("expires_at")?;
        if kind != "reset" || expires_at < 0 || now_secs() > expires_at as u64 {
            sqlx::query("DELETE FROM verification_tokens WHERE token=$1")
                .bind(token)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(None);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&sub)
            .fetch_one(&mut *tx)
            .await?;
        let user = sqlx::query(
            "SELECT u.email_verified,u.disabled,u.factor_epoch,\
                    COALESCE(f.disabled_by_lifecycle,FALSE) AS disabled_by_lifecycle \
             FROM users u LEFT JOIN subject_lifecycle_fences f ON f.subject=u.sub \
             WHERE u.sub=$1 FOR UPDATE OF u",
        )
        .bind(&sub)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(user) = user else {
            sqlx::query("DELETE FROM verification_tokens WHERE token=$1")
                .bind(token)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(None);
        };
        let email_verified: bool = user.try_get("email_verified")?;
        let factor_epoch: i64 = user.try_get("factor_epoch")?;
        let next_factor_epoch = factor_epoch
            .checked_add(1)
            .ok_or_else(|| sqlx::Error::Protocol("factor epoch exhausted".to_string()))?;
        if email_verified {
            sqlx::query("UPDATE users SET password_hash=$2,factor_epoch=$3 WHERE sub=$1")
                .bind(&sub)
                .bind(password_hash)
                .bind(next_factor_epoch)
                .execute(&mut *tx)
                .await?;
        } else {
            let account_version: i64 = sqlx::query_scalar(
                "UPDATE users SET password_hash=$2,factor_epoch=$3,email_verified=TRUE,\
                        account_version=account_version+1 \
                 WHERE sub=$1 RETURNING account_version",
            )
            .bind(&sub)
            .bind(password_hash)
            .bind(next_factor_epoch)
            .fetch_one(&mut *tx)
            .await?;
            let login_disabled: bool = user.try_get("disabled")?;
            let disabled_by_lifecycle: bool = user.try_get("disabled_by_lifecycle")?;
            let (state, enabled) = registration_state(true, login_disabled, disabled_by_lifecycle);
            Self::append_registration_event_tx(
                &mut tx,
                &sub,
                account_version,
                state,
                true,
                enabled,
                now_secs() as i64,
            )
            .await?;
        }
        sqlx::query("DELETE FROM verification_tokens WHERE token=$1")
            .bind(token)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some((sub, next_factor_epoch as u64)))
    }

    async fn create_registration_snapshot_async(
        &self,
    ) -> Result<RegistrationSnapshotManifest, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await?;
        let clock =
            sqlx::query("SELECT next_cursor,generation FROM identity_outbox_clock WHERE id=1")
                .fetch_one(&mut *tx)
                .await?;
        let high_watermark: i64 = clock.try_get("next_cursor")?;
        let generation: i64 = clock.try_get("generation")?;
        let live_rows = sqlx::query(
            "SELECT u.sub,u.account_version,u.email_verified,u.disabled,\
                    COALESCE(f.disabled_by_lifecycle,FALSE) AS disabled_by_lifecycle \
             FROM users u LEFT JOIN subject_lifecycle_fences f ON f.subject=u.sub",
        )
        .fetch_all(&mut *tx)
        .await?;
        let mut rows = Vec::with_capacity(live_rows.len());
        for row in live_rows {
            let raw_sub: String = row.try_get("sub")?;
            let account_version: i64 = row.try_get("account_version")?;
            let email_verified: bool = row.try_get("email_verified")?;
            let login_disabled: bool = row.try_get("disabled")?;
            let disabled_by_lifecycle: bool = row.try_get("disabled_by_lifecycle")?;
            let (state, enabled) =
                registration_state(email_verified, login_disabled, disabled_by_lifecycle);
            let subject = canonical_registration_subject(&raw_sub);
            let account_version = u64::try_from(account_version).map_err(|_| {
                sqlx::Error::Protocol("negative snapshot account version".to_string())
            })?;
            rows.push(RegistrationSnapshotRow {
                ordinal: 0,
                payload_hash: registration_payload_hash(
                    &subject,
                    account_version,
                    state,
                    email_verified,
                    enabled,
                ),
                subject,
                account_version,
                registration_state: state,
                email_verified,
                enabled,
            });
        }
        let deleted_rows = sqlx::query(
            "SELECT t.subject,t.account_version,t.payload_hash \
             FROM identity_registration_tombstone t \
             WHERE NOT EXISTS (SELECT 1 FROM users u WHERE ('user:'||u.sub)=t.subject)",
        )
        .fetch_all(&mut *tx)
        .await?;
        for row in deleted_rows {
            let account_version: i64 = row.try_get("account_version")?;
            rows.push(RegistrationSnapshotRow {
                ordinal: 0,
                subject: row.try_get("subject")?,
                account_version: u64::try_from(account_version).map_err(|_| {
                    sqlx::Error::Protocol("negative tombstone account version".to_string())
                })?,
                registration_state: RegistrationState::Deleted,
                email_verified: false,
                enabled: false,
                payload_hash: row.try_get("payload_hash")?,
            });
        }
        rows.sort_by(|left, right| left.subject.cmp(&right.subject));
        for (index, row) in rows.iter_mut().enumerate() {
            row.ordinal = u64::try_from(index + 1)
                .map_err(|_| sqlx::Error::Protocol("snapshot row ordinal exhausted".to_string()))?;
        }
        let high_watermark_u64 = u64::try_from(high_watermark)
            .map_err(|_| sqlx::Error::Protocol("negative outbox watermark".to_string()))?;
        let (high_watermark_event_id, high_watermark_payload_hash) = if high_watermark == 0 {
            (String::new(), String::new())
        } else {
            // Retention may already have pruned the high-watermark event. A durable ACK at
            // the exact same cursor is equivalent evidence because ACK ingestion verifies it
            // against the immutable outbox before advancing.
            let evidence = sqlx::query(
                "SELECT event_id,payload_hash FROM (\
                     SELECT event_id,payload_hash,0 AS priority \
                       FROM identity_registration_outbox WHERE cursor=$1 \
                     UNION ALL \
                     SELECT event_id,payload_hash,1 AS priority \
                       FROM identity_registration_consumer_ack WHERE acked_cursor=$1\
                 ) evidence ORDER BY priority,event_id LIMIT 1",
            )
            .bind(high_watermark)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                sqlx::Error::Protocol(
                    "registration snapshot high watermark has no durable ACK evidence".to_string(),
                )
            })?;
            let event_id: String = evidence.try_get("event_id")?;
            let payload_hash: String = evidence.try_get("payload_hash")?;
            if !valid_registration_watermark_evidence(high_watermark_u64, &event_id, &payload_hash)
            {
                return Err(sqlx::Error::Protocol(
                    "invalid registration snapshot high-watermark ACK evidence".to_string(),
                ));
            }
            (event_id, payload_hash)
        };
        let digest = registration_snapshot_digest(high_watermark_u64, &rows);
        let snapshot_id = format!("irs_{}", uuid::Uuid::new_v4().simple());
        let created_at = now_secs() as i64;
        sqlx::query(
            "INSERT INTO identity_registration_snapshot \
                 (snapshot_id,generation,high_watermark,high_watermark_event_id,\
                  high_watermark_payload_hash,row_count,digest,complete,created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,FALSE,$8)",
        )
        .bind(&snapshot_id)
        .bind(generation)
        .bind(high_watermark)
        .bind(&high_watermark_event_id)
        .bind(&high_watermark_payload_hash)
        .bind(rows.len() as i64)
        .bind(&digest)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;
        for row in &rows {
            sqlx::query(
                "INSERT INTO identity_registration_snapshot_row \
                     (snapshot_id,ordinal,subject,account_version,registration_state,\
                      email_verified,enabled,payload_hash) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(&snapshot_id)
            .bind(row.ordinal as i64)
            .bind(&row.subject)
            .bind(row.account_version as i64)
            .bind(row.registration_state.as_str())
            .bind(row.email_verified)
            .bind(row.enabled)
            .bind(&row.payload_hash)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "UPDATE identity_registration_snapshot SET complete=TRUE \
             WHERE snapshot_id=$1 AND complete=FALSE",
        )
        .bind(&snapshot_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(RegistrationSnapshotManifest {
            snapshot_id,
            generation: u64::try_from(generation)
                .map_err(|_| sqlx::Error::Protocol("invalid feed generation".to_string()))?,
            high_watermark: high_watermark_u64,
            high_watermark_event_id,
            high_watermark_payload_hash,
            count: rows.len() as u64,
            digest,
        })
    }

    async fn get_registration_snapshot_page_async(
        &self,
        snapshot_id: &str,
        after_ordinal: u64,
        limit: u16,
    ) -> Result<RegistrationSnapshotPage, RegistrationFeedError> {
        let manifest = sqlx::query(
            "SELECT generation,high_watermark,high_watermark_event_id,\
                    high_watermark_payload_hash,row_count,digest,complete \
             FROM identity_registration_snapshot WHERE snapshot_id=$1",
        )
        .bind(snapshot_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| RegistrationFeedError::Backend)?;
        let Some(manifest) = manifest else {
            return Err(RegistrationFeedError::SnapshotIncomplete);
        };
        if !manifest
            .try_get::<bool, _>("complete")
            .map_err(|_| RegistrationFeedError::Backend)?
        {
            return Err(RegistrationFeedError::SnapshotIncomplete);
        }
        let high_watermark: i64 = manifest
            .try_get("high_watermark")
            .map_err(|_| RegistrationFeedError::Backend)?;
        let high_watermark =
            u64::try_from(high_watermark).map_err(|_| RegistrationFeedError::SnapshotIncomplete)?;
        let high_watermark_event_id: Option<String> =
            manifest
                .try_get("high_watermark_event_id")
                .map_err(|_| RegistrationFeedError::Backend)?;
        let high_watermark_payload_hash: Option<String> = manifest
            .try_get("high_watermark_payload_hash")
            .map_err(|_| RegistrationFeedError::Backend)?;
        let (Some(high_watermark_event_id), Some(high_watermark_payload_hash)) =
            (high_watermark_event_id, high_watermark_payload_hash)
        else {
            return Err(RegistrationFeedError::SnapshotIncomplete);
        };
        if !valid_registration_watermark_evidence(
            high_watermark,
            &high_watermark_event_id,
            &high_watermark_payload_hash,
        ) {
            return Err(RegistrationFeedError::SnapshotIncomplete);
        }
        let generation: i64 = manifest
            .try_get("generation")
            .map_err(|_| RegistrationFeedError::Backend)?;
        let row_count: i64 = manifest
            .try_get("row_count")
            .map_err(|_| RegistrationFeedError::Backend)?;
        let rows = sqlx::query(
            "SELECT ordinal,subject,account_version,registration_state,email_verified,enabled,\
                    payload_hash FROM identity_registration_snapshot_row \
             WHERE snapshot_id=$1 AND ordinal>$2 ORDER BY ordinal LIMIT $3",
        )
        .bind(snapshot_id)
        .bind(i64::try_from(after_ordinal).map_err(|_| RegistrationFeedError::Backend)?)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|_| RegistrationFeedError::Backend)?;
        let mut page_rows = Vec::with_capacity(rows.len());
        for row in rows {
            let state_raw: String = row
                .try_get("registration_state")
                .map_err(|_| RegistrationFeedError::Backend)?;
            let state =
                RegistrationState::from_db(&state_raw).ok_or(RegistrationFeedError::Backend)?;
            let ordinal: i64 = row
                .try_get("ordinal")
                .map_err(|_| RegistrationFeedError::Backend)?;
            let account_version: i64 = row
                .try_get("account_version")
                .map_err(|_| RegistrationFeedError::Backend)?;
            page_rows.push(RegistrationSnapshotRow {
                ordinal: u64::try_from(ordinal).map_err(|_| RegistrationFeedError::Backend)?,
                subject: row
                    .try_get("subject")
                    .map_err(|_| RegistrationFeedError::Backend)?,
                account_version: u64::try_from(account_version)
                    .map_err(|_| RegistrationFeedError::Backend)?,
                registration_state: state,
                email_verified: row
                    .try_get("email_verified")
                    .map_err(|_| RegistrationFeedError::Backend)?,
                enabled: row
                    .try_get("enabled")
                    .map_err(|_| RegistrationFeedError::Backend)?,
                payload_hash: row
                    .try_get("payload_hash")
                    .map_err(|_| RegistrationFeedError::Backend)?,
            });
        }
        let next_after_ordinal = page_rows
            .last()
            .map(|row| row.ordinal)
            .unwrap_or(after_ordinal);
        let count = u64::try_from(row_count).map_err(|_| RegistrationFeedError::Backend)?;
        Ok(RegistrationSnapshotPage {
            snapshot_id: snapshot_id.to_string(),
            generation: u64::try_from(generation).map_err(|_| RegistrationFeedError::Backend)?,
            high_watermark,
            high_watermark_event_id,
            high_watermark_payload_hash,
            digest: manifest
                .try_get("digest")
                .map_err(|_| RegistrationFeedError::Backend)?,
            rows: page_rows,
            next_after_ordinal,
            done: next_after_ordinal >= count,
        })
    }

    async fn get_registration_changes_async(
        &self,
        after: u64,
        limit: u16,
    ) -> Result<RegistrationChangesPage, RegistrationFeedError> {
        let after = i64::try_from(after).map_err(|_| RegistrationFeedError::FeedGap)?;
        let clock = sqlx::query(
            "SELECT next_cursor,generation,retention_floor_cursor \
             FROM identity_outbox_clock WHERE id=1",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| RegistrationFeedError::Backend)?;
        let head: i64 = clock
            .try_get("next_cursor")
            .map_err(|_| RegistrationFeedError::Backend)?;
        let generation: i64 = clock
            .try_get("generation")
            .map_err(|_| RegistrationFeedError::Backend)?;
        let floor: i64 = clock
            .try_get("retention_floor_cursor")
            .map_err(|_| RegistrationFeedError::Backend)?;
        if after < floor {
            return Err(RegistrationFeedError::ResnapshotRequired);
        }
        if after > head {
            return Err(RegistrationFeedError::FeedGap);
        }
        let rows = sqlx::query(
            "SELECT cursor,event_id,subject,account_version,registration_state,enabled,\
                    email_verified,payload_hash,occurred_at \
             FROM identity_registration_outbox WHERE cursor>$1 ORDER BY cursor LIMIT $2",
        )
        .bind(after)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|_| RegistrationFeedError::Backend)?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(
                Self::registration_event_from_row(&row)
                    .map_err(|_| RegistrationFeedError::Backend)?,
            );
        }
        let mut expected = after.saturating_add(1);
        for event in &events {
            if event.cursor != expected as u64 {
                return Err(RegistrationFeedError::FeedGap);
            }
            expected = expected.saturating_add(1);
        }
        if after < head && events.is_empty() {
            return Err(RegistrationFeedError::FeedGap);
        }
        Ok(RegistrationChangesPage {
            generation: u64::try_from(generation).map_err(|_| RegistrationFeedError::Backend)?,
            events,
            head_cursor: u64::try_from(head).map_err(|_| RegistrationFeedError::Backend)?,
            retention_floor_cursor: u64::try_from(floor)
                .map_err(|_| RegistrationFeedError::Backend)?,
        })
    }

    async fn acknowledge_registration_async(
        &self,
        command: RegistrationAckCommand,
    ) -> Result<RegistrationAckOutcome, RegistrationFeedError> {
        let cursor =
            i64::try_from(command.acked_cursor).map_err(|_| RegistrationFeedError::AckAhead)?;
        let generation = i64::try_from(command.generation)
            .map_err(|_| RegistrationFeedError::AckGenerationConflict)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| RegistrationFeedError::Backend)?;
        let clock = sqlx::query(
            "SELECT next_cursor,generation,retention_floor_cursor \
             FROM identity_outbox_clock WHERE id=1 FOR UPDATE",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| RegistrationFeedError::Backend)?;
        let head: i64 = clock
            .try_get("next_cursor")
            .map_err(|_| RegistrationFeedError::Backend)?;
        let source_generation: i64 = clock
            .try_get("generation")
            .map_err(|_| RegistrationFeedError::Backend)?;
        let current_floor: i64 = clock
            .try_get("retention_floor_cursor")
            .map_err(|_| RegistrationFeedError::Backend)?;
        if generation <= 0 || generation != source_generation {
            return Err(RegistrationFeedError::AckGenerationConflict);
        }
        if cursor > head {
            return Err(RegistrationFeedError::AckAhead);
        }
        let current = sqlx::query(
            "SELECT acked_cursor,generation,event_id,payload_hash \
             FROM identity_registration_consumer_ack WHERE consumer=$1 FOR UPDATE",
        )
        .bind(&command.consumer)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| RegistrationFeedError::Backend)?;
        let mut event_verified_from_ack = false;
        if let Some(current) = current {
            let current_generation: i64 = current
                .try_get("generation")
                .map_err(|_| RegistrationFeedError::Backend)?;
            let current_cursor: i64 = current
                .try_get("acked_cursor")
                .map_err(|_| RegistrationFeedError::Backend)?;
            if current_generation > generation {
                return Err(RegistrationFeedError::AckGenerationConflict);
            }
            if cursor < current_cursor {
                return Err(RegistrationFeedError::AckRegression);
            }
            if cursor == current_cursor {
                let current_event: String = current
                    .try_get("event_id")
                    .map_err(|_| RegistrationFeedError::Backend)?;
                let current_hash: String = current
                    .try_get("payload_hash")
                    .map_err(|_| RegistrationFeedError::Backend)?;
                if current_event != command.event_id || current_hash != command.payload_hash {
                    return Err(RegistrationFeedError::AckEventMismatch);
                }
                if current_generation == generation {
                    tx.commit()
                        .await
                        .map_err(|_| RegistrationFeedError::Backend)?;
                    return Ok(RegistrationAckOutcome {
                        consumer: command.consumer,
                        generation: command.generation,
                        stored_cursor: command.acked_cursor,
                    });
                }
                event_verified_from_ack = true;
            }
        }
        if !event_verified_from_ack {
            let event = sqlx::query(
                "SELECT event_id,payload_hash FROM identity_registration_outbox WHERE cursor=$1",
            )
            .bind(cursor)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| RegistrationFeedError::Backend)?
            .ok_or(RegistrationFeedError::AckEventMismatch)?;
            let event_id: String = event
                .try_get("event_id")
                .map_err(|_| RegistrationFeedError::Backend)?;
            let payload_hash: String = event
                .try_get("payload_hash")
                .map_err(|_| RegistrationFeedError::Backend)?;
            if event_id != command.event_id || payload_hash != command.payload_hash {
                return Err(RegistrationFeedError::AckEventMismatch);
            }
        }
        sqlx::query(
            "INSERT INTO identity_registration_consumer_ack \
                 (consumer,acked_cursor,generation,event_id,payload_hash,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (consumer) DO UPDATE SET \
                 acked_cursor=EXCLUDED.acked_cursor,generation=EXCLUDED.generation,\
                 event_id=EXCLUDED.event_id,\
                 payload_hash=EXCLUDED.payload_hash,updated_at=EXCLUDED.updated_at \
             WHERE identity_registration_consumer_ack.generation<=EXCLUDED.generation \
               AND EXCLUDED.acked_cursor>=identity_registration_consumer_ack.acked_cursor",
        )
        .bind(&command.consumer)
        .bind(cursor)
        .bind(generation)
        .bind(&command.event_id)
        .bind(&command.payload_hash)
        .bind(now_secs() as i64)
        .execute(&mut *tx)
        .await
        .map_err(|_| RegistrationFeedError::Backend)?;
        let minimum_ack: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MIN(acked_cursor),0) FROM identity_registration_consumer_ack",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| RegistrationFeedError::Backend)?;
        let cutoff = i64::try_from(now_secs().saturating_sub(REGISTRATION_RETENTION_SECONDS))
            .map_err(|_| RegistrationFeedError::Backend)?;
        let first_recent: Option<i64> = sqlx::query_scalar(
            "SELECT MIN(cursor) FROM identity_registration_outbox WHERE occurred_at >= $1",
        )
        .bind(cutoff)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| RegistrationFeedError::Backend)?;
        let time_floor = first_recent
            .map(|first| first.saturating_sub(1))
            .unwrap_or(head);
        let next_floor = current_floor.max(minimum_ack.min(time_floor));
        if next_floor > current_floor {
            sqlx::query("DELETE FROM identity_registration_outbox WHERE cursor <= $1")
                .bind(next_floor)
                .execute(&mut *tx)
                .await
                .map_err(|_| RegistrationFeedError::Backend)?;
            sqlx::query("UPDATE identity_outbox_clock SET retention_floor_cursor=$1 WHERE id=1")
                .bind(next_floor)
                .execute(&mut *tx)
                .await
                .map_err(|_| RegistrationFeedError::Backend)?;
        }
        tx.commit()
            .await
            .map_err(|_| RegistrationFeedError::Backend)?;
        Ok(RegistrationAckOutcome {
            consumer: command.consumer,
            generation: command.generation,
            stored_cursor: command.acked_cursor,
        })
    }

    async fn claim_registration_nonce_async(
        &self,
        nonce_hash: &str,
        kid: &str,
        audience: &str,
        seen_at: u64,
        expires_at: u64,
    ) -> Result<(), RegistrationFeedError> {
        let seen_at = i64::try_from(seen_at).map_err(|_| RegistrationFeedError::Backend)?;
        let expires_at = i64::try_from(expires_at).map_err(|_| RegistrationFeedError::Backend)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| RegistrationFeedError::Backend)?;
        sqlx::query("DELETE FROM identity_registration_replay WHERE expires_at<$1")
            .bind(seen_at)
            .execute(&mut *tx)
            .await
            .map_err(|_| RegistrationFeedError::Backend)?;
        let inserted = sqlx::query(
            "INSERT INTO identity_registration_replay \
                 (nonce_hash,kid,audience,seen_at,expires_at) VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(nonce_hash)
        .bind(kid)
        .bind(audience)
        .bind(seen_at)
        .bind(expires_at)
        .execute(&mut *tx)
        .await;
        match inserted {
            Ok(_) => {
                tx.commit()
                    .await
                    .map_err(|_| RegistrationFeedError::Backend)?;
                Ok(())
            }
            Err(error)
                if error
                    .as_database_error()
                    .is_some_and(|database| database.is_unique_violation()) =>
            {
                Err(RegistrationFeedError::Replay)
            }
            Err(_) => Err(RegistrationFeedError::Backend),
        }
    }

    async fn put_code_async(&self, code: &AuthCode) -> Result<(), sqlx::Error> {
        let binding = code.binding.as_ref();
        sqlx::query(
            "INSERT INTO auth_codes \
                 (code, client_id, redirect_uri, code_challenge, sub, nonce, scope, expires_at, \
                  snap_session_binding, snap_aal, snap_uv, snap_auth_time, snap_factor_epoch, \
                  required_acr) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(&code.code)
        .bind(&code.client_id)
        .bind(&code.redirect_uri)
        .bind(&code.code_challenge)
        .bind(&code.sub)
        .bind(code.nonce.as_deref())
        .bind(&code.scope)
        .bind(code.expires_at as i64)
        .bind(binding.map(|value| value.session_binding.as_str()))
        .bind(binding.map(|value| value.aal.as_str()))
        .bind(binding.map(|value| value.uv))
        .bind(binding.map(|value| value.auth_time as i64))
        .bind(binding.map(|value| value.factor_epoch as i64))
        .bind(code.required_acr.as_deref())
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
            "SELECT code, client_id, redirect_uri, code_challenge, sub, nonce, scope, expires_at, \
                    snap_session_binding, snap_aal, snap_uv, snap_auth_time, snap_factor_epoch, \
                    required_acr \
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
        Ok(Some(Self::auth_code_from_row(&row)?))
    }

    async fn redeem_code_async(
        &self,
        code_value: &str,
        now: u64,
    ) -> Result<Option<RedeemedAuthCode>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT code, client_id, redirect_uri, code_challenge, sub, nonce, scope, expires_at, \
                    snap_session_binding, snap_aal, snap_uv, snap_auth_time, snap_factor_epoch, \
                    required_acr \
             FROM auth_codes WHERE code = $1",
        )
        .bind(code_value)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let code = Self::auth_code_from_row(&row)?;

        // All lifecycle, factor-generation and session mutations use this same subject lock.
        // Whichever transaction obtains it first defines the token/revocation linearization.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&code.sub)
            .fetch_one(&mut *tx)
            .await?;
        let deleted = sqlx::query("DELETE FROM auth_codes WHERE code = $1")
            .bind(code_value)
            .execute(&mut *tx)
            .await?;
        if deleted.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(None);
        }

        let user_row = sqlx::query(
            "SELECT sub, email, password_hash, email_verified, created_at, is_admin, disabled, \
                    factor_epoch FROM users WHERE sub = $1 FOR UPDATE",
        )
        .bind(&code.sub)
        .fetch_optional(&mut *tx)
        .await?;
        let user = user_row.as_ref().map(Self::user_from_row).transpose()?;
        let Some(user) = user.filter(|user| !user.disabled) else {
            tx.commit().await?;
            return Ok(None);
        };
        let (assurance, session_expires_at) = match code.binding.as_ref() {
            None => (None, None),
            Some(binding) => {
                let session_row = sqlx::query(
                    "SELECT id, user_sub, created_at, expires_at, user_agent, ip, last_seen, \
                            session_binding, aal, uv, auth_time, amr, factor_epoch \
                     FROM sessions WHERE session_binding = $1 FOR UPDATE",
                )
                .bind(&binding.session_binding)
                .fetch_optional(&mut *tx)
                .await?;
                let session = session_row
                    .as_ref()
                    .map(Self::session_from_row)
                    .transpose()?;
                let Some(session) = session.filter(|session| {
                    session.user_sub == code.sub
                        && user.factor_epoch == binding.factor_epoch
                        && binding.matches_session(session)
                }) else {
                    tx.commit().await?;
                    return Ok(None);
                };
                let assurance = session.assurance().ok_or_else(|| {
                    sqlx::Error::Protocol("bound session lacked assurance binding".to_string())
                })?;
                (Some(assurance), Some(session.expires_at))
            }
        };
        // The caller timestamp is a lower bound only. Sampling after the subject advisory lock,
        // user row lock and bound-session row lock prevents lock waiting from extending the
        // validity window of either the authorization code or its source session.
        let validated_at = now.max(now_secs());
        if validated_at > code.expires_at
            || session_expires_at.is_some_and(|expires_at| validated_at > expires_at)
        {
            tx.commit().await?;
            return Ok(None);
        }
        tx.commit().await?;
        Ok(Some(RedeemedAuthCode {
            code,
            user,
            assurance,
            validated_at,
            session_expires_at,
        }))
    }

    async fn put_session_if_active_async(&self, s: &Session) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&s.user_sub)
            .fetch_one(&mut *tx)
            .await?;
        let active = sqlx::query("SELECT disabled, factor_epoch FROM users WHERE sub = $1")
            .bind(&s.user_sub)
            .fetch_optional(&mut *tx)
            .await?
            .is_some_and(|row| {
                !row.get::<bool, _>("disabled")
                    && row.get::<i64, _>("factor_epoch") == s.factor_epoch as i64
            });
        if !active {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO sessions \
                 (id, user_sub, created_at, expires_at, user_agent, ip, last_seen, \
                  session_binding, aal, uv, auth_time, amr, factor_epoch) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             ON CONFLICT (id) DO UPDATE SET user_sub = EXCLUDED.user_sub, \
             created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at, \
             user_agent = EXCLUDED.user_agent, ip = EXCLUDED.ip, last_seen = EXCLUDED.last_seen, \
             session_binding = EXCLUDED.session_binding, aal = EXCLUDED.aal, uv = EXCLUDED.uv, \
             auth_time = EXCLUDED.auth_time, amr = EXCLUDED.amr, \
             factor_epoch = EXCLUDED.factor_epoch",
        )
        .bind(&s.id)
        .bind(&s.user_sub)
        .bind(s.created_at as i64)
        .bind(s.expires_at as i64)
        .bind(&s.user_agent)
        .bind(&s.ip)
        .bind(s.last_seen as i64)
        .bind(s.session_binding.as_deref())
        .bind(s.aal.as_str())
        .bind(s.uv)
        .bind(s.auth_time as i64)
        .bind(&s.amr)
        .bind(s.factor_epoch as i64)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn get_session_async(&self, id: &str) -> Result<Option<Session>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, user_sub, created_at, expires_at, user_agent, ip, last_seen, \
                    session_binding, aal, uv, auth_time, amr, factor_epoch \
             FROM sessions WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(Self::session_from_row(&row)?))
    }

    async fn delete_session_async(&self, id: &str) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let subject: Option<String> =
            sqlx::query_scalar("SELECT user_sub FROM sessions WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(subject) = subject {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(subject)
                .fetch_one(&mut *tx)
                .await?;
        }
        sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn list_sessions_async(&self, user_sub: &str) -> Result<Vec<Session>, sqlx::Error> {
        let now = now_secs() as i64;
        let rows = sqlx::query(
            "SELECT id, user_sub, created_at, expires_at, user_agent, ip, last_seen, \
                    session_binding, aal, uv, auth_time, amr, factor_epoch \
             FROM sessions WHERE user_sub = $1 AND expires_at > $2 ORDER BY created_at DESC",
        )
        .bind(user_sub)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::session_from_row).collect()
    }

    async fn revoke_session_async(&self, user_sub: &str, id: &str) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(user_sub)
            .fetch_one(&mut *tx)
            .await?;
        // Ownership is enforced in SQL: the row is deleted only when both id and owner match.
        sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_sub = $2")
            .bind(id)
            .bind(user_sub)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn revoke_other_sessions_async(
        &self,
        user_sub: &str,
        keep_id: &str,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(user_sub)
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM sessions WHERE user_sub = $1 AND id <> $2")
            .bind(user_sub)
            .bind(keep_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
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

    async fn lookup_session_assurance_async(
        &self,
        subject: &str,
        session_binding: &str,
        now: u64,
    ) -> Result<SessionAssuranceLookup, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(subject)
            .fetch_one(&mut *tx)
            .await?;
        let user_row = sqlx::query("SELECT disabled, factor_epoch FROM users WHERE sub = $1")
            .bind(subject)
            .fetch_optional(&mut *tx)
            .await?;
        let factor_epoch = user_row
            .as_ref()
            .map_or(0, |row| row.get::<i64, _>("factor_epoch") as u64);
        let Some(user_row) = user_row.filter(|row| !row.get::<bool, _>("disabled")) else {
            tx.commit().await?;
            return Ok(SessionAssuranceLookup::Absent { factor_epoch });
        };
        let session_row = sqlx::query(
            "SELECT id, user_sub, created_at, expires_at, user_agent, ip, last_seen, \
                    session_binding, aal, uv, auth_time, amr, factor_epoch \
             FROM sessions WHERE session_binding = $1",
        )
        .bind(session_binding)
        .fetch_optional(&mut *tx)
        .await?;
        let session = session_row
            .as_ref()
            .map(Self::session_from_row)
            .transpose()?;
        let current_epoch = user_row.get::<i64, _>("factor_epoch") as u64;
        let result = match session.filter(|session| {
            session.user_sub == subject
                && now <= session.expires_at
                && session.factor_epoch == current_epoch
        }) {
            Some(session) => match session.assurance() {
                Some(assurance) => SessionAssuranceLookup::Live(assurance),
                None => SessionAssuranceLookup::Absent { factor_epoch },
            },
            None => SessionAssuranceLookup::Absent { factor_epoch },
        };
        tx.commit().await?;
        Ok(result)
    }

    async fn bump_factor_epoch_async(&self, user_sub: &str) -> Result<Option<u64>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(user_sub)
            .fetch_one(&mut *tx)
            .await?;
        let epoch: Option<i64> = sqlx::query_scalar(
            "UPDATE users SET factor_epoch = factor_epoch + 1 WHERE sub = $1 \
             RETURNING factor_epoch",
        )
        .bind(user_sub)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(epoch.map(|value| value as u64))
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

    async fn put_credential_and_bump_factor_async(
        &self,
        c: &Credential,
    ) -> Result<Option<u64>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&c.user_sub)
            .fetch_one(&mut *tx)
            .await?;
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE sub = $1 AND disabled = false)",
        )
        .bind(&c.user_sub)
        .fetch_one(&mut *tx)
        .await?;
        if !active {
            tx.commit().await?;
            return Ok(None);
        }
        sqlx::query(
            "INSERT INTO webauthn_credentials (cred_id, user_sub, passkey, created_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (cred_id) DO UPDATE SET passkey = EXCLUDED.passkey",
        )
        .bind(&c.cred_id)
        .bind(&c.user_sub)
        .bind(&c.passkey)
        .bind(c.created_at as i64)
        .execute(&mut *tx)
        .await?;
        let epoch: i64 = sqlx::query_scalar(
            "UPDATE users SET factor_epoch = factor_epoch + 1 WHERE sub = $1 \
             RETURNING factor_epoch",
        )
        .bind(&c.user_sub)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(epoch as u64))
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

    fn totp_from_row(row: &sqlx::postgres::PgRow) -> Result<TotpConfig, sqlx::Error> {
        let created_at: i64 = row.try_get("created_at")?;
        let verified_at: i64 = row.try_get("verified_at")?;
        Ok(TotpConfig {
            user_sub: row.try_get("user_sub")?,
            secret: row.try_get("secret")?,
            enabled: row.try_get("enabled")?,
            created_at: created_at as u64,
            verified_at: verified_at as u64,
            last_accepted_counter: row
                .try_get::<Option<i64>, _>("last_accepted_counter")?
                .map(|counter| counter as u64),
        })
    }

    async fn get_totp_async(&self, user_sub: &str) -> Result<Option<TotpConfig>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT user_sub, secret, enabled, created_at, verified_at, last_accepted_counter \
             FROM mfa_totp WHERE user_sub = $1",
        )
        .bind(user_sub)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::totp_from_row).transpose()
    }

    async fn put_totp_async(&self, c: &TotpConfig) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO mfa_totp \
                 (user_sub, secret, enabled, created_at, verified_at, last_accepted_counter) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (user_sub) DO UPDATE SET secret = EXCLUDED.secret, \
             enabled = EXCLUDED.enabled, created_at = EXCLUDED.created_at, \
             verified_at = EXCLUDED.verified_at, \
             last_accepted_counter = EXCLUDED.last_accepted_counter",
        )
        .bind(&c.user_sub)
        .bind(&c.secret)
        .bind(c.enabled)
        .bind(c.created_at as i64)
        .bind(c.verified_at as i64)
        .bind(c.last_accepted_counter.map(|counter| counter as i64))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn begin_totp_enrollment_async(
        &self,
        c: &TotpConfig,
    ) -> Result<Option<u64>, sqlx::Error> {
        if c.enabled || c.verified_at != 0 || c.last_accepted_counter.is_some() {
            return Err(sqlx::Error::Protocol(
                "pending TOTP enrollment must be unverified and have no accepted counter"
                    .to_string(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&c.user_sub)
            .fetch_one(&mut *tx)
            .await?;
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE sub = $1 AND disabled = false)",
        )
        .bind(&c.user_sub)
        .fetch_one(&mut *tx)
        .await?;
        if !active {
            tx.commit().await?;
            return Ok(None);
        }
        sqlx::query(
            "INSERT INTO mfa_totp \
                 (user_sub, secret, enabled, created_at, verified_at, last_accepted_counter) \
             VALUES ($1, $2, false, $3, 0, NULL) \
             ON CONFLICT (user_sub) DO UPDATE SET secret = EXCLUDED.secret, enabled = false, \
             created_at = EXCLUDED.created_at, verified_at = 0, last_accepted_counter = NULL",
        )
        .bind(&c.user_sub)
        .bind(&c.secret)
        .bind(c.created_at as i64)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_sub = $1")
            .bind(&c.user_sub)
            .execute(&mut *tx)
            .await?;
        let epoch: i64 = sqlx::query_scalar(
            "UPDATE users SET factor_epoch = factor_epoch + 1 WHERE sub = $1 \
             RETURNING factor_epoch",
        )
        .bind(&c.user_sub)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(epoch as u64))
    }

    async fn enable_totp_async(
        &self,
        user_sub: &str,
        expected_secret: &str,
        accepted_counter: u64,
        verified_at: u64,
        code_hashes: Vec<String>,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(user_sub)
            .fetch_one(&mut *tx)
            .await?;
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE sub = $1 AND disabled = false)",
        )
        .bind(user_sub)
        .fetch_one(&mut *tx)
        .await?;
        if !active {
            tx.commit().await?;
            return Ok(false);
        }
        let updated = sqlx::query(
            "UPDATE mfa_totp SET enabled = true, verified_at = $4, \
                 last_accepted_counter = $3 \
             WHERE user_sub = $1 AND secret = $2 AND enabled = false AND \
                   (last_accepted_counter IS NULL OR last_accepted_counter < $3)",
        )
        .bind(user_sub)
        .bind(expected_secret)
        .bind(accepted_counter as i64)
        .bind(verified_at as i64)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_sub = $1")
            .bind(user_sub)
            .execute(&mut *tx)
            .await?;
        for code_hash in code_hashes {
            sqlx::query(
                "INSERT INTO mfa_recovery_codes (user_sub, code_hash, created_at) \
                 VALUES ($1, $2, $3)",
            )
            .bind(user_sub)
            .bind(code_hash)
            .bind(verified_at as i64)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    async fn accept_totp_counter_async(
        &self,
        user_sub: &str,
        expected_secret: &str,
        counter: u64,
    ) -> Result<Option<u64>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(user_sub)
            .fetch_one(&mut *tx)
            .await?;
        let user =
            sqlx::query("SELECT disabled, factor_epoch FROM users WHERE sub = $1 FOR UPDATE")
                .bind(user_sub)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(epoch) = user
            .filter(|row| !row.get::<bool, _>("disabled"))
            .map(|row| row.get::<i64, _>("factor_epoch") as u64)
        else {
            tx.commit().await?;
            return Ok(None);
        };
        let updated = sqlx::query(
            "UPDATE mfa_totp SET last_accepted_counter = $3 \
             WHERE user_sub = $1 AND secret = $2 AND enabled = true AND \
                   (last_accepted_counter IS NULL OR last_accepted_counter < $3)",
        )
        .bind(user_sub)
        .bind(expected_secret)
        .bind(counter as i64)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((updated.rows_affected() == 1).then_some(epoch))
    }

    async fn delete_totp_async(&self, user_sub: &str) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_sub = $1")
            .bind(user_sub)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM mfa_totp WHERE user_sub = $1")
            .bind(user_sub)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn disable_totp_and_bump_factor_async(
        &self,
        user_sub: &str,
    ) -> Result<Option<u64>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(user_sub)
            .fetch_one(&mut *tx)
            .await?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE sub = $1)")
            .bind(user_sub)
            .fetch_one(&mut *tx)
            .await?;
        if !exists {
            tx.commit().await?;
            return Ok(None);
        }
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_sub = $1")
            .bind(user_sub)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM mfa_totp WHERE user_sub = $1")
            .bind(user_sub)
            .execute(&mut *tx)
            .await?;
        let epoch: i64 = sqlx::query_scalar(
            "UPDATE users SET factor_epoch = factor_epoch + 1 WHERE sub = $1 \
             RETURNING factor_epoch",
        )
        .bind(user_sub)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(epoch as u64))
    }

    async fn put_recovery_codes_async(
        &self,
        user_sub: &str,
        code_hashes: Vec<String>,
        created_at: u64,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_sub = $1")
            .bind(user_sub)
            .execute(&mut *tx)
            .await?;
        for code_hash in code_hashes {
            sqlx::query(
                "INSERT INTO mfa_recovery_codes (user_sub, code_hash, created_at) \
                 VALUES ($1, $2, $3)",
            )
            .bind(user_sub)
            .bind(&code_hash)
            .bind(created_at as i64)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn recovery_code_count_async(&self, user_sub: &str) -> Result<usize, sqlx::Error> {
        let rows = sqlx::query("SELECT code_hash FROM mfa_recovery_codes WHERE user_sub = $1")
            .bind(user_sub)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.len())
    }

    async fn take_recovery_code_async(
        &self,
        user_sub: &str,
        code_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let res =
            sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_sub = $1 AND code_hash = $2")
                .bind(user_sub)
                .bind(code_hash)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected() == 1)
    }

    async fn take_recovery_code_and_bump_factor_async(
        &self,
        user_sub: &str,
        code_hash: &str,
    ) -> Result<Option<u64>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(user_sub)
            .fetch_one(&mut *tx)
            .await?;
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE sub = $1 AND disabled = false)",
        )
        .bind(user_sub)
        .fetch_one(&mut *tx)
        .await?;
        if !active {
            tx.commit().await?;
            return Ok(None);
        }
        let removed =
            sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_sub = $1 AND code_hash = $2")
                .bind(user_sub)
                .bind(code_hash)
                .execute(&mut *tx)
                .await?;
        if removed.rows_affected() != 1 {
            tx.commit().await?;
            return Ok(None);
        }
        let epoch: i64 = sqlx::query_scalar(
            "UPDATE users SET factor_epoch = factor_epoch + 1 WHERE sub = $1 \
             RETURNING factor_epoch",
        )
        .bind(user_sub)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(epoch as u64))
    }

    async fn put_totp_challenge_async(&self, c: &TotpChallenge) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO mfa_login_challenges \
                 (id, user_sub, return_to, user_agent, ip, expires_at, source_session_binding, \
                  expected_factor_epoch, required_acr, password_verified) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO UPDATE SET user_sub = EXCLUDED.user_sub, \
             return_to = EXCLUDED.return_to, user_agent = EXCLUDED.user_agent, \
             ip = EXCLUDED.ip, expires_at = EXCLUDED.expires_at, \
             source_session_binding = EXCLUDED.source_session_binding, \
             expected_factor_epoch = EXCLUDED.expected_factor_epoch, \
             required_acr = EXCLUDED.required_acr, \
             password_verified = EXCLUDED.password_verified",
        )
        .bind(&c.id)
        .bind(&c.user_sub)
        .bind(&c.return_to)
        .bind(&c.user_agent)
        .bind(&c.ip)
        .bind(c.expires_at as i64)
        .bind(c.source_session_binding.as_deref())
        .bind(c.expected_factor_epoch.map(|epoch| epoch as i64))
        .bind(c.required_acr.as_deref())
        .bind(c.password_verified)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn take_totp_challenge_async(
        &self,
        id: &str,
    ) -> Result<Option<TotpChallenge>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT id, user_sub, return_to, user_agent, ip, expires_at, \
                    source_session_binding, expected_factor_epoch, required_acr, password_verified \
             FROM mfa_login_challenges WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let deleted = sqlx::query("DELETE FROM mfa_login_challenges WHERE id = $1")
            .bind(id)
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
        Ok(Some(TotpChallenge {
            id: row.try_get("id")?,
            user_sub: row.try_get("user_sub")?,
            return_to: row.try_get("return_to")?,
            user_agent: row.try_get("user_agent")?,
            ip: row.try_get("ip")?,
            expires_at: expires_at as u64,
            source_session_binding: row.try_get("source_session_binding")?,
            expected_factor_epoch: row
                .try_get::<Option<i64>, _>("expected_factor_epoch")?
                .map(|epoch| epoch as u64),
            required_acr: row.try_get("required_acr")?,
            password_verified: row.try_get("password_verified")?,
        }))
    }

    async fn put_login_event_async(&self, e: &LoginEvent) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO login_events \
                 (id, user_sub, username, occurred_at, ip, user_agent, method, result, detail) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&e.id)
        .bind(&e.user_sub)
        .bind(&e.username)
        .bind(e.occurred_at as i64)
        .bind(&e.ip)
        .bind(&e.user_agent)
        .bind(&e.method)
        .bind(&e.result)
        .bind(&e.detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn login_event_from_row(row: &sqlx::postgres::PgRow) -> Result<LoginEvent, sqlx::Error> {
        let occurred_at: i64 = row.try_get("occurred_at")?;
        Ok(LoginEvent {
            id: row.try_get("id")?,
            user_sub: row.try_get("user_sub")?,
            username: row.try_get("username")?,
            occurred_at: occurred_at as u64,
            ip: row.try_get("ip")?,
            user_agent: row.try_get("user_agent")?,
            method: row.try_get("method")?,
            result: row.try_get("result")?,
            detail: row.try_get("detail")?,
        })
    }

    async fn list_login_events_async(
        &self,
        user_sub: &str,
        limit: usize,
    ) -> Result<Vec<LoginEvent>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, user_sub, username, occurred_at, ip, user_agent, method, result, detail \
             FROM login_events WHERE user_sub = $1 ORDER BY occurred_at DESC",
        )
        .bind(user_sub)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .take(limit)
            .map(Self::login_event_from_row)
            .collect()
    }

    async fn put_personal_token_async(&self, t: &PersonalAccessToken) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&t.user_sub)
            .fetch_one(&mut *tx)
            .await?;
        let active = sqlx::query("SELECT disabled FROM users WHERE sub = $1")
            .bind(&t.user_sub)
            .fetch_optional(&mut *tx)
            .await?
            .is_some_and(|row| !row.get::<bool, _>("disabled"));
        if !active {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO personal_access_tokens \
                 (id, user_sub, name, token_hash, scopes, created_at, expires_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&t.id)
        .bind(&t.user_sub)
        .bind(&t.name)
        .bind(&t.token_hash)
        .bind(&t.scopes)
        .bind(t.created_at as i64)
        .bind(t.expires_at as i64)
        .bind(t.revoked_at as i64)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    fn personal_token_from_row(
        row: &sqlx::postgres::PgRow,
    ) -> Result<PersonalAccessToken, sqlx::Error> {
        let created_at: i64 = row.try_get("created_at")?;
        let expires_at: i64 = row.try_get("expires_at")?;
        let revoked_at: i64 = row.try_get("revoked_at")?;
        Ok(PersonalAccessToken {
            id: row.try_get("id")?,
            user_sub: row.try_get("user_sub")?,
            name: row.try_get("name")?,
            token_hash: row.try_get("token_hash")?,
            scopes: row.try_get("scopes")?,
            created_at: created_at as u64,
            expires_at: expires_at as u64,
            revoked_at: revoked_at as u64,
        })
    }

    async fn list_personal_tokens_async(
        &self,
        user_sub: &str,
    ) -> Result<Vec<PersonalAccessToken>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, user_sub, name, token_hash, scopes, created_at, expires_at, revoked_at \
             FROM personal_access_tokens WHERE user_sub = $1 AND revoked_at = 0 \
             ORDER BY created_at DESC",
        )
        .bind(user_sub)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::personal_token_from_row).collect()
    }

    async fn find_active_personal_token_async(
        &self,
        token_hash: &str,
        now: u64,
    ) -> Result<Option<PersonalAccessToken>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT p.id, p.user_sub, p.name, p.token_hash, p.scopes, p.created_at, \
                    p.expires_at, p.revoked_at \
             FROM personal_access_tokens p \
             JOIN users u ON u.sub = p.user_sub \
             WHERE p.token_hash = $1 AND p.revoked_at = 0 AND p.expires_at > $2 \
                   AND u.disabled = false \
             LIMIT 1",
        )
        .bind(token_hash)
        .bind(now as i64)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::personal_token_from_row).transpose()
    }

    async fn revoke_personal_token_async(
        &self,
        user_sub: &str,
        id: &str,
        revoked_at: u64,
    ) -> Result<(), sqlx::Error> {
        if revoked_at == 0 {
            return Err(sqlx::Error::Protocol(
                "revoked_at must be positive".to_string(),
            ));
        }
        sqlx::query(
            "UPDATE personal_access_tokens SET revoked_at = $3 \
             WHERE id = $1 AND user_sub = $2 AND revoked_at = 0",
        )
        .bind(id)
        .bind(user_sub)
        .bind(revoked_at as i64)
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
        self.get_client_async(client_id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_client failed");
            None
        })
    }

    async fn put_client(&self, client: Client) {
        if let Err(e) = self.put_client_async(&client).await {
            tracing::error!(error = %e, "pg put_client failed");
        }
    }

    async fn get_consent(&self, user_sub: &str, client_id: &str) -> Option<String> {
        self.get_consent_async(user_sub, client_id)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg get_consent failed");
                None
            })
    }

    async fn put_consent(&self, user_sub: &str, client_id: &str, scope: &str, granted_at: u64) {
        if let Err(e) = self
            .put_consent_async(user_sub, client_id, scope, granted_at)
            .await
        {
            tracing::error!(error = %e, "pg put_consent failed");
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

    async fn set_password_hash_and_bump_factor(
        &self,
        sub: &str,
        hash: &str,
    ) -> Result<u64, StoreError> {
        self.set_password_hash_and_bump_factor_async(sub, hash)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "pg password rotation failed");
                StoreError::Backend
            })?
            .ok_or(StoreError::Backend)
    }

    async fn create_user(
        &self,
        sub: &str,
        email: &str,
        password_hash: &str,
        created_at: u64,
    ) -> Result<(), CreateUserError> {
        self.create_user_async(sub, email, password_hash, created_at, None)
            .await
    }

    async fn create_user_with_verification_token(
        &self,
        sub: &str,
        email: &str,
        password_hash: &str,
        created_at: u64,
        token: VerificationToken,
    ) -> Result<(), CreateUserError> {
        self.create_user_async(sub, email, password_hash, created_at, Some(&token))
            .await
    }

    async fn set_email_verified(&self, sub: &str) -> Result<bool, StoreError> {
        self.set_email_verification_async(sub, true)
            .await
            .map_err(|error| {
                tracing::error!(
                    database_error = error.as_database_error().is_some(),
                    "pg set_email_verified failed"
                );
                StoreError::Backend
            })
    }

    async fn set_email_unverified(&self, sub: &str) -> Result<bool, StoreError> {
        self.set_email_verification_async(sub, false)
            .await
            .map_err(|error| {
                tracing::error!(
                    database_error = error.as_database_error().is_some(),
                    "pg set_email_unverified failed"
                );
                StoreError::Backend
            })
    }

    async fn list_users(&self) -> Vec<User> {
        self.list_users_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_users failed");
            Vec::new()
        })
    }

    async fn set_disabled(
        &self,
        sub: &str,
        disabled: bool,
    ) -> Result<ManualDisabledOutcome, StoreError> {
        self.set_disabled_async(sub, disabled)
            .await
            .map_err(|error| {
                tracing::error!(
                    database_error = error.as_database_error().is_some(),
                    "pg set_disabled failed"
                );
                StoreError::Backend
            })
    }

    async fn delete_user(&self, sub: &str) -> Result<bool, StoreError> {
        self.delete_user_async(sub).await.map_err(|error| {
            tracing::error!(
                database_error = error.as_database_error().is_some(),
                "pg delete_user failed"
            );
            StoreError::Backend
        })
    }

    async fn apply_subject_lifecycle(
        &self,
        command: SubjectLifecycleCommand,
    ) -> Result<SubjectLifecycleOutcome, SubjectLifecycleError> {
        match self.apply_subject_lifecycle_async(&command).await {
            Ok(outcome) => Ok(outcome),
            Err(PgSubjectLifecycleError::Conflict) => Err(SubjectLifecycleError::Conflict),
            Err(PgSubjectLifecycleError::Backend(error)) => {
                // Database details can contain values from a failing PAT row. Keep this
                // generic so lifecycle errors never disclose credential hashes.
                tracing::error!(
                    database_error = error.as_database_error().is_some(),
                    "pg apply_subject_lifecycle failed"
                );
                Err(SubjectLifecycleError::Backend)
            }
        }
    }

    async fn set_is_admin(&self, sub: &str, is_admin: bool) {
        if let Err(e) = self.set_is_admin_async(sub, is_admin).await {
            tracing::error!(error = %e, "pg set_is_admin failed");
        }
    }

    async fn list_clients(&self) -> Vec<Client> {
        self.list_clients_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_clients failed");
            Vec::new()
        })
    }

    async fn put_verification_token(&self, token: VerificationToken) -> Result<(), StoreError> {
        self.put_verification_token_async(&token)
            .await
            .map_err(|error| {
                tracing::error!(
                    database_error = error.as_database_error().is_some(),
                    "pg put_verification_token failed"
                );
                StoreError::Backend
            })
    }

    async fn take_verification_token(
        &self,
        token: &str,
    ) -> Result<Option<(String, String)>, StoreError> {
        self.take_verification_token_async(token)
            .await
            .map_err(|error| {
                tracing::error!(
                    database_error = error.as_database_error().is_some(),
                    "pg take_verification_token failed"
                );
                StoreError::Backend
            })
    }

    async fn consume_verification_token_and_verify(
        &self,
        token: &str,
    ) -> Result<Option<String>, StoreError> {
        self.consume_verification_token_and_verify_async(token)
            .await
            .map_err(|error| {
                tracing::error!(
                    database_error = error.as_database_error().is_some(),
                    "pg atomic email verification failed"
                );
                StoreError::Backend
            })
    }

    async fn consume_reset_token_and_rotate_password(
        &self,
        token: &str,
        password_hash: &str,
    ) -> Result<Option<(String, u64)>, StoreError> {
        self.consume_reset_token_and_rotate_password_async(token, password_hash)
            .await
            .map_err(|error| {
                tracing::error!(
                    database_error = error.as_database_error().is_some(),
                    "pg atomic password reset failed"
                );
                StoreError::Backend
            })
    }

    async fn create_registration_snapshot(
        &self,
    ) -> Result<RegistrationSnapshotManifest, RegistrationFeedError> {
        self.create_registration_snapshot_async()
            .await
            .map_err(|error| {
                tracing::error!(
                    database_error = error.as_database_error().is_some(),
                    "pg registration snapshot creation failed"
                );
                RegistrationFeedError::Backend
            })
    }

    async fn get_registration_snapshot_page(
        &self,
        snapshot_id: &str,
        after_ordinal: u64,
        limit: u16,
    ) -> Result<RegistrationSnapshotPage, RegistrationFeedError> {
        self.get_registration_snapshot_page_async(snapshot_id, after_ordinal, limit)
            .await
    }

    async fn get_registration_changes(
        &self,
        after: u64,
        limit: u16,
    ) -> Result<RegistrationChangesPage, RegistrationFeedError> {
        self.get_registration_changes_async(after, limit).await
    }

    async fn acknowledge_registration(
        &self,
        command: RegistrationAckCommand,
    ) -> Result<RegistrationAckOutcome, RegistrationFeedError> {
        self.acknowledge_registration_async(command).await
    }

    async fn claim_registration_nonce(
        &self,
        nonce_hash: &str,
        kid: &str,
        audience: &str,
        seen_at: u64,
        expires_at: u64,
    ) -> Result<(), RegistrationFeedError> {
        self.claim_registration_nonce_async(nonce_hash, kid, audience, seen_at, expires_at)
            .await
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

    async fn redeem_code(
        &self,
        code: &str,
        now: u64,
    ) -> Result<Option<RedeemedAuthCode>, StoreError> {
        self.redeem_code_async(code, now).await.map_err(|error| {
            tracing::error!(error = %error, "pg redeem_code failed");
            StoreError::Backend
        })
    }

    async fn put_session_if_active(&self, session: Session) -> Result<bool, StoreError> {
        self.put_session_if_active_async(&session)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "pg put_session_if_active failed");
                StoreError::Backend
            })
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
        self.list_sessions_async(user_sub)
            .await
            .unwrap_or_else(|e| {
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

    async fn lookup_session_assurance(
        &self,
        subject: &str,
        session_binding: &str,
        now: u64,
    ) -> Result<SessionAssuranceLookup, StoreError> {
        self.lookup_session_assurance_async(subject, session_binding, now)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "pg lookup_session_assurance failed");
                StoreError::Backend
            })
    }

    async fn bump_factor_epoch(&self, user_sub: &str) -> Result<u64, StoreError> {
        self.bump_factor_epoch_async(user_sub)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "pg bump_factor_epoch failed");
                StoreError::Backend
            })?
            .ok_or(StoreError::Backend)
    }

    async fn put_credential(&self, cred: Credential) {
        if let Err(e) = self.put_credential_async(&cred).await {
            tracing::error!(error = %e, "pg put_credential failed");
        }
    }

    async fn put_credential_and_bump_factor(&self, cred: Credential) -> Result<u64, StoreError> {
        self.put_credential_and_bump_factor_async(&cred)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "pg passkey registration failed");
                StoreError::Backend
            })?
            .ok_or(StoreError::Backend)
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

    async fn get_totp(&self, user_sub: &str) -> Option<TotpConfig> {
        self.get_totp_async(user_sub).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_totp failed");
            None
        })
    }

    async fn put_totp(&self, config: TotpConfig) {
        if let Err(e) = self.put_totp_async(&config).await {
            tracing::error!(error = %e, "pg put_totp failed");
        }
    }

    async fn begin_totp_enrollment(&self, config: TotpConfig) -> Result<u64, StoreError> {
        self.begin_totp_enrollment_async(&config)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "pg begin TOTP enrollment failed");
                StoreError::Backend
            })?
            .ok_or(StoreError::Backend)
    }

    async fn enable_totp(
        &self,
        user_sub: &str,
        expected_secret: &str,
        accepted_counter: u64,
        verified_at: u64,
        code_hashes: Vec<String>,
    ) -> Result<bool, StoreError> {
        self.enable_totp_async(
            user_sub,
            expected_secret,
            accepted_counter,
            verified_at,
            code_hashes,
        )
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "pg enable TOTP failed");
            StoreError::Backend
        })
    }

    async fn accept_totp_counter(
        &self,
        user_sub: &str,
        expected_secret: &str,
        counter: u64,
    ) -> Result<Option<u64>, StoreError> {
        self.accept_totp_counter_async(user_sub, expected_secret, counter)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "pg accept TOTP counter failed");
                StoreError::Backend
            })
    }

    async fn delete_totp(&self, user_sub: &str) {
        if let Err(e) = self.delete_totp_async(user_sub).await {
            tracing::error!(error = %e, "pg delete_totp failed");
        }
    }

    async fn disable_totp_and_bump_factor(&self, user_sub: &str) -> Result<u64, StoreError> {
        self.disable_totp_and_bump_factor_async(user_sub)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "pg disable TOTP failed");
                StoreError::Backend
            })?
            .ok_or(StoreError::Backend)
    }

    async fn put_recovery_codes(&self, user_sub: &str, code_hashes: Vec<String>, created_at: u64) {
        if let Err(e) = self
            .put_recovery_codes_async(user_sub, code_hashes, created_at)
            .await
        {
            tracing::error!(error = %e, "pg put_recovery_codes failed");
        }
    }

    async fn recovery_code_count(&self, user_sub: &str) -> usize {
        self.recovery_code_count_async(user_sub)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg recovery_code_count failed");
                0
            })
    }

    async fn take_recovery_code(&self, user_sub: &str, code_hash: &str) -> bool {
        self.take_recovery_code_async(user_sub, code_hash)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg take_recovery_code failed");
                false
            })
    }

    async fn take_recovery_code_and_bump_factor(
        &self,
        user_sub: &str,
        code_hash: &str,
    ) -> Result<Option<u64>, StoreError> {
        self.take_recovery_code_and_bump_factor_async(user_sub, code_hash)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "pg recovery-code consumption failed");
                StoreError::Backend
            })
    }

    async fn put_totp_challenge(&self, challenge: TotpChallenge) {
        if let Err(e) = self.put_totp_challenge_async(&challenge).await {
            tracing::error!(error = %e, "pg put_totp_challenge failed");
        }
    }

    async fn take_totp_challenge(&self, id: &str) -> Option<TotpChallenge> {
        self.take_totp_challenge_async(id)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg take_totp_challenge failed");
                None
            })
    }

    async fn put_login_event(&self, event: LoginEvent) {
        if let Err(e) = self.put_login_event_async(&event).await {
            tracing::error!(error = %e, "pg put_login_event failed");
        }
    }

    async fn list_login_events(&self, user_sub: &str, limit: usize) -> Vec<LoginEvent> {
        self.list_login_events_async(user_sub, limit)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg list_login_events failed");
                Vec::new()
            })
    }

    async fn put_personal_token(&self, token: PersonalAccessToken) -> Result<(), StoreError> {
        match self.put_personal_token_async(&token).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(StoreError::Backend),
            Err(_) => {
                // Database constraint details can echo token_hash values. Keep this log
                // deliberately generic so neither PAT plaintext nor its hash is disclosed.
                tracing::error!("pg put_personal_token failed");
                Err(StoreError::Backend)
            }
        }
    }

    async fn list_personal_tokens(&self, user_sub: &str) -> Vec<PersonalAccessToken> {
        self.list_personal_tokens_async(user_sub)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg list_personal_tokens failed");
                Vec::new()
            })
    }

    async fn find_active_personal_token(
        &self,
        token_hash: &str,
        now: u64,
    ) -> Result<Option<PersonalAccessToken>, StoreError> {
        self.find_active_personal_token_async(token_hash, now)
            .await
            .map_err(|_| StoreError::Backend)
    }

    async fn revoke_personal_token(
        &self,
        user_sub: &str,
        id: &str,
        revoked_at: u64,
    ) -> Result<(), StoreError> {
        self.revoke_personal_token_async(user_sub, id, revoked_at)
            .await
            .map_err(|_| {
                tracing::error!("pg revoke_personal_token failed");
                StoreError::Backend
            })
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
