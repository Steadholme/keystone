//! WebAuthn relying-party setup.
//!
//! One [`Webauthn`] is built at startup from `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_ORIGIN`
//! and shared (read-only) for the process lifetime. rp_id is the PARENT domain
//! (`w33d.xyz`) so passkeys remain valid across future `*.w33d.xyz` services, while the
//! origin is the single public entrypoint (`https://id.w33d.xyz`).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use webauthn_rs::prelude::{CredentialID, Url, Uuid};
use webauthn_rs::{Webauthn, WebauthnBuilder};

/// Build the relying-party instance. Returns an error string on bad config so `main`
/// (and `build_dev_state`) can fail loudly rather than serve a broken login path.
pub fn build(rp_id: &str, rp_origin: &str) -> Result<Webauthn, String> {
    let origin = Url::parse(rp_origin)
        .map_err(|e| format!("invalid WEBAUTHN_RP_ORIGIN {rp_origin:?}: {e}"))?;
    let builder = WebauthnBuilder::new(rp_id, &origin)
        .map_err(|e| format!("webauthn rp_id {rp_id:?} / origin {rp_origin:?} mismatch: {e}"))?;
    builder
        .rp_name("Steadholme Keystone")
        .build()
        .map_err(|e| format!("webauthn build: {e}"))
}

/// Deterministic per-user WebAuthn user-handle (UUIDv5 of the subject), so the same
/// user yields the same handle across register and authenticate ceremonies.
pub fn user_handle(sub: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, sub.as_bytes())
}

/// Stable string key for a credential id (base64url-no-pad of the raw bytes), used as
/// the `webauthn_credentials.cred_id` primary key.
pub fn cred_id_str(cred_id: &CredentialID) -> String {
    URL_SAFE_NO_PAD.encode(cred_id.as_ref())
}
