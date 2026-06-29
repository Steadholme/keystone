//! `POST /token` — application/x-www-form-urlencoded, grant_type=authorization_code.
//!
//! Authenticates the client (confidential clients MUST present a valid secret via
//! `client_secret_post` OR HTTP Basic, verified constant-time; public clients present
//! none), consumes the single-use code, checks client_id + exact redirect_uri match,
//! verifies PKCE S256, then signs and returns the RS256 access + id tokens.

use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::{Form, Json};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::{jwt, now_secs, pkce, AppState};

#[derive(Debug, Deserialize)]
pub struct TokenParams {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    /// Present for public (PKCE) clients and for `client_secret_post`. May be omitted
    /// when the client authenticates via HTTP Basic (`client_secret_basic`).
    #[serde(default)]
    pub client_id: Option<String>,
    /// Confidential client secret via `client_secret_post`.
    #[serde(default)]
    pub client_secret: Option<String>,
    pub code_verifier: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
}

pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(params): Form<TokenParams>,
) -> Result<Json<TokenResponse>, AppError> {
    if params.grant_type != "authorization_code" {
        return Err(AppError::InvalidRequest(
            "grant_type must be authorization_code".to_string(),
        ));
    }

    // --- Client identification (client_secret_post OR HTTP Basic) ---------------
    // The client_id may arrive in the form body (public PKCE / client_secret_post) or
    // in the HTTP Basic header (client_secret_basic). Resolve ONE effective client_id;
    // if both are present they MUST agree.
    let basic = parse_basic_auth(&headers);
    let effective_client_id = match (
        params.client_id.as_deref(),
        basic.as_ref().map(|(id, _)| id.as_str()),
    ) {
        (Some(form_id), Some(basic_id)) if form_id != basic_id => {
            return Err(AppError::InvalidClientAuth(
                "client_id mismatch between body and Authorization header".to_string(),
            ));
        }
        (Some(form_id), _) => form_id.to_string(),
        (None, Some(basic_id)) => basic_id.to_string(),
        (None, None) => {
            return Err(AppError::InvalidRequest("client_id is required".to_string()));
        }
    };

    // Load the client to learn its authentication method. Done BEFORE consuming the
    // code so a bad-secret request never burns a valid single-use code.
    let client = state
        .store
        .get_client(&effective_client_id)
        .ok_or_else(|| AppError::InvalidClient("unknown client_id".to_string()))?;

    // Confidential clients MUST present a valid secret (constant-time Argon2id verify).
    // Public clients (no stored hash) present none — unchanged PKCE-only path.
    if let Some(ref secret_hash) = client.client_secret_hash {
        let presented = params
            .client_secret
            .as_deref()
            .or_else(|| basic.as_ref().map(|(_, secret)| secret.as_str()));
        let ok = matches!(presented, Some(secret) if auth::verify_password(secret, secret_hash));
        if !ok {
            // Confidential client presented a bad/missing secret. Audit the client_id only.
            state.audit.emit(AuditEvent::warning(
                "client_auth.failure",
                &effective_client_id,
                "token_endpoint",
                "invalid client credentials",
            ));
            return Err(AppError::InvalidClientAuth(
                "invalid client credentials".to_string(),
            ));
        }
    }

    // --- Authorization-code grant ----------------------------------------------
    // Single-use consume: removal makes replay -> invalid_grant by construction.
    let auth_code = state
        .store
        .take_code(&params.code)
        .ok_or_else(|| AppError::InvalidGrant("unknown or already-used code".to_string()))?;

    // Expiry.
    if now_secs() > auth_code.expires_at {
        return Err(AppError::InvalidGrant(
            "authorization code expired".to_string(),
        ));
    }

    // Binding: client_id + exact redirect_uri must match those bound at /authorize.
    if auth_code.client_id != effective_client_id {
        return Err(AppError::InvalidGrant("client_id mismatch".to_string()));
    }
    if auth_code.redirect_uri != params.redirect_uri {
        return Err(AppError::InvalidGrant("redirect_uri mismatch".to_string()));
    }

    // PKCE S256: base64url(sha256(code_verifier)) == stored challenge.
    if !pkce::verify_s256(&params.code_verifier, &auth_code.code_challenge) {
        return Err(AppError::InvalidGrant(
            "PKCE verification failed".to_string(),
        ));
    }

    // Resolve the approved user for the id_token email claim.
    let user = state
        .store
        .get_user(&auth_code.sub)
        .ok_or_else(|| AppError::Internal("approved subject not found".to_string()))?;

    let access_token = jwt::sign_access(
        &state.keys,
        &state.config,
        &auth_code.sub,
        &auth_code.client_id,
        &auth_code.scope,
    )
    .map_err(|e| AppError::Internal(format!("sign access_token: {e}")))?;

    // `aud` = the requesting client_id and `nonce` (when sent to /authorize) round-trip
    // into the id_token, so the RP can validate it.
    let id_token = jwt::sign_id(
        &state.keys,
        &state.config,
        &auth_code.sub,
        &auth_code.client_id,
        &auth_code.scope,
        &user.email,
        auth_code.nonce.clone(),
    )
    .map_err(|e| AppError::Internal(format!("sign id_token: {e}")))?;

    // Tokens minted — audit the issuance (subject + client_id; no token material).
    state.audit.emit(AuditEvent::info(
        "token.issue",
        &auth_code.sub,
        &auth_code.client_id,
        "access + id token issued",
    ));

    Ok(Json(TokenResponse {
        access_token,
        id_token,
        token_type: "Bearer",
        expires_in: state.config.access_ttl,
        scope: auth_code.scope,
    }))
}

/// Parse `Authorization: Basic base64(client_id:client_secret)` into its parts.
/// Returns `None` when the header is absent or not a well-formed Basic credential.
fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded = BASE64_STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}
