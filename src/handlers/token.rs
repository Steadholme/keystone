//! `POST /token` — application/x-www-form-urlencoded, grant_type=authorization_code.
//!
//! Consumes the single-use code, checks client_id + exact redirect_uri match,
//! verifies PKCE S256, then signs and returns the RS256 access + id tokens.

use axum::extract::State;
use axum::{Form, Json};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::{jwt, now_secs, pkce, AppState};

#[derive(Debug, Deserialize)]
pub struct TokenParams {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
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
    Form(params): Form<TokenParams>,
) -> Result<Json<TokenResponse>, AppError> {
    if params.grant_type != "authorization_code" {
        return Err(AppError::InvalidRequest(
            "grant_type must be authorization_code".to_string(),
        ));
    }

    // Single-use consume: removal makes replay -> invalid_grant by construction.
    let auth_code = state
        .store
        .take_code(&params.code)
        .ok_or_else(|| AppError::InvalidGrant("unknown or already-used code".to_string()))?;

    // Expiry.
    if now_secs() > auth_code.expires_at {
        return Err(AppError::InvalidGrant("authorization code expired".to_string()));
    }

    // Binding: client_id + exact redirect_uri must match those bound at /authorize.
    if auth_code.client_id != params.client_id {
        return Err(AppError::InvalidGrant("client_id mismatch".to_string()));
    }
    if auth_code.redirect_uri != params.redirect_uri {
        return Err(AppError::InvalidGrant("redirect_uri mismatch".to_string()));
    }

    // PKCE S256: base64url(sha256(code_verifier)) == stored challenge.
    if !pkce::verify_s256(&params.code_verifier, &auth_code.code_challenge) {
        return Err(AppError::InvalidGrant("PKCE verification failed".to_string()));
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

    Ok(Json(TokenResponse {
        access_token,
        id_token,
        token_type: "Bearer",
        expires_in: state.config.access_ttl,
        scope: auth_code.scope,
    }))
}
