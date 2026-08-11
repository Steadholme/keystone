//! `GET /userinfo` — Authorization: Bearer <access_token>.
//!
//! Validates the JWT against our own JWKS key (RS256, iss, exp) and returns
//! `{ sub, email }`. 401 + `WWW-Authenticate: Bearer` on missing/invalid token.

use axum::extract::State;
use axum::http::header;
use axum::http::HeaderMap;
use axum::Json;
use jsonwebtoken::{decode, Algorithm, Validation};
use serde_json::{json, Value};

use crate::error::AppError;
use crate::jwt::AccessTokenClaims;
use crate::AppState;

pub async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let token = bearer_token(&headers)
        .ok_or_else(|| AppError::Unauthorized("missing Bearer token".to_string()))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[state.config.issuer.as_str()]);
    // access_token aud = client_id; userinfo verifies signature + iss + exp only.
    validation.validate_aud = false;

    let data = decode::<AccessTokenClaims>(token, &state.keys.decoding_key(), &validation)
        .map_err(|e| AppError::Unauthorized(format!("invalid access token: {e}")))?;

    let user = state
        .store
        .get_user(&data.claims.sub)
        .await
        .filter(|user| !user.disabled)
        .ok_or_else(|| AppError::Unauthorized("subject unavailable".to_string()))?;

    Ok(Json(json!({
        "sub": user.sub,
        "email": user.email,
    })))
}

/// Extract the bearer credential from the `Authorization` header (case-insensitive scheme).
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("Bearer") && !token.is_empty() {
        Some(token.trim())
    } else {
        None
    }
}
