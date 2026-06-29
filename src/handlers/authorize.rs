//! `GET /authorize` — authorization_code + PKCE S256.
//!
//! Validates client_id and EXACT redirect_uri (400 JSON if bad — never redirect
//! to an untrusted URI), requires `code_challenge` + `code_challenge_method=S256`,
//! auto-approves the seeded dev user, mints+stores an [`AuthCode`], then 302s back.

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::error::AppError;
use crate::store::{new_opaque_code, AuthCode};
use crate::{now_secs, AppState};

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}

pub async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, AppError> {
    // 1. Client must exist. Do NOT redirect on an unknown client.
    let client = state
        .store
        .get_client(&params.client_id)
        .ok_or_else(|| AppError::InvalidClient("unknown client_id".to_string()))?;

    // 2. EXACT redirect_uri match. Do NOT redirect to an unregistered URI.
    if !client.allows_redirect(&params.redirect_uri) {
        return Err(AppError::InvalidClient(
            "redirect_uri is not registered for this client".to_string(),
        ));
    }

    // 3. Only the authorization_code flow exists (response_types_supported = ["code"]).
    if params.response_type != "code" {
        return Err(AppError::InvalidRequest(
            "response_type must be \"code\"".to_string(),
        ));
    }

    // 4. PKCE S256 is MANDATORY.
    let code_challenge = match params.code_challenge {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => {
            return Err(AppError::InvalidRequest(
                "code_challenge is required (PKCE S256)".to_string(),
            ))
        }
    };
    if params.code_challenge_method.as_deref() != Some("S256") {
        return Err(AppError::InvalidRequest(
            "code_challenge_method must be S256".to_string(),
        ));
    }

    // 5. v0 dev path: auto-approve the seeded user (no login UI / consent yet — seam).
    let sub = state.config.dev_user_sub.clone();

    // 6. Mint + store a single-use, bound authorization code.
    let code = new_opaque_code();
    state.store.put_code(AuthCode {
        code: code.clone(),
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        scope: params.scope.clone(),
        nonce: params.nonce.clone(),
        code_challenge,
        sub,
        expires_at: now_secs() + state.config.code_ttl,
        used: false,
    });

    // 7. 302 back to redirect_uri with code (+ state, preserved verbatim).
    let mut location = format!("{}?code={}", params.redirect_uri, code);
    if let Some(st) = params.state.as_deref() {
        location.push_str("&state=");
        location.push_str(st);
    }

    Ok((StatusCode::FOUND, [(header::LOCATION, location)]).into_response())
}
