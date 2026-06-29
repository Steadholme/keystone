//! `GET /authorize` — authorization_code + PKCE S256.
//!
//! Validates client_id and EXACT redirect_uri (400 JSON if bad — never redirect
//! to an untrusted URI), requires `code_challenge` + `code_challenge_method=S256`,
//! then GATES ON A SESSION: no valid session 302s to `/login?return_to=<this URL>`;
//! a valid session mints+stores an [`AuthCode`] for the authenticated user and 302s back.

use axum::extract::{OriginalUri, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
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
    headers: HeaderMap,
    OriginalUri(original_uri): OriginalUri,
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

    // 5. GATE: require a valid login session. No session -> bounce to /login, carrying
    //    the full /authorize request (path + query) as a same-origin return_to so the
    //    user lands back here after authenticating. Auto-consent for the first-party
    //    seeded client is fine for v0.
    let sub = match auth::current_session(&state, &headers) {
        Some(session) => session.user_sub,
        None => {
            let return_to = original_uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/authorize");
            let location = format!("/login?return_to={}", urlencode_component(return_to));
            return Ok((StatusCode::FOUND, [(header::LOCATION, location)]).into_response());
        }
    };

    // 6. Mint + store a single-use, bound authorization code.
    let code = new_opaque_code();
    // Audit the grant (subject + client_id; never the code/challenge).
    state.audit.emit(AuditEvent::info(
        "authorize.grant",
        &sub,
        &params.client_id,
        "authorization code issued",
    ));
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

/// Percent-encode a string for safe use as a single query-string component value
/// (encodes everything outside the RFC 3986 unreserved set).
fn urlencode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
