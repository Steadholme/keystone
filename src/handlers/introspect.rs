//! Service-authenticated opaque PAT introspection for first-party gateways.
//!
//! The gateway authenticates with the configured `GW_CLIENT_ID` / `GW_CLIENT_SECRET`
//! through HTTP Basic. PAT plaintext is accepted only in the form body, hashed once,
//! and never logged or returned.

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};

use crate::{auth, now_secs, AppState};

/// Current PATs are `pat_` plus a 43-character base64url payload. Leave bounded room
/// for a future opaque encoding while rejecting oversized attacker-controlled input.
pub const MAX_PAT_TOKEN_LEN: usize = 128;
pub const MAX_INTROSPECTION_FORM_LEN: usize = 512;

#[derive(Deserialize)]
pub struct IntrospectionParams {
    #[serde(default)]
    token: String,
}

#[derive(Serialize)]
struct InactiveResponse {
    active: bool,
}

#[derive(Serialize)]
struct ActiveResponse {
    active: bool,
    sub: String,
    scope: String,
    exp: u64,
    token_type: &'static str,
}

/// `POST /internal/v1/pats/introspect`.
pub async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(params): Form<IntrospectionParams>,
) -> Response {
    let Some(expected_secret) = state.config.gw_client_secret.as_deref() else {
        return service_unavailable();
    };

    // Compute both comparisons for every configured request. Neither the client id nor
    // the secret is logged, and malformed/missing Basic credentials use empty values.
    let (presented_id, presented_secret) =
        auth::parse_basic_auth(&headers).unwrap_or_else(|| (String::new(), String::new()));
    let id_ok = auth::constant_time_eq(
        presented_id.as_bytes(),
        state.config.gw_client_id.as_bytes(),
    );
    // Hash both sides before comparing so the constant-time comparison always receives
    // equal-length inputs, independent of the presented secret's length.
    let presented_secret_hash = auth::secret_hash(&presented_secret);
    let expected_secret_hash = auth::secret_hash(expected_secret);
    let secret_ok = auth::constant_time_eq(
        presented_secret_hash.as_bytes(),
        expected_secret_hash.as_bytes(),
    );
    if !(id_ok & secret_ok) {
        return invalid_client();
    }

    if !valid_pat_shape(&params.token) {
        return inactive();
    }

    let token_hash = auth::secret_hash(&params.token);
    match state
        .store
        .find_active_personal_token(&token_hash, now_secs())
        .await
    {
        Ok(Some(token)) => no_store_json(
            StatusCode::OK,
            ActiveResponse {
                active: true,
                sub: token.user_sub,
                scope: token.scopes,
                exp: token.expires_at,
                token_type: "Bearer",
            },
        ),
        Ok(None) => inactive(),
        Err(_) => service_unavailable(),
    }
}

fn valid_pat_shape(token: &str) -> bool {
    if token.len() > MAX_PAT_TOKEN_LEN {
        return false;
    }
    let Some(payload) = token.strip_prefix("pat_") else {
        return false;
    };
    !payload.is_empty()
        && payload
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn inactive() -> Response {
    no_store_json(StatusCode::OK, InactiveResponse { active: false })
}

fn invalid_client() -> Response {
    let mut response = no_store_json(
        StatusCode::UNAUTHORIZED,
        serde_json::json!({ "error": "invalid_client" }),
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"keystone-pat-introspection\""),
    );
    response
}

fn service_unavailable() -> Response {
    no_store_json(
        StatusCode::SERVICE_UNAVAILABLE,
        serde_json::json!({ "error": "temporarily_unavailable" }),
    )
}

fn no_store_json<T: Serialize>(status: StatusCode, body: T) -> Response {
    let mut response = (status, Json(body)).into_response();
    apply_privacy_headers(&mut response);
    response
}

/// Route-level response wrapper. This also covers extractor and body-limit rejections
/// that happen before [`introspect`] starts running.
pub async fn privacy_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    apply_privacy_headers(&mut response);
    response
}

fn apply_privacy_headers(response: &mut Response) {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Authorization"));
}
