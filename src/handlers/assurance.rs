//! Authoritative, service-authenticated lookup for one Keystone session binding.
//!
//! The lookup credential belongs to Keystone/Sluice only. It is intentionally independent
//! from the HMAC key Sluice later uses to sign downstream MFA assertions.

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::store::SessionAssuranceLookup;
use crate::{auth, now_secs, AppState};

pub const MAX_ASSURANCE_JSON_LEN: usize = 1024;
const MIN_SERVICE_TOKEN_LEN: usize = 32;
const MAX_SERVICE_TOKEN_LEN: usize = 512;
const MAX_SUBJECT_LEN: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssuranceRequest {
    subject: String,
    session_binding: String,
}

#[derive(Debug, Serialize)]
struct AssuranceResponse {
    result: &'static str,
    subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_binding: Option<String>,
    aal: &'static str,
    uv: bool,
    auth_time: u64,
    factor_epoch: u64,
    as_of: u64,
}

/// `POST /internal/v1/session-assurance`.
pub(crate) async fn lookup(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AssuranceRequest>, JsonRejection>,
) -> Response {
    let Some(current_token) = state
        .config
        .assurance_service_token
        .as_deref()
        .filter(|token| valid_service_token(token))
    else {
        return service_unavailable();
    };
    let previous_token = match state.config.assurance_previous_service_token.as_deref() {
        Some(token) if !valid_service_token(token) || token == current_token => {
            return service_unavailable();
        }
        value => value,
    };
    let presented = bearer_token(&headers).unwrap_or_default();
    let current_matches = auth::constant_time_eq(
        auth::secret_hash(presented).as_bytes(),
        auth::secret_hash(current_token).as_bytes(),
    );
    let previous_matches = previous_token.is_some_and(|token| {
        auth::constant_time_eq(
            auth::secret_hash(presented).as_bytes(),
            auth::secret_hash(token).as_bytes(),
        )
    });
    if !current_matches && !previous_matches {
        return unauthorized();
    }
    let Ok(Json(body)) = payload else {
        return invalid_request();
    };
    if !valid_subject(&body.subject) || !valid_binding(&body.session_binding) {
        return invalid_request();
    }

    let now = now_secs();
    match state
        .store
        .lookup_session_assurance(&body.subject, &body.session_binding, now)
        .await
    {
        Ok(SessionAssuranceLookup::Live(value)) => no_store_json(
            StatusCode::OK,
            AssuranceResponse {
                result: "live",
                subject: body.subject,
                session_binding: Some(value.session_binding),
                aal: value.aal.as_str(),
                uv: value.uv,
                auth_time: value.auth_time,
                factor_epoch: value.factor_epoch,
                as_of: now,
            },
        ),
        Ok(SessionAssuranceLookup::Absent { factor_epoch }) => no_store_json(
            StatusCode::OK,
            AssuranceResponse {
                result: "absent",
                subject: body.subject,
                session_binding: None,
                aal: "AAL_NONE",
                uv: false,
                auth_time: 0,
                factor_epoch,
                as_of: now,
            },
        ),
        Err(_) => service_unavailable(),
    }
}

fn valid_service_token(token: &str) -> bool {
    (MIN_SERVICE_TOKEN_LEN..=MAX_SERVICE_TOKEN_LEN).contains(&token.len())
        && token.trim() == token
        && token.bytes().all(|byte| byte.is_ascii_graphic())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() || value.len() > MAX_SERVICE_TOKEN_LEN + 16 {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.trim() != token
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return None;
    }
    Some(token)
}

fn valid_subject(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SUBJECT_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_binding(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_request() -> Response {
    no_store_json(
        StatusCode::BAD_REQUEST,
        serde_json::json!({ "error": "invalid_request" }),
    )
}

fn unauthorized() -> Response {
    let mut response = no_store_json(
        StatusCode::UNAUTHORIZED,
        serde_json::json!({ "error": "unauthorized" }),
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"keystone-assurance\""),
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
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Authorization"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_is_exact_lower_hex() {
        assert!(valid_binding(&"a5".repeat(32)));
        assert!(!valid_binding(&"A5".repeat(32)));
        assert!(!valid_binding(&"a5".repeat(31)));
    }
}
