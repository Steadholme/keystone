//! Service-authenticated workforce lifecycle ingress.
//!
//! This endpoint accepts only version-fenced JML state transitions. It never creates a
//! Keystone user: missing subjects are durably tombstoned so a delayed older event cannot
//! reactivate an identity that appears later.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::audit::AuditEvent;
use crate::store::{SubjectLifecycleCommand, SubjectLifecycleError, SubjectLifecycleState};
use crate::{auth, AppState};

pub const MAX_LIFECYCLE_JSON_LEN: usize = 4096;
const MIN_SERVICE_TOKEN_LEN: usize = 32;
const MAX_SERVICE_TOKEN_LEN: usize = 512;
const MAX_SUBJECT_LEN: usize = 256;
const MAX_EVENT_ID_LEN: usize = 256;
const MAX_CORRELATION_ID_LEN: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RequestedState {
    Active,
    Frozen,
    Terminated,
}

impl From<RequestedState> for SubjectLifecycleState {
    fn from(value: RequestedState) -> Self {
        match value {
            RequestedState::Active => Self::Active,
            RequestedState::Frozen => Self::Frozen,
            RequestedState::Terminated => Self::Terminated,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LifecycleRequest {
    subject: String,
    state: RequestedState,
    source_event_id: String,
    source_version: u64,
    correlation_id: String,
}

#[derive(Debug, Serialize)]
struct LifecycleResponse {
    subject: String,
    state: &'static str,
    source_version: u64,
    replayed: bool,
    user_found: bool,
    revoked_sessions: u64,
}

/// `POST /internal/v1/jml/subjects/lifecycle`.
pub(crate) async fn apply_lifecycle(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<LifecycleRequest>, JsonRejection>,
) -> Response {
    let Some(expected_token) = state
        .config
        .jml_service_token
        .as_deref()
        .filter(|token| valid_service_token(token))
    else {
        return service_unavailable();
    };

    let presented = bearer_token(&headers).unwrap_or_default();
    let presented_hash = auth::secret_hash(presented);
    let expected_hash = auth::secret_hash(expected_token);
    if !auth::constant_time_eq(presented_hash.as_bytes(), expected_hash.as_bytes()) {
        return unauthorized();
    }

    let Ok(Json(body)) = payload else {
        return invalid_request();
    };
    if !valid_subject(&body.subject)
        || !valid_identifier(&body.source_event_id, MAX_EVENT_ID_LEN)
        || !valid_identifier(&body.correlation_id, MAX_CORRELATION_ID_LEN)
        || body.source_version == 0
        || body.source_version > i64::MAX as u64
    {
        return invalid_request();
    }

    let requested_state = SubjectLifecycleState::from(body.state);
    let subject = body.subject;
    let source_version = body.source_version;
    let command = SubjectLifecycleCommand {
        subject: subject.clone(),
        state: requested_state,
        source_event_id: body.source_event_id,
        source_version,
        correlation_id: body.correlation_id,
    };

    match state.store.apply_subject_lifecycle(command).await {
        Ok(outcome) => {
            let detail = format!(
                "state={} version={} replayed={}",
                outcome.state.as_str(),
                source_version,
                outcome.replayed
            );
            state.audit.emit(AuditEvent::info(
                "identity.lifecycle.apply",
                "jml-service",
                &subject,
                &detail,
            ));
            no_store_json(
                StatusCode::OK,
                LifecycleResponse {
                    subject,
                    state: outcome.state.as_str(),
                    source_version,
                    replayed: outcome.replayed,
                    user_found: outcome.user_found,
                    revoked_sessions: outcome.revoked_sessions,
                },
            )
        }
        Err(SubjectLifecycleError::Conflict) => no_store_json(
            StatusCode::CONFLICT,
            serde_json::json!({ "error": "lifecycle_conflict" }),
        ),
        Err(SubjectLifecycleError::Backend) => service_unavailable(),
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

fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        })
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
        HeaderValue::from_static("Bearer realm=\"keystone-jml\""),
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

/// Route-level wrapper also covers body-limit and content-type extractor rejections.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_is_raw_keystone_identifier() {
        assert!(valid_subject("u_admin"));
        assert!(valid_subject("usr_abC-123"));
        assert!(!valid_subject("user:u_admin"));
        assert!(!valid_subject(" u_admin"));
        assert!(!valid_subject(""));
    }

    #[test]
    fn service_token_requires_at_least_32_visible_bytes() {
        assert!(valid_service_token(&"a".repeat(32)));
        assert!(!valid_service_token(&"a".repeat(31)));
        assert!(!valid_service_token(&format!(" {}", "a".repeat(32))));
    }
}
