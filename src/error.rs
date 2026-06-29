//! OAuth2-style error envelope.
//!
//! Every failure maps to `{ "error": ..., "error_description": ... }` with the
//! correct status code; 401s additionally carry `WWW-Authenticate: Bearer`.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed/missing parameters (e.g. missing PKCE, bad code_challenge_method).
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    /// Code replay / expired / binding mismatch / bad PKCE verifier.
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),

    /// Unknown client or unregistered redirect_uri (never redirect to untrusted URI).
    #[error("invalid_client: {0}")]
    InvalidClient(String),

    /// Missing/invalid Bearer access token at `/userinfo`.
    #[error("invalid_token: {0}")]
    Unauthorized(String),

    /// Unexpected internal failure.
    #[error("server_error: {0}")]
    Internal(String),
}

impl AppError {
    fn parts(&self) -> (StatusCode, &'static str, String, bool) {
        match self {
            AppError::InvalidRequest(d) => {
                (StatusCode::BAD_REQUEST, "invalid_request", d.clone(), false)
            }
            AppError::InvalidGrant(d) => {
                (StatusCode::BAD_REQUEST, "invalid_grant", d.clone(), false)
            }
            AppError::InvalidClient(d) => {
                (StatusCode::BAD_REQUEST, "invalid_client", d.clone(), false)
            }
            AppError::Unauthorized(d) => {
                (StatusCode::UNAUTHORIZED, "invalid_token", d.clone(), true)
            }
            AppError::Internal(d) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                d.clone(),
                false,
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error, description, www_authenticate) = self.parts();
        let body = Json(serde_json::json!({
            "error": error,
            "error_description": description,
        }));
        let mut response = (status, body).into_response();
        if www_authenticate {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}
