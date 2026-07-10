//! `GET /static/{file}` — embedded CSS/JS.
//!
//! Assets are baked into the binary with `include_str!`, so the slim/distroless image
//! never misses a file at runtime. Only an explicit allowlist of names is served.

use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

const APP_CSS: &str = include_str!("../../static/app.css");
const LOGIN_JS: &str = include_str!("../../static/login.js");

pub async fn serve(Path(file): Path<String>) -> Response {
    let (body, ctype) = match file.as_str() {
        "app.css" => (APP_CSS, "text/css; charset=utf-8"),
        "login.js" => (LOGIN_JS, "application/javascript; charset=utf-8"),
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(ctype)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600"),
            ),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_css_tracks_the_odyssey_material_contract() {
        assert!(APP_CSS.contains("Odyssey 1.1 adapter"));
        assert!(APP_CSS.contains("--c-oxide-600: #B6422C"));
        assert!(APP_CSS.contains("--c-paper-50: #F2F0E8"));
        assert!(APP_CSS.contains("background-size: 48px 48px"));
        assert!(!APP_CSS.contains("--accent: #4F46E5"));
    }
}
