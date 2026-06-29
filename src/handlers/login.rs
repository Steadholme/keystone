//! Server-rendered login surface: `GET/POST /login`, `GET /account`, `POST /logout`.
//!
//! Password login is the fallback factor (Argon2); passkeys are driven from these pages
//! via `/static/login.js`. Every state-changing POST is double-submit CSRF protected.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::AppState;

const LOGIN_HTML: &str = include_str!("../../templates/login.html");
const ACCOUNT_HTML: &str = include_str!("../../templates/account.html");

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    pub return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LogoutForm {
    #[serde(default)]
    pub csrf_token: String,
}

/// `GET /login` — render the form (or bounce to the target if already signed in).
pub async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> Response {
    let return_to = sanitize_return_to(q.return_to.as_deref());
    if auth::current_session(&state, &headers).await.is_some() {
        return redirect(&return_to, &[]);
    }
    let csrf = auth::new_csrf_token();
    let body = render_login(&csrf, &return_to, "", None);
    html_with_cookies(StatusCode::OK, body, &[auth::csrf_cookie(&csrf)])
}

/// `POST /login` — verify CSRF + Argon2 password, then create a session.
pub async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let return_to = sanitize_return_to(form.return_to.as_deref());

    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return reject_login(
            &return_to,
            &form.username,
            "Invalid or expired form token — please try again.",
        );
    }

    let user = state.store.get_user_by_username(&form.username).await;
    let verified = user
        .as_ref()
        .and_then(|u| u.password_hash.as_deref())
        .map(|hash| auth::verify_password(&form.password, hash))
        .unwrap_or(false);

    if !verified {
        // Audit the denial: submitted username + a fixed reason only — NEVER the password.
        state.audit.emit(AuditEvent::warning(
            "login.failure",
            &form.username,
            "password",
            "invalid credentials",
        ));
        return reject_login(
            &return_to,
            &form.username,
            "Incorrect username or password.",
        );
    }

    let user = user.expect("verified implies user present");
    let cookie = auth::create_session(&state, &user.sub).await;
    state.audit.emit(AuditEvent::info(
        "login.success",
        &user.email,
        "password",
        "password login",
    ));
    redirect(
        &return_to,
        &[
            auth::session_cookie(&cookie, state.config.session_ttl),
            auth::clear_cookie(auth::CSRF_COOKIE),
        ],
    )
}

/// `GET /account` — session-required; shows the user + passkey/logout controls.
pub async fn account_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session) = auth::current_session(&state, &headers).await else {
        return redirect("/login", &[]);
    };
    let Some(user) = state.store.get_user(&session.user_sub).await else {
        auth::destroy_session(&state, &headers).await;
        return redirect("/login", &[auth::clear_cookie(auth::SESSION_COOKIE)]);
    };
    let count = state.store.list_credentials(&user.sub).await.len();
    let csrf = auth::new_csrf_token();
    let body = render_account(&csrf, &user.sub, &user.email, count);
    html_with_cookies(StatusCode::OK, body, &[auth::csrf_cookie(&csrf)])
}

/// `POST /logout` — CSRF-checked; destroys the session and clears cookies.
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LogoutForm>,
) -> Response {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/account", &[]);
    }
    // Audit the logout with the user's email (best-effort) before tearing the session down.
    if let Some(session) = auth::current_session(&state, &headers).await {
        let actor = state
            .store
            .get_user(&session.user_sub)
            .await
            .map(|u| u.email)
            .unwrap_or(session.user_sub);
        state
            .audit
            .emit(AuditEvent::info("session.logout", &actor, "session", "logged out"));
    }
    auth::destroy_session(&state, &headers).await;
    redirect(
        "/login",
        &[
            auth::clear_cookie(auth::SESSION_COOKIE),
            auth::clear_cookie(auth::CSRF_COOKIE),
        ],
    )
}

// ---------------------------------------------------------------------------
// Rendering + helpers
// ---------------------------------------------------------------------------

fn reject_login(return_to: &str, username: &str, msg: &str) -> Response {
    // A fresh CSRF token (and cookie) for the retry.
    let csrf = auth::new_csrf_token();
    let body = render_login(&csrf, return_to, username, Some(msg));
    html_with_cookies(StatusCode::UNAUTHORIZED, body, &[auth::csrf_cookie(&csrf)])
}

fn render_login(csrf: &str, return_to: &str, username: &str, error: Option<&str>) -> String {
    let error_html = match error {
        Some(e) => format!(r#"<div class="alert">{}</div>"#, esc(e)),
        None => String::new(),
    };
    LOGIN_HTML
        .replace("{{ERROR}}", &error_html)
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{RETURN_TO}}", &esc(return_to))
        .replace("{{USERNAME}}", &esc(username))
}

fn render_account(csrf: &str, sub: &str, email: &str, passkeys: usize) -> String {
    // Display name: the email local-part (the closest thing to a human name we hold).
    let name = email
        .split('@')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(email);
    ACCOUNT_HTML
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{SUB}}", &esc(sub))
        .replace("{{EMAIL}}", &esc(email))
        .replace("{{NAME}}", &esc(name))
        .replace("{{PASSKEYS}}", &passkeys.to_string())
}

/// Only allow same-origin relative paths as a post-login redirect target (no open redirect).
fn sanitize_return_to(raw: Option<&str>) -> String {
    match raw {
        Some(r) if r.starts_with('/') && !r.starts_with("//") => r.to_string(),
        _ => "/account".to_string(),
    }
}

/// Minimal HTML escaping for text/attribute interpolation.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn redirect(target: &str, cookies: &[String]) -> Response {
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, target.to_string())]).into_response();
    attach_cookies(&mut resp, cookies);
    resp
}

fn html_with_cookies(status: StatusCode, body: String, cookies: &[String]) -> Response {
    let mut resp = (status, Html(body)).into_response();
    attach_cookies(&mut resp, cookies);
    resp
}

fn attach_cookies(resp: &mut Response, cookies: &[String]) {
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
}
