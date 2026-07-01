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
use crate::handlers::register::client_ip;
use crate::store::Session;
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

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub session_id: String,
}

/// `GET /` — bare root: 302 to `/account`. `/account` itself bounces to `/login`
/// when there is no session, so this is the single convenience entry point:
/// signed-in -> `/account`, signed-out -> `/account` -> `/login`.
pub async fn root_redirect() -> Response {
    redirect("/account", &[])
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

    // GATE: a disabled account is rejected up front — BEFORE any password verification —
    // with an explicit 403, so neither the outcome nor its timing depends on the password.
    if user.as_ref().is_some_and(|u| u.disabled) {
        state.audit.emit(AuditEvent::warning(
            "login.disabled",
            &form.username,
            "password",
            "account disabled",
        ));
        let csrf = auth::new_csrf_token();
        let body = render_login(
            &csrf,
            &return_to,
            &form.username,
            Some("This account is disabled. Contact your administrator."),
        );
        return html_with_cookies(StatusCode::FORBIDDEN, body, &[auth::csrf_cookie(&csrf)]);
    }

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

    // GATE: a self-service user who has not confirmed their email cannot complete a login
    // (and therefore cannot reach any session-gated page, including /authorize). Seeded and
    // pre-provisioned accounts are backfilled to verified, so this never locks them out.
    if !user.email_verified {
        state.audit.emit(AuditEvent::warning(
            "login.unverified",
            &user.email,
            "password",
            "email not verified",
        ));
        return reject_login(
            &return_to,
            &form.username,
            "Please verify your email before signing in — check your inbox for the link.",
        );
    }

    let cookie =
        auth::create_session(&state, &user.sub, &user_agent(&headers), &client_ip(&headers)).await;
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

/// `GET /account` — session-required; shows the user + passkey/session controls.
pub async fn account_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session) = auth::current_session(&state, &headers).await else {
        return redirect("/login", &[]);
    };
    let Some(user) = state.store.get_user(&session.user_sub).await else {
        auth::destroy_session(&state, &headers).await;
        return redirect("/login", &[auth::clear_cookie(auth::SESSION_COOKIE)]);
    };
    let count = state.store.list_credentials(&user.sub).await.len();
    let sessions = state.store.list_sessions(&user.sub).await;
    let csrf = auth::new_csrf_token();
    let body = render_account(&csrf, &user.sub, &user.email, count, &sessions, &session.id);
    html_with_cookies(StatusCode::OK, body, &[auth::csrf_cookie(&csrf)])
}

/// `POST /account/sessions/revoke` — CSRF-checked; end one *other* device's session.
/// The store scopes the delete to the signed-in user, so a forged id cannot touch
/// anyone else's session. Revoking the current session is a no-op here (use `/logout`).
pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> Response {
    let Some(session) = auth::current_session(&state, &headers).await else {
        return redirect("/login", &[]);
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/account", &[]);
    }
    if !form.session_id.is_empty() && form.session_id != session.id {
        state.store.revoke_session(&session.user_sub, &form.session_id).await;
        let actor = actor_email(&state, &session.user_sub).await;
        state.audit.emit(AuditEvent::info(
            "session.revoke",
            &actor,
            "session",
            "revoked one session",
        ));
    }
    redirect("/account", &[])
}

/// `POST /account/sessions/revoke-all` — CSRF-checked; "log out all other devices".
/// Keeps the current session alive and deletes every other session for this user.
pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LogoutForm>,
) -> Response {
    let Some(session) = auth::current_session(&state, &headers).await else {
        return redirect("/login", &[]);
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/account", &[]);
    }
    state.store.revoke_other_sessions(&session.user_sub, &session.id).await;
    let actor = actor_email(&state, &session.user_sub).await;
    state.audit.emit(AuditEvent::info(
        "session.revoke_all",
        &actor,
        "session",
        "logged out all other devices",
    ));
    redirect("/account", &[])
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

fn render_account(
    csrf: &str,
    sub: &str,
    email: &str,
    passkeys: usize,
    sessions: &[Session],
    current_id: &str,
) -> String {
    // Display name: the email local-part (the closest thing to a human name we hold).
    let name = email
        .split('@')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(email);
    let others = sessions.iter().filter(|s| s.id != current_id).count();
    ACCOUNT_HTML
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{SUB}}", &esc(sub))
        .replace("{{EMAIL}}", &esc(email))
        .replace("{{NAME}}", &esc(name))
        .replace("{{PASSKEYS}}", &passkeys.to_string())
        .replace("{{SESSION_COUNT}}", &sessions.len().to_string())
        .replace("{{OTHER_SESSIONS}}", &others.to_string())
        .replace("{{REVOKE_ALL}}", &render_revoke_all(csrf, others))
        .replace("{{SESSIONS}}", &render_sessions(csrf, sessions, current_id))
}

/// Render the session list as HTML rows. The current session is badged and cannot be
/// revoked from here (that is what `/logout` is for); every other session gets a
/// per-row "End session" button carrying its opaque id.
fn render_sessions(csrf: &str, sessions: &[Session], current_id: &str) -> String {
    if sessions.is_empty() {
        return r#"<p class="muted">No active sessions.</p>"#.to_string();
    }
    let now = crate::now_secs();
    let mut out = String::new();
    for s in sessions {
        let is_current = s.id == current_id;
        let device = if s.user_agent.is_empty() {
            "Unknown device".to_string()
        } else {
            device_label(&s.user_agent)
        };
        let ip = if s.ip.is_empty() { "unknown".to_string() } else { s.ip.clone() };
        let last = if s.last_seen == 0 {
            "—".to_string()
        } else {
            ago(now, s.last_seen)
        };
        let badge = if is_current {
            r#"<span class="badge">This device</span>"#
        } else {
            ""
        };
        let action = if is_current {
            String::new()
        } else {
            format!(
                r#"<form method="post" action="/account/sessions/revoke" class="session-row__action">
                     <input type="hidden" name="csrf_token" value="{csrf}">
                     <input type="hidden" name="session_id" value="{id}">
                     <button class="btn btn-ghost btn-sm" type="submit">End session</button>
                   </form>"#,
                csrf = esc(csrf),
                id = esc(&s.id),
            )
        };
        out.push_str(&format!(
            r#"<div class="session-row">
                 <div class="session-row__meta">
                   <div class="session-row__device">{device} {badge}</div>
                   <div class="muted session-row__sub">{ip} · signed in {created} · active {last}</div>
                 </div>
                 {action}
               </div>"#,
            device = esc(&device),
            badge = badge,
            ip = esc(&ip),
            created = esc(&ago(now, s.created_at)),
            last = esc(&last),
            action = action,
        ));
    }
    out
}

/// The "log out all other devices" control — only shown when there is at least one other session.
fn render_revoke_all(csrf: &str, others: usize) -> String {
    if others == 0 {
        return String::new();
    }
    format!(
        r#"<form method="post" action="/account/sessions/revoke-all" class="revoke-all">
             <input type="hidden" name="csrf_token" value="{csrf}">
             <button class="btn btn-secondary" type="submit">Log out all other devices ({others})</button>
           </form>"#,
        csrf = esc(csrf),
        others = others,
    )
}

/// Best-effort human device label from a `User-Agent` string (browser · OS heuristics).
fn device_label(ua: &str) -> String {
    let browser = if ua.contains("Edg") {
        "Edge"
    } else if ua.contains("Chrome") {
        "Chrome"
    } else if ua.contains("Firefox") {
        "Firefox"
    } else if ua.contains("Safari") {
        "Safari"
    } else {
        "Browser"
    };
    let os = if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Mac OS") || ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "device"
    };
    format!("{browser} · {os}")
}

/// Compact "time ago" rendering (seconds/minutes/hours/days) from `now` to `then`.
pub(crate) fn ago(now: u64, then: u64) -> String {
    let d = now.saturating_sub(then);
    if d < 60 {
        "just now".to_string()
    } else if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 86400 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86400)
    }
}

/// Best-effort email of a subject for audit actor labelling; falls back to the sub.
async fn actor_email(state: &AppState, sub: &str) -> String {
    state
        .store
        .get_user(sub)
        .await
        .map(|u| u.email)
        .unwrap_or_else(|| sub.to_string())
}

/// Extract the `User-Agent` header as an owned string (empty when absent/non-ASCII).
pub(crate) fn user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Only allow same-origin relative paths as a post-login redirect target (no open redirect).
fn sanitize_return_to(raw: Option<&str>) -> String {
    match raw {
        Some(r) if r.starts_with('/') && !r.starts_with("//") => r.to_string(),
        _ => "/account".to_string(),
    }
}

/// Minimal HTML escaping for text/attribute interpolation.
pub(crate) fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub(crate) fn redirect(target: &str, cookies: &[String]) -> Response {
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, target.to_string())]).into_response();
    attach_cookies(&mut resp, cookies);
    resp
}

pub(crate) fn html_with_cookies(status: StatusCode, body: String, cookies: &[String]) -> Response {
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
