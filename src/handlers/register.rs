//! Public self-service identity lifecycle: registration, email verification, password
//! reset, and authenticated change-password.
//!
//! `GET/POST /register`, `GET /verify`, `GET/POST /forgot`, `GET/POST /reset`, and
//! `POST /account/password`. Every state-changing POST is double-submit CSRF protected
//! (same `__Host-csrf` scheme as `/login`). Registration and password-reset are throttled
//! per client IP, and neither `/register` nor `/forgot` leaks whether an email exists —
//! both always render the same neutral "check your inbox" notice on the happy path.
//!
//! Verification/reset links point at `PUBLIC_ISSUER` (the browser-facing origin); emails are
//! sent through the non-blocking [`crate::email::EmailSink`] so a down mail hop never fails a
//! request. New subjects are `usr_<opaque>` so they never collide with the seeded `u_*` subs.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::handlers::login::{esc, html_with_cookies, redirect};
use crate::store::{new_opaque_code, CreateUserError, VerificationToken};
use crate::{now_secs, AppState};

const REGISTER_HTML: &str = include_str!("../../templates/register.html");
const FORGOT_HTML: &str = include_str!("../../templates/forgot.html");
const RESET_HTML: &str = include_str!("../../templates/reset.html");
const NOTICE_HTML: &str = include_str!("../../templates/notice.html");

/// Email-verification link lifetime (24h).
const VERIFY_TTL: u64 = 24 * 3600;
/// Password-reset link lifetime (1h). Shared with the admin console's forced reset.
pub(crate) const RESET_TTL: u64 = 3600;
/// Minimum acceptable password length for self-service accounts.
const MIN_PASSWORD_LEN: usize = 8;

#[derive(Debug, Deserialize)]
pub struct RegisterForm {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ForgotForm {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenQuery {
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResetForm {
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordForm {
    #[serde(default)]
    pub current_password: String,
    #[serde(default)]
    pub new_password: String,
    #[serde(default)]
    pub csrf_token: String,
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// `GET /register` — render the sign-up form (bounce to `/account` if already signed in).
pub async fn register_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if auth::current_session(&state, &headers).await.is_some() {
        return redirect("/account", &[]);
    }
    let csrf = auth::new_csrf_token();
    let body = render_register(&csrf, "", None);
    html_with_cookies(StatusCode::OK, body, &[auth::csrf_cookie(&csrf)])
}

/// `POST /register` — CSRF + throttle + validate, create the user (unverified), and email a
/// verification link. Always renders the same neutral notice on success OR a duplicate email
/// so registration never confirms whether an address is already taken.
pub async fn register_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return reject_register(&form.email, "Invalid or expired form token — please try again.");
    }
    if !state.rate_limiter.check(&client_ip(&headers)) {
        return reject_register(
            &form.email,
            "Too many attempts. Please wait a few minutes and try again.",
        );
    }

    let email = form.email.trim();
    if !valid_email(email) {
        return reject_register(&form.email, "Enter a valid email address.");
    }
    if form.password.len() < MIN_PASSWORD_LEN {
        return reject_register(
            &form.email,
            "Password must be at least 8 characters.",
        );
    }

    let hash = match auth::hash_password(&form.password) {
        Ok(h) => h,
        Err(_) => {
            return reject_register(&form.email, "Something went wrong. Please try again.");
        }
    };

    let sub = format!("usr_{}", new_opaque_code());
    match state
        .store
        .create_user(&sub, email, &hash, now_secs())
        .await
    {
        Ok(()) => {
            let token = new_opaque_code();
            state
                .store
                .put_verification_token(VerificationToken {
                    token: token.clone(),
                    sub: sub.clone(),
                    kind: "verify".to_string(),
                    expires_at: now_secs() + VERIFY_TTL,
                })
                .await;
            let link = format!("{}/verify?token={}", state.config.public_issuer, token);
            state.email.send(
                email,
                "Verify your Steadholme account",
                &verify_email_body(&link),
            );
            state.audit.emit(AuditEvent::info(
                "user.register",
                email,
                "self-service",
                "registration submitted; verification email sent",
            ));
        }
        Err(CreateUserError::EmailTaken) => {
            // Do NOT send mail and do NOT reveal the conflict — render the same notice as a
            // fresh signup so the response cannot be used to enumerate existing accounts.
            state.audit.emit(AuditEvent::warning(
                "user.register",
                email,
                "self-service",
                "duplicate email — suppressed (no enumeration)",
            ));
        }
        Err(CreateUserError::Backend) => {
            return reject_register(&form.email, "Something went wrong. Please try again.");
        }
    }

    notice(
        StatusCode::OK,
        "Check your inbox",
        "If that email can be registered, we've sent a verification link. Click it to activate your account, then sign in.",
        "/login",
        "Back to sign in",
    )
}

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------

/// `GET /verify?token=` — consume a verification token and mark the email verified.
pub async fn verify(State(state): State<AppState>, Query(q): Query<TokenQuery>) -> Response {
    let Some(token) = q.token.filter(|t| !t.is_empty()) else {
        return invalid_link_notice();
    };
    match state.store.take_verification_token(&token).await {
        Some((sub, kind)) if kind == "verify" => {
            state.store.set_email_verified(&sub).await;
            let actor = state
                .store
                .get_user(&sub)
                .await
                .map(|u| u.email)
                .unwrap_or(sub);
            state.audit.emit(AuditEvent::info(
                "user.verify",
                &actor,
                "self-service",
                "email verified",
            ));
            notice(
                StatusCode::OK,
                "Email verified",
                "Your email is confirmed. You can now sign in to Steadholme.",
                "/login",
                "Continue to sign in",
            )
        }
        _ => invalid_link_notice(),
    }
}

// ---------------------------------------------------------------------------
// Password reset (forgot -> reset)
// ---------------------------------------------------------------------------

/// `GET /forgot` — render the "email me a reset link" form.
pub async fn forgot_page() -> Response {
    let csrf = auth::new_csrf_token();
    let body = render_forgot(&csrf, None);
    html_with_cookies(StatusCode::OK, body, &[auth::csrf_cookie(&csrf)])
}

/// `POST /forgot` — always renders the same 200 notice (no user enumeration); when the email
/// belongs to a real account, a reset link is emailed as a side effect.
pub async fn forgot_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ForgotForm>,
) -> Response {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        let csrf = auth::new_csrf_token();
        let body = render_forgot(&csrf, Some("Invalid or expired form token — please try again."));
        return html_with_cookies(StatusCode::OK, body, &[auth::csrf_cookie(&csrf)]);
    }
    // Throttle regardless of whether the email exists (defends the same-response invariant).
    if state.rate_limiter.check(&client_ip(&headers)) {
        let email = form.email.trim();
        if valid_email(email) {
            if let Some(user) = state.store.get_user_by_username(email).await {
                // Only email the address that was submitted (which equals the account email),
                // never an internal identifier — and only when a real account matches.
                if user.email == email {
                    let token = new_opaque_code();
                    state
                        .store
                        .put_verification_token(VerificationToken {
                            token: token.clone(),
                            sub: user.sub.clone(),
                            kind: "reset".to_string(),
                            expires_at: now_secs() + RESET_TTL,
                        })
                        .await;
                    let link = format!("{}/reset?token={}", state.config.public_issuer, token);
                    state.email.send(
                        email,
                        "Reset your Steadholme password",
                        &reset_email_body(&link),
                    );
                    state.audit.emit(AuditEvent::info(
                        "password.forgot",
                        email,
                        "self-service",
                        "reset link emailed",
                    ));
                }
            }
        }
    }

    notice(
        StatusCode::OK,
        "Check your inbox",
        "If an account exists for that email, we've sent a password reset link. It expires in one hour.",
        "/login",
        "Back to sign in",
    )
}

/// `GET /reset?token=` — render the new-password form carrying the token (consumed on POST).
pub async fn reset_page(Query(q): Query<TokenQuery>) -> Response {
    let Some(token) = q.token.filter(|t| !t.is_empty()) else {
        return invalid_link_notice();
    };
    let csrf = auth::new_csrf_token();
    let body = render_reset(&csrf, &token, None);
    html_with_cookies(StatusCode::OK, body, &[auth::csrf_cookie(&csrf)])
}

/// `POST /reset` — CSRF + validate, consume the reset token, and set the new password.
pub async fn reset_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ResetForm>,
) -> Response {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return reject_reset(&form.token, "Invalid or expired form token — please try again.");
    }
    if form.password.len() < MIN_PASSWORD_LEN {
        return reject_reset(&form.token, "Password must be at least 8 characters.");
    }

    match state.store.take_verification_token(&form.token).await {
        Some((sub, kind)) if kind == "reset" => {
            let hash = match auth::hash_password(&form.password) {
                Ok(h) => h,
                Err(_) => return reject_reset(&form.token, "Something went wrong. Please try again."),
            };
            state.store.set_password_hash(&sub, &hash).await;
            // A completed reset proves control of the mailbox: verify the email too so a
            // never-verified account can recover through this path.
            state.store.set_email_verified(&sub).await;
            let actor = state
                .store
                .get_user(&sub)
                .await
                .map(|u| u.email)
                .unwrap_or(sub);
            state.audit.emit(AuditEvent::info(
                "password.reset",
                &actor,
                "self-service",
                "password reset via emailed link",
            ));
            notice(
                StatusCode::OK,
                "Password updated",
                "Your password has been reset. You can now sign in with your new password.",
                "/login",
                "Continue to sign in",
            )
        }
        _ => notice(
            StatusCode::OK,
            "Link expired",
            "This password reset link is invalid or has expired. Request a new one to continue.",
            "/forgot",
            "Request a new link",
        ),
    }
}

// ---------------------------------------------------------------------------
// Authenticated change-password
// ---------------------------------------------------------------------------

/// `POST /account/password` — session-required; verify the current password, then set a new one.
pub async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    let Some(session) = auth::current_session(&state, &headers).await else {
        return redirect("/login", &[]);
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return account_notice(
            "Couldn't update password",
            "Invalid or expired form token — please reload the account page and try again.",
        );
    }
    let Some(user) = state.store.get_user(&session.user_sub).await else {
        return redirect("/login", &[]);
    };

    let current_ok = user
        .password_hash
        .as_deref()
        .map(|h| auth::verify_password(&form.current_password, h))
        .unwrap_or(false);
    if !current_ok {
        state.audit.emit(AuditEvent::warning(
            "password.change",
            &user.email,
            "self-service",
            "current password incorrect",
        ));
        return account_notice(
            "Couldn't update password",
            "Your current password is incorrect. Please try again.",
        );
    }
    if form.new_password.len() < MIN_PASSWORD_LEN {
        return account_notice(
            "Couldn't update password",
            "Your new password must be at least 8 characters.",
        );
    }

    let hash = match auth::hash_password(&form.new_password) {
        Ok(h) => h,
        Err(_) => {
            return account_notice(
                "Couldn't update password",
                "Something went wrong. Please try again.",
            )
        }
    };
    state.store.set_password_hash(&user.sub, &hash).await;
    state.audit.emit(AuditEvent::info(
        "password.change",
        &user.email,
        "self-service",
        "password changed from account page",
    ));
    account_notice(
        "Password updated",
        "Your password has been changed. It will be required the next time you sign in.",
    )
}

// ---------------------------------------------------------------------------
// Rendering + helpers
// ---------------------------------------------------------------------------

fn reject_register(email: &str, msg: &str) -> Response {
    let csrf = auth::new_csrf_token();
    let body = render_register(&csrf, email, Some(msg));
    html_with_cookies(StatusCode::BAD_REQUEST, body, &[auth::csrf_cookie(&csrf)])
}

fn reject_reset(token: &str, msg: &str) -> Response {
    let csrf = auth::new_csrf_token();
    let body = render_reset(&csrf, token, Some(msg));
    html_with_cookies(StatusCode::BAD_REQUEST, body, &[auth::csrf_cookie(&csrf)])
}

fn render_register(csrf: &str, email: &str, error: Option<&str>) -> String {
    REGISTER_HTML
        .replace("{{ERROR}}", &error_html(error))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{EMAIL}}", &esc(email))
}

fn render_forgot(csrf: &str, error: Option<&str>) -> String {
    FORGOT_HTML
        .replace("{{ERROR}}", &error_html(error))
        .replace("{{CSRF}}", &esc(csrf))
}

fn render_reset(csrf: &str, token: &str, error: Option<&str>) -> String {
    RESET_HTML
        .replace("{{ERROR}}", &error_html(error))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{TOKEN}}", &esc(token))
}

fn error_html(error: Option<&str>) -> String {
    match error {
        Some(e) => format!(r#"<div class="alert">{}</div>"#, esc(e)),
        None => String::new(),
    }
}

/// Render the shared notice/confirmation page.
pub(crate) fn notice(
    status: StatusCode,
    title: &str,
    message: &str,
    link_href: &str,
    link_text: &str,
) -> Response {
    let body = NOTICE_HTML
        .replace("{{TITLE}}", &esc(title))
        .replace("{{MESSAGE}}", &esc(message))
        .replace("{{LINK_HREF}}", &esc(link_href))
        .replace("{{LINK_TEXT}}", &esc(link_text));
    // Clear any lingering CSRF cookie — these terminal pages carry no form.
    html_with_cookies(status, body, &[auth::clear_cookie(auth::CSRF_COOKIE)])
}

/// A notice that links back to the account console (used by change-password outcomes).
fn account_notice(title: &str, message: &str) -> Response {
    notice(StatusCode::OK, title, message, "/account", "Back to account")
}

fn invalid_link_notice() -> Response {
    notice(
        StatusCode::OK,
        "Invalid link",
        "This link is invalid or has already been used. Please request a new one.",
        "/login",
        "Back to sign in",
    )
}

fn verify_email_body(link: &str) -> String {
    format!(
        "Welcome to Steadholme.\n\nConfirm your email address to activate your account:\n\n{link}\n\n\
         This link expires in 24 hours. If you did not create this account, you can ignore this message."
    )
}

fn reset_email_body(link: &str) -> String {
    format!(
        "We received a request to reset your Steadholme password.\n\nReset it here:\n\n{link}\n\n\
         This link expires in 1 hour. If you did not request this, you can safely ignore this message."
    )
}

/// Best-effort email syntax check: a single `@`, non-empty local + domain, a dot in the
/// domain, no whitespace, and a sane length. Deliberately permissive — the emailed
/// verification link is the real proof of ownership.
fn valid_email(email: &str) -> bool {
    if email.is_empty() || email.len() > 254 || email.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
}

/// Derive a throttling key from the forwarded client IP (Keystone sits behind Sluice, which
/// sets `X-Forwarded-For`). Falls back to `X-Real-IP`, then a shared bucket when neither is
/// present — so the limiter still applies (globally) rather than silently disabling.
pub(crate) fn client_ip(headers: &HeaderMap) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    if let Some(xr) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = xr.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }
    "unknown".to_string()
}
