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
use crate::handlers::register::{client_ip, notice};
use crate::store::{
    new_opaque_code, LoginEvent, PersonalAccessToken, Session, TotpChallenge, TotpConfig, User,
};
use crate::{now_secs, totp, AppState};

const LOGIN_HTML: &str = include_str!("../../templates/login.html");
const ACCOUNT_HTML: &str = include_str!("../../templates/account.html");
const TOTP_LOGIN_HTML: &str = include_str!("../../templates/totp_login.html");
const TOTP_ENROLL_HTML: &str = include_str!("../../templates/totp_enroll.html");
const RECOVERY_CODES_HTML: &str = include_str!("../../templates/recovery_codes.html");
const TOKEN_CREATED_HTML: &str = include_str!("../../templates/token_created.html");

const TOTP_CHALLENGE_TTL: u64 = 5 * 60;
const RECOVERY_CODE_COUNT: usize = 10;

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

#[derive(Debug, Deserialize)]
pub struct TotpLoginForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub challenge_id: String,
    #[serde(default)]
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpEnrollForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub current_password: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpVerifyForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct PatCreateForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub current_password: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub scopes: String,
    #[serde(default)]
    pub expiry_days: String,
}

#[derive(Debug, Deserialize)]
pub struct PatRevokeForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub token_id: String,
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
    if let Some(disabled_user) = user.as_ref().filter(|u| u.disabled) {
        record_login_event(
            &state,
            &disabled_user.sub,
            &form.username,
            "password",
            "failure",
            "account disabled",
            &headers,
        )
        .await;
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
        if let Some(u) = user.as_ref() {
            record_login_event(
                &state,
                &u.sub,
                &form.username,
                "password",
                "failure",
                "invalid credentials",
                &headers,
            )
            .await;
        }
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
        record_login_event(
            &state,
            &user.sub,
            &form.username,
            "password",
            "failure",
            "email not verified",
            &headers,
        )
        .await;
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

    let ua = user_agent(&headers);
    let ip = client_ip(&headers);
    if state
        .store
        .get_totp(&user.sub)
        .await
        .is_some_and(|m| m.enabled)
    {
        let challenge_id = new_opaque_code();
        state
            .store
            .put_totp_challenge(TotpChallenge {
                id: challenge_id.clone(),
                user_sub: user.sub.clone(),
                return_to: return_to.clone(),
                user_agent: ua,
                ip,
                expires_at: now_secs() + TOTP_CHALLENGE_TTL,
            })
            .await;
        record_login_event(
            &state,
            &user.sub,
            &form.username,
            "password",
            "challenge",
            "totp required",
            &headers,
        )
        .await;
        state.audit.emit(AuditEvent::info(
            "login.totp_required",
            &user.email,
            "totp",
            "password accepted; second factor required",
        ));
        let csrf = auth::new_csrf_token();
        let body = render_totp_login(&csrf, &challenge_id, &return_to, None);
        return html_with_cookies(StatusCode::OK, body, &[auth::csrf_cookie(&csrf)]);
    }

    let cookie = auth::create_session(&state, &user.sub, &ua, &ip).await;
    record_login_event(
        &state,
        &user.sub,
        &form.username,
        "password",
        "success",
        "password login",
        &headers,
    )
    .await;
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
    let (session, user) = match require_session_user(&state, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let count = state.store.list_credentials(&user.sub).await.len();
    let sessions = state.store.list_sessions(&user.sub).await;
    let totp = state.store.get_totp(&user.sub).await;
    let recovery_count = if totp.as_ref().is_some_and(|m| m.enabled) {
        state.store.recovery_code_count(&user.sub).await
    } else {
        0
    };
    let login_events = state.store.list_login_events(&user.sub, 10).await;
    let tokens = state.store.list_personal_tokens(&user.sub).await;
    let csrf = auth::new_csrf_token();
    let body = render_account(
        &csrf,
        &user.sub,
        &user.email,
        count,
        &sessions,
        &session.id,
        totp.as_ref(),
        recovery_count,
        &login_events,
        &tokens,
    );
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
        state
            .store
            .revoke_session(&session.user_sub, &form.session_id)
            .await;
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
    state
        .store
        .revoke_other_sessions(&session.user_sub, &session.id)
        .await;
    let actor = actor_email(&state, &session.user_sub).await;
    state.audit.emit(AuditEvent::info(
        "session.revoke_all",
        &actor,
        "session",
        "logged out all other devices",
    ));
    redirect("/account", &[])
}

/// `POST /login/totp` — complete a password-accepted TOTP challenge and mint the session.
pub async fn totp_login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TotpLoginForm>,
) -> Response {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return reject_login(
            "/account",
            "",
            "Invalid or expired form token — please try again.",
        );
    }
    let Some(challenge) = state.store.take_totp_challenge(&form.challenge_id).await else {
        return reject_login(
            "/account",
            "",
            "The verification challenge expired. Sign in again.",
        );
    };
    let Some(user) = state.store.get_user(&challenge.user_sub).await else {
        return reject_login(
            "/account",
            "",
            "The verification challenge expired. Sign in again.",
        );
    };
    let Some(mfa) = state.store.get_totp(&user.sub).await.filter(|m| m.enabled) else {
        return reject_login("/account", "", "Two-step verification is not enabled.");
    };

    let (ok, method, detail) = if totp::verify_code(&mfa.secret, &form.code, now_secs()) {
        (true, "totp", "totp login")
    } else if state
        .store
        .take_recovery_code(
            &user.sub,
            &auth::secret_hash(&normalize_recovery_code(&form.code)),
        )
        .await
    {
        (true, "recovery", "recovery code login")
    } else {
        (false, "totp", "invalid second factor")
    };

    if !ok {
        record_login_event(
            &state,
            &user.sub,
            &user.email,
            method,
            "failure",
            detail,
            &headers,
        )
        .await;
        state.audit.emit(AuditEvent::warning(
            "login.totp_failure",
            &user.email,
            "totp",
            "invalid second factor",
        ));
        return reject_login(
            &challenge.return_to,
            &user.email,
            "Incorrect verification code. Please sign in again.",
        );
    }

    let cookie =
        auth::create_session(&state, &user.sub, &challenge.user_agent, &challenge.ip).await;
    record_login_event(
        &state,
        &user.sub,
        &user.email,
        method,
        "success",
        detail,
        &headers,
    )
    .await;
    state.audit.emit(AuditEvent::info(
        "login.success",
        &user.email,
        method,
        detail,
    ));
    redirect(
        &challenge.return_to,
        &[
            auth::session_cookie(&cookie, state.config.session_ttl),
            auth::clear_cookie(auth::CSRF_COOKIE),
        ],
    )
}

/// `POST /account/mfa/totp/enroll` — verify current password and show QR/manual secret.
pub async fn totp_enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TotpEnrollForm>,
) -> Response {
    let (_session, user) = match require_session_user(&state, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/account", &[]);
    }
    if !verify_current_password(&user, &form.current_password) {
        return notice(
            StatusCode::BAD_REQUEST,
            "Two-step setup rejected",
            "Your current password is incorrect.",
            "/account",
            "Back to account",
        );
    }

    let secret = totp::new_secret();
    state
        .store
        .put_totp(TotpConfig {
            user_sub: user.sub.clone(),
            secret: secret.clone(),
            enabled: false,
            created_at: now_secs(),
            verified_at: 0,
        })
        .await;
    state.audit.emit(AuditEvent::info(
        "mfa.totp.enroll_start",
        &user.email,
        "totp",
        "totp enrollment started",
    ));
    let csrf = auth::new_csrf_token();
    let body = render_totp_enroll(&csrf, &user.email, &secret, None);
    html_with_cookies(StatusCode::OK, body, &[auth::csrf_cookie(&csrf)])
}

/// `POST /account/mfa/totp/verify` — verify the first code and show recovery codes once.
pub async fn totp_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TotpVerifyForm>,
) -> Response {
    let (_session, user) = match require_session_user(&state, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/account", &[]);
    }
    let Some(mut cfg) = state.store.get_totp(&user.sub).await else {
        return redirect("/account", &[]);
    };
    if !totp::verify_code(&cfg.secret, &form.code, now_secs()) {
        let csrf = auth::new_csrf_token();
        let body = render_totp_enroll(
            &csrf,
            &user.email,
            &cfg.secret,
            Some("The verification code did not match. Try the current code from your app."),
        );
        return html_with_cookies(StatusCode::BAD_REQUEST, body, &[auth::csrf_cookie(&csrf)]);
    }

    cfg.enabled = true;
    cfg.verified_at = now_secs();
    state.store.put_totp(cfg).await;
    let codes: Vec<String> = (0..RECOVERY_CODE_COUNT)
        .map(|_| totp::new_recovery_code())
        .collect();
    let hashes: Vec<String> = codes
        .iter()
        .map(|c| auth::secret_hash(&normalize_recovery_code(c)))
        .collect();
    state
        .store
        .put_recovery_codes(&user.sub, hashes, now_secs())
        .await;
    state.audit.emit(AuditEvent::info(
        "mfa.totp.enabled",
        &user.email,
        "totp",
        "totp enabled",
    ));
    let body = render_recovery_codes(&user.email, &codes);
    html_with_cookies(
        StatusCode::OK,
        body,
        &[auth::clear_cookie(auth::CSRF_COOKIE)],
    )
}

/// `POST /account/mfa/totp/disable` — verify current password and remove TOTP.
pub async fn totp_disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TotpEnrollForm>,
) -> Response {
    let (_session, user) = match require_session_user(&state, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/account", &[]);
    }
    if !verify_current_password(&user, &form.current_password) {
        return notice(
            StatusCode::BAD_REQUEST,
            "Two-step disable rejected",
            "Your current password is incorrect.",
            "/account",
            "Back to account",
        );
    }
    state.store.delete_totp(&user.sub).await;
    state.audit.emit(AuditEvent::info(
        "mfa.totp.disabled",
        &user.email,
        "totp",
        "totp disabled",
    ));
    redirect("/account", &[])
}

/// `POST /account/tokens/create` — create a hashed PAT and show plaintext once.
pub async fn pat_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PatCreateForm>,
) -> Response {
    let (_session, user) = match require_session_user(&state, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/account", &[]);
    }
    if !verify_current_password(&user, &form.current_password) {
        return notice(
            StatusCode::BAD_REQUEST,
            "Token rejected",
            "Your current password is incorrect.",
            "/account",
            "Back to account",
        );
    }
    let Some(name) = clean_token_name(&form.name) else {
        return notice(
            StatusCode::BAD_REQUEST,
            "Token rejected",
            "Enter a token name between 1 and 80 characters.",
            "/account",
            "Back to account",
        );
    };
    let Some(scopes) = clean_scopes(&form.scopes) else {
        return notice(
            StatusCode::BAD_REQUEST,
            "Token rejected",
            "Scopes may contain letters, numbers, colon, dot, underscore, and dash.",
            "/account",
            "Back to account",
        );
    };
    let Some(days) = parse_expiry_days(&form.expiry_days) else {
        return notice(
            StatusCode::BAD_REQUEST,
            "Token rejected",
            "Expiry must be between 1 and 365 days.",
            "/account",
            "Back to account",
        );
    };

    let plaintext = format!("pat_{}", new_opaque_code());
    let token = PersonalAccessToken {
        id: format!("pat_{}", new_opaque_code()),
        user_sub: user.sub.clone(),
        name: name.clone(),
        token_hash: auth::secret_hash(&plaintext),
        scopes: scopes.clone(),
        created_at: now_secs(),
        expires_at: now_secs() + days * 86400,
        revoked_at: 0,
    };
    if state.store.put_personal_token(token).await.is_err() {
        return notice(
            StatusCode::SERVICE_UNAVAILABLE,
            "Token unavailable",
            "We couldn't create this token. No credential was issued; please try again.",
            "/account",
            "Back to account",
        );
    }
    state.audit.emit(AuditEvent::info(
        "pat.create",
        &user.email,
        &name,
        "personal access token created",
    ));
    let body = render_token_created(&user.email, &name, &scopes, days, &plaintext);
    html_with_cookies(
        StatusCode::OK,
        body,
        &[auth::clear_cookie(auth::CSRF_COOKIE)],
    )
}

/// `POST /account/tokens/revoke` — revoke one PAT owned by the current user.
pub async fn pat_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PatRevokeForm>,
) -> Response {
    let (_session, user) = match require_session_user(&state, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/account", &[]);
    }
    if !form.token_id.is_empty() {
        if state
            .store
            .revoke_personal_token(&user.sub, &form.token_id, now_secs())
            .await
            .is_err()
        {
            return notice(
                StatusCode::SERVICE_UNAVAILABLE,
                "Token revocation unavailable",
                "We couldn't confirm this revocation. The token may still be active; please try again.",
                "/account",
                "Back to account",
            );
        }
        state.audit.emit(AuditEvent::info(
            "pat.revoke",
            &user.email,
            "personal-access-token",
            "personal access token revoked",
        ));
    }
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
        state.audit.emit(AuditEvent::info(
            "session.logout",
            &actor,
            "session",
            "logged out",
        ));
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
    totp: Option<&TotpConfig>,
    recovery_count: usize,
    login_events: &[LoginEvent],
    tokens: &[PersonalAccessToken],
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
        .replace("{{TOTP_STATUS}}", &render_totp_status(totp, recovery_count))
        .replace("{{TOTP_CONTROLS}}", &render_totp_controls(csrf, totp))
        .replace("{{LOGIN_EVENTS}}", &render_login_events(login_events))
        .replace("{{TOKENS}}", &render_tokens(csrf, tokens))
        .replace("{{REVOKE_ALL}}", &render_revoke_all(csrf, others))
        .replace("{{SESSIONS}}", &render_sessions(csrf, sessions, current_id))
}

fn render_totp_login(
    csrf: &str,
    challenge_id: &str,
    return_to: &str,
    error: Option<&str>,
) -> String {
    TOTP_LOGIN_HTML
        .replace("{{ERROR}}", &error_html(error))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{CHALLENGE_ID}}", &esc(challenge_id))
        .replace("{{RETURN_TO}}", &esc(return_to))
}

fn render_totp_enroll(csrf: &str, email: &str, secret: &str, error: Option<&str>) -> String {
    let uri = totp::otpauth_uri("Steadholme", email, secret);
    let qr = totp::qr_svg(&uri).unwrap_or_else(|| {
        format!(
            r#"<div class="qr-fallback"><code>{}</code></div>"#,
            esc(&uri)
        )
    });
    TOTP_ENROLL_HTML
        .replace("{{ERROR}}", &error_html(error))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{EMAIL}}", &esc(email))
        .replace("{{SECRET}}", &esc(secret))
        .replace("{{OTPAUTH}}", &esc(&uri))
        .replace("{{QR}}", &qr)
}

fn render_recovery_codes(email: &str, codes: &[String]) -> String {
    let rows = codes
        .iter()
        .map(|c| format!(r#"<code>{}</code>"#, esc(c)))
        .collect::<Vec<_>>()
        .join("");
    RECOVERY_CODES_HTML
        .replace("{{EMAIL}}", &esc(email))
        .replace("{{CODES}}", &rows)
}

fn render_token_created(
    email: &str,
    name: &str,
    scopes: &str,
    days: u64,
    plaintext: &str,
) -> String {
    TOKEN_CREATED_HTML
        .replace("{{EMAIL}}", &esc(email))
        .replace("{{NAME}}", &esc(name))
        .replace("{{SCOPES}}", &esc(scopes))
        .replace("{{DAYS}}", &days.to_string())
        .replace("{{TOKEN}}", &esc(plaintext))
}

fn error_html(error: Option<&str>) -> String {
    match error {
        Some(e) => format!(r#"<div class="alert">{}</div>"#, esc(e)),
        None => String::new(),
    }
}

fn render_totp_status(totp: Option<&TotpConfig>, recovery_count: usize) -> String {
    match totp {
        Some(m) if m.enabled => format!(
            r#"<span class="badge">Authenticator app</span>
               <span class="muted">{} recovery code(s) unused.</span>"#,
            recovery_count
        ),
        Some(_) => r#"<span class="pill">Setup pending</span>"#.to_string(),
        None => r#"<span class="pill">Not enabled</span>"#.to_string(),
    }
}

fn render_totp_controls(csrf: &str, totp: Option<&TotpConfig>) -> String {
    match totp {
        Some(m) if m.enabled => format!(
            r#"<form class="inline-secure-form" method="post" action="/account/mfa/totp/disable">
                 <input type="hidden" name="csrf_token" value="{csrf}">
                 <input name="current_password" type="password" autocomplete="current-password"
                        placeholder="Current password" required>
                 <button class="btn btn-ghost btn-sm" type="submit">Disable TOTP</button>
               </form>"#,
            csrf = esc(csrf),
        ),
        Some(_) => format!(
            r#"<form class="inline-secure-form" method="post" action="/account/mfa/totp/verify">
                 <input type="hidden" name="csrf_token" value="{csrf}">
                 <input name="code" type="text" inputmode="numeric" autocomplete="one-time-code"
                        placeholder="123456" required>
                 <button class="btn btn-secondary btn-sm" type="submit">Verify setup</button>
               </form>"#,
            csrf = esc(csrf),
        ),
        None => format!(
            r#"<form class="inline-secure-form" method="post" action="/account/mfa/totp/enroll">
                 <input type="hidden" name="csrf_token" value="{csrf}">
                 <input name="current_password" type="password" autocomplete="current-password"
                        placeholder="Current password" required>
                 <button class="btn btn-secondary btn-sm" type="submit">Enable TOTP</button>
               </form>"#,
            csrf = esc(csrf),
        ),
    }
}

fn render_login_events(events: &[LoginEvent]) -> String {
    if events.is_empty() {
        return r#"<p class="muted">No login history yet.</p>"#.to_string();
    }
    let now = now_secs();
    let mut out = String::new();
    for (idx, e) in events.iter().enumerate() {
        let device = if e.user_agent.is_empty() {
            "Unknown device".to_string()
        } else {
            device_label(&e.user_agent)
        };
        let ip = if e.ip.is_empty() { "unknown" } else { &e.ip };
        let flag = login_event_flag(events, idx);
        out.push_str(&format!(
            r#"<div class="history-row">
                 <div>
                   <div class="history-row__main">{method} · {result} {flag}</div>
                   <div class="muted history-row__sub">{ip} · {device} · {when} · {detail}</div>
                 </div>
               </div>"#,
            method = esc(&e.method),
            result = esc(&e.result),
            flag = flag,
            ip = esc(ip),
            device = esc(&device),
            when = esc(&ago(now, e.occurred_at)),
            detail = esc(&e.detail),
        ));
    }
    out
}

fn login_event_flag(events: &[LoginEvent], idx: usize) -> String {
    let e = &events[idx];
    if e.result == "failure" {
        return r#"<span class="pill pill--warn">Failed</span>"#.to_string();
    }
    if e.result == "challenge" {
        return r#"<span class="pill">MFA required</span>"#.to_string();
    }
    if e.result == "success" && !e.ip.is_empty() && e.ip != "unknown" {
        let older_success_same_ip = events[idx + 1..]
            .iter()
            .any(|old| old.result == "success" && old.ip == e.ip);
        let older_success_other_ip = events[idx + 1..]
            .iter()
            .any(|old| old.result == "success" && old.ip != e.ip);
        if !older_success_same_ip && older_success_other_ip {
            return r#"<span class="pill pill--warn">New IP</span>"#.to_string();
        }
    }
    String::new()
}

fn render_tokens(csrf: &str, tokens: &[PersonalAccessToken]) -> String {
    if tokens.is_empty() {
        return r#"<p class="muted">No personal access tokens.</p>"#.to_string();
    }
    let now = now_secs();
    let mut out = String::new();
    for t in tokens {
        let badge = if now > t.expires_at {
            r#"<span class="pill pill--warn">Expired</span>"#
        } else {
            r#"<span class="pill pill--ok">Active</span>"#
        };
        out.push_str(&format!(
            r#"<div class="token-row">
                 <div>
                   <div class="token-row__main">{name} {badge}</div>
                   <div class="muted token-row__sub">{scopes} · created {created} · expires in {expires}</div>
                 </div>
                 <form method="post" action="/account/tokens/revoke" class="token-row__action">
                   <input type="hidden" name="csrf_token" value="{csrf}">
                   <input type="hidden" name="token_id" value="{id}">
                   <button class="btn btn-ghost btn-sm" type="submit">Revoke</button>
                 </form>
               </div>"#,
            name = esc(&t.name),
            badge = badge,
            scopes = esc(&t.scopes),
            created = esc(&ago(now, t.created_at)),
            expires = esc(&ago(t.expires_at, now)),
            csrf = esc(csrf),
            id = esc(&t.id),
        ));
    }
    out
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
        let ip = if s.ip.is_empty() {
            "unknown".to_string()
        } else {
            s.ip.clone()
        };
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

async fn require_session_user(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(Session, User), Response> {
    let Some(session) = auth::current_session(state, headers).await else {
        return Err(redirect("/login", &[]));
    };
    let Some(user) = state.store.get_user(&session.user_sub).await else {
        auth::destroy_session(state, headers).await;
        return Err(redirect(
            "/login",
            &[auth::clear_cookie(auth::SESSION_COOKIE)],
        ));
    };
    Ok((session, user))
}

fn verify_current_password(user: &User, password: &str) -> bool {
    user.password_hash
        .as_deref()
        .map(|h| auth::verify_password(password, h))
        .unwrap_or(false)
}

pub(crate) async fn record_login_event(
    state: &AppState,
    user_sub: &str,
    username: &str,
    method: &str,
    result: &str,
    detail: &str,
    headers: &HeaderMap,
) {
    state
        .store
        .put_login_event(LoginEvent {
            id: new_opaque_code(),
            user_sub: user_sub.to_string(),
            username: username.to_string(),
            occurred_at: now_secs(),
            ip: client_ip(headers),
            user_agent: user_agent(headers),
            method: method.to_string(),
            result: result.to_string(),
            detail: detail.to_string(),
        })
        .await;
}

fn normalize_recovery_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase()
}

fn clean_token_name(raw: &str) -> Option<String> {
    let name = raw.trim();
    (!name.is_empty() && name.len() <= 80).then_some(name.to_string())
}

fn clean_scopes(raw: &str) -> Option<String> {
    let scopes: Vec<String> = raw
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if scopes.is_empty() || scopes.len() > 10 {
        return None;
    }
    let valid = scopes.iter().all(|s| {
        s.len() <= 64
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-'))
    });
    valid.then(|| scopes.join(" "))
}

fn parse_expiry_days(raw: &str) -> Option<u64> {
    let days = raw.trim().parse::<u64>().ok()?;
    (1..=365).contains(&days).then_some(days)
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;
    use crate::config;
    use crate::store::{InMemoryStore, Store};

    const TEST_PASSWORD: &str = "handler-failure-password";

    async fn state_with_faultable_store() -> (AppState, Arc<InMemoryStore>, String) {
        let mut state = crate::build_dev_state();
        let store = Arc::new(InMemoryStore::new());
        store.seed_client(config::seed_client());
        store.put_user(config::seed_user());
        store
            .set_password_hash(
                config::SEED_USER_SUB,
                &auth::hash_password(TEST_PASSWORD).expect("hash test password"),
            )
            .await;
        state.store = store.clone();
        let session = auth::create_session(
            &state,
            config::SEED_USER_SUB,
            "pat-failure-test",
            "127.0.0.1",
        )
        .await;
        (state, store, session)
    }

    async fn post_account_form(
        state: &AppState,
        session: &str,
        path: &str,
        body: String,
    ) -> Response {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                header::COOKIE,
                format!("__Host-session={session}; __Host-csrf=test-csrf"),
            )
            .body(Body::from(body))
            .expect("build PAT handler request");
        crate::app(state.clone())
            .oneshot(request)
            .await
            .expect("call PAT handler")
    }

    async fn response_body(response: Response) -> String {
        String::from_utf8_lossy(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("read PAT handler response"),
        )
        .into_owned()
    }

    #[tokio::test]
    async fn pat_create_store_failure_is_503_without_plaintext() {
        let (state, store, session) = state_with_faultable_store().await;
        store.set_personal_token_write_failures(true, false);

        let response = post_account_form(
            &state,
            &session,
            "/account/tokens/create",
            format!(
                "csrf_token=test-csrf&name=deploy&scopes=corvid%3Atemp-mail%3Adelete&expiry_days=30&current_password={TEST_PASSWORD}"
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response_body(response).await;
        assert!(body.contains("No credential was issued"));
        assert!(
            !body.contains("pat_"),
            "failed creation must not reveal a PAT"
        );
        assert!(store
            .list_personal_tokens(config::SEED_USER_SUB)
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn pat_revoke_store_failure_is_503_and_token_stays_active() {
        let (state, store, session) = state_with_faultable_store().await;
        let plaintext = "pat_handler_failure_fixture";
        let token = PersonalAccessToken {
            id: "pat_record_for_revoke_failure".to_string(),
            user_sub: config::SEED_USER_SUB.to_string(),
            name: "revoke failure".to_string(),
            token_hash: auth::secret_hash(plaintext),
            scopes: "corvid:temp-mail:delete".to_string(),
            created_at: now_secs(),
            expires_at: now_secs() + 300,
            revoked_at: 0,
        };
        store
            .put_personal_token(token.clone())
            .await
            .expect("store revocation fixture");
        store.set_personal_token_write_failures(false, true);

        let response = post_account_form(
            &state,
            &session,
            "/account/tokens/revoke",
            format!("csrf_token=test-csrf&token_id={}", token.id),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response_body(response).await;
        assert!(body.contains("may still be active"));
        assert!(!body.contains(plaintext));
        assert!(!body.contains(&token.id));
        assert!(!body.contains(&token.token_hash));

        let persisted = store
            .find_active_personal_token(&token.token_hash, now_secs())
            .await
            .expect("authoritative lookup after failed revocation")
            .expect("token remains active after failed revocation");
        assert_eq!(persisted.id, token.id);
    }
}
