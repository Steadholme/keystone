//! Operator admin console: `GET /admin` + user-management actions.
//!
//! Gated on Keystone's OWN `__Host-session` cookie (Keystone is fronted as a public
//! route, so no gateway identity headers exist here) AND the user's `is_admin` flag —
//! a signed-in non-admin gets a 403. Every action is a double-submit-CSRF POST scoped
//! to an existing target user, and an admin can never disable their own account or
//! drop their own admin bit, so the console cannot lock the operator out.
//!
//! Actions: disable/enable a user, mint (and display) a password-reset link through the
//! existing single-use reset-token infra, revoke all of a user's sessions, and toggle the
//! admin bit. The OAuth clients table on the same page is read-only.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::handlers::login::{ago, esc, html_with_cookies, redirect};
use crate::handlers::register::{notice, RESET_TTL};
use crate::store::{new_opaque_code, Client, User, VerificationToken};
use crate::{now_secs, AppState};

const ADMIN_HTML: &str = include_str!("../../templates/admin.html");

#[derive(Debug, Deserialize)]
pub struct AdminQuery {
    #[serde(default)]
    pub q: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdminUserForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub sub: String,
}

/// Resolve the signed-in ADMIN user or produce the rejection response: no session ->
/// bounce to `/login` (returning here), unknown user -> tear the session down, and a
/// signed-in non-admin -> 403. Mirrors the `/account` gate, plus the `is_admin` check.
async fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<User, Response> {
    let Some(session) = auth::current_session(state, headers).await else {
        return Err(redirect("/login?return_to=%2Fadmin", &[]));
    };
    let Some(user) = state.store.get_user(&session.user_sub).await else {
        auth::destroy_session(state, headers).await;
        return Err(redirect("/login", &[auth::clear_cookie(auth::SESSION_COOKIE)]));
    };
    if !user.is_admin {
        return Err(notice(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "You do not have access to the admin console.",
            "/account",
            "Back to account",
        ));
    }
    Ok(user)
}

/// A rejected admin action (self-targeting or unknown user) — notice + back link.
fn admin_reject(message: &str) -> Response {
    notice(
        StatusCode::BAD_REQUEST,
        "Action rejected",
        message,
        "/admin",
        "Back to admin console",
    )
}

/// `GET /admin` — session + is_admin gated; renders the searchable user table and the
/// read-only OAuth clients table. `?q=` filters users by substring on sub OR email.
pub async fn admin_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AdminQuery>,
) -> Response {
    let admin = match require_admin(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let query = q.q.unwrap_or_default();
    let needle = query.trim().to_lowercase();
    let mut users = state.store.list_users().await;
    if !needle.is_empty() {
        users.retain(|u| {
            u.sub.to_lowercase().contains(&needle) || u.email.to_lowercase().contains(&needle)
        });
    }
    // Per-user active-session count (reuses the existing owner-scoped listing).
    let mut session_counts = Vec::with_capacity(users.len());
    for u in &users {
        session_counts.push(state.store.list_sessions(&u.sub).await.len());
    }
    let clients = state.store.list_clients().await;
    let csrf = auth::new_csrf_token();
    let body = render_admin(&csrf, &admin, &query, &users, &session_counts, &clients);
    html_with_cookies(StatusCode::OK, body, &[auth::csrf_cookie(&csrf)])
}

/// `POST /admin/users/disable` — CSRF-checked; block a user from logging in. An admin
/// cannot disable their own account (that would be a self-lockout foot-gun).
pub async fn disable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminUserForm>,
) -> Response {
    let admin = match require_admin(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/admin", &[]);
    }
    if form.sub == admin.sub {
        return admin_reject("You cannot disable your own account.");
    }
    let Some(target) = state.store.get_user(&form.sub).await else {
        return admin_reject("No such user.");
    };
    state.store.set_disabled(&target.sub, true).await;
    // Disabling must also terminate the account's live sessions — otherwise the disabled user keeps
    // access until each session's TTL lapses. Reuse the owner-scoped revoke (empty keep_id => all),
    // exactly as `revoke_user_sessions` does.
    state.store.revoke_other_sessions(&target.sub, "").await;
    state.audit.emit(AuditEvent::info(
        "admin.user.disable",
        &admin.email,
        &target.email,
        "account disabled by admin (sessions revoked)",
    ));
    redirect("/admin", &[])
}

/// `POST /admin/users/enable` — CSRF-checked; lift a user's disabled flag.
pub async fn enable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminUserForm>,
) -> Response {
    let admin = match require_admin(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/admin", &[]);
    }
    let Some(target) = state.store.get_user(&form.sub).await else {
        return admin_reject("No such user.");
    };
    state.store.set_disabled(&target.sub, false).await;
    state.audit.emit(AuditEvent::info(
        "admin.user.enable",
        &admin.email,
        &target.email,
        "account enabled by admin",
    ));
    redirect("/admin", &[])
}

/// `POST /admin/users/reset` — CSRF-checked; mint a single-use password-reset token via
/// the EXISTING reset-token infra and DISPLAY the link to the admin (no email required —
/// the operator hands it over out of band). The token itself is never audited or logged.
pub async fn force_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminUserForm>,
) -> Response {
    let admin = match require_admin(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/admin", &[]);
    }
    let Some(target) = state.store.get_user(&form.sub).await else {
        return admin_reject("No such user.");
    };
    let token = new_opaque_code();
    state
        .store
        .put_verification_token(VerificationToken {
            token: token.clone(),
            sub: target.sub.clone(),
            kind: "reset".to_string(),
            expires_at: now_secs() + RESET_TTL,
        })
        .await;
    let link = format!("{}/reset?token={}", state.config.public_issuer, token);
    state.audit.emit(AuditEvent::info(
        "admin.user.reset_link",
        &admin.email,
        &target.email,
        "password reset link minted by admin",
    ));
    notice(
        StatusCode::OK,
        "Reset link created",
        &format!(
            "Share this single-use link with {} — it expires in one hour: {link}",
            target.email
        ),
        "/admin",
        "Back to admin console",
    )
}

/// `POST /admin/users/revoke-sessions` — CSRF-checked; end every session of the target
/// user. Reuses the existing owner-scoped store method: an empty `keep_id` matches no
/// opaque session id, so all of the target's sessions are deleted.
pub async fn revoke_user_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminUserForm>,
) -> Response {
    let admin = match require_admin(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/admin", &[]);
    }
    let Some(target) = state.store.get_user(&form.sub).await else {
        return admin_reject("No such user.");
    };
    state.store.revoke_other_sessions(&target.sub, "").await;
    state.audit.emit(AuditEvent::info(
        "admin.user.revoke_sessions",
        &admin.email,
        &target.email,
        "all sessions revoked by admin",
    ));
    redirect("/admin", &[])
}

/// `POST /admin/users/toggle-admin` — CSRF-checked; flip the target's admin bit. An
/// admin cannot remove their OWN admin bit (the console must always keep one way in).
pub async fn toggle_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminUserForm>,
) -> Response {
    let admin = match require_admin(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return redirect("/admin", &[]);
    }
    if form.sub == admin.sub {
        return admin_reject("You cannot remove your own admin access.");
    }
    let Some(target) = state.store.get_user(&form.sub).await else {
        return admin_reject("No such user.");
    };
    let grant = !target.is_admin;
    state.store.set_is_admin(&target.sub, grant).await;
    state.audit.emit(AuditEvent::info(
        "admin.user.toggle_admin",
        &admin.email,
        &target.email,
        if grant { "admin granted" } else { "admin revoked" },
    ));
    redirect("/admin", &[])
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_admin(
    csrf: &str,
    admin: &User,
    query: &str,
    users: &[User],
    session_counts: &[usize],
    clients: &[Client],
) -> String {
    ADMIN_HTML
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{EMAIL}}", &esc(&admin.email))
        .replace("{{QUERY}}", &esc(query))
        .replace("{{USER_COUNT}}", &users.len().to_string())
        .replace(
            "{{USER_ROWS}}",
            &render_user_rows(csrf, &admin.sub, users, session_counts),
        )
        .replace("{{CLIENT_COUNT}}", &clients.len().to_string())
        .replace("{{CLIENT_ROWS}}", &render_client_rows(clients))
}

/// One `<form>` per admin action, carrying the CSRF token + target sub (POST-only).
fn action_form(action: &str, csrf: &str, sub: &str, label: &str) -> String {
    format!(
        r#"<form method="post" action="{action}">
             <input type="hidden" name="csrf_token" value="{csrf}">
             <input type="hidden" name="sub" value="{sub}">
             <button class="btn btn-ghost btn-sm" type="submit">{label}</button>
           </form>"#,
        action = action,
        csrf = esc(csrf),
        sub = esc(sub),
        label = esc(label),
    )
}

fn render_user_rows(
    csrf: &str,
    admin_sub: &str,
    users: &[User],
    session_counts: &[usize],
) -> String {
    if users.is_empty() {
        return r#"<tr><td colspan="8" class="muted">No users match.</td></tr>"#.to_string();
    }
    let now = now_secs();
    let mut out = String::new();
    for (u, sessions) in users.iter().zip(session_counts) {
        let is_self = u.sub == admin_sub;
        let you = if is_self {
            r#" <span class="pill">you</span>"#
        } else {
            ""
        };
        let verified = if u.email_verified {
            r#"<span class="pill pill--ok">verified</span>"#
        } else {
            r#"<span class="pill">unverified</span>"#
        };
        let status = if u.disabled {
            r#"<span class="pill pill--warn">disabled</span>"#
        } else {
            r#"<span class="pill pill--ok">active</span>"#
        };
        let role = if u.is_admin {
            r#"<span class="pill pill--ok">admin</span>"#
        } else {
            r#"<span class="muted">&mdash;</span>"#
        };
        let created = if u.created_at == 0 {
            "&mdash;".to_string()
        } else {
            esc(&ago(now, u.created_at))
        };
        // Self-protection is enforced server-side too; here we just don't render the
        // self-lockout buttons (disable / remove admin) on the admin's own row.
        let mut actions = String::new();
        if !is_self {
            if u.disabled {
                actions.push_str(&action_form("/admin/users/enable", csrf, &u.sub, "Enable"));
            } else {
                actions.push_str(&action_form("/admin/users/disable", csrf, &u.sub, "Disable"));
            }
        }
        actions.push_str(&action_form("/admin/users/reset", csrf, &u.sub, "Reset link"));
        actions.push_str(&action_form(
            "/admin/users/revoke-sessions",
            csrf,
            &u.sub,
            "Revoke sessions",
        ));
        if !is_self {
            let label = if u.is_admin { "Remove admin" } else { "Make admin" };
            actions.push_str(&action_form("/admin/users/toggle-admin", csrf, &u.sub, label));
        }
        out.push_str(&format!(
            r#"<tr>
                 <td><code>{sub}</code></td>
                 <td>{email}{you}</td>
                 <td>{verified}</td>
                 <td>{status}</td>
                 <td>{role}</td>
                 <td>{created}</td>
                 <td>{sessions}</td>
                 <td><div class="admin-actions">{actions}</div></td>
               </tr>"#,
            sub = esc(&u.sub),
            email = esc(&u.email),
            you = you,
            verified = verified,
            status = status,
            role = role,
            created = created,
            sessions = sessions,
            actions = actions,
        ));
    }
    out
}

fn render_client_rows(clients: &[Client]) -> String {
    if clients.is_empty() {
        return r#"<tr><td colspan="4" class="muted">No clients registered.</td></tr>"#.to_string();
    }
    let mut out = String::new();
    for c in clients {
        let first_party = if c.first_party {
            r#"<span class="pill pill--ok">yes</span>"#
        } else {
            r#"<span class="pill">no</span>"#
        };
        let uris = if c.redirect_uris.is_empty() {
            r#"<span class="muted">&mdash;</span>"#.to_string()
        } else {
            c.redirect_uris
                .iter()
                .map(|u| format!("<code>{}</code>", esc(u)))
                .collect::<Vec<_>>()
                .join("<br>")
        };
        out.push_str(&format!(
            r#"<tr>
                 <td><code>{id}</code></td>
                 <td>{name}</td>
                 <td>{first_party}</td>
                 <td>{uris}</td>
               </tr>"#,
            id = esc(&c.client_id),
            name = esc(&c.name),
            first_party = first_party,
            uris = uris,
        ));
    }
    out
}
