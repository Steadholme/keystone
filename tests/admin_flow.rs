//! Admin console integration tests (in-process, memory store, no DB).
//!
//! Proves:
//!   1. `/admin` is gated on Keystone's OWN session cookie AND `is_admin` (403 for a
//!      signed-in non-admin; redirect to `/login` with no session).
//!   2. Disable blocks `POST /login` with a 403 "disabled" page BEFORE the password is
//!      checked (right and wrong passwords behave identically); enable restores login.
//!   3. Self-protection: an admin can neither disable their own account nor remove
//!      their own admin bit.
//!   4. Forced reset mints a single-use link via the existing reset-token infra and the
//!      displayed link completes a real password reset.
//!   5. Revoke-sessions ends every session of the target user.
//!   6. Toggle-admin grants `/admin` access; CSRF-less admin POSTs are no-ops.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use keystone::AppState;
use tower::ServiceExt;

const ADMIN_PASSWORD: &str = "hunter2bravo";
const USER_PASSWORD: &str = "correct-horse-battery";

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = keystone::app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, bytes)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn get_with_cookie(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

/// First `name=value` from any `Set-Cookie` response header.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::SET_COOKIE).iter() {
        let raw = hv.to_str().ok()?;
        let first = raw.split(';').next()?.trim();
        if let Some((k, v)) = first.split_once('=') {
            if k == name {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn location(headers: &HeaderMap) -> String {
    headers
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap()
        .to_string()
}

/// Dev state + admin password, plus one verified non-admin user (`u_member`).
async fn setup() -> AppState {
    let state = keystone::build_dev_state();
    let hash = keystone::auth::hash_password(ADMIN_PASSWORD).unwrap();
    state.store.set_password_hash("u_admin", &hash).await;
    let hash = keystone::auth::hash_password(USER_PASSWORD).unwrap();
    state
        .store
        .create_user("u_member", "member@steadholme.local", &hash, keystone::now_secs())
        .await
        .unwrap();
    state.store.set_email_verified("u_member").await;
    state
}

/// A signed session cookie header value for `sub`.
async fn session_cookie(state: &AppState, sub: &str) -> String {
    let signed = keystone::auth::create_session(state, sub, "test-agent", "127.0.0.1").await;
    format!("__Host-session={signed}")
}

/// Full password login; returns `(status, headers, body)` of the `POST /login`.
async fn login(state: &AppState, username: &str, password: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    let (_, headers, _) = call(state, get("/login")).await;
    let csrf = cookie_value(&headers, "__Host-csrf").expect("csrf cookie issued");
    let body =
        format!("username={username}&password={password}&csrf_token={csrf}&return_to=%2Faccount");
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={csrf}"))
        .body(Body::from(body))
        .unwrap();
    call(state, req).await
}

/// Perform one admin action POST: fresh CSRF from `GET /admin`, then the form POST.
async fn admin_action(
    state: &AppState,
    admin_cookie: &str,
    action: &str,
    sub: &str,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let (status, headers, _) = call(state, get_with_cookie("/admin", admin_cookie)).await;
    assert_eq!(status, StatusCode::OK, "admin page renders before action");
    let csrf = cookie_value(&headers, "__Host-csrf").expect("csrf issued by /admin");
    let req = Request::builder()
        .method("POST")
        .uri(action)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("{admin_cookie}; __Host-csrf={csrf}"))
        .body(Body::from(format!("csrf_token={csrf}&sub={sub}")))
        .unwrap();
    call(state, req).await
}

#[tokio::test]
async fn admin_page_is_session_and_admin_gated() {
    let state = setup().await;

    // No session -> bounce to /login, returning to /admin after sign-in.
    let (status, headers, _) = call(&state, get("/admin")).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?return_to=%2Fadmin");

    // A signed-in NON-admin -> 403 (not a redirect: the page exists, access is denied).
    let member = session_cookie(&state, "u_member").await;
    let (status, _, body) = call(&state, get_with_cookie("/admin", &member)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("Forbidden"));

    // The seeded operator is admin out of the box -> full console with both tables.
    let admin = session_cookie(&state, "u_admin").await;
    let (status, _, body) = call(&state, get_with_cookie("/admin", &admin)).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("u_admin"), "user table lists the admin");
    assert!(html.contains("member@steadholme.local"), "user table lists members");
    assert!(html.contains("sluice-dev"), "clients table lists the seeded client");
    assert!(
        html.contains("http://127.0.0.1:9090/callback"),
        "clients table shows redirect URIs"
    );
}

#[tokio::test]
async fn admin_search_filters_users() {
    let state = setup().await;
    let admin = session_cookie(&state, "u_admin").await;

    let (status, _, body) = call(&state, get_with_cookie("/admin?q=member", &admin)).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("member@steadholme.local"), "match shown");
    assert!(
        !html.contains("<code>u_admin</code>"),
        "non-matching user filtered out of the table"
    );

    // The query round-trips into the search box (escaped).
    let (_, _, body) = call(&state, get_with_cookie("/admin?q=%22quoted%22", &admin)).await;
    assert!(String::from_utf8_lossy(&body).contains("&quot;quoted&quot;"));
}

#[tokio::test]
async fn disable_blocks_login_before_password_and_enable_restores() {
    let state = setup().await;
    let admin = session_cookie(&state, "u_admin").await;

    // Sanity: the member can log in.
    let (status, _, _) = login(&state, "member@steadholme.local", USER_PASSWORD).await;
    assert_eq!(status, StatusCode::FOUND, "member logs in before disable");

    // Admin disables the member.
    let (status, headers, _) =
        admin_action(&state, &admin, "/admin/users/disable", "u_member").await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/admin");

    // Disabled: 403 + clear message, and NO session — with the RIGHT password...
    let (status, headers, body) = login(&state, "member@steadholme.local", USER_PASSWORD).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "disabled account is 403");
    assert!(String::from_utf8_lossy(&body).contains("disabled"));
    assert!(cookie_value(&headers, "__Host-session").is_none());
    // ...and identically with a WRONG password (the gate runs before the password check,
    // so the response cannot leak whether the password was correct).
    let (status, _, body) = login(&state, "member@steadholme.local", "totally-wrong").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "same outcome regardless of password");
    assert!(String::from_utf8_lossy(&body).contains("disabled"));

    // Enable restores login.
    let (status, _, _) = admin_action(&state, &admin, "/admin/users/enable", "u_member").await;
    assert_eq!(status, StatusCode::FOUND);
    let (status, _, _) = login(&state, "member@steadholme.local", USER_PASSWORD).await;
    assert_eq!(status, StatusCode::FOUND, "member logs in again after enable");
}

#[tokio::test]
async fn admin_cannot_disable_self_or_drop_own_admin_bit() {
    let state = setup().await;
    let admin = session_cookie(&state, "u_admin").await;

    let (status, _, body) = admin_action(&state, &admin, "/admin/users/disable", "u_admin").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "self-disable rejected");
    assert!(String::from_utf8_lossy(&body).contains("cannot disable your own account"));
    let me = state.store.get_user("u_admin").await.unwrap();
    assert!(!me.disabled, "admin account stays enabled");

    let (status, _, body) =
        admin_action(&state, &admin, "/admin/users/toggle-admin", "u_admin").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "self-demote rejected");
    assert!(String::from_utf8_lossy(&body).contains("cannot remove your own admin access"));
    let me = state.store.get_user("u_admin").await.unwrap();
    assert!(me.is_admin, "admin bit survives");
}

#[tokio::test]
async fn forced_reset_link_completes_a_real_password_reset() {
    let state = setup().await;
    let admin = session_cookie(&state, "u_admin").await;

    // Admin mints a reset link for the member; the link is DISPLAYED (no email needed).
    let (status, _, body) = admin_action(&state, &admin, "/admin/users/reset", "u_member").await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body).to_string();
    let marker = "/reset?token=";
    let start = html.find(marker).expect("reset link displayed to the admin") + marker.len();
    let token: String = html[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    assert!(!token.is_empty(), "opaque token embedded in the link");

    // The displayed link drives the EXISTING reset flow end-to-end.
    let (status, headers, _) = call(&state, get(&format!("/reset?token={token}"))).await;
    assert_eq!(status, StatusCode::OK);
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/reset")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={csrf}"))
        .body(Body::from(format!(
            "token={token}&password=fresh-password-1&csrf_token={csrf}"
        )))
        .unwrap();
    let (status, _, body) = call(&state, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("Password updated"));

    // Old password out, new password in.
    let (status, _, _) = login(&state, "member@steadholme.local", USER_PASSWORD).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "old password rejected");
    let (status, _, _) = login(&state, "member@steadholme.local", "fresh-password-1").await;
    assert_eq!(status, StatusCode::FOUND, "new password accepted");
}

#[tokio::test]
async fn revoke_sessions_ends_all_target_sessions() {
    let state = setup().await;
    let admin = session_cookie(&state, "u_admin").await;

    // Two member "devices", both live.
    let member_a = session_cookie(&state, "u_member").await;
    let member_b = session_cookie(&state, "u_member").await;
    let (status, _, _) = call(&state, get_with_cookie("/account", &member_a)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, _) =
        admin_action(&state, &admin, "/admin/users/revoke-sessions", "u_member").await;
    assert_eq!(status, StatusCode::FOUND);

    // Both member sessions are gone; the admin's own session is untouched.
    let (status, _, _) = call(&state, get_with_cookie("/account", &member_a)).await;
    assert_eq!(status, StatusCode::FOUND, "member session A revoked");
    let (status, _, _) = call(&state, get_with_cookie("/account", &member_b)).await;
    assert_eq!(status, StatusCode::FOUND, "member session B revoked");
    let (status, _, _) = call(&state, get_with_cookie("/admin", &admin)).await;
    assert_eq!(status, StatusCode::OK, "admin session survives");
}

#[tokio::test]
async fn disable_revokes_existing_sessions() {
    // A6: disabling an account must terminate its LIVE sessions, not merely block new logins —
    // otherwise the disabled user keeps access until each session's TTL lapses.
    let state = setup().await;
    let admin = session_cookie(&state, "u_admin").await;
    let member = session_cookie(&state, "u_member").await;

    // The member has a live session before being disabled.
    let (status, _, _) = call(&state, get_with_cookie("/account", &member)).await;
    assert_eq!(status, StatusCode::OK, "member session live before disable");

    let (status, _, _) = admin_action(&state, &admin, "/admin/users/disable", "u_member").await;
    assert_eq!(status, StatusCode::FOUND);

    // Disable revoked the existing session: the once-valid cookie no longer reaches /account.
    let (status, _, _) = call(&state, get_with_cookie("/account", &member)).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "member session revoked immediately on disable"
    );
}

#[tokio::test]
async fn toggle_admin_grants_console_access() {
    let state = setup().await;
    let admin = session_cookie(&state, "u_admin").await;
    let member = session_cookie(&state, "u_member").await;

    // Before: the member is locked out of /admin.
    let (status, _, _) = call(&state, get_with_cookie("/admin", &member)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _, _) =
        admin_action(&state, &admin, "/admin/users/toggle-admin", "u_member").await;
    assert_eq!(status, StatusCode::FOUND);

    // After: the member reaches the console; toggling again revokes it.
    let (status, _, _) = call(&state, get_with_cookie("/admin", &member)).await;
    assert_eq!(status, StatusCode::OK, "granted admin reaches the console");
    let (status, _, _) =
        admin_action(&state, &admin, "/admin/users/toggle-admin", "u_member").await;
    assert_eq!(status, StatusCode::FOUND);
    let (status, _, _) = call(&state, get_with_cookie("/admin", &member)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "revoked admin is locked out again");
}

#[tokio::test]
async fn admin_post_without_csrf_is_a_noop() {
    let state = setup().await;
    let admin = session_cookie(&state, "u_admin").await;

    // Session cookie present but NO csrf cookie/token: redirected, nothing changes.
    let req = Request::builder()
        .method("POST")
        .uri("/admin/users/disable")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, admin.clone())
        .body(Body::from("csrf_token=forged&sub=u_member"))
        .unwrap();
    let (status, headers, _) = call(&state, req).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/admin");
    let member = state.store.get_user("u_member").await.unwrap();
    assert!(!member.disabled, "CSRF-less POST must not mutate state");

    // And a non-admin CANNOT drive any action even with a valid CSRF pair.
    let member_cookie = session_cookie(&state, "u_member").await;
    let (_, headers, _) = call(&state, get_with_cookie("/login", &member_cookie)).await;
    // /login redirects when signed in and sets no csrf; mint one via /forgot instead.
    let _ = headers;
    let (_, headers, _) = call(&state, get("/forgot")).await;
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/admin/users/disable")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::COOKIE,
            format!("{member_cookie}; __Host-csrf={csrf}"),
        )
        .body(Body::from(format!("csrf_token={csrf}&sub=u_admin")))
        .unwrap();
    let (status, _, _) = call(&state, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-admin POST is 403");
    let target = state.store.get_user("u_admin").await.unwrap();
    assert!(!target.disabled, "non-admin cannot disable anyone");
}
