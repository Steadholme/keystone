//! Session-gating + password-login integration tests (in-process, memory store, no DB).
//!
//! Proves:
//!   1. `/authorize` with no session 302s to `/login?return_to=…`; with a session it
//!      302s back to the redirect_uri with a code (the gate replaced auto-approve).
//!   2. A full password login (`POST /login`) creates a session that then drives the
//!      OIDC chain: authorize -> token -> userinfo.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use keystone::AppState;
use serde_json::Value;
use tower::ServiceExt;

const CLIENT_ID: &str = "sluice-dev";
const REDIRECT_URI: &str = "http://127.0.0.1:9090/callback";
// RFC 7636 Appendix B test vector.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const PASSWORD: &str = "hunter2bravo";

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

fn post_form(uri: &str, cookie: Option<&str>, body: String) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::from(body)).unwrap()
}

fn body_str(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

fn hidden_value(html: &str, name: &str) -> String {
    let marker = format!(r#"name="{name}" value=""#);
    let start = html.find(&marker).expect("hidden field present") + marker.len();
    html[start..].chars().take_while(|c| *c != '"').collect()
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

fn authorize_uri() -> String {
    format!(
        "/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}\
         &scope=openid+email+profile&state=xyz123&code_challenge={CHALLENGE}\
         &code_challenge_method=S256&nonce=n-abc"
    )
}

fn code_from(location: &str) -> String {
    let query = location.split_once('?').expect("redirect has query").1;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == "code" {
                return v.to_string();
            }
        }
    }
    panic!("no code in {location}");
}

fn token_request(code: &str) -> Request<Body> {
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI}\
         &client_id={CLIENT_ID}&code_verifier={VERIFIER}"
    );
    Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn root_redirects_to_account() {
    let state = keystone::build_dev_state();
    // Bare root is a convenience entry point: 302 -> /account (which itself
    // bounces to /login when there is no session).
    let (status, headers, _) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/account");
}

#[tokio::test]
async fn authorize_without_session_redirects_to_login() {
    let state = keystone::build_dev_state();

    // No session -> bounce to /login carrying the original /authorize as return_to.
    let (status, headers, _) = call(&state, get(&authorize_uri())).await;
    assert_eq!(status, StatusCode::FOUND);
    let loc = location(&headers);
    assert!(loc.starts_with("/login?return_to="), "got {loc}");
    assert!(
        loc.contains("%2Fauthorize"),
        "return_to is the encoded authorize URL: {loc}"
    );

    // With a session -> 302 straight back to the redirect_uri with a code.
    let session =
        keystone::auth::create_session(&state, "u_admin", "test-agent", "127.0.0.1").await;
    let (status, headers, _) = call(
        &state,
        get_with_cookie(&authorize_uri(), &format!("__Host-session={session}")),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let loc = location(&headers);
    assert!(loc.starts_with(REDIRECT_URI), "got {loc}");
    assert!(!code_from(&loc).is_empty());
}

#[tokio::test]
async fn factor_epoch_change_requires_reauthentication_before_authorize() {
    let state = keystone::build_dev_state();
    let session = keystone::auth::try_create_session(&state, "u_admin", "test-agent", "127.0.0.1")
        .await
        .expect("active user session");
    let session_id = keystone::auth::verify_signed(&state.config.session_secret, &session)
        .expect("signed session id");
    let session_cookie = format!("__Host-session={session}");
    let mut session_headers = HeaderMap::new();
    session_headers.insert(header::COOKIE, session_cookie.parse().unwrap());

    assert!(
        keystone::auth::current_session(&state, &session_headers)
            .await
            .is_some(),
        "session is current before the factor generation changes"
    );
    state
        .store
        .bump_factor_epoch("u_admin")
        .await
        .expect("factor epoch bump");

    assert!(
        keystone::auth::current_session(&state, &session_headers)
            .await
            .is_some(),
        "factor enrollment may continue on the base account session"
    );
    assert!(
        state.store.get_session(&session_id).await.is_some(),
        "base session remains until it reaches the OIDC authority gate"
    );

    let (status, headers, _) =
        call(&state, get_with_cookie(&authorize_uri(), &session_cookie)).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location(&headers).starts_with("/login?return_to="),
        "stale session must not mint an authorization code"
    );
    assert!(
        state.store.get_session(&session_id).await.is_none(),
        "the OIDC authority gate deletes the stale session"
    );

    let current_session =
        keystone::auth::try_create_session(&state, "u_admin", "fresh-agent", "127.0.0.1")
            .await
            .expect("current factor generation session");
    let (status, headers, _) = call(
        &state,
        get_with_cookie(
            &authorize_uri(),
            &format!("__Host-session={current_session}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let location = location(&headers);
    assert!(location.starts_with(REDIRECT_URI), "got {location}");
    assert!(!code_from(&location).is_empty());
}

#[tokio::test]
async fn password_login_creates_session_then_oidc_flow() {
    let state = keystone::build_dev_state();
    // Seed the admin password (mirrors the BOOTSTRAP_ADMIN_PASSWORD startup path).
    let hash = keystone::auth::hash_password(PASSWORD).unwrap();
    state.store.set_password_hash("u_admin", &hash).await;

    // 1. GET /login -> obtain a CSRF cookie/token.
    let (status, headers, _) = call(&state, get("/login")).await;
    assert_eq!(status, StatusCode::OK);
    let csrf = cookie_value(&headers, "__Host-csrf").expect("csrf cookie issued");

    // 2. POST /login (double-submit CSRF) -> 302 + session cookie.
    let body = format!(
        "username=admin@steadholme.local&password={PASSWORD}&csrf_token={csrf}&return_to=%2Faccount"
    );
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={csrf}"))
        .body(Body::from(body))
        .unwrap();
    let (status, headers, _) = call(&state, req).await;
    assert_eq!(status, StatusCode::FOUND, "successful login redirects");
    assert_eq!(location(&headers), "/account");
    let session = cookie_value(&headers, "__Host-session").expect("session cookie set");
    let session_cookie = format!("__Host-session={session}");

    // 3. /account is now reachable with the session.
    let (status, _, body) = call(&state, get_with_cookie("/account", &session_cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("u_admin"));

    // 4. /authorize with the session -> code.
    let (status, headers, _) =
        call(&state, get_with_cookie(&authorize_uri(), &session_cookie)).await;
    assert_eq!(status, StatusCode::FOUND);
    let code = code_from(&location(&headers));

    // 5. /token -> access_token.
    let (status, _, body) = call(&state, token_request(&code)).await;
    assert_eq!(status, StatusCode::OK);
    let tok: Value = serde_json::from_slice(&body).unwrap();
    let access_token = tok["access_token"].as_str().unwrap().to_string();

    // 6. /userinfo -> {sub, email}.
    let req = Request::builder()
        .uri("/userinfo")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = call(&state, req).await;
    assert_eq!(status, StatusCode::OK);
    let ui: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ui["sub"], "u_admin");
    assert_eq!(ui["email"], "admin@steadholme.local");
}

#[tokio::test]
async fn login_with_wrong_password_is_rejected_no_session() {
    let state = keystone::build_dev_state();
    let hash = keystone::auth::hash_password(PASSWORD).unwrap();
    state.store.set_password_hash("u_admin", &hash).await;

    let (_, headers, _) = call(&state, get("/login")).await;
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let body = format!(
        "username=admin@steadholme.local&password=wrongpass&csrf_token={csrf}&return_to=%2Faccount"
    );
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={csrf}"))
        .body(Body::from(body))
        .unwrap();
    let (status, headers, _) = call(&state, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "bad password is 401");
    assert!(
        cookie_value(&headers, "__Host-session").is_none(),
        "no session granted"
    );
}

#[tokio::test]
async fn account_lists_sessions_and_revoke_all_keeps_current() {
    let state = keystone::build_dev_state();

    // Two independent sessions for the same user (two "devices").
    let sess_a = keystone::auth::create_session(
        &state,
        "u_admin",
        "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
        "203.0.113.1",
    )
    .await;
    let sess_b = keystone::auth::create_session(
        &state,
        "u_admin",
        "Mozilla/5.0 (iPhone) Safari/17",
        "203.0.113.2",
    )
    .await;
    let cookie_a = format!("__Host-session={sess_a}");
    let cookie_b = format!("__Host-session={sess_b}");

    // /account from device A lists BOTH sessions and badges the current one.
    let (status, headers, body) = call(&state, get_with_cookie("/account", &cookie_a)).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("Chrome · Windows"),
        "device A labelled: {html:.0}"
    );
    assert!(html.contains("Safari · iOS"), "device B labelled");
    assert!(html.contains("This device"), "current session badged");
    assert!(html.contains("2 active"), "session count shown");

    // A fresh CSRF cookie/token was issued by the account render — reuse it to POST.
    let csrf = cookie_value(&headers, "__Host-csrf").expect("csrf issued");

    // "Log out all other devices" from A: keeps A, drops B.
    let req = Request::builder()
        .method("POST")
        .uri("/account/sessions/revoke-all")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("{cookie_a}; __Host-csrf={csrf}"))
        .body(Body::from(format!("csrf_token={csrf}")))
        .unwrap();
    let (status, headers, _) = call(&state, req).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/account");

    // A still works; B is gone (its /account now bounces to /login).
    let (status, _, _) = call(&state, get_with_cookie("/account", &cookie_a)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "current session survives revoke-all"
    );
    let (status, headers, _) = call(&state, get_with_cookie("/account", &cookie_b)).await;
    assert_eq!(status, StatusCode::FOUND, "other session was revoked");
    assert_eq!(location(&headers), "/login");
}

#[tokio::test]
async fn revoke_one_session_by_id_is_owner_scoped() {
    let state = keystone::build_dev_state();
    let sess_a =
        keystone::auth::create_session(&state, "u_admin", "Chrome/120", "203.0.113.1").await;
    let sess_b =
        keystone::auth::create_session(&state, "u_admin", "Safari/17", "203.0.113.2").await;
    let cookie_a = format!("__Host-session={sess_a}");

    // Discover B's opaque id from A's account listing (it is embedded in the revoke form).
    let (_, headers, _) = call(&state, get_with_cookie("/account", &cookie_a)).await;
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    // B's raw id: the signed cookie is `id.mac`; the store id is the part before the dot.
    let b_id = sess_b.split('.').next().unwrap().to_string();

    let req = Request::builder()
        .method("POST")
        .uri("/account/sessions/revoke")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("{cookie_a}; __Host-csrf={csrf}"))
        .body(Body::from(format!("csrf_token={csrf}&session_id={b_id}")))
        .unwrap();
    let (status, _, _) = call(&state, req).await;
    assert_eq!(status, StatusCode::FOUND);

    // B is gone; A survives.
    let cookie_b = format!("__Host-session={sess_b}");
    let (status, _, _) = call(&state, get_with_cookie("/account", &cookie_b)).await;
    assert_eq!(status, StatusCode::FOUND, "targeted session revoked");
    let (status, _, _) = call(&state, get_with_cookie("/account", &cookie_a)).await;
    assert_eq!(status, StatusCode::OK, "actor session untouched");
}

#[tokio::test]
async fn login_without_csrf_is_rejected() {
    let state = keystone::build_dev_state();
    let hash = keystone::auth::hash_password(PASSWORD).unwrap();
    state.store.set_password_hash("u_admin", &hash).await;

    // Submit a CSRF token in the form but DO NOT send the matching cookie.
    let body = format!(
        "username=admin@steadholme.local&password={PASSWORD}&csrf_token=forged&return_to=%2Faccount"
    );
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let (status, headers, _) = call(&state, req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "missing CSRF cookie is rejected"
    );
    assert!(cookie_value(&headers, "__Host-session").is_none());
}

#[tokio::test]
async fn totp_enrollment_requires_second_factor_after_password() {
    let state = keystone::build_dev_state();
    let hash = keystone::auth::hash_password(PASSWORD).unwrap();
    state.store.set_password_hash("u_admin", &hash).await;
    let signed =
        keystone::auth::create_session(&state, "u_admin", "Mozilla/5.0 Chrome/120", "203.0.113.9")
            .await;
    let session_cookie = format!("__Host-session={signed}");

    // Start enrollment from the authenticated account page.
    let (_, headers, _) = call(&state, get_with_cookie("/account", &session_cookie)).await;
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let (status, headers, body) = call(
        &state,
        post_form(
            "/account/mfa/totp/enroll",
            Some(&format!("{session_cookie}; __Host-csrf={csrf}")),
            format!("csrf_token={csrf}&current_password={PASSWORD}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body_str(&body).contains("Manual key"));
    let pending = state.store.get_totp("u_admin").await.expect("totp pending");
    assert!(!pending.enabled, "enrollment starts pending");

    // Verify the current TOTP code and receive one-time recovery codes.
    let code = keystone::totp::code_at(&pending.secret, keystone::now_secs()).unwrap();
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let (status, _, body) = call(
        &state,
        post_form(
            "/account/mfa/totp/verify",
            Some(&format!("{session_cookie}; __Host-csrf={csrf}")),
            format!("csrf_token={csrf}&code={code}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body_str(&body).contains("Recovery codes"));
    let enabled = state.store.get_totp("u_admin").await.unwrap();
    assert!(enabled.enabled, "totp enabled after first verified code");
    assert!(
        enabled.last_accepted_counter.is_some(),
        "enrollment counter is persisted as the replay floor"
    );
    assert_eq!(state.store.recovery_code_count("u_admin").await, 10);

    // Password alone no longer creates a session; it renders the TOTP challenge.
    let (_, headers, _) = call(&state, get("/login")).await;
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let (status, headers, body) = call(
        &state,
        post_form(
            "/login",
            Some(&format!("__Host-csrf={csrf}")),
            format!(
                "username=admin@steadholme.local&password={PASSWORD}&csrf_token={csrf}&return_to=%2Faccount"
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "TOTP challenge is rendered");
    assert!(
        cookie_value(&headers, "__Host-session").is_none(),
        "password step alone grants no session"
    );
    let html = body_str(&body);
    assert!(html.contains("Two-step verification"));
    // Ordinary two-step login (no strong ACR) may be completed with a recovery code, so the
    // copy offers that path.
    assert!(html.contains("or a recovery code"));
    assert!(html.contains("recovery codes"));
    let challenge_id = hidden_value(&html, "challenge_id");

    // The TOTP code completes login and yields the normal session cookie.
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    // Use the next counter, which is inside the accepted +1 skew window but has not been
    // consumed by enrollment. This avoids sleeping while still exercising monotonic advance.
    let code = keystone::totp::code_at(&enabled.secret, keystone::now_secs() + 30).unwrap();
    let (status, headers, _) = call(
        &state,
        post_form(
            "/login/totp",
            Some(&format!("__Host-csrf={csrf}")),
            format!("csrf_token={csrf}&challenge_id={challenge_id}&code={code}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/account");
    let session = cookie_value(&headers, "__Host-session").expect("session after TOTP");

    let strong_authorize = format!("{}&acr_values=hf-aal-strong", authorize_uri());
    let (status, headers, _) = call(
        &state,
        get_with_cookie(&strong_authorize, &format!("__Host-session={session}")),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location(&headers).contains("code="));

    let (status, _, body) = call(
        &state,
        get_with_cookie("/account", &format!("__Host-session={session}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let html = body_str(&body);
    assert!(html.contains("Authenticator app"));
    assert!(html.contains("Login history"));
    assert!(html.contains("totp"));
    assert!(html.contains("success"));

    // A fresh password challenge cannot reuse the exact TOTP counter that just minted the
    // strong session, even though it remains inside the accepted ±1 time window.
    let (_, headers, _) = call(&state, get("/login")).await;
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let (status, headers, body) = call(
        &state,
        post_form(
            "/login",
            Some(&format!("__Host-csrf={csrf}")),
            format!(
                "username=admin@steadholme.local&password={PASSWORD}&csrf_token={csrf}&return_to=%2Faccount"
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let challenge_id = hidden_value(&body_str(&body), "challenge_id");
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let (status, headers, body) = call(
        &state,
        post_form(
            "/login/totp",
            Some(&format!("__Host-csrf={csrf}")),
            format!("csrf_token={csrf}&challenge_id={challenge_id}&code={code}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(cookie_value(&headers, "__Host-session").is_none());
    assert!(body_str(&body).contains("Incorrect verification code"));
}

#[tokio::test]
async fn personal_tokens_are_hashed_shown_once_and_revocable() {
    let state = keystone::build_dev_state();
    let hash = keystone::auth::hash_password(PASSWORD).unwrap();
    state.store.set_password_hash("u_admin", &hash).await;
    let signed = keystone::auth::create_session(&state, "u_admin", "test-agent", "127.0.0.1").await;
    let session_cookie = format!("__Host-session={signed}");

    let (_, headers, _) = call(&state, get_with_cookie("/account", &session_cookie)).await;
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let (status, _, body) = call(
        &state,
        post_form(
            "/account/tokens/create",
            Some(&format!("{session_cookie}; __Host-csrf={csrf}")),
            format!(
                "csrf_token={csrf}&name=deploy&scopes=profile+admin:read&expiry_days=30&current_password={PASSWORD}"
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let html = body_str(&body);
    let token_start = html.find("pat_").expect("plaintext token shown once");
    let plaintext: String = html[token_start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect();
    assert!(plaintext.starts_with("pat_"));

    let tokens = state.store.list_personal_tokens("u_admin").await;
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].name, "deploy");
    assert_ne!(tokens[0].token_hash, plaintext, "store keeps only a hash");

    let (status, headers, body) = call(&state, get_with_cookie("/account", &session_cookie)).await;
    assert_eq!(status, StatusCode::OK);
    let account_html = body_str(&body);
    assert!(account_html.contains("deploy"));
    assert!(
        !account_html.contains(&plaintext),
        "plaintext token is not rendered by account page"
    );

    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let (status, _, _) = call(
        &state,
        post_form(
            "/account/tokens/revoke",
            Some(&format!("{session_cookie}; __Host-csrf={csrf}")),
            format!("csrf_token={csrf}&token_id={}", tokens[0].id),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(state.store.list_personal_tokens("u_admin").await.is_empty());
}

#[tokio::test]
async fn login_history_records_password_failures() {
    let state = keystone::build_dev_state();
    let hash = keystone::auth::hash_password(PASSWORD).unwrap();
    state.store.set_password_hash("u_admin", &hash).await;

    let (_, headers, _) = call(&state, get("/login")).await;
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let (status, _, _) = call(
        &state,
        post_form(
            "/login",
            Some(&format!("__Host-csrf={csrf}")),
            format!(
                "username=admin@steadholme.local&password=wrong&csrf_token={csrf}&return_to=%2Faccount"
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let events = state.store.list_login_events("u_admin", 10).await;
    assert!(events.iter().any(|e| e.result == "failure"));

    let signed = keystone::auth::create_session(&state, "u_admin", "test-agent", "127.0.0.1").await;
    let (status, _, body) = call(
        &state,
        get_with_cookie("/account", &format!("__Host-session={signed}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body_str(&body).contains("Failed"));
}
