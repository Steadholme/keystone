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
    let session = keystone::auth::create_session(&state, "u_admin").await;
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
        "username=admin@holdfast.local&password={PASSWORD}&csrf_token={csrf}&return_to=%2Faccount"
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
    assert_eq!(ui["email"], "admin@holdfast.local");
}

#[tokio::test]
async fn login_with_wrong_password_is_rejected_no_session() {
    let state = keystone::build_dev_state();
    let hash = keystone::auth::hash_password(PASSWORD).unwrap();
    state.store.set_password_hash("u_admin", &hash).await;

    let (_, headers, _) = call(&state, get("/login")).await;
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let body = format!(
        "username=admin@holdfast.local&password=wrongpass&csrf_token={csrf}&return_to=%2Faccount"
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
async fn login_without_csrf_is_rejected() {
    let state = keystone::build_dev_state();
    let hash = keystone::auth::hash_password(PASSWORD).unwrap();
    state.store.set_password_hash("u_admin", &hash).await;

    // Submit a CSRF token in the form but DO NOT send the matching cookie.
    let body = format!(
        "username=admin@holdfast.local&password={PASSWORD}&csrf_token=forged&return_to=%2Faccount"
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
