//! Public self-service identity lifecycle integration tests (in-process, memory store, no DB).
//!
//! Proves the two headline flows and their guards:
//!   1. register -> (email-verify gate blocks login) -> verify -> login succeeds.
//!   2. forgot (always a neutral 200) -> reset consumes the token -> new password works.
//!   3. authenticated change-password verifies the current password before rotating.
//!
//! The emitted verification/reset *link* is exercised by the email unit tests; here the token
//! is planted directly through the `Store` seam and then driven through the real `/verify` and
//! `/reset` handlers — the same `take_verification_token` + `set_*` path a mailed token takes.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use keystone::store::VerificationToken;
use keystone::{now_secs, AppState};
use tower::ServiceExt;

const EMAIL: &str = "newcomer@steadholme.local";
const PASSWORD: &str = "correct horse staple";
const NEW_PASSWORD: &str = "an even longer secret";

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

fn body_str(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

/// Fetch a CSRF token by GETting a form page (register/forgot), returning `(csrf, cookie_header)`.
async fn csrf_from(state: &AppState, uri: &str) -> (String, String) {
    let (_, headers, _) = call(state, get(uri)).await;
    let csrf = cookie_value(&headers, "__Host-csrf").expect("csrf cookie issued");
    let cookie = format!("__Host-csrf={csrf}");
    (csrf, cookie)
}

#[tokio::test]
async fn register_verify_login_flow() {
    let state = keystone::build_dev_state();

    // 1. Register a brand-new account.
    let (csrf, cookie) = csrf_from(&state, "/register").await;
    let (status, _, body) = call(
        &state,
        post_form(
            "/register",
            Some(&cookie),
            format!("email={EMAIL}&password={PASSWORD}&csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "registration renders a 200 notice");
    assert!(body_str(&body).contains("Check your inbox"));

    // The user now exists, unverified, with a real created_at.
    let user = state
        .store
        .get_user_by_username(EMAIL)
        .await
        .expect("registered user present");
    assert!(!user.email_verified, "new user starts unverified");
    assert!(
        user.created_at > 0,
        "self-service user carries a created_at"
    );
    assert!(
        user.sub.starts_with("usr_"),
        "opaque sub, no collision with u_*"
    );

    // 2. Login is BLOCKED until the email is verified.
    let (csrf, cookie) = csrf_from(&state, "/login").await;
    let (status, headers, body) = call(
        &state,
        post_form(
            "/login",
            Some(&cookie),
            format!("username={EMAIL}&password={PASSWORD}&csrf_token={csrf}&return_to=%2Faccount"),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unverified login is rejected"
    );
    assert!(
        cookie_value(&headers, "__Host-session").is_none(),
        "no session granted"
    );
    assert!(body_str(&body).to_lowercase().contains("verify your email"));

    // 3. Plant + consume a verification token through the real /verify handler.
    let token = "verify-token-abc";
    state
        .store
        .put_verification_token(VerificationToken {
            token: token.to_string(),
            sub: user.sub.clone(),
            kind: "verify".to_string(),
            expires_at: now_secs() + 3600,
        })
        .await
        .expect("persist expired verification token");
    let (status, _, body) = call(&state, get(&format!("/verify?token={token}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body_str(&body).contains("Email verified"));
    assert!(
        state
            .store
            .get_user(&user.sub)
            .await
            .unwrap()
            .email_verified,
        "verify flipped the flag"
    );
    // Single-use: the token is gone.
    assert!(state
        .store
        .take_verification_token(token)
        .await
        .expect("inspect consumed verification token")
        .is_none());

    // 4. Login now succeeds and yields a session.
    let (csrf, cookie) = csrf_from(&state, "/login").await;
    let (status, headers, _) = call(
        &state,
        post_form(
            "/login",
            Some(&cookie),
            format!("username={EMAIL}&password={PASSWORD}&csrf_token={csrf}&return_to=%2Faccount"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "verified login redirects");
    assert!(
        cookie_value(&headers, "__Host-session").is_some(),
        "session issued after verification"
    );
}

#[tokio::test]
async fn forgot_is_neutral_and_reset_rotates_password() {
    let state = keystone::build_dev_state();
    // Seed a verified user with a known password (create_user starts unverified, so verify it).
    let hash = keystone::auth::hash_password(PASSWORD).unwrap();
    state
        .store
        .create_user("usr_reset", EMAIL, &hash, now_secs())
        .await
        .expect("create user");
    state
        .store
        .set_email_verified("usr_reset")
        .await
        .expect("verify reset user");

    // /forgot for a real email AND a nonexistent one return the SAME neutral 200 (no enumeration).
    let (csrf, cookie) = csrf_from(&state, "/forgot").await;
    let (status_real, _, body_real) = call(
        &state,
        post_form(
            "/forgot",
            Some(&cookie),
            format!("email={EMAIL}&csrf_token={csrf}"),
        ),
    )
    .await;
    let (csrf, cookie) = csrf_from(&state, "/forgot").await;
    let (status_ghost, _, body_ghost) = call(
        &state,
        post_form(
            "/forgot",
            Some(&cookie),
            format!("email=ghost@nowhere.test&csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(status_real, StatusCode::OK);
    assert_eq!(status_ghost, StatusCode::OK);
    assert_eq!(
        body_str(&body_real),
        body_str(&body_ghost),
        "forgot response is identical whether or not the account exists"
    );

    // Plant + consume a reset token through the real /reset handler.
    let token = "reset-token-xyz";
    state
        .store
        .put_verification_token(VerificationToken {
            token: token.to_string(),
            sub: "usr_reset".to_string(),
            kind: "reset".to_string(),
            expires_at: now_secs() + 3600,
        })
        .await
        .expect("persist reset token");
    let (csrf, cookie) = csrf_from(&state, &format!("/reset?token={token}")).await;
    let (status, _, body) = call(
        &state,
        post_form(
            "/reset",
            Some(&cookie),
            format!("token={token}&password={NEW_PASSWORD}&csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body_str(&body).contains("Password updated"));

    // The stored hash now verifies the NEW password, not the old one.
    let user = state.store.get_user("usr_reset").await.unwrap();
    let phc = user.password_hash.unwrap();
    assert!(keystone::auth::verify_password(NEW_PASSWORD, &phc));
    assert!(!keystone::auth::verify_password(PASSWORD, &phc));
    // Reset token is single-use.
    assert!(state
        .store
        .take_verification_token(token)
        .await
        .expect("inspect consumed reset token")
        .is_none());
}

#[tokio::test]
async fn change_password_requires_correct_current_password() {
    let state = keystone::build_dev_state();
    let hash = keystone::auth::hash_password(PASSWORD).unwrap();
    state
        .store
        .create_user("usr_chg", EMAIL, &hash, now_secs())
        .await
        .unwrap();
    state
        .store
        .set_email_verified("usr_chg")
        .await
        .expect("verify password-change user");
    let session =
        keystone::auth::create_session(&state, "usr_chg", "test-agent", "127.0.0.1").await;
    let session_cookie = format!("__Host-session={session}");

    // Grab a CSRF token from the authenticated account page.
    let (_, headers, _) = call(&state, get_with_cookie("/account", &session_cookie)).await;
    let csrf = cookie_value(&headers, "__Host-csrf").expect("csrf on account page");
    let cookie = format!("{session_cookie}; __Host-csrf={csrf}");

    // Wrong current password -> rejected, hash unchanged.
    let (status, _, body) = call(
        &state,
        post_form(
            "/account/password",
            Some(&cookie),
            format!("current_password=WRONG&new_password={NEW_PASSWORD}&csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Note: the notice title "Couldn't…" is HTML-escaped, so assert on the (apostrophe-free) body.
    assert!(body_str(&body).contains("current password is incorrect"));
    let phc = state
        .store
        .get_user("usr_chg")
        .await
        .unwrap()
        .password_hash
        .unwrap();
    assert!(
        keystone::auth::verify_password(PASSWORD, &phc),
        "old password still valid"
    );

    // Correct current password -> rotated.
    let (status, _, body) = call(
        &state,
        post_form(
            "/account/password",
            Some(&cookie),
            format!("current_password={PASSWORD}&new_password={NEW_PASSWORD}&csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body_str(&body).contains("Password updated"));
    let phc = state
        .store
        .get_user("usr_chg")
        .await
        .unwrap()
        .password_hash
        .unwrap();
    assert!(keystone::auth::verify_password(NEW_PASSWORD, &phc));
}
