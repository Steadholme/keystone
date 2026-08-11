//! Audit emission must be fire-and-forget: enabling it (even pointed at an unreachable
//! Watchtower) MUST NOT block, slow, or fail the auth request path.
//!
//! Drives the in-process app (memory store, no DB) with the audit sink ENABLED but aimed
//! at a black-hole address, then runs a `login.failure`: the handler must still return the
//! normal 401 promptly (the emit is `try_send`-only, so it never awaits the dead socket).

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use keystone::audit::AuditSink;
use keystone::AppState;
use tower::ServiceExt;

const PASSWORD: &str = "hunter2bravo";

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap) {
    let resp = keystone::app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    (status, headers)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
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

#[tokio::test]
async fn login_failure_is_prompt_with_unreachable_audit_sink() {
    let state = keystone::build_dev_state();
    let hash = keystone::auth::hash_password(PASSWORD).unwrap();
    state.store.set_password_hash("u_admin", &hash).await;

    // Audit ON, aimed at a non-routable address. The background worker may stall on connect,
    // but the request path uses `try_send` and must never wait on it.
    let mut state = state;
    state.audit = AuditSink::start(true, "http://10.255.255.1:9/", Some("test-token"));

    // GET /login for a CSRF cookie/token pair.
    let (status, headers) = call(&state, get("/login")).await;
    assert_eq!(status, StatusCode::OK);
    let csrf = cookie_value(&headers, "__Host-csrf").expect("csrf cookie issued");

    // POST /login with a WRONG password -> emits `login.failure`, returns 401.
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

    let started = Instant::now();
    let (status, headers) = call(&state, req).await;
    let elapsed = started.elapsed();

    // The handler returned the normal failure response — emission did not error it.
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "bad password is still 401"
    );
    assert!(
        cookie_value(&headers, "__Host-session").is_none(),
        "no session granted on failure"
    );
    // And it returned promptly: well under the worker's 2s POST timeout. Emission never
    // blocked the request on the unreachable sink.
    assert!(
        elapsed < Duration::from_secs(1),
        "login path must not block on audit emission, took {elapsed:?}"
    );
}
