//! OAuth consent-screen integration tests (in-process, memory store, no DB).
//!
//! Proves the third-party consent gate on `/authorize`:
//!   1. First-party clients (seeded Sluice) skip consent -> 302 code directly.
//!   2. A third-party client with no prior consent -> 200 consent screen.
//!   3. Deny -> 302 back with `error=access_denied`.
//!   4. Approve (CSRF-checked) -> 302 back with a code; consent is remembered so the next
//!      authorize for a covered scope set skips the screen.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use keystone::store::Client;
use keystone::AppState;
use tower::ServiceExt;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const TP_ID: &str = "thirdparty-app";
const TP_REDIRECT: &str = "https://app.example.com/cb";
const SEED_ID: &str = "sluice-dev";
const SEED_REDIRECT: &str = "http://127.0.0.1:9090/callback";

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
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn hidden_value(html: &str, name: &str) -> String {
    let marker = format!(r#"name="{name}" value=""#);
    let start = html.find(&marker).expect("hidden field") + marker.len();
    html[start..].chars().take_while(|ch| *ch != '"').collect()
}

fn authorize_uri(client_id: &str, redirect_uri: &str) -> String {
    let enc = redirect_uri.replace(':', "%3A").replace('/', "%2F");
    format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={enc}\
         &scope=openid+email+profile&state=xyz&code_challenge={CHALLENGE}\
         &code_challenge_method=S256&nonce=n1"
    )
}

fn get_with_cookie(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

async fn seed_third_party(state: &AppState) {
    state
        .store
        .put_client(Client {
            client_id: TP_ID.to_string(),
            redirect_uris: vec![TP_REDIRECT.to_string()],
            name: "Third Party App".to_string(),
            client_secret_hash: None,
            first_party: false,
        })
        .await;
}

/// Build a consent POST carrying the request verbatim + a decision.
fn consent_post(decision: &str, csrf: &str, acr_binding: &str, session: &str) -> Request<Body> {
    let body = format!(
        "response_type=code&client_id={TP_ID}&redirect_uri={TP_REDIRECT}\
         &scope=openid+email+profile&state=xyz&nonce=n1&code_challenge={CHALLENGE}\
         &code_challenge_method=S256&acr_binding={acr_binding}&csrf_token={csrf}&decision={decision}"
    );
    Request::builder()
        .method("POST")
        .uri("/authorize/consent")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::COOKIE,
            format!("__Host-session={session}; __Host-csrf={csrf}"),
        )
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn first_party_skips_consent() {
    let state = keystone::build_dev_state();
    let session = keystone::auth::create_session(&state, "u_admin", "ua", "ip").await;
    let (status, headers, _) = call(
        &state,
        get_with_cookie(
            &authorize_uri(SEED_ID, SEED_REDIRECT),
            &format!("__Host-session={session}"),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "first-party gets a code immediately"
    );
    assert!(location(&headers).starts_with(SEED_REDIRECT));
    assert!(location(&headers).contains("code="));
}

#[tokio::test]
async fn third_party_consent_deny_then_approve_then_remembered() {
    let state = keystone::build_dev_state();
    seed_third_party(&state).await;
    let session = keystone::auth::create_session(&state, "u_admin", "ua", "ip").await;
    let sc = format!("__Host-session={session}");

    // 1. No prior consent -> the consent screen (200) naming the client + scopes.
    let (status, headers, body) = call(
        &state,
        get_with_cookie(&authorize_uri(TP_ID, TP_REDIRECT), &sc),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "third-party is prompted");
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("Third Party App"), "client name shown");
    assert!(
        html.contains("Read your email address"),
        "scope description shown"
    );
    let csrf = cookie_value(&headers, "__Host-csrf").expect("consent issues csrf");
    let acr_binding = hidden_value(&html, "acr_binding");

    // 2. Deny -> 302 back with error=access_denied.
    let (status, headers, _) =
        call(&state, consent_post("deny", &csrf, &acr_binding, &session)).await;
    assert_eq!(status, StatusCode::FOUND);
    let loc = location(&headers);
    assert!(loc.starts_with(TP_REDIRECT), "got {loc}");
    assert!(loc.contains("error=access_denied"), "got {loc}");
    assert!(!loc.contains("code="));

    // 3. Approve -> 302 back with a code.
    let (status, headers, _) = call(
        &state,
        consent_post("approve", &csrf, &acr_binding, &session),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let loc = location(&headers);
    assert!(
        loc.starts_with(TP_REDIRECT) && loc.contains("code="),
        "got {loc}"
    );

    // 4. Consent is remembered: the next authorize for the same scopes skips the screen.
    let (status, headers, _) = call(
        &state,
        get_with_cookie(&authorize_uri(TP_ID, TP_REDIRECT), &sc),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "remembered consent skips the screen"
    );
    assert!(location(&headers).contains("code="));
}

#[tokio::test]
async fn factor_epoch_change_mid_consent_requires_reauthentication() {
    let state = keystone::build_dev_state();
    seed_third_party(&state).await;
    let session = keystone::auth::create_session(&state, "u_admin", "ua", "ip").await;
    let session_id = keystone::auth::verify_signed(&state.config.session_secret, &session)
        .expect("signed session id");
    let session_cookie = format!("__Host-session={session}");

    let (status, headers, body) = call(
        &state,
        get_with_cookie(&authorize_uri(TP_ID, TP_REDIRECT), &session_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    let csrf = cookie_value(&headers, "__Host-csrf").expect("consent issues csrf");
    let acr_binding = hidden_value(&html, "acr_binding");

    state
        .store
        .bump_factor_epoch("u_admin")
        .await
        .expect("factor epoch bump");
    let (status, headers, _) = call(
        &state,
        consent_post("approve", &csrf, &acr_binding, &session),
    )
    .await;

    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location(&headers).starts_with("/login?return_to="),
        "stale consent session must return through login"
    );
    assert!(
        state.store.get_consent("u_admin", TP_ID).await.is_none(),
        "stale consent is not persisted"
    );
    assert!(
        state.store.get_session(&session_id).await.is_none(),
        "the stale consent session is deleted"
    );
}

#[tokio::test]
async fn consent_requires_csrf() {
    let state = keystone::build_dev_state();
    seed_third_party(&state).await;
    let session = keystone::auth::create_session(&state, "u_admin", "ua", "ip").await;
    // Approve with a form csrf token but NO matching __Host-csrf cookie -> double-submit fails.
    let body = format!(
        "response_type=code&client_id={TP_ID}&redirect_uri={TP_REDIRECT}\
         &scope=openid+email+profile&state=xyz&nonce=n1&code_challenge={CHALLENGE}\
         &code_challenge_method=S256&csrf_token=forged&decision=approve"
    );
    let req = Request::builder()
        .method("POST")
        .uri("/authorize/consent")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-session={session}")) // no csrf cookie
        .body(Body::from(body))
        .unwrap();
    let (status, _, _) = call(&state, req).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing CSRF cookie is refused"
    );
}

#[tokio::test]
async fn consent_round_trips_strong_acr_and_encodes_state() {
    let state = keystone::build_dev_state();
    seed_third_party(&state).await;
    let epoch = state.store.get_user("u_admin").await.unwrap().factor_epoch;
    let session = keystone::auth::try_create_strong_session_at_epoch(
        &state, "u_admin", "ua", "ip", true, "pwd,otp", epoch,
    )
    .await
    .unwrap();
    let uri = format!(
        "{}&acr_values=hf-aal-strong&state=a%26b%3Dc",
        authorize_uri(TP_ID, TP_REDIRECT).replace("&state=xyz", "")
    );
    let (status, headers, body) = call(
        &state,
        get_with_cookie(&uri, &format!("__Host-session={session}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains(r#"name="acr_values" value="hf-aal-strong""#));
    let acr_binding = hidden_value(&html, "acr_binding");
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();

    // Removing the requested ACR while retaining the server-issued binding cannot downgrade
    // this consent POST to the ordinary path.
    let downgraded = format!(
        "response_type=code&client_id={TP_ID}&redirect_uri={TP_REDIRECT}\
         &scope=openid+email+profile&state=a%26b%3Dc&nonce=n1&code_challenge={CHALLENGE}\
         &code_challenge_method=S256&acr_binding={acr_binding}&csrf_token={csrf}&decision=approve"
    );
    let request = Request::builder()
        .method("POST")
        .uri("/authorize/consent")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::COOKIE,
            format!("__Host-session={session}; __Host-csrf={csrf}"),
        )
        .body(Body::from(downgraded))
        .unwrap();
    let (status, _, _) = call(&state, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A binding from the same CSRF/client/redirect cannot be mixed with another
    // state, PKCE verifier, scope, nonce, or other authorize flow field.
    let mixed_flow = format!(
        "response_type=code&client_id={TP_ID}&redirect_uri={TP_REDIRECT}\
		 &scope=openid+email+profile&state=a%26b%3Dc&nonce=n1&code_challenge=forged-challenge\
		 &code_challenge_method=S256&acr_values=hf-aal-strong&acr_binding={acr_binding}\
		 &csrf_token={csrf}&decision=approve"
    );
    let request = Request::builder()
        .method("POST")
        .uri("/authorize/consent")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::COOKIE,
            format!("__Host-session={session}; __Host-csrf={csrf}"),
        )
        .body(Body::from(mixed_flow))
        .unwrap();
    let (status, _, _) = call(&state, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let body = format!(
        "response_type=code&client_id={TP_ID}&redirect_uri={TP_REDIRECT}\
         &scope=openid+email+profile&state=a%26b%3Dc&nonce=n1&code_challenge={CHALLENGE}\
         &code_challenge_method=S256&acr_values=hf-aal-strong&acr_binding={acr_binding}\
         &csrf_token={csrf}&decision=approve"
    );
    let request = Request::builder()
        .method("POST")
        .uri("/authorize/consent")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::COOKIE,
            format!("__Host-session={session}; __Host-csrf={csrf}"),
        )
        .body(Body::from(body))
        .unwrap();
    let (status, headers, _) = call(&state, request).await;
    assert_eq!(status, StatusCode::FOUND);
    let redirect = location(&headers);
    assert!(redirect.contains("code="), "{redirect}");
    assert!(redirect.contains("state=a%26b%3Dc"), "{redirect}");
}
