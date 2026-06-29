//! WebAuthn end-to-end test using a real software authenticator (no browser).
//!
//! Drives the live `Webauthn` config (rp_id `w33d.xyz`, origin `https://id.w33d.xyz`)
//! through both ceremonies with webauthn-authenticator-rs' `SoftPasskey`:
//!
//!   register/begin -> SoftPasskey.do_registration -> register/finish (persists Passkey)
//!   authenticate/begin -> SoftPasskey.do_authentication -> authenticate/finish (session)
//!
//! Finally proves the passkey-minted session drives the OIDC `/authorize` gate.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use keystone::AppState;
use tower::ServiceExt;
use webauthn_authenticator_rs::prelude::{
    CreationChallengeResponse, RequestChallengeResponse, Url,
};
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_authenticator_rs::WebauthnAuthenticator;

const CSRF: &str = "test-csrf-token-value";
const ORIGIN: &str = "https://id.w33d.xyz";

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

/// JSON POST with explicit Cookie header + double-submit `X-CSRF-Token`.
fn json_post(uri: &str, cookie: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .header("X-CSRF-Token", CSRF)
        .body(Body::from(body))
        .unwrap()
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
async fn passkey_register_then_authenticate_end_to_end() {
    let state = keystone::build_dev_state();
    let origin = Url::parse(ORIGIN).unwrap();
    // UV is Required by our relying party; falsify_uv=true makes SoftPasskey assert it.
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // --- Registration (session-protected) ----------------------------------
    let session = keystone::auth::create_session(&state, "u_admin");
    let reg_cookie = format!("__Host-session={session}; __Host-csrf={CSRF}");

    let (status, headers, body) = call(
        &state,
        json_post("/webauthn/register/begin", &reg_cookie, b"{}".to_vec()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "register/begin: {}",
        String::from_utf8_lossy(&body)
    );
    let wa1 = cookie_value(&headers, "__Host-wa").expect("ceremony-state cookie set");
    let ccr: CreationChallengeResponse = serde_json::from_slice(&body).expect("parse CCR");

    let reg = authenticator
        .do_registration(origin.clone(), ccr)
        .expect("SoftPasskey registration");

    let finish_cookie = format!("__Host-session={session}; __Host-csrf={CSRF}; __Host-wa={wa1}");
    let (status, _, body) = call(
        &state,
        json_post(
            "/webauthn/register/finish",
            &finish_cookie,
            serde_json::to_vec(&reg).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "register/finish: {}",
        String::from_utf8_lossy(&body)
    );

    // The passkey is now persisted under the user.
    assert_eq!(
        state.store.list_credentials("u_admin").len(),
        1,
        "one passkey stored"
    );

    // --- Authentication (passwordless — NO prior session) -------------------
    let auth_cookie = format!("__Host-csrf={CSRF}");
    let (status, headers, body) = call(
        &state,
        json_post(
            "/webauthn/authenticate/begin",
            &auth_cookie,
            br#"{"username":"u_admin"}"#.to_vec(),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "authenticate/begin: {}",
        String::from_utf8_lossy(&body)
    );
    let wa2 = cookie_value(&headers, "__Host-wa").expect("auth ceremony-state cookie");
    let rcr: RequestChallengeResponse = serde_json::from_slice(&body).expect("parse RCR");

    let pkc = authenticator
        .do_authentication(origin.clone(), rcr)
        .expect("SoftPasskey authentication");

    let auth_finish_cookie = format!("__Host-csrf={CSRF}; __Host-wa={wa2}");
    let (status, headers, body) = call(
        &state,
        json_post(
            "/webauthn/authenticate/finish",
            &auth_finish_cookie,
            serde_json::to_vec(&pkc).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "authenticate/finish: {}",
        String::from_utf8_lossy(&body)
    );

    // A fresh login session was minted by the passkey assertion.
    let new_session = cookie_value(&headers, "__Host-session").expect("passkey login -> session");
    assert_ne!(new_session, session, "a new session id was issued");

    // --- The passkey session drives the OIDC /authorize gate ----------------
    let authorize_uri = "/authorize?response_type=code&client_id=sluice-dev\
         &redirect_uri=http://127.0.0.1:9090/callback&scope=openid+email&state=s1\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";
    let req = Request::builder()
        .uri(authorize_uri)
        .header(header::COOKIE, format!("__Host-session={new_session}"))
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = call(&state, req).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "authorize with passkey session 302s"
    );
    let loc = headers.get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(
        loc.starts_with("http://127.0.0.1:9090/callback?code="),
        "got {loc}"
    );
}
