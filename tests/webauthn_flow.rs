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
    json_post_with_csrf(uri, cookie, CSRF, body)
}

fn json_post_with_csrf(uri: &str, cookie: &str, csrf: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .header("X-CSRF-Token", csrf)
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
    let session =
        keystone::auth::create_session(&state, "u_admin", "test-agent", "127.0.0.1").await;
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
        state.store.list_credentials("u_admin").await.len(),
        1,
        "one passkey stored"
    );

    // --- On-demand strong step-up stays bound to the current weak session --
    let strong_authorize_uri = "/authorize?response_type=code&client_id=sluice-dev\
         &redirect_uri=http://127.0.0.1:9090/callback&scope=openid+email&state=step-up\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256\
         &acr_values=hf-aal-strong";
    let (status, headers, _) = call(
        &state,
        Request::builder()
            .uri(strong_authorize_uri)
            .header(header::COOKIE, format!("__Host-session={session}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let login_location = headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(login_location.starts_with("/login?return_to="));
    let step_up_id = login_location
        .split('&')
        .find_map(|pair| pair.strip_prefix("step_up="))
        .expect("server-side step-up flow id");

    let (status, headers, _) = call(
        &state,
        Request::builder()
            .uri(&login_location)
            .header(header::COOKIE, format!("__Host-session={session}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let step_up_csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let step_up_cookie = format!("__Host-session={session}; __Host-csrf={step_up_csrf}");
    let begin_body = serde_json::to_vec(&serde_json::json!({
        "username": "a-browser-value-cannot-switch-the-subject",
        "return_to": strong_authorize_uri,
        "step_up": step_up_id,
    }))
    .unwrap();
    let (status, headers, body) = call(
        &state,
        json_post_with_csrf(
            "/webauthn/authenticate/begin",
            &step_up_cookie,
            &step_up_csrf,
            begin_body,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let wa_step_up = cookie_value(&headers, "__Host-wa").unwrap();
    let rcr: RequestChallengeResponse = serde_json::from_slice(&body).unwrap();
    let pkc = authenticator
        .do_authentication(origin.clone(), rcr)
        .expect("SoftPasskey step-up authentication");
    let finish_cookie =
        format!("__Host-session={session}; __Host-csrf={step_up_csrf}; __Host-wa={wa_step_up}");
    let (status, headers, body) = call(
        &state,
        json_post_with_csrf(
            "/webauthn/authenticate/finish",
            &finish_cookie,
            &step_up_csrf,
            serde_json::to_vec(&pkc).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "step-up finish: {}",
        String::from_utf8_lossy(&body)
    );
    let stepped_up_session =
        cookie_value(&headers, "__Host-session").expect("step-up minted a new strong session");
    assert_ne!(stepped_up_session, session);
    let (status, headers, _) = call(
        &state,
        Request::builder()
            .uri(strong_authorize_uri)
            .header(
                header::COOKIE,
                format!("__Host-session={stepped_up_session}"),
            )
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("code="));

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
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256\
         &acr_values=hf-aal-strong";
    let req = Request::builder()
        .uri(authorize_uri)
        .header(header::COOKIE, format!("__Host-session={new_session}"))
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = call(&state, req).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "authorize with fresh UV passkey session satisfies strong ACR"
    );
    let loc = headers.get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(
        loc.starts_with("http://127.0.0.1:9090/callback?code="),
        "got {loc}"
    );

    // A factor reset between assertion begin and finish invalidates the ceremony epoch and must
    // not mint even a weak fallback session.
    let (status, headers, body) = call(
        &state,
        json_post(
            "/webauthn/authenticate/begin",
            &auth_cookie,
            br#"{"username":"u_admin"}"#.to_vec(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let wa_race = cookie_value(&headers, "__Host-wa").unwrap();
    let rcr: RequestChallengeResponse = serde_json::from_slice(&body).unwrap();
    let pkc = authenticator
        .do_authentication(origin, rcr)
        .expect("SoftPasskey factor-race assertion");
    state
        .store
        .bump_factor_epoch("u_admin")
        .await
        .expect("race factor epoch bump");
    let race_cookie = format!("__Host-csrf={CSRF}; __Host-wa={wa_race}");
    let (status, headers, _) = call(
        &state,
        json_post(
            "/webauthn/authenticate/finish",
            &race_cookie,
            serde_json::to_vec(&pkc).unwrap(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(cookie_value(&headers, "__Host-session").is_none());
}
