//! On-demand OIDC strong-ACR integration tests (in-process, memory store).

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use keystone::store::{
    new_opaque_code, AssuranceLevel, AuthCode, AuthCodeBinding, Session, TotpConfig,
};
use keystone::AppState;
use serde_json::Value;
use tower::ServiceExt;

const CLIENT_ID: &str = "sluice-dev";
const REDIRECT_URI: &str = "http://127.0.0.1:9090/callback";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PASSWORD: &str = "strong-step-up-password";

async fn call(state: &AppState, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = keystone::app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

fn get(uri: &str, session: Option<&str>) -> Request<Body> {
    let mut request = Request::builder().uri(uri);
    if let Some(session) = session {
        request = request.header(header::COOKIE, format!("__Host-session={session}"));
    }
    request.body(Body::empty()).unwrap()
}

fn post_form(uri: &str, cookie: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(body))
        .unwrap()
}

fn authorize_uri(acr: Option<&str>, state: &str) -> String {
    let mut uri = format!(
        "/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}\
         &scope=openid+email&state={}&code_challenge={CHALLENGE}&code_challenge_method=S256",
        percent_encode(state),
    );
    if let Some(acr) = acr {
        uri.push_str("&acr_values=");
        uri.push_str(&percent_encode(acr));
    }
    uri
}

fn location(headers: &HeaderMap) -> String {
    headers
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap()
        .to_string()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|value| {
            let first = value.to_str().ok()?.split(';').next()?;
            let (key, value) = first.split_once('=')?;
            (key == name).then(|| value.to_string())
        })
}

fn hidden_value(html: &str, name: &str) -> String {
    let marker = format!(r#"name="{name}" value=""#);
    let start = html.find(&marker).expect("hidden field") + marker.len();
    html[start..].chars().take_while(|ch| *ch != '"').collect()
}

fn query_value(uri: &str, name: &str) -> String {
    uri.split_once('?')
        .expect("query")
        .1
        .split('&')
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| value.to_string())
        })
        .expect("query value")
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

async fn bound_session(
    state: &AppState,
    aal: AssuranceLevel,
    uv: bool,
    auth_time: u64,
    amr: &str,
) -> String {
    let id = keystone::store::new_opaque_code();
    let user = state.store.get_user("u_admin").await.unwrap();
    let now = keystone::now_secs();
    let persisted = state
        .store
        .put_session_if_active(Session {
            id: id.clone(),
            user_sub: user.sub,
            created_at: now,
            expires_at: now + 3600,
            user_agent: "strong-test".to_string(),
            ip: "127.0.0.1".to_string(),
            last_seen: now,
            session_binding: Some(keystone::auth::session_binding(&id)),
            aal,
            uv,
            auth_time,
            amr: amr.to_string(),
            factor_epoch: user.factor_epoch,
        })
        .await
        .unwrap();
    assert!(persisted);
    keystone::auth::signed_value(&state.config.session_secret, &id)
}

#[tokio::test]
async fn closed_acr_parser_rejects_unknown_mixed_and_duplicate_values() {
    let state = keystone::build_dev_state();
    for uri in [
        authorize_uri(Some("unknown"), "s"),
        authorize_uri(Some("hf-aal-strong other"), "s"),
        format!(
            "{}&acr_values=hf-aal-strong",
            authorize_uri(Some("hf-aal-strong"), "s")
        ),
    ] {
        let (status, _, body) = call(&state, get(&uri, None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "uri={uri}");
        if let Ok(error) = serde_json::from_slice::<Value>(&body) {
            assert_eq!(error["error"], "invalid_request");
        }
    }

    let weak = keystone::auth::create_session(&state, "u_admin", "ua", "ip").await;
    let (status, headers, _) =
        call(&state, get(&authorize_uri(Some(""), "empty"), Some(&weak))).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location(&headers).contains("code="));
}

#[tokio::test]
async fn weak_never_gets_a_strong_code_and_missing_factor_is_access_denied() {
    let state = keystone::build_dev_state();
    let weak = keystone::auth::create_session(&state, "u_admin", "ua", "ip").await;
    let (status, headers, _) = call(
        &state,
        get(
            &authorize_uri(Some("hf-aal-strong"), "a&b=c d"),
            Some(&weak),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let redirect = location(&headers);
    assert!(redirect.contains("error=access_denied"), "{redirect}");
    assert!(!redirect.contains("code="), "{redirect}");
    assert!(redirect.contains("state=a%26b%3Dc%20d"), "{redirect}");
}

#[tokio::test]
async fn fresh_strong_goes_direct_while_stale_future_and_uv_false_fail_closed() {
    let state = keystone::build_dev_state();
    let now = keystone::now_secs();
    let fresh = bound_session(&state, AssuranceLevel::MfaStrong, true, now, "pwd,otp").await;
    let (status, headers, _) = call(
        &state,
        get(&authorize_uri(Some("hf-aal-strong"), "fresh"), Some(&fresh)),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location(&headers).contains("code="));

    for cookie in [
        bound_session(
            &state,
            AssuranceLevel::MfaStrong,
            true,
            now.saturating_sub(301),
            "pwd,otp",
        )
        .await,
        bound_session(&state, AssuranceLevel::MfaStrong, true, now + 30, "pwd,otp").await,
        bound_session(&state, AssuranceLevel::MfaStrong, false, now, "hwk,user").await,
    ] {
        let (status, headers, _) = call(
            &state,
            get(
                &authorize_uri(Some("hf-aal-strong"), "closed"),
                Some(&cookie),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FOUND);
        let redirect = location(&headers);
        assert!(redirect.contains("error=access_denied"), "{redirect}");
        assert!(!redirect.contains("code="), "{redirect}");
    }
}

#[tokio::test]
async fn enrolled_totp_forces_a_bound_ceremony_and_recovery_cannot_satisfy_strong() {
    let state = keystone::build_dev_state();
    state
        .store
        .set_password_hash("u_admin", &keystone::auth::hash_password(PASSWORD).unwrap())
        .await;
    state
        .store
        .put_totp(TotpConfig {
            user_sub: "u_admin".to_string(),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            enabled: true,
            created_at: keystone::now_secs(),
            verified_at: keystone::now_secs(),
            last_accepted_counter: None,
        })
        .await;
    state
        .store
        .put_recovery_codes(
            "u_admin",
            vec![keystone::auth::secret_hash("RECOVERY1234")],
            keystone::now_secs(),
        )
        .await;
    let weak = keystone::auth::create_session(&state, "u_admin", "ua", "ip").await;
    let authorize = authorize_uri(Some("hf-aal-strong"), "recovery");
    let (status, headers, _) = call(&state, get(&authorize, Some(&weak))).await;
    assert_eq!(status, StatusCode::FOUND);
    let login_location = location(&headers);
    assert!(login_location.starts_with("/login?return_to="));
    assert!(login_location.contains("&step_up="));
    assert!(!login_location.contains("code="));
    let flow_id = query_value(&login_location, "step_up");

    let (status, headers, login_body) = call(&state, get(&login_location, Some(&weak))).await;
    assert_eq!(status, StatusCode::OK);
    // The login page during a strong step-up truthfully says a recent strong verification is
    // required; ordinary sign-in copy does not carry this notice.
    let login_html = String::from_utf8_lossy(&login_body);
    assert!(login_html.contains("recent strong verification is required"));
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let body = format!(
        "username=admin%40steadholme.local&password={PASSWORD}&csrf_token={csrf}\
         &return_to={}&step_up={flow_id}",
        percent_encode(&authorize),
    );
    let cookie = format!("__Host-session={weak}; __Host-csrf={csrf}");
    let (status, headers, body) = call(&state, post_form("/login", &cookie, body)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    // The strong step-up TOTP page must not invite recovery-code entry, because recovery cannot
    // satisfy the strong ACR. It states the recovery caveat instead of offering it as an option.
    let totp_html = String::from_utf8_lossy(&body);
    assert!(totp_html.contains("A recent strong confirmation is required"));
    assert!(totp_html.contains("Recovery codes cannot be used for this step"));
    assert!(
        !totp_html.contains("or a recovery code"),
        "strong step-up must not offer recovery-code entry"
    );
    let csrf = cookie_value(&headers, "__Host-csrf").unwrap();
    let challenge_id = hidden_value(&String::from_utf8_lossy(&body), "challenge_id");

    let body = format!("csrf_token={csrf}&challenge_id={challenge_id}&code=RECOVERY1234");
    let cookie = format!("__Host-session={weak}; __Host-csrf={csrf}");
    let (status, headers, body) = call(&state, post_form("/login/totp", &cookie, body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(cookie_value(&headers, "__Host-session").is_none());
    assert!(String::from_utf8_lossy(&body).contains("Incorrect verification code"));
    assert_eq!(state.store.recovery_code_count("u_admin").await, 1);

    let (status, headers, _) = call(&state, get(&authorize, Some(&weak))).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(!location(&headers).contains("code="));
}

#[tokio::test]
async fn required_acr_is_rechecked_when_the_code_is_redeemed() {
    let state = keystone::build_dev_state();
    let now = keystone::now_secs();
    let session = bound_session(&state, AssuranceLevel::MfaStrong, true, now, "pwd,otp").await;
    let (status, headers, _) = call(
        &state,
        get(
            &authorize_uri(Some("hf-aal-strong"), "token"),
            Some(&session),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let code = query_value(&location(&headers), "code");

    let session_id = keystone::auth::verify_signed(&state.config.session_secret, &session).unwrap();
    let mut row = state.store.get_session(&session_id).await.unwrap();
    row.auth_time = now.saturating_sub(301);
    assert!(state.store.put_session_if_active(row).await.unwrap());

    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI}\
         &client_id={CLIENT_ID}&code_verifier={VERIFIER}"
    );
    let (status, _, body) = call(&state, post_form("/token", "", body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn store_redemption_treats_the_caller_clock_as_a_lower_bound() {
    let state = keystone::build_dev_state();
    let user = state.store.get_user("u_admin").await.unwrap();
    let now = keystone::now_secs();
    let session_id = new_opaque_code();
    let binding = keystone::auth::session_binding(&session_id);
    let session = Session {
        id: session_id,
        user_sub: user.sub.clone(),
        created_at: now.saturating_sub(60),
        expires_at: now.saturating_sub(1),
        user_agent: "stale-caller-clock-test".to_string(),
        ip: "127.0.0.1".to_string(),
        last_seen: now.saturating_sub(60),
        session_binding: Some(binding.clone()),
        aal: AssuranceLevel::MfaStrong,
        uv: true,
        auth_time: now.saturating_sub(60),
        amr: "pwd,otp".to_string(),
        factor_epoch: user.factor_epoch,
    };
    assert!(state
        .store
        .put_session_if_active(session.clone())
        .await
        .unwrap());

    let code_value = new_opaque_code();
    state
        .store
        .put_code(AuthCode {
            code: code_value.clone(),
            client_id: CLIENT_ID.to_string(),
            redirect_uri: REDIRECT_URI.to_string(),
            scope: "openid".to_string(),
            nonce: None,
            code_challenge: CHALLENGE.to_string(),
            sub: user.sub,
            expires_at: now + 60,
            used: false,
            binding: Some(AuthCodeBinding::from_session(&session).unwrap()),
            required_acr: Some("hf-aal-strong".to_string()),
        })
        .await;

    let stale_caller_time = now.saturating_sub(60);
    assert!(state
        .store
        .redeem_code(&code_value, stale_caller_time)
        .await
        .unwrap()
        .is_none());
    assert!(
        state
            .store
            .redeem_code(&code_value, keystone::now_secs())
            .await
            .unwrap()
            .is_none(),
        "failed validation still burns the single-use code"
    );
}

#[tokio::test]
async fn strong_reauthentication_with_a_live_source_session_requires_the_bound_flow() {
    let state = keystone::build_dev_state();
    state
        .store
        .set_password_hash("u_admin", &keystone::auth::hash_password(PASSWORD).unwrap())
        .await;
    let weak = keystone::auth::create_session(&state, "u_admin", "ua", "ip").await;
    let csrf = "strong-passkey-csrf";
    let return_to = authorize_uri(Some("hf-aal-strong"), "bound");
    let form = format!(
        "username=u_admin&password={PASSWORD}&csrf_token={csrf}&return_to={}",
        percent_encode(&return_to),
    );
    let cookie = format!("__Host-session={weak}; __Host-csrf={csrf}");
    let (status, headers, _) = call(&state, post_form("/login", &cookie, form)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(cookie_value(&headers, "__Host-session").is_none());

    let body = serde_json::to_vec(&serde_json::json!({
        "username": "u_admin",
        "return_to": return_to,
    }))
    .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/webauthn/authenticate/begin")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-csrf-token", csrf)
        .header(header::COOKIE, cookie)
        .body(Body::from(body))
        .unwrap();
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "invalid_request");
}
