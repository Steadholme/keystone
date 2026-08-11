use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use jsonwebtoken::{decode, Algorithm, Validation};
use keystone::store::{AssuranceLevel, AuthCode};
use keystone::AppState;
use serde_json::Value;
use tower::ServiceExt;

const CLIENT_ID: &str = "sluice-dev";
const REDIRECT_URI: &str = "http://127.0.0.1:9090/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const ASSURANCE_TOKEN: &str = "keystone-assurance-test-token-0000000001";
const NEXT_ASSURANCE_TOKEN: &str = "keystone-assurance-test-token-0000000002";

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

async fn strong_session(state: &AppState) -> (String, String, String) {
    let signed = keystone::auth::try_create_session_with_assurance(
        state,
        "u_admin",
        "test-agent",
        "127.0.0.1",
        AssuranceLevel::MfaStrong,
        true,
        "pwd,otp",
    )
    .await
    .expect("strong session");
    let id = keystone::auth::verify_signed(&state.config.session_secret, &signed)
        .expect("signed session id");
    let binding = keystone::auth::session_binding(&id);
    (signed, id, binding)
}

async fn authorize_code(state: &AppState, session_cookie: &str) -> String {
    let uri = format!(
        "/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}\
         &scope=openid+email&code_challenge={CHALLENGE}&code_challenge_method=S256&nonce=n-mfa"
    );
    let request = Request::builder()
        .uri(uri)
        .header(header::COOKIE, format!("__Host-session={session_cookie}"))
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = call(state, request).await;
    assert_eq!(status, StatusCode::FOUND);
    headers[header::LOCATION]
        .to_str()
        .unwrap()
        .split_once('?')
        .unwrap()
        .1
        .split('&')
        .find_map(|pair| pair.strip_prefix("code="))
        .unwrap()
        .to_string()
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

fn assurance_request(token: &str, binding: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/internal/v1/session-assurance")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "subject": "u_admin",
                "session_binding": binding,
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn bound_strong_code_mints_claims_only_from_verified_session_tuple() {
    let state = keystone::build_dev_state();
    let (session_cookie, _, binding) = strong_session(&state).await;
    let code = authorize_code(&state, &session_cookie).await;
    let (status, _, body) = call(&state, token_request(&code)).await;
    assert_eq!(status, StatusCode::OK);
    let response: Value = serde_json::from_slice(&body).unwrap();
    let id_token = response["id_token"].as_str().unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[state.config.issuer.as_str()]);
    validation.set_audience(&[CLIENT_ID]);
    let claims = decode::<Value>(id_token, &state.keys.decoding_key(), &validation)
        .unwrap()
        .claims;
    assert_eq!(claims["acr"], "hf-aal-strong");
    assert_eq!(claims["amr"], serde_json::json!(["pwd", "otp"]));
    assert_eq!(claims["hf_mfa"]["aal"], "MFA_STRONG");
    assert_eq!(claims["hf_mfa"]["uv"], true);
    assert_eq!(claims["hf_mfa"]["sb"], binding);
    assert_eq!(claims["hf_mfa"]["fe"], 0);
    assert!(claims["auth_time"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn legacy_unbound_code_preserves_id_token_shape_without_mfa_claims() {
    let state = keystone::build_dev_state();
    let code = keystone::store::new_opaque_code();
    state
        .store
        .put_code(AuthCode {
            code: code.clone(),
            client_id: CLIENT_ID.to_string(),
            redirect_uri: REDIRECT_URI.to_string(),
            scope: "openid email".to_string(),
            nonce: Some("legacy-nonce".to_string()),
            code_challenge: CHALLENGE.to_string(),
            sub: "u_admin".to_string(),
            expires_at: keystone::now_secs() + 60,
            used: false,
            binding: None,
            required_acr: None,
        })
        .await;

    let (status, _, body) = call(&state, token_request(&code)).await;
    assert_eq!(status, StatusCode::OK);
    let response: Value = serde_json::from_slice(&body).unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[state.config.issuer.as_str()]);
    validation.set_audience(&[CLIENT_ID]);
    let claims = decode::<Value>(
        response["id_token"].as_str().unwrap(),
        &state.keys.decoding_key(),
        &validation,
    )
    .unwrap()
    .claims;
    assert!(claims.get("hf_mfa").is_none());
    assert!(claims.get("auth_time").is_none());
    assert!(claims.get("acr").is_none());
    assert!(claims.get("amr").is_none());
}

#[tokio::test]
async fn bound_code_is_invalid_grant_after_session_revoke_or_factor_epoch_change() {
    let state = keystone::build_dev_state();
    let (session_cookie, session_id, _) = strong_session(&state).await;
    let revoked_code = authorize_code(&state, &session_cookie).await;
    state.store.delete_session(&session_id).await;
    let (status, _, body) = call(&state, token_request(&revoked_code)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["error"],
        "invalid_grant"
    );

    let (session_cookie, _, _) = strong_session(&state).await;
    let stale_code = authorize_code(&state, &session_cookie).await;
    state.store.bump_factor_epoch("u_admin").await.unwrap();
    let (status, _, body) = call(&state, token_request(&stale_code)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["error"],
        "invalid_grant"
    );
}

#[tokio::test]
async fn assurance_lookup_is_independent_and_deterministically_degrades_revoked_session() {
    let mut state = keystone::build_dev_state();
    let mut config = state.config.as_ref().clone();
    config.assurance_service_token = Some(ASSURANCE_TOKEN.to_string());
    state.config = Arc::new(config);
    let (_, session_id, binding) = strong_session(&state).await;

    let (status, headers, body) = call(&state, assurance_request(ASSURANCE_TOKEN, &binding)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "private, no-store");
    let live: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(live["result"], "live");
    assert_eq!(live["aal"], "MFA_STRONG");
    assert_eq!(live["session_binding"], binding);

    state.store.delete_session(&session_id).await;
    let (status, _, body) = call(&state, assurance_request(ASSURANCE_TOKEN, &binding)).await;
    assert_eq!(status, StatusCode::OK);
    let absent: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(absent["result"], "absent");
    assert_eq!(absent["aal"], "AAL_NONE");
    assert_eq!(absent["auth_time"], 0);
    assert!(absent.get("session_binding").is_none());
}

#[tokio::test]
async fn assurance_lookup_auth_failure_does_not_depend_on_assertion_signing_key() {
    let mut state = keystone::build_dev_state();
    let mut config = state.config.as_ref().clone();
    config.assurance_service_token = Some(ASSURANCE_TOKEN.to_string());
    state.config = Arc::new(config);
    let (_, _, binding) = strong_session(&state).await;

    let (status, _, _) = call(&state, assurance_request("wrong-token", &binding)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn assurance_lookup_rotation_accepts_previous_then_removes_it_fail_closed() {
    let mut state = keystone::build_dev_state();
    let mut config = state.config.as_ref().clone();
    config.assurance_service_token = Some(NEXT_ASSURANCE_TOKEN.to_string());
    config.assurance_previous_service_token = Some(ASSURANCE_TOKEN.to_string());
    state.config = Arc::new(config);
    let (_, _, binding) = strong_session(&state).await;

    for token in [NEXT_ASSURANCE_TOKEN, ASSURANCE_TOKEN] {
        let (status, _, _) = call(&state, assurance_request(token, &binding)).await;
        assert_eq!(status, StatusCode::OK);
    }

    let mut config = state.config.as_ref().clone();
    config.assurance_previous_service_token = None;
    state.config = Arc::new(config);
    let (status, _, _) = call(&state, assurance_request(ASSURANCE_TOKEN, &binding)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let mut config = state.config.as_ref().clone();
    config.assurance_previous_service_token = Some(NEXT_ASSURANCE_TOKEN.to_string());
    state.config = Arc::new(config);
    let (status, _, _) = call(&state, assurance_request(NEXT_ASSURANCE_TOKEN, &binding)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}
