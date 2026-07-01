//! Confidential-client `/token` authentication tests (in-process via `tower::oneshot`).
//!
//! Proves: a confidential client (stored Argon2id secret hash) MUST present a valid
//! secret — via `client_secret_post` AND HTTP Basic — to redeem a code; a wrong/missing
//! secret is 401 `invalid_client`; the public client (sluice-dev) still redeems with
//! PKCE only; and `nonce` + `aud` round-trip into the id_token for the requesting client.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use keystone::store::Client;
use keystone::AppState;
use serde_json::Value;
use tower::ServiceExt;

const GW_CLIENT_ID: &str = "sluice-gw";
const GW_SECRET: &str = "super-secret-gateway-value";
const GW_REDIRECT: &str = "http://127.0.0.1:9091/cb";
const ISSUER: &str = "http://127.0.0.1:8080";
// RFC 7636 Appendix B test vector.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

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

/// Seed a confidential client (Argon2id-hashed secret) into the dev store.
async fn state_with_confidential_client() -> AppState {
    let state = keystone::build_dev_state();
    let hash = keystone::auth::hash_password(GW_SECRET).unwrap();
    state
        .store
        .put_client(Client {
            client_id: GW_CLIENT_ID.to_string(),
            redirect_uris: vec![GW_REDIRECT.to_string()],
            name: "gw".to_string(),
            client_secret_hash: Some(hash),
            first_party: true,
        })
        .await;
    state
}

/// Run `/authorize` for `client_id`/`redirect_uri` (with a live session) and return the code.
async fn authorize_code(state: &AppState, client_id: &str, redirect_uri: &str) -> String {
    let uri = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}\
         &scope=openid+email+profile&state=xyz&code_challenge={CHALLENGE}\
         &code_challenge_method=S256&nonce=n-gw"
    );
    let session_cookie = keystone::auth::create_session(state, "u_admin", "test-agent", "127.0.0.1").await;
    let req = Request::builder()
        .uri(uri)
        .header(header::COOKIE, format!("__Host-session={session_cookie}"))
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = call(state, req).await;
    assert_eq!(status, StatusCode::FOUND, "authorize should 302");
    let location = headers.get(header::LOCATION).unwrap().to_str().unwrap();
    let query = location.split_once('?').unwrap().1;
    query
        .split('&')
        .find_map(|p| p.strip_prefix("code="))
        .expect("code in redirect")
        .to_string()
}

/// `POST /token` with `client_secret_post` body fields (client_id + client_secret).
fn token_post(code: &str, redirect_uri: &str, client_id: &str, secret: Option<&str>) -> Request<Body> {
    let mut body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={redirect_uri}\
         &client_id={client_id}&code_verifier={VERIFIER}"
    );
    if let Some(s) = secret {
        body.push_str("&client_secret=");
        body.push_str(s);
    }
    Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

/// `POST /token` authenticating via HTTP Basic (client_secret_basic), no body client_id.
fn token_basic(code: &str, redirect_uri: &str, client_id: &str, secret: &str) -> Request<Body> {
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={redirect_uri}\
         &code_verifier={VERIFIER}"
    );
    let basic = BASE64_STANDARD.encode(format!("{client_id}:{secret}"));
    Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, format!("Basic {basic}"))
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn confidential_client_secret_post_success_and_nonce_roundtrips() {
    let state = state_with_confidential_client().await;
    let code = authorize_code(&state, GW_CLIENT_ID, GW_REDIRECT).await;

    let (status, _, body) = call(
        &state,
        token_post(&code, GW_REDIRECT, GW_CLIENT_ID, Some(GW_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "correct secret -> 200");
    let tok: Value = serde_json::from_slice(&body).unwrap();
    let id_token = tok["id_token"].as_str().expect("id_token").to_string();

    // Verify the id_token against the live JWKS; aud = requesting client_id, nonce echoed.
    let (_, _, jwks_body) = call(&state, Request::builder().uri("/jwks.json").body(Body::empty()).unwrap()).await;
    let jwks: Value = serde_json::from_slice(&jwks_body).unwrap();
    let key = &jwks["keys"][0];
    let decoding =
        DecodingKey::from_rsa_components(key["n"].as_str().unwrap(), key["e"].as_str().unwrap())
            .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[GW_CLIENT_ID]);
    let id = decode::<Value>(&id_token, &decoding, &validation).unwrap();
    assert_eq!(id.claims["aud"], GW_CLIENT_ID, "aud = requesting client_id");
    assert_eq!(id.claims["nonce"], "n-gw", "nonce round-trips into id_token");
    assert_eq!(id.claims["sub"], "u_admin");
}

#[tokio::test]
async fn confidential_client_secret_basic_success() {
    let state = state_with_confidential_client().await;
    let code = authorize_code(&state, GW_CLIENT_ID, GW_REDIRECT).await;
    let (status, _, _) = call(&state, token_basic(&code, GW_REDIRECT, GW_CLIENT_ID, GW_SECRET)).await;
    assert_eq!(status, StatusCode::OK, "HTTP Basic correct secret -> 200");
}

#[tokio::test]
async fn confidential_client_wrong_and_missing_secret_is_401() {
    let state = state_with_confidential_client().await;
    let code = authorize_code(&state, GW_CLIENT_ID, GW_REDIRECT).await;

    // Wrong secret -> 401 invalid_client. Client auth runs BEFORE the code is consumed.
    let (status, headers, body) = call(
        &state,
        token_post(&code, GW_REDIRECT, GW_CLIENT_ID, Some("wrong-secret")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong secret -> 401");
    assert!(headers.get(header::WWW_AUTHENTICATE).is_some());
    let e: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(e["error"], "invalid_client");

    // Missing secret -> 401 invalid_client.
    let (status, _, body) =
        call(&state, token_post(&code, GW_REDIRECT, GW_CLIENT_ID, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "missing secret -> 401");
    let e: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(e["error"], "invalid_client");

    // The code was never consumed by the failed attempts: a correct secret still works.
    let (status, _, _) = call(
        &state,
        token_post(&code, GW_REDIRECT, GW_CLIENT_ID, Some(GW_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "code survived failed auth -> redeemable");
}

#[tokio::test]
async fn public_client_still_redeems_with_pkce_only() {
    // sluice-dev is public: no secret needed, PKCE alone redeems the code.
    let state = keystone::build_dev_state();
    let code = authorize_code(&state, "sluice-dev", "http://127.0.0.1:9090/callback").await;
    let (status, _, _) = call(
        &state,
        token_post(&code, "http://127.0.0.1:9090/callback", "sluice-dev", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "public client redeems with PKCE only");
}

#[tokio::test]
async fn confidential_client_basic_and_body_client_id_mismatch_is_401() {
    let state = state_with_confidential_client().await;
    let code = authorize_code(&state, GW_CLIENT_ID, GW_REDIRECT).await;
    // Body client_id = sluice-dev but Basic client_id = sluice-gw -> mismatch 401.
    let basic = BASE64_STANDARD.encode(format!("{GW_CLIENT_ID}:{GW_SECRET}"));
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={GW_REDIRECT}\
         &client_id=sluice-dev&code_verifier={VERIFIER}"
    );
    let req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, format!("Basic {basic}"))
        .body(Body::from(body))
        .unwrap();
    let (status, _, body) = call(&state, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "client_id mismatch -> 401");
    let e: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(e["error"], "invalid_client");
}
