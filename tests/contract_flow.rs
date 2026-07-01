//! End-to-end contract tests driven in-process via `tower::oneshot` (no port binding).
//!
//! The centerpiece proves the exact JWKS-verification path Sluice will use
//! (`DecodingKey::from_rsa_components(n, e)`), so the two services interoperate
//! by construction.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use keystone::AppState;
use serde_json::Value;
use tower::ServiceExt;

const CLIENT_ID: &str = "sluice-dev";
const REDIRECT_URI: &str = "http://127.0.0.1:9090/callback";
const ISSUER: &str = "http://127.0.0.1:8080";
// RFC 7636 Appendix B test vector.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Drive one request through a fresh router that shares `state` (same keys + store).
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

fn authorize_uri(challenge: &str, method: &str) -> String {
    format!(
        "/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}\
         &scope=openid+email+profile&state=xyz123&code_challenge={challenge}\
         &code_challenge_method={method}&nonce=n-abc"
    )
}

/// Run a valid `/authorize` (with an established login session, since `/authorize` now
/// gates on one) and return the issued (code, state).
async fn authorize_ok(state: &AppState) -> (String, String) {
    // Establish a session for the seeded admin and carry its signed cookie.
    let session_cookie = keystone::auth::create_session(state, "u_admin", "test-agent", "127.0.0.1").await;
    let req = Request::builder()
        .uri(authorize_uri(CHALLENGE, "S256"))
        .header(header::COOKIE, format!("__Host-session={session_cookie}"))
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = call(state, req).await;
    assert_eq!(status, StatusCode::FOUND, "authorize should 302");
    let location = headers
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        location.starts_with(REDIRECT_URI),
        "redirect to registered URI"
    );
    parse_redirect(&location)
}

fn parse_redirect(location: &str) -> (String, String) {
    let query = location.split_once('?').expect("redirect has query").1;
    let (mut code, mut state) = (String::new(), String::new());
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "code" => code = v.to_string(),
                "state" => state = v.to_string(),
                _ => {}
            }
        }
    }
    (code, state)
}

fn token_request(code: &str, redirect_uri: &str, verifier: &str) -> Request<Body> {
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={redirect_uri}\
         &client_id={CLIENT_ID}&code_verifier={verifier}"
    );
    Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

// ----------------------------------------------------------------------------
// CENTERPIECE: full /authorize -> 302 -> /token -> verify -> /userinfo
// ----------------------------------------------------------------------------
#[tokio::test]
async fn full_authorization_code_pkce_flow() {
    let state = keystone::build_dev_state();

    // /authorize -> 302 with code + preserved state.
    let (code, returned_state) = authorize_ok(&state).await;
    assert!(!code.is_empty(), "code present");
    assert_eq!(returned_state, "xyz123", "state preserved");

    // /token -> 200 JSON token response.
    let (status, _, body) = call(&state, token_request(&code, REDIRECT_URI, VERIFIER)).await;
    assert_eq!(status, StatusCode::OK, "token exchange should succeed");
    let tok: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(tok["token_type"], "Bearer");
    assert_eq!(tok["expires_in"], 3600);
    assert_eq!(tok["scope"], "openid email profile");
    let access_token = tok["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    let id_token = tok["id_token"].as_str().expect("id_token").to_string();

    // Fetch JWKS and build the SAME verifier Sluice uses.
    let (_, _, jwks_body) = call(&state, get("/jwks.json")).await;
    let jwks: Value = serde_json::from_slice(&jwks_body).unwrap();
    let key = &jwks["keys"][0];
    let kid = key["kid"].as_str().unwrap();
    let decoding =
        DecodingKey::from_rsa_components(key["n"].as_str().unwrap(), key["e"].as_str().unwrap())
            .unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[CLIENT_ID]);

    // access_token: verify signature + claims + header.kid == jwks.kid.
    let access = decode::<Value>(&access_token, &decoding, &validation).unwrap();
    assert_eq!(access.header.kid.as_deref(), Some(kid));
    assert_eq!(access.claims["iss"], ISSUER);
    assert_eq!(access.claims["aud"], CLIENT_ID);
    assert_eq!(access.claims["sub"], "u_admin");

    // id_token: same checks + email + nonce.
    let id = decode::<Value>(&id_token, &decoding, &validation).unwrap();
    assert_eq!(id.header.kid.as_deref(), Some(kid));
    assert_eq!(id.claims["sub"], "u_admin");
    assert_eq!(id.claims["email"], "admin@holdfast.local");
    assert_eq!(id.claims["nonce"], "n-abc");

    // /userinfo with the access_token -> {sub, email}.
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
async fn healthz_ok() {
    let state = keystone::build_dev_state();
    let (status, _, body) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"ok");
}

#[tokio::test]
async fn discovery_document() {
    let state = keystone::build_dev_state();
    let (status, _, body) = call(&state, get("/.well-known/openid-configuration")).await;
    assert_eq!(status, StatusCode::OK);
    let d: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(d["issuer"], ISSUER);
    assert_eq!(d["authorization_endpoint"], format!("{ISSUER}/authorize"));
    assert_eq!(d["token_endpoint"], format!("{ISSUER}/token"));
    assert_eq!(d["userinfo_endpoint"], format!("{ISSUER}/userinfo"));
    assert_eq!(d["jwks_uri"], format!("{ISSUER}/jwks.json"));
    assert_eq!(d["response_types_supported"], serde_json::json!(["code"]));
    assert_eq!(
        d["grant_types_supported"],
        serde_json::json!(["authorization_code"])
    );
    assert_eq!(
        d["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
    assert_eq!(
        d["id_token_signing_alg_values_supported"],
        serde_json::json!(["RS256"])
    );
    assert_eq!(d["subject_types_supported"], serde_json::json!(["public"]));
    assert!(d["scopes_supported"].is_array());
}

#[tokio::test]
async fn jwks_shape_and_kid_matches_token_header() {
    let state = keystone::build_dev_state();
    let (status, _, body) = call(&state, get("/jwks.json")).await;
    assert_eq!(status, StatusCode::OK);
    let jwks: Value = serde_json::from_slice(&body).unwrap();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "exactly one key");
    let k = &keys[0];
    assert_eq!(k["kty"], "RSA");
    assert_eq!(k["use"], "sig");
    assert_eq!(k["alg"], "RS256");
    let kid = k["kid"].as_str().unwrap();
    assert!(!kid.is_empty());
    assert!(!k["n"].as_str().unwrap().is_empty());
    assert!(!k["e"].as_str().unwrap().is_empty());

    // kid equals the kid in an issued token header.
    let token =
        keystone::jwt::sign_access(&state.keys, &state.config, "u_admin", CLIENT_ID, "openid")
            .unwrap();
    let header = decode_header(&token).unwrap();
    assert_eq!(header.kid.as_deref(), Some(kid));
}

#[tokio::test]
async fn token_wrong_verifier_is_invalid_grant() {
    let state = keystone::build_dev_state();
    let (code, _) = authorize_ok(&state).await;
    let (status, _, body) =
        call(&state, token_request(&code, REDIRECT_URI, "wrong-verifier")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let e: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(e["error"], "invalid_grant");
}

#[tokio::test]
async fn token_replay_is_invalid_grant() {
    let state = keystone::build_dev_state();
    let (code, _) = authorize_ok(&state).await;
    let (first, _, _) = call(&state, token_request(&code, REDIRECT_URI, VERIFIER)).await;
    assert_eq!(first, StatusCode::OK);
    // Replay the same single-use code.
    let (status, _, body) = call(&state, token_request(&code, REDIRECT_URI, VERIFIER)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let e: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(e["error"], "invalid_grant");
}

#[tokio::test]
async fn token_redirect_uri_mismatch_is_invalid_grant() {
    let state = keystone::build_dev_state();
    let (code, _) = authorize_ok(&state).await;
    let (status, _, body) = call(
        &state,
        token_request(&code, "http://127.0.0.1:9090/other", VERIFIER),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let e: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(e["error"], "invalid_grant");
}

#[tokio::test]
async fn authorize_unknown_client_is_400_no_redirect() {
    let state = keystone::build_dev_state();
    let uri = format!(
        "/authorize?response_type=code&client_id=ghost&redirect_uri={REDIRECT_URI}\
         &scope=openid&state=s&code_challenge={CHALLENGE}&code_challenge_method=S256"
    );
    let (status, headers, body) = call(&state, get(&uri)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(headers.get(header::LOCATION).is_none(), "must not redirect");
    let e: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(e["error"], "invalid_client");
}

#[tokio::test]
async fn authorize_unregistered_redirect_is_400_no_redirect() {
    let state = keystone::build_dev_state();
    let uri = format!(
        "/authorize?response_type=code&client_id={CLIENT_ID}\
         &redirect_uri=http://evil.example/cb&scope=openid&state=s\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    );
    let (status, headers, body) = call(&state, get(&uri)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(headers.get(header::LOCATION).is_none(), "must not redirect");
    let e: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(e["error"], "invalid_client");
}

#[tokio::test]
async fn authorize_missing_pkce_is_invalid_request() {
    let state = keystone::build_dev_state();
    let uri = format!(
        "/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}\
         &scope=openid&state=s"
    );
    let (status, _, body) = call(&state, get(&uri)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let e: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(e["error"], "invalid_request");
}

#[tokio::test]
async fn authorize_non_s256_method_is_invalid_request() {
    let state = keystone::build_dev_state();
    let (status, _, body) = call(&state, get(&authorize_uri(CHALLENGE, "plain"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let e: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(e["error"], "invalid_request");
}

#[tokio::test]
async fn userinfo_without_token_is_401_with_www_authenticate() {
    let state = keystone::build_dev_state();
    let (status, headers, _) = call(&state, get("/userinfo")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers.get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer",
        "401 carries WWW-Authenticate: Bearer"
    );
}

#[tokio::test]
async fn userinfo_with_garbage_token_is_401() {
    let state = keystone::build_dev_state();
    let req = Request::builder()
        .uri("/userinfo")
        .header(header::AUTHORIZATION, "Bearer not-a-jwt")
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = call(&state, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.get(header::WWW_AUTHENTICATE).is_some());
}
