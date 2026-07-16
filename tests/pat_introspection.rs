//! PAT introspection contract tests (in-process via `tower::oneshot`).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use keystone::store::{new_opaque_code, PersonalAccessToken, PgStore, Store, StoreError};
use keystone::{now_secs, AppState};
use serde_json::{json, Value};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tower::ServiceExt;

const GW_CLIENT_ID: &str = "sluice-gw";
const GW_CLIENT_SECRET: &str = "test-gateway-secret";

fn configured_state() -> AppState {
    let mut state = keystone::build_dev_state();
    let mut config = state.config.as_ref().clone();
    config.gw_client_id = GW_CLIENT_ID.to_string();
    config.gw_client_secret = Some(GW_CLIENT_SECRET.to_string());
    state.config = Arc::new(config);
    state
}

async fn put_pat(
    state: &AppState,
    plaintext: &str,
    expires_at: u64,
    revoked_at: u64,
) -> PersonalAccessToken {
    let token = PersonalAccessToken {
        id: new_opaque_code(),
        user_sub: "u_admin".to_string(),
        name: "corvid test".to_string(),
        token_hash: keystone::auth::secret_hash(plaintext),
        scopes: "profile corvid:temp-mail:delete".to_string(),
        created_at: now_secs(),
        expires_at,
        revoked_at,
    };
    state
        .store
        .put_personal_token(token.clone())
        .await
        .expect("store PAT fixture");
    token
}

fn request(token: &str, client_id: &str, secret: &str) -> Request<Body> {
    let basic = BASE64_STANDARD.encode(format!("{client_id}:{secret}"));
    Request::builder()
        .method("POST")
        .uri("/internal/v1/pats/introspect")
        .header(header::AUTHORIZATION, format!("Basic {basic}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("token={token}")))
        .unwrap()
}

async fn call_raw(state: &AppState, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = keystone::app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

async fn call(state: &AppState, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let (status, headers, body) = call_raw(state, request).await;
    let body = serde_json::from_slice(&body).unwrap();
    (status, headers, body)
}

fn assert_no_store(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("private, no-store")
    );
    assert_eq!(
        headers.get(header::VARY).and_then(|v| v.to_str().ok()),
        Some("Authorization")
    );
}

#[tokio::test]
async fn in_memory_lookup_is_authoritative_for_lifecycle_and_user_state() {
    let state = configured_state();
    let now = now_secs();
    let plaintext = format!("pat_{}", new_opaque_code());
    let mut token = put_pat(&state, &plaintext, now + 300, 0).await;
    let hash = keystone::auth::secret_hash(&plaintext);

    let active = state
        .store
        .find_active_personal_token(&hash, now)
        .await
        .unwrap()
        .expect("active token");
    assert_eq!(active.id, token.id);
    assert!(state
        .store
        .find_active_personal_token("not-a-token-hash", now)
        .await
        .unwrap()
        .is_none());

    token.revoked_at = now;
    state
        .store
        .put_personal_token(token.clone())
        .await
        .expect("store revoked PAT fixture");
    assert!(state
        .store
        .find_active_personal_token(&hash, now)
        .await
        .unwrap()
        .is_none());

    token.revoked_at = 0;
    token.expires_at = now;
    state
        .store
        .put_personal_token(token.clone())
        .await
        .expect("store expired PAT fixture");
    assert!(state
        .store
        .find_active_personal_token(&hash, now)
        .await
        .unwrap()
        .is_none());

    token.expires_at = now + 300;
    state
        .store
        .put_personal_token(token)
        .await
        .expect("restore active PAT fixture");
    state.store.set_disabled("u_admin", true).await;
    assert!(state
        .store
        .find_active_personal_token(&hash, now)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn active_pat_returns_minimal_authoritative_metadata_without_caching() {
    let state = configured_state();
    let plaintext = format!("pat_{}", new_opaque_code());
    let expires_at = now_secs() + 300;
    put_pat(&state, &plaintext, expires_at, 0).await;

    let (status, headers, body) =
        call(&state, request(&plaintext, GW_CLIENT_ID, GW_CLIENT_SECRET)).await;
    assert_eq!(status, StatusCode::OK);
    assert_no_store(&headers);
    assert_eq!(
        body,
        json!({
            "active": true,
            "sub": "u_admin",
            "scope": "profile corvid:temp-mail:delete",
            "exp": expires_at,
            "token_type": "Bearer"
        })
    );
    assert!(!body.to_string().contains(&plaintext));
    assert!(!body
        .to_string()
        .contains(&keystone::auth::secret_hash(&plaintext)));
}

#[tokio::test]
async fn wrong_basic_is_401_and_unconfigured_gateway_is_503() {
    let state = configured_state();
    let plaintext = format!("pat_{}", new_opaque_code());
    put_pat(&state, &plaintext, now_secs() + 300, 0).await;

    for (client_id, secret) in [
        ("wrong-client", GW_CLIENT_SECRET),
        (GW_CLIENT_ID, "wrong-secret"),
    ] {
        let (status, headers, body) = call(&state, request(&plaintext, client_id, secret)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_no_store(&headers);
        assert_eq!(body, json!({ "error": "invalid_client" }));
        assert_eq!(
            headers
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Basic realm=\"keystone-pat-introspection\"")
        );
    }

    let mut missing_basic = request(&plaintext, GW_CLIENT_ID, GW_CLIENT_SECRET);
    missing_basic.headers_mut().remove(header::AUTHORIZATION);
    let (status, headers, body) = call(&state, missing_basic).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_no_store(&headers);
    assert_eq!(body, json!({ "error": "invalid_client" }));

    let state = keystone::build_dev_state();
    let (status, headers, body) =
        call(&state, request(&plaintext, GW_CLIENT_ID, GW_CLIENT_SECRET)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_no_store(&headers);
    assert_eq!(body, json!({ "error": "temporarily_unavailable" }));
}

#[tokio::test]
async fn invalid_revoked_expired_and_disabled_are_uniformly_inactive() {
    let state = configured_state();
    let now = now_secs();

    let invalid_tokens = [
        "not-a-pat".to_string(),
        "pat_".to_string(),
        format!(
            "pat_{}",
            "x".repeat(keystone::handlers::introspect::MAX_PAT_TOKEN_LEN)
        ),
        format!("pat_{}", new_opaque_code()),
    ];
    for plaintext in invalid_tokens {
        let (status, headers, body) =
            call(&state, request(&plaintext, GW_CLIENT_ID, GW_CLIENT_SECRET)).await;
        assert_eq!(status, StatusCode::OK);
        assert_no_store(&headers);
        assert_eq!(body, json!({ "active": false }));
    }

    let revoked = format!("pat_{}", new_opaque_code());
    put_pat(&state, &revoked, now + 300, now).await;
    let expired = format!("pat_{}", new_opaque_code());
    put_pat(&state, &expired, now, 0).await;
    let disabled = format!("pat_{}", new_opaque_code());
    put_pat(&state, &disabled, now + 300, 0).await;
    state.store.set_disabled("u_admin", true).await;

    for plaintext in [revoked, expired, disabled] {
        let (status, headers, body) =
            call(&state, request(&plaintext, GW_CLIENT_ID, GW_CLIENT_SECRET)).await;
        assert_eq!(status, StatusCode::OK);
        assert_no_store(&headers);
        assert_eq!(body, json!({ "active": false }));
    }
}

#[tokio::test]
async fn database_failure_is_503_not_inactive() {
    let mut state = configured_state();
    let options = PgConnectOptions::new()
        .host("127.0.0.1")
        .port(1)
        .username("keystone")
        .database("keystone");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy_with(options);
    state.store = Arc::new(PgStore::from_pool(pool));

    let plaintext = format!("pat_{}", new_opaque_code());
    let (status, headers, body) =
        call(&state, request(&plaintext, GW_CLIENT_ID, GW_CLIENT_SECRET)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_no_store(&headers);
    assert_eq!(body, json!({ "error": "temporarily_unavailable" }));
}

#[tokio::test]
async fn pg_pat_write_failures_are_explicit() {
    let options = PgConnectOptions::new()
        .host("127.0.0.1")
        .port(1)
        .username("keystone")
        .database("keystone");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy_with(options);
    let store = PgStore::from_pool(pool);
    let token = PersonalAccessToken {
        id: new_opaque_code(),
        user_sub: "u_admin".to_string(),
        name: "unreachable database".to_string(),
        token_hash: keystone::auth::secret_hash("pat_unreachable_database_fixture"),
        scopes: "corvid:temp-mail:delete".to_string(),
        created_at: now_secs(),
        expires_at: now_secs() + 300,
        revoked_at: 0,
    };

    assert_eq!(
        store.put_personal_token(token.clone()).await,
        Err(StoreError::Backend)
    );
    assert_eq!(
        store
            .revoke_personal_token(&token.user_sub, &token.id, now_secs())
            .await,
        Err(StoreError::Backend)
    );
}

#[tokio::test]
async fn extractor_rejections_are_also_private_and_not_cacheable() {
    let state = configured_state();
    let basic = BASE64_STANDARD.encode(format!("{GW_CLIENT_ID}:{GW_CLIENT_SECRET}"));

    let oversized = Request::builder()
        .method("POST")
        .uri("/internal/v1/pats/introspect")
        .header(header::AUTHORIZATION, format!("Basic {basic}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("x".repeat(
            keystone::handlers::introspect::MAX_INTROSPECTION_FORM_LEN + 1,
        )))
        .unwrap();
    let (status, headers, _) = call_raw(&state, oversized).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_no_store(&headers);

    let wrong_content_type = Request::builder()
        .method("POST")
        .uri("/internal/v1/pats/introspect")
        .header(header::AUTHORIZATION, format!("Basic {basic}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"token":"pat_x"}"#))
        .unwrap();
    let (status, headers, _) = call_raw(&state, wrong_content_type).await;
    assert!(status.is_client_error());
    assert_no_store(&headers);
}
