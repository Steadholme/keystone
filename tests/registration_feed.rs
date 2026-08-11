//! Keystone registration-authority feed contract tests.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use hmac::{Hmac, Mac};
use keystone::store::{
    InMemoryStore, PgStore, RegistrationAckCommand, RegistrationFeedError, RegistrationState,
    Store, SubjectLifecycleCommand, SubjectLifecycleState, VerificationToken,
};
use keystone::{now_secs, AppState};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use tower::ServiceExt;

const CURRENT_KID: &str = "reg-current-1";
const CURRENT_KEY: &str = "current-registration-mac-key-0000000000000001";
const PREVIOUS_KID: &str = "reg-previous-1";
const PREVIOUS_KEY: &str = "previous-registration-mac-key-00000000000001";
const CONSUMER: &str = "access-governance-registration-v1";

type HmacSha256 = Hmac<Sha256>;

fn configured_memory_state() -> (AppState, Arc<InMemoryStore>) {
    let mut state = keystone::build_dev_state();
    let store = Arc::new(InMemoryStore::new());
    state.store = store.clone();
    let mut config = state.config.as_ref().clone();
    config.internal_tls = true;
    config.registration_mac_kid = Some(CURRENT_KID.to_string());
    config.registration_mac_key = Some(CURRENT_KEY.to_string());
    config.registration_previous_mac_kid = Some(PREVIOUS_KID.to_string());
    config.registration_previous_mac_key = Some(PREVIOUS_KEY.to_string());
    state.config = Arc::new(config);
    (state, store)
}

fn sha256_hex(value: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(value) {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn sorted_raw_query(uri: &Uri) -> String {
    let Some(query) = uri.query().filter(|query| !query.is_empty()) else {
        return String::new();
    };
    let mut fields: Vec<&str> = query.split('&').collect();
    fields.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    fields.join("&")
}

#[allow(clippy::too_many_arguments)]
fn mac_hex_for_identity(
    service: &str,
    audience: &str,
    method: &Method,
    canonical_uri: &str,
    body: &[u8],
    kid: &str,
    key: &str,
    timestamp: u64,
    nonce: &str,
) -> String {
    let uri: Uri = canonical_uri.parse().unwrap();
    let canonical = format!(
        "regfeed-v1\n{service}\n{audience}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        uri.path(),
        sorted_raw_query(&uri),
        sha256_hex(body),
        kid,
        timestamp,
        nonce,
    );
    assert!(!canonical.ends_with('\n'));
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(canonical.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in mac.finalize().into_bytes() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn mac_hex(
    method: &Method,
    canonical_uri: &str,
    body: &[u8],
    kid: &str,
    key: &str,
    timestamp: u64,
    nonce: &str,
) -> String {
    mac_hex_for_identity(
        "access-governance",
        "keystone-registration",
        method,
        canonical_uri,
        body,
        kid,
        key,
        timestamp,
        nonce,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_request(
    method: Method,
    request_uri: &str,
    canonical_uri: &str,
    body: &[u8],
    kid: &str,
    key: &str,
    timestamp: u64,
    nonce: &str,
) -> Request<Body> {
    let mac = mac_hex(&method, canonical_uri, body, kid, key, timestamp, nonce);
    Request::builder()
        .method(method)
        .uri(request_uri)
        .header(
            "X-Keystone-RegSig",
            format!("kid={kid},ts={timestamp},nonce={nonce},mac={mac}"),
        )
        .body(Body::from(body.to_vec()))
        .unwrap()
}

fn with_snapshot_ack_evidence_v2(mut request: Request<Body>) -> Request<Body> {
    request.headers_mut().insert(
        HeaderName::from_static("x-keystone-registration-feed-version"),
        HeaderValue::from_static("2"),
    );
    request
}

#[allow(clippy::too_many_arguments)]
fn signed_request_for_identity(
    service: &str,
    audience: &str,
    method: Method,
    request_uri: &str,
    canonical_uri: &str,
    body: &[u8],
    kid: &str,
    key: &str,
    timestamp: u64,
    nonce: &str,
) -> Request<Body> {
    let mac = mac_hex_for_identity(
        service,
        audience,
        &method,
        canonical_uri,
        body,
        kid,
        key,
        timestamp,
        nonce,
    );
    Request::builder()
        .method(method)
        .uri(request_uri)
        .header(
            "X-Keystone-RegSig",
            format!("kid={kid},ts={timestamp},nonce={nonce},mac={mac}"),
        )
        .body(Body::from(body.to_vec()))
        .unwrap()
}

async fn call(state: &AppState, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let response = keystone::app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).expect("registration endpoint returns JSON");
    (status, headers, body)
}

fn assert_private(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("private, no-store")
    );
    assert_eq!(
        headers
            .get(header::VARY)
            .and_then(|value| value.to_str().ok()),
        Some("X-Keystone-RegSig, X-Keystone-Registration-Feed-Version")
    );
}

fn nonce(value: u128) -> String {
    format!("{value:032x}")
}

#[tokio::test]
async fn identity_mutations_export_full_state_and_mask_lifecycle_echo() {
    let store = InMemoryStore::new();
    let subject = "registration-state-machine";
    let verification = VerificationToken {
        token: "registration-verify-token".to_string(),
        sub: subject.to_string(),
        kind: "verify".to_string(),
        expires_at: now_secs() + 300,
    };
    store
        .create_user_with_verification_token(
            subject,
            "registration-state-machine@example.test",
            "test-password-hash",
            now_secs(),
            verification.clone(),
        )
        .await
        .unwrap();

    let immutable = store.create_registration_snapshot().await.unwrap();
    assert_eq!(immutable.generation, 1);
    assert_eq!(immutable.high_watermark, 1);
    assert_eq!(immutable.count, 1);
    let initial_event = store
        .get_registration_changes(0, 1)
        .await
        .unwrap()
        .events
        .pop()
        .unwrap();
    assert_eq!(immutable.high_watermark_event_id, initial_event.event_id);
    assert_eq!(
        immutable.high_watermark_payload_hash,
        initial_event.payload_hash
    );
    let immutable_page = store
        .get_registration_snapshot_page(&immutable.snapshot_id, 0, 1)
        .await
        .unwrap();
    assert_eq!(
        immutable_page.high_watermark_event_id,
        immutable.high_watermark_event_id
    );
    assert_eq!(
        immutable_page.high_watermark_payload_hash,
        immutable.high_watermark_payload_hash
    );
    assert_eq!(immutable_page.rows[0].ordinal, 1);
    assert_eq!(
        immutable_page.rows[0].registration_state,
        RegistrationState::Unverified
    );
    let row = &immutable_page.rows[0];
    let canonical = format!(
        "registration-snapshot-v1\n1\nR\t1\t{}\t1\tunverified\t0\t1\t{}",
        row.subject, row.payload_hash
    );
    assert_eq!(immutable.digest, sha256_hex(canonical.as_bytes()));

    assert_eq!(
        store
            .consume_verification_token_and_verify(&verification.token)
            .await
            .unwrap(),
        Some(subject.to_string())
    );
    let before_lifecycle = store.get_registration_changes(0, 500).await.unwrap();
    assert_eq!(before_lifecycle.events.len(), 2);

    store
        .apply_subject_lifecycle(SubjectLifecycleCommand {
            subject: subject.to_string(),
            state: SubjectLifecycleState::Frozen,
            source_event_id: "registration-lifecycle-frozen-1".to_string(),
            source_version: 1,
            correlation_id: "registration-lifecycle-correlation-1".to_string(),
        })
        .await
        .unwrap();
    let after_lifecycle = store.get_registration_changes(0, 500).await.unwrap();
    assert_eq!(
        after_lifecycle.events, before_lifecycle.events,
        "Access lifecycle echo must not bump registration version or emit"
    );
    assert!(store.get_user(subject).await.unwrap().disabled);

    let lifecycle_snapshot = store.create_registration_snapshot().await.unwrap();
    let lifecycle_page = store
        .get_registration_snapshot_page(&lifecycle_snapshot.snapshot_id, 0, 10)
        .await
        .unwrap();
    assert_eq!(
        lifecycle_page.rows[0].registration_state,
        RegistrationState::Registered
    );
    assert!(lifecycle_page.rows[0].enabled);
    assert_eq!(lifecycle_page.rows[0].account_version, 2);

    let disabled = store.set_disabled(subject, true).await.unwrap();
    assert!(disabled.changed);
    assert_eq!(disabled.registration_state, RegistrationState::Disabled);
    assert!(disabled.login_disabled);
    assert!(disabled.lifecycle_blocked);

    let enabled = store.set_disabled(subject, false).await.unwrap();
    assert!(enabled.changed);
    assert_eq!(enabled.registration_state, RegistrationState::Registered);
    assert!(
        enabled.login_disabled,
        "independent lifecycle fence still blocks login"
    );
    assert!(enabled.lifecycle_blocked);

    assert!(store.set_email_unverified(subject).await.unwrap());
    assert!(store.set_email_verified(subject).await.unwrap());
    assert!(store.delete_user(subject).await.unwrap());

    let page = store.get_registration_changes(0, 500).await.unwrap();
    assert_eq!(page.generation, 1);
    assert_eq!(page.head_cursor, 7);
    assert_eq!(page.retention_floor_cursor, 0);
    let states: Vec<_> = page
        .events
        .iter()
        .map(|event| event.registration_state)
        .collect();
    assert_eq!(
        states,
        vec![
            RegistrationState::Unverified,
            RegistrationState::Registered,
            RegistrationState::Disabled,
            RegistrationState::Registered,
            RegistrationState::Unverified,
            RegistrationState::Registered,
            RegistrationState::Deleted,
        ]
    );
    for (index, event) in page.events.iter().enumerate() {
        assert_eq!(event.cursor, (index + 1) as u64);
        assert_eq!(event.account_version, (index + 1) as u64);
        assert_eq!(event.payload_hash.len(), 64);
    }

    let old_page = store
        .get_registration_snapshot_page(&immutable.snapshot_id, 0, 10)
        .await
        .unwrap();
    assert_eq!(old_page.rows, immutable_page.rows);
    assert_eq!(old_page.digest, immutable.digest);

    let deleted_snapshot = store.create_registration_snapshot().await.unwrap();
    let deleted_page = store
        .get_registration_snapshot_page(&deleted_snapshot.snapshot_id, 0, 10)
        .await
        .unwrap();
    assert_eq!(deleted_page.rows.len(), 1);
    assert_eq!(
        deleted_page.rows[0].registration_state,
        RegistrationState::Deleted
    );
    assert_eq!(deleted_page.rows[0].account_version, 7);

    let last = page.events.last().unwrap().clone();
    let accepted = store
        .acknowledge_registration(RegistrationAckCommand {
            consumer: CONSUMER.to_string(),
            generation: page.generation,
            acked_cursor: last.cursor,
            event_id: last.event_id.clone(),
            payload_hash: last.payload_hash.clone(),
        })
        .await
        .unwrap();
    assert_eq!(accepted.stored_cursor, last.cursor);
    assert!(store
        .acknowledge_registration(RegistrationAckCommand {
            consumer: CONSUMER.to_string(),
            generation: page.generation,
            acked_cursor: last.cursor,
            event_id: last.event_id.clone(),
            payload_hash: last.payload_hash.clone(),
        })
        .await
        .is_ok());
    let previous = &page.events[page.events.len() - 2];
    assert_eq!(
        store
            .acknowledge_registration(RegistrationAckCommand {
                consumer: CONSUMER.to_string(),
                generation: page.generation,
                acked_cursor: previous.cursor,
                event_id: previous.event_id.clone(),
                payload_hash: previous.payload_hash.clone(),
            })
            .await,
        Err(RegistrationFeedError::AckRegression)
    );
    assert_eq!(
        store
            .acknowledge_registration(RegistrationAckCommand {
                consumer: CONSUMER.to_string(),
                generation: page.generation + 1,
                acked_cursor: last.cursor,
                event_id: last.event_id.clone(),
                payload_hash: last.payload_hash.clone(),
            })
            .await,
        Err(RegistrationFeedError::AckGenerationConflict)
    );
}

#[tokio::test]
async fn signed_wire_accepts_rotation_and_rejects_tamper_stale_and_replay() {
    let (state, _) = configured_memory_state();
    let now = now_secs();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/internal/v1/identity/registration/snapshot")
        .body(Body::empty())
        .unwrap();
    let (status, headers, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error":"malformed_sig"}));
    assert_private(&headers);

    let first_nonce = nonce(1);
    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &first_nonce,
    );
    let (status, headers, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["generation"], 1);
    assert_eq!(body["high_watermark"], 0);
    assert_eq!(body["count"], 0);
    assert_eq!(body["acked_nonce"], first_nonce);
    assert!(body.get("high_watermark_event_id").is_none());
    assert!(body.get("high_watermark_payload_hash").is_none());
    assert_private(&headers);

    let v2_nonce = nonce(1_000);
    let request = with_snapshot_ack_evidence_v2(signed_request(
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &v2_nonce,
    ));
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["high_watermark_event_id"], "");
    assert_eq!(body["high_watermark_payload_hash"], "");
    assert_eq!(body["acked_nonce"], v2_nonce);

    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &nonce(1),
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"replay","acked_nonce":nonce(1)}));

    let previous_nonce = nonce(2);
    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        &[],
        PREVIOUS_KID,
        PREVIOUS_KEY,
        now,
        &previous_nonce,
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["acked_nonce"], previous_nonce);

    let request = signed_request(
        Method::GET,
        "/internal/v1/identity/registration/changes?after=0&limit=1",
        "/internal/v1/identity/registration/changes?after=1&limit=1",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &nonce(3),
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"bad_mac"}));

    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/changes",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &nonce(9),
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"bad_mac"}));

    let mut request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &nonce(10),
    );
    *request.body_mut() = Body::from("{}");
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"bad_mac"}));

    let request = signed_request_for_identity(
        "access-governance",
        "wrong-registration-audience",
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &nonce(11),
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"bad_mac"}));

    let request = signed_request_for_identity(
        "wrong-access-service",
        "keystone-registration",
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &nonce(12),
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"bad_mac"}));

    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        b"{}",
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &nonce(4),
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({"error":"invalid_request","acked_nonce":nonce(4)})
    );

    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        &[],
        "unknown-kid",
        CURRENT_KEY,
        now,
        &nonce(5),
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"unknown_kid"}));

    let stale = now.saturating_sub(61);
    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        stale,
        &nonce(6),
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"stale"}));

    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        &[],
        CURRENT_KID,
        "different-registration-mac-key-000000000000001",
        now,
        &nonce(7),
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"bad_mac"}));

    let mut plaintext_state = state.clone();
    let mut config = plaintext_state.config.as_ref().clone();
    config.internal_tls = false;
    plaintext_state.config = Arc::new(config);
    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &nonce(8),
    );
    let (status, headers, body) = call(&plaintext_state, request).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({"error":"registration_feed_unavailable"}));
    assert_private(&headers);
}

#[tokio::test]
async fn ack_wire_uses_cursor_and_returns_nonce_on_authenticated_errors() {
    let (state, store) = configured_memory_state();
    store
        .create_user(
            "registration-wire",
            "registration-wire@example.test",
            "test-password-hash",
            now_secs(),
        )
        .await
        .unwrap();
    store.set_email_verified("registration-wire").await.unwrap();
    let page = store.get_registration_changes(0, 10).await.unwrap();
    let first = &page.events[0];
    let last = &page.events[1];
    let now = now_secs();

    let snapshot_nonce = nonce(2_000);
    let request = with_snapshot_ack_evidence_v2(signed_request(
        Method::POST,
        "/internal/v1/identity/registration/snapshot",
        "/internal/v1/identity/registration/snapshot",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &snapshot_nonce,
    ));
    let (status, _, snapshot) = call(&state, request).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(snapshot["high_watermark"], last.cursor);
    assert_eq!(snapshot["high_watermark_event_id"], last.event_id);
    assert_eq!(snapshot["high_watermark_payload_hash"], last.payload_hash);
    let snapshot_id = snapshot["snapshot_id"].as_str().unwrap();
    let page_uri = format!(
        "/internal/v1/identity/registration/snapshot/{snapshot_id}?after_ordinal=0&limit=10"
    );
    let page_nonce = nonce(2_001);
    let request = with_snapshot_ack_evidence_v2(signed_request(
        Method::GET,
        &page_uri,
        &page_uri,
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &page_nonce,
    ));
    let (status, _, snapshot_page) = call(&state, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(snapshot_page["high_watermark_event_id"], last.event_id);
    assert_eq!(
        snapshot_page["high_watermark_payload_hash"],
        last.payload_hash
    );
    assert_eq!(snapshot_page["acked_nonce"], page_nonce);

    let changes_nonce = nonce(20);
    let request = signed_request(
        Method::GET,
        "/internal/v1/identity/registration/changes?limit=10&after=0",
        "/internal/v1/identity/registration/changes?limit=10&after=0",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &changes_nonce,
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["generation"], page.generation);
    assert_eq!(body["events"][1]["cursor"], last.cursor);
    assert_eq!(body["acked_nonce"], changes_nonce);

    let old_wire_nonce = nonce(21);
    let old_wire = serde_json::to_vec(&json!({
        "consumer": CONSUMER,
        "generation": page.generation,
        "acked_cursor": last.cursor,
        "event_id": last.event_id,
        "payload_hash": last.payload_hash,
    }))
    .unwrap();
    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/ack",
        "/internal/v1/identity/registration/ack",
        &old_wire,
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &old_wire_nonce,
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({"error":"invalid_request","acked_nonce":old_wire_nonce})
    );

    let ack_nonce = nonce(22);
    let ack = serde_json::to_vec(&json!({
        "consumer": CONSUMER,
        "generation": page.generation,
        "cursor": last.cursor,
        "event_id": last.event_id,
        "payload_hash": last.payload_hash,
    }))
    .unwrap();
    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/ack",
        "/internal/v1/identity/registration/ack",
        &ack,
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &ack_nonce,
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["consumer"], CONSUMER);
    assert_eq!(body["generation"], page.generation);
    assert_eq!(body["stored_cursor"], last.cursor);
    assert_eq!(body["acked_nonce"], ack_nonce);

    let regression_nonce = nonce(23);
    let regression = serde_json::to_vec(&json!({
        "consumer": CONSUMER,
        "generation": page.generation,
        "cursor": first.cursor,
        "event_id": first.event_id,
        "payload_hash": first.payload_hash,
    }))
    .unwrap();
    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/ack",
        "/internal/v1/identity/registration/ack",
        &regression,
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &regression_nonce,
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body,
        json!({"error":"ack_regression","acked_nonce":regression_nonce})
    );

    let generation_nonce = nonce(24);
    let wrong_generation = serde_json::to_vec(&json!({
        "consumer": CONSUMER,
        "generation": page.generation + 1,
        "cursor": last.cursor,
        "event_id": last.event_id,
        "payload_hash": last.payload_hash,
    }))
    .unwrap();
    let request = signed_request(
        Method::POST,
        "/internal/v1/identity/registration/ack",
        "/internal/v1/identity/registration/ack",
        &wrong_generation,
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &generation_nonce,
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body,
        json!({"error":"ack_generation_conflict","acked_nonce":generation_nonce})
    );

    let gap_nonce = nonce(25);
    let request = signed_request(
        Method::GET,
        "/internal/v1/identity/registration/changes?after=999&limit=1",
        "/internal/v1/identity/registration/changes?after=999&limit=1",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &gap_nonce,
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({"error":"feed_gap","acked_nonce":gap_nonce}));

    let snapshot_nonce = nonce(26);
    let request = signed_request(
        Method::GET,
        "/internal/v1/identity/registration/snapshot/irs_00000000000000000000000000000000?after_ordinal=0&limit=1",
        "/internal/v1/identity/registration/snapshot/irs_00000000000000000000000000000000?after_ordinal=0&limit=1",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now,
        &snapshot_nonce,
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body,
        json!({"error":"snapshot_incomplete","acked_nonce":snapshot_nonce})
    );
}

#[tokio::test]
async fn ack_and_thirty_day_floor_prune_only_a_safe_prefix_and_force_resnapshot() {
    let (state, store) = configured_memory_state();
    let old_timestamp = now_secs().saturating_sub(31 * 24 * 60 * 60);
    store
        .create_user(
            "registration-retention",
            "registration-retention@example.test",
            "test-password-hash",
            old_timestamp,
        )
        .await
        .unwrap();
    let page = store.get_registration_changes(0, 10).await.unwrap();
    let event = page.events[0].clone();
    let command = RegistrationAckCommand {
        consumer: CONSUMER.to_string(),
        generation: page.generation,
        acked_cursor: event.cursor,
        event_id: event.event_id,
        payload_hash: event.payload_hash,
    };
    store
        .acknowledge_registration(command.clone())
        .await
        .unwrap();
    store
        .acknowledge_registration(command)
        .await
        .expect("exact ACK remains idempotent after its event is pruned");
    assert_eq!(
        store.get_registration_changes(0, 10).await,
        Err(RegistrationFeedError::ResnapshotRequired)
    );

    let request_nonce = nonce(30);
    let request = signed_request(
        Method::GET,
        "/internal/v1/identity/registration/changes?after=0&limit=10",
        "/internal/v1/identity/registration/changes?after=0&limit=10",
        &[],
        CURRENT_KID,
        CURRENT_KEY,
        now_secs(),
        &request_nonce,
    );
    let (status, _, body) = call(&state, request).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(
        body,
        json!({"error":"resnapshot_required","acked_nonce":request_nonce})
    );

    let current = store.get_registration_changes(1, 10).await.unwrap();
    assert_eq!(current.head_cursor, 1);
    assert_eq!(current.retention_floor_cursor, 1);
    assert!(current.events.is_empty());
}

#[tokio::test]
async fn plaintext_health_router_never_mounts_internal_feed() {
    let response = keystone::health_app()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/internal/v1/identity/registration/snapshot")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_registration_transaction_snapshot_ack_and_replay() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping registration-feed PostgreSQL test");
        return;
    };

    let pg = PgStore::connect(&url).await.expect("connect test Postgres");
    pg.migrate().await.expect("registration migration");
    pg.migrate()
        .await
        .expect("registration migration is idempotent");
    let inspect = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect inspection pool");

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let failed_sub = format!("reg_fail_{suffix}");
    let failed_email = format!("{failed_sub}@example.test");
    let function = format!("fail_registration_outbox_{suffix}");
    let trigger = format!("fail_registration_outbox_trigger_{suffix}");
    sqlx::query(&format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.subject='user:{failed_sub}' THEN \
         RAISE EXCEPTION 'forced_registration_outbox_failure'; END IF; RETURN NEW; END $$"
    ))
    .execute(&inspect)
    .await
    .expect("install scoped outbox fault function");
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT ON identity_registration_outbox \
         FOR EACH ROW EXECUTE FUNCTION {function}()"
    ))
    .execute(&inspect)
    .await
    .expect("install scoped outbox fault trigger");
    let clock_before: i64 =
        sqlx::query_scalar("SELECT next_cursor FROM identity_outbox_clock WHERE id=1")
            .fetch_one(&inspect)
            .await
            .unwrap();
    let failed = pg
        .create_user(&failed_sub, &failed_email, "test-password-hash", now_secs())
        .await;
    sqlx::query(&format!(
        "DROP TRIGGER {trigger} ON identity_registration_outbox"
    ))
    .execute(&inspect)
    .await
    .expect("remove scoped outbox fault trigger");
    sqlx::query(&format!("DROP FUNCTION {function}()"))
        .execute(&inspect)
        .await
        .expect("remove scoped outbox fault function");
    assert!(failed.is_err(), "outbox failure propagates to caller");
    let failed_user_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE sub=$1)")
            .bind(&failed_sub)
            .fetch_one(&inspect)
            .await
            .unwrap();
    assert!(!failed_user_exists, "user mutation rolled back with outbox");
    let clock_after: i64 =
        sqlx::query_scalar("SELECT next_cursor FROM identity_outbox_clock WHERE id=1")
            .fetch_one(&inspect)
            .await
            .unwrap();
    assert_eq!(
        clock_after, clock_before,
        "rolled-back TX consumes no cursor"
    );

    if clock_before == 0 {
        let old_sub = format!("reg_old_{suffix}");
        pg.create_user(
            &old_sub,
            &format!("{old_sub}@example.test"),
            "test-password-hash",
            now_secs().saturating_sub(31 * 24 * 60 * 60),
        )
        .await
        .unwrap();
        let old_event = sqlx::query(
        "SELECT cursor,event_id,payload_hash FROM identity_registration_outbox WHERE subject=$1",
    )
    .bind(format!("user:{old_sub}"))
    .fetch_one(&inspect)
    .await
    .unwrap();
        let old_cursor = u64::try_from(old_event.get::<i64, _>("cursor")).unwrap();
        let source_generation: i64 =
            sqlx::query_scalar("SELECT generation FROM identity_outbox_clock WHERE id=1")
                .fetch_one(&inspect)
                .await
                .unwrap();
        let old_ack = RegistrationAckCommand {
            consumer: format!("registration-pg-retention-{suffix}"),
            generation: u64::try_from(source_generation).unwrap(),
            acked_cursor: old_cursor,
            event_id: old_event.get("event_id"),
            payload_hash: old_event.get("payload_hash"),
        };
        pg.acknowledge_registration(old_ack.clone()).await.unwrap();
        pg.acknowledge_registration(old_ack.clone())
            .await
            .expect("exact PG ACK is idempotent after retention pruning");
        assert_eq!(
            pg.get_registration_changes(old_cursor - 1, 10).await,
            Err(RegistrationFeedError::ResnapshotRequired)
        );
        let retained = pg.get_registration_changes(old_cursor, 10).await.unwrap();
        assert_eq!(retained.retention_floor_cursor, old_cursor);
        let pruned_snapshot = pg.create_registration_snapshot().await.unwrap();
        assert_eq!(pruned_snapshot.high_watermark, old_cursor);
        assert_eq!(pruned_snapshot.high_watermark_event_id, old_ack.event_id);
        assert_eq!(
            pruned_snapshot.high_watermark_payload_hash,
            old_ack.payload_hash
        );
    } else {
        eprintln!("NOTE: retention-prefix PG assertion skipped on non-empty reusable database");
    }

    let sub = format!("reg_ok_{suffix}");
    let email = format!("{sub}@example.test");
    pg.create_user(&sub, &email, "test-password-hash", now_secs())
        .await
        .unwrap();
    pg.set_email_verified(&sub).await.unwrap();
    let events_before_lifecycle: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM identity_registration_outbox WHERE subject=$1")
            .bind(format!("user:{sub}"))
            .fetch_one(&inspect)
            .await
            .unwrap();
    assert_eq!(events_before_lifecycle, 2);
    pg.apply_subject_lifecycle(SubjectLifecycleCommand {
        subject: sub.clone(),
        state: SubjectLifecycleState::Frozen,
        source_event_id: format!("reg-pg-frozen-{suffix}"),
        source_version: 1,
        correlation_id: format!("reg-pg-correlation-{suffix}"),
    })
    .await
    .unwrap();
    let events_after_lifecycle: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM identity_registration_outbox WHERE subject=$1")
            .bind(format!("user:{sub}"))
            .fetch_one(&inspect)
            .await
            .unwrap();
    assert_eq!(events_after_lifecycle, events_before_lifecycle);

    let frozen_snapshot = pg.create_registration_snapshot().await.unwrap();
    assert!(frozen_snapshot.generation > 0);
    let frozen_watermark = sqlx::query(
        "SELECT event_id,payload_hash FROM identity_registration_outbox WHERE cursor=$1",
    )
    .bind(i64::try_from(frozen_snapshot.high_watermark).unwrap())
    .fetch_one(&inspect)
    .await
    .unwrap();
    assert_eq!(
        frozen_snapshot.high_watermark_event_id,
        frozen_watermark.get::<String, _>("event_id")
    );
    assert_eq!(
        frozen_snapshot.high_watermark_payload_hash,
        frozen_watermark.get::<String, _>("payload_hash")
    );
    let frozen_page = pg
        .get_registration_snapshot_page(&frozen_snapshot.snapshot_id, 0, 1000)
        .await
        .unwrap();
    assert_eq!(
        frozen_page.high_watermark_event_id,
        frozen_snapshot.high_watermark_event_id
    );
    assert_eq!(
        frozen_page.high_watermark_payload_hash,
        frozen_snapshot.high_watermark_payload_hash
    );
    let frozen_row = frozen_page
        .rows
        .iter()
        .find(|row| row.subject == format!("user:{sub}"))
        .expect("subject materialized in snapshot");
    assert_eq!(frozen_row.registration_state, RegistrationState::Registered);
    assert!(frozen_row.enabled, "lifecycle-owned disabled bit is masked");
    assert_eq!(frozen_row.account_version, 2);

    pg.set_disabled(&sub, true).await.unwrap();
    let enabled = pg.set_disabled(&sub, false).await.unwrap();
    assert_eq!(enabled.registration_state, RegistrationState::Registered);
    assert!(enabled.login_disabled);
    pg.set_email_unverified(&sub).await.unwrap();
    pg.set_email_verified(&sub).await.unwrap();

    let immutable = pg
        .get_registration_snapshot_page(&frozen_snapshot.snapshot_id, 0, 1000)
        .await
        .unwrap();
    let immutable_row = immutable
        .rows
        .iter()
        .find(|row| row.subject == format!("user:{sub}"))
        .unwrap();
    assert_eq!(immutable_row.account_version, 2);
    assert_eq!(immutable.digest, frozen_snapshot.digest);
    let direct_manifest_mutation = sqlx::query(
        "UPDATE identity_registration_snapshot SET high_watermark_event_id=$2 \
         WHERE snapshot_id=$1",
    )
    .bind(&frozen_snapshot.snapshot_id)
    .bind(&frozen_snapshot.high_watermark_event_id)
    .execute(&inspect)
    .await;
    assert!(
        direct_manifest_mutation.is_err(),
        "completed snapshot high-watermark evidence is immutable"
    );
    let direct_mutation = sqlx::query(
        "UPDATE identity_registration_snapshot_row SET enabled=FALSE \
         WHERE snapshot_id=$1 AND subject=$2",
    )
    .bind(&frozen_snapshot.snapshot_id)
    .bind(format!("user:{sub}"))
    .execute(&inspect)
    .await;
    assert!(
        direct_mutation.is_err(),
        "completed snapshot rows are immutable"
    );

    let legacy_snapshot_id = format!("irs_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO identity_registration_snapshot \
             (snapshot_id,generation,high_watermark,high_watermark_event_id,\
              high_watermark_payload_hash,row_count,digest,complete,created_at) \
         VALUES ($1,$2,$3,NULL,NULL,0,repeat('0',64),TRUE,$4)",
    )
    .bind(&legacy_snapshot_id)
    .bind(i64::try_from(frozen_snapshot.generation).unwrap())
    .bind(i64::try_from(frozen_snapshot.high_watermark).unwrap())
    .bind(i64::try_from(now_secs()).unwrap())
    .execute(&inspect)
    .await
    .unwrap();
    assert_eq!(
        pg.get_registration_snapshot_page(&legacy_snapshot_id, 0, 1)
            .await,
        Err(RegistrationFeedError::SnapshotIncomplete),
        "legacy snapshots without exact high-watermark evidence force resnapshot"
    );
    let partial_evidence_id = format!("irs_{}", uuid::Uuid::new_v4().simple());
    let partial_evidence = sqlx::query(
        "INSERT INTO identity_registration_snapshot \
             (snapshot_id,generation,high_watermark,high_watermark_event_id,\
              high_watermark_payload_hash,row_count,digest,complete,created_at) \
         VALUES ($1,$2,0,'',NULL,0,repeat('0',64),TRUE,$3)",
    )
    .bind(partial_evidence_id)
    .bind(i64::try_from(frozen_snapshot.generation).unwrap())
    .bind(i64::try_from(now_secs()).unwrap())
    .execute(&inspect)
    .await;
    assert!(
        partial_evidence.is_err(),
        "snapshot high-watermark evidence is an all-or-nothing pair"
    );

    let rows = sqlx::query(
        "SELECT cursor,event_id,payload_hash,account_version,registration_state \
         FROM identity_registration_outbox WHERE subject=$1 ORDER BY account_version",
    )
    .bind(format!("user:{sub}"))
    .fetch_all(&inspect)
    .await
    .unwrap();
    let versions: Vec<i64> = rows
        .iter()
        .map(|row| row.get::<i64, _>("account_version"))
        .collect();
    assert_eq!(versions, vec![1, 2, 3, 4, 5, 6]);
    let last = rows.last().unwrap();
    let ack_cursor = u64::try_from(last.get::<i64, _>("cursor")).unwrap();
    let ack_event_id: String = last.get("event_id");
    let ack_payload_hash: String = last.get("payload_hash");
    let ack = pg
        .acknowledge_registration(RegistrationAckCommand {
            consumer: format!("registration-pg-consumer-{suffix}"),
            generation: frozen_snapshot.generation,
            acked_cursor: ack_cursor,
            event_id: ack_event_id.clone(),
            payload_hash: ack_payload_hash.clone(),
        })
        .await
        .unwrap();
    assert_eq!(ack.stored_cursor, ack_cursor);
    assert_eq!(
        pg.acknowledge_registration(RegistrationAckCommand {
            consumer: format!("registration-pg-consumer-{suffix}"),
            generation: frozen_snapshot.generation + 1,
            acked_cursor: ack_cursor,
            event_id: ack_event_id,
            payload_hash: ack_payload_hash,
        })
        .await,
        Err(RegistrationFeedError::AckGenerationConflict)
    );

    let nonce_hash = sha256_hex(format!("registration-pg-nonce-{suffix}").as_bytes());
    pg.claim_registration_nonce(
        &nonce_hash,
        CURRENT_KID,
        "keystone-registration",
        now_secs(),
        now_secs() + 120,
    )
    .await
    .unwrap();
    assert_eq!(
        pg.claim_registration_nonce(
            &nonce_hash,
            CURRENT_KID,
            "keystone-registration",
            now_secs(),
            now_secs() + 120,
        )
        .await,
        Err(RegistrationFeedError::Replay)
    );

    assert!(pg.delete_user(&sub).await.unwrap());
    let deleted_snapshot = pg.create_registration_snapshot().await.unwrap();
    let deleted_page = pg
        .get_registration_snapshot_page(&deleted_snapshot.snapshot_id, 0, 1000)
        .await
        .unwrap();
    let tombstone = deleted_page
        .rows
        .iter()
        .find(|row| row.subject == format!("user:{sub}"))
        .expect("deleted identity retained in materialized snapshot");
    assert_eq!(tombstone.registration_state, RegistrationState::Deleted);
    assert_eq!(tombstone.account_version, 7);
}
