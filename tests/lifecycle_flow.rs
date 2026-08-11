//! Enterprise JML lifecycle ingress and fencing tests.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use keystone::config::{seed_client, seed_user};
use keystone::store::{
    new_opaque_code, InMemoryStore, PersonalAccessToken, PgStore, Store, SubjectLifecycleCommand,
    SubjectLifecycleError, SubjectLifecycleState, User,
};
use keystone::{now_secs, AppState};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

const JML_TOKEN: &str = "jml-test-token-0123456789-ABCDEFGHIJ";
const SECOND_SUBJECT: &str = "usr_jml_second";

fn configured_memory_state() -> (AppState, Arc<InMemoryStore>) {
    let mut state = keystone::build_dev_state();
    let store = Arc::new(InMemoryStore::new());
    store.seed_client(seed_client());
    store.put_user(seed_user());
    store.put_user(test_user(SECOND_SUBJECT, "jml-second@example.test"));
    state.store = store.clone();
    let mut config = state.config.as_ref().clone();
    config.jml_service_token = Some(JML_TOKEN.to_string());
    state.config = Arc::new(config);
    (state, store)
}

fn test_user(subject: &str, email: &str) -> User {
    User {
        sub: subject.to_string(),
        email: email.to_string(),
        password_hash: None,
        email_verified: true,
        created_at: now_secs(),
        is_admin: false,
        disabled: false,
        factor_epoch: 0,
    }
}

fn test_personal_token(subject: &str, label: &str) -> PersonalAccessToken {
    let now = now_secs();
    PersonalAccessToken {
        id: format!("pat_{label}_{}", new_opaque_code()),
        user_sub: subject.to_string(),
        name: label.to_string(),
        token_hash: keystone::auth::secret_hash(&format!("pat_{}", new_opaque_code())),
        scopes: "profile".to_string(),
        created_at: now,
        expires_at: now + 86_400,
        revoked_at: 0,
    }
}

fn lifecycle_request(body: Value, token: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/internal/v1/jml/subjects/lifecycle")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    request.body(Body::from(body.to_string())).unwrap()
}

fn command_body(subject: &str, state: &str, event: &str, version: u64) -> Value {
    json!({
        "subject": subject,
        "state": state,
        "source_event_id": event,
        "source_version": version,
        "correlation_id": format!("corr:{subject}:{version}")
    })
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
    let body = serde_json::from_slice(&body).expect("JSON response");
    (status, headers, body)
}

fn assert_private_no_store(headers: &HeaderMap) {
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
        Some("Authorization")
    );
}

fn session_headers(cookie: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("__Host-session={cookie}").parse().unwrap(),
    );
    headers
}

#[tokio::test]
async fn lifecycle_endpoint_fails_closed_for_config_auth_and_strict_json() {
    let unconfigured = keystone::build_dev_state();
    let (status, headers, body) = call(
        &unconfigured,
        lifecycle_request(
            command_body("u_admin", "frozen", "evt:unconfigured", 1),
            Some(JML_TOKEN),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({"error": "temporarily_unavailable"}));
    assert_private_no_store(&headers);

    let mut weak = unconfigured.clone();
    let mut weak_config = weak.config.as_ref().clone();
    weak_config.jml_service_token = Some("too-short".to_string());
    weak.config = Arc::new(weak_config);
    let (status, headers, _) = call(
        &weak,
        lifecycle_request(
            command_body("u_admin", "frozen", "evt:weak", 1),
            Some("too-short"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_private_no_store(&headers);

    let (state, _) = configured_memory_state();
    for token in [None, Some("wrong-token-that-is-never-authorized")].into_iter() {
        let (status, headers, body) = call(
            &state,
            lifecycle_request(
                command_body("u_admin", "frozen", "evt:unauthorized", 1),
                token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, json!({"error": "unauthorized"}));
        assert_eq!(
            headers
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer realm=\"keystone-jml\"")
        );
        assert_private_no_store(&headers);
    }

    let mut unknown_field = command_body("u_admin", "frozen", "evt:strict", 1);
    unknown_field["unexpected"] = json!(JML_TOKEN);
    let (status, headers, body) =
        call(&state, lifecycle_request(unknown_field, Some(JML_TOKEN))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "invalid_request"}));
    assert!(!body.to_string().contains(JML_TOKEN));
    assert_private_no_store(&headers);

    let (status, _, body) = call(
        &state,
        lifecycle_request(
            command_body("user:u_admin", "frozen", "evt:canonicalized", 1),
            Some(JML_TOKEN),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "invalid_request"}));

    let (status, _, body) = call(
        &state,
        lifecycle_request(
            command_body("u_admin", "frozen", "evt:zero-version", 0),
            Some(JML_TOKEN),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "invalid_request"}));
}

#[tokio::test]
async fn memory_lifecycle_is_fenced_revokes_sessions_and_preserves_tombstones() {
    let (state, store) = configured_memory_state();
    let pre_freeze_pat = test_personal_token("u_admin", "pre-freeze");
    state
        .store
        .put_personal_token(pre_freeze_pat.clone())
        .await
        .expect("active user PAT");
    assert!(state
        .store
        .find_active_personal_token(&pre_freeze_pat.token_hash, now_secs())
        .await
        .expect("pre-freeze PAT lookup")
        .is_some());
    let first = keystone::auth::try_create_session(&state, "u_admin", "first", "10.0.0.1")
        .await
        .expect("active user session");
    let second = keystone::auth::try_create_session(&state, "u_admin", "second", "10.0.0.2")
        .await
        .expect("active user session");
    let other = keystone::auth::try_create_session(&state, SECOND_SUBJECT, "other", "10.0.0.3")
        .await
        .expect("other active user session");

    let body = command_body("u_admin", "frozen", "evt:freeze:1", 1);
    let (status, headers, response) =
        call(&state, lifecycle_request(body.clone(), Some(JML_TOKEN))).await;
    assert_eq!(status, StatusCode::OK);
    assert_private_no_store(&headers);
    assert_eq!(response["state"], "frozen");
    assert_eq!(response["replayed"], false);
    assert_eq!(response["user_found"], true);
    assert_eq!(response["revoked_sessions"], 2);
    assert!(store.get_user("u_admin").await.unwrap().disabled);
    let blocked_pat = test_personal_token("u_admin", "blocked-during-freeze");
    assert_eq!(
        state.store.put_personal_token(blocked_pat).await,
        Err(keystone::store::StoreError::Backend),
        "a lifecycle-disabled subject cannot persist a PAT"
    );
    state
        .store
        .set_disabled("u_admin", false)
        .await
        .expect("enable admin");
    assert!(
        store.get_user("u_admin").await.unwrap().disabled,
        "local enable cannot bypass an authoritative frozen fence"
    );
    assert!(
        keystone::auth::current_session(&state, &session_headers(&first))
            .await
            .is_none()
    );
    assert!(
        keystone::auth::current_session(&state, &session_headers(&second))
            .await
            .is_none()
    );
    assert!(
        keystone::auth::current_session(&state, &session_headers(&other))
            .await
            .is_some(),
        "another subject is isolated"
    );

    let (status, _, replay) = call(&state, lifecycle_request(body, Some(JML_TOKEN))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["revoked_sessions"], 2);

    for conflict in [
        command_body("u_admin", "active", "evt:freeze:1", 1),
        command_body("u_admin", "frozen", "evt:different", 1),
    ] {
        let (status, _, body) = call(&state, lifecycle_request(conflict, Some(JML_TOKEN))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": "lifecycle_conflict"}));
    }

    let (status, _, active) = call(
        &state,
        lifecycle_request(
            command_body("u_admin", "active", "evt:rehire:2", 2),
            Some(JML_TOKEN),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(active["state"], "active");
    assert!(!store.get_user("u_admin").await.unwrap().disabled);
    assert!(
        state
            .store
            .find_active_personal_token(&pre_freeze_pat.token_hash, now_secs())
            .await
            .expect("rehire PAT lookup")
            .is_none(),
        "rehire must not resurrect a PAT revoked by JML"
    );
    assert_eq!(
        state.store.put_personal_token(pre_freeze_pat.clone()).await,
        Err(keystone::store::StoreError::Backend),
        "a JML-revoked PAT is immutable after rehire"
    );
    let post_rehire_pat = test_personal_token("u_admin", "post-rehire");
    state
        .store
        .put_personal_token(post_rehire_pat.clone())
        .await
        .expect("rehired user may mint a fresh PAT");
    let rehire_session =
        keystone::auth::try_create_session(&state, "u_admin", "rehire", "10.0.0.4")
            .await
            .expect("rehired user can create a fresh session");

    let (status, _, terminated) = call(
        &state,
        lifecycle_request(
            command_body("u_admin", "terminated", "evt:leave:3", 3),
            Some(JML_TOKEN),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(terminated["revoked_sessions"], 1);
    assert!(state
        .store
        .find_active_personal_token(&post_rehire_pat.token_hash, now_secs())
        .await
        .expect("terminated PAT lookup")
        .is_none());
    assert!(
        keystone::auth::current_session(&state, &session_headers(&rehire_session))
            .await
            .is_none()
    );

    let missing = "usr_jml_tombstone";
    let (status, _, tombstone) = call(
        &state,
        lifecycle_request(
            command_body(missing, "terminated", "evt:tombstone:7", 7),
            Some(JML_TOKEN),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tombstone["user_found"], false);
    store.put_user(test_user(missing, "jml-tombstone@example.test"));
    assert!(
        store.get_user(missing).await.unwrap().disabled,
        "a later-created user inherits the tombstone"
    );
    let (status, _, _) = call(
        &state,
        lifecycle_request(
            command_body(missing, "active", "evt:old-rehire:6", 6),
            Some(JML_TOKEN),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn memory_rehire_only_reverses_lifecycle_owned_disables() {
    let (state, store) = configured_memory_state();

    state
        .store
        .set_disabled(SECOND_SUBJECT, true)
        .await
        .expect("manually disable second subject");
    state
        .store
        .apply_subject_lifecycle(SubjectLifecycleCommand {
            subject: SECOND_SUBJECT.to_string(),
            state: SubjectLifecycleState::Frozen,
            source_event_id: "evt:manual-before:freeze:1".to_string(),
            source_version: 1,
            correlation_id: "corr:manual-before:freeze:1".to_string(),
        })
        .await
        .expect("freeze manually disabled user");
    state
        .store
        .apply_subject_lifecycle(SubjectLifecycleCommand {
            subject: SECOND_SUBJECT.to_string(),
            state: SubjectLifecycleState::Active,
            source_event_id: "evt:manual-before:active:2".to_string(),
            source_version: 2,
            correlation_id: "corr:manual-before:active:2".to_string(),
        })
        .await
        .expect("rehire manually disabled user");
    assert!(
        store.get_user(SECOND_SUBJECT).await.unwrap().disabled,
        "rehire must preserve a pre-existing administrator disable"
    );

    const MANUAL_TAKEOVER: &str = "usr_jml_manual_takeover";
    store.put_user(test_user(
        MANUAL_TAKEOVER,
        "jml-manual-takeover@example.test",
    ));
    state
        .store
        .apply_subject_lifecycle(SubjectLifecycleCommand {
            subject: MANUAL_TAKEOVER.to_string(),
            state: SubjectLifecycleState::Frozen,
            source_event_id: "evt:manual-after:freeze:1".to_string(),
            source_version: 1,
            correlation_id: "corr:manual-after:freeze:1".to_string(),
        })
        .await
        .expect("freeze enabled user");
    state
        .store
        .set_disabled(MANUAL_TAKEOVER, true)
        .await
        .expect("manual disable takes ownership");
    state
        .store
        .apply_subject_lifecycle(SubjectLifecycleCommand {
            subject: MANUAL_TAKEOVER.to_string(),
            state: SubjectLifecycleState::Active,
            source_event_id: "evt:manual-after:active:2".to_string(),
            source_version: 2,
            correlation_id: "corr:manual-after:active:2".to_string(),
        })
        .await
        .expect("rehire after manual takeover");
    assert!(
        store.get_user(MANUAL_TAKEOVER).await.unwrap().disabled,
        "manual disable during a lifecycle freeze must take ownership"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_lifecycle_serializes_session_races_and_conflicting_events() {
    let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping lifecycle PostgreSQL test");
        return;
    };

    const RACE_SUBJECT: &str = "usr_jml_pg_race_20260806";
    const OTHER_SUBJECT: &str = "usr_jml_pg_other_20260806";
    const TOMBSTONE_SUBJECT: &str = "usr_jml_pg_tombstone_20260806";
    const MANUAL_SUBJECT: &str = "usr_jml_pg_manual_20260806";
    let subjects = [
        RACE_SUBJECT,
        OTHER_SUBJECT,
        TOMBSTONE_SUBJECT,
        MANUAL_SUBJECT,
    ];

    let inspection_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("connect PostgreSQL inspection pool");
    let pg = PgStore::connect(&database_url)
        .await
        .expect("connect PostgreSQL store");
    pg.migrate().await.expect("migrate lifecycle tables");
    let positive_version_constraint: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
             SELECT 1 FROM pg_constraint \
             WHERE conrelid='subject_lifecycle_fences'::regclass \
               AND conname='ck_subject_lifecycle_source_version_positive' \
               AND convalidated \
               AND pg_get_constraintdef(oid) LIKE '%source_version > 0%'\
         )",
    )
    .fetch_one(&inspection_pool)
    .await
    .expect("inspect positive lifecycle source-version constraint");
    assert!(
        positive_version_constraint,
        "the durable JML fence must reject non-positive source versions"
    );
    cleanup_subjects(&inspection_pool, &subjects).await;

    let mut state = keystone::build_dev_state();
    state.store = Arc::new(pg);
    state
        .store
        .create_user(
            RACE_SUBJECT,
            "jml-pg-race-20260806@example.test",
            "unused-hash",
            now_secs(),
        )
        .await
        .expect("create race user");
    state
        .store
        .create_user(
            OTHER_SUBJECT,
            "jml-pg-other-20260806@example.test",
            "unused-hash",
            now_secs(),
        )
        .await
        .expect("create other user");
    state
        .store
        .create_user(
            MANUAL_SUBJECT,
            "jml-pg-manual-20260806@example.test",
            "unused-hash",
            now_secs(),
        )
        .await
        .expect("create manual provenance user");

    state
        .store
        .apply_subject_lifecycle(SubjectLifecycleCommand {
            subject: MANUAL_SUBJECT.to_string(),
            state: SubjectLifecycleState::Frozen,
            source_event_id: "evt:pg:manual:freeze:1".to_string(),
            source_version: 1,
            correlation_id: "corr:pg:manual:freeze:1".to_string(),
        })
        .await
        .expect("freeze manual provenance user");
    state
        .store
        .set_disabled(MANUAL_SUBJECT, true)
        .await
        .expect("manually disable subject");
    state
        .store
        .apply_subject_lifecycle(SubjectLifecycleCommand {
            subject: MANUAL_SUBJECT.to_string(),
            state: SubjectLifecycleState::Active,
            source_event_id: "evt:pg:manual:active:2".to_string(),
            source_version: 2,
            correlation_id: "corr:pg:manual:active:2".to_string(),
        })
        .await
        .expect("rehire manual provenance user");
    assert!(
        state.store.get_user(MANUAL_SUBJECT).await.unwrap().disabled,
        "PostgreSQL rehire must preserve an administrator disable"
    );

    let other_cookie =
        keystone::auth::try_create_session(&state, OTHER_SUBJECT, "other", "10.1.0.1")
            .await
            .expect("other user session");
    let pre_freeze_pat = test_personal_token(RACE_SUBJECT, "pg-pre-freeze");
    state
        .store
        .put_personal_token(pre_freeze_pat.clone())
        .await
        .expect("persist pre-freeze PostgreSQL PAT");

    const SESSION_WRITERS: usize = 24;
    let barrier = Arc::new(tokio::sync::Barrier::new(SESSION_WRITERS + 2));
    let mut writers = Vec::with_capacity(SESSION_WRITERS);
    for index in 0..SESSION_WRITERS {
        let state = state.clone();
        let barrier = barrier.clone();
        writers.push(tokio::spawn(async move {
            barrier.wait().await;
            keystone::auth::try_create_session(
                &state,
                RACE_SUBJECT,
                &format!("racer-{index}"),
                "10.1.0.2",
            )
            .await
        }));
    }
    let lifecycle_state = state.clone();
    let lifecycle_barrier = barrier.clone();
    let lifecycle = tokio::spawn(async move {
        lifecycle_barrier.wait().await;
        lifecycle_state
            .store
            .apply_subject_lifecycle(SubjectLifecycleCommand {
                subject: RACE_SUBJECT.to_string(),
                state: SubjectLifecycleState::Frozen,
                source_event_id: "evt:pg:freeze:1".to_string(),
                source_version: 1,
                correlation_id: "corr:pg:freeze:1".to_string(),
            })
            .await
    });
    let racing_pat = test_personal_token(RACE_SUBJECT, "pg-racing-freeze");
    let racing_pat_hash = racing_pat.token_hash.clone();
    let pat_state = state.clone();
    let pat_barrier = barrier.clone();
    let pat_writer = tokio::spawn(async move {
        pat_barrier.wait().await;
        pat_state.store.put_personal_token(racing_pat).await
    });

    let mut returned_cookies = Vec::new();
    for writer in writers {
        if let Some(cookie) = writer.await.expect("session writer task") {
            returned_cookies.push(cookie);
        }
    }
    let pat_write_result = pat_writer.await.expect("PAT writer task");
    let frozen = lifecycle
        .await
        .expect("lifecycle task")
        .expect("freeze transition");
    assert_eq!(frozen.state, SubjectLifecycleState::Frozen);
    assert!(state.store.get_user(RACE_SUBJECT).await.unwrap().disabled);
    state
        .store
        .set_disabled(RACE_SUBJECT, false)
        .await
        .expect("manually enable subject");
    assert!(
        state.store.get_user(RACE_SUBJECT).await.unwrap().disabled,
        "local enable cannot bypass the durable PostgreSQL fence"
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_sub = $1")
        .bind(RACE_SUBJECT)
        .fetch_one(&inspection_pool)
        .await
        .expect("count race sessions");
    assert_eq!(
        count, 0,
        "the serialized freeze leaves no persisted session"
    );
    let pre_freeze_revoked_at: i64 =
        sqlx::query_scalar("SELECT revoked_at FROM personal_access_tokens WHERE token_hash=$1")
            .bind(&pre_freeze_pat.token_hash)
            .fetch_one(&inspection_pool)
            .await
            .expect("inspect pre-freeze PAT revocation");
    assert!(
        pre_freeze_revoked_at > 0,
        "the freeze must physically revoke a pre-existing PAT"
    );
    let racing_revoked_at: Option<i64> =
        sqlx::query_scalar("SELECT revoked_at FROM personal_access_tokens WHERE token_hash=$1")
            .bind(&racing_pat_hash)
            .fetch_optional(&inspection_pool)
            .await
            .expect("inspect racing PAT revocation");
    match pat_write_result {
        Ok(()) => assert!(
            racing_revoked_at.is_some_and(|revoked_at| revoked_at > 0),
            "a racing PAT that wins the subject lock must be physically revoked"
        ),
        Err(keystone::store::StoreError::Backend) => assert!(
            racing_revoked_at.is_none(),
            "a racing PAT that loses the subject lock must not be persisted"
        ),
    }
    for token_hash in [&pre_freeze_pat.token_hash, &racing_pat_hash] {
        assert!(
            state
                .store
                .find_active_personal_token(token_hash, now_secs())
                .await
                .expect("post-freeze PAT lookup")
                .is_none(),
            "the serialized freeze leaves no active PAT"
        );
    }
    assert_eq!(
        state
            .store
            .put_personal_token(test_personal_token(RACE_SUBJECT, "pg-blocked-freeze"))
            .await,
        Err(keystone::store::StoreError::Backend)
    );

    // Simulate an older deployment where the fence existed but user/session/PAT state
    // had not yet converged. Re-running migrate must repair all three before rehire.
    let legacy_session_id = format!("legacy-session-{}", new_opaque_code());
    sqlx::query("UPDATE users SET disabled=FALSE WHERE sub=$1")
        .bind(RACE_SUBJECT)
        .execute(&inspection_pool)
        .await
        .expect("simulate legacy enabled user");
    sqlx::query("UPDATE subject_lifecycle_fences SET disabled_by_lifecycle=FALSE WHERE subject=$1")
        .bind(RACE_SUBJECT)
        .execute(&inspection_pool)
        .await
        .expect("simulate legacy lifecycle provenance default");
    sqlx::query("UPDATE personal_access_tokens SET revoked_at=0 WHERE token_hash=$1")
        .bind(&pre_freeze_pat.token_hash)
        .execute(&inspection_pool)
        .await
        .expect("simulate legacy active PAT");
    let legacy_now = now_secs();
    sqlx::query(
        "INSERT INTO sessions \
         (id,user_sub,created_at,expires_at,user_agent,ip,last_seen) \
         VALUES ($1,$2,$3,$4,'legacy','10.1.0.9',$3)",
    )
    .bind(&legacy_session_id)
    .bind(RACE_SUBJECT)
    .bind(legacy_now as i64)
    .bind((legacy_now + 300) as i64)
    .execute(&inspection_pool)
    .await
    .expect("simulate legacy session");
    PgStore::connect(&database_url)
        .await
        .expect("connect migration replay store")
        .migrate()
        .await
        .expect("forward-converge legacy lifecycle state");
    assert!(state.store.get_user(RACE_SUBJECT).await.unwrap().disabled);
    let migrated_lifecycle_provenance: bool = sqlx::query_scalar(
        "SELECT disabled_by_lifecycle FROM subject_lifecycle_fences WHERE subject=$1",
    )
    .bind(RACE_SUBJECT)
    .fetch_one(&inspection_pool)
    .await
    .expect("inspect migrated lifecycle disable provenance");
    assert!(
        migrated_lifecycle_provenance,
        "migration repair must record ownership of the disabled bit"
    );
    assert!(state.store.get_session(&legacy_session_id).await.is_none());
    let migrated_revoked_at: i64 =
        sqlx::query_scalar("SELECT revoked_at FROM personal_access_tokens WHERE token_hash=$1")
            .bind(&pre_freeze_pat.token_hash)
            .fetch_one(&inspection_pool)
            .await
            .expect("inspect migrated PAT revocation");
    assert!(migrated_revoked_at > 0);

    // Exact replay is also a convergence operation. If storage drift appears after
    // migration, replaying the authoritative frozen event repairs it without changing
    // the fence version or the original response counters.
    let replay_session_id = format!("replay-session-{}", new_opaque_code());
    sqlx::query("UPDATE users SET disabled=FALSE WHERE sub=$1")
        .bind(RACE_SUBJECT)
        .execute(&inspection_pool)
        .await
        .expect("simulate replay user drift");
    sqlx::query("UPDATE subject_lifecycle_fences SET disabled_by_lifecycle=FALSE WHERE subject=$1")
        .bind(RACE_SUBJECT)
        .execute(&inspection_pool)
        .await
        .expect("simulate replay provenance drift");
    sqlx::query("UPDATE personal_access_tokens SET revoked_at=0 WHERE token_hash=$1")
        .bind(&pre_freeze_pat.token_hash)
        .execute(&inspection_pool)
        .await
        .expect("simulate replay PAT drift");
    let replay_now = now_secs();
    sqlx::query(
        "INSERT INTO sessions \
         (id,user_sub,created_at,expires_at,user_agent,ip,last_seen) \
         VALUES ($1,$2,$3,$4,'replay','10.1.0.10',$3)",
    )
    .bind(&replay_session_id)
    .bind(RACE_SUBJECT)
    .bind(replay_now as i64)
    .bind((replay_now + 300) as i64)
    .execute(&inspection_pool)
    .await
    .expect("simulate replay session drift");
    let frozen_replay = state
        .store
        .apply_subject_lifecycle(SubjectLifecycleCommand {
            subject: RACE_SUBJECT.to_string(),
            state: SubjectLifecycleState::Frozen,
            source_event_id: "evt:pg:freeze:1".to_string(),
            source_version: 1,
            correlation_id: "corr:pg:freeze:1".to_string(),
        })
        .await
        .expect("exact frozen replay convergence");
    assert!(frozen_replay.replayed);
    assert!(state.store.get_user(RACE_SUBJECT).await.unwrap().disabled);
    let replay_lifecycle_provenance: bool = sqlx::query_scalar(
        "SELECT disabled_by_lifecycle FROM subject_lifecycle_fences WHERE subject=$1",
    )
    .bind(RACE_SUBJECT)
    .fetch_one(&inspection_pool)
    .await
    .expect("inspect replay lifecycle disable provenance");
    assert!(
        replay_lifecycle_provenance,
        "exact replay repair must record ownership of the disabled bit"
    );
    assert!(state.store.get_session(&replay_session_id).await.is_none());
    let replay_revoked_at: i64 =
        sqlx::query_scalar("SELECT revoked_at FROM personal_access_tokens WHERE token_hash=$1")
            .bind(&pre_freeze_pat.token_hash)
            .fetch_one(&inspection_pool)
            .await
            .expect("inspect replay PAT convergence");
    assert!(replay_revoked_at > 0);
    for cookie in returned_cookies {
        assert!(
            keystone::auth::current_session(&state, &session_headers(&cookie))
                .await
                .is_none(),
            "every racing cookie is invalid after freeze commits"
        );
    }
    assert!(
        keystone::auth::current_session(&state, &session_headers(&other_cookie))
            .await
            .is_some(),
        "freezing one subject does not affect another"
    );

    let rehire = SubjectLifecycleCommand {
        subject: RACE_SUBJECT.to_string(),
        state: SubjectLifecycleState::Active,
        source_event_id: "evt:pg:rehire:2".to_string(),
        source_version: 2,
        correlation_id: "corr:pg:rehire:2".to_string(),
    };
    assert!(
        !state
            .store
            .apply_subject_lifecycle(rehire.clone())
            .await
            .expect("rehire")
            .replayed
    );
    assert!(
        state
            .store
            .apply_subject_lifecycle(rehire.clone())
            .await
            .expect("exact rehire replay")
            .replayed
    );
    assert!(
        state
            .store
            .find_active_personal_token(&pre_freeze_pat.token_hash, now_secs())
            .await
            .expect("PostgreSQL rehire PAT lookup")
            .is_none(),
        "PostgreSQL rehire must not resurrect a JML-revoked PAT"
    );
    assert!(
        state
            .store
            .find_active_personal_token(&racing_pat_hash, now_secs())
            .await
            .expect("PostgreSQL racing PAT rehire lookup")
            .is_none(),
        "PostgreSQL rehire must not resurrect a racing PAT"
    );
    assert_eq!(
        state.store.put_personal_token(pre_freeze_pat.clone()).await,
        Err(keystone::store::StoreError::Backend),
        "PostgreSQL PAT rows are immutable after JML revocation"
    );
    let stale = SubjectLifecycleCommand {
        source_version: 1,
        source_event_id: "evt:pg:stale:1".to_string(),
        ..rehire.clone()
    };
    assert_eq!(
        state.store.apply_subject_lifecycle(stale).await,
        Err(SubjectLifecycleError::Conflict)
    );
    let fresh_cookie =
        keystone::auth::try_create_session(&state, RACE_SUBJECT, "rehire", "10.1.0.3")
            .await
            .expect("rehire requires a new session");

    let left = state
        .store
        .apply_subject_lifecycle(SubjectLifecycleCommand {
            subject: RACE_SUBJECT.to_string(),
            state: SubjectLifecycleState::Terminated,
            source_event_id: "evt:pg:leave:3".to_string(),
            source_version: 3,
            correlation_id: "corr:pg:leave:3".to_string(),
        })
        .await
        .expect("terminate");
    assert_eq!(left.revoked_sessions, 1);
    assert!(
        keystone::auth::current_session(&state, &session_headers(&fresh_cookie))
            .await
            .is_none()
    );

    let first_command = SubjectLifecycleCommand {
        subject: OTHER_SUBJECT.to_string(),
        state: SubjectLifecycleState::Frozen,
        source_event_id: "evt:pg:contender:a".to_string(),
        source_version: 1,
        correlation_id: "corr:pg:contender:a".to_string(),
    };
    let second_command = SubjectLifecycleCommand {
        subject: OTHER_SUBJECT.to_string(),
        state: SubjectLifecycleState::Active,
        source_event_id: "evt:pg:contender:b".to_string(),
        source_version: 1,
        correlation_id: "corr:pg:contender:b".to_string(),
    };
    let first_state = state.clone();
    let second_state = state.clone();
    let first = tokio::spawn(async move {
        first_state
            .store
            .apply_subject_lifecycle(first_command)
            .await
    });
    let second = tokio::spawn(async move {
        second_state
            .store
            .apply_subject_lifecycle(second_command)
            .await
    });
    let results = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(SubjectLifecycleError::Conflict)))
            .count(),
        1
    );

    let tombstone = state
        .store
        .apply_subject_lifecycle(SubjectLifecycleCommand {
            subject: TOMBSTONE_SUBJECT.to_string(),
            state: SubjectLifecycleState::Terminated,
            source_event_id: "evt:pg:tombstone:10".to_string(),
            source_version: 10,
            correlation_id: "corr:pg:tombstone:10".to_string(),
        })
        .await
        .expect("persist tombstone");
    assert!(!tombstone.user_found);
    state
        .store
        .create_user(
            TOMBSTONE_SUBJECT,
            "jml-pg-tombstone-20260806@example.test",
            "unused-hash",
            now_secs(),
        )
        .await
        .expect("create user after tombstone");
    assert!(
        state
            .store
            .get_user(TOMBSTONE_SUBJECT)
            .await
            .unwrap()
            .disabled
    );
    state
        .store
        .apply_subject_lifecycle(SubjectLifecycleCommand {
            subject: TOMBSTONE_SUBJECT.to_string(),
            state: SubjectLifecycleState::Active,
            source_event_id: "evt:pg:tombstone:active:11".to_string(),
            source_version: 11,
            correlation_id: "corr:pg:tombstone:active:11".to_string(),
        })
        .await
        .expect("activate user created under tombstone");
    assert!(
        !state
            .store
            .get_user(TOMBSTONE_SUBJECT)
            .await
            .unwrap()
            .disabled,
        "rehire may reverse the lifecycle-owned disable on a later-created user"
    );

    cleanup_subjects(&inspection_pool, &subjects).await;
}

async fn cleanup_subjects(pool: &sqlx::PgPool, subjects: &[&str]) {
    for subject in subjects {
        for query in [
            "DELETE FROM sessions WHERE user_sub = $1",
            "DELETE FROM personal_access_tokens WHERE user_sub = $1",
            "DELETE FROM webauthn_credentials WHERE user_sub = $1",
            "DELETE FROM subject_lifecycle_fences WHERE subject = $1",
            "DELETE FROM users WHERE sub = $1",
        ] {
            sqlx::query(query)
                .bind(*subject)
                .execute(pool)
                .await
                .unwrap_or_else(|error| panic!("cleanup subject {subject}: {error}"));
        }
    }
}
