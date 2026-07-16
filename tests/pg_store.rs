//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When
//! unset the test prints a note and returns early — it never fails CI / the default
//! `cargo test` run, which stays database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55432/keystone \
//!   cargo test --test pg_store -- --nocapture
//! ```
//!
//! Uses a multi-threaded runtime (matching production); the `Store` trait is async, so the
//! handlers `.await` sqlx natively with no sync-over-async bridge.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use keystone::config::{seed_client, seed_user};
use keystone::store::{
    new_opaque_code, AuthCode, Credential, LoginEvent, PersonalAccessToken, PgStore, Session,
    TotpChallenge, TotpConfig, WebauthnState,
};
use keystone::{now_secs, AppState};
use serde_json::Value;
use tower::ServiceExt;

const CLIENT_ID: &str = "sluice-dev";
const REDIRECT_URI: &str = "http://127.0.0.1:9090/callback";
const ISSUER: &str = "http://127.0.0.1:8080";
// RFC 7636 Appendix B test vector.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test \
             (needs external Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate / idempotent seed -------------------------------
    let pg = PgStore::connect(&url)
        .await
        .expect("connect to TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");
    pg.seed(&seed_client(), &seed_user()).await.expect("seed");
    // Seeding twice MUST be idempotent (UPSERT) — no error, no duplicate rows.
    pg.seed(&seed_client(), &seed_user())
        .await
        .expect("seed is idempotent");

    // Wire the PG store behind Arc<dyn Store> in an otherwise-dev AppState.
    let mut state = keystone::build_dev_state();
    state.store = Arc::new(pg);

    // --- direct Store-trait round-trip (async methods over async sqlx) -----
    let client = state
        .store
        .get_client(CLIENT_ID)
        .await
        .expect("seeded client present");
    assert_eq!(client.client_id, CLIENT_ID);
    assert!(
        client.allows_redirect(REDIRECT_URI),
        "redirect URI seeded into child table"
    );
    assert!(
        state.store.get_client("ghost").await.is_none(),
        "unknown client"
    );

    let user = state
        .store
        .get_user("u_admin")
        .await
        .expect("seeded user present");
    assert_eq!(user.email, "admin@steadholme.local");
    assert!(
        state.store.get_user("nobody").await.is_none(),
        "unknown user"
    );

    // Admin-console columns: the seeded operator is admin + enabled out of the box
    // (seed INSERT on a fresh DB; created_at=0 backfill on a pre-existing one).
    assert!(user.is_admin, "seeded operator is admin");
    assert!(!user.disabled, "seeded operator starts enabled");
    // disable/enable + admin-bit round-trips on real Postgres (restored afterwards so
    // the test database stays reusable).
    state.store.set_disabled("u_admin", true).await;
    assert!(state.store.get_user("u_admin").await.unwrap().disabled);
    state.store.set_disabled("u_admin", false).await;
    assert!(!state.store.get_user("u_admin").await.unwrap().disabled);
    state.store.set_is_admin("u_admin", false).await;
    assert!(!state.store.get_user("u_admin").await.unwrap().is_admin);
    state.store.set_is_admin("u_admin", true).await;
    assert!(
        state
            .store
            .list_users()
            .await
            .iter()
            .any(|u| u.sub == "u_admin"),
        "list_users surfaces the operator"
    );
    let clients = state.store.list_clients().await;
    let listed = clients
        .iter()
        .find(|c| c.client_id == CLIENT_ID)
        .expect("list_clients surfaces the seeded client");
    assert!(listed.first_party, "first_party round-trips");
    assert!(
        listed.redirect_uris.iter().any(|u| u == REDIRECT_URI),
        "redirect URIs merged from the child table"
    );

    // put_code -> take_code, and single-use (delete-on-consume) enforcement.
    let code = new_opaque_code();
    state
        .store
        .put_code(AuthCode {
            code: code.clone(),
            client_id: CLIENT_ID.to_string(),
            redirect_uri: REDIRECT_URI.to_string(),
            scope: "openid email".to_string(),
            nonce: Some("n-direct".to_string()),
            code_challenge: CHALLENGE.to_string(),
            sub: "u_admin".to_string(),
            expires_at: now_secs() + 60,
            used: false,
        })
        .await;
    let taken = state
        .store
        .take_code(&code)
        .await
        .expect("code present once");
    assert_eq!(taken.client_id, CLIENT_ID);
    assert_eq!(taken.redirect_uri, REDIRECT_URI);
    assert_eq!(taken.code_challenge, CHALLENGE);
    assert_eq!(taken.nonce.as_deref(), Some("n-direct"));
    assert_eq!(taken.scope, "openid email");
    assert!(
        state.store.take_code(&code).await.is_none(),
        "single-use: a consumed code is gone"
    );

    // --- login-layer tables round-trip on real Postgres --------------------
    // password hash: set + read back via username lookup (sub OR email).
    let hash = keystone::auth::hash_password("pg-bootstrap-pass").unwrap();
    state.store.set_password_hash("u_admin", &hash).await;
    let by_email = state
        .store
        .get_user_by_username("admin@steadholme.local")
        .await
        .expect("lookup by email");
    assert_eq!(by_email.sub, "u_admin");
    assert_eq!(by_email.password_hash.as_deref(), Some(hash.as_str()));
    assert!(
        keystone::auth::verify_password(
            "pg-bootstrap-pass",
            by_email.password_hash.as_deref().unwrap()
        ),
        "stored Argon2 hash verifies"
    );

    // sessions: put -> get -> delete.
    let sess = Session {
        id: new_opaque_code(),
        user_sub: "u_admin".to_string(),
        created_at: now_secs(),
        expires_at: now_secs() + 3600,
        user_agent: "pg-test-agent".to_string(),
        ip: "10.0.0.1".to_string(),
        last_seen: now_secs(),
    };
    state.store.put_session(sess.clone()).await;
    assert_eq!(
        state.store.get_session(&sess.id).await.map(|s| s.user_sub),
        Some("u_admin".to_string())
    );
    // metadata round-trips through the DB.
    let fetched = state.store.get_session(&sess.id).await.unwrap();
    assert_eq!(fetched.user_agent, "pg-test-agent");
    assert_eq!(fetched.ip, "10.0.0.1");
    // list_sessions surfaces it; revoke_other keeps a different id and drops this one.
    assert!(state
        .store
        .list_sessions("u_admin")
        .await
        .iter()
        .any(|s| s.id == sess.id));
    state
        .store
        .revoke_other_sessions("u_admin", "some-other-id")
        .await;
    assert!(
        state.store.get_session(&sess.id).await.is_none(),
        "revoke_other_sessions removed the non-kept session"
    );
    // re-put for the delete_session assertion below.
    state.store.put_session(sess.clone()).await;
    state.store.delete_session(&sess.id).await;
    assert!(
        state.store.get_session(&sess.id).await.is_none(),
        "session deleted"
    );

    // TOTP config + recovery codes + login challenge.
    state
        .store
        .put_totp(TotpConfig {
            user_sub: "u_admin".to_string(),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            enabled: true,
            created_at: now_secs(),
            verified_at: now_secs(),
        })
        .await;
    assert!(state.store.get_totp("u_admin").await.unwrap().enabled);
    state
        .store
        .put_recovery_codes(
            "u_admin",
            vec!["hash-a".to_string(), "hash-b".to_string()],
            now_secs(),
        )
        .await;
    assert_eq!(state.store.recovery_code_count("u_admin").await, 2);
    assert!(state.store.take_recovery_code("u_admin", "hash-a").await);
    assert!(!state.store.take_recovery_code("u_admin", "hash-a").await);
    let challenge = TotpChallenge {
        id: new_opaque_code(),
        user_sub: "u_admin".to_string(),
        return_to: "/account".to_string(),
        user_agent: "pg-totp-agent".to_string(),
        ip: "10.0.0.2".to_string(),
        expires_at: now_secs() + 300,
    };
    state.store.put_totp_challenge(challenge.clone()).await;
    assert_eq!(
        state
            .store
            .take_totp_challenge(&challenge.id)
            .await
            .map(|c| c.user_agent),
        Some("pg-totp-agent".to_string())
    );
    assert!(state
        .store
        .take_totp_challenge(&challenge.id)
        .await
        .is_none());
    state.store.delete_totp("u_admin").await;
    assert!(state.store.get_totp("u_admin").await.is_none());
    assert_eq!(state.store.recovery_code_count("u_admin").await, 0);

    // Login history and personal access tokens.
    state
        .store
        .put_login_event(LoginEvent {
            id: new_opaque_code(),
            user_sub: "u_admin".to_string(),
            username: "admin@steadholme.local".to_string(),
            occurred_at: now_secs(),
            ip: "10.0.0.3".to_string(),
            user_agent: "pg-history-agent".to_string(),
            method: "password".to_string(),
            result: "success".to_string(),
            detail: "password login".to_string(),
        })
        .await;
    assert_eq!(state.store.list_login_events("u_admin", 10).await.len(), 1);
    let pat_plaintext = format!("pat_{}", new_opaque_code());
    let pat_hash = keystone::auth::secret_hash(&pat_plaintext);
    let pat_now = now_secs();
    let pat = PersonalAccessToken {
        id: new_opaque_code(),
        user_sub: "u_admin".to_string(),
        name: "pg token".to_string(),
        token_hash: pat_hash.clone(),
        scopes: "profile".to_string(),
        created_at: pat_now,
        expires_at: pat_now + 86400,
        revoked_at: 0,
    };
    state
        .store
        .put_personal_token(pat.clone())
        .await
        .expect("persist PAT");
    assert!(state
        .store
        .list_personal_tokens("u_admin")
        .await
        .iter()
        .any(|token| token.id == pat.id));
    let mut duplicate_hash = pat.clone();
    duplicate_hash.id = new_opaque_code();
    duplicate_hash.name = "duplicate hash must fail".to_string();
    assert_eq!(
        state.store.put_personal_token(duplicate_hash).await,
        Err(keystone::store::StoreError::Backend),
        "duplicate token hash is an explicit persistence failure"
    );
    assert_eq!(
        state
            .store
            .list_personal_tokens("u_admin")
            .await
            .iter()
            .filter(|token| token.token_hash == pat_hash)
            .count(),
        1,
        "unique token_hash index rejects ambiguous authority"
    );
    assert_eq!(
        state
            .store
            .find_active_personal_token(&pat_hash, pat_now)
            .await
            .expect("authoritative PAT lookup")
            .map(|token| token.id),
        Some(pat.id.clone())
    );
    assert!(state
        .store
        .find_active_personal_token("missing-hash", pat_now)
        .await
        .expect("authoritative PAT miss")
        .is_none());
    state.store.set_disabled("u_admin", true).await;
    assert!(state
        .store
        .find_active_personal_token(&pat_hash, pat_now)
        .await
        .expect("disabled owner lookup")
        .is_none());
    state.store.set_disabled("u_admin", false).await;
    state
        .store
        .revoke_personal_token("u_admin", &pat.id, pat_now)
        .await
        .expect("revoke PAT");
    assert!(state
        .store
        .find_active_personal_token(&pat_hash, pat_now)
        .await
        .expect("revoked PAT lookup")
        .is_none());

    let expired_plaintext = format!("pat_{}", new_opaque_code());
    let expired = PersonalAccessToken {
        id: new_opaque_code(),
        user_sub: "u_admin".to_string(),
        name: "expired pg token".to_string(),
        token_hash: keystone::auth::secret_hash(&expired_plaintext),
        scopes: "profile".to_string(),
        created_at: pat_now.saturating_sub(60),
        expires_at: pat_now,
        revoked_at: 0,
    };
    state
        .store
        .put_personal_token(expired.clone())
        .await
        .expect("persist expired PAT fixture");
    assert!(state
        .store
        .find_active_personal_token(&expired.token_hash, pat_now)
        .await
        .expect("expired PAT lookup")
        .is_none());
    state
        .store
        .revoke_personal_token("u_admin", &expired.id, pat_now)
        .await
        .expect("revoke expired PAT fixture");

    // webauthn credentials: put -> list -> get -> update passkey.
    let cred = Credential {
        cred_id: "cred-pg-1".to_string(),
        user_sub: "u_admin".to_string(),
        passkey: r#"{"v":1}"#.to_string(),
        created_at: now_secs(),
    };
    state.store.put_credential(cred.clone()).await;
    assert_eq!(state.store.list_credentials("u_admin").await.len(), 1);
    assert_eq!(
        state
            .store
            .get_credential("cred-pg-1")
            .await
            .map(|c| c.passkey),
        Some(r#"{"v":1}"#.to_string())
    );
    state
        .store
        .update_credential_passkey("cred-pg-1", r#"{"v":2}"#)
        .await;
    assert_eq!(
        state
            .store
            .get_credential("cred-pg-1")
            .await
            .map(|c| c.passkey),
        Some(r#"{"v":2}"#.to_string()),
        "counter/passkey update persisted"
    );

    // webauthn ceremony state: put -> single-use take.
    let wstate = WebauthnState {
        id: new_opaque_code(),
        kind: "reg".to_string(),
        state: r#"{"reg":true}"#.to_string(),
        expires_at: now_secs() + 300,
    };
    state.store.put_state(wstate.clone()).await;
    let taken = state
        .store
        .take_state(&wstate.id)
        .await
        .expect("state present once");
    assert_eq!(taken.kind, "reg");
    assert!(
        state.store.take_state(&wstate.id).await.is_none(),
        "single-use: ceremony state is consumed"
    );

    // --- full HTTP flow through the PG-backed app (authorize -> token -> userinfo) ---
    let (issued_code, returned_state) = authorize_ok(&state).await;
    assert!(!issued_code.is_empty(), "authorize minted a code");
    assert_eq!(returned_state, "xyz123", "state preserved");

    let (status, _, body) = call(&state, token_request(&issued_code, REDIRECT_URI, VERIFIER)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token exchange via PG store succeeds"
    );
    let tok: Value = serde_json::from_slice(&body).unwrap();
    let access_token = tok["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    let id_token = tok["id_token"].as_str().expect("id_token").to_string();

    // Verify tokens against the live JWKS (same path Sluice uses).
    let (_, _, jwks_body) = call(&state, get("/jwks.json")).await;
    let jwks: Value = serde_json::from_slice(&jwks_body).unwrap();
    let key = &jwks["keys"][0];
    let decoding =
        DecodingKey::from_rsa_components(key["n"].as_str().unwrap(), key["e"].as_str().unwrap())
            .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[CLIENT_ID]);
    let id = decode::<Value>(&id_token, &decoding, &validation).unwrap();
    assert_eq!(id.claims["sub"], "u_admin");
    assert_eq!(id.claims["email"], "admin@steadholme.local");

    // Replay the consumed code -> invalid_grant (single-use through the HTTP path).
    let (status, _, body) = call(&state, token_request(&issued_code, REDIRECT_URI, VERIFIER)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "replay rejected");
    let e: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(e["error"], "invalid_grant");

    // /userinfo with the access_token resolves the seeded user from Postgres.
    let req = Request::builder()
        .uri("/userinfo")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = call(&state, req).await;
    assert_eq!(status, StatusCode::OK);
    let ui: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ui["sub"], "u_admin");
    assert_eq!(ui["email"], "admin@steadholme.local");

    println!("PG STORE INTEGRATION OK: migrate + idempotent seed + client/user/code round-trip + single-use + full authorize/token/userinfo flow against real Postgres");
}

// --- helpers (mirror the in-process contract test) -------------------------

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

async fn authorize_ok(state: &AppState) -> (String, String) {
    let uri = format!(
        "/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}\
         &scope=openid+email+profile&state=xyz123&code_challenge={CHALLENGE}\
         &code_challenge_method=S256&nonce=n-abc"
    );
    // `/authorize` now gates on a session; establish one for the seeded admin.
    let session_cookie =
        keystone::auth::create_session(state, "u_admin", "test-agent", "127.0.0.1").await;
    let req = Request::builder()
        .uri(uri)
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
    let query = location.split_once('?').expect("redirect has query").1;
    let (mut code, mut st) = (String::new(), String::new());
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "code" => code = v.to_string(),
                "state" => st = v.to_string(),
                _ => {}
            }
        }
    }
    (code, st)
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
