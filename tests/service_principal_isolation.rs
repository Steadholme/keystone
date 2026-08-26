//! Structural isolation tests for non-human service principals.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use keystone::{now_secs, AppState};
use tower::ServiceExt;

const PRINCIPAL_SLUG: &str = "nonhuman-fixture";
const ACTOR: &str = "integration-test-operator";
const CLIENT_ID: &str = "sluice-dev";
const REDIRECT_URI: &str = "http://127.0.0.1:9090/callback";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

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

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all(header::SET_COOKIE).iter() {
        let raw = value.to_str().ok()?;
        let (key, value) = raw.split(';').next()?.split_once('=')?;
        if key == name {
            return Some(value.to_string());
        }
    }
    None
}

fn authorize_uri() -> String {
    format!(
        "/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}\
         &scope=openid+email+profile&state=system-isolation&code_challenge={CHALLENGE}\
         &code_challenge_method=S256&nonce=system-isolation"
    )
}

#[tokio::test]
async fn service_principal_cannot_enter_human_login_sso_or_admin_surfaces() {
    let state = keystone::build_dev_state();
    state
        .store
        .create_service_principal(
            PRINCIPAL_SLUG,
            "Non-human fixture identity",
            ACTOR,
            now_secs(),
        )
        .await
        .expect("create service-principal fixture");
    let subject = format!("service:{PRINCIPAL_SLUG}");

    // The principal is deliberately stored outside the human `users` authority.
    let principal = state
        .store
        .get_service_principal(PRINCIPAL_SLUG)
        .await
        .expect("read service-principal fixture")
        .expect("service-principal fixture exists");
    assert_eq!(principal.subject, subject);
    let events = state
        .store
        .list_service_principal_events(PRINCIPAL_SLUG)
        .await
        .expect("list service-principal events");
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].action,
        keystone::store::ServicePrincipalEventAction::Created
    );
    assert!(state.store.get_user(&subject).await.is_none());
    assert!(state
        .store
        .get_user_by_username(PRINCIPAL_SLUG)
        .await
        .is_none());
    assert!(state
        .store
        .list_users()
        .await
        .iter()
        .all(|user| user.sub != subject && user.email != PRINCIPAL_SLUG));

    // Even the authoritative session seam refuses a non-user subject, so it cannot enter SSO.
    assert!(
        keystone::auth::try_create_session(&state, &subject, "test", "127.0.0.1")
            .await
            .is_none()
    );
    let authorize = Request::builder()
        .uri(authorize_uri())
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = call(&state, authorize).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|location| location.starts_with("/login?return_to=")));

    // The browser password-login path cannot resolve the service-principal slug as a user.
    let login_get = Request::builder()
        .uri("/login")
        .body(Body::empty())
        .unwrap();
    let (_, login_headers, _) = call(&state, login_get).await;
    let csrf = cookie_value(&login_headers, "__Host-csrf").expect("login CSRF cookie");
    let login_post = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={csrf}"))
        .body(Body::from(format!(
            "username={PRINCIPAL_SLUG}&password=never-valid&csrf_token={csrf}&return_to=%2Faccount"
        )))
        .unwrap();
    let (status, headers, _) = call(&state, login_post).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(cookie_value(&headers, "__Host-session").is_none());

    // The human admin console is user-backed and therefore does not enumerate the principal.
    let admin_session = keystone::auth::try_create_session(&state, "u_admin", "test", "127.0.0.1")
        .await
        .expect("seeded human admin can create a session");
    let admin_get = Request::builder()
        .uri("/admin")
        .header(header::COOKIE, format!("__Host-session={admin_session}"))
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = call(&state, admin_get).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(!html.contains(PRINCIPAL_SLUG));
    assert!(!html.contains(&subject));
}
