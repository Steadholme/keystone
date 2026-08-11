//! WebAuthn ceremony endpoints (passkey register + passwordless authenticate).
//!
//!   POST /webauthn/register/begin      (session)  -> CreationChallengeResponse
//!   POST /webauthn/register/finish     (session)  -> 204, persists the Passkey
//!   POST /webauthn/authenticate/begin             -> RequestChallengeResponse
//!   POST /webauthn/authenticate/finish            -> 204, creates a session
//!
//! In-flight ceremony state (the `PasskeyRegistration` / `PasskeyAuthentication`) is
//! parked in the `webauthn_states` table, keyed by a short-lived HttpOnly cookie. All
//! four endpoints are double-submit CSRF protected via the `X-CSRF-Token` header.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::authorize::{return_to_requests_strong, STRONG_ACR};
use crate::handlers::login::sanitize_return_to;
use crate::store::{Credential, TotpChallenge, WebauthnState};
use crate::webauthn as rp;
use crate::{now_secs, AppState};

const KIND_REG: &str = "reg";
const KIND_AUTH: &str = "auth";

#[derive(Debug, Deserialize)]
pub struct AuthenticateBegin {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub return_to: Option<String>,
    #[serde(default)]
    pub step_up: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BoundAuthentication {
    ceremony: PasskeyAuthentication,
    expected_user_sub: String,
    expected_factor_epoch: u64,
    source_session_binding: Option<String>,
    required_acr: Option<String>,
}

/// Guard the fetch endpoints with the double-submit CSRF header.
fn check_csrf(headers: &HeaderMap) -> Result<(), AppError> {
    let token = auth::header_csrf(headers)
        .ok_or_else(|| AppError::InvalidRequest("missing X-CSRF-Token".to_string()))?;
    if auth::verify_csrf(headers, &token) {
        Ok(())
    } else {
        Err(AppError::InvalidRequest("CSRF token mismatch".to_string()))
    }
}

fn wa_err(context: &str, e: impl std::fmt::Display) -> AppError {
    AppError::InvalidRequest(format!("{context}: {e}"))
}

// ---------------------------------------------------------------------------
// Registration (session-protected)
// ---------------------------------------------------------------------------

pub async fn register_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    check_csrf(&headers)?;
    let session = auth::current_session(&state, &headers)
        .await
        .ok_or_else(|| {
            AppError::Unauthorized("login required to register a passkey".to_string())
        })?;
    let user = state
        .store
        .get_user(&session.user_sub)
        .await
        .ok_or_else(|| AppError::Internal("session user not found".to_string()))?;

    // Exclude already-registered credentials so the authenticator won't double-enroll.
    let exclude: Vec<_> = state
        .store
        .list_credentials(&user.sub)
        .await
        .iter()
        .filter_map(|c| serde_json::from_str::<Passkey>(&c.passkey).ok())
        .map(|pk| pk.cred_id().clone())
        .collect();
    let exclude = (!exclude.is_empty()).then_some(exclude);

    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(
            rp::user_handle(&user.sub),
            &user.email,
            &user.email,
            exclude,
        )
        .map_err(|e| wa_err("start registration", e))?;

    let state_json =
        serde_json::to_string(&reg_state).map_err(|e| AppError::Internal(e.to_string()))?;
    let state_id = crate::store::new_opaque_code();
    state
        .store
        .put_state(WebauthnState {
            id: state_id.clone(),
            kind: KIND_REG.to_string(),
            state: state_json,
            expires_at: now_secs() + auth::WA_STATE_TTL,
        })
        .await;

    json_with_cookies(ccr, &[auth::wa_state_cookie(&state_id)])
}

pub async fn register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(cred): Json<RegisterPublicKeyCredential>,
) -> Result<Response, AppError> {
    check_csrf(&headers)?;
    let session = auth::current_session(&state, &headers)
        .await
        .ok_or_else(|| {
            AppError::Unauthorized("login required to register a passkey".to_string())
        })?;

    let reg_state: PasskeyRegistration = take_ceremony(&state, &headers, KIND_REG).await?;
    let passkey = state
        .webauthn
        .finish_passkey_registration(&cred, &reg_state)
        .map_err(|e| wa_err("finish registration", e))?;

    let passkey_json =
        serde_json::to_string(&passkey).map_err(|e| AppError::Internal(e.to_string()))?;
    let cred_id = rp::cred_id_str(passkey.cred_id());
    // Resolve the registrant's email for the audit actor before moving `user_sub`.
    let actor = state
        .store
        .get_user(&session.user_sub)
        .await
        .map(|u| u.email)
        .unwrap_or_else(|| session.user_sub.clone());
    state
        .store
        .put_credential_and_bump_factor(Credential {
            cred_id: cred_id.clone(),
            user_sub: session.user_sub,
            passkey: passkey_json,
            created_at: now_secs(),
        })
        .await
        .map_err(|_| {
            AppError::Internal("passkey registration could not be committed".to_string())
        })?;
    // Audit the registration with the public credential id (safe to record).
    state.audit.emit(AuditEvent::info(
        "webauthn.register",
        &actor,
        &cred_id,
        "passkey registered",
    ));

    Ok(no_content(&[auth::clear_cookie(auth::WA_STATE_COOKIE)]))
}

// ---------------------------------------------------------------------------
// Authentication (passwordless — no prior session)
// ---------------------------------------------------------------------------

pub async fn authenticate_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AuthenticateBegin>,
) -> Result<Response, AppError> {
    check_csrf(&headers)?;
    let step_up = body.step_up.as_deref().filter(|value| !value.is_empty());
    let (user, source_session_binding, expected_factor_epoch, required_acr, ceremony_expires_at) =
        if let Some(flow_id) = step_up {
            if flow_id.len() > 256 {
                return Err(AppError::InvalidRequest(
                    "step-up flow is invalid".to_string(),
                ));
            }
            let flow = state
                .store
                .take_totp_challenge(flow_id)
                .await
                .ok_or_else(|| AppError::InvalidRequest("step-up flow expired".to_string()))?;
            validate_passkey_step_up(&state, &headers, &flow).await?;
            let expected_epoch = flow.expected_factor_epoch.ok_or_else(|| {
                AppError::InvalidRequest("step-up factor binding missing".to_string())
            })?;
            let user = state
                .store
                .get_user(&flow.user_sub)
                .await
                .filter(|user| !user.disabled && user.factor_epoch == expected_epoch)
                .ok_or_else(|| AppError::Unauthorized("step-up subject changed".to_string()))?;
            (
                user,
                flow.source_session_binding,
                expected_epoch,
                Some(STRONG_ACR.to_string()),
                flow.expires_at.min(now_secs() + auth::WA_STATE_TTL),
            )
        } else {
            let user = state
                .store
                .get_user_by_username(&body.username)
                .await
                .ok_or_else(|| AppError::InvalidRequest("no passkeys for that user".to_string()))?;
            let return_to = sanitize_return_to(body.return_to.as_deref());
            let required_acr =
                return_to_requests_strong(&return_to).then(|| STRONG_ACR.to_string());
            if required_acr.is_some() && auth::current_session(&state, &headers).await.is_some() {
                return Err(AppError::InvalidRequest(
                    "a server-bound step-up flow is required".to_string(),
                ));
            }
            let expected_epoch = user.factor_epoch;
            (
                user,
                None,
                expected_epoch,
                required_acr,
                now_secs() + auth::WA_STATE_TTL,
            )
        };
    // A disabled account cannot start a passkey ceremony (defense in depth; finish re-checks).
    // Return the SAME opaque error as "no passkeys" so a disabled account can't be probed.
    if user.disabled {
        return Err(AppError::InvalidRequest(
            "no passkeys for that user".to_string(),
        ));
    }

    let passkeys: Vec<Passkey> = state
        .store
        .list_credentials(&user.sub)
        .await
        .iter()
        .filter_map(|c| serde_json::from_str::<Passkey>(&c.passkey).ok())
        .collect();
    if passkeys.is_empty() {
        return Err(AppError::InvalidRequest(
            "no passkeys for that user".to_string(),
        ));
    }

    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| wa_err("start authentication", e))?;

    let state_json = serde_json::to_string(&BoundAuthentication {
        ceremony: auth_state,
        expected_user_sub: user.sub.clone(),
        expected_factor_epoch,
        source_session_binding,
        required_acr,
    })
    .map_err(|e| AppError::Internal(e.to_string()))?;
    let state_id = crate::store::new_opaque_code();
    state
        .store
        .put_state(WebauthnState {
            id: state_id.clone(),
            kind: KIND_AUTH.to_string(),
            state: state_json,
            expires_at: ceremony_expires_at,
        })
        .await;

    json_with_cookies(rcr, &[auth::wa_state_cookie(&state_id)])
}

pub async fn authenticate_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(cred): Json<PublicKeyCredential>,
) -> Result<Response, AppError> {
    check_csrf(&headers)?;
    let row = take_ceremony_state(&state, &headers, KIND_AUTH).await?;
    let bound: BoundAuthentication = serde_json::from_str(&row.state).map_err(|_| {
        AppError::InvalidRequest("authentication ceremony binding invalid".to_string())
    })?;

    let result = match state
        .webauthn
        .finish_passkey_authentication(&cred, &bound.ceremony)
    {
        Ok(r) => r,
        Err(e) => {
            // Passwordless assertion failed — actor unknown at this point.
            state.audit.emit(AuditEvent::warning(
                "webauthn.authenticate.failure",
                "anonymous",
                "passkey",
                "assertion verification failed",
            ));
            return Err(wa_err("finish authentication", e));
        }
    };

    // Resolve the owning credential/user from the asserted credential id.
    let cred_id = rp::cred_id_str(result.cred_id());
    let stored = state
        .store
        .get_credential(&cred_id)
        .await
        .ok_or_else(|| AppError::Unauthorized("unknown credential".to_string()))?;
    if stored.user_sub != bound.expected_user_sub {
        return Err(AppError::Unauthorized(
            "credential subject mismatch".to_string(),
        ));
    }

    // Resolve the owning user and enforce the SAME gates as the password path (login.rs): a
    // disabled or unverified account cannot complete passkey login. Without this, a user disabled
    // AFTER registering a passkey could still authenticate and mint a session.
    let user = state
        .store
        .get_user(&stored.user_sub)
        .await
        .ok_or_else(|| AppError::Unauthorized("unknown user".to_string()))?;
    if user.disabled {
        crate::handlers::login::record_login_event(
            &state,
            &user.sub,
            &user.email,
            "passkey",
            "failure",
            "account disabled",
            &headers,
        )
        .await;
        state.audit.emit(AuditEvent::warning(
            "webauthn.authenticate.failure",
            &user.email,
            "passkey",
            "account disabled",
        ));
        return Err(AppError::Unauthorized("account disabled".to_string()));
    }
    if !user.email_verified {
        crate::handlers::login::record_login_event(
            &state,
            &user.sub,
            &user.email,
            "passkey",
            "failure",
            "email not verified",
            &headers,
        )
        .await;
        state.audit.emit(AuditEvent::warning(
            "webauthn.authenticate.failure",
            &user.email,
            "passkey",
            "email not verified",
        ));
        return Err(AppError::Unauthorized("email not verified".to_string()));
    }
    if user.factor_epoch != bound.expected_factor_epoch {
        return Err(AppError::Unauthorized(
            "factor state changed during authentication".to_string(),
        ));
    }
    if let Some(expected_binding) = bound.source_session_binding.as_deref() {
        let source_matches = auth::current_session(&state, &headers)
            .await
            .is_some_and(|session| {
                session.user_sub == bound.expected_user_sub
                    && session.session_binding.as_deref() == Some(expected_binding)
            });
        if !source_matches {
            return Err(AppError::Unauthorized(
                "step-up source session changed".to_string(),
            ));
        }
    }
    let requires_strong = match bound.required_acr.as_deref() {
        None => false,
        Some(STRONG_ACR) => true,
        Some(_) => {
            return Err(AppError::Unauthorized(
                "authentication assurance binding invalid".to_string(),
            ))
        }
    };
    if requires_strong && !result.user_verified() {
        return Err(AppError::Unauthorized(
            "user verification required for strong authentication".to_string(),
        ));
    }

    // Bump the stored signature counter only after the asserted credential, subject, source
    // session and factor generation have all matched the server-side ceremony binding.
    if result.needs_update() {
        if let Ok(mut pk) = serde_json::from_str::<Passkey>(&stored.passkey) {
            if pk.update_credential(&result).is_some() {
                if let Ok(updated) = serde_json::to_string(&pk) {
                    state
                        .store
                        .update_credential_passkey(&cred_id, &updated)
                        .await;
                }
            }
        }
    }
    let actor = user.email.clone();
    let session_cookie = if result.user_verified() {
        auth::try_create_strong_session_at_epoch(
            &state,
            &stored.user_sub,
            &crate::handlers::login::user_agent(&headers),
            &crate::handlers::register::client_ip(&headers),
            true,
            "hwk,user",
            bound.expected_factor_epoch,
        )
        .await
    } else {
        auth::try_create_session(
            &state,
            &stored.user_sub,
            &crate::handlers::login::user_agent(&headers),
            &crate::handlers::register::client_ip(&headers),
        )
        .await
    }
    .ok_or_else(|| AppError::Unauthorized("account not active".to_string()))?;
    crate::handlers::login::record_login_event(
        &state,
        &stored.user_sub,
        &actor,
        "passkey",
        "success",
        "passkey login",
        &headers,
    )
    .await;
    state.audit.emit(AuditEvent::info(
        "webauthn.authenticate.success",
        &actor,
        &cred_id,
        "passkey login",
    ));
    Ok(no_content(&[
        auth::session_cookie(&session_cookie, state.config.session_ttl),
        auth::clear_cookie(auth::WA_STATE_COOKIE),
    ]))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Consume the in-flight ceremony state referenced by the `__Host-wa` cookie, check its
/// kind + expiry, and deserialize it into `T`.
async fn take_ceremony<T: for<'de> Deserialize<'de>>(
    state: &AppState,
    headers: &HeaderMap,
    kind: &str,
) -> Result<T, AppError> {
    let row = take_ceremony_state(state, headers, kind).await?;
    serde_json::from_str(&row.state).map_err(|e| AppError::Internal(e.to_string()))
}

async fn take_ceremony_state(
    state: &AppState,
    headers: &HeaderMap,
    kind: &str,
) -> Result<WebauthnState, AppError> {
    let state_id = auth::get_cookie(headers, auth::WA_STATE_COOKIE)
        .ok_or_else(|| AppError::InvalidRequest("no ceremony in progress".to_string()))?;
    let row =
        state.store.take_state(&state_id).await.ok_or_else(|| {
            AppError::InvalidRequest("ceremony state expired or missing".to_string())
        })?;
    if row.kind != kind || now_secs() > row.expires_at {
        return Err(AppError::InvalidRequest(
            "ceremony state invalid".to_string(),
        ));
    }
    Ok(row)
}

async fn validate_passkey_step_up(
    state: &AppState,
    headers: &HeaderMap,
    flow: &TotpChallenge,
) -> Result<(), AppError> {
    let Some(expected_binding) = flow.source_session_binding.as_deref() else {
        return Err(AppError::InvalidRequest(
            "step-up source binding missing".to_string(),
        ));
    };
    if flow.required_acr.as_deref() != Some(STRONG_ACR)
        || !return_to_requests_strong(&flow.return_to)
    {
        return Err(AppError::InvalidRequest(
            "step-up assurance binding invalid".to_string(),
        ));
    }
    let source_matches = auth::current_session(state, headers)
        .await
        .is_some_and(|session| {
            session.user_sub == flow.user_sub
                && session.session_binding.as_deref() == Some(expected_binding)
        });
    if !source_matches {
        return Err(AppError::Unauthorized(
            "step-up source session changed".to_string(),
        ));
    }
    Ok(())
}

fn json_with_cookies<T: Serialize>(value: T, cookies: &[String]) -> Result<Response, AppError> {
    let mut resp = Json(value).into_response();
    attach(&mut resp, cookies)?;
    Ok(resp)
}

fn no_content(cookies: &[String]) -> Response {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    // Header values built from our own cookie strings never fail to parse.
    let _ = attach(&mut resp, cookies);
    resp
}

fn attach(resp: &mut Response, cookies: &[String]) -> Result<(), AppError> {
    for c in cookies {
        let v = HeaderValue::from_str(c)
            .map_err(|e| AppError::Internal(format!("bad Set-Cookie: {e}")))?;
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    Ok(())
}
