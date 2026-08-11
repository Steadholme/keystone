//! `GET /authorize` — authorization_code + PKCE S256, with a consent step.
//!
//! Validates client_id and EXACT redirect_uri (400 JSON if bad — never redirect
//! to an untrusted URI), requires `code_challenge` + `code_challenge_method=S256`,
//! then GATES ON A SESSION: no valid session 302s to `/login?return_to=<this URL>`.
//!
//! With a session: a FIRST-PARTY client (the Sluice gateway) or a client the user has
//! already consented to for the requested scopes gets a code immediately. A third-party
//! client the user has not yet approved is shown a consent screen (`POST /authorize/consent`
//! records the decision) before any code is minted.

use axum::extract::{OriginalUri, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::login::{esc, html_with_cookies, user_agent};
use crate::handlers::register::client_ip;
use crate::store::{
    new_opaque_code, AssuranceLevel, AuthCode, AuthCodeBinding, Client, Session, SessionAssurance,
    SessionAssuranceLookup, TotpChallenge,
};
use crate::{now_secs, AppState};

const CONSENT_HTML: &str = include_str!("../../templates/consent.html");
pub(crate) const STRONG_ACR: &str = "hf-aal-strong";
pub(crate) const STRONG_AUTH_MAX_AGE: u64 = 300;
const STEP_UP_TTL: u64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequiredAcr {
    None,
    Strong,
}

impl RequiredAcr {
    fn persisted(self) -> Option<String> {
        match self {
            Self::None => None,
            Self::Strong => Some(STRONG_ACR.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub acr_values: Option<String>,
}

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(original_uri): OriginalUri,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, AppError> {
    // Steps 1–4: validate client, redirect_uri, response_type, PKCE.
    let acr_occurrences = original_uri
        .query()
        .map_or(0, |query| query_key_occurrences(query, "acr_values"));
    let (client, code_challenge, required_acr) = validate(&state, &params, acr_occurrences).await?;

    // Step 5. GATE: require a valid login session. No session -> bounce to /login carrying the
    // full /authorize request (path + query) as a same-origin return_to.
    let session = match auth::current_session(&state, &headers).await {
        Some(session) => session,
        None => {
            let return_to = original_uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/authorize");
            let location = format!("/login?return_to={}", urlencode_component(return_to));
            return Ok((StatusCode::FOUND, [(header::LOCATION, location)]).into_response());
        }
    };

    if required_acr == RequiredAcr::Strong && !authoritative_fresh_strong(&state, &session).await? {
        let return_to = original_uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/authorize");
        return Ok(begin_strong_step_up(&state, &headers, &params, &session, return_to).await);
    }

    // Step 6. CONSENT: first-party clients and previously-consented scope sets skip the screen.
    if client.first_party
        || already_consented(&state, &session.user_sub, &params.client_id, &params.scope).await
    {
        return issue_code(&state, &params, code_challenge, &session, required_acr).await;
    }

    // Otherwise render the consent screen (a fresh CSRF cookie/token is minted for the POST).
    let csrf = auth::new_csrf_token();
    let acr_binding = consent_acr_binding(&state, &csrf, &params);
    let body = render_consent(&csrf, &acr_binding, &client, &params);
    Ok(html_with_cookies(
        StatusCode::OK,
        body,
        &[auth::csrf_cookie(&csrf)],
    ))
}

#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub acr_values: Option<String>,
    #[serde(default)]
    pub acr_binding: String,
    #[serde(default)]
    pub csrf_token: String,
    /// `approve` or `deny`.
    #[serde(default)]
    pub decision: String,
}

/// `POST /authorize/consent` — record the user's decision for a third-party client.
///
/// Re-validates client + redirect_uri + PKCE from the hidden form fields (so a forged form
/// cannot smuggle an unregistered redirect_uri), requires the same login session, and checks
/// CSRF. Approve -> persist consent + mint code; Deny -> redirect with `error=access_denied`.
pub async fn consent_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> Result<Response, AppError> {
    let params = AuthorizeParams {
        response_type: form.response_type,
        client_id: form.client_id,
        redirect_uri: form.redirect_uri,
        scope: form.scope,
        state: form.state,
        code_challenge: form.code_challenge,
        code_challenge_method: form.code_challenge_method,
        nonce: form.nonce,
        acr_values: form.acr_values,
    };
    let acr_occurrences = usize::from(params.acr_values.is_some());
    let (_client, code_challenge, required_acr) =
        validate(&state, &params, acr_occurrences).await?;
    if !verify_consent_acr_binding(&state, &form.csrf_token, &params, &form.acr_binding) {
        return Err(AppError::InvalidRequest(
            "consent request binding is invalid or expired".to_string(),
        ));
    }

    let session = match auth::current_session(&state, &headers).await {
        Some(session) => session,
        None => {
            // Session expired mid-consent — send them back through the login gate.
            let location = format!(
                "/login?return_to={}",
                urlencode_component(&authorize_url(&params))
            );
            return Ok((StatusCode::FOUND, [(header::LOCATION, location)]).into_response());
        }
    };

    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::InvalidRequest(
            "invalid or expired form token".to_string(),
        ));
    }

    if form.decision != "approve" {
        state.audit.emit(AuditEvent::warning(
            "authorize.consent.deny",
            &session.user_sub,
            &params.client_id,
            "user denied consent",
        ));
        return Ok(redirect_error(&params, "access_denied"));
    }

    if required_acr == RequiredAcr::Strong && !authoritative_fresh_strong(&state, &session).await? {
        let return_to = authorize_url(&params);
        return Ok(begin_strong_step_up(&state, &headers, &params, &session, &return_to).await);
    }

    // Persist the granted scope (union with any prior grant) so future authorizes skip consent.
    let granted = union_scopes(
        &state
            .store
            .get_consent(&session.user_sub, &params.client_id)
            .await
            .unwrap_or_default(),
        &params.scope,
    );
    state
        .store
        .put_consent(&session.user_sub, &params.client_id, &granted, now_secs())
        .await;
    state.audit.emit(AuditEvent::info(
        "authorize.consent.grant",
        &session.user_sub,
        &params.client_id,
        "user granted consent",
    ));

    issue_code(&state, &params, code_challenge, &session, required_acr).await
}

// ---------------------------------------------------------------------------
// Shared validation + code issuance
// ---------------------------------------------------------------------------

/// Steps 1–4: the client/redirect/response_type/PKCE checks shared by GET authorize and the
/// consent POST. Returns the resolved client and the validated `code_challenge`.
async fn validate(
    state: &AppState,
    params: &AuthorizeParams,
    acr_occurrences: usize,
) -> Result<(Client, String, RequiredAcr), AppError> {
    let client = state
        .store
        .get_client(&params.client_id)
        .await
        .ok_or_else(|| AppError::InvalidClient("unknown client_id".to_string()))?;

    if !client.allows_redirect(&params.redirect_uri) {
        return Err(AppError::InvalidClient(
            "redirect_uri is not registered for this client".to_string(),
        ));
    }
    if params.response_type != "code" {
        return Err(AppError::InvalidRequest(
            "response_type must be \"code\"".to_string(),
        ));
    }
    let code_challenge = match params.code_challenge {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => {
            return Err(AppError::InvalidRequest(
                "code_challenge is required (PKCE S256)".to_string(),
            ))
        }
    };
    if params.code_challenge_method.as_deref() != Some("S256") {
        return Err(AppError::InvalidRequest(
            "code_challenge_method must be S256".to_string(),
        ));
    }
    let required_acr = match (acr_occurrences, params.acr_values.as_deref()) {
        (0, None) | (1, Some("")) => RequiredAcr::None,
        (1, Some(STRONG_ACR)) => RequiredAcr::Strong,
        _ => {
            return Err(AppError::InvalidRequest(
                "acr_values must be absent, empty, or exactly hf-aal-strong".to_string(),
            ))
        }
    };
    Ok((client, code_challenge, required_acr))
}

/// Mint + store a single-use authorization code and 302 back to redirect_uri (state preserved).
async fn issue_code(
    state: &AppState,
    params: &AuthorizeParams,
    code_challenge: String,
    session: &Session,
    required_acr: RequiredAcr,
) -> Result<Response, AppError> {
    // Re-check immediately before the code snapshot is persisted. `/token` repeats the same
    // closed-ACR/freshness check after atomically redeeming the bound code.
    if required_acr == RequiredAcr::Strong && !authoritative_fresh_strong(state, session).await? {
        return Ok(redirect_error(params, "access_denied"));
    }
    let code = new_opaque_code();
    state.audit.emit(AuditEvent::info(
        "authorize.grant",
        &session.user_sub,
        &params.client_id,
        "authorization code issued",
    ));
    state
        .store
        .put_code(AuthCode {
            code: code.clone(),
            client_id: params.client_id.clone(),
            redirect_uri: params.redirect_uri.clone(),
            scope: params.scope.clone(),
            nonce: params.nonce.clone(),
            code_challenge,
            sub: session.user_sub.clone(),
            expires_at: now_secs() + state.config.code_ttl,
            used: false,
            binding: AuthCodeBinding::from_session(session),
            required_acr: required_acr.persisted(),
        })
        .await;

    let mut pairs = vec![("code", code.as_str())];
    if let Some(st) = params.state.as_deref() {
        pairs.push(("state", st));
    }
    let location = append_query_params(&params.redirect_uri, &pairs);
    Ok((StatusCode::FOUND, [(header::LOCATION, location)]).into_response())
}

/// True when the user already consented to a scope set covering `requested` for this client.
async fn already_consented(state: &AppState, sub: &str, client_id: &str, requested: &str) -> bool {
    match state.store.get_consent(sub, client_id).await {
        Some(granted) => scopes_covered(&granted, requested),
        None => false,
    }
}

/// 302 back to redirect_uri with an OAuth `error` (+ state), for the deny path.
fn redirect_error(params: &AuthorizeParams, error: &str) -> Response {
    let mut pairs = vec![("error", error)];
    if let Some(st) = params.state.as_deref() {
        pairs.push(("state", st));
    }
    let location = append_query_params(&params.redirect_uri, &pairs);
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

async fn authoritative_fresh_strong(state: &AppState, session: &Session) -> Result<bool, AppError> {
    let Some(binding) = session.session_binding.as_deref() else {
        return Ok(false);
    };
    let now = now_secs();
    let assurance = state
        .store
        .lookup_session_assurance(&session.user_sub, binding, now)
        .await
        .map_err(|_| AppError::Internal("session assurance unavailable".to_string()))?;
    Ok(matches!(
        assurance,
        SessionAssuranceLookup::Live(ref value) if fresh_strong_assurance(value, now)
    ))
}

pub(crate) fn fresh_strong_assurance(value: &SessionAssurance, now: u64) -> bool {
    value.aal == AssuranceLevel::MfaStrong
        && value.uv
        && matches!(value.amr.as_str(), "pwd,otp" | "hwk,user")
        && value.auth_time > 0
        && now
            .checked_sub(value.auth_time)
            .is_some_and(|age| age <= STRONG_AUTH_MAX_AGE)
}

async fn begin_strong_step_up(
    state: &AppState,
    headers: &HeaderMap,
    params: &AuthorizeParams,
    session: &Session,
    return_to: &str,
) -> Response {
    let Some(source_session_binding) = session.session_binding.clone() else {
        return redirect_error(params, "access_denied");
    };
    let Some(user) = state
        .store
        .get_user(&session.user_sub)
        .await
        .filter(|user| !user.disabled)
    else {
        return redirect_error(params, "access_denied");
    };
    let has_totp = state
        .store
        .get_totp(&user.sub)
        .await
        .is_some_and(|factor| factor.enabled);
    let has_passkey = !state.store.list_credentials(&user.sub).await.is_empty();
    if !has_totp && !has_passkey {
        state.audit.emit(AuditEvent::warning(
            "authorize.step_up_unavailable",
            &user.sub,
            &params.client_id,
            "no qualifying strong factor enrolled",
        ));
        return redirect_error(params, "access_denied");
    }

    let flow_id = new_opaque_code();
    state
        .store
        .put_totp_challenge(TotpChallenge {
            id: flow_id.clone(),
            user_sub: user.sub,
            return_to: return_to.to_string(),
            user_agent: user_agent(headers),
            ip: client_ip(headers),
            expires_at: now_secs() + STEP_UP_TTL,
            source_session_binding: Some(source_session_binding),
            expected_factor_epoch: Some(user.factor_epoch),
            required_acr: Some(STRONG_ACR.to_string()),
            password_verified: false,
        })
        .await;
    let location = format!(
        "/login?return_to={}&step_up={}",
        urlencode_component(return_to),
        urlencode_component(&flow_id)
    );
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

// ---------------------------------------------------------------------------
// Scope helpers + consent rendering
// ---------------------------------------------------------------------------

/// Every requested scope must be present in the granted set.
fn scopes_covered(granted: &str, requested: &str) -> bool {
    let g: std::collections::HashSet<&str> = granted.split_whitespace().collect();
    requested.split_whitespace().all(|s| g.contains(s))
}

/// Union of two space-delimited scope strings, sorted + de-duplicated for a stable record.
fn union_scopes(a: &str, b: &str) -> String {
    let mut set: std::collections::BTreeSet<&str> = a.split_whitespace().collect();
    for s in b.split_whitespace() {
        set.insert(s);
    }
    set.into_iter().collect::<Vec<_>>().join(" ")
}

/// Human description for a known scope token (falls back to the raw token).
fn scope_description(scope: &str) -> &str {
    match scope {
        "openid" => "Verify your identity",
        "email" => "Read your email address",
        "profile" => "Read your basic profile (display name)",
        "offline_access" => "Keep you signed in when you're away",
        other => other,
    }
}

/// Rebuild the `/authorize?...` URL from params (for a mid-consent re-login return_to).
fn authorize_url(p: &AuthorizeParams) -> String {
    let mut q = format!(
        "/authorize?response_type={}&client_id={}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256",
        urlencode_component(&p.response_type),
        urlencode_component(&p.client_id),
        urlencode_component(&p.redirect_uri),
        urlencode_component(&p.scope),
        urlencode_component(p.code_challenge.as_deref().unwrap_or("")),
    );
    if let Some(st) = p.state.as_deref() {
        q.push_str(&format!("&state={}", urlencode_component(st)));
    }
    if let Some(n) = p.nonce.as_deref() {
        q.push_str(&format!("&nonce={}", urlencode_component(n)));
    }
    if let Some(acr) = p.acr_values.as_deref() {
        q.push_str(&format!("&acr_values={}", urlencode_component(acr)));
    }
    q
}

fn render_consent(
    csrf: &str,
    acr_binding: &str,
    client: &Client,
    params: &AuthorizeParams,
) -> String {
    let scopes_html: String = params
        .scope
        .split_whitespace()
        .map(|s| {
            format!(
                r#"<li class="scope"><span class="scope__name">{}</span></li>"#,
                esc(scope_description(s))
            )
        })
        .collect();
    let scopes_html = if scopes_html.is_empty() {
        r#"<li class="scope"><span class="scope__name">Sign you in</span></li>"#.to_string()
    } else {
        scopes_html
    };
    // Hidden fields carrying the request verbatim through the POST.
    let hidden = |name: &str, val: &str| {
        format!(
            r#"<input type="hidden" name="{}" value="{}">"#,
            name,
            esc(val)
        )
    };
    CONSENT_HTML
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{CLIENT_NAME}}", &esc(&client.name))
        .replace("{{SCOPES}}", &scopes_html)
        .replace("{{HIDDEN}}", &{
            let mut fields = vec![
                hidden("response_type", &params.response_type),
                hidden("client_id", &params.client_id),
                hidden("redirect_uri", &params.redirect_uri),
                hidden("scope", &params.scope),
                hidden("state", params.state.as_deref().unwrap_or("")),
                hidden("nonce", params.nonce.as_deref().unwrap_or("")),
                hidden("acr_binding", acr_binding),
                hidden(
                    "code_challenge",
                    params.code_challenge.as_deref().unwrap_or(""),
                ),
                hidden(
                    "code_challenge_method",
                    params.code_challenge_method.as_deref().unwrap_or("S256"),
                ),
            ];
            if let Some(acr) = params.acr_values.as_deref() {
                fields.push(hidden("acr_values", acr));
            }
            fields.join("\n            ")
        })
}

fn consent_acr_binding(state: &AppState, csrf: &str, params: &AuthorizeParams) -> String {
    let digest = auth::secret_hash(&consent_acr_binding_message(csrf, params));
    auth::signed_value(&state.config.session_secret, &digest)
}

fn verify_consent_acr_binding(
    state: &AppState,
    csrf: &str,
    params: &AuthorizeParams,
    presented: &str,
) -> bool {
    let expected = auth::secret_hash(&consent_acr_binding_message(csrf, params));
    auth::verify_signed(&state.config.session_secret, presented)
        .is_some_and(|actual| auth::constant_time_eq(actual.as_bytes(), expected.as_bytes()))
}

fn consent_acr_binding_message(csrf: &str, params: &AuthorizeParams) -> String {
    let fields = [
        params.response_type.as_str(),
        params.client_id.as_str(),
        params.redirect_uri.as_str(),
        params.scope.as_str(),
        params.state.as_deref().unwrap_or(""),
        params.code_challenge.as_deref().unwrap_or(""),
        params.code_challenge_method.as_deref().unwrap_or(""),
        params.nonce.as_deref().unwrap_or(""),
        params.acr_values.as_deref().unwrap_or(""),
    ];
    let mut message = format!("holdfast.keystone.consent-acr.v1\n{}:{}", csrf.len(), csrf);
    for field in fields {
        message.push('\n');
        message.push_str(&field.len().to_string());
        message.push(':');
        message.push_str(field);
    }
    message
}

pub(crate) fn return_to_requests_strong(return_to: &str) -> bool {
    let Some((path, query)) = return_to.split_once('?') else {
        return false;
    };
    if path != "/authorize" || query.contains('#') {
        return false;
    }
    let values = query_values(query, "acr_values");
    values.len() == 1 && values[0].as_deref() == Some(STRONG_ACR)
}

fn query_key_occurrences(query: &str, expected: &str) -> usize {
    query
        .split('&')
        .filter(|pair| {
            let key = pair.split_once('=').map_or(*pair, |(key, _)| key);
            decode_form_component(key).as_deref() == Some(expected)
        })
        .count()
}

fn query_values(query: &str, expected: &str) -> Vec<Option<String>> {
    query
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode_form_component(key).as_deref() == Some(expected))
                .then(|| decode_form_component(value))
        })
        .collect()
}

fn decode_form_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let high = hex_value(bytes[index + 1])?;
                let low = hex_value(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 2;
            }
            b'%' => return None,
            byte => decoded.push(byte),
        }
        index += 1;
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn append_query_params(base: &str, pairs: &[(&str, &str)]) -> String {
    let (without_fragment, fragment) = base
        .split_once('#')
        .map_or((base, None), |(head, tail)| (head, Some(tail)));
    let mut location = without_fragment.to_string();
    let mut separator = if without_fragment.contains('?') {
        if without_fragment.ends_with('?') || without_fragment.ends_with('&') {
            ""
        } else {
            "&"
        }
    } else {
        "?"
    };
    for (key, value) in pairs {
        location.push_str(separator);
        location.push_str(&urlencode_component(key));
        location.push('=');
        location.push_str(&urlencode_component(value));
        separator = "&";
    }
    if let Some(fragment) = fragment {
        location.push('#');
        location.push_str(fragment);
    }
    location
}

/// Percent-encode a string for safe use as a single query-string component value
/// (encodes everything outside the RFC 3986 unreserved set).
fn urlencode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strong(auth_time: u64) -> SessionAssurance {
        SessionAssurance {
            session_binding: "ab".repeat(32),
            aal: AssuranceLevel::MfaStrong,
            uv: true,
            auth_time,
            amr: "pwd,otp".to_string(),
            factor_epoch: 7,
        }
    }

    #[test]
    fn strong_freshness_boundaries_are_closed() {
        let now = 10_000;
        assert!(fresh_strong_assurance(&strong(now - 300), now));
        assert!(!fresh_strong_assurance(&strong(now - 301), now));
        assert!(!fresh_strong_assurance(&strong(now + 1), now));

        let mut uv_false = strong(now);
        uv_false.uv = false;
        assert!(!fresh_strong_assurance(&uv_false, now));

        let mut recovery = strong(now);
        recovery.amr = "pwd,rcv".to_string();
        assert!(!fresh_strong_assurance(&recovery, now));
    }

    #[test]
    fn return_to_accepts_only_one_exact_strong_acr() {
        assert!(return_to_requests_strong(
            "/authorize?client_id=c&acr_values=hf-aal-strong"
        ));
        assert!(!return_to_requests_strong(
            "/authorize?acr_values=hf-aal-strong&acr_values=hf-aal-strong"
        ));
        assert!(!return_to_requests_strong(
            "/authorize?acr_values=hf-aal-strong+other"
        ));
        assert!(!return_to_requests_strong(
            "/other?acr_values=hf-aal-strong"
        ));
    }

    #[test]
    fn redirect_query_values_are_encoded_and_existing_query_is_preserved() {
        assert_eq!(
            append_query_params(
                "https://rp.example/cb?tenant=one",
                &[("code", "opaque"), ("state", "a&b=c d")],
            ),
            "https://rp.example/cb?tenant=one&code=opaque&state=a%26b%3Dc%20d"
        );
    }

    #[test]
    fn encoded_acr_key_is_counted_for_duplicate_rejection() {
        assert_eq!(
            query_key_occurrences(
                "acr_values=hf-aal-strong&acr%5Fvalues=hf-aal-strong",
                "acr_values",
            ),
            2
        );
    }
}
