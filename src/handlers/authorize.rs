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
use crate::handlers::login::{esc, html_with_cookies};
use crate::store::{new_opaque_code, AuthCode, Client};
use crate::{now_secs, AppState};

const CONSENT_HTML: &str = include_str!("../../templates/consent.html");

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
}

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(original_uri): OriginalUri,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, AppError> {
    // Steps 1–4: validate client, redirect_uri, response_type, PKCE.
    let (client, code_challenge) = validate(&state, &params).await?;

    // Step 5. GATE: require a valid login session. No session -> bounce to /login carrying the
    // full /authorize request (path + query) as a same-origin return_to.
    let sub = match auth::current_session(&state, &headers).await {
        Some(session) => session.user_sub,
        None => {
            let return_to = original_uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/authorize");
            let location = format!("/login?return_to={}", urlencode_component(return_to));
            return Ok((StatusCode::FOUND, [(header::LOCATION, location)]).into_response());
        }
    };

    // Step 6. CONSENT: first-party clients and previously-consented scope sets skip the screen.
    if client.first_party || already_consented(&state, &sub, &params.client_id, &params.scope).await
    {
        return Ok(issue_code(&state, &params, code_challenge, &sub).await);
    }

    // Otherwise render the consent screen (a fresh CSRF cookie/token is minted for the POST).
    let csrf = auth::new_csrf_token();
    let body = render_consent(&csrf, &client, &params);
    Ok(html_with_cookies(StatusCode::OK, body, &[auth::csrf_cookie(&csrf)]))
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
    };
    let (_client, code_challenge) = validate(&state, &params).await?;

    let sub = match auth::current_session(&state, &headers).await {
        Some(session) => session.user_sub,
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
            &sub,
            &params.client_id,
            "user denied consent",
        ));
        return Ok(redirect_error(&params, "access_denied"));
    }

    // Persist the granted scope (union with any prior grant) so future authorizes skip consent.
    let granted = union_scopes(
        &state
            .store
            .get_consent(&sub, &params.client_id)
            .await
            .unwrap_or_default(),
        &params.scope,
    );
    state
        .store
        .put_consent(&sub, &params.client_id, &granted, now_secs())
        .await;
    state.audit.emit(AuditEvent::info(
        "authorize.consent.grant",
        &sub,
        &params.client_id,
        "user granted consent",
    ));

    Ok(issue_code(&state, &params, code_challenge, &sub).await)
}

// ---------------------------------------------------------------------------
// Shared validation + code issuance
// ---------------------------------------------------------------------------

/// Steps 1–4: the client/redirect/response_type/PKCE checks shared by GET authorize and the
/// consent POST. Returns the resolved client and the validated `code_challenge`.
async fn validate(
    state: &AppState,
    params: &AuthorizeParams,
) -> Result<(Client, String), AppError> {
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
    Ok((client, code_challenge))
}

/// Mint + store a single-use authorization code and 302 back to redirect_uri (state preserved).
async fn issue_code(
    state: &AppState,
    params: &AuthorizeParams,
    code_challenge: String,
    sub: &str,
) -> Response {
    let code = new_opaque_code();
    state.audit.emit(AuditEvent::info(
        "authorize.grant",
        sub,
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
            sub: sub.to_string(),
            expires_at: now_secs() + state.config.code_ttl,
            used: false,
        })
        .await;

    // `state` is echoed verbatim (unchanged from the pre-consent contract the gateway relies on).
    let mut location = format!("{}?code={}", params.redirect_uri, code);
    if let Some(st) = params.state.as_deref() {
        location.push_str("&state=");
        location.push_str(st);
    }
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

/// True when the user already consented to a scope set covering `requested` for this client.
async fn already_consented(
    state: &AppState,
    sub: &str,
    client_id: &str,
    requested: &str,
) -> bool {
    match state.store.get_consent(sub, client_id).await {
        Some(granted) => scopes_covered(&granted, requested),
        None => false,
    }
}

/// 302 back to redirect_uri with an OAuth `error` (+ state), for the deny path.
fn redirect_error(params: &AuthorizeParams, error: &str) -> Response {
    let mut location = format!("{}?error={}", params.redirect_uri, error);
    if let Some(st) = params.state.as_deref() {
        location.push_str("&state=");
        location.push_str(st);
    }
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
    q
}

fn render_consent(csrf: &str, client: &Client, params: &AuthorizeParams) -> String {
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
        .replace(
            "{{HIDDEN}}",
            &[
                hidden("response_type", &params.response_type),
                hidden("client_id", &params.client_id),
                hidden("redirect_uri", &params.redirect_uri),
                hidden("scope", &params.scope),
                hidden("state", params.state.as_deref().unwrap_or("")),
                hidden("nonce", params.nonce.as_deref().unwrap_or("")),
                hidden("code_challenge", params.code_challenge.as_deref().unwrap_or("")),
                hidden(
                    "code_challenge_method",
                    params.code_challenge_method.as_deref().unwrap_or("S256"),
                ),
            ]
            .join("\n            "),
        )
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
