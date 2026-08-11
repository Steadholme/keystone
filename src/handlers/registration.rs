//! Durable Keystone registration-authority feed for Access Governance.
//!
//! The wire is available only when Keystone is running its full app on the mTLS listener.
//! Every request is additionally bound to service, audience, method, path, sorted raw query,
//! body hash, rotating KID, timestamp, and a durable one-time nonce.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{DEFAULT_REGISTRATION_AUDIENCE, DEFAULT_REGISTRATION_SERVICE_IDENTITY};
use crate::store::{
    RegistrationAckCommand, RegistrationEvent, RegistrationFeedError, RegistrationSnapshotRow,
};
use crate::{now_secs, AppState};

pub const MAX_REGISTRATION_JSON_LEN: usize = 4096;
const SIGNATURE_HEADER: &str = "x-keystone-regsig";
const PROTOCOL_VERSION_HEADER: &str = "x-keystone-registration-feed-version";
const SNAPSHOT_ACK_EVIDENCE_VERSION: &str = "2";
const PRIVATE_VARY: &str = "X-Keystone-RegSig, X-Keystone-Registration-Feed-Version";
const CLOCK_SKEW_SECONDS: u64 = 60;
const MAX_KID_LEN: usize = 64;
const MIN_MAC_KEY_LEN: usize = 32;
const MAX_MAC_KEY_LEN: usize = 512;
const MAX_AUDIENCE_LEN: usize = 128;
const MAX_SERVICE_LEN: usize = 128;
const MAX_SNAPSHOT_PAGE: u16 = 1000;
const MAX_CHANGES_PAGE: u16 = 500;
const ACCESS_CONSUMER: &str = "access-governance-registration-v1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
struct AuthenticatedRequest {
    nonce: String,
}

#[derive(Debug)]
struct SignatureFields {
    kid: String,
    timestamp: u64,
    nonce: String,
    mac: [u8; 32],
}

#[derive(Clone, Copy)]
struct MacKey<'a> {
    kid: &'a str,
    key: &'a str,
}

struct ConfiguredKeys<'a> {
    current: MacKey<'a>,
    previous: Option<MacKey<'a>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AckRequest {
    consumer: String,
    generation: u64,
    cursor: u64,
    event_id: String,
    payload_hash: String,
}

#[derive(Serialize)]
struct SnapshotCreatedResponse {
    snapshot_id: String,
    generation: u64,
    high_watermark: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    high_watermark_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    high_watermark_payload_hash: Option<String>,
    count: u64,
    digest: String,
    acked_nonce: String,
}

#[derive(Serialize)]
struct SnapshotRowResponse {
    ordinal: u64,
    subject: String,
    account_version: u64,
    registration_state: &'static str,
    email_verified: bool,
    enabled: bool,
    payload_hash: String,
}

impl From<RegistrationSnapshotRow> for SnapshotRowResponse {
    fn from(value: RegistrationSnapshotRow) -> Self {
        Self {
            ordinal: value.ordinal,
            subject: value.subject,
            account_version: value.account_version,
            registration_state: value.registration_state.as_str(),
            email_verified: value.email_verified,
            enabled: value.enabled,
            payload_hash: value.payload_hash,
        }
    }
}

#[derive(Serialize)]
struct SnapshotPageResponse {
    snapshot_id: String,
    generation: u64,
    high_watermark: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    high_watermark_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    high_watermark_payload_hash: Option<String>,
    digest: String,
    rows: Vec<SnapshotRowResponse>,
    next_after_ordinal: u64,
    done: bool,
    acked_nonce: String,
}

#[derive(Serialize)]
struct ChangeEventResponse {
    cursor: u64,
    event_id: String,
    subject: String,
    account_version: u64,
    registration_state: &'static str,
    email_verified: bool,
    enabled: bool,
    payload_hash: String,
    occurred_at: u64,
}

impl From<RegistrationEvent> for ChangeEventResponse {
    fn from(value: RegistrationEvent) -> Self {
        Self {
            cursor: value.cursor,
            event_id: value.event_id,
            subject: value.subject,
            account_version: value.account_version,
            registration_state: value.registration_state.as_str(),
            email_verified: value.email_verified,
            enabled: value.enabled,
            payload_hash: value.payload_hash,
            occurred_at: value.occurred_at,
        }
    }
}

#[derive(Serialize)]
struct ChangesResponse {
    generation: u64,
    events: Vec<ChangeEventResponse>,
    head_cursor: u64,
    retention_floor_cursor: u64,
    acked_nonce: String,
}

#[derive(Serialize)]
struct AckResponse {
    consumer: String,
    generation: u64,
    stored_cursor: u64,
    acked_nonce: String,
}

/// `POST /internal/v1/identity/registration/snapshot`.
pub(crate) async fn create_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Response {
    let authenticated = match authenticate(&state, &headers, &Method::POST, &uri, &body).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !body.is_empty() {
        return error_after_auth(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &authenticated.nonce,
        );
    }
    let include_ack_evidence = match include_snapshot_ack_evidence(&headers) {
        Ok(value) => value,
        Err(()) => {
            return error_after_auth(
                StatusCode::BAD_REQUEST,
                "unsupported_feed_version",
                &authenticated.nonce,
            )
        }
    };
    match state.store.create_registration_snapshot().await {
        Ok(manifest) => private_json(
            StatusCode::CREATED,
            SnapshotCreatedResponse {
                snapshot_id: manifest.snapshot_id,
                generation: manifest.generation,
                high_watermark: manifest.high_watermark,
                high_watermark_event_id: include_ack_evidence
                    .then_some(manifest.high_watermark_event_id),
                high_watermark_payload_hash: include_ack_evidence
                    .then_some(manifest.high_watermark_payload_hash),
                count: manifest.count,
                digest: manifest.digest,
                acked_nonce: authenticated.nonce,
            },
        ),
        Err(error) => feed_error(error, &authenticated.nonce),
    }
}

/// `GET /internal/v1/identity/registration/snapshot/{snapshot_id}`.
pub(crate) async fn snapshot_page(
    State(state): State<AppState>,
    Path(snapshot_id): Path<String>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let authenticated = match authenticate(&state, &headers, &Method::GET, &uri, &[]).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !valid_snapshot_id(&snapshot_id) {
        return error_after_auth(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &authenticated.nonce,
        );
    }
    let Some((after_ordinal, limit)) = parse_page_query(&uri, "after_ordinal", MAX_SNAPSHOT_PAGE)
    else {
        return error_after_auth(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &authenticated.nonce,
        );
    };
    let include_ack_evidence = match include_snapshot_ack_evidence(&headers) {
        Ok(value) => value,
        Err(()) => {
            return error_after_auth(
                StatusCode::BAD_REQUEST,
                "unsupported_feed_version",
                &authenticated.nonce,
            )
        }
    };
    match state
        .store
        .get_registration_snapshot_page(&snapshot_id, after_ordinal, limit)
        .await
    {
        Ok(page) => private_json(
            StatusCode::OK,
            SnapshotPageResponse {
                snapshot_id: page.snapshot_id,
                generation: page.generation,
                high_watermark: page.high_watermark,
                high_watermark_event_id: include_ack_evidence
                    .then_some(page.high_watermark_event_id),
                high_watermark_payload_hash: include_ack_evidence
                    .then_some(page.high_watermark_payload_hash),
                digest: page.digest,
                rows: page.rows.into_iter().map(Into::into).collect(),
                next_after_ordinal: page.next_after_ordinal,
                done: page.done,
                acked_nonce: authenticated.nonce,
            },
        ),
        Err(error) => feed_error(error, &authenticated.nonce),
    }
}

/// Shape negotiation is deliberately outside the authorization MAC canonical. It changes only
/// response fields: a stripped v2 header makes the new deny-unknown/required-field consumer reject
/// the v1 response, while an old consumer receives the unchanged v1 shape during producer-first
/// rollout.
fn include_snapshot_ack_evidence(headers: &HeaderMap) -> Result<bool, ()> {
    let mut values = headers.get_all(PROTOCOL_VERSION_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(false);
    };
    if values.next().is_some() {
        return Err(());
    }
    match value.to_str().map_err(|_| ())? {
        SNAPSHOT_ACK_EVIDENCE_VERSION => Ok(true),
        _ => Err(()),
    }
}

/// `GET /internal/v1/identity/registration/changes`.
pub(crate) async fn changes(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let authenticated = match authenticate(&state, &headers, &Method::GET, &uri, &[]).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some((after, limit)) = parse_page_query(&uri, "after", MAX_CHANGES_PAGE) else {
        return error_after_auth(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &authenticated.nonce,
        );
    };
    match state.store.get_registration_changes(after, limit).await {
        Ok(page) => private_json(
            StatusCode::OK,
            ChangesResponse {
                generation: page.generation,
                events: page.events.into_iter().map(Into::into).collect(),
                head_cursor: page.head_cursor,
                retention_floor_cursor: page.retention_floor_cursor,
                acked_nonce: authenticated.nonce,
            },
        ),
        Err(error) => feed_error(error, &authenticated.nonce),
    }
}

/// `POST /internal/v1/identity/registration/ack`.
pub(crate) async fn acknowledge(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Response {
    let authenticated = match authenticate(&state, &headers, &Method::POST, &uri, &body).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Ok(request) = serde_json::from_slice::<AckRequest>(&body) else {
        return error_after_auth(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &authenticated.nonce,
        );
    };
    if request.consumer != ACCESS_CONSUMER
        || request.generation == 0
        || request.cursor == 0
        || !valid_event_id(&request.event_id)
        || !is_lower_hex(&request.payload_hash, 64)
    {
        return error_after_auth(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &authenticated.nonce,
        );
    }
    let command = RegistrationAckCommand {
        consumer: request.consumer,
        generation: request.generation,
        acked_cursor: request.cursor,
        event_id: request.event_id,
        payload_hash: request.payload_hash,
    };
    match state.store.acknowledge_registration(command).await {
        Ok(outcome) => private_json(
            StatusCode::OK,
            AckResponse {
                consumer: outcome.consumer,
                generation: outcome.generation,
                stored_cursor: outcome.stored_cursor,
                acked_nonce: authenticated.nonce,
            },
        ),
        Err(error) => feed_error(error, &authenticated.nonce),
    }
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<AuthenticatedRequest, Response> {
    if !state.config.internal_tls {
        return Err(error_without_nonce(
            StatusCode::SERVICE_UNAVAILABLE,
            "registration_feed_unavailable",
        ));
    }
    let Some(keys) = configured_keys(state) else {
        return Err(error_without_nonce(
            StatusCode::SERVICE_UNAVAILABLE,
            "registration_feed_unavailable",
        ));
    };
    if !valid_canonical_identity(DEFAULT_REGISTRATION_AUDIENCE, MAX_AUDIENCE_LEN)
        || !valid_canonical_identity(DEFAULT_REGISTRATION_SERVICE_IDENTITY, MAX_SERVICE_LEN)
    {
        return Err(error_without_nonce(
            StatusCode::SERVICE_UNAVAILABLE,
            "registration_feed_unavailable",
        ));
    }
    let signature = match parse_signature_header(headers) {
        Ok(value) => value,
        Err(()) => {
            return Err(error_without_nonce(
                StatusCode::BAD_REQUEST,
                "malformed_sig",
            ))
        }
    };
    let key = if signature.kid == keys.current.kid {
        keys.current.key
    } else if let Some(previous) = keys.previous {
        if signature.kid == previous.kid {
            previous.key
        } else {
            return Err(error_without_nonce(StatusCode::UNAUTHORIZED, "unknown_kid"));
        }
    } else {
        return Err(error_without_nonce(StatusCode::UNAUTHORIZED, "unknown_kid"));
    };
    let now = now_secs();
    if now.abs_diff(signature.timestamp) > CLOCK_SKEW_SECONDS {
        return Err(error_without_nonce(StatusCode::UNAUTHORIZED, "stale"));
    }
    let canonical = canonical_mac_bytes(
        DEFAULT_REGISTRATION_SERVICE_IDENTITY,
        DEFAULT_REGISTRATION_AUDIENCE,
        method,
        uri,
        body,
        &signature,
    );
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| {
        error_without_nonce(
            StatusCode::SERVICE_UNAVAILABLE,
            "registration_feed_unavailable",
        )
    })?;
    mac.update(canonical.as_bytes());
    if mac.verify_slice(&signature.mac).is_err() {
        return Err(error_without_nonce(StatusCode::UNAUTHORIZED, "bad_mac"));
    }
    let nonce_hash = sha256_hex(signature.nonce.as_bytes());
    match state
        .store
        .claim_registration_nonce(
            &nonce_hash,
            &signature.kid,
            DEFAULT_REGISTRATION_AUDIENCE,
            now,
            now.saturating_add(CLOCK_SKEW_SECONDS * 2),
        )
        .await
    {
        Ok(()) => Ok(AuthenticatedRequest {
            nonce: signature.nonce,
        }),
        Err(RegistrationFeedError::Replay) => Err(error_after_auth(
            StatusCode::UNAUTHORIZED,
            "replay",
            &signature.nonce,
        )),
        Err(_) => Err(error_after_auth(
            StatusCode::SERVICE_UNAVAILABLE,
            "registration_feed_unavailable",
            &signature.nonce,
        )),
    }
}

fn configured_keys(state: &AppState) -> Option<ConfiguredKeys<'_>> {
    let current_kid = state.config.registration_mac_kid.as_deref()?;
    let current_key = state.config.registration_mac_key.as_deref()?;
    if !valid_kid(current_kid) || !valid_mac_key(current_key) {
        return None;
    }
    let previous = match (
        state.config.registration_previous_mac_kid.as_deref(),
        state.config.registration_previous_mac_key.as_deref(),
    ) {
        (None, None) => None,
        (Some(kid), Some(key)) if kid != current_kid && valid_kid(kid) && valid_mac_key(key) => {
            Some(MacKey { kid, key })
        }
        _ => return None,
    };
    Some(ConfiguredKeys {
        current: MacKey {
            kid: current_kid,
            key: current_key,
        },
        previous,
    })
}

fn parse_signature_header(headers: &HeaderMap) -> Result<SignatureFields, ()> {
    let mut values = headers.get_all(SIGNATURE_HEADER).iter();
    let raw = values.next().ok_or(())?.to_str().map_err(|_| ())?;
    if values.next().is_some() || raw.len() > 256 {
        return Err(());
    }
    let mut parts = HashMap::with_capacity(4);
    for pair in raw.split(',') {
        let (name, value) = pair.split_once('=').ok_or(())?;
        if !matches!(name, "kid" | "ts" | "nonce" | "mac")
            || value.is_empty()
            || parts.insert(name, value).is_some()
        {
            return Err(());
        }
    }
    if parts.len() != 4 {
        return Err(());
    }
    let kid = parts.remove("kid").ok_or(())?;
    let timestamp_raw = parts.remove("ts").ok_or(())?;
    let timestamp = timestamp_raw.parse::<u64>().map_err(|_| ())?;
    if timestamp.to_string() != timestamp_raw || !valid_kid(kid) {
        return Err(());
    }
    let nonce = parts.remove("nonce").ok_or(())?;
    if !is_lower_hex(nonce, 32) {
        return Err(());
    }
    let mac = decode_fixed_hex::<32>(parts.remove("mac").ok_or(())?).ok_or(())?;
    Ok(SignatureFields {
        kid: kid.to_string(),
        timestamp,
        nonce: nonce.to_string(),
        mac,
    })
}

fn canonical_mac_bytes(
    service: &str,
    audience: &str,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    signature: &SignatureFields,
) -> String {
    // Fields are separated by exactly one LF; there is deliberately no trailing LF.
    format!(
        "regfeed-v1\n{service}\n{audience}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        uri.path(),
        sorted_raw_query(uri),
        sha256_hex(body),
        signature.kid,
        signature.timestamp,
        signature.nonce
    )
}

fn sorted_raw_query(uri: &Uri) -> String {
    let Some(query) = uri.query().filter(|value| !value.is_empty()) else {
        return String::new();
    };
    let mut fields: Vec<&str> = query.split('&').collect();
    fields.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    fields.join("&")
}

fn parse_page_query(uri: &Uri, cursor_name: &str, max_limit: u16) -> Option<(u64, u16)> {
    let query = uri.query()?;
    let mut values = HashMap::with_capacity(2);
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=')?;
        if !matches!(name, "after" | "after_ordinal" | "limit")
            || value.is_empty()
            || values.insert(name, value).is_some()
        {
            return None;
        }
    }
    if values.len() != 2
        || values.contains_key(if cursor_name == "after" {
            "after_ordinal"
        } else {
            "after"
        })
    {
        return None;
    }
    let cursor_raw = values.get(cursor_name)?;
    let cursor = cursor_raw.parse::<u64>().ok()?;
    if cursor.to_string() != *cursor_raw {
        return None;
    }
    let limit_raw = values.get("limit")?;
    let limit = limit_raw.parse::<u16>().ok()?;
    if limit == 0 || limit > max_limit || limit.to_string() != *limit_raw {
        return None;
    }
    Some((cursor, limit))
}

fn valid_kid(value: &str) -> bool {
    (1..=MAX_KID_LEN).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_mac_key(value: &str) -> bool {
    (MIN_MAC_KEY_LEN..=MAX_MAC_KEY_LEN).contains(&value.len())
        && value.trim() == value
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_canonical_identity(value: &str, max_len: usize) -> bool {
    (1..=max_len).contains(&value.len())
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\n' && byte != b'\r')
}

fn valid_snapshot_id(value: &str) -> bool {
    value.len() == 36 && value.starts_with("irs_") && is_lower_hex(&value[4..], 32)
}

fn valid_event_id(value: &str) -> bool {
    value.len() == 37
        && value.starts_with("ire_")
        && value.as_bytes().get(20) == Some(&b'_')
        && is_lower_hex(&value[4..20], 16)
        && is_lower_hex(&value[21..], 16)
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if !is_lower_hex(value, N * 2) {
        return None;
    }
    let mut out = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(out)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn feed_error(error: RegistrationFeedError, nonce: &str) -> Response {
    let (status, code) = match error {
        RegistrationFeedError::SnapshotIncomplete => (StatusCode::CONFLICT, "snapshot_incomplete"),
        RegistrationFeedError::ResnapshotRequired => (StatusCode::GONE, "resnapshot_required"),
        RegistrationFeedError::AckRegression => (StatusCode::CONFLICT, "ack_regression"),
        RegistrationFeedError::AckGenerationConflict => {
            (StatusCode::CONFLICT, "ack_generation_conflict")
        }
        RegistrationFeedError::AckAhead => (StatusCode::CONFLICT, "ack_ahead"),
        RegistrationFeedError::AckEventMismatch => (StatusCode::CONFLICT, "ack_event_mismatch"),
        RegistrationFeedError::FeedGap => (StatusCode::SERVICE_UNAVAILABLE, "feed_gap"),
        RegistrationFeedError::Replay => (StatusCode::UNAUTHORIZED, "replay"),
        RegistrationFeedError::Backend => (
            StatusCode::SERVICE_UNAVAILABLE,
            "registration_feed_unavailable",
        ),
    };
    error_after_auth(status, code, nonce)
}

fn error_without_nonce(status: StatusCode, code: &'static str) -> Response {
    private_json(status, serde_json::json!({ "error": code }))
}

fn error_after_auth(status: StatusCode, code: &'static str, nonce: &str) -> Response {
    private_json(
        status,
        serde_json::json!({ "error": code, "acked_nonce": nonce }),
    )
}

fn private_json<T: Serialize>(status: StatusCode, value: T) -> Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::VARY,
        HeaderValue::from_static(PRIVATE_VARY),
    );
    response
}

/// Route-level wrapper also covers body-limit rejections before a handler can run.
pub async fn privacy_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::VARY,
        HeaderValue::from_static(PRIVATE_VARY),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_has_no_trailing_line_feed_and_sorts_query() {
        let uri: Uri = "/x?limit=2&after=1".parse().unwrap();
        let signature = SignatureFields {
            kid: "k1".to_string(),
            timestamp: 7,
            nonce: "0".repeat(32),
            mac: [0; 32],
        };
        let canonical = canonical_mac_bytes(
            "access-governance",
            "keystone-registration",
            &Method::GET,
            &uri,
            &[],
            &signature,
        );
        assert_eq!(
            canonical,
            format!(
                "regfeed-v1\naccess-governance\nkeystone-registration\nGET\n/x\nafter=1&limit=2\n{}\nk1\n7\n{}",
                sha256_hex(&[]),
                "0".repeat(32)
            )
        );
        assert!(!canonical.ends_with('\n'));
    }

    #[test]
    fn signature_parser_rejects_duplicate_and_uppercase_hex() {
        let mut headers = HeaderMap::new();
        headers.append(
            SIGNATURE_HEADER,
            "kid=k1,ts=7,nonce=00000000000000000000000000000000,mac=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .parse()
                .unwrap(),
        );
        assert!(parse_signature_header(&headers).is_err());
        headers.clear();
        headers.append(
            SIGNATURE_HEADER,
            "kid=k1,ts=7,nonce=00000000000000000000000000000000,mac=0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
        );
        headers.append(
            SIGNATURE_HEADER,
            "kid=k1,ts=7,nonce=00000000000000000000000000000000,mac=0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
        );
        assert!(parse_signature_header(&headers).is_err());
    }
}
