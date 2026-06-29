//! `GET /healthz`, `/.well-known/openid-configuration`, `/jwks.json`.

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::AppState;

/// Liveness probe -> 200 text/plain "ok".
pub async fn healthz() -> &'static str {
    "ok"
}

/// OIDC discovery document. All endpoint URLs are derived from `issuer`.
pub async fn openid_configuration(State(state): State<AppState>) -> Json<Value> {
    let c = &state.config;
    Json(json!({
        "issuer": c.issuer,
        "authorization_endpoint": c.authorization_endpoint(),
        "token_endpoint": c.token_endpoint(),
        "userinfo_endpoint": c.userinfo_endpoint(),
        "jwks_uri": c.jwks_uri(),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "subject_types_supported": ["public"],
        // `none` = public PKCE clients (e.g. sluice-dev); `client_secret_post` /
        // `client_secret_basic` = confidential clients (e.g. the sluice-gw gateway).
        "token_endpoint_auth_methods_supported": [
            "client_secret_post", "client_secret_basic", "none"
        ],
    }))
}

/// JWKS with exactly one RS256 public key. `kid` equals the kid in issued JWT headers.
pub async fn jwks(State(state): State<AppState>) -> Json<Value> {
    let k = &state.keys;
    Json(json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": k.kid,
            "n": k.jwk_n,
            "e": k.jwk_e,
        }]
    }))
}
