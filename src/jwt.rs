//! RS256 JWT claims + signing helpers.
//!
//! Both tokens carry `alg=RS256` and the signing key's `kid` in the header.

use jsonwebtoken::{encode, Algorithm, Header};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::keys::SigningKey;
use crate::now_secs;

/// access_token claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    /// audience = client_id.
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub scope: String,
}

/// id_token claims. Adds `email`, plus `nonce` iff one was supplied at `/authorize`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    /// audience = client_id.
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub scope: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

fn rs256_header(keys: &SigningKey) -> Header {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(keys.kid.clone());
    header
}

/// Sign an access_token (RS256, kid header).
pub fn sign_access(
    keys: &SigningKey,
    config: &Config,
    sub: &str,
    aud: &str,
    scope: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let iat = now_secs();
    let claims = AccessTokenClaims {
        iss: config.issuer.clone(),
        sub: sub.to_string(),
        aud: aud.to_string(),
        exp: iat + config.access_ttl,
        iat,
        scope: scope.to_string(),
    };
    encode(&rs256_header(keys), &claims, &keys.enc)
}

/// Sign an id_token (RS256, kid header).
#[allow(clippy::too_many_arguments)]
pub fn sign_id(
    keys: &SigningKey,
    config: &Config,
    sub: &str,
    aud: &str,
    scope: &str,
    email: &str,
    nonce: Option<String>,
) -> Result<String, jsonwebtoken::errors::Error> {
    let iat = now_secs();
    let claims = IdTokenClaims {
        iss: config.issuer.clone(),
        sub: sub.to_string(),
        aud: aud.to_string(),
        exp: iat + config.id_ttl,
        iat,
        scope: scope.to_string(),
        email: email.to_string(),
        nonce,
    };
    encode(&rs256_header(keys), &claims, &keys.enc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;
    use jsonwebtoken::{decode, DecodingKey, Validation};

    // Sign -> verify round-trip (RS256), proving the JWK n/e export round-trips
    // through DecodingKey::from_rsa_components — the exact path Sluice uses.
    #[test]
    fn access_token_round_trip() {
        let keys = SigningKey::generate();
        let config = Config::dev();
        let token = sign_access(&keys, &config, "u_admin", "sluice-dev", "openid email").unwrap();

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&["sluice-dev"]);
        let decoding: DecodingKey =
            DecodingKey::from_rsa_components(&keys.jwk_n, &keys.jwk_e).unwrap();

        let data = decode::<AccessTokenClaims>(&token, &decoding, &validation).unwrap();
        assert_eq!(data.header.alg, Algorithm::RS256);
        assert_eq!(data.header.kid.as_deref(), Some(keys.kid.as_str()));
        assert_eq!(data.claims.sub, "u_admin");
        assert_eq!(data.claims.aud, "sluice-dev");
        assert_eq!(data.claims.iss, config.issuer);
    }

    #[test]
    fn id_token_carries_email_and_nonce() {
        let keys = SigningKey::generate();
        let config = Config::dev();
        let token = sign_id(
            &keys,
            &config,
            "u_admin",
            "sluice-dev",
            "openid email",
            "admin@steadholme.local",
            Some("n-123".to_string()),
        )
        .unwrap();

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&["sluice-dev"]);
        let decoding = keys.decoding_key();

        let data = decode::<IdTokenClaims>(&token, &decoding, &validation).unwrap();
        assert_eq!(data.claims.email, "admin@steadholme.local");
        assert_eq!(data.claims.nonce.as_deref(), Some("n-123"));
    }
}
