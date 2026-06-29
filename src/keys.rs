//! Signing key: RSA-2048 keygen, RS256 EncodingKey, JWK export, DecodingKey builder.
//!
//! One keypair is generated once at startup and held in `Arc<SigningKey>`.
//! `kid` is the RFC 7638 JWK thumbprint so the JWKS `kid` and the JWT header
//! `kid` are derived from the same canonical key material and can never drift.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rand::rngs::OsRng;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

/// Runtime signing material. Not persisted in v0.
pub struct SigningKey {
    /// RFC 7638 JWK thumbprint = base64url(sha256(canonical {e,kty,n})).
    pub kid: String,
    /// RS256 signing key, built from PKCS#1 DER (avoids the jsonwebtoken `pem` feature).
    pub enc: EncodingKey,
    /// JWK modulus (base64url-no-pad).
    pub jwk_n: String,
    /// JWK exponent (base64url-no-pad).
    pub jwk_e: String,
}

impl SigningKey {
    /// Generate a fresh RSA-2048 keypair and derive all signing/JWK material.
    ///
    /// Costs ~50-300ms (RSA keygen). Generate once and share via `Arc`.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA-2048 keygen failed");
        let pub_key = RsaPublicKey::from(&priv_key);

        let jwk_n = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
        let jwk_e = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());

        let der = priv_key
            .to_pkcs1_der()
            .expect("encode RSA private key to PKCS#1 DER failed");
        let enc = EncodingKey::from_rsa_der(der.as_bytes());

        let kid = jwk_thumbprint(&jwk_e, &jwk_n);

        SigningKey {
            kid,
            enc,
            jwk_n,
            jwk_e,
        }
    }

    /// Build a verifier from this key's public components — the SAME path Sluice
    /// uses from the published JWKS (`DecodingKey::from_rsa_components(n, e)`).
    pub fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_rsa_components(&self.jwk_n, &self.jwk_e)
            .expect("build DecodingKey from RSA components failed")
    }
}

// TODO seam: load/rotate the signing key from FusionDB/HSM instead of generating
// an ephemeral keypair at startup. Not required for v0.

/// RFC 7638 JWK thumbprint over the canonical RSA public-key JSON
/// `{"e":<e>,"kty":"RSA","n":<n>}` (members in lexicographic order, no whitespace).
fn jwk_thumbprint(e: &str, n: &str) -> String {
    let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
    let digest = Sha256::digest(canonical.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}
