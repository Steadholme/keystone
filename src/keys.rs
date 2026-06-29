//! Signing key: RSA-2048 keygen, RS256 EncodingKey, JWK export, DecodingKey builder.
//!
//! One keypair is held in `Arc<SigningKey>` for the process lifetime. `kid` is the
//! RFC 7638 JWK thumbprint so the JWKS `kid` and the JWT header `kid` are derived
//! from the same canonical key material and can never drift.
//!
//! The key is either generated fresh ([`SigningKey::generate`], ephemeral — dev/test)
//! or loaded from / persisted to a PEM file ([`SigningKey::load_or_generate`]). Because
//! the `kid` is a deterministic thumbprint of the public key, a persisted key yields the
//! SAME `kid` across restarts — so a restart no longer rotates the `kid` and downstream
//! verifiers (Sluice's JWKS cache) keep validating freshly-minted tokens without a 401 gap.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

/// Runtime signing material. Either ephemeral ([`generate`]) or persisted to a PEM
/// file ([`load_or_generate`]); the `kid` is identical for the same key material.
///
/// [`generate`]: SigningKey::generate
/// [`load_or_generate`]: SigningKey::load_or_generate
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
    /// Ephemeral: the `kid` changes on every call, so a restart rotates the `kid`.
    /// Used by the dev/test path. Costs ~50-300ms (RSA keygen); generate once and
    /// share via `Arc`.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA-2048 keygen failed");
        Self::from_private_key(&priv_key)
    }

    /// Load the signing key from `path` if it exists, otherwise generate a fresh
    /// RSA-2048 keypair AND persist it to `path` (PKCS#1 PEM, parent dirs created,
    /// file mode `0600`).
    ///
    /// Persistence makes the `kid` STABLE across restarts: the `kid` is a pure
    /// thumbprint of the public key, so reloading the same PEM reproduces the same
    /// `kid`, JWK `n`/`e`, and `EncodingKey`. This is what keeps Sluice from
    /// rejecting (401) tokens minted by a restarted Keystone.
    ///
    /// Errors (I/O, malformed PEM, keygen) are returned so `main` can fail loudly
    /// instead of silently falling back to an ephemeral key.
    pub fn load_or_generate(path: &Path) -> io::Result<Self> {
        if path.exists() {
            let pem = fs::read_to_string(path)?;
            let priv_key = RsaPrivateKey::from_pkcs1_pem(&pem).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse PKCS#1 PEM signing key at {}: {e}", path.display()),
                )
            })?;
            Ok(Self::from_private_key(&priv_key))
        } else {
            let mut rng = OsRng;
            let priv_key = RsaPrivateKey::new(&mut rng, 2048)
                .map_err(|e| io::Error::other(format!("RSA-2048 keygen failed: {e}")))?;
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            let pem = priv_key
                .to_pkcs1_pem(LineEnding::LF)
                .map_err(|e| io::Error::other(format!("encode PKCS#1 PEM: {e}")))?;
            write_private_pem(path, pem.as_bytes())?;
            Ok(Self::from_private_key(&priv_key))
        }
    }

    /// Derive all signing/JWK material from an RSA private key. The single source of
    /// truth for `kid` derivation, so the `kid` is identical whether the key was just
    /// generated or reloaded from PEM.
    fn from_private_key(priv_key: &RsaPrivateKey) -> Self {
        let pub_key = RsaPublicKey::from(priv_key);

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

// TODO seam: rotate / source the signing key from FusionDB/HSM. Persistence to a PEM
// file (`load_or_generate`) covers the v0 restart-stability requirement; rotation is
// still deferred.

/// Write `bytes` to `path`, creating the file with owner-only `0600` perms on unix so
/// the private key is never world/group-readable, even briefly.
#[cfg(unix)]
fn write_private_pem(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

/// Non-unix fallback: best-effort write without unix mode bits.
#[cfg(not(unix))]
fn write_private_pem(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = fs::File::create(path)?;
    f.write_all(bytes)
}

/// RFC 7638 JWK thumbprint over the canonical RSA public-key JSON
/// `{"e":<e>,"kty":"RSA","n":<n>}` (members in lexicographic order, no whitespace).
fn jwk_thumbprint(e: &str, n: &str) -> String {
    let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
    let digest = Sha256::digest(canonical.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Load-or-generate twice against the SAME path must yield the SAME `kid` and the
    /// SAME public modulus/exponent — i.e. the key is persisted and reloaded, not
    /// regenerated. This is the property that keeps the JWKS `kid` stable across a
    /// Keystone restart.
    #[test]
    fn load_or_generate_is_stable_across_reloads() {
        let dir = std::env::temp_dir().join(format!("keystone-key-test-{}", std::process::id()));
        let path = dir.join("signing_key.pem");
        // Clean any leftover from a previous run so the first call truly generates.
        let _ = fs::remove_file(&path);

        // First call: file absent -> generate + persist.
        let first = SigningKey::load_or_generate(&path).expect("first load_or_generate");
        assert!(path.exists(), "PEM file should have been written");

        // Second call: file present -> load the SAME key.
        let second = SigningKey::load_or_generate(&path).expect("second load_or_generate");

        assert_eq!(first.kid, second.kid, "kid must be stable across reloads");
        assert_eq!(first.jwk_n, second.jwk_n, "modulus must match across reloads");
        assert_eq!(first.jwk_e, second.jwk_e, "exponent must match across reloads");

        // Persisted file must be owner-only (0600) on unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "persisted key file must be mode 0600");
        }

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    /// A persisted key must differ from a freshly generated ephemeral one (sanity:
    /// the stability above is real persistence, not a constant key).
    #[test]
    fn persisted_key_differs_from_fresh_generate() {
        let dir = std::env::temp_dir().join(format!("keystone-key-test2-{}", std::process::id()));
        let path = dir.join("signing_key.pem");
        let _ = fs::remove_file(&path);

        let persisted = SigningKey::load_or_generate(&path).expect("load_or_generate");
        let ephemeral = SigningKey::generate();
        assert_ne!(
            persisted.kid, ephemeral.kid,
            "an independently generated key should have a different kid"
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
