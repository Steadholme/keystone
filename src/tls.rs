//! Internal mutual-TLS server for the keystone<->sluice hop (env-toggled, default OFF).
//!
//! When `INTERNAL_TLS=on`, Keystone serves the SAME axum app over an HTTPS listener that
//! REQUIRES and verifies a client certificate against the Keyward root CA (mTLS), while
//! presenting a Keyward-issued server cert/key (CN/SAN=keystone). Sluice then reaches
//! Keystone only over this mTLS port. A separate plaintext loopback health listener
//! (see `main`) keeps the docker HEALTHCHECK working without a client cert.
//!
//! rustls is pinned to the `ring` crypto provider and that provider is passed EXPLICITLY
//! to both the server-config and client-verifier builders, so this never relies on a
//! process-default provider (and never pulls aws-lc-rs).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use axum::Router;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;

/// Build a mutual-TLS [`ServerConfig`] from in-memory PEM bytes:
/// presents `cert_pem`/`key_pem` and REQUIRES a client cert chaining to `client_ca_pem`.
///
/// Separated from file IO so it is unit-testable with fixture PEMs.
pub fn build_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<ServerConfig, String> {
    // Explicit ring provider — matches sqlx; no reliance on a process-default provider.
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // Server certificate chain (leaf first).
    let mut cert_reader = cert_pem;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("parse server certificate PEM: {e}"))?;
    if certs.is_empty() {
        return Err("server certificate PEM contained no certificates".to_string());
    }

    // Server private key (PKCS#8 / PKCS#1 / SEC1 all accepted by `private_key`).
    let mut key_reader = key_pem;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("parse server key PEM: {e}"))?
        .ok_or_else(|| "server key PEM contained no private key".to_string())?;

    // Trust anchors for client-certificate verification (the Keyward root CA).
    let mut roots = RootCertStore::empty();
    let mut ca_reader = client_ca_pem;
    for ca in rustls_pemfile::certs(&mut ca_reader) {
        let ca = ca.map_err(|e| format!("parse client CA PEM: {e}"))?;
        roots
            .add(ca)
            .map_err(|e| format!("add client CA certificate: {e}"))?;
    }
    if roots.is_empty() {
        return Err("client CA PEM contained no certificates".to_string());
    }

    // REQUIRE + verify a client certificate (mutual TLS).
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| format!("build client-certificate verifier: {e}"))?;

    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("select TLS protocol versions: {e}"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("load server certificate/key: {e}"))?;

    Ok(config)
}

/// Load the mutual-TLS [`ServerConfig`] from PEM file paths.
pub fn load_server_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
) -> Result<ServerConfig, String> {
    let cert = std::fs::read(cert_path).map_err(|e| format!("read {cert_path}: {e}"))?;
    let key = std::fs::read(key_path).map_err(|e| format!("read {key_path}: {e}"))?;
    let ca = std::fs::read(client_ca_path).map_err(|e| format!("read {client_ca_path}: {e}"))?;
    build_server_config(&cert, &key, &ca)
}

/// Serve `app` over mutual TLS on `addr`. Each accepted TCP connection is TLS-handshaked
/// (client cert REQUIRED + verified by `config`), then served as HTTP/1.1. Per-connection
/// errors are logged and dropped; the accept loop runs until `addr` bind/accept fails.
pub async fn serve(addr: SocketAddr, config: ServerConfig, app: Router) -> std::io::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "internal mTLS listener up");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "internal TCP accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    // Includes a missing/untrusted client cert — reject quietly.
                    tracing::debug!(error = %e, %peer, "internal mTLS handshake rejected");
                    return;
                }
            };
            let io = TokioIo::new(tls);
            // Adapt the axum Router (a tower Service over Request<Body>) to a hyper
            // service over Request<Incoming> by mapping the body.
            let service =
                service_fn(move |req: Request<Incoming>| app.clone().call(req.map(Body::new)));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!(error = %e, "internal mTLS connection closed with error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixture PEMs (EC P-256): a self-signed test root CA and a leaf cert/key signed by
    // it (CN=keystone, SAN DNS:keystone). Used only to prove the rustls mTLS ServerConfig
    // builds from PEMs — no network, no expiry check at config-build time.
    const CA_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBljCCATugAwIBAgIUKOL9SYz5z96cVT8NM66iNAIlzBUwCgYIKoZIzj0EAwIw\n\
IDEeMBwGA1UEAwwVSE9MREZBU1QgVGVzdCBSb290IENBMB4XDTI2MDYyOTEwMTEx\n\
MloXDTQ2MDYyNDEwMTExMlowIDEeMBwGA1UEAwwVSE9MREZBU1QgVGVzdCBSb290\n\
IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9lJCcwMwbpGM2vAephHxnmuB\n\
Ay/+oBAeQtEYpQSW493sk3rDXDSKA6eyv5BoxLOUY6SCQhPl4G7r5/X0XPHh1aNT\n\
MFEwHQYDVR0OBBYEFGgkrme7oVRiDLlaDhKumOLxmr+gMB8GA1UdIwQYMBaAFGgk\n\
rme7oVRiDLlaDhKumOLxmr+gMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID\n\
SQAwRgIhAMK/DfwuNUv34DBK0gvX/mEe9kpMrVnAnbS3/FPugJyyAiEA46PrFl2R\n\
6q0i88L0NH3Fz40JFHGR2EI+nJPXrDIbP8I=\n\
-----END CERTIFICATE-----\n";

    const SERVER_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBjDCCATKgAwIBAgIUAyuE4Abnl36P36fS5q2ZRSdRZV0wCgYIKoZIzj0EAwIw\n\
IDEeMBwGA1UEAwwVSE9MREZBU1QgVGVzdCBSb290IENBMB4XDTI2MDYyOTEwMTEx\n\
MloXDTQ2MDYyNDEwMTExMlowEzERMA8GA1UEAwwIa2V5c3RvbmUwWTATBgcqhkjO\n\
PQIBBggqhkjOPQMBBwNCAARRu+zivWsDVkmTwiWmcwyS46vD6E6BHkoy6hPLeKsI\n\
EAAQ/c4nTEj8103TttZ2ydEwpNByQU78AY5qhOcDM4PXo1cwVTATBgNVHREEDDAK\n\
gghrZXlzdG9uZTAdBgNVHQ4EFgQUE3iXKgajjyogWSs5Mtgt+oraCrIwHwYDVR0j\n\
BBgwFoAUaCSuZ7uhVGIMuVoOEq6Y4vGav6AwCgYIKoZIzj0EAwIDSAAwRQIgK37A\n\
ms9CkSlUvAMMByjvmRRFaQ48q9M4qhBRkfQpqGgCIQCaHRCE6wyleA+l4nJkh1cj\n\
CI2JPrYOwls12WHuRA6/KA==\n\
-----END CERTIFICATE-----\n";

    const SERVER_KEY: &str = "-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIJ9ofhl5mBhGDlpJRrzJ5xdIs/7YyEUYp5G+4kAxzkzWoAoGCCqGSM49\n\
AwEHoUQDQgAEUbvs4r1rA1ZJk8IlpnMMkuOrw+hOgR5KMuoTy3irCBAAEP3OJ0xI\n\
/NdN07bWdsnRMKTQckFO/AGOaoTnAzOD1w==\n\
-----END EC PRIVATE KEY-----\n";

    #[test]
    fn server_config_builds_from_pem() {
        let cfg = build_server_config(
            SERVER_CERT.as_bytes(),
            SERVER_KEY.as_bytes(),
            CA_CERT.as_bytes(),
        )
        .expect("mTLS ServerConfig builds from fixture PEMs");
        // The config carries the explicitly-pinned ring provider (non-empty cipher set).
        assert!(
            !cfg.crypto_provider().cipher_suites.is_empty(),
            "ring crypto provider wired into the ServerConfig"
        );
    }

    #[test]
    fn missing_certificate_is_rejected() {
        let err = build_server_config(b"not a pem", SERVER_KEY.as_bytes(), CA_CERT.as_bytes())
            .expect_err("garbage server cert must fail");
        assert!(err.contains("server certificate"), "got: {err}");
    }

    #[test]
    fn missing_client_ca_is_rejected() {
        let err = build_server_config(SERVER_CERT.as_bytes(), SERVER_KEY.as_bytes(), b"")
            .expect_err("empty client CA must fail");
        assert!(err.contains("client CA"), "got: {err}");
    }
}
