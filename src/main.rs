//! Keystone v0 entry point: init state from env, smoke-test the crypto provider, serve.
//!
//! Also exposes a dependency-free `keystone healthcheck` subcommand used as the
//! container HEALTHCHECK: it GETs `http://127.0.0.1:$PORT/healthz` (port derived from
//! `BIND_ADDR`) over a raw TCP socket and exits 0 on `200`, 1 otherwise — so the image
//! needs no `curl`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Container HEALTHCHECK path — handled before any server setup, exits the process.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(run_healthcheck());
    }

    tracing_subscriber::fmt::init();

    let state = match keystone::build_state_from_env().await {
        Ok(state) => state,
        Err(e) => {
            tracing::error!(error = %e, "failed to build application state");
            std::process::exit(1);
        }
    };

    // Crypto smoke test: sign once at startup so a misconfigured jsonwebtoken
    // crypto-provider build fails loudly here instead of on the first request.
    match keystone::jwt::sign_access(
        &state.keys,
        &state.config,
        "startup-smoke",
        keystone::config::SEED_CLIENT_ID,
        "openid",
    ) {
        Ok(t) => tracing::info!(kid = %state.keys.kid, token_len = t.len(), "crypto provider OK"),
        Err(e) => {
            tracing::error!(error = %e, "crypto smoke sign failed");
            std::process::exit(1);
        }
    }

    // Keep the config handy (the app consumes `state`); decide the listener topology.
    let config = state.config.clone();
    let issuer = config.issuer.clone();
    let app = keystone::app(state);

    if config.internal_tls {
        serve_internal_tls(&config, issuer, app).await;
    } else {
        // Unchanged plaintext behavior: serve the app on bind_addr.
        let addr: SocketAddr = config
            .bind_addr
            .parse()
            .expect("invalid bind_addr in config");
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
        tracing::info!(%addr, %issuer, "Keystone v0 listening");
        axum::serve(listener, app).await.expect("server error");
    }
}

/// `INTERNAL_TLS=on` path: serve the app over mutual TLS (client cert REQUIRED) on
/// `INTERNAL_TLS_ADDR`, plus a plaintext loopback health listener on
/// `INTERNAL_HEALTH_ADDR` for the docker HEALTHCHECK (no client cert needed). The public
/// plaintext `BIND_ADDR` is intentionally NOT bound here — Sluice reaches Keystone only
/// over mTLS. Any misconfiguration fails loudly (exit 1) instead of degrading silently.
async fn serve_internal_tls(config: &keystone::config::Config, issuer: String, app: axum::Router) {
    let (cert, key, ca) = match (
        config.internal_tls_cert.as_deref(),
        config.internal_tls_key.as_deref(),
        config.internal_tls_client_ca.as_deref(),
    ) {
        (Some(c), Some(k), Some(a)) => (c, k, a),
        _ => {
            tracing::error!(
                "INTERNAL_TLS=on requires INTERNAL_TLS_CERT, INTERNAL_TLS_KEY and \
                 INTERNAL_TLS_CLIENT_CA (PEM paths)"
            );
            std::process::exit(1);
        }
    };

    let server_config = match keystone::tls::load_server_config(cert, key, ca) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to build internal mTLS server config");
            std::process::exit(1);
        }
    };

    let tls_addr: SocketAddr = config
        .internal_tls_addr
        .parse()
        .expect("invalid INTERNAL_TLS_ADDR");
    let health_addr: SocketAddr = config
        .internal_health_addr
        .parse()
        .expect("invalid INTERNAL_HEALTH_ADDR");

    // Plaintext loopback health listener for the HEALTHCHECK. It mounts only `/healthz`;
    // the full app and every `/internal` endpoint remain exclusive to the mTLS listener.
    let health_app = keystone::health_app();
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(health_addr).await {
            Ok(listener) => {
                tracing::info!(%health_addr, "plaintext health listener up");
                if let Err(e) = axum::serve(listener, health_app).await {
                    tracing::error!(error = %e, "health listener error");
                }
            }
            Err(e) => tracing::error!(error = %e, %health_addr, "failed to bind health listener"),
        }
    });

    tracing::info!(%tls_addr, %issuer, "Keystone listening (internal mTLS)");
    if let Err(e) = keystone::tls::serve(tls_addr, server_config, app).await {
        tracing::error!(error = %e, "internal mTLS server error");
        std::process::exit(1);
    }
}

/// GET `/healthz` over a raw TCP socket. Returns process exit code (0 = healthy).
fn run_healthcheck() -> i32 {
    // When internal mTLS is on, the main listener (:8443) requires a client cert, so the
    // dependency-free probe instead targets the plaintext loopback health listener.
    // Otherwise it targets the normal BIND_ADDR port. The probe always uses loopback,
    // regardless of the bind interface.
    let internal_tls = std::env::var("INTERNAL_TLS")
        .map(|v| v.eq_ignore_ascii_case("on"))
        .unwrap_or(false);
    let probe_addr = if internal_tls {
        std::env::var("INTERNAL_HEALTH_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string())
    } else {
        std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string())
    };
    let port = probe_addr.rsplit(':').next().unwrap_or("8080");
    let target = format!("127.0.0.1:{port}");

    match healthcheck_once(&target) {
        Ok(true) => 0,
        Ok(false) => {
            eprintln!("healthcheck: {target} did not return 200");
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {target} error: {e}");
            1
        }
    }
}

fn healthcheck_once(target: &str) -> std::io::Result<bool> {
    let addr: SocketAddr = target
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    let status_line = buf.lines().next().unwrap_or("");
    Ok(status_line.contains("200"))
}
