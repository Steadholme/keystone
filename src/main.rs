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

    let addr: SocketAddr = state
        .config
        .bind_addr
        .parse()
        .expect("invalid bind_addr in config");

    let issuer = state.config.issuer.clone();
    let app = keystone::app(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));

    tracing::info!(%addr, %issuer, "Keystone v0 listening");
    axum::serve(listener, app).await.expect("server error");
}

/// GET `/healthz` over a raw TCP socket. Returns process exit code (0 = healthy).
fn run_healthcheck() -> i32 {
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    // Healthcheck always talks to the loopback regardless of the bind interface.
    let port = bind_addr.rsplit(':').next().unwrap_or("8080");
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
