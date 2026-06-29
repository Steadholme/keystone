//! Keystone v0 entry point: init state, smoke-test the crypto provider, serve.

use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = keystone::build_dev_state();

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

    let app = keystone::app(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));

    tracing::info!(%addr, "Keystone v0 listening");
    axum::serve(listener, app)
        .await
        .expect("server error");
}
