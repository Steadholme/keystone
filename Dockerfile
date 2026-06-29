# syntax=docker/dockerfile:1
#
# Multi-stage build for Keystone.
#   - builder: rust:1.96-slim (Debian trixie; ships gcc for the rustls `ring` build).
#     Adds libssl-dev + pkg-config because webauthn-rs-core links OpenSSL.
#   - runtime: debian:trixie-slim (matching glibc), non-root, libssl3 + ca-certificates.
# The container HEALTHCHECK uses the built-in `keystone healthcheck` subcommand, so no
# extra HTTP tool is needed in the image.

FROM rust:1.96-slim AS builder
WORKDIR /build

# OpenSSL dev headers (webauthn-rs-core -> openssl-sys) + pkg-config to locate them.
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache the dependency graph first: build a throwaway lib against the real manifest so
# `cargo build` only recompiles our crate when src/ changes, not the whole tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --bin keystone \
    && rm -rf src

# Now build the real binary. Templates + static assets are embedded via include_str!,
# so they MUST be present at compile time (and are then baked into the binary — the
# runtime image needs neither directory).
COPY src ./src
COPY templates ./templates
COPY static ./static
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin keystone \
    && strip target/release/keystone

FROM debian:trixie-slim AS runtime
# OpenSSL runtime shared lib (dynamically linked by the binary) + CA roots.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home keystone
COPY --from=builder /build/target/release/keystone /usr/local/bin/keystone

# Persistent data dir for the RSA signing key (SIGNING_KEY_PATH). Created owned by the
# non-root uid so a mounted named volume inherits writable ownership — the key file is
# NOT baked into the image, only generated/persisted at runtime under /data.
RUN mkdir -p /data && chown 10001:10001 /data
VOLUME ["/data"]

USER keystone
# Default in-container bind; overridable at runtime. Discovery `iss` comes from ISSUER.
ENV BIND_ADDR=0.0.0.0:8080
EXPOSE 8080

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["keystone", "healthcheck"]

ENTRYPOINT ["keystone"]
