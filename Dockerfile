# syntax=docker/dockerfile:1
#
# Multi-stage build for Keystone.
#   - builder: rust:1.96-slim (Debian trixie; ships gcc for the rustls `ring` build).
#   - runtime: debian:trixie-slim (matching glibc), non-root, no openssl/curl.
# The container HEALTHCHECK uses the built-in `keystone healthcheck` subcommand, so no
# extra HTTP tool is needed in the image.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Cache the dependency graph first: build a throwaway lib against the real manifest so
# `cargo build` only recompiles our crate when src/ changes, not the whole tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --bin keystone \
    && rm -rf src

# Now build the real binary.
COPY src ./src
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin keystone \
    && strip target/release/keystone

FROM debian:trixie-slim AS runtime
# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home keystone
COPY --from=builder /build/target/release/keystone /usr/local/bin/keystone

USER keystone
# Default in-container bind; overridable at runtime. Discovery `iss` comes from ISSUER.
ENV BIND_ADDR=0.0.0.0:8080
EXPOSE 8080

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["keystone", "healthcheck"]

ENTRYPOINT ["keystone"]
