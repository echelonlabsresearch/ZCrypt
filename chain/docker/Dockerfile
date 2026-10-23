# syntax=docker/dockerfile:1
# Foundation / validator image: ABCI node + explorer + bridge watcher (one build, different
# CMD per service).
#
# Reproducibility: the compiler is the DATE-PINNED nightly from impl/rust-toolchain.toml
# (RUST_NIGHTLY below must match it; the build fails loudly if it does not), the base image
# is a versioned stable Rust image (rustup only, the pinned nightly is installed on top),
# and cargo runs with --locked so Cargo.lock is authoritative.
#
# Native deps: librocksdb-sys builds RocksDB from source and generates bindings with
# bindgen, which needs clang + libclang; cmake/pkg-config are needed by its C++ build.
ARG RUST_NIGHTLY=nightly-2025-10-12

FROM rust:1.90-bookworm AS build
ARG RUST_NIGHTLY
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-dev cmake pkg-config build-essential \
    && rm -rf /var/lib/apt/lists/*
# Pre-install the pinned nightly in its own layer so source changes do not re-download it.
RUN rustup toolchain install "$RUST_NIGHTLY" --profile minimal
WORKDIR /build
COPY impl /build/impl
# Refuse to build with a compiler other than the one the workspace pins.
RUN grep -q "channel = \"$RUST_NIGHTLY\"" /build/impl/rust-toolchain.toml \
    || { echo "RUST_NIGHTLY ($RUST_NIGHTLY) does not match impl/rust-toolchain.toml"; exit 1; }
# DEFAULT is PRODUCTION (empty features); mainnet-grade FRI parameters are compiled in
# unconditionally. Local faucet/dev: ABCI_FEATURES=devnet. Only abci-node takes features.
ARG ABCI_FEATURES=
RUN cd /build/impl && \
    if [ -n "$ABCI_FEATURES" ]; then \
      cargo build --locked --release -p zcrypt-abci-node --features "$ABCI_FEATURES"; \
    else \
      cargo build --locked --release -p zcrypt-abci-node; \
    fi && \
    cargo build --locked --release -p zcrypt-explorer && \
    cargo build --locked --release -p zcrypt-bridge --bin bridge_watcher --bin bond_validator

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 zcrypt \
    && useradd --uid 10001 --gid zcrypt --no-create-home --shell /usr/sbin/nologin zcrypt \
    && mkdir -p /data && chown zcrypt:zcrypt /data
COPY --from=build /build/impl/target/release/zcrypt-abci-node /usr/local/bin/zcrypt-abci-node
COPY --from=build /build/impl/target/release/zcrypt-explorer /usr/local/bin/zcrypt-explorer
COPY --from=build /build/impl/target/release/bridge_watcher /usr/local/bin/bridge_watcher
# Host-side bond signer for the wallet's two-step bond (README-validator.md, step 3).
COPY --from=build /build/impl/target/release/bond_validator /usr/local/bin/bond_validator
ENV ABCI_PORT=26658
ENV EXPLORER_PORT=8080
# Consensus state lives on the /data volume (RocksDB dir + periodic postcard backup).
ENV ZCRYPT_STATE_DB=/data/zcrypt-state.db
ENV ZCRYPT_STATE_FILE=/data/zcrypt-state.bin
# Never run as root: the image ships a dedicated unprivileged user that owns /data.
USER zcrypt
WORKDIR /data
VOLUME ["/data"]
EXPOSE 26658 8080
# Default process is the ABCI app; compose overrides command for explorer / watcher.
CMD ["zcrypt-abci-node"]
