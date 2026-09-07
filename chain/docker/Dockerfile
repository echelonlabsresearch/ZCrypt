# Foundation image: ABCI node + explorer + bridge watcher (same build, different CMD).
# Nightly: Plonky3 / zcrypt-shield require it (see impl/rust-toolchain.toml).
FROM rustlang/rust:nightly-bookworm AS build
WORKDIR /build
COPY impl /build/impl
# DEFAULT is PRODUCTION (empty features); mainnet-grade FRI parameters are compiled in
# unconditionally. Local faucet/dev: ABCI_FEATURES=devnet. Only abci-node takes features.
ARG ABCI_FEATURES=
RUN cd /build/impl && \
    if [ -n "$ABCI_FEATURES" ]; then \
      cargo build --release -p zcrypt-abci-node --features "$ABCI_FEATURES"; \
    else \
      cargo build --release -p zcrypt-abci-node; \
    fi && \
    cargo build --release -p zcrypt-explorer && \
    cargo build --release -p zcrypt-bridge --bin bridge_watcher

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/impl/target/release/zcrypt-abci-node /usr/local/bin/zcrypt-abci-node
COPY --from=build /build/impl/target/release/zcrypt-explorer /usr/local/bin/zcrypt-explorer
COPY --from=build /build/impl/target/release/bridge_watcher /usr/local/bin/bridge_watcher
ENV ABCI_PORT=26658
ENV EXPLORER_PORT=8080
EXPOSE 26658 8080
# Default process is the ABCI app; compose overrides command for explorer / watcher.
CMD ["zcrypt-abci-node"]
