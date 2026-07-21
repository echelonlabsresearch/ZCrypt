# Native Rust ABCI node (ABCI 2.0 / CometBFT 0.38).
# Nightly toolchain: the Plonky3 hidden-amount value layer (zcrypt-shield)
# requires nightly (see impl/rust-toolchain.toml + vendored p3-util patch).
FROM rustlang/rust:nightly-bookworm AS build
WORKDIR /build
COPY impl /build/impl
# Devnet images enable the `devnet` feature, which turns on the SEED tx (0x56) that
# the wallet's Fund faucet and custom-asset Mint use to issue coins locally. A
# PRODUCTION image MUST build with ABCI_FEATURES="" so 0x56 (unbacked coin
# injection) stays disabled — see the SEED gating in abci-node/src/main.rs.
ARG ABCI_FEATURES=devnet
RUN cd /build/impl && \
    if [ -n "$ABCI_FEATURES" ]; then \
      cargo build --release -p zcrypt-abci-node --features "$ABCI_FEATURES"; \
    else \
      cargo build --release -p zcrypt-abci-node; \
    fi

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/impl/target/release/zcrypt-abci-node /usr/local/bin/zcrypt-abci-node
ENV ABCI_PORT=26658
EXPOSE 26658
CMD ["zcrypt-abci-node"]
