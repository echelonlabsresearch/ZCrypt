# ZCrypt Block Explorer

A privacy-preserving block explorer: a public window onto the chain that, by construction,
reveals nothing private. It reads the same data any node sees (CometBFT RPC plus the node's
ABCI queries) and renders it, decoding each tagged transaction into a public-safe summary.

For a shielded transfer it shows the nullifiers, output commitments, anchor root, proof size,
and the fixed gas burn that an observer really sees, and names the hidden fields (amount,
sender, recipient, asset type) explicitly as **protected**. The point is to *demonstrate* the
privacy, not to hide the fact that the sensitive data was never published.

## Run

```sh
# defaults: node http://localhost:26657, listen on :8080
cargo run --release -p zcrypt-explorer

# point at the 3-node stack's node0 and pick a port
EXPLORER_NODE=http://localhost:46657 EXPLORER_PORT=8080 cargo run --release -p zcrypt-explorer
```

Then open <http://localhost:8080>.

## What it shows

- **Overview**: block height, the anonymity-set size (total commitments in the pool), ZCRYPT
  issued vs the 21M cap, validator and shielded-asset counts, chain id.
- **Blocks**: recent blocks; click one to expand its transactions. Each transaction renders
  its public fields, its protected (hidden) fields, and a one-line explanation of what an
  observer can and cannot learn.
- **Assets**: the shielded-asset registry (ticker, id, minted supply).
- **Validators**: the bonded set and stakes.

Transaction types decoded: shielded transfer (`0x55`), seed (`0x56`), bond/claim/unbond/
delegate/undelegate, asset registration (`0x59`), authority rotation (`0x61`), the HTLC
family (`0x5A`/`0x5B`/`0x5C`/`0x5D`), and in-pool swap locks (`0x62`).

## Design

- **Read-only.** The explorer never signs or broadcasts. It sees exactly what consensus
  publishes and nothing more.
- **No new heavy dependencies.** RPC via `ureq`; the HTTP server is hand-rolled on
  `std::net::TcpListener`; the transaction decoders reuse the real wire format
  (`zcrypt_core::shield_tx::from_bytes`) so the explorer cannot drift from the chain.
- **Self-contained UI.** The single-page front end is embedded in the binary (no build
  step, no external fonts or scripts), so the explorer is one binary to deploy.
