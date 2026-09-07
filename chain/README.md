# ZCrypt × CometBFT (ABCI)

Dockerised **CometBFT 0.38** (ABCI 2.0) consensus with a **native Rust ABCI app**
(`zcrypt-abci-node`) that wraps `zcrypt-core::Node` directly.

This is the Cosmos-stack **consensus layer** (CometBFT, formerly Tendermint). It is
**not** a full Cosmos SDK chain (that layer is Go). For ZCrypt — a thin nullifier
registry — a small Rust ABCI binary is the right fit: it reuses the exact ZVM path
as `node.submit()`, with no FFI or language boundary (the core is already Rust).

## Architecture

```
Wallet / CLI                CometBFT 0.38 (consensus)          Rust ABCI node            zcrypt-core
─────────────               ─────────────────────────         ──────────────            ───────────
ZVM bytecode  ──broadcast──► mempool          ──socket──────► check_tx()      ───────►  Node::check()
                            FinalizeBlock      ─────────────► finalize_block() ──────►  Node::submit()  (per tx)
                            (app_hash)         ◄─────────────  state_root       ◄─────  SMT root
```

| ABCI 2.0 hook | ZCrypt |
|---------------|--------|
| `CheckTx` | `Node::check(bytecode)` — ZVM + supply cap + double-spend gate, no mutation |
| `FinalizeBlock` | `Node::submit(bytecode)` for each tx — insert nullifiers, update minted total; returns per-tx results + `app_hash` = SMT root |
| `Commit` | persists (state is in-memory here) |
| `Query` | `/registry/root`, `/registry/minted`, `/prove/<nf_hex>` |

**Tx format:** raw ZVM bytecode bytes (same as `impl/core` `zvm::encode` output).

## Quick start (foundation VPS)

One compose stack: **abci + cometbft + explorer + Caddy** (HTTPS host routing).

```bash
cd chain
cp .env.example .env   # set EXPLORER_DOMAIN, RPC_DOMAIN, ACME_EMAIL, genesis/SPV fields
# DNS: explorer.* and rpc.* both A → this VPS public IP (before Let's Encrypt works)
docker compose up --build -d
```

| What | Where |
|------|--------|
| Explorer (HTTPS) | `https://$EXPLORER_DOMAIN` (via Caddy) |
| CometBFT RPC (HTTPS) | `https://$RPC_DOMAIN` (via Caddy) |
| **P2P on host** | **`${FOUNDATION_P2P_PORT:-26656}` → container 26656** — open this in the VPS firewall for other validators |
| Raw RPC on host | `127.0.0.1:36657` by default (local admin only; public clients use `rpc.*`) |
| ABCI | internal only (`tcp://abci:26658`) |

Optional profiles:

```bash
# Regtest bitcoind (local demos only — not for a public production host)
docker compose --profile dev up -d

# Bridge watcher (requires ZCRYPT_RESERVE_SEED in .env; pulls bitcoind if using defaults)
ZCRYPT_RESERVE_SEED=... docker compose --profile bridge up -d
```

Query registry state:

```bash
curl -s 'http://127.0.0.1:36657/abci_query?path="/registry/root"'
curl -s 'http://127.0.0.1:36657/abci_query?path="/registry/minted"'
```

Submit a transaction (bytecode is base64 in JSON-RPC; large spends exceed GET URL limits):

```bash
curl -s -X POST http://127.0.0.1:36657 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"broadcast_tx_commit","params":{"tx":"<base64 bytecode>"}}'
```

Build the bytecode with the wallet (`Wallet::mint` / `Wallet::send` return `zvm::encode` output).

## Local dev (without Docker)

```bash
# terminal 1 — the ABCI app
cargo run --release -p zcrypt-abci-node        # binds 0.0.0.0:26658

# terminal 2 — consensus
cometbft init --home ~/.zcrypt/cometbft
#   set proxy_app = "tcp://127.0.0.1:26658" in config.toml
cometbft start --home ~/.zcrypt/cometbft
```

## Stack

Native Rust ABCI on modern CometBFT — **no Python, no PyO3, no py-abci**. The
previous Python front-end (py-abci) was unmaintained and stuck on the 0.34-era
ABCI protocol; it was replaced with `tendermint-abci` (ABCI 2.0).

| Path | Role |
|------|------|
| `impl/abci-node/` | Rust ABCI binary (`tendermint-abci` 0.40, CometBFT 0.38) wrapping `Node` |
| `impl/core/src/registry_state.rs` | JSON export/import for genesis & snapshots |
| `chain/docker-compose.yml` | `abci` + `cometbft` (v0.38) services |
| `chain/docker/Dockerfile` | Builds the Rust `zcrypt-abci-node` binary |
| `chain/docker/cometbft-entrypoint.sh` | inits genesis, points consensus at the ABCI app, exposes RPC |

## Genesis

On first start, `cometbft-entrypoint.sh` injects:

```json
"app_state": {
  "registry": { "minted_total": 0, "leaves": [] }
}
```

`init_chain` loads this into the registry (`Node::from_state`).
```
