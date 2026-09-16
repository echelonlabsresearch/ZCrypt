//! Native Rust ABCI app for ZCrypt, targeting CometBFT 0.38 (ABCI 2.0).
//!
//! Replaces the old Python (py-abci) + PyO3 shim. The transaction is raw ZVM
//! bytecode; this wraps `zcrypt_core::node::Node` directly:
//!   * check_tx        -> Node::check   (mempool: ZVM + double-spend gate, no mutation)
//!   * finalize_block  -> Node::submit  (apply each tx; return per-tx results + app_hash)
//!   * commit          -> RocksDB StateDb (incremental leaves + fsync WriteBatch)
//!   * query           -> /registry/root, /registry/minted, /prove/<nf_hex>

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tendermint_abci::{Application, ServerBuilder};
use tendermint_proto::v0_38::abci::{
    CheckTxType, ExecTxResult, MisbehaviorType, RequestCheckTx, RequestFinalizeBlock, RequestInfo,
    RequestInitChain, RequestQuery, ResponseCheckTx, ResponseCommit, ResponseFinalizeBlock,
    ResponseInfo, ResponseInitChain, ResponseQuery, ValidatorUpdate,
};
use zcrypt_core::shield_tx::ShieldTx;
use tendermint_proto::v0_38::crypto::{public_key::Sum as PubKeySum, PublicKey};
use tendermint_proto::v0_38::types::BlockIdFlag;

use zcrypt_core::node::Node;
use zcrypt_core::smt;
use zcrypt_core::state_db::StateDb;

const OK: u32 = 0;
const ERR: u32 = 1;

/// Default chain id used only until `InitChain` (or a persisted chain_id file) sets the
/// real value from genesis. Production wallets should query CometBFT `status.network`.
const DEFAULT_CHAIN_ID: &[u8] = b"zcrypt-1";
/// Magic first byte marking a SHIELD **transfer** (hidden-amount, post-quantum
/// zero-knowledge value proof via Plonky3). A transfer bundles two proofs so that gas
/// is always paid in ZCRYPT even for a hidden non-ZCRYPT asset. Payload:
///   gas_blind(4×u64 = 32) ‖ gas_tx_len(u32 LE = 4) ‖ gas_tx_bytes ‖ main_tx_bytes
/// where `gas_tx.output[0]` burns exactly `MIN_FEE` ZCRYPT and `main_tx.fee == 0`.
/// Native ZVM bytecode always starts with `OP_PUSH` (0x01), so there is no collision.
const SHIELD_TAG: u8 = 0x55;
/// Devnet: seed a coin commitment into the tree so ring spends have decoys
/// (a real chain seeds via issuance). Payload: 64-byte commitment (8×u64 LE).
const SEED_TAG: u8 = 0x56;
/// The SEED tx appends an UNBACKED coin to the tree (no signature, no value
/// backing) — a counterfeiting primitive intended only for bootstrapping a local
/// devnet with decoys. It is compiled in ONLY under the off-by-default `devnet`
/// feature; a production build rejects `0x56` outright.
const SEED_ENABLED: bool = cfg!(feature = "devnet");
/// Bond a validator for staking block rewards. Payload (60 bytes):
///   [0..20]  CometBFT consensus **address** (matches `decided_last_commit` votes)
///   [20..28] stake, atomic units, u64 LE (≥ 10,000 ZCRYPT)
///   [28..60] reward address (32 bytes) rewards accrue to
/// Trustless: the reward is a pure function of height, split by the *verifiable*
/// signer set, so a validator cannot mint itself extra.
const BOND_TAG: u8 = 0x57;

/// Claim accrued staking rewards into spendable coinbase shield coins. Payload
/// (72 bytes): 64B shield pubkey `pk` (8×u64 LE) ‖ 8B amount (atomic, u64 LE).
/// The node mints coin(s) bound to `pk` and debits the reward ledger — trustless,
/// since coins can only be created against a real consensus-agreed balance.
const CLAIM_TAG: u8 = 0x58;

/// Register a shielded-asset ticker (first-mint-wins). Payload:
///   GAS PREFIX: gas_blind(4×u64 = 32) ‖ gas_tx_len(u32 LE) ‖ gas_tx_bytes (a ZCRYPT shield
///   spend whose output[0] burns exactly MIN_FEE ZCRYPT, exactly as a 0x55 transfer bundles),
///   then:
///   [0]      decimals
///   [1]      ticker length L
///   [2..2+L] ticker (UTF-8, e.g. "zBTC")
///   [2+L..2+L+8] max_supply (u64 LE)
///   [2+L+8..] optional 32-byte controlled-mint authority or 33-byte SPV reserve pubkey
/// State-creating txs used to be free, so a flood of registrations / opens grew every
/// node's per-block hashing and persistence for nothing (consensus H1).
const REGISTER_TAG: u8 = 0x59;

/// Open a shield-native HTLC escrow. Payload: the same GAS PREFIX as REGISTER, then
///   [0..8]    asset_id (u64 LE)   [8..16]   value (u64 LE)
///   [16..48]  hashlock (SHA-256)  [48..56]  timeout height (u64 LE)
///   [56..120] claim shield pubkey (8×u64 LE)   [120..] M-of-N mint authorization
const HTLC_OPEN_TAG: u8 = 0x5A;
/// Claim an HTLC escrow: escrow_id(32) ‖ preimage(rest). Mints the escrow coin.
const HTLC_CLAIM_TAG: u8 = 0x5B;
/// Expire an HTLC escrow after its timeout: escrow_id(32).
const HTLC_EXPIRE_TAG: u8 = 0x5C;
/// Lock existing zBTC into a **burn** escrow (zBTC→BTC). Payload:
///   [0..8] value  [8..40] blind(4×u64 LE)  [40..48] asset_id
///   [48..80] hashlock  [80..88] timeout  [88..152] refund_pk(8×u64 LE)
///   [152..] the shield tx bytes (its output[0] must be the burn coin)
const HTLC_BURN_LOCK_TAG: u8 = 0x5D;
/// Unbond a validator (signed by its consensus key). Releases its stake so it stops
/// accruing block rewards. Payload: ed25519_pubkey(32) ‖ signature(64).
const UNBOND_TAG: u8 = 0x5E;

/// Delegate coins toward a validator (coin-backed, signed by the delegator's ed25519
/// key). The pledged stake boosts the validator's voting power and earns the delegator
/// a share of its rewards (net of commission). Payload:
///   delegator_pubkey(32) ‖ target_addr(20) ‖ stake_le(8) ‖ reward(32) ‖ sig(64)
///   ‖ stake_blind(32) ‖ shield_tx (the burn-coin pledge).
const DELEGATE_TAG: u8 = 0x5F;

/// Undelegate a delegator's stake from a validator (signed by the delegator's key). The
/// stake leaves the validator's power at once and unbonds for the standard 10-day period
/// before returning. Payload: delegator_pubkey(32) ‖ target_addr(20) ‖ sig(64).
const UNDELEGATE_TAG: u8 = 0x60;

/// Rotate an asset's mint authority to a new key-set commitment (distributed-custody
/// migration / signer replacement). Payload:
///   [0..8] asset_id (u64 LE)  [8..40] new authority commitment (32)
///   [40..] the encoded threshold authorization from the CURRENT key set
const ROTATE_AUTH_TAG: u8 = 0x61;

/// Lock existing coins into a **swap** escrow (in-pool asset↔asset atomic swap). Two of
/// these across two assets, sharing one hashlock, form a private DEX/OTC trade — claim
/// and expire reuse the HTLC_CLAIM / HTLC_EXPIRE tags. Payload:
///   [0..8] value  [8..40] blind  [40..48] asset_id  [48..80] hashlock  [80..88] timeout
///   [88..152] counterparty_pk  [152..216] refund_pk  [216..] the lock shield tx
const SWAP_LOCK_TAG: u8 = 0x62;

/// Relay raw Bitcoin headers into the consensus SPV chain (anyone may send; each
/// header carries its own proof-of-work). Payload: N×80-byte headers, concatenated.
const BTC_HEADERS_TAG: u8 = 0x63;
/// Raw header bytes a single block may relay (two full batches). Header relays carry no
/// gas, so without a cap a relayer could fill every block with 161 KB header txs.
const MAX_HEADER_BYTES_PER_BLOCK: usize = 2 * zcrypt_core::spv::MAX_HEADER_BATCH * 80;
/// Leaves per `/commit/leaves` page. Clients page with `/commit/leaves/<from>` until a page
/// comes back shorter than this; one query never clones the whole tree (consensus H3).
const LEAF_PAGE: usize = 20_000;
/// Verified-proof cache size for mempool rechecks (tx digests whose STARKs already verified).
const VERIFIED_CACHE: usize = 4096;

/// Open a **zBTC** mint escrow gated by a Bitcoin **SPV deposit proof** — the
/// trustless bridge mint (no treasury, no signers). Payload:
///   [0..8]    asset_id (u64 LE)   [8..16]   value (u64 LE)
///   [16..48]  hashlock (SHA-256)  [48..56]  timeout height (u64 LE)
///   [56..120] claim shield pubkey (8×u64 LE)
///   [120..]   the encoded [`zcrypt_core::spv::MintProof`]
const HTLC_OPEN_SPV_TAG: u8 = 0x64;

/// **Re-anchor** an immature SPV mint whose Bitcoin deposit was orphaned but re-mined
/// into a new block by a benign reorg (inclusion re-verification): a relayer submits a
/// fresh SPV proof for the SAME deposit txid on the new best chain, and consensus moves
/// the mint's anchor forward so it keeps maturing instead of being voided. Payload: the
/// encoded [`zcrypt_core::spv::MintProof`].
const BTC_REANCHOR_TAG: u8 = 0x65;

/// Claim accrued **bridge-fee yield** as a staker: mints coins of the bridged asset
/// (the staker's share of protocol bridge fees) to a shield key. Payload (80 bytes):
///   [0..64] shield pubkey `pk` (8×u64 LE) ‖ [64..72] asset_id (u64 LE) ‖ [72..80] amount.
const CLAIM_FEE_TAG: u8 = 0x66;

/// A zBTC->BTC redeem burn-lock that ALSO carries the user's 33-byte Bitcoin claim pubkey, so
/// the bridge operator reads the payout key from the ON-CHAIN tx (authored by the escrow owner,
/// who proved ownership by spending the zBTC) instead of trusting an off-chain value. It creates
/// the EXACT same burn escrow as `HTLC_BURN_LOCK_TAG` (0x5D) — the pubkey is opaque to consensus
/// and only rides in the tx for the operator's redeem watcher. Payload:
///   [0..33] btc_claim_pk (compressed secp256k1) ‖ [33..] the 0x5D burn-lock payload.
const HTLC_BURN_LOCK_BTC_TAG: u8 = 0x67;

/// Retire the foundation sentinel: a tx SIGNED BY THE SENTINEL'S OWN consensus key that removes
/// its >2/3 liveness inflation, dropping it to normal staked power. Governance path to end the
/// bootstrap crutch early (it also auto-retires once external stake reaches the genesis decay
/// threshold). Payload: sentinel_pubkey(32) ‖ nonce(8) ‖ sig(64), signed over
/// "ZCRYPT-SENTINEL-DISABLE-v1" ‖ chain_id ‖ pubkey ‖ nonce (nonce = replay protection).
const SENTINEL_DISABLE_TAG: u8 = 0x68;
/// Rotate an SPV asset's Bitcoin reserve key (bridge review H3): `asset_le(8) ‖ old_pk(33) ‖
/// new_pk(33) ‖ sig(64)`, where `sig` is the CURRENT reserve key's compact ECDSA signature
/// over `spv::reserve_rotation_digest(chain, asset, epoch, old, new)`. The old key is
/// retired (its in-flight deposits still mint), new deposits must pay the new key.
const ROTATE_RESERVE_TAG: u8 = 0x69;

/// Devnet foundation account seed. The genesis foundation allocation is registered to
/// this account's REWARD ADDRESS (`h("ZC-REWARD-ADDR", pk)`), so the matching wallet
/// can actually claim vested tranches (tag 0x58) into spendable coins. This seed is
/// PUBLIC (it is in the repo) — it exists only as the ZERO-CONFIG devnet default, used
/// solely when a devnet genesis carries no `foundation_addr`.
#[cfg(feature = "devnet")]
const FOUNDATION_SEED: [u8; 32] = [0xF0; 32];

/// The foundation reward address for the genesis allocation. GENESIS IS THE SINGLE SOURCE
/// OF TRUTH: it is read from the genesis `app_state` `foundation_addr` field, so a
/// published `genesis.json` fully describes the chain and every node computes the identical
/// genesis app_hash with no out-of-band configuration. There is no env-var fallback. A
/// production genesis that omits it is a launch error (panic); a devnet build alone falls
/// back to the well-known dev seed so zero-config devnets and in-process tests still run.
fn foundation_addr(app_state_bytes: &[u8]) -> [u8; 32] {
    if let Some(a) = foundation_addr_from_genesis(app_state_bytes) {
        return a;
    }
    #[cfg(feature = "devnet")]
    {
        zcrypt_core::keys::Account::from_seed(FOUNDATION_SEED).reward_address()
    }
    #[cfg(not(feature = "devnet"))]
    panic!(
        "genesis app_state must carry `foundation_addr` (64 hex): the foundation's reward \
         address. Set ZCRYPT_FOUNDATION_ADDR when CREATING genesis so it is baked in \
         (generate the address offline with `cargo run -p zcrypt-core --example \
         foundation_keys new`)."
    )
}

/// Extract the foundation reward address from the genesis `app_state` JSON, if it carries
/// one: `{"foundation_addr":"<64 hex>", ...}`. Returns `None` (so the caller falls back to
/// the env var / dev seed) when the field is absent, empty, or malformed — the fallback is
/// deterministic across nodes (they all run this same parse), so it never forks the
/// app_hash. When present and valid it makes the genesis self-describing: a downloaded
/// `genesis.json` is all a new validator needs to compute the identical genesis app_hash.
fn foundation_addr_from_genesis(app_state_bytes: &[u8]) -> Option<[u8; 32]> {
    if app_state_bytes.is_empty() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(app_state_bytes).ok()?;
    let h = v.get("foundation_addr")?.as_str()?.trim();
    if h.is_empty() {
        return None;
    }
    hex::decode(h).ok()?.try_into().ok()
}

/// A 33-byte compressed secp256k1 key from the genesis `app_state` JSON (hex), e.g.
/// `zbtc_reserve_pk`. `None` when absent, empty, or malformed (deterministic across nodes).
fn genesis_pubkey33(app_state_bytes: &[u8], name: &str) -> Option<[u8; 33]> {
    let v: serde_json::Value = serde_json::from_slice(app_state_bytes).ok()?;
    let h = v.get(name)?.as_str()?.trim();
    if h.is_empty() {
        return None;
    }
    let raw: [u8; 33] = hex::decode(h).ok()?.try_into().ok()?;
    bitcoin_pk_ok(&raw).then_some(raw)
}

/// Whether `pk` is a well-formed compressed secp256k1 point.
fn bitcoin_pk_ok(pk: &[u8; 33]) -> bool {
    zcrypt_core::spv::reserve_pk_ok(pk)
}

/// A boolean flag in the genesis `app_state` JSON (e.g. `foundation_sentinel: true`).
/// Returns false when absent or not `true` — deterministic across nodes.
fn genesis_flag(app_state_bytes: &[u8], name: &str) -> bool {
    serde_json::from_slice::<serde_json::Value>(app_state_bytes)
        .ok()
        .and_then(|v| v.get(name).and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

/// A u64 field in the genesis `app_state` JSON (e.g. `foundation_sentinel_decay`). 0 if absent
/// or malformed — deterministic across nodes.
fn genesis_u64(app_state_bytes: &[u8], name: &str) -> u64 {
    serde_json::from_slice::<serde_json::Value>(app_state_bytes)
        .ok()
        .and_then(|v| v.get(name).and_then(|n| n.as_u64()))
        .unwrap_or(0)
}

/// The Bitcoin SPV mint-gate config `(network, checkpoint)` for this chain. GENESIS is the
/// source of truth: `btc_net` ("mainnet"|"signet"|"regtest") and optional `btc_checkpoint`
/// ("<160-hex-header>:<height>") in the genesis `app_state`, so a downloaded genesis.json
/// FULLY describes the bridge and a joining validator inherits the identical anchor with no
/// out-of-band env var (exactly like `foundation_addr`). Env vars (`ZCRYPT_BTC_NET` /
/// `ZCRYPT_BTC_CHECKPOINT`) are only a fallback for local/devnet stacks whose genesis omits
/// the fields. Returns empty strings when neither source provides a value. The genesis parse
/// is deterministic across nodes, so a launched chain (genesis carries `btc_net`) never forks
/// the app_hash on this.
fn btc_spv_config(app_state_bytes: &[u8]) -> (String, String) {
    let genesis = serde_json::from_slice::<serde_json::Value>(app_state_bytes).ok();
    let from_genesis = |k: &str| -> Option<String> {
        genesis
            .as_ref()
            .and_then(|v| v.get(k))
            .and_then(|s| s.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let from_env = |k: &str| -> Option<String> {
        std::env::var(k).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    };
    let net = from_genesis("btc_net").or_else(|| from_env("ZCRYPT_BTC_NET")).unwrap_or_default();
    let cp = from_genesis("btc_checkpoint")
        .or_else(|| from_env("ZCRYPT_BTC_CHECKPOINT"))
        .unwrap_or_default();
    (net, cp)
}

/// Build the consensus Bitcoin [`HeaderChain`] from a `(net, checkpoint)` config (see
/// [`btc_spv_config`]), applying the production fail-closed rules: a production build refuses
/// to run on regtest (trivial-difficulty SPV would accept forged, unbacked zBTC mints) and
/// mainnet REQUIRES a checkpoint (it will not sync ~900k headers from the Bitcoin genesis).
/// Returns `None` when no network is configured (devnet default: keep the node's regtest SPV).
/// Panics on a malformed/invalid checkpoint or, in production, a missing/regtest network — a
/// mis-anchored mint gate must never produce a chain.
fn build_spv_chain(net_str: &str, cp_str: &str) -> Option<zcrypt_core::spv::HeaderChain> {
    use zcrypt_core::spv::{BtcNet, HeaderChain};
    let production = !SEED_ENABLED;
    if net_str.is_empty() {
        if production {
            panic!(
                "production genesis must carry `btc_net` (\"mainnet\"|\"signet\") in app_state \
                 (set ZCRYPT_BTC_NET when CREATING genesis so it is baked in); refusing to \
                 default to regtest, which would accept forged zBTC mints"
            );
        }
        return None;
    }
    let btc_net = match net_str.to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" | "main" => BtcNet::Mainnet,
        "signet" => BtcNet::Signet,
        "regtest" => BtcNet::Regtest,
        other => panic!("btc_net: unrecognized network {other:?} (expected mainnet|signet|regtest)"),
    };
    if production && btc_net == BtcNet::Regtest {
        panic!(
            "production build refuses btc_net=regtest — trivial-difficulty SPV would accept \
             forged (unbacked) zBTC mints"
        );
    }
    if production && btc_net == BtcNet::Signet && !cfg!(test) {
        // Skipped under cfg(test): unit tests build signet configs to prove the SPV anchor is
        // folded into the app_hash. The guard protects the shipped production binary.
        panic!(
            "production build refuses btc_net=signet — SPV validates only signet's (low) \
             proof-of-work, never its block *signature* (signet's real authority), so an \
             attacker could grind cheap signet-difficulty headers and mint unbacked zBTC. \
             Use mainnet for real value; build with the `devnet` feature for signet testing"
        );
    }
    if production && btc_net == BtcNet::Mainnet && cp_str.is_empty() {
        panic!(
            "mainnet requires `btc_checkpoint`=<160-hex-header>:<height> with height % 2016 == 0 \
             — refusing to sync ~900k headers from the Bitcoin genesis block. Generate and \
             INDEPENDENTLY VERIFY a recent buried header first (chain/mainnet-checkpoint.sh)"
        );
    }
    if production && btc_net == BtcNet::Mainnet && !cfg!(test) {
        // A production mainnet node must run mainnet-grade shield FRI parameters. Those are
        // now compiled in unconditionally (no lower-security build variant exists), so this
        // is a belt-and-braces guard against a future edit lowering the constants: refuse to
        // anchor a real-value chain on an under-parameterised binary. Skipped under
        // `cfg(test)` so the mainnet-genesis unit tests can run the SPV-config paths.
        zcrypt_shield::assert_mainnet_grade();
    }
    Some(if cp_str.is_empty() {
        HeaderChain::new(btc_net)
    } else {
        let (hdr, height) = cp_str
            .split_once(':')
            .expect("btc_checkpoint must be <160-hex-header>:<height>");
        let raw: [u8; 80] = hex::decode(hdr)
            .expect("checkpoint header: invalid hex")
            .try_into()
            .expect("checkpoint header must be exactly 80 bytes");
        let height: u64 = height.parse().expect("checkpoint height: invalid number");
        HeaderChain::with_checkpoint(btc_net, raw, height).expect("invalid checkpoint")
    })
}

/// Parse the GAS PREFIX that state-creating txs carry: `gas_blind(32) ‖ gas_len(u32 LE) ‖
/// gas_tx`. Returns `(gas_blind, gas_tx, rest)`.
fn parse_gas_prefix(b: &[u8]) -> Option<([u64; 4], ShieldTx, &[u8])> {
    if b.len() < 36 {
        return None;
    }
    let mut gas_blind = [0u64; 4];
    for (i, limb) in gas_blind.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().ok()?);
    }
    let gas_len = u32::from_le_bytes(b[32..36].try_into().ok()?) as usize;
    let gas_end = 36usize.checked_add(gas_len)?;
    if b.len() < gas_end {
        return None;
    }
    let gas_tx = zcrypt_core::shield_tx::from_bytes(&b[36..gas_end])?;
    Some((gas_blind, gas_tx, &b[gas_end..]))
}

/// Parse an HTLC-open payload into (asset_id, value, hashlock, timeout, claim_pk, capability).
#[allow(clippy::type_complexity)]
fn parse_htlc_open(b: &[u8]) -> Option<(u64, u64, [u8; 32], u64, [u64; 8], Vec<u8>)> {
    if b.len() < 120 {
        return None;
    }
    let asset_id = u64::from_le_bytes(b[0..8].try_into().ok()?);
    let value = u64::from_le_bytes(b[8..16].try_into().ok()?);
    let mut hashlock = [0u8; 32];
    hashlock.copy_from_slice(&b[16..48]);
    let timeout = u64::from_le_bytes(b[48..56].try_into().ok()?);
    let claim_pk = parse_pubkey(&b[56..120])?;
    let capability = b[120..].to_vec();
    Some((asset_id, value, hashlock, timeout, claim_pk, capability))
}

/// Parse an SPV-gated HTLC-open payload into (asset_id, value, hashlock, timeout,
/// claim_pk, open_auth, mint_proof). Layout:
///   asset(8) ‖ value(8) ‖ hashlock(32) ‖ timeout(8) ‖ claim_pk(64) ‖ open_auth(64) ‖ MintProof
/// `open_auth` is the depositor's refund-key ECDSA signature binding `claim_pk` to the
/// deposit (H1 front-run defense).
#[allow(clippy::type_complexity)]
fn parse_htlc_open_spv(
    b: &[u8],
) -> Option<(u64, u64, [u8; 32], u64, [u64; 8], [u8; 64], zcrypt_core::spv::MintProof)> {
    if b.len() < 184 {
        return None;
    }
    let asset_id = u64::from_le_bytes(b[0..8].try_into().ok()?);
    let value = u64::from_le_bytes(b[8..16].try_into().ok()?);
    let mut hashlock = [0u8; 32];
    hashlock.copy_from_slice(&b[16..48]);
    let timeout = u64::from_le_bytes(b[48..56].try_into().ok()?);
    let claim_pk = parse_pubkey(&b[56..120])?;
    let open_auth: [u8; 64] = b[120..184].try_into().ok()?;
    let proof = zcrypt_core::spv::MintProof::from_bytes(&b[184..])?;
    Some((asset_id, value, hashlock, timeout, claim_pk, open_auth, proof))
}

/// Parse an authority-rotation payload into (asset_id, new_commitment, auth_blob).
fn parse_rotate(b: &[u8]) -> Option<(u64, [u8; 32], Vec<u8>)> {
    if b.len() < 40 {
        return None;
    }
    let asset_id = u64::from_le_bytes(b[0..8].try_into().ok()?);
    let mut new_commitment = [0u8; 32];
    new_commitment.copy_from_slice(&b[8..40]);
    Some((asset_id, new_commitment, b[40..].to_vec()))
}

/// Parse a 32-byte escrow id from a claim/expire payload (preimage, if any, follows).
fn parse_escrow_id(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() < 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&b[0..32]);
    Some(id)
}

/// Parse a burn-lock payload into (value, blind, asset_id, hashlock, timeout,
/// refund_pk, shield_tx).
#[allow(clippy::type_complexity)]
fn parse_burn_lock(
    b: &[u8],
) -> Option<(u64, [u64; 4], u64, [u8; 32], u64, [u64; 8], zcrypt_core::shield_tx::ShieldTx)> {
    // value(8) + blind(32) + asset(8) + hashlock(32) + timeout(8) + refund_pk(64) = 152
    if b.len() < 152 {
        return None;
    }
    let value = u64::from_le_bytes(b[0..8].try_into().ok()?);
    let blind = [
        u64::from_le_bytes(b[8..16].try_into().ok()?),
        u64::from_le_bytes(b[16..24].try_into().ok()?),
        u64::from_le_bytes(b[24..32].try_into().ok()?),
        u64::from_le_bytes(b[32..40].try_into().ok()?),
    ];
    let asset_id = u64::from_le_bytes(b[40..48].try_into().ok()?);
    let mut hashlock = [0u8; 32];
    hashlock.copy_from_slice(&b[48..80]);
    let timeout = u64::from_le_bytes(b[80..88].try_into().ok()?);
    let refund_pk = parse_pubkey(&b[88..152])?;
    let tx = zcrypt_core::shield_tx::from_bytes(&b[152..])?;
    Some((value, blind, asset_id, hashlock, timeout, refund_pk, tx))
}

/// Parse a swap-lock payload into (value, blind, asset_id, hashlock, timeout,
/// counterparty_pk, refund_pk, shield_tx). Like a burn-lock but with TWO keys: the
/// counterparty (claims with the preimage) and the refunder (the locker, on timeout).
#[allow(clippy::type_complexity)]
fn parse_swap_lock(
    b: &[u8],
) -> Option<(u64, [u64; 4], u64, [u8; 32], u64, [u64; 8], [u64; 8], zcrypt_core::shield_tx::ShieldTx)> {
    // value(8)+blind(32)+asset(8)+hashlock(32)+timeout(8)+counterparty_pk(64)+refund_pk(64) = 216
    if b.len() < 216 {
        return None;
    }
    let value = u64::from_le_bytes(b[0..8].try_into().ok()?);
    let blind = [
        u64::from_le_bytes(b[8..16].try_into().ok()?),
        u64::from_le_bytes(b[16..24].try_into().ok()?),
        u64::from_le_bytes(b[24..32].try_into().ok()?),
        u64::from_le_bytes(b[32..40].try_into().ok()?),
    ];
    let asset_id = u64::from_le_bytes(b[40..48].try_into().ok()?);
    let mut hashlock = [0u8; 32];
    hashlock.copy_from_slice(&b[48..80]);
    let timeout = u64::from_le_bytes(b[80..88].try_into().ok()?);
    let counterparty_pk = parse_pubkey(&b[88..152])?;
    let refund_pk = parse_pubkey(&b[152..216])?;
    let tx = zcrypt_core::shield_tx::from_bytes(&b[216..])?;
    Some((value, blind, asset_id, hashlock, timeout, counterparty_pk, refund_pk, tx))
}

/// Parse a register payload into (ticker, decimals, optional authority, max_supply,
/// is_spv). Layout: decimals(1) ‖ tlen(1) ‖ ticker ‖ max_supply_le(8) ‖ tail, where
/// tail is empty (protocol mint), a 32-byte authority hash (M-of-N key-set
/// commitment — user-minted assets), or a **33-byte compressed Bitcoin reserve
/// pubkey**, from which consensus derives the SPV sentinel authority itself —
/// the registrant never chooses the hash, so an SPV asset can only ever be minted
/// against proven Bitcoin deposits claimable by that reserve key.
fn parse_register(b: &[u8]) -> Option<(String, u8, Option<[u8; 32]>, u64, Option<[u8; 33]>)> {
    if b.len() < 2 {
        return None;
    }
    let decimals = b[0];
    let tlen = b[1] as usize;
    if b.len() < 2 + tlen + 8 {
        return None;
    }
    let ticker = String::from_utf8(b[2..2 + tlen].to_vec()).ok()?;
    let max_supply = u64::from_le_bytes(b[2 + tlen..2 + tlen + 8].try_into().ok()?);
    let rest = &b[2 + tlen + 8..];
    let (authority, reserve_pk) = if rest.is_empty() {
        (None, None)
    } else if rest.len() == 32 {
        let mut a = [0u8; 32];
        a.copy_from_slice(rest);
        (Some(a), None)
    } else if rest.len() == 33 {
        let pk: [u8; 33] = rest.try_into().ok()?;
        (Some(zcrypt_core::spv::spv_authority(&pk)), Some(pk))
    } else {
        return None;
    };
    Some((ticker, decimals, authority, max_supply, reserve_pk))
}

/// zBTC may ONLY be registered in SPV form (a 33-byte reserve key): its mint
/// authority is then trustless by construction — no key set, treasury, or
/// capability can ever authorize a zBTC mint on this chain.
fn zbtc_requires_spv(ticker: &str, is_spv: bool) -> Result<(), String> {
    use zcrypt_core::asset_registry::{canonical_ticker, ZBTC_TICKER};
    if canonical_ticker(ticker) == canonical_ticker(ZBTC_TICKER) && !SEED_ENABLED && !cfg!(test) {
        // Production chains bind the peg's reserve key at genesis; the ticker can never be
        // claimed by a transaction (first-come hijack, bridge H3 / consensus M4).
        return Err(format!(
            "'{ZBTC_TICKER}' is bound from genesis (zbtc_reserve_pk) and cannot be registered by transaction"
        ));
    }
    if canonical_ticker(ticker) == canonical_ticker(ZBTC_TICKER) && !is_spv {
        return Err(format!(
            "'{ZBTC_TICKER}' must be registered with a 33-byte Bitcoin reserve pubkey \
             (SPV-gated trustless mint) — discretionary mint authorities are not \
             accepted for the canonical BTC-pegged asset"
        ));
    }
    Ok(())
}

/// Parse a ROTATE_RESERVE (`0x69`) payload: `asset_le(8) ‖ old_pk(33) ‖ new_pk(33) ‖ sig(64)`.
fn parse_rotate_reserve(b: &[u8]) -> Option<(u64, [u8; 33], [u8; 33], [u8; 64])> {
    if b.len() != 8 + 33 + 33 + 64 {
        return None;
    }
    let asset = u64::from_le_bytes(b[0..8].try_into().ok()?);
    let old_pk: [u8; 33] = b[8..41].try_into().ok()?;
    let new_pk: [u8; 33] = b[41..74].try_into().ok()?;
    let sig: [u8; 64] = b[74..138].try_into().ok()?;
    Some((asset, old_pk, new_pk, sig))
}

/// Parse a 64-byte shield pubkey (8×u64 LE).
fn parse_pubkey(b: &[u8]) -> Option<[u64; 8]> {
    if b.len() != 64 {
        return None;
    }
    let mut pk = [0u64; 8];
    for (i, x) in pk.iter_mut().enumerate() {
        *x = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().ok()?);
    }
    Some(pk)
}

/// Parse a 72-byte claim payload into (pk, amount).
fn pubkey_bytes(pk: &[u64; 8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    for x in pk {
        b.extend_from_slice(&x.to_le_bytes());
    }
    b
}

fn parse_claim(b: &[u8]) -> Option<([u64; 8], u64)> {
    if b.len() != 72 {
        return None;
    }
    let pk = parse_pubkey(&b[0..64])?;
    let amount = u64::from_le_bytes(b[64..72].try_into().ok()?);
    Some((pk, amount))
}

/// Parse an 80-byte fee-claim payload into (pk, asset_id, amount).
fn parse_claim_fee(b: &[u8]) -> Option<([u64; 8], u64, u64)> {
    if b.len() != 80 {
        return None;
    }
    let pk = parse_pubkey(&b[0..64])?;
    let asset_id = u64::from_le_bytes(b[64..72].try_into().ok()?);
    let amount = u64::from_le_bytes(b[72..80].try_into().ok()?);
    Some((pk, asset_id, amount))
}

/// Parse and AUTHENTICATE a bond payload (H1). Layout (146 bytes):
///   ed25519_pubkey(32) ‖ stake_le(8) ‖ reward_address(32) ‖ commission_bps_le(2)
///   ‖ nonce_le(8) ‖ signature(64)
///
/// The signature must be by the ed25519 consensus key over
///   "ZCRYPT-BOND-v1" ‖ chain_id ‖ pubkey ‖ stake_le ‖ reward ‖ commission_le ‖ nonce_le
/// which proves the submitter controls that consensus key — so an attacker can no longer
/// bond in another validator's name to redirect its block rewards, re-point a reward
/// address, or forge its commission. The per-signer-key monotonic `nonce` makes the
/// signature single-use: a captured BOND signature can no longer be replayed (with the
/// attacker's own fresh pledge coins) to force a decommissioned validator back into the
/// active set. Returns `(address, pubkey, stake, reward, commission, nonce)`.
fn verify_bond(b: &[u8], chain_id: &[u8]) -> Option<(Vec<u8>, Vec<u8>, u64, [u8; 32], u16, u64)> {
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::{Digest, Sha256};
    if b.len() != 146 {
        return None;
    }
    let pubkey: [u8; 32] = b[0..32].try_into().ok()?;
    let stake = u64::from_le_bytes(b[32..40].try_into().ok()?);
    let mut reward = [0u8; 32];
    reward.copy_from_slice(&b[40..72]);
    let commission = u16::from_le_bytes(b[72..74].try_into().ok()?);
    let nonce = u64::from_le_bytes(b[74..82].try_into().ok()?);
    let sig_bytes: [u8; 64] = b[82..146].try_into().ok()?;

    let vk = VerifyingKey::from_bytes(&pubkey).ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    let mut msg = Vec::with_capacity(14 + chain_id.len() + 82);
    msg.extend_from_slice(b"ZCRYPT-BOND-v1");
    msg.extend_from_slice(chain_id);
    msg.extend_from_slice(&pubkey);
    msg.extend_from_slice(&stake.to_le_bytes());
    msg.extend_from_slice(&reward);
    msg.extend_from_slice(&commission.to_le_bytes());
    msg.extend_from_slice(&nonce.to_le_bytes());
    vk.verify_strict(&msg, &sig).ok()?;

    let addr = Sha256::digest(pubkey)[..20].to_vec();
    Some((addr, pubkey.to_vec(), stake, reward, commission, nonce))
}

/// Parse a **coin-backed** BOND payload:
///   verify_bond header (138) ‖ stake_blind (4×u64 = 32) ‖ shield_tx_bytes.
/// The header authenticates the validator + stake + reward + commission (as [`verify_bond`]);
/// the stake_blind + shield_tx are the pledge — the node checks the shield tx's `output[0]`
/// is the burn coin `commit(stake, stake_blind, BURN_PK, ZCRYPT)` and applies the spend.
#[allow(clippy::type_complexity)]
fn parse_bond_coin(
    b: &[u8],
    chain_id: &[u8],
) -> Option<(Vec<u8>, Vec<u8>, u64, [u8; 32], u16, u64, [u64; 4], zcrypt_core::shield_tx::ShieldTx)> {
    // 146-byte authenticated header ‖ stake_blind(32) ‖ shield_tx.
    if b.len() < 178 {
        return None;
    }
    let (addr, pubkey, stake, reward, commission, nonce) = verify_bond(&b[..146], chain_id)?;
    let mut stake_blind = [0u64; 4];
    for (i, limb) in stake_blind.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(b[146 + i * 8..154 + i * 8].try_into().ok()?);
    }
    let stx = zcrypt_core::shield_tx::from_bytes(&b[178..])?;
    Some((addr, pubkey, stake, reward, commission, nonce, stake_blind, stx))
}

/// Parse and AUTHENTICATE an unbond payload (104 bytes):
///   ed25519_pubkey(32) ‖ nonce(8) ‖ signature(64),
/// signed over "ZCRYPT-UNBOND-v1" ‖ chain_id ‖ pubkey ‖ nonce.
/// Returns `(validator_address, pubkey, nonce)`.
fn verify_unbond(b: &[u8], chain_id: &[u8]) -> Option<(Vec<u8>, [u8; 32], u64)> {
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::{Digest, Sha256};
    // pubkey(32) ‖ nonce(8) ‖ sig(64). The nonce (replay protection) + the REAL chain_id are
    // both signed, so a captured UNBOND cannot be replayed within or across chains.
    if b.len() != 104 {
        return None;
    }
    let pubkey: [u8; 32] = b[0..32].try_into().ok()?;
    let nonce = u64::from_le_bytes(b[32..40].try_into().ok()?);
    let sig_bytes: [u8; 64] = b[40..104].try_into().ok()?;
    let vk = VerifyingKey::from_bytes(&pubkey).ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    let mut msg = Vec::with_capacity(16 + chain_id.len() + 40);
    msg.extend_from_slice(b"ZCRYPT-UNBOND-v1");
    msg.extend_from_slice(chain_id);
    msg.extend_from_slice(&pubkey);
    msg.extend_from_slice(&nonce.to_le_bytes());
    vk.verify_strict(&msg, &sig).ok()?;
    Some((Sha256::digest(pubkey)[..20].to_vec(), pubkey, nonce))
}

/// Parse a bundled SHIELD **transfer** payload:
///   gas_blind(4×u64 = 32) ‖ gas_tx_len(u32 LE) ‖ gas_tx_bytes ‖ main_tx_bytes.
/// Returns `(gas_blind, gas_tx, main_tx)`. The node checks `gas_tx.output[0]` burns
/// exactly `MIN_FEE` ZCRYPT (so gas is ZCRYPT even when `main_tx` moves a hidden asset).
#[allow(clippy::type_complexity)]
fn parse_transfer(
    b: &[u8],
) -> Option<([u64; 4], zcrypt_core::shield_tx::ShieldTx, zcrypt_core::shield_tx::ShieldTx)> {
    if b.len() < 36 {
        return None;
    }
    let mut gas_blind = [0u64; 4];
    for (i, limb) in gas_blind.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().ok()?);
    }
    let gas_len = u32::from_le_bytes(b[32..36].try_into().ok()?) as usize;
    let gas_end = 36usize.checked_add(gas_len)?;
    if b.len() < gas_end {
        return None;
    }
    let gas_tx = zcrypt_core::shield_tx::from_bytes(&b[36..gas_end])?;
    let main_tx = zcrypt_core::shield_tx::from_bytes(&b[gas_end..])?;
    Some((gas_blind, gas_tx, main_tx))
}

/// Parse and AUTHENTICATE a delegate header (156 bytes):
///   delegator_pubkey(32) ‖ target_addr(20) ‖ stake_le(8) ‖ reward(32) ‖ signature(64)
///
/// The signature must be by the delegator's ed25519 key over
///   "ZCRYPT-DELEGATE-v1" ‖ chain_id ‖ delegator_pubkey ‖ target_addr ‖ stake_le ‖ reward
/// which proves the submitter controls the delegator identity — so only they can later
/// undelegate it, and nobody can delegate someone else's coins or redirect their returns.
/// Returns `(target_addr, delegator_id, stake, reward)` where `delegator_id =
/// SHA256(delegator_pubkey)[..20]` (the identity the undelegate signature must match).
fn verify_delegate(b: &[u8], chain_id: &[u8]) -> Option<(Vec<u8>, Vec<u8>, u64, [u8; 32])> {
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::{Digest, Sha256};
    if b.len() != 156 {
        return None;
    }
    let pubkey: [u8; 32] = b[0..32].try_into().ok()?;
    let target = b[32..52].to_vec();
    let stake = u64::from_le_bytes(b[52..60].try_into().ok()?);
    let mut reward = [0u8; 32];
    reward.copy_from_slice(&b[60..92]);
    let sig_bytes: [u8; 64] = b[92..156].try_into().ok()?;

    let vk = VerifyingKey::from_bytes(&pubkey).ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    let mut msg = Vec::with_capacity(18 + chain_id.len() + 92);
    msg.extend_from_slice(b"ZCRYPT-DELEGATE-v1");
    msg.extend_from_slice(chain_id);
    msg.extend_from_slice(&pubkey);
    msg.extend_from_slice(&target);
    msg.extend_from_slice(&stake.to_le_bytes());
    msg.extend_from_slice(&reward);
    vk.verify_strict(&msg, &sig).ok()?;

    let delegator_id = Sha256::digest(pubkey)[..20].to_vec();
    Some((target, delegator_id, stake, reward))
}

/// Parse a **coin-backed** DELEGATE payload:
///   verify_delegate header (156) ‖ stake_blind (4×u64 = 32) ‖ shield_tx_bytes.
/// The header authenticates the delegator + target + stake + reward; the stake_blind +
/// shield_tx are the pledge (checked against the burn coin exactly like a bond).
#[allow(clippy::type_complexity)]
fn parse_delegate_coin(
    b: &[u8],
    chain_id: &[u8],
) -> Option<(Vec<u8>, Vec<u8>, u64, [u8; 32], [u64; 4], zcrypt_core::shield_tx::ShieldTx)> {
    if b.len() < 188 {
        return None;
    }
    let (target, delegator_id, stake, reward) = verify_delegate(&b[..156], chain_id)?;
    let mut stake_blind = [0u64; 4];
    for (i, limb) in stake_blind.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(b[156 + i * 8..164 + i * 8].try_into().ok()?);
    }
    let stx = zcrypt_core::shield_tx::from_bytes(&b[188..])?;
    Some((target, delegator_id, stake, reward, stake_blind, stx))
}

/// Parse and AUTHENTICATE an undelegate payload (124 bytes):
///   delegator_pubkey(32) ‖ target_addr(20) ‖ nonce(8) ‖ signature(64),
/// signed over "ZCRYPT-UNDELEGATE-v1" ‖ chain_id ‖ pubkey ‖ target ‖ nonce.
/// Returns `(target_addr, delegator_id, pubkey, nonce)`.
fn verify_undelegate(b: &[u8], chain_id: &[u8]) -> Option<(Vec<u8>, Vec<u8>, [u8; 32], u64)> {
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::{Digest, Sha256};
    // pubkey(32) ‖ target(20) ‖ nonce(8) ‖ sig(64). Nonce + real chain_id are signed → single-use.
    if b.len() != 124 {
        return None;
    }
    let pubkey: [u8; 32] = b[0..32].try_into().ok()?;
    let target = b[32..52].to_vec();
    let nonce = u64::from_le_bytes(b[52..60].try_into().ok()?);
    let sig_bytes: [u8; 64] = b[60..124].try_into().ok()?;
    let vk = VerifyingKey::from_bytes(&pubkey).ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    let mut msg = Vec::with_capacity(20 + chain_id.len() + 60);
    msg.extend_from_slice(b"ZCRYPT-UNDELEGATE-v1");
    msg.extend_from_slice(chain_id);
    msg.extend_from_slice(&pubkey);
    msg.extend_from_slice(&target);
    msg.extend_from_slice(&nonce.to_le_bytes());
    vk.verify_strict(&msg, &sig).ok()?;
    let delegator_id = Sha256::digest(pubkey)[..20].to_vec();
    Some((target, delegator_id, pubkey, nonce))
}

/// Verify a SENTINEL_DISABLE (0x68): pubkey(32) ‖ nonce(8) ‖ sig(64), signed over
/// "ZCRYPT-SENTINEL-DISABLE-v1" ‖ chain_id ‖ pubkey ‖ nonce. Returns (pubkey, nonce). The
/// handler further checks the pubkey IS the current sentinel key before retiring it.
fn verify_sentinel_disable(b: &[u8], chain_id: &[u8]) -> Option<([u8; 32], u64)> {
    use ed25519_dalek::{Signature, VerifyingKey};
    if b.len() != 104 {
        return None;
    }
    let pubkey: [u8; 32] = b[0..32].try_into().ok()?;
    let nonce = u64::from_le_bytes(b[32..40].try_into().ok()?);
    let sig_bytes: [u8; 64] = b[40..104].try_into().ok()?;
    let vk = VerifyingKey::from_bytes(&pubkey).ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    let mut msg = Vec::with_capacity(26 + chain_id.len() + 40);
    msg.extend_from_slice(b"ZCRYPT-SENTINEL-DISABLE-v1");
    msg.extend_from_slice(chain_id);
    msg.extend_from_slice(&pubkey);
    msg.extend_from_slice(&nonce.to_le_bytes());
    vk.verify_strict(&msg, &sig).ok()?;
    Some((pubkey, nonce))
}

/// Extract the validator addresses that *signed* the just-decided block from
/// CometBFT's `decided_last_commit` (only `BlockIdFlag::Commit` votes count).
fn signers_of(req: &RequestFinalizeBlock) -> Vec<Vec<u8>> {
    let commit = match &req.decided_last_commit {
        Some(c) => c,
        None => return Vec::new(),
    };
    commit
        .votes
        .iter()
        .filter(|v| v.block_id_flag == BlockIdFlag::Commit as i32)
        .filter_map(|v| v.validator.as_ref().map(|val| val.address.to_vec()))
        .collect()
}

/// CometBFT voting power for a bonded `stake`: whole ZCRYPT (`stake / ATOMIC`),
/// floored to ≥ 1 so a bonded validator always carries real weight. A deterministic
/// function of the consensus-committed stake, so every node derives the same power.
fn voting_power(stake: u64) -> i64 {
    (stake / zcrypt_core::emission::ATOMIC).max(1) as i64
}

/// Build CometBFT validator-set updates from the change in the app's bonded set over
/// a block. `before`/`after` are `node.validator_set()` (consensus_pubkey → stake)
/// snapshots taken before and after applying the block's txs:
///   * a newly-bonded or re-staked validator → `power = voting_power(stake)` (joins /
///     re-weights the block-producing set),
///   * an unbonded validator → power 0 (CometBFT removes it),
///   * a validator that never bonded (e.g. the genesis set) is in neither snapshot,
///     so it is never touched.
///
/// Purely a function of consensus-committed state (the staking ledger is in the
/// app_hash), so every validator computes identical updates and their CometBFT
/// validator sets stay in lockstep — a divergent update would fork the app_hash and
/// halt, never silently split the set.
fn validator_updates(before: &[(Vec<u8>, u64)], after: &[(Vec<u8>, u64)]) -> Vec<ValidatorUpdate> {
    validator_updates_excluding(before, after, None)
}

/// [`validator_updates`] with the sentinel key EXCLUDED from the diff. The sentinel's
/// CometBFT power is owned by `Node::sentinel_update` (its supermajority inflation);
/// emitting it here too let any 1-ZCRYPT delegation to the sentinel overwrite that power
/// with its stake, and a block that changed both produced two updates for one key, which
/// CometBFT rejects (a permanent halt). Consensus C1.
fn validator_updates_excluding(
    before: &[(Vec<u8>, u64)],
    after: &[(Vec<u8>, u64)],
    exclude: Option<&[u8]>,
) -> Vec<ValidatorUpdate> {
    use std::collections::BTreeMap;
    let keep = |k: &&Vec<u8>| exclude.map(|x| x != k.as_slice()).unwrap_or(true);
    let bmap: BTreeMap<&Vec<u8>, u64> = before.iter().map(|(k, v)| (k, *v)).filter(|(k, _)| keep(k)).collect();
    let amap: BTreeMap<&Vec<u8>, u64> = after.iter().map(|(k, v)| (k, *v)).filter(|(k, _)| keep(k)).collect();
    let mk = |pubkey: &[u8], power: i64| ValidatorUpdate {
        pub_key: Some(PublicKey { sum: Some(PubKeySum::Ed25519(pubkey.to_vec())) }),
        power,
    };
    let mut out = Vec::new();
    // Added or re-staked (present after with a different — or new — power).
    for (pk, &stake) in &amap {
        if pk.is_empty() {
            continue; // never emit an update for a keyless (impossible) validator
        }
        if bmap.get(*pk) != Some(&stake) {
            out.push(mk(pk, voting_power(stake)));
        }
    }
    // Removed (present before, gone after) → power 0 tells CometBFT to drop it.
    for pk in bmap.keys() {
        if !pk.is_empty() && !amap.contains_key(*pk) {
            out.push(mk(pk, 0));
        }
    }
    out
}

fn parse_commitment(b: &[u8]) -> Option<[u64; 8]> {
    if b.len() != 64 {
        return None;
    }
    let mut c = [0u64; 8];
    for (i, ci) in c.iter_mut().enumerate() {
        *ci = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().ok()?);
    }
    Some(c)
}

/// Rejection for any classical / native path. The Pedersen/Bulletproofs value
/// layer (native transfer, native mint, transparent HTLC, VRF, transparent-STARK)
/// has been removed entirely — the post-quantum hidden-amount **shield** path
/// (`0x55`) is the only value layer. Assets/rewards/HTLC use their own tags.
const CLASSICAL_DISABLED: &str = "unknown tx: only shield (0x55) + shield-asset/reward/HTLC tags are accepted";

/// Human-readable name for a tx's leading tag byte (for CheckTx/FinalizeBlock logs).
fn tag_name(b: Option<u8>) -> &'static str {
    match b {
        Some(SHIELD_TAG) => "SHIELD",
        Some(SEED_TAG) => "SEED",
        Some(BOND_TAG) => "BOND",
        Some(UNBOND_TAG) => "UNBOND",
        Some(DELEGATE_TAG) => "DELEGATE",
        Some(UNDELEGATE_TAG) => "UNDELEGATE",
        Some(SENTINEL_DISABLE_TAG) => "SENTINEL_DISABLE",
        Some(CLAIM_TAG) => "CLAIM",
        Some(REGISTER_TAG) => "REGISTER",
        Some(HTLC_OPEN_TAG) => "HTLC_OPEN",
        Some(HTLC_CLAIM_TAG) => "HTLC_CLAIM",
        Some(HTLC_EXPIRE_TAG) => "HTLC_EXPIRE",
        Some(HTLC_BURN_LOCK_TAG) => "HTLC_BURN_LOCK",
        Some(HTLC_BURN_LOCK_BTC_TAG) => "HTLC_BURN_LOCK_BTC",
        Some(ROTATE_AUTH_TAG) => "ROTATE_AUTH",
        Some(SWAP_LOCK_TAG) => "SWAP_LOCK",
        Some(BTC_HEADERS_TAG) => "BTC_HEADERS",
        Some(HTLC_OPEN_SPV_TAG) => "HTLC_OPEN_SPV",
        Some(BTC_REANCHOR_TAG) => "BTC_REANCHOR",
        Some(CLAIM_FEE_TAG) => "CLAIM_FEE",
        Some(ROTATE_RESERVE_TAG) => "ROTATE_RESERVE",
        _ => "UNKNOWN",
    }
}

struct State {
    node: Node,
    height: i64,
    /// CometBFT genesis `chain_id` bytes — bound into shield proofs and staking signatures.
    chain_id: Vec<u8>,
    /// The app hash of the last finalized (or loaded) state, served to `info` and `/app/hash`
    /// so public queries never recompute consensus roots under the state lock.
    app_hash: [u8; 32],
}

/// ABCI application. `Clone` is required by tendermint-abci; all heavy state is behind `Arc`.
#[derive(Clone)]
struct ZcryptApp {
    state: Arc<Mutex<State>>,
    /// RocksDB-backed durable store (incremental leaves + synced WriteBatch per Commit).
    store: Arc<Mutex<StateDb>>,
    /// Directory/path passed to RocksDB (also anchors `.chain_id` sidecar).
    db_path: PathBuf,
    /// Postcard backup path (legacy-compatible single-file format), written after each commit.
    backup_path: PathBuf,
    /// When true (default), a failed DB commit panics so CometBFT restarts and replays
    /// rather than continuing with unsaved state. Set `ZCRYPT_STATE_STRICT=0` to log-only.
    strict: bool,
    /// Write the postcard backup file every this many blocks (0 = never). The backup
    /// serializes the ENTIRE state, so writing it every block was O(state) per block.
    backup_every: u64,
    /// Digests of mempool txs whose STARK proofs already verified, so CometBFT's per-block
    /// recheck does not re-run every pending proof (bounded FIFO).
    verified: Arc<Mutex<(HashSet<[u8; 32]>, VecDeque<[u8; 32]>)>>,
}

/// SHA-256 of the raw tx bytes (the verified-proof cache key).
fn tx_digest(tx: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(tx).into()
}

/// Persist genesis chain id next to the state DB directory so restarts keep the same domain.
fn chain_id_path(db_path: &Path) -> PathBuf {
    // Prefer `<db>.chain_id` beside the DB directory/file stem.
    PathBuf::from(format!("{}.chain_id", db_path.display()))
}

fn load_chain_id(db_path: &Path) -> Vec<u8> {
    match std::fs::read(chain_id_path(db_path)) {
        Ok(b) if !b.is_empty() => b,
        _ => DEFAULT_CHAIN_ID.to_vec(),
    }
}

/// Header-relay txs must not exceed the per-block byte budget; tracked per block so the
/// cap is a deterministic function of the block's contents.
fn header_budget_ok(used: usize, len: usize) -> bool {
    used.saturating_add(len) <= MAX_HEADER_BYTES_PER_BLOCK
}

fn persist_chain_id(db_path: &Path, chain_id: &[u8]) {
    let path = chain_id_path(db_path);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&path, chain_id);
}

impl ZcryptApp {
    /// Open the RocksDB store at `db_path`, migrating `legacy_bin` if the DB is empty.
    fn new(db_path: PathBuf, legacy_bin: Option<PathBuf>, backup_path: PathBuf, strict: bool) -> Self {
        Self::with_backup_every(db_path, legacy_bin, backup_path, strict, 1000)
    }

    fn with_backup_every(
        db_path: PathBuf,
        legacy_bin: Option<PathBuf>,
        backup_path: PathBuf,
        strict: bool,
        backup_every: u64,
    ) -> Self {
        let (store, loaded) = StateDb::open_or_migrate(&db_path, legacy_bin.as_deref()).unwrap_or_else(|e| {
            panic!("cannot open state db {}: {e}", db_path.display());
        });
        let (node, height) = match loaded {
            Some((n, h)) => (n, h as i64),
            None => (Node::new(), 0),
        };
        // The chain id stamped in the durable state is authoritative; the sidecar file and
        // the compiled default are fallbacks only (a lost sidecar used to silently switch a
        // node to the default domain and reject every valid tx).
        let chain_id = match store.chain_id() {
            Ok(Some(id)) => id,
            _ => load_chain_id(&db_path),
        };
        let app_hash = node.state_root();
        ZcryptApp {
            state: Arc::new(Mutex::new(State { node, height, chain_id, app_hash })),
            store: Arc::new(Mutex::new(store)),
            db_path,
            backup_path,
            strict,
            backup_every,
            verified: Arc::new(Mutex::new((HashSet::new(), VecDeque::new()))),
        }
    }

    fn verified_contains(&self, d: &[u8; 32]) -> bool {
        self.verified.lock().unwrap_or_else(|p| p.into_inner()).0.contains(d)
    }

    fn verified_insert(&self, d: [u8; 32]) {
        let mut g = self.verified.lock().unwrap_or_else(|p| p.into_inner());
        if g.0.insert(d) {
            g.1.push_back(d);
            while g.1.len() > VERIFIED_CACHE {
                if let Some(old) = g.1.pop_front() {
                    g.0.remove(&old);
                }
            }
        }
    }

    /// Acquire the state lock, tolerating mutex poisoning.
    ///
    /// Without this, a panic in ANY handler poisons the mutex, and then every
    /// subsequent `lock().unwrap()` panics too — one fault cascades into total node
    /// death (even read-only queries die). Recovering the guard breaks that cascade.
    ///
    /// It is safe to continue on a recovered guard because CometBFT compares each
    /// block's app_hash across validators: a node that ever proceeded on
    /// inconsistent state would diverge and HALT, never fork. And because state is
    /// snapshotted every block, a hard crash simply restarts from the last
    /// consistent snapshot. So the worst case is a clean halt/restart, not a
    /// silently-forked chain.
    fn locked(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn store_locked(&self) -> std::sync::MutexGuard<'_, StateDb> {
        self.store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Application for ZcryptApp {
    fn info(&self, _req: RequestInfo) -> ResponseInfo {
        let s = self.locked();
        ResponseInfo {
            data: "zcrypt-registry".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            app_version: 1,
            last_block_height: s.height,
            last_block_app_hash: s.app_hash.to_vec().into(),
        }
    }

    fn init_chain(&self, req: RequestInitChain) -> ResponseInitChain {
        let mut s = self.locked();
        // Genesis chain_id is the single cryptographic domain for proofs + staking sigs.
        let cid = req.chain_id.as_bytes();
        if cid.is_empty() {
            eprintln!("[chain_id] genesis chain_id empty — keeping {}", String::from_utf8_lossy(&s.chain_id));
        } else {
            s.chain_id = cid.to_vec();
            persist_chain_id(&self.db_path, &s.chain_id);
            eprintln!("[chain_id] set from genesis: {}", req.chain_id);
        }
        // One-time 20% foundation allocation (idempotent inside the node). The reward
        // address comes from the genesis `app_state` — genesis is the single source of
        // truth, so a downloaded genesis.json FULLY describes the chain and no out-of-band
        // env var is needed to join (a devnet build alone falls back to the dev seed).
        s.node.mint_foundation(foundation_addr(&req.app_state_bytes));
        // Liveness guarantor: if the genesis opts in (`foundation_sentinel: true`), make the
        // sole genesis validator the foundation SENTINEL — the app then keeps its voting
        // power above 2/3 of the total forever, so it alone can always commit blocks and the
        // chain never halts, even if every other validator unbonds or goes offline.
        if genesis_flag(&req.app_state_bytes, "foundation_sentinel") {
            match req.validators.as_slice() {
                [v] => {
                    if let Some(PublicKey { sum: Some(PubKeySum::Ed25519(pk)) }) = &v.pub_key {
                        // Auto-decay threshold (whole ZCRYPT of external stake at which the
                        // sentinel retires). 0 = permanent (legacy). It can also be disabled early
                        // by a sentinel-signed tx (0x68).
                        let decay = genesis_u64(&req.app_state_bytes, "foundation_sentinel_decay") as i64;
                        s.node.set_sentinel(pk.clone(), v.power, decay);
                        eprintln!(
                            "[sentinel] foundation liveness guarantor = {} (power floor {}, auto-retires when external stake ≥ {} ZCRYPT; 0=permanent)",
                            hex::encode(pk), v.power, decay
                        );
                    }
                }
                other => eprintln!(
                    "[sentinel] foundation_sentinel set but genesis has {} validators (need exactly 1); no sentinel",
                    other.len()
                ),
            }
        }
        // Configure the in-consensus Bitcoin SPV mint gate (trustless zBTC) from GENESIS, so a
        // downloaded genesis.json fully describes the bridge and a joining validator inherits
        // the identical Bitcoin anchor with ZERO out-of-band config (mirrors foundation_addr).
        // Genesis-only by nature: init_chain runs once at genesis, so a restart keeps the
        // persisted SPV chain. A production build fails closed here (see `build_spv_chain`).
        let (btc_net, btc_cp) = btc_spv_config(&req.app_state_bytes);
        if let Some(chain) = build_spv_chain(&btc_net, &btc_cp) {
            match s.node.configure_btc_chain(chain) {
                Ok(()) => eprintln!("[spv] Bitcoin network configured from genesis: {btc_net}"),
                Err(e) => eprintln!("[spv] keeping persisted SPV chain ({e})"),
            }
        }
        // zBTC's reserve key is bound in GENESIS (`zbtc_reserve_pk`), never by a first-come
        // REGISTER tx: whoever landed that tx first owned every bridged BTC forever, with no
        // rotation (bridge H3 / consensus M4). Once registered here, a later REGISTER of the
        // ticker fails as "already registered".
        if let Some(pk) = genesis_pubkey33(&req.app_state_bytes, "zbtc_reserve_pk") {
            use zcrypt_core::asset_registry::{ZBTC_DECIMALS, ZBTC_MAX_SUPPLY, ZBTC_TICKER};
            match s.node.register_spv_asset(ZBTC_TICKER, ZBTC_DECIMALS, &pk, ZBTC_MAX_SUPPLY) {
                Ok(id) => eprintln!("[zbtc] reserve key pinned from genesis: asset {id}, reserve {}", hex::encode(pk)),
                Err(e) => panic!("[zbtc] genesis registration failed: {e}"),
            }
        } else if !SEED_ENABLED && !cfg!(test) {
            // Production: a missing or malformed reserve key must not silently fall back to
            // first-come registration of the peg ticker (the race the genesis binding exists
            // to close). Devnet stacks may run without a bridge.
            panic!(
                "production genesis must carry `zbtc_reserve_pk` (66-hex compressed secp256k1 \
                 reserve public key); see chain/.env.example ZCRYPT_RESERVE_PK"
            );
        }
        s.app_hash = s.node.state_root();
        ResponseInitChain {
            app_hash: s.app_hash.to_vec().into(),
            ..Default::default()
        }
    }

    fn check_tx(&self, req: RequestCheckTx) -> ResponseCheckTx {
        let tx = req.tx.as_ref();
        let name = tag_name(tx.first().copied());
        let is_recheck = req.r#type == CheckTxType::Recheck as i32;
        let digest = tx_digest(tx);
        // Phase 1 (under the state lock, microseconds): parse, authenticate, and run every
        // proof-FREE precondition. Shield proofs are collected and verified in phase 2 with
        // the lock RELEASED, so a flood of expensive-but-invalid proofs cannot starve
        // block execution (consensus M3).
        let (result, deferred, chain_id) = {
            let s = self.locked();
            let (r, d) = self.check_tx_locked(&s, tx);
            (r, d, s.chain_id.clone())
        };
        let result = match result {
            Err(e) => Err(e),
            Ok(()) if deferred.is_empty() => Ok(()),
            Ok(()) if is_recheck && self.verified_contains(&digest) => Ok(()),
            Ok(()) => {
                let mut r = Ok(());
                for (stx, env) in &deferred {
                    if let Err(e) = zcrypt_core::shield_tx::verify_bound(&chain_id, stx, env) {
                        r = Err(e);
                        break;
                    }
                }
                if r.is_ok() {
                    self.verified_insert(digest);
                }
                r
            }
        };
        match result {
            Ok(()) => {
                eprintln!("[check_tx]  {name:<14} accepted ({} bytes)", tx.len());
                ResponseCheckTx { code: OK, ..Default::default() }
            }
            Err(e) => {
                eprintln!("[check_tx]  {name:<14} REJECTED: {e}");
                ResponseCheckTx { code: ERR, log: e, ..Default::default() }
            }
        }
    }

    fn finalize_block(&self, req: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        self.finalize_block_impl(req)
    }

    fn commit(&self) -> ResponseCommit {
        self.commit_impl()
    }

    fn query(&self, req: RequestQuery) -> ResponseQuery {
        self.query_impl(req)
    }
}

impl ZcryptApp {
    /// The proof-free mempool checks (see [`Application::check_tx`]). Returns the outcome
    /// and the `(shield tx, envelope)` proofs still to verify outside the lock.
    #[allow(clippy::type_complexity)]
    fn check_tx_locked(&self, s: &State, tx: &[u8]) -> (Result<(), String>, Vec<(ShieldTx, Vec<u8>)>) {
        let chain_id = s.chain_id.as_slice();
        let mut deferred: Vec<(ShieldTx, Vec<u8>)> = Vec::new();
        let result = if tx.first() == Some(&SHIELD_TAG) {
            match parse_transfer(&tx[1..]) {
                Some((gas_blind, gas_tx, main_tx)) => {
                    s.node.precheck_transfer(&main_tx, &gas_tx, gas_blind).map(|()| {
                        deferred.push((gas_tx, Vec::new()));
                        deferred.push((main_tx, Vec::new()));
                    })
                }
                None => Err("malformed transfer (needs a ZCRYPT gas note + main tx)".to_string()),
            }
        } else if tx.first() == Some(&SEED_TAG) {
            if !SEED_ENABLED {
                Err("SEED tx (0x56) is disabled: unbacked coin injection is devnet-only".to_string())
            } else if parse_commitment(&tx[1..]).is_some() {
                Ok(())
            } else {
                Err("bad seed".to_string())
            }
        } else if tx.first() == Some(&BOND_TAG) {
            match parse_bond_coin(&tx[1..], chain_id) {
                Some((addr, pubkey, stake, reward, commission, nonce, stake_blind, stx)) => {
                    let pk32: Option<[u8; 32]> = pubkey.as_slice().try_into().ok();
                    if stake < zcrypt_core::staking::MIN_STAKE {
                        Err("stake below minimum (10,000 ZCRYPT)".to_string())
                    } else if s.node.is_validator(&addr) {
                        Err("validator already bonded; unbond before re-bonding".to_string())
                    } else if s.node.is_tombstoned(&addr) {
                        Err("validator is tombstoned and cannot re-bond".to_string())
                    } else if commission > zcrypt_core::staking::MAX_COMMISSION_BPS {
                        Err("commission exceeds 100%".to_string())
                    } else if pk32.map(|k| nonce != s.node.auth_nonce(&k)).unwrap_or(true) {
                        Err("bond nonce mismatch (replay?)".to_string())
                    } else if stx.fee < zcrypt_core::emission::MIN_FEE {
                        Err("bond: pledge spend must burn ≥ MIN_FEE gas".to_string())
                    } else {
                        let expected = zcrypt_shield::commit_asset(
                            stake, &stake_blind, &zcrypt_core::htlc_shield::BURN_PK, zcrypt_shield::ASSET_ZCRYPT,
                        );
                        if stx.output_commitments.first() != Some(&expected) {
                            Err("bond: output[0] is not the declared stake burn coin".to_string())
                        } else {
                            // The pledge proof must be bound to this exact header (see
                            // `Node::bond_with_stake`): verified with the same envelope.
                            let env = zcrypt_core::staking::bond_envelope(&pubkey, stake, &reward, commission, nonce);
                            s.node.precheck_shield(&stx).map(|()| deferred.push((stx, env)))
                        }
                    }
                }
                None => Err("malformed or unauthenticated bond tx (needs the stake pledge)".to_string()),
            }
        } else if tx.first() == Some(&UNBOND_TAG) {
            match verify_unbond(&tx[1..], chain_id) {
                // CheckTx mirrors DeliverTx: the signer must currently BE a bonded validator, or
                // any fresh key with nonce 0 could fill blocks with unbonds that fail at delivery
                // for free (consensus M2).
                Some((addr, _, _)) if !s.node.is_validator(&addr) => {
                    Err("unbond: signer is not a bonded validator".to_string())
                }
                Some((_, signer_pk, nonce)) if nonce == s.node.auth_nonce(&signer_pk) => Ok(()),
                Some(_) => Err("unbond nonce mismatch (replay?)".to_string()),
                None => Err("malformed or unauthenticated unbond tx".to_string()),
            }
        } else if tx.first() == Some(&DELEGATE_TAG) {
            match parse_delegate_coin(&tx[1..], chain_id) {
                Some((target, delegator, stake, reward, stake_blind, stx)) => {
                    if stake == 0 {
                        Err("delegation must be a positive stake".to_string())
                    } else if !s.node.is_validator(&target) {
                        Err("delegation target is not a bonded validator".to_string())
                    } else if s.node.is_tombstoned(&target) {
                        Err("cannot delegate to a tombstoned validator".to_string())
                    } else if stx.fee < zcrypt_core::emission::MIN_FEE {
                        Err("delegate: pledge spend must burn ≥ MIN_FEE gas".to_string())
                    } else {
                        let expected = zcrypt_shield::commit_asset(
                            stake, &stake_blind, &zcrypt_core::htlc_shield::BURN_PK, zcrypt_shield::ASSET_ZCRYPT,
                        );
                        if stx.output_commitments.first() != Some(&expected) {
                            Err("delegate: output[0] is not the declared stake burn coin".to_string())
                        } else {
                            let env = zcrypt_core::staking::delegate_envelope(&delegator, &target, stake, &reward);
                            s.node.precheck_shield(&stx).map(|()| deferred.push((stx, env)))
                        }
                    }
                }
                None => Err("malformed or unauthenticated delegate tx (needs the stake pledge)".to_string()),
            }
        } else if tx.first() == Some(&UNDELEGATE_TAG) {
            match verify_undelegate(&tx[1..], chain_id) {
                Some((target, delegator, pk, nonce))
                    if s.node.delegation_of(&target, &delegator) > 0 && nonce == s.node.auth_nonce(&pk) =>
                {
                    Ok(())
                }
                Some(_) => Err("undelegate: no such delegation or nonce mismatch (replay?)".to_string()),
                None => Err("malformed or unauthenticated undelegate tx".to_string()),
            }
        } else if tx.first() == Some(&SENTINEL_DISABLE_TAG) {
            match verify_sentinel_disable(&tx[1..], chain_id) {
                Some((pk, nonce))
                    if s.node.sentinel_info().map(|(k, _)| k == pk).unwrap_or(false)
                        && nonce == s.node.auth_nonce(&pk) =>
                {
                    Ok(())
                }
                Some(_) => Err("sentinel-disable: not current sentinel key or nonce mismatch (replay?)".to_string()),
                None => Err("malformed or unauthenticated sentinel-disable tx".to_string()),
            }
        } else if tx.first() == Some(&CLAIM_TAG) {
            match parse_claim(&tx[1..]) {
                Some((pk, amount)) => {
                    let bal = s.node.claimable(&pk);
                    // Full-balance claims only (consensus C2: partial claims shred balances),
                    // and never below the 1 ZCRYPT floor (a forced claim per epoch would
                    // otherwise still dust a small staker).
                    if bal < zcrypt_core::emission::MIN_CLAIM {
                        Err(format!("claimable {bal} is below the 1 ZCRYPT claim minimum (rewards keep accruing)"))
                    } else if amount == 0 || amount != bal {
                        Err(format!("claim {amount} must equal the full claimable balance {bal}"))
                    } else {
                        Ok(())
                    }
                }
                None => Err("malformed claim tx".to_string()),
            }
        } else if tx.first() == Some(&CLAIM_FEE_TAG) {
            match parse_claim_fee(&tx[1..]) {
                Some((pk, asset, amount)) => {
                    let bal = s.node.claimable_fee(&pk, asset);
                    if !zcrypt_core::asset_registry::asset_id_ok(asset) {
                        Err("asset id is not a canonical field element".to_string())
                    } else if amount == 0 || amount != bal {
                        Err(format!("fee claim {amount} must equal the full claimable balance {bal}"))
                    } else {
                        Ok(())
                    }
                }
                None => Err("malformed fee-claim tx".to_string()),
            }
        } else if tx.first() == Some(&REGISTER_TAG) {
            match parse_gas_prefix(&tx[1..]) {
                None => Err("malformed register tx (needs a ZCRYPT gas note prefix)".to_string()),
                Some((gas_blind, gas_tx, rest)) => match parse_register(rest) {
                    Some((ticker, _, _, _, _)) if s.node.asset_id_of(&ticker).is_some() => {
                        Err(format!("ticker '{ticker}' is already registered"))
                    }
                    Some((_, _, _, max_supply, _)) if max_supply == 0 => {
                        Err("asset must declare a non-zero max supply".to_string())
                    }
                    Some((ticker, _, _, _, reserve_pk))
                        if zcrypt_core::asset_registry::valid_ticker(&ticker) =>
                    {
                        zbtc_requires_spv(&ticker, reserve_pk.is_some())
                            .and_then(|()| s.node.precheck_gas_note(&gas_tx, gas_blind))
                            .map(|()| deferred.push((gas_tx, Vec::new())))
                    }
                    Some((ticker, _, _, _, _)) => Err(format!("invalid ticker '{ticker}'")),
                    None => Err("malformed register tx".to_string()),
                },
            }
        } else if tx.first() == Some(&HTLC_OPEN_TAG) {
            match parse_gas_prefix(&tx[1..]) {
                None => Err("malformed htlc-open tx (needs a ZCRYPT gas note prefix)".to_string()),
                Some((gas_blind, gas_tx, rest)) => match parse_htlc_open(rest) {
                    Some((asset, value, lock, timeout, claim_pk, auth)) => {
                        let Some((keyset, sigs)) = zcrypt_core::mint_auth::decode_auth(&auth) else {
                            return (Err("malformed htlc-open auth".into()), deferred);
                        };
                        let msg = zcrypt_core::mint_auth::mint_message(chain_id, asset, value, &lock, timeout, &claim_pk);
                        if !zcrypt_core::asset_registry::asset_id_ok(asset) {
                            Err("asset id is not a canonical field element".to_string())
                        } else if !zcrypt_core::mint_auth::verify_threshold(&keyset, &msg, &sigs) {
                            Err("htlc-open: mint authorization invalid".to_string())
                        } else if s.node.asset_meta(asset).and_then(|m| m.authority) != Some(keyset.commitment()) {
                            Err("htlc-open: keyset does not match asset authority".to_string())
                        } else {
                            s.node
                                .precheck_gas_note(&gas_tx, gas_blind)
                                .map(|()| deferred.push((gas_tx, Vec::new())))
                        }
                    }
                    None => Err("malformed htlc-open tx".to_string()),
                },
            }
        } else if tx.first() == Some(&ROTATE_AUTH_TAG) {
            match parse_rotate(&tx[1..]) {
                Some((asset, new_auth, auth)) => {
                    let Some((keyset, sigs)) = zcrypt_core::mint_auth::decode_auth(&auth) else {
                        return (Err("malformed rotate auth".into()), deferred);
                    };
                    let epoch = s.node.authority_epoch(asset);
                    let msg = zcrypt_core::mint_auth::rotate_message(chain_id, asset, epoch, &new_auth);
                    if !zcrypt_core::mint_auth::verify_threshold(&keyset, &msg, &sigs) {
                        Err("rotate-auth: authorization invalid".to_string())
                    } else if s.node.asset_meta(asset).and_then(|m| m.authority) != Some(keyset.commitment()) {
                        Err("rotate-auth: keyset does not match current authority".to_string())
                    } else {
                        Ok(())
                    }
                }
                None => Err("malformed rotate-authority tx".to_string()),
            }
        } else if tx.first() == Some(&ROTATE_RESERVE_TAG) {
            match parse_rotate_reserve(&tx[1..]) {
                Some((asset, old_pk, new_pk, sig)) => {
                    s.node.verify_rotate_spv_reserve(chain_id, asset, &old_pk, &new_pk, &sig)
                }
                None => Err("malformed rotate-reserve tx".to_string()),
            }
        } else if tx.first() == Some(&BTC_HEADERS_TAG) {
            // Borrow-only pre-check (size cap + parse + first-parent-known). Full PoW/linkage
            // validation runs authoritatively at deliver. Avoids cloning the whole header
            // chain under the consensus lock on every (cheap, spammable) 0x63 tx.
            s.node.spv().precheck_headers(&tx[1..])
        } else if tx.first() == Some(&HTLC_OPEN_SPV_TAG) {
            match parse_htlc_open_spv(&tx[1..]) {
                Some((asset, value, lock, timeout, claim_pk, open_auth, proof)) => {
                    // Same reserve history (current + retired keys) and tip-freshness rule as
                    // delivery, so admission and block execution agree.
                    let reserve = s.node.asset_meta(asset).and_then(|m| m.reserve_auth());
                    match reserve {
                        Some(reserve) => s
                            .node
                            .spv()
                            .verify_mint_proof_with(&reserve, value, &lock, &proof)
                            .and_then(|(outpoint, _)| {
                                // The depositor's authorization over EVERY open parameter is
                                // checked at admission too, so a front-run never reaches a block.
                                let a = zcrypt_core::spv::OpenAuth {
                                    chain_id,
                                    outpoint: &outpoint,
                                    claim_pk: &claim_pk,
                                    asset_id: asset,
                                    value,
                                    hashlock: &lock,
                                    timeout_height: timeout,
                                };
                                zcrypt_core::spv::verify_open_auth(&proof.refund_pk, &a, &open_auth)
                            })
                            .and_then(|()| s.node.btc_tip_fresh("SPV mint open")),
                        None => Err("asset not registered / no mint authority".to_string()),
                    }
                }
                None => Err("malformed SPV htlc-open tx".to_string()),
            }
        } else if tx.first() == Some(&BTC_REANCHOR_TAG) {
            match zcrypt_core::spv::MintProof::from_bytes(&tx[1..]) {
                // CheckTx mirrors DeliverTx: an immature mint for this deposit must exist, or
                // 12 MB re-anchor payloads for nonexistent deposits fill blocks for free (M2).
                Some(proof) => match proof.funding_txid() {
                    Some(txid) if s.node.has_immature_deposit(&txid, proof.vout) => Ok(()),
                    Some(_) => Err("re-anchor: no immature mint for this deposit outpoint".to_string()),
                    None => Err("re-anchor: bad funding tx".to_string()),
                },
                None => Err("malformed BTC re-anchor tx".to_string()),
            }
        } else if tx.first() == Some(&HTLC_CLAIM_TAG) {
            match parse_escrow_id(&tx[1..]) {
                Some(id) if tx.len() > 33 => {
                    let preimage = &tx[33..];
                    match s.node.htlc_escrow(&id) {
                        Some(e) if e.state == zcrypt_core::htlc_shield::EscrowState::Open => {
                            if s.node.height() >= e.timeout_height {
                                Err("escrow has timed out: expire/refund only".to_string())
                            } else if preimage.len() != zcrypt_core::htlc_shield::HTLC_PREIMAGE_LEN {
                                Err("preimage must be exactly 32 bytes".to_string())
                            } else if zcrypt_core::nullifier::htlc_hashlock(preimage) != e.hashlock {
                                Err("preimage does not match the hashlock".to_string())
                            } else if e.spv_deposit.is_some() {
                                // SPV mint claims need a fresh consensus Bitcoin tip (parity
                                // with `Node::htlc_claim`).
                                s.node.btc_tip_fresh("SPV mint claim")
                            } else {
                                Ok(())
                            }
                        }
                        Some(_) => Err("escrow is not open".to_string()),
                        None => Err("no such escrow".to_string()),
                    }
                }
                _ => Err("malformed htlc claim tx".to_string()),
            }
        } else if tx.first() == Some(&HTLC_EXPIRE_TAG) {
            match parse_escrow_id(&tx[1..]) {
                Some(id) => match s.node.htlc_escrow(&id) {
                    Some(e) if e.state == zcrypt_core::htlc_shield::EscrowState::Open => {
                        if s.node.height() < e.timeout_height {
                            Err("escrow has not yet timed out".to_string())
                        } else {
                            Ok(())
                        }
                    }
                    Some(_) => Err("escrow is not open".to_string()),
                    None => Err("no such escrow".to_string()),
                },
                None => Err("malformed htlc expire tx".to_string()),
            }
        } else if tx.first() == Some(&HTLC_BURN_LOCK_TAG) {
            match parse_burn_lock(&tx[1..]) {
                Some((value, blind, asset, lock, timeout, refund, stx)) => {
                    if !s.node.asset_is_registered(asset) {
                        Err("asset not registered".to_string())
                    } else {
                        let expected = zcrypt_shield::commit_asset(
                            value, &blind, &zcrypt_core::htlc_shield::BURN_PK, asset,
                        );
                        if stx.output_commitments.first() != Some(&expected) {
                            Err("burn-lock: output[0] is not the declared burn coin".to_string())
                        } else {
                            // Reject a malleated envelope here, so a front-run never even
                            // reaches a block (the same binding runs again at execution).
                            let env = zcrypt_core::htlc_shield::lock_envelope(
                                zcrypt_core::htlc_shield::ENV_BURN_LOCK,
                                asset, value, &lock, timeout, &refund, &refund, &[],
                            );
                            // Mirror the delivery-time admission rules that would otherwise
                            // only fail AFTER the pledge is applied: value bound and escrow id.
                            zcrypt_core::node::lock_value_ok(value)
                                .and_then(|()| s.node.escrow_id_available(asset, value, &lock, timeout, &refund))
                                .and_then(|()| s.node.precheck_shield(&stx))
                                .map(|()| deferred.push((stx, env)))
                        }
                    }
                }
                None => Err("malformed htlc-burn-lock tx".to_string()),
            }
        } else if tx.first() == Some(&HTLC_BURN_LOCK_BTC_TAG) {
            if tx.len() < 1 + 33 {
                Err("malformed htlc-burn-lock-btc tx".to_string())
            } else {
                let btc_claim_pk = &tx[1..1 + 33];
                match parse_burn_lock(&tx[1 + 33..]) {
                    Some((value, blind, asset, lock, timeout, refund, stx)) => {
                        if !s.node.asset_is_registered(asset) {
                            Err("asset not registered".to_string())
                        } else {
                            let expected = zcrypt_shield::commit_asset(
                                value, &blind, &zcrypt_core::htlc_shield::BURN_PK, asset,
                            );
                            if stx.output_commitments.first() != Some(&expected) {
                                Err("burn-lock: output[0] is not the declared burn coin".to_string())
                            } else {
                                let env = zcrypt_core::htlc_shield::lock_envelope(
                                    zcrypt_core::htlc_shield::ENV_BURN_LOCK_BTC,
                                    asset, value, &lock, timeout, &refund, &refund, btc_claim_pk,
                                );
                                zcrypt_core::node::lock_value_ok(value)
                                    .and_then(|()| s.node.escrow_id_available(asset, value, &lock, timeout, &refund))
                                    .and_then(|()| s.node.precheck_shield(&stx))
                                    .map(|()| deferred.push((stx, env)))
                            }
                        }
                    }
                    None => Err("malformed htlc-burn-lock-btc tx".to_string()),
                }
            }
        } else if tx.first() == Some(&SWAP_LOCK_TAG) {
            match parse_swap_lock(&tx[1..]) {
                Some((value, blind, asset, lock, timeout, cp, refund, stx)) => {
                    if !s.node.asset_is_registered(asset) {
                        Err("asset not registered".to_string())
                    } else {
                        let expected = zcrypt_shield::commit_asset(
                            value, &blind, &zcrypt_core::htlc_shield::BURN_PK, asset,
                        );
                        if stx.output_commitments.first() != Some(&expected) {
                            Err("swap-lock: output[0] is not the declared burn coin".to_string())
                        } else {
                            let env = zcrypt_core::htlc_shield::lock_envelope(
                                zcrypt_core::htlc_shield::ENV_SWAP_LOCK,
                                asset, value, &lock, timeout, &cp, &refund, &[],
                            );
                            zcrypt_core::node::lock_value_ok(value)
                                .and_then(|()| s.node.escrow_id_available(asset, value, &lock, timeout, &cp))
                                .and_then(|()| s.node.precheck_shield(&stx))
                                .map(|()| deferred.push((stx, env)))
                        }
                    }
                }
                None => Err("malformed swap-lock tx".to_string()),
            }
        } else {
            Err(CLASSICAL_DISABLED.to_string()) // classical native path removed
        };
        (result, deferred)
    }

    fn finalize_block_impl(&self, req: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        let mut s = self.locked();
        let chain_id = s.chain_id.clone();
        let chain_id = chain_id.as_slice();
        let height = req.height.max(0) as u64;
        // Evaluate HTLC timeouts against this block's height.
        s.node.set_height(height);
        // BFT block time (unix seconds) — drives the validator unbonding period.
        let block_secs = req.time.as_ref().map(|t| t.seconds.max(0) as u64).unwrap_or(0);
        s.node.set_block_time(block_secs);
        // Credit consensus participation for the just-decided block, so this
        // epoch's block reward is split by who actually signed.
        let signers = signers_of(&req);
        s.node.record_block_signers(&signers);
        // Snapshot the bonded validator set BEFORE this block's txs (and before slashing),
        // so the diff below tells CometBFT exactly which block producers to add/remove —
        // including any validator ejected by a slash this block.
        let vset_before = s.node.validator_set();
        // The sentinel's key (if active) is excluded from the bonded-set diff for the whole
        // block; `sentinel_update` alone emits its power (also on retirement).
        let sentinel_key = s.node.sentinel_key();
        let mut header_bytes_used = 0usize;
        // SLASHING: punish validators CometBFT reported for provable equivocation
        // (double-signing / light-client attack). Deterministic — the evidence is part of
        // the block and the penalty is integer math, so every node slashes identically.
        for m in &req.misbehavior {
            if m.r#type == MisbehaviorType::DuplicateVote as i32
                || m.r#type == MisbehaviorType::LightClientAttack as i32
            {
                if let Some(v) = &m.validator {
                    let addr = v.address.to_vec();
                    let burned = s.node.slash(&addr);
                    if burned > 0 {
                        eprintln!(
                            "[slash] height {height}: validator {} slashed {burned} atomic + tombstoned (misbehavior type {})",
                            hex::encode(&addr),
                            m.r#type
                        );
                    }
                }
            }
        }
        let mut tx_results = Vec::with_capacity(req.txs.len());
        if !req.txs.is_empty() {
            eprintln!("[finalize]  height {height}: delivering {} tx(s)", req.txs.len());
        }
        for tx in &req.txs {
            let bytes = tx.as_ref();
            let outcome = if bytes.first() == Some(&SHIELD_TAG) {
                match parse_transfer(&bytes[1..]) {
                    Some((gas_blind, gas_tx, main_tx)) => {
                        s.node.submit_transfer(chain_id, &main_tx, &gas_tx, gas_blind)
                    }
                    None => Err("malformed transfer".to_string()),
                }
            } else if bytes.first() == Some(&SEED_TAG) {
                if !SEED_ENABLED {
                    Err("SEED tx (0x56) is disabled: unbacked coin injection is devnet-only".to_string())
                } else {
                    match parse_commitment(&bytes[1..]) {
                        Some(c) => {
                            s.node.seed_coin(c);
                            Ok(zcrypt_core::node::Receipt {
                                txbind: [0u8; 32],
                                nullifiers: vec![],
                            })
                        }
                        None => Err("bad seed".to_string()),
                    }
                }
            } else if bytes.first() == Some(&BOND_TAG) {
                match parse_bond_coin(&bytes[1..], chain_id) {
                    Some((addr, pubkey, stake, reward, commission, nonce, stake_blind, stx)) => {
                        // verify_bond guarantees a 32-byte key; auth_nonce is keyed on it.
                        let signer_pk: [u8; 32] = pubkey.as_slice().try_into().expect("32-byte bond pubkey");
                        let expected = s.node.auth_nonce(&signer_pk);
                        if nonce != expected {
                            Err(format!("bond nonce {nonce} != expected {expected} (replay?)"))
                        } else {
                            match s.node.bond_with_stake(
                                chain_id, &stx, stake, stake_blind, addr, pubkey, reward, commission, nonce,
                            ) {
                                Ok(()) => {
                                    // Advance the nonce so the exact BOND signature can never be replayed.
                                    s.node.bump_auth_nonce(&signer_pk);
                                    Ok(zcrypt_core::node::Receipt {
                                        txbind: [0u8; 32],
                                        nullifiers: vec![],
                                    })
                                }
                                Err(e) => Err(e),
                            }
                        }
                    }
                    None => Err("malformed bond tx".to_string()),
                }
            } else if bytes.first() == Some(&UNBOND_TAG) {
                match verify_unbond(&bytes[1..], chain_id) {
                    Some((addr, signer_pk, nonce)) => {
                        // Replay protection: the signed nonce must equal the stored one, then
                        // it advances — so the exact UNBOND signature can never be replayed.
                        let expected = s.node.auth_nonce(&signer_pk);
                        if nonce != expected {
                            Err(format!("unbond nonce {nonce} != expected {expected} (replay?)"))
                        } else {
                            match s.node.unbond(&addr) {
                                Ok(_released) => {
                                    s.node.bump_auth_nonce(&signer_pk);
                                    Ok(zcrypt_core::node::Receipt {
                                        txbind: [0u8; 32],
                                        nullifiers: vec![],
                                    })
                                }
                                Err(e) => Err(e),
                            }
                        }
                    }
                    None => Err("malformed unbond tx".to_string()),
                }
            } else if bytes.first() == Some(&DELEGATE_TAG) {
                match parse_delegate_coin(&bytes[1..], chain_id) {
                    Some((target, delegator, stake, reward, stake_blind, stx)) => {
                        match s.node.delegate_with_stake(
                            chain_id, &stx, stake, stake_blind, target, delegator, reward,
                        ) {
                            Ok(()) => Ok(zcrypt_core::node::Receipt {
                                txbind: [0u8; 32],
                                nullifiers: vec![],
                            }),
                            Err(e) => Err(e),
                        }
                    }
                    None => Err("malformed delegate tx".to_string()),
                }
            } else if bytes.first() == Some(&UNDELEGATE_TAG) {
                match verify_undelegate(&bytes[1..], chain_id) {
                    Some((target, delegator, signer_pk, nonce)) => {
                        let expected = s.node.auth_nonce(&signer_pk);
                        if nonce != expected {
                            Err(format!("undelegate nonce {nonce} != expected {expected} (replay?)"))
                        } else {
                            match s.node.undelegate(&target, &delegator) {
                                Ok(_release_time) => {
                                    s.node.bump_auth_nonce(&signer_pk);
                                    Ok(zcrypt_core::node::Receipt {
                                        txbind: [0u8; 32],
                                        nullifiers: vec![],
                                    })
                                }
                                Err(e) => Err(e),
                            }
                        }
                    }
                    None => Err("malformed undelegate tx".to_string()),
                }
            } else if bytes.first() == Some(&SENTINEL_DISABLE_TAG) {
                match verify_sentinel_disable(&bytes[1..], chain_id) {
                    Some((pk, nonce)) => {
                        let expected = s.node.auth_nonce(&pk);
                        if nonce != expected {
                            Err(format!("sentinel-disable nonce {nonce} != expected {expected} (replay?)"))
                        } else {
                            match s.node.disable_sentinel(&pk) {
                                Ok(()) => {
                                    s.node.bump_auth_nonce(&pk);
                                    Ok(zcrypt_core::node::Receipt {
                                        txbind: [0u8; 32],
                                        nullifiers: vec![],
                                    })
                                }
                                Err(e) => Err(e),
                            }
                        }
                    }
                    None => Err("malformed sentinel-disable tx".to_string()),
                }
            } else if bytes.first() == Some(&CLAIM_TAG) {
                match parse_claim(&bytes[1..]) {
                    Some((pk, amount)) => match s.node.claim_rewards(&pk, amount) {
                        Ok(coins) => {
                            // Report the minted coinbase commitments so the
                            // claimer can find their new coins' tree indices.
                            let data = serde_json::json!({
                                "claimed": amount,
                                "coins": coins.iter().map(|c| {
                                    let mut b = Vec::new();
                                    for x in c { b.extend_from_slice(&x.to_le_bytes()); }
                                    hex::encode(b)
                                }).collect::<Vec<_>>(),
                            })
                            .to_string();
                            tx_results.push(ExecTxResult {
                                code: OK,
                                data: data.into_bytes().into(),
                                ..Default::default()
                            });
                            continue;
                        }
                        Err(e) => Err(e),
                    },
                    None => Err("malformed claim tx".to_string()),
                }
            } else if bytes.first() == Some(&CLAIM_FEE_TAG) {
                match parse_claim_fee(&bytes[1..]) {
                    Some((pk, asset, amount)) => match s.node.claim_fee_rewards(&pk, asset, amount) {
                        Ok(coins) => {
                            let data = serde_json::json!({
                                "claimed_fee": amount,
                                "asset_id": asset.to_string(),
                                "coins": coins.iter().map(|c| {
                                    let mut b = Vec::new();
                                    for x in c { b.extend_from_slice(&x.to_le_bytes()); }
                                    hex::encode(b)
                                }).collect::<Vec<_>>(),
                            })
                            .to_string();
                            tx_results.push(ExecTxResult {
                                code: OK,
                                data: data.into_bytes().into(),
                                ..Default::default()
                            });
                            continue;
                        }
                        Err(e) => Err(e),
                    },
                    None => Err("malformed fee-claim tx".to_string()),
                }
            } else if bytes.first() == Some(&REGISTER_TAG) {
                match parse_gas_prefix(&bytes[1..]) {
                    None => Err("malformed register tx (needs a ZCRYPT gas note prefix)".to_string()),
                    Some((gas_blind, gas_tx, rest)) => match parse_register(rest) {
                        Some((ticker, decimals, authority, max_supply, reserve_pk)) => {
                            // Gas is burned FIRST (a rejected registration still pays), then
                            // the registration is applied.
                            match zbtc_requires_spv(&ticker, reserve_pk.is_some())
                                .and_then(|()| s.node.submit_gas_note(chain_id, &gas_tx, gas_blind))
                                .and_then(|_| {
                                    match reserve_pk {
                                        Some(pk) => s.node.register_spv_asset(&ticker, decimals, &pk, max_supply),
                                        None => s.node.register_asset(&ticker, decimals, authority, max_supply),
                                    }
                                    .map_err(|e| format!("{e} (gas consumed)"))
                                }) {
                                Ok(id) => {
                                    let data = serde_json::json!({
                                        "ticker": ticker,
                                        "asset_id": id,
                                    })
                                    .to_string();
                                    tx_results.push(ExecTxResult {
                                        code: OK,
                                        data: data.into_bytes().into(),
                                        ..Default::default()
                                    });
                                    continue;
                                }
                                Err(e) => Err(e),
                            }
                        }
                        None => Err("malformed register tx".to_string()),
                    },
                }
            } else if bytes.first() == Some(&HTLC_OPEN_TAG) {
                match parse_gas_prefix(&bytes[1..]) {
                    None => Err("malformed htlc-open tx (needs a ZCRYPT gas note prefix)".to_string()),
                    Some((gas_blind, gas_tx, rest)) => match parse_htlc_open(rest)
                        .and_then(|(asset, value, lock, timeout, pk, auth)| {
                            // The trailing bytes are the M-of-N mint authorization (key set +
                            // threshold ML-DSA signatures); decode before gating the mint.
                            zcrypt_core::mint_auth::decode_auth(&auth)
                                .map(|(ks, sigs)| (asset, value, lock, timeout, pk, ks, sigs))
                        }) {
                        Some((asset, value, lock, timeout, pk, keyset, sigs)) => {
                            match s.node.submit_gas_note(chain_id, &gas_tx, gas_blind).and_then(|_| {
                                s.node
                                    .htlc_open(chain_id, asset, value, lock, timeout, pk, &keyset, &sigs)
                                    .map_err(|e| format!("{e} (gas consumed)"))
                            }) {
                                Ok(id) => {
                                    let data =
                                        serde_json::json!({ "escrow_id": hex::encode(id) }).to_string();
                                    tx_results.push(ExecTxResult {
                                        code: OK,
                                        data: data.into_bytes().into(),
                                        ..Default::default()
                                    });
                                    continue;
                                }
                                Err(e) => Err(e),
                            }
                        }
                        None => Err("malformed htlc-open tx".to_string()),
                    },
                }
            } else if bytes.first() == Some(&ROTATE_RESERVE_TAG) {
                match parse_rotate_reserve(&bytes[1..]) {
                    Some((asset, old_pk, new_pk, sig)) => {
                        match s.node.rotate_spv_reserve(chain_id, asset, &old_pk, &new_pk, &sig) {
                            Ok(epoch) => {
                                let data = serde_json::json!({
                                    "asset_id": asset.to_string(),
                                    "new_reserve_pk": hex::encode(new_pk),
                                    "retired_reserve_pk": hex::encode(old_pk),
                                    "epoch": epoch,
                                })
                                .to_string();
                                tx_results.push(ExecTxResult {
                                    code: OK,
                                    data: data.into_bytes().into(),
                                    ..Default::default()
                                });
                                continue;
                            }
                            Err(e) => Err(e),
                        }
                    }
                    None => Err("malformed rotate-reserve tx".to_string()),
                }
            } else if bytes.first() == Some(&ROTATE_AUTH_TAG) {
                match parse_rotate(&bytes[1..]).and_then(|(asset, new_commitment, auth)| {
                    zcrypt_core::mint_auth::decode_auth(&auth)
                        .map(|(ks, sigs)| (asset, new_commitment, ks, sigs))
                }) {
                    Some((asset, new_commitment, keyset, sigs)) => {
                        match s.node.rotate_authority(chain_id, asset, new_commitment, &keyset, &sigs) {
                            Ok(()) => {
                                let data = serde_json::json!({
                                    "asset_id": asset.to_string(),
                                    "new_authority": hex::encode(new_commitment),
                                    "epoch": s.node.authority_epoch(asset),
                                })
                                .to_string();
                                tx_results.push(ExecTxResult {
                                    code: OK,
                                    data: data.into_bytes().into(),
                                    ..Default::default()
                                });
                                continue;
                            }
                            Err(e) => Err(e),
                        }
                    }
                    None => Err("malformed rotate-authority tx".to_string()),
                }
            } else if bytes.first() == Some(&HTLC_BURN_LOCK_TAG) {
                match parse_burn_lock(&bytes[1..]) {
                    Some((value, blind, asset, lock, timeout, refund_pk, stx)) => {
                        match s.node.htlc_burn_lock(
                            chain_id, &stx, value, blind, asset, lock, timeout, refund_pk, &[],
                        ) {
                            Ok(id) => {
                                let data =
                                    serde_json::json!({ "escrow_id": hex::encode(id) }).to_string();
                                tx_results.push(ExecTxResult {
                                    code: OK,
                                    data: data.into_bytes().into(),
                                    ..Default::default()
                                });
                                continue;
                            }
                            Err(e) => Err(e),
                        }
                    }
                    None => Err("malformed htlc-burn-lock tx".to_string()),
                }
            } else if bytes.first() == Some(&HTLC_BURN_LOCK_BTC_TAG) {
                // Same escrow as 0x5D, plus the leading 33-byte btc_claim_pk the operator's
                // redeem watcher pays out to. That key is NOT opaque: it is bound into the
                // shield proof along with the rest of the lock envelope, so only the owner of
                // the burned zBTC can name the Bitcoin address the reserve pays.
                if bytes.len() < 1 + 33 {
                    Err("htlc-burn-lock-btc: missing btc_claim_pk".to_string())
                } else {
                    let btc_claim_pk = bytes[1..1 + 33].to_vec();
                    match parse_burn_lock(&bytes[1 + 33..]) {
                        Some((value, blind, asset, lock, timeout, refund_pk, stx)) => {
                            match s.node.htlc_burn_lock(
                                chain_id, &stx, value, blind, asset, lock, timeout, refund_pk,
                                &btc_claim_pk,
                            ) {
                                Ok(id) => {
                                    let data =
                                        serde_json::json!({ "escrow_id": hex::encode(id) }).to_string();
                                    tx_results.push(ExecTxResult {
                                        code: OK,
                                        data: data.into_bytes().into(),
                                        ..Default::default()
                                    });
                                    continue;
                                }
                                Err(e) => Err(e),
                            }
                        }
                        None => Err("malformed htlc-burn-lock-btc tx".to_string()),
                    }
                }
            } else if bytes.first() == Some(&SWAP_LOCK_TAG) {
                match parse_swap_lock(&bytes[1..]) {
                    Some((value, blind, asset, lock, timeout, counterparty_pk, refund_pk, stx)) => {
                        match s.node.swap_lock(
                            chain_id, &stx, value, blind, asset, lock, timeout, counterparty_pk, refund_pk,
                        ) {
                            Ok(id) => {
                                let data =
                                    serde_json::json!({ "escrow_id": hex::encode(id) }).to_string();
                                tx_results.push(ExecTxResult {
                                    code: OK,
                                    data: data.into_bytes().into(),
                                    ..Default::default()
                                });
                                continue;
                            }
                            Err(e) => Err(e),
                        }
                    }
                    None => Err("malformed swap-lock tx".to_string()),
                }
            } else if bytes.first() == Some(&BTC_HEADERS_TAG) {
                // The per-block budget is charged only for batches consensus ACCEPTS. Charging
                // up front let rejected junk batches (which CheckTx now also refuses, see
                // `precheck_headers`) eat the whole budget and starve honest relay for free.
                let relay = if header_budget_ok(header_bytes_used, bytes.len() - 1) {
                    let r = s.node.submit_btc_headers(&bytes[1..]);
                    if r.is_ok() {
                        header_bytes_used += bytes.len() - 1;
                    }
                    r
                } else {
                    Err(format!("header relay exceeds the {MAX_HEADER_BYTES_PER_BLOCK}-byte per-block budget"))
                };
                match relay {
                    Ok((accepted, tip)) => {
                        let data = serde_json::json!({ "accepted": accepted, "btc_tip": tip })
                            .to_string();
                        tx_results.push(ExecTxResult {
                            code: OK,
                            data: data.into_bytes().into(),
                            ..Default::default()
                        });
                        continue;
                    }
                    Err(e) => Err(e),
                }
            } else if bytes.first() == Some(&HTLC_OPEN_SPV_TAG) {
                match parse_htlc_open_spv(&bytes[1..]) {
                    Some((asset, value, lock, timeout, pk, open_auth, proof)) => {
                        match s.node.htlc_open_spv(chain_id, asset, value, lock, timeout, pk, &proof, &open_auth) {
                            Ok(id) => {
                                let data =
                                    serde_json::json!({ "escrow_id": hex::encode(id) }).to_string();
                                tx_results.push(ExecTxResult {
                                    code: OK,
                                    data: data.into_bytes().into(),
                                    ..Default::default()
                                });
                                continue;
                            }
                            Err(e) => Err(e),
                        }
                    }
                    None => Err("malformed SPV htlc-open tx".to_string()),
                }
            } else if bytes.first() == Some(&BTC_REANCHOR_TAG) {
                match zcrypt_core::spv::MintProof::from_bytes(&bytes[1..]) {
                    Some(proof) => match s.node.reanchor_deposit(&proof) {
                        Ok(txid) => {
                            let data = serde_json::json!({ "reanchored_txid": hex::encode(txid) })
                                .to_string();
                            tx_results.push(ExecTxResult {
                                code: OK,
                                data: data.into_bytes().into(),
                                ..Default::default()
                            });
                            continue;
                        }
                        Err(e) => Err(e),
                    },
                    None => Err("malformed BTC re-anchor tx".to_string()),
                }
            } else if bytes.first() == Some(&HTLC_CLAIM_TAG) {
                match parse_escrow_id(&bytes[1..]) {
                    Some(id) => match s.node.htlc_claim(&id, &bytes[33..]) {
                        Ok(coin) => {
                            // Some(commitment) for a mint escrow; None for a burn.
                            let coin_hex = coin.map(|c| {
                                let mut cb = Vec::new();
                                for x in &c {
                                    cb.extend_from_slice(&x.to_le_bytes());
                                }
                                hex::encode(cb)
                            });
                            let data = serde_json::json!({ "coin": coin_hex }).to_string();
                            tx_results.push(ExecTxResult {
                                code: OK,
                                data: data.into_bytes().into(),
                                ..Default::default()
                            });
                            continue;
                        }
                        Err(e) => Err(e),
                    },
                    None => Err("malformed htlc-claim tx".to_string()),
                }
            } else if bytes.first() == Some(&HTLC_EXPIRE_TAG) {
                match parse_escrow_id(&bytes[1..]) {
                    Some(id) => match s.node.htlc_expire(&id) {
                        Ok(refund) => {
                            let coin_hex = refund.map(|c| {
                                let mut cb = Vec::new();
                                for x in &c {
                                    cb.extend_from_slice(&x.to_le_bytes());
                                }
                                hex::encode(cb)
                            });
                            let data =
                                serde_json::json!({ "refund_coin": coin_hex }).to_string();
                            tx_results.push(ExecTxResult {
                                code: OK,
                                data: data.into_bytes().into(),
                                ..Default::default()
                            });
                            continue;
                        }
                        Err(e) => Err(e),
                    },
                    None => Err("malformed htlc-expire tx".to_string()),
                }
            } else {
                Err(CLASSICAL_DISABLED.to_string()) // classical native path removed
            };
            match outcome {
                Ok(receipt) => {
                    // No per-tx state root: it cost a full recomputation of every component
                    // root per transaction, and consensus only uses the block's app hash
                    // (returned below, and queryable at `/app/hash`).
                    let data = serde_json::json!({
                        "txbind": hex::encode(receipt.txbind),
                        "nullifiers": receipt.nullifiers.iter().map(hex::encode).collect::<Vec<_>>(),
                    })
                    .to_string();
                    tx_results.push(ExecTxResult {
                        code: OK,
                        data: data.into_bytes().into(),
                        ..Default::default()
                    });
                }
                Err(e) => tx_results.push(ExecTxResult {
                    code: ERR,
                    log: e,
                    ..Default::default()
                }),
            }
        }
        if !req.txs.is_empty() {
            let committed = tx_results.iter().filter(|r| r.code == OK).count();
            for r in tx_results.iter().filter(|r| r.code != OK) {
                eprintln!("[finalize]  height {height}: tx REJECTED: {}", r.log);
            }
            eprintln!("[finalize]  height {height}: {committed}/{} tx committed", req.txs.len());
        }
        // Process SPV-mint maturity against the Bitcoin header chain: mature deposits
        // deep enough to be reorg-safe (their zBTC becomes spendable), and VOID any
        // whose deposit block was orphaned by a Bitcoin reorg (burn the supply back).
        // Deterministic (a pure function of the app-hash-committed SPV state).
        let mat = s.node.process_btc_maturity();
        if !mat.matured.is_empty() {
            eprintln!("[spv-maturity] height {height}: {} mint(s) matured → spendable", mat.matured.len());
        }
        if !mat.voided.is_empty() {
            eprintln!(
                "[spv-REORG] height {height}: VOIDED {} unbacked mint(s) worth {} base units \
                 (deposit orphaned off the best Bitcoin chain)",
                mat.voided.len(),
                mat.voided_value
            );
        }
        // Release any validator stakes whose 10-day unbonding lock has expired at this
        // block's time. Deterministic (BFT time + committed queue) ⇒ folded into app_hash.
        let released = s.node.release_matured_unbonding();
        if released > 0 {
            eprintln!("[unbonding] height {height}: released {released} atomic stake from the queue");
        }
        // At each epoch boundary, mint + distribute the block reward by
        // stake × participation. Deterministic ⇒ folded into app_hash below.
        let minted = s.node.maybe_distribute_rewards(height);
        if minted > 0 {
            eprintln!(
                "[epoch {}] distributed {} atomic block reward; total issued {}",
                height,
                minted,
                s.node.total_issued()
            );
        }
        // Block-boundary anchor root + escrow pruning (deterministic housekeeping).
        s.node.end_block();
        s.height = req.height;
        // Dynamic validator set: diff the bonded set across this block and hand
        // CometBFT the resulting add/remove/re-weight updates, so a BOND actually
        // makes a node a block producer and an UNBOND stops it. Deterministic (a pure
        // function of the app-hash-committed staking ledger), so all nodes agree. The
        // sentinel key is excluded: its power is emitted only by `sentinel_update`.
        let vset_after = s.node.validator_set();
        let mut updates = validator_updates_excluding(&vset_before, &vset_after, sentinel_key.as_deref());
        // Keep the foundation sentinel above 2/3 of the total whenever the bonded set's
        // power changed this block, so the chain can never be halted by validators leaving.
        if let Some((key, power)) = s.node.sentinel_update() {
            updates.push(ValidatorUpdate {
                pub_key: Some(PublicKey { sum: Some(PubKeySum::Ed25519(key)) }),
                power,
            });
        }
        if !updates.is_empty() {
            for u in &updates {
                let pk = u.pub_key.as_ref().and_then(|k| match &k.sum {
                    Some(PubKeySum::Ed25519(b)) => Some(hex::encode(b)),
                    _ => None,
                }).unwrap_or_default();
                eprintln!("[validators] height {height}: set {pk} -> power {}", u.power);
            }
        }
        s.app_hash = s.node.state_root();
        ResponseFinalizeBlock {
            tx_results,
            validator_updates: updates,
            app_hash: s.app_hash.to_vec().into(),
            ..Default::default()
        }
    }

    fn commit_impl(&self) -> ResponseCommit {
        // Persist consensus state at the just-finalized height via RocksDB
        // (incremental commitment leaves + nullifier keys, synced WriteBatch).
        // The snapshot reflects exactly the state whose `state_root()` was returned
        // as this block's app_hash, so on restart `info()` matches and CometBFT
        // resumes from here instead of replaying the whole chain from genesis.
        let mut s = self.locked();
        let height = s.height.max(0) as u64;
        let commit_result = {
            let mut store = self.store_locked();
            let State { node, chain_id, .. } = &mut *s;
            store.commit(node, height, chain_id)
        };
        match commit_result {
            Ok(stats) => {
                eprintln!(
                    "[state-db] commit height={} new_c={} new_nf={} total_c={} total_nf={} puts={} {}ms",
                    stats.height,
                    stats.new_commitments,
                    stats.new_nullifiers,
                    stats.total_commitments,
                    stats.total_nullifiers,
                    stats.batch_puts,
                    stats.elapsed_ms
                );
                // Phase 2: keep a legacy-compatible postcard backup for disaster recovery
                // / offline inspection, written PERIODICALLY (it serializes the whole
                // state). Failure here is non-fatal if the DB write succeeded.
                if self.backup_every > 0 && height % self.backup_every == 0 {
                    if let Err(e) = StateDb::write_backup_file(&self.backup_path, &s.node, height) {
                        eprintln!(
                            "[state-db] WARNING: postcard backup {} failed ({e})",
                            self.backup_path.display()
                        );
                    }
                }
            }
            Err(e) => {
                if self.strict {
                    // Fail closed: abort the process so CometBFT restarts and replays
                    // from the last durable height rather than acknowledging Commit
                    // without durable state.
                    panic!(
                        "[state-db] FATAL: persist failed at height {height} ({e}); \
                         refusing to acknowledge Commit (set ZCRYPT_STATE_STRICT=0 to log-only)"
                    );
                }
                eprintln!(
                    "[state-db] WARNING: failed to persist state at height {height} ({e}); \
                     will retry on the next commit (replays this block if the node restarts first)"
                );
            }
        }
        ResponseCommit { retain_height: 0 }
    }

    fn query_impl(&self, req: RequestQuery) -> ResponseQuery {
        let s = self.locked();
        let value: Vec<u8> = match req.path.as_str() {
            "/chain_id" => s.chain_id.clone(),
            "/registry/root" => hex::encode(s.node.registry_root()).into_bytes(),
            "/commit/root" => {
                let r = s.node.commitment_root();
                let mut b = Vec::new();
                for x in &r {
                    b.extend_from_slice(&x.to_le_bytes());
                }
                hex::encode(b).into_bytes()
            }
            "/commit/count" => s.node.commitment_count().to_string().into_bytes(),
            // Leaves are PAGED: `/commit/leaves` is page 0 and `/commit/leaves/<from>` the
            // page starting at `from`; each page holds at most LEAF_PAGE leaves (64 bytes,
            // 8×u64 LE each, concatenated, hex). Clients keep paging until a page comes
            // back shorter than LEAF_PAGE. The wallet's decoy pool + a way to find its own
            // coin's index.
            "/commit/leaves" => {
                let mut b = Vec::new();
                for c in s.node.commitment_leaves_range(0, LEAF_PAGE) {
                    for x in &c {
                        b.extend_from_slice(&x.to_le_bytes());
                    }
                }
                hex::encode(b).into_bytes()
            }
            "/commit/leaf_page" => LEAF_PAGE.to_string().into_bytes(),
            p if p.starts_with("/commit/leaves/") => {
                let from: usize = p["/commit/leaves/".len()..].parse().unwrap_or(0);
                let mut b = Vec::new();
                for c in s.node.commitment_leaves_range(from, LEAF_PAGE) {
                    for x in &c {
                        b.extend_from_slice(&x.to_le_bytes());
                    }
                }
                hex::encode(b).into_bytes()
            }
            "/app/hash" => hex::encode(s.app_hash).into_bytes(),
            // ---- Bitcoin SPV chain (the trustless zBTC mint gate) ----
            "/spv/height" => s.node.btc_tip().0.to_string().into_bytes(),
            "/spv/tip" => {
                let (h, hash) = s.node.btc_tip();
                // Display hash big-endian like every Bitcoin explorer.
                let mut be = hash;
                be.reverse();
                format!("{h}:{}", hex::encode(be)).into_bytes()
            }
            "/spv/claimed" => s.node.spv().claimed_count().to_string().into_bytes(),
            // A staker's claimable bridge-fee yield: "/staking/fees/<pk_hex>/<asset_id>".
            p if p.starts_with("/staking/fees/") => {
                let rest = &p["/staking/fees/".len()..];
                match rest.split_once('/') {
                    Some((pk_hex, asset_str)) => {
                        match (
                            hex::decode(pk_hex).ok().and_then(|b| parse_pubkey(&b)),
                            asset_str.parse::<u64>().ok(),
                        ) {
                            (Some(pk), Some(asset)) => {
                                s.node.claimable_fee(&pk, asset).to_string().into_bytes()
                            }
                            _ => {
                                return ResponseQuery {
                                    code: ERR,
                                    log: "bad /staking/fees/<pk_hex>/<asset_id>".into(),
                                    ..Default::default()
                                }
                            }
                        }
                    }
                    None => {
                        return ResponseQuery {
                            code: ERR,
                            log: "usage: /staking/fees/<pk_hex>/<asset_id>".into(),
                            ..Default::default()
                        }
                    }
                }
            }
            // Immature SPV mints: minted but not yet spendable (still maturing / still
            // reorg-voidable). "<count>:<total_base_units>".
            "/spv/pending" => {
                format!("{}:{}", s.node.immature_count(), s.node.immature_value()).into_bytes()
            }
            // Net-coin commitments of every immature SPV mint, same wire format as
            // `/commit/leaves` (64 bytes = 8×u64 LE each, concatenated, hex). A wallet
            // uses this to protect a maturing zBTC coin from its stale-coin reconcile
            // (the coin is not in the tree yet but IS pending here), and to drop it only
            // once a reorg voids it (it leaves this set without ever becoming a leaf).
            "/spv/pending_coins" => {
                let mut b = Vec::new();
                for c in s.node.immature_commitments() {
                    for x in &c {
                        b.extend_from_slice(&x.to_le_bytes());
                    }
                }
                hex::encode(b).into_bytes()
            }
            // ---- shielded-asset ticker registry ----
            "/asset/list" => {
                // "<ticker>:<asset_id>:<minted>:<decimals> …" (decimals let a client
                // render the minted supply in whole units, e.g. 8-dp zBTC).
                let list: Vec<String> = s
                    .node
                    .assets_list()
                    .iter()
                    .map(|m| format!("{}:{}:{}:{}", m.ticker, m.asset_id, m.minted, m.decimals))
                    .collect();
                list.join(",").into_bytes()
            }
            p if p.starts_with("/asset/by_ticker/") => {
                let t = &p["/asset/by_ticker/".len()..];
                match s.node.asset_id_of(t) {
                    Some(id) => id.to_string().into_bytes(),
                    None => {
                        return ResponseQuery {
                            code: ERR,
                            log: format!("ticker '{t}' not registered"),
                            ..Default::default()
                        }
                    }
                }
            }
            p if p.starts_with("/htlc/") => {
                let id_hex = &p["/htlc/".len()..];
                match hex::decode(id_hex).ok().filter(|b| b.len() == 32) {
                    Some(b) => {
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&b);
                        match s.node.htlc_escrow(&id) {
                            Some(e) => serde_json::json!({
                                "asset_id": e.asset_id,
                                "value": e.value,
                                "hashlock": hex::encode(e.hashlock),
                                "timeout_height": e.timeout_height,
                                "state": match e.state {
                                    zcrypt_core::htlc_shield::EscrowState::Open => "open",
                                    zcrypt_core::htlc_shield::EscrowState::Claimed => "claimed",
                                    zcrypt_core::htlc_shield::EscrowState::Expired => "expired",
                                },
                                "kind": match e.kind {
                                    zcrypt_core::htlc_shield::EscrowKind::Mint => "mint",
                                    zcrypt_core::htlc_shield::EscrowKind::Burn => "burn",
                                    zcrypt_core::htlc_shield::EscrowKind::Swap => "swap",
                                },
                                "party_pk": hex::encode(pubkey_bytes(&e.party_pk)),
                                "refund_pk": hex::encode(pubkey_bytes(&e.refund_pk)),
                                // Consensus-committed payout key for burn-for-BTC escrows (empty
                                // otherwise). The watcher MUST read it from here, never from raw
                                // block txs: a failed duplicate lock in the same block can carry a
                                // different key and would otherwise get its own funded HTLC.
                                "btc_claim_pk": hex::encode(&e.btc_claim_pk),
                            })
                            .to_string()
                            .into_bytes(),
                            None => {
                                return ResponseQuery {
                                    code: ERR,
                                    log: "no such escrow".into(),
                                    ..Default::default()
                                }
                            }
                        }
                    }
                    None => {
                        return ResponseQuery {
                            code: ERR,
                            log: "bad escrow id hex (want 32 bytes)".into(),
                            ..Default::default()
                        }
                    }
                }
            }
            p if p.starts_with("/asset/id/") => {
                let id = p["/asset/id/".len()..].parse::<u64>().ok();
                match id.and_then(|i| s.node.asset_meta(i)) {
                    Some(m) => serde_json::json!({
                        "ticker": m.ticker,
                        "asset_id": m.asset_id,
                        "decimals": m.decimals,
                        "minted": m.minted,
                        // Mint authority = H(capability), or null for protocol-only mint.
                        // One-way, so publishing it reveals no secret; the minter's
                        // wallet re-derives its capability to prove ownership.
                        "authority": m.authority.map(hex::encode),
                        "authority_epoch": m.authority_epoch,
                        // SPV assets: the CURRENT Bitcoin reserve pubkey deposits must pay
                        // (wallets fetch this instead of assuming a fixed key), plus keys
                        // retired by rotation and the BTC height each was retired at.
                        "reserve_pk": m.reserve_pk33().map(hex::encode),
                        "retired_reserves": m.retired_reserves.iter().map(|r| serde_json::json!({
                            "reserve_pk": hex::encode(&r.reserve_pk),
                            "retired_at_btc_height": r.retired_at_btc_height,
                        })).collect::<Vec<_>>(),
                    })
                    .to_string()
                    .into_bytes(),
                    None => {
                        return ResponseQuery {
                            code: ERR,
                            log: "asset id not registered".into(),
                            ..Default::default()
                        }
                    }
                }
            }
            // ---- staking / block rewards ----
            "/staking/emitted" => s.node.emitted().to_string().into_bytes(),
            "/staking/issued" => s.node.total_issued().to_string().into_bytes(),
            // Foundation vesting: total remaining (locked + claimable), the amount
            // vested by the current height, claimed so far, and claimable right now.
            "/staking/foundation" => (zcrypt_core::emission::FOUNDATION
                - s.node.foundation_claimed())
            .to_string()
            .into_bytes(),
            "/staking/foundation_vested" => {
                s.node.foundation_vested().to_string().into_bytes()
            }
            "/staking/foundation_claimed" => {
                s.node.foundation_claimed().to_string().into_bytes()
            }
            "/staking/foundation_claimable" => {
                s.node.foundation_claimable().to_string().into_bytes()
            }
            "/staking/validators" => {
                // "<pubkey_hex>:<stake>:<commission_bps>" per bonded validator, comma-joined.
                let list: Vec<String> = s
                    .node
                    .validator_set_full()
                    .iter()
                    .map(|(pk, stake, comm)| format!("{}:{}:{}", hex::encode(pk), stake, comm))
                    .collect();
                list.join(",").into_bytes()
            }
            "/staking/validators_json" => {
                // The explorer's validator view: every bonded validator with its full
                // public profile — stake breakdown, lifetime + unclaimed rewards,
                // participation this epoch, delegations, pending unbonding — plus the
                // chain-level staking context (epoch schedule, totals). All of it is
                // consensus state; nothing here is private.
                let st = s.node.staking();
                let height = s.node.height();
                let epoch = zcrypt_core::emission::EPOCH;
                let vals: Vec<serde_json::Value> = st
                    .validators()
                    .map(|(id, v)| {
                        let addr = v.reward_address;
                        serde_json::json!({
                            "id": hex::encode(id),
                            "consensus_pubkey": hex::encode(&v.consensus_pubkey),
                            "stake": v.stake,
                            "delegated": v.delegated,
                            "power": v.stake + v.delegated,
                            "reward_address": hex::encode(addr),
                            // Lifetime rewards ever credited vs. still-unclaimed balance
                            // (the latter also holds returned unbonded stake).
                            "earned": st.earned_of(&addr),
                            "unclaimed": st.reward_balance(&addr),
                            "fee_earned": st
                                .fee_earned_of(&addr)
                                .iter()
                                .map(|(asset, amt)| {
                                    // Asset ids are full u64 hashes and exceed JS's
                                    // safe-integer range — send them as strings.
                                    serde_json::json!({ "asset_id": asset.to_string(), "amount": amt })
                                })
                                .collect::<Vec<_>>(),
                            "signed_this_epoch": st.participation_of(id),
                            "delegations": st
                                .delegations_of(id)
                                .iter()
                                .map(|(did, stake, _)| {
                                    serde_json::json!({
                                        "delegator": hex::encode(did),
                                        "stake": stake,
                                    })
                                })
                                .collect::<Vec<_>>(),
                            "unbonding": st
                                .unbonding_of(id)
                                .iter()
                                .map(|(stake, release)| {
                                    serde_json::json!({
                                        "stake": stake,
                                        "release_time": release,
                                    })
                                })
                                .collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                serde_json::json!({
                    "height": height,
                    "epoch_blocks": epoch,
                    "epoch_progress": if epoch > 0 { height % epoch } else { 0 },
                    "epoch_reward": zcrypt_core::emission::epoch_reward(height),
                    "total_staked": st.total_staked(),
                    "total_unbonding": st.total_unbonding(),
                    "commission_percent": zcrypt_core::staking::COMMISSION_NUM * 100
                        / zcrypt_core::staking::COMMISSION_DEN,
                    "min_stake": zcrypt_core::staking::MIN_STAKE,
                    "validators": vals,
                })
                .to_string()
                .into_bytes()
            }
            "/staking/unbonding_total" => {
                // Total stake frozen in the unbonding queue (atomic units).
                s.node.total_unbonding().to_string().into_bytes()
            }
            // A STAKER'S OWN pending unbondings by reward address (32B hex): "<stake>:<release_unix>,…".
            // Lets a delegator (or validator) see its own unbonding schedule regardless of which
            // validator the stake was with.
            p if p.starts_with("/staking/my_unbonding/") => {
                let addr_hex = &p["/staking/my_unbonding/".len()..];
                match hex::decode(addr_hex) {
                    Ok(b) if b.len() == 32 => {
                        let mut addr = [0u8; 32];
                        addr.copy_from_slice(&b);
                        let list: Vec<String> = s
                            .node
                            .unbonding_by_reward(&addr)
                            .iter()
                            .map(|(stake, release)| format!("{stake}:{release}"))
                            .collect();
                        list.join(",").into_bytes()
                    }
                    _ => {
                        return ResponseQuery {
                            code: ERR,
                            log: "bad reward address hex (want 32 bytes)".into(),
                            ..Default::default()
                        }
                    }
                }
            }
            p if p.starts_with("/staking/unbonding/") => {
                // Pending unbonding for a validator address: "<stake>:<release_unix>,…".
                let addr_hex = &p["/staking/unbonding/".len()..];
                match hex::decode(addr_hex) {
                    Ok(addr) => {
                        let list: Vec<String> = s
                            .node
                            .unbonding_of(&addr)
                            .iter()
                            .map(|(stake, release)| format!("{stake}:{release}"))
                            .collect();
                        list.join(",").into_bytes()
                    }
                    Err(_) => {
                        return ResponseQuery {
                            code: ERR,
                            log: "bad validator address hex".into(),
                            ..Default::default()
                        }
                    }
                }
            }
            p if p.starts_with("/staking/delegations/") => {
                // Delegations to a validator address: "<delegator_hex>:<stake>,…".
                let addr_hex = &p["/staking/delegations/".len()..];
                match hex::decode(addr_hex) {
                    Ok(addr) => {
                        let list: Vec<String> = s
                            .node
                            .delegations_of(&addr)
                            .iter()
                            .map(|(did, stake, _)| format!("{}:{}", hex::encode(did), stake))
                            .collect();
                        list.join(",").into_bytes()
                    }
                    Err(_) => {
                        return ResponseQuery {
                            code: ERR,
                            log: "bad validator address hex".into(),
                            ..Default::default()
                        }
                    }
                }
            }
            p if p.starts_with("/staking/claimable/") => {
                // claimable balance by shield pubkey (64-byte hex, 8×u64 LE)
                let pk_hex = &p["/staking/claimable/".len()..];
                match hex::decode(pk_hex).ok().and_then(|b| parse_pubkey(&b)) {
                    Some(pk) => s.node.claimable(&pk).to_string().into_bytes(),
                    None => {
                        return ResponseQuery {
                            code: ERR,
                            log: "bad pubkey hex (want 64 bytes / 8×u64 LE)".into(),
                            ..Default::default()
                        }
                    }
                }
            }
            p if p.starts_with("/staking/claim_index/") => {
                // next reward-coin index for a shield pubkey (for coin reconstruction)
                let pk_hex = &p["/staking/claim_index/".len()..];
                match hex::decode(pk_hex).ok().and_then(|b| parse_pubkey(&b)) {
                    Some(pk) => s.node.claim_index(&pk).to_string().into_bytes(),
                    None => {
                        return ResponseQuery {
                            code: ERR,
                            log: "bad pubkey hex (want 64 bytes / 8×u64 LE)".into(),
                            ..Default::default()
                        }
                    }
                }
            }
            // Replay-protection nonce a UNBOND/UNDELEGATE from this 32-byte ed25519 signer key
            // must carry next. A signer queries this, signs it in, and it advances on use.
            p if p.starts_with("/staking/auth_nonce/") => {
                let pk_hex = &p["/staking/auth_nonce/".len()..];
                match hex::decode(pk_hex).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) {
                    Some(pk) => s.node.auth_nonce(&pk).to_string().into_bytes(),
                    None => {
                        return ResponseQuery {
                            code: ERR,
                            log: "bad signer pubkey hex (want 32 bytes)".into(),
                            ..Default::default()
                        }
                    }
                }
            }
            // Next bridge-FEE coin index for "<pk_hex>/<asset_id>" (reconstruct fee coins).
            p if p.starts_with("/staking/fee_claim_index/") => {
                let rest = &p["/staking/fee_claim_index/".len()..];
                match rest.split_once('/') {
                    Some((pk_hex, asset_str)) => match (
                        hex::decode(pk_hex).ok().and_then(|b| parse_pubkey(&b)),
                        asset_str.parse::<u64>().ok(),
                    ) {
                        (Some(pk), Some(asset)) => s.node.fee_claim_index(&pk, asset).to_string().into_bytes(),
                        _ => {
                            return ResponseQuery {
                                code: ERR,
                                log: "bad /staking/fee_claim_index/<pk_hex>/<asset_id>".into(),
                                ..Default::default()
                            }
                        }
                    },
                    None => {
                        return ResponseQuery {
                            code: ERR,
                            log: "usage: /staking/fee_claim_index/<pk_hex>/<asset_id>".into(),
                            ..Default::default()
                        }
                    }
                }
            }
            p if p.starts_with("/staking/rewards/") => {
                let addr_hex = &p["/staking/rewards/".len()..];
                match hex::decode(addr_hex) {
                    Ok(b) if b.len() == 32 => {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        s.node.reward_balance(&a).to_string().into_bytes()
                    }
                    _ => {
                        return ResponseQuery {
                            code: ERR,
                            log: "bad reward address hex (want 32 bytes)".into(),
                            ..Default::default()
                        }
                    }
                }
            }
            p if p.starts_with("/prove/") => {
                let nf_hex = &p["/prove/".len()..];
                match hex::decode(nf_hex) {
                    Ok(b) if b.len() == 32 => {
                        let mut nf = [0u8; 32];
                        nf.copy_from_slice(&b);
                        let proofs = s.node.prove_batch(&[nf]);
                        let p0 = &proofs[0];
                        // Return a self-authenticating answer: the serialized SMT proof plus
                        // the nullifier-registry ROOT it was generated against. A wallet
                        // recomputes the root from the proof and checks it matches, so the
                        // node must produce a cryptographically valid proof (it can no longer
                        // just assert the `included` bit). `included`/`key`/`value` are kept
                        // for backward compatibility but are now redundant with `proof`.
                        serde_json::json!({
                            "key": hex::encode(p0.key),
                            "value": hex::encode(p0.value),
                            "included": p0.included,
                            "proof": hex::encode(smt::proof_to_bytes(p0)),
                            "root": hex::encode(s.node.registry_root()),
                        })
                        .to_string()
                        .into_bytes()
                    }
                    _ => {
                        return ResponseQuery {
                            code: ERR,
                            log: "bad nullifier hex".into(),
                            ..Default::default()
                        }
                    }
                }
            }
            other => {
                return ResponseQuery {
                    code: ERR,
                    log: format!("unknown path: {other}"),
                    ..Default::default()
                }
            }
        };
        ResponseQuery {
            code: OK,
            value: value.into(),
            height: s.height,
            ..Default::default()
        }
    }
}

fn main() {
    let port: u16 = std::env::var("ABCI_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(26658);
    // RocksDB directory for durable consensus state. Override with ZCRYPT_STATE_DB.
    let db_path: PathBuf = std::env::var("ZCRYPT_STATE_DB")
        .unwrap_or_else(|_| "zcrypt-state.db".to_string())
        .into();
    // Legacy single-file postcard snapshot: used once to migrate into RocksDB when the
    // DB is empty. Also the default path for ongoing postcard backups after each commit.
    let legacy_bin: PathBuf = std::env::var("ZCRYPT_STATE_FILE")
        .unwrap_or_else(|_| "zcrypt-state.bin".to_string())
        .into();
    let backup_path: PathBuf = std::env::var("ZCRYPT_STATE_BACKUP")
        .map(PathBuf::from)
        .unwrap_or_else(|_| legacy_bin.clone());
    let strict = std::env::var("ZCRYPT_STATE_STRICT")
        .map(|v| v != "0" && v != "false" && v != "no")
        .unwrap_or(true);
    eprintln!(
        "[state] rocksdb={} backup={} strict={} (legacy migrate from {})",
        db_path.display(),
        backup_path.display(),
        strict,
        legacy_bin.display()
    );
    // Devnet-only vesting acceleration: ZCRYPT_VESTING_ACCEL divides the foundation
    // vesting cliff/month lengths (amounts unchanged) so the whole schedule can be
    // watched live. Consensus-critical — every validator must set the same value.
    // Production builds ignore it entirely.
    #[cfg(feature = "devnet")]
    if let Some(scale) = std::env::var("ZCRYPT_VESTING_ACCEL").ok().and_then(|v| v.trim().parse::<u64>().ok()) {
        if scale > 1 {
            zcrypt_core::emission::set_vesting_time_scale(scale);
            eprintln!("[devnet] vesting time scale ×{scale}: cliff/month lengths divided (amounts unchanged)");
        }
    }
    #[cfg(not(feature = "devnet"))]
    if std::env::var("ZCRYPT_VESTING_ACCEL").is_ok() {
        eprintln!("[warn] ZCRYPT_VESTING_ACCEL ignored: production build vests on the real schedule");
    }
    let backup_every: u64 = std::env::var("ZCRYPT_BACKUP_EVERY")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(1000);
    let app = ZcryptApp::with_backup_every(db_path, Some(legacy_bin), backup_path, strict, backup_every);
    // The Bitcoin SPV mint gate (network + checkpoint) is configured at InitChain from the
    // GENESIS app_state (see `btc_spv_config` / `build_spv_chain`), so a downloaded genesis
    // fully describes the bridge and joining validators need no out-of-band env var. Env vars
    // remain a fallback for local/devnet genesis that omit the fields. Nothing to do here.
    let server = ServerBuilder::default()
        .bind(format!("0.0.0.0:{port}"), app)
        .expect("bind ABCI server");
    eprintln!("zcrypt-abci-node (ABCI 2.0) listening on 0.0.0.0:{port}");
    server.listen().expect("ABCI server");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    #[test]
    fn foundation_addr_read_from_genesis_app_state() {
        // A genesis app_state carrying a valid foundation_addr is the source of truth.
        let addr = [0xABu8; 32];
        let app_state =
            format!(r#"{{"registry":{{"minted_total":0,"leaves":[]}},"foundation_addr":"{}"}}"#, hex::encode(addr));
        assert_eq!(foundation_addr_from_genesis(app_state.as_bytes()), Some(addr));
        // ...and `foundation_addr` uses it (no env var involved).
        assert_eq!(foundation_addr(app_state.as_bytes()), addr);
    }

    #[test]
    fn foundation_addr_none_when_absent_empty_or_malformed() {
        // Absent field, empty value, wrong length, and non-JSON all yield None so the
        // caller applies its build-specific default (dev seed on devnet, panic on prod).
        assert_eq!(foundation_addr_from_genesis(br#"{"registry":{}}"#), None);
        assert_eq!(foundation_addr_from_genesis(br#"{"foundation_addr":""}"#), None);
        assert_eq!(foundation_addr_from_genesis(br#"{"foundation_addr":"abcd"}"#), None); // 2 bytes
        assert_eq!(foundation_addr_from_genesis(b""), None);
        assert_eq!(foundation_addr_from_genesis(b"not json"), None);
    }

    // A real, buried mainnet checkpoint (block 957600, a 2016 boundary) used as a
    // known-good vector. Its double-SHA256 hashes to
    // 00000000000000000000c1294b131fbf6d489c74e52c13e905f003ad9ccb9ba2.
    const MAINNET_CP_HDR: &str = "000001203442819fd7d32482308009a438242c7b423ca4b64ad6010000000000000000003150749c3de8487a6243a7cccea88d6e3679d035c9fcfbeb8fe33185eb423fafe7a2526a9d360217b279e223";

    #[test]
    fn btc_spv_config_reads_net_and_checkpoint_from_genesis() {
        // The exact app_state shape the cometbft entrypoint bakes for a mainnet launch.
        let app_state = format!(
            r#"{{"registry":{{"minted_total":0,"leaves":[]}},"foundation_addr":"{}","foundation_sentinel":true,"btc_net":"mainnet","btc_checkpoint":"{}:957600"}}"#,
            hex::encode([0xABu8; 32]),
            MAINNET_CP_HDR
        );
        let (net, cp) = btc_spv_config(app_state.as_bytes());
        assert_eq!(net, "mainnet");
        assert_eq!(cp, format!("{MAINNET_CP_HDR}:957600"));
        // And the genesis-driven config builds a real mainnet SPV chain (checkpoint accepted).
        assert!(build_spv_chain(&net, &cp).is_some());
    }

    #[test]
    fn btc_spv_config_empty_when_genesis_omits_it() {
        // A devnet genesis without the fields (and no env) yields empty strings, so a devnet
        // build keeps its default regtest SPV. (Env fallback is exercised only in real stacks.)
        let app_state = br#"{"registry":{"minted_total":0,"leaves":[]}}"#;
        // Only assert the genesis parse here; env may be set in some CI shells.
        let genesis_only = serde_json::from_slice::<serde_json::Value>(app_state)
            .ok()
            .and_then(|v| v.get("btc_net").cloned());
        assert!(genesis_only.is_none());
    }

    // Mirror the state-affecting steps of `ZcryptApp::init_chain` (foundation mint + SPV
    // config from genesis) on a bare Node, so we can compare the genesis app_hash two
    // independent "nodes" would compute from the SAME downloaded genesis.
    fn init_node_from_genesis(app_state: &[u8]) -> Node {
        let mut node = Node::new();
        node.mint_foundation(foundation_addr(app_state));
        let (net, cp) = btc_spv_config(app_state);
        if let Some(chain) = build_spv_chain(&net, &cp) {
            node.configure_btc_chain(chain).expect("fresh node accepts genesis SPV config");
        }
        node
    }

    #[test]
    fn validator_inherits_mainnet_spv_from_genesis_and_agrees_on_app_hash() {
        let faddr = hex::encode([0xF0u8; 32]);
        // The exact genesis app_state a mainnet foundation bakes (foundation addr + the SPV
        // network + checkpoint). A joining validator downloads this identical object.
        let mainnet = format!(
            r#"{{"registry":{{"minted_total":0,"leaves":[]}},"foundation_addr":"{faddr}","foundation_sentinel":true,"btc_net":"mainnet","btc_checkpoint":"{MAINNET_CP_HDR}:957600"}}"#
        );

        // Two INDEPENDENT nodes given the identical (as-if-downloaded) genesis must land on
        // the same genesis app_hash: a validator inherits the foundation's Bitcoin anchor
        // with zero out-of-band config and does NOT fork at replay.
        let foundation = init_node_from_genesis(mainnet.as_bytes());
        let validator = init_node_from_genesis(mainnet.as_bytes());
        assert_eq!(
            foundation.state_root(),
            validator.state_root(),
            "same genesis -> same app_hash (validator inherits the anchor, no fork)"
        );

        // The Bitcoin network + checkpoint are genuinely COMMITTED into consensus state: a
        // different anchor (signet, which needs no checkpoint) yields a DIFFERENT app_hash,
        // proving the SPV config is folded into the app_hash rather than ignored.
        let signet = format!(
            r#"{{"registry":{{"minted_total":0,"leaves":[]}},"foundation_addr":"{faddr}","btc_net":"signet","btc_checkpoint":""}}"#
        );
        let signet_node = init_node_from_genesis(signet.as_bytes());
        assert_ne!(
            foundation.state_root(),
            signet_node.state_root(),
            "different Bitcoin anchor -> different app_hash (checkpoint is committed)"
        );
    }

    // Build a signed BOND payload (H1) for consensus key `sk` bonding `stake` to
    // reward address `reward` at the default commission.
    fn signed_bond(sk: &SigningKey, stake: u64, reward: [u8; 32]) -> Vec<u8> {
        signed_bond_c(sk, stake, reward, zcrypt_core::staking::DEFAULT_COMMISSION_BPS)
    }
    // Same, with an explicit commission (basis points) in the signed header.
    fn signed_bond_c(sk: &SigningKey, stake: u64, reward: [u8; 32], commission: u16) -> Vec<u8> {
        let pubkey = sk.verifying_key().to_bytes();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"ZCRYPT-BOND-v1");
        msg.extend_from_slice(DEFAULT_CHAIN_ID);
        msg.extend_from_slice(&pubkey);
        msg.extend_from_slice(&stake.to_le_bytes());
        msg.extend_from_slice(&reward);
        msg.extend_from_slice(&commission.to_le_bytes());
        // A fresh validator's first bond carries nonce 0 (auth_nonce starts at 0).
        let nonce: u64 = 0;
        msg.extend_from_slice(&nonce.to_le_bytes());
        let sig = sk.sign(&msg);
        let mut b = Vec::new();
        b.extend_from_slice(&pubkey);
        b.extend_from_slice(&stake.to_le_bytes());
        b.extend_from_slice(&reward);
        b.extend_from_slice(&commission.to_le_bytes());
        b.extend_from_slice(&nonce.to_le_bytes());
        b.extend_from_slice(&sig.to_bytes());
        b
    }

    #[test]
    fn bond_requires_a_valid_consensus_signature() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let reward = [3u8; 32];
        let payload = signed_bond(&sk, 10_000, reward);

        // A correctly-signed bond authenticates, recovering the validator address
        // (SHA256(pubkey)[..20], the CometBFT consensus address) AND the full ed25519
        // pubkey (used to add it to the block-producing set).
        let (addr, pubkey, stake, got_reward, commission, _nonce) =
            verify_bond(&payload, DEFAULT_CHAIN_ID).expect("valid signature accepted");
        assert_eq!(stake, 10_000);
        assert_eq!(got_reward, reward);
        assert_eq!(commission, zcrypt_core::staking::DEFAULT_COMMISSION_BPS);
        assert_eq!(pubkey, sk.verifying_key().to_bytes().to_vec());
        assert_eq!(addr, Sha256::digest(sk.verifying_key().to_bytes())[..20].to_vec());
    }

    #[test]
    fn bond_carries_a_chosen_commission_and_rejects_tampering() {
        // A validator sets its own commission (e.g. 3.5% = 350 bps); it round-trips.
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let payload = signed_bond_c(&sk, 10_000, [4u8; 32], 350);
        let (_, _, _, _, commission, _) = verify_bond(&payload, DEFAULT_CHAIN_ID).expect("valid");
        assert_eq!(commission, 350);
        // Flipping the commission bytes ([72..74]) breaks the signature -> rejected.
        let mut tampered = payload.clone();
        tampered[72] ^= 0xff;
        assert!(verify_bond(&tampered, DEFAULT_CHAIN_ID).is_none(), "forged commission must fail auth");
    }

    // Build a signed DELEGATE header for delegator key `sk` pledging `stake` toward
    // validator `target` (20-byte address), returns going to `reward`.
    fn signed_delegate_header(sk: &SigningKey, target: &[u8], stake: u64, reward: [u8; 32]) -> Vec<u8> {
        let pubkey = sk.verifying_key().to_bytes();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"ZCRYPT-DELEGATE-v1");
        msg.extend_from_slice(DEFAULT_CHAIN_ID);
        msg.extend_from_slice(&pubkey);
        msg.extend_from_slice(target);
        msg.extend_from_slice(&stake.to_le_bytes());
        msg.extend_from_slice(&reward);
        let sig = sk.sign(&msg);
        let mut b = Vec::new();
        b.extend_from_slice(&pubkey);
        b.extend_from_slice(target);
        b.extend_from_slice(&stake.to_le_bytes());
        b.extend_from_slice(&reward);
        b.extend_from_slice(&sig.to_bytes());
        b
    }

    fn signed_undelegate(sk: &SigningKey, target: &[u8], nonce: u64) -> Vec<u8> {
        let pubkey = sk.verifying_key().to_bytes();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"ZCRYPT-UNDELEGATE-v1");
        msg.extend_from_slice(DEFAULT_CHAIN_ID);
        msg.extend_from_slice(&pubkey);
        msg.extend_from_slice(target);
        msg.extend_from_slice(&nonce.to_le_bytes());
        let sig = sk.sign(&msg);
        let mut b = Vec::new();
        b.extend_from_slice(&pubkey);
        b.extend_from_slice(target);
        b.extend_from_slice(&nonce.to_le_bytes());
        b.extend_from_slice(&sig.to_bytes());
        b
    }

    #[test]
    fn delegate_requires_a_valid_delegator_signature() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let target = vec![0xABu8; 20];
        let reward = [4u8; 32];
        let header = signed_delegate_header(&sk, &target, 5_000, reward);

        // The header authenticates the delegator, recovering the target + delegator id.
        let (got_target, delegator, stake, got_reward) =
            verify_delegate(&header, DEFAULT_CHAIN_ID).expect("valid signature accepted");
        assert_eq!(got_target, target);
        assert_eq!(stake, 5_000);
        assert_eq!(got_reward, reward);
        assert_eq!(delegator, Sha256::digest(sk.verifying_key().to_bytes())[..20].to_vec());

        // The same key signs a matching undelegate → same delegator id (so only they can
        // withdraw their own delegation).
        let (u_target, u_delegator, _pk, u_nonce) =
            verify_undelegate(&signed_undelegate(&sk, &target, 0), DEFAULT_CHAIN_ID).expect("valid undelegate");
        assert_eq!(u_target, target);
        assert_eq!(u_delegator, delegator);
        assert_eq!(u_nonce, 0);

        // Tampering with the target after signing breaks authentication.
        let mut forged = header.clone();
        forged[32] ^= 0xFF; // flip a byte of the target address
        assert!(verify_delegate(&forged, DEFAULT_CHAIN_ID).is_none(), "tampered target rejected");

        // A different key cannot undelegate this delegation (different delegator id).
        let other = SigningKey::from_bytes(&[10u8; 32]);
        let (_, other_delegator, _, _) =
            verify_undelegate(&signed_undelegate(&other, &target, 0), DEFAULT_CHAIN_ID).expect("well-formed");
        assert_ne!(other_delegator, delegator, "another key ⇒ another delegator id");
    }

    #[test]
    fn validator_updates_add_reweight_remove() {
        let a = vec![0xAAu8; 32];
        let b = vec![0xBBu8; 32];
        let atomic = zcrypt_core::emission::ATOMIC;
        // a joins with 10,000 ZCRYPT → power 10,000; nobody before.
        let ups = validator_updates(&[], &[(a.clone(), 10_000 * atomic)]);
        assert_eq!(ups.len(), 1);
        assert_eq!(ups[0].power, 10_000);
        assert!(matches!(&ups[0].pub_key, Some(PublicKey { sum: Some(PubKeySum::Ed25519(k)) }) if *k == a));

        // a re-stakes to 25,000 ZCRYPT while b joins with 10,000 → re-weight + add.
        let ups = validator_updates(
            &[(a.clone(), 10_000 * atomic)],
            &[(a.clone(), 25_000 * atomic), (b.clone(), 10_000 * atomic)],
        );
        let by_power: std::collections::BTreeMap<i64, ()> = ups.iter().map(|u| (u.power, ())).collect();
        assert!(by_power.contains_key(&25_000) && by_power.contains_key(&10_000));
        assert_eq!(ups.len(), 2);

        // a unbonds (gone from `after`) → power 0 removes it; b unchanged → no update.
        let ups = validator_updates(
            &[(a.clone(), 25_000 * atomic), (b.clone(), 10_000 * atomic)],
            &[(b.clone(), 10_000 * atomic)],
        );
        assert_eq!(ups.len(), 1);
        assert_eq!(ups[0].power, 0);
        assert!(matches!(&ups[0].pub_key, Some(PublicKey { sum: Some(PubKeySum::Ed25519(k)) }) if *k == a));

        // No change → no updates (genesis validators never in either snapshot).
        assert!(validator_updates(&[(b.clone(), 10_000 * atomic)], &[(b.clone(), 10_000 * atomic)]).is_empty());
    }

    #[test]
    fn bond_rejects_reward_address_tampering() {
        // H1 exploit attempt: take a validator's signed bond and rewrite the reward
        // address to the attacker's. The signature no longer matches -> rejected.
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let mut payload = signed_bond(&sk, 50_000, [1u8; 32]);
        // reward address is bytes [40..72]; flip one.
        payload[40] ^= 0xff;
        assert!(verify_bond(&payload, DEFAULT_CHAIN_ID).is_none(), "tampered reward address must fail auth");
    }

    #[test]
    fn bond_rejects_forged_stake_and_bad_length() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let mut payload = signed_bond(&sk, 10_000, [2u8; 32]);
        // bump the stake (bytes [32..40]) — signature was over the original stake.
        payload[32] ^= 0x01;
        assert!(verify_bond(&payload, DEFAULT_CHAIN_ID).is_none(), "forged stake must fail auth");
        // wrong length is rejected outright.
        assert!(verify_bond(&[0u8; 60], DEFAULT_CHAIN_ID).is_none());
        assert!(verify_bond(&[], DEFAULT_CHAIN_ID).is_none());
    }

    fn signed_unbond(sk: &SigningKey, nonce: u64) -> Vec<u8> {
        let pubkey = sk.verifying_key().to_bytes();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"ZCRYPT-UNBOND-v1");
        msg.extend_from_slice(DEFAULT_CHAIN_ID);
        msg.extend_from_slice(&pubkey);
        msg.extend_from_slice(&nonce.to_le_bytes());
        let sig = sk.sign(&msg);
        let mut b = Vec::new();
        b.extend_from_slice(&pubkey);
        b.extend_from_slice(&nonce.to_le_bytes());
        b.extend_from_slice(&sig.to_bytes());
        b
    }

    #[test]
    fn unbond_requires_a_valid_signature_and_binds_the_nonce() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let payload = signed_unbond(&sk, 0);
        let (addr, pk, nonce) = verify_unbond(&payload, DEFAULT_CHAIN_ID).expect("valid unbond accepted");
        assert_eq!(addr, Sha256::digest(sk.verifying_key().to_bytes())[..20].to_vec());
        assert_eq!(pk, sk.verifying_key().to_bytes());
        assert_eq!(nonce, 0);
        // Tampering the pubkey (so the sig no longer matches) is rejected.
        let mut bad = payload.clone();
        bad[0] ^= 0xff;
        assert!(verify_unbond(&bad, DEFAULT_CHAIN_ID).is_none());
        assert!(verify_unbond(&[0u8; 50], DEFAULT_CHAIN_ID).is_none(), "wrong length rejected");
        // A signature made for nonce 0 does NOT verify as nonce 1 (the nonce is signed).
        assert_ne!(verify_unbond(&signed_unbond(&sk, 1), DEFAULT_CHAIN_ID).unwrap().2, 0);
        assert!(
            verify_unbond(&signed_unbond(&sk, 5), DEFAULT_CHAIN_ID).map(|t| t.2) == Some(5),
            "the nonce round-trips"
        );
        // Replaying a nonce-0 signature's BYTES but claiming nonce 1 fails auth (sig covers nonce).
        let mut forged = signed_unbond(&sk, 0);
        let n1 = 1u64.to_le_bytes();
        forged[32..40].copy_from_slice(&n1); // rewrite the nonce field only
        assert!(verify_unbond(&forged, DEFAULT_CHAIN_ID).is_none(), "nonce not covered by sig => rejected");
    }

    #[test]
    fn sentinel_is_removable_and_auto_decays() {
        use zcrypt_core::emission::ATOMIC;
        use zcrypt_core::node::Node;
        let skey = vec![9u8; 32];

        // (1) DISABLE path: only the sentinel key may retire it; then it's gone.
        let mut node = Node::new();
        node.set_sentinel(skey.clone(), 100, 50_000);
        assert!(node.disable_sentinel(&[1u8; 32]).is_err(), "a non-sentinel key cannot disable it");
        node.disable_sentinel(&skey).expect("the sentinel key retires it");
        let (k, _p) = node.sentinel_update().expect("retirement emits a CometBFT update");
        assert_eq!(k, skey);
        assert!(node.sentinel_info().is_none(), "sentinel removed after disable");

        // (2) AUTO-DECAY: retires only once external stake reaches the threshold AND no single
        // external validator holds more than a third of it AND that has held for the full
        // dwell window, so neither a transient spike nor a Sybil spread of one whale's stake
        // across a few keys retires the guarantor (M5). (`sentinel_update` returns Some on any
        // power change, so retirement is detected via `sentinel_info()` going None.)
        use zcrypt_core::node::SENTINEL_DECAY_DWELL_BLOCKS as DWELL;
        let mut node = Node::new();
        node.set_sentinel(skey.clone(), 100, 50_000);
        // One big validator alone (> 50k threshold) must NOT retire it: it holds 100%.
        node.bond(vec![1u8; 20], vec![1u8; 32], 60_000 * ATOMIC, [0u8; 32], 1_000).unwrap();
        for _ in 0..DWELL + 1 {
            node.sentinel_update();
        }
        assert!(node.sentinel_info().is_some(), "one whale can't retire the sentinel");
        // Three more 20k validators: the whale still holds 60k of 120k = 50% > 1/3, so the
        // old "4 distinct validators" rule would have retired it, but the share rule holds.
        for i in 2..=4u8 {
            node.bond(vec![i; 20], vec![i; 32], 20_000 * ATOMIC, [0u8; 32], 1_000).unwrap();
        }
        for _ in 0..DWELL + 1 {
            node.sentinel_update();
        }
        assert!(node.sentinel_info().is_some(), "a 50% whale among 4 validators can't retire it");
        // Dilute the whale below a third (60k of 200k = 30%): now the condition holds; it
        // retires only AFTER the dwell window, never before.
        for i in 5..=8u8 {
            node.bond(vec![i; 20], vec![i; 32], 20_000 * ATOMIC, [0u8; 32], 1_000).unwrap();
        }
        let mut retired_at = None;
        for n in 0..DWELL + 5 {
            node.sentinel_update();
            if node.sentinel_info().is_none() {
                retired_at = Some(n);
                break;
            }
        }
        let n = retired_at.expect("auto-retires after sustained, well-distributed external stake");
        assert!(n >= DWELL - 1, "retired too early ({n} < dwell {DWELL})");

        // (3) PERMANENT (decay=0): stays a sentinel and inflates above 2/3.
        let mut node = Node::new();
        node.set_sentinel(skey.clone(), 1, 0);
        node.bond(vec![7u8; 20], vec![7u8; 32], 60_000 * ATOMIC, [0u8; 32], 1_000).unwrap();
        node.sentinel_update();
        let (_k, p) = node.sentinel_info().expect("permanent sentinel remains");
        assert!(p > 2 * 60_000 / 3, "permanent sentinel keeps >2/3 (power {p})");
    }

    #[test]
    fn sentinel_key_is_never_emitted_by_the_bonded_set_diff() {
        // Consensus C1. The launch runbook bonds the sentinel's own consensus key, so its
        // stake appears in the bonded set. The ordinary diff must EXCLUDE that key: (a) a
        // dust delegation to the sentinel must not overwrite its supermajority with its
        // stake-based power, (b) a block that changes both the sentinel's stake and another
        // validator's must never yield two updates for one key (CometBFT rejects that and
        // the chain halts), and (c) the sentinel unbonding as sole validator must not emit
        // an empty set.
        use zcrypt_core::emission::ATOMIC;
        use zcrypt_core::node::Node;
        let skey = vec![0xAAu8; 32];
        let other = vec![0xBBu8; 32];
        let mut node = Node::new();
        node.set_sentinel(skey.clone(), 10, 1_000_000);
        // Block 1: the sentinel bonds its own key, another validator bonds too.
        let before = node.validator_set();
        node.bond(skey.clone(), skey.clone(), 10_000 * ATOMIC, [0u8; 32], 1_000).unwrap();
        node.bond(other.clone(), other.clone(), 10_000 * ATOMIC, [0u8; 32], 1_000).unwrap();
        let after = node.validator_set();
        let mut updates = validator_updates_excluding(&before, &after, node.sentinel_key().as_deref());
        if let Some((k, p)) = node.sentinel_update() {
            updates.push(ValidatorUpdate { pub_key: Some(PublicKey { sum: Some(PubKeySum::Ed25519(k)) }), power: p });
        }
        let keys: Vec<Vec<u8>> = updates
            .iter()
            .filter_map(|u| match &u.pub_key { Some(PublicKey { sum: Some(PubKeySum::Ed25519(k)) }) => Some(k.clone()), _ => None })
            .collect();
        assert_eq!(keys.iter().filter(|k| **k == skey).count(), 1, "exactly one update for the sentinel key");
        let spow = updates.iter().zip(&keys).find(|(_, k)| **k == skey).map(|(u, _)| u.power).unwrap();
        assert_eq!(spow, 2 * 10_000 + 1, "sentinel power comes from sentinel_update, not its stake");
        assert!(3 * spow > 2 * (spow + 10_000), "sentinel keeps > 2/3");

        // Block 2: a 1-ZCRYPT delegation to the sentinel AND to the other validator. The old
        // diff emitted (S, 10_001) here, deflating the sentinel to a minority and, with the
        // sentinel_update emitted in the same block, a duplicate key.
        let before = node.validator_set();
        node.staking_delegate_for_test(&skey, vec![1u8; 20], ATOMIC);
        node.staking_delegate_for_test(&other, vec![2u8; 20], ATOMIC);
        let after = node.validator_set();
        let mut updates = validator_updates_excluding(&before, &after, node.sentinel_key().as_deref());
        if let Some((k, p)) = node.sentinel_update() {
            updates.push(ValidatorUpdate { pub_key: Some(PublicKey { sum: Some(PubKeySum::Ed25519(k)) }), power: p });
        }
        let keys: Vec<Vec<u8>> = updates
            .iter()
            .filter_map(|u| match &u.pub_key { Some(PublicKey { sum: Some(PubKeySum::Ed25519(k)) }) => Some(k.clone()), _ => None })
            .collect();
        assert_eq!(keys.iter().filter(|k| **k == skey).count(), 1, "still exactly one update for the sentinel");
        let spow = updates.iter().zip(&keys).find(|(_, k)| **k == skey).map(|(u, _)| u.power).unwrap();
        assert_eq!(spow, 2 * 10_001 + 1, "re-inflated above 2/3 of the grown external power");
        assert!(updates.iter().all(|u| u.power > 0), "no removal");

        // Block 3: the other validator leaves; only S remains. Then S itself unbonds: the
        // diff must NOT emit (S, 0) (an empty validator set is a halt); S keeps its power.
        let before = node.validator_set();
        node.staking_unbond_for_test(&other);
        node.staking_unbond_for_test(&skey);
        let after = node.validator_set();
        let updates = validator_updates_excluding(&before, &after, node.sentinel_key().as_deref());
        assert!(updates.iter().all(|u| match &u.pub_key { Some(PublicKey { sum: Some(PubKeySum::Ed25519(k)) }) => *k != skey, _ => true }), "sentinel never in the diff");
        let (k, p) = node.sentinel_update().expect("power drops back to the floor");
        assert_eq!(k, skey);
        assert_eq!(p, 10, "floor, never zero");
    }

    #[test]
    fn seed_tx_is_disabled_in_production_builds() {
        // C3: without the `devnet` feature, the unbacked coin-injection tx is off.
        assert_eq!(SEED_ENABLED, cfg!(feature = "devnet"));
        #[cfg(not(feature = "devnet"))]
        assert!(!SEED_ENABLED, "SEED must be disabled unless devnet is explicitly enabled");
    }

    fn tmp_app_paths(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "zcrypt-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = base.join("state.db");
        let backup = base.join("backup.bin");
        let _ = std::fs::remove_dir_all(&base);
        (db, backup, base)
    }

    #[test]
    fn mutex_poisoning_does_not_cascade() {
        // The cascade: a panic while holding the state lock poisons the mutex, after
        // which a raw `lock().unwrap()` panics forever — one fault kills the whole
        // node. `locked()` must recover the guard so later calls keep working.
        let (db, backup, base) = tmp_app_paths("poison");
        let app = ZcryptApp::new(db, None, backup, true);
        {
            let mut g = app.locked();
            g.height = 5;
        }
        // Poison the mutex by panicking while a guard is held.
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = app.state.lock().unwrap();
            panic!("boom while holding the state lock");
        }));
        assert!(poisoned.is_err(), "the closure must have panicked");
        assert!(app.state.lock().is_err(), "the mutex must now be poisoned");

        // The poison-tolerant accessor still yields a usable guard with intact state
        // — no cascade. A raw `.lock().unwrap()` here would panic instead.
        let g = app.locked();
        assert_eq!(g.height, 5, "state survives a recovered lock");
        drop(g);
        drop(app);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn persist_and_restart_resumes_at_same_height_and_app_hash() {
        // Simulate a full restart: commit via RocksDB, then open a fresh store.
        // The resumed node must report the same height and app_hash so CometBFT
        // replays only new blocks (not the whole chain from genesis).
        let (db, backup, base) = tmp_app_paths("persist");
        let mut node = Node::new();
        #[allow(unused_mut)]
        let mut node = node;
        node.mint_foundation([0xF0; 32]);
        node.set_height(42);
        for k in 0..8u64 {
            node.seed_coin([k + 100; 8]);
        }
        let app_hash_before = node.state_root();

        {
            let mut store = StateDb::open(&db).expect("open db");
            store.commit(&mut node, 42, DEFAULT_CHAIN_ID).expect("commit");
            StateDb::write_backup_file(&backup, &node, 42).expect("backup");
        }

        let (store2, loaded) = StateDb::open_or_migrate(&db, None).expect("reopen");
        let (resumed, height) = loaded.expect("state present");
        assert_eq!(height, 42, "resumed at the persisted height");
        assert_eq!(resumed.state_root(), app_hash_before, "app_hash survives restart");
        drop(store2);

        // Empty DB path (fresh dir) is a fresh chain, not an error.
        let fresh = base.join("empty.db");
        let (_s, loaded_none) = StateDb::open_or_migrate(&fresh, None).unwrap();
        assert!(loaded_none.is_none());

        // Legacy postcard backup still restores.
        let (from_backup, h2) =
            Node::from_snapshot_bytes(&std::fs::read(&backup).unwrap()).unwrap();
        assert_eq!(h2, 42);
        assert_eq!(from_backup.state_root(), app_hash_before);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn abci_commit_then_new_app_resumes() {
        let (db, backup, base) = tmp_app_paths("abci-commit");
        let app = ZcryptApp::new(db.clone(), None, backup.clone(), true);
        {
            let mut s = app.locked();
            s.node.mint_foundation([0xAB; 32]);
            s.node.set_height(9);
            s.node.seed_coin([1u64; 8]);
            s.node.seed_coin([2u64; 8]);
            s.height = 9;
        }
        let hash = app.locked().node.state_root();
        // Drive the ABCI commit path.
        let _ = app.commit();

        drop(app);
        let app2 = ZcryptApp::new(db, None, backup, true);
        let s2 = app2.locked();
        assert_eq!(s2.height, 9);
        assert_eq!(s2.node.state_root(), hash);
        assert_eq!(s2.node.commitment_count(), 2);
        drop(s2);
        drop(app2);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Crash suite (ABCI): finalize advances RAM; without Commit, restart must
    /// not see the uncommitted height (CometBFT would replay that block).
    #[test]
    fn abci_crash_before_commit_loses_unpersisted_finalize() {
        let (db, backup, base) = tmp_app_paths("abci-crash-pre-commit");
        let app = ZcryptApp::new(db.clone(), None, backup.clone(), true);

        // Commit height 1.
        {
            let mut s = app.locked();
            s.node.mint_foundation([0xCD; 32]);
            s.node.set_height(1);
            s.node.seed_coin([11u64; 8]);
            s.height = 1;
        }
        let hash1 = app.locked().node.state_root();
        let _ = app.commit();

        // Finalize height 2 in RAM only — never call Commit (crash window).
        {
            let mut s = app.locked();
            s.node.set_height(2);
            s.node.seed_coin([22u64; 8]);
            s.height = 2;
        }
        let hash2_ram = app.locked().node.state_root();
        assert_ne!(hash1, hash2_ram);
        assert_eq!(app.locked().height, 2);

        // Process death without Commit.
        drop(app);

        let app2 = ZcryptApp::new(db, None, backup, true);
        let s2 = app2.locked();
        assert_eq!(s2.height, 1, "uncommitted finalize must not be durable");
        assert_eq!(s2.node.state_root(), hash1);
        assert_eq!(s2.node.commitment_count(), 1);
        drop(s2);
        drop(app2);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// After a durable Commit, killing the app and reopening recovers tip only.
    #[test]
    fn abci_multi_commit_restart_at_tip() {
        let (db, backup, base) = tmp_app_paths("abci-multi");
        let app = ZcryptApp::new(db.clone(), None, backup.clone(), true);
        let mut last_hash = [0u8; 32];
        for h in 1..=4i64 {
            {
                let mut s = app.locked();
                if h == 1 {
                    s.node.mint_foundation([0x11; 32]);
                }
                s.node.set_height(h as u64);
                s.node.seed_coin([h as u64; 8]);
                s.height = h;
            }
            let _ = app.commit();
            last_hash = app.locked().node.state_root();
        }
        drop(app);

        let app2 = ZcryptApp::new(db, None, backup, true);
        let s = app2.locked();
        assert_eq!(s.height, 4);
        assert_eq!(s.node.state_root(), last_hash);
        assert_eq!(s.node.commitment_count(), 4);
        drop(s);
        drop(app2);
        let _ = std::fs::remove_dir_all(&base);
    }
}
