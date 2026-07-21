//! Native Rust ABCI app for ZCrypt, targeting CometBFT 0.38 (ABCI 2.0).
//!
//! Replaces the old Python (py-abci) + PyO3 shim. The transaction is raw ZVM
//! bytecode; this wraps `zcrypt_core::node::Node` directly:
//!   * check_tx        -> Node::check   (mempool: ZVM + double-spend gate, no mutation)
//!   * finalize_block  -> Node::submit  (apply each tx; return per-tx results + app_hash)
//!   * commit          -> persist (no-op here; state is in-memory)
//!   * query           -> /registry/root, /registry/minted, /prove/<nf_hex>

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tendermint_abci::{Application, ServerBuilder};
use tendermint_proto::v0_38::abci::{
    ExecTxResult, MisbehaviorType, RequestCheckTx, RequestFinalizeBlock, RequestInfo,
    RequestInitChain, RequestQuery, ResponseCheckTx, ResponseCommit, ResponseFinalizeBlock,
    ResponseInfo, ResponseInitChain, ResponseQuery, ValidatorUpdate,
};
use tendermint_proto::v0_38::crypto::{public_key::Sum as PubKeySum, PublicKey};
use tendermint_proto::v0_38::types::BlockIdFlag;

use zcrypt_core::node::Node;
use zcrypt_core::smt;

const OK: u32 = 0;
const ERR: u32 = 1;

/// Chain id for shielded-tx verification (must match the genesis chain-id and the
/// `chain_id` the wallet binds into shielded transactions).
const CHAIN_ID: &[u8] = b"zcrypt-devnet";
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
///   [0]      decimals
///   [1]      ticker length L
///   [2..2+L] ticker (UTF-8, e.g. "zBTC")
///   [2+L..]  optional 32-byte controlled-mint authority (absent = protocol/bridge mint)
const REGISTER_TAG: u8 = 0x59;

/// Open a shield-native HTLC escrow. Payload:
///   [0..8]    asset_id (u64 LE)   [8..16]   value (u64 LE)
///   [16..48]  hashlock (SHA-256)  [48..56]  timeout height (u64 LE)
///   [56..120] claim shield pubkey (8×u64 LE)   [120..] mint capability
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

/// Devnet foundation account seed. The genesis foundation allocation is registered to
/// this account's REWARD ADDRESS (`h("ZC-REWARD-ADDR", pk)`), so the matching wallet
/// can actually claim vested tranches (tag 0x58) into spendable coins. This seed is
/// PUBLIC (it is in the repo) — it exists only so devnet tests can claim.
#[cfg(feature = "devnet")]
const FOUNDATION_SEED: [u8; 32] = [0xF0; 32];

/// The foundation's reward address, resolved once at startup.
///
/// * `ZCRYPT_FOUNDATION_ADDR` (64 hex chars) — the reward address of the foundation's
///   OFFLINE cold key (print one with `cargo run -p zcrypt-core --example
///   foundation_keys new`, run on an air-gapped machine). Consensus-critical at
///   genesis: every validator must set the identical value.
/// * Production builds REQUIRE the env var and refuse to start without it — launching
///   a value-bearing chain on the public devnet seed would let anyone claim the
///   foundation allocation.
/// * Devnet builds fall back to the well-known dev seed when the env var is unset.
fn foundation_addr() -> [u8; 32] {
    static ADDR: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *ADDR.get_or_init(|| {
        if let Ok(h) = std::env::var("ZCRYPT_FOUNDATION_ADDR") {
            let b = hex::decode(h.trim()).expect("ZCRYPT_FOUNDATION_ADDR: invalid hex");
            let a: [u8; 32] = b.try_into().expect("ZCRYPT_FOUNDATION_ADDR must be 64 hex chars (32 bytes)");
            return a;
        }
        #[cfg(feature = "devnet")]
        {
            zcrypt_core::keys::Account::from_seed(FOUNDATION_SEED).reward_address()
        }
        #[cfg(not(feature = "devnet"))]
        panic!(
            "production build requires ZCRYPT_FOUNDATION_ADDR (64 hex chars): the reward \
             address of the foundation's offline cold key. Generate one offline with \
             `cargo run -p zcrypt-core --example foundation_keys new`."
        )
    })
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

/// Parse a register payload into (ticker, decimals, optional authority).
/// Layout: decimals(1) ‖ tlen(1) ‖ ticker ‖ max_supply_le(8) ‖ [authority(32)].
fn parse_register(b: &[u8]) -> Option<(String, u8, Option<[u8; 32]>, u64)> {
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
    let authority = if rest.is_empty() {
        None
    } else if rest.len() == 32 {
        let mut a = [0u8; 32];
        a.copy_from_slice(rest);
        Some(a)
    } else {
        return None;
    };
    Some((ticker, decimals, authority, max_supply))
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
fn parse_claim(b: &[u8]) -> Option<([u64; 8], u64)> {
    if b.len() != 72 {
        return None;
    }
    let pk = parse_pubkey(&b[0..64])?;
    let amount = u64::from_le_bytes(b[64..72].try_into().ok()?);
    Some((pk, amount))
}

/// Parse and AUTHENTICATE a bond payload (H1). Layout (136 bytes):
///   ed25519_pubkey(32) ‖ stake_le(8) ‖ reward_address(32) ‖ signature(64)
///
/// The signature must be by the ed25519 consensus key over
///   "ZCRYPT-BOND-v1" ‖ chain_id ‖ pubkey ‖ stake_le ‖ reward
/// which proves the submitter controls that consensus key — so an attacker can no
/// longer bond in another validator's name to redirect its block rewards, nor
/// silently re-point a reward address. Returns `(address, pubkey, stake, reward)`:
/// the CometBFT address `SHA256(pubkey)[..20]` (matches the signer addresses in
/// `decided_last_commit` the reward split is keyed on) AND the full 32-byte ed25519
/// key (used to add/remove this validator from the block-producing set).
fn verify_bond(b: &[u8]) -> Option<(Vec<u8>, Vec<u8>, u64, [u8; 32])> {
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::{Digest, Sha256};
    if b.len() != 136 {
        return None;
    }
    let pubkey: [u8; 32] = b[0..32].try_into().ok()?;
    let stake = u64::from_le_bytes(b[32..40].try_into().ok()?);
    let mut reward = [0u8; 32];
    reward.copy_from_slice(&b[40..72]);
    let sig_bytes: [u8; 64] = b[72..136].try_into().ok()?;

    let vk = VerifyingKey::from_bytes(&pubkey).ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    let mut msg = Vec::with_capacity(14 + CHAIN_ID.len() + 72);
    msg.extend_from_slice(b"ZCRYPT-BOND-v1");
    msg.extend_from_slice(CHAIN_ID);
    msg.extend_from_slice(&pubkey);
    msg.extend_from_slice(&stake.to_le_bytes());
    msg.extend_from_slice(&reward);
    vk.verify_strict(&msg, &sig).ok()?;

    let addr = Sha256::digest(pubkey)[..20].to_vec();
    Some((addr, pubkey.to_vec(), stake, reward))
}

/// Parse a **coin-backed** BOND payload:
///   verify_bond header (136) ‖ stake_blind (4×u64 = 32) ‖ shield_tx_bytes.
/// The header authenticates the validator + stake + reward (as [`verify_bond`]); the
/// stake_blind + shield_tx are the pledge — the node checks the shield tx's `output[0]`
/// is the burn coin `commit(stake, stake_blind, BURN_PK, ZCRYPT)` and applies the spend.
#[allow(clippy::type_complexity)]
fn parse_bond_coin(
    b: &[u8],
) -> Option<(Vec<u8>, Vec<u8>, u64, [u8; 32], [u64; 4], zcrypt_core::shield_tx::ShieldTx)> {
    if b.len() < 168 {
        return None;
    }
    let (addr, pubkey, stake, reward) = verify_bond(&b[..136])?;
    let mut stake_blind = [0u64; 4];
    for (i, limb) in stake_blind.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(b[136 + i * 8..144 + i * 8].try_into().ok()?);
    }
    let stx = zcrypt_core::shield_tx::from_bytes(&b[168..])?;
    Some((addr, pubkey, stake, reward, stake_blind, stx))
}

/// Parse and AUTHENTICATE an unbond payload (96 bytes): ed25519_pubkey(32) ‖
/// signature(64), signed over "ZCRYPT-UNBOND-v1" ‖ chain_id ‖ pubkey. Only the
/// holder of the consensus key can unbond its own validator. Returns the CometBFT
/// validator address `SHA256(pubkey)[..20]`.
fn verify_unbond(b: &[u8]) -> Option<Vec<u8>> {
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::{Digest, Sha256};
    if b.len() != 96 {
        return None;
    }
    let pubkey: [u8; 32] = b[0..32].try_into().ok()?;
    let sig_bytes: [u8; 64] = b[32..96].try_into().ok()?;
    let vk = VerifyingKey::from_bytes(&pubkey).ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    let mut msg = Vec::with_capacity(16 + CHAIN_ID.len() + 32);
    msg.extend_from_slice(b"ZCRYPT-UNBOND-v1");
    msg.extend_from_slice(CHAIN_ID);
    msg.extend_from_slice(&pubkey);
    vk.verify_strict(&msg, &sig).ok()?;
    Some(Sha256::digest(pubkey)[..20].to_vec())
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
fn verify_delegate(b: &[u8]) -> Option<(Vec<u8>, Vec<u8>, u64, [u8; 32])> {
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
    let mut msg = Vec::with_capacity(18 + CHAIN_ID.len() + 92);
    msg.extend_from_slice(b"ZCRYPT-DELEGATE-v1");
    msg.extend_from_slice(CHAIN_ID);
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
) -> Option<(Vec<u8>, Vec<u8>, u64, [u8; 32], [u64; 4], zcrypt_core::shield_tx::ShieldTx)> {
    if b.len() < 188 {
        return None;
    }
    let (target, delegator_id, stake, reward) = verify_delegate(&b[..156])?;
    let mut stake_blind = [0u64; 4];
    for (i, limb) in stake_blind.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(b[156 + i * 8..164 + i * 8].try_into().ok()?);
    }
    let stx = zcrypt_core::shield_tx::from_bytes(&b[188..])?;
    Some((target, delegator_id, stake, reward, stake_blind, stx))
}

/// Parse and AUTHENTICATE an undelegate payload (116 bytes):
///   delegator_pubkey(32) ‖ target_addr(20) ‖ signature(64),
/// signed over "ZCRYPT-UNDELEGATE-v1" ‖ chain_id ‖ delegator_pubkey ‖ target_addr. Only
/// the delegator can undelegate their own stake. Returns `(target_addr, delegator_id)`.
fn verify_undelegate(b: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::{Digest, Sha256};
    if b.len() != 116 {
        return None;
    }
    let pubkey: [u8; 32] = b[0..32].try_into().ok()?;
    let target = b[32..52].to_vec();
    let sig_bytes: [u8; 64] = b[52..116].try_into().ok()?;
    let vk = VerifyingKey::from_bytes(&pubkey).ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    let mut msg = Vec::with_capacity(20 + CHAIN_ID.len() + 52);
    msg.extend_from_slice(b"ZCRYPT-UNDELEGATE-v1");
    msg.extend_from_slice(CHAIN_ID);
    msg.extend_from_slice(&pubkey);
    msg.extend_from_slice(&target);
    vk.verify_strict(&msg, &sig).ok()?;
    let delegator_id = Sha256::digest(pubkey)[..20].to_vec();
    Some((target, delegator_id))
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
    use std::collections::BTreeMap;
    let bmap: BTreeMap<&Vec<u8>, u64> = before.iter().map(|(k, v)| (k, *v)).collect();
    let amap: BTreeMap<&Vec<u8>, u64> = after.iter().map(|(k, v)| (k, *v)).collect();
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
        Some(CLAIM_TAG) => "CLAIM",
        Some(REGISTER_TAG) => "REGISTER",
        Some(HTLC_OPEN_TAG) => "HTLC_OPEN",
        Some(HTLC_CLAIM_TAG) => "HTLC_CLAIM",
        Some(HTLC_EXPIRE_TAG) => "HTLC_EXPIRE",
        Some(HTLC_BURN_LOCK_TAG) => "HTLC_BURN_LOCK",
        Some(ROTATE_AUTH_TAG) => "ROTATE_AUTH",
        Some(SWAP_LOCK_TAG) => "SWAP_LOCK",
        _ => "UNKNOWN",
    }
}

struct State {
    node: Node,
    height: i64,
}

#[derive(Clone)]
struct ZcryptApp {
    state: Arc<Mutex<State>>,
    /// File the full consensus state is snapshotted to on each Commit, so the node
    /// resumes after a restart instead of replaying the whole chain from genesis.
    state_path: PathBuf,
}

/// Load persisted state from `path`. Returns `None` for a fresh chain (no file).
/// PANICS on a present-but-unreadable/corrupt file — silently starting from genesis
/// would drop all balances and re-mint the foundation, so we fail loudly instead.
fn load_state(path: &Path) -> Option<(Node, i64)> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("cannot read state file {}: {e}", path.display()),
    };
    match Node::from_snapshot_bytes(&bytes) {
        Ok((node, h)) => {
            eprintln!("[state] resumed from {} at height {h}", path.display());
            Some((node, h as i64))
        }
        Err(e) => panic!(
            "state file {} is present but unreadable ({e}); refusing to start from genesis \
             (move it aside to intentionally reset the chain)",
            path.display()
        ),
    }
}

/// Atomically persist `bytes` to `path` (write a temp file in the same directory,
/// then rename over the target) so a crash mid-write can never corrupt the state.
fn persist_state(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

impl ZcryptApp {
    fn new(state_path: PathBuf) -> Self {
        let (node, height) = load_state(&state_path).unwrap_or_else(|| (Node::new(), 0));
        ZcryptApp {
            state: Arc::new(Mutex::new(State { node, height })),
            state_path,
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
}

impl Application for ZcryptApp {
    fn info(&self, _req: RequestInfo) -> ResponseInfo {
        let s = self.locked();
        ResponseInfo {
            data: "zcrypt-registry".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            app_version: 1,
            last_block_height: s.height,
            last_block_app_hash: s.node.state_root().to_vec().into(),
        }
    }

    fn init_chain(&self, _req: RequestInitChain) -> ResponseInitChain {
        let mut s = self.locked();
        // One-time 20% foundation allocation (idempotent inside the node).
        s.node.mint_foundation(foundation_addr());
        ResponseInitChain {
            app_hash: s.node.state_root().to_vec().into(),
            ..Default::default()
        }
    }

    fn check_tx(&self, req: RequestCheckTx) -> ResponseCheckTx {
        let s = self.locked();
        let tx = req.tx.as_ref();
        let result = if tx.first() == Some(&SHIELD_TAG) {
            match parse_transfer(&tx[1..]) {
                Some((gas_blind, gas_tx, main_tx)) => {
                    s.node.check_transfer(CHAIN_ID, &main_tx, &gas_tx, gas_blind)
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
            match parse_bond_coin(&tx[1..]) {
                Some((_, _, stake, _, _, _)) if stake >= zcrypt_core::staking::MIN_STAKE => Ok(()),
                Some(_) => Err("stake below minimum (10,000 ZCRYPT)".to_string()),
                None => Err("malformed or unauthenticated bond tx (needs the stake pledge)".to_string()),
            }
        } else if tx.first() == Some(&UNBOND_TAG) {
            if verify_unbond(&tx[1..]).is_some() {
                Ok(())
            } else {
                Err("malformed or unauthenticated unbond tx".to_string())
            }
        } else if tx.first() == Some(&DELEGATE_TAG) {
            match parse_delegate_coin(&tx[1..]) {
                Some((target, _, stake, _, _, _)) if stake > 0 && s.node.is_validator(&target) => Ok(()),
                Some((_, _, 0, _, _, _)) => Err("delegation must be a positive stake".to_string()),
                Some((_, _, _, _, _, _)) => Err("delegation target is not a bonded validator".to_string()),
                None => Err("malformed or unauthenticated delegate tx (needs the stake pledge)".to_string()),
            }
        } else if tx.first() == Some(&UNDELEGATE_TAG) {
            match verify_undelegate(&tx[1..]) {
                Some((target, delegator)) if s.node.delegation_of(&target, &delegator) > 0 => Ok(()),
                Some(_) => Err("no such delegation to undelegate".to_string()),
                None => Err("malformed or unauthenticated undelegate tx".to_string()),
            }
        } else if tx.first() == Some(&CLAIM_TAG) {
            match parse_claim(&tx[1..]) {
                Some((pk, amount)) => {
                    let bal = s.node.claimable(&pk);
                    if amount == 0 || amount > bal {
                        Err(format!("claim {amount} exceeds claimable {bal}"))
                    } else {
                        Ok(())
                    }
                }
                None => Err("malformed claim tx".to_string()),
            }
        } else if tx.first() == Some(&REGISTER_TAG) {
            match parse_register(&tx[1..]) {
                Some((ticker, _, _, _)) if s.node.asset_id_of(&ticker).is_some() => {
                    Err(format!("ticker '{ticker}' is already registered"))
                }
                Some((_, _, _, max_supply)) if max_supply == 0 => {
                    Err("asset must declare a non-zero max supply".to_string())
                }
                Some((ticker, _, _, _)) if zcrypt_core::asset_registry::valid_ticker(&ticker) => Ok(()),
                Some((ticker, _, _, _)) => Err(format!("invalid ticker '{ticker}'")),
                None => Err("malformed register tx".to_string()),
            }
        } else if tx.first() == Some(&HTLC_OPEN_TAG) {
            // Well-formed only if the params parse AND the mint authorization decodes.
            match parse_htlc_open(&tx[1..]) {
                Some((.., auth)) if zcrypt_core::mint_auth::decode_auth(&auth).is_some() => Ok(()),
                _ => Err("malformed htlc-open tx".to_string()),
            }
        } else if tx.first() == Some(&ROTATE_AUTH_TAG) {
            match parse_rotate(&tx[1..]) {
                Some((.., auth)) if zcrypt_core::mint_auth::decode_auth(&auth).is_some() => Ok(()),
                _ => Err("malformed rotate-authority tx".to_string()),
            }
        } else if tx.first() == Some(&HTLC_CLAIM_TAG) || tx.first() == Some(&HTLC_EXPIRE_TAG) {
            if parse_escrow_id(&tx[1..]).is_some() { Ok(()) } else { Err("malformed htlc tx".to_string()) }
        } else if tx.first() == Some(&HTLC_BURN_LOCK_TAG) {
            if parse_burn_lock(&tx[1..]).is_some() { Ok(()) } else { Err("malformed htlc-burn-lock tx".to_string()) }
        } else if tx.first() == Some(&SWAP_LOCK_TAG) {
            if parse_swap_lock(&tx[1..]).is_some() { Ok(()) } else { Err("malformed swap-lock tx".to_string()) }
        } else {
            Err(CLASSICAL_DISABLED.to_string()) // classical native path removed
        };
        let name = tag_name(tx.first().copied());
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
        let mut s = self.locked();
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
                        s.node.submit_transfer(CHAIN_ID, &main_tx, &gas_tx, gas_blind)
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
                                state_root: s.node.state_root(),
                            })
                        }
                        None => Err("bad seed".to_string()),
                    }
                }
            } else if bytes.first() == Some(&BOND_TAG) {
                match parse_bond_coin(&bytes[1..]) {
                    Some((addr, pubkey, stake, reward, stake_blind, stx)) => match s.node.bond_with_stake(
                        CHAIN_ID, &stx, stake, stake_blind, addr, pubkey, reward,
                    ) {
                        Ok(()) => Ok(zcrypt_core::node::Receipt {
                            txbind: [0u8; 32],
                            nullifiers: vec![],
                            state_root: s.node.state_root(),
                        }),
                        Err(e) => Err(e),
                    },
                    None => Err("malformed bond tx".to_string()),
                }
            } else if bytes.first() == Some(&UNBOND_TAG) {
                match verify_unbond(&bytes[1..]) {
                    Some(addr) => match s.node.unbond(&addr) {
                        Ok(_released) => Ok(zcrypt_core::node::Receipt {
                            txbind: [0u8; 32],
                            nullifiers: vec![],
                            state_root: s.node.state_root(),
                        }),
                        Err(e) => Err(e),
                    },
                    None => Err("malformed unbond tx".to_string()),
                }
            } else if bytes.first() == Some(&DELEGATE_TAG) {
                match parse_delegate_coin(&bytes[1..]) {
                    Some((target, delegator, stake, reward, stake_blind, stx)) => {
                        match s.node.delegate_with_stake(
                            CHAIN_ID, &stx, stake, stake_blind, target, delegator, reward,
                        ) {
                            Ok(()) => Ok(zcrypt_core::node::Receipt {
                                txbind: [0u8; 32],
                                nullifiers: vec![],
                                state_root: s.node.state_root(),
                            }),
                            Err(e) => Err(e),
                        }
                    }
                    None => Err("malformed delegate tx".to_string()),
                }
            } else if bytes.first() == Some(&UNDELEGATE_TAG) {
                match verify_undelegate(&bytes[1..]) {
                    Some((target, delegator)) => match s.node.undelegate(&target, &delegator) {
                        Ok(_release_time) => Ok(zcrypt_core::node::Receipt {
                            txbind: [0u8; 32],
                            nullifiers: vec![],
                            state_root: s.node.state_root(),
                        }),
                        Err(e) => Err(e),
                    },
                    None => Err("malformed undelegate tx".to_string()),
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
            } else if bytes.first() == Some(&REGISTER_TAG) {
                match parse_register(&bytes[1..]) {
                    Some((ticker, decimals, authority, max_supply)) => {
                        match s.node.register_asset(&ticker, decimals, authority, max_supply) {
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
                }
            } else if bytes.first() == Some(&HTLC_OPEN_TAG) {
                match parse_htlc_open(&bytes[1..])
                    .and_then(|(asset, value, lock, timeout, pk, auth)| {
                        // The trailing bytes are the M-of-N mint authorization (key set +
                        // threshold ML-DSA signatures); decode before gating the mint.
                        zcrypt_core::mint_auth::decode_auth(&auth)
                            .map(|(ks, sigs)| (asset, value, lock, timeout, pk, ks, sigs))
                    }) {
                    Some((asset, value, lock, timeout, pk, keyset, sigs)) => {
                        match s.node.htlc_open(asset, value, lock, timeout, pk, &keyset, &sigs) {
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
                }
            } else if bytes.first() == Some(&ROTATE_AUTH_TAG) {
                match parse_rotate(&bytes[1..]).and_then(|(asset, new_commitment, auth)| {
                    zcrypt_core::mint_auth::decode_auth(&auth)
                        .map(|(ks, sigs)| (asset, new_commitment, ks, sigs))
                }) {
                    Some((asset, new_commitment, keyset, sigs)) => {
                        match s.node.rotate_authority(asset, new_commitment, &keyset, &sigs) {
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
                            CHAIN_ID, &stx, value, blind, asset, lock, timeout, refund_pk,
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
            } else if bytes.first() == Some(&SWAP_LOCK_TAG) {
                match parse_swap_lock(&bytes[1..]) {
                    Some((value, blind, asset, lock, timeout, counterparty_pk, refund_pk, stx)) => {
                        match s.node.swap_lock(
                            CHAIN_ID, &stx, value, blind, asset, lock, timeout, counterparty_pk, refund_pk,
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
                    let data = serde_json::json!({
                        "txbind": hex::encode(receipt.txbind),
                        "nullifiers": receipt.nullifiers.iter().map(hex::encode).collect::<Vec<_>>(),
                        "state_root": hex::encode(receipt.state_root),
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
        s.height = req.height;
        // Dynamic validator set: diff the bonded set across this block and hand
        // CometBFT the resulting add/remove/re-weight updates, so a BOND actually
        // makes a node a block producer and an UNBOND stops it. Deterministic (a pure
        // function of the app-hash-committed staking ledger), so all nodes agree.
        let vset_after = s.node.validator_set();
        let updates = validator_updates(&vset_before, &vset_after);
        if !updates.is_empty() {
            for u in &updates {
                let pk = u.pub_key.as_ref().and_then(|k| match &k.sum {
                    Some(PubKeySum::Ed25519(b)) => Some(hex::encode(b)),
                    _ => None,
                }).unwrap_or_default();
                eprintln!("[validators] height {height}: set {pk} -> power {}", u.power);
            }
        }
        ResponseFinalizeBlock {
            tx_results,
            validator_updates: updates,
            app_hash: s.node.state_root().to_vec().into(),
            ..Default::default()
        }
    }

    fn commit(&self) -> ResponseCommit {
        // Persist the full consensus state at the just-finalized height. The
        // snapshot reflects exactly the state whose `state_root()` was returned as
        // this block's app_hash, so on restart `info()` reports a matching height +
        // app_hash and CometBFT resumes from here instead of replaying from genesis.
        let s = self.locked();
        let bytes = s.node.to_snapshot_bytes(s.height.max(0) as u64);
        if let Err(e) = persist_state(&self.state_path, &bytes) {
            // Log loudly but do NOT panic: each snapshot is a FULL state dump, so the
            // next successful commit re-persists everything, and a hard crash before
            // then simply replays the un-persisted block(s) from CometBFT. Panicking
            // here would instead poison the mutex (killing every later call) over a
            // possibly-transient disk hiccup — strictly worse than a degraded, loud,
            // self-healing mode.
            eprintln!(
                "[state] WARNING: failed to persist state at height {} ({e}); \
                 will retry on the next commit (replays this block if the node restarts first)",
                s.height
            );
        }
        ResponseCommit { retain_height: 0 }
    }

    fn query(&self, req: RequestQuery) -> ResponseQuery {
        let s = self.locked();
        let value: Vec<u8> = match req.path.as_str() {
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
            "/commit/leaves" => {
                // hex of all leaves concatenated, 64 bytes (8×u64 LE) each — the
                // wallet's decoy pool + a way to find its own coin's index.
                let mut b = Vec::new();
                for c in s.node.commitment_leaves() {
                    for x in &c {
                        b.extend_from_slice(&x.to_le_bytes());
                    }
                }
                hex::encode(b).into_bytes()
            }
            // Incremental leaf sync: `/commit/leaves/<from_index>` returns only
            // leaves[from..] so wallets need not re-download the whole tree.
            p if p.starts_with("/commit/leaves/") => {
                let from: usize = p["/commit/leaves/".len()..].parse().unwrap_or(0);
                let leaves = s.node.commitment_leaves();
                let mut b = Vec::new();
                for c in leaves.into_iter().skip(from) {
                    for x in &c {
                        b.extend_from_slice(&x.to_le_bytes());
                    }
                }
                hex::encode(b).into_bytes()
            }
            "/app/hash" => hex::encode(s.node.state_root()).into_bytes(),
            // ---- shielded-asset ticker registry ----
            "/asset/list" => {
                // "<ticker>:<asset_id>:<minted> …"
                let list: Vec<String> = s
                    .node
                    .assets_list()
                    .iter()
                    .map(|m| format!("{}:{}:{}", m.ticker, m.asset_id, m.minted))
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
                // "<addr_hex>:<stake> …" one per bonded validator
                let list: Vec<String> = s
                    .node
                    .validator_set()
                    .iter()
                    .map(|(pk, stake)| format!("{}:{}", hex::encode(pk), stake))
                    .collect();
                list.join(",").into_bytes()
            }
            "/staking/unbonding_total" => {
                // Total stake frozen in the unbonding queue (atomic units).
                s.node.total_unbonding().to_string().into_bytes()
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
                        serde_json::json!({
                            "key": hex::encode(p0.key),
                            "value": hex::encode(p0.value),
                            "included": p0.included,
                            "proof": hex::encode(smt::proof_to_bytes(p0)),
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
    // Where consensus state is persisted between restarts. Override with
    // ZCRYPT_STATE_FILE; defaults to ./zcrypt-state.bin in the working directory.
    let state_path: PathBuf = std::env::var("ZCRYPT_STATE_FILE")
        .unwrap_or_else(|_| "zcrypt-state.bin".to_string())
        .into();
    eprintln!("[state] persisting consensus state to {}", state_path.display());
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
    let app = ZcryptApp::new(state_path);
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

    // Build a signed BOND payload (H1) for consensus key `sk` bonding `stake` to
    // reward address `reward`.
    fn signed_bond(sk: &SigningKey, stake: u64, reward: [u8; 32]) -> Vec<u8> {
        let pubkey = sk.verifying_key().to_bytes();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"ZCRYPT-BOND-v1");
        msg.extend_from_slice(CHAIN_ID);
        msg.extend_from_slice(&pubkey);
        msg.extend_from_slice(&stake.to_le_bytes());
        msg.extend_from_slice(&reward);
        let sig = sk.sign(&msg);
        let mut b = Vec::new();
        b.extend_from_slice(&pubkey);
        b.extend_from_slice(&stake.to_le_bytes());
        b.extend_from_slice(&reward);
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
        let (addr, pubkey, stake, got_reward) = verify_bond(&payload).expect("valid signature accepted");
        assert_eq!(stake, 10_000);
        assert_eq!(got_reward, reward);
        assert_eq!(pubkey, sk.verifying_key().to_bytes().to_vec());
        assert_eq!(addr, Sha256::digest(sk.verifying_key().to_bytes())[..20].to_vec());
    }

    // Build a signed DELEGATE header for delegator key `sk` pledging `stake` toward
    // validator `target` (20-byte address), returns going to `reward`.
    fn signed_delegate_header(sk: &SigningKey, target: &[u8], stake: u64, reward: [u8; 32]) -> Vec<u8> {
        let pubkey = sk.verifying_key().to_bytes();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"ZCRYPT-DELEGATE-v1");
        msg.extend_from_slice(CHAIN_ID);
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

    fn signed_undelegate(sk: &SigningKey, target: &[u8]) -> Vec<u8> {
        let pubkey = sk.verifying_key().to_bytes();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"ZCRYPT-UNDELEGATE-v1");
        msg.extend_from_slice(CHAIN_ID);
        msg.extend_from_slice(&pubkey);
        msg.extend_from_slice(target);
        let sig = sk.sign(&msg);
        let mut b = Vec::new();
        b.extend_from_slice(&pubkey);
        b.extend_from_slice(target);
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
            verify_delegate(&header).expect("valid signature accepted");
        assert_eq!(got_target, target);
        assert_eq!(stake, 5_000);
        assert_eq!(got_reward, reward);
        assert_eq!(delegator, Sha256::digest(sk.verifying_key().to_bytes())[..20].to_vec());

        // The same key signs a matching undelegate → same delegator id (so only they can
        // withdraw their own delegation).
        let (u_target, u_delegator) =
            verify_undelegate(&signed_undelegate(&sk, &target)).expect("valid undelegate");
        assert_eq!(u_target, target);
        assert_eq!(u_delegator, delegator);

        // Tampering with the target after signing breaks authentication.
        let mut forged = header.clone();
        forged[32] ^= 0xFF; // flip a byte of the target address
        assert!(verify_delegate(&forged).is_none(), "tampered target rejected");

        // A different key cannot undelegate this delegation (different delegator id).
        let other = SigningKey::from_bytes(&[10u8; 32]);
        let (_, other_delegator) =
            verify_undelegate(&signed_undelegate(&other, &target)).expect("well-formed");
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
        assert!(verify_bond(&payload).is_none(), "tampered reward address must fail auth");
    }

    #[test]
    fn bond_rejects_forged_stake_and_bad_length() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let mut payload = signed_bond(&sk, 10_000, [2u8; 32]);
        // bump the stake (bytes [32..40]) — signature was over the original stake.
        payload[32] ^= 0x01;
        assert!(verify_bond(&payload).is_none(), "forged stake must fail auth");
        // wrong length is rejected outright.
        assert!(verify_bond(&[0u8; 60]).is_none());
        assert!(verify_bond(&[]).is_none());
    }

    fn signed_unbond(sk: &SigningKey) -> Vec<u8> {
        let pubkey = sk.verifying_key().to_bytes();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"ZCRYPT-UNBOND-v1");
        msg.extend_from_slice(CHAIN_ID);
        msg.extend_from_slice(&pubkey);
        let sig = sk.sign(&msg);
        let mut b = Vec::new();
        b.extend_from_slice(&pubkey);
        b.extend_from_slice(&sig.to_bytes());
        b
    }

    #[test]
    fn unbond_requires_a_valid_signature() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let payload = signed_unbond(&sk);
        let addr = verify_unbond(&payload).expect("valid unbond accepted");
        assert_eq!(addr, Sha256::digest(sk.verifying_key().to_bytes())[..20].to_vec());
        // Tampering the pubkey (so the sig no longer matches) is rejected.
        let mut bad = payload.clone();
        bad[0] ^= 0xff;
        assert!(verify_unbond(&bad).is_none());
        assert!(verify_unbond(&[0u8; 50]).is_none(), "wrong length rejected");
    }

    #[test]
    fn seed_tx_is_disabled_in_production_builds() {
        // C3: without the `devnet` feature, the unbacked coin-injection tx is off.
        assert_eq!(SEED_ENABLED, cfg!(feature = "devnet"));
        #[cfg(not(feature = "devnet"))]
        assert!(!SEED_ENABLED, "SEED must be disabled unless devnet is explicitly enabled");
    }

    #[test]
    fn mutex_poisoning_does_not_cascade() {
        // The cascade: a panic while holding the state lock poisons the mutex, after
        // which a raw `lock().unwrap()` panics forever — one fault kills the whole
        // node. `locked()` must recover the guard so later calls keep working.
        let path = std::env::temp_dir().join(format!("zcrypt-poison-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let app = ZcryptApp::new(path);
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
    }

    #[test]
    fn persist_and_restart_resumes_at_same_height_and_app_hash() {
        // Simulate a full restart: build + persist state, then load it as a fresh
        // process would. The resumed node must report the same height and app_hash,
        // so CometBFT replays only new blocks (not the whole chain from genesis).
        let mut node = Node::new();
        node.mint_foundation([0xF0; 32]);
        node.set_height(42);
        for k in 0..8u64 {
            node.seed_coin([k + 100; 8]);
        }
        let app_hash_before = node.state_root();

        let path = std::env::temp_dir().join(format!("zcrypt-test-state-{}.bin", std::process::id()));
        persist_state(&path, &node.to_snapshot_bytes(42)).unwrap();

        let (resumed, height) = load_state(&path).expect("state file present");
        assert_eq!(height, 42, "resumed at the persisted height");
        assert_eq!(resumed.state_root(), app_hash_before, "app_hash survives restart");

        // A missing file is a fresh chain, not an error.
        let _ = std::fs::remove_file(&path);
        assert!(load_state(&path).is_none());
    }
}
