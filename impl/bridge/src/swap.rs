//! Cross-chain BTC↔zBTC atomic-swap orchestration.
//!
//! One SHA-256 preimage settles both legs: a Bitcoin HTLC and a ZCrypt shield HTLC
//! escrow. The bridge reads the preimage *from whichever chain reveals it first*
//! and uses it to settle the other, so neither side can take without giving.

use bitcoin::{Address, Amount, OutPoint, PublicKey};
use zcrypt_core::keys::{Account, Coin};
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_core::shield_tx::{self, Spend};
use zcrypt_core::spv::MintProof;
use zcrypt_shield::{Commitment, OutCoin, PubKey};

use crate::zcrypt::Zcrypt;
use crate::{htlc_script, BtcBackend, HtlcUtxo, Key};

pub const CHAIN: &[u8] = b"zcrypt-1";

// =============================================================================
// Race-hardened HTLC timing
//
// Integrity goal (BTC→zBTC): after a *worst-case late* ZC claim, enough Bitcoin
// blocks remain before the user's CLTV refund that the operator can always sweep
// (including waiting for SPV safe_sweep depth and fee bumps) — unless the hot
// key itself is compromised (out of scope here).
//
// Inequality enforced at open (see [`required_btc_lock_blocks`]):
//   BTC_lock >= max(
//     spv_locktime_margin,
//     zc_claim_window_in_btc_blocks + operator_sweep_sla,
//     max_safe_sweep_depth + operator_sweep_sla,
//   )
// Profiles differ by network; mainnet is the strict production schedule.
// =============================================================================

/// Assumed ZCrypt block time (seconds). Used only to convert wall budgets → ZC heights.
pub const ZC_BLOCK_TIME_SECS: u64 = 1;
/// Assumed Bitcoin block time (seconds) for wall-clock → block conversions.
pub const BTC_BLOCK_TIME_SECS: u64 = 600;

/// Default / mainnet-oriented wall budgets (also used by legacy const aliases).
/// BTC refund CLTV: 7 days — large buffer after late claim + maturity wait.
pub const BTC_HTLC_LOCK_SECS: u64 = 7 * 24 * 3600;
/// ZC claim window (BTC→zBTC): 36 hours — bounds how late a user can reveal.
pub const ZC_HTLC_CLAIM_SECS: u64 = 36 * 3600;
/// Extra ZC lifetime on redeem burns beyond the BTC operator lock (~48h finalize margin).
pub const ZC_REDEEM_EXTRA_SECS: u64 = 48 * 3600;

/// Mainnet default ZC shield timeout in blocks (legacy alias for callers/tests).
pub const ZC_HTLC_TIMEOUT_BLOCKS: u64 = ZC_HTLC_CLAIM_SECS / ZC_BLOCK_TIME_SECS;
/// Mainnet default ZC redeem (burn) timeout in blocks.
pub const ZC_REDEEM_TIMEOUT_BLOCKS: u64 =
    (BTC_HTLC_LOCK_SECS + ZC_REDEEM_EXTRA_SECS) / ZC_BLOCK_TIME_SECS;
/// Mainnet default BTC HTLC refund offset from tip (blocks).
pub const BTC_HTLC_LOCKTIME_BLOCKS: u64 = BTC_HTLC_LOCK_SECS / BTC_BLOCK_TIME_SECS;

/// Soft alert: refund CLTV within this many BTC blocks of tip → page operator.
pub const LOCKTIME_ALERT_BLOCKS: u64 = 144; // ~1 day mainnet
/// Hard alert: refund imminent — watcher should treat as emergency + pause new shields.
pub const LOCKTIME_HARD_BLOCKS: u64 = 72; // ~12 hours mainnet
/// Minimum BTC blocks that must remain after a worst-case late ZC claim for the operator
/// to broadcast + confirm a sweep (fee spikes / brief outage).
pub const OPERATOR_SWEEP_SLA_BLOCKS: u64 = 144; // ~1 day mainnet

const _: () = assert!(ZC_HTLC_CLAIM_SECS + 24 * 3600 < BTC_HTLC_LOCK_SECS);
const _: () = assert!(ZC_REDEEM_TIMEOUT_BLOCKS * ZC_BLOCK_TIME_SECS > BTC_HTLC_LOCK_SECS);
const _: () = assert!(BTC_HTLC_LOCKTIME_BLOCKS >= 144); // ≥ mainnet SPV locktime_margin
const _: () = assert!(LOCKTIME_HARD_BLOCKS < LOCKTIME_ALERT_BLOCKS);

/// Map a bitcoin crate network to the consensus SPV network enum.
pub fn spv_net(network: bitcoin::Network) -> zcrypt_core::spv::BtcNet {
    match network {
        bitcoin::Network::Bitcoin => zcrypt_core::spv::BtcNet::Mainnet,
        bitcoin::Network::Signet => zcrypt_core::spv::BtcNet::Signet,
        _ => zcrypt_core::spv::BtcNet::Regtest,
    }
}

/// Wall-clock ZC claim budget (seconds) for shields on this Bitcoin network.
pub fn zc_claim_secs(network: bitcoin::Network) -> u64 {
    match network {
        bitcoin::Network::Bitcoin => ZC_HTLC_CLAIM_SECS, // 36h
        bitcoin::Network::Signet => 12 * 3600,           // 12h — faster iteration, still staggered
        _ => 2 * 3600,                                   // regtest: short but > maturity waits
    }
}

/// BTC blocks from tip to HTLC refund CLTV for **shield** deposits on this network.
pub fn btc_lock_blocks(network: bitcoin::Network) -> u64 {
    match network {
        bitcoin::Network::Bitcoin => BTC_HTLC_LOCKTIME_BLOCKS, // 1008 ≈ 7d
        bitcoin::Network::Signet => 504,                       // ≈ 3.5d
        _ => 100,                                              // regtest: > SPV margin (20), e2e-friendly
    }
}

/// BTC blocks from tip to refund CLTV when the **operator** locks BTC for a redeem.
/// Shorter than shield locks so capital recycles; still leaves the user time to claim.
pub fn btc_redeem_lock_blocks(network: bitcoin::Network) -> u64 {
    match network {
        bitcoin::Network::Bitcoin => 504, // ≈ 3.5d
        bitcoin::Network::Signet => 288,  // ≈ 2d
        _ => 50,
    }
}

/// Minimum BTC lock length that keeps the race safe on `network` (worst-case late claim
/// + max safe_sweep deferral + operator SLA). Open paths must use ≥ this.
pub fn required_btc_lock_blocks(network: bitcoin::Network) -> u64 {
    let net = spv_net(network);
    let spv_margin = match net {
        zcrypt_core::spv::BtcNet::Mainnet => 144,
        _ => 20,
    };
    let max_sweep = zcrypt_core::spv::safe_sweep_conf(net, u64::MAX);
    let zc_as_btc = (zc_claim_secs(network) + BTC_BLOCK_TIME_SECS - 1) / BTC_BLOCK_TIME_SECS;
    let sla = match network {
        bitcoin::Network::Bitcoin => OPERATOR_SWEEP_SLA_BLOCKS,
        bitcoin::Network::Signet => 36,
        _ => 10,
    };
    // Late claim: BTC advanced ~zc_as_btc; remaining must still cover SLA.
    let for_late_claim = zc_as_btc.saturating_add(sla);
    // Early claim: may defer sweep until max_sweep confs; then need SLA to confirm.
    let for_early_claim = max_sweep.saturating_add(sla);
    spv_margin.max(for_late_claim).max(for_early_claim)
}

/// Refuse a shield BTC locktime that cannot absorb late claim + maturity + sweep SLA.
pub fn assert_safe_shield_locktime(
    network: bitcoin::Network,
    tip: u64,
    btc_locktime: u32,
) -> Result<(), String> {
    let need = required_btc_lock_blocks(network);
    let have = (btc_locktime as u64).saturating_sub(tip);
    if have < need {
        return Err(format!(
            "BTC HTLC refund locktime too soon: {have} blocks after tip {tip} \
             (locktime {btc_locktime}); need ≥ {need} for race-safe shield on {network:?} \
             (SPV margin + late-claim window + safe_sweep + operator SLA)"
        ));
    }
    let profile = btc_lock_blocks(network);
    if have < profile {
        return Err(format!(
            "BTC HTLC refund locktime below network profile: {have} < {profile} blocks \
             after tip (use tip + btc_lock_blocks({network:?}))"
        ));
    }
    Ok(())
}

/// Compute shield HTLC CLTV and ZC escrow timeout for the current tips.
pub fn shield_timeouts(
    network: bitcoin::Network,
    btc_tip: u64,
    zc_tip: u64,
) -> Result<(u32, u64), String> {
    let lock_blocks = btc_lock_blocks(network);
    let btc_locktime = btc_tip
        .checked_add(lock_blocks)
        .ok_or("btc tip + lock overflow")? as u32;
    assert_safe_shield_locktime(network, btc_tip, btc_locktime)?;
    let zc_timeout = zc_tip
        .checked_add(zc_claim_secs(network) / ZC_BLOCK_TIME_SECS)
        .ok_or("zc tip + claim window overflow")?;
    Ok((btc_locktime, zc_timeout))
}

/// ZC burn-escrow lifetime (blocks) for redeems on this network.
pub fn zc_redeem_timeout_blocks(network: bitcoin::Network) -> u64 {
    let btc_secs = btc_redeem_lock_blocks(network) * BTC_BLOCK_TIME_SECS;
    let extra = match network {
        bitcoin::Network::Bitcoin => ZC_REDEEM_EXTRA_SECS,
        bitcoin::Network::Signet => 12 * 3600,
        _ => 3600,
    };
    (btc_secs + extra) / ZC_BLOCK_TIME_SECS
}

/// Approx vsize (vbytes) of a 1-input P2WSH HTLC claim/refund spend paying one P2WPKH
/// output: ~82 non-witness bytes + a witness of (signature, preimage, selector, redeem
/// script). Rounded up so the fee never underpays.
const HTLC_SPEND_VSIZE: u64 = 200;

/// Dynamic fee for an HTLC claim/refund spend, from the backend's fee estimator, so the
/// spend confirms before its CLTV timelock. Replaces a flat 2000-sat fee that could sit
/// below the mempool min-relay rate on a busy mainnet and strand the swap. `target` is the
/// desired confirmation window in blocks; a 500-sat floor keeps tiny-mempool cases relayable.
fn htlc_spend_fee(backend: &dyn BtcBackend, target: u32) -> Result<Amount, String> {
    let rate = backend.fee_rate_sat_vb(target)?.max(1.0);
    let sats = (rate * HTLC_SPEND_VSIZE as f64).ceil() as u64;
    Ok(Amount::from_sat(sats.max(500)))
}

// ---- ZCrypt tx payload builders (match the ABCI tags) ----

fn pk_bytes(pk: &PubKey) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    for x in pk {
        b.extend_from_slice(&x.to_le_bytes());
    }
    b
}

/// Build the GAS PREFIX state-creating txs (REGISTER 0x59, HTLC_OPEN 0x5A) must carry:
/// `gas_blind(32) ‖ gas_len(u32 LE) ‖ gas_tx`, where `gas_tx` is a ZCRYPT shield spend of
/// `gas_coin` (owned by `gas_owner`) whose output[0] burns exactly MIN_FEE ZCRYPT and whose
/// change returns to `gas_owner`. Exactly the gas note a 0x55 transfer bundles. Consensus
/// rejects these tags without it (they used to be free: consensus H1).
pub fn build_gas_prefix(zc: &Zcrypt, gas_owner: &Account, gas_coin: &Coin) -> Result<Vec<u8>, String> {
    let min_fee = zcrypt_core::emission::MIN_FEE;
    if gas_coin.value < min_fee {
        return Err("gas coin is below the minimum fee".to_string());
    }
    let gas_blind = zcrypt_core::keys::random_blind();
    let burn: OutCoin = (min_fee, gas_blind, zcrypt_core::htlc_shield::BURN_PK, zcrypt_shield::ASSET_ZCRYPT);
    let chg_val = gas_coin.value - min_fee;
    let chg_blind = zcrypt_core::keys::random_blind();
    let chg = zcrypt_core::keys::out_coin(&gas_owner.normal_address(), chg_val, chg_blind);
    let chg_note = zcrypt_core::kem::ciphertext_to_bytes(&zcrypt_core::keys::encrypt_note(
        &gas_owner.normal_address(),
        chg_val,
        chg_blind,
    ));
    let gas_tx = build_shield_spend(
        zc,
        &[gas_coin.clone()],
        &[burn, chg],
        0,
        vec![zcrypt_core::keys::cover_note_bytes(), chg_note],
    )?;
    let gas_bytes = shield_tx::to_bytes(&gas_tx);
    let mut out = Vec::with_capacity(36 + gas_bytes.len());
    for limb in gas_blind {
        out.extend_from_slice(&limb.to_le_bytes());
    }
    out.extend_from_slice(&(gas_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&gas_bytes);
    Ok(out)
}

/// Build a REGISTER tx (0x59). `gas` is the encoded gas prefix from [`build_gas_prefix`].
pub fn register_tx(ticker: &str, decimals: u8, authority: &[u8; 32], max_supply: u64, gas: &[u8]) -> Vec<u8> {
    let mut t = vec![0x59u8];
    t.extend_from_slice(gas);
    t.push(decimals);
    t.push(ticker.len() as u8);
    t.extend_from_slice(ticker.as_bytes());
    t.extend_from_slice(&max_supply.to_le_bytes());
    t.extend_from_slice(authority);
    t
}

/// Register an **SPV-gated** asset (zBTC): the 33-byte compressed Bitcoin reserve
/// pubkey is the trailing payload, and CONSENSUS derives the authority
/// `spv_authority(reserve_pk)` from it — minting is then possible only via a
/// verified Bitcoin deposit claimable by that reserve key. zBTC is *required* to
/// be registered this way (the node rejects any discretionary-authority zBTC).
///
/// NOTE: on a launched chain zBTC is pinned in GENESIS (`zbtc_reserve_pk`), never by this
/// tx; the ticker then fails as "already registered". `gas` is the encoded gas prefix from
/// [`build_gas_prefix`] (an empty prefix is rejected by consensus).
pub fn register_spv_tx(ticker: &str, decimals: u8, reserve_pk: &[u8; 33], max_supply: u64, gas: &[u8]) -> Vec<u8> {
    let mut t = vec![0x59u8];
    t.extend_from_slice(gas);
    t.push(decimals);
    t.push(ticker.len() as u8);
    t.extend_from_slice(ticker.as_bytes());
    t.extend_from_slice(&max_supply.to_le_bytes());
    t.extend_from_slice(reserve_pk);
    t
}

/// Build a Bitcoin header-relay tx (0x63): concatenated raw 80-byte headers.
pub fn headers_tx(headers: &[u8]) -> Vec<u8> {
    let mut t = vec![0x63u8];
    t.extend_from_slice(headers);
    t
}

/// Build a BTC re-anchor tx (0x65): a fresh SPV proof for a deposit that a benign reorg
/// re-mined into a new block, so its immature mint follows the deposit instead of being
/// voided. Payload = the encoded [`zcrypt_core::spv::MintProof`].
pub fn reanchor_tx(proof: &zcrypt_core::spv::MintProof) -> Vec<u8> {
    let mut t = vec![0x65u8];
    t.extend_from_slice(&proof.to_bytes());
    t
}

/// Build an **SPV-gated** mint-escrow open tx (0x64). `proof` is the Bitcoin deposit proof
/// every validator re-verifies against the consensus header chain. `refund` is the deposit's
/// HTLC refund key: its ECDSA signature over (outpoint ‖ claim_pk) AUTHORIZES this recipient
/// (H1), so a third party cannot front-run the public proof to mint to a different key.
pub fn open_spv_tx(
    asset: u64,
    value: u64,
    lock: &[u8; 32],
    timeout: u64,
    claim_pk: &PubKey,
    proof: &zcrypt_core::spv::MintProof,
    refund: &Key,
) -> Vec<u8> {
    let mut t = vec![0x64u8];
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(&value.to_le_bytes());
    t.extend_from_slice(lock);
    t.extend_from_slice(&timeout.to_le_bytes());
    t.extend_from_slice(&pk_bytes(claim_pk));
    // Recipient binding, extended to EVERY open parameter: the refund key signs the chain,
    // outpoint, claim_pk, asset, value, hashlock and timeout, so a mempool front-runner can
    // neither redirect the mint nor open it as a 1-sat / already-expired escrow.
    let txid = proof.funding_txid().expect("open_spv_tx: proof carries a valid funding tx");
    let mut op = [0u8; 36];
    op[..32].copy_from_slice(&txid);
    op[32..].copy_from_slice(&proof.vout.to_le_bytes());
    let a = zcrypt_core::spv::OpenAuth {
        chain_id: CHAIN,
        outpoint: &op,
        claim_pk,
        asset_id: asset,
        value,
        hashlock: lock,
        timeout_height: timeout,
    };
    let auth = zcrypt_core::spv::sign_open_auth(&refund.sk, &a);
    t.extend_from_slice(&auth);
    t.extend_from_slice(&proof.to_bytes());
    t
}

/// Headers per relay tx (500 × 80 B = 40 KB, comfortably inside CometBFT's tx cap).
const HEADER_BATCH: usize = 500;

/// Wait until all SPV-minted zBTC has MATURED into spendable coins. Because a mint is
/// held immature (out of the spendable pool, reorg-voidable) until its Bitcoin deposit
/// is buried past reorg risk, a freshly-shielded coin cannot be spent/redeemed
/// immediately — the caller must first let the deposit reach `maturity_conf` depth.
/// This helper does that: on regtest it MINES the extra blocks (via `mine`), relays the
/// new headers, and polls the chain's `/spv/pending` until it clears. On a real network
/// there is no `mine` — you simply wait for real blocks (this returns once enough have
/// arrived and been relayed). `mine` is `Some` only for the self-mining regtest backend.
pub fn wait_for_maturity(
    zc: &Zcrypt,
    btc: &dyn crate::BtcBackend,
    mine: Option<&dyn Fn(u64) -> Result<(), String>>,
    extra_blocks: u64,
) -> Result<(), String> {
    if let Some(m) = mine {
        m(extra_blocks)?; // regtest: bury the deposits past maturity_conf
    }
    relay_btc_headers(zc, btc)?;
    // The chain matures deposits once per block (~1s); poll until nothing is pending.
    for _ in 0..120 {
        let pending = zc.query("/spv/pending").unwrap_or_default();
        if pending.trim().starts_with("0:") || pending.trim().is_empty() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err("timed out waiting for SPV mints to mature".to_string())
}

/// Catch the consensus SPV chain up to `btc`'s current tip: query the chain's
/// `/spv/height`, fetch every missing header from the (untrusted) backend, and
/// relay them in batches. Idempotent and race-safe — duplicate headers are
/// consensus no-ops. Returns the chain's new Bitcoin tip height.
pub fn relay_btc_headers(zc: &Zcrypt, btc: &dyn crate::BtcBackend) -> Result<u64, String> {
    let chain_tip: u64 = zc
        .query("/spv/height")?
        .trim()
        .parse()
        .map_err(|e| format!("bad /spv/height: {e}"))?;
    let btc_tip = btc.height()?;
    if btc_tip <= chain_tip {
        return Ok(chain_tip);
    }
    let mut batch = Vec::with_capacity(HEADER_BATCH * 80);
    for h in (chain_tip + 1)..=btc_tip {
        batch.extend_from_slice(&btc.block_header(h)?);
        if batch.len() >= HEADER_BATCH * 80 {
            zc.broadcast(&headers_tx(&batch))?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        zc.broadcast(&headers_tx(&batch))?;
    }
    Ok(btc_tip)
}

/// Build a mint-escrow open tx (0x5A). `auth` is the encoded M-of-N mint authorization
/// (key set + threshold ML-DSA signatures over these exact params) from
/// [`zcrypt_core::mint_auth::encode_auth`] — no secret is ever placed on-chain.
/// `gas` is the encoded gas prefix from [`build_gas_prefix`].
pub fn open_tx(asset: u64, value: u64, lock: &[u8; 32], timeout: u64, claim_pk: &PubKey, auth: &[u8], gas: &[u8]) -> Vec<u8> {
    let mut t = vec![0x5Au8];
    t.extend_from_slice(gas);
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(&value.to_le_bytes());
    t.extend_from_slice(lock);
    t.extend_from_slice(&timeout.to_le_bytes());
    t.extend_from_slice(&pk_bytes(claim_pk));
    t.extend_from_slice(auth);
    t
}

/// Build an authority-rotation tx (0x61): swap asset `asset`'s mint authority to
/// `new_commitment` (the commitment of the NEW key set). `auth` is the encoded threshold
/// authorization from the CURRENT key set ([`zcrypt_core::mint_auth::encode_auth`]) over the
/// rotation message. This is how a treasury moves to distributed custody without a chain reset.
pub fn rotate_tx(asset: u64, new_commitment: &[u8; 32], auth: &[u8]) -> Vec<u8> {
    let mut t = vec![0x61u8];
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(new_commitment);
    t.extend_from_slice(auth);
    t
}

pub fn claim_tx(escrow_id: &[u8; 32], preimage: &[u8]) -> Vec<u8> {
    let mut t = vec![0x5Bu8];
    t.extend_from_slice(escrow_id);
    t.extend_from_slice(preimage);
    t
}

/// Build an HTLC-expire tx (0x5C): close a timed-out escrow. A timed-out **burn**
/// escrow refunds its locked zBTC back to the owner (reconstruct the refunded coin
/// with `Account::htlc_coin(value, asset, escrow_id)`).
pub fn expire_tx(escrow_id: &[u8; 32]) -> Vec<u8> {
    let mut t = vec![0x5Cu8];
    t.extend_from_slice(escrow_id);
    t
}

/// The ONLY HTLC preimage length consensus (and the Bitcoin script's `OP_SIZE 32`) accepts.
/// A short preimage is brute-forceable from the public hashlock; a long one can never be
/// pushed as a Bitcoin witness element, so the reserve could never sweep the deposit.
pub const PREIMAGE_LEN: usize = zcrypt_core::htlc_shield::HTLC_PREIMAGE_LEN;
/// Legacy alias (the minimum is now also the maximum).
pub const MIN_PREIMAGE_LEN: usize = PREIMAGE_LEN;

/// Generate a fresh, unguessable 32-byte HTLC preimage from OS entropy. Swaps MUST
/// use this (or another CSPRNG source) rather than a fixed/guessable string.
pub fn fresh_preimage() -> [u8; 32] {
    use rand::RngCore;
    let mut p = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut p);
    p
}

pub fn burn_lock_tx(
    value: u64,
    blind: &[u64; 4],
    asset: u64,
    lock: &[u8; 32],
    timeout: u64,
    refund_pk: &PubKey,
    stx: &shield_tx::ShieldTx,
) -> Vec<u8> {
    let mut t = vec![0x5Du8];
    t.extend_from_slice(&value.to_le_bytes());
    for limb in blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(lock);
    t.extend_from_slice(&timeout.to_le_bytes());
    t.extend_from_slice(&pk_bytes(refund_pk));
    t.extend_from_slice(&shield_tx::to_bytes(stx));
    t
}

/// Like [`burn_lock_tx`] but tagged `0x67` and carrying the user's 33-byte Bitcoin claim pubkey
/// up front, so the operator's redeem watcher reads the payout key from the ON-CHAIN tx (which
/// the escrow owner authored by spending their zBTC) instead of trusting an off-chain value. It
/// creates the IDENTICAL burn escrow — the pubkey is opaque to consensus.
#[allow(clippy::too_many_arguments)]
pub fn burn_lock_btc_tx(
    btc_claim_pk: &PublicKey,
    value: u64,
    blind: &[u64; 4],
    asset: u64,
    lock: &[u8; 32],
    timeout: u64,
    refund_pk: &PubKey,
    stx: &shield_tx::ShieldTx,
) -> Vec<u8> {
    let mut t = vec![0x67u8];
    t.extend_from_slice(&btc_claim_pk.inner.serialize()); // 33 bytes, compressed secp256k1
    // The 0x5D burn-lock body (everything after its tag), byte-identical.
    t.extend_from_slice(&value.to_le_bytes());
    for limb in blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(lock);
    t.extend_from_slice(&timeout.to_le_bytes());
    t.extend_from_slice(&pk_bytes(refund_pk));
    t.extend_from_slice(&shield_tx::to_bytes(stx));
    t
}

/// Parse a `0x67` burn-lock-with-btc-key tx body (bytes AFTER the tag) into the fields the redeem
/// watcher needs: the user's BTC claim pubkey (33B), asset, value, hashlock, timeout, refund_pk.
/// (The trailing shield_tx isn't needed operator-side.) Fail-closed on malformed input.
pub fn parse_burn_lock_btc(payload: &[u8]) -> Option<([u8; 33], u64, u64, [u8; 32], u64, PubKey)> {
    // btc_claim_pk(33) ‖ value(8) ‖ blind(32) ‖ asset(8) ‖ hashlock(32) ‖ timeout(8) ‖ refund_pk(64) ‖ stx
    const HEAD: usize = 33 + 8 + 32 + 8 + 32 + 8 + 64;
    if payload.len() < HEAD {
        return None;
    }
    let btc_claim_pk: [u8; 33] = payload[0..33].try_into().ok()?;
    let value = u64::from_le_bytes(payload[33..41].try_into().ok()?);
    // payload[41..73] is the blind — not needed operator-side.
    let asset = u64::from_le_bytes(payload[73..81].try_into().ok()?);
    let hashlock: [u8; 32] = payload[81..113].try_into().ok()?;
    let timeout = u64::from_le_bytes(payload[113..121].try_into().ok()?);
    let mut refund_pk: PubKey = [0u64; 8];
    for (i, limb) in refund_pk.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(payload[121 + i * 8..129 + i * 8].try_into().ok()?);
    }
    Some((btc_claim_pk, asset, value, hashlock, timeout, refund_pk))
}

/// Build a swap-lock tx (0x62): lock existing coins into a swap escrow. Like a burn-lock
/// but with TWO keys — `counterparty_pk` (claims with the preimage) and `refund_pk` (the
/// locker, refunded on timeout). Two of these across two assets, one hashlock, = an atomic
/// in-pool swap. `stx`'s output[0] must be `commit_asset(value, blind, BURN_PK, asset)`.
#[allow(clippy::too_many_arguments)]
pub fn swap_lock_tx(
    value: u64,
    blind: &[u64; 4],
    asset: u64,
    lock: &[u8; 32],
    timeout: u64,
    counterparty_pk: &PubKey,
    refund_pk: &PubKey,
    stx: &shield_tx::ShieldTx,
) -> Vec<u8> {
    let mut t = vec![0x62u8];
    t.extend_from_slice(&value.to_le_bytes());
    for limb in blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(lock);
    t.extend_from_slice(&timeout.to_le_bytes());
    t.extend_from_slice(&pk_bytes(counterparty_pk));
    t.extend_from_slice(&pk_bytes(refund_pk));
    t.extend_from_slice(&shield_tx::to_bytes(stx));
    t
}

pub fn seed_tx(c: &Commitment) -> Vec<u8> {
    let mut t = vec![0x56u8];
    for x in c {
        t.extend_from_slice(&x.to_le_bytes());
    }
    t
}

fn escrow_id_from(data: &str) -> Result<[u8; 32], String> {
    let v: serde_json::Value = serde_json::from_str(data).map_err(|e| e.to_string())?;
    let hexs = v["escrow_id"].as_str().ok_or("no escrow_id in tx result")?;
    let raw = hex::decode(hexs).map_err(|e| e.to_string())?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&raw);
    Ok(id)
}

fn find_index(leaves: &[Commitment], c: &Commitment) -> Option<u32> {
    leaves.iter().position(|x| x == c).map(|i| i as u32)
}

/// Build a shield spend of `coins` (1..=N_IN, same asset) with the given outputs.
/// Each coin is proven a real leaf of the shielded pool via its Merkle path, so the
/// spend hides among the whole tree — no ring selection.
pub fn build_shield_spend(
    zc: &Zcrypt,
    coins: &[Coin],
    outputs: &[OutCoin; 2],
    fee: u64,
    notes: Vec<Vec<u8>>,
) -> Result<shield_tx::ShieldTx, String> {
    build_shield_spend_bound(zc, coins, outputs, fee, notes, &[])
}

/// [`build_shield_spend`] with the proof additionally bound to an escrow-lock `envelope`
/// (`zcrypt_core::htlc_shield::lock_envelope`). Every lock transaction must use this: the
/// envelope carries the lock parameters in plaintext next to the proof, and binding them is
/// what stops a mempool front-runner from replaying the proof with the payout redirected to
/// themselves. Consensus rebuilds the same envelope and rejects the spend if it disagrees, so
/// the envelope passed here must match the one in the broadcast transaction exactly.
pub fn build_shield_spend_bound(
    zc: &Zcrypt,
    coins: &[Coin],
    outputs: &[OutCoin; 2],
    fee: u64,
    notes: Vec<Vec<u8>>,
    envelope: &[u8],
) -> Result<shield_tx::ShieldTx, String> {
    let leaves = zc.leaves()?;
    // Rebuild the commitment tree from the current leaves so we can produce each
    // coin's Merkle authentication path (L1). The resulting root is the node's
    // current root, so the proof anchors on an anchor the node will recognize.
    let mut tree = zcrypt_shield::tree::CommitmentTree::new();
    for &c in &leaves {
        tree.append(c);
    }
    let mut spends = Vec::new();
    for coin in coins {
        let idx = find_index(&leaves, &coin.commitment()).ok_or("input coin not on chain")?;
        let (path_siblings, path_dirs) =
            tree.path(idx as usize).ok_or("input coin not in commitment tree")?;
        spends.push(Spend {
            value: coin.value,
            blind: coin.blind,
            spend_secret: coin.spend_secret,
            asset_id: coin.asset_id,
            path_siblings,
            path_dirs,
        });
    }
    shield_tx::build_bound(CHAIN, &spends, outputs, fee, notes, envelope)
        .ok_or("shield proof failed".to_string())
}

/// Build a bundled `0x55` SHIELD **transfer**: the main transfer (no in-tx fee — the
/// moved asset is never burned) plus a ZCRYPT **gas note** that burns exactly `MIN_FEE`
/// ZCRYPT (spending `gas_coin`, owned by `gas_owner`, change back to it). So ZCRYPT is
/// the gas even when `main_inputs` are a hidden non-ZCRYPT asset like zBTC or GOLD.
/// Returns the full tx bytes including the `0x55` tag.
pub fn build_transfer(
    zc: &Zcrypt,
    main_inputs: &[Coin],
    main_outs: &[OutCoin; 2],
    main_notes: Vec<Vec<u8>>,
    gas_owner: &Account,
    gas_coin: &Coin,
) -> Result<Vec<u8>, String> {
    let min_fee = zcrypt_core::emission::MIN_FEE;
    if gas_coin.value < min_fee {
        return Err("gas coin is below the minimum fee".to_string());
    }
    // Main transfer: no in-tx fee.
    let main_tx = build_shield_spend(zc, main_inputs, main_outs, 0, main_notes)?;
    // ZCRYPT gas note: output[0] burns MIN_FEE, output[1] is change back to gas_owner.
    let gas_blind = zcrypt_core::keys::random_blind();
    let burn: OutCoin = (
        min_fee,
        gas_blind,
        zcrypt_core::htlc_shield::BURN_PK,
        zcrypt_shield::ASSET_ZCRYPT,
    );
    let chg_val = gas_coin.value - min_fee;
    let chg_blind = zcrypt_core::keys::random_blind();
    let chg = zcrypt_core::keys::out_coin(&gas_owner.normal_address(), chg_val, chg_blind);
    let chg_note = zcrypt_core::kem::ciphertext_to_bytes(&zcrypt_core::keys::encrypt_note(
        &gas_owner.normal_address(),
        chg_val,
        chg_blind,
    ));
    let gas_tx = build_shield_spend(
        zc,
        &[gas_coin.clone()],
        &[burn, chg],
        0,
        vec![zcrypt_core::keys::cover_note_bytes(), chg_note],
    )?;
    // Bundle: 0x55 ‖ gas_blind(32) ‖ gas_len(4) ‖ gas_tx ‖ main_tx.
    let gas_bytes = shield_tx::to_bytes(&gas_tx);
    let main_bytes = shield_tx::to_bytes(&main_tx);
    let mut out = vec![0x55u8];
    for limb in gas_blind {
        out.extend_from_slice(&limb.to_le_bytes());
    }
    out.extend_from_slice(&(gas_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&gas_bytes);
    out.extend_from_slice(&main_bytes);
    Ok(out)
}

/// Parse a bundled transfer payload (the bytes AFTER the `0x55` tag) into
/// `(gas_tx, main_tx)`, for scanning received coins. Mirrors the node's parser.
pub fn parse_transfer_payload(b: &[u8]) -> Option<(shield_tx::ShieldTx, shield_tx::ShieldTx)> {
    if b.len() < 36 {
        return None;
    }
    let gas_len = u32::from_le_bytes(b[32..36].try_into().ok()?) as usize;
    let gas_end = 36usize.checked_add(gas_len)?;
    if b.len() < gas_end {
        return None;
    }
    let gas_tx = shield_tx::from_bytes(&b[36..gas_end])?;
    let main_tx = shield_tx::from_bytes(&b[gas_end..])?;
    Some((gas_tx, main_tx))
}

pub struct BtcParams<'a> {
    /// Alice's Bitcoin backend (the user). Any [`BtcBackend`] — a node-free self-custody
    /// wallet on an Esplora API in production, or a local node for regtest/dev.
    pub alice: &'a dyn BtcBackend,
    /// The bridge/LP's Bitcoin backend — a *distinct* wallet, so Alice's BTC really
    /// leaves on shield and really arrives on redeem. Also any [`BtcBackend`].
    pub bridge: &'a dyn BtcBackend,
    pub bridge_key: &'a Key,
    pub alice_key: &'a Key,
    pub alice_dest: &'a Address,  // where Alice receives BTC (redeem)
    pub bridge_dest: &'a Address, // where the bridge receives BTC (shield)
}

/// **BTC → zBTC.** Alice locks BTC claimable by the pinned reserve key; the SPV
/// proof of that deposit (headers + merkle inclusion) is what mints zBTC into a
/// shield HTLC escrow to her — no treasury, no signers, nothing trusted. Alice
/// reveals the preimage claiming zBTC; the reserve reads it on-chain and sweeps
/// the BTC (reserves grow 1:1 with supply). Returns Alice's new zBTC coin.
#[allow(clippy::too_many_arguments)]
pub fn btc_to_zbtc(
    zc: &Zcrypt,
    b: &BtcParams,
    alice: &Account,
    asset: u64,
    preimage: &[u8],
    btc_amount: Amount,
    zbtc_value: u64,
) -> Result<Coin, String> {
    btc_to_zbtc_progress(zc, b, alice, asset, preimage, btc_amount, zbtc_value, &|_, _| {})
}

/// Like [`btc_to_zbtc`] but reports each atomic-swap step via `progress(percent, phase)`
/// so a UI can show a live progress bar. Every step is a settled on-chain action, so the
/// phase you last saw is where the swap actually is if it errors.
#[allow(clippy::too_many_arguments)]
pub fn btc_to_zbtc_progress(
    zc: &Zcrypt,
    b: &BtcParams,
    alice: &Account,
    asset: u64,
    preimage: &[u8],
    btc_amount: Amount,
    zbtc_value: u64,
    progress: &dyn Fn(u8, &str),
) -> Result<Coin, String> {
    if preimage.len() != PREIMAGE_LEN {
        return Err(format!("HTLC preimage must be exactly {PREIMAGE_LEN} bytes (got {})", preimage.len()));
    }
    if zbtc_value > btc_amount.to_sat() {
        return Err(format!(
            "cannot mint {zbtc_value} zBTC base units against {} locked sats — the SPV \
             gate enforces 1:1 backing",
            btc_amount.to_sat()
        ));
    }
    let lock = htlc_hashlock(preimage);
    // The BRIDGE claims the BTC leg (step 4), so price its claim from the bridge backend.
    let fee = htlc_spend_fee(b.bridge, 3)?;

    // 1. Alice locks BTC (claimable by the RESERVE key w/ preimage, refund Alice later).
    progress(10, "Locking your BTC in a hashlocked HTLC…");
    let net = b.alice.network();
    let (btc_locktime, zc_timeout) =
        shield_timeouts(net, b.alice.height()?, zc.height()? as u64)?;
    let script = htlc_script(&lock, &b.bridge_key.pk, &b.alice_key.pk, btc_locktime);
    let utxo = b.alice.fund_htlc(&script, btc_amount)?;
    println!("  [btc] Alice locked {} BTC in HTLC {}", btc_amount.to_btc(), utxo.outpoint.txid);

    // 2. Relay any Bitcoin headers the consensus SPV chain is missing (untrusted
    // transport — each header proves itself by its PoW), then submit the deposit
    // proof. Every validator re-verifies inclusion, depth, script, value, and the
    // reserve-key binding before a single base unit mints.
    progress(35, "Proving your BTC deposit to the chain (SPV)…");
    relay_btc_headers(zc, b.alice)?;
    let proof = zcrypt_core::spv::MintProof {
        reserve_pk: b.bridge_key.pk.inner.serialize(),
        refund_pk: b.alice_key.pk.inner.serialize(),
        btc_locktime,
        vout: utxo.outpoint.vout,
        raw_tx: b.alice.raw_tx(&utxo.outpoint.txid)?,
        merkle_block: b.alice.txout_proof(&utxo.outpoint.txid)?,
    };
    let data =
        zc.broadcast(&open_spv_tx(asset, zbtc_value, &lock, zc_timeout, &alice.pubkey(), &proof, b.alice_key))?;
    let escrow_id = escrow_id_from(&data)?;
    println!("  [zc]  SPV-verified deposit opened zBTC escrow {}", hex::encode(escrow_id));

    // 3. Alice claims the zBTC escrow, revealing the preimage on ZCrypt.
    progress(60, "Claiming your zBTC (revealing the preimage)…");
    let h0 = zc.height()?;
    zc.broadcast(&claim_tx(&escrow_id, preimage))?;
    // The mint skims a small protocol bridge fee to stakers, so the recipient's coin is
    // `zbtc_value - fee` (both node and wallet compute the same fee).
    let net = zbtc_value - zcrypt_core::emission::bridge_fee(zbtc_value);
    let coin = alice.htlc_coin(net, asset, &escrow_id);
    println!("  [zc]  Alice claimed {net} zBTC (of {zbtc_value}; {} to stakers as bridge fee)",
        zcrypt_core::emission::bridge_fee(zbtc_value));

    // 4. Bridge reads the preimage FROM the ZCrypt chain and claims the BTC.
    progress(85, "Bridge settling the BTC side…");
    let h1 = zc.height()?;
    let revealed = zc
        .find_claim_preimage(&escrow_id, h0, h1 + 1)
        .ok_or("preimage not found on ZCrypt")?;
    if revealed != preimage {
        return Err("on-chain preimage mismatch".to_string());
    }
    let txid = b.bridge.claim(&utxo, &revealed, b.bridge_key, b.bridge_dest, fee)?;
    b.bridge.confirm(&txid)?; // regtest mines; real networks wait for confirmations
    println!("  [btc] bridge took the BTC with the revealed preimage ({txid})");
    progress(100, "Done — zBTC is in your wallet.");
    Ok(coin)
}

// ============================================================================
// PUBLIC (multi-user) BTC -> zBTC shield.
//
// The single-process `btc_to_zbtc_progress` above derives BOTH the reserve claim key
// and the user refund key from ONE seed, so only that seed can shield. The functions
// below split the two roles so ANY user (any seed) can shield against a single
// operator reserve key:
//
//   * `btc_to_zbtc_public_progress` (USER side) needs only the operator's PUBLISHED
//     reserve PUBKEY. It locks BTC to the HTLC, proves the deposit via SPV (the mint is
//     trustless — consensus re-verifies), and claims the freshly minted zBTC by revealing
//     the preimage on ZCrypt. It never touches the operator's Bitcoin key.
//   * `reserve_claim_revealed` (OPERATOR watcher) holds the reserve PRIVKEY. It scans
//     ZCrypt blocks for deposits locked to its reserve whose preimage has been revealed,
//     reconstructs each BTC HTLC UTXO from the deposit's on-chain `MintProof`, and sweeps
//     the locked BTC to the operator's address.
//
// SECURITY NOTE (not yet hardened — do NOT run on mainnet without this): the BTC refund
// timelock is still the regtest-tuned `+100` and is NOT staggered against the zBTC escrow
// timeout. A production deployment MUST set the BTC refund window so it always outlives the
// zBTC claim window, and the watcher MUST claim well before it, or a user who reveals the
// preimage late could refund the BTC after already minting zBTC (unbacked supply). Validate
// on signet, including a deliberate late-reveal, before real funds.
// ============================================================================

/// USER side of a public shield: lock BTC to an HTLC claimable by the operator's
/// `reserve_pk` (with the preimage) or refundable to the user's own `user_refund` key after
/// the timelock, prove it via SPV, and claim the minted zBTC. Returns the user's zBTC coin.
/// The operator's watcher ([`reserve_claim_revealed`]) later sweeps the locked BTC.
#[allow(clippy::too_many_arguments)]
pub fn btc_to_zbtc_public_progress(
    zc: &Zcrypt,
    user_btc: &dyn BtcBackend,
    user_refund: &Key,
    reserve_pk: &PublicKey,
    user: &Account,
    asset: u64,
    preimage: &[u8],
    btc_amount: Amount,
    zbtc_value: u64,
    progress: &dyn Fn(u8, &str),
) -> Result<Coin, String> {
    if preimage.len() != PREIMAGE_LEN {
        return Err(format!("HTLC preimage must be exactly {PREIMAGE_LEN} bytes (got {})", preimage.len()));
    }
    if zbtc_value > btc_amount.to_sat() {
        return Err(format!(
            "cannot mint {zbtc_value} zBTC base units against {} locked sats — the SPV \
             gate enforces 1:1 backing",
            btc_amount.to_sat()
        ));
    }
    let lock = htlc_hashlock(preimage);

    // 1. Lock BTC: claim branch = the OPERATOR's reserve pubkey + preimage; refund branch =
    //    the USER's own key after the timelock. The user holds no reserve key.
    //    Race-safe CLTV: tip + network profile (≥ required_btc_lock_blocks).
    progress(10, "Locking your BTC in a hashlocked HTLC…");
    let net = user_btc.network();
    let (btc_locktime, zc_timeout) =
        shield_timeouts(net, user_btc.height()?, zc.height()? as u64)?;
    let script = htlc_script(&lock, reserve_pk, &user_refund.pk, btc_locktime);
    let utxo = user_btc.fund_htlc(&script, btc_amount)?;

    // 2. Prove the deposit. The proof pins the OPERATOR's reserve_pk (which must match the
    //    zBTC asset's registered authority) and the user's refund_pk. Consensus re-verifies
    //    everything; nobody signs the mint.
    progress(40, "Proving your BTC deposit to the chain (SPV)…");
    relay_btc_headers(zc, user_btc)?;
    let proof = MintProof {
        reserve_pk: reserve_pk.inner.serialize(),
        refund_pk: user_refund.pk.inner.serialize(),
        btc_locktime,
        vout: utxo.outpoint.vout,
        raw_tx: user_btc.raw_tx(&utxo.outpoint.txid)?,
        merkle_block: user_btc.txout_proof(&utxo.outpoint.txid)?,
    };
    let data =
        zc.broadcast(&open_spv_tx(asset, zbtc_value, &lock, zc_timeout, &user.pubkey(), &proof, user_refund))?;
    let escrow_id = escrow_id_from(&data)?;

    // 3. Claim the zBTC, revealing the preimage on ZCrypt (this is what lets the operator
    //    sweep the BTC). Refuse success unless consensus actually accepted the claim —
    //    never treat a leaked preimage alone as settlement.
    progress(75, "Claiming your zBTC (revealing the preimage)…");
    zc.broadcast(&claim_tx(&escrow_id, preimage))?;
    // Confirm the escrow is claimed on-chain (not merely that a claim tx was broadcast).
    let mut claimed = false;
    for _ in 0..30 {
        match query_escrow(zc, &escrow_id) {
            Ok(Some(info)) if info.state == "claimed" => {
                claimed = true;
                break;
            }
            _ => std::thread::sleep(std::time::Duration::from_millis(200)),
        }
    }
    if !claimed {
        return Err(
            "zBTC claim was not accepted by consensus; do not assume the mint succeeded \
             (and do not re-broadcast the same preimage). Check the escrow and retry carefully."
                .to_string(),
        );
    }
    let net = zbtc_value - zcrypt_core::emission::bridge_fee(zbtc_value);
    let coin = user.htlc_coin(net, asset, &escrow_id);
    progress(
        100,
        "Done — zBTC is minting/maturing. Operator must sweep the BTC HTLC before CLTV refund.",
    );
    Ok(coin)
}

/// Parse an SPV mint-escrow open tx (`0x64`) payload (the bytes AFTER the tag) into
/// `(asset, value, hashlock, timeout, claim_pk, MintProof)`. Used by the operator watcher to
/// recover each deposit's HTLC parameters AND recompute its escrow id (which needs `claim_pk`)
/// so it can confirm the deposit was consensus-accepted. Fail-closed on any malformed input.
pub fn parse_open_spv(payload: &[u8]) -> Option<(u64, u64, [u8; 32], u64, PubKey, MintProof)> {
    // asset(8) ‖ value(8) ‖ lock(32) ‖ timeout(8) ‖ claim_pk(64) ‖ open_auth(64) ‖ MintProof
    // The watcher does not need the open_auth signature, so it is skipped (bytes [120..184]).
    const HEAD: usize = 8 + 8 + 32 + 8 + 64 + 64;
    if payload.len() < HEAD {
        return None;
    }
    let asset = u64::from_le_bytes(payload[0..8].try_into().ok()?);
    let value = u64::from_le_bytes(payload[8..16].try_into().ok()?);
    let lock: [u8; 32] = payload[16..48].try_into().ok()?;
    let timeout = u64::from_le_bytes(payload[48..56].try_into().ok()?);
    let mut claim_pk: PubKey = [0u64; 8];
    for (i, limb) in claim_pk.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(payload[56 + i * 8..64 + i * 8].try_into().ok()?);
    }
    let proof = MintProof::from_bytes(&payload[HEAD..])?;
    Some((asset, value, lock, timeout, claim_pk, proof))
}

/// The consensus-visible fields of an HTLC escrow, parsed from the `/htlc/<id>` query.
/// Presence of a record here means the escrow tx was ACCEPTED by consensus, so the operator
/// watchers use it to filter out rejected/garbage txs that also appear in raw block data.
#[derive(Clone, Debug)]
pub struct EscrowInfo {
    pub asset_id: u64,
    pub value: u64,
    pub hashlock: [u8; 32],
    pub timeout_height: u64,
    pub state: String, // "open" | "claimed" | "expired"
}

/// Query one escrow by id; `Ok(None)` if consensus has no such escrow (rejected/garbage tx).
pub fn query_escrow(zc: &Zcrypt, escrow_id: &[u8; 32]) -> Result<Option<EscrowInfo>, String> {
    let raw = match zc.query(&format!("/htlc/{}", hex::encode(escrow_id))) {
        Ok(s) if !s.trim().is_empty() => s,
        Ok(_) => return Ok(None),
        Err(e) if e.contains("no such escrow") => return Ok(None),
        Err(e) => return Err(e),
    };
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let hl = v.get("hashlock").and_then(|x| x.as_str()).unwrap_or("");
    let hashlock: [u8; 32] = hex::decode(hl)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("escrow: bad hashlock")?;
    Ok(Some(EscrowInfo {
        asset_id: v.get("asset_id").and_then(|x| x.as_u64()).unwrap_or(0),
        value: v.get("value").and_then(|x| x.as_u64()).unwrap_or(0),
        hashlock,
        timeout_height: v.get("timeout_height").and_then(|x| x.as_u64()).unwrap_or(0),
        state: v.get("state").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    }))
}

/// Reconstruct the BTC HTLC UTXO a shield deposit funded, from that deposit's on-chain
/// [`MintProof`] (which carries the funding tx, output index, and both HTLC keys) and the
/// shared `hashlock`. This is what lets a watcher spend a deposit it did not itself create.
pub fn htlc_utxo_from_proof(proof: &MintProof, hashlock: &[u8; 32]) -> Result<HtlcUtxo, String> {
    let tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&proof.raw_tx).map_err(|e| e.to_string())?;
    let txid = tx.compute_txid();
    let out = tx
        .output
        .get(proof.vout as usize)
        .ok_or("MintProof vout out of range for the funding tx")?;
    let reserve_pk = PublicKey::from_slice(&proof.reserve_pk).map_err(|e| e.to_string())?;
    let refund_pk = PublicKey::from_slice(&proof.refund_pk).map_err(|e| e.to_string())?;
    // Byte-identical to the script the user funded (and to the consensus `btc_htlc_script`).
    let script = htlc_script(hashlock, &reserve_pk, &refund_pk, proof.btc_locktime);
    Ok(HtlcUtxo { outpoint: OutPoint { txid, vout: proof.vout }, value: out.value, script })
}

/// The result of one operator watcher pass: what it swept, what it skipped, what failed
/// (non-fatally, per deposit), and which deposits are dangerously close to their refund window.
#[derive(Debug, Default)]
pub struct WatchReport {
    /// `(escrow_id, btc_txid)` for deposits swept THIS pass.
    pub swept: Vec<([u8; 32], bitcoin::Txid)>,
    /// Deposits skipped because already swept (idempotency across restarts / overlaps).
    pub already_swept: usize,
    /// Per-deposit non-fatal failures `(escrow_id, reason)` — logged, never aborting the pass.
    pub errors: Vec<([u8; 32], String)>,
    /// Deposits whose BTC refund locktime is within [`LOCKTIME_ALERT_BLOCKS`] of the tip — the
    /// operator is racing the depositor's refund. ALERT and prioritize these.
    pub at_risk: Vec<[u8; 32]>,
    /// Deposits within [`LOCKTIME_HARD_BLOCKS`] of refund — emergency; recommend pause.
    pub critical: Vec<[u8; 32]>,
    /// Deposits whose preimage is revealed but whose Bitcoin deposit is NOT yet buried past
    /// the mint's maturity + reorg-void grace, so the sweep is DEFERRED to a later pass (M4).
    /// Not an error: these become sweepable once they mature.
    pub deferred: Vec<[u8; 32]>,
    /// True if any deposit is in `critical` or a sweep failed while already soft-at-risk.
    /// Operator frontends should refuse new shield deposits while this is set.
    pub pause_new_shields: bool,
}

/// OPERATOR shield watcher: scan ZCrypt blocks `from..=to` for deposits locked to `reserve.pk`
/// whose preimage has been revealed, and sweep each locked BTC to `dest`. Hardened vs the naive
/// scanner:
///   * **Acceptance-checked** — a `0x64` open that appears in raw block data but was REJECTED by
///     consensus creates no escrow, so [`query_escrow`] filters it out. A garbage-open flood
///     (matching our reserve_pk) can neither poison the index nor divert a real sweep.
///   * **Addressed by escrow id** — the authoritative id from the `0x5B` claim, not a hashlock
///     lookup, so a crafted duplicate hashlock cannot shadow a real deposit.
///   * **Idempotent** — `already_swept` (persisted by the caller across restarts) makes re-scans
///     and overlapping ranges no-ops; an already-spent UTXO also just fails non-fatally.
///   * **Non-fatal** — a single deposit's failure is recorded and the pass continues to the rest
///     (the old `?` aborted the whole scan, silently skipping every later real deposit).
///   * **Alerting** — deposits near their refund locktime are surfaced in `at_risk`.
#[allow(clippy::too_many_arguments)]
pub fn reserve_claim_revealed(
    zc: &Zcrypt,
    operator_btc: &dyn BtcBackend,
    reserve: &Key,
    dest: &Address,
    from: i64,
    to: i64,
    fee_target: u32,
    already_swept: &mut std::collections::HashSet<[u8; 32]>,
) -> Result<WatchReport, String> {
    use zcrypt_core::htlc_shield::escrow_id as derive_escrow_id;
    let reserve_ser = reserve.pk.inner.serialize();
    let btc_tip = operator_btc.height().unwrap_or(0);
    let net = spv_net(operator_btc.network());
    let mut report = WatchReport::default();

    // 1. Index CONSENSUS-ACCEPTED deposits locked to our reserve, keyed by escrow id.
    let mut ours: std::collections::HashMap<[u8; 32], (MintProof, [u8; 32], u32, u64)> = std::collections::HashMap::new();
    for h in from..=to {
        let txs = zc.block_txs(h)?;
        for tx in txs {
            if tx.first() != Some(&0x64) {
                continue;
            }
            let Some((asset, value, lock, timeout, claim_pk, proof)) = parse_open_spv(&tx[1..]) else {
                continue;
            };
            if proof.reserve_pk != reserve_ser {
                continue;
            }
            let eid = derive_escrow_id(asset, value, &lock, timeout, &claim_pk);
            match query_escrow(zc, &eid) {
                // Escrow exists AND its on-chain hashlock matches ⇒ consensus accepted this deposit.
                Ok(Some(info)) if info.hashlock == lock => {
                    let btc_locktime = proof.btc_locktime;
                    ours.insert(eid, (proof, lock, btc_locktime, value));
                }
                Ok(_) => {} // rejected / garbage / mismatched — ignore
                Err(e) => report.errors.push((eid, format!("escrow query: {e}"))),
            }
        }
    }

    // 2. Sweep every deposit whose preimage was revealed AND consensus accepted the claim.
    // Never sweep on a raw 0x5B alone: a failed DeliverTx can still leak the preimage in
    // block data while leaving the escrow open (no zBTC minted).
    for h in from..=to {
        let txs = zc.block_txs(h)?;
        for tx in txs {
            if tx.first() != Some(&0x5B) || tx.len() <= 33 {
                continue;
            }
            let Ok(eid): Result<[u8; 32], _> = tx[1..33].try_into() else { continue };
            let preimage = &tx[33..];
            let Some((proof, lock, btc_locktime, value)) = ours.get(&eid).cloned() else {
                continue;
            };
            if htlc_hashlock(preimage) != lock {
                continue; // this preimage doesn't open our escrow
            }
            if already_swept.contains(&eid) {
                report.already_swept += 1;
                continue;
            }
            // Require consensus-accepted claim (minted / immature) before taking BTC.
            match query_escrow(zc, &eid) {
                Ok(Some(info)) if info.state == "claimed" && info.hashlock == lock => {}
                Ok(Some(info)) => {
                    // Preimage seen but claim not settled — do NOT sweep.
                    report.errors.push((
                        eid,
                        format!("preimage on-chain but escrow state is '{}' (not claimed); refusing BTC sweep", info.state),
                    ));
                    continue;
                }
                Ok(None) => continue,
                Err(e) => {
                    report.errors.push((eid, format!("escrow query before sweep: {e}")));
                    continue;
                }
            }
            // M4: defer the sweep until the deposit is buried past the mint's maturity +
            // reorg-void grace, so a benign reorg that voids the still-immature mint can never
            // strand an already-swept deposit. Race-safe open params guarantee CLTV still
            // outlives max safe_sweep + SLA on every network profile.
            {
                use bitcoin::hashes::Hash as _;
                let need = zcrypt_core::spv::safe_sweep_conf(net, value);
                if let Some(txb) = proof.funding_txid() {
                    let txid = bitcoin::Txid::from_byte_array(txb);
                    let confs = operator_btc.tx_confirmations(&txid).unwrap_or(0);
                    if confs < need {
                        report.deferred.push(eid);
                        // Still track refund proximity while deferred — operator must not
                        // accept new shields if a deferred deposit is near CLTV.
                        let remaining = (btc_locktime as u64).saturating_sub(btc_tip);
                        if remaining < LOCKTIME_HARD_BLOCKS {
                            report.critical.push(eid);
                            report.pause_new_shields = true;
                        } else if remaining < LOCKTIME_ALERT_BLOCKS {
                            report.at_risk.push(eid);
                        }
                        continue;
                    }
                }
            }
            let remaining = (btc_locktime as u64).saturating_sub(btc_tip);
            if remaining < LOCKTIME_HARD_BLOCKS {
                report.critical.push(eid);
                report.pause_new_shields = true;
            } else if remaining < LOCKTIME_ALERT_BLOCKS {
                report.at_risk.push(eid);
            }
            // Near the deadline: force aggressive fee target so the sweep confirms.
            let effective_fee_target = if remaining < LOCKTIME_ALERT_BLOCKS {
                1
            } else {
                fee_target
            };
            let outcome = (|| -> Result<bitcoin::Txid, String> {
                let utxo = htlc_utxo_from_proof(&proof, &lock)?;
                let fee = htlc_spend_fee(operator_btc, effective_fee_target)?;
                let txid = operator_btc.claim(&utxo, preimage, reserve, dest, fee)?;
                operator_btc.confirm(&txid)?;
                Ok(txid)
            })();
            match outcome {
                Ok(txid) => {
                    already_swept.insert(eid);
                    report.swept.push((eid, txid));
                }
                Err(e) => {
                    if remaining < LOCKTIME_ALERT_BLOCKS {
                        report.pause_new_shields = true;
                    }
                    report.errors.push((eid, e));
                }
            }
        }
    }
    Ok(report)
}

// ============================================================================
// PUBLIC (multi-user) zBTC -> BTC redeem.
//
// A fixed 1:1 peg, so there is NO price/quote: burn N zBTC, receive N BTC (minus the fixed
// bridge fee) from the operator's reserve — which is exactly the BTC swept in on shields, so
// redeems are backed 1:1 by construction. The four steps split cleanly by who holds what key:
//
//   USER (their own keys, never the reserve key):
//     * `redeem_user_burn`  — lock the zBTC in a burn escrow (hashlock = H(preimage)).
//     * `redeem_user_claim` — claim the operator-locked BTC, revealing the preimage.
//   OPERATOR (only the reserve key; reads the chain):
//     * `reserve_lock_for_redeem`  — lock reserve BTC the user can claim with the preimage.
//     * `reserve_finalize_redeem`  — read the revealed preimage, destroy the zBTC (keep 1:1).
//
// Unlike shield's mint (fully trustless), redeem needs the operator to ACTIVELY lock BTC, so
// the operator must be online. The HTLC keeps it safe either way: if the operator never
// locks, the user's burn escrow times out and REFUNDS the zBTC (no one loses).
//
// SECURITY NOTE (not yet hardened for mainnet): the operator locks with a BTC refund timelock
// (`+100`) shorter than the zBTC burn-escrow timeout (`ZC_HTLC_TIMEOUT_BLOCKS`), which is the
// correct stagger direction (the operator, who reveals second on ZCrypt, gets the longer
// window). Re-derive both for real block times and validate a deliberate late-reveal on signet
// before real funds. The operator learns the user's BTC claim pubkey from the redeem
// instruction; moving it fully on-chain (a burn-lock field) would make the redeem watcher as
// autonomous as the shield watcher — a small follow-up.
// ============================================================================

/// USER side, step 1 of a redeem: lock `zbtc_value` zBTC into a burn escrow (output[0] = burn
/// coin to the unspendable `BURN_PK`, output[1] = change back to the user). `hashlock` is
/// `H(preimage)` for a preimage the USER holds. `btc_claim_pk` is the user's Bitcoin key, carried
/// ON-CHAIN (tag 0x67) so the operator's redeem watcher pays out to a key the user themselves
/// committed to — no off-chain trust. Returns `(escrow_id, change_value, change_blind)`.
#[allow(clippy::too_many_arguments)]
pub fn redeem_user_burn(
    zc: &Zcrypt,
    user: &Account,
    coins: &[Coin],
    asset: u64,
    hashlock: &[u8; 32],
    zbtc_value: u64,
    btc_claim_pk: &PublicKey,
) -> Result<([u8; 32], u64, [u64; 4]), String> {
    if coins.is_empty() {
        return Err("no zBTC coins to redeem".to_string());
    }
    let in_total: u64 = coins.iter().map(|c| c.value).sum();
    if zbtc_value + zcrypt_core::emission::MIN_FEE > in_total {
        return Err("lock value + fee exceeds the user's zBTC coins".to_string());
    }
    let burn_blind = zcrypt_core::keys::random_blind();
    let change_blind = zcrypt_core::keys::random_blind();
    let change_value = in_total - zbtc_value - zcrypt_core::emission::MIN_FEE;
    let burn_out: OutCoin = (zbtc_value, burn_blind, zcrypt_core::htlc_shield::BURN_PK, asset);
    let change_out: OutCoin = (change_value, change_blind, user.pubkey(), asset);
    let change_note = zcrypt_core::kem::ciphertext_to_bytes(&zcrypt_core::keys::encrypt_note_asset(
        &user.normal_address(),
        change_value,
        change_blind,
        asset,
    ));
    // The timeout is part of the bound envelope, so it must be fixed BEFORE proving.
    let zc_timeout = zc.height()? as u64 + ZC_REDEEM_TIMEOUT_BLOCKS;
    let envelope = zcrypt_core::htlc_shield::lock_envelope(
        zcrypt_core::htlc_shield::ENV_BURN_LOCK_BTC,
        asset,
        zbtc_value,
        hashlock,
        zc_timeout,
        &user.pubkey(),
        &user.pubkey(),
        &btc_claim_pk.inner.serialize(),
    );
    let stx = build_shield_spend_bound(
        zc,
        coins,
        &[burn_out, change_out],
        zcrypt_core::emission::MIN_FEE,
        vec![zcrypt_core::keys::cover_note_bytes(), change_note],
        &envelope,
    )?;
    let data = zc.broadcast(&burn_lock_btc_tx(btc_claim_pk, zbtc_value, &burn_blind, asset, hashlock, zc_timeout, &user.pubkey(), &stx))?;
    let escrow_id = escrow_id_from(&data)?;
    Ok((escrow_id, change_value, change_blind))
}

/// OPERATOR side, step 2 of a redeem: lock RESERVE BTC into an HTLC the user can claim with the
/// preimage, refundable to the reserve after the timelock — but ONLY after validating the user's
/// on-chain burn escrow, so the operator can't be tricked into paying out BTC it shouldn't. It
/// fetches the escrow by id from consensus and refuses to lock unless ALL hold:
///   * the escrow EXISTS and is `open` (no replay of a claimed/expired escrow);
///   * `asset_id == zbtc_asset` (never pay real BTC for a burned worthless token);
///   * `value == btc_amount` (the 1:1 peg — no over-payment);
///   * `timeout_height ≥ tip + min_finalize_margin` (a short-timeout burn can't let the user
///     claim the BTC and then refund the zBTC before the operator finalizes — the short-timeout
///     theft in the threat model).
/// The BTC HTLC is bound to the escrow's OWN on-chain `hashlock`, not a caller-supplied one.
///
/// REMAINING TRUST (until the Batch-2 consensus binding lands): `user_btc_pk` is not yet bound
/// on-chain to the escrow, so it MUST come from a request AUTHENTICATED as the escrow owner —
/// otherwise an attacker could have the operator lock BTC to the attacker's key against a
/// victim's burn. The forthcoming on-chain `btc_claim_pk` field removes this trust entirely.
#[allow(clippy::too_many_arguments)]
pub fn reserve_lock_for_redeem(
    zc: &Zcrypt,
    operator_btc: &dyn BtcBackend,
    reserve: &Key,
    user_btc_pk: &PublicKey,
    escrow_id: &[u8; 32],
    zbtc_asset: u64,
    btc_amount: Amount,
    min_finalize_margin: u64,
) -> Result<HtlcUtxo, String> {
    let info = query_escrow(zc, escrow_id)?
        .ok_or("redeem: no such burn escrow on-chain (tx rejected or nonexistent)")?;
    if info.state != "open" {
        return Err(format!("redeem: escrow is not open (state={}) — refusing to lock BTC", info.state));
    }
    if info.asset_id != zbtc_asset {
        return Err(format!("redeem: escrow asset {} is not zBTC ({zbtc_asset}) — refusing to pay BTC", info.asset_id));
    }
    if info.value != btc_amount.to_sat() {
        return Err(format!(
            "redeem: escrow value {} != requested {} sats — the 1:1 peg is violated",
            info.value,
            btc_amount.to_sat()
        ));
    }
    let zc_tip = zc.height()? as u64;
    if info.timeout_height < zc_tip + min_finalize_margin {
        return Err(format!(
            "redeem: escrow timeout {} too soon (tip {zc_tip} + finalize margin {min_finalize_margin}) — \
             a short-timeout burn could refund the zBTC before the operator finalizes; refusing to lock BTC",
            info.timeout_height
        ));
    }
    // Operator refund must unlock before the ZC burn times out (capital recovery) but
    // leave the user a long claim window — network redeem profile, not shield profile.
    let net = operator_btc.network();
    let btc_locktime = (operator_btc.height()? + btc_redeem_lock_blocks(net)) as u32;
    // Bind the BTC HTLC to the escrow's OWN hashlock (not a caller-supplied value).
    let script = htlc_script(&info.hashlock, user_btc_pk, &reserve.pk, btc_locktime);
    operator_btc.fund_htlc(&script, btc_amount)
}

/// USER side, step 3 of a redeem: claim the operator-locked BTC to `user_dest`, revealing the
/// preimage on Bitcoin (which is what lets the operator finalize the burn). Returns the claim txid.
pub fn redeem_user_claim(
    user_btc: &dyn BtcBackend,
    user_btc_key: &Key,
    utxo: &HtlcUtxo,
    preimage: &[u8],
    user_dest: &Address,
) -> Result<bitcoin::Txid, String> {
    let fee = htlc_spend_fee(user_btc, 3)?;
    let txid = user_btc.claim(utxo, preimage, user_btc_key, user_dest, fee)?;
    user_btc.confirm(&txid)?;
    Ok(txid)
}

/// OPERATOR side, step 4 of a redeem: after the user has claimed the BTC, read the revealed
/// preimage from their claim tx and submit it to the burn escrow, permanently destroying the
/// zBTC so supply stays 1:1 with the reserve. MUST run before the burn escrow times out.
pub fn reserve_finalize_redeem(
    zc: &Zcrypt,
    operator_btc: &dyn BtcBackend,
    escrow_id: &[u8; 32],
    user_claim_txid: &bitcoin::Txid,
    expected_hashlock: &[u8; 32],
) -> Result<(), String> {
    let preimage = operator_btc
        .preimage_from_claim(user_claim_txid)
        .ok_or("preimage not found in the user's BTC claim tx")?;
    if htlc_hashlock(&preimage) != *expected_hashlock {
        return Err("revealed preimage does not match the burn escrow hashlock".to_string());
    }
    zc.broadcast(&claim_tx(escrow_id, &preimage))?;
    Ok(())
}

/// Finalize a redeem burn given an ALREADY-READ preimage (the watcher extracts it from the
/// user's BTC claim via `find_htlc_spend_preimage`). Verifies it opens the escrow's hashlock,
/// then submits the burn claim (destroying the zBTC, keeping supply 1:1 with the reserve).
pub fn reserve_finalize_with_preimage(
    zc: &Zcrypt,
    escrow_id: &[u8; 32],
    preimage: &[u8],
    expected_hashlock: &[u8; 32],
) -> Result<(), String> {
    if htlc_hashlock(preimage) != *expected_hashlock {
        return Err("revealed preimage does not match the burn escrow hashlock".to_string());
    }
    zc.broadcast(&claim_tx(escrow_id, preimage))?;
    Ok(())
}

/// A reserve BTC lock the redeem watcher funded for one user redeem, ready for the user to claim.
#[derive(Debug)]
pub struct RedeemLock {
    pub escrow_id: [u8; 32],
    pub utxo: HtlcUtxo,
    pub hashlock: [u8; 32],
}

/// The result of one autonomous redeem-watcher pass.
#[derive(Default)]
pub struct RedeemReport {
    /// BTC locks funded THIS pass (present them to the users to claim).
    pub locked: Vec<RedeemLock>,
    /// Redeems skipped because already funded (idempotency across restarts / overlaps).
    pub already_funded: usize,
    /// Redeems the operator REFUSED after validation (bad asset/value/timeout/hashlock) — safe.
    pub rejected: Vec<([u8; 32], String)>,
    /// Non-fatal funding errors (e.g. transient RPC / insufficient reserve) — retry later.
    pub errors: Vec<([u8; 32], String)>,
}

/// OPERATOR autonomous REDEEM watcher: scan ZCrypt blocks `from..=to` for `0x67` redeem burn-locks
/// and, for each valid one, lock the matching RESERVE BTC (1:1) claimable by the user's ON-CHAIN
/// `btc_claim_pk`. It trusts NOTHING off-chain — it re-derives the escrow id, confirms consensus
/// accepted the burn ([`query_escrow`]), enforces asset==zBTC, value==btc paid, the escrow's own
/// hashlock, and a finalize-margin on the timeout, and is idempotent via `already_funded`. The
/// returned locks are then claimed by the users; the operator finalizes each with
/// [`reserve_finalize_redeem`] once it sees the user's BTC claim.
#[allow(clippy::too_many_arguments)]
pub fn reserve_serve_redeems(
    zc: &Zcrypt,
    operator_btc: &dyn BtcBackend,
    reserve: &Key,
    from: i64,
    to: i64,
    zbtc_asset: u64,
    min_finalize_margin: u64,
    already_funded: &mut std::collections::HashSet<[u8; 32]>,
) -> Result<RedeemReport, String> {
    use zcrypt_core::htlc_shield::escrow_id as derive_escrow_id;
    let zc_tip = zc.height()? as u64;
    let mut report = RedeemReport::default();
    for h in from..=to {
        let txs = zc.block_txs(h)?;
        for tx in txs {
            if tx.first() != Some(&0x67) {
                continue;
            }
            let Some((btc_pk_ser, asset, value, hashlock, timeout, refund_pk)) = parse_burn_lock_btc(&tx[1..]) else {
                continue;
            };
            let eid = derive_escrow_id(asset, value, &hashlock, timeout, &refund_pk);
            if already_funded.contains(&eid) {
                report.already_funded += 1;
                continue;
            }
            let info = match query_escrow(zc, &eid) {
                Ok(Some(i)) => i,
                Ok(None) => continue, // consensus rejected this burn-lock — nothing to serve
                Err(e) => {
                    report.errors.push((eid, format!("escrow query: {e}")));
                    continue;
                }
            };
            // Validate every peg-critical property BEFORE committing reserve BTC.
            let reject = if info.state != "open" {
                Some(format!("escrow not open (state={})", info.state))
            } else if info.asset_id != zbtc_asset {
                Some(format!("escrow asset {} is not zBTC ({zbtc_asset})", info.asset_id))
            } else if info.hashlock != hashlock {
                Some("burn-lock hashlock disagrees with the escrow".to_string())
            } else if info.value != value {
                Some(format!("burn-lock value {value} disagrees with the escrow {}", info.value))
            } else if info.timeout_height < zc_tip + min_finalize_margin {
                Some(format!("escrow timeout {} too soon (tip {zc_tip} + margin {min_finalize_margin})", info.timeout_height))
            } else {
                None
            };
            if let Some(r) = reject {
                report.rejected.push((eid, r));
                continue;
            }
            // Claim the funding slot BEFORE broadcast so a crash mid-fund does not
            // double-fund on restart. On fund failure, release the slot for retry.
            already_funded.insert(eid);
            let outcome = (|| -> Result<HtlcUtxo, String> {
                let btc_pk = PublicKey::from_slice(&btc_pk_ser).map_err(|e| e.to_string())?;
                let btc_locktime =
                    (operator_btc.height()? + btc_redeem_lock_blocks(operator_btc.network())) as u32;
                let script = htlc_script(&info.hashlock, &btc_pk, &reserve.pk, btc_locktime);
                operator_btc.fund_htlc(&script, Amount::from_sat(info.value))
            })();
            match outcome {
                Ok(utxo) => {
                    report.locked.push(RedeemLock { escrow_id: eid, utxo, hashlock });
                }
                Err(e) => {
                    already_funded.remove(&eid);
                    report.errors.push((eid, e));
                }
            }
        }
    }
    Ok(report)
}

/// **zBTC → BTC.** Alice locks zBTC (burn escrow); the bridge locks BTC claimable by
/// Alice; Alice claims the BTC revealing the preimage; the bridge reads it from
/// Bitcoin and burns the zBTC.
#[allow(clippy::too_many_arguments)]
pub fn zbtc_to_btc(
    zc: &Zcrypt,
    b: &BtcParams,
    alice: &Account,
    asset: u64,
    coins: &[Coin],
    preimage: &[u8],
    zbtc_value: u64,
    btc_amount: Amount,
) -> Result<(), String> {
    zbtc_to_btc_progress(zc, b, alice, asset, coins, preimage, zbtc_value, btc_amount, &|_, _| {}).map(|_| ())
}

/// Like [`zbtc_to_btc`] but reports each step via `progress(percent, phase)` for a live UI,
/// and returns the `(change_value, change_blind)` of the zBTC change output so the caller
/// can record the change coin (a partial redeem leaves change back at Alice's address).
#[allow(clippy::too_many_arguments)]
pub fn zbtc_to_btc_progress(
    zc: &Zcrypt,
    b: &BtcParams,
    alice: &Account,
    asset: u64,
    coins: &[Coin],
    preimage: &[u8],
    zbtc_value: u64,
    btc_amount: Amount,
    progress: &dyn Fn(u8, &str),
) -> Result<(u64, [u64; 4]), String> {
    if preimage.len() != PREIMAGE_LEN {
        return Err(format!("HTLC preimage must be exactly {PREIMAGE_LEN} bytes (got {})", preimage.len()));
    }
    // Peg integrity: BTC locked must equal zBTC burned (1:1 base units).
    if btc_amount.to_sat() != zbtc_value {
        return Err(format!(
            "redeem must be 1:1: btc_amount {} sats != zbtc_value {zbtc_value}",
            btc_amount.to_sat()
        ));
    }
    let lock = htlc_hashlock(preimage);
    // ALICE claims the BTC leg (step 3), so price her claim from Alice's backend.
    let fee = htlc_spend_fee(b.alice, 3)?;
    if coins.is_empty() {
        return Err("no zBTC coins to redeem".to_string());
    }
    let in_total: u64 = coins.iter().map(|c| c.value).sum();
    // The coins must cover the locked value PLUS the zBTC transaction fee (the shielded
    // pool hides asset_id, so a zBTC spend pays its fee in zBTC).
    if zbtc_value + zcrypt_core::emission::MIN_FEE > in_total {
        return Err("lock value + fee exceeds Alice's zBTC coins".to_string());
    }

    // 1. Alice locks zBTC into a burn escrow: output[0] = burn coin, output[1] change.
    // H4: fresh CSPRNG blinds — a hardcoded blind makes the amount brute-forceable
    // from the public commitment and collides equal-value coins into one nullifier.
    progress(15, "Locking your zBTC in a burn escrow…");
    let burn_blind = zcrypt_core::keys::random_blind();
    let change_blind = zcrypt_core::keys::random_blind();
    let change_value = in_total - zbtc_value - zcrypt_core::emission::MIN_FEE;
    let burn_out: OutCoin = (zbtc_value, burn_blind, zcrypt_core::htlc_shield::BURN_PK, asset);
    let change_out: OutCoin = (change_value, change_blind, alice.pubkey(), asset);
    // A REAL encrypted change note to Alice's normal address, so the wallet recovers the
    // change zBTC (the burn output goes to BURN_PK and needs no readable note). This is what
    // makes a PARTIAL redeem safe — the un-redeemed zBTC comes back instead of being lost.
    let change_note = zcrypt_core::kem::ciphertext_to_bytes(&zcrypt_core::keys::encrypt_note_asset(
        &alice.normal_address(),
        change_value,
        change_blind,
        asset,
    ));
    let net = b.bridge.network();
    // The timeout is part of the bound envelope, so it must be fixed BEFORE proving.
    let zc_timeout = zc.height()? as u64 + zc_redeem_timeout_blocks(net);
    let envelope = zcrypt_core::htlc_shield::lock_envelope(
        zcrypt_core::htlc_shield::ENV_BURN_LOCK,
        asset,
        zbtc_value,
        &lock,
        zc_timeout,
        &alice.pubkey(),
        &alice.pubkey(),
        &[],
    );
    let stx = build_shield_spend_bound(
        zc,
        coins,
        &[burn_out, change_out],
        zcrypt_core::emission::MIN_FEE,
        vec![zcrypt_core::keys::cover_note_bytes(), change_note],
        &envelope,
    )?;
    let data = zc.broadcast(&burn_lock_tx(zbtc_value, &burn_blind, asset, &lock, zc_timeout, &alice.pubkey(), &stx))?;
    let escrow_id = escrow_id_from(&data)?;
    println!("  [zc]  Alice locked {} zBTC in burn escrow {}", zbtc_value, hex::encode(escrow_id));

    // 2. Bridge locks BTC claimable by Alice with the preimage.
    progress(40, "Bridge locking BTC for you to claim…");
    let btc_locktime = (b.bridge.height()? + btc_redeem_lock_blocks(net)) as u32;
    let script = htlc_script(&lock, &b.alice_key.pk, &b.bridge_key.pk, btc_locktime);
    let utxo = b.bridge.fund_htlc(&script, btc_amount)?;
    println!("  [btc] bridge locked {} BTC in HTLC {}", btc_amount.to_btc(), utxo.outpoint.txid);

    // 3. Alice claims the BTC (to her own wallet), revealing the preimage on Bitcoin.
    progress(65, "Claiming your BTC (revealing the preimage)…");
    let claim_txid = b.alice.claim(&utxo, preimage, b.alice_key, b.alice_dest, fee)?;
    // Confirm Alice's claim before the bridge reads the preimage from it and burns the
    // zBTC — on a real network an unconfirmed claim could still be replaced.
    b.alice.confirm(&claim_txid)?;
    println!("  [btc] Alice took the BTC (preimage revealed on Bitcoin)");

    // 4. Bridge reads the preimage FROM Bitcoin and burns the zBTC.
    progress(90, "Bridge settling (burning the zBTC)…");
    let revealed = b.alice.preimage_from_claim(&claim_txid).ok_or("preimage not in BTC claim")?;
    if revealed != preimage {
        return Err("on-chain preimage mismatch".to_string());
    }
    zc.broadcast(&claim_tx(&escrow_id, &revealed))?;
    println!("  [zc]  bridge burned the zBTC with the revealed preimage");
    progress(100, "Done — BTC is in your Bitcoin wallet.");
    Ok((change_value, change_blind))
}

// ===========================================================================
// In-pool private asset↔asset swap (shielded DEX / OTC), RFQ-priced.
// ===========================================================================

/// An agreed **RFQ quote**: the *taker* gives `give_amount` of `give_asset` and receives
/// `take_amount` of `take_asset`. The price is set off-chain by the *maker* (LP) — the chain
/// never checks it, it only settles the trade atomically and privately (the taker simply
/// won't proceed on a quote they don't like). MEV-proof: the terms are bilateral, never in a
/// public mempool or pool. Both legs settle or both refund after `timeout_blocks`.
#[derive(Clone, Copy, Debug)]
pub struct SwapQuote {
    pub give_asset: u64,
    pub give_amount: u64,
    pub take_asset: u64,
    pub take_amount: u64,
    pub timeout_blocks: u64,
}

/// The taker's outcome of a swap: the coin received (of `take_asset`) plus the change coin
/// left over from the coins they spent to fund their leg.
pub struct SwapResult {
    pub received: Coin,
    pub give_change: Coin,
}

/// Lock `value` of `asset` from `locker`'s `coins` into a **swap escrow** claimable by
/// `counterparty_pk` (refund to the locker on timeout). Broadcasts the lock and returns
/// `(escrow_id, change_coin)`. Fee is paid in the moved asset (the pool hides asset_id).
#[allow(clippy::too_many_arguments)]
fn send_swap_lock(
    zc: &Zcrypt,
    locker: &Account,
    asset: u64,
    value: u64,
    coins: &[Coin],
    hashlock: &[u8; 32],
    timeout: u64,
    counterparty_pk: &PubKey,
) -> Result<([u8; 32], Coin), String> {
    let in_total: u64 = coins.iter().map(|c| c.value).sum();
    if value + zcrypt_core::emission::MIN_FEE > in_total {
        return Err("lock value + fee exceeds the locker's coins".to_string());
    }
    let burn_blind = zcrypt_core::keys::random_blind();
    let change_blind = zcrypt_core::keys::random_blind();
    let change_value = in_total - value - zcrypt_core::emission::MIN_FEE;
    let burn_out: OutCoin = (value, burn_blind, zcrypt_core::htlc_shield::BURN_PK, asset);
    let change_out: OutCoin = (change_value, change_blind, locker.pubkey(), asset);
    let change_note = zcrypt_core::kem::ciphertext_to_bytes(&zcrypt_core::keys::encrypt_note_asset(
        &locker.normal_address(),
        change_value,
        change_blind,
        asset,
    ));
    let envelope = zcrypt_core::htlc_shield::lock_envelope(
        zcrypt_core::htlc_shield::ENV_SWAP_LOCK,
        asset,
        value,
        hashlock,
        timeout,
        counterparty_pk,
        &locker.pubkey(),
        &[],
    );
    let stx = build_shield_spend_bound(
        zc,
        coins,
        &[burn_out, change_out],
        zcrypt_core::emission::MIN_FEE,
        vec![zcrypt_core::keys::cover_note_bytes(), change_note],
        &envelope,
    )?;
    let data = zc.broadcast(&swap_lock_tx(
        value,
        &burn_blind,
        asset,
        hashlock,
        timeout,
        counterparty_pk,
        &locker.pubkey(),
        &stx,
    ))?;
    let escrow = escrow_id_from(&data)?;
    Ok((escrow, locker.own_asset_coin(change_value, change_blind, asset)))
}

/// Run a **private in-pool atomic swap** between two shielded assets, per an agreed
/// [`SwapQuote`]. Two swap escrows share one hashlock: the taker locks `give`, the maker
/// locks `take`, the taker claims `take` (revealing the preimage), the maker reads it from
/// the chain and claims `give`. Amounts, asset ids and identities stay hidden; only the HTLC
/// structure is visible. Returns the taker's received coin + change. (The single-wallet demo
/// supplies both `taker` and `maker`, exactly like the BTC bridge plays Alice + LP.)
#[allow(clippy::too_many_arguments)]
pub fn swap_in_pool_progress(
    zc: &Zcrypt,
    taker: &Account,
    maker: &Account,
    taker_give_coins: &[Coin],
    maker_take_coins: &[Coin],
    quote: &SwapQuote,
    preimage: &[u8],
    progress: &dyn Fn(u8, &str),
) -> Result<SwapResult, String> {
    if preimage.len() != PREIMAGE_LEN {
        return Err(format!("HTLC preimage must be exactly {PREIMAGE_LEN} bytes (got {})", preimage.len()));
    }
    let lock = htlc_hashlock(preimage);
    // Stagger timeouts: maker's locked leg (give) expires first; taker's locked leg
    // (take) expires later so the party that reveals the preimage cannot outrun the
    // counterparty claim + refund race.
    let base = zc.height()? as u64;
    let give_timeout = base + quote.timeout_blocks as u64;
    let take_timeout = give_timeout + quote.timeout_blocks.max(1) as u64;

    progress(15, "Locking your side of the swap…");
    let (give_escrow, give_change) =
        send_swap_lock(zc, taker, quote.give_asset, quote.give_amount, taker_give_coins, &lock, give_timeout, &maker.pubkey())?;

    progress(40, "Maker locking their side…");
    let (take_escrow, _maker_change) =
        send_swap_lock(zc, maker, quote.take_asset, quote.take_amount, maker_take_coins, &lock, take_timeout, &taker.pubkey())?;

    progress(65, "Claiming what you receive (revealing the preimage)…");
    zc.broadcast(&claim_tx(&take_escrow, preimage))?;
    let received = taker.htlc_coin(quote.take_amount, quote.take_asset, &take_escrow);

    progress(85, "Maker settling their side…");
    // The maker reads the now-public preimage from the chain and claims the give leg.
    zc.broadcast(&claim_tx(&give_escrow, preimage))?;

    progress(100, "Swap complete — the asset is in your wallet.");
    Ok(SwapResult { received, give_change })
}

#[cfg(test)]
mod public_shield_tests {
    use super::*;
    use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Transaction, Witness};

    // Build a funding tx whose output `vout` pays the HTLC P2WSH, then prove the operator
    // watcher reconstructs the SAME outpoint, value, and (critically) the SAME redeem script
    // from the on-chain MintProof alone — that identity is what lets it spend a deposit it
    // never created.
    #[test]
    fn watcher_reconstructs_the_exact_funded_htlc() {
        let reserve = Key::from_bytes(&[7u8; 32]);
        let refund = Key::from_bytes(&[9u8; 32]);
        let preimage = [3u8; 32];
        let lock = htlc_hashlock(&preimage);
        let locktime = 800_000u32;
        let script = htlc_script(&lock, &reserve.pk, &refund.pk, locktime);
        let spk = crate::htlc_address(&script, Network::Bitcoin).script_pubkey();

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut { value: Amount::from_sat(123_456), script_pubkey: ScriptBuf::new() }, // decoy vout 0
                TxOut { value: Amount::from_sat(555_000), script_pubkey: spk },               // HTLC vout 1
            ],
        };
        let proof = MintProof {
            reserve_pk: reserve.pk.inner.serialize(),
            refund_pk: refund.pk.inner.serialize(),
            btc_locktime: locktime,
            vout: 1,
            raw_tx: bitcoin::consensus::serialize(&tx),
            merkle_block: vec![],
        };

        let utxo = htlc_utxo_from_proof(&proof, &lock).expect("reconstruct");
        assert_eq!(utxo.outpoint.txid, tx.compute_txid(), "txid");
        assert_eq!(utxo.outpoint.vout, 1, "vout");
        assert_eq!(utxo.value, Amount::from_sat(555_000), "value comes from the funding output, not escrow.value");
        assert_eq!(utxo.script, script, "reconstructed redeem script is byte-identical to what the user funded");
    }

    // The operator watcher recovers the deposit's HTLC params by parsing the 0x64 open tx.
    #[test]
    fn parse_open_spv_roundtrips_the_deposit() {
        let reserve = Key::from_bytes(&[7u8; 32]);
        let refund = Key::from_bytes(&[9u8; 32]);
        let lock = htlc_hashlock(&[3u8; 32]);
        // open_spv_tx now signs the funding outpoint (H1 recipient binding), so the proof must
        // carry a REAL, parseable funding tx — placeholder bytes no longer round-trip.
        let locktime = 800_000u32;
        let script = htlc_script(&lock, &reserve.pk, &refund.pk, locktime);
        let spk = crate::htlc_address(&script, Network::Bitcoin).script_pubkey();
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut { value: Amount::from_sat(123_456), script_pubkey: ScriptBuf::new() }, // decoy vout 0
                TxOut { value: Amount::from_sat(555_000), script_pubkey: spk },               // HTLC vout 1
            ],
        };
        let proof = MintProof {
            reserve_pk: reserve.pk.inner.serialize(),
            refund_pk: refund.pk.inner.serialize(),
            btc_locktime: locktime,
            vout: 1,
            raw_tx: bitcoin::consensus::serialize(&tx),
            merkle_block: vec![0x01, 0x02, 0x03],
        };
        let claim_pk: PubKey = [1, 2, 3, 4, 5, 6, 7, 8];
        let payload = open_spv_tx(0xABCD, 555_000, &lock, 42, &claim_pk, &proof, &refund);
        assert_eq!(payload[0], 0x64, "tag");

        let (asset, value, plock, timeout, pclaim, pproof) =
            parse_open_spv(&payload[1..]).expect("parse");
        assert_eq!(asset, 0xABCD);
        assert_eq!(value, 555_000);
        assert_eq!(plock, lock);
        assert_eq!(timeout, 42);
        assert_eq!(pclaim, claim_pk, "claim_pk parsed (needed to derive the escrow id)");
        assert_eq!(pproof, proof, "MintProof survives the open-tx round trip");
        // And the parsed fields recompute the SAME escrow id consensus used — the watcher's
        // acceptance check depends on this.
        let eid = zcrypt_core::htlc_shield::escrow_id(asset, value, &plock, timeout, &pclaim);
        let eid2 = zcrypt_core::htlc_shield::escrow_id(0xABCD, 555_000, &lock, 42, &claim_pk);
        assert_eq!(eid, eid2, "escrow id is deterministic from the parsed open-tx fields");
    }

    #[test]
    fn mainnet_profile_beats_required_race_budget() {
        let net = Network::Bitcoin;
        let required = required_btc_lock_blocks(net);
        let profile = btc_lock_blocks(net);
        assert!(
            profile >= required,
            "profile {profile} must cover required race budget {required}"
        );
        // Late claim burns ~36h of BTC blocks; remaining must still cover operator SLA.
        let zc_btc = (zc_claim_secs(net) + BTC_BLOCK_TIME_SECS - 1) / BTC_BLOCK_TIME_SECS;
        let remaining_after_late = profile.saturating_sub(zc_btc);
        assert!(
            remaining_after_late >= OPERATOR_SWEEP_SLA_BLOCKS,
            "after late claim only {remaining_after_late} blocks left before refund; need ≥ {}",
            OPERATOR_SWEEP_SLA_BLOCKS
        );
        // Early claim + max safe_sweep still leaves SLA.
        let max_sweep =
            zcrypt_core::spv::safe_sweep_conf(zcrypt_core::spv::BtcNet::Mainnet, u64::MAX);
        assert!(
            profile >= max_sweep + OPERATOR_SWEEP_SLA_BLOCKS,
            "profile must cover max safe_sweep ({max_sweep}) + SLA"
        );
    }

    #[test]
    fn assert_safe_shield_locktime_rejects_short_cltv() {
        let tip = 800_000u64;
        let too_short = (tip + 50) as u32; // way below mainnet requirement
        let err = assert_safe_shield_locktime(Network::Bitcoin, tip, too_short).unwrap_err();
        assert!(err.contains("too soon") || err.contains("below network profile"), "{err}");

        let ok_lt = (tip + btc_lock_blocks(Network::Bitcoin)) as u32;
        assert!(assert_safe_shield_locktime(Network::Bitcoin, tip, ok_lt).is_ok());
    }

    #[test]
    fn shield_timeouts_are_internally_staggered() {
        for net in [Network::Bitcoin, Network::Signet, Network::Regtest] {
            let (btc_lt, zc_to) = shield_timeouts(net, 100_000, 1_000).expect("timeouts");
            let btc_blocks = btc_lt as u64 - 100_000;
            let zc_blocks = zc_to - 1_000;
            // Wall-clock: ZC claim window + 1h < BTC lock window.
            let zc_secs = zc_blocks * ZC_BLOCK_TIME_SECS;
            let btc_secs = btc_blocks * BTC_BLOCK_TIME_SECS;
            assert!(
                zc_secs + 3600 < btc_secs,
                "{net:?}: zc {zc_secs}s not safely before btc {btc_secs}s"
            );
        }
    }

    #[test]
    fn redeem_btc_lock_shorter_than_shield_but_zc_burn_longer() {
        let net = Network::Bitcoin;
        assert!(btc_redeem_lock_blocks(net) < btc_lock_blocks(net));
        let burn = zc_redeem_timeout_blocks(net) * ZC_BLOCK_TIME_SECS;
        let op_lock = btc_redeem_lock_blocks(net) * BTC_BLOCK_TIME_SECS;
        assert!(
            burn > op_lock,
            "user zBTC burn must outlive operator BTC refund so user recovers if operator ghosts"
        );
    }

    #[test]
    fn conf_targets_match_spv_min_conf() {
        // Documented contract: bridge waits ≥ SPV mint floor.
        assert_eq!(
            zcrypt_core::spv::min_conf_for(zcrypt_core::spv::BtcNet::Mainnet),
            6
        );
        assert_eq!(
            zcrypt_core::spv::min_conf_for(zcrypt_core::spv::BtcNet::Signet),
            1
        );
    }
}
