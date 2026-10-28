//! Cross-chain BTC↔zBTC atomic-swap orchestration.
//!
//! One SHA-256 preimage settles both legs: a Bitcoin HTLC and a ZCrypt shield HTLC
//! escrow. The bridge reads the preimage *from whichever chain reveals it first*
//! and uses it to settle the other, so neither side can take without giving.

use zcrypt_shield::Blind;
use bitcoin::{Address, Amount, OutPoint, PublicKey, ScriptBuf};
use zcrypt_core::keys::{Account, Coin};
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_core::shield_tx::{self, Spend};
use zcrypt_core::spv::MintProof;
use zcrypt_shield::{Commitment, OutCoin, PubKey};

use crate::zcrypt::{ZcNode, Zcrypt};
use crate::{htlc_script, BtcBackend, HtlcUtxo, Key};

/// The default chain id the bridge binds into shield envelopes and open authorizations.
/// Prefer [`chain_id`], which honours `ZCRYPT_CHAIN_ID`; this constant stays for callers
/// that hardcode the production chain.
pub const CHAIN: &[u8] = b"zcrypt-1";

/// The chain id this process binds transactions to: env `ZCRYPT_CHAIN_ID` if set (a signet
/// or devnet chain), else [`CHAIN`]. Read once. A tx bound to the wrong chain id is rejected
/// by consensus, so a misconfiguration fails closed.
pub fn chain_id() -> &'static [u8] {
    static ID: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    ID.get_or_init(|| match std::env::var("ZCRYPT_CHAIN_ID") {
        Ok(v) if !v.trim().is_empty() => v.trim().as_bytes().to_vec(),
        _ => CHAIN.to_vec(),
    })
    .as_slice()
}

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

// ---- Redeem direction (zBTC -> BTC): the operator locks BTC the USER claims. ----
//
// Theft scenario this guards against (bridge H1): the user burn-locks zBTC with a SHORT
// ZCrypt escrow, the operator locks BTC with its usual (long) refund lock, the user lets
// the ZC escrow expire (zBTC refunded to them) and THEN claims the BTC. The operator's
// finalize fails ("escrow not open") and the reserve is drained. The BTC lock the operator
// funds must therefore expire BEFORE the ZC escrow does, with time to spare for the
// operator to land the ZC burn claim after the user's BTC claim confirms:
//
//   btc_lock_secs + REDEEM_FINALIZE_SLA_SECS  <=  (timeout_height - zc_tip) * ZC_BLOCK_TIME
//
// [`redeem_btc_locktime_for`] derives the lock from the escrow's remaining life and REFUSES
// to fund when that leaves the user less than [`min_user_claim_blocks`].

/// Operator time budget after the user's BTC claim confirms: read the preimage, submit the
/// ZC burn claim, survive a transient outage. Mainnet value; see [`redeem_finalize_sla_secs`].
pub const REDEEM_FINALIZE_SLA_SECS: u64 = 6 * 3600;
/// Minimum BTC lock (blocks) the operator will fund on mainnet: the user's claim window.
pub const MIN_USER_CLAIM_BLOCKS_MAINNET: u64 = 144;
// The default operator redeem lock (504 blocks) plus the finalize SLA fits inside the
// default ZC redeem escrow with the user's minimum window to spare.
// The default redeem escrow must leave room for at least the MINIMUM user claim window at
// half-speed Bitcoin plus the finalize SLA (the derived lock is min(nominal, what fits)).
const _: () = assert!(
    MIN_USER_CLAIM_BLOCKS_MAINNET * BTC_BLOCK_TIME_SECS * 2
        + MIN_USER_CLAIM_BLOCKS_MAINNET * BTC_BLOCK_TIME_SECS / 4
        + REDEEM_FINALIZE_SLA_SECS
        <= ZC_REDEEM_TIMEOUT_BLOCKS * ZC_BLOCK_TIME_SECS
);

/// Operator finalize budget (seconds) by network.
pub fn redeem_finalize_sla_secs(network: bitcoin::Network) -> u64 {
    match network {
        bitcoin::Network::Bitcoin => REDEEM_FINALIZE_SLA_SECS,
        bitcoin::Network::Signet => 3600,
        _ => 60,
    }
}

/// The shortest BTC lock the operator will fund for a redeem (blocks): below this the user
/// could not reliably claim before the operator's refund, so the redeem is refused instead.
pub fn min_user_claim_blocks(network: bitcoin::Network) -> u64 {
    match network {
        bitcoin::Network::Bitcoin => MIN_USER_CLAIM_BLOCKS_MAINNET,
        bitcoin::Network::Signet => 36,
        _ => 10,
    }
}

/// Safety slack the operator keeps between the BTC refund lock it funds and the ZC escrow
/// expiry, in seconds: at least the finalize SLA, and at least this fraction of the lock
/// itself (a lock of `L` Bitcoin blocks gets `L * 600 / SLACK_FRACTION_DEN` extra seconds),
/// so a run of slow Bitcoin blocks cannot push the user's claim past the ZC escrow on short
/// escrows either. With 1/4: a 504-block lock keeps 21 hours of slack, never just the 6-hour
/// SLA that a variance of a few percent in block times could eat (bridge N9).
pub const SLACK_FRACTION_DEN: u64 = 4;

/// How much slower than nominal (600 s) Bitcoin blocks are assumed to be able to run for the
/// whole life of a redeem lock. The BTC CLTV is in Bitcoin HEIGHTS while the ZC escrow expires
/// by ZC height (wall time); if Bitcoin runs slow enough the escrow expires first and the user
/// refunds the zBTC while still able to claim the BTC. Sizing the lock for half-speed Bitcoin
/// (2x) covers every historical hashrate shock with a wide margin.
pub const BTC_SLOWDOWN_FACTOR: u64 = 2;

/// The slack (seconds) required for a BTC lock of `lock_blocks` on `network`.
pub fn redeem_slack_secs(network: bitcoin::Network, lock_blocks: u64) -> u64 {
    redeem_finalize_sla_secs(network).max(lock_blocks * BTC_BLOCK_TIME_SECS / SLACK_FRACTION_DEN)
}

/// Minimum ZC escrow life (blocks) a redeem must have LEFT when the operator locks BTC:
/// the user's minimum claim window plus the slack that window needs. The daemon's
/// `WATCHER_FINALIZE_MARGIN` can only raise this floor, never lower it.
pub fn min_redeem_margin_blocks(network: bitcoin::Network) -> u64 {
    let min_lock = min_user_claim_blocks(network);
    (min_lock * BTC_BLOCK_TIME_SECS * BTC_SLOWDOWN_FACTOR + redeem_slack_secs(network, min_lock))
        / ZC_BLOCK_TIME_SECS
}

/// The BTC HTLC refund locktime the operator may fund for a redeem escrow that times out at
/// ZC height `timeout_height`, given the current tips: the network's redeem lock, SHRUNK so
/// it plus its slack ([`redeem_slack_secs`]) always expires before the ZC escrow. `Err` when
/// the escrow's remaining life leaves the user less than [`min_user_claim_blocks`]: refuse
/// to lock. The largest lock `L` with `L * 600 + max(SLA, L * 600 / 4) <= remaining` is
/// `min((remaining - SLA) / 600, remaining / 750)`.
pub fn redeem_btc_locktime_for(
    network: bitcoin::Network,
    btc_tip: u64,
    zc_tip: u64,
    timeout_height: u64,
) -> Result<u32, String> {
    let remaining_zc = timeout_height.saturating_sub(zc_tip);
    let remaining_secs = remaining_zc * ZC_BLOCK_TIME_SECS;
    let sla = redeem_finalize_sla_secs(network);
    // Every bound is evaluated with Bitcoin at 1/BTC_SLOWDOWN_FACTOR speed: the lock's wall
    // time is `lock * 600 * factor`, and the slack is on top of that.
    let slow_block = BTC_BLOCK_TIME_SECS * BTC_SLOWDOWN_FACTOR;
    let by_sla = remaining_secs.saturating_sub(sla) / slow_block;
    let by_fraction = remaining_secs / (slow_block + BTC_BLOCK_TIME_SECS / SLACK_FRACTION_DEN);
    let max_lock = by_sla.min(by_fraction);
    // Regtest adds a constant clock-lead allowance so the lock still clears the tip after a
    // `generatetoaddress` burst. Capped by `max_lock`, so it can never outlive the escrow.
    let mut wanted = btc_redeem_lock_blocks(network);
    if network == bitcoin::Network::Regtest {
        wanted = wanted.saturating_add(REGTEST_REDEEM_CLOCK_LEAD_BLOCKS);
    }
    let lock = wanted.min(max_lock);
    let min_lock = min_user_claim_blocks(network);
    if lock < min_lock {
        return Err(format!(
            "redeem: escrow timeout {timeout_height} leaves only {remaining_zc} ZC blocks (tip {zc_tip}); \
             with the {sla}s finalize SLA and proportional slack the BTC lock could be at most \
             {max_lock} blocks, below the {min_lock}-block minimum claim window: refusing to lock \
             reserve BTC (the user's zBTC refunds at the escrow expiry; nobody loses)"
        ));
    }
    debug_assert!(
        lock * BTC_BLOCK_TIME_SECS * BTC_SLOWDOWN_FACTOR + redeem_slack_secs(network, lock) <= remaining_secs
    );
    let lt = btc_tip.checked_add(lock).ok_or("btc tip + lock overflow")?;
    u32::try_from(lt).map_err(|_| "btc locktime overflow".to_string())
}

// ---- Deterministic redeem locks (bridge/swap audit 2026-10 H5) ----
//
// The BTC HTLC the operator funds is a P2WSH whose script commits to the CLTV. If that CLTV
// were derived from the Bitcoin tip at PLANNING time, a daemon that lost or rolled back its
// state file (or a second instance) would re-plan every open burn escrow with a different
// locktime, hence a different address, and `find_funded_htlc` could not see the funding
// already made: every redeem would be funded twice. The lock is therefore anchored to
// CONSENSUS data only: the ZC block the burn-lock was included in (its BFT time, which every
// node agrees on) mapped to a Bitcoin height through Bitcoin's own median-time-past. A replan
// at any later time reproduces the same script byte for byte.

/// How far behind the ZC block time the Bitcoin anchor is taken (seconds). Median-time-past
/// trails wall time by about an hour and varies with block luck; anchoring six hours back
/// guarantees that, when the daemon first plans (seconds after the burn), the anchor block is
/// already buried and can never move as more Bitcoin blocks arrive.
pub const REDEEM_ANCHOR_LAG_SECS: u64 = 6 * 3600;
/// How many Bitcoin blocks below the tip the anchor search looks (four weeks): a burn older
/// than that cannot have a live redeem escrow anyway.
pub const REDEEM_ANCHOR_LOOKBACK_BLOCKS: u64 = 4032;

fn header_time(hdr: &[u8; 80]) -> u64 {
    u32::from_le_bytes([hdr[68], hdr[69], hdr[70], hdr[71]]) as u64
}

/// Bitcoin median-time-past of block `h` (the median of the 11 timestamps ending at `h`;
/// fewer near genesis), fetching headers through `btc` with a per-call cache.
fn median_time_past(
    btc: &dyn BtcBackend,
    h: u64,
    cache: &mut std::collections::HashMap<u64, u64>,
) -> Result<u64, String> {
    let lo = h.saturating_sub(10);
    let mut ts = Vec::with_capacity(11);
    for x in lo..=h {
        let t = match cache.get(&x) {
            Some(t) => *t,
            None => {
                let t = header_time(&btc.block_header(x).map_err(|e| format!("header {x}: {e}"))?);
                cache.insert(x, t);
                t
            }
        };
        ts.push(t);
    }
    ts.sort_unstable();
    Ok(ts[ts.len() / 2])
}

/// The Bitcoin height anchored to unix time `t`: the HIGHEST block at or below `btc_tip`
/// whose median-time-past is `<= t - REDEEM_ANCHOR_LAG_SECS` (floored at the lookback window).
/// Deterministic in the confirmed Bitcoin chain and `t`; monotone in `t`.
pub fn btc_anchor_height(btc: &dyn BtcBackend, btc_tip: u64, t: u64) -> Result<u64, String> {
    btc_anchor_height_with_lag(btc, btc_tip, t, REDEEM_ANCHOR_LAG_SECS)
}

fn btc_anchor_height_with_lag(
    btc: &dyn BtcBackend,
    btc_tip: u64,
    t: u64,
    lag_secs: u64,
) -> Result<u64, String> {
    let target = t.saturating_sub(lag_secs);
    let mut cache = std::collections::HashMap::new();
    let mut lo = btc_tip.saturating_sub(REDEEM_ANCHOR_LOOKBACK_BLOCKS);
    let mut hi = btc_tip;
    if median_time_past(btc, lo, &mut cache)? > target {
        return Ok(lo);
    }
    // Invariant: mtp(lo) <= target. Find the greatest such height in [lo, hi].
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if median_time_past(btc, mid, &mut cache)? <= target {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Ok(lo)
}

/// The deterministic Bitcoin anchor for the burn-lock included in ZC block `lock_height`:
/// the ZC block's BFT time mapped through the median-time-past search. Production networks
/// lag [`REDEEM_ANCHOR_LAG_SECS`] so the anchor is already buried. Regtest uses lag 0 (the
/// burn's own BFT time): a 6h lag on a young regtest chain lands the CLTV in the past.
/// A lag of 0 still sits behind the tip when `generatetoaddress` has run the median time
/// ahead of wall clock; [`REGTEST_REDEEM_CLOCK_LEAD_BLOCKS`] covers that gap. The anchor
/// is never a pure function of the ZC height.
pub fn redeem_anchor_for_block(
    zc: &dyn ZcNode,
    btc: &dyn BtcBackend,
    lock_height: i64,
    btc_tip: u64,
) -> Result<u64, String> {
    let t = zc.block_time(lock_height).map_err(|e| format!("zc block time {lock_height}: {e}"))?;
    let lag = if btc.network() == bitcoin::Network::Regtest { 0 } else { REDEEM_ANCHOR_LAG_SECS };
    btc_anchor_height_with_lag(btc, btc_tip, t, lag)
}

/// The BTC refund locktime for a redeem escrow, DETERMINISTIC per escrow: sized by
/// [`redeem_btc_locktime_for`] from the burn's inclusion point (`anchor_btc`, `lock_height`)
/// rather than from the current tips, then RE-VALIDATED against the current tips with the same
/// rule, so every safety property holds for the funding actually made now:
///
/// * the user still has at least [`min_user_claim_blocks`] of Bitcoin blocks to claim, and
/// * the lock, at half-speed Bitcoin plus its slack, still expires before the ZC escrow.
///
/// Both checks only ever fail when the daemon plans long after the burn (an outage) or when
/// Bitcoin ran slower than the slowdown factor since the burn; the refusal is permanent and
/// safe (the user's zBTC refunds at expiry; nothing was locked).
pub fn redeem_btc_locktime_deterministic(
    network: bitcoin::Network,
    anchor_btc: u64,
    lock_height: u64,
    btc_tip: u64,
    zc_tip: u64,
    timeout_height: u64,
) -> Result<u32, String> {
    let lt = redeem_btc_locktime_for(network, anchor_btc, lock_height, timeout_height)?;
    let lock_now = (lt as u64).saturating_sub(btc_tip);
    let min_lock = min_user_claim_blocks(network);
    if lock_now < min_lock {
        return Err(format!(
            "redeem: deterministic lock {lt} (anchor {anchor_btc}, burn at ZC {lock_height}) leaves the user only \
             {lock_now} Bitcoin blocks from tip {btc_tip}, below the {min_lock}-block minimum claim window: refusing \
             to lock reserve BTC (planned too long after the burn; the user's zBTC refunds at the escrow expiry)"
        ));
    }
    let remaining_secs = timeout_height.saturating_sub(zc_tip) * ZC_BLOCK_TIME_SECS;
    let need = lock_now * BTC_BLOCK_TIME_SECS * BTC_SLOWDOWN_FACTOR + redeem_slack_secs(network, lock_now);
    if need > remaining_secs {
        return Err(format!(
            "redeem: deterministic lock {lt} needs {need}s at half-speed Bitcoin but the escrow has {remaining_secs}s \
             left (tip {zc_tip}, timeout {timeout_height}): refusing to lock reserve BTC"
        ));
    }
    Ok(lt)
}

/// The daemon's DEFAULT finalize margin (ZC blocks a redeem escrow must have left before the
/// operator locks BTC): the network's full redeem window, i.e. what an honest wallet's burn
/// escrow carries (`zc_redeem_timeout_blocks`). Mainnet: 475,200 (the value the production
/// compose ships). Any smaller escrow still gets a proportionally SHORTER BTC lock from
/// [`redeem_btc_locktime_for`], and anything under [`min_redeem_margin_blocks`] is refused.
pub fn default_finalize_margin(network: bitcoin::Network) -> u64 {
    zc_redeem_timeout_blocks(network)
}

/// Smallest redeem the operator serves (sats): mirrors the consensus minimum deposit, so a
/// redeem is always worth more than the fee to claim it (bridge M5).
pub fn min_redeem_sats(network: bitcoin::Network) -> u64 {
    zcrypt_core::spv::min_deposit_sats(spv_net(network))
}

/// Map a bitcoin crate network to the consensus SPV network enum. Testnet (3 and 4) take the
/// SIGNET profile (a real, public test network: real confirmation floors and sweep depths),
/// never the regtest one, whose instant-mining assumptions only hold for a private chain
/// (audit 2026-10 L15). Only `Regtest` itself maps to `Regtest`.
pub fn spv_net(network: bitcoin::Network) -> zcrypt_core::spv::BtcNet {
    match network {
        bitcoin::Network::Bitcoin => zcrypt_core::spv::BtcNet::Mainnet,
        bitcoin::Network::Regtest => zcrypt_core::spv::BtcNet::Regtest,
        _ => zcrypt_core::spv::BtcNet::Signet,
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

/// Extra blocks added to a **regtest** redeem lock, on top of [`btc_redeem_lock_blocks`].
///
/// `generatetoaddress` stamps each block at `max(median-time-past + 1, wall clock)`. A burst
/// therefore finishes with its tip time ahead of wall clock, and ahead of the ZC burn's BFT
/// time. The lag-0 anchor (highest block whose median-time-past is still `<=` that BFT time)
/// then sits the whole burst behind the tip — a hundred blocks or more after the shields and
/// maturity mines in a live test. The nominal 50-block regtest lock does not reach back over
/// that lead, so a burn that was just included looks "planned too late" and the watcher
/// refuses to fund it.
///
/// The allowance is a constant, still capped by the escrow's half-speed budget inside
/// [`redeem_btc_locktime_for`], so a replan reproduces the same CLTV. Mainnet and signet do
/// not need it: their six-hour anchor lag is ~36 blocks and their locks are 504 and 288.
const REGTEST_REDEEM_CLOCK_LEAD_BLOCKS: u64 = 288;

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

/// ZC burn-escrow lifetime (blocks) for redeems on this network: the operator's full BTC
/// lock plus an extra margin that is never less than the slack [`redeem_btc_locktime_for`]
/// demands for that lock, so an honest wallet's escrow always gets the full lock.
pub fn zc_redeem_timeout_blocks(network: bitcoin::Network) -> u64 {
    let lock = btc_redeem_lock_blocks(network);
    let btc_secs = lock * BTC_BLOCK_TIME_SECS;
    let extra = match network {
        bitcoin::Network::Bitcoin => ZC_REDEEM_EXTRA_SECS,
        bitcoin::Network::Signet => 12 * 3600,
        _ => 3600,
    };
    (btc_secs + extra.max(redeem_slack_secs(network, lock))) / ZC_BLOCK_TIME_SECS
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
    let rate = crate::cap_fee_rate(backend.fee_rate_sat_vb(target)?);
    let sats = (rate * HTLC_SPEND_VSIZE as f64).ceil() as u64;
    Ok(Amount::from_sat(sats.max(500)))
}

/// [`htlc_spend_fee`] additionally capped against the value being spent (never more than a
/// quarter of it, except the 500-sat relay floor): a fee oracle cannot make a claim or
/// refund burn the HTLC in fees (bridge M4).
pub fn htlc_spend_fee_for(backend: &dyn BtcBackend, target: u32, value_sat: u64) -> Result<Amount, String> {
    let fee = htlc_spend_fee(backend, target)?.to_sat();
    Ok(Amount::from_sat(crate::cap_fee_for_value(fee, value_sat, 500)?))
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
/// `gas_blind(64) ‖ gas_len(u32 LE) ‖ gas_tx`, where `gas_tx` is a ZCRYPT shield spend of
/// `gas_coin` (owned by `gas_owner`) whose output[0] burns exactly MIN_FEE ZCRYPT and whose
/// change returns to `gas_owner`. `payload` is the transparent body that follows this
/// prefix; the gas proof is bound to it.
pub fn build_gas_prefix(
    zc: &Zcrypt,
    gas_owner: &Account,
    gas_coin: &Coin,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
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
    let gas_tx = build_shield_spend_bound(
        zc,
        &[gas_coin.clone()],
        &[burn, chg],
        0,
        vec![zcrypt_core::keys::cover_note_bytes(), chg_note],
        &shield_tx::gas_pay_envelope(payload),
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

/// Transparent body of a REGISTER tx: the bytes that follow the gas prefix.
pub fn register_body(decimals: u8, ticker: &str, max_supply: u64, authority: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(2 + ticker.len() + 8 + 32);
    t.push(decimals);
    t.push(ticker.len() as u8);
    t.extend_from_slice(ticker.as_bytes());
    t.extend_from_slice(&max_supply.to_le_bytes());
    t.extend_from_slice(authority);
    t
}

/// Transparent body of an SPV REGISTER tx (33-byte reserve key in place of the authority).
pub fn register_spv_body(decimals: u8, ticker: &str, max_supply: u64, reserve_pk: &[u8; 33]) -> Vec<u8> {
    let mut t = Vec::with_capacity(2 + ticker.len() + 8 + 33);
    t.push(decimals);
    t.push(ticker.len() as u8);
    t.extend_from_slice(ticker.as_bytes());
    t.extend_from_slice(&max_supply.to_le_bytes());
    t.extend_from_slice(reserve_pk);
    t
}

/// Transparent body of an HTLC_OPEN tx: the bytes that follow the gas prefix.
/// 120-byte header, then the claim [`CoinOpening`], then the M-of-N capability.
pub fn open_body(
    asset: u64,
    value: u64,
    lock: &[u8; 32],
    timeout: u64,
    claim_pk: &PubKey,
    opening: &zcrypt_core::htlc_shield::CoinOpening,
    auth: &[u8],
) -> Vec<u8> {
    let enc = opening.encode();
    let mut t = Vec::with_capacity(8 + 8 + 32 + 8 + 64 + enc.len() + auth.len());
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(&value.to_le_bytes());
    t.extend_from_slice(lock);
    t.extend_from_slice(&timeout.to_le_bytes());
    t.extend_from_slice(&pk_bytes(claim_pk));
    t.extend_from_slice(&enc);
    t.extend_from_slice(auth);
    t
}

/// Build a REGISTER tx (0x59). `gas` is the encoded gas prefix from [`build_gas_prefix`],
/// bound to [`register_body`] of these same fields.
pub fn register_tx(ticker: &str, decimals: u8, authority: &[u8; 32], max_supply: u64, gas: &[u8]) -> Vec<u8> {
    let mut t = vec![0x59u8];
    t.extend_from_slice(gas);
    t.extend_from_slice(&register_body(decimals, ticker, max_supply, authority));
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
    t.extend_from_slice(&register_spv_body(decimals, ticker, max_supply, reserve_pk));
    t
}

/// Build a ROTATE_RESERVE tx (`0x69`): move an SPV asset's Bitcoin reserve to `new_pk`,
/// authorised by the CURRENT reserve key's signature (`spv::sign_reserve_rotation`). The
/// chain retires the old key (its in-flight deposits still mint and can be re-anchored) and
/// requires every later deposit to pay the new key.
pub fn rotate_reserve_tx(asset: u64, old_pk: &[u8; 33], new_pk: &[u8; 33], sig: &[u8; 64]) -> Vec<u8> {
    let mut t = vec![0x69u8];
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(old_pk);
    t.extend_from_slice(new_pk);
    t.extend_from_slice(sig);
    t
}

/// The asset's CURRENT Bitcoin reserve pubkey as published by consensus (`/asset/id`), or
/// `None` for a non-SPV asset / a node that predates reserve rotation. Wallets must fund
/// deposits to THIS key: after a rotation the previously known key only mints for deposits
/// mined within a short grace window.
pub fn chain_reserve_pk(zc: &dyn ZcNode, asset: u64) -> Result<Option<[u8; 33]>, String> {
    let raw = zc.query(&format!("/asset/id/{asset}"))?;
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("/asset/id/{asset}: {e}"))?;
    match v.get("reserve_pk").and_then(|p| p.as_str()) {
        Some(h) if !h.is_empty() => {
            let b = hex::decode(h).map_err(|e| format!("reserve_pk hex: {e}"))?;
            let pk: [u8; 33] = b.as_slice().try_into().map_err(|_| "reserve_pk is not 33 bytes".to_string())?;
            Ok(Some(pk))
        }
        _ => Ok(None),
    }
}

/// The asset's authority epoch (the value a reserve rotation must be signed against).
pub fn chain_authority_epoch(zc: &dyn ZcNode, asset: u64) -> Result<u64, String> {
    let raw = zc.query(&format!("/asset/id/{asset}"))?;
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("/asset/id/{asset}: {e}"))?;
    Ok(v.get("authority_epoch").and_then(|e| e.as_u64()).unwrap_or(0))
}

/// The operator's reserve keys: the CURRENT one (funds redeems, is what the chain pins) and
/// keys RETIRED by rotation that still have deposits to sweep or redeems to refund. Every
/// deposit/refund is signed with the key whose pubkey is in that HTLC's script.
pub struct ReserveKeys<'a> {
    pub current: &'a Key,
    pub previous: &'a [Key],
}

impl<'a> ReserveKeys<'a> {
    /// A never-rotated operator.
    pub fn single(current: &'a Key) -> Self {
        ReserveKeys { current, previous: &[] }
    }
    /// The key whose compressed pubkey is `pk33`, if the operator holds it.
    pub fn key_for(&self, pk33: &[u8]) -> Option<&'a Key> {
        std::iter::once(self.current)
            .chain(self.previous.iter())
            .find(|k| k.pk.inner.serialize().as_slice() == pk33)
    }
    /// The key whose pubkey appears in an HTLC `script` (the refund key of a redeem the
    /// operator funded), if held.
    pub fn key_in_script(&self, script: &[u8]) -> Option<&'a Key> {
        std::iter::once(self.current)
            .chain(self.previous.iter())
            .find(|k| script.windows(33).any(|w| w == k.pk.inner.serialize()))
    }
    /// Every held pubkey, current first.
    pub fn pubkeys(&self) -> Vec<[u8; 33]> {
        std::iter::once(self.current)
            .chain(self.previous.iter())
            .map(|k| k.pk.inner.serialize())
            .collect()
    }
}

// ---- Validator BOND authentication (signed on the validator HOST, never in the wallet) ----

/// The BOND (0x57) authentication message, byte-identical to the wallet's `bond_message`
/// and to what consensus verifies with `verify_strict`:
/// `"ZCRYPT-BOND-v1" ‖ chain_id ‖ consensus_pubkey(32) ‖ stake_le(8) ‖ reward(32) ‖
///  commission_bps_le(2) ‖ nonce_le(8)`.
pub fn bond_message(chain_id: &[u8], pk: &[u8; 32], stake: u64, reward: &[u8; 32], commission_bps: u16, nonce: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(14 + chain_id.len() + 32 + 8 + 32 + 2 + 8);
    msg.extend_from_slice(b"ZCRYPT-BOND-v1");
    msg.extend_from_slice(chain_id);
    msg.extend_from_slice(pk);
    msg.extend_from_slice(&stake.to_le_bytes());
    msg.extend_from_slice(reward);
    msg.extend_from_slice(&commission_bps.to_le_bytes());
    msg.extend_from_slice(&nonce.to_le_bytes()); // replay-protection nonce
    msg
}

/// Sign a BOND message with the validator's ed25519 consensus key (the first 32 bytes of
/// `priv_validator_key.json`). This is the `bond_validator sign` step of the wallet's
/// two-step bond: the wallet prepares the parameters, the HOST produces this signature,
/// the wallet funds the pledge and broadcasts. Returns the 64-byte signature.
pub fn sign_bond(
    sk: &ed25519_dalek::SigningKey,
    chain_id: &[u8],
    stake: u64,
    reward: &[u8; 32],
    commission_bps: u16,
    nonce: u64,
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let pk = sk.verifying_key().to_bytes();
    sk.sign(&bond_message(chain_id, &pk, stake, reward, commission_bps, nonce)).to_bytes()
}

/// The zBTC asset id on this chain. zBTC is bound to its reserve key in GENESIS
/// (`zbtc_reserve_pk`), so nothing here registers it: if the chain has no zBTC this fails
/// with instructions for the chain operator. Use instead of the old fire-and-forget
/// `register_spv_tx` broadcast.
pub fn ensure_zbtc_registered(zc: &dyn ZcNode) -> Result<u64, String> {
    match zc.query("/asset/by_ticker/zBTC") {
        Ok(s) if !s.trim().is_empty() => s.trim().parse().map_err(|e| format!("zBTC asset id: {e}")),
        _ => Err("zBTC is not registered on this chain. It must be bound at genesis: set \
                  ZCRYPT_RESERVE_PK to the operator's 33-byte compressed reserve pubkey (hex) \
                  before the chain is created (print it with `cargo run -p zcrypt-bridge --bin \
                  reserve_pubkey`). A running chain cannot add zBTC."
            .to_string()),
    }
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
    opening: &zcrypt_core::htlc_shield::CoinOpening,
) -> Vec<u8> {
    let mut t = vec![0x64u8];
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(&value.to_le_bytes());
    t.extend_from_slice(lock);
    t.extend_from_slice(&timeout.to_le_bytes());
    t.extend_from_slice(&pk_bytes(claim_pk));
    // Recipient binding, extended to EVERY open parameter including the claim coin:
    // the refund key signs the chain, outpoint, claim_pk, asset, value, hashlock,
    // timeout, claim commitment and note bind, so a mempool front-runner can neither
    // redirect the mint nor swap the note for one the beneficiary cannot decrypt.
    // `value` here is the GROSS deposit; the opening itself is the net of the bridge fee.
    let txid = proof.funding_txid().expect("open_spv_tx: proof carries a valid funding tx");
    let mut op = [0u8; 36];
    op[..32].copy_from_slice(&txid);
    op[32..].copy_from_slice(&proof.vout.to_le_bytes());
    let a = zcrypt_core::spv::OpenAuth {
        chain_id: chain_id(),
        outpoint: &op,
        claim_pk,
        asset_id: asset,
        value,
        hashlock: lock,
        timeout_height: timeout,
        claim_commitment: &opening.coin.commitment,
        note_bind: &opening.coin.note_bind(),
    };
    let auth = zcrypt_core::spv::sign_open_auth(&refund.sk, &a);
    t.extend_from_slice(&auth);
    t.extend_from_slice(&opening.encode());
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
pub fn relay_btc_headers(zc: &dyn ZcNode, btc: &dyn crate::BtcBackend) -> Result<u64, String> {
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
pub fn open_tx(
    asset: u64,
    value: u64,
    lock: &[u8; 32],
    timeout: u64,
    claim_pk: &PubKey,
    opening: &zcrypt_core::htlc_shield::CoinOpening,
    auth: &[u8],
    gas: &[u8],
) -> Vec<u8> {
    let mut t = vec![0x5Au8];
    t.extend_from_slice(gas);
    t.extend_from_slice(&open_body(asset, value, lock, timeout, claim_pk, opening, auth));
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
/// escrow refunds its locked zBTC back to the owner. Recover that coin by decrypting
/// the escrow's refund note (`refund_enc_note` from [`query_escrow`]), not with
/// `htlc_coin(value, asset, escrow_id)` — the blind is not a function of the escrow id.
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
    blind: &Blind,
    asset: u64,
    lock: &[u8; 32],
    timeout: u64,
    refund_pk: &PubKey,
    stx: &shield_tx::ShieldTx,
    refund: &zcrypt_core::htlc_shield::CoinOpening,
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
    t.extend_from_slice(&refund.encode());
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
    blind: &Blind,
    asset: u64,
    lock: &[u8; 32],
    timeout: u64,
    refund_pk: &PubKey,
    stx: &shield_tx::ShieldTx,
    refund: &zcrypt_core::htlc_shield::CoinOpening,
) -> Vec<u8> {
    let mut t = vec![0x67u8];
    t.extend_from_slice(&btc_claim_pk.inner.serialize()); // 33 bytes, compressed secp256k1
    // The 0x5D burn-lock body (header + refund opening + shield tx), byte-identical.
    let body = burn_lock_tx(value, blind, asset, lock, timeout, refund_pk, stx, refund);
    t.extend_from_slice(&body[1..]);
    t
}

/// Parse a `0x67` burn-lock-with-btc-key tx body (bytes AFTER the tag) into the fields the redeem
/// watcher needs: the user's BTC claim pubkey (33B), asset, value, hashlock, timeout, refund_pk.
/// Header only (`len >= HEAD`): a refund opening and the shield tx may follow and are not parsed.
/// Fail-closed on a short header.
pub fn parse_burn_lock_btc(payload: &[u8]) -> Option<([u8; 33], u64, u64, [u8; 32], u64, PubKey)> {
    // btc_claim_pk(33) ‖ value(8) ‖ blind(BLIND_BYTES) ‖ asset(8) ‖ hashlock(32) ‖ timeout(8) ‖ refund_pk(64) ‖ stx
    const BB: usize = zcrypt_shield::BLIND_BYTES;
    const V: usize = 33;
    const A: usize = V + 8 + BB; // the blind is not needed operator-side
    const H: usize = A + 8;
    const T: usize = H + 32;
    const R: usize = T + 8;
    const HEAD: usize = R + 64;
    if payload.len() < HEAD {
        return None;
    }
    let btc_claim_pk: [u8; 33] = payload[0..V].try_into().ok()?;
    let value = u64::from_le_bytes(payload[V..V + 8].try_into().ok()?);
    let asset = u64::from_le_bytes(payload[A..A + 8].try_into().ok()?);
    let hashlock: [u8; 32] = payload[H..T].try_into().ok()?;
    let timeout = u64::from_le_bytes(payload[T..R].try_into().ok()?);
    let mut refund_pk: PubKey = [0u64; 8];
    for (i, limb) in refund_pk.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(payload[R + i * 8..R + 8 + i * 8].try_into().ok()?);
    }
    Some((btc_claim_pk, asset, value, hashlock, timeout, refund_pk))
}

/// Build a swap-lock tx (0x62): lock existing coins into a swap escrow. Like a burn-lock
/// but with TWO keys — `counterparty_pk` (claims with the preimage) and `refund_pk` (the
/// locker, refunded on timeout). Two of these across two assets, one hashlock, = an atomic
/// in-pool swap. `stx`'s output[0] must be `commit_asset(value, blind, BURN_PK, asset)` and
/// its fee is 0. After the 248-byte header come the claim opening, the refund opening,
/// then the ZCRYPT gas prefix (`gas_blind ‖ gas_len ‖ gas_tx`), then the asset spend.
/// The gas note's output[0] burns 0.01 ZCRYPT. Wire order is claim then refund.
#[allow(clippy::too_many_arguments)]
pub fn swap_lock_tx(
    value: u64,
    blind: &Blind,
    asset: u64,
    lock: &[u8; 32],
    timeout: u64,
    counterparty_pk: &PubKey,
    refund_pk: &PubKey,
    gas_blind: &Blind,
    gas_tx: &shield_tx::ShieldTx,
    stx: &shield_tx::ShieldTx,
    claim: &zcrypt_core::htlc_shield::CoinOpening,
    refund: &zcrypt_core::htlc_shield::CoinOpening,
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
    t.extend_from_slice(&claim.encode());
    t.extend_from_slice(&refund.encode());
    let gas_bytes = shield_tx::to_bytes(gas_tx);
    for limb in gas_blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&(gas_bytes.len() as u32).to_le_bytes());
    t.extend_from_slice(&gas_bytes);
    t.extend_from_slice(&shield_tx::to_bytes(stx));
    t
}

/// Parse the 248-byte header of a SWAP_LOCK (`0x62`) payload (the bytes after the tag):
/// `value(8) ‖ blind(BLIND_BYTES) ‖ asset(8) ‖ hashlock(32) ‖ timeout(8) ‖ counterparty_pk(64) ‖
/// refund_pk(64)`. The claim and refund openings, a ZCRYPT gas prefix and the asset spend
/// follow that header; this parser does not read them (a longer payload still succeeds).
/// Returns `(value, blind, asset, hashlock, timeout, counterparty_pk, refund_pk)`.
#[allow(clippy::type_complexity)]
pub fn parse_swap_lock(payload: &[u8]) -> Option<(u64, Blind, u64, [u8; 32], u64, PubKey, PubKey)> {
    const BB: usize = zcrypt_shield::BLIND_BYTES;
    const A: usize = 8 + BB;
    const H: usize = A + 8;
    const T: usize = H + 32;
    const C: usize = T + 8;
    const R: usize = C + 64;
    const HEAD: usize = R + 64;
    if payload.len() < HEAD {
        return None;
    }
    let value = u64::from_le_bytes(payload[0..8].try_into().ok()?);
    let mut blind: Blind = [0u64; zcrypt_shield::BLIND_LIMBS];
    for (i, limb) in blind.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(payload[8 + i * 8..16 + i * 8].try_into().ok()?);
    }
    let asset = u64::from_le_bytes(payload[A..A + 8].try_into().ok()?);
    let mut hashlock = [0u8; 32];
    hashlock.copy_from_slice(&payload[H..H + 32]);
    let timeout = u64::from_le_bytes(payload[T..T + 8].try_into().ok()?);
    let pk = |off: usize| -> Option<PubKey> {
        let mut k = [0u64; 8];
        for (i, limb) in k.iter_mut().enumerate() {
            *limb = u64::from_le_bytes(payload[off + i * 8..off + i * 8 + 8].try_into().ok()?);
        }
        Some(k)
    };
    Some((value, blind, asset, hashlock, timeout, pk(C)?, pk(R)?))
}

pub fn seed_tx(c: &Commitment) -> Vec<u8> {
    let mut t = vec![0x56u8];
    for x in c {
        t.extend_from_slice(&x.to_le_bytes());
    }
    t
}

/// A funded, confirmed, header-relayed SPV deposit with its mint proof built, NOT yet
/// opened on ZCrypt. Drivers use it to exercise the open/claim gates step by step.
pub struct PreparedDeposit {
    pub proof: zcrypt_core::spv::MintProof,
    pub lock: [u8; 32],
    pub zc_timeout: u64,
    pub btc_locktime: u32,
    pub utxo: HtlcUtxo,
    pub sats: u64,
}

/// Mint proof for a confirmed funding tx: raw tx, coinbase, and a merkle block that
/// matches both. The coinbase is the index-0 leaf, which pins the tree height.
pub fn mint_proof_for_txid(
    backend: &dyn BtcBackend,
    reserve_pk: [u8; 33],
    refund_pk: [u8; 33],
    btc_locktime: u32,
    vout: u32,
    txid: &bitcoin::Txid,
) -> Result<MintProof, String> {
    Ok(MintProof {
        reserve_pk,
        refund_pk,
        btc_locktime,
        vout,
        raw_tx: backend.raw_tx(txid)?,
        merkle_block: backend.txout_proof(txid)?,
        coinbase_raw: backend.coinbase_raw(txid)?,
    })
}

/// Fund a Bitcoin HTLC to `reserve_pk` for `preimage`, confirm it, relay the headers, and
/// build the SPV mint proof. Returns everything an `open_spv_tx` needs, without opening.
#[allow(clippy::too_many_arguments)]
pub fn prepare_spv_deposit(
    zc: &Zcrypt,
    user_btc: &dyn BtcBackend,
    user_refund: &Key,
    reserve_pk: &PublicKey,
    preimage: &[u8],
    btc_amount: Amount,
) -> Result<PreparedDeposit, String> {
    let lock = htlc_hashlock(preimage);
    let net = user_btc.network();
    let (btc_locktime, zc_timeout) = shield_timeouts(net, user_btc.height()?, zc.height()? as u64)?;
    let script = htlc_script(&lock, reserve_pk, &user_refund.pk, btc_locktime);
    let utxo = user_btc.fund_htlc(&script, btc_amount)?;
    user_btc.confirm(&utxo.outpoint.txid)?;
    relay_btc_headers(zc, user_btc)?;
    let proof = mint_proof_for_txid(
        user_btc,
        reserve_pk.inner.serialize(),
        user_refund.pk.inner.serialize(),
        btc_locktime,
        utxo.outpoint.vout,
        &utxo.outpoint.txid,
    )?;
    Ok(PreparedDeposit { proof, lock, zc_timeout, btc_locktime, utxo, sats: btc_amount.to_sat() })
}

/// The escrow id a successful open/lock broadcast reports in its result data.
pub fn escrow_id_from(data: &str) -> Result<[u8; 32], String> {
    let v: serde_json::Value = serde_json::from_str(data).map_err(|e| e.to_string())?;
    let hexs = v["escrow_id"].as_str().ok_or("no escrow_id in tx result")?;
    let raw = hex::decode(hexs).map_err(|e| e.to_string())?;
    let id: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("escrow_id in tx result is {} bytes, want 32", raw.len()))?;
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
        tree.append(c).unwrap();
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
    shield_tx::build_bound(chain_id(), &spends, outputs, fee, notes, envelope)
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
    // Main transfer: no in-tx fee. The gas proof is bound to this tx's binding hash.
    let main_tx = build_shield_spend(zc, main_inputs, main_outs, 0, main_notes)?;
    let gas_env = shield_tx::gas_pay_envelope(&shield_tx::txbind(chain_id(), &main_tx));
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
    let gas_tx = build_shield_spend_bound(
        zc,
        &[gas_coin.clone()],
        &[burn, chg],
        0,
        vec![zcrypt_core::keys::cover_note_bytes(), chg_note],
        &gas_env,
    )?;
    // Bundle: 0x55 ‖ gas_blind(64) ‖ gas_len(4) ‖ gas_tx ‖ main_tx.
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
    const BB: usize = zcrypt_shield::BLIND_BYTES;
    if b.len() < BB + 4 {
        return None;
    }
    let gas_len = u32::from_le_bytes(b[BB..BB + 4].try_into().ok()?) as usize;
    let gas_end = (BB + 4).checked_add(gas_len)?;
    if b.len() < gas_end {
        return None;
    }
    let gas_tx = shield_tx::from_bytes(&b[BB + 4..gas_end])?;
    let main_tx = shield_tx::from_bytes(&b[gas_end..])?;
    Some((gas_tx, main_tx))
}

/// Build a **native ZCRYPT transfer** (`0x6A`): `0x6A ‖ burn_value(8) ‖ burn_blind(64) ‖
/// shield_tx`, where `stx.output[0] == commit_asset(burn_value, burn_blind, BURN_PK, ZCRYPT)`
/// and `burn_value ≥ MIN_FEE`. ONE proof: the revealed ZCRYPT burn pins the (single-asset)
/// spend to ZCRYPT, so the gas is ZCRYPT without a second coin or a bundled gas note.
pub fn zcrypt_transfer_tx(burn_value: u64, burn_blind: &Blind, stx: &shield_tx::ShieldTx) -> Vec<u8> {
    let body = shield_tx::to_bytes(stx);
    let mut t = Vec::with_capacity(1 + 8 + zcrypt_shield::BLIND_BYTES + body.len());
    t.push(0x6Au8);
    t.extend_from_slice(&burn_value.to_le_bytes());
    for limb in burn_blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&body);
    t
}

/// Parse a native ZCRYPT transfer payload (the bytes AFTER the `0x6A` tag) into
/// `(burn_value, burn_blind, shield_tx)`, for scanning received coins. Mirrors the node.
pub fn parse_zcrypt_transfer_payload(b: &[u8]) -> Option<(u64, Blind, shield_tx::ShieldTx)> {
    const BB: usize = zcrypt_shield::BLIND_BYTES;
    if b.len() < 8 + BB {
        return None;
    }
    let value = u64::from_le_bytes(b[0..8].try_into().ok()?);
    let mut blind: Blind = [0u64; zcrypt_shield::BLIND_LIMBS];
    for (i, limb) in blind.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(b[8 + i * 8..16 + i * 8].try_into().ok()?);
    }
    let stx = shield_tx::from_bytes(&b[8 + BB..])?;
    Some((value, blind, stx))
}

/// Prove and encode a native ZCRYPT transfer of `recipient` (an `OutCoin` of `amount` ZCRYPT)
/// from `inputs` (1..=N_IN ZCRYPT coins), burning exactly `burn` (≥ MIN_FEE; a wallet burns
/// `MIN_FEE`, or `MIN_FEE + dust` to avoid keeping a dust change coin) and returning the
/// change to `change_to`. `recipient_note` is the on-chain note for output[1] (a real note,
/// or cover bytes for a stealth/bearer send). Returns the tx bytes and the change coin.
/// This is how a wallet holding a SINGLE ZCRYPT coin sends: no second coin, no second proof.
pub fn build_zcrypt_transfer(
    zc: &Zcrypt,
    inputs: &[Coin],
    recipient: OutCoin,
    recipient_note: Vec<u8>,
    change_to: &Account,
    burn: u64,
) -> Result<(Vec<u8>, Coin), String> {
    if inputs.is_empty() || inputs.iter().any(|c| c.asset_id != zcrypt_shield::ASSET_ZCRYPT) {
        return Err("a native ZCRYPT transfer spends ZCRYPT coins only".to_string());
    }
    if recipient.3 != zcrypt_shield::ASSET_ZCRYPT {
        return Err("a native ZCRYPT transfer pays ZCRYPT only".to_string());
    }
    let total: u64 = inputs.iter().map(|c| c.value).sum();
    let change = total
        .checked_sub(recipient.0)
        .and_then(|r| r.checked_sub(burn))
        .ok_or_else(|| format!("insufficient funds: inputs {total} < amount {} + burn {burn}", recipient.0))?;
    let burn_blind = zcrypt_core::keys::random_blind();
    let burn_out: OutCoin = (burn, burn_blind, zcrypt_core::htlc_shield::BURN_PK, zcrypt_shield::ASSET_ZCRYPT);
    let chg_blind = zcrypt_core::keys::random_blind();
    let chg_out = zcrypt_core::keys::out_coin(&change_to.normal_address(), change, chg_blind);
    let chg_note = zcrypt_core::kem::ciphertext_to_bytes(&zcrypt_core::keys::encrypt_note(&change_to.normal_address(), change, chg_blind));
    let stx = build_shield_spend_n(zc, inputs, &[burn_out, recipient, chg_out], 0, vec![zcrypt_core::keys::cover_note_bytes(), recipient_note, chg_note], &[])?;
    Ok((zcrypt_transfer_tx(burn, &burn_blind, &stx), change_to.own_coin(change, chg_blind)))
}

/// [`build_shield_spend_bound`] for any output count up to `N_OUT` (short lists are padded by
/// `shield_tx::build`).
pub fn build_shield_spend_n(
    zc: &Zcrypt,
    coins: &[Coin],
    outputs: &[OutCoin],
    fee: u64,
    notes: Vec<Vec<u8>>,
    envelope: &[u8],
) -> Result<shield_tx::ShieldTx, String> {
    let leaves = zc.leaves()?;
    let mut tree = zcrypt_shield::tree::CommitmentTree::new();
    for &c in &leaves {
        tree.append(c).unwrap();
    }
    let mut spends = Vec::new();
    for coin in coins {
        let idx = find_index(&leaves, &coin.commitment()).ok_or("input coin not on chain")?;
        let (path_siblings, path_dirs) = tree.path(idx as usize).ok_or("input coin not in commitment tree")?;
        spends.push(Spend {
            value: coin.value,
            blind: coin.blind,
            spend_secret: coin.spend_secret,
            asset_id: coin.asset_id,
            path_siblings,
            path_dirs,
        });
    }
    shield_tx::build_bound(chain_id(), &spends, outputs, fee, notes, envelope).ok_or("shield proof failed".to_string())
}

/// Build a **native swap lock** (`0x6B`): the 0x62 header and openings, then `sponsor_ref`
/// (32 bytes) and the asset spend — NO gas prefix. For a ZCRYPT lock `sponsor_ref` is the
/// escrow id of the counter-lock it pays for (`stx.fee ≥ 2 × MIN_FEE`), or all-zero
/// (`stx.fee ≥ MIN_FEE`, sponsors nothing). For any other asset it is the live ZCRYPT swap
/// lock that sponsors this one (`stx.fee == 0`).
#[allow(clippy::too_many_arguments)]
pub fn swap_lock_native_tx(
    value: u64,
    blind: &Blind,
    asset: u64,
    lock: &[u8; 32],
    timeout: u64,
    counterparty_pk: &PubKey,
    refund_pk: &PubKey,
    sponsor_ref: &[u8; 32],
    stx: &shield_tx::ShieldTx,
    claim: &zcrypt_core::htlc_shield::CoinOpening,
    refund: &zcrypt_core::htlc_shield::CoinOpening,
) -> Vec<u8> {
    let mut t = vec![0x6Bu8];
    t.extend_from_slice(&value.to_le_bytes());
    for limb in blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(lock);
    t.extend_from_slice(&timeout.to_le_bytes());
    t.extend_from_slice(&pk_bytes(counterparty_pk));
    t.extend_from_slice(&pk_bytes(refund_pk));
    t.extend_from_slice(sponsor_ref);
    t.extend_from_slice(&claim.encode());
    t.extend_from_slice(&refund.encode());
    t.extend_from_slice(&shield_tx::to_bytes(stx));
    t
}

/// Parse the header of a native swap lock (the bytes AFTER the `0x6B` tag):
/// `(value, blind, asset, hashlock, timeout, counterparty_pk, refund_pk, sponsor_ref)`.
#[allow(clippy::type_complexity)]
pub fn parse_swap_lock_native(payload: &[u8]) -> Option<(u64, Blind, u64, [u8; 32], u64, PubKey, PubKey, [u8; 32])> {
    const HEAD: usize = 8 + zcrypt_shield::BLIND_BYTES + 8 + 32 + 8 + 64 + 64;
    let (value, blind, asset, hashlock, timeout, cp, refund) = parse_swap_lock(payload)?;
    let mut sponsor_ref = [0u8; 32];
    sponsor_ref.copy_from_slice(payload.get(HEAD..HEAD + 32)?);
    Some((value, blind, asset, hashlock, timeout, cp, refund, sponsor_ref))
}

/// The gas a native swap lock of `asset` burns in-proof: a ZCRYPT lock pays `MIN_FEE` for
/// itself and another `MIN_FEE` when it sponsors a counter-lock; any other asset pays 0 (it
/// must be sponsored). Mirrors `Node::native_lock_gas_rule`.
pub fn native_lock_fee(asset: u64, sponsors: bool) -> u64 {
    if asset != zcrypt_shield::ASSET_ZCRYPT {
        0
    } else if sponsors {
        2 * zcrypt_core::emission::MIN_FEE
    } else {
        zcrypt_core::emission::MIN_FEE
    }
}

/// The timeout of a lock placed SECOND against a sponsor that was placed first: the sponsor
/// (the ZCRYPT leg, claimed by the party who reveals the preimage) must expire
/// [`SWAP_MAKER_CLAIM_MARGIN_BLOCKS`] before the sponsored leg, so the ZCRYPT giver always
/// has time to claim after the reveal. Deterministic, so the sponsor can name the sponsored
/// lock's id before it exists.
pub fn sponsored_lock_timeout(sponsor_timeout: u64) -> u64 {
    sponsor_timeout + SWAP_MAKER_CLAIM_MARGIN_BLOCKS
}

/// Lock `value` of `asset` from `locker`'s `coins` into a swap escrow claimable by
/// `counterparty` with NO gas note (`0x6B`). ZCRYPT: the fee is burned in-proof (one coin is
/// enough); `sponsor_ref` names the counter-lock to sponsor, or `[0; 32]`. Other assets: fee
/// 0, `sponsor_ref` is the ZCRYPT lock that sponsors this one. Broadcasts and returns
/// `(escrow_id, change_coin, claim_enc_note)`.
#[allow(clippy::too_many_arguments)]
pub fn send_swap_lock_native(
    zc: &Zcrypt,
    locker: &Account,
    asset: u64,
    value: u64,
    coins: &[Coin],
    hashlock: &[u8; 32],
    timeout: u64,
    counterparty: &zcrypt_core::keys::Address,
    sponsor_ref: [u8; 32],
) -> Result<([u8; 32], Coin, Vec<u8>), String> {
    let in_total: u64 = coins.iter().map(|c| c.value).sum();
    let fee = native_lock_fee(asset, sponsor_ref != [0u8; 32]);
    let change_value = in_total
        .checked_sub(value)
        .and_then(|r| r.checked_sub(fee))
        .ok_or_else(|| format!("lock value {value} + fee {fee} exceeds the locker's coins ({in_total})"))?;
    let burn_blind = zcrypt_core::keys::random_blind();
    let change_blind = zcrypt_core::keys::random_blind();
    let burn_out: OutCoin = (value, burn_blind, zcrypt_core::htlc_shield::BURN_PK, asset);
    let change_out: OutCoin = (change_value, change_blind, locker.pubkey(), asset);
    let change_note = zcrypt_core::kem::ciphertext_to_bytes(&zcrypt_core::keys::encrypt_note_asset(
        &locker.normal_address(),
        change_value,
        change_blind,
        asset,
    ));
    let (_claim_blind, claim_open) = zcrypt_core::htlc_shield::CoinOpening::create(counterparty, value, asset)?;
    let (_refund_blind, refund_open) =
        zcrypt_core::htlc_shield::CoinOpening::create(&locker.normal_address(), value, asset)?;
    let counterparty_pk = counterparty.pubkey();
    let settlements = [claim_open.coin.clone(), refund_open.coin.clone()];
    let envelope = zcrypt_core::htlc_shield::lock_envelope(
        zcrypt_core::htlc_shield::ENV_SWAP_LOCK,
        asset,
        value,
        hashlock,
        timeout,
        &counterparty_pk,
        &locker.pubkey(),
        &[],
        &settlements,
    );
    let stx = build_shield_spend_bound(
        zc,
        coins,
        &[burn_out, change_out],
        fee,
        vec![zcrypt_core::keys::cover_note_bytes(), change_note],
        &envelope,
    )?;
    let data = zc.broadcast(&swap_lock_native_tx(
        value, &burn_blind, asset, hashlock, timeout, &counterparty_pk, &locker.pubkey(), &sponsor_ref, &stx, &claim_open, &refund_open,
    ))?;
    let escrow = escrow_id_from(&data)?;
    Ok((escrow, locker.own_asset_coin(change_value, change_blind, asset), claim_open.coin.enc_note))
}

/// Prove the SPV claim coin: net of the bridge fee, encrypted to `to`. The open tx
/// header still carries the gross deposit. Returns the blind the beneficiary spends with.
pub fn spv_claim_opening(
    to: &zcrypt_core::keys::Address,
    gross: u64,
    asset: u64,
) -> Result<(Blind, zcrypt_core::htlc_shield::CoinOpening), String> {
    let fee = zcrypt_core::emission::bridge_fee(gross);
    let net = gross.checked_sub(fee).ok_or("SPV mint value underflow")?;
    if net == 0 {
        return Err("SPV mint net of the bridge fee is zero".into());
    }
    zcrypt_core::htlc_shield::CoinOpening::create(to, net, asset)
}

/// An opening that parses (`commitment` canonical, note the wire length, proof non-empty)
/// but does not prove. Unit tests and header fixtures only — never broadcast.
#[cfg(test)]
pub(crate) fn dummy_opening() -> zcrypt_core::htlc_shield::CoinOpening {
    zcrypt_core::htlc_shield::CoinOpening {
        coin: zcrypt_core::htlc_shield::HiddenCoin {
            commitment: [1u64; 8],
            enc_note: vec![0u8; zcrypt_core::kem::NOTE_WIRE_LEN],
        },
        proof: vec![1],
    }
}

/// Decrypt a settlement note the counterparty encrypted to `account`.
pub fn coin_from_note(account: &Account, note: &[u8]) -> Result<Coin, String> {
    let ct = zcrypt_core::kem::ciphertext_from_bytes(note).ok_or("settlement note is not a ciphertext")?;
    account.receive(&ct).ok_or_else(|| "could not decrypt the settlement note".to_string())
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
    let proof = mint_proof_for_txid(
        b.alice,
        b.bridge_key.pk.inner.serialize(),
        b.alice_key.pk.inner.serialize(),
        btc_locktime,
        utxo.outpoint.vout,
        &utxo.outpoint.txid,
    )?;
    // The claim coin is the net of the bridge fee. The open header still carries the gross.
    let (blind, opening) = spv_claim_opening(&alice.normal_address(), zbtc_value, asset)?;
    let data =
        zc.broadcast(&open_spv_tx(asset, zbtc_value, &lock, zc_timeout, &alice.pubkey(), &proof, b.alice_key, &opening))?;
    let escrow_id = escrow_id_from(&data)?;
    println!("  [zc]  SPV-verified deposit opened zBTC escrow {}", hex::encode(escrow_id));

    // 3. Alice claims the zBTC escrow, revealing the preimage on ZCrypt.
    progress(60, "Claiming your zBTC (revealing the preimage)…");
    let h0 = zc.height()?;
    zc.broadcast(&claim_tx(&escrow_id, preimage))?;
    // The mint skims a small protocol bridge fee to stakers, so the recipient's coin is
    // `zbtc_value - fee` (both node and wallet compute the same fee). The blind is the one
    // `CoinOpening::create` sampled; it is not a function of the escrow id.
    let net = zbtc_value - zcrypt_core::emission::bridge_fee(zbtc_value);
    let coin = alice.htlc_coin(net, asset, blind);
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
    // The BRIDGE claims the BTC leg, so price its claim from the bridge backend (capped
    // against the locked value: a lying fee oracle cannot eat the HTLC).
    let fee = htlc_spend_fee_for(b.bridge, 3, utxo.value.to_sat())?;
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
///
/// Privacy (H3): the 0x64 open publishes `user.pubkey()` as the zBTC claimer and
/// `user_refund.pk` inside the Bitcoin HTLC. Pass a FRESH stealth sub-account as `user` and
/// a per-deposit key from [`crate::refund_key_for`] as `user_refund`, never the reusable
/// Normal-address account, or every deposit is linkable to the same identity on both chains.
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
    resume_public_shield(
        zc, user_btc, user_refund, reserve_pk, user, asset, preimage, &utxo, btc_locktime, zc_timeout, zbtc_value, progress,
    )
}

/// Find an HTLC funding that already landed for `script` (at least `min_value`), so a
/// deposit whose flow aborted after broadcast (confirmation wait timed out, process died)
/// can be RESUMED with [`resume_public_shield`] instead of funded a second time (bridge
/// L3; the operator uses the same check before funding a redeem, bridge H2). `Ok(None)`
/// when nothing is there OR the backend cannot look addresses up.
pub fn find_funded_htlc(backend: &dyn BtcBackend, script: &ScriptBuf, min_value: Amount) -> Result<Option<HtlcUtxo>, String> {
    match backend.htlc_utxos(script) {
        Ok(utxos) => Ok(utxos.into_iter().find(|u| u.value >= min_value)),
        Err(e) if e.contains("not supported") => Ok(None),
        Err(e) => Err(e),
    }
}

/// The resumable tail of a public shield: given an ALREADY-FUNDED HTLC `utxo` (locked to
/// `reserve_pk` with `user_refund` as the refund key and CLTV `btc_locktime`), prove the
/// deposit, open the mint escrow and claim the zBTC. This is exactly what
/// [`btc_to_zbtc_public_progress`] does after funding, exposed so a wallet can pick a
/// deposit back up from the funding UTXO alone (bridge L3). `zc_timeout` is the ZC escrow
/// timeout to request; pass the value from [`shield_timeouts`] at the current tip.
#[allow(clippy::too_many_arguments)]
/// Progress text for a Bitcoin confirmation wait: "Bitcoin confirmations: 3/6 (about 30 min left)".
pub fn confirmation_phase(have: u32, need: u32) -> String {
    let left = need.saturating_sub(have);
    if left == 0 {
        format!("Bitcoin confirmations: {need}/{need}")
    } else {
        format!("Bitcoin confirmations: {have}/{need} (about {} min left)", left * 10)
    }
}

#[cfg(test)]
mod confirmation_phase_tests {
    #[test]
    fn counts_and_eta() {
        assert_eq!(super::confirmation_phase(0, 6), "Bitcoin confirmations: 0/6 (about 60 min left)");
        assert_eq!(super::confirmation_phase(4, 6), "Bitcoin confirmations: 4/6 (about 20 min left)");
        assert_eq!(super::confirmation_phase(6, 6), "Bitcoin confirmations: 6/6");
    }
}

pub fn resume_public_shield(
    zc: &Zcrypt,
    user_btc: &dyn BtcBackend,
    user_refund: &Key,
    reserve_pk: &PublicKey,
    user: &Account,
    asset: u64,
    preimage: &[u8],
    utxo: &HtlcUtxo,
    btc_locktime: u32,
    zc_timeout: u64,
    zbtc_value: u64,
    progress: &dyn Fn(u8, &str),
) -> Result<Coin, String> {
    if preimage.len() != PREIMAGE_LEN {
        return Err(format!("HTLC preimage must be exactly {PREIMAGE_LEN} bytes (got {})", preimage.len()));
    }
    let lock = htlc_hashlock(preimage);
    let expected_script = htlc_script(&lock, reserve_pk, &user_refund.pk, btc_locktime);
    if utxo.script != expected_script {
        return Err("resume: the funded UTXO's script does not match this preimage/keys/locktime".to_string());
    }
    if zbtc_value > utxo.value.to_sat() {
        return Err(format!(
            "cannot mint {zbtc_value} zBTC base units against {} locked sats — the SPV \
             gate enforces 1:1 backing",
            utxo.value.to_sat()
        ));
    }
    // Confirmed enough for the mint gate? (A resumed deposit may still be shallow.) Report
    // the count as it climbs so the wallet can show "3/6 confirmations" rather than a blind wait.
    user_btc.confirm_with(&utxo.outpoint.txid, &|have, need| {
        progress(20 + (18 * have / need.max(1)) as u8, &confirmation_phase(have, need));
    })?;

    // 2. Prove the deposit. The proof pins the OPERATOR's reserve_pk (which must match the
    //    zBTC asset's registered authority) and the user's refund_pk. Consensus re-verifies
    //    everything; nobody signs the mint.
    progress(40, "Proving your BTC deposit to the chain (SPV)…");
    relay_btc_headers(zc, user_btc)?;
    let proof = mint_proof_for_txid(
        user_btc,
        reserve_pk.inner.serialize(),
        user_refund.pk.inner.serialize(),
        btc_locktime,
        utxo.outpoint.vout,
        &utxo.outpoint.txid,
    )?;
    let (blind, opening) = spv_claim_opening(&user.normal_address(), zbtc_value, asset)?;
    let data =
        zc.broadcast(&open_spv_tx(asset, zbtc_value, &lock, zc_timeout, &user.pubkey(), &proof, user_refund, &opening))?;
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
    let coin = user.htlc_coin(net, asset, blind);
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
    // asset(8) ‖ value(8) ‖ lock(32) ‖ timeout(8) ‖ claim_pk(64) ‖ open_auth(64)
    // ‖ CoinOpening ‖ MintProof. The opening is dropped; a failed decode is a failed parse.
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
    let (_opening, n) = zcrypt_core::htlc_shield::CoinOpening::decode(&payload[HEAD..])?;
    let proof = MintProof::from_bytes(&payload[HEAD + n..])?;
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
    /// "mint" | "burn" | "swap" (empty when the node predates the field).
    pub kind: String,
    /// The consensus-committed Bitcoin payout key of a burn-for-BTC escrow (33 bytes), empty
    /// otherwise. The operator MUST take the payout key from here, never from raw block
    /// txs: a duplicate lock that failed delivery can carry a different key.
    pub btc_claim_pk: Vec<u8>,
    pub party_pk: Vec<u8>,
    pub refund_pk: Vec<u8>,
    /// Settlement coins from `/htlc/<id>`. Empty when the node omits the field or this
    /// side has no coin (a burn has no claim coin; a mint has no refund coin).
    pub claim_commitment: Vec<u8>,
    pub claim_enc_note: Vec<u8>,
    pub refund_commitment: Vec<u8>,
    pub refund_enc_note: Vec<u8>,
    /// Gas sponsorship (native swap locks, `0x6B`): the escrow id of the ONE counter-lock
    /// this ZCRYPT lock pays gas for (32 bytes), empty when it sponsors nothing.
    pub sponsor_for: Vec<u8>,
    /// Whether that sponsorship has already admitted a lock.
    pub sponsor_used: bool,
}

/// Query one escrow by id; `Ok(None)` if consensus has no such escrow (rejected/garbage tx).
pub fn query_escrow(zc: &dyn ZcNode, escrow_id: &[u8; 32]) -> Result<Option<EscrowInfo>, String> {
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
    let hex_field = |k: &str| -> Vec<u8> {
        v.get(k).and_then(|x| x.as_str()).and_then(|h| hex::decode(h).ok()).unwrap_or_default()
    };
    Ok(Some(EscrowInfo {
        asset_id: v.get("asset_id").and_then(|x| x.as_u64()).unwrap_or(0),
        value: v.get("value").and_then(|x| x.as_u64()).unwrap_or(0),
        hashlock,
        timeout_height: v.get("timeout_height").and_then(|x| x.as_u64()).unwrap_or(0),
        state: v.get("state").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        kind: v.get("kind").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        btc_claim_pk: hex_field("btc_claim_pk"),
        party_pk: hex_field("party_pk"),
        refund_pk: hex_field("refund_pk"),
        claim_commitment: hex_field("claim_commitment"),
        claim_enc_note: hex_field("claim_enc_note"),
        refund_commitment: hex_field("refund_commitment"),
        refund_enc_note: hex_field("refund_enc_note"),
        sponsor_for: hex_field("sponsor_for"),
        sponsor_used: v.get("sponsor_used").and_then(|x| x.as_bool()).unwrap_or(false),
    }))
}

impl EscrowInfo {
    /// Whether `pk` is the escrow's consensus-committed claim recipient.
    pub fn party_is(&self, pk: &PubKey) -> bool {
        self.party_pk == pk_bytes(pk)
    }
    /// Whether `pk` is the escrow's consensus-committed refund (expire) recipient.
    pub fn refund_is(&self, pk: &PubKey) -> bool {
        self.refund_pk == pk_bytes(pk)
    }
    /// The consensus-committed refund key as a `PubKey`, if the node reported one.
    pub fn refund_pubkey(&self) -> Option<PubKey> {
        if self.refund_pk.len() != 64 {
            return None;
        }
        let mut pk = [0u64; 8];
        for (i, limb) in pk.iter_mut().enumerate() {
            *limb = u64::from_le_bytes(self.refund_pk[i * 8..i * 8 + 8].try_into().ok()?);
        }
        Some(pk)
    }
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
    /// Every consensus-accepted deposit locked to this reserve seen in the scanned range,
    /// claimed or not: the caller keeps tracking them with [`reanchor_reorged_deposits`]
    /// until they are buried past any reorg-void risk.
    pub tracked: Vec<TrackedDeposit>,
}

/// A deposit the operator keeps an eye on until its immature mint can no longer be voided:
/// if a benign Bitcoin reorg re-mines the funding tx into another block, the watcher
/// submits a fresh proof (0x65 re-anchor) so the mint follows the deposit instead of being
/// voided after the grace window (bridge M2). JSON-serializable for the daemon state file.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrackedDeposit {
    /// Escrow id (hex).
    pub escrow_id: String,
    /// The accepted `MintProof` (hex of `to_bytes`); a re-anchor reuses everything but the
    /// merkle block.
    pub proof_hex: String,
    /// Block the mint is currently anchored to (hex, internal byte order).
    pub deposit_block: String,
    /// Minted value (drives the maturity depth).
    pub value: u64,
    /// The deposit HTLC's refund CLTV.
    pub btc_locktime: u32,
    /// The escrow's hashlock (hex). Lets a later tick match a `0x5B` claim to this deposit
    /// and verify the revealed preimage without re-reading the open tx (bridge N2).
    #[serde(default)]
    pub hashlock: String,
    /// Set once consensus reports the escrow claimed (the immature mint exists).
    #[serde(default)]
    pub claimed: bool,
}

impl TrackedDeposit {
    pub fn escrow_id_bytes(&self) -> Option<[u8; 32]> {
        hex::decode(&self.escrow_id).ok().and_then(|b| b.try_into().ok())
    }
    pub fn proof(&self) -> Option<MintProof> {
        hex::decode(&self.proof_hex).ok().and_then(|b| MintProof::from_bytes(&b))
    }
    pub fn hashlock_bytes(&self) -> Option<[u8; 32]> {
        hex::decode(&self.hashlock).ok().and_then(|b| b.try_into().ok())
    }
}

/// Outcome of one re-anchor pass.
#[derive(Default, Debug)]
pub struct ReanchorReport {
    /// Deposits re-anchored to a new block THIS pass.
    pub reanchored: Vec<[u8; 32]>,
    /// Deposits dropped from tracking: buried past all void risk, or already matured.
    pub settled: Vec<[u8; 32]>,
    /// Per-deposit non-fatal failures (kept for the next pass).
    pub errors: Vec<([u8; 32], String)>,
    /// The backend cannot report a tx's block, so nothing could be checked.
    pub unsupported: bool,
}

/// OPERATOR watcher: for every tracked deposit, compare the block the mint is anchored to
/// with the block the operator's Bitcoin backend currently has the funding tx in. On a
/// mismatch (the deposit was re-mined by a reorg) build a fresh proof and submit a 0x65
/// re-anchor before consensus voids the immature mint. A deposit whose escrow is not yet
/// CLAIMED has no immature mint to re-anchor: it stays tracked (the reorg is remembered)
/// and is re-anchored as soon as the claim lands (bridge N11). Deposits are dropped only
/// when claimed AND buried past maturity + reorg grace, or when their escrow is gone.
pub fn reanchor_reorged_deposits(
    zc: &dyn ZcNode,
    backend: &dyn BtcBackend,
    tracked: &mut Vec<TrackedDeposit>,
) -> ReanchorReport {
    use bitcoin::hashes::Hash as _;
    let net = spv_net(backend.network());
    let mut report = ReanchorReport::default();
    let mut keep = Vec::with_capacity(tracked.len());
    let mut relayed = false;
    for mut t in tracked.drain(..) {
        let Some(eid) = t.escrow_id_bytes() else {
            continue; // corrupt entry: drop
        };
        let Some(proof) = t.proof() else {
            report.errors.push((eid, "tracked deposit: corrupt proof, dropped".to_string()));
            continue;
        };
        let Some(txid_bytes) = proof.funding_txid() else {
            report.errors.push((eid, "tracked deposit: corrupt funding tx, dropped".to_string()));
            continue;
        };
        let txid = bitcoin::Txid::from_byte_array(txid_bytes);
        // Refresh the claimed flag from consensus (cheap, and it gates the re-anchor).
        if !t.claimed {
            match query_escrow(zc, &eid) {
                Ok(Some(info)) if info.state == "claimed" => t.claimed = true,
                Ok(Some(info)) if info.state == "open" => {}
                Ok(_) => {
                    // Expired or unknown: no mint can ever exist for it; nothing to protect.
                    report.settled.push(eid);
                    continue;
                }
                Err(e) => {
                    report.errors.push((eid, format!("escrow query: {e}")));
                    keep.push(t);
                    continue;
                }
            }
        }
        let current = match backend.tx_block_hash(&txid) {
            Ok(h) => h,
            Err(e) if e.contains("not supported") => {
                report.unsupported = true;
                keep.push(t);
                continue;
            }
            Err(e) => {
                report.errors.push((eid, format!("block lookup: {e}")));
                keep.push(t);
                continue;
            }
        };
        let anchored = hex::decode(&t.deposit_block).ok().and_then(|b| <[u8; 32]>::try_from(b).ok());
        match current {
            None => keep.push(t), // reorged out and not yet re-mined: nothing to prove yet
            Some(h) if Some(h) != anchored => {
                if !t.claimed {
                    // The mint does not exist yet; remember the reorg and re-anchor at claim time.
                    keep.push(t);
                    continue;
                }
                // Re-mined into a different block: re-anchor with a fresh merkle proof.
                let outcome = (|| -> Result<(), String> {
                    let merkle_block = backend.txout_proof(&txid)?;
                    let coinbase_raw = backend.coinbase_raw(&txid)?;
                    let fresh = MintProof { merkle_block, coinbase_raw, ..proof.clone() };
                    if fresh.deposit_block_hash() != Some(h) {
                        return Err("fresh merkle proof is not for the block the backend reports".to_string());
                    }
                    if !relayed {
                        let _ = relay_btc_headers(zc, backend); // the new block must be on the SPV chain
                        relayed = true;
                    }
                    zc.broadcast(&reanchor_tx(&fresh)).map(|_| ())
                })();
                match outcome {
                    Ok(()) => {
                        report.reanchored.push(eid);
                        keep.push(TrackedDeposit { deposit_block: hex::encode(h), ..t });
                    }
                    Err(e) if e.contains("immature") || e.contains("no pending") => {
                        // No immature mint: it matured (buried) or was voided. Keep following it
                        // until it is buried past all risk, so a voided-then-reopened deposit is
                        // still re-anchored when its new mint appears.
                        let confs = backend.tx_confirmations(&txid).unwrap_or(0);
                        let deep = zcrypt_core::spv::safe_sweep_conf(net, t.value) + zcrypt_core::spv::reanchor_grace_for(net);
                        if confs >= deep {
                            report.settled.push(eid);
                        } else {
                            report.errors.push((eid, e));
                            keep.push(t);
                        }
                    }
                    Err(e) => {
                        report.errors.push((eid, e));
                        keep.push(t);
                    }
                }
            }
            Some(_) => {
                // Still in its block: stop tracking once CLAIMED and buried past any void risk.
                let confs = backend.tx_confirmations(&txid).unwrap_or(0);
                let deep = zcrypt_core::spv::safe_sweep_conf(net, t.value) + zcrypt_core::spv::reanchor_grace_for(net);
                if t.claimed && confs >= deep {
                    report.settled.push(eid);
                } else {
                    keep.push(t);
                }
            }
        }
    }
    *tracked = keep;
    report
}

/// How close a deposit's Bitcoin refund lock is (operator alerting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundProximity {
    Ok,
    /// Within [`LOCKTIME_ALERT_BLOCKS`]: page the operator, prioritise.
    AtRisk,
    /// Within [`LOCKTIME_HARD_BLOCKS`]: emergency, pause new shields.
    Critical,
}

pub fn refund_proximity(btc_locktime: u32, btc_tip: u64) -> RefundProximity {
    let remaining = (btc_locktime as u64).saturating_sub(btc_tip);
    if remaining < LOCKTIME_HARD_BLOCKS {
        RefundProximity::Critical
    } else if remaining < LOCKTIME_ALERT_BLOCKS {
        RefundProximity::AtRisk
    } else {
        RefundProximity::Ok
    }
}

/// A claim whose sweep could not run yet: the deposit is not buried past maturity + reorg
/// grace. Persisted by the daemon and retried EVERY tick until swept, independent of the
/// scan cursor, so a deferral is never forgotten (bridge N1). Self-contained: carries the
/// deposit (proof, lock, locktime, value) and the revealed preimage.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeferredSweep {
    pub deposit: TrackedDeposit,
    pub preimage_hex: String,
    /// ZC height the claim was first seen at.
    pub first_seen_zc: i64,
}

/// Index every CONSENSUS-ACCEPTED SPV deposit (`0x64`) locked to `reserve` in ZC blocks
/// `from..=to`. A `0x64` that appears in raw block data but was rejected creates no escrow,
/// so [`query_escrow`] filters it out: a garbage-open flood cannot poison the index.
pub fn index_reserve_deposits(
    zc: &dyn ZcNode,
    keys: &ReserveKeys<'_>,
    from: i64,
    to: i64,
) -> Result<(Vec<TrackedDeposit>, Vec<([u8; 32], String)>), String> {
    let mut found = Vec::new();
    let mut errors = Vec::new();
    for h in from..=to {
        let (f, e) = index_reserve_deposits_in(zc, keys, &zc.block_txs(h)?);
        found.extend(f);
        errors.extend(e);
    }
    Ok((found, errors))
}

/// [`index_reserve_deposits`] for ONE block whose raw txs the caller already fetched (the
/// daemon fetches each block once and dispatches it to every scanner, audit M9). Errors are
/// TRANSIENT (an escrow or claimed-set query failed): the caller must re-scan this block
/// later rather than advance past it (audit H4). A `0x64` whose escrow consensus no longer
/// holds (pruned after retention) but whose Bitcoin outpoint is in the consensus CLAIMED set
/// is indexed as claimed (audit H3): the mint happened, the sweep is still owed.
pub fn index_reserve_deposits_in(
    zc: &dyn ZcNode,
    keys: &ReserveKeys<'_>,
    txs: &[Vec<u8>],
) -> (Vec<TrackedDeposit>, Vec<([u8; 32], String)>) {
    use zcrypt_core::htlc_shield::{escrow_id as derive_escrow_id, EscrowKind};
    let mut found = Vec::new();
    let mut errors = Vec::new();
    for tx in txs {
        if tx.first() != Some(&0x64) {
            continue;
        }
        let Some((asset, value, lock, timeout, claim_pk, proof)) = parse_open_spv(&tx[1..]) else {
            continue;
        };
        // Deposits to the current key AND to retired keys this operator still holds.
        if keys.key_for(&proof.reserve_pk).is_none() {
            continue;
        }
        let eid = derive_escrow_id(EscrowKind::Mint, asset, value, &lock, timeout, &claim_pk, &claim_pk);
        let Some(bh) = proof.deposit_block_hash() else { continue };
        let tracked = |claimed: bool| TrackedDeposit {
            escrow_id: hex::encode(eid),
            proof_hex: hex::encode(proof.to_bytes()),
            deposit_block: hex::encode(bh),
            value,
            btc_locktime: proof.btc_locktime,
            hashlock: hex::encode(lock),
            claimed,
        };
        match query_escrow(zc, &eid) {
            Ok(Some(info)) if info.hashlock == lock => found.push(tracked(info.state == "claimed")),
            Ok(Some(_)) => {} // an escrow with this id but another hashlock: not this deposit
            Ok(None) => {
                // No escrow: rejected/garbage, OR settled and pruned while we were away. The
                // claimed set is permanent and tells the two apart.
                let Some(txid) = proof.funding_txid() else { continue };
                match zc.spv_claimed(&txid, proof.vout) {
                    Ok(true) => found.push(tracked(true)),
                    Ok(false) => {}
                    Err(e) => errors.push((eid, format!("claimed-set query: {e}"))),
                }
            }
            Err(e) => errors.push((eid, format!("escrow query: {e}"))),
        }
    }
    (found, errors)
}

/// Collect every `0x5B` claim in ZC blocks `from..=to` that opens one of `known` deposits
/// (matched by escrow id, preimage checked against the deposit's hashlock). `known` is the
/// PERSISTED set of tracked deposits plus this window's, so an open in one tick window and
/// its claim in the next still pair up (bridge N2). Returns `(deposit, preimage, height)`.
pub fn collect_reserve_claims(
    zc: &dyn ZcNode,
    from: i64,
    to: i64,
    known: &std::collections::HashMap<[u8; 32], TrackedDeposit>,
) -> Result<Vec<(TrackedDeposit, Vec<u8>, i64)>, String> {
    let mut out = Vec::new();
    for h in from..=to {
        out.extend(collect_reserve_claims_in(&zc.block_txs(h)?, h, known));
    }
    Ok(out)
}

/// [`collect_reserve_claims`] for ONE block whose raw txs the caller already fetched.
pub fn collect_reserve_claims_in(
    txs: &[Vec<u8>],
    height: i64,
    known: &std::collections::HashMap<[u8; 32], TrackedDeposit>,
) -> Vec<(TrackedDeposit, Vec<u8>, i64)> {
    let mut out = Vec::new();
    for tx in txs {
        if tx.first() != Some(&0x5B) || tx.len() <= 33 {
            continue;
        }
        let Ok(eid): Result<[u8; 32], _> = tx[1..33].try_into() else { continue };
        let Some(dep) = known.get(&eid) else { continue };
        let preimage = &tx[33..];
        if dep.hashlock_bytes() != Some(htlc_hashlock(preimage)) {
            continue; // this preimage does not open our escrow
        }
        out.push((dep.clone(), preimage.to_vec(), height));
    }
    out
}

/// Whether a tracked deposit's zBTC mint exists, from every durable source consensus offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintStatus {
    /// The mint settled (escrow claimed, or the outpoint is in the permanent claimed set):
    /// the BTC is owed to the reserve.
    Claimed,
    /// The escrow is still open: a claim may yet land.
    Open,
    /// No mint exists and none ever will (expired, or pruned without a claim): the depositor
    /// keeps the refund path; never sweep.
    Never(String),
}

/// Resolve [`MintStatus`] for `dep`: a persisted `claimed` flag is trusted (it was set from
/// consensus and the escrow may since have been pruned, audit H3); otherwise the escrow
/// record, and when that is gone, the consensus claimed-outpoint set. `Err` is transient.
pub fn mint_status(zc: &dyn ZcNode, dep: &TrackedDeposit) -> Result<MintStatus, String> {
    if dep.claimed {
        return Ok(MintStatus::Claimed);
    }
    let (Some(eid), Some(lock)) = (dep.escrow_id_bytes(), dep.hashlock_bytes()) else {
        return Err("corrupt tracked deposit".to_string());
    };
    match query_escrow(zc, &eid)? {
        Some(info) if info.hashlock != lock => Ok(MintStatus::Never("escrow hashlock differs from the deposit".to_string())),
        Some(info) if info.state == "claimed" => Ok(MintStatus::Claimed),
        Some(info) if info.state == "open" => Ok(MintStatus::Open),
        Some(info) => Ok(MintStatus::Never(format!("escrow state is '{}'", info.state))),
        None => {
            let txid = dep.proof().and_then(|p| p.funding_txid()).ok_or("corrupt tracked deposit proof")?;
            let vout = dep.proof().map(|p| p.vout).unwrap_or(0);
            if zc.spv_claimed(&txid, vout)? {
                Ok(MintStatus::Claimed)
            } else {
                Ok(MintStatus::Never("escrow unknown to consensus and outpoint not in the claimed set".to_string()))
            }
        }
    }
}

/// What one sweep attempt did.
#[derive(Debug)]
pub enum SweepOutcome {
    /// The reserve claim was broadcast (and, on regtest, mined).
    Swept(bitcoin::Txid),
    /// The deposit is not buried past maturity + reorg grace yet: retry later.
    Deferred { confs: u64, need: u64 },
    /// Consensus does not show a mint for this deposit (a leaked preimage without a mint, or
    /// a claim still settling): the status says whether to keep waiting or to stop. Never
    /// sweep: the depositor keeps the refund path.
    NotClaimed(MintStatus),
    /// A per-deposit failure (RPC, fees, broadcast): retry next tick.
    Failed(String),
}

/// Sweep ONE deposit whose preimage is revealed: verify consensus accepted the claim,
/// defer until the funding is buried past `safe_sweep_conf`, then spend the HTLC's claim
/// branch to `dest`. Never blocks on confirmations on a real network (regtest self-mines);
/// the caller tracks the sweep txid (bridge N7).
pub fn sweep_deposit(
    zc: &dyn ZcNode,
    operator_btc: &dyn BtcBackend,
    keys: &ReserveKeys<'_>,
    dest: &Address,
    dep: &TrackedDeposit,
    preimage: &[u8],
    fee_target: u32,
    btc_tip: u64,
) -> SweepOutcome {
    use bitcoin::hashes::Hash as _;
    let net = spv_net(operator_btc.network());
    let (Some(eid), Some(proof), Some(lock)) = (dep.escrow_id_bytes(), dep.proof(), dep.hashlock_bytes()) else {
        return SweepOutcome::Failed("corrupt tracked deposit".to_string());
    };
    // Sign with the key the deposit script actually names (a retired key after a rotation).
    let Some(reserve) = keys.key_for(&proof.reserve_pk) else {
        return SweepOutcome::Failed(format!(
            "no reserve key loaded for this deposit's reserve pubkey {} (retired key missing from ZCRYPT_RESERVE_PREV_KEY_FILES?)",
            hex::encode(proof.reserve_pk)
        ));
    };
    // Require a consensus-accepted claim (minted / immature) before taking BTC. Escrow
    // presence is NOT the only proof: a persisted claimed flag or the permanent claimed
    // outpoint set also count, since settled escrows are pruned after retention (audit H3).
    match mint_status(zc, dep) {
        Ok(MintStatus::Claimed) => {}
        Ok(status @ (MintStatus::Open | MintStatus::Never(_))) => return SweepOutcome::NotClaimed(status),
        Err(e) => return SweepOutcome::Failed(format!("escrow query before sweep: {e}")),
    }
    let _ = eid;
    // Defer until the deposit is buried past the mint's maturity + reorg-void grace, so a
    // benign reorg that voids the still-immature mint can never strand a swept deposit.
    let need = zcrypt_core::spv::safe_sweep_conf(net, dep.value);
    if let Some(txb) = proof.funding_txid() {
        let confs = operator_btc.tx_confirmations(&bitcoin::Txid::from_byte_array(txb)).unwrap_or(0);
        if confs < need {
            return SweepOutcome::Deferred { confs, need };
        }
    }
    let effective_fee_target = if refund_proximity(dep.btc_locktime, btc_tip) != RefundProximity::Ok { 1 } else { fee_target };
    // One fresh address per sweep. "not supported" keeps the caller's destination
    // (sim / mock backends). A real `new_address` failure is retried next tick.
    let pay = match operator_btc.fresh_payout_address() {
        Ok(a) => a,
        Err(e) if e.contains("not supported") => dest.clone(),
        Err(e) => return SweepOutcome::Failed(e),
    };
    let outcome = (|| -> Result<bitcoin::Txid, String> {
        let utxo = htlc_utxo_from_proof(&proof, &lock)?;
        let fee = htlc_spend_fee_for(operator_btc, effective_fee_target, utxo.value.to_sat())?;
        let txid = operator_btc.claim(&utxo, preimage, reserve, &pay, fee)?;
        if operator_btc.network() == bitcoin::Network::Regtest {
            operator_btc.confirm(&txid)?; // instant self-mine; real networks are polled per tick
        }
        Ok(txid)
    })();
    match outcome {
        Ok(txid) => SweepOutcome::Swept(txid),
        Err(e) => SweepOutcome::Failed(e),
    }
}

/// OPERATOR shield watcher, ONE-SHOT form (the e2e drivers): scan ZCrypt blocks `from..=to`
/// for deposits locked to `reserve.pk` whose preimage has been revealed in the SAME range
/// and sweep each locked BTC to `dest`. The daemon uses the pieces directly
/// ([`index_reserve_deposits`], [`collect_reserve_claims`], [`sweep_deposit`]) with
/// persisted deposits and deferrals, so opens, claims and sweeps may fall in different
/// ticks. Idempotent via `already_swept`; non-fatal per deposit; alerting via `at_risk`.
#[allow(clippy::too_many_arguments)]
pub fn reserve_claim_revealed(
    zc: &dyn ZcNode,
    operator_btc: &dyn BtcBackend,
    reserve: &Key,
    dest: &Address,
    from: i64,
    to: i64,
    fee_target: u32,
    already_swept: &mut std::collections::HashSet<[u8; 32]>,
) -> Result<WatchReport, String> {
    let btc_tip = operator_btc.height().unwrap_or(0);
    let mut report = WatchReport::default();
    let keys = ReserveKeys::single(reserve);
    let (deposits, errs) = index_reserve_deposits(zc, &keys, from, to)?;
    report.errors.extend(errs);
    report.tracked = deposits.clone();
    let known: std::collections::HashMap<[u8; 32], TrackedDeposit> =
        deposits.into_iter().filter_map(|d| d.escrow_id_bytes().map(|e| (e, d))).collect();
    for (dep, preimage, _h) in collect_reserve_claims(zc, from, to, &known)? {
        let Some(eid) = dep.escrow_id_bytes() else { continue };
        if already_swept.contains(&eid) {
            report.already_swept += 1;
            continue;
        }
        let prox = refund_proximity(dep.btc_locktime, btc_tip);
        match sweep_deposit(zc, operator_btc, &keys, dest, &dep, &preimage, fee_target, btc_tip) {
            SweepOutcome::Swept(txid) => {
                already_swept.insert(eid);
                report.swept.push((eid, txid));
            }
            SweepOutcome::Deferred { .. } => report.deferred.push(eid),
            SweepOutcome::NotClaimed(status) => report.errors.push((eid, format!("not claimed: {status:?}; refusing BTC sweep"))),
            SweepOutcome::Failed(e) => {
                if prox != RefundProximity::Ok {
                    report.pause_new_shields = true;
                }
                report.errors.push((eid, e));
            }
        }
        match prox {
            RefundProximity::Critical => {
                report.critical.push(eid);
                report.pause_new_shields = true;
            }
            RefundProximity::AtRisk => report.at_risk.push(eid),
            RefundProximity::Ok => {}
        }
    }
    Ok(report)
}

/// Startup self-check for the operator daemon (bridge N10): the reserve key it holds MUST
/// be the one the chain registered zBTC against, otherwise every deposit filters out as
/// "not ours", nothing is ever swept, and each deposit becomes unbacked after its CLTV.
pub fn assert_reserve_matches_chain(zc: &dyn ZcNode, zbtc_asset: u64, reserve: &Key) -> Result<(), String> {
    let raw = zc.query(&format!("/asset/id/{zbtc_asset}"))?;
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("/asset/id/{zbtc_asset}: {e}"))?;
    let on_chain = v.get("authority").and_then(|a| a.as_str()).unwrap_or("").to_ascii_lowercase();
    let ours = hex::encode(zcrypt_core::spv::spv_authority(&reserve.pk.inner.serialize()));
    if on_chain != ours {
        return Err(format!(
            "reserve key mismatch: the chain's zBTC authority is {on_chain:?} but this daemon's key derives \
             {ours} (reserve pubkey {}). Refusing to run: with the wrong key no deposit would ever be swept. \
             Fix ZCRYPT_RESERVE_KEY_FILE (print the pubkey with `reserve_pubkey`) or the genesis zbtc_reserve_pk.",
            hex::encode(reserve.pk.inner.serialize())
        ));
    }
    Ok(())
}

/// Resume a user's SPV deposit from its already-funded HTLC in ONE call (bridge L3): derive
/// the deposit's refund key from the wallet `seed` and its per-deposit `refund_index`
/// ([`crate::refund_key_for`]), rebuild the HTLC script, find the funding UTXO on the user's
/// backend (confirmed or in the mempool), and run the resumable tail
/// ([`resume_public_shield`]: prove, open the mint escrow, claim). The wallet's
/// `bridge_recover` can call this for every deposit whose flow aborted after funding.
#[allow(clippy::too_many_arguments)]
pub fn resume_deposit(
    zc: &Zcrypt,
    user_btc: &dyn BtcBackend,
    seed: &[u8; 32],
    refund_index: u32,
    reserve_pk: &PublicKey,
    user: &Account,
    asset: u64,
    preimage: &[u8],
    btc_locktime: u32,
    zc_timeout: u64,
    zbtc_value: u64,
    progress: &dyn Fn(u8, &str),
) -> Result<Coin, String> {
    if preimage.len() != PREIMAGE_LEN {
        return Err(format!("HTLC preimage must be exactly {PREIMAGE_LEN} bytes (got {})", preimage.len()));
    }
    let refund = crate::refund_key_for(seed, refund_index);
    let lock = htlc_hashlock(preimage);
    let script = htlc_script(&lock, reserve_pk, &refund.pk, btc_locktime);
    let utxo = find_funded_htlc(user_btc, &script, Amount::from_sat(zbtc_value))?
        .ok_or("resume: no funding of at least the deposit value found at the HTLC address (confirmed or mempool)")?;
    resume_public_shield(zc, user_btc, &refund, reserve_pk, user, asset, preimage, &utxo, btc_locktime, zc_timeout, zbtc_value, progress)
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
) -> Result<([u8; 32], u64, Blind), String> {
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
    // The refund coin's blind is hidden. Create it before the envelope so the proof
    // binds the commitment the user can spend on expire (by decrypting the note).
    let (_refund_blind, refund_open) =
        zcrypt_core::htlc_shield::CoinOpening::create(&user.normal_address(), zbtc_value, asset)?;
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
        std::slice::from_ref(&refund_open.coin),
    );
    let stx = build_shield_spend_bound(
        zc,
        coins,
        &[burn_out, change_out],
        zcrypt_core::emission::MIN_FEE,
        vec![zcrypt_core::keys::cover_note_bytes(), change_note],
        &envelope,
    )?;
    let data = zc.broadcast(&burn_lock_btc_tx(
        btc_claim_pk, zbtc_value, &burn_blind, asset, hashlock, zc_timeout, &user.pubkey(), &stx, &refund_open,
    ))?;
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
    zc: &dyn ZcNode,
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
    if info.kind != "burn" {
        return Err(format!("redeem: escrow kind '{}' is not a burn escrow — refusing to pay BTC", info.kind));
    }
    if info.btc_claim_pk != user_btc_pk.inner.serialize() {
        return Err(
            "redeem: the requested payout key is not the one consensus committed for this escrow — refusing to lock BTC"
                .to_string(),
        );
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
    let net = operator_btc.network();
    if info.value < min_redeem_sats(net) {
        return Err(format!(
            "redeem: escrow value {} sats is below the {}-sat minimum (uneconomic to claim)",
            info.value,
            min_redeem_sats(net)
        ));
    }
    let zc_tip = zc.height()? as u64;
    let margin = min_finalize_margin.max(min_redeem_margin_blocks(net));
    if info.timeout_height < zc_tip + margin {
        return Err(format!(
            "redeem: escrow timeout {} too soon (tip {zc_tip} + finalize margin {margin}) — \
             a short-timeout burn could refund the zBTC before the operator finalizes; refusing to lock BTC",
            info.timeout_height
        ));
    }
    // The BTC refund lock is DERIVED from the escrow's remaining life so it (plus the
    // finalize SLA) always expires before the ZC escrow: the user can never refund the zBTC
    // and still claim the BTC (bridge H1). Refuses if the user would get too short a window.
    let btc_locktime = redeem_btc_locktime_for(net, operator_btc.height()?, zc_tip, info.timeout_height)?;
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
    let fee = htlc_spend_fee_for(user_btc, 3, utxo.value.to_sat())?;
    let txid = user_btc.claim(utxo, preimage, user_btc_key, user_dest, fee)?;
    user_btc.confirm(&txid)?;
    Ok(txid)
}

/// OPERATOR side, step 4 of a redeem: after the user has claimed the BTC, read the revealed
/// preimage from their claim tx and submit it to the burn escrow, permanently destroying the
/// zBTC so supply stays 1:1 with the reserve. MUST run before the burn escrow times out.
pub fn reserve_finalize_redeem(
    zc: &dyn ZcNode,
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
    zc: &dyn ZcNode,
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
    /// The BTC HTLC's refund CLTV: after it the operator may take the BTC back if the user
    /// never claimed (bridge M5).
    pub btc_locktime: u32,
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

/// One validated redeem the operator has decided to fund. No BTC has moved yet: the daemon
/// persists this as a funding INTENT before broadcasting, so a crash between broadcast and
/// state save can never lead to funding the same escrow twice (bridge H2).
#[derive(Clone, Debug)]
pub struct RedeemPlan {
    pub escrow_id: [u8; 32],
    pub hashlock: [u8; 32],
    pub value: u64,
    pub script: ScriptBuf,
    pub btc_locktime: u32,
    /// The ZC escrow's expiry height (drives the unconfirmed-funding deadline, audit M6).
    pub zc_timeout: u64,
}

/// Outcome of a planning pass over a block range.
#[derive(Default)]
pub struct RedeemPlanReport {
    pub plans: Vec<RedeemPlan>,
    /// Redeems refused after validation (permanent: bad asset/value/hashlock/timeout).
    pub rejected: Vec<([u8; 32], String)>,
    /// Transient failures (escrow query) to retry later.
    pub errors: Vec<([u8; 32], String)>,
    /// Redeems skipped because `skip` already contained them.
    pub skipped: usize,
}

/// OPERATOR redeem watcher, planning half: scan ZCrypt blocks `from..=to` for `0x67` redeem
/// burn-locks and validate each against consensus WITHOUT moving BTC. It trusts NOTHING
/// off-chain: re-derives the escrow id, confirms consensus accepted the burn
/// ([`query_escrow`]), enforces asset==zBTC, value==btc paid, the escrow's own hashlock, the
/// minimum redeem value, and a finalize margin; and derives a BTC lock that always expires
/// before the ZC escrow ([`redeem_btc_locktime_for`], bridge H1). Escrows in `skip` are not
/// re-planned (already funded / permanently rejected).
#[allow(clippy::too_many_arguments)]
pub fn plan_redeems(
    zc: &dyn ZcNode,
    operator_btc: &dyn BtcBackend,
    reserve: &Key,
    from: i64,
    to: i64,
    zbtc_asset: u64,
    min_finalize_margin: u64,
    skip: &std::collections::HashSet<[u8; 32]>,
) -> Result<RedeemPlanReport, String> {
    let tips = PlanTips::read(zc, operator_btc)?;
    let mut report = RedeemPlanReport::default();
    let mut planned_ids: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for h in from..=to {
        let txs = zc.block_txs(h)?;
        plan_redeems_in(zc, operator_btc, reserve, h, &txs, zbtc_asset, min_finalize_margin, skip, &tips, &mut planned_ids, &mut report);
    }
    Ok(report)
}

/// The chain tips one planning pass is evaluated against (read once per tick).
#[derive(Clone, Copy, Debug)]
pub struct PlanTips {
    pub zc_tip: u64,
    pub btc_tip: u64,
}

impl PlanTips {
    pub fn read(zc: &dyn ZcNode, operator_btc: &dyn BtcBackend) -> Result<Self, String> {
        Ok(PlanTips { zc_tip: zc.height()? as u64, btc_tip: operator_btc.height()? })
    }
}

/// [`plan_redeems`] for ONE block whose raw txs the caller already fetched (audit M9).
/// `planned_ids` carries the one-plan-per-escrow-id guard across the blocks of a pass
/// (bridge C1). Entries in `report.errors` are TRANSIENT (an escrow query or the anchor
/// lookup failed): the caller must re-scan this block later instead of advancing past it
/// (audit H4); `report.rejected` is permanent.
#[allow(clippy::too_many_arguments)]
pub fn plan_redeems_in(
    zc: &dyn ZcNode,
    operator_btc: &dyn BtcBackend,
    reserve: &Key,
    height: i64,
    txs: &[Vec<u8>],
    zbtc_asset: u64,
    min_finalize_margin: u64,
    skip: &std::collections::HashSet<[u8; 32]>,
    tips: &PlanTips,
    planned_ids: &mut std::collections::HashSet<[u8; 32]>,
    report: &mut RedeemPlanReport,
) {
    use zcrypt_core::htlc_shield::{escrow_id as derive_escrow_id, EscrowKind};
    let PlanTips { zc_tip, btc_tip } = *tips;
    let net = operator_btc.network();
    let margin = min_finalize_margin.max(min_redeem_margin_blocks(net));
    // The deterministic Bitcoin anchor of this ZC block (audit H5), resolved lazily: only a
    // block that carries a servable burn-lock pays for the lookup.
    let mut anchor: Option<u64> = None;
    for tx in txs {
        if tx.first() != Some(&0x67) {
            continue;
        }
        let Some((tx_btc_pk, asset, value, hashlock, timeout, refund_pk)) = parse_burn_lock_btc(&tx[1..]) else {
            continue;
        };
        let eid = derive_escrow_id(EscrowKind::Burn, asset, value, &hashlock, timeout, &refund_pk, &refund_pk);
        if skip.contains(&eid) {
            report.skipped += 1;
            continue;
        }
        // One plan per escrow id per pass. A block can carry two 0x67 txs with identical lock
        // parameters (same id) where only the first succeeded at delivery; without this the
        // second, failed copy would get its own funded HTLC (bridge C1).
        if !planned_ids.insert(eid) {
            report.rejected.push((eid, format!(
                "duplicate burn-lock for an escrow already planned this pass (tx payout key {})",
                hex::encode(tx_btc_pk)
            )));
            continue;
        }
        let info = match query_escrow(zc, &eid) {
            Ok(Some(i)) => i,
            Ok(None) => continue, // consensus rejected this burn-lock: nothing to serve
            Err(e) => {
                planned_ids.remove(&eid); // let the re-scan plan it
                report.errors.push((eid, format!("escrow query: {e}")));
                continue;
            }
        };
        // Validate every peg-critical property BEFORE committing reserve BTC.
        let reject = if info.state != "open" {
            Some(format!("escrow not open (state={})", info.state))
        } else if info.kind != "burn" {
            Some(format!("escrow kind '{}' is not a burn escrow", info.kind))
        } else if info.btc_claim_pk.len() != 33 {
            Some(format!(
                "consensus committed no 33-byte payout key for this escrow ({} bytes); the key in the raw tx is not trusted",
                info.btc_claim_pk.len()
            ))
        } else if info.asset_id != zbtc_asset {
            Some(format!("escrow asset {} is not zBTC ({zbtc_asset})", info.asset_id))
        } else if info.hashlock != hashlock {
            Some("burn-lock hashlock disagrees with the escrow".to_string())
        } else if info.value != value {
            Some(format!("burn-lock value {value} disagrees with the escrow {}", info.value))
        } else if info.value < min_redeem_sats(net) {
            Some(format!("value {} below the {}-sat minimum redeem", info.value, min_redeem_sats(net)))
        } else if info.timeout_height < zc_tip + margin {
            // Deliberately PERMANENT (bridge N15): an escrow's remaining life only shrinks,
            // so a "too soon" verdict can never flip to acceptable later. Refusing is the
            // safe choice: the user's zBTC refunds at expiry and they can burn-lock again
            // with a fresh timeout; locking reserve BTC against a short escrow is what
            // enables the H1 theft.
            Some(format!(
                "escrow timeout {} too soon (tip {zc_tip} + margin {margin}); permanent: the user's zBTC \
                 refunds at expiry, re-lock with a fresh timeout",
                info.timeout_height
            ))
        } else {
            None
        };
        if let Some(r) = reject {
            report.rejected.push((eid, r));
            continue;
        }
        let anchor_btc = match anchor {
            Some(a) => a,
            None => match redeem_anchor_for_block(zc, operator_btc, height, btc_tip) {
                Ok(a) => {
                    anchor = Some(a);
                    a
                }
                Err(e) => {
                    planned_ids.remove(&eid);
                    report.errors.push((eid, format!("redeem anchor: {e}")));
                    continue;
                }
            },
        };
        // Always the burn-time script. A later tip must rediscover the same CLTV so an
        // existing funding is found; refusing a too-short window is fund_redeem_plan's job
        // and only applies when nothing is funded yet.
        let btc_locktime =
            match redeem_btc_locktime_for(net, anchor_btc, height.max(0) as u64, info.timeout_height) {
                Ok(lt) => lt,
                Err(e) => {
                    report.rejected.push((eid, e));
                    continue;
                }
            };
        // Payout key from CONSENSUS STATE (the escrow the successful tx created), not from
        // whichever raw tx we happened to parse.
        let btc_pk = match PublicKey::from_slice(&info.btc_claim_pk) {
            Ok(pk) => pk,
            Err(e) => {
                report.rejected.push((eid, format!("bad user btc key in consensus escrow: {e}")));
                continue;
            }
        };
        let script = htlc_script(&info.hashlock, &btc_pk, &reserve.pk, btc_locktime);
        report.plans.push(RedeemPlan { escrow_id: eid, hashlock, value: info.value, script, btc_locktime, zc_timeout: info.timeout_height });
    }
}

/// OPERATOR redeem watcher, funding half: lock reserve BTC for one [`RedeemPlan`]. Looks
/// for an EXISTING funding of the same HTLC first (a previous attempt that broadcast but
/// was not recorded) and reuses it instead of funding again (bridge H2), even if the
/// claim window has since closed. A NEW funding is refused when the user would have
/// fewer than [`min_user_claim_blocks`] left, or when the ZC escrow's remaining life
/// cannot cover the lock at half-speed Bitcoin. `zc_tip` is the current ZC height.
/// Returns the UTXO, still UNCONFIRMED, plus whether it was reused; the caller persists
/// the txid, then waits for confirmations with `confirm`.
pub fn fund_redeem_plan(
    operator_btc: &dyn BtcBackend,
    plan: &RedeemPlan,
    zc_tip: u64,
) -> Result<(HtlcUtxo, bool), String> {
    if let Some(existing) = find_funded_htlc(operator_btc, &plan.script, Amount::from_sat(plan.value))? {
        return Ok((existing, true));
    }
    let net = operator_btc.network();
    let btc_tip = operator_btc.height()?;
    let lock_now = (plan.btc_locktime as u64).saturating_sub(btc_tip);
    let min_lock = min_user_claim_blocks(net);
    if lock_now < min_lock {
        return Err(format!(
            "redeem: deterministic lock {} (btc tip {btc_tip}) leaves the user only {lock_now} Bitcoin blocks, \
             below the {min_lock}-block minimum claim window: refusing to lock reserve BTC \
             (planned too long after the burn; the user's zBTC refunds at the escrow expiry)",
            plan.btc_locktime
        ));
    }
    // `zc_timeout == 0` is an intent saved before the field existed. Those files have no
    // ZC deadline on record, so only the Bitcoin window above applies (FundingIntent).
    if plan.zc_timeout > 0 {
        let remaining = plan.zc_timeout.saturating_sub(zc_tip) * ZC_BLOCK_TIME_SECS;
        let need = lock_now * BTC_BLOCK_TIME_SECS * BTC_SLOWDOWN_FACTOR + redeem_slack_secs(net, lock_now);
        if need > remaining {
            return Err(format!(
                "redeem: deterministic lock {} needs {need}s at half-speed Bitcoin but the escrow has {remaining}s \
                 left (tip {zc_tip}, timeout {}): refusing to lock reserve BTC",
                plan.btc_locktime, plan.zc_timeout
            ));
        }
    }
    let utxo = operator_btc.fund_htlc_unconfirmed(&plan.script, Amount::from_sat(plan.value))?;
    Ok((utxo, false))
}

/// OPERATOR autonomous REDEEM watcher: [`plan_redeems`] + [`fund_redeem_plan`] + confirm,
/// for one-shot callers (the e2e drivers). Idempotent via `already_funded`. The daemon
/// uses the two halves directly so it can persist each funding intent before broadcast.
#[allow(clippy::too_many_arguments)]
pub fn reserve_serve_redeems(
    zc: &dyn ZcNode,
    operator_btc: &dyn BtcBackend,
    reserve: &Key,
    from: i64,
    to: i64,
    zbtc_asset: u64,
    min_finalize_margin: u64,
    already_funded: &mut std::collections::HashSet<[u8; 32]>,
) -> Result<RedeemReport, String> {
    let planned = plan_redeems(zc, operator_btc, reserve, from, to, zbtc_asset, min_finalize_margin, already_funded)?;
    let zc_tip = zc.height()? as u64;
    let mut report = RedeemReport {
        already_funded: planned.skipped,
        rejected: planned.rejected,
        errors: planned.errors,
        ..Default::default()
    };
    for plan in planned.plans {
        // Claim the funding slot BEFORE broadcast; release it only if nothing was sent.
        already_funded.insert(plan.escrow_id);
        let outcome = fund_redeem_plan(operator_btc, &plan, zc_tip).and_then(|(utxo, _reused)| {
            operator_btc.confirm(&utxo.outpoint.txid)?;
            Ok(utxo)
        });
        match outcome {
            Ok(utxo) => report.locked.push(RedeemLock {
                escrow_id: plan.escrow_id,
                utxo,
                hashlock: plan.hashlock,
                btc_locktime: plan.btc_locktime,
            }),
            Err(e) => {
                already_funded.remove(&plan.escrow_id);
                report.errors.push((plan.escrow_id, e));
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
) -> Result<(u64, Blind), String> {
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
    // Refund coin first, then the envelope, then the proof bound to that envelope.
    let (_refund_blind, refund_open) =
        zcrypt_core::htlc_shield::CoinOpening::create(&alice.normal_address(), zbtc_value, asset)?;
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
        std::slice::from_ref(&refund_open.coin),
    );
    let stx = build_shield_spend_bound(
        zc,
        coins,
        &[burn_out, change_out],
        zcrypt_core::emission::MIN_FEE,
        vec![zcrypt_core::keys::cover_note_bytes(), change_note],
        &envelope,
    )?;
    let data = zc.broadcast(&burn_lock_tx(
        zbtc_value, &burn_blind, asset, &lock, zc_timeout, &alice.pubkey(), &stx, &refund_open,
    ))?;
    let escrow_id = escrow_id_from(&data)?;
    println!("  [zc]  Alice locked {} zBTC in burn escrow {}", zbtc_value, hex::encode(escrow_id));

    // 2. Bridge locks BTC claimable by Alice with the preimage. The lock is derived from the
    // escrow's remaining life (same rule as the operator daemon, bridge H1).
    progress(40, "Bridge locking BTC for you to claim…");
    let btc_locktime = redeem_btc_locktime_for(net, b.bridge.height()?, zc.height()? as u64, zc_timeout)?;
    let script = htlc_script(&lock, &b.alice_key.pk, &b.bridge_key.pk, btc_locktime);
    let utxo = b.bridge.fund_htlc(&script, btc_amount)?;
    println!("  [btc] bridge locked {} BTC in HTLC {}", btc_amount.to_btc(), utxo.outpoint.txid);

    // 3. Alice claims the BTC (to her own wallet), revealing the preimage on Bitcoin.
    // ALICE claims the BTC leg, so price her claim from Alice's backend (value-capped).
    progress(65, "Claiming your BTC (revealing the preimage)…");
    let fee = htlc_spend_fee_for(b.alice, 3, utxo.value.to_sat())?;
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

/// ZC blocks the MAKER must keep between the expiry of the leg the taker claims (the maker's
/// lock) and the expiry of the leg the maker claims (the taker's lock). The taker reveals the
/// preimage by claiming the maker's lock, possibly in its last block; the maker then needs
/// time to see the preimage and land its own claim before the taker's lock can be refunded.
/// Two hours at 1 s blocks (audit 2026-10 H9): the maker's wallet polls while its Bridge tab
/// is open, so a ten-minute window was lost to any ordinary interruption.
pub const SWAP_MAKER_CLAIM_MARGIN_BLOCKS: u64 = 7_200;

/// The two swap-escrow timeouts for a quote, as `(give_timeout, take_timeout)`: the TAKER's
/// lock (`give`, claimable by the maker) and the MAKER's lock (`take`, claimable by the taker).
///
/// Ordering is the whole safety argument of an atomic swap. The party who reveals the
/// preimage is the taker, by claiming the maker's `take` lock. That lock must therefore
/// expire FIRST: if it outlived the taker's own `give` lock, a patient taker could wait for
/// `give` to expire, refund it, and still claim `take`, walking away with both sides. So
/// `take` expires at `base + timeout`, and `give` expires at least
/// [`SWAP_MAKER_CLAIM_MARGIN_BLOCKS`] (and at least one further `timeout`) after that, which
/// is the window the maker has to claim after the reveal.
pub fn swap_timeouts(base: u64, timeout_blocks: u64) -> (u64, u64) {
    let t = timeout_blocks.max(1);
    let take_timeout = base + t;
    let give_timeout = take_timeout + t.max(SWAP_MAKER_CLAIM_MARGIN_BLOCKS);
    (give_timeout, take_timeout)
}

/// MAKER-side check before locking: the maker's lock (which the taker will claim, revealing
/// the preimage) must expire at least [`SWAP_MAKER_CLAIM_MARGIN_BLOCKS`] before the taker's
/// lock (which the maker claims afterwards). A maker wallet must refuse any quote for which
/// this is false, whatever the taker proposes.
pub fn maker_lock_is_safe(taker_give_timeout: u64, maker_take_timeout: u64) -> bool {
    maker_take_timeout.saturating_add(SWAP_MAKER_CLAIM_MARGIN_BLOCKS) <= taker_give_timeout
}

/// The least ZC blocks of life a lock must have when its counterparty is expected to claim
/// it: below this a swap cannot realistically complete and the lock only costs its fee.
pub const SWAP_MIN_CLAIM_BLOCKS: u64 = 60;

/// A counterparty's swap lock as read from the chain AND confirmed by consensus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapLock {
    pub escrow_id: [u8; 32],
    pub asset: u64,
    pub value: u64,
    pub hashlock: [u8; 32],
    pub timeout: u64,
    /// The locker (the escrow's refund key).
    pub locker_pk: PubKey,
    /// ZC height the lock transaction appeared in.
    pub height: i64,
}

/// ZC blocks of life a counterparty's swap lock must have left before this side acts on it
/// (locks against it, or claims it and thereby PUBLISHES the preimage). A claim whose escrow
/// expires within a block or two can pass CheckTx and still fail at delivery, with the
/// preimage in the block for the other side to use (bridge/swap audit 2026-10 H6).
pub const SWAP_CLAIM_SAFETY_BLOCKS: u64 = 30;

/// Consensus-side checks a party runs on the counterparty's lock BEFORE acting on it (audit
/// H6): the escrow is `open`, is a `swap` (not a burn or mint squatting the id), pays `me`
/// on claim, refunds `locker` on expiry, carries exactly the agreed asset, value and hashlock,
/// and has more than [`SWAP_CLAIM_SAFETY_BLOCKS`] of life past `zc_tip`. Nothing from the raw
/// transaction is trusted: every field comes from the `/htlc/<id>` record.
#[allow(clippy::too_many_arguments)]
pub fn check_counter_escrow(
    info: &EscrowInfo,
    me: &PubKey,
    locker: &PubKey,
    asset: u64,
    value: u64,
    hashlock: &[u8; 32],
    zc_tip: u64,
) -> Result<(), String> {
    if info.state != "open" {
        return Err(format!("counter-escrow is not open (state '{}')", info.state));
    }
    if info.kind != "swap" {
        return Err(format!("counter-escrow kind is '{}', not 'swap'", info.kind));
    }
    if !info.party_is(me) {
        return Err("counter-escrow does not pay this wallet on claim".to_string());
    }
    if !info.refund_is(locker) {
        return Err("counter-escrow is not refundable to the expected counterparty".to_string());
    }
    if info.asset_id != asset || info.value != value || info.hashlock != *hashlock {
        return Err(format!(
            "counter-escrow locks {} of asset {} (expected {value} of {asset}) or another hashlock",
            info.value, info.asset_id
        ));
    }
    if info.timeout_height <= zc_tip.saturating_add(SWAP_CLAIM_SAFETY_BLOCKS) {
        return Err(format!(
            "counter-escrow expires at {} with the tip at {zc_tip}: fewer than {SWAP_CLAIM_SAFETY_BLOCKS} blocks \
             of life, a claim could fail at delivery and still publish the preimage; let it expire",
            info.timeout_height
        ));
    }
    Ok(())
}

/// TAKER side, before claiming the maker's lock `escrow_id`: fetch the consensus record and
/// run [`check_counter_escrow`] against the current tip. Returns the record on success.
pub fn swap_claim_check(
    zc: &dyn ZcNode,
    escrow_id: &[u8; 32],
    me: &PubKey,
    maker: &PubKey,
    asset: u64,
    value: u64,
    hashlock: &[u8; 32],
) -> Result<EscrowInfo, String> {
    let zc_tip = zc.height()? as u64;
    let info = query_escrow(zc, escrow_id)?.ok_or("swap: the counter-escrow does not exist in consensus")?;
    check_counter_escrow(&info, me, maker, asset, value, hashlock, zc_tip)?;
    Ok(info)
}

/// Scan ZC blocks `from..=to` for a SWAP_LOCK whose hashlock is `hashlock`, whose claimant is
/// `claimant_pk`, and which locks exactly `value` of `asset`, then confirm with consensus that
/// the escrow exists, is an `open` SWAP escrow with those parameters, pays `claimant_pk` on
/// claim, and has more than [`SWAP_CLAIM_SAFETY_BLOCKS`] of life left ([`check_counter_escrow`],
/// audit H6). The escrow id binds the kind, the claimant and the refund key, so deriving it
/// from the wire fields and finding the record is proof the lock really pays this claimant;
/// the locker key is then taken from CONSENSUS, never from the raw tx. Returns the first
/// confirmed match.
pub fn find_swap_lock(
    zc: &dyn ZcNode,
    from: i64,
    to: i64,
    hashlock: &[u8; 32],
    claimant_pk: &PubKey,
    asset: u64,
    value: u64,
) -> Result<Option<SwapLock>, String> {
    use zcrypt_core::htlc_shield::{escrow_id as derive_escrow_id, EscrowKind};
    let zc_tip = zc.height()? as u64;
    for h in from..=to {
        for tx in zc.block_txs(h)? {
            // Both lock wires open the same escrow: 0x62 (gas prefix) and 0x6B (native gas).
            let parsed = match tx.first() {
                Some(&0x62) => parse_swap_lock(&tx[1..]),
                Some(&0x6B) => parse_swap_lock_native(&tx[1..]).map(|(v, b, a, l, t, c, r, _)| (v, b, a, l, t, c, r)),
                _ => None,
            };
            let Some((v, _blind, a, lock, timeout, counterparty, refund)) = parsed else {
                continue;
            };
            if lock != *hashlock || counterparty != *claimant_pk || a != asset || v != value {
                continue;
            }
            let eid = derive_escrow_id(EscrowKind::Swap, a, v, &lock, timeout, claimant_pk, &refund);
            let Some(info) = query_escrow(zc, &eid)? else { continue }; // rejected by consensus
            if info.timeout_height != timeout || check_counter_escrow(&info, claimant_pk, &refund, a, v, &lock, zc_tip).is_err() {
                continue; // settled, squatted by another kind, too short-lived, or parameters differ
            }
            let Some(locker_pk) = info.refund_pubkey() else { continue };
            return Ok(Some(SwapLock { escrow_id: eid, asset: a, value: v, hashlock: lock, timeout, locker_pk, height: h }));
        }
    }
    Ok(None)
}

/// MAKER side: the timeout for the maker's own lock given the taker's confirmed lock, or
/// `Err` if the taker's lock leaves too little room for a safe swap. The maker's lock must
/// expire [`SWAP_MAKER_CLAIM_MARGIN_BLOCKS`] before the taker's and still give the taker at
/// least [`SWAP_MIN_CLAIM_BLOCKS`] to claim it.
pub fn maker_take_timeout_for(taker_lock: &SwapLock, zc_tip: u64) -> Result<u64, String> {
    let take_timeout = taker_lock.timeout.saturating_sub(SWAP_MAKER_CLAIM_MARGIN_BLOCKS);
    if take_timeout < zc_tip.saturating_add(SWAP_MIN_CLAIM_BLOCKS) {
        return Err(format!(
            "swap: taker lock expires at {} (tip {zc_tip}); after the {SWAP_MAKER_CLAIM_MARGIN_BLOCKS}-block maker margin \
             the taker would have under {SWAP_MIN_CLAIM_BLOCKS} blocks to claim; refusing to lock",
            taker_lock.timeout
        ));
    }
    debug_assert!(maker_lock_is_safe(taker_lock.timeout, take_timeout));
    Ok(take_timeout)
}

/// TAKER side, step 1: lock `quote.give` for `maker_pk` under `hashlock`. `gas_coin` is
/// ZCRYPT the taker owns; the lock burns 0.01 of it and does not charge the locked asset.
/// Returns the escrow id, the taker's change coin, and the lock's timeout (which the
/// maker's lock must undercut).
pub fn taker_lock_give(
    zc: &Zcrypt,
    taker: &Account,
    coins: &[Coin],
    quote: &SwapQuote,
    maker: &zcrypt_core::keys::Address,
    hashlock: &[u8; 32],
    gas_coin: &Coin,
) -> Result<([u8; 32], Coin, u64), String> {
    let base = zc.height()? as u64;
    let (give_timeout, _take_timeout) = swap_timeouts(base, quote.timeout_blocks);
    let (eid, change, _claim_note) = send_swap_lock(
        zc, taker, quote.give_asset, quote.give_amount, coins, hashlock, give_timeout, maker, gas_coin,
    )?;
    Ok((eid, change, give_timeout))
}

/// MAKER side, step 2: given the taker's CONFIRMED lock (from [`find_swap_lock`] with the
/// maker as claimant), check it matches the quote, derive a safe timeout, and lock
/// `quote.take` for the taker under the same hashlock. Returns the maker's escrow id and
/// change coin.
pub fn maker_lock_take(
    zc: &Zcrypt,
    maker: &Account,
    coins: &[Coin],
    quote: &SwapQuote,
    taker_lock: &SwapLock,
    taker: &zcrypt_core::keys::Address,
    gas_coin: &Coin,
) -> Result<([u8; 32], Coin), String> {
    if taker_lock.asset != quote.give_asset || taker_lock.value != quote.give_amount {
        return Err(format!(
            "swap: taker lock is {} of asset {}, quote says {} of asset {}",
            taker_lock.value, taker_lock.asset, quote.give_amount, quote.give_asset
        ));
    }
    let zc_tip = zc.height()? as u64;
    let take_timeout = maker_take_timeout_for(taker_lock, zc_tip)?;
    if !maker_lock_is_safe(taker_lock.timeout, take_timeout) {
        return Err("swap: maker lock would not expire safely before the taker's lock; refusing".to_string());
    }
    if taker.pubkey() != taker_lock.locker_pk {
        return Err("swap: taker address does not match the locker's spend key".to_string());
    }
    let (eid, change, _claim_note) = send_swap_lock(
        zc, maker, quote.take_asset, quote.take_amount, coins, &taker_lock.hashlock, take_timeout, taker, gas_coin,
    )?;
    Ok((eid, change))
}

/// Scan ZC blocks `from..=to` for an HTLC_CLAIM (`0x5B`) of `escrow_id` whose preimage opens
/// `hashlock`. This is how the MAKER learns the preimage once the taker claims the maker's
/// lock, and how the TAKER can confirm the maker settled. Returns the preimage and the height
/// it was revealed at.
pub fn find_claim_preimage(
    zc: &dyn ZcNode,
    from: i64,
    to: i64,
    escrow_id: &[u8; 32],
    hashlock: &[u8; 32],
) -> Result<Option<(Vec<u8>, i64)>, String> {
    for h in from..=to {
        for tx in zc.block_txs(h)? {
            if tx.first() != Some(&0x5B) || tx.len() <= 33 || tx[1..33] != escrow_id[..] {
                continue;
            }
            let preimage = &tx[33..];
            if htlc_hashlock(preimage) == *hashlock {
                return Ok(Some((preimage.to_vec(), h)));
            }
        }
    }
    Ok(None)
}

/// The taker's outcome of a swap: the coin received (of `take_asset`) plus the change coin
/// left over from the coins they spent to fund their leg.
pub struct SwapResult {
    pub received: Coin,
    pub give_change: Coin,
}

/// Lock `value` of `asset` from `locker`'s `coins` into a **swap escrow** claimable by
/// `counterparty` (refund to the locker on timeout). The claim note is encrypted to
/// `counterparty` (it carries the ML-KEM key; a bare spend key is not enough) and the
/// refund note to the locker. Broadcasts the lock and returns
/// `(escrow_id, change_coin, claim_enc_note)`. The asset spend has fee 0, so change is
/// `inputs − value`. Gas is `gas_coin` (ZCRYPT owned by the locker): a separate proof
/// burns 0.01 ZCRYPT.
#[allow(clippy::too_many_arguments)]
fn send_swap_lock(
    zc: &Zcrypt,
    locker: &Account,
    asset: u64,
    value: u64,
    coins: &[Coin],
    hashlock: &[u8; 32],
    timeout: u64,
    counterparty: &zcrypt_core::keys::Address,
    gas_coin: &Coin,
) -> Result<([u8; 32], Coin, Vec<u8>), String> {
    let in_total: u64 = coins.iter().map(|c| c.value).sum();
    if value > in_total {
        return Err("lock value exceeds the locker's coins".to_string());
    }
    let min_fee = zcrypt_core::emission::MIN_FEE;
    if gas_coin.asset_id != zcrypt_shield::ASSET_ZCRYPT {
        return Err("swap gas coin must be ZCRYPT".to_string());
    }
    if gas_coin.value < min_fee {
        return Err("gas coin is below the minimum fee".to_string());
    }
    let burn_blind = zcrypt_core::keys::random_blind();
    let change_blind = zcrypt_core::keys::random_blind();
    let change_value = in_total - value;
    let burn_out: OutCoin = (value, burn_blind, zcrypt_core::htlc_shield::BURN_PK, asset);
    let change_out: OutCoin = (change_value, change_blind, locker.pubkey(), asset);
    let change_note = zcrypt_core::kem::ciphertext_to_bytes(&zcrypt_core::keys::encrypt_note_asset(
        &locker.normal_address(),
        change_value,
        change_blind,
        asset,
    ));
    // Claim note to the counterparty, refund note to the locker. Both exist before the
    // envelope, and the asset proof is bound to that envelope.
    let (_claim_blind, claim_open) = zcrypt_core::htlc_shield::CoinOpening::create(counterparty, value, asset)?;
    let (_refund_blind, refund_open) =
        zcrypt_core::htlc_shield::CoinOpening::create(&locker.normal_address(), value, asset)?;
    let counterparty_pk = counterparty.pubkey();
    let settlements = [claim_open.coin.clone(), refund_open.coin.clone()];
    let envelope = zcrypt_core::htlc_shield::lock_envelope(
        zcrypt_core::htlc_shield::ENV_SWAP_LOCK,
        asset,
        value,
        hashlock,
        timeout,
        &counterparty_pk,
        &locker.pubkey(),
        &[],
        &settlements,
    );
    let stx = build_shield_spend_bound(
        zc,
        coins,
        &[burn_out, change_out],
        0,
        vec![zcrypt_core::keys::cover_note_bytes(), change_note],
        &envelope,
    )?;
    // ZCRYPT gas note: output[0] burns MIN_FEE, output[1] is change back to the locker.
    let gas_blind = zcrypt_core::keys::random_blind();
    let gas_burn: OutCoin = (
        min_fee,
        gas_blind,
        zcrypt_core::htlc_shield::BURN_PK,
        zcrypt_shield::ASSET_ZCRYPT,
    );
    let gas_change_value = gas_coin.value - min_fee;
    let gas_change_blind = zcrypt_core::keys::random_blind();
    let gas_change = zcrypt_core::keys::out_coin(&locker.normal_address(), gas_change_value, gas_change_blind);
    let gas_change_note = zcrypt_core::kem::ciphertext_to_bytes(&zcrypt_core::keys::encrypt_note(
        &locker.normal_address(),
        gas_change_value,
        gas_change_blind,
    ));
    let gas_env = zcrypt_core::shield_tx::gas_pay_envelope(
        &zcrypt_core::shield_tx::txbind(chain_id(), &stx),
    );
    let gas_tx = build_shield_spend_bound(
        zc,
        &[gas_coin.clone()],
        &[gas_burn, gas_change],
        0,
        vec![zcrypt_core::keys::cover_note_bytes(), gas_change_note],
        &gas_env,
    )?;
    let data = zc.broadcast(&swap_lock_tx(
        value,
        &burn_blind,
        asset,
        hashlock,
        timeout,
        &counterparty_pk,
        &locker.pubkey(),
        &gas_blind,
        &gas_tx,
        &stx,
        &claim_open,
        &refund_open,
    ))?;
    let escrow = escrow_id_from(&data)?;
    Ok((escrow, locker.own_asset_coin(change_value, change_blind, asset), claim_open.coin.enc_note))
}

/// Run a **private in-pool atomic swap** between two shielded assets, per an agreed
/// [`SwapQuote`]. Two swap escrows share one hashlock: the taker locks `give`, the maker
/// locks `take`, the taker claims `take` (revealing the preimage), the maker reads it from
/// the chain and claims `give`. What is PRIVATE is the coins' history: the locked coins are
/// spent out of the shielded pool with a membership proof, and the settlement coins are fresh
/// leaves. The escrows themselves are transparent in the current design: each lock publishes
/// its value, asset id, hashlock, timeout and BOTH party keys (claimant and refund), so an
/// observer can read the trade's terms and link the two legs through the shared hashlock.
/// Returns the taker's received coin + change. (The single-wallet demo supplies both `taker`
/// and `maker`, exactly like the BTC bridge plays Alice + LP.)
#[allow(clippy::too_many_arguments)]
pub fn swap_in_pool_progress(
    zc: &Zcrypt,
    taker: &Account,
    maker: &Account,
    taker_give_coins: &[Coin],
    maker_take_coins: &[Coin],
    taker_gas: &Coin,
    maker_gas: &Coin,
    quote: &SwapQuote,
    preimage: &[u8],
    progress: &dyn Fn(u8, &str),
) -> Result<SwapResult, String> {
    if preimage.len() != PREIMAGE_LEN {
        return Err(format!("HTLC preimage must be exactly {PREIMAGE_LEN} bytes (got {})", preimage.len()));
    }
    let lock = htlc_hashlock(preimage);
    // Stagger the timeouts so the leg the TAKER claims (the maker's `take` lock, whose claim
    // reveals the preimage) expires first, and the leg the MAKER claims (the taker's `give`
    // lock) expires a margin later. See `swap_timeouts` for why the reverse order lets the
    // taker keep both sides.
    let base = zc.height()? as u64;
    let (give_timeout, take_timeout) = swap_timeouts(base, quote.timeout_blocks);
    debug_assert!(maker_lock_is_safe(give_timeout, take_timeout));

    progress(15, "Locking your side of the swap…");
    let (give_escrow, give_change, give_claim_note) = send_swap_lock(
        zc, taker, quote.give_asset, quote.give_amount, taker_give_coins, &lock, give_timeout,
        &maker.normal_address(), taker_gas,
    )?;

    progress(40, "Maker locking their side…");
    // What a maker wallet must check against the taker's on-chain lock before committing.
    if !maker_lock_is_safe(give_timeout, take_timeout) {
        return Err("swap: maker lock would not expire safely before the taker's lock; refusing".to_string());
    }
    let (take_escrow, _maker_change, take_claim_note) = send_swap_lock(
        zc, maker, quote.take_asset, quote.take_amount, maker_take_coins, &lock, take_timeout,
        &taker.normal_address(), maker_gas,
    )?;

    progress(65, "Claiming what you receive (revealing the preimage)…");
    // Never publish the preimage against a lock that is not a live swap escrow paying us with
    // enough life left for the claim to settle (audit H6).
    swap_claim_check(zc, &take_escrow, &taker.pubkey(), &maker.pubkey(), quote.take_asset, quote.take_amount, &lock)?;
    zc.broadcast(&claim_tx(&take_escrow, preimage))?;
    // The maker chose the claim blind. The taker learns the coin by decrypting the note,
    // and the maker does the same for the taker's claim note.
    let received = coin_from_note(taker, &take_claim_note)?;
    let _maker_received = coin_from_note(maker, &give_claim_note)?;

    progress(85, "Maker settling their side…");
    // The maker reads the now-public preimage from the chain and claims the give leg.
    zc.broadcast(&claim_tx(&give_escrow, preimage))?;

    progress(100, "Swap complete — the asset is in your wallet.");
    Ok(SwapResult { received, give_change })
}

#[cfg(test)]
mod native_gas_wire_tests {
    use super::*;

    fn stx(fee: u64) -> shield_tx::ShieldTx {
        shield_tx::ShieldTx { inputs: vec![], output_commitments: vec![], enc_notes: vec![], fee, root: [0u64; 8], proof: vec![9, 9] }
    }

    #[test]
    fn zcrypt_transfer_wire_round_trips() {
        let blind: Blind = core::array::from_fn(|i| 3 + i as u64);
        let raw = zcrypt_transfer_tx(10_000, &blind, &stx(0));
        assert_eq!(raw[0], 0x6A);
        let (v, b, tx) = parse_zcrypt_transfer_payload(&raw[1..]).expect("parses");
        assert_eq!((v, b, tx.proof), (10_000, blind, vec![9, 9]));
        assert!(parse_zcrypt_transfer_payload(&raw[1..raw.len() - 1]).is_none());
    }

    #[test]
    fn native_swap_lock_wire_round_trips_and_find_swap_lock_reads_both_tags() {
        let blind: Blind = core::array::from_fn(|i| 5 + i as u64);
        let cp: PubKey = core::array::from_fn(|i| 30 + i as u64);
        let rf: PubKey = core::array::from_fn(|i| 50 + i as u64);
        let lock = [0x22u8; 32];
        let sponsor = [0xCDu8; 32];
        let (holder, _) = zcrypt_core::keys::new_account();
        let (_, claim) = zcrypt_core::htlc_shield::CoinOpening::prove(&holder.normal_address(), &cp, 700, 4, zcrypt_core::keys::random_blind()).unwrap();
        let (_, refund) = zcrypt_core::htlc_shield::CoinOpening::prove(&holder.normal_address(), &rf, 700, 4, zcrypt_core::keys::random_blind()).unwrap();
        let raw = swap_lock_native_tx(700, &blind, 4, &lock, 999, &cp, &rf, &sponsor, &stx(20_000), &claim, &refund);
        assert_eq!(raw[0], 0x6B);
        let (v, b, a, l, t, c, r, sp) = parse_swap_lock_native(&raw[1..]).expect("header parses");
        assert_eq!((v, b, a, l, t), (700, blind, 4, lock, 999));
        assert_eq!((c, r, sp), (cp, rf, sponsor));
        // The 0x62 header parser reads the same 248 bytes (it ignores what follows).
        let (v2, _, a2, l2, t2, c2, r2) = parse_swap_lock(&raw[1..]).unwrap();
        assert_eq!((v2, a2, l2, t2, c2, r2), (700, 4, lock, 999, cp, rf));
        assert_eq!(native_lock_fee(zcrypt_shield::ASSET_ZCRYPT, false), zcrypt_core::emission::MIN_FEE);
        assert_eq!(native_lock_fee(zcrypt_shield::ASSET_ZCRYPT, true), 2 * zcrypt_core::emission::MIN_FEE);
        assert_eq!(native_lock_fee(4, true), 0);
        assert_eq!(sponsored_lock_timeout(1_000), 1_000 + SWAP_MAKER_CLAIM_MARGIN_BLOCKS);
    }
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
            coinbase_raw: vec![],
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
            coinbase_raw: vec![],
        };
        let claim_pk: PubKey = [1, 2, 3, 4, 5, 6, 7, 8];
        let payload = open_spv_tx(0xABCD, 555_000, &lock, 42, &claim_pk, &proof, &refund, &dummy_opening());
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
        use zcrypt_core::htlc_shield::EscrowKind;
        let eid = zcrypt_core::htlc_shield::escrow_id(EscrowKind::Mint, asset, value, &plock, timeout, &pclaim, &pclaim);
        let eid2 = zcrypt_core::htlc_shield::escrow_id(EscrowKind::Mint, 0xABCD, 555_000, &lock, 42, &claim_pk, &claim_pk);
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
    fn redeem_lock_is_derived_from_escrow_life_and_short_escrows_are_refused() {
        for net in [Network::Bitcoin, Network::Signet, Network::Regtest] {
            let btc_tip = 800_000u64;
            let zc_tip = 5_000u64;
            // An honest wallet's escrow (network redeem window) gets the largest lock that
            // still fits at half-speed Bitcoin (bridge M14): never more than the nominal
            // network lock, never below the minimum user claim window.
            let honest = zc_tip + zc_redeem_timeout_blocks(net);
            let lt = redeem_btc_locktime_for(net, btc_tip, zc_tip, honest).expect("honest escrow funds");
            let lock_blocks = lt as u64 - btc_tip;
            assert!(lock_blocks <= btc_redeem_lock_blocks(net), "{net:?}: never above the nominal lock");
            assert!(lock_blocks >= min_user_claim_blocks(net), "{net:?}: never below the claim window");
            // The lock at half-speed Bitcoin plus its slack (max of the SLA and a quarter of the
            // lock) always expires before the ZC escrow (bridge N9 / M14).
            let lock_secs = lock_blocks * BTC_BLOCK_TIME_SECS * BTC_SLOWDOWN_FACTOR + redeem_slack_secs(net, lock_blocks);
            assert!(lock_secs <= (honest - zc_tip) * ZC_BLOCK_TIME_SECS, "{net:?}: lock outlives escrow");
            assert!(redeem_slack_secs(net, lock_blocks) >= lock_blocks * BTC_BLOCK_TIME_SECS / SLACK_FRACTION_DEN);
            // The audit's theft: a burn with a 36h escrow against an 84h BTC lock. Now the
            // lock SHRINKS to fit, and a too-short escrow is refused outright.
            let short = zc_tip + min_redeem_margin_blocks(net) - 1;
            assert!(redeem_btc_locktime_for(net, btc_tip, zc_tip, short).is_err(), "{net:?}: short escrow refused");
            let just_enough = zc_tip + min_redeem_margin_blocks(net);
            let lt2 = redeem_btc_locktime_for(net, btc_tip, zc_tip, just_enough).expect("minimum escrow funds");
            assert!(lt2 as u64 - btc_tip >= min_user_claim_blocks(net));
            let lb2 = lt2 as u64 - btc_tip;
            let lock2 = lb2 * BTC_BLOCK_TIME_SECS * BTC_SLOWDOWN_FACTOR + redeem_slack_secs(net, lb2);
            assert!(lock2 <= (just_enough - zc_tip) * ZC_BLOCK_TIME_SECS);
            // Whatever escrow life the user picks, the slack never collapses to the bare SLA
            // once the lock is long enough for a quarter of it to exceed the SLA.
            for extra in [0u64, 10_000, 100_000, 300_000] {
                let t = just_enough + extra;
                if let Ok(lt3) = redeem_btc_locktime_for(net, btc_tip, zc_tip, t) {
                    let lb3 = lt3 as u64 - btc_tip;
                    let slack = (t - zc_tip) * ZC_BLOCK_TIME_SECS - lb3 * BTC_BLOCK_TIME_SECS * BTC_SLOWDOWN_FACTOR;
                    assert!(slack >= redeem_slack_secs(net, lb3), "{net:?}: slack {slack}s below the rule for a {lb3}-block lock");
                }
            }
        }
        // The daemon's margin floor is at least the user's claim window plus its slack.
        assert!(min_redeem_margin_blocks(Network::Bitcoin) >= MIN_USER_CLAIM_BLOCKS_MAINNET * BTC_BLOCK_TIME_SECS);
        // Mainnet at the default margin: the lock is the largest that fits at half-speed
        // Bitcoin (below the 504 nominal), and still well above the 144-block claim window.
        let lt = redeem_btc_locktime_for(Network::Bitcoin, 800_000, 5_000, 5_000 + default_finalize_margin(Network::Bitcoin)).unwrap();
        let lock = lt as u64 - 800_000;
        assert!(lock <= 504 && lock >= 2 * MIN_USER_CLAIM_BLOCKS_MAINNET, "lock {lock}");
        assert!(default_finalize_margin(Network::Bitcoin) >= lock * 600 * BTC_SLOWDOWN_FACTOR + redeem_slack_secs(Network::Bitcoin, lock));
    }

    /// Regtest `generatetoaddress` runs Bitcoin's median time ahead of the burn's BFT time, so
    /// the lag-0 anchor sits a whole burst behind the tip. A wallet burn (the long
    /// `ZC_REDEEM_TIMEOUT_BLOCKS` escrow `redeem_user_burn` uses on every network) must still
    /// leave the user [`min_user_claim_blocks`] after a 200-block lead, and the CLTV must be a
    /// function of the anchor alone so a later replan does not move it. Mainnet does not gain
    /// the regtest allowance.
    #[test]
    fn regtest_redeem_lock_covers_generatetoaddress_clock_lead() {
        let anchor = 1_000u64;
        let burn_height = 50u64;
        let timeout = burn_height + ZC_REDEEM_TIMEOUT_BLOCKS;
        let lt = redeem_btc_locktime_for(Network::Regtest, anchor, burn_height, timeout).expect("regtest funds");
        let lead = 200u64;
        let btc_tip = anchor + lead;
        let lock_now = (lt as u64).saturating_sub(btc_tip);
        assert!(
            lock_now >= min_user_claim_blocks(Network::Regtest),
            "lock {lt} from anchor {anchor} leaves only {lock_now} blocks above tip {btc_tip}"
        );
        let remaining = timeout.saturating_sub(burn_height) * ZC_BLOCK_TIME_SECS;
        let need = lock_now * BTC_BLOCK_TIME_SECS * BTC_SLOWDOWN_FACTOR + redeem_slack_secs(Network::Regtest, lock_now);
        assert!(need <= remaining, "half-speed need {need}s exceeds the escrow's {remaining}s");
        assert_eq!(redeem_btc_locktime_for(Network::Regtest, anchor, burn_height, timeout).unwrap(), lt);
        let main = redeem_btc_locktime_for(Network::Bitcoin, anchor, burn_height, timeout).unwrap();
        assert!(main as u64 - anchor <= btc_redeem_lock_blocks(Network::Bitcoin));
        assert!(lt as u64 - anchor > btc_redeem_lock_blocks(Network::Regtest));
    }

    #[test]
    fn fee_caps_bound_a_lying_oracle() {
        assert_eq!(crate::cap_fee_rate(1_000_000.0), crate::MAX_FEE_RATE_SAT_VB);
        assert_eq!(crate::cap_fee_rate(0.1), 1.0);
        assert_eq!(crate::cap_fee_rate(f64::NAN), 1.0);
        // A 100k-sat HTLC never pays more than 25k in fees, whatever the estimator says.
        assert_eq!(crate::cap_fee_for_value(90_000, 100_000, 500).unwrap(), 25_000);
        // The relay floor survives on small values...
        assert_eq!(crate::cap_fee_for_value(5_000, 1_500, 500).unwrap(), 500);
        // ...but dust that the floor would consume is refused.
        assert!(crate::cap_fee_for_value(5_000, 400, 500).is_err());
    }

    /// An 80-byte Bitcoin header whose only meaningful field is the timestamp.
    fn synthetic_header(ts: u32) -> [u8; 80] {
        let mut h = [0u8; 80];
        h[68..72].copy_from_slice(&ts.to_le_bytes());
        h
    }

    /// A backend that only answers the funding-discovery questions, counting broadcasts.
    struct MockBtc {
        existing: Vec<HtlcUtxo>,
        broadcasts: std::cell::Cell<u32>,
        tip: u64,
    }
    impl crate::BtcBackend for MockBtc {
        fn fund_htlc(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
            self.fund_htlc_unconfirmed(script, amount)
        }
        fn fund_htlc_unconfirmed(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
            self.broadcasts.set(self.broadcasts.get() + 1);
            Ok(HtlcUtxo { outpoint: OutPoint::null(), value: amount, script: script.clone() })
        }
        fn htlc_utxos(&self, script: &ScriptBuf) -> Result<Vec<HtlcUtxo>, String> {
            Ok(self.existing.iter().filter(|u| &u.script == script).cloned().collect())
        }
        fn claim(&self, _: &HtlcUtxo, _: &[u8], _: &Key, _: &Address, _: Amount) -> Result<bitcoin::Txid, String> {
            Err("mock".into())
        }
        fn height(&self) -> Result<u64, String> {
            Ok(self.tip)
        }
        fn network(&self) -> Network {
            Network::Bitcoin
        }
        fn preimage_from_claim(&self, _: &bitcoin::Txid) -> Option<Vec<u8>> {
            None
        }
        fn confirm(&self, _: &bitcoin::Txid) -> Result<(), String> {
            Ok(())
        }
        fn fee_rate_sat_vb(&self, _: u32) -> Result<f64, String> {
            Ok(1.0)
        }
        fn find_htlc_spend(&self, _: &HtlcUtxo, _: u64) -> Result<crate::HtlcSpend, String> {
            Ok(crate::HtlcSpend::Unspent)
        }
        fn block_header(&self, h: u64) -> Result<[u8; 80], String> {
            // Synthetic chain: one block every 600 s from the epoch.
            Ok(synthetic_header((h * 600) as u32))
        }
        fn raw_tx(&self, _: &bitcoin::Txid) -> Result<Vec<u8>, String> {
            Err("mock".into())
        }
        fn txout_proof(&self, _: &bitcoin::Txid) -> Result<Vec<u8>, String> {
            Err("mock".into())
        }
    }

    #[test]
    fn funding_reuses_an_existing_htlc_instead_of_paying_twice() {
        let reserve = Key::from_bytes(&[7u8; 32]);
        let user = Key::from_bytes(&[9u8; 32]);
        let lock = htlc_hashlock(&[3u8; 32]);
        // Locktime leaves more than the 144-block claim window above tip 800_000, and
        // zc_timeout covers that lock at half-speed Bitcoin, so a fresh backend may fund.
        let script = htlc_script(&lock, &user.pk, &reserve.pk, 800_200);
        let plan = RedeemPlan { escrow_id: [1u8; 32], hashlock: lock, value: 50_000, script: script.clone(), btc_locktime: 800_200, zc_timeout: 1_000_000 };

        // Nothing on the address yet: exactly one broadcast.
        let fresh = MockBtc { existing: vec![], broadcasts: std::cell::Cell::new(0), tip: MOCK_BTC_TIP };
        let (utxo, reused) = fund_redeem_plan(&fresh, &plan, 0).unwrap();
        assert!(!reused);
        assert_eq!(fresh.broadcasts.get(), 1);
        assert_eq!(utxo.value, Amount::from_sat(50_000));

        // A previous attempt already funded it (crash after broadcast): NO second broadcast.
        let funded = MockBtc {
            existing: vec![HtlcUtxo { outpoint: OutPoint::null(), value: Amount::from_sat(50_000), script: script.clone() }],
            broadcasts: std::cell::Cell::new(0),
            tip: MOCK_BTC_TIP,
        };
        let (_utxo, reused) = fund_redeem_plan(&funded, &plan, 0).unwrap();
        assert!(reused, "existing funding is reused");
        assert_eq!(funded.broadcasts.get(), 0, "never funds the same escrow twice");

        // An underfunded stray output does not count; a different script is not ours.
        let other = htlc_script(&lock, &user.pk, &reserve.pk, 800_300);
        let strays = MockBtc {
            existing: vec![
                HtlcUtxo { outpoint: OutPoint::null(), value: Amount::from_sat(1), script: script.clone() },
                HtlcUtxo { outpoint: OutPoint::null(), value: Amount::from_sat(50_000), script: other },
            ],
            broadcasts: std::cell::Cell::new(0),
            tip: MOCK_BTC_TIP,
        };
        assert!(find_funded_htlc(&strays, &script, Amount::from_sat(50_000)).unwrap().is_none());
        // ...and a resume lookup finds a real funding by script (bridge L3).
        assert!(find_funded_htlc(&funded, &script, Amount::from_sat(50_000)).unwrap().is_some());
    }

    /// Minimal in-memory node for the maker-side lookups: raw blocks plus the consensus
    /// escrow table the `/htlc/<id>` query reads.
    struct SwapFakeZc {
        blocks: Vec<Vec<Vec<u8>>>,
        escrows: std::collections::HashMap<[u8; 32], (u64, u64, [u8; 32], u64, &'static str)>,
        /// Consensus-committed payout key per burn escrow (what `/htlc/<id>` reports).
        btc_keys: std::collections::HashMap<[u8; 32], Vec<u8>>,
        /// Consensus-committed `(party_pk, refund_pk)` per escrow (swap tests).
        parties: std::collections::HashMap<[u8; 32], (PubKey, PubKey)>,
        /// BFT time of block 1; each block is one second later.
        base_time: u64,
    }
    impl ZcNode for SwapFakeZc {
        fn height(&self) -> Result<i64, String> {
            Ok(self.blocks.len() as i64)
        }
        fn block_txs(&self, height: i64) -> Result<Vec<Vec<u8>>, String> {
            Ok(self.blocks.get((height - 1).max(0) as usize).cloned().unwrap_or_default())
        }
        fn block_time(&self, height: i64) -> Result<u64, String> {
            Ok(self.base_time + height.max(0) as u64)
        }
        fn query(&self, path: &str) -> Result<String, String> {
            let Some(h) = path.strip_prefix("/htlc/") else { return Err(format!("unexpected query {path}")) };
            let raw = hex::decode(h).map_err(|e| e.to_string())?;
            let eid: [u8; 32] = raw.as_slice().try_into().map_err(|_| "bad id".to_string())?;
            match self.escrows.get(&eid) {
                Some((a, v, l, t, s)) => {
                    let key = self.btc_keys.get(&eid).cloned().unwrap_or_default();
                    let (party, refund) = self.parties.get(&eid).map(|(p, r)| (pk_bytes(p), pk_bytes(r))).unwrap_or_default();
                    Ok(serde_json::json!({
                        "asset_id": a, "value": v, "hashlock": hex::encode(l), "timeout_height": t, "state": s,
                        "kind": if key.is_empty() { "swap" } else { "burn" },
                        "btc_claim_pk": hex::encode(&key),
                        "party_pk": hex::encode(party),
                        "refund_pk": hex::encode(refund),
                    })
                    .to_string())
                }
                None => Err("no such escrow".into()),
            }
        }
        fn broadcast(&self, _tx: &[u8]) -> Result<String, String> {
            Err("not used".into())
        }
    }

    /// A SWAP_LOCK tx as it appears in a block (the shield tx bytes are irrelevant to the
    /// lookup, which trusts consensus, not the raw proof).
    fn raw_swap_lock(value: u64, asset: u64, lock: &[u8; 32], timeout: u64, claimant: &PubKey, locker: &PubKey) -> Vec<u8> {
        let mut t = vec![0x62u8];
        t.extend_from_slice(&value.to_le_bytes());
        t.extend_from_slice(&[0u8; zcrypt_shield::BLIND_BYTES]);
        t.extend_from_slice(&asset.to_le_bytes());
        t.extend_from_slice(lock);
        t.extend_from_slice(&timeout.to_le_bytes());
        t.extend_from_slice(&pk_bytes(claimant));
        t.extend_from_slice(&pk_bytes(locker));
        t.extend_from_slice(b"proof-bytes-not-parsed-here");
        t
    }

    #[test]
    fn maker_finds_only_a_consensus_confirmed_lock_that_pays_it() {
        use zcrypt_core::htlc_shield::{escrow_id, EscrowKind};
        let maker: PubKey = [11; 8];
        let taker: PubKey = [22; 8];
        let other: PubKey = [33; 8];
        let preimage = [7u8; 32];
        let lock = htlc_hashlock(&preimage);
        let (asset, value, timeout) = (5u64, 100_000u64, 20_000u64);
        let good = raw_swap_lock(value, asset, &lock, timeout, &maker, &taker);
        let wrong_claimant = raw_swap_lock(value, asset, &lock, timeout, &other, &taker);
        let wrong_value = raw_swap_lock(value - 1, asset, &lock, timeout, &maker, &taker);
        let wrong_lock = raw_swap_lock(value, asset, &[9u8; 32], timeout, &maker, &taker);
        // A lock that LOOKS right on the wire but consensus rejected (no escrow), and one that
        // is already settled.
        let unconfirmed = raw_swap_lock(value, asset, &lock, timeout + 1, &maker, &taker);
        let settled = raw_swap_lock(value, asset, &lock, timeout + 2, &maker, &taker);
        // A swap-looking lock whose consensus record is a BURN squatting the id space (H6/H7),
        // and one with too little life left for a safe claim.
        let squat = raw_swap_lock(value, asset, &lock, timeout + 3, &maker, &taker);
        let short = raw_swap_lock(value, asset, &lock, 4 + SWAP_CLAIM_SAFETY_BLOCKS, &maker, &taker);
        let sid = |t: u64, v: u64| escrow_id(EscrowKind::Swap, asset, v, &lock, t, &maker, &taker);
        let mut escrows = std::collections::HashMap::new();
        let mut parties = std::collections::HashMap::new();
        for (t, v, s) in [(timeout, value, "open"), (timeout, value - 1, "open"), (timeout + 2, value, "claimed"), (timeout + 3, value, "open"), (4 + SWAP_CLAIM_SAFETY_BLOCKS, value, "open")] {
            escrows.insert(sid(t, v), (asset, v, lock, t, s));
            parties.insert(sid(t, v), (maker, taker));
        }
        let mut btc_keys = std::collections::HashMap::new();
        btc_keys.insert(sid(timeout + 3, value), vec![2u8; 33]); // reported as kind "burn"
        let zc = SwapFakeZc {
            blocks: vec![vec![wrong_claimant, wrong_value], vec![wrong_lock, unconfirmed, settled, squat, short], vec![good], vec![]],
            escrows,
            btc_keys,
            parties,
            base_time: 0,
        };
        let found = find_swap_lock(&zc, 1, 3, &lock, &maker, asset, value).unwrap().expect("the good lock is found");
        assert_eq!(found.height, 3);
        assert_eq!(found.timeout, timeout);
        assert_eq!(found.locker_pk, taker, "locker key comes from consensus");
        assert_eq!(found.escrow_id, sid(timeout, value));
        // Scanning only the blocks with decoys finds nothing.
        assert!(find_swap_lock(&zc, 1, 2, &lock, &maker, asset, value).unwrap().is_none());
        // The taker-side claim gate agrees: only the good lock may be claimed against.
        assert!(swap_claim_check(&zc, &sid(timeout, value), &maker, &taker, asset, value, &lock).is_ok());
        assert!(swap_claim_check(&zc, &sid(timeout + 3, value), &maker, &taker, asset, value, &lock).unwrap_err().contains("not 'swap'"));
        assert!(swap_claim_check(&zc, &sid(4 + SWAP_CLAIM_SAFETY_BLOCKS, value), &maker, &taker, asset, value, &lock).unwrap_err().contains("let it expire"));
        assert!(swap_claim_check(&zc, &sid(timeout, value), &other, &taker, asset, value, &lock).unwrap_err().contains("does not pay"));
        assert!(swap_claim_check(&zc, &sid(timeout, value), &maker, &other, asset, value, &lock).unwrap_err().contains("not refundable"));
        // The maker's own timeout undercuts the taker's by the margin, and is refused when the
        // taker's lock is too short to leave a claim window.
        assert_eq!(maker_take_timeout_for(&found, 100).unwrap(), timeout - SWAP_MAKER_CLAIM_MARGIN_BLOCKS);
        let err = maker_take_timeout_for(&found, timeout - SWAP_MAKER_CLAIM_MARGIN_BLOCKS - SWAP_MIN_CLAIM_BLOCKS + 1).unwrap_err();
        assert!(err.contains("refusing to lock"), "{err}");
    }

    #[test]
    fn maker_reads_the_preimage_from_the_takers_claim() {
        let preimage = [4u8; 32];
        let lock = htlc_hashlock(&preimage);
        let eid = [0xEE; 32];
        let other_eid = [0xEF; 32];
        let zc = SwapFakeZc {
            blocks: vec![
                vec![claim_tx(&other_eid, &preimage)],   // someone else's escrow
                vec![claim_tx(&eid, &[5u8; 32])],       // wrong preimage (consensus rejects it)
                vec![claim_tx(&eid, &preimage)],
            ],
            escrows: Default::default(),
            btc_keys: Default::default(),
            parties: Default::default(),
            base_time: 0,
        };
        assert!(find_claim_preimage(&zc, 1, 2, &eid, &lock).unwrap().is_none());
        let (p, h) = find_claim_preimage(&zc, 1, 3, &eid, &lock).unwrap().expect("found");
        assert_eq!(p, preimage);
        assert_eq!(h, 3);
    }

    /// A 0x67 burn-lock-for-BTC as it appears in a block (the shield tx bytes are not parsed by
    /// the planner, which trusts consensus for the escrow and its payout key).
    fn raw_burn_lock_btc(btc_pk: &[u8; 33], value: u64, asset: u64, lock: &[u8; 32], timeout: u64, refund: &PubKey) -> Vec<u8> {
        let mut t = vec![0x67u8];
        t.extend_from_slice(btc_pk);
        t.extend_from_slice(&value.to_le_bytes());
        t.extend_from_slice(&[0u8; zcrypt_shield::BLIND_BYTES]);
        t.extend_from_slice(&asset.to_le_bytes());
        t.extend_from_slice(lock);
        t.extend_from_slice(&timeout.to_le_bytes());
        t.extend_from_slice(&pk_bytes(refund));
        t.extend_from_slice(b"proof-bytes-not-parsed-here");
        t
    }

    /// Bridge C1: two burn-locks with identical lock parameters (one accepted, one that failed
    /// delivery but still sits in the block) carry different BTC payout keys. The planner must
    /// produce ONE plan for the escrow, and its script must use the key CONSENSUS committed,
    /// never the key parsed from whichever raw tx came first.
    #[test]
    fn planner_funds_one_htlc_per_escrow_using_the_consensus_payout_key() {
        use zcrypt_core::htlc_shield::{escrow_id, EscrowKind};
        let reserve = Key::from_bytes(&[9u8; 32]);
        let k_real = Key::from_bytes(&[1u8; 32]).pk.inner.serialize();
        let k_dup = Key::from_bytes(&[2u8; 32]).pk.inner.serialize();
        let refund: PubKey = [7; 8];
        let preimage = [3u8; 32];
        let lock = htlc_hashlock(&preimage);
        let (asset, value) = (5u64, 200_000u64);
        let zc_tip = 2u64; // two blocks below
        let timeout = zc_tip + zc_redeem_timeout_blocks(Network::Bitcoin);
        let eid = escrow_id(EscrowKind::Burn, asset, value, &lock, timeout, &refund, &refund);
        let mut escrows = std::collections::HashMap::new();
        escrows.insert(eid, (asset, value, lock, timeout, "open"));
        let mut btc_keys = std::collections::HashMap::new();
        btc_keys.insert(eid, k_real.to_vec());
        // The duplicate (attacker) copy is ordered FIRST in the block on purpose.
        let zc = SwapFakeZc {
            blocks: vec![
                vec![
                    raw_burn_lock_btc(&k_dup, value, asset, &lock, timeout, &refund),
                    raw_burn_lock_btc(&k_real, value, asset, &lock, timeout, &refund),
                ],
                vec![raw_burn_lock_btc(&k_dup, value, asset, &lock, timeout, &refund)],
            ],
            escrows,
            btc_keys,
            parties: Default::default(),
            base_time: MOCK_BTC_TIP * 600, // the burn lands at Bitcoin's wall time
        };
        let btc = MockBtc { existing: vec![], broadcasts: std::cell::Cell::new(0), tip: MOCK_BTC_TIP };
        let skip = std::collections::HashSet::new();
        let report = plan_redeems(&zc, &btc, &reserve, 1, 2, asset, 0, &skip).unwrap();
        assert_eq!(report.plans.len(), 1, "exactly one plan per escrow id per pass");
        let plan = &report.plans[0];
        assert_eq!(plan.escrow_id, eid);
        let real_pk = PublicKey::from_slice(&k_real).unwrap();
        let expected = htlc_script(&lock, &real_pk, &reserve.pk, plan.btc_locktime);
        assert_eq!(plan.script, expected, "the script pays the CONSENSUS key, not the raw-tx key");
        let dup_pk = PublicKey::from_slice(&k_dup).unwrap();
        assert_ne!(plan.script, htlc_script(&lock, &dup_pk, &reserve.pk, plan.btc_locktime));
        assert_eq!(report.rejected.len(), 2, "both duplicate copies are rejected, not planned");
        assert!(report.rejected.iter().all(|(id, why)| *id == eid && why.contains("duplicate")));

        // Same block, but consensus committed NO payout key (older node): nothing is funded.
        let zc_nokey = SwapFakeZc {
            blocks: vec![vec![raw_burn_lock_btc(&k_real, value, asset, &lock, timeout, &refund)]],
            escrows: {
                let mut e = std::collections::HashMap::new();
                e.insert(eid, (asset, value, lock, timeout, "open"));
                e
            },
            btc_keys: Default::default(),
            parties: Default::default(),
            base_time: MOCK_BTC_TIP * 600,
        };
        let report = plan_redeems(&zc_nokey, &btc, &reserve, 1, 1, asset, 0, &skip).unwrap();
        assert!(report.plans.is_empty(), "no consensus payout key means no funding");
        assert_eq!(report.rejected.len(), 1);
    }

    /// Audit 2026-10 design note: the wallet burns with the fixed `ZC_REDEEM_TIMEOUT_BLOCKS`
    /// while the daemon's default margin is `default_finalize_margin(Bitcoin)`. A burn built
    /// at tip T and planned at T+1 with the default margin MUST be accepted; if the two
    /// constants ever converge (or invert) this test fails before a release rejects every
    /// honest redeem.
    #[test]
    fn honest_wallet_burn_is_planned_at_the_default_margin() {
        use zcrypt_core::htlc_shield::{escrow_id, EscrowKind};
        let reserve = Key::from_bytes(&[9u8; 32]);
        let k_user = Key::from_bytes(&[1u8; 32]).pk.inner.serialize();
        let refund: PubKey = [7; 8];
        let lock = htlc_hashlock(&[3u8; 32]);
        let (asset, value) = (5u64, 200_000u64);
        let burn_tip = 1u64; // the wallet reads tip T = 1 and burns into block 2
        let timeout = burn_tip + ZC_REDEEM_TIMEOUT_BLOCKS;
        let eid = escrow_id(EscrowKind::Burn, asset, value, &lock, timeout, &refund, &refund);
        let mut escrows = std::collections::HashMap::new();
        escrows.insert(eid, (asset, value, lock, timeout, "open"));
        let mut btc_keys = std::collections::HashMap::new();
        btc_keys.insert(eid, k_user.to_vec());
        let zc = SwapFakeZc {
            blocks: vec![vec![], vec![raw_burn_lock_btc(&k_user, value, asset, &lock, timeout, &refund)]], // planned at tip 2 = T+1
            escrows,
            btc_keys,
            parties: Default::default(),
            base_time: MOCK_BTC_TIP * 600,
        };
        let btc = MockBtc { existing: vec![], broadcasts: std::cell::Cell::new(0), tip: MOCK_BTC_TIP };
        let margin = default_finalize_margin(Network::Bitcoin);
        let report = plan_redeems(&zc, &btc, &reserve, 1, 2, asset, margin, &std::collections::HashSet::new()).unwrap();
        assert!(report.rejected.is_empty(), "honest burn rejected: {:?}", report.rejected);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.plans.len(), 1, "the honest wallet redeem is planned at the default margin");
        let plan = &report.plans[0];
        assert_eq!(plan.zc_timeout, timeout);
        let lock_blocks = plan.btc_locktime as u64 - MOCK_BTC_TIP;
        assert!(lock_blocks >= min_user_claim_blocks(Network::Bitcoin), "lock {lock_blocks}");
        assert!(ZC_REDEEM_TIMEOUT_BLOCKS > margin, "the wallet's burn window must exceed the daemon's margin");
    }

    /// Audit 2026-10 H5: the BTC lock is a function of consensus data (the burn's ZC block
    /// time mapped through Bitcoin's median-time-past), so a replan hours later, after the
    /// state file is gone and Bitcoin has moved on, reproduces the IDENTICAL script and the
    /// funding-reuse check can see the earlier funding.
    #[test]
    fn redeem_lock_is_deterministic_across_a_replan() {
        use zcrypt_core::htlc_shield::{escrow_id, EscrowKind};
        let reserve = Key::from_bytes(&[9u8; 32]);
        let k_user = Key::from_bytes(&[1u8; 32]).pk.inner.serialize();
        let refund: PubKey = [7; 8];
        let lock = htlc_hashlock(&[3u8; 32]);
        let (asset, value) = (5u64, 200_000u64);
        let timeout = 1 + zc_redeem_timeout_blocks(Network::Bitcoin);
        let eid = escrow_id(EscrowKind::Burn, asset, value, &lock, timeout, &refund, &refund);
        let mut escrows = std::collections::HashMap::new();
        escrows.insert(eid, (asset, value, lock, timeout, "open"));
        let mut btc_keys = std::collections::HashMap::new();
        btc_keys.insert(eid, k_user.to_vec());
        let mut zc = SwapFakeZc {
            blocks: vec![vec![raw_burn_lock_btc(&k_user, value, asset, &lock, timeout, &refund)]],
            escrows,
            btc_keys,
            parties: Default::default(),
            base_time: MOCK_BTC_TIP * 600,
        };
        let btc = MockBtc { existing: vec![], broadcasts: std::cell::Cell::new(0), tip: MOCK_BTC_TIP };
        let skip = std::collections::HashSet::new();
        let first = plan_redeems(&zc, &btc, &reserve, 1, 1, asset, 0, &skip).unwrap();
        assert_eq!(first.plans.len(), 1, "{:?} {:?}", first.rejected, first.errors);
        // The anchor sits REDEEM_ANCHOR_LAG_SECS behind the burn: strictly below the tip.
        let anchor = btc_anchor_height(&btc, MOCK_BTC_TIP, zc.base_time + 1).unwrap();
        assert!(anchor < MOCK_BTC_TIP && anchor >= MOCK_BTC_TIP - REDEEM_ANCHOR_LAG_SECS / 600 - 11, "anchor {anchor}");
        let lt = first.plans[0].btc_locktime as u64;
        assert!(lt > anchor && lt - anchor <= btc_redeem_lock_blocks(Network::Bitcoin), "lock {lt} anchored at {anchor}");

        // Hours later: 40 more ZC blocks (empty) and a Bitcoin tip 40 blocks higher.
        for _ in 0..40 {
            zc.blocks.push(vec![]);
        }
        let later = MockBtcAt { tip: MOCK_BTC_TIP + 40 };
        let again = plan_redeems(&zc, &later, &reserve, 1, 1, asset, 0, &skip).unwrap();
        assert_eq!(again.plans.len(), 1, "{:?} {:?}", again.rejected, again.errors);
        assert_eq!(again.plans[0].script, first.plans[0].script, "identical script after the replan");
        assert_eq!(again.plans[0].btc_locktime, first.plans[0].btc_locktime);
        // ...so the funding made the first time is REUSED, never duplicated.
        let zc_tip = zc.height().unwrap() as u64;
        let funded = MockBtc {
            existing: vec![HtlcUtxo { outpoint: OutPoint::null(), value: Amount::from_sat(value), script: first.plans[0].script.clone() }],
            broadcasts: std::cell::Cell::new(0),
            tip: MOCK_BTC_TIP,
        };
        let (_u, reused) = fund_redeem_plan(&funded, &again.plans[0], zc_tip).unwrap();
        assert!(reused);
        assert_eq!(funded.broadcasts.get(), 0);

        // A very late Bitcoin tip still PRODUCES the same plan and script, so an existing
        // funding is found. Refusing a new funding whose claim window has closed is
        // fund_redeem_plan's job, and only when nothing is funded yet.
        let late_tip = first.plans[0].btc_locktime as u64 - min_user_claim_blocks(Network::Bitcoin) + 1;
        let very_late = MockBtcAt { tip: late_tip };
        let late = plan_redeems(&zc, &very_late, &reserve, 1, 1, asset, 0, &skip).unwrap();
        assert_eq!(late.plans.len(), 1, "{:?} {:?}", late.rejected, late.errors);
        assert_eq!(late.plans[0].script, first.plans[0].script, "identical script after a late replan");
        assert_eq!(late.plans[0].btc_locktime, first.plans[0].btc_locktime);
        let funded_late = MockBtc {
            existing: vec![HtlcUtxo { outpoint: OutPoint::null(), value: Amount::from_sat(value), script: first.plans[0].script.clone() }],
            broadcasts: std::cell::Cell::new(0),
            tip: late_tip,
        };
        let (_u, reused) = fund_redeem_plan(&funded_late, &late.plans[0], zc_tip).unwrap();
        assert!(reused, "an existing funding is reused after the claim window has closed");
        assert_eq!(funded_late.broadcasts.get(), 0);
        let fresh_late = MockBtc { existing: vec![], broadcasts: std::cell::Cell::new(0), tip: late_tip };
        let err = fund_redeem_plan(&fresh_late, &late.plans[0], zc_tip).unwrap_err();
        assert!(err.contains("minimum claim window"), "{err}");
        assert_eq!(fresh_late.broadcasts.get(), 0, "a closed window never broadcasts a new funding");
    }

    /// The anchor search is monotone in time and stable once the target sits below the tip.
    #[test]
    fn btc_anchor_is_monotone_and_stable_under_tip_growth() {
        let btc = MockBtc { existing: vec![], broadcasts: std::cell::Cell::new(0), tip: MOCK_BTC_TIP };
        let t = MOCK_BTC_TIP * 600;
        let a = btc_anchor_height(&btc, MOCK_BTC_TIP, t).unwrap();
        let b = btc_anchor_height(&btc, MOCK_BTC_TIP, t + 600).unwrap();
        assert!(b >= a);
        for extra in [1u64, 10, 100, 1000] {
            assert_eq!(btc_anchor_height(&MockBtcAt { tip: MOCK_BTC_TIP + extra }, MOCK_BTC_TIP + extra, t).unwrap(), a, "tip +{extra}");
        }
        // Far in the past: floored at the lookback window, never an error.
        assert_eq!(btc_anchor_height(&btc, MOCK_BTC_TIP, 0).unwrap(), MOCK_BTC_TIP - REDEEM_ANCHOR_LOOKBACK_BLOCKS);
    }

    const MOCK_BTC_TIP: u64 = 800_000;

    /// `MockBtc` at another tip (same synthetic header chain).
    struct MockBtcAt {
        tip: u64,
    }
    impl crate::BtcBackend for MockBtcAt {
        fn fund_htlc(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
            Ok(HtlcUtxo { outpoint: OutPoint::null(), value: amount, script: script.clone() })
        }
        fn htlc_utxos(&self, _: &ScriptBuf) -> Result<Vec<HtlcUtxo>, String> {
            Ok(vec![])
        }
        fn claim(&self, _: &HtlcUtxo, _: &[u8], _: &Key, _: &Address, _: Amount) -> Result<bitcoin::Txid, String> {
            Err("mock".into())
        }
        fn height(&self) -> Result<u64, String> {
            Ok(self.tip)
        }
        fn network(&self) -> Network {
            Network::Bitcoin
        }
        fn preimage_from_claim(&self, _: &bitcoin::Txid) -> Option<Vec<u8>> {
            None
        }
        fn confirm(&self, _: &bitcoin::Txid) -> Result<(), String> {
            Ok(())
        }
        fn fee_rate_sat_vb(&self, _: u32) -> Result<f64, String> {
            Ok(1.0)
        }
        fn find_htlc_spend(&self, _: &HtlcUtxo, _: u64) -> Result<crate::HtlcSpend, String> {
            Ok(crate::HtlcSpend::Unspent)
        }
        fn block_header(&self, h: u64) -> Result<[u8; 80], String> {
            Ok(synthetic_header((h * 600) as u32))
        }
        fn raw_tx(&self, _: &bitcoin::Txid) -> Result<Vec<u8>, String> {
            Err("mock".into())
        }
        fn txout_proof(&self, _: &bitcoin::Txid) -> Result<Vec<u8>, String> {
            Err("mock".into())
        }
    }

    /// Bridge M14: the operator lock is sized for half-speed Bitcoin. A 60% slowdown over the
    /// lock's life must still leave the ZC escrow alive when the CLTV passes.
    #[test]
    fn redeem_lock_survives_a_sixty_percent_bitcoin_slowdown() {
        for net in [Network::Bitcoin, Network::Signet] {
            let (btc_tip, zc_tip) = (800_000u64, 5_000u64);
            let honest = zc_tip + zc_redeem_timeout_blocks(net);
            let lt = redeem_btc_locktime_for(net, btc_tip, zc_tip, honest).expect("funds");
            let lock_blocks = lt as u64 - btc_tip;
            // Bitcoin at 16 min/block for the whole lock: wall time until the CLTV passes.
            let slow_secs = lock_blocks * (BTC_BLOCK_TIME_SECS * 16 / 10);
            let escrow_secs = (honest - zc_tip) * ZC_BLOCK_TIME_SECS;
            assert!(
                slow_secs + redeem_finalize_sla_secs(net) <= escrow_secs,
                "{net:?}: lock {lock_blocks} blocks at 60% slowdown ({slow_secs}s) must end before the escrow ({escrow_secs}s)"
            );
        }
    }

    #[test]
    fn swap_lock_payload_round_trips() {
        let claimant: PubKey = [1; 8];
        let locker: PubKey = [2; 8];
        let lock = [3u8; 32];
        let raw = raw_swap_lock(42, 7, &lock, 999, &claimant, &locker);
        let (v, _b, a, l, t, c, r) = parse_swap_lock(&raw[1..]).unwrap();
        assert_eq!((v, a, l, t, c, r), (42, 7, lock, 999, claimant, locker));
        assert!(parse_swap_lock(&raw[1..100]).is_none());
    }

    /// The 0x67 parser must agree with the real builder (not just the test fixture): a stale
    /// blind width here silently makes the redeem watcher skip every burn.
    #[test]
    fn burn_lock_btc_payload_round_trips_through_the_real_builder() {
        let btc_pk = Key::from_bytes(&[5u8; 32]).pk;
        let refund: PubKey = [4; 8];
        let lock = [6u8; 32];
        let blind: Blind = std::array::from_fn(|i| i as u64 + 1);
        let stx = shield_tx::ShieldTx {
            inputs: vec![],
            output_commitments: vec![],
            enc_notes: vec![],
            fee: 0,
            root: [0u64; 8],
            proof: vec![],
        };
        let raw = burn_lock_btc_tx(&btc_pk, 42, &blind, 7, &lock, 999, &refund, &stx, &dummy_opening());
        let (pk, a, v, l, t, r) = parse_burn_lock_btc(&raw[1..]).expect("parses");
        assert_eq!(pk, btc_pk.inner.serialize());
        assert_eq!((a, v, l, t, r), (7, 42, lock, 999, refund));
        assert!(parse_burn_lock_btc(&raw[1..100]).is_none());
    }

    #[test]
    fn swap_timeouts_expire_the_revealed_leg_first() {
        // The maker's lock (claimed by the taker, revealing the preimage) expires at base + T;
        // the taker's lock (claimed by the maker afterwards) expires a full margin later.
        let (give, take) = swap_timeouts(1_000, 500);
        assert_eq!(take, 1_500);
        assert!(give >= take + SWAP_MAKER_CLAIM_MARGIN_BLOCKS);
        assert!(maker_lock_is_safe(give, take));
        // The reverse ordering (the bug) is exactly what the maker check refuses.
        assert!(!maker_lock_is_safe(take, give));
        assert!(!maker_lock_is_safe(give, give));
        // A tiny quote timeout still leaves the maker the full margin.
        let (give, take) = swap_timeouts(1_000, 1);
        assert_eq!(take, 1_001);
        assert_eq!(give, 1_001 + SWAP_MAKER_CLAIM_MARGIN_BLOCKS);
    }

    #[test]
    fn bond_signature_matches_the_wallet_layout() {
        use ed25519_dalek::Verifier;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]);
        let reward = [0x33u8; 32];
        let (stake, commission, nonce) = (10_000u64 * 100_000_000, 1_000u16, 7u64);
        let sig = sign_bond(&sk, b"zcrypt-1", stake, &reward, commission, nonce);
        // Rebuild the message independently, field by field, exactly as the wallet does.
        let mut msg = Vec::new();
        msg.extend_from_slice(b"ZCRYPT-BOND-v1");
        msg.extend_from_slice(b"zcrypt-1");
        msg.extend_from_slice(&sk.verifying_key().to_bytes());
        msg.extend_from_slice(&stake.to_le_bytes());
        msg.extend_from_slice(&reward);
        msg.extend_from_slice(&commission.to_le_bytes());
        msg.extend_from_slice(&nonce.to_le_bytes());
        assert_eq!(msg.len(), 14 + 8 + 32 + 8 + 32 + 2 + 8);
        sk.verifying_key()
            .verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("host signature verifies against the wallet's layout");
        // Any field change (here: the nonce) breaks it.
        let mut wrong = msg.clone();
        let n = wrong.len();
        wrong[n - 1] ^= 1;
        assert!(sk.verifying_key().verify(&wrong, &ed25519_dalek::Signature::from_bytes(&sig)).is_err());
    }

    #[test]
    fn default_finalize_margin_matches_compose_and_floor() {
        // chain/docker-compose.yml ships WATCHER_FINALIZE_MARGIN=475200 for mainnet.
        assert_eq!(default_finalize_margin(Network::Bitcoin), 475_200);
        for net in [Network::Bitcoin, Network::Signet, Network::Regtest] {
            assert!(default_finalize_margin(net) >= min_redeem_margin_blocks(net), "{net:?}");
        }
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
