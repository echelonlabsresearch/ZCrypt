//! The bridge operator's WATCHER — the always-on service that settles the public bridge
//! autonomously. One [`watcher_tick`] does a full pass over new ZCrypt blocks:
//!
//!   1. relay any missing Bitcoin headers (keeps the SPV chain current),
//!   2. SHIELD: sweep each deposit whose preimage was revealed into the reserve,
//!   3. REDEEM (lock): for each on-chain `0x67` redeem, lock reserve BTC 1:1 to the user's
//!      on-chain key,
//!   4. REDEEM (finalize): detect the user's BTC claim of a locked HTLC and burn the zBTC.
//!
//! All of it is idempotent and resumable via [`WatcherState`], which persists a scan cursor,
//! the swept/funded escrow sets, and the redeems awaiting the user's BTC claim. A crash and
//! restart re-loads the state and continues without double-spending or missing a settlement.
//! Every step is non-fatal per item, so one bad escrow never stalls the rest.

use std::collections::HashSet;

use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Txid};
use std::str::FromStr;

use crate::swap;
use crate::zcrypt::Zcrypt;
use crate::{BtcBackend, HtlcUtxo, Key};

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

/// A redeem the operator has locked BTC for, awaiting the user's BTC claim so it can finalize
/// (burn) the zBTC. Stored in a JSON-serializable shape so the daemon survives restarts.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingRedeem {
    pub escrow_id: String,   // hex
    pub funding_txid: String,
    pub vout: u32,
    pub value_sat: u64,
    pub script_hex: String,
    pub hashlock: String, // hex
    pub funded_at_btc: u64,
}

impl PendingRedeem {
    fn from_lock(l: &swap::RedeemLock, funded_at_btc: u64) -> Self {
        PendingRedeem {
            escrow_id: hex::encode(l.escrow_id),
            funding_txid: l.utxo.outpoint.txid.to_string(),
            vout: l.utxo.outpoint.vout,
            value_sat: l.utxo.value.to_sat(),
            script_hex: hex::encode(l.utxo.script.as_bytes()),
            hashlock: hex::encode(l.hashlock),
            funded_at_btc,
        }
    }
    fn utxo(&self) -> Result<HtlcUtxo, String> {
        Ok(HtlcUtxo {
            outpoint: OutPoint {
                txid: Txid::from_str(&self.funding_txid).map_err(|e| e.to_string())?,
                vout: self.vout,
            },
            value: Amount::from_sat(self.value_sat),
            script: ScriptBuf::from_bytes(hex::decode(&self.script_hex).map_err(|e| e.to_string())?),
        })
    }
}

/// The watcher's durable state. Persist between ticks and across restarts.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct WatcherState {
    /// Highest ZCrypt height fully scanned. The next tick resumes from here.
    pub cursor: i64,
    /// Hex escrow ids already swept (shield) — idempotency.
    pub swept: Vec<String>,
    /// Hex escrow ids already funded (redeem) — idempotency.
    pub funded: Vec<String>,
    /// Redeems locked and awaiting the user's BTC claim.
    pub pending: Vec<PendingRedeem>,
}

impl WatcherState {
    pub fn load(path: &std::path::Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string()) // atomic replace
    }
    fn set(&self, which: &[String]) -> HashSet<[u8; 32]> {
        which.iter().filter_map(|s| hex32(s)).collect()
    }
}

/// Outcome of one watcher pass (for logging / alerting).
#[derive(Default, Debug)]
pub struct TickReport {
    pub swept: usize,
    pub locked: usize,
    pub finalized: usize,
    /// Shield deposits whose refund locktime is within soft alert (~1 day) — PAGE.
    pub at_risk: usize,
    /// Shield deposits within hard deadline (~12h of refund) — emergency.
    pub critical: usize,
    /// True when new user shields should be refused (critical race risk or failed near-CLTV sweep).
    pub pause_new_shields: bool,
    /// Redeems the operator refused after validation (safe; bad asset/value/timeout).
    pub rejected: usize,
    /// Non-fatal per-item errors (transient RPC, insufficient reserve, etc.) — retried next tick.
    pub errors: Vec<String>,
}

/// Run ONE full watcher pass. Mutates `state` in place; the caller persists it after.
#[allow(clippy::too_many_arguments)]
pub fn watcher_tick(
    state: &mut WatcherState,
    zc: &Zcrypt,
    operator_btc: &dyn BtcBackend,
    reserve: &Key,
    shield_dest: &Address,
    zbtc_asset: u64,
    min_finalize_margin: u64,
    fee_target: u32,
) -> Result<TickReport, String> {
    // 1. Keep the consensus SPV chain current (non-fatal — a user's own shield relays too).
    let _ = swap::relay_btc_headers(zc, operator_btc);

    let tip = zc.height()?;
    // Block heights are 1-indexed (height 0 is the CometBFT genesis, which has no queryable
    // block — `/block?height=0` 500s). A fresh operator has cursor 0, so start the scan at 1;
    // otherwise the block-scan pass errors before it ever reaches a real deposit.
    let from = state.cursor.max(1);
    let mut report = TickReport::default();
    // Do not advance the cursor if a block-scan pass fails: empty/error blocks would
    // permanently skip settlements for those heights.
    let mut scan_ok = true;

    // 2. SHIELD sweep.
    let mut swept = state.set(&state.swept);
    match swap::reserve_claim_revealed(zc, operator_btc, reserve, shield_dest, from, tip, fee_target, &mut swept) {
        Ok(sr) => {
            report.swept = sr.swept.len();
            report.at_risk = sr.at_risk.len();
            report.critical = sr.critical.len();
            report.pause_new_shields = sr.pause_new_shields;
            for (eid, e) in sr.errors {
                report.errors.push(format!("shield {}: {e}", hex::encode(eid)));
            }
        }
        Err(e) => {
            scan_ok = false;
            report.errors.push(format!("shield pass: {e}"));
        }
    }
    state.swept = swept.iter().map(hex::encode).collect();

    // 3. REDEEM: lock reserve BTC for each valid on-chain redeem.
    let mut funded = state.set(&state.funded);
    match swap::reserve_serve_redeems(zc, operator_btc, reserve, from, tip, zbtc_asset, min_finalize_margin, &mut funded) {
        Ok(rr) => {
            report.locked = rr.locked.len();
            report.rejected = rr.rejected.len();
            let now_btc = operator_btc.height().unwrap_or(0);
            for l in &rr.locked {
                state.pending.push(PendingRedeem::from_lock(l, now_btc));
            }
            for (eid, e) in rr.errors {
                report.errors.push(format!("redeem-serve {}: {e}", hex::encode(eid)));
            }
        }
        Err(e) => {
            scan_ok = false;
            report.errors.push(format!("redeem-serve pass: {e}"));
        }
    }
    state.funded = funded.iter().map(hex::encode).collect();

    // 4. REDEEM finalize: detect each user's BTC claim and burn the zBTC.
    let mut still_pending = Vec::new();
    for p in std::mem::take(&mut state.pending) {
        let utxo = match p.utxo() {
            Ok(u) => u,
            Err(e) => {
                // Keep corrupt entries for operator inspection — never silently drop
                // a funded redeem (would leave zBTC unfinalized / peg broken).
                report.errors.push(format!("finalize decode {} (quarantined): {e}", p.escrow_id));
                still_pending.push(p);
                continue;
            }
        };
        match operator_btc.find_htlc_spend_preimage(&utxo, p.funded_at_btc) {
            Ok(Some(preimage)) => {
                // Empty preimage = refund branch, not a claim.
                if preimage.is_empty() {
                    still_pending.push(p);
                    continue;
                }
                let (Some(eid), Some(hl)) = (hex32(&p.escrow_id), hex32(&p.hashlock)) else {
                    report.errors.push(format!("finalize bad ids {} (quarantined)", p.escrow_id));
                    still_pending.push(p);
                    continue;
                };
                if zcrypt_core::nullifier::htlc_hashlock(&preimage) != hl {
                    // Not a valid claim for this escrow (refund or garbage).
                    still_pending.push(p);
                    continue;
                }
                match swap::reserve_finalize_with_preimage(zc, &eid, &preimage, &hl) {
                    Ok(()) => report.finalized += 1,
                    Err(e) => {
                        report.errors.push(format!("finalize {}: {e}", p.escrow_id));
                        still_pending.push(p); // retry next tick
                    }
                }
            }
            Ok(None) => still_pending.push(p), // user hasn't claimed yet
            Err(e) => {
                report.errors.push(format!("finalize-scan {}: {e}", p.escrow_id));
                still_pending.push(p);
            }
        }
    }
    state.pending = still_pending;

    // 5. Advance the cursor only after successful block scans.
    if scan_ok {
        state.cursor = tip;
    }
    Ok(report)
}
