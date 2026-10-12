//! The bridge operator's WATCHER: the always-on service that settles the public bridge
//! autonomously. One [`watcher_tick`] does a full, NON-BLOCKING pass over new ZCrypt blocks:
//!
//!   1. relay any missing Bitcoin headers (keeps the SPV chain current),
//!   2. SHIELD: index every deposit locked to the reserve, sweep each one whose preimage was
//!      revealed into the reserve (deferring, and REMEMBERING, the ones not yet buried past
//!      maturity), and RE-ANCHOR any tracked deposit a Bitcoin reorg re-mined elsewhere,
//!   3. REDEEM (lock): for each on-chain `0x67` redeem, lock reserve BTC 1:1 to the user's
//!      on-chain key, persisting a funding INTENT before the broadcast and polling its
//!      confirmations across ticks,
//!   4. REDEEM (finalize): detect the user's BTC claim of a locked HTLC and burn the zBTC,
//!      or REFUND a lock the user never claimed once its CLTV has passed (and keep watching
//!      until the refund confirms, finalizing instead if the user's claim wins the race).
//!
//! Nothing in a tick waits for a Bitcoin confirmation (bridge N7): every wait is a persisted
//! state machine advanced by later ticks, so header relay, re-anchoring, finalizing and
//! refunding keep running while fundings and sweeps confirm.
//!
//! All of it is idempotent and resumable via [`WatcherState`], which persists a scan cursor,
//! the swept/funded/rejected escrow sets, in-flight funding intents, tracked deposits,
//! deferred sweeps, sweeps awaiting confirmation, and the redeems awaiting the user's BTC
//! claim. A crash and restart re-loads the state and continues without double-funding or
//! missing a settlement. Every step is non-fatal per item, so one bad escrow never stalls
//! the rest.

use std::collections::{BTreeMap, HashMap, HashSet};

use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Txid};
use std::str::FromStr;

use crate::swap::{self, DeferredSweep, RefundProximity, SweepOutcome, TrackedDeposit};
use crate::zcrypt::ZcNode;
use crate::{BtcBackend, HtlcSpend, HtlcUtxo, Key};

/// How many recent Bitcoin blocks the finalize scan re-covers each tick for a lock whose
/// spend is reported but not yet confirmed (reorg safety without a full-history rescan).
const REORG_WINDOW_BLOCKS: u64 = 12;

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

/// A redeem the operator has locked BTC for, awaiting the user's BTC claim so it can finalize
/// (burn) the zBTC. Stored in a JSON-serializable shape so the daemon survives restarts.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PendingRedeem {
    pub escrow_id: String,   // hex
    pub funding_txid: String,
    pub vout: u32,
    pub value_sat: u64,
    pub script_hex: String,
    pub hashlock: String, // hex
    /// Legacy field (older daemons): the Bitcoin tip when the funding reached its
    /// confirmation target. Kept only so old state files still load.
    #[serde(default)]
    pub funded_at_btc: u64,
    /// The lowest Bitcoin height the funding tx can be in (recorded when it was broadcast or
    /// discovered). Spend scans start HERE, never at the height the funding confirmed at, so
    /// a user who claims in the very next block is always seen (bridge N3).
    #[serde(default)]
    pub funding_height: u64,
    /// Bitcoin height through which the HTLC output is known to be UNSPENT; the next spend
    /// scan resumes from here instead of re-reading every block since funding (bridge N8).
    #[serde(default)]
    pub scanned_to: u64,
    /// The BTC HTLC refund CLTV. Once the Bitcoin tip passes it and the user still has not
    /// claimed, the watcher takes the BTC back to the reserve (bridge M5). `0` on entries
    /// written by older daemons: those are never auto-refunded.
    #[serde(default)]
    pub locktime: u32,
    /// The refund tx the watcher broadcast after CLTV, if any. The entry stays pending until
    /// that refund CONFIRMS; if the user's claim is mined first, the watcher finalizes with
    /// the revealed preimage instead of forgetting the escrow (bridge N4).
    #[serde(default)]
    pub refund_txid: Option<String>,
    /// Bitcoin tip when the refund was broadcast.
    #[serde(default)]
    pub refund_at_btc: u64,
    /// Set once a full rescan from the funding height has been done for a "spent but spender
    /// not found" report; a second such report never rescans from funding again (bridge M15).
    #[serde(default)]
    pub rescanned_from_funding: bool,
    /// The claim preimage once seen on Bitcoin. Kept so a failed finalize retries from here
    /// without rescanning blocks.
    #[serde(default)]
    pub claim_preimage_hex: Option<String>,
}

impl PendingRedeem {
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
    /// Where a spend scan must start: the funding height (old files: the legacy field).
    fn scan_floor(&self) -> u64 {
        if self.funding_height > 0 {
            self.funding_height
        } else {
            self.funded_at_btc
        }
    }
}

/// A redeem the watcher has DECIDED to fund. Written to the state file BEFORE the funding
/// tx is broadcast and updated with the txid the moment the broadcast succeeds, so a crash
/// or a transient RPC error at any point resumes from the recorded txid (or from the HTLC
/// address, mempool included) instead of funding the escrow again (bridge H2 / N5).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FundingIntent {
    pub escrow_id: String, // hex
    pub hashlock: String,  // hex
    pub script_hex: String,
    pub value_sat: u64,
    pub locktime: u32,
    /// Set once a funding tx has been broadcast or discovered (`txid:vout`).
    #[serde(default)]
    pub funding: Option<(String, u32)>,
    /// The ACTUAL value of the funding output (a reused output may carry more than the plan;
    /// the BIP-143 sighash must use the real amount, bridge N13).
    #[serde(default)]
    pub funding_value_sat: Option<u64>,
    /// The lowest Bitcoin height the funding tx can be in.
    #[serde(default)]
    pub funding_height: Option<u64>,
}

impl FundingIntent {
    fn script(&self) -> Result<ScriptBuf, String> {
        Ok(ScriptBuf::from_bytes(hex::decode(&self.script_hex).map_err(|e| e.to_string())?))
    }
}

/// A reserve sweep (HTLC claim) broadcast on a REAL network, tracked until it has one
/// confirmation. If it vanishes from the mempool while the HTLC is still unspent, the
/// watcher re-sweeps at the aggressive fee target (the claim is RBF-enabled).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SweepTx {
    pub deposit: TrackedDeposit,
    pub preimage_hex: String,
    pub txid: String,
    pub broadcast_at_btc: u64,
}

/// The watcher's durable state. Persist between ticks and across restarts.
#[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
pub struct WatcherState {
    /// Highest ZCrypt height fully scanned. The next tick resumes from here.
    pub cursor: i64,
    /// Hex escrow ids already swept (shield): idempotency.
    pub swept: Vec<String>,
    /// Hex escrow ids already funded (redeem): idempotency.
    pub funded: Vec<String>,
    /// Redeems locked and awaiting the user's BTC claim.
    pub pending: Vec<PendingRedeem>,
    /// Redeems decided but not yet confirmed on Bitcoin (see [`FundingIntent`]).
    #[serde(default)]
    pub funding: Vec<FundingIntent>,
    /// Shield deposits watched for reorgs until buried past any void risk (bridge M2), and
    /// the index later claims are matched against (bridge N2).
    #[serde(default)]
    pub tracked: Vec<TrackedDeposit>,
    /// Hex escrow ids permanently refused (bad asset / value / hashlock / timeout). Never
    /// re-evaluated, so a dust or hostile burn-lock costs the operator one look, not one
    /// look per tick (bridge M5).
    #[serde(default)]
    pub rejected: Vec<String>,
    /// Hex escrow ids whose operator-funded HTLC was refunded after CLTV (never claimed).
    #[serde(default)]
    pub refunded: Vec<String>,
    /// Escrows with a transient funding failure: ZC height before which they are not retried.
    #[serde(default)]
    pub retry_after: BTreeMap<String, i64>,
    /// Claims whose sweep is waiting for the deposit to bury past maturity (bridge N1).
    #[serde(default)]
    pub deferred: Vec<DeferredSweep>,
    /// Sweeps broadcast on a real network and not yet confirmed (bridge N7).
    #[serde(default)]
    pub sweeps: Vec<SweepTx>,
}

/// ZC blocks to wait before retrying a redeem whose funding hit a transient error. MORE than
/// one Bitcoin block (1 s ZC blocks, 600 s Bitcoin blocks), so a broadcast whose read-back
/// failed has propagated and is visible to the mempool-aware reuse check before the daemon
/// considers funding again (bridge N5).
pub const RETRY_BACKOFF_BLOCKS: i64 = 900;

/// Bitcoin blocks a broadcast sweep may sit unconfirmed before the watcher checks whether
/// it was dropped (HTLC still unspent) and re-sweeps with an aggressive fee.
pub const SWEEP_RESWEEP_AFTER_BLOCKS: u64 = 3;

impl WatcherState {
    /// Load the state file. A MISSING file is a fresh daemon (default state); a file that is
    /// present but unreadable or unparseable is a HARD error (bridge N12): silently starting
    /// from an empty state would forget every unfinalized redeem and funding intent.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| {
                format!(
                    "watcher state file {} exists but does not parse ({e}); refusing to start from an empty \
                     state. Restore it from backup or move it aside deliberately.",
                    path.display()
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("watcher state file {}: {e}", path.display())),
        }
    }
    /// Atomically replace the state file: write a temp file, fsync it, rename over the target.
    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        use std::io::Write as _;
        let tmp = path.with_extension("tmp");
        let body = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
            f.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?; // durable before the rename
        }
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?; // atomic replace
        if let Some(dir) = path.parent() {
            if let Ok(d) = std::fs::File::open(if dir.as_os_str().is_empty() { std::path::Path::new(".") } else { dir }) {
                let _ = d.sync_all(); // the directory entry too (best effort)
            }
        }
        Ok(())
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
    /// Operator-funded redeem HTLCs refunded after their CLTV (user never claimed).
    pub refunded: usize,
    /// Tracked shield deposits re-anchored after a Bitcoin reorg.
    pub reanchored: usize,
    /// Funding intents resumed from a previous crash/timeout (reused an existing funding).
    pub resumed: usize,
    /// Claims whose sweep is deferred (deposit not yet buried): retried every tick.
    pub deferred: usize,
    /// Shield deposits whose refund locktime is within soft alert (~1 day): PAGE.
    pub at_risk: usize,
    /// Shield deposits within hard deadline (~12h of refund): emergency.
    pub critical: usize,
    /// True when new user shields should be refused (critical race risk or failed near-CLTV sweep).
    pub pause_new_shields: bool,
    /// Redeems the operator refused after validation (safe; bad asset/value/timeout).
    pub rejected: usize,
    /// Non-fatal per-item errors (transient RPC, insufficient reserve, etc.): retried next tick.
    pub errors: Vec<String>,
}

/// Run ONE full watcher pass without intermediate persistence (one-shot callers and tests).
/// The daemon uses [`watcher_tick_persisting`] so funding intents hit disk before broadcast.
#[allow(clippy::too_many_arguments)]
pub fn watcher_tick(
    state: &mut WatcherState,
    zc: &dyn ZcNode,
    operator_btc: &dyn BtcBackend,
    reserve: &swap::ReserveKeys<'_>,
    shield_dest: &Address,
    zbtc_asset: u64,
    min_finalize_margin: u64,
    fee_target: u32,
) -> Result<TickReport, String> {
    watcher_tick_persisting(state, zc, operator_btc, reserve, shield_dest, zbtc_asset, min_finalize_margin, fee_target, &|_| Ok(()))
}

/// Confirmations a redeem funding needs before the operator treats it as locked.
fn funding_confs_needed(operator_btc: &dyn BtcBackend) -> u64 {
    match operator_btc.network() {
        bitcoin::Network::Regtest => 0,
        bitcoin::Network::Bitcoin => zcrypt_core::spv::min_conf_for(zcrypt_core::spv::BtcNet::Mainnet),
        _ => 1,
    }
}

enum IntentStep {
    /// A funding was broadcast or discovered this call (txid now recorded on the intent).
    Recorded,
    /// The recorded funding is still short of its confirmation target.
    Waiting,
    /// Confirmed: the redeem is now pending the user's claim.
    Confirmed(PendingRedeem),
}

/// Advance one funding intent WITHOUT blocking: fund (or reuse an existing funding) if no
/// txid is recorded yet, then poll confirmations. `Err` means nothing could be recorded this
/// call; the caller keeps the intent and backs off, never releasing the escrow's funding slot
/// (a broadcast whose read-back failed is rediscovered by the mempool-aware reuse check).
/// Insert-or-replace a deferred sweep by escrow id (no duplicates across ticks).
fn defer_sweep(deferred: &mut Vec<DeferredSweep>, d: DeferredSweep) {
    deferred.retain(|x| x.deposit.escrow_id != d.deposit.escrow_id);
    deferred.push(d);
}

fn drive_intent(
    intent: &mut FundingIntent,
    operator_btc: &dyn BtcBackend,
    report: &mut TickReport,
) -> Result<IntentStep, String> {
    let script = intent.script()?;
    // A failed height read must NOT be treated as tip 0: `btc_tip + 1 - confs` would wrap and
    // put the scan floor out of reach forever (bridge M13). Err keeps the intent for retry.
    let btc_tip = operator_btc.height().map_err(|e| format!("btc height: {e}"))?;
    let mut just_recorded = false;
    if intent.funding.is_none() {
        let (utxo, reused) = swap::fund_redeem_plan(
            operator_btc,
            &swap::RedeemPlan {
                escrow_id: hex32(&intent.escrow_id).ok_or("intent: bad escrow id")?,
                hashlock: hex32(&intent.hashlock).ok_or("intent: bad hashlock")?,
                value: intent.value_sat,
                script: script.clone(),
                btc_locktime: intent.locktime,
            },
        )?;
        if reused {
            report.resumed += 1;
        }
        let confs = operator_btc.tx_confirmations(&utxo.outpoint.txid).unwrap_or(0);
        intent.funding = Some((utxo.outpoint.txid.to_string(), utxo.outpoint.vout));
        intent.funding_value_sat = Some(utxo.value.to_sat());
        // Lowest block the funding can be in: already mined `confs` deep, or the next block.
        intent.funding_height = Some(if confs > 0 {
            btc_tip.saturating_add(1).saturating_sub(confs)
        } else {
            btc_tip.saturating_add(1)
        });
        just_recorded = true;
    }
    let (txid_s, vout) = intent.funding.clone().expect("recorded above");
    let txid = Txid::from_str(&txid_s).map_err(|e| e.to_string())?;
    let confs = operator_btc.tx_confirmations(&txid).unwrap_or(0);
    if confs < funding_confs_needed(operator_btc) {
        return Ok(if just_recorded { IntentStep::Recorded } else { IntentStep::Waiting });
    }
    let funding_height = intent.funding_height.unwrap_or(btc_tip);
    Ok(IntentStep::Confirmed(PendingRedeem {
        escrow_id: intent.escrow_id.clone(),
        funding_txid: txid_s,
        vout,
        value_sat: intent.funding_value_sat.unwrap_or(intent.value_sat),
        script_hex: intent.script_hex.clone(),
        hashlock: intent.hashlock.clone(),
        funded_at_btc: btc_tip,
        funding_height,
        scanned_to: funding_height.saturating_sub(1),
        locktime: intent.locktime,
        refund_txid: None,
        refund_at_btc: 0,
        rescanned_from_funding: false,
        claim_preimage_hex: None,
    }))
}

/// Run ONE full watcher pass, calling `persist` with the whole state at every point where a
/// crash must not lose information (after each funding intent is recorded, after each
/// broadcast, after each sweep). Mutates `state` in place; the caller persists it again after.
#[allow(clippy::too_many_arguments)]
pub fn watcher_tick_persisting(
    state: &mut WatcherState,
    zc: &dyn ZcNode,
    operator_btc: &dyn BtcBackend,
    reserve: &swap::ReserveKeys<'_>,
    shield_dest: &Address,
    zbtc_asset: u64,
    min_finalize_margin: u64,
    fee_target: u32,
    persist: &dyn Fn(&WatcherState) -> Result<(), String>,
) -> Result<TickReport, String> {
    // 1. Keep the consensus SPV chain current (non-fatal: a user's own shield relays too).
    let _ = swap::relay_btc_headers(zc, operator_btc);

    let tip = zc.height()?;
    // Block heights are 1-indexed (height 0 is the CometBFT genesis, which has no queryable
    // block). A fresh operator has cursor 0, so start the scan at 1.
    let from = state.cursor.max(1);
    // Every step below takes a Bitcoin action or a CLTV decision keyed on the tip; a tip of 0
    // from a failed read would silently disable refund-proximity alerts and mis-stamp
    // sweeps, so a tick with no Bitcoin tip does nothing (bridge M13).
    let btc_tip = operator_btc.height().map_err(|e| format!("btc height unavailable, skipping tick: {e}"))?;
    let regtest = operator_btc.network() == bitcoin::Network::Regtest;
    let mut report = TickReport::default();
    // Do not advance the cursor if a block-scan pass fails: empty/error blocks would
    // permanently skip settlements for those heights.
    let mut scan_ok = true;

    // 2. SHIELD: index new deposits into the persisted tracked set.
    match swap::index_reserve_deposits(zc, reserve, from, tip) {
        Ok((found, errs)) => {
            for (eid, e) in errs {
                report.errors.push(format!("shield index {}: {e}", hex::encode(eid)));
            }
            for d in found {
                match state.tracked.iter_mut().find(|t| t.escrow_id == d.escrow_id) {
                    Some(t) => {
                        if t.hashlock.is_empty() {
                            t.hashlock = d.hashlock.clone();
                        }
                        t.claimed |= d.claimed;
                    }
                    None => state.tracked.push(d),
                }
            }
        }
        Err(e) => {
            scan_ok = false;
            report.errors.push(format!("shield index pass: {e}"));
        }
    }
    // Deposits tracked by an older daemon carry no hashlock: fill it from consensus once.
    for t in state.tracked.iter_mut().filter(|t| t.hashlock.is_empty()) {
        if let Some(eid) = t.escrow_id_bytes() {
            if let Ok(Some(info)) = swap::query_escrow(zc, &eid) {
                t.hashlock = hex::encode(info.hashlock);
                t.claimed |= info.state == "claimed";
            }
        }
    }

    // 2a. Claims in the scanned range, matched against EVERY tracked deposit (bridge N2).
    let known: HashMap<[u8; 32], TrackedDeposit> =
        state.tracked.iter().filter_map(|d| d.escrow_id_bytes().map(|e| (e, d.clone()))).collect();
    let mut swept = state.set(&state.swept);
    let mut work: Vec<(TrackedDeposit, Vec<u8>, i64)> = Vec::new();
    match swap::collect_reserve_claims(zc, from, tip, &known) {
        Ok(claims) => work.extend(claims),
        Err(e) => {
            scan_ok = false;
            report.errors.push(format!("shield claim pass: {e}"));
        }
    }
    // 2b. Plus every deferred sweep from earlier ticks (bridge N1), retried regardless of cursor.
    // Deferred sweeps stay IN `state.deferred` while they are processed: if a persist fails
    // mid-loop and this function returns early, nothing is lost from memory or from the next
    // successful persist (bridge M12). Each entry is removed/replaced only once handled.
    for d in state.deferred.clone() {
        let pre = hex::decode(&d.preimage_hex).unwrap_or_default();
        work.push((d.deposit, pre, d.first_seen_zc));
    }
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for (dep, preimage, first_seen) in work {
        let Some(eid) = dep.escrow_id_bytes() else { continue };
        if !seen.insert(eid) {
            continue; // a claim can appear both in the scan and in the deferred list
        }
        if swept.contains(&eid) {
            continue;
        }
        let prox = swap::refund_proximity(dep.btc_locktime, btc_tip);
        match prox {
            RefundProximity::Critical => {
                report.critical += 1;
                report.pause_new_shields = true;
            }
            RefundProximity::AtRisk => report.at_risk += 1,
            RefundProximity::Ok => {}
        }
        match swap::sweep_deposit(zc, operator_btc, reserve, shield_dest, &dep, &preimage, fee_target, btc_tip) {
            SweepOutcome::Swept(txid) => {
                swept.insert(eid);
                state.deferred.retain(|d| d.deposit.escrow_id != dep.escrow_id);
                report.swept += 1;
                if let Some(t) = state.tracked.iter_mut().find(|t| t.escrow_id == dep.escrow_id) {
                    t.claimed = true;
                }
                if !regtest {
                    state.sweeps.push(SweepTx {
                        deposit: dep.clone(),
                        preimage_hex: hex::encode(&preimage),
                        txid: txid.to_string(),
                        broadcast_at_btc: btc_tip,
                    });
                }
                state.swept = swept.iter().map(hex::encode).collect();
                persist(state)?;
            }
            SweepOutcome::Deferred { confs, need } => {
                report.deferred += 1;
                report.errors.push(format!(
                    "shield {} deferred: deposit has {confs} of {need} confirmations",
                    hex::encode(eid)
                ));
                defer_sweep(&mut state.deferred, DeferredSweep { deposit: dep, preimage_hex: hex::encode(&preimage), first_seen_zc: first_seen });
            }
            SweepOutcome::NotClaimed(why) => {
                // Keep retrying while the escrow is open (the claim may still be settling);
                // drop once consensus says it can never be claimed.
                let still_open = matches!(swap::query_escrow(zc, &eid), Ok(Some(ref i)) if i.state == "open");
                report.errors.push(format!("shield {}: {why}", hex::encode(eid)));
                if !still_open {
                    state.deferred.retain(|d| d.deposit.escrow_id != dep.escrow_id);
                }
                if still_open {
                    defer_sweep(&mut state.deferred, DeferredSweep { deposit: dep, preimage_hex: hex::encode(&preimage), first_seen_zc: first_seen });
                }
            }
            SweepOutcome::Failed(e) => {
                if prox != RefundProximity::Ok {
                    report.pause_new_shields = true;
                }
                report.errors.push(format!("shield {}: {e}", hex::encode(eid)));
                defer_sweep(&mut state.deferred, DeferredSweep { deposit: dep, preimage_hex: hex::encode(&preimage), first_seen_zc: first_seen });
            }
        }
    }
    state.swept = swept.iter().map(hex::encode).collect();

    // 2c. Sweeps awaiting confirmation on a real network: confirm, or re-sweep if dropped.
    let mut still_sweeping = Vec::new();
    for s in std::mem::take(&mut state.sweeps) {
        let confs = Txid::from_str(&s.txid).ok().and_then(|t| operator_btc.tx_confirmations(&t).ok()).unwrap_or(0);
        if confs >= 1 {
            continue; // done
        }
        if btc_tip.saturating_sub(s.broadcast_at_btc) < SWEEP_RESWEEP_AFTER_BLOCKS {
            still_sweeping.push(s);
            continue;
        }
        // Long enough: is the HTLC still unspent (our sweep vanished)? Re-sweep aggressively.
        let unspent = s
            .deposit
            .proof()
            .zip(s.deposit.hashlock_bytes())
            .and_then(|(p, l)| swap::htlc_utxo_from_proof(&p, &l).ok())
            .and_then(|u| operator_btc.utxo_unspent(&u).ok().flatten());
        if unspent == Some(true) {
            let pre = hex::decode(&s.preimage_hex).unwrap_or_default();
            match swap::sweep_deposit(zc, operator_btc, reserve, shield_dest, &s.deposit, &pre, 1, btc_tip) {
                SweepOutcome::Swept(txid) => {
                    report.errors.push(format!("shield {}: sweep {} was dropped, re-swept as {txid}", s.deposit.escrow_id, s.txid));
                    still_sweeping.push(SweepTx { txid: txid.to_string(), broadcast_at_btc: btc_tip, ..s });
                }
                other => {
                    report.errors.push(format!("shield {}: re-sweep: {other:?}", s.deposit.escrow_id));
                    still_sweeping.push(s);
                }
            }
        } else {
            still_sweeping.push(s); // spent (by us, unconfirmed) or unknown: keep polling
        }
    }
    state.sweeps = still_sweeping;

    // 2d. RE-ANCHOR deposits a Bitcoin reorg re-mined elsewhere (bridge M2 / N11).
    if !state.tracked.is_empty() {
        let rr = swap::reanchor_reorged_deposits(zc, operator_btc, &mut state.tracked);
        report.reanchored = rr.reanchored.len();
        for (eid, e) in rr.errors {
            report.errors.push(format!("reanchor {}: {e}", hex::encode(eid)));
        }
    }
    persist(state)?;

    // 3. REDEEM: advance in-flight intents (no blocking), then plan + fund new ones.
    let mut funded = state.set(&state.funded);
    let mut done = Vec::new();
    for i in 0..state.funding.len() {
        let eid = state.funding[i].escrow_id.clone();
        if state.funding[i].funding.is_none() && state.retry_after.get(&eid).is_some_and(|&until| tip < until) {
            continue; // backing off after a transient failure; the slot stays claimed
        }
        let mut intent = state.funding[i].clone();
        match drive_intent(&mut intent, operator_btc, &mut report) {
            Ok(IntentStep::Confirmed(p)) => {
                funded.insert(hex32(&p.escrow_id).unwrap_or([0u8; 32]));
                state.pending.push(p);
                report.locked += 1;
                done.push(i);
            }
            Ok(IntentStep::Recorded) => {
                state.funding[i] = intent;
                persist(state)?; // the txid is on disk before anything else can fail
            }
            Ok(IntentStep::Waiting) => state.funding[i] = intent,
            Err(e) => {
                report.errors.push(format!("redeem-fund {eid}: {e} (kept; retry after {RETRY_BACKOFF_BLOCKS} blocks)"));
                state.funding[i] = intent;
                state.retry_after.insert(eid, tip + RETRY_BACKOFF_BLOCKS);
            }
        }
    }
    for i in done.into_iter().rev() {
        state.funding.remove(i);
    }
    state.funded = funded.iter().map(hex::encode).collect();
    persist(state)?;

    // 3b. New redeems in the scanned range.
    let mut skip = funded.clone();
    skip.extend(state.set(&state.rejected));
    skip.extend(state.funding.iter().filter_map(|i| hex32(&i.escrow_id)));
    match swap::plan_redeems(zc, operator_btc, reserve.current, from, tip, zbtc_asset, min_finalize_margin, &skip) {
        Ok(pr) => {
            report.rejected = pr.rejected.len();
            for (eid, why) in pr.rejected {
                let h = hex::encode(eid);
                report.errors.push(format!("redeem-rejected {h}: {why}"));
                if !state.rejected.contains(&h) {
                    state.rejected.push(h);
                }
            }
            for (eid, e) in pr.errors {
                report.errors.push(format!("redeem-plan {}: {e}", hex::encode(eid)));
            }
            for plan in pr.plans {
                let h = hex::encode(plan.escrow_id);
                let mut intent = FundingIntent {
                    escrow_id: h.clone(),
                    hashlock: hex::encode(plan.hashlock),
                    script_hex: hex::encode(plan.script.as_bytes()),
                    value_sat: plan.value,
                    locktime: plan.btc_locktime,
                    funding: None,
                    funding_value_sat: None,
                    funding_height: None,
                };
                // The INTENT and the funding slot are on disk before any BTC moves.
                state.funding.push(intent.clone());
                if !state.funded.contains(&h) {
                    state.funded.push(h.clone());
                }
                persist(state)?;
                let idx = state.funding.len() - 1;
                match drive_intent(&mut intent, operator_btc, &mut report) {
                    Ok(IntentStep::Confirmed(p)) => {
                        state.funding.remove(idx);
                        state.pending.push(p);
                        report.locked += 1;
                    }
                    Ok(_) => state.funding[idx] = intent,
                    Err(e) => {
                        // Funding UNKNOWN (the send may or may not have gone out): keep the intent
                        // and the slot; the next attempt, after a Bitcoin block, reuses whatever
                        // landed in the mempool instead of funding twice (bridge N5).
                        report.errors.push(format!("redeem-fund {h}: {e} (kept; retry after {RETRY_BACKOFF_BLOCKS} blocks)"));
                        state.funding[idx] = intent;
                        state.retry_after.insert(h.clone(), tip + RETRY_BACKOFF_BLOCKS);
                    }
                }
                persist(state)?;
            }
        }
        Err(e) => {
            scan_ok = false;
            report.errors.push(format!("redeem-plan pass: {e}"));
        }
    }
    state.retry_after.retain(|_, until| *until > tip);

    // 4. REDEEM finalize: detect each user's BTC claim and burn the zBTC; refund after CLTV;
    //    keep a refunded entry until the refund confirms (bridge N3 / N4 / N8).
    let mut still_pending = Vec::new();
    for mut p in std::mem::take(&mut state.pending) {
        let utxo = match p.utxo() {
            Ok(u) => u,
            Err(e) => {
                // Keep corrupt entries for operator inspection: never silently drop a funded
                // redeem (it would leave zBTC unfinalized / the peg broken).
                report.errors.push(format!("finalize decode {} (quarantined): {e}", p.escrow_id));
                still_pending.push(p);
                continue;
            }
        };
        // A refund we broadcast: done once it confirms.
        if let Some(rt) = p.refund_txid.as_deref().and_then(|t| Txid::from_str(t).ok()) {
            if operator_btc.tx_confirmations(&rt).unwrap_or(0) >= 1 {
                report.refunded += 1;
                state.refunded.push(p.escrow_id.clone());
                continue;
            }
        }
        // A preimage already seen on Bitcoin: retry the finalize directly, no block scan.
        let mut claim_preimage: Option<Vec<u8>> =
            p.claim_preimage_hex.as_deref().and_then(|h| hex::decode(h).ok()).filter(|v| !v.is_empty());
        let mut refund_spent = false;
        if claim_preimage.is_none() {
            // Cheap check first: an untouched output needs no block scan.
            let unspent = operator_btc.utxo_unspent(&utxo).unwrap_or(None);
            if unspent != Some(true) {
                let since = p.scan_floor().max(p.scanned_to);
                match operator_btc.find_htlc_spend(&utxo, since) {
                    Ok(HtlcSpend::Refunded) => refund_spent = true,
                    Ok(HtlcSpend::Claimed(pre)) => {
                        p.claim_preimage_hex = Some(hex::encode(&pre));
                        claim_preimage = Some(pre);
                    }
                    Ok(HtlcSpend::Unspent) => {
                        if unspent == Some(false) && !p.rescanned_from_funding {
                            // Backend says spent but the window missed it (e.g. a reorg moved
                            // the spend): ONE full rescan from the funding height.
                            report.errors.push(format!("finalize-scan {}: spent but spender not found; rescanning once from funding", p.escrow_id));
                            p.scanned_to = p.scan_floor().saturating_sub(1);
                            p.rescanned_from_funding = true;
                        } else if unspent == Some(false) {
                            // Still unresolved (typically an unconfirmed spend in the mempool):
                            // keep a short reorg-safe window, never the whole history again.
                            report.errors.push(format!("finalize-scan {}: spent but spender not yet confirmed; watching recent blocks", p.escrow_id));
                            p.scanned_to = btc_tip.saturating_sub(REORG_WINDOW_BLOCKS).max(p.scan_floor()).saturating_sub(1);
                        } else if btc_tip > 0 {
                            // Nothing through the tip: resume next time from just below it.
                            p.scanned_to = btc_tip.saturating_sub(1);
                        }
                    }
                    Err(e) => report.errors.push(format!("finalize-scan {}: {e}", p.escrow_id)),
                }
            } else if btc_tip > 0 {
                p.scanned_to = btc_tip.saturating_sub(1);
            }
        }
        if refund_spent {
            // The refund branch spent it (ours confirmed, or an older daemon's): done.
            report.refunded += 1;
            state.refunded.push(p.escrow_id.clone());
            continue;
        }
        if let Some(preimage) = claim_preimage {
            let (Some(eid), Some(hl)) = (hex32(&p.escrow_id), hex32(&p.hashlock)) else {
                report.errors.push(format!("finalize bad ids {} (quarantined)", p.escrow_id));
                still_pending.push(p);
                continue;
            };
            if zcrypt_core::nullifier::htlc_hashlock(&preimage) != hl {
                report.errors.push(format!("finalize {}: spend witness is not this escrow's preimage", p.escrow_id));
                still_pending.push(p);
                continue;
            }
            match swap::reserve_finalize_with_preimage(zc, &eid, &preimage, &hl) {
                Ok(()) => report.finalized += 1,
                Err(e) => {
                    report.errors.push(format!("finalize {}: {e}", p.escrow_id));
                    // Retry from the STORED preimage next tick; the block scan is done.
                    if btc_tip > 0 {
                        p.scanned_to = btc_tip.saturating_sub(1);
                    }
                    still_pending.push(p);
                }
            }
            continue;
        }
        // Unclaimed. Past the CLTV, take the BTC back (bridge M5), once; then keep watching.
        if p.refund_txid.is_none() && p.locktime > 0 && btc_tip >= p.locktime as u64 {
            let outcome = (|| -> Result<Txid, String> {
                let fee = swap::htlc_spend_fee_for(operator_btc, fee_target, utxo.value.to_sat())?;
                // A redeem funded before a reserve rotation names the retired key as its
                // refund key: sign with whichever held key the script commits to.
                let key = reserve.key_in_script(utxo.script.as_bytes()).unwrap_or(reserve.current);
                operator_btc.refund(&utxo, key, p.locktime, shield_dest, fee)
            })();
            match outcome {
                Ok(txid) => {
                    p.refund_txid = Some(txid.to_string());
                    p.refund_at_btc = btc_tip;
                    if regtest {
                        // Self-mined instantly; the next tick sees it confirmed.
                        let _ = operator_btc.confirm(&txid);
                    }
                }
                Err(e) => report.errors.push(format!("refund {}: {e}", p.escrow_id)),
            }
        }
        still_pending.push(p);
    }
    state.pending = still_pending;

    // 5. Advance the cursor only after successful block scans. Deferred claims are persisted
    //    above, so advancing never forgets an unswept claim (bridge N1).
    if scan_ok {
        state.cursor = tip;
    }
    persist(state)?;
    Ok(report)
}

/// The finalize margin (ZC blocks of escrow life a redeem must have left) the daemon runs
/// with: the operator's request, floored at the network minimum, and REFUSED below the
/// network default unless `allow_low` (env `ZCRYPT_WATCHER_ALLOW_LOW_MARGIN=1`) is set,
/// because a low margin hands attackers exactly the short-escrow window (bridge N9).
pub fn finalize_margin_policy(network: bitcoin::Network, requested: Option<u64>, allow_low: bool) -> Result<u64, String> {
    let floor = swap::min_redeem_margin_blocks(network);
    let default = swap::default_finalize_margin(network);
    let margin = requested.unwrap_or(default).max(floor);
    if margin < default && !allow_low {
        return Err(format!(
            "WATCHER_FINALIZE_MARGIN {margin} is below the {network:?} default of {default} ZC blocks. Redeem \
             escrows shorter than the default get proportionally shorter BTC locks and thinner safety slack; \
             set ZCRYPT_WATCHER_ALLOW_LOW_MARGIN=1 only if you accept that on this network."
        ));
    }
    Ok(margin)
}

/// Transport policy for the operator's bitcoind RPC URL. The bitcoind client speaks plain
/// HTTP with basic auth (no TLS), so on a real network the URL must stay on a private path:
/// loopback, an RFC 1918 / CGNAT / link-local / ULA address (a WireGuard or VPC interface),
/// a single-label hostname (a compose service or LAN name), or an `https://` URL fronted by
/// a TLS proxy. Plain `http://` to a public address or a dotted hostname would send the
/// RPC password and every wallet call across the internet in the clear, so it is refused
/// unless `allow_public` (env `ZCRYPT_BTC_RPC_ALLOW_PUBLIC=1`) is set. Regtest is exempt.
pub fn btc_rpc_url_policy(network: bitcoin::Network, url: &str, allow_public: bool) -> Result<(), String> {
    if network == bitcoin::Network::Regtest || allow_public {
        return Ok(());
    }
    let parsed = url::Url::parse(url).map_err(|e| format!("BTC_URL {url:?}: {e}"))?;
    if parsed.scheme() == "https" {
        return Ok(());
    }
    if parsed.scheme() != "http" {
        return Err(format!("BTC_URL {url:?}: expected http:// or https://"));
    }
    let private = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
        }
        Some(url::Host::Ipv6(ip)) => {
            ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
        Some(url::Host::Domain(d)) => d == "localhost" || !d.contains('.'),
        None => false,
    };
    if private {
        return Ok(());
    }
    Err(format!(
        "BTC_URL {url:?} is plain http to a public host on {network:?}. The bitcoind RPC carries the RPC \
         password and wallet calls unencrypted, so reach the node over a private link instead (WireGuard, \
         VPC peering, an SSH tunnel to 127.0.0.1) or front it with TLS and use https://. Set \
         ZCRYPT_BTC_RPC_ALLOW_PUBLIC=1 only if you accept the exposure."
    ))
}

/// Load the operator's RESERVE key the way the daemon expects it (bridge L4). Sources, in
/// order of preference:
///
/// 1. `ZCRYPT_RESERVE_KEY_FILE`: a file holding the DERIVED 32-byte secp256k1 key (64 hex
///    chars, or 32 raw bytes that are not all ASCII hex). This is the key the wallet's
///    `bridge_init` derives as `H("BTCBRDG", wallet_seed)` and whose pubkey is the chain's
///    `zbtc_reserve_pk`. Mount it as a docker secret / 0400 file; it never has to sit in
///    the environment.
/// 2. `ZCRYPT_RESERVE_WALLET_SEED_FILE`: a file holding the operator WALLET seed (32 bytes);
///    the daemon applies the same `H("BTCBRDG", seed)` derivation. Discouraged: that seed
///    also spends the operator's shielded coins.
///
/// The old `ZCRYPT_RESERVE_SEED` environment variable is REFUSED (a set variable is a hard
/// error): an environment variable is visible in `docker inspect` and procfs.
pub fn reserve_key_from_env() -> Result<Key, String> {
    if std::env::var_os("ZCRYPT_RESERVE_SEED").is_some() {
        return Err("ZCRYPT_RESERVE_SEED is no longer accepted (secrets must not live in the environment). \
                    Write the derived reserve key to a 0600 file and point ZCRYPT_RESERVE_KEY_FILE at it \
                    (`reserve_pubkey --wallet-seed-file <seed> --write-derived-key <path>`), then unset \
                    ZCRYPT_RESERVE_SEED."
            .to_string());
    }
    if let Ok(path) = std::env::var("ZCRYPT_RESERVE_KEY_FILE") {
        let raw = std::fs::read(&path).map_err(|e| format!("ZCRYPT_RESERVE_KEY_FILE {path}: {e}"))?;
        let k = crate::parse_secret_bytes(&raw)?;
        return Ok(Key::from_bytes(&k));
    }
    if let Ok(path) = std::env::var("ZCRYPT_RESERVE_WALLET_SEED_FILE") {
        let raw = std::fs::read(&path).map_err(|e| format!("ZCRYPT_RESERVE_WALLET_SEED_FILE {path}: {e}"))?;
        let seed = crate::parse_secret_bytes(&raw)?;
        return Ok(crate::reserve_key_from_wallet_seed(&seed));
    }
    Err("no reserve key: set ZCRYPT_RESERVE_KEY_FILE (derived key file, preferred) or \
         ZCRYPT_RESERVE_WALLET_SEED_FILE (wallet seed file)"
        .to_string())
}

/// Reserve keys RETIRED by a rotation that this operator still needs to sweep old deposits
/// and refund old redeems with: `ZCRYPT_RESERVE_PREV_KEY_FILES`, a comma-separated list of
/// 0600 key files (same format as `ZCRYPT_RESERVE_KEY_FILE`). Empty when unset.
pub fn previous_reserve_keys_from_env() -> Result<Vec<Key>, String> {
    let Ok(list) = std::env::var("ZCRYPT_RESERVE_PREV_KEY_FILES") else {
        return Ok(Vec::new());
    };
    let mut keys = Vec::new();
    for path in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let raw = std::fs::read(path).map_err(|e| format!("ZCRYPT_RESERVE_PREV_KEY_FILES {path}: {e}"))?;
        let k = crate::parse_secret_bytes(&raw)?;
        keys.push(Key::from_bytes(&k));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    #[test]
    fn btc_rpc_url_policy_keeps_mainnet_rpc_off_the_public_internet() {
        use bitcoin::Network::{Bitcoin, Regtest};
        for ok in [
            "http://127.0.0.1:8332",
            "http://localhost:8332",
            "http://10.8.0.2:8332",
            "http://192.168.1.10:8332",
            "http://172.31.5.9:8332",
            "http://100.64.3.1:8332",
            "http://[fd00::1]:8332",
            "http://bitcoind:8332",
            "https://btc.example.com:8332",
        ] {
            assert!(btc_rpc_url_policy(Bitcoin, ok, false).is_ok(), "{ok}");
        }
        for bad in ["http://203.0.113.5:8332", "http://btc.example.com:8332", "http://100.128.0.1:8332", "ftp://x"] {
            assert!(btc_rpc_url_policy(Bitcoin, bad, false).is_err(), "{bad}");
        }
        assert!(btc_rpc_url_policy(Bitcoin, "http://203.0.113.5:8332", true).is_ok());
        assert!(btc_rpc_url_policy(Regtest, "http://203.0.113.5:18443", false).is_ok());
    }
    use bitcoin::Network;
    use std::cell::{Cell, RefCell};
    use zcrypt_core::nullifier::htlc_hashlock;
    use zcrypt_core::spv::{testutil, MintProof, REGTEST_GENESIS};

    // ------------------------------------------------------------------ fakes ----------

    /// In-memory ZCrypt node: blocks of raw txs, an escrow book, recorded broadcasts.
    struct FakeZc {
        blocks: RefCell<Vec<Vec<Vec<u8>>>>,
        escrows: RefCell<HashMap<[u8; 32], (u64, u64, [u8; 32], u64, String)>>,
        /// Consensus-committed payout key per burn escrow (what `/htlc/<id>` reports).
        btc_keys: RefCell<HashMap<[u8; 32], Vec<u8>>>,
        broadcasts: RefCell<Vec<Vec<u8>>>,
        authority: String,
    }
    impl FakeZc {
        fn new() -> Self {
            FakeZc {
                blocks: RefCell::new(vec![]),
                escrows: RefCell::new(HashMap::new()),
                btc_keys: RefCell::new(HashMap::new()),
                broadcasts: RefCell::new(vec![]),
                authority: String::new(),
            }
        }
        #[allow(dead_code)]
        fn set_escrow_btc_key(&self, eid: [u8; 32], pk: &[u8]) {
            self.btc_keys.borrow_mut().insert(eid, pk.to_vec());
        }
        fn push_block(&self, txs: Vec<Vec<u8>>) -> i64 {
            self.blocks.borrow_mut().push(txs);
            self.blocks.borrow().len() as i64
        }
        fn set_escrow(&self, eid: [u8; 32], asset: u64, value: u64, lock: [u8; 32], timeout: u64, state: &str) {
            self.escrows.borrow_mut().insert(eid, (asset, value, lock, timeout, state.to_string()));
        }
        fn escrow_state(&self, eid: &[u8; 32]) -> String {
            self.escrows.borrow().get(eid).map(|e| e.4.clone()).unwrap_or_default()
        }
    }
    impl ZcNode for FakeZc {
        fn height(&self) -> Result<i64, String> {
            Ok(self.blocks.borrow().len() as i64)
        }
        fn block_txs(&self, height: i64) -> Result<Vec<Vec<u8>>, String> {
            Ok(self.blocks.borrow().get((height - 1).max(0) as usize).cloned().unwrap_or_default())
        }
        fn query(&self, path: &str) -> Result<String, String> {
            if path == "/spv/height" {
                return Ok("999999999".into()); // never behind the fake backend: no relay
            }
            if let Some(h) = path.strip_prefix("/htlc/") {
                let eid = hex32(h).ok_or("bad id")?;
                return match self.escrows.borrow().get(&eid) {
                    Some((a, v, l, t, s)) => {
                        let key = self.btc_keys.borrow().get(&eid).cloned().unwrap_or_default();
                        Ok(serde_json::json!({
                            "asset_id": a, "value": v, "hashlock": hex::encode(l), "timeout_height": t, "state": s,
                            "kind": if key.is_empty() { "mint" } else { "burn" },
                            "btc_claim_pk": hex::encode(&key),
                        })
                        .to_string())
                    }
                    None => Err("no such escrow".into()),
                };
            }
            if path.starts_with("/asset/id/") {
                return Ok(serde_json::json!({ "authority": self.authority }).to_string());
            }
            Err(format!("fake: unknown query {path}"))
        }
        fn broadcast(&self, tx: &[u8]) -> Result<String, String> {
            self.broadcasts.borrow_mut().push(tx.to_vec());
            if tx.first() == Some(&0x5B) && tx.len() > 33 {
                let eid: [u8; 32] = tx[1..33].try_into().unwrap();
                if let Some(e) = self.escrows.borrow_mut().get_mut(&eid) {
                    e.4 = "claimed".into();
                }
            }
            Ok(String::new())
        }
    }

    #[derive(Clone)]
    struct SimUtxo {
        outpoint: OutPoint,
        value: Amount,
        script: ScriptBuf,
        mined_at: Option<u64>,
        /// (height or None while in the mempool, preimage or None for the refund branch)
        spend: Option<(Option<u64>, Option<Vec<u8>>)>,
    }

    /// Simulated Bitcoin backend on SIGNET (funding needs 1 conf, sweeps need 4).
    struct SimBtc {
        tip: Cell<u64>,
        utxos: RefCell<Vec<SimUtxo>>,
        next_txid: Cell<u32>,
        broadcasts: Cell<u32>,
        claims: Cell<u32>,
        refunds: Cell<u32>,
        /// The next fund_htlc_unconfirmed broadcasts, then errors (read-back failure).
        fail_readback_once: Cell<bool>,
        /// Block hashes reported by tx_block_hash, per txid (reorg simulation).
        block_of: RefCell<HashMap<Txid, [u8; 32]>>,
        proof_for: RefCell<HashMap<Txid, Vec<u8>>>,
    }
    impl SimBtc {
        fn new(tip: u64) -> Self {
            SimBtc {
                tip: Cell::new(tip),
                utxos: RefCell::new(vec![]),
                next_txid: Cell::new(1),
                broadcasts: Cell::new(0),
                claims: Cell::new(0),
                refunds: Cell::new(0),
                fail_readback_once: Cell::new(false),
                block_of: RefCell::new(HashMap::new()),
                proof_for: RefCell::new(HashMap::new()),
            }
        }
        fn fresh_txid(&self) -> Txid {
            let n = self.next_txid.get();
            self.next_txid.set(n + 1);
            Txid::from_byte_array(zcrypt_core::hash::h(b"SIM-TXID", &[&n.to_le_bytes()]))
        }
        fn add_confirmed(&self, u: HtlcUtxo, at: u64) {
            self.utxos.borrow_mut().push(SimUtxo { outpoint: u.outpoint, value: u.value, script: u.script, mined_at: Some(at), spend: None });
        }
        fn mine(&self, n: u64) {
            for _ in 0..n {
                let t = self.tip.get() + 1;
                self.tip.set(t);
                for u in self.utxos.borrow_mut().iter_mut() {
                    if u.mined_at.is_none() {
                        u.mined_at = Some(t);
                    }
                    if let Some((h, _)) = u.spend.as_mut() {
                        if h.is_none() {
                            *h = Some(t);
                        }
                    }
                }
            }
        }
        /// The user spends the HTLC via the claim branch (in the mempool until mined).
        fn user_claims(&self, op: OutPoint, preimage: &[u8]) {
            for u in self.utxos.borrow_mut().iter_mut().filter(|u| u.outpoint == op) {
                u.spend = Some((None, Some(preimage.to_vec())));
            }
        }
        fn is_spent_confirmed(&self, op: OutPoint) -> bool {
            self.utxos.borrow().iter().any(|u| u.outpoint == op && matches!(u.spend, Some((Some(_), _))))
        }
    }
    impl BtcBackend for SimBtc {
        fn fund_htlc(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
            self.fund_htlc_unconfirmed(script, amount)
        }
        fn fund_htlc_unconfirmed(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
            self.broadcasts.set(self.broadcasts.get() + 1);
            let op = OutPoint { txid: self.fresh_txid(), vout: 0 };
            self.utxos.borrow_mut().push(SimUtxo { outpoint: op, value: amount, script: script.clone(), mined_at: None, spend: None });
            if self.fail_readback_once.replace(false) {
                return Err(format!("funding {} BROADCAST but unreadable (simulated)", op.txid));
            }
            Ok(HtlcUtxo { outpoint: op, value: amount, script: script.clone() })
        }
        fn htlc_utxos(&self, script: &ScriptBuf) -> Result<Vec<HtlcUtxo>, String> {
            Ok(self
                .utxos
                .borrow()
                .iter()
                .filter(|u| &u.script == script && u.spend.is_none())
                .map(|u| HtlcUtxo { outpoint: u.outpoint, value: u.value, script: u.script.clone() })
                .collect())
        }
        fn claim(&self, utxo: &HtlcUtxo, preimage: &[u8], _: &Key, _: &Address, _: Amount) -> Result<Txid, String> {
            self.claims.set(self.claims.get() + 1);
            for u in self.utxos.borrow_mut().iter_mut().filter(|u| u.outpoint == utxo.outpoint) {
                u.spend = Some((None, Some(preimage.to_vec())));
            }
            let txid = self.fresh_txid();
            // The sweep tx itself: unconfirmed until the next mined block (for tx_confirmations).
            self.utxos.borrow_mut().push(SimUtxo { outpoint: OutPoint { txid, vout: 0 }, value: utxo.value, script: ScriptBuf::new(), mined_at: None, spend: None });
            Ok(txid)
        }
        fn refund(&self, utxo: &HtlcUtxo, _: &Key, _: u32, _: &Address, _: Amount) -> Result<Txid, String> {
            self.refunds.set(self.refunds.get() + 1);
            let txid = self.fresh_txid();
            for u in self.utxos.borrow_mut().iter_mut().filter(|u| u.outpoint == utxo.outpoint) {
                u.spend = Some((None, None));
            }
            // Register the refund tx as an (unconfirmed) utxo-less tx we can count confs for.
            self.utxos.borrow_mut().push(SimUtxo { outpoint: OutPoint { txid, vout: 0 }, value: utxo.value, script: ScriptBuf::new(), mined_at: None, spend: None });
            Ok(txid)
        }
        fn height(&self) -> Result<u64, String> {
            Ok(self.tip.get())
        }
        fn network(&self) -> Network {
            Network::Signet
        }
        fn preimage_from_claim(&self, _: &Txid) -> Option<Vec<u8>> {
            None
        }
        fn confirm(&self, _: &Txid) -> Result<(), String> {
            panic!("the watcher must never block on confirmations on a real network (bridge N7)")
        }
        fn fee_rate_sat_vb(&self, _: u32) -> Result<f64, String> {
            Ok(1.0)
        }
        fn find_htlc_spend(&self, utxo: &HtlcUtxo, since_height: u64) -> Result<HtlcSpend, String> {
            for u in self.utxos.borrow().iter().filter(|u| u.outpoint == utxo.outpoint) {
                if let Some((Some(h), pre)) = &u.spend {
                    if *h >= since_height {
                        return Ok(match pre {
                            Some(p) => HtlcSpend::Claimed(p.clone()),
                            None => HtlcSpend::Refunded,
                        });
                    }
                }
            }
            Ok(HtlcSpend::Unspent)
        }
        fn tx_confirmations(&self, txid: &Txid) -> Result<u64, String> {
            let tip = self.tip.get();
            Ok(self
                .utxos
                .borrow()
                .iter()
                .find(|u| u.outpoint.txid == *txid)
                .and_then(|u| u.mined_at)
                .map(|h| tip + 1 - h)
                .unwrap_or(0))
        }
        fn utxo_unspent(&self, utxo: &HtlcUtxo) -> Result<Option<bool>, String> {
            Ok(Some(!self.is_spent_confirmed(utxo.outpoint)))
        }
        fn tx_block_hash(&self, txid: &Txid) -> Result<Option<[u8; 32]>, String> {
            Ok(self.block_of.borrow().get(txid).copied())
        }
        fn block_header(&self, _: u64) -> Result<[u8; 80], String> {
            Err("sim".into())
        }
        fn raw_tx(&self, _: &Txid) -> Result<Vec<u8>, String> {
            Err("sim".into())
        }
        fn txout_proof(&self, txid: &Txid) -> Result<Vec<u8>, String> {
            self.proof_for.borrow().get(txid).cloned().ok_or("sim: no proof".into())
        }
        fn coinbase_raw(&self, _txid: &Txid) -> Result<Vec<u8>, String> {
            Ok(vec![0])
        }
    }

    /// One reserve deposit: keys, preimage, funding tx in a mined block, the 0x64 open tx
    /// and the 0x5B claim tx, plus the escrow id consensus derives.
    struct Deposit {
        reserve: Key,
        preimage: [u8; 32],
        lock: [u8; 32],
        eid: [u8; 32],
        open_tx: Vec<u8>,
        claim_tx: Vec<u8>,
        utxo: HtlcUtxo,
        proof: MintProof,
        header: [u8; 80],
    }
    const ASSET: u64 = 77;
    const VALUE: u64 = 50_000;
    const LOCKTIME: u32 = 5_000;
    fn deposit(salt: u32) -> Deposit {
        let reserve = Key::from_bytes(&[0xB1u8; 32]);
        let refund = Key::from_bytes(&[0x9Au8; 32]);
        let preimage = [0x30u8 + salt as u8; 32];
        let lock = htlc_hashlock(&preimage);
        let tx = testutil::funding_tx(&lock, &reserve.pk.inner.serialize(), &refund.pk.inner.serialize(), LOCKTIME, VALUE, salt);
        let (header, proof) = testutil::deposit_proof(
            &REGTEST_GENESIS,
            &tx,
            1_296_689_000 + salt,
            reserve.pk.inner.serialize(),
            refund.pk.inner.serialize(),
            LOCKTIME,
            0,
            salt,
        );
        let claim_pk: zcrypt_shield::PubKey = [salt as u64 + 1; 8];
        let timeout = 100_000u64;
        let eid = zcrypt_core::htlc_shield::escrow_id(ASSET, VALUE, &lock, timeout, &claim_pk);
        let open_tx = swap::open_spv_tx(ASSET, VALUE, &lock, timeout, &claim_pk, &proof, &refund);
        let claim_tx = swap::claim_tx(&eid, &preimage);
        let utxo = swap::htlc_utxo_from_proof(&proof, &lock).unwrap();
        Deposit { reserve, preimage, lock, eid, open_tx, claim_tx, utxo, proof, header }
    }
    fn dest() -> Address {
        Address::p2wpkh(&Key::from_bytes(&[0xEE; 32]).compressed(), Network::Signet)
    }
    fn tick(st: &mut WatcherState, zc: &FakeZc, btc: &SimBtc, reserve: &Key) -> TickReport {
        watcher_tick(st, zc, btc, &swap::ReserveKeys::single(reserve), &dest(), ASSET, swap::default_finalize_margin(Network::Signet), 3).expect("tick")
    }

    // ------------------------------------------------------------------ tests ----------

    #[test]
    fn deferred_sweep_is_persisted_and_retried_across_a_cursor_advance() {
        // N1: the claim is seen while the deposit has 1 confirmation (signet needs 4).
        let d = deposit(1);
        let zc = FakeZc::new();
        let btc = SimBtc::new(1);
        btc.add_confirmed(d.utxo.clone(), 1);
        zc.set_escrow(d.eid, ASSET, VALUE, d.lock, 100_000, "open");
        zc.push_block(vec![d.open_tx.clone()]);
        zc.set_escrow(d.eid, ASSET, VALUE, d.lock, 100_000, "claimed");
        zc.push_block(vec![d.claim_tx.clone()]);

        let mut st = WatcherState::default();
        let r1 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r1.swept, 0);
        assert_eq!(r1.deferred, 1, "sweep deferred at 1 of 4 confirmations");
        assert_eq!(st.deferred.len(), 1, "the deferral is PERSISTED");
        assert_eq!(st.cursor, 2, "the cursor advanced past the claim block");
        assert_eq!(btc.claims.get(), 0);

        // The cursor is past the claim; only the persisted deferral can bring it back.
        zc.push_block(vec![]);
        let r2 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r2.swept, 0, "still only 1 confirmation");
        btc.mine(3); // 4 confirmations
        let r3 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r3.swept, 1, "swept on a later tick, after the cursor moved on");
        assert!(st.deferred.is_empty());
        assert_eq!(btc.claims.get(), 1);
        assert_eq!(st.sweeps.len(), 1, "real network: the sweep is tracked until confirmed");
        btc.mine(1);
        let _ = tick(&mut st, &zc, &btc, &d.reserve);
        assert!(st.sweeps.is_empty(), "confirmed sweep is released");
        // Idempotent: nothing is swept twice.
        let r4 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r4.swept, 0);
        assert_eq!(btc.claims.get(), 1);
    }

    #[test]
    fn open_in_one_tick_and_claim_in_the_next_is_swept() {
        // N2: the 0x64 open and the 0x5B claim straddle a tick boundary.
        let d = deposit(2);
        let zc = FakeZc::new();
        let btc = SimBtc::new(1);
        btc.add_confirmed(d.utxo.clone(), 1);
        zc.set_escrow(d.eid, ASSET, VALUE, d.lock, 100_000, "open");
        zc.push_block(vec![d.open_tx.clone()]);
        let mut st = WatcherState::default();
        let r1 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r1.swept, 0);
        assert_eq!(st.tracked.len(), 1, "the open is tracked");
        assert_eq!(st.cursor, 1);

        zc.set_escrow(d.eid, ASSET, VALUE, d.lock, 100_000, "claimed");
        zc.push_block(vec![d.claim_tx.clone()]);
        btc.mine(3);
        let r2 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r2.swept, 1, "claim matched against the PERSISTED deposit");
        assert_eq!(btc.claims.get(), 1);
    }

    fn pending_redeem(d: &Deposit, funding_height: u64) -> PendingRedeem {
        PendingRedeem {
            escrow_id: hex::encode(d.eid),
            funding_txid: d.utxo.outpoint.txid.to_string(),
            vout: 0,
            value_sat: VALUE,
            script_hex: hex::encode(d.utxo.script.as_bytes()),
            hashlock: hex::encode(d.lock),
            funded_at_btc: 0,
            funding_height,
            scanned_to: funding_height.saturating_sub(1),
            locktime: 15,
            refund_txid: None,
            refund_at_btc: 0,
            rescanned_from_funding: false,
            claim_preimage_hex: None,
        }
    }

    #[test]
    fn finalize_sees_a_claim_mined_right_after_funding() {
        // N3: the funding is at height 10, the user claims in block 11, the daemon only
        // looks at height 20. The scan starts at the funding height, not at "confirmed at".
        let d = deposit(3);
        let zc = FakeZc::new();
        let btc = SimBtc::new(20);
        btc.add_confirmed(d.utxo.clone(), 10);
        btc.user_claims(d.utxo.outpoint, &d.preimage);
        // Mine the claim into block 11 by rewinding the sim: set the spend height directly.
        for u in btc.utxos.borrow_mut().iter_mut() {
            u.spend = Some((Some(11), Some(d.preimage.to_vec())));
        }
        zc.set_escrow(d.eid, ASSET, VALUE, d.lock, 100_000, "open");
        zc.push_block(vec![]);
        let mut st = WatcherState::default();
        st.pending.push(pending_redeem(&d, 10));
        st.funded.push(hex::encode(d.eid));
        let r = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r.finalized, 1, "claim at funding+1 is found and the burn is finalized");
        assert!(st.pending.is_empty());
        assert_eq!(zc.escrow_state(&d.eid), "claimed");
        assert!(zc.broadcasts.borrow().iter().any(|t| t.first() == Some(&0x5B)));
    }

    #[test]
    fn refund_stays_pending_until_confirmed_and_a_winning_claim_still_finalizes() {
        // N4, branch A: refund broadcast at CLTV, entry kept, released once it confirms.
        let d = deposit(4);
        let zc = FakeZc::new();
        let btc = SimBtc::new(15);
        btc.add_confirmed(d.utxo.clone(), 10);
        zc.set_escrow(d.eid, ASSET, VALUE, d.lock, 100_000, "open");
        zc.push_block(vec![]);
        let mut st = WatcherState::default();
        st.pending.push(pending_redeem(&d, 10));
        let r1 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(btc.refunds.get(), 1, "refund broadcast at the CLTV");
        assert_eq!(r1.refunded, 0, "not counted until confirmed");
        assert_eq!(st.pending.len(), 1, "entry KEPT with the refund txid");
        assert!(st.pending[0].refund_txid.is_some());
        let r1b = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(btc.refunds.get(), 1, "no second refund broadcast");
        assert_eq!(r1b.refunded, 0);
        btc.mine(1); // refund confirms
        let r2 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r2.refunded, 1);
        assert!(st.pending.is_empty());
        assert_eq!(st.refunded.len(), 1);

        // Branch B: the user's claim is mined before the refund. The daemon must finalize.
        let d = deposit(5);
        let zc = FakeZc::new();
        let btc = SimBtc::new(15);
        btc.add_confirmed(d.utxo.clone(), 10);
        zc.set_escrow(d.eid, ASSET, VALUE, d.lock, 100_000, "open");
        zc.push_block(vec![]);
        let mut st = WatcherState::default();
        st.pending.push(pending_redeem(&d, 10));
        let _ = tick(&mut st, &zc, &btc, &d.reserve);
        assert!(st.pending[0].refund_txid.is_some(), "refund broadcast");
        // Race: the user's claim gets mined instead of the refund.
        for u in btc.utxos.borrow_mut().iter_mut().filter(|u| u.outpoint == d.utxo.outpoint) {
            u.spend = Some((Some(16), Some(d.preimage.to_vec())));
        }
        btc.tip.set(16);
        let r = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r.finalized, 1, "the winning claim is finalized, not forgotten");
        assert!(st.pending.is_empty());
        assert_eq!(zc.escrow_state(&d.eid), "claimed");
    }

    #[test]
    fn a_broadcast_whose_readback_failed_is_reused_after_the_backoff() {
        // N5: the send goes out but the RPC read-back fails; the intent is KEPT, the slot
        // stays claimed, and after the backoff the mempool funding is reused, not re-sent.
        let d = deposit(6);
        let zc = FakeZc::new();
        let btc = SimBtc::new(1);
        btc.fail_readback_once.set(true);
        zc.set_escrow(d.eid, ASSET, VALUE, d.lock, 100_000, "open");
        zc.push_block(vec![]);
        let mut st = WatcherState::default();
        st.funding.push(FundingIntent {
            escrow_id: hex::encode(d.eid),
            hashlock: hex::encode(d.lock),
            script_hex: hex::encode(d.utxo.script.as_bytes()),
            value_sat: VALUE,
            locktime: 5_000,
            funding: None,
            funding_value_sat: None,
            funding_height: None,
        });
        st.funded.push(hex::encode(d.eid));
        let r1 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(btc.broadcasts.get(), 1);
        assert!(r1.errors.iter().any(|e| e.contains("BROADCAST but unreadable")));
        assert_eq!(st.funding.len(), 1, "intent kept");
        assert!(st.funding[0].funding.is_none());
        assert!(st.funded.contains(&hex::encode(d.eid)), "slot still claimed");
        let until = *st.retry_after.get(&hex::encode(d.eid)).expect("backoff recorded");
        assert!(until - zc.height().unwrap() >= 900, "backoff exceeds one Bitcoin block");

        // Inside the backoff: nothing happens.
        zc.push_block(vec![]);
        let _ = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(btc.broadcasts.get(), 1);
        // Past the backoff: the mempool funding is discovered and reused.
        for _ in 0..RETRY_BACKOFF_BLOCKS {
            zc.push_block(vec![]);
        }
        let r3 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(btc.broadcasts.get(), 1, "never funded twice");
        assert_eq!(r3.resumed, 1);
        assert!(st.funding[0].funding.is_some(), "txid recorded from the discovered funding");
        // Confirms next block, moves to pending with the funding height, no blocking.
        btc.mine(1);
        let r4 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r4.locked, 1);
        assert_eq!(st.pending.len(), 1);
        assert!(st.funding.is_empty());
        assert!(st.pending[0].funding_height >= 1 && st.pending[0].funding_height <= 2);
    }

    #[test]
    fn every_persisted_snapshot_keeps_every_intent() {
        // N6: two intents, the first broadcasts this tick; no snapshot may drop the second.
        let d1 = deposit(7);
        let d2 = deposit(8);
        let zc = FakeZc::new();
        let btc = SimBtc::new(1);
        zc.set_escrow(d1.eid, ASSET, VALUE, d1.lock, 100_000, "open");
        zc.set_escrow(d2.eid, ASSET, VALUE, d2.lock, 100_000, "open");
        zc.push_block(vec![]);
        let mk = |d: &Deposit, funding: Option<(String, u32)>| FundingIntent {
            escrow_id: hex::encode(d.eid),
            hashlock: hex::encode(d.lock),
            script_hex: hex::encode(d.utxo.script.as_bytes()),
            value_sat: VALUE,
            locktime: 5_000,
            funding,
            funding_value_sat: None,
            funding_height: None,
        };
        let mut st = WatcherState::default();
        st.funding.push(mk(&d1, None));
        st.funding.push(mk(&d2, Some(("11".repeat(32), 0)))); // broadcast earlier, unconfirmed
        st.funded.push(hex::encode(d1.eid));
        st.funded.push(hex::encode(d2.eid));
        let snapshots: RefCell<Vec<Vec<String>>> = RefCell::new(vec![]);
        let persist = |s: &WatcherState| -> Result<(), String> {
            let ids: Vec<String> = s.funding.iter().map(|i| i.escrow_id.clone()).chain(s.pending.iter().map(|p| p.escrow_id.clone())).collect();
            snapshots.borrow_mut().push(ids);
            Ok(())
        };
        watcher_tick_persisting(&mut st, &zc, &btc, &swap::ReserveKeys::single(&d1.reserve), &dest(), ASSET, swap::default_finalize_margin(Network::Signet), 3, &persist).unwrap();
        assert!(!snapshots.borrow().is_empty());
        for snap in snapshots.borrow().iter() {
            assert!(snap.contains(&hex::encode(d1.eid)) && snap.contains(&hex::encode(d2.eid)), "snapshot dropped an intent: {snap:?}");
        }
        assert_eq!(st.funding.len(), 2, "both still in flight (unconfirmed)");
    }

    #[test]
    fn a_reused_funding_carries_its_actual_value() {
        // N13: the existing HTLC output holds more than the plan; the pending record must use it.
        let d = deposit(9);
        let zc = FakeZc::new();
        let btc = SimBtc::new(5);
        btc.add_confirmed(HtlcUtxo { value: Amount::from_sat(VALUE + 1_234), ..d.utxo.clone() }, 3);
        zc.set_escrow(d.eid, ASSET, VALUE, d.lock, 100_000, "open");
        zc.push_block(vec![]);
        let mut st = WatcherState::default();
        st.funding.push(FundingIntent {
            escrow_id: hex::encode(d.eid),
            hashlock: hex::encode(d.lock),
            script_hex: hex::encode(d.utxo.script.as_bytes()),
            value_sat: VALUE,
            locktime: 5_000,
            funding: None,
            funding_value_sat: None,
            funding_height: None,
        });
        st.funded.push(hex::encode(d.eid));
        let r = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r.resumed, 1);
        assert_eq!(r.locked, 1);
        assert_eq!(btc.broadcasts.get(), 0);
        assert_eq!(st.pending[0].value_sat, VALUE + 1_234, "sighash value is the real output value");
        assert_eq!(st.pending[0].funding_height, 3, "funding height recovered from confirmations");
    }

    #[test]
    fn unclaimed_deposit_survives_a_reorg_and_is_reanchored_once_claimed() {
        // N11: the deposit moves to another block BEFORE the claim; the daemon keeps tracking
        // it (no immature mint exists yet) and re-anchors as soon as the claim lands.
        let d = deposit(10);
        let zc = FakeZc::new();
        let btc = SimBtc::new(1);
        btc.add_confirmed(d.utxo.clone(), 1);
        // A different block (re-mined) with its own merkle proof.
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&d.proof.raw_tx).unwrap();
        let other = testutil::mine_header(&d.header, &[tx.clone()], 1_296_700_000);
        let other_hash = {
            let h: bitcoin::block::Header = bitcoin::consensus::deserialize(&other).unwrap();
            h.block_hash().to_byte_array()
        };
        btc.block_of.borrow_mut().insert(d.utxo.outpoint.txid, other_hash);
        btc.proof_for.borrow_mut().insert(d.utxo.outpoint.txid, testutil::merkle_proof(&other, &[tx.clone()], &tx));
        zc.set_escrow(d.eid, ASSET, VALUE, d.lock, 100_000, "open");
        zc.push_block(vec![d.open_tx.clone()]);
        let mut st = WatcherState::default();
        let r1 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r1.reanchored, 0, "nothing to re-anchor before the claim");
        assert_eq!(st.tracked.len(), 1, "still tracked");
        assert!(!zc.broadcasts.borrow().iter().any(|t| t.first() == Some(&0x65)));

        zc.set_escrow(d.eid, ASSET, VALUE, d.lock, 100_000, "claimed");
        zc.push_block(vec![d.claim_tx.clone()]);
        let r2 = tick(&mut st, &zc, &btc, &d.reserve);
        assert_eq!(r2.reanchored, 1, "re-anchored right after the claim");
        assert!(zc.broadcasts.borrow().iter().any(|t| t.first() == Some(&0x65)));
        assert_eq!(st.tracked[0].deposit_block, hex::encode(other_hash));
    }

    #[test]
    fn reserve_key_must_match_the_chain_authority() {
        let reserve = Key::from_bytes(&[0xB1u8; 32]);
        let mut zc = FakeZc::new();
        zc.authority = hex::encode(zcrypt_core::spv::spv_authority(&reserve.pk.inner.serialize()));
        assert!(swap::assert_reserve_matches_chain(&zc, ASSET, &reserve).is_ok());
        zc.authority = hex::encode([0u8; 32]);
        let err = swap::assert_reserve_matches_chain(&zc, ASSET, &reserve).unwrap_err();
        assert!(err.contains("reserve key mismatch"));
    }

    #[test]
    fn low_finalize_margin_needs_an_explicit_override() {
        let net = Network::Bitcoin;
        let default = swap::default_finalize_margin(net);
        assert_eq!(finalize_margin_policy(net, None, false).unwrap(), default);
        assert_eq!(finalize_margin_policy(net, Some(default + 5), false).unwrap(), default + 5);
        assert!(finalize_margin_policy(net, Some(200_000), false).is_err());
        assert_eq!(finalize_margin_policy(net, Some(200_000), true).unwrap(), 200_000);
        // Even with the override the network floor holds.
        assert_eq!(finalize_margin_policy(net, Some(1), true).unwrap(), swap::min_redeem_margin_blocks(net));
    }

    #[test]
    fn state_file_round_trips_and_a_corrupt_file_is_a_hard_error() {
        // An old state file (no new fields) still loads.
        let old = r#"{"cursor":7,"swept":[],"funded":[],"pending":[{"escrow_id":"00","funding_txid":"0000000000000000000000000000000000000000000000000000000000000000","vout":0,"value_sat":1,"script_hex":"","hashlock":"00","funded_at_btc":9}]}"#;
        let st: WatcherState = serde_json::from_str(old).expect("old state loads");
        assert_eq!(st.cursor, 7);
        assert_eq!(st.pending[0].locktime, 0, "old entries carry no locktime and are never auto-refunded");
        assert_eq!(st.pending[0].scan_floor(), 9, "old entries scan from the legacy field");
        assert!(st.funding.is_empty() && st.tracked.is_empty() && st.deferred.is_empty() && st.sweeps.is_empty());

        let dir = std::env::temp_dir().join(format!("zcrypt-watcher-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("state.json");
        let mut st = WatcherState::default();
        st.rejected.push("ef".repeat(32));
        st.save(&path).unwrap();
        assert_eq!(WatcherState::load(&path).unwrap().rejected.len(), 1);
        std::fs::write(&path, b"{ definitely not json").unwrap();
        let err = WatcherState::load(&path).unwrap_err();
        assert!(err.contains("does not parse"), "{err}");
        assert!(WatcherState::load(&dir.join("missing.json")).unwrap().pending.is_empty(), "a missing file is a fresh daemon");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reserve_key_sources_agree_with_the_wallet_derivation_and_reject_ambiguity() {
        let seed = [0x42u8; 32];
        let derived = crate::reserve_key_from_wallet_seed(&seed);
        // The wallet's rule, spelled out: H("BTCBRDG", seed).
        let expect = Key::from_bytes(&zcrypt_core::hash::h(b"BTCBRDG", &[&seed]));
        assert_eq!(derived.pk, expect.pk);
        // Hex and raw file encodings parse to the same key.
        let raw = derived.sk.secret_bytes();
        assert_eq!(crate::parse_secret_bytes(&raw).unwrap(), raw);
        assert_eq!(crate::parse_secret_bytes(format!(" {}\n", hex::encode(raw)).as_bytes()).unwrap(), raw);
        assert!(crate::parse_secret_bytes(b"zz").is_err());
        // 32 bytes of ASCII hex is refused as ambiguous (L4).
        assert!(crate::parse_secret_bytes(b"0123456789abcdef0123456789abcdef").unwrap_err().contains("ambiguous"));
        // The legacy env var is a hard error (coordinator item C).
        std::env::set_var("ZCRYPT_RESERVE_SEED", hex::encode(raw));
        let err = reserve_key_from_env().unwrap_err();
        std::env::remove_var("ZCRYPT_RESERVE_SEED");
        assert!(err.contains("ZCRYPT_RESERVE_KEY_FILE"), "{err}");
        // Per-deposit refund keys: canonical form matches the wallet for index 0 too.
        let k0 = crate::refund_key_for(&seed, 0);
        let wallet0 = Key::from_bytes(&zcrypt_core::hash::h(b"BTCALIC", &[&seed, &0u32.to_le_bytes()]));
        assert_eq!(k0.pk, wallet0.pk);
        assert_ne!(crate::refund_key_legacy(&seed).pk, k0.pk);
    }
}
