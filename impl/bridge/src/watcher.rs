//! The bridge operator's WATCHER — the always-on service that settles the public bridge
//! autonomously. One [`watcher_tick`] does a full pass over new ZCrypt blocks:
//!
//!   1. relay any missing Bitcoin headers (keeps the SPV chain current),
//!   2. SHIELD: sweep each deposit whose preimage was revealed into the reserve, and
//!      RE-ANCHOR any tracked deposit a Bitcoin reorg re-mined into another block,
//!   3. REDEEM (lock): for each on-chain `0x67` redeem, lock reserve BTC 1:1 to the user's
//!      on-chain key, persisting a funding INTENT before the broadcast,
//!   4. REDEEM (finalize): detect the user's BTC claim of a locked HTLC and burn the zBTC,
//!      or REFUND a lock the user never claimed once its CLTV has passed.
//!
//! All of it is idempotent and resumable via [`WatcherState`], which persists a scan cursor,
//! the swept/funded/rejected escrow sets, in-flight funding intents, tracked deposits, and
//! the redeems awaiting the user's BTC claim. A crash and restart re-loads the state and
//! continues without double-funding or missing a settlement. Every step is non-fatal per
//! item, so one bad escrow never stalls the rest.

use std::collections::{BTreeMap, HashSet};

use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Txid};
use std::str::FromStr;

use crate::swap::{self, TrackedDeposit};
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
    /// The BTC HTLC refund CLTV. Once the Bitcoin tip passes it and the user still has not
    /// claimed, the watcher takes the BTC back to the reserve (bridge M5). `0` on entries
    /// written by older daemons: those are never auto-refunded.
    #[serde(default)]
    pub locktime: u32,
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
            locktime: l.btc_locktime,
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

/// A redeem the watcher has DECIDED to fund. Written to the state file BEFORE the funding
/// tx is broadcast and updated with the txid the moment the broadcast succeeds, so a crash
/// or a confirmation-wait timeout at any point resumes from the recorded txid (or from the
/// HTLC address) instead of funding the escrow again (bridge H2).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FundingIntent {
    pub escrow_id: String, // hex
    pub hashlock: String,  // hex
    pub script_hex: String,
    pub value_sat: u64,
    pub locktime: u32,
    /// Set once a funding tx has been broadcast (`txid:vout`).
    #[serde(default)]
    pub funding: Option<(String, u32)>,
}

impl FundingIntent {
    fn script(&self) -> Result<ScriptBuf, String> {
        Ok(ScriptBuf::from_bytes(hex::decode(&self.script_hex).map_err(|e| e.to_string())?))
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
    /// Redeems decided but not yet confirmed on Bitcoin (see [`FundingIntent`]).
    #[serde(default)]
    pub funding: Vec<FundingIntent>,
    /// Shield deposits watched for reorgs until buried past any void risk (bridge M2).
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
}

/// ZC blocks to wait before retrying a redeem whose funding hit a transient error.
const RETRY_BACKOFF_BLOCKS: i64 = 120;

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
    /// Operator-funded redeem HTLCs refunded after their CLTV (user never claimed).
    pub refunded: usize,
    /// Tracked shield deposits re-anchored after a Bitcoin reorg.
    pub reanchored: usize,
    /// Funding intents resumed from a previous crash/timeout (reused an existing funding).
    pub resumed: usize,
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

/// Run ONE full watcher pass without intermediate persistence (one-shot callers and tests).
/// The daemon uses [`watcher_tick_persisting`] so funding intents hit disk before broadcast.
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
    watcher_tick_persisting(state, zc, operator_btc, reserve, shield_dest, zbtc_asset, min_finalize_margin, fee_target, &|_| Ok(()))
}

/// Drive one funding intent to a confirmed [`PendingRedeem`]: reuse a recorded or discovered
/// funding, else broadcast one; record the txid via `persist` BEFORE waiting for confirmations.
/// `Ok(None)` when funding is broadcast but not yet confirmed (the intent stays for the next
/// tick); `Ok(Some)` when confirmed.
#[allow(clippy::too_many_arguments)]
fn drive_intent(
    intent: &mut FundingIntent,
    operator_btc: &dyn BtcBackend,
    persist: &dyn Fn(&FundingIntent) -> Result<(), String>,
    report: &mut TickReport,
) -> Result<Option<PendingRedeem>, String> {
    let script = intent.script()?;
    // 1. Find the funding: recorded txid, else an existing UTXO at the HTLC address, else fund.
    let utxo = match &intent.funding {
        Some((txid, vout)) => HtlcUtxo {
            outpoint: OutPoint { txid: Txid::from_str(txid).map_err(|e| e.to_string())?, vout: *vout },
            value: Amount::from_sat(intent.value_sat),
            script: script.clone(),
        },
        None => {
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
            intent.funding = Some((utxo.outpoint.txid.to_string(), utxo.outpoint.vout));
            // The broadcast happened: it must be on disk before anything else can fail.
            persist(intent)?;
            utxo
        }
    };
    // 2. Confirmation: a timeout here leaves the intent (with its txid) for the next tick.
    let confs = operator_btc.tx_confirmations(&utxo.outpoint.txid).unwrap_or(0);
    let need = match operator_btc.network() {
        bitcoin::Network::Regtest => 0,
        bitcoin::Network::Bitcoin => zcrypt_core::spv::min_conf_for(zcrypt_core::spv::BtcNet::Mainnet),
        _ => 1,
    };
    if confs < need {
        if let Err(e) = operator_btc.confirm(&utxo.outpoint.txid) {
            return Err(format!("funding {} not yet confirmed: {e}", utxo.outpoint.txid));
        }
    }
    let funded_at_btc = operator_btc.height().unwrap_or(0);
    Ok(Some(PendingRedeem {
        escrow_id: intent.escrow_id.clone(),
        funding_txid: utxo.outpoint.txid.to_string(),
        vout: utxo.outpoint.vout,
        value_sat: intent.value_sat,
        script_hex: intent.script_hex.clone(),
        hashlock: intent.hashlock.clone(),
        funded_at_btc,
        locktime: intent.locktime,
    }))
}

/// Run ONE full watcher pass, calling `persist` with the whole state at every point where a
/// crash must not lose information (after each funding intent is recorded and after each
/// broadcast). Mutates `state` in place; the caller persists it again after.
#[allow(clippy::too_many_arguments)]
pub fn watcher_tick_persisting(
    state: &mut WatcherState,
    zc: &Zcrypt,
    operator_btc: &dyn BtcBackend,
    reserve: &Key,
    shield_dest: &Address,
    zbtc_asset: u64,
    min_finalize_margin: u64,
    fee_target: u32,
    persist: &dyn Fn(&WatcherState) -> Result<(), String>,
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

    // 2. SHIELD sweep (+ collect deposits to track for reorgs).
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
            for t in sr.tracked {
                if !state.tracked.iter().any(|x| x.escrow_id == t.escrow_id) {
                    state.tracked.push(t);
                }
            }
        }
        Err(e) => {
            scan_ok = false;
            report.errors.push(format!("shield pass: {e}"));
        }
    }
    state.swept = swept.iter().map(hex::encode).collect();

    // 2b. RE-ANCHOR deposits a Bitcoin reorg re-mined elsewhere (bridge M2).
    if !state.tracked.is_empty() {
        let rr = swap::reanchor_reorged_deposits(zc, operator_btc, &mut state.tracked);
        report.reanchored = rr.reanchored.len();
        for (eid, e) in rr.errors {
            report.errors.push(format!("reanchor {}: {e}", hex::encode(eid)));
        }
    }

    // 3. REDEEM: resume in-flight intents first, then plan + fund new ones.
    let mut funded = state.set(&state.funded);
    let mut skip = funded.clone();
    skip.extend(state.set(&state.rejected));
    skip.extend(state.funding.iter().filter_map(|i| hex32(&i.escrow_id)));

    // 3a. Intents left by a previous tick (crash or confirmation timeout).
    let mut remaining = Vec::new();
    for mut intent in std::mem::take(&mut state.funding) {
        let snapshot_persist = |i: &FundingIntent| -> Result<(), String> {
            // Persist the full state with this intent's latest txid.
            let mut st = WatcherState {
                cursor: state.cursor,
                swept: state.swept.clone(),
                funded: state.funded.clone(),
                pending: state.pending.clone(),
                funding: remaining.clone(),
                tracked: state.tracked.clone(),
                rejected: state.rejected.clone(),
                refunded: state.refunded.clone(),
                retry_after: state.retry_after.clone(),
            };
            st.funding.push(i.clone());
            persist(&st)
        };
        match drive_intent(&mut intent, operator_btc, &snapshot_persist, &mut report) {
            Ok(Some(p)) => {
                funded.insert(hex32(&p.escrow_id).unwrap_or([0u8; 32]));
                state.pending.push(p);
                report.locked += 1;
            }
            Ok(None) => remaining.push(intent),
            Err(e) => {
                report.errors.push(format!("redeem-resume {}: {e}", intent.escrow_id));
                remaining.push(intent);
            }
        }
    }
    state.funding = remaining;
    state.funded = funded.iter().map(hex::encode).collect();
    persist(state)?;

    // 3b. New redeems in the scanned range.
    match swap::plan_redeems(zc, operator_btc, reserve, from, tip, zbtc_asset, min_finalize_margin, &skip) {
        Ok(pr) => {
            report.rejected = pr.rejected.len();
            for (eid, why) in pr.rejected {
                // Permanent: never look at this escrow again.
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
                if state.retry_after.get(&h).is_some_and(|&until| tip < until) {
                    continue; // backing off after a transient failure
                }
                let mut intent = FundingIntent {
                    escrow_id: h.clone(),
                    hashlock: hex::encode(plan.hashlock),
                    script_hex: hex::encode(plan.script.as_bytes()),
                    value_sat: plan.value,
                    locktime: plan.btc_locktime,
                    funding: None,
                };
                // The INTENT is on disk before any BTC moves.
                state.funding.push(intent.clone());
                if !state.funded.contains(&h) {
                    state.funded.push(h.clone());
                }
                persist(state)?;
                let idx = state.funding.len() - 1;
                let snapshot_persist = |i: &FundingIntent| -> Result<(), String> {
                    let mut st = WatcherState {
                        cursor: state.cursor,
                        swept: state.swept.clone(),
                        funded: state.funded.clone(),
                        pending: state.pending.clone(),
                        funding: state.funding.clone(),
                        tracked: state.tracked.clone(),
                        rejected: state.rejected.clone(),
                        refunded: state.refunded.clone(),
                        retry_after: state.retry_after.clone(),
                    };
                    st.funding[idx] = i.clone();
                    persist(&st)
                };
                match drive_intent(&mut intent, operator_btc, &snapshot_persist, &mut report) {
                    Ok(Some(p)) => {
                        state.funding.remove(idx);
                        state.pending.push(p);
                        report.locked += 1;
                    }
                    Ok(None) => state.funding[idx] = intent,
                    Err(e) => {
                        report.errors.push(format!("redeem-serve {h}: {e}"));
                        if intent.funding.is_some() {
                            // Broadcast happened: keep the intent so the next tick resumes it.
                            state.funding[idx] = intent;
                        } else {
                            // Nothing was sent: release the slot and back off.
                            state.funding.remove(idx);
                            state.funded.retain(|x| x != &h);
                            state.retry_after.insert(h.clone(), tip + RETRY_BACKOFF_BLOCKS);
                        }
                    }
                }
                persist(state)?;
            }
        }
        Err(e) => {
            scan_ok = false;
            report.errors.push(format!("redeem-serve pass: {e}"));
        }
    }
    state.retry_after.retain(|_, until| *until > tip);

    // 4. REDEEM finalize: detect each user's BTC claim and burn the zBTC; refund after CLTV.
    let btc_tip = operator_btc.height().unwrap_or(0);
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
            Ok(None) => {
                // User has not claimed. Past the CLTV, take the BTC back (bridge M5).
                if p.locktime > 0 && btc_tip >= p.locktime as u64 {
                    let outcome = (|| -> Result<Txid, String> {
                        let fee = swap::htlc_spend_fee_for(operator_btc, fee_target, utxo.value.to_sat())?;
                        operator_btc.refund(&utxo, reserve, p.locktime, shield_dest, fee)
                    })();
                    match outcome {
                        Ok(_txid) => {
                            report.refunded += 1;
                            state.refunded.push(p.escrow_id.clone());
                        }
                        Err(e) => {
                            report.errors.push(format!("refund {}: {e}", p.escrow_id));
                            still_pending.push(p);
                        }
                    }
                } else {
                    still_pending.push(p);
                }
            }
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

/// Load the operator's RESERVE key the way the daemon expects it (bridge L4). Sources, in
/// order of preference:
///
/// 1. `ZCRYPT_RESERVE_KEY_FILE`: a file holding the DERIVED 32-byte secp256k1 key (64 hex
///    chars or 32 raw bytes). This is the key the wallet's `bridge_init` derives as
///    `H("BTCBRDG", wallet_seed)` and whose pubkey is the chain's `zbtc_reserve_pk`. Mount it
///    as a docker secret / 0400 file; it never has to sit in the environment.
/// 2. `ZCRYPT_RESERVE_WALLET_SEED_FILE`: a file holding the operator WALLET seed (32 bytes);
///    the daemon applies the same `H("BTCBRDG", seed)` derivation. Discouraged: that seed
///    also spends the operator's shielded coins.
/// 3. `ZCRYPT_RESERVE_SEED` (legacy env var): the DERIVED key as 64 hex (NOT the wallet
///    seed, despite the name). Visible in `docker inspect` and procfs; prefer 1.
pub fn reserve_key_from_env() -> Result<Key, String> {
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
    if let Ok(hexkey) = std::env::var("ZCRYPT_RESERVE_SEED") {
        let k = crate::parse_secret_bytes(hexkey.trim().as_bytes())?;
        return Ok(Key::from_bytes(&k));
    }
    Err("no reserve key: set ZCRYPT_RESERVE_KEY_FILE (derived key file, preferred), \
         ZCRYPT_RESERVE_WALLET_SEED_FILE (wallet seed file), or ZCRYPT_RESERVE_SEED (derived key hex)"
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_new_fields_and_tolerates_old_files() {
        // An old state file (no funding/tracked/rejected fields) still loads.
        let old = r#"{"cursor":7,"swept":[],"funded":[],"pending":[{"escrow_id":"00","funding_txid":"0000000000000000000000000000000000000000000000000000000000000000","vout":0,"value_sat":1,"script_hex":"","hashlock":"00","funded_at_btc":1}]}"#;
        let st: WatcherState = serde_json::from_str(old).expect("old state loads");
        assert_eq!(st.cursor, 7);
        assert_eq!(st.pending[0].locktime, 0, "old entries carry no locktime and are never auto-refunded");
        assert!(st.funding.is_empty() && st.tracked.is_empty() && st.rejected.is_empty());

        // New fields survive a save/load cycle.
        let mut st = WatcherState::default();
        st.funding.push(FundingIntent {
            escrow_id: "ab".repeat(32),
            hashlock: "cd".repeat(32),
            script_hex: "00".into(),
            value_sat: 5,
            locktime: 900_000,
            funding: Some(("11".repeat(32), 1)),
        });
        st.rejected.push("ef".repeat(32));
        let dir = std::env::temp_dir().join(format!("zcrypt-watcher-test-{}.json", std::process::id()));
        st.save(&dir).unwrap();
        let back = WatcherState::load(&dir);
        let _ = std::fs::remove_file(&dir);
        assert_eq!(back.funding.len(), 1);
        assert_eq!(back.funding[0].funding.as_ref().unwrap().1, 1);
        assert_eq!(back.rejected.len(), 1);
    }

    #[test]
    fn reserve_key_sources_agree_with_the_wallet_derivation() {
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
    }
}
