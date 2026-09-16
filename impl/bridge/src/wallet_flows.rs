//! Wallet-side bridge flows: the USER half of the operator-served redeem and the persisted
//! public shield. These are the pieces the desktop wallet drives; the operator half lives in
//! `watcher` / `swap::plan_redeems`.

use bitcoin::{Amount, PublicKey, ScriptBuf};

use crate::swap::{self, find_funded_htlc};
use crate::{htlc_script, BtcBackend, HtlcUtxo};

/// How far (in Bitcoin blocks, either side) the operator's chosen CLTV may sit from the value
/// the user computes from its own view of the two tips. The operator derives the lock from
/// `redeem_btc_locktime_for(net, btc_tip, zc_tip, timeout)` at its own poll tick, so the two
/// views differ by at most a few blocks of drift on either chain.
pub const REDEEM_LOCKTIME_SEARCH_RADIUS: u32 = 12;

/// The candidate CLTVs (and scripts) the operator may have funded for a burn escrow, centred
/// on what the lock rule yields from the caller's current tips. Deterministic and
/// side-effect free; the caller looks each script up.
pub fn redeem_candidate_scripts(
    network: bitcoin::Network,
    btc_tip: u64,
    zc_tip: u64,
    zc_timeout: u64,
    hashlock: &[u8; 32],
    user_btc_pk: &PublicKey,
    reserve_pk: &PublicKey,
) -> Vec<(u32, ScriptBuf)> {
    let Ok(centre) = swap::redeem_btc_locktime_for(network, btc_tip, zc_tip, zc_timeout) else {
        return Vec::new();
    };
    let lo = centre.saturating_sub(REDEEM_LOCKTIME_SEARCH_RADIUS);
    let hi = centre.saturating_add(REDEEM_LOCKTIME_SEARCH_RADIUS);
    (lo..=hi).map(|lt| (lt, htlc_script(hashlock, user_btc_pk, reserve_pk, lt))).collect()
}

/// Look for the operator's funded HTLC for a burn escrow: any candidate script holding at
/// least `value`. Returns the UTXO and the CLTV it was built with, or `None` if nothing is
/// funded yet. The caller polls this with a bounded wait.
#[allow(clippy::too_many_arguments)]
pub fn find_operator_redeem_htlc(
    user_btc: &dyn BtcBackend,
    zc_tip: u64,
    zc_timeout: u64,
    hashlock: &[u8; 32],
    user_btc_pk: &PublicKey,
    reserve_pk: &PublicKey,
    value: Amount,
) -> Result<Option<(HtlcUtxo, u32)>, String> {
    let btc_tip = user_btc.height()?;
    for (lt, script) in
        redeem_candidate_scripts(user_btc.network(), btc_tip, zc_tip, zc_timeout, hashlock, user_btc_pk, reserve_pk)
    {
        if let Some(u) = find_funded_htlc(user_btc, &script, value)? {
            return Ok(Some((u, lt)));
        }
    }
    Ok(None)
}

/// The exact Bitcoin HTLC script a public shield funded, rebuilt from persisted parameters
/// (no dependence on current chain state: the reserve key may rotate later).
pub fn shield_script(hashlock: &[u8; 32], reserve_pk: &PublicKey, refund_pk: &PublicKey, btc_locktime: u32) -> ScriptBuf {
    htlc_script(hashlock, reserve_pk, refund_pk, btc_locktime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Key;

    #[test]
    fn candidate_window_is_centred_on_the_lock_rule_and_bounded() {
        let net = bitcoin::Network::Bitcoin;
        let user = Key::from_bytes(&[1u8; 32]).pk;
        let reserve = Key::from_bytes(&[2u8; 32]).pk;
        let lock = [3u8; 32];
        let (btc_tip, zc_tip) = (800_000u64, 5_000u64);
        let timeout = zc_tip + swap::zc_redeem_timeout_blocks(net);
        let centre = swap::redeem_btc_locktime_for(net, btc_tip, zc_tip, timeout).unwrap();
        let c = redeem_candidate_scripts(net, btc_tip, zc_tip, timeout, &lock, &user, &reserve);
        assert_eq!(c.len(), 2 * REDEEM_LOCKTIME_SEARCH_RADIUS as usize + 1);
        assert_eq!(c[REDEEM_LOCKTIME_SEARCH_RADIUS as usize].0, centre);
        assert_eq!(c[REDEEM_LOCKTIME_SEARCH_RADIUS as usize].1, htlc_script(&lock, &user, &reserve, centre));
        // A too-short escrow yields no candidates (the operator would refuse to fund it).
        let short = zc_tip + swap::min_redeem_margin_blocks(net) - 1;
        assert!(redeem_candidate_scripts(net, btc_tip, zc_tip, short, &lock, &user, &reserve).is_empty());
    }
}
