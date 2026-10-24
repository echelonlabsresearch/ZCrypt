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

/// The public header of a burn-lock transaction (`0x5D`, or `0x67` with the user's Bitcoin
/// claim key up front), as a wallet scanner needs it to recognise its own refund key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnLockFields {
    /// The 33-byte Bitcoin payout key of a `0x67` lock; `None` for a plain `0x5D`.
    pub btc_claim_pk: Option<[u8; 33]>,
    pub value: u64,
    pub asset: u64,
    pub hashlock: [u8; 32],
    pub timeout: u64,
    pub refund_pk: zcrypt_shield::PubKey,
}

/// Parse the body (bytes after the tag) of a plain `0x5D` burn lock:
/// `value(8) ‖ blind(BLIND_BYTES) ‖ asset(8) ‖ hashlock(32) ‖ timeout(8) ‖ refund_pk(64) ‖ stx`.
/// The blind is skipped (it is the escrow's, not the wallet's). Fail-closed on short input.
pub fn parse_burn_lock(payload: &[u8]) -> Option<BurnLockFields> {
    const BB: usize = zcrypt_shield::BLIND_BYTES;
    const A: usize = 8 + BB;
    const H: usize = A + 8;
    const T: usize = H + 32;
    const R: usize = T + 8;
    const HEAD: usize = R + 64;
    if payload.len() < HEAD {
        return None;
    }
    let value = u64::from_le_bytes(payload[0..8].try_into().ok()?);
    let asset = u64::from_le_bytes(payload[A..A + 8].try_into().ok()?);
    let hashlock: [u8; 32] = payload[H..T].try_into().ok()?;
    let timeout = u64::from_le_bytes(payload[T..R].try_into().ok()?);
    let mut refund_pk: zcrypt_shield::PubKey = [0u64; 8];
    for (i, limb) in refund_pk.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(payload[R + i * 8..R + 8 + i * 8].try_into().ok()?);
    }
    Some(BurnLockFields { btc_claim_pk: None, value, asset, hashlock, timeout, refund_pk })
}

/// Parse either burn-lock form from its tag and body: `0x5D` (plain) or `0x67` (with the
/// Bitcoin claim key). Any other tag yields `None`.
pub fn parse_burn_lock_any(tag: u8, body: &[u8]) -> Option<BurnLockFields> {
    match tag {
        0x5D => parse_burn_lock(body),
        0x67 => {
            let (btc_claim_pk, asset, value, hashlock, timeout, refund_pk) = swap::parse_burn_lock_btc(body)?;
            Some(BurnLockFields { btc_claim_pk: Some(btc_claim_pk), value, asset, hashlock, timeout, refund_pk })
        }
        _ => None,
    }
}

/// A bridge or swap HTLC preimage derived from the wallet seed and the HD action index the
/// operation consumed: `H("ZC-BRIDGE-PRE", seed, index)`. Deterministic, so a seed restore
/// can rebuild an in-flight escrow's preimage from the public hashlock (check
/// `htlc_hashlock(preimage) == hashlock`), and unguessable to anyone without the seed.
pub fn bridge_preimage(seed: &[u8; 32], index: u32) -> [u8; 32] {
    zcrypt_core::hash::h(b"ZC-BRIDGE-PRE", &[seed, &index.to_le_bytes()])
}

/// ZC blocks of life a counterparty's swap lock must still have before this wallet reveals
/// the preimage by claiming it. A claim whose escrow expires within a block or two can be
/// accepted into a block and still fail delivery, publishing the preimage for nothing.
pub const SWAP_CLAIM_SAFETY_BLOCKS: u64 = 30;

/// TAKER-side gate before revealing the preimage against the maker's lock (`info` is the
/// consensus view of that escrow). Every field must match what the taker expects: the kind,
/// that it pays `my_pk`, that it refunds to the counterparty, and that it has at least
/// `SWAP_CLAIM_SAFETY_BLOCKS` of life left at `tip`.
pub fn swap_claim_is_safe(
    info: &swap::EscrowInfo,
    tip: u64,
    my_pk: &[u8; 64],
    counterparty_pk: &[u8; 64],
    asset: u64,
    value: u64,
    hashlock: &[u8; 32],
) -> Result<(), String> {
    if info.state != "open" {
        return Err(format!("their lock is {}", info.state));
    }
    if info.kind != "swap" {
        return Err(format!("their escrow is a {} lock, not a swap", if info.kind.is_empty() { "unknown" } else { &info.kind }));
    }
    if info.asset_id != asset || info.value != value || info.hashlock != *hashlock {
        return Err("their lock does not match the agreed terms".to_string());
    }
    if info.party_pk != my_pk.to_vec() {
        return Err("their lock does not pay this wallet".to_string());
    }
    if info.refund_pk != counterparty_pk.to_vec() {
        return Err("their lock refunds to someone other than the counterparty".to_string());
    }
    if info.timeout_height <= tip.saturating_add(SWAP_CLAIM_SAFETY_BLOCKS) {
        return Err(format!(
            "their lock expires at block {} (tip {tip}); fewer than {SWAP_CLAIM_SAFETY_BLOCKS} blocks left, not revealing the preimage",
            info.timeout_height
        ));
    }
    Ok(())
}

/// Extra Bitcoin blocks the operator's CLTV must still have beyond the confirmation target
/// before the user reveals the preimage in a claim, so the claim confirms before the operator
/// could refund.
pub const REDEEM_CLAIM_CLTV_MARGIN: u64 = 6;

/// USER-side gate before spending the operator's redeem HTLC with the preimage: the funding
/// must be buried `min_conf` deep (an RBF replacement of a 0-conf funding would orphan the
/// claim and hand the operator the preimage) and the CLTV must leave room for the claim.
pub fn redeem_claim_is_safe(confirmations: u64, min_conf: u64, locktime: u32, btc_tip: u64, conf_target: u64) -> Result<(), String> {
    if confirmations < min_conf {
        return Err(format!(
            "the operator's funding has {confirmations} confirmation(s), needs {min_conf} before the preimage is revealed"
        ));
    }
    let need = conf_target.saturating_add(REDEEM_CLAIM_CLTV_MARGIN);
    if u64::from(locktime) < btc_tip.saturating_add(need) {
        return Err(format!(
            "the operator's lock (block {locktime}) is within {need} blocks of the tip ({btc_tip}); too close to claim safely"
        ));
    }
    Ok(())
}

/// Pay `amount` from the self-custody wallet to an external `dest` address: build, sign
/// and broadcast through Esplora with the wallet's own keys. Returns the txid and the fee
/// paid (satoshis). Nothing but the signed transaction leaves the process.
pub fn selfcustody_send(
    sc: &crate::selfcustody::SelfCustodyBtc,
    dest: &bitcoin::Address,
    amount: Amount,
) -> Result<(bitcoin::Txid, u64), String> {
    let change = sc.fresh_change_address()?.script_pubkey();
    let utxos = sc.esplora.wallet_utxos(&sc.hd)?;
    let fee_rate = sc.esplora.fee_rate_sat_vb(sc.conf_target().max(3))?;
    let signed = crate::txbuilder::build_and_sign(&sc.hd, &utxos, dest.script_pubkey(), amount.to_sat(), change, fee_rate)?;
    sc.esplora.broadcast(&signed.hex)?;
    Ok((signed.txid, signed.fee))
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

    fn dummy_stx() -> zcrypt_core::shield_tx::ShieldTx {
        zcrypt_core::shield_tx::ShieldTx {
            inputs: vec![],
            output_commitments: vec![],
            enc_notes: vec![],
            fee: 0,
            root: [0u64; 8],
            proof: vec![],
        }
    }

    #[test]
    fn burn_lock_parsers_read_the_widened_blind_layout() {
        let blind: zcrypt_shield::Blind = core::array::from_fn(|i| 0x1111 * (i as u64 + 1));
        let refund: zcrypt_shield::PubKey = core::array::from_fn(|i| 0xABCD + i as u64);
        let lock = [7u8; 32];
        let stx = dummy_stx();
        let opening = swap::dummy_opening();
        let plain = swap::burn_lock_tx(123_456, &blind, 99, &lock, 4_242, &refund, &stx, &opening);
        assert_eq!(plain[0], 0x5D);
        let f = parse_burn_lock_any(0x5D, &plain[1..]).expect("0x5D parses");
        assert_eq!(f, BurnLockFields { btc_claim_pk: None, value: 123_456, asset: 99, hashlock: lock, timeout: 4_242, refund_pk: refund });
        let btc_pk = Key::from_bytes(&[5u8; 32]).pk;
        let with_btc = swap::burn_lock_btc_tx(&btc_pk, 123_456, &blind, 99, &lock, 4_242, &refund, &stx, &opening);
        assert_eq!(with_btc[0], 0x67);
        let g = parse_burn_lock_any(0x67, &with_btc[1..]).expect("0x67 parses");
        assert_eq!(g.btc_claim_pk, Some(btc_pk.inner.serialize()));
        assert_eq!((g.value, g.asset, g.hashlock, g.timeout, g.refund_pk), (123_456, 99, lock, 4_242, refund));
        // A body truncated inside the refund key is rejected, never mis-sliced.
        assert!(parse_burn_lock_any(0x5D, &plain[1..plain.len().min(1 + 8 + zcrypt_shield::BLIND_BYTES + 8 + 32 + 8 + 10)]).is_none());
        assert!(parse_burn_lock_any(0x62, &plain[1..]).is_none());
    }

    #[test]
    fn swap_lock_parser_round_trips_swap_lock_tx_bytes() {
        let blind: zcrypt_shield::Blind = core::array::from_fn(|i| 77 + i as u64);
        let gas_blind: zcrypt_shield::Blind = core::array::from_fn(|i| 1_000 + i as u64);
        let party: zcrypt_shield::PubKey = core::array::from_fn(|i| 0x10 + i as u64);
        let refund: zcrypt_shield::PubKey = core::array::from_fn(|i| 0x20 + i as u64);
        let lock = [9u8; 32];
        let stx = dummy_stx();
        let claim = swap::dummy_opening();
        let refund_open = swap::dummy_opening();
        let tx = swap::swap_lock_tx(555, &blind, 3, &lock, 9_999, &party, &refund, &gas_blind, &stx, &stx, &claim, &refund_open);
        assert_eq!(tx[0], 0x62);
        let (v, b, a, h, t, c, r) = swap::parse_swap_lock(&tx[1..]).expect("0x62 parses");
        assert_eq!((v, b, a, h, t, c, r), (555, blind, 3, lock, 9_999, party, refund));
    }

    #[test]
    fn bridge_preimage_is_deterministic_per_index_and_seed() {
        let seed = [3u8; 32];
        let a = bridge_preimage(&seed, 0);
        assert_eq!(a, bridge_preimage(&seed, 0));
        assert_ne!(a, bridge_preimage(&seed, 1));
        assert_ne!(a, bridge_preimage(&[4u8; 32], 0));
        assert_eq!(a.len(), swap::PREIMAGE_LEN);
    }

    fn info(state: &str, kind: &str, party: &[u8; 64], refund: &[u8; 64], timeout: u64) -> swap::EscrowInfo {
        swap::EscrowInfo {
            asset_id: 1,
            value: 10,
            hashlock: [1u8; 32],
            timeout_height: timeout,
            state: state.into(),
            kind: kind.into(),
            btc_claim_pk: vec![],
            party_pk: party.to_vec(),
            refund_pk: refund.to_vec(),
            claim_commitment: vec![],
            claim_enc_note: vec![],
            refund_commitment: vec![],
            refund_enc_note: vec![],
            sponsor_for: vec![],
            sponsor_used: false,
        }
    }

    #[test]
    fn taker_claim_gate_checks_kind_recipient_refund_and_life() {
        let me = [1u8; 64];
        let them = [2u8; 64];
        let ok = info("open", "swap", &me, &them, 1_000);
        assert!(swap_claim_is_safe(&ok, 900, &me, &them, 1, 10, &[1u8; 32]).is_ok());
        assert!(swap_claim_is_safe(&ok, 1_000 - SWAP_CLAIM_SAFETY_BLOCKS, &me, &them, 1, 10, &[1u8; 32]).is_err());
        assert!(swap_claim_is_safe(&info("open", "burn", &me, &them, 1_000), 900, &me, &them, 1, 10, &[1u8; 32]).is_err());
        assert!(swap_claim_is_safe(&info("open", "swap", &them, &them, 1_000), 900, &me, &them, 1, 10, &[1u8; 32]).is_err());
        assert!(swap_claim_is_safe(&info("open", "swap", &me, &me, 1_000), 900, &me, &them, 1, 10, &[1u8; 32]).is_err());
        assert!(swap_claim_is_safe(&ok, 900, &me, &them, 1, 11, &[1u8; 32]).is_err());
        assert!(swap_claim_is_safe(&info("claimed", "swap", &me, &them, 1_000), 900, &me, &them, 1, 10, &[1u8; 32]).is_err());
    }

    #[test]
    fn redeem_claim_gate_needs_confirmations_and_cltv_room() {
        assert!(redeem_claim_is_safe(6, 6, 1_000, 900, 6).is_ok());
        assert!(redeem_claim_is_safe(5, 6, 1_000, 900, 6).is_err());
        assert!(redeem_claim_is_safe(6, 6, 911, 900, 6).is_err());
        assert!(redeem_claim_is_safe(6, 6, 912, 900, 6).is_ok());
    }
}
