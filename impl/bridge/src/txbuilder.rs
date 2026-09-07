//! Local Bitcoin transaction construction + signing for the self-custody wallet.
//! Selects UTXOs, sizes the fee, adds change, and signs each input with BIP-143
//! (P2WPKH segwit) using keys derived from the mnemonic — so no node holds the keys
//! and nothing but the finished, signed transaction leaves the process.
//!
//! Money-critical: a signing bug loses funds. The signatures produced here are
//! independently re-verified in the tests (recompute the sighash, verify the ECDSA
//! signature against the derived pubkey), which is exactly the check Bitcoin's script
//! interpreter does — so a passing test means a node would accept the input.

use crate::esplora::WalletUtxo;
use crate::hdwallet::HdWallet;
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use std::str::FromStr;

/// Outputs below this many satoshis are uneconomical to create (dust); change under it
/// is dropped into the fee instead. A safe floor for P2WPKH/P2WSH outputs.
const DUST: u64 = 330;

/// Approx virtual sizes (vB) for fee estimation. A P2WPKH input is ~68 vB spent; an
/// output ~31–43 vB; fixed tx overhead ~11 vB. We slightly over-estimate outputs (43)
/// so the fee is never short.
const VB_INPUT: u64 = 68;
const VB_OUTPUT: u64 = 43;
const VB_OVERHEAD: u64 = 11;

/// A signed, ready-to-broadcast transaction.
pub struct SignedTx {
    pub txid: Txid,
    pub hex: String,
    /// The outpoint of output 0 (the primary destination), for the caller to reference.
    pub vout0: OutPoint,
    /// Fee paid (satoshis).
    pub fee: u64,
}

fn est_fee(n_in: usize, n_out: usize, fee_rate_sat_vb: f64) -> u64 {
    let vsize = VB_OVERHEAD + VB_INPUT * n_in as u64 + VB_OUTPUT * n_out as u64;
    (vsize as f64 * fee_rate_sat_vb).ceil() as u64
}

/// Build + sign a transaction paying `amount` to `dest_spk`, funded from the wallet's
/// `utxos`, with change back to `change_spk`. `fee_rate_sat_vb` sets the fee. Selects the
/// fewest (largest-first) confirmed inputs that cover amount + fee; drops dust change into
/// the fee. Signs every input with BIP-143 P2WPKH.
pub fn build_and_sign(
    wallet: &HdWallet,
    utxos: &[WalletUtxo],
    dest_spk: ScriptBuf,
    amount: u64,
    change_spk: ScriptBuf,
    fee_rate_sat_vb: f64,
) -> Result<SignedTx, String> {
    if amount == 0 {
        return Err("amount must be positive".into());
    }
    // Bridge M4: never trust a fee oracle blindly. Clamp the rate, and below refuse a fee
    // that would eat more than a quarter of the amount (dust-level amounts excepted by the
    // relay floor). The chosen fee is returned in `SignedTx.fee` so a UI can show it.
    let fee_rate_sat_vb = crate::cap_fee_rate(fee_rate_sat_vb);
    // Spend confirmed coins only, largest first (fewest inputs).
    let mut avail: Vec<&WalletUtxo> = utxos.iter().filter(|u| u.utxo.confirmed).collect();
    avail.sort_by(|a, b| b.utxo.value.cmp(&a.utxo.value));

    // Accumulate inputs until they cover amount + the fee for the current input count
    // (assume 2 outputs: destination + change).
    let mut chosen: Vec<&WalletUtxo> = Vec::new();
    let mut in_total: u64 = 0;
    for u in &avail {
        chosen.push(u);
        in_total += u.utxo.value;
        let fee = est_fee(chosen.len(), 2, fee_rate_sat_vb);
        if in_total >= amount + fee {
            break;
        }
    }
    let fee_two_out = est_fee(chosen.len(), 2, fee_rate_sat_vb);
    if in_total < amount + fee_two_out {
        let have = in_total;
        return Err(format!(
            "insufficient funds: need ~{} sat (amount {amount} + fee), confirmed balance {have} sat across {} coin(s)",
            amount + fee_two_out,
            chosen.len()
        ));
    }

    // Decide change: if the change output would be dust, drop it (add to fee, 1 output).
    let mut change = in_total - amount - fee_two_out;
    let mut outputs = vec![TxOut { value: Amount::from_sat(amount), script_pubkey: dest_spk }];
    let fee = if change > DUST {
        outputs.push(TxOut { value: Amount::from_sat(change), script_pubkey: change_spk });
        fee_two_out
    } else {
        // No change output: recompute fee for a single output; the remainder is the fee.
        let fee_one_out = est_fee(chosen.len(), 1, fee_rate_sat_vb);
        change = 0;
        in_total - amount - if in_total >= amount + fee_one_out { fee_one_out } else { fee_two_out }
    };
    let _ = change;
    // Bridge M4: refuse to pay more than a quarter of the amount in fees (the relay floor for
    // a 1-in/2-out P2WPKH tx at 1 sat/vB is the only exception, for dust-level amounts).
    let floor = est_fee(chosen.len(), 2, 1.0);
    if fee > (amount / crate::MAX_FEE_FRACTION_DEN).max(floor) {
        return Err(format!(
            "refusing to build: fee {fee} sats exceeds a quarter of the {amount}-sat amount \
             (fee rate {fee_rate_sat_vb:.1} sat/vB); lower the rate or move a larger amount"
        ));
    }

    // Build the unsigned skeleton (RBF-enabled, no locktime).
    let input: Vec<TxIn> = chosen
        .iter()
        .map(|u| {
            Ok(TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(&u.utxo.txid).map_err(|e| format!("bad utxo txid: {e}"))?,
                    vout: u.utxo.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
        })
        .collect::<Result<_, String>>()?;
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input,
        output: outputs,
    };

    // Sign each P2WPKH input (BIP-143). The witness is [DER sig ‖ sighash type, pubkey].
    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(&tx);
    let mut witnesses = Vec::with_capacity(chosen.len());
    for (i, u) in chosen.iter().enumerate() {
        let sk = wallet.signing_key(u.change, u.index)?;
        let pk = sk.public_key(&secp); // compressed
        let wpkh = pk.wpubkey_hash().map_err(|e| format!("uncompressed key: {e}"))?;
        let spk = ScriptBuf::new_p2wpkh(&wpkh); // the P2WPKH output being spent
        let sighash = cache
            .p2wpkh_signature_hash(i, &spk, Amount::from_sat(u.utxo.value), EcdsaSighashType::All)
            .map_err(|e| e.to_string())?;
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_ecdsa(&msg, &sk.inner);
        let mut ser = sig.serialize_der().to_vec();
        ser.push(EcdsaSighashType::All as u8);
        let mut w = Witness::new();
        w.push(ser);
        w.push(pk.to_bytes());
        witnesses.push(w);
    }
    for (i, w) in witnesses.into_iter().enumerate() {
        tx.input[i].witness = w;
    }

    let txid = tx.compute_txid();
    let hex = bitcoin::consensus::encode::serialize_hex(&tx);
    Ok(SignedTx {
        txid,
        hex,
        vout0: OutPoint { txid, vout: 0 },
        fee,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esplora::Utxo;
    use bitcoin::secp256k1::ecdsa;
    use bitcoin::Network;

    const MN: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Build a fake confirmed UTXO owned by the wallet at (change,index) with `value` sats.
    fn wu(change: u32, index: u32, value: u64, txid_byte: u8) -> WalletUtxo {
        WalletUtxo {
            utxo: Utxo {
                txid: hex::encode([txid_byte; 32]),
                vout: 0,
                value,
                confirmed: true,
                block_height: Some(1),
            },
            change,
            index,
            address: String::new(),
        }
    }

    #[test]
    fn builds_signs_and_signatures_verify() {
        let w = HdWallet::from_mnemonic(MN, "", Network::Signet).unwrap();
        // Two inputs the wallet owns (receive/0 and change/3), paying to some address.
        let utxos = vec![wu(0, 0, 100_000, 0xa1), wu(1, 3, 60_000, 0xb2)];
        let dest = w.receive_address(5).unwrap().script_pubkey();
        let change = w.change_address(9).unwrap().script_pubkey();

        let signed = build_and_sign(&w, &utxos, dest.clone(), 120_000, change, 2.0).unwrap();
        // Decode the signed tx back.
        let raw = hex::decode(&signed.hex).unwrap();
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&raw).unwrap();
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output[0].value.to_sat(), 120_000);
        assert!(signed.fee > 0);

        // INDEPENDENTLY verify each input's signature — the real correctness gate.
        let secp = Secp256k1::new();
        let mut cache = SighashCache::new(&tx);
        for (i, u) in utxos.iter().enumerate() {
            let sk = w.signing_key(u.change, u.index).unwrap();
            let pk = sk.public_key(&secp);
            let spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap());
            let sighash = cache
                .p2wpkh_signature_hash(i, &spk, Amount::from_sat(u.utxo.value), EcdsaSighashType::All)
                .unwrap();
            let wit = &tx.input[i].witness;
            let sig_bytes = wit.nth(0).unwrap(); // DER ‖ sighash type
            let pk_bytes = wit.nth(1).unwrap();
            assert_eq!(pk_bytes, pk.to_bytes(), "witness pubkey matches the derived key");
            let der = &sig_bytes[..sig_bytes.len() - 1];
            let sig = ecdsa::Signature::from_der(der).unwrap();
            let msg = Message::from_digest(sighash.to_byte_array());
            secp.verify_ecdsa(&msg, &sig, &pk.inner)
                .unwrap_or_else(|e| panic!("input {i} signature INVALID: {e}"));
        }
    }

    #[test]
    fn conservation_inputs_equal_outputs_plus_fee() {
        let w = HdWallet::from_mnemonic(MN, "", Network::Signet).unwrap();
        let utxos = vec![wu(0, 0, 100_000, 0xc3)];
        let dest = w.receive_address(1).unwrap().script_pubkey();
        let change = w.change_address(0).unwrap().script_pubkey();
        let signed = build_and_sign(&w, &utxos, dest, 40_000, change, 1.5).unwrap();
        let raw = hex::decode(&signed.hex).unwrap();
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&raw).unwrap();
        let out_total: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        // inputs (100_000) == outputs + fee, exactly (no value created or lost).
        assert_eq!(100_000, out_total + signed.fee);
    }

    #[test]
    fn rejects_insufficient_funds() {
        let w = HdWallet::from_mnemonic(MN, "", Network::Signet).unwrap();
        let utxos = vec![wu(0, 0, 5_000, 0xd4)];
        let dest = w.receive_address(1).unwrap().script_pubkey();
        let change = w.change_address(0).unwrap().script_pubkey();
        assert!(build_and_sign(&w, &utxos, dest, 50_000, change, 2.0).is_err());
    }
}
