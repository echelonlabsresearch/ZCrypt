//! Self-custody Bitcoin backend for the bridge's USER side. Provides the same
//! operations the atomic swap needs — fund an HTLC, claim/refund it, read the tip,
//! wait for confirmations, extract a revealed preimage, report balance — but with:
//!
//!   * keys from the BIP-39 mnemonic ([`HdWallet`]), never a node's wallet,
//!   * chain data from an [`Esplora`] endpoint, never a local full node,
//!   * transactions built and signed locally ([`crate::txbuilder`]).
//!
//! So the user's mnemonic backs up their Bitcoin, and no bitcoind is required. The
//! bridge/LP operator can still run its own node; this is the user half.

use crate::esplora::Esplora;
use crate::hdwallet::HdWallet;
use crate::txbuilder;
use crate::{htlc_address, HtlcUtxo, Key};
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Address, Amount, Network, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness};
use std::str::FromStr;

pub struct SelfCustodyBtc {
    pub hd: HdWallet,
    pub esplora: Esplora,
    network: Network,
}

impl SelfCustodyBtc {
    /// Build from the mnemonic + an Esplora endpoint for `network` (account 0).
    pub fn new(mnemonic: &str, passphrase: &str, network: Network, esplora_url: &str) -> Result<Self, String> {
        Self::new_account(mnemonic, passphrase, network, esplora_url, 0)
    }

    /// Build on a specific BIP-84 account. Account 0 is the user; the demo bridge/LP uses
    /// account 1 so its addresses (and UTXOs) are distinct from the user's under one seed.
    /// A real LP is a separate operator with its own mnemonic + endpoint.
    pub fn new_account(
        mnemonic: &str,
        passphrase: &str,
        network: Network,
        esplora_url: &str,
        account: u32,
    ) -> Result<Self, String> {
        // Money-critical guard: a mainnet wallet pointed at a signet/testnet/regtest
        // Esplora would derive real `bc1…` addresses while every UTXO/fee/header/broadcast
        // call hit a DIFFERENT chain — balances read as 0 and a real broadcast could target
        // the wrong network. The endpoint path names the network, so catch the mismatch here
        // (the single constructor every self-custody path flows through). Only enforced for
        // mainnet, to avoid blocking custom self-hosted test endpoints.
        if network == Network::Bitcoin {
            let u = esplora_url.to_ascii_lowercase();
            if u.contains("signet") || u.contains("testnet") || u.contains("regtest") {
                return Err(format!(
                    "Bitcoin mainnet is configured, but the Esplora endpoint ({esplora_url}) \
                     looks like a test network. Point esplora_url at a MAINNET endpoint \
                     (e.g. https://blockstream.info/api) before moving real BTC."
                ));
            }
        }
        let hd = HdWallet::from_mnemonic_account(mnemonic, passphrase, network, account)?;
        Ok(Self { hd, esplora: Esplora::new(esplora_url), network })
    }

    /// The wallet's first receiving address (the deposit address to fund from a faucet
    /// or another wallet). Restorable from the mnemonic alone.
    pub fn receive_address(&self) -> Result<Address, String> {
        self.hd.receive_address(0)
    }

    /// The `index`-th receiving address (BIP-84 external chain). Use a fresh index as the
    /// payout destination of each redeem instead of always `receive_address()` (index 0),
    /// so an observer cannot cluster all of a user's redeems by one address (privacy H3).
    /// Restorable: the gap-limit scan finds every index with history.
    pub fn receive_address_at(&self, index: u32) -> Result<Address, String> {
        self.hd.receive_address(index)
    }

    /// Gap-limit scan of one chain (0 = receive, 1 = change): the index right after the
    /// last address with on-chain history, stopping once `GAP` consecutive unused
    /// addresses have been seen (so a restored wallet lands on the same index a running
    /// one would).
    fn first_unused_index(&self, change: u32) -> Result<u32, String> {
        const GAP: u32 = 20;
        let mut last_used: Option<u32> = None;
        let mut unused_run = 0u32;
        let mut index = 0u32;
        while unused_run < GAP {
            let addr = self.hd.address(change, index)?.to_string();
            if self.esplora.address_used(&addr)? {
                last_used = Some(index);
                unused_run = 0;
            } else {
                unused_run += 1;
            }
            index += 1;
        }
        Ok(last_used.map(|u| u + 1).unwrap_or(0))
    }

    /// A FRESH (never used) receiving address. Reusing one Bitcoin address for every
    /// bridge deposit lets an observer cluster all of a user's activity; rotate instead
    /// (privacy H3). If the endpoint cannot be reached the error is returned: silently
    /// falling back to index 0 would reuse the most-used address (bridge L7).
    pub fn fresh_receive_address(&self) -> Result<Address, String> {
        let i = self.first_unused_index(0)?;
        self.hd.receive_address(i)
    }

    /// A FRESH change address (see [`Self::fresh_receive_address`]).
    pub fn fresh_change_address(&self) -> Result<Address, String> {
        let i = self.first_unused_index(1)?;
        self.hd.change_address(i)
    }

    /// The fee (satoshis) and rate (sat/vB) a funding of `amount` would pay right now, so a
    /// UI can show the user BEFORE signing (bridge M4). Uses the same capped estimator the
    /// real build uses.
    pub fn estimate_fund_fee(&self, amount: Amount) -> Result<(u64, f64), String> {
        let utxos = self.esplora.wallet_utxos(&self.hd)?;
        let fee_rate = self.esplora.fee_rate_sat_vb(self.conf_target().max(3))?;
        let dest = self.hd.receive_address(0)?.script_pubkey();
        let change = self.hd.change_address(0)?.script_pubkey();
        let signed = txbuilder::build_and_sign(&self.hd, &utxos, dest, amount.to_sat(), change, fee_rate)?;
        Ok((signed.fee, fee_rate))
    }

    /// Confirmed + unconfirmed balance (satoshis), summed over the wallet's UTXOs.
    /// Does a full gap-limit scan (many Esplora calls) — use for spending decisions.
    pub fn balance_sats(&self) -> Result<u64, String> {
        self.esplora.wallet_balance(&self.hd)
    }

    /// Fast balance of just the primary deposit address (receive/0) — one Esplora call.
    /// This is what a user funds from a faucet, so it's the right number for the UI.
    pub fn deposit_balance_sats(&self) -> Result<u64, String> {
        let addr = self.receive_address()?.to_string();
        Ok(self.esplora.address_utxos(&addr)?.iter().map(|u| u.value).sum())
    }

    /// Current chain tip (for HTLC locktime math).
    pub fn height(&self) -> Result<u64, String> {
        self.esplora.tip_height()
    }

    /// Confirmations to treat a tx as final — aligned with SPV `min_conf`.
    pub fn conf_target(&self) -> u32 {
        match self.network {
            Network::Bitcoin => zcrypt_core::spv::min_conf_for(zcrypt_core::spv::BtcNet::Mainnet) as u32,
            Network::Signet => zcrypt_core::spv::min_conf_for(zcrypt_core::spv::BtcNet::Signet) as u32,
            Network::Regtest => 0,
            _ => 1,
        }
    }

    /// Wait until `txid` reaches [`Self::conf_target`] confirmations.
    pub fn confirm(&self, txid: &Txid) -> Result<(), String> {
        self.esplora.wait_confirmed(&txid.to_string(), self.conf_target())
    }

    /// [`Self::confirm`] reporting `(have, need)` confirmations on every poll.
    pub fn confirm_with(&self, txid: &Txid, on_conf: &dyn Fn(u32, u32)) -> Result<(), String> {
        self.esplora.wait_confirmed_with(&txid.to_string(), self.conf_target(), on_conf)
    }

    /// Fund an HTLC: build a tx from our own UTXOs paying `amount` to the HTLC's P2WSH
    /// address (change back to a FRESH change address), sign locally, broadcast via
    /// Esplora, and block until confirmed. Returns the funding UTXO (output 0).
    ///
    /// If the confirmation wait times out the funding is still on the network; recover it
    /// with [`crate::swap::find_funded_htlc`] + [`crate::swap::resume_public_shield`]
    /// instead of funding again (bridge L3).
    pub fn fund_htlc(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
        let utxo = self.fund_htlc_unconfirmed(script, amount)?;
        self.esplora.wait_confirmed(&utxo.outpoint.txid.to_string(), self.conf_target()).map_err(|e| {
            format!(
                "{e}; the funding tx {} IS broadcast: resume from it rather than funding again",
                utxo.outpoint.txid
            )
        })?;
        Ok(utxo)
    }

    /// Build, sign and broadcast the HTLC funding tx; return its UTXO without waiting for
    /// confirmations (the caller persists the txid, then waits).
    pub fn fund_htlc_unconfirmed(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
        let dest = htlc_address(script, self.network).script_pubkey();
        let change = self.fresh_change_address()?.script_pubkey();
        let utxos = self.esplora.wallet_utxos(&self.hd)?;
        let fee_rate = self.esplora.fee_rate_sat_vb(self.conf_target().max(3))?;
        let signed = txbuilder::build_and_sign(&self.hd, &utxos, dest, amount.to_sat(), change, fee_rate)?;
        self.esplora.broadcast(&signed.hex)?;
        Ok(HtlcUtxo { outpoint: signed.vout0, value: amount, script: script.clone() })
    }

    /// Unspent outputs at the HTLC's P2WSH address (confirmed or not), via Esplora.
    pub fn htlc_utxos(&self, script: &ScriptBuf) -> Result<Vec<HtlcUtxo>, String> {
        let addr = htlc_address(script, self.network).to_string();
        let mut out = Vec::new();
        for u in self.esplora.address_utxos(&addr)? {
            let txid = Txid::from_str(&u.txid).map_err(|e| e.to_string())?;
            out.push(HtlcUtxo {
                outpoint: bitcoin::OutPoint { txid, vout: u.vout },
                value: Amount::from_sat(u.value),
                script: script.clone(),
            });
        }
        Ok(out)
    }

    /// The block `txid` is confirmed in (internal byte order), or `None` while unconfirmed.
    pub fn tx_block_hash(&self, txid: &Txid) -> Result<Option<[u8; 32]>, String> {
        Ok(self.esplora.tx_status(&txid.to_string())?.map(|(_, h)| h))
    }

    /// Spend an HTLC's **claim** branch with `preimage`, signed by `claim`, paying `dest`.
    pub fn claim(&self, utxo: &HtlcUtxo, preimage: &[u8], claim: &Key, dest: &Address, fee: Amount) -> Result<Txid, String> {
        let witness = |sig: Vec<u8>| {
            let mut w = Witness::new();
            w.push(sig);
            w.push(preimage);
            w.push([1u8]); // OP_IF selector = true
            w.push(utxo.script.as_bytes());
            w
        };
        self.spend_htlc(utxo, claim, dest, fee, bitcoin::absolute::LockTime::ZERO, witness)
    }

    /// Spend an HTLC's **refund** branch after `locktime`, signed by `refund`.
    pub fn refund(&self, utxo: &HtlcUtxo, refund: &Key, locktime: u32, dest: &Address, fee: Amount) -> Result<Txid, String> {
        let lt = bitcoin::absolute::LockTime::from_consensus(locktime);
        let witness = |sig: Vec<u8>| {
            let mut w = Witness::new();
            w.push(sig);
            w.push([] as [u8; 0]); // OP_IF selector = false
            w.push(utxo.script.as_bytes());
            w
        };
        self.spend_htlc(utxo, refund, dest, fee, lt, witness)
    }

    /// Build + sign a 1-in/1-out P2WSH HTLC spend (BIP-143) and broadcast it via Esplora.
    fn spend_htlc(
        &self,
        utxo: &HtlcUtxo,
        key: &Key,
        dest: &Address,
        fee: Amount,
        locktime: bitcoin::absolute::LockTime,
        mk_witness: impl Fn(Vec<u8>) -> Witness,
    ) -> Result<Txid, String> {
        if fee >= utxo.value {
            return Err("HTLC fee exceeds the locked value".into());
        }
        // 0xFFFFFFFD on both branches: non-final (CLTV enforced on the refund) and
        // BIP-125 RBF-signalling, so a stuck claim or refund can be fee-bumped (bridge L4).
        let sequence = crate::HTLC_SPEND_SEQUENCE;
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: locktime,
            input: vec![TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: utxo.value - fee, script_pubkey: dest.script_pubkey() }],
        };
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .p2wsh_signature_hash(0, &utxo.script, utxo.value, EcdsaSighashType::All)
            .map_err(|e| e.to_string())?;
        let secp = Secp256k1::new();
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_ecdsa(&msg, &key.sk);
        let mut ser = sig.serialize_der().to_vec();
        ser.push(EcdsaSighashType::All as u8);
        tx.input[0].witness = mk_witness(ser);
        let hex = bitcoin::consensus::encode::serialize_hex(&tx);
        let txid = self.esplora.broadcast(&hex)?;
        Txid::from_str(&txid).map_err(|e| e.to_string())
    }

    /// The preimage revealed in a claim tx (witness item 1), read via Esplora. Only a txid
    /// is known here, so the first input whose item 1 is exactly 32 bytes is taken (the
    /// caller checks it against the hashlock). A refund (empty item 1) or any other shape
    /// gives `None`, so a refund is never mistaken for a claim (bridge M11). With the HTLC
    /// outpoint in hand use [`Self::htlc_spend_in_tx`], which matches the input by prevout.
    pub fn preimage_from_claim(&self, txid: &Txid) -> Option<Vec<u8>> {
        let v = self.esplora.tx_json(&txid.to_string()).ok()?;
        v["vin"].as_array()?.iter().find_map(|vin| {
            let raw = hex::decode(vin["witness"].as_array()?.get(1)?.as_str()?).ok()?;
            (raw.len() == crate::HTLC_PREIMAGE_LEN).then_some(raw)
        })
    }

    /// How `spend_txid` spends the HTLC `outpoint`, read via Esplora: the input is selected
    /// by its prevout (never by position, a claim can be batched with other inputs), and its
    /// witness item 1 is classified by [`crate::classify_htlc_witness_item`]. Errors when no
    /// input of the tx spends `outpoint` (bridge M11).
    pub fn htlc_spend_in_tx(&self, spend_txid: &Txid, outpoint: &bitcoin::OutPoint) -> Result<crate::HtlcSpend, String> {
        let v = self.esplora.tx_json(&spend_txid.to_string())?;
        htlc_spend_from_tx_json(&v, outpoint)
    }

    pub fn network(&self) -> Network {
        self.network
    }
}

/// Classify how an Esplora `/tx` JSON body spends `outpoint`: find the vin whose
/// (`txid`, `vout`) equals the outpoint, then classify its witness item 1. Pure so the
/// vin selection is unit-tested offline.
fn htlc_spend_from_tx_json(v: &serde_json::Value, outpoint: &bitcoin::OutPoint) -> Result<crate::HtlcSpend, String> {
    let want_txid = outpoint.txid.to_string();
    let vins = v["vin"].as_array().ok_or("esplora: tx has no vin array")?;
    let vin = vins
        .iter()
        .find(|vin| vin["txid"].as_str() == Some(want_txid.as_str()) && vin["vout"].as_u64() == Some(outpoint.vout as u64))
        .ok_or_else(|| format!("tx does not spend HTLC outpoint {outpoint}"))?;
    let item_hex = vin["witness"]
        .as_array()
        .and_then(|w| w.get(1))
        .and_then(|x| x.as_str())
        .ok_or("HTLC spend input has no witness item 1")?;
    let item = hex::decode(item_hex).map_err(|e| format!("witness item 1: {e}"))?;
    crate::classify_htlc_witness_item(&item)
}

impl crate::BtcBackend for SelfCustodyBtc {
    fn fund_htlc(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
        SelfCustodyBtc::fund_htlc(self, script, amount)
    }
    fn claim(&self, utxo: &HtlcUtxo, preimage: &[u8], key: &Key, dest: &Address, fee: Amount) -> Result<Txid, String> {
        SelfCustodyBtc::claim(self, utxo, preimage, key, dest, fee)
    }
    fn height(&self) -> Result<u64, String> {
        SelfCustodyBtc::height(self)
    }
    fn network(&self) -> Network {
        self.network
    }
    fn preimage_from_claim(&self, txid: &Txid) -> Option<Vec<u8>> {
        SelfCustodyBtc::preimage_from_claim(self, txid)
    }
    fn confirm(&self, txid: &Txid) -> Result<(), String> {
        SelfCustodyBtc::confirm(self, txid)
    }
    fn confirm_with(&self, txid: &Txid, on_conf: &dyn Fn(u32, u32)) -> Result<(), String> {
        SelfCustodyBtc::confirm_with(self, txid, on_conf)
    }
    fn fee_rate_sat_vb(&self, target: u32) -> Result<f64, String> {
        self.esplora.fee_rate_sat_vb(target)
    }
    fn fund_htlc_unconfirmed(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
        SelfCustodyBtc::fund_htlc_unconfirmed(self, script, amount)
    }
    fn htlc_utxos(&self, script: &ScriptBuf) -> Result<Vec<HtlcUtxo>, String> {
        SelfCustodyBtc::htlc_utxos(self, script)
    }
    fn refund(&self, utxo: &HtlcUtxo, key: &Key, locktime: u32, dest: &Address, fee: Amount) -> Result<Txid, String> {
        SelfCustodyBtc::refund(self, utxo, key, locktime, dest, fee)
    }
    fn fresh_payout_address(&self) -> Result<Address, String> {
        self.fresh_receive_address()
    }
    fn tx_block_hash(&self, txid: &Txid) -> Result<Option<[u8; 32]>, String> {
        SelfCustodyBtc::tx_block_hash(self, txid)
    }
    fn tx_confirmations(&self, txid: &Txid) -> Result<u64, String> {
        Ok(self.esplora.confirmations(&txid.to_string())? as u64)
    }
    /// `Some(true)`: unspent. `Some(false)`: a CONFIRMED spend exists. `None`: a spend is in
    /// the mempool only, which can still be replaced or dropped, so neither answer is safe
    /// (bridge M12).
    fn utxo_unspent(&self, utxo: &HtlcUtxo) -> Result<Option<bool>, String> {
        Ok(match self.esplora.outspend_status(&utxo.outpoint.txid.to_string(), utxo.outpoint.vout)? {
            None => Some(true),
            Some(s) if s.confirmed => Some(false),
            Some(_) => None,
        })
    }
    /// Esplora exposes the spender directly, so no block scan is needed. Only a CONFIRMED
    /// spend counts, matching the node backend's block scan (a mempool spend reads as
    /// `Unspent` until it confirms). The spending input is matched by outpoint and its
    /// witness item 1 must be exactly 32 bytes to be a claim (bridge M11, M12).
    fn find_htlc_spend(&self, utxo: &HtlcUtxo, _since_height: u64) -> Result<crate::HtlcSpend, String> {
        match self.esplora.outspend_status(&utxo.outpoint.txid.to_string(), utxo.outpoint.vout)? {
            Some(spend) if spend.confirmed => {
                let txid = Txid::from_str(&spend.txid).map_err(|e| e.to_string())?;
                self.htlc_spend_in_tx(&txid, &utxo.outpoint)
            }
            _ => Ok(crate::HtlcSpend::Unspent),
        }
    }
    fn block_header(&self, height: u64) -> Result<[u8; 80], String> {
        self.esplora.block_header(height)
    }
    fn raw_tx(&self, txid: &Txid) -> Result<Vec<u8>, String> {
        self.esplora.tx_raw(&txid.to_string())
    }
    fn txout_proof(&self, txid: &Txid) -> Result<Vec<u8>, String> {
        Ok(self.esplora.mint_inclusion(&txid.to_string())?.0)
    }
    fn coinbase_raw(&self, txid: &Txid) -> Result<Vec<u8>, String> {
        Ok(self.esplora.mint_inclusion(&txid.to_string())?.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MN: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn htlc_spend_matches_vin_by_outpoint_not_position() {
        use crate::HtlcSpend;
        let fund = Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let other = "2222222222222222222222222222222222222222222222222222222222222222";
        let op = bitcoin::OutPoint { txid: fund, vout: 1 };
        let pre = hex::encode([0x42u8; 32]);
        // vin 0 is some unrelated input (its item 1 is a 32-byte lookalike); vin 1 is the HTLC claim.
        let claim = serde_json::json!({ "vin": [
            { "txid": other, "vout": 0, "witness": ["00", hex::encode([0x99u8; 32]), "01", "aa"] },
            { "txid": fund.to_string(), "vout": 1, "witness": ["00", pre, "01", "aa"] },
        ]});
        assert_eq!(htlc_spend_from_tx_json(&claim, &op).unwrap(), HtlcSpend::Claimed(vec![0x42u8; 32]));
        // Refund: empty item 1 on the matching vin.
        let refund = serde_json::json!({ "vin": [
            { "txid": fund.to_string(), "vout": 1, "witness": ["00", "", "aa"] },
        ]});
        assert_eq!(htlc_spend_from_tx_json(&refund, &op).unwrap(), HtlcSpend::Refunded);
        // Wrong vout / no matching vin: an error, not Refunded.
        let wrong = bitcoin::OutPoint { txid: fund, vout: 0 };
        assert!(htlc_spend_from_tx_json(&refund, &wrong).is_err());
        // A non-32-byte, non-empty item 1 is neither branch.
        let odd = serde_json::json!({ "vin": [
            { "txid": fund.to_string(), "vout": 1, "witness": ["00", "abcd", "01", "aa"] },
        ]});
        assert!(htlc_spend_from_tx_json(&odd, &op).is_err());
    }

    #[test]
    fn address_is_seed_derived_and_restorable() {
        let a = SelfCustodyBtc::new(MN, "", Network::Signet, "https://mempool.space/signet/api").unwrap();
        let addr = a.receive_address().unwrap().to_string();
        assert!(addr.starts_with("tb1q"));
        // Same mnemonic → same address (restorable), independent of the Esplora endpoint.
        let b = SelfCustodyBtc::new(MN, "", Network::Signet, "https://blockstream.info/signet/api").unwrap();
        assert_eq!(addr, b.receive_address().unwrap().to_string());
    }
}
