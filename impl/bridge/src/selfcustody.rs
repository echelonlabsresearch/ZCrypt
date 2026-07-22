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
use bitcoin::{Address, Amount, Network, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
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
        let hd = HdWallet::from_mnemonic_account(mnemonic, passphrase, network, account)?;
        Ok(Self { hd, esplora: Esplora::new(esplora_url), network })
    }

    /// The wallet's first receiving address (the deposit address to fund from a faucet
    /// or another wallet). Restorable from the mnemonic alone.
    pub fn receive_address(&self) -> Result<Address, String> {
        self.hd.receive_address(0)
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

    /// Confirmations to treat a tx as final, by network.
    pub fn conf_target(&self) -> u32 {
        match self.network {
            Network::Bitcoin => 2,
            _ => 1,
        }
    }

    /// Wait until `txid` reaches [`Self::conf_target`] confirmations.
    pub fn confirm(&self, txid: &Txid) -> Result<(), String> {
        self.esplora.wait_confirmed(&txid.to_string(), self.conf_target())
    }

    /// Fund an HTLC: build a tx from our own UTXOs paying `amount` to the HTLC's P2WSH
    /// address (change back to our change/0 address), sign locally, broadcast via
    /// Esplora, and block until confirmed. Returns the funding UTXO (output 0).
    pub fn fund_htlc(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
        let dest = htlc_address(script, self.network).script_pubkey();
        let change = self.hd.change_address(0)?.script_pubkey();
        let utxos = self.esplora.wallet_utxos(&self.hd)?;
        let fee_rate = self.esplora.fee_rate_sat_vb(self.conf_target().max(3))?;
        let signed = txbuilder::build_and_sign(&self.hd, &utxos, dest, amount.to_sat(), change, fee_rate)?;
        self.esplora.broadcast(&signed.hex)?;
        self.esplora.wait_confirmed(&signed.txid.to_string(), self.conf_target())?;
        Ok(HtlcUtxo { outpoint: signed.vout0, value: amount, script: script.clone() })
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
        let sequence = if locktime == bitcoin::absolute::LockTime::ZERO {
            Sequence::ENABLE_RBF_NO_LOCKTIME
        } else {
            Sequence::ENABLE_LOCKTIME_NO_RBF
        };
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

    /// The preimage revealed in a claim tx (witness item 1), read via Esplora.
    pub fn preimage_from_claim(&self, txid: &Txid) -> Option<Vec<u8>> {
        let v = self.esplora.tx_json(&txid.to_string()).ok()?;
        let wit = v["vin"][0]["witness"].as_array()?;
        hex::decode(wit.get(1)?.as_str()?).ok()
    }

    pub fn network(&self) -> Network {
        self.network
    }
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
    fn preimage_from_claim(&self, txid: &Txid) -> Option<Vec<u8>> {
        SelfCustodyBtc::preimage_from_claim(self, txid)
    }
    fn confirm(&self, txid: &Txid) -> Result<(), String> {
        SelfCustodyBtc::confirm(self, txid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MN: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
