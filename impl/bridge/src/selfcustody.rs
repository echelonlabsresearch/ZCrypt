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
    /// (privacy H3). Falls back to index 0 only if the endpoint cannot be reached.
    pub fn fresh_receive_address(&self) -> Result<Address, String> {
        let i = self.first_unused_index(0).unwrap_or(0);
        self.hd.receive_address(i)
    }

    /// A FRESH change address (see [`Self::fresh_receive_address`]).
    pub fn fresh_change_address(&self) -> Result<Address, String> {
        let i = self.first_unused_index(1).unwrap_or(0);
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
    /// Returns `None` for refund spends (empty witness item 1) so callers do not
    /// treat a refund as a successful claim.
    pub fn preimage_from_claim(&self, txid: &Txid) -> Option<Vec<u8>> {
        let v = self.esplora.tx_json(&txid.to_string()).ok()?;
        let wit = v["vin"][0]["witness"].as_array()?;
        let raw = hex::decode(wit.get(1)?.as_str()?).ok()?;
        if raw.is_empty() {
            None // refund branch: OP_IF selector false, empty preimage slot
        } else {
            Some(raw)
        }
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
    fn network(&self) -> Network {
        self.network
    }
    fn preimage_from_claim(&self, txid: &Txid) -> Option<Vec<u8>> {
        SelfCustodyBtc::preimage_from_claim(self, txid)
    }
    fn confirm(&self, txid: &Txid) -> Result<(), String> {
        SelfCustodyBtc::confirm(self, txid)
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
    fn tx_block_hash(&self, txid: &Txid) -> Result<Option<[u8; 32]>, String> {
        SelfCustodyBtc::tx_block_hash(self, txid)
    }
    fn tx_confirmations(&self, txid: &Txid) -> Result<u64, String> {
        Ok(self.esplora.confirmations(&txid.to_string())? as u64)
    }
    fn utxo_unspent(&self, utxo: &HtlcUtxo) -> Result<Option<bool>, String> {
        Ok(Some(self.esplora.outspend(&utxo.outpoint.txid.to_string(), utxo.outpoint.vout)?.is_none()))
    }
    fn find_htlc_spend_preimage(&self, utxo: &HtlcUtxo, _since_height: u64) -> Result<Option<Vec<u8>>, String> {
        // Esplora exposes the spender directly — no block scan needed.
        // `preimage_from_claim` returns None for refund spends (empty witness item).
        match self.esplora.outspend(&utxo.outpoint.txid.to_string(), utxo.outpoint.vout)? {
            Some(spend_txid) => {
                let txid = Txid::from_str(&spend_txid).map_err(|e| e.to_string())?;
                Ok(self.preimage_from_claim(&txid))
            }
            None => Ok(None),
        }
    }
    fn block_header(&self, height: u64) -> Result<[u8; 80], String> {
        self.esplora.block_header(height)
    }
    fn raw_tx(&self, txid: &Txid) -> Result<Vec<u8>, String> {
        self.esplora.tx_raw(&txid.to_string())
    }
    fn txout_proof(&self, txid: &Txid) -> Result<Vec<u8>, String> {
        self.esplora.merkleblock_proof(&txid.to_string())
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
