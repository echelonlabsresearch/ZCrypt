//! Bitcoin (regtest) HTLC leg of the BTC↔zBTC atomic-swap bridge.
//!
//! A hash time-locked contract on Bitcoin, sharing its SHA-256 hashlock with the
//! ZCrypt shield HTLC (`zcrypt_core::htlc_shield`) so one preimage settles both
//! chains atomically. The redeem script (P2WSH):
//!
//! ```text
//! OP_IF                                  # claim branch
//!   OP_SHA256 <hashlock> OP_EQUALVERIFY
//!   <claim_pubkey> OP_CHECKSIG
//! OP_ELSE                                # refund branch
//!   <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
//!   <refund_pubkey> OP_CHECKSIG
//! OP_ENDIF
//! ```

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::*;
use bitcoin::script::{Builder, PushBytesBuf, ScriptBuf};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, CompressedPublicKey, EcdsaSighashType as _Sht, Network, OutPoint, PublicKey,
    Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::str::FromStr;

pub const NETWORK: Network = Network::Regtest;

/// The HTLC redeem (witness) script.
pub fn htlc_script(
    hashlock: &[u8; 32],
    claim_pk: &PublicKey,
    refund_pk: &PublicKey,
    locktime: u32,
) -> ScriptBuf {
    let mut lock = PushBytesBuf::new();
    lock.extend_from_slice(hashlock).unwrap();
    Builder::new()
        .push_opcode(OP_IF)
        .push_opcode(OP_SHA256)
        .push_slice(lock)
        .push_opcode(OP_EQUALVERIFY)
        .push_key(claim_pk)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_int(locktime as i64)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_key(refund_pk)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script()
}

/// The P2WSH address the HTLC script commits to.
pub fn htlc_address(script: &ScriptBuf) -> Address {
    Address::p2wsh(script, NETWORK)
}

/// A secp256k1 keypair for HTLC participants.
pub struct Key {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

impl Key {
    pub fn from_bytes(b: &[u8; 32]) -> Self {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(b).expect("valid secret");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        Key { sk, pk }
    }
    pub fn compressed(&self) -> CompressedPublicKey {
        CompressedPublicKey(self.pk.inner)
    }
}

/// A funded HTLC output on Bitcoin.
pub struct HtlcUtxo {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub script: ScriptBuf,
}

pub struct Btc {
    pub rpc: Client,
}

impl Btc {
    pub fn connect(url: &str, user: &str, pass: &str, wallet: &str) -> Result<Self, String> {
        let full = format!("{}/wallet/{}", url.trim_end_matches('/'), wallet);
        let rpc = Client::new(&full, Auth::UserPass(user.into(), pass.into()))
            .map_err(|e| e.to_string())?;
        Ok(Btc { rpc })
    }

    /// Best-effort create/load a bitcoind wallet by name (idempotent). Used to make
    /// a `bridge`/LP wallet distinct from the user's `demo` wallet.
    pub fn ensure_wallet(url: &str, user: &str, pass: &str, name: &str) -> Result<(), String> {
        let rpc = Client::new(url.trim_end_matches('/'), Auth::UserPass(user.into(), pass.into()))
            .map_err(|e| e.to_string())?;
        let _ = rpc.create_wallet(name, None, None, None, None);
        let _ = rpc.load_wallet(name);
        Ok(())
    }

    pub fn height(&self) -> Result<u64, String> {
        self.rpc.get_block_count().map_err(|e| e.to_string())
    }

    /// A fresh receiving address from the connected bitcoind wallet.
    pub fn new_address(&self) -> Result<Address, String> {
        self.rpc
            .get_new_address(None, None)
            .map_err(|e| e.to_string())?
            .require_network(NETWORK)
            .map_err(|e| e.to_string())
    }

    pub fn balance_btc(&self) -> Result<f64, String> {
        self.rpc.get_balance(None, None).map(|a| a.to_btc()).map_err(|e| e.to_string())
    }

    /// Withdraw `amount` BTC to an external address. Parses + network-checks the
    /// address, broadcasts from this wallet, mines 1 block (regtest), returns txid.
    pub fn send_to_address(&self, address: &str, amount: Amount) -> Result<String, String> {
        use std::str::FromStr;
        let addr = Address::from_str(address.trim())
            .map_err(|e| format!("bad BTC address: {e}"))?
            .require_network(NETWORK)
            .map_err(|e| format!("address not valid for this network: {e}"))?;
        let txid = self
            .rpc
            .send_to_address(&addr, amount, None, None, None, None, None, None)
            .map_err(|e| e.to_string())?;
        self.mine(1)?;
        Ok(txid.to_string())
    }

    /// Mine `n` blocks to a **throwaway** address whose key nobody holds — the
    /// coinbase is effectively burned, so confirming swap txs never inflates any
    /// tracked wallet's balance.
    pub fn mine(&self, n: u64) -> Result<(), String> {
        let addr = throwaway_address();
        self.rpc.generate_to_address(n, &addr).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// One-time: give this wallet ONE spendable coinbase (~50 BTC on regtest). Mines a
    /// single block to this wallet, then `n-1` blocks to a **throwaway** for maturity — so
    /// there's no backlog of immature coinbases that would later mature and silently
    /// inflate the balance (which is what made the demo wallet balloon to hundreds of BTC).
    pub fn fund_self(&self, n: u64) -> Result<(), String> {
        let addr = self.new_address()?;
        self.rpc.generate_to_address(1, &addr).map_err(|e| e.to_string())?;
        if n > 1 {
            self.rpc
                .generate_to_address(n - 1, &throwaway_address())
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Fund an HTLC: pay `amount` BTC to the script's P2WSH address, mine 1 block,
    /// and return the resulting UTXO.
    pub fn fund_htlc(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
        let addr = htlc_address(script);
        let txid = self
            .rpc
            .send_to_address(&addr, amount, None, None, None, None, None, None)
            .map_err(|e| e.to_string())?;
        self.mine(1)?;
        // find the vout paying our address
        let tx = self.rpc.get_raw_transaction(&txid, None).map_err(|e| e.to_string())?;
        let spk = addr.script_pubkey();
        let (vout, txout) = tx
            .output
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey == spk)
            .ok_or("funding vout not found")?;
        Ok(HtlcUtxo {
            outpoint: OutPoint { txid, vout: vout as u32 },
            value: txout.value,
            script: script.clone(),
        })
    }

    /// Broadcast a raw transaction, returning its txid.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid, String> {
        self.rpc.send_raw_transaction(tx).map_err(|e| e.to_string())
    }

    /// Spend an HTLC via the **claim** branch (preimage + claim key). `dest` gets
    /// the value minus `fee`.
    pub fn claim(
        &self,
        utxo: &HtlcUtxo,
        preimage: &[u8],
        claim: &Key,
        dest: &Address,
        fee: Amount,
    ) -> Result<Txid, String> {
        let witness = |script_sig: Vec<u8>| {
            let mut w = Witness::new();
            w.push(script_sig); // <claim_sig>
            w.push(preimage); // <preimage>
            w.push([1u8]); // OP_IF selector = true
            w.push(utxo.script.as_bytes()); // witnessScript
            w
        };
        self.spend(utxo, claim, dest, fee, LockTime::ZERO, witness)
    }

    /// Spend an HTLC via the **refund** branch (after `locktime`, refund key).
    pub fn refund(
        &self,
        utxo: &HtlcUtxo,
        refund: &Key,
        locktime: u32,
        dest: &Address,
        fee: Amount,
    ) -> Result<Txid, String> {
        let lt = LockTime::from_consensus(locktime);
        let witness = |script_sig: Vec<u8>| {
            let mut w = Witness::new();
            w.push(script_sig); // <refund_sig>
            w.push([] as [u8; 0]); // OP_IF selector = false (empty)
            w.push(utxo.script.as_bytes());
            w
        };
        self.spend(utxo, refund, dest, fee, lt, witness)
    }

    /// Build, sign (BIP-143), and broadcast a 1-in/1-out tx spending `utxo`.
    fn spend(
        &self,
        utxo: &HtlcUtxo,
        key: &Key,
        dest: &Address,
        fee: Amount,
        locktime: LockTime,
        mk_witness: impl Fn(Vec<u8>) -> Witness,
    ) -> Result<Txid, String> {
        // The refund branch needs a non-final sequence for CLTV to be enforced.
        let sequence = if locktime == LockTime::ZERO {
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
            output: vec![TxOut {
                value: utxo.value - fee,
                script_pubkey: dest.script_pubkey(),
            }],
        };
        // BIP-143 sighash over the witness script.
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
        self.broadcast(&tx)
    }

    /// Extract the SHA-256 preimage revealed in a claim tx (witness item 1), so the
    /// other leg can be settled from what's actually on-chain.
    pub fn preimage_from_claim(&self, txid: &Txid) -> Option<Vec<u8>> {
        let tx = self.rpc.get_raw_transaction(txid, None).ok()?;
        // claim witness = [sig, preimage, 0x01, witnessScript]
        let w = &tx.input.first()?.witness;
        let item = w.nth(1)?;
        Some(item.to_vec())
    }
}

pub mod swap;
pub mod zcrypt;

/// A fixed P2WPKH address whose private key nobody uses — mining here burns the
/// coinbase so confirming swap txs doesn't credit any tracked wallet's balance.
fn throwaway_address() -> Address {
    let key = Key::from_bytes(&[0xEE; 32]);
    Address::p2wpkh(&key.compressed(), NETWORK)
}

/// Parse a regtest address string.
pub fn parse_address(s: &str) -> Result<Address, String> {
    Address::from_str(s)
        .map_err(|e| e.to_string())?
        .require_network(NETWORK)
        .map_err(|e| e.to_string())
}

// Silence an unused-import lint for the re-exported sighash-type alias.
const _: _Sht = _Sht::All;
