//! Bitcoin (regtest) HTLC leg of the BTC↔zBTC atomic-swap bridge.
//!
//! A hash time-locked contract on Bitcoin, sharing its SHA-256 hashlock with the
//! ZCrypt shield HTLC (`zcrypt_core::htlc_shield`) so one preimage settles both
//! chains atomically. The redeem script (P2WSH):
//!
//! ```text
//! OP_IF                                  # claim branch
//!   OP_SIZE 32 OP_EQUALVERIFY            # preimage is exactly 32 bytes (bridge C2)
//!   OP_SHA256 <hashlock> OP_EQUALVERIFY
//!   <claim_pubkey> OP_CHECKSIG
//! OP_ELSE                                # refund branch
//!   <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
//!   <refund_pubkey> OP_CHECKSIG
//! OP_ENDIF
//! ```

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, CompressedPublicKey, EcdsaSighashType as _Sht, Network, OutPoint, PublicKey,
    Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::str::FromStr;

/// SOCKS proxy for the bridge's outbound HTTP (the ZCrypt node RPC in `zcrypt.rs` and the
/// Esplora API in `esplora.rs`). `None` = direct. Set from the wallet's Tor setting; remote
/// hosts route through it, loopback always bypasses it (Tor can't reach a local process).
/// NOTE: the bitcoind JSON-RPC (`bitcoincore-rpc`) is NOT covered — it has no client-side
/// proxy and is your own, usually local, node.
static TOR_PROXY: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Route the bridge's outbound HTTP through this SOCKS proxy (e.g. "socks5://127.0.0.1:9050").
/// `None` reverts to direct. Loopback targets always bypass it.
pub fn set_tor(proxy: Option<String>) {
    *TOR_PROXY.write().unwrap() = proxy;
}

/// Whether `url`'s host is loopback (Tor is pointless and would break a local connection).
fn is_loopback_url(url: &str) -> bool {
    let host = url
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(['/', ':', '?'])
        .next()
        .unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// A `ureq` agent for reaching `target_url`, routed through the configured Tor SOCKS proxy
/// for REMOTE hosts and direct for loopback. Fails CLOSED on a bad proxy string (points at
/// an unusable port rather than leaking the real IP). Built per call — the bridge's request
/// volume is low. Every bridge HTTP call MUST use this, never a bare `ureq::builder()`.
pub(crate) fn proxied_agent(target_url: &str, timeout_secs: u64) -> ureq::Agent {
    let mut b = ureq::builder().timeout(std::time::Duration::from_secs(timeout_secs));
    if !is_loopback_url(target_url) {
        if let Some(proxy) = TOR_PROXY.read().unwrap().clone() {
            match ureq::Proxy::new(&proxy) {
                Ok(p) => b = b.proxy(p),
                Err(_) => b = b.proxy(ureq::Proxy::new("socks5://127.0.0.1:1").expect("static proxy")),
            }
        }
    }
    b.build()
}

/// Default Bitcoin network when none is configured (the devnet/demo stack).
pub const NETWORK: Network = Network::Regtest;

/// Resolve a config string to a Bitcoin network. `testnet4` maps to the testnet
/// address format (same `tb1…` prefix) for crate compatibility. Unknown → regtest.
pub fn network_from_str(s: &str) -> Network {
    match s.trim().to_ascii_lowercase().as_str() {
        "bitcoin" | "mainnet" | "main" => Network::Bitcoin,
        "testnet" | "testnet3" | "testnet4" => Network::Testnet,
        "signet" => Network::Signet,
        _ => Network::Regtest,
    }
}

// ---------------------------------------------------------------------------
// Reserve / refund key derivation (ONE rule, shared by the wallet and the daemon)
// ---------------------------------------------------------------------------

/// The bridge operator's Bitcoin RESERVE key, derived from the operator wallet's 32-byte
/// ZCrypt seed exactly as the desktop wallet's `bridge_init` does: `H("BTCBRDG", seed)`.
/// The daemon must use this same rule (or be handed the derived 32-byte key itself), so
/// the key the chain's `zbtc_reserve_pk` is bound to and the key the daemon sweeps with can
/// never diverge (bridge L4). Prefer exporting the DERIVED key to the daemon host: the wallet
/// seed also spends the operator's shielded coins and must never leave the wallet.
pub fn reserve_key_from_wallet_seed(seed: &[u8; 32]) -> Key {
    Key::from_bytes(&zcrypt_core::hash::h(b"BTCBRDG", &[seed]))
}

/// A user's Bitcoin HTLC refund key for deposit number `index`, derived from the wallet's
/// 32-byte seed. Index 0 is the legacy single refund key (`H("BTCALIC", seed)`, what the
/// wallet used for every deposit); index `n > 0` is `H("BTCALIC", seed ‖ n)`. Using a FRESH
/// index per deposit stops a chain-analysis observer from clustering all of one user's
/// deposits by their shared refund key in the HTLC scripts (privacy H3).
pub fn refund_key_for(seed: &[u8; 32], index: u32) -> Key {
    if index == 0 {
        Key::from_bytes(&zcrypt_core::hash::h(b"BTCALIC", &[seed]))
    } else {
        Key::from_bytes(&zcrypt_core::hash::h(b"BTCALIC", &[seed, &index.to_le_bytes()]))
    }
}

/// Parse a 32-byte secp256k1 secret from a file's contents: either 64 hex characters
/// (whitespace tolerated) or exactly 32 raw bytes.
pub fn parse_secret_bytes(raw: &[u8]) -> Result<[u8; 32], String> {
    if raw.len() == 32 {
        return raw.try_into().map_err(|_| "secret: not 32 bytes".to_string());
    }
    let text = std::str::from_utf8(raw).map_err(|_| "secret: neither 32 raw bytes nor hex text")?;
    let h: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let b = hex::decode(&h).map_err(|e| format!("secret: invalid hex: {e}"))?;
    b.try_into().map_err(|_| "secret: hex must decode to exactly 32 bytes".to_string())
}

// ---------------------------------------------------------------------------
// Fee sanity caps (bridge M4): a lying fee oracle (Esplora, or a compromised bitcoind)
// must not be able to make a wallet pay most of an HTLC as fees.
// ---------------------------------------------------------------------------

/// Hard ceiling on any fee rate the bridge will act on (sat/vB). Real mempools rarely
/// exceed a few hundred sat/vB even under extreme congestion.
pub const MAX_FEE_RATE_SAT_VB: f64 = 500.0;
/// A single HTLC spend or funding tx never pays more than this fraction of the value it
/// moves as fees (1/4), except the absolute relay floor on tiny amounts.
pub const MAX_FEE_FRACTION_DEN: u64 = 4;

/// Clamp a fee rate into `[1, MAX_FEE_RATE_SAT_VB]`.
pub fn cap_fee_rate(rate: f64) -> f64 {
    if !rate.is_finite() {
        return 1.0;
    }
    rate.clamp(1.0, MAX_FEE_RATE_SAT_VB)
}

/// Cap an absolute fee against the value being moved: at most `value / MAX_FEE_FRACTION_DEN`,
/// but never below `floor` (the relay minimum for the spend). Errors when even the floor
/// would eat the value (the amount is dust for this fee market).
pub fn cap_fee_for_value(fee_sat: u64, value_sat: u64, floor_sat: u64) -> Result<u64, String> {
    let max = (value_sat / MAX_FEE_FRACTION_DEN).max(floor_sat);
    if max >= value_sat {
        return Err(format!(
            "fee floor {floor_sat} sats would consume the {value_sat}-sat value: amount too small to move"
        ));
    }
    Ok(fee_sat.min(max))
}

/// The HTLC redeem (witness) script. Delegates to the CONSENSUS definition
/// (`zcrypt_core::spv::btc_htlc_script`) so the script the wallet funds and the script the
/// chain verifies a deposit against can never diverge. Includes the `OP_SIZE 32` guard that
/// pins the preimage length on Bitcoin.
pub fn htlc_script(
    hashlock: &[u8; 32],
    claim_pk: &PublicKey,
    refund_pk: &PublicKey,
    locktime: u32,
) -> ScriptBuf {
    zcrypt_core::spv::btc_htlc_script(hashlock, &claim_pk.inner.serialize(), &refund_pk.inner.serialize(), locktime)
        .expect("valid compressed keys")
}

/// The P2WSH address the HTLC script commits to, on `network`.
pub fn htlc_address(script: &ScriptBuf, network: Network) -> Address {
    Address::p2wsh(script, network)
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
#[derive(Debug, Clone)]
pub struct HtlcUtxo {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub script: ScriptBuf,
}

pub struct Btc {
    pub rpc: Client,
    pub network: Network,
}

impl Btc {
    pub fn connect(url: &str, user: &str, pass: &str, wallet: &str, network: Network) -> Result<Self, String> {
        let full = format!("{}/wallet/{}", url.trim_end_matches('/'), wallet);
        let rpc = Client::new(&full, Auth::UserPass(user.into(), pass.into()))
            .map_err(|e| e.to_string())?;
        Ok(Btc { rpc, network })
    }

    /// True on regtest, where the bridge may mine its own blocks. On real networks
    /// (mainnet/testnet/signet) mining is impossible, so swap confirmation must come
    /// from polling for real confirmations instead (see `send_to_address`/`fund_htlc`).
    pub fn is_regtest(&self) -> bool {
        self.network == Network::Regtest
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
            .require_network(self.network)
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
            .require_network(self.network)
            .map_err(|e| format!("address not valid for this network: {e}"))?;
        let txid = self
            .rpc
            .send_to_address(&addr, amount, None, None, None, None, None, None)
            .map_err(|e| e.to_string())?;
        // Regtest confirms instantly by self-mining. On real networks the tx enters the
        // mempool; the caller must poll for confirmations before treating it as final.
        if self.is_regtest() {
            self.mine(1)?;
        }
        Ok(txid.to_string())
    }

    /// Minimum confirmations to treat a Bitcoin tx as final — aligned with consensus
    /// SPV `min_conf` so the bridge client never treats a deposit as final before the
    /// mint gate would accept it (mainnet 6, signet 1, regtest 0 after self-mine).
    pub fn conf_target(&self) -> u32 {
        match self.network {
            Network::Regtest => 0,
            Network::Bitcoin => zcrypt_core::spv::min_conf_for(zcrypt_core::spv::BtcNet::Mainnet) as u32,
            Network::Signet => zcrypt_core::spv::min_conf_for(zcrypt_core::spv::BtcNet::Signet) as u32,
            _ => 1,
        }
    }

    /// Block until `txid` reaches [`conf_target`] confirmations (no-op on regtest).
    /// Polls `getrawtransaction` (verbose). Times out after ~3h so a dropped/replaced
    /// tx doesn't hang forever. NOTE: this BLOCKS the caller — on mainnet block times a
    /// swap step can wait many minutes; the async watcher (MAINNET.md step 3) removes
    /// that from the UI path. Run bitcoind with `-txindex` so non-wallet txs are visible.
    pub fn wait_confirmed(&self, txid: &Txid) -> Result<(), String> {
        let target = self.conf_target();
        if target == 0 {
            return Ok(());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3 * 60 * 60);
        loop {
            if let Ok(info) = self.rpc.get_raw_transaction_info(txid, None) {
                if info.confirmations.unwrap_or(0) >= target {
                    return Ok(());
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!("timed out waiting for {target} confirmation(s) of {txid}"));
            }
            std::thread::sleep(std::time::Duration::from_secs(15));
        }
    }

    /// Confirm a broadcast tx: mine it on regtest, else wait for real confirmations.
    /// One call the swap flow uses regardless of network.
    pub fn confirm(&self, txid: &Txid) -> Result<(), String> {
        if self.is_regtest() {
            return self.mine(1);
        }
        self.wait_confirmed(txid)
    }

    /// Mine `n` blocks to a **throwaway** address whose key nobody holds — the coinbase
    /// is effectively burned. **Regtest only**: real networks cannot mine, so this
    /// errors there (confirmation must come from polling, not self-mining).
    pub fn mine(&self, n: u64) -> Result<(), String> {
        if !self.is_regtest() {
            return Err("mine() is regtest-only — a real Bitcoin network confirms via mined blocks you must wait for, not generate".to_string());
        }
        let addr = throwaway_address(self.network);
        self.rpc.generate_to_address(n, &addr).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// One-time: give this wallet ONE spendable coinbase (~50 BTC on regtest). Mines a
    /// single block to this wallet, then `n-1` blocks to a **throwaway** for maturity — so
    /// there's no backlog of immature coinbases that would later mature and silently
    /// inflate the balance (which is what made the demo wallet balloon to hundreds of BTC).
    pub fn fund_self(&self, n: u64) -> Result<(), String> {
        if !self.is_regtest() {
            return Err("fund_self() is regtest-only — on a real network fund this wallet with actual BTC".to_string());
        }
        let addr = self.new_address()?;
        self.rpc.generate_to_address(1, &addr).map_err(|e| e.to_string())?;
        if n > 1 {
            self.rpc
                .generate_to_address(n - 1, &throwaway_address(self.network))
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// ⚠️ MONEY-CRITICAL, and UNTESTED against live bitcoind — validate on signet before
    /// trusting it with value. Watch for an EXTERNAL confirmed deposit of at least
    /// `expected` BTC to the HTLC address. This is the detection the bridge must run for
    /// BTC→zBTC: it may **not** mint zBTC until a real, confirmed deposit exists. Uses
    /// `scantxoutset` (scans the confirmed UTXO set — no wallet import, works on descriptor
    /// or legacy wallets) then verifies `conf_target` confirmations. Returns the funding
    /// UTXO with its actual value. This is a standalone primitive for the future bridge
    /// watcher service; it is NOT yet wired into the single-process demo flow.
    pub fn watch_htlc_deposit(
        &self,
        script: &ScriptBuf,
        expected: Amount,
        timeout_secs: u64,
    ) -> Result<HtlcUtxo, String> {
        use serde_json::json;
        let addr = htlc_address(script, self.network);
        let desc = format!("addr({addr})");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        loop {
            let res: serde_json::Value = self
                .rpc
                .call("scantxoutset", &[json!("start"), json!([{ "desc": desc }])])
                .map_err(|e| e.to_string())?;
            if let Some(unspents) = res["unspents"].as_array() {
                for u in unspents {
                    // scantxoutset reports amounts in BTC; compare in sats to avoid float drift.
                    let sats = (u["amount"].as_f64().unwrap_or(0.0) * 1e8).round() as u64;
                    if sats >= expected.to_sat() {
                        let txid_str = u["txid"].as_str().ok_or("scan: missing txid")?;
                        let vout = u["vout"].as_u64().ok_or("scan: missing vout")? as u32;
                        let txid = Txid::from_str(txid_str).map_err(|e| e.to_string())?;
                        self.wait_confirmed(&txid)?; // require conf_target confirmations
                        return Ok(HtlcUtxo {
                            outpoint: OutPoint { txid, vout },
                            value: Amount::from_sat(sats),
                            script: script.clone(),
                        });
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "no confirmed deposit of ≥{} BTC to the HTLC address within the watch window",
                    expected.to_btc()
                ));
            }
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

    /// Fund an HTLC: pay `amount` BTC to the script's P2WSH address, mine 1 block,
    /// and return the resulting UTXO.
    pub fn fund_htlc(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
        let utxo = self.fund_htlc_unconfirmed(script, amount)?;
        // Regtest confirms instantly; real networks BLOCK here until the funding tx has
        // `conf_target` confirmations, so the returned UTXO is settled (not a mempool tx
        // a counterparty could still double-spend/RBF) before anyone acts on it.
        if self.is_regtest() {
            self.mine(1)?;
        } else {
            self.wait_confirmed(&utxo.outpoint.txid)?;
        }
        Ok(utxo)
    }

    /// Broadcast an HTLC funding tx and return its UTXO WITHOUT waiting for confirmation.
    /// Split out from [`Self::fund_htlc`] so a daemon can persist the txid the moment it is
    /// on the network: a confirmation wait that times out (or a crash during it) must never
    /// lose track of a broadcast that already happened, or the next attempt would fund the
    /// same escrow twice (bridge H2).
    pub fn fund_htlc_unconfirmed(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
        let addr = htlc_address(script, self.network);
        let txid = self
            .rpc
            .send_to_address(&addr, amount, None, None, None, None, None, None)
            .map_err(|e| e.to_string())?;
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

    /// Every unspent output currently locked to `script`'s P2WSH address (confirmed UTXO
    /// set via `scantxoutset`). Lets a daemon discover an HTLC it already funded before it
    /// funds again, and lets a user resume a deposit whose funding landed but whose flow
    /// aborted before the SPV open (bridge H2 / L3).
    pub fn htlc_utxos(&self, script: &ScriptBuf) -> Result<Vec<HtlcUtxo>, String> {
        use serde_json::json;
        let addr = htlc_address(script, self.network);
        let desc = format!("addr({addr})");
        let res: serde_json::Value = self
            .rpc
            .call("scantxoutset", &[json!("start"), json!([{ "desc": desc }])])
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for u in res["unspents"].as_array().into_iter().flatten() {
            let sats = (u["amount"].as_f64().unwrap_or(0.0) * 1e8).round() as u64;
            let txid_str = u["txid"].as_str().ok_or("scan: missing txid")?;
            let vout = u["vout"].as_u64().ok_or("scan: missing vout")? as u32;
            let txid = Txid::from_str(txid_str).map_err(|e| e.to_string())?;
            out.push(HtlcUtxo { outpoint: OutPoint { txid, vout }, value: Amount::from_sat(sats), script: script.clone() });
        }
        Ok(out)
    }

    /// The hash of the block `txid` is confirmed in on this node's best chain (internal
    /// byte order, matching `MintProof::deposit_block_hash`), or `None` while unconfirmed.
    pub fn tx_block_hash(&self, txid: &Txid) -> Result<Option<[u8; 32]>, String> {
        match self.rpc.get_raw_transaction_info(txid, None) {
            Ok(info) => Ok(info.blockhash.map(|h| h.to_byte_array())),
            Err(_) => Ok(None),
        }
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
        if fee >= utxo.value {
            return Err(format!(
                "HTLC spend fee {} sats >= utxo value {} sats",
                fee.to_sat(),
                utxo.value.to_sat()
            ));
        }
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

/// The Bitcoin operations the atomic swap needs from a wallet backend, abstracted so
/// the swap can run over EITHER a local node ([`Btc`], regtest/dev) OR a node-free
/// self-custody wallet on an Esplora API ([`selfcustody::SelfCustodyBtc`], production).
/// Both the user and the bridge/LP use the same interface, so no bitcoind is required.
pub trait BtcBackend {
    /// Fund an HTLC's P2WSH address with `amount`; return the confirmed funding UTXO.
    fn fund_htlc(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String>;
    /// Spend an HTLC's claim branch with `preimage`, signed by `key`, paying `dest`.
    fn claim(&self, utxo: &HtlcUtxo, preimage: &[u8], key: &Key, dest: &Address, fee: Amount) -> Result<Txid, String>;
    /// Current chain tip height (for locktime math).
    fn height(&self) -> Result<u64, String>;
    /// Bitcoin network this backend is talking to (drives race-safe timeout profiles).
    fn network(&self) -> Network;
    /// The preimage revealed in a claim transaction (witness item 1).
    fn preimage_from_claim(&self, txid: &Txid) -> Option<Vec<u8>>;
    /// Wait until `txid` is confirmed (mines on regtest; waits for real confs otherwise).
    fn confirm(&self, txid: &Txid) -> Result<(), String>;
    /// Estimated fee rate (sat/vB) for confirmation within ~`target` blocks. Used to
    /// price HTLC claim/refund spends dynamically — a hardcoded fee can fall below the
    /// mempool min-relay rate on a busy mainnet and strand a claim past its CLTV timelock.
    fn fee_rate_sat_vb(&self, target: u32) -> Result<f64, String>;
    /// Broadcast an HTLC funding tx and return its UTXO WITHOUT waiting for confirmations
    /// (see [`Btc::fund_htlc_unconfirmed`]). Default: the confirmed variant.
    fn fund_htlc_unconfirmed(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
        self.fund_htlc(script, amount)
    }
    /// Unspent outputs locked to `script`'s P2WSH address, if this backend can look them up.
    /// Used to avoid double-funding an HTLC and to resume an aborted deposit.
    fn htlc_utxos(&self, _script: &ScriptBuf) -> Result<Vec<HtlcUtxo>, String> {
        Err("htlc_utxos not supported by this backend".to_string())
    }
    /// Spend an HTLC's REFUND branch after `locktime` with `key`, paying `dest`. Lets the
    /// operator watcher recover BTC it locked for a redeem the user never claimed (bridge M5).
    fn refund(&self, _utxo: &HtlcUtxo, _key: &Key, _locktime: u32, _dest: &Address, _fee: Amount) -> Result<Txid, String> {
        Err("refund not supported by this backend".to_string())
    }
    /// The block (internal byte order) `txid` is confirmed in on this backend's best chain,
    /// `None` while unconfirmed. Used to detect a deposit re-mined by a reorg so its immature
    /// mint can be re-anchored before the void grace expires (bridge M2).
    fn tx_block_hash(&self, _txid: &Txid) -> Result<Option<[u8; 32]>, String> {
        Err("tx_block_hash not supported by this backend".to_string())
    }
    /// If the HTLC `utxo` has been spent via its CLAIM branch (revealing the preimage), return
    /// that preimage; `None` if still unspent or spent via the refund branch. Lets the redeem
    /// watcher detect the user's BTC claim and finalize the burn autonomously, without being
    /// handed the claim txid. `since_height` bounds any block scan (the lock's funding height).
    fn find_htlc_spend_preimage(&self, utxo: &HtlcUtxo, since_height: u64) -> Result<Option<Vec<u8>>, String>;

    /// Confirmations of `txid` on this backend's best chain (0 if unconfirmed/unknown). Used
    /// by the operator watcher to DEFER sweeping a deposit until it is buried past the mint's
    /// maturity + reorg-void grace (M4), so a benign reorg that voids an immature mint can
    /// never strand an already-swept deposit. Only the operator's node backend needs this;
    /// the default is "unsupported" (the self-custody user wallet never runs the sweep).
    fn tx_confirmations(&self, _txid: &Txid) -> Result<u64, String> {
        Err("tx_confirmations not supported by this backend".to_string())
    }

    // ---- SPV proof material (UNTRUSTED transport: headers carry their own
    // proof-of-work and the merkle proof is re-verified by every validator, so a
    // lying backend can only fail to deliver, never forge a mint) ----

    /// The raw 80-byte header at `height` on this backend's best chain.
    fn block_header(&self, height: u64) -> Result<[u8; 80], String>;
    /// The raw bytes of a confirmed transaction.
    fn raw_tx(&self, txid: &Txid) -> Result<Vec<u8>, String>;
    /// A `merkleblock` inclusion proof for a confirmed transaction (bitcoind's
    /// `gettxoutproof` / Esplora's `merkleblock-proof` — identical wire format).
    fn txout_proof(&self, txid: &Txid) -> Result<Vec<u8>, String>;
}

impl BtcBackend for Btc {
    fn fund_htlc(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
        Btc::fund_htlc(self, script, amount)
    }
    fn claim(&self, utxo: &HtlcUtxo, preimage: &[u8], key: &Key, dest: &Address, fee: Amount) -> Result<Txid, String> {
        Btc::claim(self, utxo, preimage, key, dest, fee)
    }
    fn height(&self) -> Result<u64, String> {
        Btc::height(self)
    }
    fn network(&self) -> Network {
        self.network
    }
    fn preimage_from_claim(&self, txid: &Txid) -> Option<Vec<u8>> {
        Btc::preimage_from_claim(self, txid)
    }
    fn confirm(&self, txid: &Txid) -> Result<(), String> {
        Btc::confirm(self, txid)
    }
    fn fund_htlc_unconfirmed(&self, script: &ScriptBuf, amount: Amount) -> Result<HtlcUtxo, String> {
        Btc::fund_htlc_unconfirmed(self, script, amount)
    }
    fn htlc_utxos(&self, script: &ScriptBuf) -> Result<Vec<HtlcUtxo>, String> {
        Btc::htlc_utxos(self, script)
    }
    fn refund(&self, utxo: &HtlcUtxo, key: &Key, locktime: u32, dest: &Address, fee: Amount) -> Result<Txid, String> {
        Btc::refund(self, utxo, key, locktime, dest, fee)
    }
    fn tx_block_hash(&self, txid: &Txid) -> Result<Option<[u8; 32]>, String> {
        Btc::tx_block_hash(self, txid)
    }
    fn fee_rate_sat_vb(&self, target: u32) -> Result<f64, String> {
        // Regtest has no fee market; use a nominal 1 sat/vB.
        if self.is_regtest() {
            return Ok(1.0);
        }
        // `estimatesmartfee` returns `feerate` in BTC/kvB; convert to sat/vB.
        let res: serde_json::Value = self
            .rpc
            .call("estimatesmartfee", &[serde_json::json!(target)])
            .map_err(|e| e.to_string())?;
        let sat_vb = res["feerate"].as_f64().unwrap_or(0.0) * 100_000_000.0 / 1000.0;
        // Never act on an absurd estimate (bridge M4).
        Ok(cap_fee_rate(if sat_vb >= 1.0 { sat_vb } else { 2.0 }))
    }
    fn find_htlc_spend_preimage(&self, utxo: &HtlcUtxo, since_height: u64) -> Result<Option<Vec<u8>>, String> {
        let tip = self.height()?;
        let want_txid = utxo.outpoint.txid.to_string();
        for h in since_height..=tip {
            let hash = self.rpc.get_block_hash(h).map_err(|e| e.to_string())?;
            // getblock verbosity 2 → full tx bodies with vin + witnesses.
            let block: serde_json::Value = self
                .rpc
                .call("getblock", &[serde_json::json!(hash.to_string()), serde_json::json!(2)])
                .map_err(|e| e.to_string())?;
            for tx in block["tx"].as_array().into_iter().flatten() {
                for vin in tx["vin"].as_array().into_iter().flatten() {
                    if vin["txid"].as_str() == Some(want_txid.as_str())
                        && vin["vout"].as_u64() == Some(utxo.outpoint.vout as u64)
                    {
                        // Claim witness = [sig, PREIMAGE, selector=1, script]; refund has an empty item 1.
                        let pre = vin["txinwitness"].as_array().and_then(|w| w.get(1)).and_then(|x| x.as_str());
                        return Ok(match pre {
                            Some(hexpre) if !hexpre.is_empty() => Some(hex::decode(hexpre).map_err(|e| e.to_string())?),
                            _ => None, // spent via refund — no preimage
                        });
                    }
                }
            }
        }
        Ok(None) // not spent yet
    }
    fn tx_confirmations(&self, txid: &Txid) -> Result<u64, String> {
        match self.rpc.get_raw_transaction_info(txid, None) {
            Ok(info) => Ok(info.confirmations.unwrap_or(0) as u64),
            Err(_) => Ok(0), // unknown / not yet in a block
        }
    }
    fn block_header(&self, height: u64) -> Result<[u8; 80], String> {
        let hash = self.rpc.get_block_hash(height).map_err(|e| e.to_string())?;
        let header = self.rpc.get_block_header(&hash).map_err(|e| e.to_string())?;
        bitcoin::consensus::encode::serialize(&header)
            .try_into()
            .map_err(|_| "header is not 80 bytes".to_string())
    }
    fn raw_tx(&self, txid: &Txid) -> Result<Vec<u8>, String> {
        let tx = self.rpc.get_raw_transaction(txid, None).map_err(|e| e.to_string())?;
        Ok(bitcoin::consensus::encode::serialize(&tx))
    }
    fn txout_proof(&self, txid: &Txid) -> Result<Vec<u8>, String> {
        let hex_proof: String = self
            .rpc
            .call("gettxoutproof", &[serde_json::json!([txid.to_string()])])
            .map_err(|e| e.to_string())?;
        hex::decode(hex_proof.trim()).map_err(|e| e.to_string())
    }
}

pub mod esplora;
pub mod hdwallet;
pub mod selfcustody;
pub mod swap;
pub mod txbuilder;
pub mod watcher;
pub mod zcrypt;

/// A fixed P2WPKH address whose private key nobody uses — mining here burns the
/// coinbase so confirming swap txs doesn't credit any tracked wallet's balance.
fn throwaway_address(network: Network) -> Address {
    let key = Key::from_bytes(&[0xEE; 32]);
    Address::p2wpkh(&key.compressed(), network)
}

/// Parse and network-check an address string against `network`.
pub fn parse_address(s: &str, network: Network) -> Result<Address, String> {
    Address::from_str(s)
        .map_err(|e| e.to_string())?
        .require_network(network)
        .map_err(|e| e.to_string())
}

// Silence an unused-import lint for the re-exported sighash-type alias.
const _: _Sht = _Sht::All;
