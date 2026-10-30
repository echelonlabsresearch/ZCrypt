//! Esplora light-wallet data client (Blockstream/mempool.space REST). Gives the
//! self-custody [`crate::hdwallet::HdWallet`] everything it needs from the Bitcoin
//! network WITHOUT running a node and WITHOUT holding keys: per-address UTXOs, fee
//! rates, transaction broadcast, and confirmation counts.
//!
//! Esplora is address-oriented, so a wallet's coins are found by a **gap-limit scan**
//! over its derived addresses (query index 0, 1, 2, … per chain until a run of unused
//! addresses). That is the one inefficiency vs a Blockbook `xpub` query (one call for
//! the whole wallet); a Blockbook variant can be added for a production endpoint. The
//! API shapes here are the standard Esplora REST format served by both blockstream.info
//! and mempool.space.
//!
//! Nothing secret ever leaves: only addresses and signed transactions are sent.

use crate::hdwallet::HdWallet;
use serde_json::Value;
use std::str::FromStr;
use std::time::Duration;

/// A reachable Esplora endpoint, e.g. `https://mempool.space/signet/api` or
/// `https://blockstream.info/api` (mainnet).
pub struct Esplora {
    base: String,
}

/// One unspent output at an address.
#[derive(Clone, Debug)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64, // satoshis
    pub confirmed: bool,
    pub block_height: Option<u64>,
}

/// The spend of one output as Esplora reports it: the spending txid and whether that
/// spending tx is confirmed (a mempool spend has `confirmed == false`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outspend {
    pub txid: String,
    pub confirmed: bool,
}

/// Parse an `/outspend` body. Pure so it can be unit-tested offline.
fn parse_outspend(v: &Value) -> Result<Option<Outspend>, String> {
    if !v["spent"].as_bool().unwrap_or(false) {
        return Ok(None);
    }
    let txid = v["txid"].as_str().ok_or("outspend: spent but no spending txid")?.to_string();
    let confirmed = v["status"]["confirmed"].as_bool().unwrap_or(false);
    Ok(Some(Outspend { txid, confirmed }))
}

/// Pick the rate for `target` from a `/fee-estimates` body: the exact target, else the
/// 6-block estimate, else [`crate::FALLBACK_FEE_RATE_SAT_VB`]. Pure for offline tests.
fn pick_fee_rate(v: &Value, target: u32) -> f64 {
    v[target.to_string()]
        .as_f64()
        .or_else(|| v["6"].as_f64())
        .filter(|r| r.is_finite() && *r > 0.0)
        .unwrap_or(crate::FALLBACK_FEE_RATE_SAT_VB)
}

/// A wallet UTXO tagged with the HD path that owns it, so the signer can derive the
/// exact key (`change` = 0 receive / 1 change; `index` = address index).
#[derive(Clone, Debug)]
pub struct WalletUtxo {
    pub utxo: Utxo,
    pub change: u32,
    pub index: u32,
    pub address: String,
}

/// How long a gap-limit scan result is reused (see [`Esplora::wallet_utxos`]).
const SCAN_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(20);

type ScanCache = std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, Vec<WalletUtxo>)>>;
fn scan_cache() -> &'static ScanCache {
    static CACHE: std::sync::OnceLock<ScanCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

impl Esplora {
    pub fn new(base: &str) -> Self {
        Esplora { base: base.trim_end_matches('/').to_string() }
    }

    /// HTTP agent for this Esplora endpoint, routed through Tor when configured. Esplora is
    /// third-party and always remote, so this is the bridge's most privacy-relevant traffic.
    fn agent(&self) -> ureq::Agent {
        crate::proxied_agent(&self.base, 30)
    }

    /// GET `path`, retrying a rate-limit or overload answer (429, 502, 503) with a growing
    /// pause: public Esplora servers throttle the burst a gap-limit scan makes, and giving
    /// up on the first 429 turned a routine send into "could not pay". A `Retry-After`
    /// header is honoured (capped); otherwise 2 s, 4 s, 8 s, 16 s.
    fn get(&self, path: &str) -> Result<ureq::Response, String> {
        const RETRIES: u32 = 4;
        let url = format!("{}{path}", self.base);
        let mut wait = std::time::Duration::from_secs(2);
        for attempt in 0..=RETRIES {
            match self.agent().get(&url).call() {
                Ok(r) => return Ok(r),
                Err(ureq::Error::Status(code @ (429 | 502 | 503), r)) if attempt < RETRIES => {
                    let hinted = r
                        .header("Retry-After")
                        .and_then(|h| h.trim().parse::<u64>().ok())
                        .map(std::time::Duration::from_secs);
                    let pause = hinted.unwrap_or(wait).min(std::time::Duration::from_secs(20));
                    let _ = code;
                    std::thread::sleep(pause);
                    wait *= 2;
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        unreachable!("the loop returns on the last attempt")
    }

    fn get_json(&self, path: &str) -> Result<Value, String> {
        self.get(path)?.into_json().map_err(|e| e.to_string())
    }

    fn get_text(&self, path: &str) -> Result<String, String> {
        self.get(path)?.into_string().map_err(|e| e.to_string())
    }

    /// UTXOs at a single address.
    pub fn address_utxos(&self, addr: &str) -> Result<Vec<Utxo>, String> {
        let v = self.get_json(&format!("/address/{addr}/utxo"))?;
        let arr = v.as_array().ok_or("esplora: /utxo did not return an array")?;
        let mut out = Vec::with_capacity(arr.len());
        for u in arr {
            out.push(Utxo {
                txid: u["txid"].as_str().ok_or("utxo: missing txid")?.to_string(),
                vout: u["vout"].as_u64().ok_or("utxo: missing vout")? as u32,
                value: u["value"].as_u64().ok_or("utxo: missing value")?,
                confirmed: u["status"]["confirmed"].as_bool().unwrap_or(false),
                block_height: u["status"]["block_height"].as_u64(),
            });
        }
        Ok(out)
    }

    /// Every CONFIRMED output paying `addr` in its recent history (`/address/:addr/txs`,
    /// the newest 25 confirmed txs plus the mempool), spent or not. Lets a wallet find an
    /// HTLC funding that has already been spent, which `/utxo` no longer lists.
    pub fn address_outputs(&self, addr: &str) -> Result<Vec<Utxo>, String> {
        let v = self.get_json(&format!("/address/{addr}/txs"))?;
        let arr = v.as_array().ok_or("esplora: /txs did not return an array")?;
        let mut out = Vec::new();
        for tx in arr {
            let txid = tx["txid"].as_str().ok_or("tx: missing txid")?.to_string();
            let confirmed = tx["status"]["confirmed"].as_bool().unwrap_or(false);
            let block_height = tx["status"]["block_height"].as_u64();
            for (i, o) in tx["vout"].as_array().into_iter().flatten().enumerate() {
                if o["scriptpubkey_address"].as_str() == Some(addr) {
                    out.push(Utxo {
                        txid: txid.clone(),
                        vout: i as u32,
                        value: o["value"].as_u64().ok_or("vout: missing value")?,
                        confirmed,
                        block_height,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Whether an address has any transaction history (used for the gap-limit scan).
    pub fn address_used(&self, addr: &str) -> Result<bool, String> {
        let v = self.get_json(&format!("/address/{addr}"))?;
        let funded = v["chain_stats"]["funded_txo_count"].as_u64().unwrap_or(0)
            + v["mempool_stats"]["funded_txo_count"].as_u64().unwrap_or(0);
        Ok(funded > 0)
    }

    /// Fee rate (sat/vB) for confirmation within ~`target` blocks. Falls back to the
    /// 6-block estimate, then to the conservative [`crate::FALLBACK_FEE_RATE_SAT_VB`]
    /// (not a 1 sat/vB floor, which could strand an HTLC claim below the relay rate until
    /// its timelock passes, bridge L4). The result is clamped to
    /// [`crate::MAX_FEE_RATE_SAT_VB`]: Esplora is a third party, and a lying or
    /// compromised endpoint must not be able to make the wallet burn an HTLC in fees
    /// (bridge M4).
    pub fn fee_rate_sat_vb(&self, target: u32) -> Result<f64, String> {
        let v = self.get_json("/fee-estimates")?;
        Ok(crate::cap_fee_rate(pick_fee_rate(&v, target)))
    }

    /// Confirmation status of a transaction: `(confirmed, block_height, block_hash)` where
    /// the hash is in INTERNAL byte order (what `MintProof::deposit_block_hash` returns),
    /// or `None` while unconfirmed.
    pub fn tx_status(&self, txid: &str) -> Result<Option<(u64, [u8; 32])>, String> {
        use bitcoin::hashes::Hash as _;
        let v = self.get_json(&format!("/tx/{txid}/status"))?;
        if !v["confirmed"].as_bool().unwrap_or(false) {
            return Ok(None);
        }
        let h = v["block_height"].as_u64().ok_or("status: confirmed but no height")?;
        let hash_hex = v["block_hash"].as_str().ok_or("status: confirmed but no block hash")?;
        let bh = bitcoin::BlockHash::from_str(hash_hex).map_err(|e| e.to_string())?;
        Ok(Some((h, bh.to_byte_array())))
    }

    /// Broadcast a raw (hex) transaction; returns the txid.
    pub fn broadcast(&self, tx_hex: &str) -> Result<String, String> {
        scan_cache().lock().unwrap().clear(); // the coin set changes with this tx
        let resp = self.agent()
            .post(&format!("{}/tx", self.base))
            .send_string(tx_hex)
            .map_err(|e| match e {
                // Esplora returns the reason in the body on a 400 (e.g. "min relay fee").
                ureq::Error::Status(code, r) => {
                    format!("broadcast rejected ({code}): {}", r.into_string().unwrap_or_default())
                }
                other => other.to_string(),
            })?;
        resp.into_string().map(|s| s.trim().to_string()).map_err(|e| e.to_string())
    }

    /// Full transaction JSON (`/tx/{txid}`) — used to read a claim tx's witness and
    /// extract the revealed HTLC preimage.
    pub fn tx_json(&self, txid: &str) -> Result<Value, String> {
        self.get_json(&format!("/tx/{txid}"))
    }

    /// The txid that SPENT output `vout` of `txid`, if any (`/tx/:txid/outspend/:vout`),
    /// confirmed OR still in the mempool. `Ok(None)` when the output is unspent. Callers
    /// that must distinguish a confirmed spend use [`Self::outspend_status`].
    pub fn outspend(&self, txid: &str, vout: u32) -> Result<Option<String>, String> {
        Ok(self.outspend_status(txid, vout)?.map(|s| s.txid))
    }

    /// The spend of output `vout` of `txid` with its confirmation state, or `Ok(None)` when
    /// unspent. Esplora reports a mempool spend with `spent: true` and
    /// `status.confirmed: false`; such a spend can still be replaced or dropped, so it is
    /// NOT a confirmed spend (bridge M12). Lets the redeem watcher detect a user's HTLC
    /// claim without scanning blocks.
    pub fn outspend_status(&self, txid: &str, vout: u32) -> Result<Option<Outspend>, String> {
        let v = self.get_json(&format!("/tx/{txid}/outspend/{vout}"))?;
        parse_outspend(&v)
    }

    /// Current chain tip height.
    pub fn tip_height(&self) -> Result<u64, String> {
        self.get_text("/blocks/tip/height")?.trim().parse().map_err(|e| format!("tip height: {e}"))
    }

    /// The raw 80-byte block header at `height` (via `/block-height` → `/block/:hash/header`).
    /// Untrusted transport for the consensus SPV chain: the header's own proof-of-work
    /// is what gets verified, so a lying endpoint cannot forge anything.
    pub fn block_header(&self, height: u64) -> Result<[u8; 80], String> {
        let hash = self.get_text(&format!("/block-height/{height}"))?;
        let hex_hdr = self.get_text(&format!("/block/{}/header", hash.trim()))?;
        hex::decode(hex_hdr.trim())
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "header is not 80 bytes".to_string())
    }

    /// Raw bytes of a transaction (`/tx/:txid/hex`).
    pub fn tx_raw(&self, txid: &str) -> Result<Vec<u8>, String> {
        let h = self.get_text(&format!("/tx/{txid}/hex"))?;
        hex::decode(h.trim()).map_err(|e| e.to_string())
    }

    /// A `merkleblock` inclusion proof for a confirmed tx
    /// (`/tx/:txid/merkleblock-proof` — byte-identical to bitcoind's `gettxoutproof`).
    pub fn merkleblock_proof(&self, txid: &str) -> Result<Vec<u8>, String> {
        let h = self.get_text(&format!("/tx/{txid}/merkleblock-proof"))?;
        hex::decode(h.trim()).map_err(|e| e.to_string())
    }

    /// Merkle proof of the coinbase and `txid` in the confirming block, plus the
    /// raw coinbase. Built from `/block/:hash/txids` and the raw header, then
    /// checked against that header's merkle root by consensus.
    pub fn mint_inclusion(&self, txid: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
        use bitcoin::consensus::{deserialize, serialize};
        use bitcoin::merkle_tree::PartialMerkleTree;
        use bitcoin::{BlockHash, MerkleBlock, Txid};

        let v = self.get_json(&format!("/tx/{txid}/status"))?;
        if !v["confirmed"].as_bool().unwrap_or(false) {
            return Err(format!("{txid} is unconfirmed"));
        }
        let hash = v["block_hash"].as_str().ok_or("status: confirmed but no block hash")?;
        let txids_v = self.get_json(&format!("/block/{hash}/txids"))?;
        let txid_strs: Vec<String> = serde_json::from_value(txids_v).map_err(|e| e.to_string())?;
        if txid_strs.is_empty() {
            return Err("block has no transactions".to_string());
        }
        let header_hex = self.get_text(&format!("/block/{hash}/header"))?;
        let header_bytes = hex::decode(header_hex.trim()).map_err(|e| e.to_string())?;
        let header: bitcoin::block::Header =
            deserialize(&header_bytes).map_err(|e| format!("block header: {e}"))?;
        let want = BlockHash::from_str(hash).map_err(|e| e.to_string())?;
        if header.block_hash() != want {
            return Err("block header does not match the reported block hash".to_string());
        }
        let parsed: Vec<Txid> = txid_strs
            .iter()
            .map(|s| Txid::from_str(s).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        let fund = Txid::from_str(txid).map_err(|e| e.to_string())?;
        let cb_id = parsed[0];
        let matches: Vec<bool> = parsed.iter().map(|t| *t == cb_id || *t == fund).collect();
        let pmt = PartialMerkleTree::from_txids(&parsed, &matches);
        let mb = MerkleBlock { header, txn: pmt };
        let coinbase_raw = self.tx_raw(&txid_strs[0])?;
        Ok((serialize(&mb), coinbase_raw))
    }

    /// Confirmations of a transaction (0 if unconfirmed / in mempool).
    pub fn confirmations(&self, txid: &str) -> Result<u32, String> {
        let v = self.get_json(&format!("/tx/{txid}/status"))?;
        if !v["confirmed"].as_bool().unwrap_or(false) {
            return Ok(0);
        }
        let h = v["block_height"].as_u64().ok_or("status: confirmed but no height")?;
        let tip = self.tip_height()?;
        Ok((tip.saturating_sub(h) + 1) as u32)
    }

    /// Block until `txid` has `min_conf` confirmations (no-op if `min_conf` == 0).
    /// Polls every 15s, times out after ~3h (a dropped/replaced tx won't hang forever).
    pub fn wait_confirmed(&self, txid: &str, min_conf: u32) -> Result<(), String> {
        self.wait_confirmed_with(txid, min_conf, &|_, _| {})
    }

    /// [`Self::wait_confirmed`] that reports `(have, need)` to `on_conf` on every poll, so a
    /// UI can show "3/6 confirmations" instead of a blind wait.
    pub fn wait_confirmed_with(&self, txid: &str, min_conf: u32, on_conf: &dyn Fn(u32, u32)) -> Result<(), String> {
        if min_conf == 0 {
            return Ok(());
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(3 * 60 * 60);
        loop {
            let have = self.confirmations(txid).unwrap_or(0);
            on_conf(have.min(min_conf), min_conf);
            if have >= min_conf {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!("timed out waiting for {min_conf} confirmation(s) of {txid}"));
            }
            std::thread::sleep(Duration::from_secs(15));
        }
    }

    /// All UTXOs owned by `wallet`, tagged with the HD path that signs each — found by
    /// scanning the receive (0) and change (1) chains until `GAP` consecutive unused
    /// addresses. (A Blockbook `xpub` query would return the same set in one call.)
    pub fn wallet_utxos(&self, wallet: &HdWallet) -> Result<Vec<WalletUtxo>, String> {
        // One scan is ~45 requests. A send prices its fee and then builds the tx, and the
        // UI shows the balance beside it: three scans in a row trip public rate limits.
        // Serve a recent scan again; a broadcast from this process invalidates it.
        let key = format!("{}|{}", self.base, wallet.address(0, 0)?);
        if let Some(hit) = scan_cache().lock().unwrap().get(&key) {
            if hit.0.elapsed() < SCAN_CACHE_TTL {
                return Ok(hit.1.clone());
            }
        }
        let out = self.wallet_utxos_uncached(wallet)?;
        scan_cache().lock().unwrap().insert(key, (std::time::Instant::now(), out.clone()));
        Ok(out)
    }

    fn wallet_utxos_uncached(&self, wallet: &HdWallet) -> Result<Vec<WalletUtxo>, String> {
        const GAP: u32 = 20;
        let mut out = Vec::new();
        for change in [0u32, 1u32] {
            let mut empty = 0u32;
            let mut index = 0u32;
            while empty < GAP {
                let addr = wallet.address(change, index)?.to_string();
                if self.address_used(&addr)? {
                    empty = 0;
                    for u in self.address_utxos(&addr)? {
                        out.push(WalletUtxo { utxo: u, change, index, address: addr.clone() });
                    }
                } else {
                    empty += 1;
                }
                index += 1;
            }
        }
        Ok(out)
    }

    /// Total confirmed + unconfirmed balance (satoshis) across the wallet.
    pub fn wallet_balance(&self, wallet: &HdWallet) -> Result<u64, String> {
        Ok(self.wallet_utxos(wallet)?.iter().map(|u| u.utxo.value).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Network-dependent smoke tests — ignored by default so CI stays offline. Run with:
    //   cargo test -p zcrypt-bridge --lib esplora -- --ignored --nocapture
    const SIGNET: &str = "https://mempool.space/signet/api";

    #[test]
    fn outspend_distinguishes_mempool_from_confirmed_spend() {
        let unspent = serde_json::json!({ "spent": false });
        assert_eq!(parse_outspend(&unspent).unwrap(), None);
        let mempool = serde_json::json!({ "spent": true, "txid": "ab", "status": { "confirmed": false } });
        assert_eq!(parse_outspend(&mempool).unwrap(), Some(Outspend { txid: "ab".into(), confirmed: false }));
        let confirmed = serde_json::json!({
            "spent": true, "txid": "cd", "status": { "confirmed": true, "block_height": 7 }
        });
        assert_eq!(parse_outspend(&confirmed).unwrap(), Some(Outspend { txid: "cd".into(), confirmed: true }));
        // spent without a txid is malformed, not "unspent"
        assert!(parse_outspend(&serde_json::json!({ "spent": true })).is_err());
    }

    #[test]
    fn fee_estimate_falls_back_conservatively() {
        let v = serde_json::json!({ "3": 12.5, "6": 8.0 });
        assert_eq!(pick_fee_rate(&v, 3), 12.5);
        assert_eq!(pick_fee_rate(&v, 4), 8.0); // missing target: 6-block estimate
        let empty = serde_json::json!({});
        assert_eq!(pick_fee_rate(&empty, 3), crate::FALLBACK_FEE_RATE_SAT_VB);
        let zero = serde_json::json!({ "6": 0.0 });
        assert_eq!(pick_fee_rate(&zero, 3), crate::FALLBACK_FEE_RATE_SAT_VB);
    }

    #[test]
    #[ignore]
    fn live_fee_and_tip() {
        let e = Esplora::new(SIGNET);
        let fee = e.fee_rate_sat_vb(6).unwrap();
        let tip = e.tip_height().unwrap();
        eprintln!("signet fee(6) = {fee} sat/vB, tip = {tip}");
        assert!(fee >= 1.0);
        assert!(tip > 100_000);
    }

    #[test]
    #[ignore]
    fn live_address_utxos_parse() {
        let e = Esplora::new(SIGNET);
        // Any address; the point is that the response parses without error.
        let u = e.address_utxos("tb1q36pc4spq97mkn5n6qe07nrvnp77mrmepudflj4").unwrap();
        eprintln!("utxos: {}", u.len());
    }
}
