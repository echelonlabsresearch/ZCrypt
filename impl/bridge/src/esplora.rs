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

/// A wallet UTXO tagged with the HD path that owns it, so the signer can derive the
/// exact key (`change` = 0 receive / 1 change; `index` = address index).
#[derive(Clone, Debug)]
pub struct WalletUtxo {
    pub utxo: Utxo,
    pub change: u32,
    pub index: u32,
    pub address: String,
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

    fn get_json(&self, path: &str) -> Result<Value, String> {
        self.agent()
            .get(&format!("{}{path}", self.base))
            .call()
            .map_err(|e| e.to_string())?
            .into_json()
            .map_err(|e| e.to_string())
    }

    fn get_text(&self, path: &str) -> Result<String, String> {
        self.agent()
            .get(&format!("{}{path}", self.base))
            .call()
            .map_err(|e| e.to_string())?
            .into_string()
            .map_err(|e| e.to_string())
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

    /// Whether an address has any transaction history (used for the gap-limit scan).
    pub fn address_used(&self, addr: &str) -> Result<bool, String> {
        let v = self.get_json(&format!("/address/{addr}"))?;
        let funded = v["chain_stats"]["funded_txo_count"].as_u64().unwrap_or(0)
            + v["mempool_stats"]["funded_txo_count"].as_u64().unwrap_or(0);
        Ok(funded > 0)
    }

    /// Fee rate (sat/vB) for confirmation within ~`target` blocks. Falls back to the
    /// 6-block estimate, then a 1 sat/vB floor. The result is clamped to
    /// [`crate::MAX_FEE_RATE_SAT_VB`]: Esplora is a third party, and a lying or
    /// compromised endpoint must not be able to make the wallet burn an HTLC in fees
    /// (bridge M4).
    pub fn fee_rate_sat_vb(&self, target: u32) -> Result<f64, String> {
        let v = self.get_json("/fee-estimates")?;
        let pick = v[target.to_string()]
            .as_f64()
            .or_else(|| v["6"].as_f64())
            .unwrap_or(1.0);
        Ok(crate::cap_fee_rate(pick))
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

    /// The txid that SPENT output `vout` of `txid`, if any (`/tx/:txid/outspend/:vout`).
    /// `Ok(None)` when the output is still unspent. Lets the redeem watcher detect a user's
    /// HTLC claim without scanning blocks.
    pub fn outspend(&self, txid: &str, vout: u32) -> Result<Option<String>, String> {
        let v = self.get_json(&format!("/tx/{txid}/outspend/{vout}"))?;
        if v["spent"].as_bool().unwrap_or(false) {
            Ok(v["txid"].as_str().map(|s| s.to_string()))
        } else {
            Ok(None)
        }
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
        if min_conf == 0 {
            return Ok(());
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(3 * 60 * 60);
        loop {
            if self.confirmations(txid).unwrap_or(0) >= min_conf {
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
