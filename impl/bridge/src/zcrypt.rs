//! Minimal ZCrypt (CometBFT) RPC client for the bridge — broadcast txs, ABCI
//! queries, and block scanning (to read a revealed HTLC preimage on-chain).

use base64::Engine;
use serde_json::Value;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub struct Zcrypt {
    url: String,
}

impl Zcrypt {
    pub fn new(url: &str) -> Self {
        Zcrypt { url: url.trim_end_matches('/').to_string() }
    }

    fn agent() -> ureq::Agent {
        ureq::builder().timeout(std::time::Duration::from_secs(60)).build()
    }

    /// Broadcast a raw tx (with its 1-byte tag). Returns the `tx_result.data`
    /// (base64-decoded JSON string) on success, or an error with the reject log.
    pub fn broadcast(&self, tx: &[u8]) -> Result<String, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "broadcast_tx_commit",
            "params": { "tx": B64.encode(tx) }
        });
        let resp: Value = Self::agent()
            .post(&self.url)
            .send_json(body)
            .map_err(|e| e.to_string())?
            .into_json()
            .map_err(|e| e.to_string())?;
        if let Some(msg) = resp["error"]["data"].as_str().or_else(|| resp["error"]["message"].as_str()) {
            return Err(format!("node error: {msg}"));
        }
        let res = &resp["result"];
        if res["check_tx"]["code"].as_i64().unwrap_or(1) != 0 {
            return Err(format!("check_tx: {}", res["check_tx"]["log"].as_str().unwrap_or("")));
        }
        if res["tx_result"]["code"].as_i64().unwrap_or(1) != 0 {
            return Err(format!("rejected: {}", res["tx_result"]["log"].as_str().unwrap_or("")));
        }
        let data = res["tx_result"]["data"].as_str().unwrap_or("");
        if data.is_empty() {
            return Ok(String::new());
        }
        let bytes = B64.decode(data).map_err(|e| e.to_string())?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }

    /// An ABCI query returning its (utf-8) string value.
    pub fn query(&self, path: &str) -> Result<String, String> {
        let u = format!("{}/abci_query?path=%22{}%22", self.url, path);
        let b: Value = Self::agent().get(&u).call().map_err(|e| e.to_string())?.into_json().map_err(|e| e.to_string())?;
        let r = &b["result"]["response"];
        if r["code"].as_i64().unwrap_or(0) != 0 {
            return Err(r["log"].as_str().unwrap_or("query error").to_string());
        }
        let v = r["value"].as_str().unwrap_or("");
        if v.is_empty() {
            return Ok(String::new());
        }
        let bytes = B64.decode(v).map_err(|e| e.to_string())?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }

    pub fn height(&self) -> Result<i64, String> {
        let b: Value = Self::agent()
            .get(&format!("{}/status", self.url))
            .call()
            .map_err(|e| e.to_string())?
            .into_json()
            .map_err(|e| e.to_string())?;
        b["result"]["sync_info"]["latest_block_height"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| "no height".to_string())
    }

    /// All raw txs in a block (decoded).
    pub fn block_txs(&self, height: i64) -> Vec<Vec<u8>> {
        let u = format!("{}/block?height={}", self.url, height);
        let b: Value = match Self::agent().get(&u).call().ok().and_then(|r| r.into_json().ok()) {
            Some(b) => b,
            None => return vec![],
        };
        b["result"]["block"]["data"]["txs"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|t| t.as_str().and_then(|s| B64.decode(s).ok()))
            .collect()
    }

    /// All commitment-tree leaves in order (the shield decoy pool).
    pub fn leaves(&self) -> Result<Vec<[u64; 8]>, String> {
        let hexs = self.query("/commit/leaves")?;
        let raw = hex::decode(hexs.trim()).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for chunk in raw.chunks(64) {
            if chunk.len() < 64 {
                break;
            }
            let mut c = [0u64; 8];
            for (i, ci) in c.iter_mut().enumerate() {
                *ci = u64::from_le_bytes(chunk[i * 8..i * 8 + 8].try_into().unwrap());
            }
            out.push(c);
        }
        Ok(out)
    }

    /// Scan blocks `from..=to` for an HTLC_CLAIM (0x5B) tx of `escrow_id`, and
    /// return the revealed preimage (the bytes after the 33-byte tag+id).
    pub fn find_claim_preimage(&self, escrow_id: &[u8; 32], from: i64, to: i64) -> Option<Vec<u8>> {
        for h in from..=to {
            for tx in self.block_txs(h) {
                if tx.first() == Some(&0x5B) && tx.len() > 33 && &tx[1..33] == escrow_id {
                    return Some(tx[33..].to_vec());
                }
            }
        }
        None
    }
}
