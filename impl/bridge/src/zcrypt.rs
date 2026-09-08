//! Minimal ZCrypt (CometBFT) RPC client for the bridge — broadcast txs, ABCI
//! queries, and block scanning (to read a revealed HTLC preimage on-chain).

use base64::Engine;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};

/// Pre-broadcast timing jitter (privacy): a random 250 to 2500 ms delay before every
/// broadcast, so the moment a tx reaches the node does not fingerprint the moment a user
/// or operator acted (the desktop wallet applies the same jitter). Default ON; the e2e
/// drivers switch it off with [`set_broadcast_jitter`] (or `ZCRYPT_BROADCAST_JITTER=0`)
/// so their hundreds of broadcasts stay fast.
static BROADCAST_JITTER: AtomicBool = AtomicBool::new(true);
static JITTER_ENV_CHECKED: AtomicBool = AtomicBool::new(false);

/// Turn the pre-broadcast jitter on or off for this process.
pub fn set_broadcast_jitter(on: bool) {
    JITTER_ENV_CHECKED.store(true, Ordering::Relaxed);
    BROADCAST_JITTER.store(on, Ordering::Relaxed);
}

/// Whether broadcasts are jittered right now (env `ZCRYPT_BROADCAST_JITTER=0` disables it
/// once, unless [`set_broadcast_jitter`] was called explicitly).
pub fn broadcast_jitter_enabled() -> bool {
    if !JITTER_ENV_CHECKED.swap(true, Ordering::Relaxed) {
        if let Ok(v) = std::env::var("ZCRYPT_BROADCAST_JITTER") {
            let off = matches!(v.trim(), "0" | "off" | "false" | "no");
            BROADCAST_JITTER.store(!off, Ordering::Relaxed);
        }
    }
    BROADCAST_JITTER.load(Ordering::Relaxed)
}

fn jitter_sleep() {
    if broadcast_jitter_enabled() {
        use rand::Rng as _;
        let ms: u64 = rand::thread_rng().gen_range(250..=2500);
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// The ZCrypt node operations the bridge's operator-side logic needs, abstracted so the
/// watcher and the swap orchestration can run against the live CometBFT RPC ([`Zcrypt`])
/// or an in-memory fake in tests. `&Zcrypt` coerces to `&dyn ZcNode` at every call site.
pub trait ZcNode {
    fn height(&self) -> Result<i64, String>;
    fn block_txs(&self, height: i64) -> Result<Vec<Vec<u8>>, String>;
    fn query(&self, path: &str) -> Result<String, String>;
    fn broadcast(&self, tx: &[u8]) -> Result<String, String>;
}

impl ZcNode for Zcrypt {
    fn height(&self) -> Result<i64, String> {
        Zcrypt::height(self)
    }
    fn block_txs(&self, height: i64) -> Result<Vec<Vec<u8>>, String> {
        Zcrypt::block_txs(self, height)
    }
    fn query(&self, path: &str) -> Result<String, String> {
        Zcrypt::query(self, path)
    }
    fn broadcast(&self, tx: &[u8]) -> Result<String, String> {
        Zcrypt::broadcast(self, tx)
    }
}

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub struct Zcrypt {
    url: String,
}

impl Zcrypt {
    pub fn new(url: &str) -> Self {
        Zcrypt { url: url.trim_end_matches('/').to_string() }
    }

    /// HTTP agent for this node's URL, routed through Tor when configured (loopback direct).
    fn agent(&self) -> ureq::Agent {
        crate::proxied_agent(&self.url, 60)
    }

    /// Broadcast a raw tx (with its 1-byte tag). Returns the `tx_result.data`
    /// (base64-decoded JSON string) on success, or an error with the reject log.
    pub fn broadcast(&self, tx: &[u8]) -> Result<String, String> {
        jitter_sleep();
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "broadcast_tx_commit",
            "params": { "tx": B64.encode(tx) }
        });
        let resp: Value = self.agent()
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
        let b: Value = self.agent().get(&u).call().map_err(|e| e.to_string())?.into_json().map_err(|e| e.to_string())?;
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
        let b: Value = self.agent()
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

    /// All raw txs in a block (decoded). Transport/JSON failures return `Err` so callers
    /// do not treat an unreachable node as an empty block (which would skip settlements).
    pub fn block_txs(&self, height: i64) -> Result<Vec<Vec<u8>>, String> {
        let u = format!("{}/block?height={}", self.url, height);
        let b: Value = self
            .agent()
            .get(&u)
            .call()
            .map_err(|e| format!("block {height}: {e}"))?
            .into_json()
            .map_err(|e| format!("block {height} json: {e}"))?;
        if b["result"]["block"].is_null() {
            return Err(format!("block {height}: missing block in RPC response"));
        }
        Ok(b["result"]["block"]["data"]["txs"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|t| t.as_str().and_then(|s| B64.decode(s).ok()))
            .collect())
    }

    /// All commitment-tree leaves in order (the shield decoy pool).
    /// All commitment leaves in tree order. The node serves them in PAGES
    /// (`/commit/leaves/<from>`, each at most `/commit/leaf_page` leaves), so keep paging
    /// until a page comes back short.
    pub fn leaves(&self) -> Result<Vec<[u64; 8]>, String> {
        let page: usize = self
            .query("/commit/leaf_page")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(20_000);
        let mut out = Vec::new();
        loop {
            let path = if out.is_empty() { "/commit/leaves".to_string() } else { format!("/commit/leaves/{}", out.len()) };
            let hexs = self.query(&path)?;
            let raw = hex::decode(hexs.trim()).map_err(|e| e.to_string())?;
            let mut got = 0usize;
            for chunk in raw.chunks(64) {
                if chunk.len() < 64 {
                    break;
                }
                let mut c = [0u64; 8];
                for (i, ci) in c.iter_mut().enumerate() {
                    *ci = u64::from_le_bytes(chunk[i * 8..i * 8 + 8].try_into().unwrap());
                }
                out.push(c);
                got += 1;
            }
            if got < page {
                break;
            }
        }
        Ok(out)
    }

    /// Scan blocks `from..=to` for an HTLC_CLAIM (0x5B) tx of `escrow_id`, and
    /// return the revealed preimage (the bytes after the 33-byte tag+id).
    pub fn find_claim_preimage(&self, escrow_id: &[u8; 32], from: i64, to: i64) -> Option<Vec<u8>> {
        for h in from..=to {
            let Ok(txs) = self.block_txs(h) else { continue };
            for tx in txs {
                if tx.first() == Some(&0x5B) && tx.len() > 33 && &tx[1..33] == escrow_id {
                    return Some(tx[33..].to_vec());
                }
            }
        }
        None
    }
}
