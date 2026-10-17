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
    /// The BFT block time of ZC block `height` (unix seconds): consensus data every node
    /// agrees on, which the redeem planner uses as the deterministic anchor of the BTC
    /// lock it funds (bridge/swap audit 2026-10 H5). Default: unsupported.
    fn block_time(&self, _height: i64) -> Result<u64, String> {
        Err("block_time not supported by this node client".to_string())
    }
    /// Whether the Bitcoin outpoint `txid:vout` (txid in INTERNAL byte order, as
    /// `MintProof::funding_txid` returns it) is in the consensus CLAIMED set, i.e. a zBTC mint
    /// was settled against it. Unlike the escrow record, which is pruned after
    /// `ESCROW_RETENTION_BLOCKS`, this set is permanent (it is what prevents a second mint
    /// from the same deposit), so it is the operator's durable proof-of-mint (audit H3).
    fn spv_claimed(&self, txid: &[u8; 32], vout: u32) -> Result<bool, String> {
        let s = self.query(&format!("/spv/claimed/{}:{vout}", hex::encode(txid)))?;
        match s.trim() {
            "1" => Ok(true),
            "0" => Ok(false),
            other => Err(format!("/spv/claimed: unexpected answer {other:?}")),
        }
    }
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
    fn block_time(&self, height: i64) -> Result<u64, String> {
        Zcrypt::block_time(self, height)
    }
}

/// Parse an RFC 3339 UTC timestamp as CometBFT prints it (`2026-10-17T12:34:56.123456789Z`)
/// into unix seconds. Fractional seconds are dropped; a numeric offset is honoured.
pub fn parse_rfc3339_secs(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let bad = || format!("bad RFC 3339 time {s:?}");
    if s.len() < 19 {
        return Err(bad());
    }
    let num = |a: usize, b: usize| -> Result<i64, String> { s.get(a..b).and_then(|x| x.parse::<i64>().ok()).ok_or_else(bad) };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hh, mm, ss) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if &s[4..5] != "-" || &s[7..8] != "-" || !matches!(&s[10..11], "T" | "t" | " ") || &s[13..14] != ":" || &s[16..17] != ":" {
        return Err(bad());
    }
    // Skip fractional seconds, then read the zone.
    let mut rest = &s[19..];
    if rest.starts_with('.') {
        let end = rest[1..].find(|c: char| !c.is_ascii_digit()).map(|i| i + 1).unwrap_or(rest.len());
        rest = &rest[end..];
    }
    let offset_secs: i64 = match rest {
        "Z" | "z" | "" => 0,
        r if r.len() == 6 && (r.starts_with('+') || r.starts_with('-')) => {
            let sign = if r.starts_with('-') { -1 } else { 1 };
            let oh: i64 = r[1..3].parse().map_err(|_| bad())?;
            let om: i64 = r[4..6].parse().map_err(|_| bad())?;
            sign * (oh * 3600 + om * 60)
        }
        _ => return Err(bad()),
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return Err(bad());
    }
    // Days from civil (Howard Hinnant's algorithm).
    let (y2, m2) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hh * 3600 + mm * 60 + ss - offset_secs;
    u64::try_from(secs).map_err(|_| bad())
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

    /// Fire-and-forget broadcast (`broadcast_tx_sync`): returns the tx hash once CheckTx
    /// passed, BEFORE the tx is in a block. Test drivers use it to land several txs in one
    /// block (e.g. a duplicate lock that only fails at delivery).
    pub fn broadcast_sync(&self, tx: &[u8]) -> Result<String, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "broadcast_tx_sync",
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
        if res["code"].as_i64().unwrap_or(1) != 0 {
            return Err(format!("check_tx: {}", res["log"].as_str().unwrap_or("")));
        }
        Ok(res["hash"].as_str().unwrap_or("").to_string())
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

    /// The BFT time (unix seconds) of ZC block `height`, from the CometBFT block header.
    pub fn block_time(&self, height: i64) -> Result<u64, String> {
        let u = format!("{}/block?height={}", self.url, height);
        let b: Value = self
            .agent()
            .get(&u)
            .call()
            .map_err(|e| format!("block {height}: {e}"))?
            .into_json()
            .map_err(|e| format!("block {height} json: {e}"))?;
        let t = b["result"]["block"]["header"]["time"].as_str().ok_or_else(|| format!("block {height}: no header time"))?;
        parse_rfc3339_secs(t)
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

#[cfg(test)]
mod tests {
    use super::parse_rfc3339_secs;

    #[test]
    fn rfc3339_parses_cometbft_header_times() {
        assert_eq!(parse_rfc3339_secs("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(parse_rfc3339_secs("2026-10-17T12:34:56.123456789Z").unwrap(), 1_792_240_496);
        assert_eq!(parse_rfc3339_secs("2026-10-17T12:34:56Z").unwrap(), 1_792_240_496);
        assert_eq!(parse_rfc3339_secs("2026-10-17T14:34:56+02:00").unwrap(), 1_792_240_496);
        assert_eq!(parse_rfc3339_secs("2000-02-29T00:00:00Z").unwrap(), 951_782_400);
        assert!(parse_rfc3339_secs("2026-13-01T00:00:00Z").is_err());
        assert!(parse_rfc3339_secs("garbage").is_err());
    }
}
