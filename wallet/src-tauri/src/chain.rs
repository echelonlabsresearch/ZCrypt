//! CometBFT JSON-RPC client + shield-tx helpers for on-chain transacting.

use base64::Engine;
use serde_json::Value;
use zcrypt_shield::Commitment;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const TIMEOUT_S: u64 = 45;

/// App-wide Tor SOCKS proxy for node RPC. `None` = direct connection (default).
/// `Some(url)` routes every node request through the local Tor proxy, hiding the
/// wallet's IP and per-coin query pattern from the node operator and the network.
/// Set from settings at startup and whenever settings are saved (see `set_tor`).
static TOR_PROXY: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Enable/disable Tor routing for all subsequent node RPC. `Some(socks_url)` turns
/// it on; `None` reverts to a direct connection.
pub fn set_tor(proxy: Option<String>) {
    *TOR_PROXY.write().unwrap() = proxy;
}

/// Whether node RPC is currently routed over Tor.
pub fn tor_active() -> bool {
    TOR_PROXY.read().unwrap().is_some()
}

/// Build a node-RPC agent with `secs` timeout, routing through the Tor SOCKS proxy
/// when enabled. Every path that contacts the node MUST use this (never a bare
/// `ureq::builder()`), or it would bypass Tor and leak the wallet's IP.
pub fn agent_with_timeout(secs: u64) -> ureq::Agent {
    let mut b = ureq::builder().timeout(std::time::Duration::from_secs(secs));
    if let Some(proxy) = TOR_PROXY.read().unwrap().clone() {
        // A misconfigured proxy string must FAIL CLOSED — build an agent that can't
        // connect — rather than silently falling back to a direct (de-anonymizing)
        // connection. We do that by only applying a successfully-parsed proxy; if
        // parsing fails we point at an unusable loopback port so requests error out
        // instead of leaking the real IP.
        match ureq::Proxy::new(&proxy) {
            Ok(p) => b = b.proxy(p),
            Err(_) => {
                b = b.proxy(ureq::Proxy::new("socks5://127.0.0.1:1").expect("static proxy"));
            }
        }
    }
    b.build()
}

fn agent() -> ureq::Agent {
    agent_with_timeout(TIMEOUT_S)
}
fn base(url: &str) -> &str {
    url.trim_end_matches('/')
}

pub fn node_height(url: &str) -> Result<i64, String> {
    let u = format!("{}/abci_info", base(url));
    let b: Value = agent().get(&u).call().map_err(|e| e.to_string())?.into_json().map_err(|e| e.to_string())?;
    Ok(b["result"]["response"]["last_block_height"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0))
}

fn abci_query_hex(url: &str, path: &str) -> Result<String, String> {
    let u = format!("{}/abci_query?path=%22{}%22", base(url), path);
    let b: Value = agent().get(&u).call().map_err(|e| e.to_string())?.into_json().map_err(|e| e.to_string())?;
    let v = b["result"]["response"]["value"].as_str().ok_or("query: no value")?;
    let bytes = B64.decode(v).map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

/// Read a staking query that returns a decimal u64 (e.g. `/staking/claimable/<pk>`
/// or `/staking/claim_index/<pk>`).
pub fn staking_u64(url: &str, path: &str) -> Result<u64, String> {
    let s = abci_query_hex(url, path)?;
    s.trim().parse::<u64>().map_err(|e| format!("staking query parse: {e}"))
}

/// Resolve a ticker to its asset id if it is already registered (None if free).
pub fn asset_by_ticker(url: &str, ticker: &str) -> Option<u64> {
    abci_query_hex(url, &format!("/asset/by_ticker/{ticker}"))
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// All registered shielded assets as `(ticker, asset_id, minted)`.
pub fn asset_list(url: &str) -> Vec<(String, u64, u64)> {
    let s = match abci_query_hex(url, "/asset/list") {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    s.split(',')
        .filter(|e| !e.is_empty())
        .filter_map(|e| {
            let mut it = e.split(':');
            let ticker = it.next()?.to_string();
            let id = it.next()?.parse::<u64>().ok()?;
            let minted = it.next()?.parse::<u64>().ok()?;
            Some((ticker, id, minted))
        })
        .collect()
}

/// The mint authority `H(capability)` registered for an asset, if any. One-way, so
/// it reveals no secret; the minter's wallet re-derives its capability to prove it.
pub fn asset_authority(url: &str, id: u64) -> Option<[u8; 32]> {
    let s = abci_query_hex(url, &format!("/asset/id/{id}")).ok()?;
    let j: Value = serde_json::from_str(&s).ok()?;
    let hexs = j["authority"].as_str()?;
    hex::decode(hexs).ok()?.try_into().ok()
}

/// Resolve a shielded asset's `(ticker, decimals)` from the node (`/asset/id/<id>`).
pub fn asset_meta(url: &str, id: u64) -> Option<(String, u8)> {
    let s = abci_query_hex(url, &format!("/asset/id/{id}")).ok()?;
    let j: Value = serde_json::from_str(&s).ok()?;
    let ticker = j["ticker"].as_str()?.to_string();
    let decimals = j["decimals"].as_u64().unwrap_or(8) as u8;
    Some((ticker, decimals))
}

fn parse_leaves_hex(hexs: &str) -> Result<Vec<Commitment>, String> {
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

/// Commitment-tree size (leaf count).
pub fn commitment_count(url: &str) -> Result<usize, String> {
    let s = abci_query_hex(url, "/commit/count")?;
    s.trim().parse().map_err(|e| format!("commit count: {e}"))
}

/// Leaves starting at `from` (inclusive). Prefer this over a full dump when the
/// wallet already holds a prefix of the tree.
pub fn fetch_leaves_from(url: &str, from: usize) -> Result<Vec<Commitment>, String> {
    let path = if from == 0 {
        "/commit/leaves".to_string()
    } else {
        format!("/commit/leaves/{from}")
    };
    let hexs = abci_query_hex(url, &path)?;
    parse_leaves_hex(&hexs)
}

/// The node's committed leaf at `idx`. The commitment tree is append-only, so a committed
/// index never changes — which makes this a reliable, race-free fingerprint for detecting a
/// chain reset (see `fetch_leaves`).
fn node_leaf_at(url: &str, idx: usize) -> Option<Commitment> {
    let hexs = abci_query_hex(url, &format!("/commit/leaves/{idx}")).ok()?;
    parse_leaves_hex(&hexs).ok()?.into_iter().next()
}

/// All commitment leaves in tree order, using an in-process cache + incremental
/// `/commit/leaves/<from>` sync so the wallet does not re-download the whole tree
/// every spend.
pub fn fetch_leaves(url: &str) -> Result<Vec<Commitment>, String> {
    use std::sync::Mutex;
    static CACHE: Mutex<Vec<Commitment>> = Mutex::new(Vec::new());
    let count = commitment_count(url).unwrap_or(0);
    let mut cache = CACHE.lock().map_err(|_| "leaf cache lock".to_string())?;
    // Drop a stale cache. The tree is append-only, so a committed leaf never changes; the
    // cache is invalid if either the tree shrank (count < cached length), OR the node's leaf
    // at our last cached index no longer matches ours. The second case catches a devnet reset
    // that then grew PAST the cache, which a length-only check misses: the cache would keep a
    // prefix of a DEAD chain's leaves, so a spend anchors on a root the node never had, and is
    // rejected with "gas note anchors on an unknown/expired root".
    let diverged = count < cache.len()
        || cache
            .last()
            .zip(node_leaf_at(url, cache.len().saturating_sub(1)))
            .map(|(last, nl)| *last != nl)
            .unwrap_or(false);
    if diverged {
        cache.clear();
    }
    if cache.len() < count {
        let more = fetch_leaves_from(url, cache.len())?;
        cache.extend(more);
    }
    // If count query failed (old node), fall back to full dump once.
    if cache.is_empty() {
        let hexs = abci_query_hex(url, "/commit/leaves")?;
        *cache = parse_leaves_hex(&hexs)?;
    }
    Ok(cache.clone())
}

pub fn find_index(leaves: &[Commitment], com: &Commitment) -> Option<u32> {
    leaves.iter().position(|c| c == com).map(|i| i as u32)
}

fn prove_included(url: &str, key_hex: &str) -> Option<bool> {
    let u = format!("{}/abci_query?path=%22/prove/{}%22", base(url), key_hex);
    agent()
        .get(&u)
        .call()
        .ok()
        .and_then(|r| r.into_json::<Value>().ok())
        .and_then(|b| {
            let v = b["result"]["response"]["value"].as_str()?.to_string();
            let by = B64.decode(&v).ok()?;
            let j: Value = serde_json::from_slice(&by).ok()?;
            j["included"].as_bool()
        })
}

/// Is a nullifier (by its registry key hex) already recorded as spent?
///
/// Always queries inside a **decoy batch** (real key + random siblings, shuffled)
/// so a node operator cannot tell which nullifier the wallet cares about from the
/// query set alone.
pub fn nullifier_spent(url: &str, key_hex: &str) -> bool {
    nullifiers_spent(url, &[key_hex.to_string()])
        .ok()
        .and_then(|v| v.into_iter().next())
        .unwrap_or(false)
}

/// Batch nullifier membership with decoys (min 32 queries). Returns one bool per
/// *real* key, in the same order as `real_keys`.
pub fn nullifiers_spent(url: &str, real_keys: &[String]) -> Result<Vec<bool>, String> {
    use rand::seq::SliceRandom;
    use rand::RngCore;
    const BATCH: usize = 32;
    let mut rng = rand::thread_rng();
    let mut batch: Vec<(String, Option<usize>)> = real_keys
        .iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), Some(i)))
        .collect();
    while batch.len() < BATCH.max(real_keys.len()) {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        batch.push((hex::encode(seed), None));
    }
    batch.shuffle(&mut rng);
    let mut out = vec![false; real_keys.len()];
    for (key, idx) in &batch {
        let included = prove_included(url, key).unwrap_or(false);
        if let Some(i) = idx {
            out[*i] = included;
        }
    }
    Ok(out)
}

/// Broadcast a raw tx (with its 1-byte tag) via JSON-RPC POST (large txs can't go
/// in a GET query string). Returns Ok only if both check_tx and tx_result pass.
pub fn broadcast(url: &str, tx: &[u8]) -> Result<(), String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "broadcast_tx_commit",
        "params": { "tx": B64.encode(tx) }
    });
    let resp: Value = agent()
        .post(base(url))
        .send_json(body)
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    if let Some(msg) = resp["error"]["data"].as_str().or_else(|| resp["error"]["message"].as_str()) {
        return Err(format!("node error: {msg}"));
    }
    let res = &resp["result"];
    if res["check_tx"]["code"].as_i64().unwrap_or(1) != 0 {
        return Err(format!("rejected in mempool: {}", res["check_tx"]["log"].as_str().unwrap_or("")));
    }
    if res["tx_result"]["code"].as_i64().unwrap_or(1) != 0 {
        return Err(format!("rejected: {}", res["tx_result"]["log"].as_str().unwrap_or("")));
    }
    Ok(())
}

/// Heights in `[from, to]` that actually contain transactions, via CometBFT's
/// `/blockchain` endpoint (up to 20 block metas per call). Devnets mint empty
/// blocks every ~1s, so this turns an O(chain-length) scan (one full-block fetch
/// per height) into O(#tx-blocks) — only the handful of blocks with real txs are
/// fetched afterward. Returns ascending heights.
pub fn nonempty_heights(url: &str, from: i64, to: i64) -> Result<Vec<i64>, String> {
    let mut out = Vec::new();
    let mut hi = to;
    while hi >= from {
        let lo = (hi - 19).max(from); // /blockchain returns at most 20 metas
        let u = format!("{}/blockchain?minHeight={}&maxHeight={}", base(url), lo, hi);
        let b: Value = agent().get(&u).call().map_err(|e| e.to_string())?.into_json().map_err(|e| e.to_string())?;
        if let Some(metas) = b["result"]["block_metas"].as_array() {
            for m in metas {
                let n = m["num_txs"]
                    .as_str()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                if n > 0 {
                    if let Some(h) = m["header"]["height"].as_str().and_then(|s| s.parse::<i64>().ok()) {
                        out.push(h);
                    }
                }
            }
        }
        hi = lo - 1;
    }
    out.sort_unstable();
    Ok(out)
}

/// Fetch the (decoded) transactions in a block.
pub fn block_txs(url: &str, height: i64) -> Vec<Vec<u8>> {
    let u = format!("{}/block?height={}", base(url), height);
    let b: Value = match agent().get(&u).call().ok().and_then(|r| r.into_json().ok()) {
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

/// The Merkle authentication path of the coin at `leaf_idx` against a tree built
/// from `leaves` (in node order), for the in-circuit membership proof (L1).
pub fn merkle_path(leaves: &[Commitment], leaf_idx: usize) -> Option<(Vec<Commitment>, Vec<bool>)> {
    let mut tree = zcrypt_shield::tree::CommitmentTree::new();
    for &c in leaves {
        tree.append(c);
    }
    tree.path(leaf_idx)
}
