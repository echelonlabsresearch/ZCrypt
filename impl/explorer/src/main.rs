//! ZCrypt block explorer: a public window onto the chain that, by construction, reveals
//! nothing private. It reads CometBFT RPC + the node's ABCI queries, decodes each tagged
//! transaction into a public-safe summary (see `decode`), and serves a small self-contained
//! web UI. For a shielded transfer it shows the nullifiers, commitments, proof, and gas
//! burn that an observer really sees, and names the hidden fields (amount, parties, asset)
//! explicitly, so the explorer demonstrates the privacy instead of papering over it.
//!
//!   zcrypt-explorer                      # node http://localhost:26657, listen :8080
//!   EXPLORER_NODE=http://localhost:46657 EXPLORER_PORT=9000 zcrypt-explorer

mod decode;

use base64::Engine;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

// ---- RPC ---------------------------------------------------------------------

fn agent() -> ureq::Agent {
    ureq::builder().timeout(std::time::Duration::from_secs(20)).build()
}

fn rpc_json(url: &str) -> Result<Value, String> {
    agent().get(url).call().map_err(|e| e.to_string())?.into_json().map_err(|e| e.to_string())
}

/// An ABCI query returning its decoded utf-8 string value ("" if empty/absent).
fn abci(node: &str, path: &str) -> String {
    let u = format!("{}/abci_query?path=%22{}%22", node.trim_end_matches('/'), path);
    let v = match rpc_json(&u) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    let r = &v["result"]["response"];
    let raw = r["value"].as_str().unwrap_or("");
    if raw.is_empty() {
        return String::new();
    }
    B64.decode(raw).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default()
}

struct Status {
    height: i64,
    chain_id: String,
    time: String,
}

fn status(node: &str) -> Result<Status, String> {
    let v = rpc_json(&format!("{}/status", node.trim_end_matches('/')))?;
    let si = &v["result"]["sync_info"];
    Ok(Status {
        height: si["latest_block_height"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
        chain_id: v["result"]["node_info"]["network"].as_str().unwrap_or("?").to_string(),
        time: si["latest_block_time"].as_str().unwrap_or("").to_string(),
    })
}

/// (block time, block hash, raw txs) for a height.
fn block(node: &str, height: i64) -> (String, String, Vec<Vec<u8>>) {
    let v = match rpc_json(&format!("{}/block?height={}", node.trim_end_matches('/'), height)) {
        Ok(v) => v,
        Err(_) => return (String::new(), String::new(), vec![]),
    };
    let time = v["result"]["block"]["header"]["time"].as_str().unwrap_or("").to_string();
    let hash = v["result"]["block_id"]["hash"].as_str().unwrap_or("").to_string();
    let txs = v["result"]["block"]["data"]["txs"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|t| t.as_str().and_then(|s| B64.decode(s).ok()))
        .collect();
    (time, hash, txs)
}

/// Block metadata (height, num_txs, time) in bulk via CometBFT `/blockchain` (≤20 per call,
/// returned highest-first). Cheap: metadata only, no full block download. Used to find
/// non-empty blocks without decoding every block in between.
fn block_metas(node: &str, min: i64, max: i64) -> Vec<(i64, i64, String)> {
    let u = format!("{}/blockchain?minHeight={}&maxHeight={}", node.trim_end_matches('/'), min.max(1), max);
    let v = match rpc_json(&u) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let num = |m: &Value| m["num_txs"].as_str().and_then(|s| s.parse().ok()).or_else(|| m["num_txs"].as_i64()).unwrap_or(0);
    v["result"]["block_metas"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|m| {
            let h = m["header"]["height"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
            let t = m["header"]["time"].as_str().unwrap_or("").to_string();
            (h, num(m), t)
        })
        .collect()
}

// ---- API handlers ------------------------------------------------------------

fn api_overview(node: &str) -> Value {
    let st = status(node).ok();
    let assets = abci(node, "/asset/list");
    let vals = abci(node, "/staking/validators");
    let n_assets = if assets.is_empty() { 0 } else { assets.split(',').count() };
    let n_vals = if vals.is_empty() { 0 } else { vals.split(',').count() };
    json!({
        "height": st.as_ref().map(|s| s.height),
        "chain_id": st.as_ref().map(|s| s.chain_id.clone()),
        "block_time": st.as_ref().map(|s| s.time.clone()),
        "commitments": abci(node, "/commit/count").trim().parse::<u64>().ok(),
        "supply_issued": abci(node, "/staking/issued").trim().parse::<u64>().ok(),
        // Foundation vesting (all consensus-enforced, pure functions of height):
        // cumulative vested, claimed into coins, and still locked.
        "foundation_vested": abci(node, "/staking/foundation_vested").trim().parse::<u64>().ok(),
        "foundation_claimed": abci(node, "/staking/foundation_claimed").trim().parse::<u64>().ok(),
        "validators": n_vals,
        "assets": n_assets,
    })
}

/// Decode one height into a list-view row (type chips only, no per-tx proof work).
fn block_row(node: &str, cid: &str, h: i64) -> Value {
    let (time, _hash, txs) = block(node, h);
    let types: Vec<String> = txs
        .iter()
        .map(|t| decode::describe_tx(t, cid.as_bytes(), false, h as u64)["type"].as_str().unwrap_or("?").to_string())
        .collect();
    json!({ "height": h, "time": time, "num_txs": txs.len(), "types": types })
}

/// Most recent `count` blocks (contiguous), highest-first.
fn api_blocks(node: &str, count: i64) -> Value {
    let st = status(node).ok();
    let top = st.as_ref().map(|s| s.height).unwrap_or(0);
    let cid = st.map(|s| s.chain_id).unwrap_or_default();
    let lo = (top - count + 1).max(1);
    let out: Vec<Value> = (lo..=top).rev().map(|h| block_row(node, &cid, h)).collect();
    json!({ "blocks": out, "top": top })
}

/// Distinct heights of the most recent transaction-bearing blocks, newest first, via the
/// node's tx index (`/tx_search`). Covers the entire chain in a few RPC calls regardless of
/// how many empty heartbeat blocks sit in between. `None` if the indexer is unavailable.
fn tx_heights(node: &str, count: i64) -> Option<Vec<i64>> {
    let mut hs: Vec<i64> = Vec::new();
    let mut page: i64 = 1;
    loop {
        let u = format!(
            "{}/tx_search?query=%22tx.height%3E0%22&order_by=%22desc%22&per_page=100&page={}",
            node.trim_end_matches('/'),
            page
        );
        let v = rpc_json(&u).ok()?;
        let r = &v["result"];
        let txs = r["txs"].as_array()?;
        for t in txs {
            let h: i64 = t["height"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
            if h > 0 && !hs.contains(&h) {
                hs.push(h);
            }
            if hs.len() as i64 >= count {
                return Some(hs);
            }
        }
        let total: i64 = r["total_count"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
        if txs.is_empty() || page * 100 >= total {
            return Some(hs);
        }
        page += 1;
    }
}

/// The most recent `count` blocks that actually carry transactions. Prefers the tx index
/// (whole-chain coverage); falls back to walking backward in bulk `/blockchain` metadata
/// windows bounded by MAX_SCAN when the indexer is disabled.
fn api_blocks_nonempty(node: &str, count: i64) -> Value {
    const MAX_SCAN: i64 = 50_000;
    let st = status(node).ok();
    let top = st.as_ref().map(|s| s.height).unwrap_or(0);
    let cid = st.map(|s| s.chain_id).unwrap_or_default();
    if let Some(hs) = tx_heights(node, count) {
        let out: Vec<Value> = hs.iter().map(|h| block_row(node, &cid, *h)).collect();
        return json!({ "blocks": out, "top": top, "scanned_from": top, "scanned_to": 1, "reached_floor": false });
    }
    let floor = (top - MAX_SCAN + 1).max(1);
    let mut kept: Vec<(i64, String)> = Vec::new();
    let mut hi = top;
    let mut scanned_to = top;
    while hi >= floor && (kept.len() as i64) < count {
        let lo = (hi - 19).max(floor);
        for (h, n, t) in block_metas(node, lo, hi) {
            if n > 0 && (kept.len() as i64) < count {
                kept.push((h, t));
            }
        }
        scanned_to = lo;
        hi = lo - 1;
    }
    kept.sort_by(|a, b| b.0.cmp(&a.0));
    let out: Vec<Value> = kept.iter().map(|(h, _t)| block_row(node, &cid, *h)).collect();
    // reached_floor: we stopped because we hit the scan window, not because we filled `count`.
    let reached_floor = (out.len() as i64) < count && scanned_to <= floor;
    json!({ "blocks": out, "top": top, "scanned_from": top, "scanned_to": scanned_to, "reached_floor": reached_floor })
}

fn api_block(node: &str, height: i64) -> Value {
    let cid = status(node).map(|s| s.chain_id).unwrap_or_default();
    let (time, hash, txs) = block(node, height);
    // detail view: full decode including the raw bytes + VM bytecode + live circuit-proof verdict.
    let decoded: Vec<Value> = txs.iter().map(|t| decode::describe_tx(t, cid.as_bytes(), true, height as u64)).collect();
    json!({ "height": height, "time": time, "hash": hash, "num_txs": txs.len(), "txs": decoded })
}

fn api_assets(node: &str) -> Value {
    let raw = abci(node, "/asset/list");
    let items: Vec<Value> = raw
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let p: Vec<&str> = s.split(':').collect();
            json!({
                "ticker": p.first().copied(),
                "asset_id": p.get(1).copied(),
                "minted": p.get(2).and_then(|x| x.parse::<u64>().ok()),
                // decimals absent on older nodes → the UI falls back to raw atomic units.
                "decimals": p.get(3).and_then(|x| x.parse::<u8>().ok()),
            })
        })
        .collect();
    json!(items)
}

fn api_validators(node: &str) -> Value {
    // Rich endpoint (newer nodes): full per-validator profile — stake breakdown,
    // lifetime + unclaimed rewards, participation, delegations — plus chain-level
    // staking context. Passed through verbatim.
    let raw = abci(node, "/staking/validators_json");
    if let Ok(v) = serde_json::from_str::<Value>(&raw) {
        if v.get("validators").is_some() {
            return v;
        }
    }
    // Legacy fallback ("<pubkey_hex>:<stake>," list): stake only, no reward data.
    let raw = abci(node, "/staking/validators");
    let items: Vec<Value> = raw
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let p: Vec<&str> = s.split(':').collect();
            json!({ "id": p.first().copied(), "stake": p.get(1).and_then(|x| x.parse::<u64>().ok()) })
        })
        .collect();
    json!({ "validators": items, "legacy": true })
}

// ---- HTTP server (std only) --------------------------------------------------

fn respond(mut s: TcpStream, code: &str, ctype: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body);
    let _ = s.flush();
}

fn json_ok(s: TcpStream, v: &Value) {
    respond(s, "200 OK", "application/json", v.to_string().as_bytes());
}

fn handle(mut s: TcpStream, node: &str) {
    let mut buf = [0u8; 2048];
    let n = match s.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split_whitespace().nth(1).unwrap_or("/");
    let (route, query) = path.split_once('?').unwrap_or((path, ""));

    match route {
        "/" => respond(s, "200 OK", "text/html; charset=utf-8", INDEX_HTML.as_bytes()),
        "/api/overview" => json_ok(s, &api_overview(node)),
        "/api/assets" => json_ok(s, &api_assets(node)),
        "/api/validators" => json_ok(s, &api_validators(node)),
        "/api/blocks" => {
            let count = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("count="))
                .and_then(|c| c.parse::<i64>().ok())
                .unwrap_or(15)
                .clamp(1, 60);
            let nonempty = query.split('&').any(|kv| kv == "nonempty=1");
            json_ok(s, &if nonempty { api_blocks_nonempty(node, count) } else { api_blocks(node, count) });
        }
        r if r.starts_with("/api/block/") => match r["/api/block/".len()..].parse::<i64>() {
            Ok(h) => json_ok(s, &api_block(node, h)),
            Err(_) => respond(s, "400 Bad Request", "text/plain", b"bad height"),
        },
        _ => respond(s, "404 Not Found", "text/plain", b"not found"),
    }
}

fn main() {
    let node = std::env::var("EXPLORER_NODE").unwrap_or_else(|_| "http://localhost:26657".to_string());
    let port: u16 = std::env::var("EXPLORER_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind explorer port");
    println!("ZCrypt explorer on http://localhost:{port}  (node {node})");
    for stream in listener.incoming().flatten() {
        let node = node.clone();
        std::thread::spawn(move || handle(stream, &node));
    }
}

const INDEX_HTML: &str = include_str!("index.html");
