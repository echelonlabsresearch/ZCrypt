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

/// Random per-process nonce mixed into every SOCKS username so each wallet launch
/// gets fresh Tor circuits (Tor isolates streams by SOCKS credentials).
static SESSION_NONCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn session_nonce() -> &'static str {
    SESSION_NONCE.get_or_init(|| {
        use rand::RngCore;
        let mut b = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut b);
        hex::encode(b)
    })
}

/// Stream isolation: give `proxy_url` a SOCKS5 username/password unique to this
/// request `class` (node queries, broadcasts, bridge/Esplora) and this process. Tor's
/// default `IsolateSOCKSAuth` then routes each class over its own circuit, so the exit
/// (or a .onion service) cannot correlate a wallet's leaf sync, its spent checks, and
/// its broadcasts by a shared source. Credentials are already-present-aware: a URL that
/// carries `user:pass@` is returned unchanged.
pub fn socks_isolated(proxy_url: &str, class: &str) -> String {
    let (scheme, rest) = match proxy_url.split_once("://") {
        Some((s, r)) => (s, r),
        None => ("socks5", proxy_url),
    };
    if rest.contains('@') {
        return proxy_url.to_string();
    }
    format!("{scheme}://zc-{class}-{n}:{n}@{rest}", n = session_nonce())
}

/// Enable/disable Tor routing for all subsequent node RPC. `Some(socks_url)` turns
/// it on; `None` reverts to a direct connection.
pub fn set_tor(proxy: Option<String>) {
    *TOR_PROXY.write().unwrap() = proxy;
}

/// Whether node RPC is currently routed over Tor.
pub fn tor_active() -> bool {
    TOR_PROXY.read().unwrap().is_some()
}

/// Random delay before a broadcast (default on). Decorrelates the moment a proof
/// finished from the moment the network first sees the transaction.
static JITTER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

pub fn set_broadcast_jitter(on: bool) {
    JITTER.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Build a node-RPC agent for one isolation `class` with `secs` timeout, routing
/// through the Tor SOCKS proxy when enabled. Every path that contacts the node MUST
/// use this (never a bare `ureq::builder()`), or it would bypass Tor and leak the
/// wallet's IP.
pub fn agent_for(class: &str, secs: u64) -> ureq::Agent {
    let mut b = ureq::builder().timeout(std::time::Duration::from_secs(secs));
    if let Some(proxy) = TOR_PROXY.read().unwrap().clone() {
        // A misconfigured proxy string must FAIL CLOSED: build an agent that can't
        // connect rather than silently falling back to a direct (de-anonymizing)
        // connection. Only a successfully-parsed proxy is applied; if parsing fails we
        // point at an unusable loopback port so requests error out instead of leaking.
        match ureq::Proxy::new(&socks_isolated(&proxy, class)) {
            Ok(p) => b = b.proxy(p),
            Err(_) => {
                b = b.proxy(ureq::Proxy::new("socks5://127.0.0.1:1").expect("static proxy"));
            }
        }
    }
    b.build()
}

/// Node-query agent (the default isolation class).
pub fn agent_with_timeout(secs: u64) -> ureq::Agent {
    agent_for("node", secs)
}

fn agent() -> ureq::Agent {
    agent_with_timeout(TIMEOUT_S)
}

/// Is `url`'s host a loopback address (`localhost`, 127.0.0.0/8, `::1`)? Decided by
/// a real URL parse, so `http://localhost:1@evil.test/` (userinfo trick) or
/// `http://localhost.evil.test/` are NOT treated as local.
pub fn is_loopback_url(url: &str) -> bool {
    let parsed = match url::Url::parse(url.trim()) {
        Ok(u) => u,
        Err(_) => return false,
    };
    match parsed.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Node-URL policy: a REMOTE node must be reached over TLS (`https://`) or as a Tor
/// onion service (`http://<x>.onion`, end-to-end encrypted inside Tor). Plain `http://`
/// to a clearnet host would let a Tor exit or any on-path party read and alter every
/// query and transaction, so it is refused. Loopback nodes may use plain http.
pub fn check_node_url(url: &str) -> Result<(), String> {
    let u = url::Url::parse(url.trim()).map_err(|e| format!("node URL: {e}"))?;
    match u.scheme() {
        "http" | "https" => {}
        other => return Err(format!("node URL must be http(s), not `{other}://`")),
    }
    if u.host().is_none() {
        return Err("node URL has no host".into());
    }
    if u.username() != "" || u.password().is_some() {
        return Err("node URL must not embed credentials".into());
    }
    if is_loopback_url(url) || u.scheme() == "https" {
        return Ok(());
    }
    let onion = matches!(u.host(), Some(url::Host::Domain(d)) if d.to_ascii_lowercase().ends_with(".onion"));
    if onion {
        return Ok(());
    }
    Err(format!(
        "refusing plain http:// to the remote node {}: use https://, a .onion address, or a node on localhost. \
         Unencrypted RPC lets anyone on the path read and tamper with your queries and transactions.",
        u.host_str().unwrap_or("")
    ))
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

/// CometBFT genesis chain id (`status.node_info.network`), used to bind shield proofs
/// and staking signatures. Prefer this over a compile-time constant so multi-network
/// binaries and genesis renames stay consistent with the node.
pub fn chain_id_bytes(url: &str) -> Result<Vec<u8>, String> {
    // Prefer the app's own binding when available (set at InitChain).
    if let Ok(s) = query_str(url, "/chain_id") {
        let s = s.trim();
        if !s.is_empty() {
            return Ok(s.as_bytes().to_vec());
        }
    }
    let u = format!("{}/status", base(url));
    let b: Value = agent().get(&u).call().map_err(|e| e.to_string())?.into_json().map_err(|e| e.to_string())?;
    let chain_id = b["result"]["node_info"]["network"].as_str().unwrap_or("");
    if chain_id.is_empty() {
        return Err("status: missing chain id".to_string());
    }
    Ok(chain_id.as_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Chain-id PINNING (FIX 2): trust the node's chain-id only on first contact,
// then bind every future signature to that pinned domain.
// ---------------------------------------------------------------------------

/// App-data directory (where `keystore.json` lives) used to persist the pinned
/// chain-id in `chain_id.txt`. Set once at startup via [`set_pin_dir`]. `None`
/// means no persistence is configured: pinning is skipped and the live node
/// answer is used directly (only reached in tests / pre-setup).
static PIN_DIR: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Point chain-id pinning at the wallet's data dir (same dir as the keystore).
pub fn set_pin_dir(dir: String) {
    *PIN_DIR.write().unwrap() = Some(dir);
}

/// Path of the pinned-chain-id file, if a data dir has been configured.
fn pin_path() -> Option<std::path::PathBuf> {
    PIN_DIR
        .read()
        .unwrap()
        .clone()
        .map(|d| std::path::Path::new(&d).join("chain_id.txt"))
}

/// Chain-id for SIGNING, PINNED to the first chain this wallet ever connected to.
///
/// On the first successful read from the node the chain-id is written to
/// `chain_id.txt` next to the keystore. Thereafter the policy is fail-closed:
///   * node reachable, reports the SAME id      -> use it (it equals the pin);
///   * node reachable, reports a DIFFERENT id    -> refuse (the node/operator
///     swapped the chain under us — a signature made here could be replayed on
///     the wrong chain);
///   * node unreachable, a pin EXISTS            -> use the pinned id (the
///     user-confirmed domain);
///   * node unreachable, NO pin yet              -> refuse (never silently fall
///     back to a hardcoded constant for signing).
pub fn pinned_chain_id(url: &str) -> Result<Vec<u8>, String> {
    let path = pin_path();
    let pinned: Option<String> = path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    match chain_id_bytes(url) {
        Ok(live_bytes) => {
            let live = String::from_utf8_lossy(&live_bytes).trim().to_string();
            match &pinned {
                Some(p) if *p != live => Err(format!(
                    "chain-id mismatch: this wallet is pinned to '{p}' but the node reports \
                     '{live}'. Refusing to sign. Point the wallet at the correct node; only \
                     delete the pinned chain_id.txt if you intend to switch chains."
                )),
                Some(_) => Ok(live_bytes), // matches the pin — safe to use
                None => {
                    // First successful contact: pin it for all future signing.
                    if let Some(p) = &path {
                        crate::privfs::write_private(p, live.as_bytes())
                            .map_err(|e| format!("could not pin chain-id to {}: {e}", p.display()))?;
                    }
                    Ok(live_bytes)
                }
            }
        }
        Err(e) => match pinned {
            Some(p) => Ok(p.into_bytes()),
            None => Err(format!(
                "cannot determine chain-id for signing: node unreachable ({e}) and no chain-id \
                 has been pinned yet. Connect to the node once to pin the chain, then retry."
            )),
        },
    }
}

/// The chain id this wallet is pinned to (from `chain_id.txt`), if any. Shown in
/// Settings so the user can see which domain their signatures are bound to.
pub fn pinned_id() -> Option<String> {
    pin_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// A tag that uniquely identifies the chain GENERATION the node is serving:
/// `"{chain_id}:{earliest_block_hash}"`. The chain id alone is not enough — a devnet
/// re-genesis (`docker compose down -v`) reuses the same chain id but produces a fresh
/// genesis, so a wallet must key its coin store to the genesis block hash to avoid
/// showing coins from a wiped chain. Returns Err if the node is unreachable.
pub fn chain_tag(url: &str) -> Result<String, String> {
    let u = format!("{}/status", base(url));
    let b: Value = agent().get(&u).call().map_err(|e| e.to_string())?.into_json().map_err(|e| e.to_string())?;
    let chain_id = b["result"]["node_info"]["network"].as_str().unwrap_or("");
    let genesis = b["result"]["sync_info"]["earliest_block_hash"].as_str().unwrap_or("");
    if chain_id.is_empty() || genesis.is_empty() {
        return Err("status: missing chain id or genesis hash".to_string());
    }
    Ok(format!("{chain_id}:{genesis}"))
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

/// Raw string value of an ABCI query (e.g. `/staking/validators` → "<hex>:<stake> …").
pub fn query_str(url: &str, path: &str) -> Result<String, String> {
    abci_query_hex(url, path)
}

/// Percent-encode a user-supplied path segment (anything outside `[A-Za-z0-9._~-]`).
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Resolve a ticker to its asset id if it is already registered (None if free).
pub fn asset_by_ticker(url: &str, ticker: &str) -> Option<u64> {
    abci_query_hex(url, &format!("/asset/by_ticker/{}", pct(ticker)))
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

/// Net-coin commitments of every immature SPV mint (freshly-shielded zBTC still
/// maturing / still reorg-voidable). Same wire format as the leaf dump. A wallet uses
/// this to keep a maturing coin (not in the tree yet, but pending here) out of its
/// stale-coin reconcile, and to drop it only once a reorg voids it (it leaves this set
/// without ever becoming a leaf). Errs if the node is too old to expose the endpoint —
/// callers should then SKIP dropping non-leaf coins rather than risk losing a maturing one.
pub fn fetch_pending_coins(url: &str) -> Result<Vec<Commitment>, String> {
    let hexs = abci_query_hex(url, "/spv/pending_coins")?;
    parse_leaves_hex(&hexs)
}

/// Commitment-tree size (leaf count).
pub fn commitment_count(url: &str) -> Result<usize, String> {
    let s = abci_query_hex(url, "/commit/count")?;
    s.trim().parse().map_err(|e| format!("commit count: {e}"))
}

/// Leaves starting at `from` (inclusive). Prefer this over a full dump when the
/// wallet already holds a prefix of the tree.
pub fn fetch_leaves_from(url: &str, from: usize) -> Result<Vec<Commitment>, String> {
    // The node serves leaves in PAGES (at most `/commit/leaf_page` per query, so a single
    // request never clones the whole tree): keep paging until a page comes back short.
    let page: usize = abci_query_hex(url, "/commit/leaf_page")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(20_000);
    let mut out = Vec::new();
    let mut cursor = from;
    loop {
        let path = if cursor == 0 {
            "/commit/leaves".to_string()
        } else {
            format!("/commit/leaves/{cursor}")
        };
        let hexs = abci_query_hex(url, &path)?;
        let got = parse_leaves_hex(&hexs)?;
        let n = got.len();
        out.extend(got);
        cursor += n;
        if n < page {
            break;
        }
    }
    Ok(out)
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

// Spent status is derived LOCALLY: `scan_onchain` reads the nullifiers of every
// shield transaction in the blocks it downloads anyway and matches them against the
// wallet's own coins. The wallet never asks the node about individual nullifiers
// (a per-key `/prove/<key>` query, even inside a decoy batch, let the operator
// intersect refreshes and attribute later spends to this session).

/// Broadcast a raw tx (with its 1-byte tag) via JSON-RPC POST (large txs can't go
/// in a GET query string). Returns Ok only if both check_tx and tx_result pass.
pub fn broadcast(url: &str, tx: &[u8]) -> Result<(), String> {
    if JITTER.load(std::sync::atomic::Ordering::Relaxed) {
        // 0.25 to 2.5 s of random delay so the submit time does not equal the prove time.
        use rand::Rng;
        let ms: u64 = rand::thread_rng().gen_range(250..2500);
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "broadcast_tx_commit",
        "params": { "tx": B64.encode(tx) }
    });
    // Broadcasts ride their own Tor circuit, separate from the query traffic.
    let resp: Value = agent_for("broadcast", TIMEOUT_S)
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

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn remote_nodes_need_tls_or_onion_and_loopback_may_be_plain() {
        assert!(check_node_url("http://localhost:36657").is_ok());
        assert!(check_node_url("http://127.0.0.1:36657").is_ok());
        assert!(check_node_url("http://[::1]:36657").is_ok());
        assert!(check_node_url("https://rpc.example.org").is_ok());
        assert!(check_node_url("http://abcdefghijklmnop.onion:26657").is_ok());
        assert!(check_node_url("http://rpc.example.org:26657").is_err(), "plain http to a remote host");
        assert!(check_node_url("ftp://rpc.example.org").is_err());
        assert!(check_node_url("not a url").is_err());
        // userinfo trick: the host is evil.test, not localhost
        assert!(check_node_url("http://localhost:1@evil.test/").is_err());
        assert!(!is_loopback_url("http://localhost:1@evil.test/"));
        assert!(!is_loopback_url("http://localhost.evil.test/"));
        assert!(is_loopback_url("http://127.0.0.1:36657"));
        assert!(is_loopback_url("http://localhost:36657"));
    }

    #[test]
    fn isolation_credentials_are_per_class_and_never_doubled() {
        let a = socks_isolated("socks5://127.0.0.1:9050", "node");
        let b = socks_isolated("socks5://127.0.0.1:9050", "broadcast");
        assert!(a.starts_with("socks5://zc-node-"));
        assert!(b.starts_with("socks5://zc-broadcast-"));
        assert_ne!(a, b, "different classes must yield different SOCKS credentials");
        assert!(a.ends_with("@127.0.0.1:9050"));
        assert_eq!(socks_isolated(&a, "bridge"), a, "existing credentials are kept");
        assert!(ureq::Proxy::new(&a).is_ok(), "ureq must accept the credentialed proxy URL");
    }
}
