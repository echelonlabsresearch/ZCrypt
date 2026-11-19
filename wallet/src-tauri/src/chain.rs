//! CometBFT JSON-RPC client + shield-tx helpers for on-chain transacting.

use base64::Engine;
use serde_json::Value;
use zcrypt_shield::Commitment;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const TIMEOUT_S: u64 = 45;
/// A broadcast uploads a multi-megabyte proof and then waits for the node to verify it
/// and include it. The node waits 30s (`timeout_broadcast_tx_commit`); this has to cover
/// that plus a slow upload.
const BROADCAST_TIMEOUT_S: u64 = 90;

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

/// Stream isolation with FRESH credentials on every call: a new random nonce each time,
/// so two broadcasts from one session (a reshape self-send and the real send seconds
/// later) never share a Tor circuit and cannot be paired by the exit or the node. Used for
/// broadcasts and for every Bitcoin-side (Esplora) session; plain queries keep one
/// per-session circuit.
pub fn socks_isolated_fresh(proxy_url: &str, class: &str) -> String {
    use rand::RngCore;
    let (scheme, rest) = match proxy_url.split_once("://") {
        Some((s, r)) => (s, r),
        None => ("socks5", proxy_url),
    };
    if rest.contains('@') {
        return proxy_url.to_string();
    }
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    let n = hex::encode(b);
    format!("{scheme}://zc-{class}-{n}:{n}@{rest}")
}

/// Enable/disable Tor routing for all subsequent node RPC. `Some(socks_url)` turns
/// it on; `None` reverts to a direct connection.
pub fn set_tor(proxy: Option<String>) {
    *TOR_PROXY.write().unwrap() = proxy;
}

/// The Tor proxy for hosts that are NOT the node (the sale desk): `Some` whenever the Tor
/// setting is on, even when the node itself is local and therefore reached directly.
static TOR_PROXY_REMOTE: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

pub fn set_tor_remote(proxy: Option<String>) {
    *TOR_PROXY_REMOTE.write().unwrap() = proxy;
}

/// An agent for a third-party host at `url`, in its own isolation `class`. [`agent_for`]
/// follows the NODE's routing, which is direct when the node is on loopback. This one
/// decides by the TARGET: Tor whenever the setting is on and `url` is not loopback, and
/// fail-closed on a bad proxy string.
pub fn agent_for_remote(class: &str, secs: u64, url: &str) -> ureq::Agent {
    let mut b = ureq::builder().timeout(std::time::Duration::from_secs(secs));
    if !is_loopback_url(url) {
        if let Some(proxy) = TOR_PROXY_REMOTE.read().unwrap().clone() {
            match ureq::Proxy::new(&socks_isolated(&proxy, class)) {
                Ok(p) => b = b.proxy(p),
                Err(_) => {
                    b = b.proxy(ureq::Proxy::new("socks5://127.0.0.1:1").expect("static proxy"));
                }
            }
        }
    }
    b.build()
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

/// Like [`agent_for`] but with fresh SOCKS credentials, i.e. a Tor circuit of its own.
pub fn agent_fresh(class: &str, secs: u64) -> ureq::Agent {
    let mut b = ureq::builder().timeout(std::time::Duration::from_secs(secs));
    if let Some(proxy) = TOR_PROXY.read().unwrap().clone() {
        match ureq::Proxy::new(&socks_isolated_fresh(&proxy, class)) {
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

/// A scan of fewer blocks than this dates what it finds with the phone's clock.
pub const CLOCK_MIN_RANGE: i64 = 600;
/// A stretch longer than this is always split, however even the chain's pace looks.
const CLOCK_ALWAYS_SPLIT: i64 = 100_000;
/// A stretch this short is not split further.
const CLOCK_MIN_SPAN: i64 = 300;
/// Split a stretch when its midpoint is further than this from a straight line, seconds.
const CLOCK_TOLERANCE_S: u64 = 60;
/// The most headers one clock reads.
const CLOCK_MAX_READS: usize = 64;

/// Block times over a height range, for dating coins a scan finds in old blocks.
///
/// Asking the node for the header of each block that paid this wallet would tell it which
/// blocks those are. The clock reads the two ends of the range and then midpoints, splitting
/// wherever the chain did not run at an even pace, so the heights it asks for depend only on
/// the chain. Times in between are interpolated.
#[derive(Default)]
pub struct HeightClock {
    /// (height, Unix seconds), ascending by height.
    anchors: Vec<(i64, u64)>,
}

impl HeightClock {
    /// The time of the block at `height`, or `None` when the clock has nothing to go on.
    pub fn at(&self, height: i64) -> Option<u64> {
        let (first, last) = (self.anchors.first()?, self.anchors.last()?);
        if height <= first.0 {
            return Some(first.1);
        }
        if height >= last.0 {
            return Some(last.1);
        }
        let i = self.anchors.partition_point(|(h, _)| *h <= height);
        let ((a, ta), (b, tb)) = (self.anchors[i - 1], self.anchors[i]);
        Some(clock_between(a, ta, b, tb, height))
    }
}

/// The time at `h` on the straight line from (`a`, `ta`) to (`b`, `tb`), `a <= h <= b`.
fn clock_between(a: i64, ta: u64, b: i64, tb: u64, h: i64) -> u64 {
    if b <= a || tb <= ta {
        return ta;
    }
    ta + ((u128::from(tb - ta) * (h - a) as u128) / (b - a) as u128) as u64
}

/// Build a clock for `[lo, hi]` with `read(height)`. If either end cannot be read the
/// clock is empty; a midpoint that cannot be read just leaves its stretch unsplit.
fn clock_from(lo: i64, hi: i64, read: &mut dyn FnMut(i64) -> Option<u64>) -> HeightClock {
    let lo = lo.max(1);
    if hi < lo {
        return HeightClock::default();
    }
    let (Some(t_lo), Some(t_hi)) = (read(lo), read(hi)) else {
        return HeightClock::default();
    };
    let mut anchors = vec![(lo, t_lo), (hi, t_hi)];
    let mut reads = 2usize;
    // Widest stretches first, so a spent budget leaves even coverage.
    let mut queue = std::collections::VecDeque::from([(lo, t_lo, hi, t_hi)]);
    while let Some((a, ta, b, tb)) = queue.pop_front() {
        if b - a <= CLOCK_MIN_SPAN || reads >= CLOCK_MAX_READS {
            continue;
        }
        let m = a + (b - a) / 2;
        reads += 1;
        let Some(tm) = read(m) else { continue };
        anchors.push((m, tm));
        if b - a > CLOCK_ALWAYS_SPLIT || tm.abs_diff(clock_between(a, ta, b, tb, m)) > CLOCK_TOLERANCE_S {
            queue.push_back((a, ta, m, tm));
            queue.push_back((m, tm, b, tb));
        }
    }
    anchors.sort_unstable();
    HeightClock { anchors }
}

/// Block times for `[lo, hi]`, read from the node. Never fails: an unreachable node gives
/// an empty clock and the caller falls back to the time of the scan.
pub fn height_clock(url: &str, lo: i64, hi: i64) -> HeightClock {
    clock_from(lo, hi, &mut |h| {
        let u = format!("{}/header?height={h}", base(url));
        let v: Value = agent().get(&u).call().ok()?.into_json().ok()?;
        rfc3339_unix(v["result"]["header"]["time"].as_str()?)
    })
}

/// Unix seconds of a UTC RFC 3339 time as CometBFT writes it (`2026-11-19T12:34:56.789Z`).
/// Fractions are dropped; anything that is not UTC is refused.
fn rfc3339_unix(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || !s.ends_with('Z') {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, sec) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // Days since 1970-01-01 in the proleptic Gregorian calendar.
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    u64::try_from(days * 86_400 + h * 3_600 + mi * 60 + sec).ok()
}

#[test]
fn rfc3339_times_parse_to_unix_seconds() {
    assert_eq!(rfc3339_unix("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(rfc3339_unix("2026-11-19T12:34:56.123456789Z"), Some(1_795_091_696));
    assert_eq!(rfc3339_unix("2024-02-29T23:59:59Z"), Some(1_709_251_199));
    assert_eq!(rfc3339_unix("2026-11-19T12:34:56+01:00"), None);
    assert_eq!(rfc3339_unix("yesterday"), None);
}

#[test]
fn the_clock_asks_the_same_heights_whatever_the_wallet_holds_and_finds_a_halt() {
    // One block a second, except a two-hour halt after height 700,000.
    let time = |h: i64| 1_000_000 + h as u64 + if h > 700_000 { 7_200 } else { 0 };
    let mut asked = Vec::new();
    let clock = clock_from(1, 1_000_000, &mut |h| {
        asked.push(h);
        Some(time(h))
    });
    assert!(asked.len() <= CLOCK_MAX_READS);
    for h in [1, 5_000, 350_000, 699_000, 760_000, 999_999, 1_000_000] {
        assert!(clock.at(h).unwrap().abs_diff(time(h)) <= 120, "height {h}");
    }
    // Outside the range the nearest end is used; an unreadable end gives no clock.
    assert_eq!(clock.at(2_000_000), Some(time(1_000_000)));
    assert!(clock_from(1, 100, &mut |_| None).at(50).is_none());
    assert!(HeightClock::default().at(5).is_none());
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

// ---------------------------------------------------------------------------
// Bridge RESERVE-KEY pinning.
//
// A BTC deposit is locked on Bitcoin to the chain's reserve key. The wallet reads that
// key from the node and checks it against a key it already trusts before using it.
//
//   * A release build can carry the trusted keys (`ZCRYPT_RESERVE_PK_PINS` at compile
//     time, `chain-id=hex[,hex...]` entries separated by `;`). For a chain listed there,
//     only those keys are accepted and nothing the node says can add one.
//   * Otherwise the first key seen for a (chain, asset) is pinned in the data dir, and a
//     different key later is refused until the user accepts it explicitly (a reserve
//     rotation is rare and announced).
// ---------------------------------------------------------------------------

/// Marker at the start of the error a changed reserve key produces; the Bridge screen keys
/// its "accept the new key" prompt on it.
pub const RESERVE_KEY_CHANGED: &str = "RESERVE-KEY-CHANGED";

const BUILTIN_RESERVE_PINS: Option<&str> = option_env!("ZCRYPT_RESERVE_PK_PINS");

/// The keys compiled into this build for `chain_id`, if the build pins that chain.
fn builtin_reserve_pins(pins: Option<&str>, chain_id: &str) -> Option<Vec<String>> {
    for entry in pins?.split(';') {
        let Some((id, keys)) = entry.split_once('=') else { continue };
        if id.trim() == chain_id {
            let v: Vec<String> = keys.split(',').map(|k| k.trim().to_ascii_lowercase()).filter(|k| !k.is_empty()).collect();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn reserve_pin_path() -> Option<std::path::PathBuf> {
    PIN_DIR.read().unwrap().clone().map(|d| std::path::Path::new(&d).join("reserve_keys.json"))
}

fn load_reserve_pins(path: &std::path::Path) -> std::collections::BTreeMap<String, Vec<String>> {
    std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn reserve_pin_slot(asset: u64) -> String {
    format!("{}:{asset}", pinned_id().unwrap_or_default())
}

/// The decision for a reserve key the node reported, given what this wallet trusts.
/// `builtin` = keys compiled in for this chain; `pinned` = keys pinned or accepted locally.
fn reserve_key_verdict(builtin: Option<&[String]>, pinned: &[String], pk_hex: &str) -> Result<bool, String> {
    if let Some(keys) = builtin {
        return if keys.iter().any(|k| k == pk_hex) {
            Ok(false)
        } else {
            Err(format!(
                "the node reports a zBTC reserve key ({pk_hex}) that this wallet build does not recognise. \
                 Nothing was sent. Update the wallet if a reserve rotation was announced; otherwise do not \
                 use this node for the bridge."
            ))
        };
    }
    if pinned.is_empty() {
        return Ok(true); // first sight: pin it
    }
    if pinned.iter().any(|k| k == pk_hex) {
        return Ok(false);
    }
    Err(format!(
        "{RESERVE_KEY_CHANGED}: the node now reports a different zBTC reserve key ({pk_hex}) than the one this \
         wallet has used before ({}). Nothing was sent. A reserve rotation is rare and announced: accept the \
         new key only if you have confirmed it from the project's own channels.",
        pinned.last().map(String::as_str).unwrap_or("")
    ))
}

/// Check a node-reported reserve key for `asset` against the trusted set, pinning it on
/// first sight. `Err` means the key is NOT trusted and nothing may be funded to it.
pub fn check_reserve_pk(asset: u64, pk: &[u8; 33]) -> Result<(), String> {
    let pk_hex = hex::encode(pk);
    let chain_id = pinned_id().unwrap_or_default();
    let builtin = builtin_reserve_pins(BUILTIN_RESERVE_PINS, &chain_id);
    let Some(path) = reserve_pin_path() else {
        // No data dir (tests / pre-setup): only the compiled-in pins can apply.
        return reserve_key_verdict(builtin.as_deref(), &[pk_hex.clone()], &pk_hex).map(|_| ());
    };
    let mut pins = load_reserve_pins(&path);
    let slot = reserve_pin_slot(asset);
    let have = pins.get(&slot).cloned().unwrap_or_default();
    if reserve_key_verdict(builtin.as_deref(), &have, &pk_hex)? {
        pins.entry(slot).or_default().push(pk_hex);
        let json = serde_json::to_string(&pins).map_err(|e| e.to_string())?;
        crate::privfs::write_private(&path, json.as_bytes()).map_err(|e| format!("could not pin the reserve key: {e}"))?;
    }
    Ok(())
}

/// Trust `pk_hex` as a reserve key for `asset` from now on (the user confirmed a rotation).
/// Refused on a chain this build pins: there the trusted keys ship with the wallet.
pub fn accept_reserve_pk(asset: u64, pk_hex: &str) -> Result<(), String> {
    let pk_hex = pk_hex.trim().to_ascii_lowercase();
    if hex::decode(&pk_hex).map(|b| b.len()).unwrap_or(0) != 33 {
        return Err("not a 33-byte compressed public key".to_string());
    }
    if builtin_reserve_pins(BUILTIN_RESERVE_PINS, &pinned_id().unwrap_or_default()).is_some() {
        return Err("this wallet build pins the reserve key for this chain; update the wallet instead".to_string());
    }
    let path = reserve_pin_path().ok_or("no wallet data directory")?;
    let mut pins = load_reserve_pins(&path);
    let keys = pins.entry(reserve_pin_slot(asset)).or_default();
    if !keys.contains(&pk_hex) {
        keys.push(pk_hex);
    }
    let json = serde_json::to_string(&pins).map_err(|e| e.to_string())?;
    crate::privfs::write_private(&path, json.as_bytes()).map_err(|e| format!("could not save the reserve key: {e}"))
}

#[cfg(test)]
mod reserve_pin_tests {
    use super::*;

    const A: &str = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn first_sight_pins_and_a_different_key_is_refused_until_accepted() {
        assert_eq!(reserve_key_verdict(None, &[], A), Ok(true), "first key is pinned");
        assert_eq!(reserve_key_verdict(None, &[A.to_string()], A), Ok(false), "the pinned key passes");
        let e = reserve_key_verdict(None, &[A.to_string()], B).unwrap_err();
        assert!(e.starts_with(RESERVE_KEY_CHANGED), "{e}");
        // Once accepted (a rotation), both the old and the new key pass.
        let both = [A.to_string(), B.to_string()];
        assert_eq!(reserve_key_verdict(None, &both, B), Ok(false));
        assert_eq!(reserve_key_verdict(None, &both, A), Ok(false));
    }

    #[test]
    fn a_build_pin_overrides_everything_the_node_or_the_data_dir_says() {
        let built = [A.to_string()];
        assert_eq!(reserve_key_verdict(Some(&built), &[], A), Ok(false));
        // A key outside the build's list is refused even on first sight and whatever the
        // local pin file says; the error is not the "accept it" kind.
        let e = reserve_key_verdict(Some(&built), &[B.to_string()], B).unwrap_err();
        assert!(!e.starts_with(RESERVE_KEY_CHANGED), "{e}");
    }

    #[test]
    fn build_pins_parse_per_chain() {
        let pins = Some("zcrypt-1=02AA, 03bb ;zcrypt-test=02cc;junk");
        assert_eq!(builtin_reserve_pins(pins, "zcrypt-1"), Some(vec!["02aa".to_string(), "03bb".to_string()]));
        assert_eq!(builtin_reserve_pins(pins, "zcrypt-test"), Some(vec!["02cc".to_string()]));
        assert_eq!(builtin_reserve_pins(pins, "other"), None);
        assert_eq!(builtin_reserve_pins(None, "zcrypt-1"), None);
        assert_eq!(builtin_reserve_pins(Some("zcrypt-1="), "zcrypt-1"), None);
    }
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

/// Where a wallet created right now may start scanning: a height a few blocks under the
/// node's tip, and the chain generation tag. One short request, so creating a wallet
/// offline does not stall; `None` means "start from genesis", which is always correct.
pub fn birth_point(url: &str) -> Option<(i64, String)> {
    let u = format!("{}/status", base(url));
    let b: Value = agent_with_timeout(5).get(&u).call().ok()?.into_json().ok()?;
    let chain_id = b["result"]["node_info"]["network"].as_str().unwrap_or("");
    let genesis = b["result"]["sync_info"]["earliest_block_hash"].as_str().unwrap_or("");
    let tip: i64 = b["result"]["sync_info"]["latest_block_height"].as_str()?.parse().ok()?;
    if chain_id.is_empty() || genesis.is_empty() || tip <= BIRTH_MARGIN_BLOCKS {
        return None;
    }
    Some((tip - BIRTH_MARGIN_BLOCKS, format!("{chain_id}:{genesis}")))
}
/// A new wallet starts this far under the tip the node reported. The scan restarts from
/// genesis if its cursor is ever above the application's height, and the two heights a
/// node reports can differ by a block.
const BIRTH_MARGIN_BLOCKS: i64 = 10;

fn abci_query_hex(url: &str, path: &str) -> Result<String, String> {
    let u = format!("{}/abci_query?path=%22{}%22", base(url), path);
    let b: Value = agent().get(&u).call().map_err(|e| e.to_string())?.into_json().map_err(|e| e.to_string())?;
    let resp = &b["result"]["response"];
    if resp["code"].as_i64().unwrap_or(0) != 0 {
        return Err(format!("query {path}: {}", resp["log"].as_str().unwrap_or("rejected")));
    }
    // CometBFT encodes an EMPTY value as null: a successful query with nothing to report
    // (e.g. no pending coins) is an empty string, not an error.
    let Some(v) = resp["value"].as_str() else {
        return Ok(String::new());
    };
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
        // An empty page always ends the walk: a node reporting a page size of 0 (or a
        // page that never comes back short) must not spin this loop forever.
        if n == 0 || n < page {
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
    // The size query is retried: one throttled or dropped request must not decide what
    // the wallet believes is on chain.
    let mut count = commitment_count(url);
    for pause_ms in [400u64, 1_200] {
        if count.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(pause_ms));
        count = commitment_count(url);
    }
    let mut cache = CACHE.lock().map_err(|_| "leaf cache lock".to_string())?;
    let count = match count {
        Ok(n) => n,
        // Nothing cached (first use, or an old node without the size query): the full
        // dump below is the fallback.
        Err(_) if cache.is_empty() => 0,
        // With a cache in hand, a failed size query used to return the cache as if it were
        // the current tree. A coin created since the last sync then looked absent from the
        // chain, and a send was refused as "insufficient balance". Say what happened.
        Err(e) => return Err(format!("could not read the commitment tree size from the node: {e}")),
    };
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
    // Every broadcast rides a Tor circuit of its OWN (fresh credentials per call), separate
    // from the query traffic and from every other broadcast of this session.
    let resp: Value = match agent_fresh("broadcast", BROADCAST_TIMEOUT_S).post(base(url)).send_json(body) {
        Ok(r) => r.into_json().map_err(|e| e.to_string())?,
        // A non-2xx still carries the reason. CometBFT's body-read failure is HTTP 400
        // with `error.data` set; dropping the body leaves only "status code 400".
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            let detail = serde_json::from_str::<Value>(&text).ok().and_then(|v| {
                v["error"]["data"]
                    .as_str()
                    .or_else(|| v["error"]["message"].as_str())
                    .map(|s| s.to_string())
            });
            let detail = detail.filter(|s| !s.is_empty()).unwrap_or(text);
            let detail = detail.trim();
            return Err(if detail.is_empty() {
                format!("node returned HTTP {code}")
            } else {
                format!("node returned HTTP {code}: {detail}")
            });
        }
        Err(e) => return Err(e.to_string()),
    };
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

/// GET `u` as JSON with backoff on transient failures: a 429 (honouring `Retry-After`),
/// a 5xx, or a transport error is retried a few times; anything else fails at once.
fn get_json_retry(u: &str) -> Result<Value, String> {
    get_json_retry_with(u, TIMEOUT_S)
}

/// Same, with its own timeout: a page of shielded transactions is tens of megabytes
/// (each carries a 2 MB proof), which the default 45 s cannot move over a slow link.
fn get_json_retry_with(u: &str, secs: u64) -> Result<Value, String> {
    let mut wait = std::time::Duration::from_millis(500);
    let max_wait = std::time::Duration::from_secs(30);
    let attempts = 4;
    for attempt in 1..=attempts {
        match agent_with_timeout(secs).get(u).call() {
            Ok(r) => return r.into_json().map_err(|e| e.to_string()),
            Err(ureq::Error::Status(code, resp)) => {
                let transient = code == 429 || code >= 500;
                if !transient || attempt == attempts {
                    return Err(format!("node returned HTTP {code}"));
                }
                let retry_after = resp
                    .header("Retry-After")
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .map(std::time::Duration::from_secs);
                std::thread::sleep(retry_after.unwrap_or(wait).min(max_wait));
            }
            Err(e) => {
                if attempt == attempts {
                    return Err(e.to_string());
                }
                std::thread::sleep(wait.min(max_wait));
            }
        }
        wait *= 2;
    }
    Err("unreachable".into())
}

/// What a resumable block fetch produced: every tx-bearing block in `[from, covered_to]`
/// (ascending), the last height fully covered, and the error that stopped it early (if any).
pub struct ScanFetch {
    pub blocks: Vec<(i64, Vec<Vec<u8>>)>,
    pub covered_to: i64,
    pub error: Option<String>,
}

impl ScanFetch {
    pub fn empty(covered_to: i64) -> ScanFetch {
        ScanFetch { blocks: Vec::new(), covered_to, error: None }
    }
}

/// Fetch the transactions of every tx-bearing block in `[from, to]`, ASCENDING, with retry
/// and backoff on rate limits. If the node keeps failing, stop and report how far the
/// contiguous prefix got, so the caller can persist that height and resume later instead
/// of restarting from `from` (a restore-from-genesis over Tor can take many requests).
///
/// Most blocks are empty, so the scan asks the node's transaction INDEX for the
/// transactions in the range (100 per request, only the blocks that have any) instead of
/// paging through every block header 20 at a time. A node without an index (`indexer =
/// "null"`) falls back to the header walk.
pub fn scan_blocks(url: &str, from: i64, to: i64) -> ScanFetch {
    scan_blocks_reporting(url, from, to, &|_, _| {})
}

/// Like [`scan_blocks`], calling `progress(height_reached, tip)` as the fetch moves.
/// `height_reached` is the highest block this fetch has covered, not a count of requests.
pub fn scan_blocks_reporting(url: &str, from: i64, to: i64, progress: &dyn Fn(i64, i64)) -> ScanFetch {
    if from > to {
        return ScanFetch::empty(to);
    }
    match scan_blocks_indexed(url, from, to, progress) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[scan] tx index unavailable ({e}); walking block headers instead");
            scan_blocks_walk(url, from, to, progress)
        }
    }
}

/// How many blocks below the tip the indexed scan leaves alone. The node indexes a block's
/// transactions right after committing it, but asynchronously; a transaction in the newest
/// block or two may not be searchable yet, and a cursor that moved past it would skip the
/// note for good. Those blocks are read on the next pass instead.
const INDEX_LAG_BLOCKS: i64 = 2;

/// One row of a `tx_search` page: (height, index within the block, raw tx bytes).
type IndexedTx = (i64, u32, Vec<u8>);

/// Ask the node's transaction index for every transaction in `[from, to]`. `Err` means the
/// index could not answer at all (so the caller should walk headers instead); a failure
/// after the first window returns `Ok` with a partial, contiguous prefix and `error` set.
///
/// The range is asked for in height windows, not as one query. The node answers a page by
/// loading every transaction the query matches and then cutting the page out, so one
/// query over the whole chain costs the whole chain again on every page.
fn scan_blocks_indexed(url: &str, from: i64, to: i64, progress: &dyn Fn(i64, i64)) -> Result<ScanFetch, String> {
    let tip = to;
    let to = to - INDEX_LAG_BLOCKS;
    if from > to {
        progress(tip, tip);
        return Ok(ScanFetch::empty(from - 1));
    }
    scan_windows(from, to, &mut |lo, hi| index_window(url, lo, hi), &|at| progress(at, tip))
}

/// Shielded transactions are ~4 MB each on the wire (two proofs), so a page is kept to
/// about 40 MB and given a long timeout: a page of 100 ran past 45 s and was cut off
/// mid-body, which made the whole index look unavailable.
const INDEX_PER_PAGE: usize = 10;
const INDEX_PAGE_TIMEOUT_S: u64 = 240;
/// Window sizes, in blocks. Most blocks are empty, so the first window is wide; each next
/// one is sized to hold about one page at the density just seen.
const INDEX_FIRST_WINDOW: i64 = 20_000;
const INDEX_MIN_WINDOW: i64 = 200;
const INDEX_MAX_WINDOW: i64 = 1_000_000;

/// What one window fetch failed with: the rows that did arrive, and the error.
type WindowError = (Vec<IndexedTx>, String);

/// The next window size after a window of `win` blocks returned `got` transactions: aim
/// for one page, moving at most a factor of four per step.
fn next_window(win: i64, got: usize) -> i64 {
    let want = INDEX_PER_PAGE as i64;
    let sized = win.saturating_mul(want) / (got as i64).max(1);
    sized.clamp(win / 4, win.saturating_mul(4)).clamp(INDEX_MIN_WINDOW, INDEX_MAX_WINDOW)
}

/// Walk `[from, to]` window by window with `fetch(lo, hi)`. The first window failing is
/// `Err` (the index is not usable). A later failure keeps every finished window, plus the
/// whole blocks of the failed one, and stops the cursor there.
fn scan_windows(
    from: i64,
    to: i64,
    fetch: &mut dyn FnMut(i64, i64) -> Result<Vec<IndexedTx>, WindowError>,
    progress: &dyn Fn(i64),
) -> Result<ScanFetch, String> {
    let mut rows: Vec<IndexedTx> = Vec::new();
    let mut win = INDEX_FIRST_WINDOW;
    let mut lo = from;
    while lo <= to {
        let hi = lo.saturating_add(win - 1).min(to);
        match fetch(lo, hi) {
            Ok(got) => {
                win = next_window(win, got.len());
                rows.extend(got);
                progress(hi);
                lo = hi + 1;
            }
            Err((_, e)) if lo == from => return Err(e),
            Err((partial, e)) => {
                let mut out = indexed_prefix(partial, lo, Some(format!("tx index from height {lo}: {e}")));
                let mut blocks = group_indexed_txs(rows);
                blocks.append(&mut out.blocks);
                out.blocks = blocks;
                return Ok(out);
            }
        }
    }
    let mut out = ScanFetch::empty(to);
    out.blocks = group_indexed_txs(rows);
    Ok(out)
}

/// Every transaction the node's index holds for heights `[lo, hi]`, page by page.
fn index_window(url: &str, lo: i64, hi: i64) -> Result<Vec<IndexedTx>, WindowError> {
    let mut rows: Vec<IndexedTx> = Vec::new();
    let mut page = 1usize;
    loop {
        let u = format!(
            "{}/tx_search?query=%22tx.height%3E%3D{lo}%20AND%20tx.height%3C%3D{hi}%22&per_page={INDEX_PER_PAGE}&page={page}&order_by=%22asc%22",
            base(url)
        );
        let v = match get_json_retry_with(&u, INDEX_PAGE_TIMEOUT_S) {
            Ok(v) => v,
            Err(e) => return Err((rows, format!("page {page}: {e}"))),
        };
        if let Some(err) = v.get("error") {
            let msg = err["message"].as_str().unwrap_or("error");
            let data = err["data"].as_str().unwrap_or("");
            return Err((rows, format!("page {page}: {}", format!("{msg} {data}").trim())));
        }
        let res = &v["result"];
        let total = res["total_count"]
            .as_str()
            .and_then(|s| s.parse::<usize>().ok())
            .or_else(|| res["total_count"].as_u64().map(|n| n as usize));
        let Some(total) = total else {
            return Err((rows, "tx_search: no total_count".to_string()));
        };
        let txs = res["txs"].as_array().cloned().unwrap_or_default();
        let got = txs.len();
        for t in txs {
            let h = t["height"].as_str().and_then(|s| s.parse::<i64>().ok());
            let raw = t["tx"].as_str().and_then(|s| B64.decode(s).ok());
            if let (Some(h), Some(raw)) = (h, raw) {
                rows.push((h, t["index"].as_u64().unwrap_or(0) as u32, raw));
            }
        }
        if got == 0 || page * INDEX_PER_PAGE >= total {
            return Ok(rows);
        }
        page += 1;
    }
}

/// Group index rows into per-block transaction lists, ascending by height and by position
/// within the block (the order a block walk would have produced).
fn group_indexed_txs(mut rows: Vec<IndexedTx>) -> Vec<(i64, Vec<Vec<u8>>)> {
    rows.sort_by_key(|(h, i, _)| (*h, *i));
    let mut out: Vec<(i64, Vec<Vec<u8>>)> = Vec::new();
    for (h, _, tx) in rows {
        match out.last_mut() {
            Some((lh, txs)) if *lh == h => txs.push(tx),
            _ => out.push((h, vec![tx])),
        }
    }
    out
}

/// The contiguous prefix an interrupted indexed scan can safely keep. A page boundary may
/// split one block's transactions, so the highest height seen is dropped and the cursor
/// stops just below it; with nothing fetched the cursor does not move.
fn indexed_prefix(rows: Vec<IndexedTx>, from: i64, error: Option<String>) -> ScanFetch {
    let cut = rows.iter().map(|(h, _, _)| *h).max();
    let mut out = ScanFetch::empty(from - 1);
    out.error = error;
    if let Some(cut) = cut {
        out.blocks = group_indexed_txs(rows.into_iter().filter(|(h, _, _)| *h < cut).collect());
        out.covered_to = cut - 1;
    }
    out
}

/// The pre-index scan: page through block headers 20 at a time and fetch each block that
/// has transactions.
fn scan_blocks_walk(url: &str, from: i64, to: i64, progress: &dyn Fn(i64, i64)) -> ScanFetch {
    let mut out = ScanFetch::empty(from - 1);
    if from > to {
        out.covered_to = to;
        return out;
    }
    let mut lo = from;
    while lo <= to {
        let hi = (lo + 19).min(to); // /blockchain returns at most 20 metas
        let u = format!("{}/blockchain?minHeight={}&maxHeight={}", base(url), lo, hi);
        let metas: Vec<i64> = match get_json_retry(&u) {
            Ok(b) => {
                let mut hs: Vec<i64> = b["result"]["block_metas"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter(|m| m["num_txs"].as_str().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) > 0)
                            .filter_map(|m| m["header"]["height"].as_str().and_then(|s| s.parse::<i64>().ok()))
                            .collect()
                    })
                    .unwrap_or_default();
                hs.sort_unstable();
                hs
            }
            Err(e) => {
                out.error = Some(format!("block index {lo}..{hi}: {e}"));
                return out;
            }
        };
        for h in metas {
            let bu = format!("{}/block?height={}", base(url), h);
            match get_json_retry(&bu) {
                Ok(b) => {
                    let txs: Vec<Vec<u8>> = b["result"]["block"]["data"]["txs"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|t| t.as_str().and_then(|s| B64.decode(s).ok()))
                        .collect();
                    out.blocks.push((h, txs));
                    out.covered_to = h;
                }
                Err(e) => {
                    out.error = Some(format!("block {h}: {e}"));
                    return out;
                }
            }
        }
        out.covered_to = hi;
        progress(hi, to);
        lo = hi + 1;
    }
    out
}

/// The Merkle authentication path of the coin at `leaf_idx` against a tree built
/// from `leaves` (in node order), for the in-circuit membership proof (L1).
pub fn merkle_path(leaves: &[Commitment], leaf_idx: usize) -> Option<(Vec<Commitment>, Vec<bool>)> {
    let mut tree = zcrypt_shield::tree::CommitmentTree::new();
    for &c in leaves {
        tree.append(c).ok()?;
    }
    tree.path(leaf_idx)
}

#[cfg(test)]
mod scan_index_tests {
    use super::*;

    fn row(h: i64, i: u32, b: u8) -> IndexedTx {
        (h, i, vec![b])
    }

    #[test]
    fn index_rows_group_per_block_in_walk_order() {
        // Rows arrive by height, but a block's own transactions may come in any order.
        let rows = vec![row(7, 1, 0xb), row(3, 0, 0xa), row(7, 0, 0xa), row(9, 0, 0xc)];
        let blocks = group_indexed_txs(rows);
        assert_eq!(blocks, vec![(3, vec![vec![0xa]]), (7, vec![vec![0xa], vec![0xb]]), (9, vec![vec![0xc]])]);
    }

    #[test]
    fn interrupted_index_scan_keeps_only_whole_blocks() {
        // Page 2 failed after rows for heights 3, 7 and 7 came back: block 7 may continue on
        // the lost page, so it is dropped and the cursor stops at 6.
        let rows = vec![row(3, 0, 0xa), row(7, 0, 0xa), row(7, 1, 0xb)];
        let f = indexed_prefix(rows, 1, Some("boom".into()));
        assert_eq!(f.blocks, vec![(3, vec![vec![0xa]])]);
        assert_eq!(f.covered_to, 6);
        assert_eq!(f.error.as_deref(), Some("boom"));
        // Nothing fetched: the cursor does not move.
        let f = indexed_prefix(Vec::new(), 10, Some("boom".into()));
        assert!(f.blocks.is_empty());
        assert_eq!(f.covered_to, 9);
    }

    #[test]
    fn windows_cover_the_range_once_and_follow_the_density() {
        // 25 transactions at heights 1..=25, then nothing up to 3,000,000.
        let calls = std::cell::RefCell::new(Vec::new());
        let mut fetch = |lo: i64, hi: i64| -> Result<Vec<IndexedTx>, WindowError> {
            calls.borrow_mut().push((lo, hi));
            Ok((lo..=hi.min(25)).map(|h| row(h, 0, h as u8)).collect())
        };
        let f = scan_windows(1, 3_000_000, &mut fetch, &|_| {}).unwrap();
        assert_eq!(f.covered_to, 3_000_000);
        assert!(f.error.is_none());
        assert_eq!(f.blocks.len(), 25);
        let calls = calls.into_inner();
        // Contiguous, no overlap, no gap.
        assert_eq!(calls[0].0, 1);
        assert_eq!(calls.last().unwrap().1, 3_000_000);
        for w in calls.windows(2) {
            assert_eq!(w[1].0, w[0].1 + 1);
        }
        // A dense first window narrows the next one; empty windows widen up to the cap.
        assert!(calls[1].1 - calls[1].0 < calls[0].1 - calls[0].0);
        assert_eq!(calls.iter().map(|(lo, hi)| hi - lo + 1).max(), Some(INDEX_MAX_WINDOW));
        assert!(calls.len() < 20, "{} requests for an almost empty chain", calls.len());
    }

    #[test]
    fn a_window_that_fails_keeps_the_finished_ones_and_its_own_whole_blocks() {
        let mut n = 0;
        let mut fetch = |lo: i64, _hi: i64| -> Result<Vec<IndexedTx>, WindowError> {
            n += 1;
            if n == 1 {
                return Ok(vec![row(lo, 0, 1), row(lo + 5, 0, 2)]);
            }
            // Second window: heights lo+1 and lo+3 arrived, then a page was lost.
            Err((vec![row(lo + 1, 0, 3), row(lo + 3, 0, 4)], "boom".into()))
        };
        let f = scan_windows(10, 5_000_000, &mut fetch, &|_| {}).unwrap();
        let second = 10 + INDEX_FIRST_WINDOW;
        assert_eq!(f.blocks.iter().map(|(h, _)| *h).collect::<Vec<_>>(), vec![10, 15, second + 1]);
        assert_eq!(f.covered_to, second + 2);
        assert!(f.error.as_deref().unwrap().contains("boom"));
        // The very first window failing means the index cannot be used at all.
        let mut dead = |_: i64, _: i64| -> Result<Vec<IndexedTx>, WindowError> { Err((Vec::new(), "no index".into())) };
        assert_eq!(scan_windows(10, 50, &mut dead, &|_| {}).err().as_deref(), Some("no index"));
    }

    #[test]
    fn empty_range_moves_nothing() {
        let f = scan_blocks("http://127.0.0.1:1", 10, 9);
        assert!(f.blocks.is_empty() && f.error.is_none());
        assert_eq!(f.covered_to, 9);
    }
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
        // Fresh credentials differ on every call (one circuit per broadcast).
        let f1 = socks_isolated_fresh("socks5://127.0.0.1:9050", "broadcast");
        let f2 = socks_isolated_fresh("socks5://127.0.0.1:9050", "broadcast");
        assert_ne!(f1, f2);
        assert!(f1.starts_with("socks5://zc-broadcast-") && f1.ends_with("@127.0.0.1:9050"));
    }
}
