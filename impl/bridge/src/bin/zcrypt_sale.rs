//! The foundation's SALE DESK daemon: "send Bitcoin, get ZCRYPT".
//!
//! Serves three routes the wallet's Buy tab talks to, watches Bitcoin for the payments,
//! and pays ZCRYPT from its own shielded coins. See `zcrypt_bridge::sale` for the order
//! model; this file is the plumbing (HTTP, Esplora, ZCrypt node, state file).
//!
//!   GET  /quote            posted price, limits, stock, confirmations, network
//!   POST /order            {"address": "zc1…", "sats": N}  ->  the order (with its BTC address)
//!   GET  /order/<id>       the order's current status
//!
//! Config (env):
//!   SALE_MNEMONIC_FILE   file holding the desk's BIP-39 phrase. ONE phrase gives both sides:
//!                        the ZCrypt account that holds the ZCRYPT stock and the BIP-84
//!                        Bitcoin addresses buyers pay (m/84'/coin'/0'/0/<order index>). Import
//!                        the same phrase into the desktop wallet to spend the Bitcoin.
//!   SALE_PRICE_SATS      satoshis per whole ZCRYPT (0 closes the desk)
//!   SALE_PRICE_FILE      optional: a file with that one number, re-read on every quote, so
//!                        the price changes without a restart (overrides SALE_PRICE_SATS)
//!   SALE_MIN_SATS        smallest order              (default 20000 = 0.0002 BTC)
//!   SALE_MAX_SATS        largest order               (default 100000000 = 1 BTC)
//!   SALE_MIN_CONF        confirmations before paying (default 1; 0 pays on first sight)
//!   SALE_TTL_SECS        how long an unpaid order stays open (default 86400)
//!   SALE_LISTEN          bind address                (default 0.0.0.0:8787)
//!   SALE_STATE           state file                  (default ./zcrypt-sale-state.json)
//!   SALE_POLL_SECS       seconds between passes      (default 20)
//!   ZC_URL               ZCrypt CometBFT RPC         (default http://localhost:36657)
//!   ESPLORA_URL          Esplora REST base           (default https://blockstream.info/api)
//!   BTC_NETWORK          bitcoin|signet|testnet|regtest (default bitcoin)
//!   ZCRYPT_CHAIN_ID      chain id to bind txs to     (default zcrypt-1)
//!
//!   zcrypt_sale --address   print the desk's ZCrypt address (fund it here) and its Bitcoin
//!                           account xpub (watch the sales in any wallet), then exit.
//!
//! Put the daemon behind TLS (a reverse proxy) when it faces the internet; it speaks plain
//! HTTP. The state file holds the desk's coin secrets and is written 0600.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::Network;
use serde::{Deserialize, Serialize};
use zcrypt_bridge::esplora::Esplora;
use zcrypt_bridge::hdwallet::HdWallet;
use zcrypt_bridge::sale::{self, Order, OrderStatus, Quote};
use zcrypt_bridge::swap;
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_core::emission::MIN_FEE;
use zcrypt_core::keys::{self, Account, Coin};
use zcrypt_core::kem;
use zcrypt_shield::{Blind, SpendSecret, N_IN};

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A coin the desk owns, as persisted. The secrets are what make the coin spendable, so
/// the state file is private (0600); the phrase can rebuild them by rescanning anyway.
#[derive(Clone, Serialize, Deserialize)]
struct CoinRec {
    value: u64,
    blind: Blind,
    spend_secret: SpendSecret,
    asset_id: u64,
    spent: bool,
}

impl CoinRec {
    fn from_coin(c: &Coin) -> Self {
        CoinRec { value: c.value, blind: c.blind, spend_secret: c.spend_secret, asset_id: c.asset_id, spent: false }
    }
    fn coin(&self) -> Coin {
        Coin { value: self.value, blind: self.blind, spend_secret: self.spend_secret, asset_id: self.asset_id }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    /// Next BIP-84 receive index to hand out.
    next_btc_index: u32,
    /// ZCrypt height scanned up to (inclusive).
    scan_height: i64,
    coins: Vec<CoinRec>,
    orders: Vec<Order>,
}

struct Desk {
    cfg: Config,
    account: Account,
    hd: HdWallet,
    state: State,
}

struct Config {
    price_sats: u64,
    price_file: Option<PathBuf>,
    min_sats: u64,
    max_sats: u64,
    min_conf: u32,
    ttl_secs: u64,
    state_path: PathBuf,
    network: Network,
}

impl Desk {
    fn price(&self) -> u64 {
        if let Some(p) = &self.cfg.price_file {
            if let Ok(s) = std::fs::read_to_string(p) {
                if let Ok(v) = s.trim().parse::<u64>() {
                    return v;
                }
                eprintln!("[sale] price file {} is not a number; desk closed until it is", p.display());
                return 0;
            }
        }
        self.cfg.price_sats
    }

    fn coin_table(&self) -> Vec<(u64, bool)> {
        self.state.coins.iter().map(|c| (c.value, c.spent || c.asset_id != zcrypt_shield::ASSET_ZCRYPT)).collect()
    }

    fn quote(&self) -> Quote {
        Quote {
            price_sats: self.price(),
            min_sats: self.cfg.min_sats,
            max_sats: self.cfg.max_sats,
            stock_atomic: sale::stock(&self.coin_table(), N_IN),
            min_conf: self.cfg.min_conf,
            network: network_name(self.cfg.network).to_string(),
            ttl_secs: self.cfg.ttl_secs,
        }
    }

    fn new_order(&mut self, zc_address: &str, sats: u64) -> Result<Order, String> {
        let q = self.quote();
        let addr = sale::validate_order(&q, zc_address, sats)?;
        let idx = self.state.next_btc_index;
        let btc = self.hd.receive_address(idx)?.to_string();
        let id: String = rand::random::<[u8; 16]>().iter().map(|b| format!("{b:02x}")).collect();
        let t = now();
        let o = Order {
            id,
            zc_address: addr.to_bech32(),
            btc_index: idx,
            btc_address: btc,
            sats,
            price_sats: q.price_sats,
            created: t,
            expires: t + self.cfg.ttl_secs,
            status: OrderStatus::Waiting,
            paid_sats: 0,
            confirmations: 0,
            zcrypt_atomic: 0,
            zc_txhash: String::new(),
        };
        self.state.next_btc_index += 1;
        self.state.orders.push(o.clone());
        self.persist()?;
        Ok(o)
    }

    fn persist(&self) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(&self.state).map_err(|e| e.to_string())?;
        let tmp = self.cfg.state_path.with_extension("json.tmp");
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| format!("state write: {e}"))?;
            f.write_all(&json).map_err(|e| format!("state write: {e}"))?;
            f.sync_all().map_err(|e| format!("state sync: {e}"))?;
        }
        std::fs::rename(&tmp, &self.cfg.state_path).map_err(|e| format!("state rename: {e}"))
    }

    /// Scan new ZCrypt blocks for coins paid to the desk (funding from the foundation
    /// wallet, and this desk's own change). Bounded per pass so a long gap catches up in
    /// steps while orders keep being served.
    fn scan(&mut self, zc: &Zcrypt) -> Result<(), String> {
        let tip = zc.height()?;
        let from = self.state.scan_height + 1;
        let to = tip.min(from + 2_000);
        if from > to {
            return Ok(());
        }
        let known: HashSet<[u64; 8]> = self.state.coins.iter().map(|c| c.coin().commitment()).collect();
        let mut found = Vec::new();
        for h in from..=to {
            for raw in zc.block_txs(h)? {
                let Some((&tag, body)) = raw.split_first() else { continue };
                let stxs = match tag {
                    0x55 => swap::parse_transfer_payload(body).map(|(g, m)| vec![g, m]).unwrap_or_default(),
                    0x6A => swap::parse_zcrypt_transfer_payload(body).map(|(_, _, s)| vec![s]).unwrap_or_default(),
                    _ => Vec::new(),
                };
                for stx in &stxs {
                    for n in &stx.enc_notes {
                        let Some(ct) = kem::ciphertext_from_bytes(n) else { continue };
                        if let Some(coin) = self.account.receive(&ct) {
                            if coin.value > 0 && !known.contains(&coin.commitment()) {
                                found.push(coin);
                            }
                        }
                    }
                }
            }
        }
        for c in &found {
            println!("[sale] received {} ZCRYPT (atomic {})", c.value / zcrypt_core::emission::ATOMIC, c.value);
            self.state.coins.push(CoinRec::from_coin(c));
        }
        self.state.scan_height = to;
        self.persist()
    }

    /// Pay `atomic` ZCRYPT to `order` from the desk's coins. Marks inputs spent and records
    /// the change coin only after the node accepted the transaction.
    fn pay(&mut self, zc: &Zcrypt, order_idx: usize, atomic: u64) -> Result<(), String> {
        let need = atomic.checked_add(MIN_FEE).ok_or("amount overflow")?;
        let chosen = sale::select_inputs(&self.coin_table(), need, N_IN).ok_or("insufficient stock")?;
        let inputs: Vec<Coin> = chosen.iter().map(|&i| self.state.coins[i].coin()).collect();
        let to = keys::Address::from_bech32(&self.state.orders[order_idx].zc_address).ok_or("bad order address")?;
        let blind = keys::random_blind();
        let out = keys::out_coin(&to, atomic, blind);
        let note = kem::ciphertext_to_bytes(&keys::encrypt_note(&to, atomic, blind));
        let (tx, change) = swap::build_zcrypt_transfer(zc, &inputs, out, note, &self.account, MIN_FEE)?;
        let hash = zc.broadcast(&tx)?;
        for &i in &chosen {
            self.state.coins[i].spent = true;
        }
        if change.value > 0 {
            self.state.coins.push(CoinRec::from_coin(&change));
        }
        self.state.orders[order_idx].mark_paid(atomic, hash);
        self.persist()
    }
}

fn network_name(n: Network) -> &'static str {
    match n {
        Network::Bitcoin => "bitcoin",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
        _ => "testnet",
    }
}

fn parse_network(s: &str) -> Result<Network, String> {
    Ok(match s {
        "bitcoin" | "mainnet" => Network::Bitcoin,
        "signet" => Network::Signet,
        "testnet" | "testnet4" => Network::Testnet,
        "regtest" => Network::Regtest,
        o => return Err(format!("unknown BTC_NETWORK {o}")),
    })
}

/// One pass: new coins, then every open order.
fn tick(desk: &Arc<Mutex<Desk>>, zc: &Zcrypt, esplora: &Esplora) {
    if let Err(e) = desk.lock().unwrap().scan(zc) {
        eprintln!("[sale] scan: {e}");
    }
    let (open, min_conf, ttl) = {
        let d = desk.lock().unwrap();
        let t = now();
        let open: Vec<(usize, String)> = d
            .state
            .orders
            .iter()
            .enumerate()
            .filter(|(_, o)| o.needs_watch(t, d.cfg.ttl_secs))
            .map(|(i, o)| (i, o.btc_address.clone()))
            .collect();
        (open, d.cfg.min_conf, d.cfg.ttl_secs)
    };
    let _ = ttl;
    if open.is_empty() {
        return;
    }
    let tip = match esplora.tip_height() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[sale] esplora tip: {e}");
            return;
        }
    };
    for (i, addr) in open {
        let utxos = match esplora.address_utxos(&addr) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("[sale] esplora {addr}: {e}");
                continue;
            }
        };
        let paid: u64 = utxos.iter().map(|u| u.value).sum();
        let confs = utxos
            .iter()
            .map(|u| match (u.confirmed, u.block_height) {
                (true, Some(h)) if tip >= h => (tip - h + 1).min(u32::MAX as u64) as u32,
                _ => 0,
            })
            .min()
            .unwrap_or(0);
        let mut d = desk.lock().unwrap();
        let due = d.state.orders[i].observe(now(), paid, confs, min_conf);
        if let Err(e) = d.persist() {
            eprintln!("[sale] persist: {e}");
        }
        if let Some(atomic) = due {
            let id = d.state.orders[i].id.clone();
            println!("[sale] order {id}: {paid} sats confirmed ({confs}); paying {atomic} atomic ZCRYPT");
            match d.pay(zc, i, atomic) {
                Ok(()) => println!("[sale] order {id}: paid, tx {}", d.state.orders[i].zc_txhash),
                Err(e) => eprintln!("[sale] order {id}: payout failed, will retry: {e}"),
            }
        }
    }
}

fn handle(mut stream: TcpStream, desk: &Arc<Mutex<Desk>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let head_end = loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 16 * 1024 {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let (mut req, len) = match sale::parse_http_head(&head) {
        Ok(x) => x,
        Err(e) => {
            let _ = stream.write_all(&sale::http_response(400, &format!("{{\"error\":\"{e}\"}}")));
            return;
        }
    };
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let n = match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    req.body = body;

    let (status, out) = route(&req, desk);
    let _ = stream.write_all(&sale::http_response(status, &out));
}

fn route(req: &sale::HttpRequest, desk: &Arc<Mutex<Desk>>) -> (u16, String) {
    let path = req.path.split('?').next().unwrap_or("/");
    match (req.method.as_str(), path) {
        ("OPTIONS", _) => (200, "{}".into()),
        ("GET", "/quote") => (200, serde_json::to_string(&desk.lock().unwrap().quote()).unwrap()),
        ("POST", "/order") => {
            let v: serde_json::Value = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(_) => return (400, "{\"error\":\"body must be JSON\"}".into()),
            };
            let address = v["address"].as_str().unwrap_or("");
            let sats = v["sats"].as_u64().unwrap_or(0);
            let mut d = desk.lock().unwrap();
            match d.new_order(address, sats) {
                Ok(o) => {
                    println!("[sale] order {}: {} sats, pay to {}", o.id, sats, o.btc_address);
                    let mc = d.cfg.min_conf;
                    (200, serde_json::to_string(&o.view(mc)).unwrap())
                }
                Err(e) => (400, serde_json::json!({ "error": e }).to_string()),
            }
        }
        ("GET", p) if p.starts_with("/order/") => {
            let id = &p["/order/".len()..];
            let d = desk.lock().unwrap();
            match d.state.orders.iter().find(|o| o.id == id) {
                Some(o) => (200, serde_json::to_string(&o.view(d.cfg.min_conf)).unwrap()),
                None => (404, "{\"error\":\"no such order\"}".into()),
            }
        }
        ("GET", _) | ("POST", _) => (404, "{\"error\":\"not found\"}".into()),
        _ => (405, "{\"error\":\"method not allowed\"}".into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let network = parse_network(&env("BTC_NETWORK", "bitcoin")).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let phrase_path = env("SALE_MNEMONIC_FILE", "");
    if phrase_path.is_empty() {
        eprintln!("SALE_MNEMONIC_FILE is required (the desk's BIP-39 phrase)");
        std::process::exit(2);
    }
    let phrase = zeroize::Zeroizing::new(std::fs::read_to_string(&phrase_path).unwrap_or_else(|e| {
        eprintln!("read {phrase_path}: {e}");
        std::process::exit(2)
    }));
    let account = Account::from_mnemonic(phrase.trim(), "").unwrap_or_else(|| {
        eprintln!("the phrase in {phrase_path} is not a valid BIP-39 mnemonic");
        std::process::exit(2)
    });
    let hd = HdWallet::from_mnemonic(phrase.trim(), "", network).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    drop(phrase);

    if args.iter().any(|a| a == "--address") {
        println!("ZCrypt address (send the ZCRYPT stock here):\n{}", account.normal_address().to_bech32());
        println!("Bitcoin account xpub (BIP-84, buyers pay m/84'/coin'/0'/0/<n>):\n{}", hd.account_xpub());
        return;
    }

    let cfg = Config {
        price_sats: env("SALE_PRICE_SATS", "0").parse().unwrap_or(0),
        price_file: std::env::var("SALE_PRICE_FILE").ok().filter(|s| !s.is_empty()).map(PathBuf::from),
        min_sats: env("SALE_MIN_SATS", "20000").parse().unwrap_or(20_000),
        max_sats: env("SALE_MAX_SATS", "100000000").parse().unwrap_or(100_000_000),
        min_conf: env("SALE_MIN_CONF", "1").parse().unwrap_or(1),
        ttl_secs: env("SALE_TTL_SECS", "86400").parse().unwrap_or(86_400),
        state_path: PathBuf::from(env("SALE_STATE", "./zcrypt-sale-state.json")),
        network,
    };
    let state: State = match std::fs::read(&cfg.state_path) {
        Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
            eprintln!("state file {} is corrupt: {e}", cfg.state_path.display());
            std::process::exit(2)
        }),
        Err(_) => State::default(),
    };
    let listen = env("SALE_LISTEN", "0.0.0.0:8787");
    let poll = Duration::from_secs(env("SALE_POLL_SECS", "20").parse().unwrap_or(20));
    let zc = Zcrypt::new(&env("ZC_URL", "http://localhost:36657"));
    let esplora = Esplora::new(&env("ESPLORA_URL", "https://blockstream.info/api"));

    let desk = Arc::new(Mutex::new(Desk { cfg, account, hd, state }));
    {
        let d = desk.lock().unwrap();
        let q = d.quote();
        println!("[sale] desk address {}", d.account.normal_address().to_bech32());
        println!(
            "[sale] price {} sats/ZCRYPT, stock {} ZCRYPT, {} coin(s), {} order(s), min_conf {}, network {}",
            q.price_sats,
            q.stock_atomic / zcrypt_core::emission::ATOMIC,
            d.state.coins.iter().filter(|c| !c.spent).count(),
            d.state.orders.len(),
            q.min_conf,
            q.network
        );
        if q.price_sats == 0 {
            println!("[sale] price is 0: the desk is CLOSED until SALE_PRICE_SATS or the price file is set");
        }
    }

    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("bind {listen}: {e}");
        std::process::exit(2)
    });
    println!("[sale] listening on {listen}");
    let d2 = desk.clone();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let d = d2.clone();
            std::thread::spawn(move || handle(s, &d));
        }
    });

    loop {
        tick(&desk, &zc, &esplora);
        std::thread::sleep(poll);
    }
}
