//! The foundation's BITCOIN SALE DESK: "send Bitcoin, get ZCRYPT".
//!
//! A buyer asks the desk for an order, pays Bitcoin to the fresh address the desk hands
//! back, and the desk pays ZCRYPT to the buyer's `zc1…` address once the payment confirms.
//! The Bitcoin lands directly in an address derived from the desk's own BIP-84 seed (the
//! same mnemonic restores the Bitcoin and the ZCRYPT side in the desktop wallet), so no
//! bridge, no zBTC and no consensus change sit in the path. The ZCRYPT comes from coins the
//! desk holds: the foundation funds it from its liquid allocation and validator rewards.
//!
//! This module is the pure, offline-testable part: the price arithmetic, the order record
//! and its state machine, the JSON wire shapes the wallet reads, and the tiny HTTP request
//! parser the daemon serves them with. `bin/zcrypt_sale.rs` adds the network side (Esplora
//! polling, shielded payout, persistence).
//!
//! Order lifecycle:
//!
//! ```text
//!   waiting ──payment seen (0-conf)──► seen ──min_conf reached──► paid
//!      │                                 │
//!      └──────── expiry, nothing paid ───┘──► expired
//!                                         (a payment that lands after expiry is still
//!                                          honoured: the address stays the buyer's)
//! ```
//!
//! Nothing here is consensus; the desk is an ordinary wallet that automates its own sends.

use serde::{Deserialize, Serialize};
use zcrypt_core::emission::{ATOMIC, MIN_FEE};
use zcrypt_core::keys::Address;

/// Hard floor on an order so a payout is never swallowed by the gas burn: the ZCRYPT a
/// buyer gets must exceed the 0.01 ZCRYPT the transfer burns many times over.
pub const MIN_PAYOUT_ATOMIC: u64 = 100 * MIN_FEE; // 1 ZCRYPT

/// What the buyer is owed for `sats` at `price_sats` (satoshis per whole ZCRYPT), in atomic
/// units, rounded down. `None` when the price is zero (desk closed) or the result overflows.
pub fn zcrypt_for_sats(sats: u64, price_sats: u64) -> Option<u64> {
    if price_sats == 0 {
        return None;
    }
    let atomic = (sats as u128) * (ATOMIC as u128) / (price_sats as u128);
    u64::try_from(atomic).ok()
}

/// The satoshis that buy exactly `atomic` ZCRYPT at `price_sats`, rounded UP so the buyer
/// always receives at least what they asked for. `None` when the price is zero or on overflow.
pub fn sats_for_zcrypt(atomic: u64, price_sats: u64) -> Option<u64> {
    if price_sats == 0 {
        return None;
    }
    let num = (atomic as u128) * (price_sats as u128);
    let sats = num.div_ceil(ATOMIC as u128);
    u64::try_from(sats).ok()
}

/// The desk's posted terms, as `GET /quote` returns them.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Quote {
    /// Satoshis per whole ZCRYPT. `0` means the desk is closed.
    pub price_sats: u64,
    /// Smallest and largest order the desk accepts, in satoshis.
    pub min_sats: u64,
    pub max_sats: u64,
    /// ZCRYPT the desk can pay out right now (atomic units), after reserving gas.
    pub stock_atomic: u64,
    /// Bitcoin confirmations before the desk pays. `0` credits on first sight (mempool).
    pub min_conf: u32,
    /// `bitcoin`, `signet` or `regtest`: the buyer's wallet must pay on this network.
    pub network: String,
    /// Seconds an unpaid order stays open.
    pub ttl_secs: u64,
}

/// Where an order is in its life.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    /// No payment at the order's address yet.
    Waiting,
    /// Payment in the mempool or below `min_conf`.
    Seen,
    /// ZCRYPT sent.
    Paid,
    /// Nothing arrived before the deadline. A late payment still flips it to `seen`.
    Expired,
}

/// One buyer's order. Persisted by the daemon; the public view is [`OrderView`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Order {
    /// 32 hex characters, random; the handle the wallet polls with.
    pub id: String,
    /// The buyer's `zc1…` address, validated at creation.
    pub zc_address: String,
    /// BIP-84 receive index of `btc_address` under the desk's seed (one address per order).
    pub btc_index: u32,
    pub btc_address: String,
    /// Satoshis the buyer said they would send (the quote they saw). What they actually
    /// send is what counts: `paid_sats`.
    pub sats: u64,
    /// Price locked at creation (satoshis per ZCRYPT), so a later repricing never changes
    /// what a buyer who already paid receives.
    pub price_sats: u64,
    /// Unix seconds.
    pub created: u64,
    pub expires: u64,
    pub status: OrderStatus,
    /// Satoshis received at `btc_address` (sum of every output there).
    pub paid_sats: u64,
    /// Confirmations of the oldest paying output, last time the desk looked.
    pub confirmations: u32,
    /// ZCRYPT paid out (atomic), and the ZCrypt transaction hash, once `Paid`.
    pub zcrypt_atomic: u64,
    pub zc_txhash: String,
}

/// The order as `GET /order/<id>` returns it: everything the buyer needs, nothing about
/// the desk's keys or indices.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrderView {
    pub id: String,
    pub btc_address: String,
    pub sats: u64,
    pub price_sats: u64,
    pub created: u64,
    pub expires: u64,
    pub status: OrderStatus,
    pub paid_sats: u64,
    pub confirmations: u32,
    pub min_conf: u32,
    pub zcrypt_atomic: u64,
    pub zc_txhash: String,
}

impl Order {
    pub fn view(&self, min_conf: u32) -> OrderView {
        OrderView {
            id: self.id.clone(),
            btc_address: self.btc_address.clone(),
            sats: self.sats,
            price_sats: self.price_sats,
            created: self.created,
            expires: self.expires,
            status: self.status,
            paid_sats: self.paid_sats,
            confirmations: self.confirmations,
            min_conf,
            zcrypt_atomic: self.zcrypt_atomic,
            zc_txhash: self.zc_txhash.clone(),
        }
    }

    /// Whether the desk should still poll Bitcoin for this order. Expired orders are
    /// polled for a grace period of one more TTL so a slow payment is not lost.
    pub fn needs_watch(&self, now: u64, ttl_secs: u64) -> bool {
        match self.status {
            OrderStatus::Paid => false,
            OrderStatus::Waiting | OrderStatus::Seen => true,
            OrderStatus::Expired => now < self.expires.saturating_add(ttl_secs),
        }
    }

    /// Fold a fresh look at the Bitcoin address into the order. `paid_sats` is the total
    /// now sitting at the address and `confirmations` the confirmations of the oldest
    /// paying output (0 while any of it is unconfirmed). Returns the ZCRYPT to pay (atomic)
    /// when the order has just become payable, else `None`. The caller pays, then calls
    /// [`Order::mark_paid`].
    pub fn observe(&mut self, now: u64, paid_sats: u64, confirmations: u32, min_conf: u32) -> Option<u64> {
        if self.status == OrderStatus::Paid {
            return None;
        }
        if paid_sats == 0 {
            if self.status == OrderStatus::Waiting && now >= self.expires {
                self.status = OrderStatus::Expired;
            }
            return None;
        }
        self.paid_sats = paid_sats;
        self.confirmations = confirmations;
        self.status = OrderStatus::Seen;
        if confirmations >= min_conf {
            zcrypt_for_sats(paid_sats, self.price_sats)
        } else {
            None
        }
    }

    pub fn mark_paid(&mut self, zcrypt_atomic: u64, zc_txhash: String) {
        self.status = OrderStatus::Paid;
        self.zcrypt_atomic = zcrypt_atomic;
        self.zc_txhash = zc_txhash;
    }
}

/// Validate a new-order request against the posted terms. Returns the parsed address.
pub fn validate_order(quote: &Quote, zc_address: &str, sats: u64) -> Result<Address, String> {
    if quote.price_sats == 0 {
        return Err("the desk is closed".to_string());
    }
    let addr = Address::from_bech32(zc_address.trim()).ok_or("invalid ZCrypt address (expected zc1…)")?;
    if sats < quote.min_sats {
        return Err(format!("minimum order is {} sats", quote.min_sats));
    }
    if sats > quote.max_sats {
        return Err(format!("maximum order is {} sats", quote.max_sats));
    }
    let atomic = zcrypt_for_sats(sats, quote.price_sats).ok_or("amount too large")?;
    if atomic < MIN_PAYOUT_ATOMIC {
        return Err("order too small: it would pay less than 1 ZCRYPT".to_string());
    }
    if atomic > quote.stock_atomic {
        return Err(format!(
            "sold out: only {} ZCRYPT available right now",
            quote.stock_atomic / ATOMIC
        ));
    }
    Ok(addr)
}

/// Pick the fewest unspent ZCRYPT coins (largest first, at most `max_inputs`) whose values
/// cover `need`. Returns their indices into `coins`, or `None` when no such subset exists.
/// `coins` is `(value, spent)`.
pub fn select_inputs(coins: &[(u64, bool)], need: u64, max_inputs: usize) -> Option<Vec<usize>> {
    let mut idx: Vec<usize> = coins.iter().enumerate().filter(|(_, c)| !c.1).map(|(i, _)| i).collect();
    idx.sort_by_key(|&i| std::cmp::Reverse(coins[i].0));
    let mut chosen = Vec::new();
    let mut total: u64 = 0;
    for i in idx.into_iter().take(max_inputs) {
        chosen.push(i);
        total = total.saturating_add(coins[i].0);
        if total >= need {
            return Some(chosen);
        }
    }
    None
}

/// What the desk can pay out in one transfer right now: the best `max_inputs` coins minus
/// the gas burn. This is the `stock_atomic` a quote advertises.
pub fn stock(coins: &[(u64, bool)], max_inputs: usize) -> u64 {
    let mut vals: Vec<u64> = coins.iter().filter(|c| !c.1).map(|c| c.0).collect();
    vals.sort_unstable_by(|a, b| b.cmp(a));
    let total: u64 = vals.iter().take(max_inputs).fold(0u64, |a, v| a.saturating_add(*v));
    total.saturating_sub(MIN_FEE)
}

/// A parsed HTTP/1.1 request: enough for the desk's three routes.
#[derive(Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// Parse the head of an HTTP request (request line + headers). Returns the request and the
/// declared `Content-Length`, with `body` still empty: the caller reads the body bytes
/// after the blank line. Rejects anything that is not a clean request line.
pub fn parse_http_head(head: &str) -> Result<(HttpRequest, usize), String> {
    let mut lines = head.split("\r\n");
    let req_line = lines.next().ok_or("empty request")?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next().ok_or("no method")?.to_ascii_uppercase();
    let path = parts.next().ok_or("no path")?.to_string();
    if !path.starts_with('/') || path.len() > 512 {
        return Err("bad path".to_string());
    }
    let mut len = 0usize;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().map_err(|_| "bad content-length")?;
            }
        }
    }
    if len > 64 * 1024 {
        return Err("body too large".to_string());
    }
    Ok((HttpRequest { method, path, body: Vec::new() }, len))
}

/// Serialize one HTTP response with a JSON body.
pub fn http_response(status: u16, body: &str) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcrypt_core::keys;

    fn err(r: Result<Address, String>) -> String {
        r.err().expect("expected an error")
    }

    fn quote() -> Quote {
        Quote {
            price_sats: 2_500,
            min_sats: 10_000,
            max_sats: 50_000_000,
            stock_atomic: 1_000 * ATOMIC,
            min_conf: 1,
            network: "bitcoin".into(),
            ttl_secs: 86_400,
        }
    }

    #[test]
    fn price_math_round_trips() {
        // 0.01 BTC at 2,500 sats/ZCRYPT = 400 ZCRYPT.
        assert_eq!(zcrypt_for_sats(1_000_000, 2_500), Some(400 * ATOMIC));
        // Rounds down: 2,499 sats buys 0.9996 ZCRYPT.
        assert_eq!(zcrypt_for_sats(2_499, 2_500), Some(999_600));
        // Closed desk.
        assert_eq!(zcrypt_for_sats(1, 0), None);
        // Inverse rounds up so the buyer is never short.
        assert_eq!(sats_for_zcrypt(400 * ATOMIC, 2_500), Some(1_000_000));
        assert_eq!(sats_for_zcrypt(1, 2_500), Some(1));
        let s = sats_for_zcrypt(999_600, 2_500).unwrap();
        assert!(zcrypt_for_sats(s, 2_500).unwrap() >= 999_600);
    }

    #[test]
    fn validation_enforces_terms() {
        let (acct, _) = keys::new_account();
        let zc = acct.normal_address().to_bech32();
        let q = quote();
        assert!(validate_order(&q, &zc, 1_000_000).is_ok());
        assert!(validate_order(&q, "zc1notanaddress", 1_000_000).is_err());
        assert!(err(validate_order(&q, &zc, 9_999)).contains("minimum"));
        assert!(err(validate_order(&q, &zc, 50_000_001)).contains("maximum"));
        // Stock: 1,000 ZCRYPT; 0.03 BTC would be 1,200.
        assert!(err(validate_order(&q, &zc, 3_000_000)).contains("sold out"));
        let closed = Quote { price_sats: 0, ..q.clone() };
        assert!(err(validate_order(&closed, &zc, 1_000_000)).contains("closed"));
        // A price so high the order rounds below 1 ZCRYPT is refused.
        let pricey = Quote { price_sats: 1_000_000_000, min_sats: 1, ..q };
        assert!(err(validate_order(&pricey, &zc, 10)).contains("too small"));
    }

    fn order() -> Order {
        Order {
            id: "ab".repeat(16),
            zc_address: "zc1x".into(),
            btc_index: 7,
            btc_address: "bc1qx".into(),
            sats: 1_000_000,
            price_sats: 2_500,
            created: 1_000,
            expires: 1_000 + 86_400,
            status: OrderStatus::Waiting,
            paid_sats: 0,
            confirmations: 0,
            zcrypt_atomic: 0,
            zc_txhash: String::new(),
        }
    }

    #[test]
    fn lifecycle_waiting_seen_paid() {
        let mut o = order();
        assert_eq!(o.observe(2_000, 0, 0, 1), None);
        assert_eq!(o.status, OrderStatus::Waiting);
        // Mempool payment: seen, not yet payable.
        assert_eq!(o.observe(2_100, 1_000_000, 0, 1), None);
        assert_eq!(o.status, OrderStatus::Seen);
        assert_eq!(o.paid_sats, 1_000_000);
        // First confirmation: payable at the LOCKED price.
        assert_eq!(o.observe(2_700, 1_000_000, 1, 1), Some(400 * ATOMIC));
        o.mark_paid(400 * ATOMIC, "deadbeef".into());
        assert_eq!(o.status, OrderStatus::Paid);
        // Never pays twice.
        assert_eq!(o.observe(3_000, 1_000_000, 6, 1), None);
        assert!(!o.needs_watch(3_000, 86_400));
    }

    #[test]
    fn zero_conf_pays_on_sight() {
        let mut o = order();
        assert_eq!(o.observe(2_100, 250_000, 0, 0), Some(100 * ATOMIC));
    }

    #[test]
    fn expiry_and_late_payment() {
        let mut o = order();
        let ttl = 86_400;
        assert_eq!(o.observe(o.expires, 0, 0, 1), None);
        assert_eq!(o.status, OrderStatus::Expired);
        // Still watched for one more TTL, then dropped.
        assert!(o.needs_watch(o.expires + 10, ttl));
        assert!(!o.needs_watch(o.expires + ttl + 1, ttl));
        // A late payment is honoured.
        assert_eq!(o.observe(o.expires + 100, 1_000_000, 2, 1), Some(400 * ATOMIC));
        assert_eq!(o.status, OrderStatus::Seen);
    }

    #[test]
    fn view_hides_the_index_and_address() {
        let o = order();
        let v = o.view(1);
        let j = serde_json::to_string(&v).unwrap();
        assert!(!j.contains("btc_index"));
        assert!(!j.contains("zc_address"));
        assert!(j.contains("\"status\":\"waiting\""));
    }

    #[test]
    fn coin_selection_and_stock() {
        let coins = [(5 * ATOMIC, false), (50 * ATOMIC, true), (20 * ATOMIC, false), (ATOMIC, false)];
        assert_eq!(select_inputs(&coins, 24 * ATOMIC, 2), Some(vec![2, 0]));
        assert_eq!(select_inputs(&coins, 20 * ATOMIC, 2), Some(vec![2]));
        assert_eq!(select_inputs(&coins, 26 * ATOMIC, 2), None); // spent coin not usable, 3rd coin not allowed
        assert_eq!(stock(&coins, 2), 25 * ATOMIC - MIN_FEE);
        assert_eq!(stock(&[], 2), 0);
    }

    #[test]
    fn http_head_parses() {
        let (r, len) = parse_http_head("POST /order HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n").unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/order");
        assert_eq!(len, 12);
        assert!(parse_http_head("GET noslash HTTP/1.1\r\n").is_err());
        assert!(parse_http_head("POST / HTTP/1.1\r\nContent-Length: 999999999\r\n").is_err());
        let resp = String::from_utf8(http_response(404, "{}")).unwrap();
        assert!(resp.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(resp.ends_with("\r\n\r\n{}"));
    }
}
