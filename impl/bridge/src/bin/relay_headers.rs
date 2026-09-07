//! Relay the latest Bitcoin block headers from bitcoind to the ZCrypt node, advancing the
//! node's consensus SPV header chain. This is what lets a freshly-shielded (immature) zBTC
//! deposit MATURE: the deposit becomes spendable once its Bitcoin block is buried
//! `maturity_for(value)` deep on the node's best header chain. The wallet's Bridge tab does
//! this automatically every 15s, but this standalone relayer covers devnet/regtest when the
//! wallet isn't open, and doubles as an operator header-relayer.
//!
//!   cargo run -p zcrypt-bridge --bin relay_headers -- [node_rpc] [btc_url] [user] [pass] [wallet]
//!   defaults:                     http://localhost:36657  http://localhost:18443  zcrypt zcrypt demo
use zcrypt_bridge::swap;
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::Btc;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let node = a.get(1).cloned().unwrap_or_else(|| "http://localhost:36657".into());
    let btc_url = a.get(2).cloned().unwrap_or_else(|| "http://localhost:18443".into());
    let user = a.get(3).cloned().unwrap_or_else(|| "zcrypt".into());
    let pass = a.get(4).cloned().unwrap_or_else(|| "zcrypt".into());
    let wallet = a.get(5).cloned().unwrap_or_else(|| "demo".into());

    let zc = Zcrypt::new(&node);
    let btc = Btc::connect(&btc_url, &user, &pass, &wallet, zcrypt_bridge::NETWORK)
        .expect("connect to bitcoind");
    let before: String = zc.query("/spv/height").unwrap_or_default();
    match swap::relay_btc_headers(&zc, &btc) {
        Ok(tip) => println!("relayed headers: node SPV {} -> {}", before.trim(), tip),
        Err(e) => {
            eprintln!("relay failed: {e}");
            std::process::exit(1);
        }
    }
}
