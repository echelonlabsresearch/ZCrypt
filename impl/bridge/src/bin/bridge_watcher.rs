//! The bridge operator's always-on WATCHER DAEMON. It settles the public bridge autonomously:
//! sweeps shield deposits into the reserve, locks reserve BTC for redeems, and finalizes each
//! redeem when the user claims — all idempotent and resumable via a persisted state file.
//!
//! Config (env):
//!   ZC_URL              ZCrypt CometBFT RPC              (default http://localhost:36657)
//!   BTC_URL/USER/PASS   bitcoind RPC                    (regtest/dev backend)
//!   BTC_WALLET          operator payout wallet          (default "operator")
//!   BTC_NETWORK         regtest|signet|testnet|bitcoin  (default regtest)
//!   ZCRYPT_RESERVE_SEED 64-hex reserve secp256k1 secret (REQUIRED — controls the reserve BTC)
//!   WATCHER_STATE       state file path                 (default ./bridge-watcher-state.json)
//!   WATCHER_POLL_SECS   seconds between passes          (default 10)
//!   WATCHER_FINALIZE_MARGIN  ZCrypt blocks a redeem escrow must have left (default 130000)
//!   WATCHER_FEE_TARGET  claim fee confirmation target   (default 1 = aggressive)
//!
//! NOTE: the reserve key is a HOT key here (single secp256k1). For mainnet, front it with
//! threshold/HSM custody and keep only a low hot float — see the launch runbook.

use std::path::PathBuf;
use std::time::Duration;

use zcrypt_bridge::watcher::{watcher_tick, WatcherState};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{Btc, Key};

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn main() {
    let zc = Zcrypt::new(&env("ZC_URL", "http://localhost:36657"));
    let btc_url = env("BTC_URL", "http://localhost:18443");
    let net = zcrypt_bridge::network_from_str(&env("BTC_NETWORK", "regtest"));
    let wallet = env("BTC_WALLET", "operator");
    let _ = Btc::ensure_wallet(&btc_url, &env("BTC_USER", "zcrypt"), &env("BTC_PASS", "zcrypt"), &wallet);
    let operator_btc = Btc::connect(&btc_url, &env("BTC_USER", "zcrypt"), &env("BTC_PASS", "zcrypt"), &wallet, net)
        .expect("connect bitcoind");

    // The reserve key controls all bridged BTC — required, never defaulted.
    let seed_hex = std::env::var("ZCRYPT_RESERVE_SEED")
        .expect("ZCRYPT_RESERVE_SEED (64 hex) is required — it is the reserve BTC key");
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .expect("ZCRYPT_RESERVE_SEED: invalid hex")
        .try_into()
        .expect("ZCRYPT_RESERVE_SEED must be exactly 32 bytes (64 hex)");
    let reserve = Key::from_bytes(&seed);
    let shield_dest = operator_btc.new_address().expect("operator payout address");

    let asset: u64 = zc
        .query("/asset/by_ticker/zBTC")
        .expect("query zBTC asset")
        .trim()
        .parse()
        .expect("zBTC asset id");
    let state_path = PathBuf::from(env("WATCHER_STATE", "bridge-watcher-state.json"));
    let poll = Duration::from_secs(env("WATCHER_POLL_SECS", "10").parse().unwrap_or(10));
    let margin: u64 = env("WATCHER_FINALIZE_MARGIN", "130000").parse().unwrap_or(130_000);
    let fee_target: u32 = env("WATCHER_FEE_TARGET", "1").parse().unwrap_or(1);

    eprintln!(
        "[bridge-watcher] zBTC asset {asset}, reserve {}, state {}, poll {}s",
        hex::encode(reserve.pk.inner.serialize()),
        state_path.display(),
        poll.as_secs()
    );

    let mut state = WatcherState::load(&state_path);
    loop {
        match watcher_tick(&mut state, &zc, &operator_btc, &reserve, &shield_dest, asset, margin, fee_target) {
            Ok(r) => {
                if r.swept + r.locked + r.finalized + r.at_risk + r.critical + r.rejected > 0
                    || r.pause_new_shields
                    || !r.errors.is_empty()
                {
                    eprintln!(
                        "[bridge-watcher] cursor={} swept={} locked={} finalized={} at_risk={} critical={} pause_shields={} rejected={} errors={}",
                        state.cursor, r.swept, r.locked, r.finalized, r.at_risk, r.critical,
                        r.pause_new_shields, r.rejected, r.errors.len()
                    );
                }
                if r.critical > 0 || r.pause_new_shields {
                    eprintln!(
                        "[bridge-watcher] *** CRITICAL: {} deposit(s) near BTC refund — \
                         PAUSE NEW SHIELDS; sweep immediately ***",
                        r.critical.max(r.at_risk)
                    );
                } else if r.at_risk > 0 {
                    eprintln!(
                        "[bridge-watcher] *** ALERT: {} deposit(s) within soft refund window — PRIORITIZE ***",
                        r.at_risk
                    );
                }
                for e in &r.errors {
                    eprintln!("[bridge-watcher]   non-fatal: {e}");
                }
                if let Err(e) = state.save(&state_path) {
                    eprintln!("[bridge-watcher] WARNING: failed to persist state: {e}");
                }
            }
            Err(e) => eprintln!("[bridge-watcher] tick error (will retry): {e}"),
        }
        std::thread::sleep(poll);
    }
}
