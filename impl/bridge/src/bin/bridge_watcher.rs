//! The bridge operator's always-on WATCHER DAEMON. It settles the public bridge autonomously:
//! sweeps shield deposits into the reserve, re-anchors deposits a Bitcoin reorg moved, locks
//! reserve BTC for redeems (persisting every funding intent before broadcast), finalizes each
//! redeem when the user claims, and refunds locks the user never claimed once their CLTV
//! passes. All idempotent and resumable via a persisted state file.
//!
//! Config (env):
//!   ZC_URL                  ZCrypt CometBFT RPC              (default http://localhost:36657)
//!   BTC_URL/USER/PASS       bitcoind RPC                    (regtest/dev backend)
//!   BTC_WALLET              operator payout wallet          (default "operator")
//!   BTC_NETWORK             regtest|signet|testnet|bitcoin  (default regtest)
//!   ZCRYPT_RESERVE_KEY_FILE file with the DERIVED 32-byte reserve key (64 hex or raw). This
//!                           is H("BTCBRDG", wallet_seed), exactly what the desktop wallet's
//!                           bridge_init derives; its pubkey is the chain's zbtc_reserve_pk.
//!                           PREFERRED: mount as a docker secret / 0400 file.
//!   ZCRYPT_RESERVE_WALLET_SEED_FILE  file with the operator WALLET seed; the daemon derives
//!                           the reserve key with the same rule. Discouraged (that seed also
//!                           spends the operator's shielded coins).
//!   ZCRYPT_RESERVE_SEED     legacy: the DERIVED key as 64 hex in the environment.
//!   WATCHER_STATE           state file path                 (default ./bridge-watcher-state.json)
//!   WATCHER_POLL_SECS       seconds between passes          (default 10)
//!   WATCHER_FINALIZE_MARGIN ZCrypt blocks a redeem escrow must have left. Default: the
//!                           network redeem window (mainnet 475200, what the compose ships);
//!                           floors at the network minimum (user claim window + finalize
//!                           SLA). The BTC lock the daemon funds is always derived to expire
//!                           before the escrow, whatever the margin.
//!   WATCHER_FEE_TARGET      claim fee confirmation target   (default 1 = aggressive)
//!
//!   bridge_watcher --print-reserve-pk   print the 33-byte compressed reserve pubkey (hex)
//!                                       for the configured key and exit (no daemon start).
//!
//! NOTE: the reserve key is a HOT key here (single secp256k1). For mainnet, front it with
//! threshold/HSM custody and keep only a low hot float — see the launch runbook. The daemon
//! never prints or logs the secret, only its pubkey.

use std::path::PathBuf;
use std::time::Duration;

use zcrypt_bridge::watcher::{reserve_key_from_env, watcher_tick_persisting, WatcherState};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{swap, Btc};

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn main() {
    // The reserve key controls all bridged BTC — required, never defaulted, never printed.
    let reserve = match reserve_key_from_env() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[bridge-watcher] {e}");
            std::process::exit(2);
        }
    };
    let reserve_pk_hex = hex::encode(reserve.pk.inner.serialize());
    if std::env::args().any(|a| a == "--print-reserve-pk") {
        println!("{reserve_pk_hex}");
        return;
    }

    let zc = Zcrypt::new(&env("ZC_URL", "http://localhost:36657"));
    let btc_url = env("BTC_URL", "http://localhost:18443");
    let net = zcrypt_bridge::network_from_str(&env("BTC_NETWORK", "regtest"));
    let wallet = env("BTC_WALLET", "operator");
    let _ = Btc::ensure_wallet(&btc_url, &env("BTC_USER", "zcrypt"), &env("BTC_PASS", "zcrypt"), &wallet);
    let operator_btc = Btc::connect(&btc_url, &env("BTC_USER", "zcrypt"), &env("BTC_PASS", "zcrypt"), &wallet, net)
        .expect("connect bitcoind");
    let shield_dest = operator_btc.new_address().expect("operator payout address");

    // zBTC is bound at genesis; a chain without it cannot be served.
    let asset: u64 = match swap::ensure_zbtc_registered(&zc) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[bridge-watcher] {e}");
            std::process::exit(2);
        }
    };
    let state_path = PathBuf::from(env("WATCHER_STATE", "bridge-watcher-state.json"));
    let poll = Duration::from_secs(env("WATCHER_POLL_SECS", "10").parse().unwrap_or(10));
    let floor = swap::min_redeem_margin_blocks(net);
    let margin: u64 = std::env::var("WATCHER_FINALIZE_MARGIN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| swap::default_finalize_margin(net))
        .max(floor);
    let fee_target: u32 = env("WATCHER_FEE_TARGET", "1").parse().unwrap_or(1);
    // Startup invariant (bridge H1): the lock the daemon funds plus the finalize SLA fits
    // inside the minimum escrow life it will accept.
    let min_lock_secs = swap::min_user_claim_blocks(net) * swap::BTC_BLOCK_TIME_SECS + swap::redeem_finalize_sla_secs(net);
    assert!(
        margin * swap::ZC_BLOCK_TIME_SECS >= min_lock_secs,
        "WATCHER_FINALIZE_MARGIN {margin} blocks is below the {net:?} floor of {floor}"
    );

    eprintln!(
        "[bridge-watcher] zBTC asset {asset}, reserve pubkey {reserve_pk_hex}, state {}, poll {}s, finalize margin {margin} ZC blocks",
        state_path.display(),
        poll.as_secs()
    );

    let mut state = WatcherState::load(&state_path);
    let persist = |st: &WatcherState| st.save(&state_path);
    loop {
        match watcher_tick_persisting(&mut state, &zc, &operator_btc, &reserve, &shield_dest, asset, margin, fee_target, &persist) {
            Ok(r) => {
                if r.swept + r.locked + r.finalized + r.refunded + r.reanchored + r.resumed + r.at_risk + r.critical + r.rejected > 0
                    || r.pause_new_shields
                    || !r.errors.is_empty()
                {
                    eprintln!(
                        "[bridge-watcher] cursor={} swept={} locked={} finalized={} refunded={} reanchored={} resumed={} at_risk={} critical={} pause_shields={} rejected={} errors={}",
                        state.cursor, r.swept, r.locked, r.finalized, r.refunded, r.reanchored, r.resumed, r.at_risk, r.critical,
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
