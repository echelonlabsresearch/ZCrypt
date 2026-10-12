//! The bridge operator's always-on WATCHER DAEMON. It settles the public bridge autonomously:
//! sweeps shield deposits into the reserve, re-anchors deposits a Bitcoin reorg moved, locks
//! reserve BTC for redeems (persisting every funding intent before broadcast), finalizes each
//! redeem when the user claims, and refunds locks the user never claimed once their CLTV
//! passes. All idempotent and resumable via a persisted state file.
//!
//! Config (env):
//!   ZC_URL                  ZCrypt CometBFT RPC              (default http://localhost:36657)
//!   BTC_URL/USER/PASS       bitcoind RPC. Plain HTTP + basic auth, so outside regtest the
//!                           URL must be loopback, a private/VPN address, a single-label
//!                           host, or https:// (ZCRYPT_BTC_RPC_ALLOW_PUBLIC=1 overrides).
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
//!                           network redeem window (mainnet 475200, what the compose ships).
//!                           A value BELOW the default is refused unless
//!                           ZCRYPT_WATCHER_ALLOW_LOW_MARGIN=1 (it thins the safety slack);
//!                           it always floors at the network minimum. The BTC lock the
//!                           daemon funds is derived to expire before the escrow, with slack.
//!   WATCHER_FEE_TARGET      claim fee confirmation target   (default 1 = aggressive)
//!   ZCRYPT_CHAIN_ID         chain id to bind txs to         (default zcrypt-1)
//!
//!   bridge_watcher --print-reserve-pk   print the 33-byte compressed reserve pubkey (hex)
//!                                       for the configured key and exit (no daemon start).
//!
//! At startup the daemon checks that its reserve key is the one the chain registered zBTC
//! against and refuses to run otherwise (with the wrong key nothing would ever be swept).
//! The legacy ZCRYPT_RESERVE_SEED environment variable is refused.
//!
//! NOTE: the reserve key is a HOT key here (single secp256k1). For mainnet, front it with
//! threshold/HSM custody and keep only a low hot float (see the launch runbook). The daemon
//! never prints or logs the secret, only its pubkey.

use std::path::PathBuf;
use std::time::Duration;

use zcrypt_bridge::watcher::{
    btc_rpc_url_policy, finalize_margin_policy, previous_reserve_keys_from_env, reserve_key_from_env, watcher_tick_persisting, WatcherState,
};
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
    // Keys retired by `rotate_reserve` that still have deposits to sweep / redeems to refund.
    let previous = match previous_reserve_keys_from_env() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[bridge-watcher] {e}");
            std::process::exit(2);
        }
    };
    let keys = swap::ReserveKeys { current: &reserve, previous: &previous };

    let zc = Zcrypt::new(&env("ZC_URL", "http://localhost:36657"));
    let btc_url = env("BTC_URL", "http://localhost:18443");
    let net = zcrypt_bridge::network_from_str(&env("BTC_NETWORK", "regtest"));
    // Startup invariant: the bitcoind RPC is plaintext, so on a real network it must be
    // reached over a private link (see `btc_rpc_url_policy`).
    let allow_public = matches!(env("ZCRYPT_BTC_RPC_ALLOW_PUBLIC", "0").trim(), "1" | "true" | "yes");
    if let Err(e) = btc_rpc_url_policy(net, &btc_url, allow_public) {
        eprintln!("[bridge-watcher] {e}");
        std::process::exit(2);
    }
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
    // Startup invariant (bridge N10): this key must be the chain's zBTC reserve authority.
    if let Err(e) = swap::assert_reserve_matches_chain(&zc, asset, &reserve) {
        eprintln!("[bridge-watcher] {e}");
        std::process::exit(2);
    }
    let state_path = PathBuf::from(env("WATCHER_STATE", "bridge-watcher-state.json"));
    let poll = Duration::from_secs(env("WATCHER_POLL_SECS", "10").parse().unwrap_or(10));
    let requested: Option<u64> = std::env::var("WATCHER_FINALIZE_MARGIN").ok().and_then(|s| s.trim().parse().ok());
    let allow_low = matches!(env("ZCRYPT_WATCHER_ALLOW_LOW_MARGIN", "0").trim(), "1" | "true" | "yes");
    // Startup invariant (bridge H1 / N9): a margin below the network default is refused unless
    // explicitly allowed; the network floor (claim window + slack) always holds.
    let margin: u64 = match finalize_margin_policy(net, requested, allow_low) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[bridge-watcher] {e}");
            std::process::exit(2);
        }
    };
    if allow_low && margin < swap::default_finalize_margin(net) {
        eprintln!("[bridge-watcher] WARNING: running with a finalize margin of {margin} ZC blocks, below the {net:?} default {} (ZCRYPT_WATCHER_ALLOW_LOW_MARGIN=1)", swap::default_finalize_margin(net));
    }
    let min_lock_secs = swap::min_user_claim_blocks(net) * swap::BTC_BLOCK_TIME_SECS + swap::redeem_slack_secs(net, swap::min_user_claim_blocks(net));
    assert!(margin * swap::ZC_BLOCK_TIME_SECS >= min_lock_secs, "margin below the network floor (policy bug)");
    let fee_target: u32 = env("WATCHER_FEE_TARGET", "1").parse().unwrap_or(1);

    eprintln!(
        "[bridge-watcher] zBTC asset {asset}, reserve pubkey {reserve_pk_hex} (+{} retired), state {}, poll {}s, finalize margin {margin} ZC blocks",
        previous.len(),
        state_path.display(),
        poll.as_secs()
    );

    // A present but unparseable state file is fatal (bridge N12): never restart from empty.
    let mut state = match WatcherState::load(&state_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bridge-watcher] {e}");
            std::process::exit(2);
        }
    };
    let persist = |st: &WatcherState| st.save(&state_path);
    loop {
        match watcher_tick_persisting(&mut state, &zc, &operator_btc, &keys, &shield_dest, asset, margin, fee_target, &persist) {
            Ok(r) => {
                if r.swept + r.locked + r.finalized + r.refunded + r.reanchored + r.resumed + r.deferred + r.at_risk + r.critical + r.rejected > 0
                    || r.pause_new_shields
                    || !r.errors.is_empty()
                {
                    eprintln!(
                        "[bridge-watcher] cursor={} swept={} locked={} finalized={} refunded={} reanchored={} resumed={} deferred={} at_risk={} critical={} pause_shields={} rejected={} errors={}",
                        state.cursor, r.swept, r.locked, r.finalized, r.refunded, r.reanchored, r.resumed, r.deferred, r.at_risk, r.critical,
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
