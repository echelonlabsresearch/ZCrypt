//! Watch the FOUNDATION VESTING schedule execute on a LIVE chain, accelerated.
//!
//! Run the 3-node stack with the devnet accel (cliff at block ~120, one vesting
//! "month" every ~10 blocks, fully vested by block ~480):
//!
//!   ZCRYPT_VESTING_ACCEL=259200 docker compose -f docker-compose.3node.yml up -d
//!   cargo run --release -p zcrypt-bridge --bin foundation_flow_3node
//!
//! The driver proves, over real RPC against real consensus:
//!   1. the genesis-liquid 50k tranche claims into a coin (and no more than that);
//!   2. nothing further is claimable until the cliff block, then exactly 25%;
//!   3. each accelerated "month" unlocks exactly 87,500 ZCRYPT;
//!   4. a claimed tranche is real, private money: it is SPENT in a 0x55 shield
//!      transfer a recipient can decrypt, and double-spending it is rejected.

use zcrypt_bridge::swap;
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_core::emission;
use zcrypt_core::keys::{self, Account};
use zcrypt_core::kem;
use zcrypt_shield::PubKey;

const ATOMIC: u64 = emission::ATOMIC;

fn pk_hex(pk: &PubKey) -> String {
    let mut b = Vec::with_capacity(64);
    for x in pk {
        b.extend_from_slice(&x.to_le_bytes());
    }
    hex::encode(b)
}

fn staking_u64(zc: &Zcrypt, path: &str) -> u64 {
    zc.query(path).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

fn claim_tx(pk: &PubKey, amount: u64) -> Vec<u8> {
    let mut t = vec![0x58u8];
    for x in pk {
        t.extend_from_slice(&x.to_le_bytes());
    }
    t.extend_from_slice(&amount.to_le_bytes());
    t
}

/// Poll until the foundation's claimable balance equals `expect` (atomic units).
/// Returns the height at which it was first observed.
fn wait_claimable(zc: &Zcrypt, expect: u64, max_secs: u64) -> i64 {
    for _ in 0..max_secs {
        let c = staking_u64(zc, "/staking/foundation_claimable");
        if c == expect {
            return zc.height().unwrap_or(0);
        }
        assert!(c < expect, "claimable {c} overshot expected {expect} — schedule wrong");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("claimable never reached {expect} within {max_secs}s");
}

/// Claim `amount` for the foundation and return the reconstructed coin.
fn claim(zc: &Zcrypt, f: &Account, amount: u64) -> keys::Coin {
    let idx = staking_u64(zc, &format!("/staking/claim_index/{}", pk_hex(&f.pubkey())));
    zc.broadcast(&claim_tx(&f.pubkey(), amount)).expect("CLAIM accepted");
    f.reward_coin(amount, idx)
}

fn zcry(v: u64) -> String {
    format!("{:.3} ZCRYPT", v as f64 / ATOMIC as f64)
}

fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:46657".to_string());
    let zc = Zcrypt::new(&url);
    let foundation = Account::from_seed([0xF0; 32]);
    let (community, _mn) = keys::new_account();

    let vested = || staking_u64(&zc, "/staking/foundation_vested");
    let claimable = || staking_u64(&zc, "/staking/foundation_claimable");
    let issued = || staking_u64(&zc, "/staking/issued");

    // ---- 1. Genesis-liquid tranche ----
    let h = wait_claimable(&zc, emission::FOUNDATION_LIQUID, 60);
    println!("[1] height {h}: claimable = {} (the genesis-liquid tranche)", zcry(claimable()));
    let liquid_coin = claim(&zc, &foundation, emission::FOUNDATION_LIQUID);
    let h = wait_claimable(&zc, 0, 30);
    println!("[1] height {h}: liquid tranche claimed into coin; claimable = 0, issued = {}", zcry(issued()));
    // Over-claim while locked must be rejected outright.
    assert!(zc.broadcast(&claim_tx(&foundation.pubkey(), 1)).is_err(), "locked tranche must not claim");
    println!("[1] claiming 1 atomic unit ahead of schedule: REJECTED (as it must be)");

    // ---- 2. The cliff ----
    let cliff_unlock = emission::VESTING_CLIFF_AMOUNT - emission::FOUNDATION_LIQUID;
    println!("[2] waiting for the cliff (expect {} to unlock)...", zcry(cliff_unlock));
    let h_cliff = wait_claimable(&zc, cliff_unlock, 600);
    println!(
        "[2] height {h_cliff}: CLIFF — vested jumped to {} (25% cumulative), claimable = {}",
        zcry(vested()),
        zcry(claimable())
    );
    let cliff_coin = claim(&zc, &foundation, cliff_unlock);
    wait_claimable(&zc, 0, 30);
    println!("[2] cliff tranche claimed into one coin ({})", zcry(cliff_coin.value));

    // ---- 3. One accelerated "month" ----
    println!("[3] waiting for the next monthly unlock (expect {})...", zcry(emission::VESTING_MONTHLY));
    let h_month = wait_claimable(&zc, emission::VESTING_MONTHLY, 600);
    println!(
        "[3] height {h_month}: month tick after {} blocks — claimable = {}",
        h_month - h_cliff,
        zcry(claimable())
    );
    let month_coin = claim(&zc, &foundation, emission::VESTING_MONTHLY);
    wait_claimable(&zc, 0, 30);
    println!("[3] monthly tranche claimed ({}); issued = {}", zcry(month_coin.value), zcry(issued()));

    // ---- 4. Spend a claimed tranche: real, private, double-spend-proof money ----
    let pay_amt = 1_000 * ATOMIC;
    let b0 = keys::random_blind();
    let b1 = keys::random_blind();
    let (out_pay, note_pay) = (
        keys::out_coin(&community.normal_address(), pay_amt, b0),
        kem::ciphertext_to_bytes(&keys::encrypt_note(&community.normal_address(), pay_amt, b0)),
    );
    let change = cliff_coin.value - pay_amt;
    let (out_chg, note_chg) = (
        keys::out_coin(&foundation.normal_address(), change, b1),
        kem::ciphertext_to_bytes(&keys::encrypt_note(&foundation.normal_address(), change, b1)),
    );
    let h_before = zc.height().unwrap_or(1);
    let tx = swap::build_transfer(
        &zc,
        &[cliff_coin.clone()],
        &[out_pay, out_chg],
        vec![note_pay, note_chg],
        &foundation,
        &liquid_coin, // 50k liquid coin pays the ZCRYPT gas; change returns to the foundation
    )
    .expect("build shield transfer from claimed tranche");
    zc.broadcast(&tx).expect("claimed tranche is spendable in a 0x55 shield transfer");
    println!("[4] spent the cliff tranche: {} to a community account (+change), gas burned", zcry(pay_amt));

    // The recipient trial-decrypts the note like any wallet.
    let h_after = zc.height().unwrap_or(h_before) + 2;
    let mut received = None;
    for _ in 0..20 {
        for h in h_before..=zc.height().unwrap_or(h_after) {
            for raw in zc.block_txs(h).unwrap_or_default() {
                if raw.first() != Some(&0x55) {
                    continue;
                }
                if let Some((gas_tx, main_tx)) = swap::parse_transfer_payload(&raw[1..]) {
                    for stx in [&main_tx, &gas_tx] {
                        for n in &stx.enc_notes {
                            if let Some(ct) = kem::ciphertext_from_bytes(n) {
                                if let Some(coin) = community.receive(&ct) {
                                    received = Some(coin);
                                }
                            }
                        }
                    }
                }
            }
        }
        if received.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let got = received.expect("community account receives the payment");
    assert_eq!(got.value, pay_amt);
    println!("[4] community account decrypted its note: received {}", zcry(got.value));

    // Double-spend: a fresh transfer from the SAME claimed coin must be rejected.
    let b2 = keys::random_blind();
    let (o2, n2) = (
        keys::out_coin(&community.normal_address(), pay_amt, b2),
        kem::ciphertext_to_bytes(&keys::encrypt_note(&community.normal_address(), pay_amt, b2)),
    );
    let (o3, n3) = (
        keys::out_coin(&foundation.normal_address(), change, b2),
        kem::ciphertext_to_bytes(&keys::encrypt_note(&foundation.normal_address(), change, b2)),
    );
    match swap::build_transfer(&zc, &[cliff_coin], &[o2, o3], vec![n2, n3], &foundation, &month_coin) {
        Ok(tx2) => assert!(zc.broadcast(&tx2).is_err(), "double-spend of a claimed tranche must be rejected"),
        Err(_) => {} // building can also legitimately fail once the coin's nullifier is spent
    }
    println!("[4] double-spending the same tranche: REJECTED");

    println!(
        "\n[ok] vesting observed live: liquid 50k -> cliff 25% at height {h_cliff} -> +87.5k/month \
         (tick every {} blocks) -> claimed coins spent privately; issued = {}, claimed = {}",
        h_month - h_cliff,
        zcry(issued()),
        zcry(staking_u64(&zc, "/staking/foundation_claimed"))
    );
}
