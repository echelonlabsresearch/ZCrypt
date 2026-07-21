//! Print the reward keys for a deterministic account, for the live claim demo:
//!   * `pk`             — 64-byte shield pubkey (8×u64 LE), used in the claim tx
//!   * `reward_address` — 32-byte hash of pk, used as the validator's bond target
//!
//! Run: `cargo run -p zcrypt-core --example reward_keys`

use zcrypt_core::keys::Account;

fn main() {
    let account = Account::from_seed([0x11; 32]);
    let pk = account.pubkey();
    let mut pk_bytes = Vec::with_capacity(64);
    for limb in &pk {
        pk_bytes.extend_from_slice(&limb.to_le_bytes());
    }
    println!("pk_hex={}", hex::encode(&pk_bytes));
    println!("reward_address_hex={}", hex::encode(account.reward_address()));

    // Reconstruct a reward coin at (value, index) given as args (default 14 ZCRYPT = one epoch,
    // index 0) and print its commitment — this must equal the coinbase commitment
    // the node minted, proving the owner can rebuild (and spend) the exact coin.
    let args: Vec<String> = std::env::args().collect();
    let value: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(14_000_000);
    let index: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    let coin = account.reward_coin(value, index);
    let c = coin.commitment();
    let mut cb = Vec::with_capacity(64);
    for x in &c {
        cb.extend_from_slice(&x.to_le_bytes());
    }
    println!("reward_coin_0_commitment={}", hex::encode(cb));
}
