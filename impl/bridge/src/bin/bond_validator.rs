//! Bond a CometBFT validator into the ACTIVE producing set, and STAY bonded.
//!
//! Unlike `product_flow_3node` (a demo that bonds then unbonds), this does the bond
//! only: it pledges >= 10,000 ZCRYPT into a burn coin and broadcasts a BOND (tag 0x57)
//! signed by the validator's ed25519 consensus key. On the next block the app emits a
//! CometBFT ValidatorUpdate and the node joins the active set, earning block rewards to
//! the reward address you choose (point it at your wallet).
//!
//!   VALIDATOR_SEED_HEX=<64 hex>            # first 32 bytes of priv_validator_key.json
//!   ZCRYPT_REWARD_ADDR=<64 hex>            # your wallet's reward address, OR:
//!   ZCRYPT_REWARD_MNEMONIC="word word ..." # derive the reward address from a wallet phrase
//!   cargo run --release -p zcrypt-bridge --bin bond_validator -- http://localhost:56657 [stake_whole_zcrypt]
//!
//! Devnet only for the STAKE FUNDING: the stake coin is minted via SEED (0x56), which a
//! production (non-devnet) node rejects — there you must instead pledge a coin your
//! wallet already holds (a wallet "Bond" flow is the follow-up for that).

use zcrypt_bridge::swap::{self, build_shield_spend};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_core::keys::{self, Account};
use zcrypt_core::{emission, htlc_shield, kem, shield_tx};
use zcrypt_shield::{Blind, OutCoin};

/// Build a coin-backed BOND (tag 0x57): authenticated header (pubkey/stake/reward/sig),
/// then `stake_blind` and the `pledge` shield tx whose output[0] burns exactly `stake`.
fn bond_tx(
    sk: &ed25519_dalek::SigningKey,
    stake: u64,
    reward: [u8; 32],
    commission: u16,
    stake_blind: Blind,
    nonce: u64,
    pledge: &shield_tx::ShieldTx,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let pk = sk.verifying_key().to_bytes();
    let mut msg = Vec::new();
    msg.extend_from_slice(b"ZCRYPT-BOND-v1");
    msg.extend_from_slice(swap::CHAIN);
    msg.extend_from_slice(&pk);
    msg.extend_from_slice(&stake.to_le_bytes());
    msg.extend_from_slice(&reward);
    msg.extend_from_slice(&commission.to_le_bytes());
    msg.extend_from_slice(&nonce.to_le_bytes()); // replay-protection nonce
    let sig = sk.sign(&msg);
    let mut t = vec![0x57u8];
    t.extend_from_slice(&pk);
    t.extend_from_slice(&stake.to_le_bytes());
    t.extend_from_slice(&reward);
    t.extend_from_slice(&commission.to_le_bytes());
    t.extend_from_slice(&nonce.to_le_bytes());
    t.extend_from_slice(&sig.to_bytes());
    for limb in stake_blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&shield_tx::to_bytes(pledge));
    t
}

fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:46657".to_string());
    let stake: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse::<u64>().ok())
        .map(|whole| whole * emission::ATOMIC)
        .unwrap_or(10_000 * emission::ATOMIC);
    if stake < 10_000 * emission::ATOMIC {
        eprintln!("stake must be >= 10000 ZCRYPT (MIN_STAKE)");
        std::process::exit(1);
    }
    let zc = Zcrypt::new(&url);

    // 1. Validator consensus key (the identity CometBFT signs blocks with).
    let hexseed = std::env::var("VALIDATOR_SEED_HEX")
        .expect("set VALIDATOR_SEED_HEX (first 32 bytes of priv_validator_key.json, hex)");
    let raw = hex::decode(hexseed.trim()).expect("VALIDATOR_SEED_HEX: invalid hex");
    let seed32: [u8; 32] = raw[..32].try_into().expect("VALIDATOR_SEED_HEX: need >= 32 bytes");
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed32);
    let val_pk = sk.verifying_key();
    // The /staking/validators set is keyed by the ed25519 consensus pubkey (32B) hex.
    let val_pk_hex = hex::encode(val_pk.to_bytes());

    // 2. Reward address — where block rewards accrue. Point it at YOUR wallet, either by
    //    its reward address (hex) or by deriving it from your wallet recovery phrase.
    let reward: [u8; 32] = if let Ok(h) = std::env::var("ZCRYPT_REWARD_ADDR") {
        if !h.trim().is_empty() {
            hex::decode(h.trim())
                .expect("ZCRYPT_REWARD_ADDR: invalid hex")
                .try_into()
                .expect("ZCRYPT_REWARD_ADDR must be 64 hex chars (32 bytes)")
        } else {
            reward_from_mnemonic()
        }
    } else {
        reward_from_mnemonic()
    };

    // 3. Idempotency: if this consensus key is already in the active set, stop.
    let already = zc
        .query("/staking/validators")
        .unwrap_or_default()
        .contains(&val_pk_hex);
    if already {
        println!("already bonded: consensus key {} is in the active set", val_pk_hex);
        return;
    }

    // 4. Fund the stake (devnet SEED) and PLEDGE it: spend the funded coin into a burn
    //    coin of exactly `stake` (output[0]), tiny change back (output[1]). Bonding is
    //    gasless — the pledge burns only the stake (fee 0).
    let funder = Account::from_seed([0xBD; 32]); // throwaway; only produces the burned coin
    // The pledge now pays MIN_FEE (M2), so fund covers stake + fee + change.
    let fund = funder.own_coin(stake + emission::MIN_FEE + 100, keys::random_blind());
    if let Err(e) = zc.broadcast(&swap::seed_tx(&fund.commitment())) {
        if !e.contains("already") {
            panic!(
                "could not fund the stake via SEED ({e}). SEED (0x56) is devnet-only; on a \
                 production node bond a coin your wallet already holds instead."
            );
        }
    }
    let stake_blind = keys::random_blind();
    let burn_out: OutCoin = (stake, stake_blind, htlc_shield::BURN_PK, 0);
    let cblind = keys::random_blind();
    let change_out = keys::out_coin(&funder.normal_address(), 100, cblind);
    let cnote = kem::ciphertext_to_bytes(&keys::encrypt_note(&funder.normal_address(), 100, cblind));
    let pledge = build_shield_spend(&zc, &[fund], &[burn_out, change_out], emission::MIN_FEE, vec![vec![], cnote])
        .expect("build the stake pledge");

    // 5. Broadcast the BOND (no unbond — this validator stays in the set).
    // Commission the validator keeps on delegators' rewards (basis points; env
    // COMMISSION_BPS, default 10% = 1000). Validators compete on this.
    let commission: u16 = std::env::var("COMMISSION_BPS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(zcrypt_core::staking::DEFAULT_COMMISSION_BPS);
    // BOND carries the signer's monotonic auth nonce (M3); query the current value.
    let bond_nonce: u64 = zc
        .query(&format!("/staking/auth_nonce/{}", hex::encode(val_pk.to_bytes())))
        .ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    zc.broadcast(&bond_tx(&sk, stake, reward, commission, stake_blind, bond_nonce, &pledge))
        .expect("BOND rejected");
    println!(
        "BOND accepted: pledged {} ZCRYPT, rewards -> {}",
        stake / emission::ATOMIC,
        hex::encode(reward)
    );

    // 6. Confirm the ValidatorUpdate landed (the node is now an active producer).
    for _ in 0..30 {
        if zc.query("/staking/validators").unwrap_or_default().contains(&val_pk_hex) {
            println!("validator is now ACTIVE in the staking set (consensus key {})", val_pk_hex);
            println!("it will start producing blocks and earning rewards to the reward address above.");
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    println!("BOND broadcast, but the validator did not appear in /staking/validators yet — check the node logs.");
}

/// Derive the reward address from a wallet recovery phrase (ZCRYPT_REWARD_MNEMONIC). The
/// phrase never leaves this process and is used only to compute the PUBLIC reward address.
fn reward_from_mnemonic() -> [u8; 32] {
    let m = std::env::var("ZCRYPT_REWARD_MNEMONIC").unwrap_or_default();
    if m.trim().is_empty() {
        eprintln!("set ZCRYPT_REWARD_ADDR (64 hex) or ZCRYPT_REWARD_MNEMONIC (your wallet phrase)");
        std::process::exit(1);
    }
    let acct = Account::from_mnemonic(m.trim(), "").expect("invalid ZCRYPT_REWARD_MNEMONIC");
    acct.reward_address()
}
