//! Live 3-node test of the DELEGATE + BRIDGE-FEE value-capture path. A validator bonds
//! (at a chosen commission), a delegator delegates to it, a BTC->zBTC bridge mint skims a
//! fee to stakers, and after maturity + an epoch that fee is split — net of the validator's
//! commission — to BOTH the validator and the DELEGATOR, who then CLAIMS its zBTC yield.
//! Proves delegation, per-validator commission, and delegator bridge-fee accrual/claim all
//! work end to end under real multi-node consensus (not just unit tests).
//!
//!   ZC_URL=http://localhost:46657 BTC_URL=http://localhost:28443 \
//!     VALIDATOR_SEED_HEX=<node0 consensus seed> fee_flow_3node

use bitcoin::Amount;
use zcrypt_bridge::swap::{self, BtcParams};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{Btc, Key};
use zcrypt_core::keys::{self, Account};
use zcrypt_core::{kem, shield_tx};
use zcrypt_shield::{Blind, OutCoin};

fn pk_hex(pk: &zcrypt_shield::PubKey) -> String {
    let mut b = Vec::with_capacity(64);
    for x in pk {
        b.extend_from_slice(&x.to_le_bytes());
    }
    hex::encode(b)
}
fn staking_u64(zc: &Zcrypt, path: &str) -> u64 {
    zc.query(path).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}
fn seed(zc: &Zcrypt, c: &[u64; 8]) {
    if let Err(e) = zc.broadcast(&swap::seed_tx(c)) {
        if !e.contains("already") {
            panic!("seed: {e}");
        }
    }
}

/// A coin-backed BOND (0x57) with an explicit commission (basis points).
fn bond_tx(sk: &ed25519_dalek::SigningKey, stake: u64, reward: [u8; 32], commission: u16, blind: Blind, nonce: u64, pledge: &shield_tx::ShieldTx) -> Vec<u8> {
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
    for limb in blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&shield_tx::to_bytes(pledge));
    t
}
/// A coin-backed DELEGATE (0x5F).
fn delegate_tx(sk: &ed25519_dalek::SigningKey, target: &[u8], stake: u64, reward: [u8; 32], blind: Blind, pledge: &shield_tx::ShieldTx) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let pk = sk.verifying_key().to_bytes();
    let mut msg = Vec::new();
    msg.extend_from_slice(b"ZCRYPT-DELEGATE-v1");
    msg.extend_from_slice(swap::CHAIN);
    msg.extend_from_slice(&pk);
    msg.extend_from_slice(target);
    msg.extend_from_slice(&stake.to_le_bytes());
    msg.extend_from_slice(&reward);
    let sig = sk.sign(&msg);
    let mut t = vec![0x5Fu8];
    t.extend_from_slice(&pk);
    t.extend_from_slice(target);
    t.extend_from_slice(&stake.to_le_bytes());
    t.extend_from_slice(&reward);
    t.extend_from_slice(&sig.to_bytes());
    for limb in blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&shield_tx::to_bytes(pledge));
    t
}
/// A bridge-fee claim (0x66): pk(64) ‖ asset(8) ‖ amount(8).
fn claim_fee_tx(pk: &zcrypt_shield::PubKey, asset: u64, amount: u64) -> Vec<u8> {
    let mut t = vec![0x66u8];
    t.extend_from_slice(&hex::decode(pk_hex(pk)).unwrap());
    t.extend_from_slice(&asset.to_le_bytes());
    t.extend_from_slice(&amount.to_le_bytes());
    t
}
/// An UNBOND (0x5E): pubkey(32) ‖ nonce(8) ‖ sig(64), signed over
/// "ZCRYPT-UNBOND-v1" ‖ chain ‖ pubkey ‖ nonce.
fn unbond_tx(sk: &ed25519_dalek::SigningKey, nonce: u64) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let pk = sk.verifying_key().to_bytes();
    let mut msg = Vec::new();
    msg.extend_from_slice(b"ZCRYPT-UNBOND-v1");
    msg.extend_from_slice(swap::CHAIN);
    msg.extend_from_slice(&pk);
    msg.extend_from_slice(&nonce.to_le_bytes());
    let sig = sk.sign(&msg);
    let mut t = vec![0x5Eu8];
    t.extend_from_slice(&pk);
    t.extend_from_slice(&nonce.to_le_bytes());
    t.extend_from_slice(&sig.to_bytes());
    t
}
/// Fund `owner` with a SEED coin and spend it into `[burn(stake -> BURN_PK), change]`.
fn pledge(zc: &Zcrypt, owner: &Account, stake: u64, envelope: &[u8]) -> (shield_tx::ShieldTx, Blind) {
    // The pledge now pays MIN_FEE (M2), so fund covers stake + fee + change.
    let fee = zcrypt_core::emission::MIN_FEE;
    let fund = owner.own_coin(stake + fee + 100, keys::random_blind());
    seed(zc, &fund.commitment());
    let blind = keys::random_blind();
    let burn: OutCoin = (stake, blind, zcrypt_core::htlc_shield::BURN_PK, 0);
    let cblind = keys::random_blind();
    let change = keys::out_coin(&owner.normal_address(), 100, cblind);
    let cnote = kem::ciphertext_to_bytes(&keys::encrypt_note(&owner.normal_address(), 100, cblind));
    let p = swap::build_shield_spend_bound(zc, &[fund], &[burn, change], fee, vec![zcrypt_core::keys::cover_note_bytes(), cnote], envelope).expect("pledge");
    (p, blind)
}

fn main() {
    zcrypt_bridge::zcrypt::set_broadcast_jitter(false); // e2e driver: no privacy delay on hundreds of broadcasts
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:46657".into());
    let btc_url = std::env::var("BTC_URL").unwrap_or_else(|_| "http://localhost:28443".into());
    let seedhex = std::env::var("VALIDATOR_SEED_HEX").expect("set VALIDATOR_SEED_HEX (node0 consensus seed)");
    let raw = hex::decode(seedhex.trim()).expect("VALIDATOR_SEED_HEX hex");
    let sk = ed25519_dalek::SigningKey::from_bytes(&raw[..32].try_into().expect("need >= 32 bytes"));
    let zc = Zcrypt::new(&zc_url);
    println!("== fee-flow (delegate + bridge fee) against chain={zc_url} bitcoind={btc_url} ==");

    // --- register zBTC (SPV form) + set up bitcoind wallets ---
    let _ = Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "demo");
    let btc = Btc::connect(&btc_url, "zcrypt", "zcrypt", "demo", zcrypt_bridge::NETWORK).unwrap();
    let bridge_key = Key::from_bytes(&[0xB1; 32]);
    let reserve_pk: [u8; 33] = bridge_key.pk.inner.serialize();
    // zBTC is bound to this reserve pubkey in GENESIS (ZCRYPT_RESERVE_PK = 0xB1 dev key).
    let asset: u64 = swap::ensure_zbtc_registered(&zc).unwrap_or_else(|e| {
        eprintln!("{e}\n    this driver's reserve pubkey: {}", hex::encode(reserve_pk));
        std::process::exit(2)
    });

    // --- bond node0's validator at 20% commission ---
    let commission: u16 = 2000; // 20% — makes the validator-vs-delegator split visible
    let validator = Account::from_seed([0xC1; 32]);
    let v_reward = keys::reward_address(&validator.pubkey());
    let v_stake = 10_000 * zcrypt_core::emission::ATOMIC;
    // BOND carries the signer's monotonic auth nonce (M3); query the current value.
    let bond_nonce: u64 = zc
        .query(&format!("/staking/auth_nonce/{}", hex::encode(sk.verifying_key().to_bytes())))
        .ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let v_env = zcrypt_core::staking::bond_envelope(&sk.verifying_key().to_bytes(), v_stake, &v_reward, commission, bond_nonce);
    let (vp, vb) = pledge(&zc, &validator, v_stake, &v_env);
    zc.broadcast(&bond_tx(&sk, v_stake, v_reward, commission, vb, bond_nonce, &vp)).expect("BOND accepted");
    println!("[1] BOND accepted (node0 validator @ {}% commission)", commission / 100);

    // --- a delegator pledges 5,000 toward it ---
    let target = {
        use sha2::{Digest, Sha256};
        Sha256::digest(sk.verifying_key().to_bytes())[..20].to_vec()
    };
    let del_sk = ed25519_dalek::SigningKey::from_bytes(&[0xD1; 32]);
    let delegator = Account::from_seed([0xD2; 32]);
    let d_reward = keys::reward_address(&delegator.pubkey());
    let d_stake = 5_000 * zcrypt_core::emission::ATOMIC;
    let d_id = {
        use sha2::{Digest, Sha256};
        Sha256::digest(del_sk.verifying_key().to_bytes())[..20].to_vec()
    };
    let d_env = zcrypt_core::staking::delegate_envelope(&d_id, &target, d_stake, &d_reward);
    let (dp, db) = pledge(&zc, &delegator, d_stake, &d_env);
    zc.broadcast(&delegate_tx(&del_sk, &target, d_stake, d_reward, db, &dp)).expect("DELEGATE accepted");
    println!("[2] DELEGATE accepted (delegator pledged 5,000 ZCRYPT)");

    // --- BTC -> zBTC bridge mint: skims a fee to stakers, held immature until maturity ---
    let alice = Account::from_seed([0x11; 32]);
    let alice_key = Key::from_bytes(&[0xA1; 32]);
    Btc::ensure_wallet(&btc_url, "zcrypt", "zcrypt", "bridge").unwrap();
    let bridge = Btc::connect(&btc_url, "zcrypt", "zcrypt", "bridge", zcrypt_bridge::NETWORK).unwrap();
    if bridge.balance_btc().unwrap_or(0.0) < 10.0 {
        bridge.fund_self(120).unwrap();
    }
    if btc.balance_btc().unwrap_or(0.0) < 1.0 {
        btc.fund_self(120).unwrap();
    }
    let alice_dest = btc.new_address().unwrap();
    let bridge_dest = bridge.new_address().unwrap();
    let b = BtcParams {
        alice: &btc,
        bridge: &bridge,
        bridge_key: &bridge_key,
        alice_key: &alice_key,
        alice_dest: &alice_dest,
        bridge_dest: &bridge_dest,
    };
    let btc_amt = Amount::from_btc(0.5).unwrap();
    let zbtc = btc_amt.to_sat();
    let _coin = swap::btc_to_zbtc(&zc, &b, &alice, asset, &swap::fresh_preimage(), btc_amt, zbtc).unwrap();
    let fee = zcrypt_core::emission::bridge_fee(zbtc);
    println!("[3] zBTC minted; {fee} base-unit bridge fee to stakers (accrues at maturity)");
    swap::wait_for_maturity(&zc, &btc, Some(&|n| btc.mine(n)), 6).expect("zBTC matures + fee accrues");

    // --- after an epoch, the zBTC fee is split to the validator AND the delegator ---
    let d_path = format!("/staking/fees/{}/{}", pk_hex(&delegator.pubkey()), asset);
    let v_path = format!("/staking/fees/{}/{}", pk_hex(&validator.pubkey()), asset);
    let (mut d_fee, mut v_fee) = (0u64, 0u64);
    for _ in 0..180 {
        d_fee = staking_u64(&zc, &d_path);
        v_fee = staking_u64(&zc, &v_path);
        if d_fee > 0 && v_fee > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    assert!(v_fee > 0, "the validator must earn a bridge-fee share");
    assert!(d_fee > 0, "the DELEGATOR must earn a bridge-fee share");
    assert!(v_fee > d_fee, "validator keeps commission + its own stake's share ({v_fee} vs {d_fee})");
    println!("[4] zBTC bridge fee split: validator={v_fee}, delegator={d_fee} (delegator net of {}% commission)", commission / 100);

    // --- the delegator CLAIMS its zBTC yield ---
    zc.broadcast(&claim_fee_tx(&delegator.pubkey(), asset, d_fee)).expect("delegator CLAIM_FEE accepted");
    let mut after = d_fee;
    for _ in 0..30 {
        after = staking_u64(&zc, &d_path);
        if after < d_fee {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert_eq!(after, 0, "claiming should drain the delegator's zBTC fee balance");
    println!("[5] delegator CLAIMED {d_fee} base units of zBTC yield (fee balance -> 0)");

    // Release node0's validator bond (cascading the delegation into the unbonding queue) so the
    // next staking flow (product_flow) can bond node0 fresh — the consensus re-bond guard
    // rejects bonding an already-bonded validator.
    let unbond_nonce: u64 = zc
        .query(&format!("/staking/auth_nonce/{}", hex::encode(sk.verifying_key().to_bytes())))
        .ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    zc.broadcast(&unbond_tx(&sk, unbond_nonce)).expect("UNBOND node0 accepted");
    println!("[6] node0 validator unbonded (released for the next staking flow)");

    println!("\nFEE-FLOW 3-node: delegate + per-validator commission + delegator bridge-fee accrual + claim GREEN");
}
