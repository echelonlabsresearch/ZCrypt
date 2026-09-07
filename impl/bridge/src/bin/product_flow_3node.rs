//! Drive the FULL product surface against a LIVE chain over RPC — every flow builds
//! a real tx, broadcasts it, and only "passes" if the node's consensus path accepts
//! (and for shield txs, VERIFIES the ~5 MB proof). Point it at node0 of the 3-node
//! stack to prove the whole product works under real multi-node consensus.
//!
//!   cargo run --release -p zcrypt-bridge --bin product_flow_3node -- http://localhost:46657
//!
//! The bond/reward/unbond flow needs a real validator's ed25519 key; set
//! VALIDATOR_SEED_HEX=<64 hex chars> (the first 32 bytes of a node's
//! priv_validator_key.json) to enable it.

use zcrypt_bridge::swap::{self, build_shield_spend};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_core::keys::{self, Account, BearerCoin, Coin};
use zcrypt_core::{kem, shield_tx};
use zcrypt_shield::{OutCoin, PubKey};

/// Universal-gas minimum fee (0.01 ZCRYPT) — every value-moving action burns at least this.
const FEE: u64 = zcrypt_core::emission::MIN_FEE;

fn seed(zc: &Zcrypt, c: &[u64; 8], what: &str) {
    // A decoy already on chain (duplicate tx from a prior driver in the same run)
    // is fine — still a valid decoy. Only fail on a real rejection.
    if let Err(e) = zc.broadcast(&swap::seed_tx(c)) {
        if !e.contains("already") {
            panic!("seed {what}: {e}");
        }
    }
}


/// (OutCoin, encrypted-note bytes) for a native-ZCRYPT payment to `addr`.
fn pay(addr: &keys::Address, value: u64, blind: [u64; 4]) -> (OutCoin, Vec<u8>) {
    (keys::out_coin(addr, value, blind), kem::ciphertext_to_bytes(&keys::encrypt_note(addr, value, blind)))
}
fn pay_asset(addr: &keys::Address, value: u64, blind: [u64; 4], asset: u64) -> (OutCoin, Vec<u8>) {
    (
        keys::out_asset_coin(addr, value, blind, asset),
        kem::ciphertext_to_bytes(&keys::encrypt_note_asset(addr, value, blind, asset)),
    )
}

/// Scan blocks [from,to] for a coin `who` can receive (trial-decrypt shield notes). A
/// 0x55 transfer bundles a ZCRYPT gas note + the main transfer, so scan both.
fn scan_for(zc: &Zcrypt, who: &Account, from: i64, to: i64) -> Option<Coin> {
    for h in from..=to {
        for raw in zc.block_txs(h).unwrap_or_default() {
            if raw.first() != Some(&0x55) {
                continue;
            }
            if let Some((gas_tx, main_tx)) = swap::parse_transfer_payload(&raw[1..]) {
                for stx in [&main_tx, &gas_tx] {
                    for n in &stx.enc_notes {
                        if let Some(ct) = kem::ciphertext_from_bytes(n) {
                            if let Some(coin) = who.receive(&ct) {
                                return Some(coin);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Seed a fresh `MIN_FEE`-worth ZCRYPT gas coin owned by `owner`, for a transfer's gas
/// note (which burns it entirely). Devnet convenience — a real wallet reuses its change.
fn gas_for(zc: &Zcrypt, owner: &Account) -> Coin {
    let c = owner.own_coin(FEE, keys::random_blind());
    seed(zc, &c.commitment(), "gas");
    c
}

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

/// Build a **coin-backed** BOND: the authenticated header (pubkey/stake/reward/sig)
/// followed by `stake_blind` and the `pledge` shield tx whose output[0] burns exactly
/// `stake` ZCRYPT (proving the stake is genuinely pledged).
fn bond_tx(
    sk: &ed25519_dalek::SigningKey,
    stake: u64,
    reward: [u8; 32],
    stake_blind: zcrypt_shield::Blind,
    nonce: u64,
    pledge: &shield_tx::ShieldTx,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let commission: u16 = zcrypt_core::staking::DEFAULT_COMMISSION_BPS;
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
        t.extend_from_slice(&limb.to_le_bytes()); // stake_blind (4×u64)
    }
    t.extend_from_slice(&shield_tx::to_bytes(pledge));
    t
}
fn unbond_tx(sk: &ed25519_dalek::SigningKey, nonce: u64) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let pk = sk.verifying_key().to_bytes();
    let mut msg = Vec::new();
    msg.extend_from_slice(b"ZCRYPT-UNBOND-v1");
    msg.extend_from_slice(swap::CHAIN);
    msg.extend_from_slice(&pk);
    msg.extend_from_slice(&nonce.to_le_bytes()); // replay-protection nonce
    let sig = sk.sign(&msg);
    let mut t = vec![0x5Eu8];
    t.extend_from_slice(&pk);
    t.extend_from_slice(&nonce.to_le_bytes());
    t.extend_from_slice(&sig.to_bytes());
    t
}
/// Build a **coin-backed** DELEGATE (tag 0x5F): the authenticated header (delegator
/// pubkey / target validator address / stake / reward / sig), then `stake_blind` and the
/// `pledge` shield tx whose output[0] burns exactly `stake` ZCRYPT.
fn delegate_tx(
    sk: &ed25519_dalek::SigningKey,
    target: &[u8],
    stake: u64,
    reward: [u8; 32],
    stake_blind: zcrypt_shield::Blind,
    pledge: &shield_tx::ShieldTx,
) -> Vec<u8> {
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
    for limb in stake_blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&shield_tx::to_bytes(pledge));
    t
}
fn undelegate_tx(sk: &ed25519_dalek::SigningKey, target: &[u8], nonce: u64) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let pk = sk.verifying_key().to_bytes();
    let mut msg = Vec::new();
    msg.extend_from_slice(b"ZCRYPT-UNDELEGATE-v1");
    msg.extend_from_slice(swap::CHAIN);
    msg.extend_from_slice(&pk);
    msg.extend_from_slice(target);
    msg.extend_from_slice(&nonce.to_le_bytes()); // replay-protection nonce
    let sig = sk.sign(&msg);
    let mut t = vec![0x60u8];
    t.extend_from_slice(&pk);
    t.extend_from_slice(target);
    t.extend_from_slice(&nonce.to_le_bytes());
    t.extend_from_slice(&sig.to_bytes());
    t
}
fn claim_tx(pk: &PubKey, amount: u64) -> Vec<u8> {
    let mut t = vec![0x58u8];
    t.extend_from_slice(&hex::decode(pk_hex(pk)).unwrap());
    t.extend_from_slice(&amount.to_le_bytes());
    t
}

fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:46657".to_string());
    let zc = Zcrypt::new(&url);
    println!("== FULL product surface against the live chain {url} ==");

    let alice = Account::from_seed([0xA1; 32]);
    let bob = Account::from_seed([0xB0; 32]);

    // Seed a pool so shield spends hide among a non-trivial shielded pool.
    const POOL_DECOYS: u64 = 24;
    for k in 0..POOL_DECOYS {
        let d = Account::from_seed([(0x50 + k) as u8; 32]).own_coin(1_000 + k, [k + 3, k + 7, (k + 3).wrapping_add(1), (k + 7).wrapping_add(1)]);
        seed(&zc, &d.commitment(), "decoy");
    }
    println!("[setup] seeded {POOL_DECOYS} pool coins");

    // ---- 1. Normal-address send -> receive -> spend onward ----
    let h0 = zc.height().unwrap();
    let a1 = alice.own_coin(1_000_000, keys::random_blind());
    seed(&zc, &a1.commitment(), "alice coin");
    let (o_bob, n_bob) = pay(&bob.normal_address(), 700_000, keys::random_blind());
    let (o_chg, n_chg) = pay(&alice.normal_address(), 300_000, keys::random_blind());
    let gc1 = gas_for(&zc, &alice);
    let tx1 = swap::build_transfer(&zc, &[a1], &[o_bob, o_chg], vec![n_bob, n_chg], &alice, &gc1).unwrap();
    zc.broadcast(&tx1).expect("normal send verified+committed");
    let h1 = zc.height().unwrap();
    let bob_coin = scan_for(&zc, &bob, h0, h1 + 1).expect("Bob scans + receives");
    assert_eq!(bob_coin.value, 700_000);
    let (o2, n2) = pay(&alice.normal_address(), bob_coin.value, keys::random_blind());
    let (o3, n3) = pay(&bob.normal_address(), 0, keys::random_blind());
    let gc1b = gas_for(&zc, &bob);
    let tx1b = swap::build_transfer(&zc, &[bob_coin], &[o2, o3], vec![n2, n3], &bob, &gc1b).unwrap();
    zc.broadcast(&tx1b).expect("Bob spends received coin onward");
    println!("[1] normal send -> receive -> spend onward (ZCRYPT gas): OK");

    // ---- 2. Stealth send: only the stealth sub-account can receive ----
    let bob_stealth = bob.stealth(0);
    let hs0 = zc.height().unwrap();
    let a2 = alice.own_coin(500_000, keys::random_blind());
    seed(&zc, &a2.commitment(), "alice coin 2");
    let (os, ns) = pay(&bob_stealth.stealth_address(), 200_000, keys::random_blind());
    let (osc, nsc) = pay(&alice.normal_address(), 300_000, keys::random_blind());
    let gc2 = gas_for(&zc, &alice);
    let tx2 = swap::build_transfer(&zc, &[a2], &[os, osc], vec![ns, nsc], &alice, &gc2).unwrap();
    zc.broadcast(&tx2).expect("stealth send committed");
    let hs1 = zc.height().unwrap();
    assert!(scan_for(&zc, &bob, hs0, hs1 + 1).map(|c| c.value == 200_000) != Some(true),
        "main account must NOT receive the stealth output");
    let sc = scan_for(&zc, &bob_stealth, hs0, hs1 + 1).expect("stealth sub-account receives");
    assert_eq!(sc.value, 200_000);
    println!("[2] stealth send received only by the stealth sub-account: OK");

    // ---- 3. Bearer coin: sweep by holder, block double-claim ----
    let bearer = BearerCoin::create(50_000);
    seed(&zc, &bearer.coin.commitment(), "bearer");
    let mk_sweep = |b: u64, s: u64, gas: &Coin| {
        let dst = Account::from_seed([s as u8; 32]);
        let (o0, m0) = pay(&dst.normal_address(), bearer.coin.value, [b, b + 1, (b).wrapping_add(1), (b + 1).wrapping_add(1)]);
        let (o1, m1) = pay(&dst.normal_address(), 0, [b + 2, b + 3, (b + 2).wrapping_add(1), (b + 3).wrapping_add(1)]);
        // Alice pays the ZCRYPT gas for the sweep.
        swap::build_transfer(&zc, &[bearer.coin], &[o0, o1], vec![m0, m1], &alice, gas).unwrap()
    };
    let gs1 = gas_for(&zc, &alice);
    zc.broadcast(&mk_sweep(11, 0x71, &gs1)).expect("bearer swept by holder");
    let gs2 = gas_for(&zc, &alice);
    assert!(zc.broadcast(&mk_sweep(22, 0x72, &gs2)).is_err(), "bearer double-claim rejected");
    println!("[3] bearer sweep OK; double-claim rejected");

    // ---- 4. Shielded asset GOLD: register, mint (1-of-1 M-of-N HTLC), spend ----
    let (gold_ks, gold_signers) = zcrypt_core::mint_auth::derive_keyset(b"gold-cap-3node", 1, 1);
    // Registration and mint-open are state-creating txs: each carries a ZCRYPT gas note.
    let rg1 = gas_for(&zc, &alice);
    let rg1p = swap::build_gas_prefix(&zc, &alice, &rg1).expect("register gas");
    let _ = zc.broadcast(&swap::register_tx("GOLD", 2, &gold_ks.commitment(), 1_000_000, &rg1p));
    let gold: u64 = zc.query("/asset/by_ticker/GOLD").unwrap().trim().parse().unwrap();
    // ABUSE: registering GOLD again must be rejected (first-mint-wins).
    let rg2 = gas_for(&zc, &alice);
    let rg2p = swap::build_gas_prefix(&zc, &alice, &rg2).expect("register gas");
    assert!(
        zc.broadcast(&swap::register_tx("GOLD", 2, &gold_ks.commitment(), 1_000_000, &rg2p)).is_err(),
        "duplicate ticker rejected"
    );
    let preimage = b"gold-mint-preimage-3node-32byte!"; // exactly 32 bytes (consensus rule)
    let lock = zcrypt_core::nullifier::htlc_hashlock(preimage);
    let timeout = zc.height().unwrap() as u64 + 100;
    let escrow = zcrypt_core::htlc_shield::escrow_id(gold, 500_000, &lock, timeout, &alice.pubkey());
    let gold_msg = zcrypt_core::mint_auth::mint_message(swap::CHAIN, gold, 500_000, &lock, timeout, &alice.pubkey());
    let gold_auth = zcrypt_core::mint_auth::encode_auth(
        &gold_ks,
        &zcrypt_core::mint_auth::authorize(&gold_ks, &gold_signers, &gold_msg),
    );
    let og = gas_for(&zc, &alice);
    let ogp = swap::build_gas_prefix(&zc, &alice, &og).expect("open gas");
    zc.broadcast(&swap::open_tx(gold, 500_000, &lock, timeout, &alice.pubkey(), &gold_auth, &ogp)).expect("htlc open");
    zc.broadcast(&swap::claim_tx(&escrow, preimage)).expect("htlc claim mints GOLD");
    let gold_coin = alice.htlc_coin(500_000, gold, &escrow);
    let (g0, gn0) = pay_asset(&bob.normal_address(), 300_000, keys::random_blind(), gold);
    let (g1, gn1) = pay_asset(&alice.normal_address(), 500_000 - 300_000, keys::random_blind(), gold);
    // A GOLD transfer pays its gas in ZCRYPT (the moved asset is never burned).
    let gc4 = gas_for(&zc, &alice);
    let gtx = swap::build_transfer(&zc, &[gold_coin], &[g0, g1], vec![gn0, gn1], &alice, &gc4).unwrap();
    zc.broadcast(&gtx).expect("GOLD spend verified+committed");
    println!("[4] GOLD register + mint + spend (ZCRYPT gas): OK; duplicate-ticker abuse rejected");

    // ---- 5. Abuse: double-spend of a fresh coin is rejected ----
    let dcoin = alice.own_coin(100_000, keys::random_blind());
    seed(&zc, &dcoin.commitment(), "dspend coin");
    let mk = |ov: u64, gas: &Coin| {
        let (o0, m0) = pay(&alice.normal_address(), ov, keys::random_blind());
        let (o1, m1) = pay(&alice.normal_address(), 100_000 - ov, keys::random_blind());
        swap::build_transfer(&zc, &[dcoin], &[o0, o1], vec![m0, m1], &alice, gas).unwrap()
    };
    let g5a = gas_for(&zc, &alice);
    zc.broadcast(&mk(80_000, &g5a)).expect("first spend");
    let g5b = gas_for(&zc, &alice);
    assert!(zc.broadcast(&mk(70_000, &g5b)).is_err(), "double-spend rejected");
    println!("[5] double-spend abuse rejected");

    // ---- 6. Bond -> block rewards -> claim -> spend -> unbond (needs validator key) ----
    match std::env::var("VALIDATOR_SEED_HEX") {
        Ok(hexseed) => {
            let raw = hex::decode(hexseed.trim()).expect("VALIDATOR_SEED_HEX hex");
            let seed32: [u8; 32] = raw[..32].try_into().expect("need >= 32 bytes");
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed32);
            let rewarder = Account::from_seed([0xCC; 32]);
            let reward = keys::reward_address(&rewarder.pubkey());
            let stake = 10_000 * zcrypt_core::emission::ATOMIC;
            // Coin-backed BOND: fund the bonder, then PLEDGE the stake by spending that
            // coin into a burn coin of exactly `stake` (output[0]), change back (output[1]).
            // Bonding is gasless — the pledge burns only the stake (fee 0).
            // The pledge now pays MIN_FEE (M2), so fund covers stake + fee + change.
            let fund = rewarder.own_coin(stake + FEE + 100, keys::random_blind());
            seed(&zc, &fund.commitment(), "bond stake funding");
            let stake_blind = keys::random_blind();
            let burn_out: OutCoin = (stake, stake_blind, zcrypt_core::htlc_shield::BURN_PK, 0);
            let cblind = keys::random_blind();
            let change_out = keys::out_coin(&rewarder.normal_address(), 100, cblind);
            let cnote = kem::ciphertext_to_bytes(&keys::encrypt_note(&rewarder.normal_address(), 100, cblind));
            let pledge = build_shield_spend(&zc, &[fund], &[burn_out, change_out], FEE, vec![keys::cover_note_bytes(), cnote])
                .expect("build the stake pledge");
            // BOND carries the signer's monotonic auth nonce (M3). Query it — a prior run
            // (e.g. fee_flow's bond/unbond of this same node) may have already advanced it.
            let bond_nonce: u64 = zc
                .query(&format!("/staking/auth_nonce/{}", hex::encode(sk.verifying_key().to_bytes())))
                .ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            zc.broadcast(&bond_tx(&sk, stake, reward, stake_blind, bond_nonce, &pledge)).expect("BOND accepted");
            println!("[6] BOND accepted (pledged {stake} ZCRYPT into a burn coin); waiting for the reward epoch...");

            // ---- Coin-backed DELEGATE: a third party pledges 5,000 ZCRYPT toward the
            //      validator we just bonded, sharing its rewards (and its slashing risk). ----
            let val_addr = {
                use sha2::{Digest, Sha256};
                Sha256::digest(sk.verifying_key().to_bytes())[..20].to_vec()
            };
            let del_sk = ed25519_dalek::SigningKey::from_bytes(&[0xDD; 32]);
            let delegator = Account::from_seed([0xDE; 32]);
            let del_reward = keys::reward_address(&delegator.pubkey());
            let del_stake = 5_000 * zcrypt_core::emission::ATOMIC; // below MIN_STAKE — fine for a delegation
            // Delegating is gasless too — the pledge burns only the delegated stake.
            let dfund = delegator.own_coin(del_stake + FEE + 100, keys::random_blind());
            seed(&zc, &dfund.commitment(), "delegation funding");
            let del_blind = keys::random_blind();
            let del_burn: OutCoin = (del_stake, del_blind, zcrypt_core::htlc_shield::BURN_PK, 0);
            let dcblind = keys::random_blind();
            let del_change = keys::out_coin(&delegator.normal_address(), 100, dcblind);
            let dcnote = kem::ciphertext_to_bytes(&keys::encrypt_note(&delegator.normal_address(), 100, dcblind));
            let del_pledge = build_shield_spend(&zc, &[dfund], &[del_burn, del_change], FEE, vec![keys::cover_note_bytes(), dcnote])
                .expect("build the delegation pledge");
            zc.broadcast(&delegate_tx(&del_sk, &val_addr, del_stake, del_reward, del_blind, &del_pledge))
                .expect("DELEGATE accepted");
            println!("[6] DELEGATE accepted (a delegator pledged {del_stake} ZCRYPT to the validator)");

            let pkh = format!("/staking/claimable/{}", pk_hex(&rewarder.pubkey()));
            let mut owed = 0u64;
            for _ in 0..150 {
                owed = staking_u64(&zc, &pkh);
                if owed > 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            assert!(owed > 0, "block rewards must accrue to the bonded validator");

            // The delegator earns a share of the same epoch's reward (net of the 10%
            // commission the validator keeps). This is what makes delegation real.
            let del_pkh = format!("/staking/claimable/{}", pk_hex(&delegator.pubkey()));
            let mut del_owed = 0u64;
            for _ in 0..150 {
                del_owed = staking_u64(&zc, &del_pkh);
                if del_owed > 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            assert!(del_owed > 0, "delegator must earn a share of the validator's rewards");
            // Prove the share is genuine spendable value: claim it into a coin and spend it.
            let didx = staking_u64(&zc, &format!("/staking/claim_index/{}", pk_hex(&delegator.pubkey())));
            zc.broadcast(&claim_tx(&delegator.pubkey(), del_owed)).expect("delegator CLAIM mints coins");
            // Claiming is gasless. The node splits a claim via `claim_chunks` (reserving a gas
            // coin on the first claim if the amount is large enough), minting each chunk at a
            // monotonic index from `didx`. Reconstruct the SAME chunks and spend the first
            // real on-chain coin — assuming a single coin of `del_owed` breaks once the split
            // kicks in (as it did once a co-delegator raised this delegator's reward).
            let first_claim = didx == 0;
            let spend_val = keys::claim_chunks(del_owed, first_claim)[0];
            let del_reward_coin = delegator.reward_coin(spend_val, didx);
            let (d0, dn0) = pay(&bob.normal_address(), spend_val, keys::random_blind());
            let (d1, dn1) = pay(&delegator.normal_address(), 0, keys::random_blind());
            let gcd = gas_for(&zc, &delegator);
            let dtx = swap::build_transfer(&zc, &[del_reward_coin], &[d0, d1], vec![dn0, dn1], &delegator, &gcd).unwrap();
            zc.broadcast(&dtx).expect("delegator reward coin is spendable");
            println!("[6] delegator earned {del_owed} reward share; claimed + spent a {spend_val} coin");

            // Undelegate: the stake leaves the validator's power at once and locks in the
            // unbonding queue (returns to the delegator after the 10-day wait).
            let unbond_before = staking_u64(&zc, "/staking/unbonding_total");
            let undel_nonce: u64 = zc
                .query(&format!("/staking/auth_nonce/{}", hex::encode(del_sk.verifying_key().to_bytes())))
                .ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            zc.broadcast(&undelegate_tx(&del_sk, &val_addr, undel_nonce)).expect("UNDELEGATE accepted");
            let mut unbond_after = unbond_before;
            for _ in 0..15 {
                unbond_after = staking_u64(&zc, "/staking/unbonding_total");
                if unbond_after >= unbond_before + del_stake {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            assert!(unbond_after >= unbond_before + del_stake, "undelegated stake is locked in the queue");
            println!("[6] UNDELEGATE accepted (stake locked for the 10-day unbonding period)");

            let idx = staking_u64(&zc, &format!("/staking/claim_index/{}", pk_hex(&rewarder.pubkey())));
            zc.broadcast(&claim_tx(&rewarder.pubkey(), owed)).expect("CLAIM mints reward coins");
            // Claiming is gasless. A large claim is split by `claim_chunks` (gas coin + rest on
            // first claim), each chunk minted at a monotonic index from `idx` — reconstruct the
            // SAME chunks and spend the first real on-chain coin (a single-coin assumption breaks
            // once the claim is big enough to split).
            let r_first = idx == 0;
            let r_spend = keys::claim_chunks(owed, r_first)[0];
            let reward_coin = rewarder.reward_coin(r_spend, idx);
            let (r0, rn0) = pay(&bob.normal_address(), r_spend, keys::random_blind());
            let (r1, rn1) = pay(&rewarder.normal_address(), 0, keys::random_blind());
            let gcr = gas_for(&zc, &rewarder);
            let rtx = swap::build_transfer(&zc, &[reward_coin], &[r0, r1], vec![rn0, rn1], &rewarder, &gcr).unwrap();
            zc.broadcast(&rtx).expect("reward coin is spendable");
            let unbond_nonce: u64 = zc
                .query(&format!("/staking/auth_nonce/{}", hex::encode(sk.verifying_key().to_bytes())))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            zc.broadcast(&unbond_tx(&sk, unbond_nonce)).expect("UNBOND accepted");
            println!("[6] validator earned {owed} reward, claimed, spent a {r_spend} coin, then unbonded: OK");
        }
        Err(_) => println!("[6] SKIPPED bond/reward/unbond (set VALIDATOR_SEED_HEX to enable)"),
    }

    let count: usize = zc.query("/commit/count").unwrap().trim().parse().unwrap_or(0);
    println!("\nALL FLOWS GREEN on the live chain. Commitment tree now has {count} leaves.");
}
