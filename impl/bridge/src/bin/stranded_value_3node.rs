//! Live **"never stranded"** suite against the 3-node chain: native ZCRYPT gas end to end.
//!
//!   [1] SINGLE COIN. A wallet whose only ZCRYPT is ONE coin pays, moves value and keeps its
//!       change in ONE proof (`0x6A`); the change spends alone again; a whole-coin sweep
//!       leaves nothing behind; dust below the fee rides along with a later coin.
//!   [1b] ADVERSARIAL. A burn below the fee, a declared burn that does not open output[0], a
//!       tampered blind, an in-tx fee, a replay: all REFUSED by consensus. The old `0x55`
//!       bundle (hidden asset + ZCRYPT gas note) still works beside it.
//!   [2] ZERO ZCRYPT. A zBTC-only wallet swaps into ZCRYPT with no ZCRYPT anywhere on its
//!       side: the LP locks ZCRYPT FIRST (`0x6B`, 2 × fee, naming the newcomer's lock), the
//!       newcomer finds that lock on chain, locks zBTC GAS-FREE (`0x6B`, fee 0, sponsored),
//!       claims the ZCRYPT (claims are gas-free), the LP reads the preimage and claims the
//!       zBTC. The newcomer then spends its single ZCRYPT coin natively.
//!   [2b] ADVERSARIAL. An unsponsored gas-free lock, a 1×-fee ZCRYPT lock that names a
//!       counter-lock, a non-ZCRYPT lock with an in-asset fee, a dust lock / wrong timeout /
//!       wrong hashlock / wrong keys against a real sponsor, a second lock on a spent
//!       sponsorship: all REFUSED; the one named lock is accepted.
//!
//!   ZC_URL (default :36657)
use zcrypt_bridge::swap::{self, sponsored_lock_timeout};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_core::emission::MIN_FEE;
use zcrypt_core::htlc_shield::{escrow_id, lock_envelope, CoinOpening, EscrowKind, BURN_PK, ENV_SWAP_LOCK};
use zcrypt_core::keys::{self, Account, Coin};
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_core::kem;
use zcrypt_shield::{Blind, OutCoin, PubKey, ASSET_ZCRYPT};

const ZC: u64 = zcrypt_core::emission::ATOMIC;
const NO_SPONSOR: [u8; 32] = [0u8; 32];

fn seed(zc: &Zcrypt, c: &Coin) {
    if let Err(e) = zc.broadcast(&swap::seed_tx(&c.commitment())) {
        if !e.contains("already") {
            panic!("seed: {e}");
        }
    }
}

fn note(to: &Account, value: u64, blind: Blind, asset: u64) -> Vec<u8> {
    kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&to.normal_address(), value, blind, asset))
}

/// What `who` can decrypt from a native transfer's notes.
fn received_native(who: &Account, raw: &[u8]) -> Vec<Coin> {
    let (_, _, tx) = swap::parse_zcrypt_transfer_payload(&raw[1..]).expect("0x6A payload");
    tx.enc_notes.iter().filter_map(|n| who.receive(&kem::ciphertext_from_bytes(n)?)).collect()
}

/// A native transfer whose declared burn and in-tx fee are chosen freely (adversarial shapes).
fn raw_native_transfer(zc: &Zcrypt, from: &Account, coin: &Coin, to: &Account, amount: u64, burn: u64, declared: u64, fee: u64) -> Result<Vec<u8>, String> {
    let change = coin.value - amount - burn - fee;
    let burn_blind = keys::random_blind();
    let pb = keys::random_blind();
    let cb = keys::random_blind();
    let outs: [OutCoin; 3] = [(burn, burn_blind, BURN_PK, ASSET_ZCRYPT), (amount, pb, to.pubkey(), ASSET_ZCRYPT), (change, cb, from.pubkey(), ASSET_ZCRYPT)];
    let stx = swap::build_shield_spend_n(zc, std::slice::from_ref(coin), &outs, fee, vec![keys::cover_note_bytes(), note(to, amount, pb, ASSET_ZCRYPT), note(from, change, cb, ASSET_ZCRYPT)], &[])?;
    Ok(swap::zcrypt_transfer_tx(declared, &burn_blind, &stx))
}

/// A native swap lock with a freely chosen fee and sponsor reference (adversarial shapes).
#[allow(clippy::too_many_arguments)]
fn raw_native_lock(
    zc: &Zcrypt,
    locker: &Account,
    coin: &Coin,
    asset: u64,
    value: u64,
    fee: u64,
    hashlock: &[u8; 32],
    timeout: u64,
    counterparty: &Account,
    sponsor_ref: [u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let change = coin.value.checked_sub(value).and_then(|r| r.checked_sub(fee)).ok_or("coin too small for value + fee")?;
    let blind = keys::random_blind();
    let cb = keys::random_blind();
    let (_, claim) = CoinOpening::create(&counterparty.normal_address(), value, asset)?;
    let (_, refund) = CoinOpening::create(&locker.normal_address(), value, asset)?;
    let env = lock_envelope(ENV_SWAP_LOCK, asset, value, hashlock, timeout, &counterparty.pubkey(), &locker.pubkey(), &[], &[claim.coin.clone(), refund.coin.clone()]);
    let outs: [OutCoin; 2] = [(value, blind, BURN_PK, asset), (change, cb, locker.pubkey(), asset)];
    let stx = swap::build_shield_spend_bound(zc, std::slice::from_ref(coin), &outs, fee, vec![keys::cover_note_bytes(), note(locker, change, cb, asset)], &env)?;
    let id = escrow_id(EscrowKind::Swap, asset, value, hashlock, timeout, &counterparty.pubkey(), &locker.pubkey());
    Ok((swap::swap_lock_native_tx(value, &blind, asset, hashlock, timeout, &counterparty.pubkey(), &locker.pubkey(), &sponsor_ref, &stx, &claim, &refund), id))
}

fn expect_refused(what: &str, r: Result<String, String>, needle: &str) {
    match r {
        // An exact replay is dropped by CometBFT's mempool cache before our node sees it.
        Err(e) if e.contains(needle) || (needle == "double-spend" && e.contains("already exists in cache")) => println!("  REFUSED as required: {what} ({})", e.lines().next().unwrap_or("").chars().take(140).collect::<String>()),
        Err(e) => panic!("{what}: refused for the wrong reason: {e}"),
        Ok(_) => panic!("{what}: consensus ACCEPTED it"),
    }
}

/// The chain's zBTC asset id (genesis), or a registered stand-in on a chain without one.
fn zbtc_asset(zc: &Zcrypt, gas_owner: &Account) -> u64 {
    for t in ["zBTC", "ZBTC"] {
        if let Ok(s) = zc.query(&format!("/asset/by_ticker/{t}")) {
            if let Ok(id) = s.trim().parse::<u64>() {
                return id;
            }
        }
    }
    let gas = gas_owner.own_coin(ZC, keys::random_blind());
    seed(zc, &gas);
    let body = swap::register_body(8, "STRD", 21_000_000 * 100_000_000, &[0x5Du8; 32]);
    let prefix = swap::build_gas_prefix(zc, gas_owner, &gas, &body).expect("gas prefix");
    let _ = zc.broadcast(&swap::register_tx("STRD", 8, &[0x5Du8; 32], 21_000_000 * 100_000_000, &prefix));
    zc.query("/asset/by_ticker/STRD").expect("STRD").trim().parse().expect("asset id")
}

fn main() {
    zcrypt_bridge::zcrypt::set_broadcast_jitter(false);
    let zc_url = std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:36657".to_string());
    println!("Native ZCRYPT gas — never stranded — against chain={zc_url}");
    let zc = Zcrypt::new(&zc_url);

    // A few unrelated coins so every spend hides in a non-trivial pool.
    for k in 0..16u64 {
        let a = Account::from_seed([(0x70 + k) as u8; 32]);
        seed(&zc, &a.own_coin(1_000 + k, zcrypt_shield::widen_blind([k + 1, k + 2, k + 3, k + 4])));
    }

    // ---------------------------------------------------------------------------------
    println!("\n== [1] ONE ZCRYPT coin pays, moves value and keeps change in ONE proof ==");
    let alice = Account::from_seed([0xA1; 32]);
    let bob = Account::from_seed([0xB2; 32]);
    let carol = Account::from_seed([0xC3; 32]);
    let only = alice.own_coin(500 * ZC, keys::random_blind());
    seed(&zc, &only);
    let pb = keys::random_blind();
    let (raw, change) = swap::build_zcrypt_transfer(&zc, &[only.clone()], keys::out_coin(&bob.normal_address(), 100 * ZC, pb), note(&bob, 100 * ZC, pb, ASSET_ZCRYPT), &alice, MIN_FEE).expect("build");
    zc.broadcast(&raw).expect("single-coin native transfer accepted");
    let got = received_native(&bob, &raw);
    assert_eq!(got.len(), 1, "bob decrypts exactly his note");
    assert_eq!(got[0].value, 100 * ZC);
    assert_eq!(change.value, 400 * ZC - MIN_FEE);
    println!("  alice (one coin, 500 ZCRYPT) -> bob 100 ZCRYPT; change {} atomic; 0.01 burned in-proof", change.value);
    // the change spends alone
    let pb2 = keys::random_blind();
    let (raw2, change2) = swap::build_zcrypt_transfer(&zc, &[change], keys::out_coin(&carol.normal_address(), ZC, pb2), note(&carol, ZC, pb2, ASSET_ZCRYPT), &alice, MIN_FEE).expect("build");
    zc.broadcast(&raw2).expect("the change coin spends alone");
    assert_eq!(received_native(&carol, &raw2)[0].value, ZC);
    // whole-coin sweep: zero change
    let sweep = change2.value - MIN_FEE;
    let pb3 = keys::random_blind();
    let (raw3, change3) = swap::build_zcrypt_transfer(&zc, &[change2], keys::out_coin(&carol.normal_address(), sweep, pb3), note(&carol, sweep, pb3, ASSET_ZCRYPT), &alice, MIN_FEE).expect("build");
    assert_eq!(change3.value, 0);
    zc.broadcast(&raw3).expect("whole-coin sweep (zero change) accepted");
    assert_eq!(received_native(&carol, &raw3)[0].value, sweep);
    println!("  change spent alone, then swept to zero: nothing stranded");
    // dust below the fee rides along with a later coin
    let dust = alice.own_coin(MIN_FEE - 1, keys::random_blind());
    let later = alice.own_coin(5 * ZC, keys::random_blind());
    seed(&zc, &dust);
    seed(&zc, &later);
    let e = swap::build_zcrypt_transfer(&zc, &[dust.clone()], keys::out_coin(&bob.normal_address(), 1, pb), note(&bob, 1, pb, ASSET_ZCRYPT), &alice, MIN_FEE).expect_err("dust alone cannot pay");
    assert!(e.contains("insufficient"), "{e}");
    let pb4 = keys::random_blind();
    let (raw4, _) = swap::build_zcrypt_transfer(&zc, &[later, dust], keys::out_coin(&bob.normal_address(), 2 * ZC, pb4), note(&bob, 2 * ZC, pb4, ASSET_ZCRYPT), &alice, MIN_FEE).expect("build");
    zc.broadcast(&raw4).expect("dust + a later coin spend together");
    println!("  dust ({} atomic) could not move alone, then rode along with a later coin", MIN_FEE - 1);

    // ---------------------------------------------------------------------------------
    println!("\n== [1b] native transfer: adversarial shapes are refused ==");
    let bad_coin = alice.own_coin(10 * ZC, keys::random_blind());
    seed(&zc, &bad_coin);
    expect_refused("burn below MIN_FEE", raw_native_transfer(&zc, &alice, &bad_coin, &bob, ZC, MIN_FEE - 1, MIN_FEE - 1, 0).and_then(|r| zc.broadcast(&r)), "burn must be ≥ MIN_FEE");
    expect_refused("declared burn != committed burn", raw_native_transfer(&zc, &alice, &bad_coin, &bob, ZC, MIN_FEE, MIN_FEE + 1, 0).and_then(|r| zc.broadcast(&r)), "not the declared burn coin");
    expect_refused("in-tx fee on a native transfer", raw_native_transfer(&zc, &alice, &bad_coin, &bob, ZC, MIN_FEE, MIN_FEE, 5).and_then(|r| zc.broadcast(&r)), "in-tx fee must be 0");
    let good = raw_native_transfer(&zc, &alice, &bad_coin, &bob, ZC, MIN_FEE, MIN_FEE, 0).expect("build");
    let mut tampered = good.clone();
    tampered[9] ^= 1; // first byte of the declared blind
    expect_refused("tampered declared blind", zc.broadcast(&tampered), "not the declared burn coin");
    zc.broadcast(&good).expect("the honest transfer");
    expect_refused("replay of the same transfer", zc.broadcast(&good), "double-spend");
    let again = raw_native_transfer(&zc, &alice, &bad_coin, &bob, 2 * ZC, MIN_FEE, MIN_FEE, 0).expect("build");
    expect_refused("second spend of the same coin", zc.broadcast(&again), "double-spend");
    println!("  the 0x55 bundle (hidden asset + ZCRYPT gas note) still works beside it:");
    let gas_owner = Account::from_seed([0xE5; 32]);
    let zbtc = zbtc_asset(&zc, &gas_owner);
    let zb = alice.own_asset_coin(1_000_000, keys::random_blind(), zbtc);
    let gas = alice.own_coin(ZC, keys::random_blind());
    seed(&zc, &zb);
    seed(&zc, &gas);
    let ob = keys::random_blind();
    let cb = keys::random_blind();
    let outs: [OutCoin; 2] = [keys::out_asset_coin(&bob.normal_address(), 400_000, ob, zbtc), keys::out_asset_coin(&alice.normal_address(), 600_000, cb, zbtc)];
    let bundle = swap::build_transfer(&zc, &[zb], &outs, vec![note(&bob, 400_000, ob, zbtc), note(&alice, 600_000, cb, zbtc)], &alice, &gas).expect("0x55 bundle");
    zc.broadcast(&bundle).expect("0x55 bundle accepted");
    println!("  zBTC moved by a 0x55 bundle with a ZCRYPT gas note (asset {zbtc})");

    // ---------------------------------------------------------------------------------
    println!("\n== [2] ZERO-ZCRYPT newcomer: zBTC -> ZCRYPT via a sponsored swap ==");
    let lp = Account::from_seed([0xD4; 32]);
    let newcomer = Account::from_seed([0xF6; 32]); // never receives ZCRYPT before the swap
    let lp_coin = lp.own_coin(100 * ZC, keys::random_blind());
    let nc_coin = newcomer.own_asset_coin(5_000_000, keys::random_blind(), zbtc);
    seed(&zc, &lp_coin);
    seed(&zc, &nc_coin);
    let (zc_give, zb_give) = (20 * ZC, 3_000_000u64);
    let preimage = swap::fresh_preimage();
    let lock = htlc_hashlock(&preimage);
    let scan_from = zc.height().unwrap();
    // LP locks FIRST: ZCRYPT, 2 × fee, naming the newcomer's lock (id known in advance: the
    // newcomer's timeout is a fixed margin past the LP's).
    let lp_timeout = zc.height().unwrap() as u64 + 600;
    let nc_timeout = sponsored_lock_timeout(lp_timeout);
    let target = escrow_id(EscrowKind::Swap, zbtc, zb_give, &lock, nc_timeout, &lp.pubkey(), &newcomer.pubkey());
    let (lp_escrow, lp_change, _) = swap::send_swap_lock_native(&zc, &lp, ASSET_ZCRYPT, zc_give, &[lp_coin], &lock, lp_timeout, &newcomer.normal_address(), target).expect("LP sponsoring lock");
    assert_eq!(lp_change.value, 100 * ZC - zc_give - 2 * MIN_FEE, "LP burned 2 × fee in-proof");
    let info = swap::query_escrow(&zc, &lp_escrow).unwrap().expect("LP escrow");
    assert_eq!(info.sponsor_for, target.to_vec());
    assert!(!info.sponsor_used);
    println!("  [LP] locked {} ZCRYPT from ONE coin, fee 2x0.01 in-proof, sponsoring {}", zc_give / ZC, hex::encode(&target[..8]));
    // The newcomer finds the LP's lock on chain (claimant = newcomer), checks it names its own
    // lock, and locks zBTC with NO gas and NO ZCRYPT.
    let found = swap::find_swap_lock(&zc, scan_from, zc.height().unwrap(), &lock, &newcomer.pubkey(), ASSET_ZCRYPT, zc_give).expect("scan").expect("newcomer finds the LP's lock");
    assert_eq!(found.escrow_id, lp_escrow);
    assert_eq!(sponsored_lock_timeout(found.timeout), nc_timeout);
    let (nc_escrow, nc_change, _) = swap::send_swap_lock_native(&zc, &newcomer, zbtc, zb_give, &[nc_coin], &lock, nc_timeout, &lp.normal_address(), lp_escrow).expect("newcomer's GAS-FREE lock");
    assert_eq!(nc_escrow, target);
    assert_eq!(nc_change.value, 5_000_000 - zb_give, "the zBTC is not charged");
    assert!(swap::query_escrow(&zc, &lp_escrow).unwrap().unwrap().sponsor_used, "sponsorship spent");
    println!("  [newcomer] locked {zb_give} zBTC atomic with fee 0 and no gas note (sponsored)");
    // Newcomer claims the ZCRYPT (claims are gas-free), revealing the preimage.
    swap::swap_claim_check(&zc, &lp_escrow, &newcomer.pubkey(), &lp.pubkey(), ASSET_ZCRYPT, zc_give, &lock).expect("safe to claim");
    zc.broadcast(&swap::claim_tx(&lp_escrow, &preimage)).expect("newcomer claims ZCRYPT");
    let lp_info = swap::query_escrow(&zc, &lp_escrow).unwrap().unwrap();
    let zc_coin = swap::coin_from_note(&newcomer, &lp_info.claim_enc_note).expect("newcomer decrypts the ZCRYPT claim note");
    assert_eq!((zc_coin.value, zc_coin.asset_id), (zc_give, ASSET_ZCRYPT));
    // LP reads the preimage and claims the zBTC.
    let (revealed, _) = swap::find_claim_preimage(&zc, scan_from, zc.height().unwrap(), &lp_escrow, &lock).expect("scan").expect("LP sees the preimage");
    assert_eq!(revealed, preimage);
    zc.broadcast(&swap::claim_tx(&nc_escrow, &revealed)).expect("LP claims zBTC");
    let nc_info = swap::query_escrow(&zc, &nc_escrow).unwrap().unwrap();
    let lp_got = swap::coin_from_note(&lp, &nc_info.claim_enc_note).expect("LP decrypts the zBTC claim note");
    assert_eq!((lp_got.value, lp_got.asset_id), (zb_give, zbtc));
    println!("  swap settled: newcomer holds {} ZCRYPT (its first), LP holds {zb_give} zBTC atomic", zc_give / ZC);
    // The newcomer's first and only ZCRYPT coin spends on its own.
    let pbn = keys::random_blind();
    let (rawn, ncc) = swap::build_zcrypt_transfer(&zc, &[zc_coin], keys::out_coin(&bob.normal_address(), 3 * ZC, pbn), note(&bob, 3 * ZC, pbn, ASSET_ZCRYPT), &newcomer, MIN_FEE).expect("build");
    zc.broadcast(&rawn).expect("the former zero-ZCRYPT wallet pays its own gas");
    assert_eq!(received_native(&bob, &rawn)[0].value, 3 * ZC);
    assert_eq!(ncc.value, zc_give - 3 * ZC - MIN_FEE);
    println!("  [newcomer] spent its single ZCRYPT coin natively: never stranded");

    // ---------------------------------------------------------------------------------
    println!("\n== [2b] sponsored locks: adversarial shapes are refused ==");
    let mallory = Account::from_seed([0x99; 32]);
    let nc2 = Account::from_seed([0xF7; 32]);
    let coins: Vec<Coin> = (0..6).map(|k| nc2.own_asset_coin(2_000_000 + k, keys::random_blind(), zbtc)).collect();
    let lp_coins: Vec<Coin> = (0..4).map(|_| lp.own_coin(50 * ZC, keys::random_blind())).collect();
    for c in coins.iter().chain(lp_coins.iter()) {
        seed(&zc, c);
    }
    let pre2 = swap::fresh_preimage();
    let lock2 = htlc_hashlock(&pre2);
    let lp_t = zc.height().unwrap() as u64 + 600;
    let nc_t = sponsored_lock_timeout(lp_t);
    let value2 = 1_500_000u64;
    let target2 = escrow_id(EscrowKind::Swap, zbtc, value2, &lock2, nc_t, &lp.pubkey(), &nc2.pubkey());
    // (a) no sponsor at all
    expect_refused("gas-free lock with no sponsor", raw_native_lock(&zc, &nc2, &coins[0], zbtc, value2, 0, &lock2, nc_t, &lp, NO_SPONSOR).and_then(|(r, _)| zc.broadcast(&r)), "must name the ZCRYPT swap lock");
    // (b) a sponsor that does not exist
    expect_refused("gas-free lock naming an unknown escrow", raw_native_lock(&zc, &nc2, &coins[0], zbtc, value2, 0, &lock2, nc_t, &lp, [0x42; 32]).and_then(|(r, _)| zc.broadcast(&r)), "no such escrow");
    // (c) an in-asset fee on a non-ZCRYPT native lock
    expect_refused("zBTC lock paying an in-asset fee", raw_native_lock(&zc, &nc2, &coins[0], zbtc, value2, 1, &lock2, nc_t, &lp, NO_SPONSOR).and_then(|(r, _)| zc.broadcast(&r)), "must have fee 0");
    // (d) a ZCRYPT lock that names a counter-lock but burns only 1 × fee
    expect_refused("1x-fee ZCRYPT lock claiming to sponsor", raw_native_lock(&zc, &lp, &lp_coins[0], ASSET_ZCRYPT, 10 * ZC, MIN_FEE, &lock2, lp_t, &nc2, target2).and_then(|(r, _)| zc.broadcast(&r)), "MIN_FEE for the counter-lock it sponsors");
    expect_refused("ZCRYPT lock below 1x fee", raw_native_lock(&zc, &lp, &lp_coins[0], ASSET_ZCRYPT, 10 * ZC, MIN_FEE - 1, &lock2, lp_t, &nc2, NO_SPONSOR).and_then(|(r, _)| zc.broadcast(&r)), "must burn ≥");
    // (e) a plain 1x ZCRYPT lock cannot be used as a sponsor
    let (plain, plain_id) = raw_native_lock(&zc, &lp, &lp_coins[0], ASSET_ZCRYPT, 10 * ZC, MIN_FEE, &lock2, lp_t + 1, &nc2, NO_SPONSOR).expect("build");
    zc.broadcast(&plain).expect("plain 1x ZCRYPT lock");
    expect_refused("gas-free lock naming a 1x-fee sponsor", raw_native_lock(&zc, &nc2, &coins[0], zbtc, value2, 0, &lock2, nc_t, &lp, plain_id).and_then(|(r, _)| zc.broadcast(&r)), "did not burn a second fee");
    // (f) a real sponsor naming target2; everything but target2 is refused
    let (sp, sp_id) = raw_native_lock(&zc, &lp, &lp_coins[1], ASSET_ZCRYPT, 10 * ZC, 2 * MIN_FEE, &lock2, lp_t, &nc2, target2).expect("build");
    zc.broadcast(&sp).expect("sponsoring lock");
    expect_refused("dust lock against the sponsor", raw_native_lock(&zc, &nc2, &coins[1], zbtc, 1, 0, &lock2, nc_t, &lp, sp_id).and_then(|(r, _)| zc.broadcast(&r)), "named a different counter-lock");
    expect_refused("wrong timeout against the sponsor", raw_native_lock(&zc, &nc2, &coins[1], zbtc, value2, 0, &lock2, nc_t + 1, &lp, sp_id).and_then(|(r, _)| zc.broadcast(&r)), "named a different counter-lock");
    let other = htlc_hashlock(&swap::fresh_preimage());
    expect_refused("wrong hashlock against the sponsor", raw_native_lock(&zc, &nc2, &coins[1], zbtc, value2, 0, &other, nc_t, &lp, sp_id).and_then(|(r, _)| zc.broadcast(&r)), "gas sponsor");
    expect_refused("keys not crossed (pays a third party)", raw_native_lock(&zc, &nc2, &coins[1], zbtc, value2, 0, &lock2, nc_t, &mallory, sp_id).and_then(|(r, _)| zc.broadcast(&r)), "gas sponsor");
    let mc = mallory.own_asset_coin(value2, keys::random_blind(), zbtc);
    seed(&zc, &mc);
    expect_refused("an impostor locking for the LP", raw_native_lock(&zc, &mallory, &mc, zbtc, value2, 0, &lock2, nc_t, &lp, sp_id).and_then(|(r, _)| zc.broadcast(&r)), "gas sponsor");
    assert!(!swap::query_escrow(&zc, &sp_id).unwrap().unwrap().sponsor_used, "no refused lock consumed the sponsorship");
    // the named lock is accepted, then the sponsorship is spent
    let (okr, ok_id) = raw_native_lock(&zc, &nc2, &coins[2], zbtc, value2, 0, &lock2, nc_t, &lp, sp_id).expect("build");
    assert_eq!(ok_id, target2);
    zc.broadcast(&okr).expect("the named counter-lock");
    assert!(swap::query_escrow(&zc, &sp_id).unwrap().unwrap().sponsor_used);
    expect_refused("a second lock on the spent sponsorship (duplicate id)", raw_native_lock(&zc, &nc2, &coins[3], zbtc, value2, 0, &lock2, nc_t, &lp, sp_id).and_then(|(r, _)| zc.broadcast(&r)), "");
    // the refused locks burned nothing: their coins still spend (as a gas-free lock under a
    // fresh sponsor, closing the loop)
    let pre3 = swap::fresh_preimage();
    let lock3 = htlc_hashlock(&pre3);
    let lp_t3 = zc.height().unwrap() as u64 + 600;
    let nc_t3 = sponsored_lock_timeout(lp_t3);
    let target3 = escrow_id(EscrowKind::Swap, zbtc, value2, &lock3, nc_t3, &lp.pubkey(), &nc2.pubkey());
    let (sp3, sp3_id) = raw_native_lock(&zc, &lp, &lp_coins[2], ASSET_ZCRYPT, 10 * ZC, 2 * MIN_FEE, &lock3, lp_t3, &nc2, target3).expect("build");
    zc.broadcast(&sp3).expect("second sponsor");
    let (r3, id3) = raw_native_lock(&zc, &nc2, &coins[1], zbtc, value2, 0, &lock3, nc_t3, &lp, sp3_id).expect("build");
    assert_eq!(id3, target3);
    zc.broadcast(&r3).expect("coin from a refused attempt locks fine later");
    println!("  every adversarial lock refused; the named lock accepted; refused coins unharmed");

    // Public API sanity: the id a wallet derives for the sponsored lock is the consensus id.
    let _unused: PubKey = lp.pubkey();
    println!("\nNative ZCRYPT gas (single-coin sends, zero-ZCRYPT sponsored swap, adversarial): GREEN");
}
