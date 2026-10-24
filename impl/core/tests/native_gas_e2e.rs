//! Native ZCRYPT gas: nobody is ever stranded.
//!
//! Two consensus rules make a wallet spendable from ANY coin position:
//!
//! * `0x6A` **native ZCRYPT transfer** — ONE proof whose `output[0]` is a revealed ZCRYPT burn
//!   coin (≥ MIN_FEE). The spend is single-asset, so the revealed burn pins the whole proof to
//!   ZCRYPT: the gas is ZCRYPT without a second coin or a second proof. A wallet holding a
//!   SINGLE ZCRYPT coin pays, moves value and keeps its change in one transaction.
//! * `0x6B` **native swap lock** — no gas prefix. A ZCRYPT lock burns its gas as the in-tx
//!   fee (one coin suffices); when it burns `2 × MIN_FEE` and names its counter-lock, that
//!   counter-lock (any asset) is admitted WITHOUT any gas. A wallet with ZERO ZCRYPT swaps
//!   zBTC for ZCRYPT, claims gas-free, and is never stuck.
//!
//! Every adversarial shape is refused: a burn below the fee, a burn that does not open the
//! declared coin, an in-tx fee on a native transfer, a replay, a gas-free lock with no
//! sponsor / a wrong sponsor / a spent sponsor / a settled sponsor, a 1× ZCRYPT lock that
//! claims to sponsor, a second lock on one sponsorship, and the "stranded value" shapes
//! (sweep a whole coin, dust below the fee).
use zcrypt_core::emission::MIN_FEE;
use zcrypt_core::htlc_shield::{escrow_id, CoinOpening, EscrowKind, EscrowState, BURN_PK};
use zcrypt_core::keys::{self, Account, Coin};
use zcrypt_core::node::{Node, NO_SPONSOR};
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_core::shield_tx::{self, ShieldTx, Spend};
use zcrypt_shield::{Blind, OutCoin, ASSET_ZCRYPT, N_OUT};

const CHAIN: &[u8] = b"zcrypt-devnet";

/// Put `coin` on chain and return it.
fn seed(node: &mut Node, coin: Coin) -> Coin {
    node.seed_coin(coin.commitment());
    coin
}

/// A spend witness for `coin`, with its Merkle path from the node's current tree.
fn spend_of(node: &Node, coin: &Coin) -> Spend {
    let leaves = node.commitment_leaves();
    let idx = leaves.iter().position(|x| *x == coin.commitment()).expect("coin is on chain");
    let (path_siblings, path_dirs) = node.commitment_path(idx).expect("path");
    Spend {
        value: coin.value,
        blind: coin.blind,
        spend_secret: coin.spend_secret,
        asset_id: coin.asset_id,
        path_siblings,
        path_dirs,
    }
}

fn note(to: &Account, value: u64, blind: Blind, asset: u64) -> Vec<u8> {
    zcrypt_core::kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&to.normal_address(), value, blind, asset))
}

/// A seeded pool of unrelated coins so spends hide among a non-trivial tree.
fn decoys(node: &mut Node, asset: u64) {
    for k in 0..12u64 {
        let a = Account::from_seed([(0x60 + k) as u8; 32]);
        node.seed_coin(a.own_asset_coin(1_000 + k, zcrypt_shield::widen_blind([k + 3, k + 7, k + 9, k + 11]), asset).commitment());
    }
}

/// Build a native ZCRYPT transfer from `from`'s coins: `output[0]` burns `burn`, `output[1]`
/// pays `amount` to `to`, `output[2]` is the change. Returns `(tx, burn_blind, change_coin)`.
fn native_transfer(node: &Node, from: &Account, coins: &[Coin], to: &Account, amount: u64, burn: u64) -> (ShieldTx, Blind, Coin) {
    let total: u64 = coins.iter().map(|c| c.value).sum();
    let change = total - amount - burn;
    let burn_blind = keys::random_blind();
    let pay_blind = keys::random_blind();
    let chg_blind = keys::random_blind();
    let outs: [OutCoin; 3] = [
        (burn, burn_blind, BURN_PK, ASSET_ZCRYPT),
        (amount, pay_blind, to.pubkey(), ASSET_ZCRYPT),
        (change, chg_blind, from.pubkey(), ASSET_ZCRYPT),
    ];
    let spends: Vec<Spend> = coins.iter().map(|c| spend_of(node, c)).collect();
    let notes = vec![keys::cover_note_bytes(), note(to, amount, pay_blind, ASSET_ZCRYPT), note(from, change, chg_blind, ASSET_ZCRYPT)];
    let tx = shield_tx::build(CHAIN, &spends, &outs, 0, notes).expect("native transfer proof");
    (tx, burn_blind, from.own_coin(change, chg_blind))
}

/// What `who` receives from a tx's notes.
fn received(who: &Account, tx: &ShieldTx) -> Vec<Coin> {
    tx.enc_notes.iter().filter_map(|n| who.receive(&zcrypt_core::kem::ciphertext_from_bytes(n)?)).collect()
}

#[test]
fn a_single_zcrypt_coin_pays_moves_and_keeps_change_in_one_proof() {
    let mut node = Node::new();
    decoys(&mut node, ASSET_ZCRYPT);
    let alice = Account::from_seed([1u8; 32]);
    let bob = Account::from_seed([2u8; 32]);
    // THE formerly stranded position: exactly one ZCRYPT coin.
    let only = seed(&mut node, alice.own_coin(500_000_000, keys::random_blind()));
    let (tx, burn_blind, change) = native_transfer(&node, &alice, &[only], &bob, 100_000_000, MIN_FEE);
    assert_eq!(tx.output_commitments.len(), N_OUT);
    node.check_zcrypt_transfer(CHAIN, &tx, MIN_FEE, burn_blind).expect("mempool accepts");
    node.precheck_zcrypt_transfer(&tx, MIN_FEE, burn_blind).expect("proof-free precheck accepts");
    let receipt = node.submit_zcrypt_transfer(CHAIN, &tx, MIN_FEE, burn_blind).expect("one coin, one proof");
    assert_eq!(receipt.nullifiers.len(), 2, "real + dummy slot, like every spend");
    let got = received(&bob, &tx);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].value, got[0].asset_id), (100_000_000, ASSET_ZCRYPT));
    assert_eq!(change.value, 500_000_000 - 100_000_000 - MIN_FEE);
    // The change is spendable at once, again alone, again paying its own gas.
    let carol = Account::from_seed([3u8; 32]);
    let (tx2, blind2, change2) = native_transfer(&node, &alice, &[change], &carol, 1_000, MIN_FEE);
    node.submit_zcrypt_transfer(CHAIN, &tx2, MIN_FEE, blind2).expect("change coin spends alone");
    assert_eq!(received(&carol, &tx2)[0].value, 1_000);
    // STRANDED VALUE: sweep the whole coin. amount = value − fee leaves a 0 change coin, and
    // nothing is left behind.
    let (tx3, blind3, change3) = native_transfer(&node, &alice, &[change2], &carol, change2.value - MIN_FEE, MIN_FEE);
    assert_eq!(change3.value, 0);
    node.submit_zcrypt_transfer(CHAIN, &tx3, MIN_FEE, blind3).expect("whole-coin sweep");
    assert_eq!(received(&carol, &tx3)[0].value, change2.value - MIN_FEE);
    // Two coins still work (the usual shape), and bob's received coin spends alone too.
    let bob2 = seed(&mut node, bob.own_coin(70_000, keys::random_blind()));
    let bob_coins: Vec<Coin> = received(&bob, &tx).into_iter().chain([bob2]).collect();
    let (tx4, blind4, _) = native_transfer(&node, &bob, &bob_coins, &alice, 100_000_000, MIN_FEE);
    node.submit_zcrypt_transfer(CHAIN, &tx4, MIN_FEE, blind4).expect("two-coin native transfer");
}

#[test]
fn dust_can_absorb_into_the_burn_and_the_burn_is_public_but_bounded() {
    // A coin of amount + fee + dust: the wallet may burn the dust rather than keep a dust coin.
    let mut node = Node::new();
    decoys(&mut node, ASSET_ZCRYPT);
    let alice = Account::from_seed([4u8; 32]);
    let bob = Account::from_seed([5u8; 32]);
    let coin = seed(&mut node, alice.own_coin(1_000_000 + MIN_FEE + 7, keys::random_blind()));
    let (tx, blind, change) = native_transfer(&node, &alice, &[coin], &bob, 1_000_000, MIN_FEE + 7);
    assert_eq!(change.value, 0);
    node.submit_zcrypt_transfer(CHAIN, &tx, MIN_FEE + 7, blind).expect("overpaid burn is allowed");
    // A coin BELOW the fee cannot move (there is nothing to pay with) — but it is not lost:
    // it is a normal coin that spends together with any later coin.
    let dust = seed(&mut node, alice.own_coin(MIN_FEE - 1, keys::random_blind()));
    let fresh = seed(&mut node, alice.own_coin(50_000, keys::random_blind()));
    let (tx2, blind2, _) = native_transfer(&node, &alice, &[dust, fresh], &bob, 30_000, MIN_FEE);
    node.submit_zcrypt_transfer(CHAIN, &tx2, MIN_FEE, blind2).expect("dust rides along with a later coin");
}

#[test]
fn native_transfer_adversarial_shapes_are_refused() {
    let mut node = Node::new();
    decoys(&mut node, ASSET_ZCRYPT);
    let alice = Account::from_seed([6u8; 32]);
    let bob = Account::from_seed([7u8; 32]);
    let coin = seed(&mut node, alice.own_coin(1_000_000, keys::random_blind()));

    // Burn below MIN_FEE: a valid proof, refused by the header rule before any proof work.
    let (tx, blind, _) = native_transfer(&node, &alice, &[coin.clone()], &bob, 10_000, MIN_FEE - 1);
    for e in [
        node.precheck_zcrypt_transfer(&tx, MIN_FEE - 1, blind).unwrap_err(),
        node.check_zcrypt_transfer(CHAIN, &tx, MIN_FEE - 1, blind).unwrap_err(),
        node.submit_zcrypt_transfer(CHAIN, &tx, MIN_FEE - 1, blind).unwrap_err(),
    ] {
        assert!(e.contains("burn must be ≥ MIN_FEE"), "{e}");
    }
    // Declaring MIN_FEE over a MIN_FEE−1 burn: the declared coin is not output[0].
    let e = node.submit_zcrypt_transfer(CHAIN, &tx, MIN_FEE, blind).unwrap_err();
    assert!(e.contains("not the declared burn coin"), "{e}");

    // A good proof with a wrong declared blind, or a wrong declared value: refused.
    let (tx, blind, _) = native_transfer(&node, &alice, &[coin.clone()], &bob, 10_000, MIN_FEE);
    let mut wrong = blind;
    wrong[0] ^= 1;
    assert!(node.submit_zcrypt_transfer(CHAIN, &tx, MIN_FEE, wrong).unwrap_err().contains("not the declared burn coin"));
    assert!(node.submit_zcrypt_transfer(CHAIN, &tx, MIN_FEE + 1, blind).unwrap_err().contains("not the declared burn coin"));
    // Aliased declared value (same commitment under the limb reduction): refused by the bound.
    let aliased = MIN_FEE + (zcrypt_shield::FIELD_ORDER << zcrypt_shield::SHIFT);
    assert!(node.submit_zcrypt_transfer(CHAIN, &tx, aliased, blind).is_err());

    // An in-tx fee on a native transfer: refused (the burn coin is the only fee channel).
    {
        let burn_blind = keys::random_blind();
        let outs: [OutCoin; 3] = [
            (MIN_FEE, burn_blind, BURN_PK, ASSET_ZCRYPT),
            (10_000, keys::random_blind(), bob.pubkey(), ASSET_ZCRYPT),
            (1_000_000 - 10_000 - MIN_FEE - 5, keys::random_blind(), alice.pubkey(), ASSET_ZCRYPT),
        ];
        let feed = shield_tx::build(CHAIN, &[spend_of(&node, &coin)], &outs, 5, vec![keys::cover_note_bytes(); 3]).unwrap();
        let e = node.submit_zcrypt_transfer(CHAIN, &feed, MIN_FEE, burn_blind).unwrap_err();
        assert!(e.contains("in-tx fee must be 0"), "{e}");
    }

    // A transfer whose output[0] is NOT a burn (two ordinary outputs + pad): the declared
    // burn coin does not match anything, however it is declared.
    {
        let outs: [OutCoin; 2] = [
            (10_000, keys::random_blind(), bob.pubkey(), ASSET_ZCRYPT),
            (1_000_000 - 10_000, keys::random_blind(), alice.pubkey(), ASSET_ZCRYPT),
        ];
        let plain = shield_tx::build(CHAIN, &[spend_of(&node, &coin)], &outs, 0, vec![keys::cover_note_bytes(); 2]).unwrap();
        let e = node.submit_zcrypt_transfer(CHAIN, &plain, MIN_FEE, keys::random_blind()).unwrap_err();
        assert!(e.contains("not the declared burn coin"), "{e}");
        // ...and a free transfer (no gas at all) is not accepted on the plain path either:
        // the plain path only exists behind the 0x55 bundle, which needs a gas note.
    }

    // A NON-ZCRYPT spend cannot pose as a ZCRYPT transfer: its burn coin commits to its own
    // asset, so it never equals commit_asset(…, ZCRYPT).
    {
        let gold = node.register_asset("GOLD", 8, None, 21_000_000 * 100_000_000).unwrap();
        decoys(&mut node, gold);
        let gcoin = seed(&mut node, alice.own_asset_coin(1_000_000, keys::random_blind(), gold));
        let burn_blind = keys::random_blind();
        let outs: [OutCoin; 3] = [
            (MIN_FEE, burn_blind, BURN_PK, gold),
            (10_000, keys::random_blind(), bob.pubkey(), gold),
            (1_000_000 - 10_000 - MIN_FEE, keys::random_blind(), alice.pubkey(), gold),
        ];
        let gtx = shield_tx::build(CHAIN, &[spend_of(&node, &gcoin)], &outs, 0, vec![keys::cover_note_bytes(); 3]).unwrap();
        let e = node.submit_zcrypt_transfer(CHAIN, &gtx, MIN_FEE, burn_blind).unwrap_err();
        assert!(e.contains("not the declared burn coin"), "{e}");
    }

    // The honest transfer lands; replaying it (same nullifiers) is a double-spend.
    let (tx, blind, _) = native_transfer(&node, &alice, &[coin.clone()], &bob, 10_000, MIN_FEE);
    node.submit_zcrypt_transfer(CHAIN, &tx, MIN_FEE, blind).expect("honest");
    let e = node.submit_zcrypt_transfer(CHAIN, &tx, MIN_FEE, blind).unwrap_err();
    assert!(e.contains("double-spend") || e.contains("already"), "{e}");
    let e = node.precheck_zcrypt_transfer(&tx, MIN_FEE, blind).unwrap_err();
    assert!(e.contains("double-spend") || e.contains("already"), "{e}");
    // A second spend of the same coin with a fresh proof is a double-spend too.
    let (tx2, blind2, _) = native_transfer(&node, &alice, &[coin], &bob, 20_000, MIN_FEE);
    assert!(node.submit_zcrypt_transfer(CHAIN, &tx2, MIN_FEE, blind2).unwrap_err().contains("double-spend"));
}

// ---------------------------------------------------------------------------------------
// Sponsored swap locks
// ---------------------------------------------------------------------------------------

struct Lock {
    tx: ShieldTx,
    value: u64,
    blind: Blind,
    asset: u64,
    hashlock: [u8; 32],
    timeout: u64,
    counterparty: zcrypt_shield::PubKey,
    refund: zcrypt_shield::PubKey,
    claim_open: CoinOpening,
    refund_open: CoinOpening,
    change: Coin,
    id: [u8; 32],
}

/// Build (do not submit) a native swap lock of `value` of `asset` from `locker`'s `coins`,
/// claimable by `counterparty`, with in-tx `fee`. `change` returns to the locker.
#[allow(clippy::too_many_arguments)]
fn native_lock(
    node: &Node,
    locker: &Account,
    coins: &[Coin],
    asset: u64,
    value: u64,
    fee: u64,
    hashlock: [u8; 32],
    timeout: u64,
    counterparty: &Account,
) -> Lock {
    let total: u64 = coins.iter().map(|c| c.value).sum();
    let change_v = total - value - fee;
    let blind = keys::random_blind();
    let chg_blind = keys::random_blind();
    let (_cb, claim_open) = CoinOpening::create(&counterparty.normal_address(), value, asset).unwrap();
    let (_rb, refund_open) = CoinOpening::create(&locker.normal_address(), value, asset).unwrap();
    let envelope = zcrypt_core::htlc_shield::lock_envelope(
        zcrypt_core::htlc_shield::ENV_SWAP_LOCK,
        asset, value, &hashlock, timeout, &counterparty.pubkey(), &locker.pubkey(), &[],
        &[claim_open.coin.clone(), refund_open.coin.clone()],
    );
    let outs: [OutCoin; 2] = [(value, blind, BURN_PK, asset), (change_v, chg_blind, locker.pubkey(), asset)];
    let spends: Vec<Spend> = coins.iter().map(|c| spend_of(node, c)).collect();
    let tx = shield_tx::build_bound(CHAIN, &spends, &outs, fee, vec![keys::cover_note_bytes(), note(locker, change_v, chg_blind, asset)], &envelope)
        .expect("lock proof");
    let id = escrow_id(EscrowKind::Swap, asset, value, &hashlock, timeout, &counterparty.pubkey(), &locker.pubkey());
    Lock {
        tx, value, blind, asset, hashlock, timeout,
        counterparty: counterparty.pubkey(), refund: locker.pubkey(),
        claim_open, refund_open, change: locker.own_asset_coin(change_v, chg_blind, asset), id,
    }
}

fn submit_lock(node: &mut Node, l: &Lock, sponsor_ref: [u8; 32]) -> Result<[u8; 32], String> {
    // The mempool mirror must agree with delivery on every refusal.
    let pre = node.precheck_swap_lock_native(
        l.asset, l.value, &l.hashlock, l.timeout, &l.counterparty, &l.refund, &sponsor_ref, l.tx.fee,
        &[l.claim_open.coin.commitment, l.refund_open.coin.commitment],
    );
    let out = node.swap_lock_native(
        CHAIN, &l.tx, l.value, l.blind, l.asset, l.hashlock, l.timeout, l.counterparty, l.refund, sponsor_ref,
        &l.claim_open, &l.refund_open,
    );
    assert_eq!(pre.is_ok(), out.is_ok(), "precheck {pre:?} vs delivery {out:?}");
    out
}

/// The coin an escrow's claim note opens for `who`.
fn claim_coin(node: &Node, id: &[u8; 32], who: &Account) -> Coin {
    let e = node.htlc_escrow(id).expect("escrow");
    let n = &e.claim_coin.as_ref().expect("claim coin").enc_note;
    who.receive(&zcrypt_core::kem::ciphertext_from_bytes(n).unwrap()).expect("claim note opens")
}

struct Swap {
    node: Node,
    lp: Account,
    newcomer: Account,
    gold: u64,
    preimage: [u8; 32],
    hashlock: [u8; 32],
}

/// An LP with ZCRYPT and a newcomer with ONLY a non-ZCRYPT asset ("zBTC-only wallet").
fn setup() -> Swap {
    let mut node = Node::new();
    node.set_height(100);
    let gold = node.register_asset("GOLD", 8, None, 21_000_000 * 100_000_000).unwrap();
    decoys(&mut node, ASSET_ZCRYPT);
    decoys(&mut node, gold);
    let preimage = [0x77u8; 32];
    Swap { node, lp: Account::from_seed([0xA1; 32]), newcomer: Account::from_seed([0xB2; 32]), gold, preimage, hashlock: htlc_hashlock(&preimage) }
}

/// LP timeout (shorter: the newcomer claims it and reveals the preimage) and the newcomer's
/// (longer: the LP claims it afterwards).
const LP_TIMEOUT: u64 = 600;
const NEWCOMER_TIMEOUT: u64 = 900;
const ZC_GIVE: u64 = 20_000_000; // 20 ZCRYPT for
const GOLD_GIVE: u64 = 5_000_000; // 0.05 GOLD

/// The id of the newcomer's lock the LP agrees to sponsor.
fn newcomer_lock_id(s: &Swap, value: u64, timeout: u64) -> [u8; 32] {
    escrow_id(EscrowKind::Swap, s.gold, value, &s.hashlock, timeout, &s.lp.pubkey(), &s.newcomer.pubkey())
}

#[test]
fn a_wallet_with_zero_zcrypt_swaps_into_zcrypt_and_is_never_stranded() {
    let mut s = setup();
    let lp_coin = seed(&mut s.node, s.lp.own_coin(100_000_000, keys::random_blind()));
    let gold_coin = seed(&mut s.node, s.newcomer.own_asset_coin(GOLD_GIVE + 1_000, keys::random_blind(), s.gold));
    // 1. The LP locks ZCRYPT FIRST, from ONE coin, burning 2 × MIN_FEE and naming the exact
    //    counter-lock it pays for.
    let target = newcomer_lock_id(&s, GOLD_GIVE, NEWCOMER_TIMEOUT);
    let lp_lock = native_lock(&s.node, &s.lp, &[lp_coin], ASSET_ZCRYPT, ZC_GIVE, 2 * MIN_FEE, s.hashlock, LP_TIMEOUT, &s.newcomer);
    let lp_id = submit_lock(&mut s.node, &lp_lock, target).expect("LP's sponsoring lock");
    let e = s.node.htlc_escrow(&lp_id).unwrap();
    assert_eq!(e.sponsor_for, Some(target));
    assert!(!e.sponsor_used);
    assert_eq!(lp_lock.change.value, 100_000_000 - ZC_GIVE - 2 * MIN_FEE);
    // 2. The newcomer (ZERO ZCRYPT) locks GOLD with fee 0 and no gas note, sponsored.
    let nc_lock = native_lock(&s.node, &s.newcomer, &[gold_coin], s.gold, GOLD_GIVE, 0, s.hashlock, NEWCOMER_TIMEOUT, &s.lp);
    assert_eq!(nc_lock.id, target, "the LP named exactly this lock");
    let nc_id = submit_lock(&mut s.node, &nc_lock, lp_id).expect("sponsored lock, no ZCRYPT anywhere");
    assert!(s.node.htlc_escrow(&lp_id).unwrap().sponsor_used, "the sponsorship is spent");
    assert!(s.node.htlc_escrow(&nc_id).unwrap().sponsor_for.is_none(), "a GOLD lock sponsors nothing");
    // 3. The newcomer claims the LP's ZCRYPT (a claim is gas-free), revealing the preimage.
    s.node.htlc_claim(&lp_id, &s.preimage).expect("claim ZCRYPT");
    let zc = claim_coin(&s.node, &lp_id, &s.newcomer);
    assert_eq!((zc.value, zc.asset_id), (ZC_GIVE, ASSET_ZCRYPT));
    // 4. The LP claims the GOLD with the now-public preimage.
    s.node.htlc_claim(&nc_id, &s.preimage).expect("claim GOLD");
    let g = claim_coin(&s.node, &nc_id, &s.lp);
    assert_eq!((g.value, g.asset_id), (GOLD_GIVE, s.gold));
    assert_eq!(s.node.htlc_escrow(&lp_id).unwrap().state, EscrowState::Claimed);
    assert_eq!(s.node.htlc_escrow(&nc_id).unwrap().state, EscrowState::Claimed);
    // 5. The newcomer now holds exactly ONE ZCRYPT coin, and spends it alone.
    let somebody = Account::from_seed([0xC3; 32]);
    let (tx, blind, change) = native_transfer(&s.node, &s.newcomer, &[zc], &somebody, 1_000_000, MIN_FEE);
    s.node.submit_zcrypt_transfer(CHAIN, &tx, MIN_FEE, blind).expect("the former zero-ZCRYPT wallet pays its own gas");
    assert_eq!(change.value, ZC_GIVE - 1_000_000 - MIN_FEE);
    // 6. The swapped-in GOLD change and the LP's ZCRYPT change are ordinary coins: the LP's
    //    change spends alone too (one coin, in-proof fee).
    let (tx2, blind2, _) = native_transfer(&s.node, &s.lp, &[lp_lock.change], &somebody, 5, MIN_FEE);
    s.node.submit_zcrypt_transfer(CHAIN, &tx2, MIN_FEE, blind2).expect("LP change spends alone");
}

#[test]
fn a_single_zcrypt_coin_can_open_a_plain_native_swap_lock() {
    // No sponsorship: a ZCRYPT lock from one coin burns MIN_FEE in-proof. Nothing else needed.
    let mut s = setup();
    let only = seed(&mut s.node, s.lp.own_coin(ZC_GIVE + MIN_FEE, keys::random_blind()));
    let lock = native_lock(&s.node, &s.lp, &[only], ASSET_ZCRYPT, ZC_GIVE, MIN_FEE, s.hashlock, LP_TIMEOUT, &s.newcomer);
    assert_eq!(lock.change.value, 0);
    let id = submit_lock(&mut s.node, &lock, NO_SPONSOR).expect("1× fee, sponsors nothing");
    assert_eq!(s.node.htlc_escrow(&id).unwrap().sponsor_for, None);
    // Timeout refund works as for any swap lock.
    s.node.set_height(LP_TIMEOUT);
    s.node.htlc_expire(&id).expect("expire");
    assert_eq!(s.node.htlc_escrow(&id).unwrap().state, EscrowState::Expired);
}

#[test]
fn gas_free_locks_without_a_valid_sponsor_are_refused() {
    let mut s = setup();
    let gold_coins: Vec<Coin> = (0..8).map(|k| seed(&mut s.node, s.newcomer.own_asset_coin(GOLD_GIVE + k, keys::random_blind(), s.gold))).collect();
    let lp_coins: Vec<Coin> = (0..6).map(|_| seed(&mut s.node, s.lp.own_coin(100_000_000, keys::random_blind()))).collect();
    let mk_nc = |node: &Node, coin: &Coin, timeout: u64| native_lock(node, &s.newcomer, &[coin.clone()], s.gold, GOLD_GIVE, 0, s.hashlock, timeout, &s.lp);

    // (a) no sponsor named at all
    let l = mk_nc(&s.node, &gold_coins[0], NEWCOMER_TIMEOUT);
    let e = submit_lock(&mut s.node, &l, NO_SPONSOR).unwrap_err();
    assert!(e.contains("must name the ZCRYPT swap lock that sponsors it"), "{e}");
    // (b) a sponsor that does not exist
    let e = submit_lock(&mut s.node, &l, [0x42; 32]).unwrap_err();
    assert!(e.contains("no such escrow"), "{e}");
    // (c) an in-asset fee on a non-ZCRYPT native lock (the locked asset is never the gas)
    let paid = native_lock(&s.node, &s.newcomer, &[gold_coins[1].clone()], s.gold, GOLD_GIVE, 1, s.hashlock, NEWCOMER_TIMEOUT, &s.lp);
    let e = submit_lock(&mut s.node, &paid, NO_SPONSOR).unwrap_err();
    assert!(e.contains("must have fee 0"), "{e}");

    // (d) a ZCRYPT lock that NAMES a counter-lock but burns only 1× MIN_FEE: refused.
    let target = newcomer_lock_id(&s, GOLD_GIVE, NEWCOMER_TIMEOUT);
    let cheap = native_lock(&s.node, &s.lp, &[lp_coins[0].clone()], ASSET_ZCRYPT, ZC_GIVE, MIN_FEE, s.hashlock, LP_TIMEOUT, &s.newcomer);
    let e = submit_lock(&mut s.node, &cheap, target).unwrap_err();
    assert!(e.contains("MIN_FEE for the counter-lock it sponsors"), "{e}");
    // (d') below even 1× MIN_FEE
    let free = native_lock(&s.node, &s.lp, &[lp_coins[0].clone()], ASSET_ZCRYPT, ZC_GIVE, MIN_FEE - 1, s.hashlock, LP_TIMEOUT, &s.newcomer);
    assert!(submit_lock(&mut s.node, &free, NO_SPONSOR).unwrap_err().contains("must burn ≥"));
    // (d'') self-sponsoring
    let selfish = native_lock(&s.node, &s.lp, &[lp_coins[0].clone()], ASSET_ZCRYPT, ZC_GIVE, 2 * MIN_FEE, s.hashlock, LP_TIMEOUT, &s.newcomer);
    assert!(submit_lock(&mut s.node, &selfish, selfish.id).unwrap_err().contains("cannot sponsor itself"));

    // (e) a plain 1× ZCRYPT lock exists; a gas-free lock pointing at it is refused: it did
    //     not burn the second fee.
    let plain = native_lock(&s.node, &s.lp, &[lp_coins[0].clone()], ASSET_ZCRYPT, ZC_GIVE, MIN_FEE, s.hashlock, LP_TIMEOUT, &s.newcomer);
    let plain_id = submit_lock(&mut s.node, &plain, NO_SPONSOR).unwrap();
    let e = submit_lock(&mut s.node, &l, plain_id).unwrap_err();
    assert!(e.contains("did not burn a second fee"), "{e}");

    // (f) a real sponsor, but the gas-free lock is NOT the one it named (dust value, or a
    //     different timeout): refused — a stranger cannot consume the sponsorship.
    let sponsor = native_lock(&s.node, &s.lp, &[lp_coins[1].clone()], ASSET_ZCRYPT, ZC_GIVE + 1, 2 * MIN_FEE, s.hashlock, LP_TIMEOUT, &s.newcomer);
    let sponsor_id = submit_lock(&mut s.node, &sponsor, target).unwrap();
    let dust = native_lock(&s.node, &s.newcomer, &[gold_coins[2].clone()], s.gold, 1, 0, s.hashlock, NEWCOMER_TIMEOUT, &s.lp);
    assert!(submit_lock(&mut s.node, &dust, sponsor_id).unwrap_err().contains("named a different counter-lock"));
    let late = mk_nc(&s.node, &gold_coins[3], NEWCOMER_TIMEOUT + 1);
    assert!(submit_lock(&mut s.node, &late, sponsor_id).unwrap_err().contains("named a different counter-lock"));
    // (g) a different hashlock (same keys): a different id, and the sponsor's hashlock differs
    {
        let other_pre = [0x11u8; 32];
        let other_lock = htlc_hashlock(&other_pre);
        let foreign = native_lock(&s.node, &s.newcomer, &[gold_coins[4].clone()], s.gold, GOLD_GIVE, 0, other_lock, NEWCOMER_TIMEOUT, &s.lp);
        let e = submit_lock(&mut s.node, &foreign, sponsor_id).unwrap_err();
        assert!(e.contains("different hashlock") || e.contains("named a different counter-lock"), "{e}");
    }
    // (h) keys not crossed: a lock claimable by a third party, refunding to the newcomer
    {
        let mallory = Account::from_seed([0xD4; 32]);
        let crossed_wrong = native_lock(&s.node, &s.newcomer, &[gold_coins[5].clone()], s.gold, GOLD_GIVE, 0, s.hashlock, NEWCOMER_TIMEOUT, &mallory);
        let e = submit_lock(&mut s.node, &crossed_wrong, sponsor_id).unwrap_err();
        assert!(e.contains("keys are not crossed") || e.contains("named a different counter-lock"), "{e}");
        // ...and a lock by MALLORY (refund to Mallory) claimable by the LP
        let mcoin = seed(&mut s.node, mallory.own_asset_coin(GOLD_GIVE, keys::random_blind(), s.gold));
        let impostor = native_lock(&s.node, &mallory, &[mcoin], s.gold, GOLD_GIVE, 0, s.hashlock, NEWCOMER_TIMEOUT, &s.lp);
        let e = submit_lock(&mut s.node, &impostor, sponsor_id).unwrap_err();
        assert!(e.contains("keys are not crossed") || e.contains("named a different counter-lock"), "{e}");
    }
    // (i) the exact named lock is accepted; the sponsorship is then spent. Nothing above
    //     consumed it, and none of the refused locks burned a coin.
    let e_before = s.node.htlc_escrow(&sponsor_id).unwrap().clone();
    assert!(!e_before.sponsor_used);
    let good = mk_nc(&s.node, &gold_coins[0], NEWCOMER_TIMEOUT);
    let good_id = submit_lock(&mut s.node, &good, sponsor_id).expect("the named counter-lock");
    assert!(s.node.htlc_escrow(&sponsor_id).unwrap().sponsor_used);
    // (j) double sponsorship: the same lock again is a duplicate id; a re-built lock with the
    //     same parameters from other coins is refused on the id before any coin burns.
    let again = mk_nc(&s.node, &gold_coins[6], NEWCOMER_TIMEOUT);
    assert_eq!(again.id, good_id);
    assert!(submit_lock(&mut s.node, &again, sponsor_id).is_err());
    // the refused duplicate's coin is still unspent: it can lock under a fresh sponsor later
    assert!(s.node.htlc_escrow(&good_id).unwrap().state == EscrowState::Open);

    // (k) a settled sponsor is no sponsor: the newcomer claims a second LP lock BEFORE locking
    //     (it has the preimage), then tries to lock gas-free against it.
    let target2 = newcomer_lock_id(&s, GOLD_GIVE + 7, NEWCOMER_TIMEOUT);
    let sponsor2 = native_lock(&s.node, &s.lp, &[lp_coins[2].clone()], ASSET_ZCRYPT, ZC_GIVE + 2, 2 * MIN_FEE, s.hashlock, LP_TIMEOUT, &s.newcomer);
    let sponsor2_id = submit_lock(&mut s.node, &sponsor2, target2).unwrap();
    s.node.htlc_claim(&sponsor2_id, &s.preimage).unwrap();
    let matching = native_lock(&s.node, &s.newcomer, &[gold_coins[7].clone()], s.gold, GOLD_GIVE + 7, 0, s.hashlock, NEWCOMER_TIMEOUT, &s.lp);
    assert_eq!(matching.id, target2);
    let e = submit_lock(&mut s.node, &matching, sponsor2_id).unwrap_err();
    assert!(e.contains("not open"), "{e}");

    // (l) an EXPIRED sponsor is no sponsor.
    let target3 = newcomer_lock_id(&s, GOLD_GIVE + 3, NEWCOMER_TIMEOUT);
    let sponsor3 = native_lock(&s.node, &s.lp, &[lp_coins[3].clone()], ASSET_ZCRYPT, ZC_GIVE + 3, 2 * MIN_FEE, s.hashlock, LP_TIMEOUT, &s.newcomer);
    let sponsor3_id = submit_lock(&mut s.node, &sponsor3, target3).unwrap();
    s.node.set_height(LP_TIMEOUT);
    let gc = seed(&mut s.node, s.newcomer.own_asset_coin(GOLD_GIVE + 3, keys::random_blind(), s.gold));
    let late_nc = native_lock(&s.node, &s.newcomer, &[gc], s.gold, GOLD_GIVE + 3, 0, s.hashlock, NEWCOMER_TIMEOUT, &s.lp);
    let e = submit_lock(&mut s.node, &late_nc, sponsor3_id).unwrap_err();
    assert!(e.contains("not open"), "{e}");
}

#[test]
fn a_zcrypt_taker_can_sponsor_the_maker_too() {
    // The symmetric direction: the party GIVING ZCRYPT locks first whichever role it plays.
    // Here the ZCRYPT giver holds the preimage (taker), locks with the longer timeout and
    // names the maker's shorter-lived GOLD lock; the maker (no ZCRYPT) locks gas-free second.
    let mut s = setup();
    let zc_coin = seed(&mut s.node, s.lp.own_coin(ZC_GIVE + 2 * MIN_FEE, keys::random_blind()));
    let gold_coin = seed(&mut s.node, s.newcomer.own_asset_coin(GOLD_GIVE, keys::random_blind(), s.gold));
    let (give_t, take_t) = (NEWCOMER_TIMEOUT, LP_TIMEOUT); // giver's lock lives longer
    let maker_id = escrow_id(EscrowKind::Swap, s.gold, GOLD_GIVE, &s.hashlock, take_t, &s.lp.pubkey(), &s.newcomer.pubkey());
    let giver = native_lock(&s.node, &s.lp, &[zc_coin], ASSET_ZCRYPT, ZC_GIVE, 2 * MIN_FEE, s.hashlock, give_t, &s.newcomer);
    assert_eq!(giver.change.value, 0, "the whole coin: value + both fees");
    let giver_id = submit_lock(&mut s.node, &giver, maker_id).unwrap();
    let maker = native_lock(&s.node, &s.newcomer, &[gold_coin], s.gold, GOLD_GIVE, 0, s.hashlock, take_t, &s.lp);
    let got = submit_lock(&mut s.node, &maker, giver_id).expect("maker's gas-free lock");
    assert_eq!(got, maker_id);
    // Settle: the ZCRYPT giver (preimage holder) claims GOLD, the maker reads the preimage
    // and claims ZCRYPT.
    s.node.htlc_claim(&maker_id, &s.preimage).unwrap();
    s.node.htlc_claim(&giver_id, &s.preimage).unwrap();
    assert_eq!(claim_coin(&s.node, &maker_id, &s.lp).asset_id, s.gold);
    assert_eq!(claim_coin(&s.node, &giver_id, &s.newcomer).value, ZC_GIVE);
}
