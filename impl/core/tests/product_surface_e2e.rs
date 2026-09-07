//! Full **product-surface** end-to-end walk against the real consensus `Node`.
//!
//! One test drives every user-facing flow in sequence — mint, staking rewards,
//! private transfers to normal/stealth/bearer recipients, and shielded-asset
//! issuance — and a second asserts the abuse cases are all rejected. This is the
//! "is the whole product green?" test: it exercises the same `Node` state machine
//! the ABCI app wraps, so a pass means the flows are correct end-to-end (multi-node
//! *consensus* over this same logic is covered by the 3-node docker stack).

use zcrypt_core::emission::{self, ATOMIC};
use zcrypt_core::htlc_shield::mint_capability;
use zcrypt_core::keys::{self, Account, BearerCoin, Coin};
use zcrypt_core::kem;
use zcrypt_core::mint_auth::{self, MintKeySet, MintSigner};
use zcrypt_core::node::Node;
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_core::shield_tx::{self, ShieldTx, Spend};
use zcrypt_shield::OutCoin;

const CHAIN: &[u8] = b"zcrypt-devnet";

/// Open a mint escrow with a valid M-of-N authorization over the exact mint params.
fn open_mint(
    node: &mut Node,
    ks: &MintKeySet,
    signers: &[MintSigner],
    asset: u64,
    value: u64,
    lock: [u8; 32],
    timeout: u64,
    pk: [u64; 8],
) -> Result<[u8; 32], String> {
    let msg = mint_auth::mint_message(CHAIN, asset, value, &lock, timeout, &pk);
    let sigs = mint_auth::authorize(ks, signers, &msg);
    node.htlc_open(CHAIN, asset, value, lock, timeout, pk, ks, &sigs)
}

/// A 32-byte preimage from a short label (consensus accepts exactly 32 bytes).
fn pre(label: &str) -> [u8; 32] {
    let mut p = [0x2Au8; 32];
    p[..label.len().min(32)].copy_from_slice(&label.as_bytes()[..label.len().min(32)]);
    p
}
/// Two fixed-size cover notes (consensus pins the note shape).
fn notes() -> Vec<Vec<u8>> {
    vec![keys::cover_note_bytes(), keys::cover_note_bytes()]
}
/// Every value-moving action burns at least this (0.01 ZCRYPT) — the universal-gas floor.
const FEE: u64 = emission::MIN_FEE;

/// Seed `n` unrelated coins so shield spends hide among a non-trivial pool.
fn seed_decoys(node: &mut Node, n: u64) {
    for k in 0..n {
        let a = Account::from_seed([(0x40 + k) as u8; 32]);
        let c = a.own_coin(1_000 + k, [k + 3, k + 7, (k + 3).wrapping_add(1), (k + 7).wrapping_add(1)]);
        node.seed_coin(c.commitment());
    }
}

/// Build a shield spend of `inputs` (owned coins already on chain) into `outs`,
/// resolving each input's Merkle path from the node's current tree — exactly what a
/// wallet does. Membership is proven against the whole shielded pool (no ring).
fn build_shield(
    node: &Node,
    inputs: &[Coin],
    outs: [OutCoin; 2],
    fee: u64,
    notes: Vec<Vec<u8>>,
) -> Result<ShieldTx, String> {
    build_shield_bound(node, inputs, outs, fee, notes, &[])
}

/// [`build_shield`] with the proof bound to an escrow-lock envelope (what every lock tx does).
fn build_shield_bound(
    node: &Node,
    inputs: &[Coin],
    outs: [OutCoin; 2],
    fee: u64,
    notes: Vec<Vec<u8>>,
    envelope: &[u8],
) -> Result<ShieldTx, String> {
    let leaves = node.commitment_leaves();
    let mut spends = Vec::new();
    for c in inputs {
        let idx = leaves
            .iter()
            .position(|x| *x == c.commitment())
            .ok_or("input coin not on chain")? as u32;
        let (path_siblings, path_dirs) = node.commitment_path(idx as usize).ok_or("no path")?;
        spends.push(Spend {
            value: c.value,
            blind: c.blind,
            spend_secret: c.spend_secret,
            asset_id: c.asset_id,
            path_siblings,
            path_dirs,
        });
    }
    shield_tx::build_bound(CHAIN, &spends, &outs, fee, notes, envelope)
        .ok_or_else(|| "prove failed".to_string())
}

/// Scan a just-applied tx's encrypted notes and return the coin `who` can receive.
fn scan_for(who: &Account, tx: &ShieldTx) -> Option<Coin> {
    tx.enc_notes.iter().find_map(|n| {
        let ct = kem::ciphertext_from_bytes(n)?;
        who.receive(&ct)
    })
}

#[test]
fn full_product_surface_happy_path() {
    let mut node = Node::new();

    // ---- 0. Genesis: one-time foundation allocation, vesting-gated — only the
    // liquid tranche counts as issued at height 0 ----
    node.mint_foundation([0xF0; 32]);
    assert_eq!(node.total_issued(), emission::FOUNDATION_LIQUID);
    seed_decoys(&mut node, 20); // seed a non-trivial shielded pool to hide among

    let (alice, _mn_a) = keys::new_account();
    let (bob, _mn_b) = keys::new_account();

    // ---- 1. Mint / fund ZCRYPT (devnet faucet seeds an owned coin) ----
    let a_fund = alice.own_coin(1_000_000, keys::random_blind());
    node.seed_coin(a_fund.commitment());
    eprintln!("[1] funded Alice with 1,000,000 base-unit ZCRYPT");

    // ---- 2. Bond a validator, run an epoch, receive block rewards ----
    let cons_pk = b"alice-consensus-key";
    node.bond(cons_pk.to_vec(), cons_pk.to_vec(), 10_000 * ATOMIC, alice.reward_address(), zcrypt_core::staking::DEFAULT_COMMISSION_BPS).unwrap();
    assert!(node.is_validator(cons_pk));
    for h in 1..=emission::EPOCH {
        node.set_height(h);
        node.record_block_signers(&[cons_pk.to_vec()]);
        node.maybe_distribute_rewards(h);
    }
    let owed = node.claimable(&alice.pubkey());
    assert_eq!(owed, emission::epoch_reward(emission::EPOCH));
    eprintln!("[2] bonded + accrued one epoch's block reward: {owed}");

    // ---- 3. Claim (mint) reward into spendable coinbase coin(s), then SPEND them ----
    // Claiming is gasless; the first claim reserves a gas coin, so the reward arrives as
    // [1 ZCRYPT gas coin, rest]. Reconstruct and spend both (≤ N_IN inputs) as the reward.
    let reward_start = node.claim_index(&alice.pubkey());
    let claimed_val = owed;
    let minted = node.claim_rewards(&alice.pubkey(), owed).unwrap();
    let chunks = keys::claim_chunks(owed, reward_start == 0);
    assert_eq!(minted.len(), chunks.len());
    let reward_coins: Vec<_> = chunks
        .iter()
        .enumerate()
        .map(|(i, &v)| alice.reward_coin(v, reward_start + i as u64))
        .collect();
    for (i, c) in reward_coins.iter().enumerate() {
        assert_eq!(c.commitment(), minted[i], "rebuild minted coin {i}");
    }
    // Spend the whole reward: pay some to Bob (normal addr), change back to Alice.
    let pay = claimed_val - 100 - FEE;
    let blind_pay = keys::random_blind();
    let blind_chg = keys::random_blind();
    let out_bob = keys::out_coin(&bob.normal_address(), pay, blind_pay);
    let out_chg = keys::out_coin(&alice.normal_address(), 100, blind_chg); // + FEE burned
    let note_bob = kem::ciphertext_to_bytes(&keys::encrypt_note(&bob.normal_address(), pay, blind_pay));
    let note_chg = kem::ciphertext_to_bytes(&keys::encrypt_note(&alice.normal_address(), 100, blind_chg));
    let tx = build_shield(&node, &reward_coins, [out_bob, out_chg], FEE, vec![note_bob, note_chg]).unwrap();
    node.submit_shield(CHAIN, &tx).expect("reward coin is spendable");
    eprintln!("[3] claimed the reward into a coin and spent it privately");

    // ---- 4. Normal-address receive: Bob discovers his coin by scanning ----
    let bob_coin = scan_for(&bob, &tx).expect("Bob receives the note addressed to him");
    assert_eq!(bob_coin.value, pay);
    assert_eq!(bob_coin.asset_id, 0);
    eprintln!("[4] Bob scanned the block and received {}", bob_coin.value);

    // ---- 5. Bob SPENDS his received coin (normal send onward) to Alice ----
    let b0 = keys::random_blind();
    let b1 = keys::random_blind();
    let to_alice = keys::out_coin(&alice.normal_address(), bob_coin.value - FEE, b0);
    let bob_change = keys::out_coin(&bob.normal_address(), 0, b1);
    let n0 = kem::ciphertext_to_bytes(&keys::encrypt_note(&alice.normal_address(), bob_coin.value - FEE, b0));
    let n1 = kem::ciphertext_to_bytes(&keys::encrypt_note(&bob.normal_address(), 0, b1));
    let tx2 = build_shield(&node, &[bob_coin], [to_alice, bob_change], FEE, vec![n0, n1]).unwrap();
    node.submit_shield(CHAIN, &tx2).expect("Bob spends his received coin");
    eprintln!("[5] Bob spent his received coin onward to Alice");

    // ---- 6. Stealth-address receive: send to Bob's one-time stealth sub-account ----
    let bob_stealth = bob.stealth(0);
    let sblind = keys::random_blind();
    let cblind = keys::random_blind();
    let stealth_out = keys::out_coin(&bob_stealth.stealth_address(), 200, sblind);
    let change_out = keys::out_coin(&alice.normal_address(), a_fund.value - 200 - FEE, cblind);
    let snote = kem::ciphertext_to_bytes(&keys::encrypt_note(&bob_stealth.stealth_address(), 200, sblind));
    let cnote = kem::ciphertext_to_bytes(&keys::encrypt_note(&alice.normal_address(), a_fund.value - 200 - FEE, cblind));
    let tx3 = build_shield(&node, &[a_fund.clone()], [stealth_out, change_out], FEE, vec![snote, cnote]).unwrap();
    node.submit_shield(CHAIN, &tx3).expect("stealth send accepted");
    // The MAIN account must NOT see it; the stealth sub-account must.
    assert!(scan_for(&bob, &tx3).is_none(), "stealth output is opaque to the main account");
    let stealth_coin = scan_for(&bob_stealth, &tx3).expect("stealth sub-account receives");
    assert_eq!(stealth_coin.value, 200);
    eprintln!("[6] stealth send received only by the intended stealth sub-account");

    // ---- 7. Bearer coin: create, put on chain, sweep by holder, block double-claim ----
    let bearer = BearerCoin::create(50_000);
    node.seed_coin(bearer.coin.commitment());
    let sweep = |node: &Node, b: u64, s: u64| -> ShieldTx {
        let out0 = keys::out_coin(&Account::from_seed([s as u8; 32]).normal_address(), bearer.coin.value - FEE, [b, b + 1, (b).wrapping_add(1), (b + 1).wrapping_add(1)]);
        let out1 = keys::out_coin(&Account::from_seed([(s + 1) as u8; 32]).normal_address(), 0, [b + 2, b + 3, (b + 2).wrapping_add(1), (b + 3).wrapping_add(1)]);
        build_shield(node, &[bearer.coin.clone()], [out0, out1], FEE, notes()).unwrap()
    };
    node.submit_shield(CHAIN, &sweep(&node, 11, 0x71)).expect("bearer coin swept by holder");
    assert!(
        node.submit_shield(CHAIN, &sweep(&node, 22, 0x72)).is_err(),
        "double-claim of a bearer coin must be rejected (same nullifier)"
    );
    eprintln!("[7] bearer coin swept once; double-claim blocked");

    // ---- 8. Shielded asset (GOLD): register, mint via M-of-N authority, spend ----
    let (gold_ks, gold_signers) = mint_auth::derive_keyset(b"gold-treasury", 2, 2);
    let gold = node.register_asset("GOLD", 2, Some(gold_ks.commitment()), 1_000_000).unwrap();
    let preimage = &pre("gold-issue-preimage-0001");
    let lock = htlc_hashlock(preimage);
    node.set_height(emission::EPOCH + 1);
    let escrow =
        open_mint(&mut node, &gold_ks, &gold_signers, gold, 500_000, lock, emission::EPOCH + 100, alice.pubkey())
            .unwrap();
    let gold_minted = node.htlc_claim(&escrow, preimage).unwrap().expect("mint yields a coin");
    let gold_coin = alice.htlc_coin(500_000, gold, &escrow);
    assert_eq!(gold_coin.commitment(), gold_minted);
    assert_eq!(node.asset_minted(gold), 500_000);
    // Spend GOLD: 300k to Bob, the rest change to Alice. The fee is paid in GOLD — the
    // pool hides asset_id, so a transfer's fee is denominated in the asset it moves (a
    // non-ZCRYPT asset can't reveal it's non-ZCRYPT to pay ZCRYPT gas without breaking
    // the unified anonymity pool).
    let gb = keys::random_blind();
    let gc = keys::random_blind();
    let g_change_val = 500_000 - 300_000 - FEE;
    let g_to_bob = keys::out_asset_coin(&bob.normal_address(), 300_000, gb, gold);
    let g_change = keys::out_asset_coin(&alice.normal_address(), g_change_val, gc, gold);
    let gn0 = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&bob.normal_address(), 300_000, gb, gold));
    let gn1 = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&alice.normal_address(), g_change_val, gc, gold));
    let gtx = build_shield(&node, &[gold_coin], [g_to_bob, g_change], FEE, vec![gn0, gn1]).unwrap();
    node.submit_shield(CHAIN, &gtx).expect("GOLD is spendable");
    let bob_gold = scan_for(&bob, &gtx).expect("Bob receives GOLD");
    assert_eq!(bob_gold.value, 300_000);
    assert_eq!(bob_gold.asset_id, gold);
    eprintln!("[8] created shielded asset GOLD, minted, spent, and received");

    // ---- Invariant: issuance never exceeds the supply cap ----
    assert!(node.total_issued() <= emission::TOTAL_SUPPLY);
    eprintln!("[ok] full product surface green; issuance {} <= cap {}", node.total_issued(), emission::TOTAL_SUPPLY);
}

/// End-to-end **private in-pool swap** (the shielded-DEX primitive): Alice swaps asset A
/// for Bob's asset B via two hashlock-linked swap escrows, then **spends the received B
/// coin privately** — proving a swap yields a real, spendable, hidden coin (settlement *and*
/// usability), and that it's supply-neutral (no asset minted or burned).
#[test]
fn shielded_swap_end_to_end() {
    use zcrypt_core::htlc_shield::BURN_PK;
    let mut node = Node::new();
    seed_decoys(&mut node, 20);
    let alice = Account::from_seed([0xA1; 32]); // taker
    let bob = Account::from_seed([0xB0; 32]); // maker / LP
    let carol = Account::from_seed([0xCA; 32]); // Alice pays Carol from the swapped asset

    // Two shielded assets — a swap moves existing coins, so authority is irrelevant.
    let asset_a = node.register_asset("AAA", 8, None, 1_000_000_000).unwrap();
    let asset_b = node.register_asset("BBB", 8, None, 1_000_000_000).unwrap();

    // Fund Alice with A and Bob with B.
    let alice_a = alice.own_asset_coin(200_000, keys::random_blind(), asset_a);
    let bob_b = bob.own_asset_coin(200_000, keys::random_blind(), asset_b);
    node.seed_coin(alice_a.commitment());
    node.seed_coin(bob_b.commitment());
    node.set_height(10);

    // RFQ terms: Alice gives 100_000 A, receives 120_000 B. One shared hashlock links both legs.
    let (give_a, take_b) = (100_000u64, 120_000u64);
    let x = &pre("in-pool-swap-preimage-01");
    let lock = htlc_hashlock(x);
    let timeout = 100u64;

    // Lock `value` of `asset` from `locker`'s `coin` into a swap escrow claimable by
    // `counterparty` (refund to the locker). The fee is paid in the moved asset.
    let lock_leg = |node: &mut Node, locker: &Account, asset: u64, coin: &Coin, value: u64, counterparty: &Account| -> [u8; 32] {
        let burn_blind = keys::random_blind();
        let chg_blind = keys::random_blind();
        let chg = coin.value - value - FEE;
        let burn_out: OutCoin = (value, burn_blind, BURN_PK, asset);
        let chg_out: OutCoin = (chg, chg_blind, locker.pubkey(), asset);
        let note = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&locker.normal_address(), chg, chg_blind, asset));
        // The lock parameters are bound into the proof, so a front-runner cannot rewrite the
        // counterparty or refund key and redirect either leg of the trade.
        let env = zcrypt_core::htlc_shield::lock_envelope(
            zcrypt_core::htlc_shield::ENV_SWAP_LOCK,
            asset, value, &lock, timeout, &counterparty.pubkey(), &locker.pubkey(), &[],
        );
        let stx = build_shield_bound(node, &[coin.clone()], [burn_out, chg_out], FEE, vec![keys::cover_note_bytes(), note], &env).unwrap();
        node.swap_lock(CHAIN, &stx, value, burn_blind, asset, lock, timeout, counterparty.pubkey(), locker.pubkey()).unwrap()
    };

    // Alice locks A → Bob; Bob locks B → Alice (same hashlock).
    let a_escrow = lock_leg(&mut node, &alice, asset_a, &alice_a, give_a, &bob);
    let b_escrow = lock_leg(&mut node, &bob, asset_b, &bob_b, take_b, &alice);

    // Alice claims B (revealing the preimage); Bob then claims A. Atomic — both or neither.
    node.htlc_claim(&b_escrow, x).unwrap().expect("Alice receives B");
    node.htlc_claim(&a_escrow, x).unwrap().expect("Bob receives A");
    let alice_b = alice.htlc_coin(take_b, asset_b, &b_escrow);
    assert_eq!(alice_b.asset_id, asset_b);
    assert_eq!(alice_b.value, take_b);
    // Bob likewise reconstructs the A he received.
    assert_eq!(bob.htlc_coin(give_a, asset_a, &a_escrow).asset_id, asset_a);

    // THE POINT: the received B is a real, spendable, PRIVATE coin — Alice pays Carol
    // 50_000 B from it, entirely inside the shielded pool.
    let pay = 50_000u64;
    let pb = keys::random_blind();
    let cb = keys::random_blind();
    let to_carol = keys::out_asset_coin(&carol.normal_address(), pay, pb, asset_b);
    let change = keys::out_asset_coin(&alice.normal_address(), take_b - pay - FEE, cb, asset_b);
    let n0 = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&carol.normal_address(), pay, pb, asset_b));
    let n1 = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&alice.normal_address(), take_b - pay - FEE, cb, asset_b));
    let spend = build_shield(&node, &[alice_b], [to_carol, change], FEE, vec![n0, n1]).unwrap();
    node.submit_shield(CHAIN, &spend).expect("the swapped B is spendable");
    let carol_b = scan_for(&carol, &spend).expect("Carol receives the swapped B");
    assert_eq!(carol_b.value, pay);
    assert_eq!(carol_b.asset_id, asset_b);

    // Supply-neutral: a swap (and a transfer) never mint or burn the assets.
    assert_eq!(node.asset_minted(asset_a), 0);
    assert_eq!(node.asset_minted(asset_b), 0);
    eprintln!("[swap] shielded A↔B swap settled; received B spent privately to Carol");
}

#[test]
fn recover_from_mnemonic_then_spend() {
    // The flow that actually matters for a wallet: a coin arrives, you rebuild your
    // account from the 24-word phrase ALONE, recover the coin by scanning, and then
    // successfully SPEND it. (This is the logic the wallet's restore_wallet +
    // scan_onchain commands rely on.)
    let mut node = Node::new();
    seed_decoys(&mut node, 20);
    let (alice, _) = keys::new_account();
    let (bob, bob_phrase) = keys::new_account();

    // Alice pays Bob's normal address — creating Bob's coin + its encrypted note on chain.
    let a = alice.own_coin(500_000, keys::random_blind());
    node.seed_coin(a.commitment());
    let bp = keys::random_blind();
    let cp = keys::random_blind();
    let out_bob = keys::out_coin(&bob.normal_address(), 400_000, bp);
    let out_chg = keys::out_coin(&alice.normal_address(), 100_000 - FEE, cp);
    let n_bob = kem::ciphertext_to_bytes(&keys::encrypt_note(&bob.normal_address(), 400_000, bp));
    let n_chg = kem::ciphertext_to_bytes(&keys::encrypt_note(&alice.normal_address(), 100_000 - FEE, cp));
    let tx = build_shield(&node, &[a], [out_bob, out_chg], FEE, vec![n_bob, n_chg]).unwrap();
    node.submit_shield(CHAIN, &tx).expect("payment to Bob committed");

    // RECOVERY: rebuild Bob's account from his phrase alone (as on a fresh machine).
    let bob_restored = Account::from_mnemonic(bob_phrase.trim(), "").expect("mnemonic restores account");
    assert_eq!(bob_restored.pubkey(), bob.pubkey(), "the phrase reproduces the same account");
    let recovered = scan_for(&bob_restored, &tx).expect("restored account recovers its coin by scanning");
    assert_eq!(recovered.value, 400_000);

    // SPEND the recovered coin — recovery yields real, spendable money.
    let s0 = keys::random_blind();
    let s1 = keys::random_blind();
    let to_alice = keys::out_coin(&alice.normal_address(), recovered.value - FEE, s0);
    let bob_chg = keys::out_coin(&bob_restored.normal_address(), 0, s1);
    let sn0 = kem::ciphertext_to_bytes(&keys::encrypt_note(&alice.normal_address(), recovered.value - FEE, s0));
    let sn1 = kem::ciphertext_to_bytes(&keys::encrypt_note(&bob_restored.normal_address(), 0, s1));
    let spend = build_shield(&node, &[recovered], [to_alice, bob_chg], FEE, vec![sn0, sn1]).unwrap();
    node.submit_shield(CHAIN, &spend).expect("the recovered coin is spendable");
    eprintln!("[recover] rebuilt account from mnemonic, recovered the coin, and spent it: OK");
}

#[test]
fn product_surface_abuse_cases() {
    let mut node = Node::new();
    node.mint_foundation([0xF0; 32]);
    seed_decoys(&mut node, 20);
    let (alice, _mn) = keys::new_account();

    // --- (a) Registering the same ticker twice is rejected (first-mint-wins) ---
    let cap = mint_capability(b"cap");
    let id = node.register_asset("USDC", 6, Some(cap), 1_000_000).unwrap();
    assert!(node.register_asset("USDC", 6, Some(cap), 1_000_000).is_err(), "duplicate ticker");
    assert!(node.register_asset("usdc", 6, Some(cap), 1_000_000).is_err(), "case-insensitive duplicate");
    assert_eq!(node.asset_id_of("USDC"), Some(id));

    // --- (b) A zero max-supply asset cannot be registered ---
    assert!(node.register_asset("ZERO", 2, None, 0).is_err(), "zero cap");

    // --- (c) Minting past the declared cap is rejected (even with valid signatures) ---
    let (cap_ks, cap_signers) = mint_auth::derive_keyset(b"cap-treasury", 1, 1);
    let capped = node.register_asset("CAP", 0, Some(cap_ks.commitment()), 1_000).unwrap();
    let lock = htlc_hashlock(&pre("cap-mint-preimage-01"));
    node.set_height(1);
    assert!(
        open_mint(&mut node, &cap_ks, &cap_signers, capped, 2_000, lock, 100, alice.pubkey()).is_err(),
        "mint over the cap must be rejected at open"
    );

    // --- (d) Bond below the minimum stake is rejected ---
    assert!(node.bond(b"v".to_vec(), b"v".to_vec(), 1, [0u8; 32], zcrypt_core::staking::DEFAULT_COMMISSION_BPS).is_err(), "stake below MIN_STAKE");
    node.bond(b"v".to_vec(), b"v".to_vec(), 10_000 * ATOMIC, [1u8; 32], zcrypt_core::staking::DEFAULT_COMMISSION_BPS).unwrap();
    // Unbond works once; a second unbond of the same key fails.
    assert!(node.unbond(b"v").is_ok());
    assert!(node.unbond(b"v").is_err(), "double unbond");

    // --- (e) Cross-asset spend is unprovable (single-asset conservation) ---
    let coin = alice.own_asset_coin(100, keys::random_blind(), id);
    node.seed_coin(coin.commitment());
    let out_native = keys::out_coin(&alice.normal_address(), 95, [1, 2, 2, 3]); // native ZCRYPT output
    let out_asset = keys::out_asset_coin(&alice.normal_address(), 0, [3, 4, 4, 5], id);
    // Mixing the input asset with a native output must fail to prove.
    let mix = build_shield(&node, &[coin.clone()], [out_native, out_asset], 5, notes());
    assert!(mix.is_err(), "cross-asset spend must be unprovable");

    // --- (f) Double-spend: re-submitting the same nullifier is rejected ---
    let spendable = alice.own_coin(100_000, keys::random_blind());
    node.seed_coin(spendable.commitment());
    let mk = |node: &Node, o: u64| {
        let o0 = keys::out_coin(&alice.normal_address(), o, [7, 8, 8, 9]);
        let o1 = keys::out_coin(&alice.normal_address(), 100_000 - o - FEE, [9, 10, 10, 11]);
        build_shield(node, &[spendable.clone()], [o0, o1], FEE, notes()).unwrap()
    };
    node.submit_shield(CHAIN, &mk(&node, 80_000)).expect("first spend");
    assert!(node.submit_shield(CHAIN, &mk(&node, 70_000)).is_err(), "double-spend rejected");

    // --- (g) An unknown anchor root is rejected by consensus (shielded-pool
    //         soundness: a proof must anchor on a tree root the node actually had,
    //         so a coin that isn't in the pool can't be "spent"). ---
    let coin2 = alice.own_coin(5_000, keys::random_blind());
    node.seed_coin(coin2.commitment());
    let mut tx = mk_single(&node, &coin2, &alice);
    tx.root[0] ^= 1; // an anchor root the node never produced
    assert!(node.submit_shield(CHAIN, &tx).is_err(), "unknown anchor root rejected");

    eprintln!("[ok] all abuse cases correctly rejected");
}

/// Build a single-input self-spend of `coin` (helper for the anchor-tamper case).
fn mk_single(node: &Node, coin: &Coin, owner: &Account) -> ShieldTx {
    let o0 = keys::out_coin(&owner.normal_address(), coin.value - 5, [5, 6, 6, 7]);
    let o1 = keys::out_coin(&owner.normal_address(), 0, [7, 8, 8, 9]);
    build_shield(node, &[coin.clone()], [o0, o1], 5, notes()).unwrap()
}

/// COIN-BACKED STAKING round-trip: bonding genuinely pledges shielded coins, and the
/// stake comes back (claimable) only after the 10-day unbonding period.
#[test]
fn coin_backed_bond_pledges_coins_and_unbonding_returns_them() {
    use zcrypt_core::htlc_shield::BURN_PK;
    let mut node = Node::new();
    seed_decoys(&mut node, 20);
    let bonder = Account::from_seed([0xB0; 32]);
    let stake = 10_000 * ATOMIC;
    let fee = FEE;

    // Fund the bonder with a coin worth stake + the fee + a little change, seeded on-chain.
    let fund = bonder.own_coin(stake + fee + 100, keys::random_blind());
    node.seed_coin(fund.commitment());

    // Build the pledge: a shield spend of that coin whose output[0] is the revealed
    // burn coin of exactly `stake`, output[1] the change back to the bonder.
    let stake_blind = keys::random_blind();
    let change_blind = keys::random_blind();
    let burn_out: OutCoin = (stake, stake_blind, BURN_PK, 0);
    let change_out = keys::out_coin(&bonder.normal_address(), 100, change_blind);
    let stx = build_shield(&node, &[fund.clone()], [burn_out, change_out], fee, notes()).unwrap();

    let reward = keys::reward_address(&bonder.pubkey());
    node.bond_with_stake(CHAIN, &stx, stake, stake_blind, b"val".to_vec(), b"val".to_vec(), reward, zcrypt_core::staking::DEFAULT_COMMISSION_BPS)
        .expect("coin-backed bond accepted");
    assert!(node.is_validator(b"val"));

    // The pledged coins are genuinely spent — replaying the pledge tx is a double-spend.
    assert!(node.submit_shield(CHAIN, &stx).is_err(), "pledged coins are locked (double-spend blocked)");

    // A "bond" whose output[0] is a NORMAL coin (not the stake burn coin) is rejected —
    // you can't claim voting weight without actually pledging the value.
    let fund2 = bonder.own_coin(stake + fee + 50, keys::random_blind());
    node.seed_coin(fund2.commitment());
    let normal = build_shield(
        &node,
        &[fund2],
        [keys::out_coin(&bonder.normal_address(), stake, keys::random_blind()),
         keys::out_coin(&bonder.normal_address(), 50, keys::random_blind())],
        fee,
        notes(),
    ).unwrap();
    assert!(
        node.bond_with_stake(CHAIN, &normal, stake, stake_blind, b"v2".to_vec(), b"v2".to_vec(), reward, zcrypt_core::staking::DEFAULT_COMMISSION_BPS).is_err(),
        "output[0] must be the declared stake burn coin"
    );
    assert!(!node.is_validator(b"v2"), "rejected bond records no validator");

    // Unbond: leaves the active set at once, full stake locked (gasless), NOT yet claimable.
    node.set_block_time(1_000_000);
    node.unbond(b"val").unwrap();
    assert!(!node.is_validator(b"val"), "out of the active set immediately");
    assert_eq!(node.total_unbonding(), stake, "stake frozen in the unbonding queue");
    assert_eq!(node.claimable(&bonder.pubkey()), 0, "not returned before the 10-day wait");

    // Before maturity: nothing releases.
    node.set_block_time(1_000_000 + zcrypt_core::staking::UNBONDING_PERIOD_SECS - 1);
    node.release_matured_unbonding();
    assert_eq!(node.claimable(&bonder.pubkey()), 0, "still locked one second early");

    // At/after the 10-day mark: the full stake returns as a claimable balance...
    node.set_block_time(1_000_000 + zcrypt_core::staking::UNBONDING_PERIOD_SECS);
    node.release_matured_unbonding();
    assert_eq!(node.claimable(&bonder.pubkey()), stake, "full stake returned after the 10-day wait");
    assert_eq!(node.total_unbonding(), 0);

    // ...which the bonder withdraws into a real spendable coin (claiming is gasless).
    let coins = node.claim_rewards(&bonder.pubkey(), stake).expect("claim returned stake into a coin");
    assert!(!coins.is_empty());
    eprintln!("[ok] coin-backed bond: pledged {stake}, locked, returned + claimed after unbonding");
}

/// COIN-BACKED DELEGATION round-trip: a delegator pledges real coins toward a validator,
/// boosts its voting power, earns a share of its rewards (net of commission), and gets
/// the stake back after undelegating and waiting out the 10-day period.
#[test]
fn coin_backed_delegation_shares_rewards_and_returns_stake() {
    use zcrypt_core::emission::EPOCH;
    use zcrypt_core::htlc_shield::BURN_PK;
    let mut node = Node::new();
    seed_decoys(&mut node, 20);
    let fee = FEE;

    // Bond a validator with a genuine coin pledge.
    let validator = Account::from_seed([0xA0; 32]);
    let vstake = 10_000 * ATOMIC;
    let vfund = validator.own_coin(vstake + fee + 100, keys::random_blind());
    node.seed_coin(vfund.commitment());
    let vblind = keys::random_blind();
    let vburn: OutCoin = (vstake, vblind, BURN_PK, 0);
    let vchange = keys::out_coin(&validator.normal_address(), 100, keys::random_blind());
    let vtx = build_shield(&node, &[vfund], [vburn, vchange], fee, notes()).unwrap();
    let vreward = keys::reward_address(&validator.pubkey());
    node.bond_with_stake(CHAIN, &vtx, vstake, vblind, b"val".to_vec(), b"val".to_vec(), vreward, zcrypt_core::staking::DEFAULT_COMMISSION_BPS)
        .expect("bond");
    assert!(node.is_validator(b"val"));

    // Delegate 5,000 ZCRYPT (below MIN_STAKE — fine for a delegation) toward that validator.
    let delegator = Account::from_seed([0xD0; 32]);
    let dstake = 5_000 * ATOMIC;
    let dfund = delegator.own_coin(dstake + fee + 100, keys::random_blind());
    node.seed_coin(dfund.commitment());
    let dblind = keys::random_blind();
    let dburn: OutCoin = (dstake, dblind, BURN_PK, 0);
    let dchange = keys::out_coin(&delegator.normal_address(), 100, keys::random_blind());
    let dtx = build_shield(&node, &[dfund], [dburn, dchange], fee, notes()).unwrap();
    let dreward = keys::reward_address(&delegator.pubkey());
    node.delegate_with_stake(CHAIN, &dtx, dstake, dblind, b"val".to_vec(), b"del".to_vec(), dreward)
        .expect("coin-backed delegation accepted");

    // The delegated coins are genuinely spent (replay = double-spend), and the stake now
    // boosts the validator's voting power.
    assert!(node.submit_shield(CHAIN, &dtx).is_err(), "delegated coins are locked");
    assert_eq!(node.delegated_to(b"val"), dstake, "voting power boosted by the delegation");
    assert_eq!(node.validator_set(), vec![(b"val".to_vec(), vstake + dstake)]);

    // Delegating to a validator that isn't bonded is rejected BEFORE the coins are spent,
    // so a bad delegation never strands the delegator's pledge.
    let bad = delegator.own_coin(dstake + fee + 50, keys::random_blind());
    node.seed_coin(bad.commitment());
    let bblind = keys::random_blind();
    let bburn: OutCoin = (dstake, bblind, BURN_PK, 0);
    let bchange = keys::out_coin(&delegator.normal_address(), 50, keys::random_blind());
    let btx = build_shield(&node, &[bad], [bburn, bchange], fee, notes()).unwrap();
    assert!(
        node.delegate_with_stake(CHAIN, &btx, dstake, bblind, b"nope".to_vec(), b"del2".to_vec(), dreward).is_err(),
        "cannot delegate to an unbonded validator"
    );
    assert!(node.submit_shield(CHAIN, &btx).is_ok(), "rejected delegation strands no coins");

    // Run one epoch: the validator signs every block, then the reward distributes and is
    // split — the validator keeps commission + its own stake's reward, the delegator gets
    // the rest of the delegated portion.
    for _ in 0..EPOCH {
        node.record_block_signers(&[b"val".to_vec()]);
    }
    node.maybe_distribute_rewards(EPOCH);
    let vearn = node.claimable(&validator.pubkey());
    let dearn = node.claimable(&delegator.pubkey());
    assert!(dearn > 0, "delegator earns a share of the validator's rewards");
    assert!(vearn > dearn, "validator keeps commission + its own stake's reward");

    // Undelegate: leaves the validator's power at once, locked in the queue, not yet back.
    node.set_block_time(2_000_000);
    node.undelegate(b"val", b"del").unwrap();
    assert_eq!(node.delegated_to(b"val"), 0, "voting power dropped");
    let before = node.claimable(&delegator.pubkey());

    // Before maturity nothing releases; after the 10-day wait the stake returns claimable.
    node.set_block_time(2_000_000 + zcrypt_core::staking::UNBONDING_PERIOD_SECS - 1);
    node.release_matured_unbonding();
    assert_eq!(node.claimable(&delegator.pubkey()), before, "still locked one second early");
    node.set_block_time(2_000_000 + zcrypt_core::staking::UNBONDING_PERIOD_SECS);
    node.release_matured_unbonding();
    assert_eq!(
        node.claimable(&delegator.pubkey()),
        before + dstake,
        "full delegation returned after the wait (undelegation is gasless)"
    );
    eprintln!("[ok] coin-backed delegation: pledged {dstake}, shared rewards, returned after unbonding");
}

/// UNIVERSAL GAS: a transfer of a *non-ZCRYPT* shielded asset (GOLD) pays its gas in
/// **ZCRYPT** via a bundled gas note — the moved asset is never burned, and the pool
/// still hides which asset moved. This is the "ZCRYPT is the one gas token" property.
#[test]
fn transfer_of_a_shielded_asset_pays_zcrypt_gas() {
    use zcrypt_core::htlc_shield::BURN_PK;
    let mut node = Node::new();
    seed_decoys(&mut node, 20);
    let alice = Account::from_seed([0x71; 32]);
    let bob = Account::from_seed([0x72; 32]);

    // Register + mint GOLD to Alice.
    let (gold_ks, gold_signers) = mint_auth::derive_keyset(b"gold-gas-treasury", 2, 2);
    let gold = node.register_asset("GOLD", 2, Some(gold_ks.commitment()), 1_000_000).unwrap();
    let preimage = &pre("gold-gas-preimage-01");
    let lock = zcrypt_core::nullifier::htlc_hashlock(preimage);
    node.set_height(1);
    let escrow =
        open_mint(&mut node, &gold_ks, &gold_signers, gold, 500_000, lock, 100, alice.pubkey()).unwrap();
    node.htlc_claim(&escrow, preimage).unwrap();
    let gold_coin = alice.htlc_coin(500_000, gold, &escrow);

    // Alice also holds a ZCRYPT coin, purely to pay gas.
    let gas_coin = alice.own_coin(FEE + 1_000, keys::random_blind());
    node.seed_coin(gas_coin.commitment());

    // MAIN transfer: 300k GOLD to Bob, 200k change to Alice — with NO in-tx fee (the GOLD
    // is never burned; conservation is Σin = Σout).
    let gb = keys::random_blind();
    let gc = keys::random_blind();
    let g_to_bob = keys::out_asset_coin(&bob.normal_address(), 300_000, gb, gold);
    let g_chg = keys::out_asset_coin(&alice.normal_address(), 200_000, gc, gold);
    let gn0 = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&bob.normal_address(), 300_000, gb, gold));
    let gn1 = kem::ciphertext_to_bytes(&keys::encrypt_note_asset(&alice.normal_address(), 200_000, gc, gold));
    let main_tx = build_shield(&node, &[gold_coin], [g_to_bob, g_chg], 0, vec![gn0, gn1]).unwrap();

    // GAS note: spend the ZCRYPT coin, output[0] = exactly MIN_FEE ZCRYPT burn, change back.
    let gas_blind = keys::random_blind();
    let gas_burn: OutCoin = (FEE, gas_blind, BURN_PK, 0);
    let gas_chg = keys::out_coin(&alice.normal_address(), 1_000, keys::random_blind());
    let gas_tx = build_shield(&node, &[gas_coin], [gas_burn, gas_chg], 0, notes()).unwrap();

    // The bundled transfer is accepted: a GOLD transfer, gas paid in ZCRYPT.
    node.submit_transfer(CHAIN, &main_tx, &gas_tx, gas_blind).expect("GOLD transfer with ZCRYPT gas");
    let bob_gold = scan_for(&bob, &main_tx).expect("Bob receives GOLD");
    assert_eq!(bob_gold.value, 300_000);
    assert_eq!(bob_gold.asset_id, gold);

    // --- Abuse (a): a gas note that burns the WRONG amount (< MIN_FEE) is rejected. ---
    let carol = Account::from_seed([0x73; 32]);
    let main_coin = carol.own_coin(10_000, keys::random_blind());
    node.seed_coin(main_coin.commitment());
    let good_main = build_shield(
        &node,
        &[main_coin],
        [keys::out_coin(&bob.normal_address(), 9_000, keys::random_blind()),
         keys::out_coin(&carol.normal_address(), 1_000, keys::random_blind())],
        0,
        notes(),
    ).unwrap();
    let underpay = carol.own_coin(FEE + 1_000, keys::random_blind());
    node.seed_coin(underpay.commitment());
    let ub = keys::random_blind();
    let under_gas = build_shield(
        &node,
        &[underpay],
        [(FEE - 1, ub, BURN_PK, 0), keys::out_coin(&carol.normal_address(), 1_001, keys::random_blind())],
        0,
        notes(),
    ).unwrap();
    assert!(
        node.submit_transfer(CHAIN, &good_main, &under_gas, ub).is_err(),
        "a gas note burning less than MIN_FEE ZCRYPT is rejected"
    );

    // --- Abuse (b): a main tx that burns its OWN asset as an in-tx fee is rejected — gas
    //     must be the external ZCRYPT note, not the moved asset. ---
    let fee_coin = carol.own_coin(10_000, keys::random_blind());
    node.seed_coin(fee_coin.commitment());
    let main_with_fee = build_shield(
        &node,
        &[fee_coin],
        [keys::out_coin(&bob.normal_address(), 8_000, keys::random_blind()),
         keys::out_coin(&carol.normal_address(), 1_995, keys::random_blind())],
        5, // nonzero in-tx fee
        notes(),
    ).unwrap();
    let gas_coin2 = carol.own_coin(FEE + 1_000, keys::random_blind());
    node.seed_coin(gas_coin2.commitment());
    let gb2 = keys::random_blind();
    let good_gas = build_shield(
        &node,
        &[gas_coin2],
        [(FEE, gb2, BURN_PK, 0), keys::out_coin(&carol.normal_address(), 1_000, keys::random_blind())],
        0,
        notes(),
    ).unwrap();
    assert!(
        node.submit_transfer(CHAIN, &main_with_fee, &good_gas, gb2).is_err(),
        "a main tx with a nonzero in-tx fee is rejected (gas is ZCRYPT-note only)"
    );
    eprintln!("[ok] shielded-asset transfer paid its gas in ZCRYPT; bad gas notes rejected");
}
