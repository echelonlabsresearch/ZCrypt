//! End-to-end shield-native HTLC: the BTC→zBTC direction. An LP registers zBTC,
//! opens a hashlocked escrow to Alice; Alice reveals the preimage to mint a zBTC
//! coin bound to her key, then **spends that zBTC privately** in a ring shield
//! transaction the node accepts — proving the minted asset is real, conserved,
//! and unlinkable after settlement.

use zcrypt_core::htlc_shield::{EscrowState, BURN_PK};
use zcrypt_core::keys::{self, Account, Coin};
use zcrypt_core::mint_auth::{self, MintKeySet, MintSigner};
use zcrypt_core::node::Node;
use zcrypt_core::nullifier::htlc_hashlock;
use zcrypt_core::shield_tx::{self, Spend};
use zcrypt_shield::{Commitment, OutCoin};

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
    let msg = mint_auth::mint_message(asset, value, &lock, timeout, &pk);
    let sigs = mint_auth::authorize(ks, signers, &msg);
    node.htlc_open(asset, value, lock, timeout, pk, ks, &sigs)
}

fn setup() -> (Account, Node, u64, MintKeySet, Vec<MintSigner>) {
    let (alice, _mn) = keys::new_account();
    let mut node = Node::new();
    // LP registers zBTC with an M-of-N (here 1-of-1) post-quantum mint authority; the
    // asset's `authority` commits to the key set. Minting needs a threshold signature.
    let (keyset, signers) = mint_auth::derive_keyset(b"lp-mint-secret", 1, 1);
    let asset =
        node.register_asset("zBTC", 8, Some(keyset.commitment()), 21_000_000 * 100_000_000).unwrap();
    (alice, node, asset, keyset, signers)
}

/// The "enable distributed custody later" path: rotate the mint authority from the original
/// (single-master) key set to a NEW one, authorized by the CURRENT key set — then minting
/// requires the new keys, the old keys are powerless, and the rotation can't be replayed.
#[test]
fn authority_rotation_hands_off_minting_and_resists_replay() {
    let (alice, mut node, asset, old_ks, old_signers) = setup();
    node.set_height(10);

    // A brand-new, independently-generated key set (the future distributed custodians).
    let (new_ks, new_signers) = mint_auth::derive_keyset(b"distributed-custody-3of5", 5, 3);
    let new_commitment = new_ks.commitment();

    // The CURRENT authority signs the rotation over (asset, epoch=0, new_commitment).
    let rot_msg = mint_auth::rotate_message(asset, node.authority_epoch(asset), &new_commitment);
    let rot_sigs = mint_auth::authorize(&old_ks, &old_signers, &rot_msg);

    // A rotation NOT signed by the current authority is rejected.
    let (imposter_ks, imposter_signers) = mint_auth::derive_keyset(b"imposter", 3, 2);
    let bad = mint_auth::authorize(&imposter_ks, &imposter_signers, &rot_msg);
    assert!(node.rotate_authority(asset, new_commitment, &imposter_ks, &bad).is_err());

    // The real rotation succeeds and advances the epoch.
    node.rotate_authority(asset, new_commitment, &old_ks, &rot_sigs).unwrap();
    assert_eq!(node.authority_epoch(asset), 1);

    // The OLD key set can no longer mint; the NEW key set can.
    let lock = htlc_hashlock(b"post-rotation-preimage");
    assert!(open_mint(&mut node, &old_ks, &old_signers, asset, 1_000, lock, 200, alice.pubkey()).is_err());
    open_mint(&mut node, &new_ks, &new_signers, asset, 1_000, lock, 200, alice.pubkey()).unwrap();

    // Replaying the exact rotation tx fails: the epoch has advanced, so the signed message
    // no longer matches (single-use). Even re-rotating BACK needs a fresh signature.
    assert!(node.rotate_authority(asset, new_commitment, &old_ks, &rot_sigs).is_err());
}

#[test]
fn claim_mints_a_spendable_private_zbtc_coin() {
    let (alice, mut node, asset, keyset, signers) = setup();
    let x = b"atomic-swap-preimage-42";
    let lock = htlc_hashlock(x);
    let value = 100_000u64; // 0.001 zBTC at 8 decimals
    node.set_height(10);

    // Free-mint guard: without the M-of-N signatures (here an empty bundle) the escrow
    // cannot be opened — the threshold gate rejects it.
    assert!(node.htlc_open(asset, value, lock, 100, alice.pubkey(), &keyset, &[]).is_err());
    // LP opens the escrow to Alice's key with a valid threshold authorization.
    let id = open_mint(&mut node, &keyset, &signers, asset, value, lock, 100, alice.pubkey()).unwrap();

    // A wrong preimage cannot claim.
    assert!(node.htlc_claim(&id, b"nope").is_err());
    // Alice reveals the preimage -> the node mints a zBTC coin bound to her key.
    let minted = node.htlc_claim(&id, x).unwrap().expect("mint escrow yields a coin");

    // Alice reconstructs the exact coin from her key + the public escrow id.
    let coin = alice.htlc_coin(value, asset, &id);
    assert_eq!(coin.commitment(), minted, "claimer rebuilds the minted coin");
    assert_eq!(coin.asset_id, asset);
    assert_eq!(node.asset_minted(asset), value, "supply tracks the mint");
    // Claiming twice is rejected.
    assert!(node.htlc_claim(&id, x).is_err());

    // Spend the claimed zBTC PRIVATELY: needs a second zBTC input; both hide in the
    // shielded pool.
    let coin2 = alice.own_asset_coin(value, keys::random_blind(), asset);
    node.seed_coin(coin2.commitment()); // tree index 1 (minted coin is index 0)
    for k in 2..16u64 {
        node.seed_coin(alice.own_asset_coin(1_000 + k, [k, k ^ 0x9e37, k.wrapping_add(1), k.wrapping_add(2)], asset).commitment());
    }
    let pool: Vec<Commitment> = node.commitment_leaves();
    assert_eq!(pool[0], minted);

    let mk = |c: &Coin, leaf_idx: usize| {
        // Build the coin's Merkle path from the pool for the whole-pool membership proof.
        let mut t = zcrypt_shield::tree::CommitmentTree::new();
        for &x in &pool {
            t.append(x);
        }
        let (path_siblings, path_dirs) = t.path(leaf_idx).unwrap();
        Spend {
            value: c.value,
            blind: c.blind,
            spend_secret: c.spend_secret,
            asset_id: c.asset_id,
            path_siblings,
            path_dirs,
        }
    };
    // All-zBTC, single-asset: 2 inputs -> 2 outputs, conserved. The fee is paid in zBTC —
    // the pool hides asset_id, so a transfer's fee is denominated in the asset it moves.
    let out0: OutCoin = (value + 100 - zcrypt_core::emission::MIN_FEE, keys::random_blind(), alice.pubkey(), asset);
    let out1: OutCoin = (value - 100, keys::random_blind(), alice.pubkey(), asset);
    let tx = shield_tx::build(
        CHAIN,
        &[mk(&coin, 0), mk(&coin2, 1)],
        &[out0, out1],
        zcrypt_core::emission::MIN_FEE,
        vec![vec![1; 8], vec![2; 8]],
    )
    .expect("zBTC shield proof over the claimed coin");
    let receipt = node.submit_shield(CHAIN, &tx).expect("minted zBTC is spendable");
    assert_eq!(receipt.nullifiers.len(), 2);
}

/// Set up Alice with two zBTC coins + a zBTC ring, and build a burn-lock tx that
/// locks `lock_value` (output[0] = burn coin) with `change` back to her.
fn burn_lock_tx(
    alice: &Account,
    node: &mut Node,
    asset: u64,
    lock_value: u64,
    burn_blind: [u64; 4],
) -> zcrypt_core::shield_tx::ShieldTx {
    let v = 100_000u64;
    let c0 = alice.own_asset_coin(v, keys::random_blind(), asset);
    let c1 = alice.own_asset_coin(v, keys::random_blind(), asset);
    node.seed_coin(c0.commitment());
    node.seed_coin(c1.commitment());
    for k in 2..16u64 {
        node.seed_coin(alice.own_asset_coin(1_000 + k, [k, k ^ 0x9e37, k.wrapping_add(1), k.wrapping_add(2)], asset).commitment());
    }
    let pool: Vec<Commitment> = node.commitment_leaves();
    let mk = |c: &Coin, leaf_idx: usize| {
        // Build the coin's Merkle path from the pool for the whole-pool membership proof.
        let mut t = zcrypt_shield::tree::CommitmentTree::new();
        for &x in &pool {
            t.append(x);
        }
        let (path_siblings, path_dirs) = t.path(leaf_idx).unwrap();
        Spend {
            value: c.value,
            blind: c.blind,
            spend_secret: c.spend_secret,
            asset_id: c.asset_id,
            path_siblings,
            path_dirs,
        }
    };
    // Locate the actual leaf indices (the tree may already hold other coins — e.g. an
    // earlier swap leg — so the inputs are NOT necessarily at indices 0/1).
    let idx = |c: &Coin| pool.iter().position(|x| *x == c.commitment()).expect("coin is in the pool");
    let burn_out: OutCoin = (lock_value, burn_blind, BURN_PK, asset);
    // The burn coin (output[0]) is exactly lock_value; the zBTC fee comes out of the change.
    let change_out: OutCoin = (2 * v - lock_value - zcrypt_core::emission::MIN_FEE, keys::random_blind(), alice.pubkey(), asset);
    shield_tx::build(CHAIN, &[mk(&c0, idx(&c0)), mk(&c1, idx(&c1))], &[burn_out, change_out], zcrypt_core::emission::MIN_FEE, vec![vec![9; 8], vec![8; 8]])
        .expect("burn-lock shield proof")
}

#[test]
fn burn_lock_then_claim_burns_zbtc() {
    let (alice, mut node, asset, _keyset, _signers) = setup();
    node.set_height(10);
    let lock_value = 150_000u64;
    let burn_blind = keys::random_blind();
    let tx = burn_lock_tx(&alice, &mut node, asset, lock_value, burn_blind);
    let x = b"redeem-preimage-99";

    // Declaring a value that doesn't match output[0]'s actual opening is rejected
    // (the node binds the escrow to the real coin, so you can't over-declare).
    assert!(node
        .htlc_burn_lock(CHAIN, &tx, lock_value + 1, burn_blind, asset, htlc_hashlock(x), 100, alice.pubkey())
        .is_err());

    let id = node
        .htlc_burn_lock(CHAIN, &tx, lock_value, burn_blind, asset, htlc_hashlock(x), 100, alice.pubkey())
        .unwrap();
    // Bridge claims with the preimage -> zBTC burned, nothing minted.
    assert!(node.htlc_claim(&id, b"wrong").is_err());
    assert!(node.htlc_claim(&id, x).unwrap().is_none(), "burn claim mints nothing");
    assert_eq!(node.htlc_escrow(&id).unwrap().state, EscrowState::Claimed);
}

#[test]
fn burn_lock_then_expire_refunds_owner() {
    let (alice, mut node, asset, _keyset, _signers) = setup();
    node.set_height(10);
    let lock_value = 60_000u64;
    let burn_blind = keys::random_blind();
    let tx = burn_lock_tx(&alice, &mut node, asset, lock_value, burn_blind);
    let x = b"never-revealed";
    let id = node
        .htlc_burn_lock(CHAIN, &tx, lock_value, burn_blind, asset, htlc_hashlock(x), 20, alice.pubkey())
        .unwrap();

    // Before timeout, expire is rejected.
    assert!(node.htlc_expire(&id).is_err());
    // After timeout, expiry refunds Alice's zBTC back to her key.
    node.set_height(20);
    let refunded = node.htlc_expire(&id).unwrap().expect("burn refund mints a coin");
    let refund_coin = alice.htlc_coin(lock_value, asset, &id);
    assert_eq!(refund_coin.commitment(), refunded, "refund coin reconstructable");
    assert_eq!(refund_coin.asset_id, asset);
}

#[test]
fn expired_escrow_never_mints() {
    let (alice, mut node, asset, keyset, signers) = setup();
    let x = b"unused-preimage";
    let id = open_mint(&mut node, &keyset, &signers, asset, 500, htlc_hashlock(x), 100, alice.pubkey()).unwrap();

    // After the timeout the preimage no longer claims...
    node.set_height(100);
    assert!(node.htlc_claim(&id, x).is_err());
    // ...and expiring closes it with no mint.
    node.htlc_expire(&id).unwrap();
    assert_eq!(node.asset_minted(asset), 0, "expired escrow mints nothing");
    assert!(node.htlc_claim(&id, x).is_err());
}

/// A1: a **private in-pool atomic swap** between two shielded assets. Alice locks A
/// claimable by Bob, Bob locks B claimable by Alice, one shared hashlock. Alice claims B
/// (revealing the preimage), Bob claims A — both settle or both refund. Supply-neutral: no
/// asset is minted or burned, so neither party needs the other asset's mint authority.
#[test]
fn in_pool_atomic_swap_between_two_assets() {
    let alice = Account::from_seed([0xA1; 32]);
    let bob = Account::from_seed([0xB0; 32]);
    let mut node = Node::new();
    // Two independent shielded assets (swap moves existing coins, so authority is irrelevant).
    let asset_a = node.register_asset("AAA", 8, None, 1_000_000_000).unwrap();
    let asset_b = node.register_asset("BBB", 8, None, 1_000_000_000).unwrap();
    node.set_height(10);
    let x = b"atomic-swap-preimage-xyz";
    let lock = htlc_hashlock(x);

    // Alice locks 100_000 A, claimable by Bob (refund to Alice on timeout).
    let a_blind = keys::random_blind();
    let a_tx = burn_lock_tx(&alice, &mut node, asset_a, 100_000, a_blind);
    let a_escrow = node
        .swap_lock(CHAIN, &a_tx, 100_000, a_blind, asset_a, lock, 100, bob.pubkey(), alice.pubkey())
        .unwrap();

    // Bob locks 120_000 B, claimable by Alice (refund to Bob on timeout).
    let b_blind = keys::random_blind();
    let b_tx = burn_lock_tx(&bob, &mut node, asset_b, 120_000, b_blind);
    let b_escrow = node
        .swap_lock(CHAIN, &b_tx, 120_000, b_blind, asset_b, lock, 100, alice.pubkey(), bob.pubkey())
        .unwrap();

    let (a_supply, b_supply) = (node.asset_minted(asset_a), node.asset_minted(asset_b));

    // Alice claims Bob's B escrow (reveals x) → she gets 120_000 B; Bob then claims A.
    let got_b = node.htlc_claim(&b_escrow, x).unwrap().expect("swap claim yields a coin");
    let got_a = node.htlc_claim(&a_escrow, x).unwrap().expect("swap claim yields a coin");

    // Each party reconstructs the coin they received (keyed by their key + the escrow id).
    let alice_b = alice.htlc_coin(120_000, asset_b, &b_escrow);
    let bob_a = bob.htlc_coin(100_000, asset_a, &a_escrow);
    assert_eq!(alice_b.commitment(), got_b, "Alice rebuilds her received B coin");
    assert_eq!(bob_a.commitment(), got_a, "Bob rebuilds his received A coin");
    assert_eq!(alice_b.asset_id, asset_b);
    assert_eq!(bob_a.asset_id, asset_a);

    // Supply-neutral: a swap moves existing coins, so `minted` is unchanged for both.
    assert_eq!(node.asset_minted(asset_a), a_supply);
    assert_eq!(node.asset_minted(asset_b), b_supply);
    // A settled escrow can't be double-claimed.
    assert!(node.htlc_claim(&a_escrow, x).is_err());
}

/// If the counterparty never shows, an unclaimed swap escrow refunds the **locker** (not
/// the counterparty) after its timeout — so a half-done swap can't strand funds.
#[test]
fn swap_escrow_refunds_the_locker_on_timeout() {
    let alice = Account::from_seed([0xA2; 32]);
    let bob = Account::from_seed([0xB2; 32]);
    let mut node = Node::new();
    let asset_a = node.register_asset("AAA", 8, None, 1_000_000_000).unwrap();
    node.set_height(10);
    let x = b"never-revealed-preimage";
    let a_blind = keys::random_blind();
    let a_tx = burn_lock_tx(&alice, &mut node, asset_a, 100_000, a_blind);
    let a_escrow = node
        .swap_lock(CHAIN, &a_tx, 100_000, a_blind, asset_a, htlc_hashlock(x), 100, bob.pubkey(), alice.pubkey())
        .unwrap();

    // Before timeout: expire is rejected.
    assert!(node.htlc_expire(&a_escrow).is_err());
    // After timeout: the locked A refunds to ALICE (the locker), not Bob.
    node.set_height(100);
    let refunded = node.htlc_expire(&a_escrow).unwrap().expect("expire refunds the locker");
    assert_eq!(alice.htlc_coin(100_000, asset_a, &a_escrow).commitment(), refunded);
    // A claim after expiry is impossible.
    assert!(node.htlc_claim(&a_escrow, x).is_err());
}
