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
use zcrypt_core::spv::{testutil, MintProof};
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

/// Open an SPV mint escrow: builds the refund-key authorization over every open parameter.
#[allow(clippy::too_many_arguments)]
fn open_spv(
    node: &mut Node,
    refund_n: u8,
    asset: u64,
    value: u64,
    lock: [u8; 32],
    timeout: u64,
    claim_pk: [u64; 8],
    proof: &MintProof,
) -> Result<[u8; 32], String> {
    let auth = testutil::open_auth_for_proof(refund_n, proof, testutil::OpenTerms {
        chain_id: CHAIN, asset_id: asset, value, hashlock: &lock, timeout_height: timeout, claim_pk: &claim_pk,
    });
    node.htlc_open_spv(CHAIN, asset, value, lock, timeout, claim_pk, proof, &auth)
}

fn setup() -> (Account, Node, u64, MintKeySet, Vec<MintSigner>) {
    let (alice, _mn) = keys::new_account();
    let mut node = Node::new();
    // A user-minted asset with an M-of-N (here 1-of-1) post-quantum mint authority;
    // the asset's `authority` commits to the key set. Minting needs a threshold
    // signature. (zBTC itself is SPV-gated — see the spv tests below — so the
    // threshold path is exercised on a generic asset.)
    let (keyset, signers) = mint_auth::derive_keyset(b"lp-mint-secret", 1, 1);
    let asset =
        node.register_asset("GOLD", 8, Some(keyset.commitment()), 21_000_000 * 100_000_000).unwrap();
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
    let rot_msg = mint_auth::rotate_message(CHAIN, asset, node.authority_epoch(asset), &new_commitment);
    let rot_sigs = mint_auth::authorize(&old_ks, &old_signers, &rot_msg);

    // A rotation NOT signed by the current authority is rejected.
    let (imposter_ks, imposter_signers) = mint_auth::derive_keyset(b"imposter", 3, 2);
    let bad = mint_auth::authorize(&imposter_ks, &imposter_signers, &rot_msg);
    assert!(node.rotate_authority(CHAIN, asset, new_commitment, &imposter_ks, &bad).is_err());

    // The real rotation succeeds and advances the epoch.
    node.rotate_authority(CHAIN, asset, new_commitment, &old_ks, &rot_sigs).unwrap();
    assert_eq!(node.authority_epoch(asset), 1);

    // The OLD key set can no longer mint; the NEW key set can.
    let lock = htlc_hashlock(&pre("post-rotation-preimage"));
    assert!(open_mint(&mut node, &old_ks, &old_signers, asset, 1_000, lock, 200, alice.pubkey()).is_err());
    open_mint(&mut node, &new_ks, &new_signers, asset, 1_000, lock, 200, alice.pubkey()).unwrap();

    // Replaying the exact rotation tx fails: the epoch has advanced, so the signed message
    // no longer matches (single-use). Even re-rotating BACK needs a fresh signature.
    assert!(node.rotate_authority(CHAIN, asset, new_commitment, &old_ks, &rot_sigs).is_err());
}

#[test]
fn claim_mints_a_spendable_private_zbtc_coin() {
    let (alice, mut node, asset, keyset, signers) = setup();
    let x = &pre("atomic-swap-preimage-42");
    let lock = htlc_hashlock(x);
    let value = 100_000u64; // 0.001 zBTC at 8 decimals
    node.set_height(10);

    // Free-mint guard: without the M-of-N signatures (here an empty bundle) the escrow
    // cannot be opened — the threshold gate rejects it.
    assert!(node.htlc_open(CHAIN, asset, value, lock, 100, alice.pubkey(), &keyset, &[]).is_err());
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
            t.append(x).unwrap();
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
        vec![keys::cover_note_bytes(), keys::cover_note_bytes()],
    )
    .expect("zBTC shield proof over the claimed coin");
    let receipt = node.submit_shield(CHAIN, &tx).expect("minted zBTC is spendable");
    assert_eq!(receipt.nullifiers.len(), 2);
}

/// Set up `alice` with two coins of `asset` plus a ring, and build a lock spend whose
/// output[0] is the burn coin for `lock_value`. `fee` comes out of the change: a burn-lock
/// passes [`MIN_FEE`] (paid in the locked asset); a swap lock passes 0, because its gas is
/// a separate ZCRYPT note.
fn asset_lock_tx(
    alice: &Account,
    node: &mut Node,
    asset: u64,
    lock_value: u64,
    burn_blind: [u64; 4],
    fee: u64,
    // The lock envelope the spend is bound to; must match what the node rebuilds from the
    // lock parameters, or the proof is (correctly) rejected as malleated.
    envelope: &[u8],
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
            t.append(x).unwrap();
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
    let change_out: OutCoin = (2 * v - lock_value - fee, keys::random_blind(), alice.pubkey(), asset);
    shield_tx::build_bound(CHAIN, &[mk(&c0, idx(&c0)), mk(&c1, idx(&c1))], &[burn_out, change_out], fee, vec![keys::cover_note_bytes(), keys::cover_note_bytes()], envelope)
        .expect("lock shield proof")
}

/// A burn-lock spend: fee is `MIN_FEE` of the locked asset, taken out of the change.
fn burn_lock_tx(
    alice: &Account,
    node: &mut Node,
    asset: u64,
    lock_value: u64,
    burn_blind: [u64; 4],
    envelope: &[u8],
) -> zcrypt_core::shield_tx::ShieldTx {
    asset_lock_tx(alice, node, asset, lock_value, burn_blind, zcrypt_core::emission::MIN_FEE, envelope)
}

/// A swap-lock asset spend: fee 0. Gas is [`zcrypt_gas`], not this proof.
fn swap_asset_tx(
    alice: &Account,
    node: &mut Node,
    asset: u64,
    lock_value: u64,
    burn_blind: [u64; 4],
    envelope: &[u8],
) -> zcrypt_core::shield_tx::ShieldTx {
    asset_lock_tx(alice, node, asset, lock_value, burn_blind, 0, envelope)
}

/// Seed a ZCRYPT coin and prove a fee-0 spend whose output[0] burns exactly 0.01 ZCRYPT.
/// Returns `(gas_tx, gas_blind)`.
fn zcrypt_gas(owner: &Account, node: &mut Node, payload: &[u8]) -> (zcrypt_core::shield_tx::ShieldTx, [u64; 4]) {
    let fee = zcrypt_core::emission::MIN_FEE;
    let coin = owner.own_coin(fee + 1_000, keys::random_blind());
    node.seed_coin(coin.commitment());
    let pool: Vec<Commitment> = node.commitment_leaves();
    let idx = pool.iter().position(|x| *x == coin.commitment()).expect("gas coin is in the pool");
    let mut t = zcrypt_shield::tree::CommitmentTree::new();
    for &x in &pool {
        t.append(x).unwrap();
    }
    let (path_siblings, path_dirs) = t.path(idx).unwrap();
    let spend = Spend {
        value: coin.value,
        blind: coin.blind,
        spend_secret: coin.spend_secret,
        asset_id: coin.asset_id,
        path_siblings,
        path_dirs,
    };
    let gas_blind = keys::random_blind();
    let burn: OutCoin = (fee, gas_blind, BURN_PK, zcrypt_shield::ASSET_ZCRYPT);
    let change: OutCoin = (1_000, keys::random_blind(), owner.pubkey(), zcrypt_shield::ASSET_ZCRYPT);
    let tx = shield_tx::build_bound(
        CHAIN,
        &[spend],
        &[burn, change],
        0,
        vec![keys::cover_note_bytes(), keys::cover_note_bytes()],
        &shield_tx::gas_pay_envelope(payload),
    )
    .expect("ZCRYPT gas proof");
    (tx, gas_blind)
}

/// The envelope for a plain `0x5D` burn-lock (claim and refund both go to `owner`).
fn burn_env(asset: u64, value: u64, lock: [u8; 32], timeout: u64, owner: &Account) -> Vec<u8> {
    zcrypt_core::htlc_shield::lock_envelope(
        zcrypt_core::htlc_shield::ENV_BURN_LOCK,
        asset, value, &lock, timeout, &owner.pubkey(), &owner.pubkey(), &[],
    )
}

/// The envelope for a `0x62` swap-lock: `counterparty` claims with the preimage, `locker` is
/// refunded on timeout.
fn swap_env(
    asset: u64, value: u64, lock: [u8; 32], timeout: u64, counterparty: &Account, locker: &Account,
) -> Vec<u8> {
    zcrypt_core::htlc_shield::lock_envelope(
        zcrypt_core::htlc_shield::ENV_SWAP_LOCK,
        asset, value, &lock, timeout, &counterparty.pubkey(), &locker.pubkey(), &[],
    )
}

#[test]
fn burn_lock_then_claim_burns_zbtc() {
    let (alice, mut node, asset, _keyset, _signers) = setup();
    node.set_height(10);
    let lock_value = 150_000u64;
    let burn_blind = keys::random_blind();
    let x = &pre("redeem-preimage-99");
    let tx = burn_lock_tx(&alice, &mut node, asset, lock_value, burn_blind,
        &burn_env(asset, lock_value, htlc_hashlock(x), 100, &alice));

    // Declaring a value that doesn't match output[0]'s actual opening is rejected
    // (the node binds the escrow to the real coin, so you can't over-declare).
    assert!(node
        .htlc_burn_lock(CHAIN, &tx, lock_value + 1, burn_blind, asset, htlc_hashlock(x), 100, alice.pubkey(), &[])
        .is_err());

    let id = node
        .htlc_burn_lock(CHAIN, &tx, lock_value, burn_blind, asset, htlc_hashlock(x), 100, alice.pubkey(), &[])
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
    let x = &pre("never-revealed");
    let tx = burn_lock_tx(&alice, &mut node, asset, lock_value, burn_blind,
        &burn_env(asset, lock_value, htlc_hashlock(x), 20, &alice));
    let id = node
        .htlc_burn_lock(CHAIN, &tx, lock_value, burn_blind, asset, htlc_hashlock(x), 20, alice.pubkey(), &[])
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

/// A valid compressed secp256k1 point, for the Bitcoin payout key of a `0x67` redeem.
fn btc_pk(seed: u8) -> [u8; 33] {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
    bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize()
}

/// MEMPOOL MALLEABILITY. A lock transaction carries its parameters in plaintext beside the
/// shield proof. A front-runner cannot reprove (that needs the victim's secrets), but they can
/// copy the proof verbatim, rewrite those parameters to point at themselves, and race the
/// original onto the chain — the nullifiers are identical, so whichever lands first wins and
/// the victim's transaction dies as a double-spend.
///
/// Two thefts followed. Rewriting `refund_pk` on a burn-lock makes the victim's coins
/// re-materialize to the attacker at timeout, no Bitcoin leg needed. Rewriting the hashlock
/// and payout key on a `0x67` redeem makes the operator's reserve pay the attacker while the
/// victim's zBTC burns. Binding the envelope into the proof kills both: consensus rebuilds the
/// envelope from the parameters it was handed, and a rewritten one no longer matches the proof.
#[test]
fn malleated_burn_lock_envelope_is_rejected() {
    let (alice, mut node, asset, _keyset, _signers) = setup();
    let attacker = Account::from_seed([0xEE; 32]);
    node.set_height(10);
    let (value, timeout) = (150_000u64, 100u64);
    let blind = keys::random_blind();
    let x = &pre("redeem-preimage-99");
    let lock = htlc_hashlock(x);
    let tx = burn_lock_tx(&alice, &mut node, asset, value, blind,
        &burn_env(asset, value, lock, timeout, &alice));

    // Each of these is a distinct rewrite of the envelope the victim proved over.
    // The proof is untouched and its nullifiers are unspent, so before the fix every one of
    // them was accepted.
    assert!(
        node.htlc_burn_lock(CHAIN, &tx, value, blind, asset, lock, timeout, attacker.pubkey(), &[]).is_err(),
        "refund key redirected to the attacker must be rejected"
    );
    assert!(
        node.htlc_burn_lock(CHAIN, &tx, value, blind, asset, htlc_hashlock(&pre("attacker")), timeout, alice.pubkey(), &[]).is_err(),
        "substituted hashlock must be rejected"
    );
    assert!(
        node.htlc_burn_lock(CHAIN, &tx, value, blind, asset, lock, timeout + 1, alice.pubkey(), &[]).is_err(),
        "altered timeout must be rejected"
    );
    // A 0x5D envelope must not pass as a 0x67 one: the kind is domain-separated.
    assert!(
        node.htlc_burn_lock(CHAIN, &tx, value, blind, asset, lock, timeout, alice.pubkey(), &btc_pk(3)).is_err(),
        "a burn-lock envelope must not be replayable as a BTC redeem"
    );
    // ...and the untouched original still works, so the binding costs the honest path nothing.
    let id = node
        .htlc_burn_lock(CHAIN, &tx, value, blind, asset, lock, timeout, alice.pubkey(), &[])
        .expect("the envelope the user actually proved over is accepted");
    assert_eq!(node.htlc_escrow(&id).unwrap().state, EscrowState::Open);
}

/// The `0x67` redeem: the Bitcoin payout key the operator's watcher reads off-chain is bound
/// to the proof, so only the owner of the burned zBTC can name where the reserve BTC goes.
#[test]
fn malleated_redeem_payout_key_is_rejected() {
    let (alice, mut node, asset, _keyset, _signers) = setup();
    node.set_height(10);
    let (value, timeout) = (150_000u64, 100u64);
    let blind = keys::random_blind();
    let lock = htlc_hashlock(&pre("redeem-x"));
    let (user_pk, attacker_pk) = (btc_pk(1), btc_pk(2));
    let envelope = zcrypt_core::htlc_shield::lock_envelope(
        zcrypt_core::htlc_shield::ENV_BURN_LOCK_BTC,
        asset, value, &lock, timeout, &alice.pubkey(), &alice.pubkey(), &user_pk,
    );
    let tx = burn_lock_tx(&alice, &mut node, asset, value, blind, &envelope);

    assert!(
        node.htlc_burn_lock(CHAIN, &tx, value, blind, asset, lock, timeout, alice.pubkey(), &attacker_pk).is_err(),
        "payout key swapped to the attacker's must be rejected"
    );
    // A malformed key is refused outright: the watcher would otherwise lock reserve BTC to an
    // address nobody can claim.
    assert!(
        node.htlc_burn_lock(CHAIN, &tx, value, blind, asset, lock, timeout, alice.pubkey(), &[0xFFu8; 33]).is_err(),
        "malformed payout key must be rejected"
    );
    node.htlc_burn_lock(CHAIN, &tx, value, blind, asset, lock, timeout, alice.pubkey(), &user_pk)
        .expect("the user's own payout key is accepted");
}

/// A swap-lock names both the counterparty who claims and the locker who is refunded, so both
/// must be bound or a front-runner redirects one leg of the trade.
#[test]
fn malleated_swap_lock_envelope_is_rejected() {
    let alice = Account::from_seed([0xA5; 32]);
    let bob = Account::from_seed([0xB5; 32]);
    let attacker = Account::from_seed([0xEE; 32]);
    let mut node = Node::new();
    let asset = node.register_asset("AAA", 8, None, 1_000_000_000).unwrap();
    node.set_height(10);
    let (value, timeout) = (100_000u64, 100u64);
    let blind = keys::random_blind();
    let lock = htlc_hashlock(&pre("swap-x"));
    let tx = swap_asset_tx(&alice, &mut node, asset, value, blind,
        &swap_env(asset, value, lock, timeout, &bob, &alice));
    let (gas_tx, gas_blind) = zcrypt_gas(&alice, &mut node, &shield_tx::txbind(CHAIN, &tx));

    // A nonzero asset fee is rejected before either proof mutates state, so the gas
    // note below is still spendable for the honest lock.
    let mut bad_fee = tx.clone();
    bad_fee.fee = 1;
    let err = node
        .swap_lock(CHAIN, &bad_fee, &gas_tx, gas_blind, value, blind, asset, lock, timeout, bob.pubkey(), alice.pubkey())
        .unwrap_err();
    assert!(err.contains("fee 0"), "{err}");
    // The gas note's first output must be the 0.01 ZCRYPT burn coin, not the asset spend.
    let err = node
        .swap_lock(CHAIN, &tx, &tx, gas_blind, value, blind, asset, lock, timeout, bob.pubkey(), alice.pubkey())
        .unwrap_err();
    assert!(err.contains("burn coin"), "{err}");

    assert!(
        node.swap_lock(CHAIN, &tx, &gas_tx, gas_blind, value, blind, asset, lock, timeout, attacker.pubkey(), alice.pubkey()).is_err(),
        "counterparty redirected to the attacker must be rejected"
    );
    assert!(
        node.swap_lock(CHAIN, &tx, &gas_tx, gas_blind, value, blind, asset, lock, timeout, bob.pubkey(), attacker.pubkey()).is_err(),
        "refund key redirected to the attacker must be rejected"
    );
    node.swap_lock(CHAIN, &tx, &gas_tx, gas_blind, value, blind, asset, lock, timeout, bob.pubkey(), alice.pubkey())
        .expect("the envelope the locker actually proved over is accepted");
}

#[test]
fn expired_escrow_never_mints() {
    let (alice, mut node, asset, keyset, signers) = setup();
    let x = &pre("unused-preimage");
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
    let x = &pre("atomic-swap-preimage-xyz");
    let lock = htlc_hashlock(x);

    // Alice locks 100_000 A, claimable by Bob (refund to Alice on timeout). Gas is 0.01 ZCRYPT.
    let a_blind = keys::random_blind();
    let a_tx = swap_asset_tx(&alice, &mut node, asset_a, 100_000, a_blind,
        &swap_env(asset_a, 100_000, lock, 100, &bob, &alice));
    let (a_gas, a_gas_blind) = zcrypt_gas(&alice, &mut node, &shield_tx::txbind(CHAIN, &a_tx));
    let a_escrow = node
        .swap_lock(CHAIN, &a_tx, &a_gas, a_gas_blind, 100_000, a_blind, asset_a, lock, 100, bob.pubkey(), alice.pubkey())
        .unwrap();

    // Bob locks 120_000 B, claimable by Alice (refund to Bob on timeout).
    let b_blind = keys::random_blind();
    let b_tx = swap_asset_tx(&bob, &mut node, asset_b, 120_000, b_blind,
        &swap_env(asset_b, 120_000, lock, 100, &alice, &bob));
    let (b_gas, b_gas_blind) = zcrypt_gas(&bob, &mut node, &shield_tx::txbind(CHAIN, &b_tx));
    let b_escrow = node
        .swap_lock(CHAIN, &b_tx, &b_gas, b_gas_blind, 120_000, b_blind, asset_b, lock, 100, alice.pubkey(), bob.pubkey())
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

/// The **trustless zBTC mint**: register zBTC with the SPV sentinel authority,
/// fabricate a valid regtest Bitcoin chain containing a real HTLC deposit, relay
/// its headers into consensus, and mint against the SPV proof. Then verify every
/// trustless guarantee: no threshold key set can mint zBTC, the authority can
/// never be rotated away from SPV, and one deposit mints exactly once.
#[test]
fn spv_mint_end_to_end_and_trustless_guarantees() {
    use zcrypt_core::spv::{self, testutil};

    let (alice, _mn) = keys::new_account();
    let mut node = Node::new();
    let reserve = testutil::test_pk(7);
    let refund = testutil::test_pk(9);
    // zBTC's authority is the SPV sentinel over the Bitcoin reserve key —
    // consensus-derived, no key set behind it.
    let asset = node
        .register_asset("zBTC", 8, Some(spv::spv_authority(&reserve)), 21_000_000 * 100_000_000)
        .unwrap();
    node.set_height(10);

    // A real (regtest-valid) Bitcoin block containing the HTLC funding tx.
    let x = &pre("spv-swap-preimage-0123456789abcdef");
    let lock = htlc_hashlock(x);
    let value = 250_000u64; // sats locked == base units minted (1:1)
    let btc_locktime = 100u32; // well past tip(1) + regtest margin(20)
    let tx = testutil::funding_tx(&lock, &reserve, &refund, btc_locktime, value, 1);
    let (block, proof) = testutil::deposit_proof(
        &spv::REGTEST_GENESIS, &tx, 1_296_689_000, reserve, refund, btc_locktime, 0, 1,
    );
    let (accepted, btc_tip) = node.submit_btc_headers(&block).unwrap();
    assert_eq!((accepted, btc_tip), (1, 1), "header relay advances the consensus BTC tip");
    // H1 recipient binding: the depositor's refund key (test_pk(9)) authorizes Alice.
    let __refund_auth = 9u8; let __proof_auth = &proof; let __pk_auth = alice.pubkey();

    // Minting more than the locked sats is rejected (1:1 backing).
    assert!(open_spv(&mut node, __refund_auth, asset, value + 1, lock, 100, alice.pubkey(), __proof_auth).is_err());

    // The SPV-verified deposit opens the escrow; Alice claims with the preimage
    // and gets a private zBTC coin, supply advances.
    let id = open_spv(&mut node, __refund_auth, asset, value, lock, 100, alice.pubkey(), __proof_auth).unwrap();
    let minted = node.htlc_claim(&id, x).unwrap().expect("mint escrow yields a coin");
    // The recipient's coin is value minus the protocol bridge fee (skimmed to stakers);
    // supply still counts the full value (net to Alice + fee to stakers = value, 1:1 backed).
    let net = value - zcrypt_core::emission::bridge_fee(value);
    assert_eq!(alice.htlc_coin(net, asset, &id).commitment(), minted);
    assert_eq!(node.asset_minted(asset), value);

    // One deposit mints ONCE. A replay with a different hashlock dies on the
    // script binding (the deposit's HTLC commits to the original preimage)...
    let lock2 = htlc_hashlock(&pre("different-preimage-0123456789"));
    assert!(open_spv(&mut node, __refund_auth, asset, value, lock2, 200, alice.pubkey(), __proof_auth)
        .unwrap_err()
        .contains("HTLC script"));
    // ...and a replay with the SAME hashlock (fresh escrow id via a new timeout)
    // dies on the claimed-outpoint guard — the deposit is spent.
    assert!(open_spv(&mut node, __refund_auth, asset, value, lock, 200, alice.pubkey(), __proof_auth)
        .unwrap_err()
        .contains("already minted"));

    // NO threshold key set can mint zBTC: no keyset commits to the SPV sentinel.
    let (ks, signers) = mint_auth::derive_keyset(b"would-be-treasury", 3, 2);
    let msg = mint_auth::mint_message(CHAIN, asset, 1_000, &lock2, 200, &alice.pubkey());
    let sigs = mint_auth::authorize(&ks, &signers, &msg);
    assert!(node.htlc_open(CHAIN, asset, 1_000, lock2, 200, alice.pubkey(), &ks, &sigs).is_err());

    // And the authority can NEVER rotate away from SPV (one-way trustlessness):
    // a rotation needs a threshold signature from a key set committing to the
    // CURRENT authority — which no key set can.
    let rot_msg = mint_auth::rotate_message(CHAIN, asset, node.authority_epoch(asset), &ks.commitment());
    let rot_sigs = mint_auth::authorize(&ks, &signers, &rot_msg);
    assert!(node.rotate_authority(CHAIN, asset, ks.commitment(), &ks, &rot_sigs).is_err());
}

/// Maturity + void-on-reorg: an SPV mint is held IMMATURE (not spendable) until its
/// Bitcoin deposit is buried past reorg risk. The honest path matures into a
/// spendable coin; the double-spend-reorg path is VOIDED (supply restored) before
/// the attacker can ever spend it — the defense against the deep-reorg attack.
#[test]
fn spv_mint_matures_or_voids_on_reorg() {
    use zcrypt_core::bitcoin::block::Header;
    use zcrypt_core::bitcoin::consensus::deserialize;
    use zcrypt_core::bitcoin::hashes::Hash as _;
    use zcrypt_core::spv::{self, testutil, REGTEST_GENESIS};

    let bhash = |raw: &[u8; 80]| deserialize::<Header>(raw).unwrap().block_hash().to_byte_array();
    let (attacker, _mn) = keys::new_account();
    let mut node = Node::new();
    let reserve = testutil::test_pk(7);
    let refund = testutil::test_pk(9);
    let asset = node
        .register_asset("zBTC", 8, Some(spv::spv_authority(&reserve)), 21_000_000 * 100_000_000)
        .unwrap();
    node.set_height(10);

    // Deposit in block A1, buried by A2/A3 (regtest min_conf=1, maturity_conf=3).
    let x = &pre("reorg-defense-preimage-0123456789");
    let lock = htlc_hashlock(x);
    let value = 100_000u64;
    let dep_tx = testutil::funding_tx(&lock, &reserve, &refund, 200, value, 1);
    let (a1, proof) = testutil::deposit_proof(&REGTEST_GENESIS, &dep_tx, 1_296_690_000, reserve, refund, 200, 0, 1);
    let a2 = testutil::mine_header(&a1, &[], 1_296_690_600);
    let a3 = testutil::mine_header(&a2, &[], 1_296_691_200);
    for h in [&a1, &a2, &a3] {
        node.submit_btc_headers(h).unwrap();
    }
    let __refund_auth = 9u8; let __proof_auth = &proof; let __pk_auth = attacker.pubkey();
    let escrow = open_spv(&mut node, __refund_auth, asset, value, lock, 500, attacker.pubkey(), __proof_auth).unwrap();
    let coin = node.htlc_claim(&escrow, x).unwrap().unwrap();

    // Immediately after claim: supply counted, but the coin is IMMATURE — held out of
    // the spendable tree, so it cannot be spent, and it's still reorg-voidable.
    assert_eq!(node.asset_minted(asset), value);
    assert_eq!(node.immature_count(), 1);
    assert!(!node.commitment_leaves().contains(&coin), "immature coin must NOT be a spendable leaf");

    // ---- Attack: heavier fork B from genesis omitting the deposit → reorg ----
    let mut prev = REGTEST_GENESIS;
    for i in 0..5u32 {
        let b = testutil::mine_header(&prev, &[], 1_296_690_001 + 700 * i);
        node.submit_btc_headers(&b).unwrap();
        prev = b;
    }
    assert!(node.spv().confirmations(&bhash(&a1)).is_none(), "deposit block must be orphaned");

    // Inclusion re-verification: the sweep does NOT void immediately — it opens a grace
    // window for a re-anchor (a benign reorg would re-mine the deposit). No void yet.
    let grace = node.spv().reanchor_grace();
    let r0 = node.process_btc_maturity();
    assert_eq!(r0.voided.len(), 0, "orphan starts a grace window, not an instant void");
    assert_eq!(node.immature_count(), 1, "still held immature during grace");
    // The double-spend fork never re-includes the deposit → no re-anchor → void after grace.
    let mut report = zcrypt_core::node::MaturityReport::default();
    for i in 0..grace {
        let b = testutil::mine_header(&prev, &[], 1_296_695_000 + 700 * i as u32);
        node.submit_btc_headers(&b).unwrap();
        prev = b;
        report = node.process_btc_maturity();
    }
    assert_eq!(report.voided.len(), 1, "genuine double-spend voided once grace elapses");
    assert_eq!(report.voided_value, value);
    assert_eq!(node.asset_minted(asset), 0, "reorg-voided mint restores supply — no unbacked zBTC");
    assert_eq!(node.immature_count(), 0);
    assert!(!node.commitment_leaves().contains(&coin), "voided coin is never spendable");

    // ---- Honest path (fresh deposit on the now-canonical chain B) matures + spends ----
    let (alice, _mn2) = keys::new_account();
    let x2 = &pre("honest-mature-preimage-0123456789");
    let lock2 = htlc_hashlock(x2);
    let dep2 = testutil::funding_tx(&lock2, &reserve, &refund, 200, value, 2);
    // Mine the deposit on top of B, then bury it maturity_conf(3)+ deep.
    let (d1, proof2) = testutil::deposit_proof(&prev, &dep2, 1_296_695_000, reserve, refund, 200, 0, 2);
    node.submit_btc_headers(&d1).unwrap();
    let mut p = d1;
    for i in 0..3u32 {
        let n = testutil::mine_header(&p, &[], 1_296_695_600 + 600 * i);
        node.submit_btc_headers(&n).unwrap();
        p = n;
    }
    let __refund_auth2 = 9u8; let __proof_auth2 = &proof2; let __pk_auth2 = alice.pubkey();
    let e2 = open_spv(&mut node, __refund_auth2, asset, value, lock2, 500, alice.pubkey(), __proof_auth2).unwrap();
    let coin2 = node.htlc_claim(&e2, x2).unwrap().unwrap();
    // The deposit already has ≥ maturity_conf confirmations, so the next sweep matures it.
    let r2 = node.process_btc_maturity();
    assert_eq!(r2.matured.len(), 1);
    assert!(node.commitment_leaves().contains(&coin2), "matured coin IS a spendable leaf");
    assert_eq!(node.immature_count(), 0);
    assert_eq!(node.asset_minted(asset), value);
}

/// Inclusion re-verification: a BENIGN reorg that re-mines the SAME deposit into a
/// different block must NOT void the mint — a relayer re-anchors it to the new block
/// and it matures normally. This distinguishes benign chain churn from a double-spend
/// (which the previous test voids), so honest users aren't punished by ordinary reorgs.
#[test]
fn spv_mint_reanchors_across_a_benign_reorg() {
    use zcrypt_core::bitcoin::block::Header;
    use zcrypt_core::bitcoin::consensus::deserialize;
    use zcrypt_core::bitcoin::hashes::Hash as _;
    use zcrypt_core::spv::{self, testutil, REGTEST_GENESIS};

    let bhash = |raw: &[u8; 80]| deserialize::<Header>(raw).unwrap().block_hash().to_byte_array();
    let (alice, _mn) = keys::new_account();
    let mut node = Node::new();
    let reserve = testutil::test_pk(7);
    let refund = testutil::test_pk(9);
    let asset = node
        .register_asset("zBTC", 8, Some(spv::spv_authority(&reserve)), 21_000_000 * 100_000_000)
        .unwrap();
    node.set_height(10);

    let x = &pre("reanchor-preimage-0123456789abcde");
    let lock = htlc_hashlock(x);
    let value = 100_000u64;
    let deposit = testutil::funding_tx(&lock, &reserve, &refund, 200, value, 1);

    // Chain A: deposit in A1, shallow (depth 2 < maturity) → mint held immature.
    let (a1, proof_a) = testutil::deposit_proof(&REGTEST_GENESIS, &deposit, 1_296_690_000, reserve, refund, 200, 0, 1);
    let a2 = testutil::mine_header(&a1, &[], 1_296_690_600);
    for h in [&a1, &a2] {
        node.submit_btc_headers(h).unwrap();
    }
    let __refund_auth = 9u8; let __proof_auth = &proof_a; let __pk_auth = alice.pubkey();
    let e = open_spv(&mut node, __refund_auth, asset, value, lock, 500, alice.pubkey(), __proof_auth).unwrap();
    let coin = node.htlc_claim(&e, x).unwrap().unwrap();
    assert_eq!(node.immature_count(), 1);

    // BENIGN reorg: heavier fork B that RE-INCLUDES the same deposit tx in block B1.
    let (b1, reproof) = testutil::deposit_proof(&REGTEST_GENESIS, &deposit, 1_296_690_001, reserve, refund, 200, 0, 2);
    node.submit_btc_headers(&b1).unwrap();
    let mut prev = b1;
    for i in 0..4u32 {
        let b = testutil::mine_header(&prev, &[], 1_296_690_800 + 700 * i);
        node.submit_btc_headers(&b).unwrap();
        prev = b;
    }
    assert!(node.spv().confirmations(&bhash(&a1)).is_none(), "A1 orphaned");
    assert!(node.spv().confirmations(&bhash(&b1)).is_some(), "deposit re-mined into B1 (canonical)");

    // The sweep opens a grace window (doesn't void) — the deposit still exists on B.
    node.process_btc_maturity();
    assert_eq!(node.immature_count(), 1, "not voided — benign reorg, grace window open");

    // A relayer RE-ANCHORS the mint to B1 with a fresh inclusion proof for the same txid.
    node.reanchor_deposit(&reproof).expect("re-anchor to the re-mined block");

    // Now anchored to B1 (buried ≥ maturity), the next sweep MATURES it — no void, no loss.
    let r = node.process_btc_maturity();
    assert_eq!(r.voided.len(), 0, "a re-anchored (benign) deposit is never voided");
    assert_eq!(r.matured.len(), 1);
    assert!(node.commitment_leaves().contains(&coin), "re-anchored coin matured → spendable");
    assert_eq!(node.asset_minted(asset), value, "supply intact — honest mint survived the reorg");
}

/// Value capture: a bridge mint skims a small protocol fee to ZCRYPT stakers, taken in
/// the bridged asset at maturity. This proves the whole path conserves value (recipient
/// net + staker fee == full minted value, backed 1:1), the fee reaches the staker by
/// stake weight, and the staker can reconstruct and spend the claimed fee coins.
#[test]
fn bridge_fee_accrues_to_stakers_and_conserves() {
    use zcrypt_core::emission;
    use zcrypt_core::spv::{self, testutil, REGTEST_GENESIS};

    let staker = Account::from_seed([0x5a; 32]);
    let (alice, _mn) = keys::new_account();
    let mut node = Node::new();
    // A single validator whose reward address is the staker's — it will earn the fee.
    let vid = vec![1u8; 20];
    node.bond(vid.clone(), vec![1u8; 32], zcrypt_core::staking::MIN_STAKE, staker.reward_address(), zcrypt_core::staking::DEFAULT_COMMISSION_BPS).unwrap();
    let reserve = testutil::test_pk(7);
    let refund = testutil::test_pk(9);
    let asset = node
        .register_asset("zBTC", 8, Some(spv::spv_authority(&reserve)), 21_000_000 * 100_000_000)
        .unwrap();
    node.set_height(1);

    let value = 100_000u64;
    let fee = emission::bridge_fee(value);
    assert!(fee > 0, "test value must produce a nonzero fee");

    // SPV-mint, buried to its value-scaled maturity depth.
    let x = &pre("fee-preimage-0123456789abcdefff");
    let lock = htlc_hashlock(x);
    let dep = testutil::funding_tx(&lock, &reserve, &refund, 200, value, 1);
    let (d1, proof) = testutil::deposit_proof(&REGTEST_GENESIS, &dep, 1_296_690_000, reserve, refund, 200, 0, 1);
    node.submit_btc_headers(&d1).unwrap();
    let mut p = d1;
    for i in 0..5u32 {
        let n = testutil::mine_header(&p, &[], 1_296_690_600 + 600 * i);
        node.submit_btc_headers(&n).unwrap();
        p = n;
    }
    let __refund_auth = 9u8; let __proof_auth = &proof; let __pk_auth = alice.pubkey();
    let e = open_spv(&mut node, __refund_auth, asset, value, lock, 500, alice.pubkey(), __proof_auth).unwrap();
    let minted = node.htlc_claim(&e, x).unwrap().unwrap();

    // Recipient's coin is net; supply counts the full value (net + fee, 1:1 backed).
    assert_eq!(alice.htlc_coin(value - fee, asset, &e).commitment(), minted);
    assert_eq!(node.asset_minted(asset), value);
    // No fee is claimable before maturity.
    assert_eq!(node.claimable_fee(&staker.pubkey(), asset), 0);

    // Mature → the fee accrues; then an epoch distributes it to the staker by weight.
    assert_eq!(node.process_btc_maturity().matured.len(), 1);
    for h in 1..=emission::EPOCH {
        node.set_height(h);
        node.record_block_signers(&[vid.clone()]);
        node.maybe_distribute_rewards(h);
    }
    assert_eq!(node.claimable_fee(&staker.pubkey(), asset), fee, "staker earns the whole bridge fee");

    // Claim it: asset coins the staker can reconstruct and that are now spendable leaves.
    let coins = node.claim_fee_rewards(&staker.pubkey(), asset, fee).unwrap();
    let claimed: u64 = coins
        .iter()
        .enumerate()
        .map(|(i, c)| {
            // Single chunk here (fee < MAX_COIN), index 0; reconstruct and confirm it matches.
            let coin = staker.fee_reward_coin(fee, asset, i as u64);
            assert_eq!(&coin.commitment(), c, "staker reconstructs the claimed fee coin");
            assert!(node.commitment_leaves().contains(c), "claimed fee coin is spendable");
            coin.value
        })
        .sum();
    assert_eq!(claimed, fee);
    assert_eq!(node.claimable_fee(&staker.pubkey(), asset), 0, "fully claimed");

    // Conservation: recipient net + staker fee == full minted value; supply unchanged.
    assert_eq!((value - fee) + claimed, value);
    assert_eq!(node.asset_minted(asset), value);
}

/// A deposit paying someone OTHER than the pinned reserve key can never mint —
/// the self-lock/self-reclaim attack that would create unbacked zBTC.
#[test]
fn spv_mint_rejects_non_reserve_deposits() {
    use zcrypt_core::spv::{self, testutil, MintProof};

    let (alice, _mn) = keys::new_account();
    let mut node = Node::new();
    let reserve = testutil::test_pk(7);
    let attacker = testutil::test_pk(13);
    let asset = node
        .register_asset("zBTC", 8, Some(spv::spv_authority(&reserve)), 21_000_000 * 100_000_000)
        .unwrap();
    node.set_height(10);

    // The attacker locks BTC claimable by THEMSELVES and proves it honestly.
    let x = &pre("self-lock-preimage-0123456789abc");
    let lock = htlc_hashlock(x);
    let tx = testutil::funding_tx(&lock, &attacker, &attacker, 100, 500_000, 2);
    let (block, proof) = testutil::deposit_proof(
        &spv::REGTEST_GENESIS, &tx, 1_296_689_600, attacker, attacker, 100, 0, 2,
    );
    node.submit_btc_headers(&block).unwrap();
    let __refund_auth = 13u8; let __proof_auth = &proof; let __pk_auth = alice.pubkey();
    assert!(open_spv(&mut node, __refund_auth, asset, 500_000, lock, 100, alice.pubkey(), __proof_auth)
        .unwrap_err()
        .contains("reserve key"));
    // Lying about the claim key instead fails the script check inside the proof.
    let lying = MintProof { reserve_pk: reserve, ..proof };
    let __refund_auth_lying = 13u8; let __proof_auth_lying = &lying; let __pk_auth_lying = alice.pubkey();
    assert!(open_spv(&mut node, __refund_auth_lying, asset, 500_000, lock, 100, alice.pubkey(), __proof_auth_lying).is_err());
    assert_eq!(node.asset_minted(asset), 0, "no unbacked zBTC exists");
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
    let x = &pre("never-revealed-preimage");
    let a_blind = keys::random_blind();
    let a_tx = swap_asset_tx(&alice, &mut node, asset_a, 100_000, a_blind,
        &swap_env(asset_a, 100_000, htlc_hashlock(x), 100, &bob, &alice));
    let (a_gas, a_gas_blind) = zcrypt_gas(&alice, &mut node, &shield_tx::txbind(CHAIN, &a_tx));
    let a_escrow = node
        .swap_lock(CHAIN, &a_tx, &a_gas, a_gas_blind, 100_000, a_blind, asset_a, htlc_hashlock(x), 100, bob.pubkey(), alice.pubkey())
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

/// Bridge C3 regression: an SPV mint escrow can be claimed only while the reserve still has
/// its full sweep margin before the deposit's Bitcoin refund lock. Once the committed Bitcoin
/// tip plus the margin reaches the lock, the claim is refused (the depositor could otherwise
/// refund the BTC on Bitcoin and still take the zBTC), and the escrow stays open for expiry.
#[test]
fn spv_mint_claim_is_refused_once_the_refund_lock_is_within_sweep_margin() {
    use zcrypt_core::spv::{self, testutil, REGTEST_GENESIS};

    // Two identical deposits on two fresh nodes: one advanced to the last safe Bitcoin
    // height (claim allowed), one advanced a single block further (claim refused).
    for (extra_headers, expect_ok) in [(2u32, true), (3u32, false)] {
        let (alice, _mn) = keys::new_account();
        let mut node = Node::new();
        let reserve = testutil::test_pk(7);
        let refund = testutil::test_pk(9);
        let asset = node
            .register_asset("zBTC", 8, Some(spv::spv_authority(&reserve)), 21_000_000 * 100_000_000)
            .unwrap();
        node.set_height(10);

        let x = &pre("claim-gate-preimage-0123456789ab");
        let lock = htlc_hashlock(x);
        let value = 250_000u64;
        // After the funding block the Bitcoin tip is 1 and the regtest sweep margin is 20, so
        // the smallest lock the gate accepts at open is 21. Lock 24 leaves three blocks of slack.
        let btc_locktime = 24u32;
        let tx = testutil::funding_tx(&lock, &reserve, &refund, btc_locktime, value, 1);
        let (block, proof) =
            testutil::deposit_proof(&REGTEST_GENESIS, &tx, 1_296_689_000, reserve, refund, btc_locktime, 0, 1);
        node.submit_btc_headers(&block).unwrap();
        let id = open_spv(&mut node, 9, asset, value, lock, 100, alice.pubkey(), &proof).unwrap();

        let mut prev = block;
        let mut tip = 1;
        for i in 0..extra_headers {
            prev = testutil::mine_header(&prev, &[], 1_296_689_600 + 600 * i);
            tip = node.submit_btc_headers(&prev).unwrap().1;
        }
        assert_eq!(tip, 1 + u64::from(extra_headers));

        let res = node.htlc_claim(&id, x);
        if expect_ok {
            // tip 3 + margin 20 = 23 < 24: still inside the sweep window.
            assert!(res.is_ok(), "claim inside the sweep window must succeed: {res:?}");
        } else {
            // tip 4 + margin 20 = 24 = lock: the reserve could no longer sweep in time.
            let err = res.unwrap_err();
            assert!(err.contains("refund lock"), "unexpected error: {err}");
            assert_eq!(node.htlc_escrow(&id).map(|e| e.state), Some(EscrowState::Open), "escrow stays open for expiry");
        }
    }
}

/// Regression (fix-pass re-audit NEW-1): once a settled escrow is pruned from the book, its
/// deterministic id must stay retired until its timeout has passed. Otherwise the identical
/// lock could be re-opened and a claim would mint a byte-identical coin commitment (and
/// nullifier) to the first one.
#[test]
fn pruned_escrow_ids_cannot_be_reopened_before_their_timeout() {
    use zcrypt_core::htlc_shield::ESCROW_RETENTION_BLOCKS;
    let (alice, mut node, asset, keyset, signers) = setup();
    node.set_height(10);
    let x = &pre("retired-id-regression-preimage-1");
    let lock = htlc_hashlock(x);
    let timeout = 10 + 2 * ESCROW_RETENTION_BLOCKS; // still far in the future after pruning
    let id = open_mint(&mut node, &keyset, &signers, asset, 1_000, lock, timeout, alice.pubkey()).unwrap();
    node.set_height(11);
    node.htlc_claim(&id, x).unwrap();
    // Same parameters while the settled escrow is still in the book: plain duplicate.
    assert!(open_mint(&mut node, &keyset, &signers, asset, 1_000, lock, timeout, alice.pubkey()).is_err());
    // Advance past the retention window so end_block prunes the settled entry.
    node.set_height(11 + ESCROW_RETENTION_BLOCKS + 1);
    node.end_block();
    assert!(node.htlc_escrow(&id).is_none(), "settled escrow is pruned");
    let err = open_mint(&mut node, &keyset, &signers, asset, 1_000, lock, timeout, alice.pubkey()).unwrap_err();
    assert!(err.contains("already used"), "re-open of a retired id must be refused: {err}");
    // A different timeout is a different escrow: allowed.
    open_mint(&mut node, &keyset, &signers, asset, 1_000, lock, timeout + 1, alice.pubkey()).unwrap();
}


/// Bridge review H1: the SPV mint claim gate measures the deposit's refund lock against the
/// consensus Bitcoin tip. If that tip is allowed to go stale, a depositor can refund on
/// Bitcoin and still claim zBTC. Opens and claims must therefore refuse a tip whose header
/// time lags the block clock by more than the freshness bound.
#[test]
fn spv_open_and_claim_refuse_a_stale_bitcoin_tip() {
    use zcrypt_core::spv::{self, testutil};

    let (alice, _mn) = keys::new_account();
    let mut node = Node::new();
    let reserve = testutil::test_pk(7);
    let refund = testutil::test_pk(9);
    let asset = node.register_spv_asset("zBTC", 8, &reserve, 21_000_000 * 100_000_000).unwrap();
    node.set_height(10);
    let max_age = node.spv().max_tip_age_secs();

    let x = &pre("stale-tip-preimage-0123456789abcdef");
    let lock = htlc_hashlock(x);
    let value = 250_000u64;
    let btc_locktime = 100u32;
    let tx = testutil::funding_tx(&lock, &reserve, &refund, btc_locktime, value, 1);
    let header_time = 1_296_689_000u32;
    let (block, proof) =
        testutil::deposit_proof(&spv::REGTEST_GENESIS, &tx, header_time, reserve, refund, btc_locktime, 0, 1);
    node.submit_btc_headers(&block).unwrap();

    // Block clock far past the tip's header time: the open is refused.
    node.set_block_time(u64::from(header_time) + max_age + 1);
    let err = open_spv(&mut node, 9, asset, value, lock, 100, alice.pubkey(), &proof).unwrap_err();
    assert!(err.contains("behind the block clock"), "{err}");

    // Fresh again (within the bound): the open succeeds.
    node.set_block_time(u64::from(header_time) + max_age);
    let id = open_spv(&mut node, 9, asset, value, lock, 100, alice.pubkey(), &proof).unwrap();

    // The tip goes stale before the claim (relay outage / header flood): claim refused, the
    // escrow stays Open (so it can still be claimed once headers catch up).
    node.set_block_time(u64::from(header_time) + max_age + 1);
    let err = node.htlc_claim(&id, x).unwrap_err();
    assert!(err.contains("behind the block clock"), "{err}");
    assert_eq!(node.htlc_escrow(&id).unwrap().state, EscrowState::Open);

    // Headers catch up (a newer header with a recent time): the claim goes through.
    let newer = testutil::mine_header(&block, &[], header_time + max_age as u32);
    node.submit_btc_headers(&newer).unwrap();
    node.htlc_claim(&id, x).unwrap().expect("mint escrow yields a coin");
}

/// Bridge review H3: the reserve key can be rotated on a running chain. The rotation must
/// be signed by the CURRENT key and is epoch-bound (no replay); after it, deposits already
/// mined to the old key (plus a short grace) still mint, later deposits to the old key are
/// refused, and deposits to the new key are accepted.
#[test]
fn spv_reserve_key_rotation() {
    use zcrypt_core::spv::{self, testutil, RESERVE_RETIRE_GRACE_BLOCKS};

    let (alice, _mn) = keys::new_account();
    let mut node = Node::new();
    let old_pk = testutil::test_pk(7);
    let new_pk = testutil::test_pk(8);
    let refund = testutil::test_pk(9);
    let cap = 21_000_000 * 100_000_000;
    let asset = node.register_spv_asset("zBTC", 8, &old_pk, cap).unwrap();
    assert_eq!(node.asset_meta(asset).unwrap().reserve_pk33(), Some(old_pk));
    node.set_height(10);

    // Deposit A: paid to the OLD key, mined at height 1 (before the rotation).
    let xa = &pre("rotation-deposit-a-0123456789abcdef");
    let lock_a = htlc_hashlock(xa);
    let value = 250_000u64;
    let tx_a = testutil::funding_tx(&lock_a, &old_pk, &refund, 100, value, 1);
    let (block1, proof_a) =
        testutil::deposit_proof(&spv::REGTEST_GENESIS, &tx_a, 1_296_689_000, old_pk, refund, 100, 0, 1);
    node.submit_btc_headers(&block1).unwrap();

    // A rotation signed by a key that is NOT the current reserve is refused.
    let wrong = spv::sign_reserve_rotation(&testutil::test_sk(9), CHAIN, asset, 0, &old_pk, &new_pk);
    assert!(node.rotate_spv_reserve(CHAIN, asset, &old_pk, &new_pk, &wrong).unwrap_err().contains("current reserve key"));
    // Naming a key that is not the pinned one as "old" is refused too.
    let sig9 = spv::sign_reserve_rotation(&testutil::test_sk(9), CHAIN, asset, 0, &refund, &new_pk);
    assert!(node.rotate_spv_reserve(CHAIN, asset, &refund, &new_pk, &sig9).is_err());

    // The genuine rotation (current key signs, epoch 0) is accepted at BTC tip height 1.
    let sig = spv::sign_reserve_rotation(&testutil::test_sk(7), CHAIN, asset, 0, &old_pk, &new_pk);
    let root_before = node.state_root();
    assert_eq!(node.rotate_spv_reserve(CHAIN, asset, &old_pk, &new_pk, &sig).unwrap(), 1);
    assert_ne!(node.state_root(), root_before, "rotation is committed in the app hash");
    let m = node.asset_meta(asset).unwrap();
    assert_eq!(m.reserve_pk33(), Some(new_pk));
    assert_eq!(m.authority, Some(spv::spv_authority(&new_pk)));
    assert_eq!(m.retired_reserves.len(), 1);
    assert_eq!(m.retired_reserves[0].retired_at_btc_height, 1);
    // Replaying the same signature fails: the epoch advanced.
    assert!(node.rotate_spv_reserve(CHAIN, asset, &old_pk, &new_pk, &sig).is_err());
    assert!(node.rotate_spv_reserve(CHAIN, asset, &new_pk, &old_pk, &sig).is_err());

    // Deposit A (old key, mined before the rotation) still opens and mints.
    let id_a = open_spv(&mut node, 9, asset, value, lock_a, 100, alice.pubkey(), &proof_a).unwrap();
    node.htlc_claim(&id_a, xa).unwrap().expect("old-key deposit still mints");

    // Deposit B: paid to the NEW key, mined after the rotation: accepted.
    let xb = &pre("rotation-deposit-b-0123456789abcdef");
    let lock_b = htlc_hashlock(xb);
    let tx_b = testutil::funding_tx(&lock_b, &new_pk, &refund, 100, value, 2);
    let (block2, proof_b) = testutil::deposit_proof(&block1, &tx_b, 1_296_689_600, new_pk, refund, 100, 0, 2);
    node.submit_btc_headers(&block2).unwrap();
    let id_b = open_spv(&mut node, 9, asset, value, lock_b, 100, alice.pubkey(), &proof_b).unwrap();
    node.htlc_claim(&id_b, xb).unwrap().expect("new-key deposit mints");

    // Deposit C: paid to the OLD key but mined well past the retirement grace: refused.
    let mut prev = block2;
    for k in 0..RESERVE_RETIRE_GRACE_BLOCKS as u32 {
        prev = testutil::mine_header(&prev, &[], 1_296_690_000 + 600 * k);
        node.submit_btc_headers(&prev).unwrap();
    }
    let xc = &pre("rotation-deposit-c-0123456789abcdef");
    let lock_c = htlc_hashlock(xc);
    let tx_c = testutil::funding_tx(&lock_c, &old_pk, &refund, 100, value, 3);
    let (late, proof_c) = testutil::deposit_proof(&prev, &tx_c, 1_296_695_000, old_pk, refund, 100, 0, 3);
    node.submit_btc_headers(&late).unwrap();
    let err = open_spv(&mut node, 9, asset, value, lock_c, 100, alice.pubkey(), &proof_c).unwrap_err();
    assert!(err.contains("pinned reserve key"), "{err}");

    // The rotation survives a snapshot round trip (it is source-of-truth state).
    let (restored, _) = Node::restore(node.snapshot(node.height())).unwrap();
    assert_eq!(restored.state_root(), node.state_root());
    assert_eq!(restored.asset_meta(asset).unwrap().reserve_pk33(), Some(new_pk));
}


/// The atomic-swap timeout ordering. The leg the preimage-revealer claims must expire FIRST.
/// With the order reversed, the revealer (Alice, the taker) can let her own lock expire,
/// refund it, and still claim Bob's lock, taking both sides. Consensus only enforces the
/// timeouts the parties chose, so this is the rule every swap wallet must apply
/// (`zcrypt_bridge::swap::swap_timeouts` / `maker_lock_is_safe`).
#[test]
fn swap_leg_claimed_by_the_revealer_must_expire_first() {
    let run = |a_timeout: u64, b_timeout: u64| -> (bool, bool) {
        let alice = Account::from_seed([0xA3; 32]);
        let bob = Account::from_seed([0xB3; 32]);
        let mut node = Node::new();
        let asset_a = node.register_asset("AAA", 8, None, 1_000_000_000).unwrap();
        let asset_b = node.register_asset("BBB", 8, None, 1_000_000_000).unwrap();
        node.set_height(10);
        let x = &pre("swap-ordering-preimage-0123456789");
        let lock = htlc_hashlock(x);
        // Alice (taker) locks A, claimable by Bob; Bob (maker) locks B, claimable by Alice.
        let a_blind = keys::random_blind();
        let a_tx = swap_asset_tx(&alice, &mut node, asset_a, 100_000, a_blind,
            &swap_env(asset_a, 100_000, lock, a_timeout, &bob, &alice));
        let (a_gas, a_gas_blind) = zcrypt_gas(&alice, &mut node, &shield_tx::txbind(CHAIN, &a_tx));
        let a_escrow = node
            .swap_lock(CHAIN, &a_tx, &a_gas, a_gas_blind, 100_000, a_blind, asset_a, lock, a_timeout, bob.pubkey(), alice.pubkey())
            .unwrap();
        let b_blind = keys::random_blind();
        let b_tx = swap_asset_tx(&bob, &mut node, asset_b, 120_000, b_blind,
            &swap_env(asset_b, 120_000, lock, b_timeout, &alice, &bob));
        let (b_gas, b_gas_blind) = zcrypt_gas(&bob, &mut node, &shield_tx::txbind(CHAIN, &b_tx));
        let b_escrow = node
            .swap_lock(CHAIN, &b_tx, &b_gas, b_gas_blind, 120_000, b_blind, asset_b, lock, b_timeout, alice.pubkey(), bob.pubkey())
            .unwrap();
        // Alice waits until the EARLIER of the two timeouts has passed, then tries to take
        // both: refund her own lock, and claim Bob's with the preimage.
        node.set_height(a_timeout.min(b_timeout));
        let alice_refunded = node.htlc_expire(&a_escrow).is_ok();
        let alice_claimed_b = node.htlc_claim(&b_escrow, x).is_ok();
        (alice_refunded, alice_claimed_b)
    };

    // WRONG order: Alice's lock (claimed by Bob) expires first. She refunds it AND claims B.
    let (refunded, claimed) = run(100, 200);
    assert!(refunded && claimed, "reversed timeouts let the revealer keep both legs");

    // RIGHT order: Bob's lock (claimed by Alice) expires first. Once it has, Alice's claim
    // fails; her own lock is still live for Bob to claim, and only later refunds to her.
    let (refunded, claimed) = run(200, 100);
    assert!(!claimed, "after the maker's lock expires the revealer can no longer claim it");
    assert!(!refunded, "the taker's lock is still live for the maker");
}
