//! End-to-end proof that a validator can **receive** its staking block rewards:
//! discover the accrued balance, claim it into coinbase shield coins, reconstruct
//! those coins from the mnemonic-derived account, and actually **spend** them in a
//! ring shield transaction the node accepts.
//!
//! This closes the loop the reward ledger alone did not: an accrued balance is now
//! convertible into spendable, private money — trustlessly (coins can only be
//! minted against a real consensus-agreed balance) and recoverably (the owner
//! rebuilds every coin from `spend_secret` + the public claim).

use zcrypt_core::emission::{self, ATOMIC};
use zcrypt_core::keys::{self, Account};
use zcrypt_core::node::Node;
use zcrypt_core::shield_tx::{self, Spend};
use zcrypt_shield::{Commitment, OutCoin};

const CHAIN: &[u8] = b"zcrypt-devnet";

/// Bond `account` as a validator, run one epoch it fully participates in, and
/// distribute — leaving one epoch's reward accrued to its reward address.
fn accrue_one_epoch(node: &mut Node, account: &Account, consensus_pk: &[u8]) {
    node.bond(consensus_pk.to_vec(), consensus_pk.to_vec(), 10_000 * ATOMIC, account.reward_address())
        .unwrap();
    for h in 1..=emission::EPOCH {
        node.set_height(h);
        node.record_block_signers(&[consensus_pk.to_vec()]);
        node.maybe_distribute_rewards(h);
    }
}

#[test]
fn validator_claims_rewards_into_a_reconstructable_coin() {
    let (account, _mnemonic) = keys::new_account();
    let mut node = Node::new();
    accrue_one_epoch(&mut node, &account, b"validator-consensus-1");

    // Discovery: the accrued balance is a public, consensus-agreed number.
    let owed = node.claimable(&account.pubkey());
    assert_eq!(owed, emission::epoch_reward(emission::EPOCH)); // 14 ZCRYPT (100 blocks x 0.14)

    // Claim it into a coinbase coin (14 ZCRYPT < MAX_COIN_VALUE ⇒ one coin).
    let minted = node.claim_rewards(&account.pubkey(), owed).unwrap();
    assert_eq!(minted.len(), 1);
    assert_eq!(node.claimable(&account.pubkey()), 0, "balance fully debited");

    // Reconstruct the coin from the account alone — its commitment must match the
    // coinbase commitment the node put in the tree, and it must be spend-openable.
    // Claiming is gasless, so the minted coin is the full reward.
    let coin = account.reward_coin(owed, 0);
    assert_eq!(coin.commitment(), minted[0], "owner rebuilds the exact coin");
    assert_eq!(coin.value, owed);

    // Claiming moved value, it did not create it: issuance is unchanged (one
    // epoch's reward, all to the sole validator; no foundation minted here).
    assert_eq!(node.total_issued(), owed);
    assert!(node.total_issued() <= emission::TOTAL_SUPPLY);
}

#[test]
fn claimed_reward_coins_are_spendable() {
    let (account, _mn) = keys::new_account();
    let mut node = Node::new();

    // Two epochs ⇒ two claims ⇒ two coinbase coins (indices 0 and 1) to spend.
    accrue_one_epoch(&mut node, &account, b"validator-consensus-2");
    // second epoch
    for h in (emission::EPOCH + 1)..=(2 * emission::EPOCH) {
        node.set_height(h);
        node.record_block_signers(&[b"validator-consensus-2".to_vec()]);
        node.maybe_distribute_rewards(h);
    }
    let per_epoch = emission::epoch_reward(emission::EPOCH);
    assert_eq!(node.claimable(&account.pubkey()), 2 * per_epoch);

    let c0 = node.claim_rewards(&account.pubkey(), per_epoch).unwrap()[0]; // tree idx 0
    let c1 = node.claim_rewards(&account.pubkey(), per_epoch).unwrap()[0]; // tree idx 1

    // Pad the tree with a handful of coins so the two real coins hide among a
    // non-trivial shielded pool.
    for k in 2..16u64 {
        node.seed_coin(account.own_coin(1_000 + k, [k, k ^ 0x9e37, k.wrapping_add(1), k.wrapping_add(2)]).commitment());
    }
    let pool: Vec<Commitment> = node.commitment_leaves();
    assert_eq!(pool[0], c0);
    assert_eq!(pool[1], c1);

    // Reconstruct both coins and spend them: inputs = the two claimed rewards.
    // Claiming is gasless, so each claimed coin is a full epoch's reward.
    let cval = per_epoch;
    let coin0 = account.reward_coin(cval, 0);
    let coin1 = account.reward_coin(cval, 1);
    let mk_spend = |coin: &zcrypt_core::keys::Coin, leaf_idx: usize| {
        let mut t = zcrypt_shield::tree::CommitmentTree::new();
        for &x in &pool {
            t.append(x);
        }
        let (path_siblings, path_dirs) = t.path(leaf_idx).unwrap();
        Spend {
            value: coin.value,
            blind: coin.blind,
            spend_secret: coin.spend_secret,
            asset_id: coin.asset_id,
            path_siblings,
            path_dirs,
        }
    };
    let a = mk_spend(&coin0, 0);
    let b = mk_spend(&coin1, 1);

    // Outputs: pay the claimed value onward to fresh coins (self, here); a fee is burned.
    let out0: OutCoin = (cval, keys::random_blind(), account.pubkey(), 0);
    let out1: OutCoin = (cval - emission::MIN_FEE, keys::random_blind(), account.pubkey(), 0);
    let notes = vec![vec![0xa1; 8], vec![0xb2; 8]];
    let tx = shield_tx::build(CHAIN, &[a, b], &[out0, out1], emission::MIN_FEE, notes)
        .expect("shield proof over claimed reward coins");

    let receipt = node.submit_shield(CHAIN, &tx).expect("claimed coins are spendable");
    assert_eq!(receipt.nullifiers.len(), 2);

    // Double-spending the same claimed coins is rejected (same nullifiers).
    // Rebuild an equivalent tx and confirm the node refuses it.
    let a2 = mk_spend(&coin0, 0);
    let b2 = mk_spend(&coin1, 1);
    let out2: OutCoin = (cval, keys::random_blind(), account.pubkey(), 0);
    let out3: OutCoin = (cval - emission::MIN_FEE, keys::random_blind(), account.pubkey(), 0);
    let tx2 = shield_tx::build(CHAIN, &[a2, b2], &[out2, out3], emission::MIN_FEE, vec![vec![1; 8], vec![2; 8]])
        .unwrap();
    assert!(node.submit_shield(CHAIN, &tx2).is_err(), "no double-spend of claimed coins");
}

#[test]
fn foundation_claims_vest_on_schedule_end_to_end() {
    // The foundation is a normal account whose reward address is registered at
    // genesis; its claims are gated by the consensus vesting schedule.
    let foundation = Account::from_seed([0xF0; 32]);
    let mut node = Node::new();
    node.mint_foundation(foundation.reward_address());

    // Genesis: exactly the liquid tranche is claimable; a random account sees 0.
    node.set_height(1);
    assert_eq!(node.claimable(&foundation.pubkey()), emission::FOUNDATION_LIQUID);
    let (stranger, _) = keys::new_account();
    assert_eq!(node.claimable(&stranger.pubkey()), 0);

    // Claiming ahead of the schedule is rejected outright.
    assert!(node.claim_rewards(&foundation.pubkey(), emission::FOUNDATION_LIQUID + 1).is_err());

    // Claim the liquid tranche into a coin the foundation wallet can reconstruct.
    let minted = node.claim_rewards(&foundation.pubkey(), emission::FOUNDATION_LIQUID).unwrap();
    assert_eq!(minted.len(), 1, "50k ZCRYPT fits one coin");
    let coin = foundation.reward_coin(emission::FOUNDATION_LIQUID, 0);
    assert_eq!(coin.commitment(), minted[0], "foundation rebuilds the exact coin");
    assert_eq!(node.claimable(&foundation.pubkey()), 0, "nothing more until the cliff");
    assert!(node.claim_rewards(&foundation.pubkey(), 1).is_err());

    // Just before the cliff: still locked. At the cliff: 25% cumulative unlocks.
    node.set_height(emission::VESTING_CLIFF - 1);
    assert_eq!(node.claimable(&foundation.pubkey()), 0);
    node.set_height(emission::VESTING_CLIFF);
    let at_cliff = emission::VESTING_CLIFF_AMOUNT - emission::FOUNDATION_LIQUID;
    assert_eq!(node.claimable(&foundation.pubkey()), at_cliff);
    node.claim_rewards(&foundation.pubkey(), at_cliff).unwrap();

    // A month later: exactly one monthly unlock more.
    node.set_height(emission::VESTING_CLIFF + emission::BLOCKS_PER_MONTH);
    assert_eq!(node.claimable(&foundation.pubkey()), emission::VESTING_MONTHLY);

    // At the end of the schedule the whole 4.2M has been claimable, no more.
    node.set_height(u64::MAX);
    let rest = node.claimable(&foundation.pubkey());
    node.claim_rewards(&foundation.pubkey(), rest).unwrap();
    assert_eq!(node.foundation_claimed(), emission::FOUNDATION);
    assert_eq!(node.claimable(&foundation.pubkey()), 0);
    assert!(node.claim_rewards(&foundation.pubkey(), 1).is_err(), "allocation exhausted forever");

    // Issuance accounting: vested foundation + nothing emitted.
    assert_eq!(node.total_issued(), emission::FOUNDATION);
    assert!(node.total_issued() <= emission::TOTAL_SUPPLY);
}
