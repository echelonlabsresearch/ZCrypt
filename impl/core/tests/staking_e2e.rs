//! End-to-end simulation of trustless staking block rewards at the node level —
//! exactly the flow the ABCI `finalize_block` drives, but deterministic and
//! testable without a live multi-validator CometBFT.
//!
//! Bonds validators, produces blocks with varying participation across several
//! epochs, and asserts: rewards split by stake × participation, the foundation is
//! minted once, issuance never exceeds the 21M cap, inactive validators earn
//! nothing, and the whole thing is deterministic (identical app_hash on replay).

use zcrypt_core::emission::{self, ATOMIC};
use zcrypt_core::node::Node;

fn pk(n: u8) -> Vec<u8> {
    vec![n; 20]
}
fn addr(n: u8) -> [u8; 32] {
    [n; 32]
}

/// Run `epochs` epochs. V1 (20k stake) and V2 (10k) sign every block; V3 (10k) is
/// bonded but never signs. Returns (node, v1_reward, v2_reward, v3_reward).
fn run(epochs: u64) -> (Node, u64, u64, u64) {
    let mut node = Node::new();
    // 20% foundation at genesis
    node.mint_foundation(addr(0xF0));

    node.bond(pk(1), pk(1), 20_000 * ATOMIC, addr(1)).unwrap();
    node.bond(pk(2), pk(2), 10_000 * ATOMIC, addr(2)).unwrap();
    node.bond(pk(3), pk(3), 10_000 * ATOMIC, addr(3)).unwrap(); // never participates

    let mut height = 0u64;
    for _ in 0..epochs {
        for _ in 0..emission::EPOCH {
            height += 1;
            node.set_height(height);
            node.record_block_signers(&[pk(1), pk(2)]); // V3 absent
            node.maybe_distribute_rewards(height);
        }
    }
    let v1 = node.reward_balance(&addr(1));
    let v2 = node.reward_balance(&addr(2));
    let v3 = node.reward_balance(&addr(3));
    (node, v1, v2, v3)
}

#[test]
fn rewards_flow_by_stake_and_participation() {
    let (node, v1, v2, v3) = run(5);

    // V1 has 2× V2's stake and equal participation -> ~2× the rewards.
    assert!(v1 > v2 && v2 > 0);
    assert!((v1 as i128 - 2 * v2 as i128).abs() <= 10, "V1≈2×V2: {v1} vs {v2}");

    // V3 was bonded but never signed a block -> earns nothing.
    assert_eq!(v3, 0, "inactive validator must earn 0");

    // Foundation registered once; nothing pre-credited — only the vested (liquid)
    // tranche is claimable this early in the schedule.
    assert_eq!(node.reward_balance(&addr(0xF0)), 0);
    assert_eq!(node.foundation_claimable(), emission::FOUNDATION_LIQUID);

    // Five epochs of block rewards were emitted (each 14M atomic, minus dust).
    let per_epoch = emission::epoch_reward(emission::EPOCH);
    assert!(node.emitted() > 0 && node.emitted() <= 5 * per_epoch);
    assert!(node.emitted() >= 5 * per_epoch - 50); // dust bound
}

#[test]
fn issuance_never_exceeds_total_supply() {
    // Grind many epochs; total (foundation + rewards) must stay ≤ 21M and the
    // mined portion ≤ 16.8M, always.
    let mut node = Node::new();
    node.mint_foundation(addr(0xF0));
    node.bond(pk(1), pk(1), 10_000 * ATOMIC, addr(1)).unwrap();
    let mut height = 0u64;
    for _ in 0..500 {
        for _ in 0..emission::EPOCH {
            height += 1;
            node.record_block_signers(&[pk(1)]);
        }
        node.maybe_distribute_rewards(height);
        assert!(node.total_issued() <= emission::TOTAL_SUPPLY);
        assert!(node.emitted() <= emission::MINEABLE);
    }
}

#[test]
fn deterministic_app_hash() {
    // Two independent replays of the same block sequence -> identical app_hash.
    let (a, ..) = run(3);
    let (b, ..) = run(3);
    assert_eq!(a.state_root(), b.state_root(), "reward state must be deterministic");
}

#[test]
fn no_participation_no_emission() {
    // A bonded validator that signs nothing -> zero emission (can't mint for free).
    let mut node = Node::new();
    node.bond(pk(1), pk(1), 10_000 * ATOMIC, addr(1)).unwrap();
    for _ in 0..3 {
        // advance an epoch with NO recorded signatures
        for h in 1..=emission::EPOCH {
            node.set_height(h);
        }
        node.maybe_distribute_rewards(emission::EPOCH);
    }
    assert_eq!(node.emitted(), 0);
    assert_eq!(node.reward_balance(&addr(1)), 0);
}
