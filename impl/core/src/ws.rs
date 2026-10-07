//! Weak subjectivity. The client ships a checkpoint and refuses a state that
//! does not descend from it.
//!
//! The shipped checkpoint is the empty node at height 0, the state *before*
//! InitChain mints the foundation allocation, the sentinel, or zBTC. It is not
//! the app hash InitChain returns to CometBFT. A launch replaces
//! [`SHIPPED_HEIGHT`] and the published hashes with a checkpoint inside the
//! 10-day unbonding window; until that replacement, a snapshot above genesis is
//! accepted only when this process has recorded passing the empty-node check.

use crate::hash::{h, Hash};

/// Height of the checkpoint compiled into this client. Genesis, until a launch
/// build replaces it with a checkpoint inside the unbonding window.
pub const SHIPPED_HEIGHT: u64 = 0;

/// A state the client treats as known-good: the app hash and the bonded
/// validator-set hash at `height`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub app_hash: Hash,
    pub validator_set_hash: Hash,
}

/// `h("ZC-VSET", len_le8 ‖ for each (pk, power): pk_len_le32 ‖ pk ‖ power_le8)`.
/// `set` is the deterministic `(consensus_pubkey, stake + delegated)` list.
pub fn validator_set_hash(set: &[(Vec<u8>, u64)]) -> Hash {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(set.len() as u64).to_le_bytes());
    for (pk, power) in set {
        buf.extend_from_slice(&(pk.len() as u32).to_le_bytes());
        buf.extend_from_slice(pk);
        buf.extend_from_slice(&power.to_le_bytes());
    }
    h(b"ZC-VSET", &[&buf])
}

/// The checkpoint compiled into this binary. Computed from [`crate::node::Node::new`],
/// not from a stored hex digest, so it tracks the hash the node actually uses.
pub fn shipped_checkpoint() -> Checkpoint {
    use std::sync::OnceLock;
    static CP: OnceLock<Checkpoint> = OnceLock::new();
    *CP.get_or_init(|| {
        let n = crate::node::Node::new();
        Checkpoint {
            height: SHIPPED_HEIGHT,
            app_hash: n.state_root(),
            validator_set_hash: validator_set_hash(&n.validator_set()),
        }
    })
}
