//! HTLC hashlock for cross-chain atomic swaps.
//!
//! Value nullifiers for transfers live in the shield path (`zcrypt_shield`), which
//! proves `nf = Poseidon2(spend_secret, value, blind)` in zero knowledge. The only
//! thing left here is the HTLC hashlock, shared with the Bitcoin leg.

use crate::hash::Hash;

/// Hashlock = `SHA256(preimage)`. A claim must reveal a preimage hashing to the
/// lock. Plain SHA-256 (no domain tag) so the SAME preimage unlocks a Bitcoin
/// HTLC (`OP_SHA256`) and a ZCrypt HTLC — enabling cross-chain atomic swaps.
pub fn htlc_hashlock(preimage: &[u8]) -> Hash {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashlock_is_sha256_and_deterministic() {
        let x = b"swap-preimage";
        assert_eq!(htlc_hashlock(x), htlc_hashlock(x));
        assert_ne!(htlc_hashlock(x), htlc_hashlock(b"other"));
        // matches a plain SHA-256 (Bitcoin OP_SHA256 compatibility)
        use sha2::{Digest, Sha256};
        let expect: [u8; 32] = Sha256::digest(x).into();
        assert_eq!(htlc_hashlock(x), expect);
    }
}
