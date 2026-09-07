//! Domain-separated hashing (SHA3-256).

use sha3::{Digest, Sha3_256};

/// A 256-bit digest, used for owner hashes, nullifiers, tx-binding, SMT nodes.
pub type Hash = [u8; 32];

/// Domain-separated hash. The full ASCII `tag` is absorbed first (length-prefixed)
/// so tags that share a common prefix never collide (e.g. `ZC-CLAIM-BLIND` vs
/// `ZC-CLAIM-BLN2`, `ZC-ASSET` vs `ZC-ASSETS`).
pub fn h(tag: &[u8], parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha3_256::new();
    // Length-prefix the full tag — truncating to 8 bytes previously collapsed several
    // intentional domain pairs into identical digests.
    Digest::update(&mut hasher, (tag.len() as u64).to_le_bytes());
    Digest::update(&mut hasher, tag);
    for p in parts {
        // length-prefix each part to make concatenation unambiguous
        Digest::update(&mut hasher, (p.len() as u64).to_le_bytes());
        Digest::update(&mut hasher, p);
    }
    let out = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&out);
    h
}

/// Convenience: hash a single blob under a tag.
pub fn h1(tag: &[u8], data: &[u8]) -> Hash {
    h(tag, &[data])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separation() {
        assert_ne!(h(b"A", &[b"x"]), h(b"B", &[b"x"]));
        // length-prefixing prevents concatenation ambiguity
        assert_ne!(h(b"T", &[b"ab", b"c"]), h(b"T", &[b"a", b"bc"]));
        // Full tags must not collide when they share an 8-byte prefix.
        assert_ne!(
            h(b"ZC-CLAIM-BLIND", &[b"pk", &0u64.to_le_bytes()]),
            h(b"ZC-CLAIM-BLN2", &[b"pk", &0u64.to_le_bytes()])
        );
        assert_ne!(h(b"ZC-ASSET", &[b"zBTC"]), h(b"ZC-ASSETS", &[b"zBTC"]));
    }
}
