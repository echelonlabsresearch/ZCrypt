//! Domain-separated hashing (SHA3-256).

use sha3::{Digest, Sha3_256};

/// A 256-bit digest, used for owner hashes, nullifiers, tx-binding, SMT nodes.
pub type Hash = [u8; 32];

/// Domain-separated hash. The ASCII `tag` is absorbed first (padded to 8 bytes)
/// so inputs for different purposes never collide.
pub fn h(tag: &[u8], parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha3_256::new();
    let mut t = [0u8; 8];
    let n = tag.len().min(8);
    t[..n].copy_from_slice(&tag[..n]);
    Digest::update(&mut hasher, t);
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
    }
}
