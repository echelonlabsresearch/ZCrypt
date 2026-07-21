//! M-of-N post-quantum (ML-DSA) mint authority for shielded assets.
//!
//! Replaces the old single-secret hash-preimage capability — which was serialized into
//! the mint transaction and therefore **revealed on-chain the first time it was used**,
//! after which anyone could mint up to the supply cap — with a proper threshold
//! signature:
//!
//!   * an asset's registered `authority` is a commitment to a **key set** (N ML-DSA
//!     public keys + a threshold M), and
//!   * a mint must carry **M valid signatures from distinct keys** over the *exact* mint
//!     parameters (asset, value, hashlock, timeout, recipient).
//!
//! Secrets never touch the chain, and no key (nor any M-1 subset) can mint. The scheme is
//! **ML-DSA-65** (FIPS 204, NIST security category 3) — the signature sibling of the
//! ML-KEM-768 we already use — so the treasury, the keystone of the peg, is verified with
//! the same post-quantum strength as the rest of the chain rather than being the one
//! classical weak link.

use std::collections::BTreeSet;

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Seed, Signature, VerifyingKey};

use crate::hash::{h, Hash};
use zcrypt_shield::PubKey;

/// The parameter set: ML-DSA-65 (Dilithium3), NIST level 3 (~192-bit).
type P = MlDsa65;

/// Domain-separation context bound into every treasury signature (FIPS 204 ctx string).
const SIG_CTX: &[u8] = b"ZC-MINTAUTH-v1";

/// Encoded ML-DSA-65 sizes (checked against the crate's constants in tests).
pub const PUBKEY_LEN: usize = 1952;
pub const SIG_LEN: usize = 3309;

/// An M-of-N mint key set. `threshold` valid signatures from distinct keys of `pubkeys`
/// authorize a mint. The set is committed into an asset's `authority` via [`Self::commitment`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintKeySet {
    pub threshold: u32,
    /// Encoded ML-DSA-65 verifying keys (each `PUBKEY_LEN` bytes).
    pub pubkeys: Vec<Vec<u8>>,
}

impl MintKeySet {
    pub fn new(threshold: u32, pubkeys: Vec<Vec<u8>>) -> Self {
        MintKeySet { threshold, pubkeys }
    }

    pub fn n(&self) -> usize {
        self.pubkeys.len()
    }

    /// Structural sanity: a real M-of-N with 1 ≤ M ≤ N, and well-formed distinct keys.
    pub fn is_valid(&self) -> bool {
        let n = self.pubkeys.len();
        if self.threshold == 0 || (self.threshold as usize) > n || n == 0 {
            return false;
        }
        if self.pubkeys.iter().any(|k| k.len() != PUBKEY_LEN) {
            return false;
        }
        // keys must be distinct (a duplicated key can't count twice toward the threshold)
        let uniq: BTreeSet<&Vec<u8>> = self.pubkeys.iter().collect();
        uniq.len() == n
    }

    /// Canonical commitment folded into the asset's `authority`. Keys are sorted first, so
    /// the commitment is independent of the order they were listed in — the same set of
    /// signers always yields the same id (and the sorted order defines the signer indices
    /// used by [`verify_threshold`]).
    pub fn commitment(&self) -> Hash {
        let mut keys = self.pubkeys.clone();
        keys.sort();
        let mut buf = Vec::with_capacity(8 + keys.len() * PUBKEY_LEN);
        buf.extend_from_slice(&self.threshold.to_le_bytes());
        buf.extend_from_slice(&(keys.len() as u32).to_le_bytes());
        for k in &keys {
            buf.extend_from_slice(k);
        }
        h(b"ZC-MINTAUTH", &[&buf])
    }
}

/// One signer's contribution to a mint: an index into the key set's **sorted** order plus
/// that signer's signature bytes.
#[derive(Clone, Debug)]
pub struct SignerSig {
    pub key_index: u32,
    pub sig: Vec<u8>,
}

/// The canonical message the treasury signs to authorize a mint: the exact escrow
/// parameters, so a signature is bound to one specific mint and cannot be repurposed for a
/// different asset, amount, hashlock, timeout, or recipient.
pub fn mint_message(asset_id: u64, value: u64, hashlock: &Hash, timeout: u64, claim_pk: &PubKey) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + 8 + 32 + 8 + 64);
    m.extend_from_slice(&asset_id.to_le_bytes());
    m.extend_from_slice(&value.to_le_bytes());
    m.extend_from_slice(hashlock);
    m.extend_from_slice(&timeout.to_le_bytes());
    for x in claim_pk {
        m.extend_from_slice(&x.to_le_bytes());
    }
    m
}

/// The canonical message the **current** key set signs to authorize rotating an asset's mint
/// authority to `new_commitment`. Domain-separated from [`mint_message`] (so a mint signature
/// can never be reused as a rotation) and bound to the asset's monotonic `epoch`, so a
/// rotation signature is single-use — it cannot be replayed, even to re-apply a previous
/// authority in an A→B→A sequence.
pub fn rotate_message(asset_id: u64, epoch: u64, new_commitment: &Hash) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + 8 + 8 + 32);
    m.extend_from_slice(b"ZC-ROTATE-AUTH-1"); // domain tag (16 bytes)
    m.extend_from_slice(&asset_id.to_le_bytes());
    m.extend_from_slice(&epoch.to_le_bytes());
    m.extend_from_slice(new_commitment);
    m
}

/// Verify that `sigs` contains **at least `keyset.threshold` valid signatures from distinct
/// keys** of `keyset` over `msg`. Returns `false` on any malformed key/signature,
/// out-of-range or duplicated signer index, an invalid signature, or an insufficient count.
/// This is the single source of truth for the mint gate — both the ZVM opcode and the node
/// call it, so they cannot diverge.
pub fn verify_threshold(keyset: &MintKeySet, msg: &[u8], sigs: &[SignerSig]) -> bool {
    if !keyset.is_valid() {
        return false;
    }
    // Signer indices refer to the canonical (sorted) key order — the same order the
    // commitment is computed over — so a submitter can't reorder keys to smuggle a dup.
    let mut keys = keyset.pubkeys.clone();
    keys.sort();

    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut valid = 0u32;
    for s in sigs {
        let idx = s.key_index as usize;
        if idx >= keys.len() || !seen.insert(idx) {
            return false; // out of range or duplicate signer → reject the whole bundle
        }
        let vk = match decode_vk(&keys[idx]) {
            Some(v) => v,
            None => return false,
        };
        let sig = match decode_sig(&s.sig) {
            Some(v) => v,
            None => return false,
        };
        if !vk.verify_with_context(msg, SIG_CTX, &sig) {
            return false; // a bad signature in the bundle → reject
        }
        valid += 1;
    }
    valid >= keyset.threshold
}

fn decode_vk(bytes: &[u8]) -> Option<VerifyingKey<P>> {
    let enc = EncodedVerifyingKey::<P>::try_from(bytes).ok()?;
    Some(VerifyingKey::<P>::decode(&enc))
}

fn decode_sig(bytes: &[u8]) -> Option<Signature<P>> {
    let enc = EncodedSignature::<P>::try_from(bytes).ok()?;
    Signature::<P>::decode(&enc)
}

// ---------------------------------------------------------------------------
// Signer side (treasury key custody). Deterministic from a 32-byte seed so a
// signer's key is reproducible from its backup, and the key set is stable.
// ---------------------------------------------------------------------------

/// One treasury signer's private key, derived deterministically from a 32-byte seed.
pub struct MintSigner {
    sk: ExpandedSigningKey<P>,
}

impl MintSigner {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        MintSigner { sk: ExpandedSigningKey::<P>::from_seed(&Seed::from(*seed)) }
    }

    /// This signer's encoded ML-DSA-65 verifying key (`PUBKEY_LEN` bytes).
    pub fn pubkey(&self) -> Vec<u8> {
        self.sk.verifying_key().encode().to_vec()
    }

    /// A deterministic signature over `msg` (ML-DSA deterministic variant, so the same
    /// message always yields the same signature — reproducible and RNG-free).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sk
            .sign_deterministic(msg, SIG_CTX)
            .expect("SIG_CTX is well under the 255-byte context limit")
            .encode()
            .to_vec()
    }
}

/// Derive treasury signer `index` from a master secret, so a whole M-of-N key set can be
/// reproduced from one backed-up secret. Each signer gets an independent seed.
pub fn derive_signer(master: &[u8], index: u32) -> MintSigner {
    let seed = h(b"ZC-TREASURY-KEY", &[master, &index.to_le_bytes()]);
    MintSigner::from_seed(&seed)
}

/// Build an M-of-N key set (and its signers) deterministically from a master secret.
pub fn derive_keyset(master: &[u8], n: u32, threshold: u32) -> (MintKeySet, Vec<MintSigner>) {
    let signers: Vec<MintSigner> = (0..n).map(|i| derive_signer(master, i)).collect();
    let pubkeys: Vec<Vec<u8>> = signers.iter().map(|s| s.pubkey()).collect();
    (MintKeySet::new(threshold, pubkeys), signers)
}

/// Assemble a threshold-signed authorization: the first `threshold` derived signers each
/// sign `msg`, tagged with their index in the key set's **sorted** order. Convenience for a
/// single-custodian treasury that holds all N keys; a distributed treasury would collect
/// these signatures from separate signers.
pub fn authorize(keyset: &MintKeySet, signers: &[MintSigner], msg: &[u8]) -> Vec<SignerSig> {
    // The canonical (sorted) order defines indices; map each signer's pubkey to its sorted position.
    let mut sorted = keyset.pubkeys.clone();
    sorted.sort();
    let sorted_index = |pk: &[u8]| sorted.iter().position(|k| k.as_slice() == pk).map(|i| i as u32);

    let mut out = Vec::new();
    for s in signers.iter().take(keyset.threshold as usize) {
        if let Some(idx) = sorted_index(&s.pubkey()) {
            out.push(SignerSig { key_index: idx, sig: s.sign(msg) });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Wire codec for the 0x5A mint transaction.
// ---------------------------------------------------------------------------

/// Upper bound on N (and on the signature count) accepted from a transaction, so a
/// malformed/hostile tx can't force unbounded allocation or ML-DSA verifications.
const MAX_KEYS: usize = 32;

/// Encode a mint authorization for the 0x5A transaction body:
/// `threshold(u32) ‖ n(u32) ‖ n×pubkey(PUBKEY_LEN) ‖ n_sigs(u32) ‖ n_sigs×(key_index(u32) ‖ sig(SIG_LEN))`.
/// ML-DSA-65 keys/signatures are fixed-width, so parsing is unambiguous.
pub fn encode_auth(keyset: &MintKeySet, sigs: &[SignerSig]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + keyset.pubkeys.len() * PUBKEY_LEN + 4 + sigs.len() * (4 + SIG_LEN));
    v.extend_from_slice(&keyset.threshold.to_le_bytes());
    v.extend_from_slice(&(keyset.pubkeys.len() as u32).to_le_bytes());
    for k in &keyset.pubkeys {
        v.extend_from_slice(k);
    }
    v.extend_from_slice(&(sigs.len() as u32).to_le_bytes());
    for s in sigs {
        v.extend_from_slice(&s.key_index.to_le_bytes());
        v.extend_from_slice(&s.sig);
    }
    v
}

fn rd_u32(b: &[u8], o: &mut usize) -> Option<u32> {
    let v = u32::from_le_bytes(b.get(*o..*o + 4)?.try_into().ok()?);
    *o += 4;
    Some(v)
}

/// Decode a mint authorization. Returns `None` on any truncation, absurd length, or
/// trailing garbage — a strict, fail-closed parse.
pub fn decode_auth(b: &[u8]) -> Option<(MintKeySet, Vec<SignerSig>)> {
    let mut o = 0usize;
    let threshold = rd_u32(b, &mut o)?;
    let n = rd_u32(b, &mut o)? as usize;
    if n == 0 || n > MAX_KEYS {
        return None;
    }
    let mut pubkeys = Vec::with_capacity(n);
    for _ in 0..n {
        pubkeys.push(b.get(o..o + PUBKEY_LEN)?.to_vec());
        o += PUBKEY_LEN;
    }
    let n_sigs = rd_u32(b, &mut o)? as usize;
    if n_sigs > MAX_KEYS {
        return None;
    }
    let mut sigs = Vec::with_capacity(n_sigs);
    for _ in 0..n_sigs {
        let key_index = rd_u32(b, &mut o)?;
        let sig = b.get(o..o + SIG_LEN)?.to_vec();
        o += SIG_LEN;
        sigs.push(SignerSig { key_index, sig });
    }
    if o != b.len() {
        return None; // trailing bytes → reject
    }
    Some((MintKeySet::new(threshold, pubkeys), sigs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_a() -> Vec<u8> {
        mint_message(0xB7C, 50_000, &[7u8; 32], 100, &[3u64; 8])
    }

    #[test]
    fn sizes_match_ml_dsa_65() {
        // Validate our declared constants against real encoded output.
        let s = derive_signer(b"m", 0);
        assert_eq!(s.pubkey().len(), PUBKEY_LEN);
        assert_eq!(s.sign(b"hello").len(), SIG_LEN);
    }

    #[test]
    fn commitment_is_order_independent() {
        let (ks1, _) = derive_keyset(b"treasury-master", 3, 2);
        // Same keys, listed in reverse order → same commitment.
        let mut rev = ks1.pubkeys.clone();
        rev.reverse();
        let ks2 = MintKeySet::new(2, rev);
        assert_eq!(ks1.commitment(), ks2.commitment());
        // A different threshold is a different authority.
        let ks3 = MintKeySet::new(3, ks1.pubkeys.clone());
        assert_ne!(ks1.commitment(), ks3.commitment());
    }

    #[test]
    fn two_of_three_authorizes() {
        let (ks, signers) = derive_keyset(b"treasury-master", 3, 2);
        assert!(ks.is_valid());
        let msg = msg_a();
        let sigs = authorize(&ks, &signers, &msg);
        assert_eq!(sigs.len(), 2, "threshold-many signatures");
        assert!(verify_threshold(&ks, &msg, &sigs));
    }

    #[test]
    fn below_threshold_rejected() {
        let (ks, signers) = derive_keyset(b"treasury-master", 3, 2);
        let msg = msg_a();
        let one = authorize(&MintKeySet::new(1, ks.pubkeys.clone()), &signers, &msg); // only 1 sig
        assert!(!verify_threshold(&ks, &msg, &one), "1 signature must not meet a 2-of-3 threshold");
    }

    #[test]
    fn wrong_message_rejected() {
        // Signatures are bound to the exact mint params — swapping the message must fail.
        let (ks, signers) = derive_keyset(b"treasury-master", 3, 2);
        let sigs = authorize(&ks, &signers, &msg_a());
        let other = mint_message(0xB7C, 50_001, &[7u8; 32], 100, &[3u64; 8]); // value off by one
        assert!(!verify_threshold(&ks, &other, &sigs));
    }

    #[test]
    fn duplicate_signer_rejected() {
        let (ks, signers) = derive_keyset(b"treasury-master", 3, 2);
        let msg = msg_a();
        let one = authorize(&MintKeySet::new(1, ks.pubkeys.clone()), &signers, &msg);
        // Replay the SAME signer twice to fake reaching the threshold.
        let dup = vec![one[0].clone(), one[0].clone()];
        assert!(!verify_threshold(&ks, &msg, &dup), "a signer can't be counted twice");
    }

    #[test]
    fn out_of_range_and_tampered_rejected() {
        let (ks, signers) = derive_keyset(b"treasury-master", 3, 2);
        let msg = msg_a();
        let mut sigs = authorize(&ks, &signers, &msg);
        // out-of-range signer index
        let mut oob = sigs.clone();
        oob[0].key_index = 99;
        assert!(!verify_threshold(&ks, &msg, &oob));
        // tampered signature bytes
        if let Some(b) = sigs[0].sig.get_mut(10) {
            *b ^= 0xFF;
        }
        assert!(!verify_threshold(&ks, &msg, &sigs));
    }

    #[test]
    fn auth_wire_roundtrips_and_verifies() {
        let (ks, signers) = derive_keyset(b"treasury-master", 3, 2);
        let msg = msg_a();
        let sigs = authorize(&ks, &signers, &msg);
        let wire = encode_auth(&ks, &sigs);
        let (ks2, sigs2) = decode_auth(&wire).expect("decodes");
        assert_eq!(ks2.commitment(), ks.commitment());
        assert!(verify_threshold(&ks2, &msg, &sigs2));
        // truncated / trailing-garbage payloads are rejected
        assert!(decode_auth(&wire[..wire.len() - 1]).is_none());
        let mut extra = wire.clone();
        extra.push(0);
        assert!(decode_auth(&extra).is_none());
    }

    #[test]
    fn foreign_key_rejected() {
        // A signature from a key NOT in the set can't authorize, even at the right index.
        let (ks, _) = derive_keyset(b"treasury-master", 3, 2);
        let (_, other_signers) = derive_keyset(b"attacker-master", 3, 2);
        let msg = msg_a();
        let sigs = vec![
            SignerSig { key_index: 0, sig: other_signers[0].sign(&msg) },
            SignerSig { key_index: 1, sig: other_signers[1].sign(&msg) },
        ];
        assert!(!verify_threshold(&ks, &msg, &sigs));
    }
}
