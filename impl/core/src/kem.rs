//! Post-quantum note encryption: ML-KEM-768 encapsulation, HKDF-SHA256 key
//! derivation (transcript-bound), ChaCha20-Poly1305 payload sealing.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{B32, Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::RngCore;
use sha2::Sha256;

pub type Ek = <MlKem768 as KemCore>::EncapsulationKey;
pub type Dk = <MlKem768 as KemCore>::DecapsulationKey;

/// Fixed padded plaintext length for on-chain encrypted notes (spec §2).
pub const PAD_LEN: usize = 256;
/// Upper bound for `.zcrypt` secrets payloads (amount + M-len blind + nonces).
pub const FILE_PAD_LEN: usize = 16_384;

/// A recipient's ML-KEM encapsulation key (Standard Address).
pub struct RecipientPublic {
    pub mlkem: Ek,
}

/// ML-KEM ciphertext + AEAD payload.
#[derive(Clone)]
pub struct KemCiphertext {
    pub mlkem_ct: Vec<u8>,
    pub nonce: [u8; 12],
    pub aead_ct: Vec<u8>,
}

/// Generate a fresh ML-KEM keypair (random — used for stealth addresses, which
/// are intentionally *not* recoverable from any seed).
pub fn generate() -> (Dk, Ek) {
    let mut rng = rand::thread_rng();
    MlKem768::generate(&mut rng)
}

/// Deterministically derive an ML-KEM keypair from a 32-byte account seed.
///
/// ML-KEM's KeyGen is a pure function of two 32-byte values `(d, z)`; we expand
/// them from the seed with domain-separated SHA3. This makes a wallet's note-
/// encryption keys **recoverable from the mnemonic** — restore the seed and you
/// reproduce the exact same `(dk, ek)`, so you can decrypt every note ever sent
/// to your normal address. (Stealth addresses deliberately use `generate()`.)
pub fn generate_deterministic(seed: &[u8; 32]) -> (Dk, Ek) {
    let d = crate::hash::h(b"ZC-KEM-D", &[seed]);
    let z = crate::hash::h(b"ZC-KEM-Z", &[seed]);
    let d32 = B32::try_from(&d[..]).expect("32-byte d");
    let z32 = B32::try_from(&z[..]).expect("32-byte z");
    MlKem768::generate_deterministic(&d32, &z32)
}

/// Serialize a decapsulation key (the private half) to bytes. Used to export a
/// **view key** for selective-disclosure compliance: whoever holds these bytes
/// can decrypt incoming notes and read amounts, but cannot spend.
pub fn dk_to_bytes(dk: &Dk) -> Vec<u8> {
    dk.as_bytes().to_vec()
}

pub fn dk_from_bytes(bytes: &[u8]) -> Option<Dk> {
    let enc = Encoded::<Dk>::try_from(bytes).ok()?;
    Some(Dk::from_bytes(&enc))
}

pub fn ek_to_bytes(ek: &Ek) -> Vec<u8> {
    ek.as_bytes().to_vec()
}

pub fn ek_from_bytes(bytes: &[u8]) -> Option<Ek> {
    let enc = Encoded::<Ek>::try_from(bytes).ok()?;
    Some(Ek::from_bytes(&enc))
}

fn derive_key(ss_pq: &[u8], mlkem_ct: &[u8], ek_bytes: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ss_pq);
    let mut info = Vec::new();
    info.extend_from_slice(b"ZCRYPT-PQ-KEM-v2");
    info.extend_from_slice(mlkem_ct);
    info.extend_from_slice(ek_bytes);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("hkdf expand");
    okm
}

fn pad<const L: usize>(plaintext: &[u8]) -> [u8; L] {
    assert!(
        plaintext.len() + 4 <= L,
        "plaintext {} bytes too large for pad length {L}",
        plaintext.len()
    );
    let mut buf = [0u8; L];
    buf[..4].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    buf[4..4 + plaintext.len()].copy_from_slice(plaintext);
    buf
}

fn unpad<const L: usize>(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() != L {
        return None;
    }
    let mut l = [0u8; 4];
    l.copy_from_slice(&buf[..4]);
    let len = u32::from_le_bytes(l) as usize;
    if 4 + len > L {
        return None;
    }
    Some(buf[4..4 + len].to_vec())
}

fn unframe(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(buf[..4].try_into().ok()?) as usize;
    buf.get(4..4 + len).map(|s| s.to_vec())
}

fn encrypt_padded<const L: usize>(
    recipient: &RecipientPublic,
    plaintext: &[u8],
) -> KemCiphertext {
    let mut rng = rand::thread_rng();
    let (ct, ss_pq) = recipient
        .mlkem
        .encapsulate(&mut rng)
        .expect("ml-kem encapsulate");
    let mlkem_ct = ct.as_slice().to_vec();
    let ek_bytes = ek_to_bytes(&recipient.mlkem);
    let key = derive_key(ss_pq.as_slice(), &mlkem_ct, &ek_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let padded = pad::<L>(plaintext);
    let aead_ct = cipher
        .encrypt(Nonce::from_slice(&nonce), padded.as_ref())
        .expect("aead encrypt");

    KemCiphertext {
        mlkem_ct,
        nonce,
        aead_ct,
    }
}

fn decrypt_padded<const L: usize>(dk: &Dk, ek: &Ek, ct: &KemCiphertext) -> Option<Vec<u8>> {
    let mlkem_ct = ml_kem::Ciphertext::<MlKem768>::try_from(ct.mlkem_ct.as_slice()).ok()?;
    let ss_pq = dk.decapsulate(&mlkem_ct).ok()?;
    let ek_bytes = ek_to_bytes(ek);
    let key = derive_key(ss_pq.as_slice(), &ct.mlkem_ct, &ek_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let padded = cipher
        .decrypt(Nonce::from_slice(&ct.nonce), ct.aead_ct.as_ref())
        .ok()?;
    unpad::<L>(&padded)
}

/// Encrypt an on-chain note to a recipient (sender side).
pub fn encrypt(recipient: &RecipientPublic, plaintext: &[u8]) -> KemCiphertext {
    encrypt_padded::<PAD_LEN>(recipient, plaintext)
}

/// Decrypt an on-chain note (recipient side).
pub fn decrypt(dk: &Dk, ek: &Ek, ct: &KemCiphertext) -> Option<Vec<u8>> {
    decrypt_padded::<PAD_LEN>(dk, ek, ct)
}

/// Encrypt a `.zcrypt` secrets payload (variable-length framed AEAD).
pub fn encrypt_file(recipient: &RecipientPublic, plaintext: &[u8]) -> KemCiphertext {
    let mut rng = rand::thread_rng();
    let (ct, ss_pq) = recipient
        .mlkem
        .encapsulate(&mut rng)
        .expect("ml-kem encapsulate");
    let mlkem_ct = ct.as_slice().to_vec();
    let ek_bytes = ek_to_bytes(&recipient.mlkem);
    let key = derive_key(ss_pq.as_slice(), &mlkem_ct, &ek_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let mut framed = Vec::with_capacity(plaintext.len() + 4);
    framed.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    framed.extend_from_slice(plaintext);
    let aead_ct = cipher
        .encrypt(Nonce::from_slice(&nonce), framed.as_ref())
        .expect("aead encrypt");

    KemCiphertext {
        mlkem_ct,
        nonce,
        aead_ct,
    }
}

/// Decrypt a `.zcrypt` secrets payload.
pub fn decrypt_file(dk: &Dk, ek: &Ek, ct: &KemCiphertext) -> Option<Vec<u8>> {
    let mlkem_ct = ml_kem::Ciphertext::<MlKem768>::try_from(ct.mlkem_ct.as_slice()).ok()?;
    let ss_pq = dk.decapsulate(&mlkem_ct).ok()?;
    let ek_bytes = ek_to_bytes(ek);
    let key = derive_key(ss_pq.as_slice(), &ct.mlkem_ct, &ek_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let framed = cipher
        .decrypt(Nonce::from_slice(&ct.nonce), ct.aead_ct.as_ref())
        .ok()?;
    unframe(&framed)
}

/// Serialize a ciphertext to bytes (for embedding in JSON / on-chain notes).
pub fn ciphertext_to_bytes(ct: &KemCiphertext) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(ct.mlkem_ct.len() as u32).to_le_bytes());
    v.extend_from_slice(&ct.mlkem_ct);
    v.extend_from_slice(&ct.nonce);
    v.extend_from_slice(&(ct.aead_ct.len() as u32).to_le_bytes());
    v.extend_from_slice(&ct.aead_ct);
    v
}

/// Deserialize a ciphertext from bytes.
pub fn ciphertext_from_bytes(b: &[u8]) -> Option<KemCiphertext> {
    let mut off = 0usize;
    let mut l = [0u8; 4];
    l.copy_from_slice(b.get(off..off + 4)?);
    off += 4;
    let mlen = u32::from_le_bytes(l) as usize;
    let mlkem_ct = b.get(off..off + mlen)?.to_vec();
    off += mlen;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(b.get(off..off + 12)?);
    off += 12;
    let mut l2 = [0u8; 4];
    l2.copy_from_slice(b.get(off..off + 4)?);
    off += 4;
    let alen = u32::from_le_bytes(l2) as usize;
    let aead_ct = b.get(off..off + alen)?.to_vec();
    Some(KemCiphertext {
        mlkem_ct,
        nonce,
        aead_ct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_kem_roundtrip() {
        let (dk, ek) = generate();
        let recipient_pub = RecipientPublic {
            mlkem: ek_from_bytes(&ek_to_bytes(&ek)).unwrap(),
        };
        let msg = b"amount=1000000;asset=ZCRYPT";
        let ct = encrypt(&recipient_pub, msg);
        let got = decrypt(&dk, &ek, &ct).unwrap();
        assert_eq!(got, msg);
    }

    #[test]
    fn constant_size_ciphertext() {
        let (_dk, ek) = generate();
        let r = RecipientPublic {
            mlkem: ek_from_bytes(&ek_to_bytes(&ek)).unwrap(),
        };
        let a = encrypt(&r, b"short");
        let b = encrypt(&r, b"a considerably longer note payload here");
        assert_eq!(a.aead_ct.len(), b.aead_ct.len());
    }

    #[test]
    fn file_encrypt_large_payload() {
        let (dk, ek) = generate();
        let recip = RecipientPublic {
            mlkem: ek_from_bytes(&ek_to_bytes(&ek)).unwrap(),
        };
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let ct = encrypt_file(&recip, &payload);
        let got = decrypt_file(&dk, &ek, &ct).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn wrong_key_fails() {
        let (_dk, ek) = generate();
        let r = RecipientPublic {
            mlkem: ek_from_bytes(&ek_to_bytes(&ek)).unwrap(),
        };
        let ct = encrypt(&r, b"secret");
        let (dk2, ek2) = generate();
        assert!(decrypt(&dk2, &ek2, &ct).is_none());
    }

    #[test]
    fn deterministic_keygen_is_recoverable() {
        let seed = [7u8; 32];
        let (dk1, ek1) = generate_deterministic(&seed);
        let (_dk2, ek2) = generate_deterministic(&seed);
        // same seed -> identical public address
        assert_eq!(ek_to_bytes(&ek1), ek_to_bytes(&ek2));
        // a note sent to the address decrypts with the seed-recovered key
        let r = RecipientPublic { mlkem: ek_from_bytes(&ek_to_bytes(&ek1)).unwrap() };
        let ct = encrypt(&r, b"amount=42");
        let (dk_restored, ek_restored) = generate_deterministic(&seed);
        assert_eq!(decrypt(&dk_restored, &ek_restored, &ct).unwrap(), b"amount=42");
        // a different seed yields a different keypair
        let (_dk3, ek3) = generate_deterministic(&[8u8; 32]);
        assert_ne!(ek_to_bytes(&ek1), ek_to_bytes(&ek3));
        let _ = dk1;
    }

    #[test]
    fn dk_serialization_roundtrip() {
        let seed = [3u8; 32];
        let (dk, ek) = generate_deterministic(&seed);
        let dk_bytes = dk_to_bytes(&dk);
        let dk_back = dk_from_bytes(&dk_bytes).unwrap();
        let r = RecipientPublic { mlkem: ek_from_bytes(&ek_to_bytes(&ek)).unwrap() };
        let ct = encrypt(&r, b"view-key test");
        // the deserialized dk (a view key) still decrypts
        assert_eq!(decrypt(&dk_back, &ek, &ct).unwrap(), b"view-key test");
    }

    #[test]
    fn ciphertext_serialization_roundtrip() {
        let (_dk, ek) = generate();
        let r = RecipientPublic {
            mlkem: ek_from_bytes(&ek_to_bytes(&ek)).unwrap(),
        };
        let ct = encrypt(&r, b"payload");
        let bytes = ciphertext_to_bytes(&ct);
        let back = ciphertext_from_bytes(&bytes).unwrap();
        assert_eq!(back.mlkem_ct, ct.mlkem_ct);
        assert_eq!(back.nonce, ct.nonce);
        assert_eq!(back.aead_ct, ct.aead_ct);
    }
}
