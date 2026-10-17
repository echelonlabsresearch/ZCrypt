//! Address & key hierarchy for shielded coins.
//!
//! A shielded coin is the triple `(value, blind, spend_secret)`. The public
//! commitment `C = Poseidon2(value, blind, pk)` — where `pk = Poseidon2(spend_secret)`
//! — lives in the note-commitment tree, binding both the amount *and* the owner.
//! Spending publishes the canonical nullifier `nf = Poseidon2(spend_secret, value,
//! blind)`. Because the commitment binds `pk`, only the holder of `spend_secret`
//! can open it (the sender knows `pk` but not the secret), and the nullifier is a
//! deterministic function of the coin (so a re-spend collides → no double-spend).
//!
//! Everything an account can do flows from one 32-byte `seed`:
//!
//! ```text
//!   seed ──┬── spend_secret = KDF(seed)              → authority to SPEND
//!          │        └── pk = Poseidon2(spend_secret) → published in the address,
//!          │                                           bound into coin commitments
//!          └── (dk, ek) = ML-KEM det. keygen(seed)   → note encryption
//!                             ├── ek = public address (recipients encrypt to it)
//!                             └── dk = decrypt/scan key   → the VIEW key
//! ```
//!
//! Three address / coin types, matching the product model:
//!
//! * **Normal**  — derived from the *mnemonic* seed. Reusable, published,
//!   scannable, and fully **recoverable**: restore the seed and you regenerate
//!   `(dk, ek, spend_secret)` and can re-scan the chain for every coin received.
//! * **Stealth** — a **fresh** account from `random_seed()` (NOT derived from the
//!   mnemonic). Unlinkable to your identity, opaque to your main view key, and
//!   NOT recoverable from the mnemonic — you must back up its seed separately.
//! * **Bearer**  — the `spend_secret` is embedded in the coin itself. No
//!   recipient, no encryption: possession is ownership. The receiver *sweeps* it
//!   to their own address. Invisible to every view key.
//!
//! **View keys (compliance).** A `ViewKey` is the ML-KEM decryption key `dk` with
//! *no* `spend_secret`. It can decrypt notes sent to a Normal address and reveal
//! their amounts, but it cannot spend, and it cannot read stealth or bearer coins.
//! Handing an auditor your view key is therefore selective disclosure of your
//! Normal-address activity — not a spending backdoor.
//!
//! Post-quantum note: a normal and a stealth address are the *same size* on the
//! wire (both wrap a ~1184-byte ML-KEM key + a 64-byte `pk`). A KEM has no compact
//! ECDH-style shared-secret, so stealth addresses cannot be shrunk the way
//! Monero's can; the stealth win here is unlinkability + non-recoverability +
//! view-opacity, not bytes.

use crate::hash::{h, Hash};
use crate::kem::{self, Dk, Ek, KemCiphertext, RecipientPublic};
use rand::RngCore;
use zcrypt_shield::{self, Blind, Commitment, OutCoin, PubKey, SpendSecret};

fn rand_blind() -> Blind {
    zcrypt_shield::random_blind()
}
fn rand_spend_secret() -> SpendSecret {
    zcrypt_shield::random_spend_secret()
}
/// Derive an 8-limb spend secret from a 32-byte seed (domain-separated SHA3 × 2,
/// each limb reduced into the BabyBear field).
fn spend_secret_from_seed(seed: &[u8; 32]) -> SpendSecret {
    let d0 = h(b"ZC-SPEND0", &[seed]);
    let d1 = h(b"ZC-SPEND1", &[seed]);
    core::array::from_fn(|i| {
        let src = if i < 4 { &d0 } else { &d1 };
        let off = (i % 4) * 8;
        zcrypt_shield::field_limb(u64::from_le_bytes(src[off..off + 8].try_into().unwrap()))
    })
}

/// A spendable coin note — the pre-image the ZK spend circuit consumes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Coin {
    pub value: u64,
    pub blind: Blind,
    pub spend_secret: SpendSecret,
    /// Which shielded asset the coin holds (0 = native ZCRYPT, e.g. zBTC otherwise).
    pub asset_id: u64,
}

/// Redacted: a coin's blind and spend secret are spend authority and must never reach a
/// log line or an error string. Only the public value and asset are printed.
impl core::fmt::Debug for Coin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Coin")
            .field("value", &self.value)
            .field("asset_id", &self.asset_id)
            .field("blind", &"<redacted>")
            .field("spend_secret", &"<redacted>")
            .finish()
    }
}

impl Coin {
    /// The public commitment that lives in the note-commitment tree (binds asset).
    pub fn commitment(&self) -> Commitment {
        zcrypt_shield::commit_asset(self.value, &self.blind, &self.pubkey(), self.asset_id)
    }
    /// The canonical nullifier published when this coin is spent (one per coin).
    pub fn nullifier(&self) -> Commitment {
        zcrypt_shield::nullifier_asset(&self.spend_secret, self.value, &self.blind, self.asset_id)
    }
    /// The owner's spend public key bound into the commitment.
    pub fn pubkey(&self) -> PubKey {
        zcrypt_shield::spend_pubkey(&self.spend_secret)
    }
}

/// Address type. The bytes are the same shape for both; the tag is a wallet-side
/// annotation of provenance and recoverability (see module docs).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddressKind {
    /// Seed-derived, reusable, mnemonic-recoverable, scannable.
    Normal,
    /// Fresh one-time keypair; NOT seed-recoverable; opaque to the main view key.
    Stealth,
}

/// Canonical byte serialization of a field limb everywhere a limb is serialized
/// here: 8 bytes, little-endian `u64`, value `< p`. Non-canonical limbs are rejected.
pub const LIMB_BYTES: usize = 8;
/// Spend public key: 8 canonical limbs.
pub const PUBKEY_BYTES: usize = 8 * LIMB_BYTES;
/// ML-KEM-768 encapsulation key (FIPS 203).
pub const ML_KEM_768_EK_BYTES: usize = 1184;
/// Address payload: `kind(1) ‖ pk(64) ‖ ek(1184)` = 1249 bytes.
pub const ADDRESS_BYTES: usize = 1 + PUBKEY_BYTES + ML_KEM_768_EK_BYTES;
/// Bearer coin payload: `value(8) ‖ blind(64) ‖ spend_secret(64) ‖ asset(8)` = 144 bytes.
pub const BEARER_COIN_BYTES: usize = LIMB_BYTES + zcrypt_shield::BLIND_BYTES + 8 * LIMB_BYTES + LIMB_BYTES;
const BC_BLIND: usize = LIMB_BYTES;
const BC_SS: usize = BC_BLIND + zcrypt_shield::BLIND_BYTES;
const BC_ASSET: usize = BC_SS + 8 * LIMB_BYTES;
/// Encoded `zc1…` address length in characters: hrp(2) + separator(1) +
/// ceil(1249·8/5) = 1999 data characters + 6 checksum = 2008.
pub const ADDRESS_BECH32_CHARS: usize = 2 + 1 + (ADDRESS_BYTES * 8 + 4) / 5 + 6;

/// A recipient address: an ML-KEM encapsulation key (for note encryption) plus the
/// recipient's spend public key `pk` (bound into the coin commitment so only the
/// recipient can spend), plus a kind tag.
#[derive(Clone)]
pub struct Address {
    pub kind: AddressKind,
    ek: Vec<u8>,
    pk: PubKey,
}

impl Address {
    pub fn ek_bytes(&self) -> &[u8] {
        &self.ek
    }
    pub fn pubkey(&self) -> PubKey {
        self.pk
    }

    /// Encode as a **bech32m** string with the `zc` human-readable prefix
    /// (`zc1…`). The trailing checksum catches typos on decode. (The payload is
    /// large, so the string is long — share it as a QR/link, not by typing.)
    pub fn to_bech32(&self) -> String {
        crate::bech::encode("zc", &self.to_bytes())
    }

    /// Decode a `zc1…` bech32m address, verifying the checksum and hrp.
    pub fn from_bech32(s: &str) -> Option<Address> {
        let (hrp, data) = crate::bech::decode(s)?;
        if hrp != "zc" {
            return None;
        }
        Address::from_bytes(&data)
    }

    /// `1 kind byte ‖ pk(64) ‖ ek` (~1249 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 64 + self.ek.len());
        v.push(match self.kind {
            AddressKind::Normal => 0u8,
            AddressKind::Stealth => 1u8,
        });
        for x in &self.pk {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.extend_from_slice(&self.ek);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Option<Address> {
        let (&tag, rest) = b.split_first()?;
        let kind = match tag {
            0 => AddressKind::Normal,
            1 => AddressKind::Stealth,
            _ => return None,
        };
        if rest.len() < 64 {
            return None;
        }
        let pk: PubKey = core::array::from_fn(|i| {
            u64::from_le_bytes(rest[i * 8..i * 8 + 8].try_into().unwrap())
        });
        // Reject non-canonical limb encodings (limb >= FIELD_ORDER). Without this,
        // `x` and `x + FIELD_ORDER` both reduce to the same on-chain `pk`, so distinct
        // address byte-strings (and distinct bech32 strings) would alias to one coin.
        // Mirror the on-chain `limbs_canonical` gate applied to commitments/nullifiers.
        if !zcrypt_shield::limbs_canonical(&pk) {
            return None;
        }
        let ek = &rest[64..];
        kem::ek_from_bytes(ek)?; // validate it's a well-formed ML-KEM key
        Some(Address {
            kind,
            ek: ek.to_vec(),
            pk,
        })
    }
}

/// A fresh CSPRNG seed — use it for a stealth account. Back it up: your mnemonic
/// will NOT regenerate it.
pub fn random_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

// ---------------------------------------------------------------------------
// BIP-39 mnemonics (human-readable wallet backup / recovery)
// ---------------------------------------------------------------------------

/// Generate a fresh **24-word BIP-39 mnemonic** (256-bit entropy). This is the
/// wallet's recovery phrase — write it down; it regenerates the whole account.
pub fn generate_mnemonic() -> String {
    let mut entropy = [0u8; 32]; // 256 bits -> 24 words
    rand::thread_rng().fill_bytes(&mut entropy);
    bip39::Mnemonic::from_entropy(&entropy)
        .expect("32 bytes of entropy is a valid 24-word mnemonic")
        .to_string()
}

/// Derive the 32-byte account seed from a BIP-39 mnemonic and an optional
/// passphrase (pass `""` for none — the BIP-39 "25th word"). Validates the phrase
/// (word list + checksum); returns `None` if it is not a valid mnemonic.
///
/// The BIP-39 512-bit seed is domain-separated down to ZCrypt's 32-byte account
/// seed, from which `Account::from_seed` derives the spend key and ML-KEM keys.
pub fn seed_from_mnemonic(phrase: &str, passphrase: &str) -> Option<[u8; 32]> {
    let m = bip39::Mnemonic::parse(phrase.trim()).ok()?;
    let seed64 = m.to_seed(passphrase); // BIP-39 PBKDF2-HMAC-SHA512, 2048 rounds
    Some(h(b"ZC-SEED", &[&seed64]))
}

impl Account {
    /// Restore an account from a BIP-39 mnemonic (+ optional passphrase). Returns
    /// `None` if the phrase is invalid (wrong word or bad checksum).
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Option<Account> {
        Some(Account::from_seed(seed_from_mnemonic(phrase, passphrase)?))
    }
}

/// Create a brand-new account together with its recovery mnemonic. Show the
/// phrase to the user once, then discard it (the account holds the derived keys).
pub fn new_account() -> (Account, String) {
    let phrase = generate_mnemonic();
    let account = Account::from_mnemonic(&phrase, "")
        .expect("a freshly generated mnemonic is always valid");
    (account, phrase)
}

/// An account: every key derived deterministically from one 32-byte seed.
pub struct Account {
    seed: [u8; 32],
    spend_secret: SpendSecret,
    dk: Dk,
    ek: Ek,
}

/// Overwrite a byte buffer with zeros in a way the optimizer must not elide.
pub fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusively borrowed `u8`.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// The seed and spend secret are wiped when an account goes out of scope, so a locked
/// wallet (or a dropped stealth sub-account) leaves no key material behind in freed
/// memory. The ML-KEM decapsulation key is re-derivable from the seed and is dropped
/// by its own type.
impl Drop for Account {
    fn drop(&mut self) {
        wipe(&mut self.seed);
        for limb in self.spend_secret.iter_mut() {
            // SAFETY: valid, aligned, exclusively borrowed `u64`.
            unsafe { core::ptr::write_volatile(limb, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl core::fmt::Debug for Account {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Account").field("pk", &self.pubkey()).field("seed", &"<redacted>").finish()
    }
}

impl Account {
    /// Derive an account from a seed. For a Normal (recoverable) account the seed
    /// is the mnemonic seed; for a Stealth account it is `random_seed()`.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let spend_secret = spend_secret_from_seed(&seed);
        let (dk, ek) = kem::generate_deterministic(&seed);
        Account {
            seed,
            spend_secret,
            dk,
            ek,
        }
    }

    /// Derive the `index`-th **stealth sub-account** deterministically from this
    /// (master) account's seed — HD-wallet style. It is fully **recoverable from
    /// the same mnemonic** (re-derive by index), yet its spend key and ML-KEM keys
    /// are independent, so on-chain it is unlinkable to the main account and it is
    /// **opaque to the main account's view key**. This is the recommended way to
    /// take private receives while keeping one backup phrase.
    ///
    /// Scanning: derive `stealth(0)`, `stealth(1)`, … and `receive` on each (stop
    /// after a run of empties, like HD gap-scanning).
    pub fn stealth(&self, index: u32) -> Account {
        let sub = h(b"ZC-STLTH", &[&self.seed, &index.to_le_bytes()]);
        Account::from_seed(sub)
    }

    /// A fresh stealth account from a *random* seed — **not** recoverable from any
    /// mnemonic (you must back up the returned seed). Use `stealth(index)` instead
    /// unless you specifically want a throwaway key outside your HD tree.
    pub fn new_stealth() -> (Self, [u8; 32]) {
        let seed = random_seed();
        (Self::from_seed(seed), seed)
    }

    /// This account's spend public key (bound into commitments of coins it owns).
    pub fn pubkey(&self) -> PubKey {
        zcrypt_shield::spend_pubkey(&self.spend_secret)
    }

    fn address(&self, kind: AddressKind) -> Address {
        Address {
            kind,
            ek: kem::ek_to_bytes(&self.ek),
            pk: self.pubkey(),
        }
    }

    /// This account's reusable Normal address (long, scannable, recoverable).
    pub fn normal_address(&self) -> Address {
        self.address(AddressKind::Normal)
    }

    /// Present this account's key material as a one-time Stealth address.
    pub fn stealth_address(&self) -> Address {
        self.address(AddressKind::Stealth)
    }

    /// Export the selective-disclosure view key: decrypts incoming notes to this
    /// account and reveals amounts, but holds NO spend secret — it cannot spend,
    /// and it cannot read coins sent to any other key or bearer coins.
    pub fn view_key(&self) -> ViewKey {
        ViewKey {
            dk: kem::dk_to_bytes(&self.dk),
            ek: kem::ek_to_bytes(&self.ek),
        }
    }

    /// Try to receive a note as a spendable coin: decrypt it to recover
    /// `(value, blind)` and pair it with *our* spend secret. The sender knew our
    /// `pk` (so it built the commitment) but not our `spend_secret`, so it can
    /// never spend the coin it sent.
    ///
    /// Scanning "by mnemonic" is just calling this over every on-chain note; the
    /// ones that decrypt are yours.
    pub fn receive(&self, note: &KemCiphertext) -> Option<Coin> {
        let pt = kem::decrypt(&self.dk, &self.ek, note)?;
        let (value, blind, asset_id) = decode_note(&pt)?;
        Some(Coin {
            value,
            blind,
            spend_secret: self.spend_secret,
            asset_id,
        })
    }

    /// The backup seed (for a stealth account, the value you must store).
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// Create a coin this account owns (bound to its spend key) with the given
    /// value/blind — used to fund a wallet by seeding a commitment it can later
    /// spend. `commitment()` on the result is what goes into the tree.
    pub fn own_coin(&self, value: u64, blind: Blind) -> Coin {
        self.own_asset_coin(value, blind, zcrypt_shield::ASSET_ZCRYPT)
    }

    /// Create a coin this account owns holding a specific shielded asset (e.g. zBTC).
    pub fn own_asset_coin(&self, value: u64, blind: Blind, asset_id: u64) -> Coin {
        Coin { value, blind, spend_secret: self.spend_secret, asset_id }
    }

    /// This account's staking reward address — hand it to `bond` so block rewards
    /// accrue to a key you control and can later claim.
    pub fn reward_address(&self) -> Hash {
        reward_address(&self.pubkey())
    }

    /// Reconstruct the `index`-th reward coin of `value` (atomic units) this
    /// account claimed. The result is a normal spendable coin — its
    /// `commitment()` equals the coinbase commitment the node minted, and its
    /// `commitment()` equals the coinbase commitment the node minted, and its
    /// `spend_secret` lets you spend it in a shield transaction.
    pub fn reward_coin(&self, value: u64, index: u64) -> Coin {
        Coin {
            value,
            blind: claim_blind(&self.pubkey(), index),
            spend_secret: self.spend_secret,
            asset_id: zcrypt_shield::ASSET_ZCRYPT,
        }
    }

    /// Reconstruct the HTLC settlement coin you were paid (`value` of `asset_id`
    /// under the blind you chose, or decrypted from the escrow's note). The blind
    /// is not a function of the escrow id.
    pub fn htlc_coin(&self, value: u64, asset_id: u64, blind: Blind) -> Coin {
        self.own_asset_coin(value, blind, asset_id)
    }

    /// Reconstruct the `index`-th bridge-fee coin of `value` in `asset_id` you claimed
    /// as a staker — a normal spendable asset coin bound to your spend key.
    pub fn fee_reward_coin(&self, value: u64, asset_id: u64, index: u64) -> Coin {
        Coin {
            value,
            blind: fee_reward_blind(&self.pubkey(), asset_id, index),
            spend_secret: self.spend_secret,
            asset_id,
        }
    }
}

/// Note plaintext layout: value(8 LE) ‖ blind(8×8 LE) ‖ asset_id(8 LE) = 80 bytes
/// (padded to `kem::PAD_LEN` before encryption).
pub const NOTE_PLAIN_LEN: usize = 8 + zcrypt_shield::BLIND_BYTES + 8;
fn encode_note(value: u64, blind: &Blind, asset_id: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(NOTE_PLAIN_LEN);
    v.extend_from_slice(&value.to_le_bytes());
    for x in blind {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.extend_from_slice(&asset_id.to_le_bytes());
    v
}

fn decode_note(b: &[u8]) -> Option<(u64, Blind, u64)> {
    // Current format: 8 + 64 + 8 = 80.
    if b.len() < NOTE_PLAIN_LEN {
        return None;
    }
    let value = u64::from_le_bytes(b[0..8].try_into().ok()?);
    let blind: Blind = core::array::from_fn(|i| {
        zcrypt_shield::field_limb(u64::from_le_bytes(b[8 + i * 8..16 + i * 8].try_into().unwrap()))
    });
    let a = 8 + zcrypt_shield::BLIND_BYTES;
    let asset_id = u64::from_le_bytes(b[a..a + 8].try_into().ok()?);
    // The commitment lane is the asset id reduced into the field, so a sender could write
    // `id + p` and the recipient would recompute the same commitment while displaying an
    // unknown asset. Only canonical ids are accepted (registry ids always are).
    if asset_id >= zcrypt_shield::FIELD_ORDER {
        return None;
    }
    // Same aliasing on the value lanes: `v + k*p*2^26` commits identically to `v`, so a
    // sender could make a 1-unit payment display as an astronomical balance. The circuit
    // only ever commits values <= MAX_COIN_VALUE, so anything above is not a real note.
    if value > zcrypt_shield::MAX_COIN_VALUE {
        return None;
    }
    Some((value, blind, asset_id))
}

/// Fixed-size cover ciphertext that looks like a real encrypted note but decrypts
/// for nobody (encrypts junk to a throwaway ML-KEM key). Used so stealth/bearer
/// outputs are indistinguishable on-chain from normal payments.
pub fn cover_note_bytes() -> Vec<u8> {
    let (_dk, ek) = kem::generate();
    let mut junk = [0u8; 48];
    rand::thread_rng().fill_bytes(&mut junk);
    kem::ciphertext_to_bytes(&kem::encrypt(&RecipientPublic { mlkem: ek }, &junk))
}

/// Send `value` to a Normal or Stealth address. Returns the coin's commitment
/// (the sender publishes this into the note-commitment tree) and the encrypted
/// note (handed to the recipient / posted alongside). A fresh random blind gives
/// each coin a unique commitment/nullifier. The sender binds the *recipient's*
/// `pk` into the commitment but does not know the recipient's spend secret — so it
/// cannot spend what it sent.
pub fn send(to: &Address, value: u64) -> (Commitment, KemCiphertext) {
    let ek = kem::ek_from_bytes(&to.ek).expect("validated at Address::from_bytes");
    let blind = rand_blind();
    let asset_id = zcrypt_shield::ASSET_ZCRYPT;
    let commitment = zcrypt_shield::commit_asset(value, &blind, &to.pk, asset_id);
    let note = encode_note(value, &blind, asset_id);
    let ct = kem::encrypt(&RecipientPublic { mlkem: ek }, &note);
    (commitment, ct)
}

/// Build the output tuple the shield prover needs to pay a native-ZCRYPT coin
/// `(value, blind)` to `to` (its `pk` is bound into the new commitment).
pub fn out_coin(to: &Address, value: u64, blind: Blind) -> OutCoin {
    (value, blind, to.pk, zcrypt_shield::ASSET_ZCRYPT)
}

/// Build an output tuple paying a specific shielded asset (e.g. zBTC) to `to`.
pub fn out_asset_coin(to: &Address, value: u64, blind: Blind, asset_id: u64) -> OutCoin {
    (value, blind, to.pk, asset_id)
}

/// A fresh random blinding factor (for building a new coin's commitment + note).
pub fn random_blind() -> Blind {
    rand_blind()
}

// ---- staking-reward claim binding -------------------------------------------
//
// A validator's block rewards accrue to a 32-byte *reward address* that is a hash
// commitment to its shield public key `pk`. To turn the accrued balance into
// spendable money the node mints a **coinbase** commitment `C = commit(value,
// blind, pk)` into the note tree; only the holder of `spend_secret` (with
// `pk = spend_pubkey(spend_secret)`) can spend it, exactly like a received coin.
//
// The blind is a *public* deterministic function of `(pk, index)`. That is safe:
// a reward's amount is already public (it's on the emission schedule), and
// spend-time privacy still comes from the ring + the secret-keyed nullifier. Any
// party can therefore submit the claim — the coins are locked to the owner's `pk`
// regardless — and the owner can always reconstruct every coin it is owed.

fn pk_bytes(pk: &PubKey) -> [u8; 64] {
    let mut b = [0u8; 64];
    for (i, limb) in pk.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    b
}

/// The 32-byte staking reward address bound to shield spend key `pk`. A validator
/// sets this at bond time (`Account::reward_address`); only the holder of the
/// matching `spend_secret` can spend the coins a claim mints.
pub fn reward_address(pk: &PubKey) -> Hash {
    h(b"ZC-REWARD-ADDR", &[&pk_bytes(pk)])
}

/// Deterministic public blind for the `index`-th coin claimed to `pk`.
pub fn claim_blind(pk: &PubKey, index: u64) -> Blind {
    let d0 = h(b"ZC-CLAIM-BLIND", &[&pk_bytes(pk), &index.to_le_bytes()]);
    let d1 = h(b"ZC-CLAIM-BLN2", &[&pk_bytes(pk), &index.to_le_bytes()]);
    blind_from_digests(&d0, &d1)
}

/// Eight canonical limbs from two 32-byte digests: four limbs from each, reduced into
/// the field. Shared by every deterministic public blind.
fn blind_from_digests(d0: &Hash, d1: &Hash) -> Blind {
    core::array::from_fn(|i| {
        let d = if i < 4 { d0 } else { d1 };
        let o = (i % 4) * 8;
        zcrypt_shield::field_limb(u64::from_le_bytes(d[o..o + 8].try_into().unwrap()))
    })
}

/// The coinbase commitment the node mints for the `index`-th claimed reward coin
/// of `value` (atomic units) to `pk` — and the exact commitment the owner
/// reconstructs from [`Account::reward_coin`].
pub fn reward_commitment(pk: &PubKey, value: u64, index: u64) -> Commitment {
    zcrypt_shield::commit(value, &claim_blind(pk, index), pk)
}

/// Deterministic public blind for a claimed bridge-fee coin, keyed by `(pk, asset, index)`
/// so it collides with neither reward nor HTLC coins.
fn fee_reward_blind(pk: &PubKey, asset_id: u64, index: u64) -> Blind {
    let d0 = h(b"ZC-FEE-BLIND", &[&pk_bytes(pk), &asset_id.to_le_bytes(), &index.to_le_bytes()]);
    let d1 = h(b"ZC-FEE-BLN2", &[&pk_bytes(pk), &asset_id.to_le_bytes(), &index.to_le_bytes()]);
    blind_from_digests(&d0, &d1)
}

/// The commitment the node mints for the `index`-th claimed bridge-fee coin of `value`
/// in `asset_id` to `pk` — asset-typed, and reconstructed by [`Account::fee_reward_coin`].
pub fn fee_reward_commitment(pk: &PubKey, value: u64, asset_id: u64, index: u64) -> Commitment {
    zcrypt_shield::commit_asset(value, &fee_reward_blind(pk, asset_id, index), pk, asset_id)
}

/// A small dedicated ZCRYPT gas coin (1 ZCRYPT, ~100 transfers) reserved on an
/// account's FIRST claim, so a freshly-claimed balance is immediately spendable.
/// A transfer bundles a separate ZCRYPT gas note, so it needs two ZCRYPT coins
/// (one to pay the 0.01 gas, one to fund the payment); without this a single
/// claimed coin (the foundation's liquid tranche, a validator's first reward)
/// could not be spent at all.
pub const CLAIM_GAS_COIN: u64 = 100 * crate::emission::MIN_FEE;

/// The coin values a claim of `amount` mints, in index order. On an account's
/// first claim (`first_claim`) and when the amount comfortably exceeds it, the
/// first coin is a [`CLAIM_GAS_COIN`] so the claimant can immediately transact;
/// the remainder is split into `MAX_COIN_VALUE` chunks. Later claims (the account
/// already holds coins) are not split, avoiding needless fragmentation.
///
/// Consensus-critical: the node mints exactly these coins and the wallet
/// reconstructs them, so both call this one function.
pub fn claim_chunks(amount: u64, first_claim: bool) -> Vec<u64> {
    let max = zcrypt_shield::MAX_COIN_VALUE;
    let mut out = Vec::new();
    let mut rem = amount;
    if first_claim && amount >= 2 * CLAIM_GAS_COIN {
        out.push(CLAIM_GAS_COIN);
        rem -= CLAIM_GAS_COIN;
    }
    while rem > 0 {
        let chunk = rem.min(max);
        out.push(chunk);
        rem -= chunk;
    }
    out
}

/// Retired public settlement blind. Settlement coins no longer use it: the
/// beneficiary samples a hidden blind and proves the opening. Kept so a leaf built
/// the old way can still be recognized, and so it is not reused by accident for a
/// new escrow.
#[allow(dead_code)]
pub fn htlc_blind(pk: &PubKey, escrow_id: &Hash) -> Blind {
    let d0 = h(b"ZC-HTLC-BLIND", &[&pk_bytes(pk), escrow_id]);
    let d1 = h(b"ZC-HTLC-BLN2", &[&pk_bytes(pk), escrow_id]);
    blind_from_digests(&d0, &d1)
}

/// Encrypt an on-chain note carrying `(value, blind)` to a recipient address
/// (ML-KEM). Pair it with `out_coin(to, value, blind)` — same blind — so the
/// recipient's decrypted note reproduces the on-chain output commitment. The
/// recipient recovers the coin with `Account::receive`.
pub fn encrypt_note(to: &Address, value: u64, blind: Blind) -> KemCiphertext {
    encrypt_note_asset(to, value, blind, zcrypt_shield::ASSET_ZCRYPT)
}

/// Encrypt an on-chain note for a specific shielded asset (pair with
/// `out_asset_coin(to, value, blind, asset_id)` — same blind + asset).
pub fn encrypt_note_asset(to: &Address, value: u64, blind: Blind, asset_id: u64) -> KemCiphertext {
    let ek = kem::ek_from_bytes(&to.ek).expect("validated at Address::from_bytes");
    let note = encode_note(value, &blind, asset_id);
    kem::encrypt(&RecipientPublic { mlkem: ek }, &note)
}

/// A bearer coin: the spend secret is embedded, so possession is ownership. There
/// is no recipient and no note encryption — whoever holds the bytes can sweep it.
/// Not covered by any view key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BearerCoin {
    pub coin: Coin,
}

/// Redacted like [`Coin`]: a bearer coin IS the money, so it never prints its secrets.
impl core::fmt::Debug for BearerCoin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BearerCoin").field("coin", &self.coin).finish()
    }
}

impl BearerCoin {
    /// Mint a native-ZCRYPT bearer coin with fresh random blind + spend secret.
    pub fn create(value: u64) -> Self {
        Self::create_asset(value, zcrypt_shield::ASSET_ZCRYPT)
    }

    /// Mint a bearer coin holding a specific shielded asset (0 = ZCRYPT, e.g. zBTC).
    /// The fresh spend secret is embedded in the token — whoever holds it can spend.
    pub fn create_asset(value: u64, asset_id: u64) -> Self {
        BearerCoin {
            coin: Coin {
                value,
                blind: rand_blind(),
                spend_secret: rand_spend_secret(),
                asset_id,
            },
        }
    }

    pub fn commitment(&self) -> Commitment {
        self.coin.commitment()
    }

    /// Serialize the whole coin (`value ‖ blind(8) ‖ spend_secret(8) ‖ asset_id`) —
    /// this IS the money (144 bytes). Anyone with these bytes can spend it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(BEARER_COIN_BYTES);
        v.extend_from_slice(&self.coin.value.to_le_bytes());
        for x in &self.coin.blind {
            v.extend_from_slice(&x.to_le_bytes());
        }
        for x in &self.coin.spend_secret {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.extend_from_slice(&self.coin.asset_id.to_le_bytes());
        v
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        // value(8) + blind(64) + spend_secret(64) + asset(8) = 144, exactly. Trailing
        // bytes are rejected so one coin has one byte string (and one bech32m string).
        if b.len() != BEARER_COIN_BYTES {
            return None;
        }
        let value = u64::from_le_bytes(b[0..8].try_into().ok()?);
        let blind: Blind = core::array::from_fn(|i| {
            u64::from_le_bytes(b[BC_BLIND + i * 8..BC_BLIND + 8 + i * 8].try_into().unwrap())
        });
        let spend_secret: SpendSecret = core::array::from_fn(|i| {
            u64::from_le_bytes(b[BC_SS + i * 8..BC_SS + 8 + i * 8].try_into().unwrap())
        });
        // Every limb is a canonical field element (< p). A limb `x + p` would open the
        // same coin as `x` under a second encoding; reject rather than reduce.
        if !blind.iter().chain(spend_secret.iter()).all(|&x| x < zcrypt_shield::FIELD_ORDER) {
            return None;
        }
        let asset_id = u64::from_le_bytes(b[BC_ASSET..BC_ASSET + 8].try_into().ok()?);
        if asset_id >= zcrypt_shield::FIELD_ORDER {
            return None; // non-canonical asset lane (see decode_note)
        }
        if value > zcrypt_shield::MAX_COIN_VALUE {
            return None; // aliased value lanes (see decode_note)
        }
        Some(BearerCoin {
            coin: Coin {
                value,
                blind,
                spend_secret,
                asset_id,
            },
        })
    }

    /// Sweep the bearer coin into a spendable `Coin`. To make it truly yours you
    /// then re-send it to your own address, binding a new spend secret only you
    /// know (otherwise the previous holder still knows this one).
    pub fn sweep(self) -> Coin {
        self.coin
    }

    /// Encode as a **bech32m** string with the `zcb` prefix (`zcb1…`) — compact
    /// (56-byte payload), handy as a QR code for offline bearer transfer.
    pub fn to_bech32(&self) -> String {
        crate::bech::encode("zcb", &self.to_bytes())
    }

    /// Decode a `zcb1…` bearer coin, verifying the checksum and hrp.
    pub fn from_bech32(s: &str) -> Option<Self> {
        let (hrp, data) = crate::bech::decode(s)?;
        if hrp != "zcb" {
            return None;
        }
        Self::from_bytes(&data)
    }
}

/// A selective-disclosure view key (compliance). Holds the ML-KEM decryption key
/// but no spend secret: reads amounts of this account's Normal-address coins and
/// nothing else.
pub struct ViewKey {
    dk: Vec<u8>,
    ek: Vec<u8>,
}

impl ViewKey {
    /// Reveal the `(value, blind)` of a note sent to this account's Normal
    /// address. Returns `None` for notes encrypted to any other key — stealth and
    /// bearer coins stay opaque.
    /// Reveal `(value, blind, asset_id)` of a note sent to the Normal address —
    /// selective compliance disclosure, including which shielded asset it holds.
    pub fn view(&self, note: &KemCiphertext) -> Option<(u64, Blind, u64)> {
        let dk = kem::dk_from_bytes(&self.dk)?;
        let ek = kem::ek_from_bytes(&self.ek)?;
        let pt = kem::decrypt(&dk, &ek, note)?;
        decode_note(&pt)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.dk.len() + self.ek.len());
        v.extend_from_slice(&(self.dk.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.dk);
        v.extend_from_slice(&self.ek);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let l = u32::from_le_bytes(b.get(0..4)?.try_into().ok()?) as usize;
        let dk = b.get(4..4 + l)?.to_vec();
        let ek = b.get(4 + l..)?.to_vec();
        Some(ViewKey { dk, ek })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn every_note_kind_has_the_fixed_wire_length() {
        // Consensus pins every note to `kem::NOTE_WIRE_LEN`; real notes and cover notes
        // must both hit it exactly or every wallet transfer would be rejected.
        let (acct, _) = new_account();
        let real = kem::ciphertext_to_bytes(&encrypt_note(&acct.normal_address(), 5, [1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(real.len(), kem::NOTE_WIRE_LEN);
        let asset = kem::ciphertext_to_bytes(&encrypt_note_asset(&acct.stealth_address(), 5, [1, 2, 3, 4, 5, 6, 7, 8], 77));
        assert_eq!(asset.len(), kem::NOTE_WIRE_LEN);
        assert_eq!(cover_note_bytes().len(), kem::NOTE_WIRE_LEN);
    }

    #[test]
    fn claim_chunks_reserves_a_gas_coin_on_first_claim_only() {
        let big = 50_000 * crate::emission::ATOMIC; // 50k ZCRYPT
        // First claim: [gas coin, rest]; sums to the full amount.
        let first = claim_chunks(big, true);
        assert_eq!(first[0], CLAIM_GAS_COIN);
        assert_eq!(first.iter().sum::<u64>(), big);
        assert!(first.len() >= 2);
        // Later claim (already holds coins): a single coin, no gas reserve.
        let later = claim_chunks(big, false);
        assert_eq!(later, vec![big]);
        // A tiny first claim (below the reserve threshold) stays a single coin.
        let tiny = CLAIM_GAS_COIN; // == 1 ZCRYPT, < 2×reserve
        assert_eq!(claim_chunks(tiny, true), vec![tiny]);
        // Every chunk is within the per-coin cap.
        for &c in &first {
            assert!(c <= zcrypt_shield::MAX_COIN_VALUE);
        }
    }

    #[test]
    fn normal_send_receive_and_recover() {
        let alice = Account::from_seed(seed(1));
        let addr = alice.normal_address();

        // Someone sends Alice 1000; only the commitment + note are produced.
        let (commitment, note) = send(&addr, 1000);

        // Alice receives it, pairing (value, blind) with her spend secret.
        let coin = alice.receive(&note).unwrap();
        assert_eq!(coin.value, 1000);
        // The commitment the sender published matches Alice's coin (binds her pk).
        assert_eq!(coin.commitment(), commitment);
        // Nullifier is well-formed and canonical.
        assert_eq!(
            coin.nullifier(),
            zcrypt_shield::nullifier(&coin.spend_secret, 1000, &coin.blind)
        );

        // Full mnemonic recovery: rebuild the account from the seed alone and
        // re-receive the exact same coin (same spend secret).
        let restored = Account::from_seed(seed(1));
        assert_eq!(restored.receive(&note).unwrap(), coin);
    }

    #[test]
    fn sender_cannot_receive_or_spend() {
        // A different account cannot decrypt the note (so cannot receive)...
        let alice = Account::from_seed(seed(1));
        let (_c, note) = send(&alice.normal_address(), 500);
        let mallory = Account::from_seed(seed(9));
        assert!(mallory.receive(&note).is_none());
        // ...and the sender, though it knows Alice's pk, does not know Alice's
        // spend secret, so it cannot form a coin that opens the commitment. (Spend
        // prevention is enforced in-circuit; see shield_tx::adversarial_respend_rejected.)
    }

    #[test]
    fn view_key_reads_amount_but_cannot_spend() {
        let alice = Account::from_seed(seed(2));
        let (_c, note) = send(&alice.normal_address(), 777);

        // Auditor gets only the view key (serialized round-trip for realism).
        let vk = ViewKey::from_bytes(&alice.view_key().to_bytes()).unwrap();
        let (value, _blind, _asset) = vk.view(&note).unwrap();
        assert_eq!(value, 777);
        // ViewKey carries no spend secret — spending is impossible by construction.
    }

    #[test]
    fn hd_stealth_recoverable_yet_view_opaque() {
        // A coin to an HD stealth sub-address is invisible to the main view key,
        // yet fully recoverable from the SAME seed (re-derive by index).
        let main = Account::from_seed(seed(3));
        let stealth = main.stealth(1);
        let (_c, note) = send(&stealth.stealth_address(), 900);

        // main view key can't read it (stealth has independent keys)...
        assert!(main.view_key().view(&note).is_none());
        // ...but re-deriving stealth(1) from the same seed recovers it.
        let restored = Account::from_seed(seed(3)).stealth(1);
        assert_eq!(restored.receive(&note).unwrap().value, 900);
        // a different index does not.
        assert!(Account::from_seed(seed(3)).stealth(2).receive(&note).is_none());
    }

    #[test]
    fn one_phrase_covers_normal_and_stealth() {
        let (master, phrase) = new_account();
        let stealth = master.stealth(5);

        let (_c, normal_note) = send(&master.normal_address(), 100);
        let (_c, stealth_note) = send(&stealth.stealth_address(), 1234);

        // Restore everything from the single phrase.
        let r = Account::from_mnemonic(&phrase, "").unwrap();
        assert_eq!(r.receive(&normal_note).unwrap().value, 100);
        assert_eq!(r.stealth(5).receive(&stealth_note).unwrap().value, 1234);
    }

    #[test]
    fn random_stealth_not_recoverable_from_mnemonic() {
        // The explicit throwaway variant is NOT in the HD tree.
        let (stealth, backup) = Account::new_stealth();
        let (_c, note) = send(&stealth.stealth_address(), 250);
        assert!(Account::from_seed(seed(4)).receive(&note).is_none());
        assert_eq!(Account::from_seed(backup).receive(&note).unwrap().value, 250);
    }

    #[test]
    fn bech32_address_roundtrip_and_checksum() {
        let a = Account::from_seed(seed(7));
        let addr = a.normal_address();
        let s = addr.to_bech32();
        assert!(s.starts_with("zc1"), "hrp prefix: {}", &s[..3]);
        let back = Address::from_bech32(&s).unwrap();
        assert_eq!(back.to_bytes(), addr.to_bytes());
        assert_eq!(back.pubkey(), a.pubkey());

        // a single corrupted character fails the checksum
        let mut chars: Vec<char> = s.chars().collect();
        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == 'q' { 'p' } else { 'q' };
        let corrupted: String = chars.into_iter().collect();
        assert!(Address::from_bech32(&corrupted).is_none(), "checksum must reject a typo");
    }

    #[test]
    fn serialized_lengths_are_exactly_the_published_ones() {
        let addr = Account::from_seed(seed(5)).normal_address();
        assert_eq!(BEARER_COIN_BYTES, 144);
        assert_eq!(PUBKEY_BYTES, 64);
        assert_eq!(ML_KEM_768_EK_BYTES, 1184);
        assert_eq!(ADDRESS_BYTES, 1249);
        assert_eq!(ADDRESS_BECH32_CHARS, 2008);
        assert_eq!(addr.to_bytes().len(), ADDRESS_BYTES);
        assert_eq!(addr.to_bech32().len(), ADDRESS_BECH32_CHARS);
        assert_eq!(BearerCoin::create(1).to_bytes().len(), BEARER_COIN_BYTES);
    }

    #[test]
    fn decoders_reject_trailing_bytes_and_noncanonical_limbs() {
        let mut a = Account::from_seed(seed(6)).normal_address().to_bytes();
        assert!(Address::from_bytes(&a).is_some());
        a.push(0);
        assert!(Address::from_bytes(&a).is_none(), "address: trailing byte");
        a.pop();
        a.pop();
        assert!(Address::from_bytes(&a).is_none(), "address: truncated");

        let b = BearerCoin::create(777).to_bytes();
        let mut t = b.clone();
        t.push(0);
        assert!(BearerCoin::from_bytes(&t).is_none(), "bearer: trailing byte");
        assert!(BearerCoin::from_bytes(&b[..BEARER_COIN_BYTES - 1]).is_none(), "bearer: truncated");
        // Every limb slot: 0, 1, p-1 accepted; p, p+1, 2^32, 2^64-1 rejected.
        let p = zcrypt_shield::FIELD_ORDER;
        for off in (BC_BLIND..BC_ASSET).step_by(8) {
            for (v, ok) in [(0u64, true), (1, true), (p - 1, true), (p, false), (p + 1, false), (1 << 32, false), (u64::MAX, false)] {
                let mut m = b.clone();
                m[off..off + 8].copy_from_slice(&v.to_le_bytes());
                assert_eq!(BearerCoin::from_bytes(&m).is_some(), ok, "limb at {off} = {v}");
            }
        }
        // A reduced alias (x + p) must not decode to the same coin as x.
        let mut m = b.clone();
        let x = u64::from_le_bytes(b[8..16].try_into().unwrap());
        m[8..16].copy_from_slice(&(x + p).to_le_bytes());
        assert!(BearerCoin::from_bytes(&m).is_none());
        // Asset lane: same canonical rule.
        let mut m = b.clone();
        m[BC_ASSET..BC_ASSET + 8].copy_from_slice(&p.to_le_bytes());
        assert!(BearerCoin::from_bytes(&m).is_none());
    }

    #[test]
    fn bech32_bearer_roundtrip() {
        let b = BearerCoin::create(777);
        let s = b.to_bech32();
        assert!(s.starts_with("zcb1"), "hrp prefix: {}", &s[..4]);
        assert_eq!(BearerCoin::from_bech32(&s).unwrap(), b);
        // wrong hrp rejected
        assert!(Address::from_bech32(&s).is_none());
    }

    #[test]
    fn bearer_coin_sweep() {
        let bearer = BearerCoin::create(1_000_000);
        let commitment = bearer.commitment();

        // The coin travels as raw bytes; anyone holding them can sweep it.
        let received = BearerCoin::from_bytes(&bearer.to_bytes()).unwrap();
        let coin = received.sweep();
        assert_eq!(coin.value, 1_000_000);
        assert_eq!(coin.commitment(), commitment);
        // Spendable: nullifier derives from the embedded spend secret.
        assert_eq!(
            coin.nullifier(),
            zcrypt_shield::nullifier(&coin.spend_secret, 1_000_000, &coin.blind)
        );
    }

    #[test]
    fn address_serialization_roundtrip() {
        let a = Account::from_seed(seed(5));
        let n = a.normal_address();
        let s = a.stealth_address();
        let n2 = Address::from_bytes(&n.to_bytes()).unwrap();
        assert_eq!(n2.kind, AddressKind::Normal);
        assert_eq!(n2.pubkey(), a.pubkey());
        assert_eq!(Address::from_bytes(&s.to_bytes()).unwrap().kind, AddressKind::Stealth);
        // Normal and stealth are the same size on the wire (indistinguishable).
        assert_eq!(n.to_bytes().len(), s.to_bytes().len());
    }

    #[test]
    fn mnemonic_generate_and_restore() {
        let (acct, phrase) = new_account();
        assert_eq!(phrase.split_whitespace().count(), 24, "24-word recovery phrase");

        // Restoring from the phrase alone reproduces the exact account.
        let restored = Account::from_mnemonic(&phrase, "").unwrap();
        assert_eq!(restored.pubkey(), acct.pubkey());
        assert_eq!(restored.normal_address().to_bytes(), acct.normal_address().to_bytes());

        // A coin sent to the address is recoverable purely from the phrase.
        let (_c, note) = send(&acct.normal_address(), 4200);
        let re = Account::from_mnemonic(&phrase, "").unwrap();
        assert_eq!(re.receive(&note).unwrap().value, 4200);
    }

    #[test]
    fn mnemonic_invalid_rejected() {
        // gibberish words
        assert!(Account::from_mnemonic("not a valid mnemonic phrase at all here ok", "").is_none());
        // real words, wrong checksum (all-zero words is not a valid 12-word phrase)
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(Account::from_mnemonic(bad, "").is_none());
    }

    #[test]
    fn mnemonic_passphrase_forks_account() {
        let phrase = generate_mnemonic();
        let a = Account::from_mnemonic(&phrase, "").unwrap();
        let b = Account::from_mnemonic(&phrase, "hunter2").unwrap();
        // The optional passphrase (BIP-39 "25th word") yields a different account.
        assert_ne!(a.pubkey(), b.pubkey());
    }

    #[test]
    fn bip39_official_test_vector() {
        // Canonical BIP-39 vector #1 (English, passphrase "TREZOR") — proves our
        // mnemonic → seed derivation is standard-conformant (interoperable backup).
        let phrase = "abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon about";
        let m = bip39::Mnemonic::parse(phrase).unwrap();
        let seed = m.to_seed("TREZOR");
        let expected = hex::decode(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        )
        .unwrap();
        assert_eq!(&seed[..], &expected[..]);
    }
}
