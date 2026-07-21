//! ZCrypt-core: reference implementation of the ZCrypt protocol.
//! See ../../protocol-specification.md.
//!
//! Primitives: hashing (SHA3/SHAKE), ML-KEM-768 KEM + ChaCha20-Poly1305 notes,
//! the SMT nullifier registry. Analysis in `../../crypto-security.md`.
//!
//! Transfer layer — **shield** (`zcrypt_shield` + `shield_tx`, tag 0x55): a
//! Plonky3 zero-knowledge proof that hides amounts and obscures which coin is
//! spent over a ring of decoys. Post-quantum, transparent (no trusted setup),
//! with an in-circuit nullifier the node verifies without learning any secret.
//! Addresses/keys (Normal / Stealth / Bearer + compliance view keys) live in
//! `keys`. Shield (0x55) is the sole value-transfer path.
//!
//! Consensus modules: `staking` (trustless block rewards), `emission` (schedule),
//! `asset_registry` (shielded-asset tickers, e.g. zBTC), `htlc_shield` (HTLC
//! escrows for cross-chain atomic swaps). The classical Ristretto/Bulletproofs
//! stack (Pedersen commitments, range proofs, the native ZVM/mint path) has been
//! removed — shield is the only value layer.

pub mod asset_registry;
pub mod bech;
pub mod emission;
pub mod hash;
pub mod htlc_shield;
pub mod kem;
pub mod keys;
pub mod mint_auth;
pub mod node;
pub mod nullifier;
pub mod reconcile;
pub mod shield_tx;
pub mod smt;
pub mod staking;
pub mod zvm;
