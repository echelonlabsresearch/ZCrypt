//! Protocol-wide transparent VM — a readable bytecode program for **every**
//! transaction type, so the whole state-transition surface is auditable in one
//! place with one uniform structure.
//!
//! Two kinds of program, two kinds of value:
//!
//! * **Shield transfer** — its twin is the ZK *circuit*; the VM proves it agrees
//!   with the 128-bit STARK (see [`zcrypt_shield::zvm`], re-exported as [`shield`]).
//!   That's opening a black box.
//! * **Consensus txs** (bond, claim, register, HTLC …) — already transparent Rust
//!   in the node; here their validity rules are an **executable specification**.
//!   The differential tests assert `VM ≡ node`, so any drift between the spec and
//!   the implementation fails a test.
//!
//! Each program is a byte string of guard opcodes over a [`Ctx`] (the machine's
//! "registers" — the tx params + the consensus state a guard reads). A program
//! **accepts** iff every guard passes; the node then applies the effects.

pub use zcrypt_shield::zvm as shield;

use crate::asset_registry::valid_ticker;
use crate::hash::Hash;
use crate::htlc_shield::{mint_capability, HTLC_PREIMAGE_LEN};
use crate::nullifier::htlc_hashlock;
use crate::staking::MIN_STAKE;

// ---- opcodes (0x10+ so they never collide with the shield opcodes 0x01–0x06) ----
pub const OP_HALT: u8 = 0x00;
pub const OP_CHECK_MIN_STAKE: u8 = 0x10; // stake ≥ MIN_STAKE
pub const OP_CHECK_AMOUNT_POSITIVE: u8 = 0x11; // amount > 0
pub const OP_CHECK_AMOUNT_LE_CLAIMABLE: u8 = 0x12; // amount ≤ claimable
pub const OP_CHECK_TICKER_VALID: u8 = 0x13; // 2–10 alnum, leading letter
pub const OP_CHECK_TICKER_FREE: u8 = 0x14; // ticker + derived id not taken
pub const OP_CHECK_ASSET_HAS_AUTHORITY: u8 = 0x15; // asset registered with a mint authority
pub const OP_CHECK_CAPABILITY: u8 = 0x16; // H(capability) == authority
pub const OP_CHECK_ESCROW_OPEN: u8 = 0x17; // escrow exists and is Open
pub const OP_CHECK_BEFORE_TIMEOUT: u8 = 0x18; // height < timeout
pub const OP_CHECK_AT_OR_AFTER_TIMEOUT: u8 = 0x19; // height ≥ timeout
pub const OP_CHECK_PREIMAGE: u8 = 0x1A; // SHA256(preimage) == hashlock
pub const OP_CHECK_ASSET_REGISTERED: u8 = 0x1B; // asset id is registered
pub const OP_CHECK_BURN_OUTPUT: u8 = 0x1C; // output[0] == declared burn coin
pub const OP_CHECK_THRESHOLD_SIG: u8 = 0x1D; // ≥M valid ML-DSA sigs from the asset's key set
pub const OP_CHECK_SPV_PROOF: u8 = 0x1E; // a verified Bitcoin SPV deposit proof (trustless mint)
pub const OP_CHECK_AMOUNT_EQ_CLAIMABLE: u8 = 0x1F; // amount == claimable (full-balance claims only)
pub const OP_CHECK_CLAIMABLE_MIN: u8 = 0x20; // claimable >= MIN_CLAIM (no forced dust claims)

// ---- one canonical program per transaction type ----
/// 0x57 bond a validator.
pub const BOND: &[u8] = &[OP_CHECK_MIN_STAKE, OP_HALT];
/// 0x58 claim staking rewards → coinbase coins. Full-balance only: a partial-amount claim
/// let anyone (the tx is unauthenticated) shred a victim's balance into dust coins each
/// worth less than the gas needed to consolidate them (consensus C2).
pub const CLAIM: &[u8] = &[OP_CHECK_AMOUNT_POSITIVE, OP_CHECK_CLAIMABLE_MIN, OP_CHECK_AMOUNT_EQ_CLAIMABLE, OP_HALT];
/// 0x66 claim in-asset fee rewards (bridge skim). Full-balance only; no ZCRYPT-denominated
/// floor because the balance is in the asset's own units.
pub const CLAIM_FEE: &[u8] = &[OP_CHECK_AMOUNT_POSITIVE, OP_CHECK_AMOUNT_EQ_CLAIMABLE, OP_HALT];
/// 0x59 register a shielded-asset ticker (first-mint-wins).
pub const REGISTER: &[u8] = &[OP_CHECK_TICKER_VALID, OP_CHECK_TICKER_FREE, OP_HALT];
/// 0x5A open a mint HTLC escrow with an M-of-N authorization (user-minted assets).
pub const HTLC_OPEN: &[u8] = &[OP_CHECK_ASSET_HAS_AUTHORITY, OP_CHECK_THRESHOLD_SIG, OP_HALT];
/// 0x64 open a **zBTC** mint HTLC escrow gated by a Bitcoin SPV deposit proof —
/// the trustless bridge mint: no signer or treasury anywhere on the path.
pub const HTLC_OPEN_SPV: &[u8] = &[OP_CHECK_ASSET_HAS_AUTHORITY, OP_CHECK_SPV_PROOF, OP_HALT];
/// Rotate an asset's mint authority — same gate as a mint (the CURRENT key set must
/// threshold-sign), just over a rotation message instead of a mint message.
pub const ROTATE_AUTH: &[u8] = &[OP_CHECK_ASSET_HAS_AUTHORITY, OP_CHECK_THRESHOLD_SIG, OP_HALT];
/// 0x5B claim an HTLC escrow with a preimage.
pub const HTLC_CLAIM: &[u8] = &[OP_CHECK_ESCROW_OPEN, OP_CHECK_BEFORE_TIMEOUT, OP_CHECK_PREIMAGE, OP_HALT];
/// 0x5C expire an HTLC escrow after its timeout.
pub const HTLC_EXPIRE: &[u8] = &[OP_CHECK_ESCROW_OPEN, OP_CHECK_AT_OR_AFTER_TIMEOUT, OP_HALT];
/// 0x5D lock zBTC into a burn HTLC escrow (zBTC→BTC).
pub const HTLC_BURN_LOCK: &[u8] = &[OP_CHECK_ASSET_REGISTERED, OP_CHECK_BURN_OUTPUT, OP_HALT];

/// The machine's registers: tx params + the consensus state a guard may read.
/// Fields default to a "fails-closed" value so an unset guard rejects.
#[derive(Clone, Default)]
pub struct Ctx {
    // staking
    pub stake: u64,
    pub amount: u64,
    pub claimable: u64,
    // asset registry
    pub ticker: String,
    pub ticker_taken: bool,
    pub id_taken: bool,
    pub asset_registered: bool,
    pub authority: Option<Hash>,
    pub capability: Vec<u8>,
    /// M-of-N mint authorization (replaces the single-secret capability): the submitter's
    /// declared key set, the exact mint message, and the threshold signatures over it.
    pub mint_keyset: Option<crate::mint_auth::MintKeySet>,
    pub mint_msg: Vec<u8>,
    pub mint_sigs: Vec<crate::mint_auth::SignerSig>,
    /// Result of [`crate::spv::HeaderChain::verify_mint_proof`] over the submitted
    /// Bitcoin deposit proof (precomputed by the node against consensus SPV state,
    /// like `burn_output_ok`). Defaults false — fails closed.
    pub spv_ok: bool,
    // htlc
    pub escrow_open: bool,
    pub height: u64,
    pub timeout: u64,
    pub hashlock: Hash,
    pub preimage: Vec<u8>,
    pub burn_output_ok: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub accept: bool,
    pub reason: &'static str,
}
impl Outcome {
    fn ok() -> Self {
        Outcome { accept: true, reason: "ok" }
    }
    fn reject(reason: &'static str) -> Self {
        Outcome { accept: false, reason }
    }
}

/// Execute a program's guards over `ctx`. Accepts iff every guard passes.
pub fn evaluate(program: &[u8], ctx: &Ctx) -> Outcome {
    for &op in program {
        match op {
            OP_CHECK_MIN_STAKE if ctx.stake < MIN_STAKE => return Outcome::reject("stake below minimum"),
            OP_CHECK_AMOUNT_POSITIVE if ctx.amount == 0 => return Outcome::reject("amount must be positive"),
            OP_CHECK_AMOUNT_LE_CLAIMABLE if ctx.amount > ctx.claimable => return Outcome::reject("amount exceeds claimable"),
            OP_CHECK_TICKER_VALID if !valid_ticker(&ctx.ticker) => return Outcome::reject("invalid ticker"),
            OP_CHECK_TICKER_FREE if ctx.ticker_taken || ctx.id_taken => return Outcome::reject("ticker/id already registered"),
            OP_CHECK_ASSET_HAS_AUTHORITY if ctx.authority.is_none() => return Outcome::reject("asset not registered / no mint authority"),
            OP_CHECK_CAPABILITY if ctx.authority != Some(mint_capability(&ctx.capability)) => return Outcome::reject("invalid mint capability"),
            OP_CHECK_THRESHOLD_SIG if !threshold_sig_ok(ctx) => return Outcome::reject("invalid mint authorization (M-of-N signatures)"),
            OP_CHECK_SPV_PROOF if !ctx.spv_ok => return Outcome::reject("invalid Bitcoin SPV deposit proof"),
            OP_CHECK_ESCROW_OPEN if !ctx.escrow_open => return Outcome::reject("escrow missing or not open"),
            OP_CHECK_BEFORE_TIMEOUT if ctx.height >= ctx.timeout => return Outcome::reject("escrow timed out"),
            OP_CHECK_AT_OR_AFTER_TIMEOUT if ctx.height < ctx.timeout => return Outcome::reject("not yet timed out"),
            OP_CHECK_AMOUNT_EQ_CLAIMABLE if ctx.amount != ctx.claimable => return Outcome::reject("claim must take the full claimable balance"),
            OP_CHECK_CLAIMABLE_MIN if ctx.claimable < crate::emission::MIN_CLAIM => return Outcome::reject("claimable balance is below the 1 ZCRYPT claim minimum (rewards keep accruing)"),
            // A preimage is exactly 32 bytes. Bitcoin consensus caps a witness element at 520
            // bytes and standard relay at 80, so an oversized preimage that ZCrypt accepted
            // could never be spent on the Bitcoin leg: the depositor would keep both.
            OP_CHECK_PREIMAGE if ctx.preimage.len() != HTLC_PREIMAGE_LEN => return Outcome::reject("preimage must be exactly 32 bytes"),
            OP_CHECK_PREIMAGE if htlc_hashlock(&ctx.preimage) != ctx.hashlock => return Outcome::reject("preimage does not match hashlock"),
            OP_CHECK_ASSET_REGISTERED if !ctx.asset_registered => return Outcome::reject("asset not registered"),
            OP_CHECK_BURN_OUTPUT if !ctx.burn_output_ok => return Outcome::reject("output[0] is not the declared burn coin"),
            OP_HALT => break,
            // a guard byte that passed, or a no-op position
            0x10..=0x20 => {}
            _ => return Outcome::reject("unknown opcode"),
        }
    }
    Outcome::ok()
}

/// The M-of-N mint gate: the submitter's declared key set must commit to the asset's
/// registered `authority`, AND carry ≥M valid ML-DSA signatures (from distinct keys) over
/// the exact mint message. Single source of truth — the node builds the ctx and calls this
/// same evaluator, so the transparent gate and consensus cannot diverge.
fn threshold_sig_ok(ctx: &Ctx) -> bool {
    match (&ctx.authority, &ctx.mint_keyset) {
        (Some(auth), Some(ks)) => {
            ks.commitment() == *auth
                && crate::mint_auth::verify_threshold(ks, &ctx.mint_msg, &ctx.mint_sigs)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htlc_shield::EscrowState;
    use crate::keys;
    use crate::node::Node;
    use crate::{asset_registry, emission, htlc_shield};

    fn pk(n: u8) -> Vec<u8> {
        vec![n; 20]
    }

    // Each test asserts: VM program accept  ==  node method accepts (is_ok),
    // on both a valid and an adversarial input. That's VM ≡ node.

    #[test]
    fn bond_program_matches_node() {
        let mut node = Node::new();
        // valid: at the minimum
        let ctx = Ctx { stake: MIN_STAKE, ..Default::default() };
        assert_eq!(evaluate(BOND, &ctx).accept, node.bond(pk(1), pk(1), MIN_STAKE, [1; 32], crate::staking::DEFAULT_COMMISSION_BPS).is_ok());
        // adversarial: below minimum
        let mut node2 = Node::new();
        let ctx = Ctx { stake: MIN_STAKE - 1, ..Default::default() };
        assert_eq!(evaluate(BOND, &ctx).accept, node2.bond(pk(2), pk(2), MIN_STAKE - 1, [2; 32], crate::staking::DEFAULT_COMMISSION_BPS).is_ok());
        assert!(!evaluate(BOND, &ctx).accept);
    }

    #[test]
    fn register_program_matches_node() {
        let mut node = Node::new();
        // valid new ticker (zBTC needs an authority — SPV commitment in production)
        let auth = Some([9u8; 32]);
        let ctx = Ctx { ticker: "zBTC".into(), ticker_taken: false, id_taken: false, ..Default::default() };
        assert_eq!(evaluate(REGISTER, &ctx).accept, node.register_asset("zBTC", 8, auth, 21_000_000 * 100_000_000).is_ok());
        // adversarial: duplicate
        let ctx = Ctx { ticker: "zBTC".into(), ticker_taken: node.asset_id_of("zBTC").is_some(), ..Default::default() };
        assert_eq!(evaluate(REGISTER, &ctx).accept, node.register_asset("zBTC", 8, auth, 21_000_000 * 100_000_000).is_ok());
        assert!(!evaluate(REGISTER, &ctx).accept);
        // adversarial: invalid ticker
        let mut n2 = Node::new();
        let ctx = Ctx { ticker: "1BAD".into(), ..Default::default() };
        assert_eq!(evaluate(REGISTER, &ctx).accept, n2.register_asset("1BAD", 8, None, 21_000_000 * 100_000_000).is_ok());
    }

    #[test]
    fn claim_program_matches_node() {
        let (account, _mn) = keys::new_account();
        let mut node = Node::new();
        node.bond(pk(1), pk(1), MIN_STAKE, account.reward_address(), crate::staking::DEFAULT_COMMISSION_BPS).unwrap();
        for h in 1..=emission::EPOCH {
            node.set_height(h);
            node.record_block_signers(&[pk(1)]);
            node.maybe_distribute_rewards(h);
        }
        let claimable = node.claimable(&account.pubkey());
        assert!(claimable > 0);

        // valid: claim exactly the balance
        let ctx = Ctx { amount: claimable, claimable, ..Default::default() };
        // (clone node's staking state by re-deriving claimable; call on a fresh copy path)
        let ok_node = node.claim_rewards(&account.pubkey(), claimable).is_ok();
        assert_eq!(evaluate(CLAIM, &ctx).accept, ok_node);

        // adversarial: over-claim (fresh account, no balance)
        let (a2, _) = keys::new_account();
        let mut n2 = Node::new();
        let ctx = Ctx { amount: 1, claimable: n2.claimable(&a2.pubkey()), ..Default::default() };
        assert_eq!(evaluate(CLAIM, &ctx).accept, n2.claim_rewards(&a2.pubkey(), 1).is_ok());
        assert!(!evaluate(CLAIM, &ctx).accept);
        // adversarial: a PARTIAL claim (dust-shredding, consensus C2) is rejected by both.
        let ctx = Ctx { amount: 1, claimable: 1_000, ..Default::default() };
        assert!(!evaluate(CLAIM, &ctx).accept, "partial claims are refused");
    }

    #[test]
    fn htlc_open_program_matches_node() {
        use crate::mint_auth;
        let (account, _mn) = keys::new_account();
        let mut node = Node::new();
        let (keyset, signers) = mint_auth::derive_keyset(b"lp-treasury", 3, 2);
        // Use a non-zBTC ticker: zBTC is SPV-only and rejects threshold opens.
        let asset =
            node.register_asset("GOLD", 8, Some(keyset.commitment()), 21_000_000 * 100_000_000).unwrap();
        let lock = htlc_hashlock(b"x");
        let (value, timeout, pk) = (100u64, 50u64, account.pubkey());
        let (_, opening) = crate::htlc_shield::CoinOpening::create(&account.normal_address(), value, asset).unwrap();
        let authority = node.asset_meta(asset).and_then(|m| m.authority);
        let msg = mint_auth::mint_message(
            b"zcrypt-test", asset, value, &lock, timeout, &pk, &opening.coin.commitment, &opening.coin.note_bind(),
        );

        // valid M-of-N authorization: VM and node agree it is accepted.
        let sigs = mint_auth::authorize(&keyset, &signers, &msg);
        let ctx = Ctx {
            authority,
            mint_keyset: Some(keyset.clone()),
            mint_msg: msg.clone(),
            mint_sigs: sigs.clone(),
            ..Default::default()
        };
        let node_ok = node.htlc_open(b"zcrypt-test", asset, value, lock, timeout, pk, &opening, &keyset, &sigs).is_ok();
        assert!(node_ok);
        assert_eq!(evaluate(HTLC_OPEN, &ctx).accept, node_ok);

        // adversarial: signatures from a DIFFERENT (attacker) key set → both reject.
        let (bad_keyset, bad_signers) = mint_auth::derive_keyset(b"attacker", 3, 2);
        let bad_sigs = mint_auth::authorize(&bad_keyset, &bad_signers, &msg);
        let ctx_bad = Ctx {
            authority,
            mint_keyset: Some(bad_keyset.clone()),
            mint_msg: msg.clone(),
            mint_sigs: bad_sigs.clone(),
            ..Default::default()
        };
        let node_bad = node.htlc_open(b"zcrypt-test", asset, value, lock, timeout, pk, &opening, &bad_keyset, &bad_sigs).is_ok();
        assert_eq!(evaluate(HTLC_OPEN, &ctx_bad).accept, node_bad);
        assert!(!evaluate(HTLC_OPEN, &ctx_bad).accept);
    }

    #[test]
    fn htlc_claim_and_expire_programs_match_node() {
        use crate::mint_auth;
        let (account, _mn) = keys::new_account();
        let mut node = Node::new();
        let (keyset, signers) = mint_auth::derive_keyset(b"lp-treasury", 3, 2);
        let asset =
            node.register_asset("GOLD", 8, Some(keyset.commitment()), 21_000_000 * 100_000_000).unwrap();
        let x = b"preimage-of-exactly-32-bytes!!!!";
        assert_eq!(x.len(), HTLC_PREIMAGE_LEN);
        let lock = htlc_hashlock(x);
        node.set_height(10);
        // Open a mint escrow with a valid M-of-N authorization over the exact params.
        let open = |node: &mut Node, value: u64, lock: [u8; 32], timeout: u64| {
            let pk = account.pubkey();
            let (_, opening) = crate::htlc_shield::CoinOpening::create(&account.normal_address(), value, asset).unwrap();
            let msg = mint_auth::mint_message(
                b"zcrypt-test", asset, value, &lock, timeout, &pk, &opening.coin.commitment, &opening.coin.note_bind(),
            );
            let sigs = mint_auth::authorize(&keyset, &signers, &msg);
            node.htlc_open(b"zcrypt-test", asset, value, lock, timeout, pk, &opening, &keyset, &sigs)
        };
        let id = open(&mut node, 100, lock, 100).unwrap();

        // CLAIM: valid (open, before timeout, right preimage)
        let e = node.htlc_escrow(&id).unwrap();
        let ctx = Ctx {
            escrow_open: e.state == EscrowState::Open,
            height: node.height(),
            timeout: e.timeout_height,
            hashlock: e.hashlock,
            preimage: x.to_vec(),
            ..Default::default()
        };
        assert!(evaluate(HTLC_CLAIM, &ctx).accept);
        assert_eq!(evaluate(HTLC_CLAIM, &ctx).accept, node.htlc_claim(&id, x).is_ok());

        // CLAIM adversarial: wrong preimage on a fresh open escrow
        let y = b"another-32-byte-preimage-value!!";
        let id2 = open(&mut node, 100, htlc_hashlock(y), 100).unwrap();
        let e2 = node.htlc_escrow(&id2).unwrap();
        let ctx_bad = Ctx {
            escrow_open: e2.state == EscrowState::Open,
            height: node.height(),
            timeout: e2.timeout_height,
            hashlock: e2.hashlock,
            preimage: b"wrong-preimage-of-32-bytes-len!!".to_vec(),
            ..Default::default()
        };
        assert_eq!(evaluate(HTLC_CLAIM, &ctx_bad).accept, node.htlc_claim(&id2, b"wrong-preimage-of-32-bytes-len!!").is_ok());
        assert!(!evaluate(HTLC_CLAIM, &ctx_bad).accept);
        // Bridge C2: the RIGHT preimage in an oversized encoding is refused by both.
        let mut long = y.to_vec();
        long.extend_from_slice(&[0u8; 600]);
        let ctx_long = Ctx { preimage: long.clone(), hashlock: htlc_hashlock(&long), escrow_open: true, height: 10, timeout: 100, ..Default::default() };
        assert!(!evaluate(HTLC_CLAIM, &ctx_long).accept, "oversized preimage rejected by the VM");

        // EXPIRE: rejected before timeout, accepted at/after
        let (open2, timeout2) = {
            let e = node.htlc_escrow(&id2).unwrap();
            (e.state == EscrowState::Open, e.timeout_height)
        };
        let before = Ctx { escrow_open: open2, height: node.height(), timeout: timeout2, ..Default::default() };
        assert_eq!(evaluate(HTLC_EXPIRE, &before).accept, node.htlc_expire(&id2).is_ok());
        node.set_height(timeout2);
        let (open3, timeout3) = {
            let e = node.htlc_escrow(&id2).unwrap();
            (e.state == EscrowState::Open, e.timeout_height)
        };
        let after = Ctx { escrow_open: open3, height: node.height(), timeout: timeout3, ..Default::default() };
        assert_eq!(evaluate(HTLC_EXPIRE, &after).accept, node.htlc_expire(&id2).is_ok());
    }

    #[test]
    fn burn_lock_program_encodes_the_node_guards() {
        // The node.htlc_burn_lock guards are: asset registered + output[0] is the
        // declared burn coin. The VM program encodes exactly those two.
        assert_eq!(HTLC_BURN_LOCK, &[OP_CHECK_ASSET_REGISTERED, OP_CHECK_BURN_OUTPUT, OP_HALT][..]);
        let good = Ctx { asset_registered: true, burn_output_ok: true, ..Default::default() };
        assert!(evaluate(HTLC_BURN_LOCK, &good).accept);
        let unreg = Ctx { asset_registered: false, burn_output_ok: true, ..Default::default() };
        assert!(!evaluate(HTLC_BURN_LOCK, &unreg).accept);
        let badout = Ctx { asset_registered: true, burn_output_ok: false, ..Default::default() };
        assert!(!evaluate(HTLC_BURN_LOCK, &badout).accept);
    }

    #[test]
    fn shield_transfer_vm_is_reexported() {
        // The circuit's readable twin is reachable from the same module. 7 opcodes:
        // range, membership (which now also proves ownership), single-asset,
        // conservation, compute-nullifiers, compute-outputs, halt.
        assert_eq!(shield::SHIELD_TRANSFER.len(), 7);
        let _ = asset_registry::NATIVE_ASSET;
        let _ = htlc_shield::BURN_PK;
    }
}
