//! Decode a raw, tagged ZCrypt transaction into a PUBLIC-SAFE summary.
//!
//! The chain publishes only what consensus must see. For a shielded transfer that is
//! nullifiers, output commitments, an anchor root, a proof, and a fixed gas burn: no
//! amount, no parties, no asset type. This module renders exactly that, and names the
//! hidden fields explicitly, so the explorer demonstrates the privacy rather than hiding
//! the fact that data is missing.

use serde_json::{json, Value};
use zcrypt_core::shield_tx::{self, ShieldTx};

/// Short hex of a commitment/nullifier/root (first 3 limbs, i.e. 24 bytes) for display.
fn short(c: &[u64; 8]) -> String {
    let mut s = String::new();
    for x in c.iter().take(3) {
        s.push_str(&hex::encode(x.to_le_bytes()));
    }
    format!("{s}…")
}

fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}
fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn rd_hex(b: &[u8], off: usize, len: usize) -> Option<String> {
    Some(hex::encode(b.get(off..off + len)?))
}
fn rd_blind(b: &[u8], off: usize) -> Option<[u64; 4]> {
    Some([rd_u64(b, off)?, rd_u64(b, off + 8)?, rd_u64(b, off + 16)?, rd_u64(b, off + 24)?])
}
fn rd_pk(b: &[u8], off: usize) -> Option<[u64; 8]> {
    let mut pk = [0u64; 8];
    for (i, x) in pk.iter_mut().enumerate() {
        *x = rd_u64(b, off + i * 8)?;
    }
    Some(pk)
}

/// Swap-lock body after the 216-byte header is the same gas prefix a transfer uses,
/// then the asset spend. Returns `(gas_tx, asset_tx)`.
fn parse_swap_proofs(body: &[u8]) -> Option<(ShieldTx, ShieldTx)> {
    const HEAD: usize = 216;
    parse_transfer(body.get(HEAD..)?)
}

/// The 0x55 bundle body: `gas_blind(32) ‖ gas_len(4) ‖ gas_tx ‖ main_tx`.
fn parse_transfer(body: &[u8]) -> Option<(ShieldTx, ShieldTx)> {
    if body.len() < 36 {
        return None;
    }
    let gas_len = rd_u32(body, 32)? as usize;
    let gas_end = 36usize.checked_add(gas_len)?;
    let gas = shield_tx::from_bytes(body.get(36..gas_end)?)?;
    let main = shield_tx::from_bytes(body.get(gas_end..)?)?;
    Some((gas, main))
}

/// The public face of one shielded spend: what an observer actually sees.
fn shield_public(tx: &ShieldTx) -> Value {
    json!({
        "nullifiers": tx.inputs.iter().map(|i| short(&i.nullifier)).collect::<Vec<_>>(),
        "output_commitments": tx.output_commitments.iter().map(short).collect::<Vec<_>>(),
        "anchor_root": short(&tx.root),
        "fee_atomic": tx.fee,
        "encrypted_notes": tx.enc_notes.len(),
        "proof_bytes": tx.proof.len(),
    })
}

const HIDDEN_TRANSFER: [&str; 4] = ["amount", "sender", "recipient", "asset type"];

/// Format atomic units as ZCRYPT for display (native amounts only: fees, stakes,
/// claims, gas). Asset-denominated amounts must use [`asset_amt`] instead.
fn zcry(v: u64) -> String {
    format!("{} atomic ({:.6} ZCRYPT)", v, v as f64 / 1_000_000.0)
}

/// Format an amount denominated in a (possibly non-native) asset's own atomic
/// units. With the asset's decimals and ticker known (a 0x59 carries both), the
/// exact human value is shown; otherwise the label stays honest about the unit.
fn asset_amt(v: u64, asset_id: Option<u64>, decimals: Option<u8>, ticker: Option<&str>) -> String {
    match (asset_id, decimals, ticker) {
        (_, Some(d), Some(t)) => format!("{} atomic ({:.prec$} {})", v, v as f64 / 10f64.powi(d as i32), t, prec = d as usize),
        (Some(0), _, _) => zcry(v),
        (Some(id), _, _) => format!("{v} atomic units of asset {id} (decimals per its registration)"),
        _ => format!("{v} atomic units of the escrowed asset"),
    }
}

/// One row of the payload byte map: the byte range, what consensus parses it as
/// (the VM register / action parameter it becomes), and its decoded value.
fn row(range: String, field: &str, value: String) -> Value {
    json!({ "range": range, "field": field, "value": value })
}

/// Structural rows for one embedded shield tx (used by the 0x55 bundle and the
/// pledge txs inside bond/delegate/locks).
fn shield_rows(prefix: &str, tx: &ShieldTx, out: &mut Vec<Value>) {
    out.push(row(format!("{prefix}"), "shield tx", format!("{} bytes total", shield_tx::to_bytes(tx).len())));
    out.push(row(format!("{prefix}.inputs"), "nullifiers (one per spent coin)", tx.inputs.iter().map(|i| short(&i.nullifier)).collect::<Vec<_>>().join("  ")));
    let outs = tx.output_commitments.iter().map(short).collect::<Vec<_>>().join("  ");
    let out_label = if prefix.contains("gas") {
        "output commitments: [0] = the 0.01 ZCRYPT burn coin (publicly checkable via the gas blind), [1] = the payer's hidden change"
    } else {
        "output commitments (new hidden coins: typically payment + change)"
    };
    out.push(row(format!("{prefix}.outputs"), out_label, outs));
    out.push(row(format!("{prefix}.root"), "anchor root (whole-pool Merkle root)", short(&tx.root)));
    out.push(row(format!("{prefix}.fee"), "in-tx fee field — 0 by design in a bundle: the 0.01 gas is burned as gas.outputs[0] (verified via the public gas blind), not via this field", zcry(tx.fee)));
    out.push(row(format!("{prefix}.enc_notes"), "encrypted notes (ML-KEM-768)", format!("{} note(s)", tx.enc_notes.len())));
    out.push(row(format!("{prefix}.proof"), "STARK proof", format!("{} bytes", tx.proof.len())));
}

/// The FULL payload byte map for a tag: every byte range of the transaction and the
/// VM register / consensus parameter it is parsed into. This is the exact layout the
/// node's parser reads before the gate program runs.
fn payload_layout(tag: u8, body: &[u8]) -> Option<Vec<Value>> {
    let mut r = vec![row("[0]".into(), "tag", format!("0x{tag:02X}"))];
    let hex_at = |off: usize, len: usize| rd_hex(body, off, len).unwrap_or_else(|| "truncated".into());
    match tag {
        0x55 => {
            r.push(row("".into(), "STRUCTURE", "a 0x55 transfer bundles TWO shield txs: a small ZCRYPT \
GAS note that provably burns the 0.01 fee, and the MAIN transfer that moves the (hidden) value. \
Both carry their own STARK proof; consensus accepts or rejects them atomically.".into()));
            r.push(row("[1..33]".into(), "gas blind: the PUBLIC opening of the gas burn. Every node recomputes \
commit(0.01 ZCRYPT, this blind, BURN_PK) and requires it to equal gas.outputs[0] — proving exactly 0.01 was \
burned, while every other output stays hidden", hex_at(0, 32)));
            let gas_len = rd_u32(body, 32)? as usize;
            r.push(row("[33..37]".into(), "gas tx length (u32 LE)", format!("{gas_len}")));
            let (gas, main) = parse_transfer(body)?;
            shield_rows(&format!("[37..{}] gas", 37 + gas_len), &gas, &mut r);
            shield_rows(&format!("[{}..] main", 37 + gas_len), &main, &mut r);
        }
        0x57 => {
            // Wire: ed25519_pk(32) ‖ stake(8) ‖ reward(32) ‖ commission_bps(2) ‖ nonce(8) ‖ sig(64) ‖ stake_blind(32) ‖ shield_tx
            r.push(row("[1..33]".into(), "consensus pubkey (ed25519) -> validator id", hex_at(0, 32)));
            r.push(row("[33..41]".into(), "stake (u64 LE) -> Ctx.stake", rd_u64(body, 32).map(zcry)?));
            r.push(row("[41..73]".into(), "reward address", hex_at(40, 32)));
            r.push(row("[73..75]".into(), "commission_bps (u16 LE)", format!("{}", u16::from_le_bytes(body.get(72..74)?.try_into().ok()?))));
            r.push(row("[75..83]".into(), "auth nonce (u64 LE, replay protection)", format!("{}", rd_u64(body, 74)?)));
            r.push(row("[83..147]".into(), "ed25519 signature over ZCRYPT-BOND-v1 ‖ chain ‖ pk ‖ stake ‖ reward ‖ commission ‖ nonce", hex_at(82, 64)));
            r.push(row("[147..179]".into(), "stake blind (opens the pledge burn output)", hex_at(146, 32)));
            if let Some(stx) = body.get(178..).and_then(shield_tx::from_bytes) {
                shield_rows("[179..] pledge", &stx, &mut r);
            }
        }
        0x58 => {
            r.push(row("[1..65]".into(), "recipient shield pubkey (8 x u64 LE) — PUBLIC by design: a claim is \
transparent income (auditable rewards / foundation vesting). Privacy begins at the coin's first SPEND, \
which hides among the whole pool", hex_at(0, 64)));
            r.push(row("[65..73]".into(), "amount (u64 LE) -> Ctx.amount", rd_u64(body, 64).map(zcry)?));
        }
        0x59 => {
            let dec = *body.first()?;
            let tlen = *body.get(1)? as usize;
            r.push(row("[1..2]".into(), "decimals", format!("{dec}")));
            r.push(row("[2..3]".into(), "ticker length", format!("{tlen}")));
            let ticker: String = String::from_utf8_lossy(body.get(2..2 + tlen)?).into();
            r.push(row(format!("[3..{}]", 3 + tlen), "ticker -> Ctx.ticker", ticker.clone()));
            r.push(row(
                format!("[{}..{}]", 3 + tlen, 11 + tlen),
                "max supply (u64 LE, in this asset's own atomic units)",
                asset_amt(rd_u64(body, 2 + tlen)?, None, Some(dec), Some(&ticker)),
            ));
            r.push(row(format!("[{}..{}]", 11 + tlen, 43 + tlen), "mint-authority commitment (H of M-of-N ML-DSA key set)", hex_at(2 + tlen + 8, 32)));
        }
        0x5A => {
            let aid = rd_u64(body, 0)?;
            r.push(row("[1..9]".into(), "asset id (u64 LE)", format!("{aid}")));
            r.push(row("[9..17]".into(), "escrow value (u64 LE, in the asset's own atomic units)", asset_amt(rd_u64(body, 8)?, Some(aid), None, None)));
            r.push(row("[17..49]".into(), "hashlock (SHA-256) -> Ctx.hashlock", hex_at(16, 32)));
            r.push(row("[49..57]".into(), "timeout height (u64 LE) -> Ctx.timeout", format!("{}", rd_u64(body, 48)?)));
            r.push(row("[57..121]".into(), "claimer shield pubkey", hex_at(56, 64)));
            r.push(row("[121..]".into(), "mint authorization: threshold(u32) ‖ n(u32) ‖ ML-DSA keys ‖ signatures -> Ctx.mint_*", format!("{} bytes", body.len().saturating_sub(120))));
        }
        0x5B => {
            r.push(row("[1..33]".into(), "escrow id -> Ctx.escrow_open lookup", hex_at(0, 32)));
            r.push(row(format!("[33..{}]", 1 + body.len()), "preimage -> Ctx.preimage", hex_at(32, body.len().saturating_sub(32).min(64))));
        }
        0x5C => r.push(row("[1..33]".into(), "escrow id -> Ctx.escrow_open lookup", hex_at(0, 32))),
        0x5D => {
            let aid = rd_u64(body, 40)?;
            r.push(row("[1..9]".into(), "locked value (u64 LE, in the asset's own atomic units)", asset_amt(rd_u64(body, 0)?, Some(aid), None, None)));
            r.push(row("[9..41]".into(), "lock blind (opens the burn output)", hex_at(8, 32)));
            r.push(row("[41..49]".into(), "asset id (u64 LE) -> Ctx.asset_registered lookup", format!("{aid}")));
            r.push(row("[49..81]".into(), "hashlock (SHA-256)", hex_at(48, 32)));
            r.push(row("[81..89]".into(), "timeout height (u64 LE)", format!("{}", rd_u64(body, 80)?)));
            r.push(row("[89..153]".into(), "refund shield pubkey", hex_at(88, 64)));
            if let Some(stx) = body.get(152..).and_then(shield_tx::from_bytes) {
                shield_rows("[153..] lock", &stx, &mut r);
            }
        }
        0x62 => {
            let aid = rd_u64(body, 40)?;
            r.push(row("".into(), "STRUCTURE", "a 0x62 swap lock keeps the 216-byte escrow header, then the \
same ZCRYPT gas prefix a transfer uses (0.01 burned, the locked asset is not charged), then the asset spend \
whose output[0] is the locked-value burn coin.".into()));
            r.push(row("[1..9]".into(), "locked value (u64 LE, in the asset's own atomic units)", asset_amt(rd_u64(body, 0)?, Some(aid), None, None)));
            r.push(row("[9..41]".into(), "lock blind (opens the burn output)", hex_at(8, 32)));
            r.push(row("[41..49]".into(), "asset id (u64 LE) -> Ctx.asset_registered lookup", format!("{aid}")));
            r.push(row("[49..81]".into(), "hashlock (SHA-256)", hex_at(48, 32)));
            r.push(row("[81..89]".into(), "timeout height (u64 LE)", format!("{}", rd_u64(body, 80)?)));
            r.push(row("[89..153]".into(), "counterparty shield pubkey", hex_at(88, 64)));
            r.push(row("[153..217]".into(), "refund shield pubkey", hex_at(152, 64)));
            let gas_len = rd_u32(body, 248)? as usize;
            r.push(row("[217..249]".into(), "gas blind: the PUBLIC opening of the 0.01 ZCRYPT burn", hex_at(216, 32)));
            r.push(row("[249..253]".into(), "gas tx length (u32 LE)", format!("{gas_len}")));
            let (gas, asset_tx) = parse_swap_proofs(body)?;
            shield_rows(&format!("[253..{}] gas", 253 + gas_len), &gas, &mut r);
            shield_rows(&format!("[{}..] asset spend", 253 + gas_len), &asset_tx, &mut r);
        }
        0x5E => {
            // Wire: pubkey(32) ‖ nonce(8) ‖ sig(64) — nonce is signed for replay protection
            r.push(row("[1..33]".into(), "consensus pubkey (ed25519)", hex_at(0, 32)));
            r.push(row("[33..41]".into(), "auth nonce (u64 LE, replay protection)", format!("{}", rd_u64(body, 32)?)));
            r.push(row("[41..105]".into(), "ed25519 signature over ZCRYPT-UNBOND-v1 ‖ chain ‖ pk ‖ nonce", hex_at(40, 64)));
        }
        0x5F => {
            // Wire: delegator_pk(32) ‖ target_addr(20) ‖ stake(8) ‖ reward(32) ‖ sig(64) ‖ stake_blind(32) ‖ shield_tx
            r.push(row("[1..33]".into(), "delegator pubkey (ed25519)", hex_at(0, 32)));
            r.push(row("[33..53]".into(), "target validator address", hex_at(32, 20)));
            r.push(row("[53..61]".into(), "stake (u64 LE) -> Ctx.stake", rd_u64(body, 52).map(zcry)?));
            r.push(row("[61..93]".into(), "reward address", hex_at(60, 32)));
            r.push(row("[93..157]".into(), "ed25519 signature", hex_at(92, 64)));
            r.push(row("[157..189]".into(), "stake blind", hex_at(156, 32)));
            if let Some(stx) = body.get(188..).and_then(shield_tx::from_bytes) {
                shield_rows("[189..] pledge", &stx, &mut r);
            }
        }
        0x60 => {
            // Wire: delegator_pk(32) ‖ target(20) ‖ nonce(8) ‖ sig(64)
            r.push(row("[1..33]".into(), "delegator pubkey (ed25519)", hex_at(0, 32)));
            r.push(row("[33..53]".into(), "target validator address", hex_at(32, 20)));
            r.push(row("[53..61]".into(), "auth nonce (u64 LE, replay protection)", format!("{}", rd_u64(body, 52)?)));
            r.push(row("[61..125]".into(), "ed25519 signature over ZCRYPT-UNDELEGATE-v1 ‖ chain ‖ pk ‖ target ‖ nonce", hex_at(60, 64)));
        }
        0x61 => {
            r.push(row("[1..9]".into(), "asset id (u64 LE)", format!("{}", rd_u64(body, 0)?)));
            r.push(row("[9..41]".into(), "new authority commitment", hex_at(8, 32)));
            r.push(row("[41..]".into(), "rotation authorization from the CURRENT key set (epoch-bound) -> Ctx.mint_*", format!("{} bytes", body.len().saturating_sub(40))));
        }
        0x56 => r.push(row("[1..65]".into(), "coin commitment (8 x u64 LE)", hex_at(0, 64))),
        0x63 => {
            let n = body.len() / 80;
            r.push(row(
                "[1..]".into(),
                "raw Bitcoin block headers (80 bytes each) — every validator verifies linkage, proof-of-work, difficulty rules, and heaviest-chain fork choice",
                format!("{n} header(s); first: {}", hex_at(0, 80.min(body.len()))),
            ));
        }
        0x64 => {
            let aid = rd_u64(body, 0)?;
            r.push(row("[1..9]".into(), "asset id (u64 LE)", format!("{aid}")));
            r.push(row("[9..17]".into(), "escrow value (u64 LE, base units — must be ≤ the proven locked sats)", asset_amt(rd_u64(body, 8)?, Some(aid), None, None)));
            r.push(row("[17..49]".into(), "hashlock (SHA-256) -> Ctx.hashlock", hex_at(16, 32)));
            r.push(row("[49..57]".into(), "timeout height (u64 LE) -> Ctx.timeout", format!("{}", rd_u64(body, 48)?)));
            r.push(row("[57..121]".into(), "claimer shield pubkey", hex_at(56, 64)));
            r.push(row("[121..154]".into(), "Bitcoin reserve claim key (33B) — must hash to the asset's SPV authority", hex_at(120, 33)));
            r.push(row("[154..187]".into(), "depositor refund key (33B)", hex_at(153, 33)));
            r.push(row("[187..]".into(), "refund locktime ‖ vout ‖ raw funding tx ‖ merkleblock proof -> Ctx.spv_ok", format!("{} bytes", body.len().saturating_sub(186))));
        }
        _ => return None,
    }
    Some(r)
}

/// The raw transaction: full bytes (hex) when small enough to display, otherwise the
/// head plus total size (shield proofs run to ~1 MB), and the complete byte map of
/// how consensus parses it.
fn raw_view(b: &[u8], tag: u8, body: &[u8]) -> Value {
    const FULL_HEX_CAP: usize = 2048;
    let mut v = json!({ "total_bytes": b.len() });
    if b.len() <= FULL_HEX_CAP {
        v["tx_hex"] = json!(hex::encode(b));
    } else {
        v["head_hex"] = json!(format!("{}… (+{} more bytes; the tail is proof/signature data shown structurally below)",
            hex::encode(&b[..96]), b.len() - 96));
    }
    if let Some(l) = payload_layout(tag, body) {
        v["layout"] = json!(l);
    }
    v
}

/// Decode a raw tagged tx into a public summary. Never panics: truncated input yields a
/// partial summary rather than an error. `height` is the block the tx was included in,
/// used to re-evaluate height-dependent checks in their historical context.
pub fn describe_tx(b: &[u8], chain_id: &[u8], with_rules: bool, height: u64) -> Value {
    let tag = b.first().copied();
    let body = b.get(1..).unwrap_or(&[]);
    let tag_hex = tag.map(|t| format!("0x{t:02X}")).unwrap_or_else(|| "empty".into());

    let mut v = match tag {
        Some(0x55) => match parse_transfer(body) {
            Some((gas, main)) => json!({
                "type": "Shielded transfer",
                "tag": tag_hex,
                "hidden": HIDDEN_TRANSFER,
                "public": { "main": shield_public(&main), "gas_note": shield_public(&gas) },
                "explains": "A full observer sees two nullifiers, two commitments, a proof, and a fixed 0.01 ZCRYPT gas burn. The amount, both parties, and the asset type are cryptographically hidden.",
            }),
            None => json!({ "type": "Shielded transfer", "tag": tag_hex, "note": "payload not decodable" }),
        },
        Some(0x56) => json!({
            "type": "Seed coin", "tag": tag_hex, "devnet": true,
            "commitment": rd_hex(body, 0, 24).map(|h| format!("{h}…")),
            "explains": "Devnet-only faucet coin (disabled on a production chain).",
        }),
        Some(0x57) => json!({
            "type": "Validator bond", "tag": tag_hex,
            "public": ["consensus key (ed25519)", "stake amount", "reward address"],
            "hidden": ["the origin of the bonded coins"],
            "explains": "Stake is public by design; the burned coins funding it are anonymous pool coins.",
        }),
        Some(0x58) => json!({
            "type": "Reward claim", "tag": tag_hex,
            "public": ["amount", "recipient shield key"],
            "explains": "Rewards are public income; the minted coins are anonymous thereafter.",
        }),
        Some(0x59) => json!({
            "type": "Asset registration", "tag": tag_hex,
            "decimals": body.first().copied(),
            "ticker": body.get(1).and_then(|&tl| body.get(2..2 + tl as usize)).and_then(|s| std::str::from_utf8(s).ok()),
            "max_supply": body.get(1).and_then(|&tl| rd_u64(body, 2 + tl as usize)),
            "authority_commitment": body.get(1).and_then(|&tl| rd_hex(body, 2 + tl as usize + 8, 32)),
            "explains": "Ticker, decimals, and hard cap are public; the mint authority is a commitment to an M-of-N ML-DSA key set (no secret on chain).",
        }),
        Some(0x5A) => {
            let auth_off = 8 + 8 + 32 + 8 + 64;
            json!({
                "type": "HTLC open (mint escrow)", "tag": tag_hex,
                "asset_id": rd_u64(body, 0).map(|a| a.to_string()),
                "value_atomic": rd_u64(body, 8),
                "hashlock": rd_hex(body, 16, 32),
                "timeout_height": rd_u64(body, 48),
                "mint_authority": mint_auth_summary(body.get(auth_off..).unwrap_or(&[])),
                "explains": "The bridge mints a shielded asset into an escrow. The value is public (an atomic swap requires it); minting is authorized by M-of-N ML-DSA signatures over these exact parameters.",
            })
        }
        Some(0x5B) => json!({
            "type": "HTLC claim", "tag": tag_hex,
            "escrow_id": rd_hex(body, 0, 32),
            "preimage": rd_hex(body, 32, body.len().saturating_sub(32).min(64)),
            "explains": "The preimage is revealed here (as every HTLC requires); it settles the matching leg of the atomic swap.",
        }),
        Some(0x5C) => json!({
            "type": "HTLC expire", "tag": tag_hex,
            "escrow_id": rd_hex(body, 0, 32),
            "explains": "An unclaimed escrow closes after its timeout and refunds its locker.",
        }),
        Some(0x5D) => json!({
            "type": "HTLC burn-lock (zBTC redeem)", "tag": tag_hex,
            "value_atomic": rd_u64(body, 0),
            "asset_id": rd_u64(body, 40).map(|a| a.to_string()),
            "hashlock": rd_hex(body, 48, 32),
            "timeout_height": rd_u64(body, 80),
            "hidden": ["which coins funded the lock"],
            "explains": "Value locked into a burn escrow is public (the swap peg requires it); the coins that funded it stay hidden behind the whole-pool proof.",
        }),
        Some(0x5E) => json!({
            "type": "Unbond", "tag": tag_hex,
            "validator_key": rd_hex(body, 0, 32),
            "auth_nonce": rd_u64(body, 32),
            "explains": "Releases a validator's stake; signed by its consensus key over chain_id + nonce (replay-safe).",
        }),
        Some(0x5F) => json!({
            "type": "Delegate", "tag": tag_hex,
            "delegator_key": rd_hex(body, 0, 32),
            "validator_addr": rd_hex(body, 32, 20),
            "stake_atomic": rd_u64(body, 52),
            "explains": "Stake and validator are public; the delegator's source coins are anonymous.",
        }),
        Some(0x60) => json!({
            "type": "Undelegate", "tag": tag_hex,
            "delegator_key": rd_hex(body, 0, 32),
            "validator_addr": rd_hex(body, 32, 20),
            "auth_nonce": rd_u64(body, 52),
            "explains": "Removes a delegation; signed over chain_id + nonce (replay-safe).",
        }),
        Some(0x61) => json!({
            "type": "Authority rotation", "tag": tag_hex,
            "asset_id": rd_u64(body, 0).map(|a| a.to_string()),
            "new_authority": rd_hex(body, 8, 32),
            "explains": "Rotates an asset's mint authority to a new M-of-N key set, authorized by a threshold signature from the current one. Epoch-bound, so it cannot be replayed.",
        }),
        Some(0x62) => json!({
            "type": "In-pool swap lock", "tag": tag_hex,
            "value_atomic": rd_u64(body, 0),
            "asset_id": rd_u64(body, 40).map(|a| a.to_string()),
            "hashlock": rd_hex(body, 48, 32),
            "timeout_height": rd_u64(body, 80),
            "hidden": ["which coins funded the lock"],
            "explains": "One leg of a private asset-for-asset swap. The locked value and asset are public for the escrow; the funding coins are hidden. Gas is 0.01 ZCRYPT in a separate proof, and the locked asset is not charged. Two such legs under one hashlock settle atomically.",
        }),
        Some(0x63) => json!({
            "type": "Bitcoin header relay", "tag": tag_hex,
            "headers": body.len() / 80,
            "explains": "Raw Bitcoin block headers feeding the consensus SPV chain — the trustless zBTC mint gate. Anyone may relay; each header proves itself by its proof-of-work, so the relayer is untrusted.",
        }),
        Some(0x64) => json!({
            "type": "HTLC open (SPV-verified mint)", "tag": tag_hex,
            "asset_id": rd_u64(body, 0).map(|a| a.to_string()),
            "value_atomic": rd_u64(body, 8),
            "hashlock": rd_hex(body, 16, 32),
            "timeout_height": rd_u64(body, 48),
            "reserve_pk": rd_hex(body, 120, 33),
            "explains": "A trustless bridge mint: every validator re-verified a Bitcoin SPV proof that real BTC (≥ the minted base units, 1:1) is locked in an HTLC claimable only by the pinned reserve key. No treasury, no signatures — nothing to trust.",
        }),
        _ => json!({ "type": "Unknown", "tag": tag_hex, "bytes": b.len() }),
    };
    // Attach the validity rule: the auditability-VM bytecode that defines this tx type, plus
    // (for a shielded transfer) the live circuit-proof verdict. Only for block detail
    // (with_rules), since verifying a proof is real work.
    if with_rules {
        if let (Some(t), Value::Object(map)) = (tag, &mut v) {
            // The FULL transaction: raw bytes + the byte map consensus parses them by.
            map.insert("raw".to_string(), raw_view(b, t, body));
            let main = if t == 0x55 { parse_transfer(body).map(|(_, m)| m) } else { None };
            if let Some(r) = rules(t, main.as_ref(), body, chain_id, height) {
                map.insert("rules".to_string(), r);
            }
        }
    }
    v
}

/// Read the leading `threshold(u32) ‖ n(u32)` of a mint-authorization blob to show the
/// M-of-N shape without decoding the (large) ML-DSA keys and signatures.
fn mint_auth_summary(auth: &[u8]) -> Value {
    match (rd_u32(auth, 0), rd_u32(auth, 4)) {
        (Some(m), Some(n)) if n > 0 && n <= 64 => json!({ "threshold": m, "keys": n, "scheme": "ML-DSA-65" }),
        _ => json!(null),
    }
}

// ---------------------------------------------------------------------------
// Rules: the auditability-VM bytecode per tx type, and the circuit twin.
//
// Two transparent VMs, both public, both the authoritative spec of validity:
//  * the shielded transfer is defined by `zcrypt_shield::zvm::SHIELD_TRANSFER` (7 opcodes),
//    each opcode one circuit constraint. The circuit is the zero-knowledge enforcement of
//    exactly that program; the two are differentially tested. The explorer re-verifies the
//    STARK proof live (the public, witness-free half). It cannot run the VM itself, because
//    the VM needs the private witness: that is precisely why the circuit exists.
//  * every other value-affecting tx is gated on chain by a `zcrypt_core::zvm` program. That
//    bytecode IS the consensus rule that admitted the transaction.
// ---------------------------------------------------------------------------

/// Human-readable name + one-line meaning for a shield-VM opcode.
fn op_shield(op: u8) -> (&'static str, &'static str) {
    match op {
        0x00 => ("HALT", "accept"),
        0x01 => ("CHECK_RANGE", "every value (inputs, outputs, fee) < 2^26"),
        0x03 => ("CHECK_SINGLE_ASSET", "all inputs and outputs carry one asset id"),
        0x04 => ("CHECK_CONSERVATION", "Sum(inputs) == Sum(outputs) + fee"),
        0x05 => ("COMPUTE_NULLIFIERS", "emit the canonical nullifier per input"),
        0x06 => ("COMPUTE_OUTPUTS", "emit the output commitments (new coins)"),
        0x07 => ("CHECK_MEMBERSHIP", "each input is a real leaf under the root (proves ownership too)"),
        _ => ("?", "unknown opcode"),
    }
}

/// Human-readable name + one-line meaning for a consensus-gate opcode.
fn op_gate(op: u8) -> (&'static str, &'static str) {
    match op {
        0x00 => ("HALT", "accept"),
        0x10 => ("CHECK_MIN_STAKE", "stake >= the minimum bond"),
        0x11 => ("CHECK_AMOUNT_POSITIVE", "amount > 0"),
        0x12 => ("CHECK_AMOUNT_LE_CLAIMABLE", "amount <= claimable rewards"),
        0x13 => ("CHECK_TICKER_VALID", "2-10 alphanumerics, leading letter"),
        0x14 => ("CHECK_TICKER_FREE", "ticker and derived id not taken"),
        0x15 => ("CHECK_ASSET_HAS_AUTHORITY", "asset is registered with a mint authority"),
        0x17 => ("CHECK_ESCROW_OPEN", "escrow exists and is Open"),
        0x18 => ("CHECK_BEFORE_TIMEOUT", "height < timeout"),
        0x19 => ("CHECK_AT_OR_AFTER_TIMEOUT", "height >= timeout"),
        0x1A => ("CHECK_PREIMAGE", "SHA256(preimage) == hashlock"),
        0x1B => ("CHECK_ASSET_REGISTERED", "asset id is registered"),
        0x1C => ("CHECK_BURN_OUTPUT", "output[0] == the declared burn coin"),
        0x1D => ("CHECK_THRESHOLD_SIG", ">= M valid ML-DSA signatures from the asset's key set"),
        _ => ("?", "unknown opcode"),
    }
}

fn disasm(program: &[u8], shield: bool) -> Vec<Value> {
    program
        .iter()
        .map(|&op| {
            let (name, note) = if shield { op_shield(op) } else { op_gate(op) };
            json!({ "op": format!("0x{op:02X}"), "name": name, "note": note })
        })
        .collect()
}

/// The shield program with each opcode ANNOTATED by the public value it checks or emits for
/// THIS transaction. The program (bytecode) is fixed; what makes each transaction's execution
/// unique is the data: the anchor root, the fee, and the specific nullifiers and commitments
/// the COMPUTE steps produce. Amounts and asset stay hidden (the proof verifies them blind).
fn shield_program(tx: Option<&ShieldTx>) -> Vec<Value> {
    zcrypt_shield::zvm::SHIELD_TRANSFER
        .iter()
        .map(|&op| {
            let (name, note) = op_shield(op);
            let mut o = json!({ "op": format!("0x{op:02X}"), "name": name, "note": note });
            if let Some(t) = tx {
                let value = match op {
                    0x07 => Some(json!(format!("anchor root {}", short(&t.root)))), // CHECK_MEMBERSHIP
                    0x04 => Some(json!(format!("public fee = {} atomic  (Σ inputs and Σ outputs stay hidden)", t.fee))), // CHECK_CONSERVATION
                    0x05 => Some(json!(t.inputs.iter().map(|i| short(&i.nullifier)).collect::<Vec<_>>())), // COMPUTE_NULLIFIERS
                    0x06 => Some(json!(t.output_commitments.iter().map(short).collect::<Vec<_>>())), // COMPUTE_OUTPUTS
                    _ => None,
                };
                if let Some(v) = value {
                    o["value"] = v;
                }
            }
            o
        })
        .collect()
}

/// The consensus-gate program with each opcode annotated by the explorer's RE-EXECUTION of it,
/// stepping through the VM: where the check is a pure function of the transaction it is
/// reproduced here (`ok: true/false`); where it depended on chain state at the time (escrow
/// open, height, ticker-free, claimable) it is marked state-dependent (`ok: null`) because the
/// state has since moved. This is the same program consensus ran, walked step by step.
fn gate_program(tag: u8, prog: &[u8], body: &[u8], chain_id: &[u8], height: u64) -> Vec<Value> {
    prog.iter()
        .map(|&op| {
            let (name, note) = op_gate(op);
            let mut o = json!({ "op": format!("0x{op:02X}"), "name": name, "note": note });
            if let Some(r) = gate_op_result(tag, op, body, chain_id, height) {
                o["result"] = r;
            }
            o
        })
        .collect()
}

fn gate_op_result(tag: u8, op: u8, body: &[u8], chain_id: &[u8], height: u64) -> Option<Value> {
    let ran = |ok: bool, note: String| json!({ "ok": ok, "note": note });
    let state = json!({ "ok": Value::Null, "note": "checked at consensus over chain state at the time (not reproducible now — the state has moved)" });
    match op {
        0x00 => None, // HALT
        0x10 => {
            // CHECK_MIN_STAKE — the stake is right in the payload; re-execute with values.
            let off = if tag == 0x5F { 52 } else { 32 }; // delegate vs bond header
            let stake = rd_u64(body, off)?;
            let min = zcrypt_core::staking::MIN_STAKE;
            let ok = stake >= min;
            Some(ran(ok, format!("Ctx.stake = {} ; MIN_STAKE = {} ; {} >= {} → {}",
                zcry(stake), zcry(min), stake, min, if ok { "pass" } else { "FAIL" })))
        }
        0x11 => {
            // CHECK_AMOUNT_POSITIVE — the claim amount is in the payload.
            let amount = rd_u64(body, 64)?;
            let ok = amount > 0;
            Some(ran(ok, format!("Ctx.amount = {} ; {} > 0 → {}", zcry(amount), amount, if ok { "pass" } else { "FAIL" })))
        }
        0x12 => {
            // CHECK_AMOUNT_LE_CLAIMABLE — the amount is public; the claimable balance is
            // historical ledger state (for the foundation it is the vesting schedule).
            let amount = rd_u64(body, 64)?;
            Some(json!({ "ok": Value::Null, "note": format!(
                "Ctx.amount = {} ; Ctx.claimable was the recipient's ledger balance at height {height} \
                 (accrued rewards, plus the vested-but-unclaimed foundation tranche if this is the \
                 foundation key). Inclusion proves consensus evaluated amount <= claimable = true.", zcry(amount)) }))
        }
        0x18 => {
            // CHECK_BEFORE_TIMEOUT — the escrow's timeout is state; the inclusion height is known.
            Some(json!({ "ok": Value::Null, "note": format!(
                "evaluated at inclusion height {height} against the escrow's registered timeout; \
                 inclusion proves height < timeout held at that block") }))
        }
        0x19 => {
            Some(json!({ "ok": Value::Null, "note": format!(
                "evaluated at inclusion height {height} against the escrow's registered timeout; \
                 inclusion proves height >= timeout held at that block") }))
        }
        0x13 => {
            // CHECK_TICKER_VALID (register: decimals(1) tlen(1) ticker …)
            let tlen = *body.get(1)? as usize;
            let ticker = std::str::from_utf8(body.get(2..2 + tlen)?).ok()?;
            let ok = zcrypt_core::asset_registry::valid_ticker(ticker);
            Some(ran(ok, format!("explorer re-checked \"{ticker}\" against the format rule → {}", if ok { "valid" } else { "invalid" })))
        }
        0x1C => {
            // CHECK_BURN_OUTPUT (swap-lock 0x62 / burn-lock 0x5D). A swap lock's asset
            // spend sits after the gas prefix, not immediately after the 216-byte header.
            let value = rd_u64(body, 0)?;
            let blind = rd_blind(body, 8)?;
            let asset = rd_u64(body, 40)?;
            let stx = if tag == 0x62 {
                parse_swap_proofs(body)?.1
            } else {
                body.get(152..).and_then(shield_tx::from_bytes)?
            };
            let expected = zcrypt_shield::commit_asset(value, &blind, &zcrypt_core::htlc_shield::BURN_PK, asset);
            let ok = stx.output_commitments.first() == Some(&expected);
            Some(ran(ok, format!("explorer recomputed commit_asset(value, blind, BURN_PK, asset) = {} and compared to output[0] → {}", short(&expected), if ok { "equal" } else { "MISMATCH" })))
        }
        0x1D if tag == 0x5A => {
            // CHECK_THRESHOLD_SIG (htlc_open: asset8 value8 lock32 timeout8 claim_pk64 auth…)
            let asset = rd_u64(body, 0)?;
            let value = rd_u64(body, 8)?;
            let mut lock = [0u8; 32];
            lock.copy_from_slice(body.get(16..48)?);
            let timeout = rd_u64(body, 48)?;
            let pk = rd_pk(body, 56)?;
            let (keyset, sigs) = zcrypt_core::mint_auth::decode_auth(body.get(120..)?)?;
            let msg = zcrypt_core::mint_auth::mint_message(chain_id, asset, value, &lock, timeout, &pk);
            let ok = zcrypt_core::mint_auth::verify_threshold(&keyset, &msg, &sigs);
            Some(ran(ok, format!("explorer re-verified {}-of-{} ML-DSA signatures over the mint message → {}", keyset.threshold, keyset.n(), if ok { "valid" } else { "INVALID" })))
        }
        0x1A => {
            // CHECK_PREIMAGE (htlc_claim: escrow_id32 preimage…): recompute the hashlock
            let preimage = body.get(32..)?;
            let hl = zcrypt_core::nullifier::htlc_hashlock(preimage);
            Some(json!({ "ok": Value::Null, "note": format!("explorer computed SHA256(preimage) = {}… (consensus checked this equals the escrow's registered hashlock)", hex::encode(&hl[..10])) }))
        }
        // state-dependent checks: honest note. (0x1D here is rotation, which binds a historical
        // epoch; 0x1E is the SPV deposit proof, verified against the consensus header chain.)
        0x14 | 0x15 | 0x17 | 0x1B | 0x1D | 0x1E => Some(state),
        _ => None,
    }
}

fn rules(tag: u8, main: Option<&ShieldTx>, body: &[u8], chain_id: &[u8], height: u64) -> Option<Value> {
    use zcrypt_core::zvm as g;
    let (prog, shield): (&[u8], bool) = match tag {
        0x55 => (zcrypt_shield::zvm::SHIELD_TRANSFER, true),
        0x57 => (g::BOND, false),
        0x58 => (g::CLAIM, false),
        0x59 => (g::REGISTER, false),
        0x5A => (g::HTLC_OPEN, false),
        0x5B => (g::HTLC_CLAIM, false),
        0x5C => (g::HTLC_EXPIRE, false),
        0x5D | 0x62 => (g::HTLC_BURN_LOCK, false),
        0x61 => (g::ROTATE_AUTH, false),
        0x64 => (g::HTLC_OPEN_SPV, false),
        _ => return None,
    };
    // Annotate each opcode with per-transaction execution: shield emits values (COMPUTE steps),
    // a consensus-gate program is walked step by step with the explorer re-executing each check
    // it can reproduce.
    let program = if shield { shield_program(main) } else { gate_program(tag, prog, body, chain_id, height) };
    let mut v = json!({
        "vm": if shield { "shield circuit" } else { "consensus gate" },
        "program_hex": hex::encode(prog),
        "program": program,
    });
    if shield {
        // Re-verify the STARK proof: the public, witness-free half of the equivalence.
        if let Some(tx) = main {
            let t = std::time::Instant::now();
            let ok = zcrypt_core::shield_tx::verify(chain_id, tx).is_ok();
            v["circuit"] = json!({ "proof_verified": ok, "verify_ms": t.elapsed().as_millis() as u64 });
        }
        v["equivalence"] = json!(
            "The 7-op program is the FIXED public spec of a valid shield spend: identical for every \
             transfer by design. What differs per transaction is the DATA shown against the opcodes \
             above: the anchor root (CHECK_MEMBERSHIP), the fee (CHECK_CONSERVATION), and the \
             nullifiers and commitments the COMPUTE steps emit. Those emitted values are exactly \
             what the STARK proof verifies for a hidden witness, so 'the VM and the circuit agree' \
             is checked on THIS transaction by its own proof. The input amounts and the asset stay \
             hidden: the VM cannot be re-run publicly because it needs that private witness, which \
             is the point of the proof."
        );
    } else {
        // Summarize the explorer's step-through: how many opcodes it re-executed and whether
        // they all matched consensus. The rest depended on chain state at the time.
        let (mut ran, mut all_ok) = (0u32, true);
        if let Some(arr) = v["program"].as_array() {
            for op in arr {
                match op["result"]["ok"].as_bool() {
                    Some(true) => ran += 1,
                    Some(false) => {
                        ran += 1;
                        all_ok = false;
                    }
                    None => {}
                }
            }
        }
        v["reexecuted"] = json!({ "ran": ran, "all_ok": all_ok });
        v["gate"] = json!(
            "This bytecode is the on-chain consensus rule for this transaction type: the VM ran it \
             over the transaction's public context to admit it. The explorer walks the same program \
             and re-executes every check that is a pure function of the transaction, confirming it \
             matches consensus; state-dependent checks are noted, since the chain state has moved on."
        );
    }
    Some(v)
}
