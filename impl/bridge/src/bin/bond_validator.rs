//! Bond a CometBFT validator into the ACTIVE producing set, and STAY bonded.
//!
//! Unlike `product_flow_3node` (a demo that bonds then unbonds), this does the bond
//! only: it pledges >= 10,000 ZCRYPT into a burn coin and broadcasts a BOND (tag 0x57)
//! signed by the validator's ed25519 consensus key. On the next block the app emits a
//! CometBFT ValidatorUpdate and the node joins the active set, earning block rewards to
//! the reward address you choose (point it at your wallet).
//!
//!   VALIDATOR_SEED_HEX=<64 hex>            # first 32 bytes of priv_validator_key.json
//!   ZCRYPT_REWARD_ADDR=<64 hex>            # your wallet's reward address, OR:
//!   ZCRYPT_REWARD_MNEMONIC="word word ..." # derive the reward address from a wallet phrase
//!   cargo run --release -p zcrypt-bridge --bin bond_validator -- http://localhost:56657 [stake_whole_zcrypt]
//!
//! WALLET TWO-STEP BOND (`sign`): the desktop wallet prepares a bond (`bond_request`: chain
//! id, reward address, stake, commission) and asks the validator HOST for a signature; the
//! consensus private key never enters the wallet. Run ON THE HOST:
//!
//!   VALIDATOR_SEED_HEX=<64 hex> bond_validator sign \
//!       --chain-id zcrypt-1 --reward <64 hex> --stake <base units> --commission-bps <bps> \
//!       [--nonce <u64> | --node http://127.0.0.1:26657]     # nonce fetched from the node if omitted
//!
//! Prints ONLY the 128-hex ed25519 signature on stdout (pubkey + nonce go to stderr), over
//! exactly the wallet's message:
//!   "ZCRYPT-BOND-v1" || chain_id || consensus_pubkey(32) || stake_le(8) || reward(32) ||
//!   commission_bps_le(2) || nonce_le(8)
//!
//! Devnet only for the STAKE FUNDING: the stake coin is minted via SEED (0x56), which a
//! production (non-devnet) node rejects — there you must instead pledge a coin your
//! wallet already holds (a wallet "Bond" flow is the follow-up for that).

use zcrypt_bridge::swap::{self, build_shield_spend};
use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_core::keys::{self, Account};
use zcrypt_core::{emission, htlc_shield, kem, shield_tx};
use zcrypt_shield::{Blind, OutCoin};

/// Build a coin-backed BOND (tag 0x57): authenticated header (pubkey/stake/reward/sig),
/// then `stake_blind` and the `pledge` shield tx whose output[0] burns exactly `stake`.
fn bond_tx(
    sk: &ed25519_dalek::SigningKey,
    stake: u64,
    reward: [u8; 32],
    commission: u16,
    stake_blind: Blind,
    nonce: u64,
    pledge: &shield_tx::ShieldTx,
) -> Vec<u8> {
    let pk = sk.verifying_key().to_bytes();
    // Same message the wallet's two-step flow signs on the host (`bond_validator sign`).
    let sig = swap::sign_bond(sk, swap::CHAIN, stake, &reward, commission, nonce);
    let mut t = vec![0x57u8];
    t.extend_from_slice(&pk);
    t.extend_from_slice(&stake.to_le_bytes());
    t.extend_from_slice(&reward);
    t.extend_from_slice(&commission.to_le_bytes());
    t.extend_from_slice(&nonce.to_le_bytes());
    t.extend_from_slice(&sig);
    for limb in stake_blind {
        t.extend_from_slice(&limb.to_le_bytes());
    }
    t.extend_from_slice(&shield_tx::to_bytes(pledge));
    t
}

/// The validator's consensus signing key from `VALIDATOR_SEED_HEX` (first 32 bytes of
/// `priv_validator_key.json`, hex).
fn consensus_key_from_env() -> ed25519_dalek::SigningKey {
    let hexseed = std::env::var("VALIDATOR_SEED_HEX")
        .expect("set VALIDATOR_SEED_HEX (first 32 bytes of priv_validator_key.json, hex)");
    let raw = hex::decode(hexseed.trim()).expect("VALIDATOR_SEED_HEX: invalid hex");
    let seed32: [u8; 32] = raw[..32].try_into().expect("VALIDATOR_SEED_HEX: need >= 32 bytes");
    ed25519_dalek::SigningKey::from_bytes(&seed32)
}

/// `bond_validator sign ...`: print the host signature for the wallet's two-step bond.
fn sign_subcommand(args: &[String]) {
    let mut chain_id: Option<String> = None;
    let mut reward: Option<[u8; 32]> = None;
    let mut stake: Option<u64> = None;
    let mut commission: Option<u16> = None;
    let mut nonce: Option<u64> = None;
    let mut node: Option<String> = None;
    let mut i = 0;
    let mut val = |i: &mut usize| -> String {
        *i += 1;
        args.get(*i).cloned().unwrap_or_else(|| {
            eprintln!("bond_validator sign: missing value for {}", args[*i - 1]);
            std::process::exit(2)
        })
    };
    while i < args.len() {
        match args[i].as_str() {
            "--chain-id" => chain_id = Some(val(&mut i)),
            "--reward" => {
                reward = Some(
                    hex::decode(val(&mut i).trim())
                        .ok()
                        .and_then(|b| b.try_into().ok())
                        .unwrap_or_else(|| {
                            eprintln!("bond_validator sign: --reward must be 64 hex chars");
                            std::process::exit(2)
                        }),
                )
            }
            "--stake" => stake = Some(val(&mut i).trim().parse().expect("--stake: base units (u64)")),
            "--commission-bps" => commission = Some(val(&mut i).trim().parse().expect("--commission-bps: u16")),
            "--nonce" => nonce = Some(val(&mut i).trim().parse().expect("--nonce: u64")),
            "--node" => node = Some(val(&mut i)),
            other => {
                eprintln!("bond_validator sign: unknown option {other}");
                std::process::exit(2)
            }
        }
        i += 1;
    }
    let sk = consensus_key_from_env();
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    let (chain_id, reward, stake, commission) = match (chain_id, reward, stake, commission) {
        (Some(c), Some(r), Some(s), Some(k)) => (c, r, s, k),
        _ => {
            eprintln!("usage: bond_validator sign --chain-id <id> --reward <64hex> --stake <base units> --commission-bps <bps> [--nonce <u64> | --node <url>]");
            std::process::exit(2)
        }
    };
    let nonce = match nonce {
        Some(n) => n,
        None => {
            let url = node.unwrap_or_else(|| "http://127.0.0.1:26657".to_string());
            Zcrypt::new(&url)
                .query(&format!("/staking/auth_nonce/{pk_hex}"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or_else(|| {
                    eprintln!("bond_validator sign: could not fetch the auth nonce from {url}; pass --nonce");
                    std::process::exit(2)
                })
        }
    };
    let sig = swap::sign_bond(&sk, chain_id.as_bytes(), stake, &reward, commission, nonce);
    eprintln!("consensus pubkey: {pk_hex}\nnonce: {nonce}\nchain: {chain_id}  stake: {stake}  commission_bps: {commission}");
    println!("{}", hex::encode(sig));
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("sign") {
        sign_subcommand(&argv[1..]);
        return;
    }
    let url = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:46657".to_string());
    let stake: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse::<u64>().ok())
        .map(|whole| whole * emission::ATOMIC)
        .unwrap_or(10_000 * emission::ATOMIC);
    if stake < 10_000 * emission::ATOMIC {
        eprintln!("stake must be >= 10000 ZCRYPT (MIN_STAKE)");
        std::process::exit(1);
    }
    let zc = Zcrypt::new(&url);

    // 1. Validator consensus key (the identity CometBFT signs blocks with).
    let sk = consensus_key_from_env();
    let val_pk = sk.verifying_key();
    // The /staking/validators set is keyed by the ed25519 consensus pubkey (32B) hex.
    let val_pk_hex = hex::encode(val_pk.to_bytes());

    // 2. Reward address — where block rewards accrue. Point it at YOUR wallet, either by
    //    its reward address (hex) or by deriving it from your wallet recovery phrase.
    let reward: [u8; 32] = if let Ok(h) = std::env::var("ZCRYPT_REWARD_ADDR") {
        if !h.trim().is_empty() {
            hex::decode(h.trim())
                .expect("ZCRYPT_REWARD_ADDR: invalid hex")
                .try_into()
                .expect("ZCRYPT_REWARD_ADDR must be 64 hex chars (32 bytes)")
        } else {
            reward_from_mnemonic()
        }
    } else {
        reward_from_mnemonic()
    };

    // 3. Idempotency: if this consensus key is already in the active set, stop.
    let already = zc
        .query("/staking/validators")
        .unwrap_or_default()
        .contains(&val_pk_hex);
    if already {
        println!("already bonded: consensus key {} is in the active set", val_pk_hex);
        return;
    }

    // 4. Fund the stake (devnet SEED) and PLEDGE it: spend the funded coin into a burn
    //    coin of exactly `stake` (output[0]), tiny change back (output[1]). Bonding is
    //    gasless — the pledge burns only the stake (fee 0).
    let funder = Account::from_seed([0xBD; 32]); // throwaway; only produces the burned coin
    // The pledge now pays MIN_FEE (M2), so fund covers stake + fee + change.
    let fund = funder.own_coin(stake + emission::MIN_FEE + 100, keys::random_blind());
    if let Err(e) = zc.broadcast(&swap::seed_tx(&fund.commitment())) {
        if !e.contains("already") {
            panic!(
                "could not fund the stake via SEED ({e}). SEED (0x56) is devnet-only; on a \
                 production node bond a coin your wallet already holds instead."
            );
        }
    }
    let stake_blind = keys::random_blind();
    let burn_out: OutCoin = (stake, stake_blind, htlc_shield::BURN_PK, 0);
    let cblind = keys::random_blind();
    let change_out = keys::out_coin(&funder.normal_address(), 100, cblind);
    let cnote = kem::ciphertext_to_bytes(&keys::encrypt_note(&funder.normal_address(), 100, cblind));
    let pledge = build_shield_spend(&zc, &[fund], &[burn_out, change_out], emission::MIN_FEE, vec![zcrypt_core::keys::cover_note_bytes(), cnote])
        .expect("build the stake pledge");

    // 5. Broadcast the BOND (no unbond — this validator stays in the set).
    // Commission the validator keeps on delegators' rewards (basis points; env
    // COMMISSION_BPS, default 10% = 1000). Validators compete on this.
    let commission: u16 = std::env::var("COMMISSION_BPS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(zcrypt_core::staking::DEFAULT_COMMISSION_BPS);
    // BOND carries the signer's monotonic auth nonce (M3); query the current value.
    let bond_nonce: u64 = zc
        .query(&format!("/staking/auth_nonce/{}", hex::encode(val_pk.to_bytes())))
        .ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    zc.broadcast(&bond_tx(&sk, stake, reward, commission, stake_blind, bond_nonce, &pledge))
        .expect("BOND rejected");
    println!(
        "BOND accepted: pledged {} ZCRYPT, rewards -> {}",
        stake / emission::ATOMIC,
        hex::encode(reward)
    );

    // 6. Confirm the ValidatorUpdate landed (the node is now an active producer).
    for _ in 0..30 {
        if zc.query("/staking/validators").unwrap_or_default().contains(&val_pk_hex) {
            println!("validator is now ACTIVE in the staking set (consensus key {})", val_pk_hex);
            println!("it will start producing blocks and earning rewards to the reward address above.");
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    println!("BOND broadcast, but the validator did not appear in /staking/validators yet — check the node logs.");
}

/// Derive the reward address from a wallet recovery phrase (ZCRYPT_REWARD_MNEMONIC). The
/// phrase never leaves this process and is used only to compute the PUBLIC reward address.
fn reward_from_mnemonic() -> [u8; 32] {
    let m = std::env::var("ZCRYPT_REWARD_MNEMONIC").unwrap_or_default();
    if m.trim().is_empty() {
        eprintln!("set ZCRYPT_REWARD_ADDR (64 hex) or ZCRYPT_REWARD_MNEMONIC (your wallet phrase)");
        std::process::exit(1);
    }
    let acct = Account::from_mnemonic(m.trim(), "").expect("invalid ZCRYPT_REWARD_MNEMONIC");
    acct.reward_address()
}
