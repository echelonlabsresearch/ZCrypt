//! Print the foundation account's claim material, for genesis setup and for
//! claiming vested tranches (tag 0x58):
//!   * `pk`             — 64-byte shield pubkey (8×u64 LE), the claim-tx payload
//!   * `reward_address` — 32-byte hash of pk; the ABCI node registers the genesis
//!                        foundation allocation to this address
//!   * `claim_tx`       — a ready-to-broadcast 0x58 claim payload for [amount]
//!
//! Run: `cargo run -p zcrypt-core --example foundation_keys [amount_atomic] [index]`
//! The devnet seed below matches `FOUNDATION_SEED` in the ABCI node. PRODUCTION
//! uses an offline cold key instead — never a committed seed.
//!
//! Reserved assets (zETH, zSOL, ... : `asset_registry::RESERVED_TICKERS`). The same
//! mnemonic also holds the foundation's reserved-asset key set, a 2-of-3 ML-DSA set
//! derived from it. Its commitment goes into genesis as `reserved_mint_authority`, and
//! only a REGISTER tx blessed by that set can claim a reserved ticker:
//!   * `foundation_keys new`                       also prints ZCRYPT_RESERVED_MINT_AUTH
//!   * `foundation_keys authority <mnemonic-file>` prints it again for an existing mnemonic
//!   * `foundation_keys bless <mnemonic-file> <chain-id> <ticker> <decimals> <max-supply-base> <authority-hex>`
//!     prints the blessing (hex) to paste into the wallet's Mint tab. The blessing covers
//!     exactly those fields on that chain; the asset then mints under `<authority-hex>`,
//!     the minting wallet's own M-of-N commitment (the Mint tab shows it).

use zcrypt_core::emission;
use zcrypt_core::hash::h;
use zcrypt_core::keys::{self, Account};
use zcrypt_core::mint_auth::{authorize, derive_keyset, encode_auth, reserved_register_message, MintKeySet, MintSigner};

/// The foundation's reserved-asset key set: 2-of-3 ML-DSA-65, derived from the cold seed
/// under its own domain tag so it shares nothing with the claim key.
fn reserved_keyset(seed: &[u8; 32]) -> (MintKeySet, Vec<MintSigner>) {
    derive_keyset(&h(b"ZC-RESERVED-MINT", &[seed]), 3, 2)
}

fn seed_from_mnemonic_file(path: &str) -> [u8; 32] {
    let phrase = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
    keys::seed_from_mnemonic(phrase.trim(), "").unwrap_or_else(|| die("that file does not hold a valid mnemonic"))
}

fn die(msg: &str) -> ! {
    eprintln!("foundation_keys: {msg}");
    std::process::exit(2)
}

fn main() {
    // `foundation_keys new` — the PRODUCTION key ceremony. Run this on an AIR-GAPPED
    // machine: it generates a fresh foundation account and prints the mnemonic (write
    // it down, never store digitally) and the reward address to bake into genesis via
    // the node's ZCRYPT_FOUNDATION_ADDR env var. Only this mnemonic can ever claim
    // the vesting tranches.
    if std::env::args().nth(1).as_deref() == Some("new") {
        let (account, mnemonic) = keys::new_account();
        println!("== FOUNDATION KEY CEREMONY — keep this output OFFLINE ==");
        println!("mnemonic (the ONLY way to claim the 4.2M — write it down, split it, vault it):");
        println!("  {mnemonic}");
        let pk = account.pubkey();
        let mut pk_bytes = Vec::with_capacity(64);
        for limb in &pk {
            pk_bytes.extend_from_slice(&limb.to_le_bytes());
        }
        println!("pk_hex={}", hex::encode(&pk_bytes));
        println!("ZCRYPT_FOUNDATION_ADDR={}", hex::encode(account.reward_address()));
        println!("ZCRYPT_RESERVED_MINT_AUTH={}", hex::encode(reserved_keyset(&account.seed()).0.commitment()));
        return;
    }
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("authority") {
        let path = args.get(2).unwrap_or_else(|| die("usage: foundation_keys authority <mnemonic-file>"));
        let seed = seed_from_mnemonic_file(path);
        println!("ZCRYPT_RESERVED_MINT_AUTH={}", hex::encode(reserved_keyset(&seed).0.commitment()));
        return;
    }
    if args.get(1).map(String::as_str) == Some("bless") {
        let usage = "usage: foundation_keys bless <mnemonic-file> <chain-id> <ticker> <decimals> <max-supply-base> <authority-hex>";
        if args.len() != 8 {
            die(usage);
        }
        let seed = seed_from_mnemonic_file(&args[2]);
        let chain_id = args[3].as_bytes();
        let ticker = &args[4];
        if !zcrypt_core::asset_registry::is_reserved_ticker(ticker) {
            die(&format!("'{ticker}' is not a reserved ticker; a blessing only applies to {:?}", zcrypt_core::asset_registry::RESERVED_TICKERS));
        }
        let decimals: u8 = args[5].parse().unwrap_or_else(|_| die(usage));
        let max_supply: u64 = args[6].parse().unwrap_or_else(|_| die(usage));
        let authority: [u8; 32] = hex::decode(&args[7]).ok().and_then(|v| v.try_into().ok()).unwrap_or_else(|| die("authority must be 64 hex"));
        let (keyset, signers) = reserved_keyset(&seed);
        let msg = reserved_register_message(chain_id, ticker, decimals, max_supply, &authority);
        let blessing = encode_auth(&keyset, &authorize(&keyset, &signers, &msg));
        println!("== RESERVED ASSET BLESSING ==");
        println!("chain={} ticker={ticker} decimals={decimals} max_supply={max_supply} authority={}", args[3], args[7]);
        println!("reserved_mint_authority={}", hex::encode(keyset.commitment()));
        println!("blessing_hex={}", hex::encode(&blessing));
        return;
    }

    let account = Account::from_seed([0xF0; 32]);
    let pk = account.pubkey();
    let mut pk_bytes = Vec::with_capacity(64);
    for limb in &pk {
        pk_bytes.extend_from_slice(&limb.to_le_bytes());
    }
    println!("pk_hex={}", hex::encode(&pk_bytes));
    println!("reward_address_hex={}", hex::encode(account.reward_address()));

    // Default claim: the genesis-liquid tranche (50,000 ZCRYPT).
    let amount: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(emission::FOUNDATION_LIQUID);
    let index: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    let mut tx = vec![0x58u8];
    tx.extend_from_slice(&pk_bytes);
    tx.extend_from_slice(&amount.to_le_bytes());
    println!("claim_tx_hex={}", hex::encode(&tx));

    // The coinbase coin the claim mints (owner reconstructs and spends it).
    let coin = account.reward_coin(amount, index);
    let c = coin.commitment();
    let mut cb = Vec::with_capacity(64);
    for x in &c {
        cb.extend_from_slice(&x.to_le_bytes());
    }
    println!("claimed_coin_commitment={}", hex::encode(cb));
}
