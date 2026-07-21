//! Generate and display a fresh ZCrypt address (Normal / Stealth) and a bearer coin.

use zcrypt_core::keys::BearerCoin;

fn main() {
    // A fresh wallet: BIP-39 gives the human-readable 24-word recovery phrase.
    let (acct, phrase) = zcrypt_core::keys::new_account();
    let addr = acct.normal_address();
    let bytes = addr.to_bytes();
    let fp = zcrypt_core::hash::h1(b"ZCADDR", &bytes);

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  ZCrypt wallet (freshly generated)                            ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");
    println!("── recovery phrase (BIP-39, 24 words — WRITE THIS DOWN) ────────");
    for (i, chunk) in phrase.split_whitespace().collect::<Vec<_>>().chunks(6).enumerate() {
        println!("  {:>2}. {}", i * 6 + 1, chunk.join("   "));
    }
    println!("\naddress length              : {} bytes", bytes.len());
    println!("fingerprint (SHA3, 8 bytes) : {}\n", hex::encode(&fp[..8]));

    let bech = addr.to_bech32();
    println!("── Normal address (bech32m, zc1… — this is what you share) ─────");
    println!("  {} chars", bech.len());
    // print wrapped for readability
    for line in bech.as_bytes().chunks(76) {
        println!("  {}", std::str::from_utf8(line).unwrap());
    }

    println!("\n── components ──────────────────────────────────────────────────");
    println!("  kind byte  : {:02x}  (00 = Normal)", bytes[0]);
    println!("  spend pk   : {} ...  (64 bytes)", hex::encode(&bytes[1..17]));
    println!("  ml-kem ek  : {} ...  ({} bytes)", hex::encode(&bytes[65..81]), bytes.len() - 65);

    // HD stealth address — recoverable from the SAME phrase (index path)
    let stealth_addr = acct.stealth(0).stealth_address().to_bech32();
    println!("\n── Stealth address #0 (same phrase, index 0 — recoverable) ─────");
    println!("  {}…{}  ({} chars, opaque to the main view key)",
        &stealth_addr[..40], &stealth_addr[stealth_addr.len()-8..], stealth_addr.len());

    // Bearer coin: the money itself, no recipient — compact bech32m
    let bearer = BearerCoin::create(1_000_000);
    println!("\n── Bearer coin (the money itself — 56 bytes, no recipient) ─────");
    println!("  {}", bearer.to_bech32());
}
