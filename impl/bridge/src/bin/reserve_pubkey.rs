//! Print the 33-byte compressed secp256k1 RESERVE PUBKEY (hex) that a chain's genesis must
//! carry as `zbtc_reserve_pk` (env `ZCRYPT_RESERVE_PK` for the compose stacks), for the key
//! the bridge operator will run the watcher with. Never prints a secret.
//!
//!   reserve_pubkey --key <64-hex>              the DERIVED reserve key itself
//!   reserve_pubkey --key-file <path>           same, from a file (hex or 32 raw bytes)
//!   reserve_pubkey --wallet-seed <64-hex>      derive H("BTCBRDG", seed) like the wallet
//!   reserve_pubkey --wallet-seed-file <path>
//!   reserve_pubkey --signet-e2e-mnemonic-file <path>   the signet_swap_e2e derivation
//!                                              (seed = H("ZC-SIGNET-E2E", mnemonic))
//!   reserve_pubkey                             fall back to the watcher's env sources
//!
//! Add `--write-derived-key <path>` to ALSO write the derived 32-byte reserve key (64 hex,
//! newline-terminated) to a NEW file with mode 0600, for use as the watcher's
//! ZCRYPT_RESERVE_KEY_FILE / Docker secret. The file is never overwritten; the key itself is
//! never printed to stdout or stderr.
//!
//! Dev/e2e reserve keys used by the regtest drivers: `--key b1b1...b1` (32 x 0xB1) for
//! swap_demo / fee_flow / public_* / watcher_daemon_e2e, and `--key 0707...07` (32 x 0x07)
//! for reorg_defense_3node.

use zcrypt_bridge::{parse_secret_bytes, reserve_key_from_wallet_seed, Key};

fn die(msg: &str) -> ! {
    eprintln!("reserve_pubkey: {msg}");
    std::process::exit(2)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // Optional trailing `--write-derived-key <path>`: taken out before positional parsing.
    let write_path = args
        .iter()
        .position(|a| a == "--write-derived-key")
        .map(|i| {
            if i + 1 >= args.len() {
                die("--write-derived-key needs a path");
            }
            let path = args.remove(i + 1);
            args.remove(i);
            path
        });
    let val = |i: usize| args.get(i + 1).unwrap_or_else(|| die("missing value"));
    let key: Key = match args.first().map(String::as_str) {
        Some("--key") => Key::from_bytes(&parse_secret_bytes(val(0).as_bytes()).unwrap_or_else(|e| die(&e))),
        Some("--key-file") => {
            let raw = std::fs::read(val(0)).unwrap_or_else(|e| die(&e.to_string()));
            Key::from_bytes(&parse_secret_bytes(&raw).unwrap_or_else(|e| die(&e)))
        }
        Some("--wallet-seed") => {
            reserve_key_from_wallet_seed(&parse_secret_bytes(val(0).as_bytes()).unwrap_or_else(|e| die(&e)))
        }
        Some("--wallet-seed-file") => {
            let raw = std::fs::read(val(0)).unwrap_or_else(|e| die(&e.to_string()));
            reserve_key_from_wallet_seed(&parse_secret_bytes(&raw).unwrap_or_else(|e| die(&e)))
        }
        Some("--signet-e2e-mnemonic-file") => {
            let m = std::fs::read_to_string(val(0)).unwrap_or_else(|e| die(&e.to_string()));
            let seed32 = zcrypt_core::hash::h(b"ZC-SIGNET-E2E", &[m.trim().as_bytes()]);
            reserve_key_from_wallet_seed(&seed32)
        }
        Some(other) if other.starts_with("--") => die(&format!("unknown option {other}")),
        _ => zcrypt_bridge::watcher::reserve_key_from_env().unwrap_or_else(|e| die(&e)),
    };
    if let Some(path) = write_path {
        write_secret_file(&path, &key.sk.secret_bytes());
        eprintln!("reserve_pubkey: wrote the derived reserve key to {path} (mode 0600)");
    }
    println!("{}", hex::encode(key.pk.inner.serialize()));
}

/// Create `path` (refusing to overwrite) with mode 0600 and write the key as 64 hex + newline.
fn write_secret_file(path: &str, secret: &[u8; 32]) {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .unwrap_or_else(|e| die(&format!("cannot create {path} (exists or unwritable): {e}")));
    let mut line = hex::encode(secret);
    line.push('\n');
    f.write_all(line.as_bytes()).unwrap_or_else(|e| die(&format!("write {path}: {e}")));
}
