//! Rotate an SPV asset's Bitcoin reserve key on a running chain (bridge review H3).
//!
//! The chain pins zBTC to one reserve pubkey. Until now that key could never change: a
//! compromise or loss meant a new chain. This tool signs a `ROTATE_RESERVE` (`0x69`) tx with
//! the CURRENT reserve key, authorising the move to a NEW key, and broadcasts it. After it
//! lands:
//!   * every new deposit must pay the new key (wallets read it from `/asset/id/<id>`);
//!   * deposits already mined to the old key (plus a 6-block grace) still mint and can be
//!     re-anchored, so nothing in flight is stranded;
//!   * the watcher must keep the OLD key loaded (`ZCRYPT_RESERVE_PREV_KEY_FILES`) until every
//!     deposit and redeem that names it has been swept or refunded.
//!
//! Usage:
//!   rotate_reserve --current-key-file <path> (--new-key-file <path> | --new-pubkey <hex>)
//!                  [--asset <id>] [--dry-run]
//! Env: ZC_URL (default http://localhost:36657). The new secret key never needs to be on
//! this machine: `--new-pubkey` accepts a key generated elsewhere (`reserve_pubkey`).

use zcrypt_bridge::zcrypt::Zcrypt;
use zcrypt_bridge::{parse_secret_bytes, swap, Key};

fn die(msg: &str) -> ! {
    eprintln!("rotate_reserve: {msg}");
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opt = |name: &str| -> Option<String> {
        args.iter().position(|a| a == name).map(|i| args.get(i + 1).cloned().unwrap_or_else(|| die(&format!("{name} needs a value"))))
    };
    let dry_run = args.iter().any(|a| a == "--dry-run");

    let current = {
        let path = opt("--current-key-file").unwrap_or_else(|| die("--current-key-file <path> is required"));
        let raw = std::fs::read(&path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
        Key::from_bytes(&parse_secret_bytes(&raw).unwrap_or_else(|e| die(&e)))
    };
    let new_pk: [u8; 33] = if let Some(path) = opt("--new-key-file") {
        let raw = std::fs::read(&path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
        Key::from_bytes(&parse_secret_bytes(&raw).unwrap_or_else(|e| die(&e))).pk.inner.serialize()
    } else if let Some(h) = opt("--new-pubkey") {
        hex::decode(h.trim())
            .ok()
            .and_then(|b| b.as_slice().try_into().ok())
            .unwrap_or_else(|| die("--new-pubkey must be 33 bytes (66 hex chars, compressed)"))
    } else {
        die("give the new key: --new-key-file <path> or --new-pubkey <hex>")
    };
    if !zcrypt_core::spv::reserve_pk_ok(&new_pk) {
        die("new pubkey is not a valid compressed secp256k1 point");
    }
    let old_pk = current.pk.inner.serialize();
    if old_pk == new_pk {
        die("new key must differ from the current key");
    }

    let zc = Zcrypt::new(&std::env::var("ZC_URL").unwrap_or_else(|_| "http://localhost:36657".to_string()));
    let asset: u64 = match opt("--asset") {
        Some(a) => a.trim().parse().unwrap_or_else(|_| die("--asset must be a number")),
        None => swap::ensure_zbtc_registered(&zc).unwrap_or_else(|e| die(&e)),
    };
    let chain_id = zc.query("/chain_id").unwrap_or_else(|e| die(&format!("/chain_id: {e}")));
    let chain_id = chain_id.trim().as_bytes().to_vec();
    // Refuse to sign against a stale view: the chain must currently pin exactly our key.
    match swap::chain_reserve_pk(&zc, asset) {
        Ok(Some(pk)) if pk == old_pk => {}
        Ok(Some(pk)) => die(&format!(
            "the chain's current reserve pubkey for asset {asset} is {}, not this key ({}); \
             sign with the key the chain pins",
            hex::encode(pk),
            hex::encode(old_pk)
        )),
        Ok(None) => die(&format!("asset {asset} publishes no reserve pubkey (not SPV-gated, or the node predates rotation)")),
        Err(e) => die(&e),
    }
    let epoch = swap::chain_authority_epoch(&zc, asset).unwrap_or_else(|e| die(&e));
    let sig = zcrypt_core::spv::sign_reserve_rotation(&current.sk, &chain_id, asset, epoch, &old_pk, &new_pk);
    let tx = swap::rotate_reserve_tx(asset, &old_pk, &new_pk, &sig);
    eprintln!(
        "rotate_reserve: asset {asset}, epoch {epoch}: {} -> {}",
        hex::encode(old_pk),
        hex::encode(new_pk)
    );
    if dry_run {
        println!("{}", hex::encode(&tx));
        return;
    }
    match zc.broadcast(&tx) {
        Ok(r) => {
            println!("{r}");
            eprintln!(
                "rotate_reserve: done. Keep the OLD key in ZCRYPT_RESERVE_PREV_KEY_FILES on the watcher until \
                 every deposit/redeem that names it is settled; point ZCRYPT_RESERVE_KEY_FILE at the NEW key."
            );
        }
        Err(e) => die(&format!("broadcast: {e}")),
    }
}
