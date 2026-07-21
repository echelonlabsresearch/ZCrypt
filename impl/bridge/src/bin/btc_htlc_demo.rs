//! Proves the Bitcoin-regtest HTLC leg: fund → claim-with-preimage, and
//! fund → refund-after-timeout, against a live bitcoind.

use bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use zcrypt_bridge::{htlc_address, htlc_script, Btc, Key, NETWORK};
use zcrypt_core::nullifier::htlc_hashlock;

fn dest(btc: &Btc) -> bitcoin::Address {
    btc.rpc
        .get_new_address(None, None)
        .unwrap()
        .require_network(NETWORK)
        .unwrap()
}

fn balance(btc: &Btc) -> Amount {
    btc.rpc.get_balance(None, None).unwrap()
}

fn main() {
    let btc = Btc::connect("http://localhost:18443", "zcrypt", "zcrypt", "demo", NETWORK).unwrap();
    println!("bitcoind height: {}", btc.height().unwrap());

    let claim = Key::from_bytes(&[0x11; 32]);
    let refund = Key::from_bytes(&[0x22; 32]);
    let fee = Amount::from_sat(2_000);

    // ---- claim path: preimage before timeout ----
    // Fresh OS-entropy preimage (never a fixed string — the hashlock is public).
    let preimage = zcrypt_bridge::swap::fresh_preimage();
    let hashlock = htlc_hashlock(&preimage);
    let locktime = (btc.height().unwrap() + 100) as u32; // far future -> only claim works
    let script = htlc_script(&hashlock, &claim.pk, &refund.pk, locktime);
    println!("HTLC address: {}", htlc_address(&script, NETWORK));

    let utxo = btc.fund_htlc(&script, Amount::from_btc(1.0).unwrap()).unwrap();
    println!("funded HTLC: {}:{} = {} BTC", utxo.outpoint.txid, utxo.outpoint.vout, utxo.value.to_btc());

    let before = balance(&btc);
    let d = dest(&btc);
    let claim_txid = btc.claim(&utxo, &preimage, &claim, &d, fee).unwrap();
    btc.mine(1).unwrap();
    let after = balance(&btc);
    println!("CLAIM tx {claim_txid} confirmed; wallet +{} BTC", (after - before).to_btc());
    assert!(after > before, "claim did not credit the wallet");
    println!("  -> claim-with-preimage: GREEN");

    // ---- refund path: after timeout, no preimage ----
    let preimage2 = b"unused-refund-preimage";
    let hashlock2 = htlc_hashlock(preimage2);
    let locktime2 = (btc.height().unwrap() + 3) as u32; // near future
    let script2 = htlc_script(&hashlock2, &claim.pk, &refund.pk, locktime2);
    let utxo2 = btc.fund_htlc(&script2, Amount::from_btc(0.5).unwrap()).unwrap();

    // refund before timeout must FAIL
    let d2 = dest(&btc);
    let early = btc.refund(&utxo2, &refund, locktime2, &d2, fee);
    println!("refund before timeout rejected: {}", early.is_err());
    assert!(early.is_err(), "refund should fail before locktime");

    // mine to reach the locktime, then refund succeeds
    btc.mine(5).unwrap();
    let before2 = balance(&btc);
    let refund_txid = btc.refund(&utxo2, &refund, locktime2, &d2, fee).unwrap();
    btc.mine(1).unwrap();
    let after2 = balance(&btc);
    println!("REFUND tx {refund_txid} confirmed; wallet +{} BTC", (after2 - before2).to_btc());
    assert!(after2 > before2, "refund did not credit the wallet");
    println!("  -> refund-after-timeout: GREEN");

    println!("\nBitcoin HTLC leg: GREEN (claim + refund).");
}
