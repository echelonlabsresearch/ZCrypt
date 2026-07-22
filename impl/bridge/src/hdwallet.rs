//! Self-custody HD Bitcoin wallet (BIP-32/39/84), derived from the SAME BIP-39
//! mnemonic as the ZCrypt account, so one seed phrase restores both. This replaces
//! the old model where bitcoind held the BTC keys and the mnemonic didn't back up
//! the Bitcoin at all.
//!
//! Derivation is BIP-84 native segwit (P2WPKH, `bc1…`/`tb1…`):
//!
//! ```text
//!   m / 84' / coin' / 0' / change / index
//!                    └ account 0     │       └ address index
//!                                    └ 0 = receive, 1 = change
//! ```
//!
//! `coin` is 0 on mainnet, 1 on test networks (BIP-44 coin type). The account
//! xpub (`m/84'/coin'/0'`) is what a Blockbook data API takes to return every UTXO
//! across the wallet in one call. Only public data leaves this module for lookups;
//! signing keys never leave the process.
//!
//! Correctness here is money-critical (a wrong address sends BTC into the void), so
//! the derivation is checked against the official BIP-84 test vectors in the tests.

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::{Secp256k1, SignOnly};
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey};
use std::str::FromStr;

/// A BIP-84 hierarchical-deterministic Bitcoin wallet for one account (account 0),
/// scoped to a network. Holds the account-level extended private key; addresses and
/// signing keys are derived on demand.
pub struct HdWallet {
    network: Network,
    account: Xpriv,
    secp: Secp256k1<SignOnly>,
}

/// BIP-44 coin type: 0 = mainnet, 1 = all test networks (testnet/signet/regtest).
fn coin_type(network: Network) -> u32 {
    if network == Network::Bitcoin {
        0
    } else {
        1
    }
}

impl HdWallet {
    /// Derive the wallet from a BIP-39 mnemonic (+ optional passphrase) for `network`.
    /// The mnemonic is the SAME one that backs the ZCrypt account.
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str, network: Network) -> Result<Self, String> {
        let mn = bip39::Mnemonic::parse(mnemonic.trim()).map_err(|e| format!("invalid mnemonic: {e}"))?;
        let seed = mn.to_seed(passphrase); // 64-byte BIP-39 seed
        let master = Xpriv::new_master(network, &seed).map_err(|e| e.to_string())?;
        let secp = Secp256k1::signing_only();
        let path = DerivationPath::from_str(&format!("m/84'/{}'/0'", coin_type(network)))
            .map_err(|e| e.to_string())?;
        let account = master.derive_priv(&secp, &path).map_err(|e| e.to_string())?;
        Ok(Self { network, account, secp })
    }

    /// The account extended PUBLIC key (`m/84'/coin'/0'`) — hand this to Blockbook to
    /// enumerate the wallet's balance and UTXOs. Public: reveals addresses, never keys.
    pub fn account_xpub(&self) -> Xpub {
        Xpub::from_priv(&self.secp, &self.account)
    }

    /// The extended private key for one leaf, `m/84'/coin'/0'/change/index`.
    fn leaf(&self, change: u32, index: u32) -> Result<Xpriv, String> {
        let path = DerivationPath::from_str(&format!("m/{change}/{index}")).map_err(|e| e.to_string())?;
        self.account.derive_priv(&self.secp, &path).map_err(|e| e.to_string())
    }

    /// The P2WPKH address at `change`/`index` (change: 0 = receive, 1 = change).
    pub fn address(&self, change: u32, index: u32) -> Result<Address, String> {
        let xpriv = self.leaf(change, index)?;
        let pk = CompressedPublicKey(xpriv.private_key.public_key(&self.secp));
        Ok(Address::p2wpkh(&pk, self.network))
    }

    /// The `index`-th receiving address (external chain 0).
    pub fn receive_address(&self, index: u32) -> Result<Address, String> {
        self.address(0, index)
    }

    /// The `index`-th change address (internal chain 1).
    pub fn change_address(&self, index: u32) -> Result<Address, String> {
        self.address(1, index)
    }

    /// The WIF/private key for signing an input owned by `change`/`index` — used to
    /// sign funding and HTLC transactions locally. Never leaves the process.
    pub fn signing_key(&self, change: u32, index: u32) -> Result<PrivateKey, String> {
        Ok(self.leaf(change, index)?.to_priv())
    }

    pub fn network(&self) -> Network {
        self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The official BIP-84 test vector mnemonic.
    const MN: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn bip84_mainnet_vectors() {
        let w = HdWallet::from_mnemonic(MN, "", Network::Bitcoin).unwrap();
        // The three canonical BIP-84 spec addresses for this mnemonic (account 0).
        assert_eq!(
            w.receive_address(0).unwrap().to_string(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            w.receive_address(1).unwrap().to_string(),
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
        assert_eq!(
            w.change_address(0).unwrap().to_string(),
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        );
        // Account xpub (m/84'/0'/0'). rust-bitcoin emits the standard `xpub…` version
        // prefix; BIP-84 tooling shows the SLIP-132 `zpub…` prefix — same key, different
        // version bytes. We assert the standard encoding this crate produces.
        assert_eq!(
            w.account_xpub().to_string(),
            "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
        );
    }

    #[test]
    fn testnet_uses_coin_type_1_and_tb_addresses() {
        let w = HdWallet::from_mnemonic(MN, "", Network::Signet).unwrap();
        let a = w.receive_address(0).unwrap().to_string();
        assert!(a.starts_with("tb1q"), "signet uses tb1 P2WPKH: {a}");
        // Deterministic: same mnemonic + network → same address every time.
        let w2 = HdWallet::from_mnemonic(MN, "", Network::Signet).unwrap();
        assert_eq!(a, w2.receive_address(0).unwrap().to_string());
    }

    #[test]
    fn signing_key_matches_its_address() {
        let w = HdWallet::from_mnemonic(MN, "", Network::Bitcoin).unwrap();
        let secp = Secp256k1::new();
        let sk = w.signing_key(0, 0).unwrap();
        let pk = CompressedPublicKey(sk.public_key(&secp).inner);
        assert_eq!(
            Address::p2wpkh(&pk, Network::Bitcoin).to_string(),
            w.receive_address(0).unwrap().to_string()
        );
    }
}
