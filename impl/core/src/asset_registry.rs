//! Consensus registry of shielded-asset tickers (first-mint-wins).
//!
//! Each registered ticker (e.g. `zBTC`) maps to a deterministic non-zero `u64`
//! **asset id** — the same id the shield circuit binds into coin commitments
//! ([`zcrypt_shield::commit_asset`]). The first registration of a ticker wins; a
//! duplicate ticker (or the astronomically-rare id collision) is rejected. The
//! registry root is folded into the app_hash, so every node agrees on which
//! ticker owns which id — no one can forge, hijack, or double-register a ticker.
//!
//! Native ZCRYPT is asset 0 and is never registered (it is implicit).

use std::collections::BTreeMap;

use crate::hash::{h, Hash};

/// Native ZCRYPT — asset id 0, used for fees, never registered here.
pub const NATIVE_ASSET: u64 = 0;

/// zBTC is the canonical Bitcoin-pegged shielded asset, and its parameters are
/// **protocol-pinned** — fixed here, NOT chosen by whoever sends the register
/// transaction. In production zBTC is registered by a consensus `register_tx` (any
/// party can send it, first-mint-wins), so without this pin someone could register
/// `zBTC` with the wrong decimals or a supply ceiling above Bitcoin's own 21M — a cap
/// that large could only ever be unbacked. Enforced in [`AssetRegistry::register`].
pub const ZBTC_TICKER: &str = "zBTC";
/// zBTC tracks Bitcoin: 8 decimals (1 zBTC = 100,000,000 base units).
pub const ZBTC_DECIMALS: u8 = 8;
/// Hard, protocol-level ceiling on zBTC: 21,000,000 whole coins in base units. Bitcoin
/// can never exceed 21M — and with lost coins never even circulates that much — so any
/// larger zBTC supply is definitionally unbacked. This is a consensus constant, not a
/// registration argument, so it cannot drift or be raised.
pub const ZBTC_MAX_SUPPLY: u64 = 21_000_000 * 100_000_000;

/// Canonical form of a ticker for identity + uniqueness: **case-insensitive**, so
/// `zBTC`, `ZBTC`, and `zbtc` are the SAME asset. Display casing (the first
/// registrant's spelling) is preserved separately in [`AssetMeta::ticker`].
pub fn canonical_ticker(t: &str) -> String {
    t.to_ascii_uppercase()
}

/// Deterministic non-zero asset id for a ticker (identical on every node and, by
/// construction, every chain — so `zBTC` means the same asset everywhere). Derived
/// from the case-insensitive canonical form, so `zBTC` and `ZBTC` share one id.
pub fn asset_id_for(ticker: &str) -> u64 {
    let d = h(b"ZC-ASSET", &[canonical_ticker(ticker).as_bytes()]);
    let id = u64::from_le_bytes(d[0..8].try_into().unwrap());
    if id == NATIVE_ASSET {
        1
    } else {
        id
    }
}

/// A ticker is 2..=10 ASCII alphanumerics beginning with a letter (so `zBTC`,
/// `USDC`, `zETH` are valid). Identity is case-insensitive (see [`canonical_ticker`]).
pub fn valid_ticker(t: &str) -> bool {
    let n = t.len();
    n >= 2
        && n <= 10
        && t.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && t.chars().all(|c| c.is_ascii_alphanumeric())
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AssetMeta {
    pub asset_id: u64,
    pub ticker: String,
    pub decimals: u8,
    /// Optional controlled-mint authority (a hash of the minter's key). `None`
    /// means the asset is only minted by a protocol path (e.g. the BTC→zBTC
    /// bridge), never by a discretionary authority.
    pub authority: Option<Hash>,
    /// Total units of this asset minted so far (supply tracking).
    pub minted: u64,
    /// Monotonic authority-rotation counter. Starts at 0 and increments on every
    /// [`AssetRegistry::rotate_authority`]. Bound into the rotation message so a rotation
    /// signature is single-use — it makes a captured rotation unreplayable, even if the
    /// authority is later rotated back to a previous key set.
    #[serde(default)]
    pub authority_epoch: u64,
    /// Hard, consensus-enforced ceiling on `minted`. Declared once at registration
    /// and folded into the registry root, so every node agrees on it and it can
    /// never be raised. This is the H2 bound: a capability holder still mints
    /// discretionarily, but only up to a fixed, publicly-auditable cap — turning an
    /// UNLIMITED counterfeiting authority into a bounded one. (Full 1:1 backing
    /// still requires the BTC SPV verifier; this caps the blast radius until then.)
    pub max_supply: u64,
}

#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AssetRegistry {
    by_ticker: BTreeMap<String, u64>,
    by_id: BTreeMap<u64, AssetMeta>,
}

impl AssetRegistry {
    /// Register `ticker` (first-mint-wins). Returns its deterministic asset id.
    /// Rejects an invalid or already-registered ticker.
    pub fn register(
        &mut self,
        ticker: &str,
        decimals: u8,
        authority: Option<Hash>,
        max_supply: u64,
    ) -> Result<u64, String> {
        if !valid_ticker(ticker) {
            return Err(format!("invalid ticker '{ticker}' (2-10 alphanumerics, leading letter)"));
        }
        if max_supply == 0 {
            return Err(format!("asset '{ticker}' must declare a non-zero max supply"));
        }
        let canon = canonical_ticker(ticker);
        // zBTC's parameters are protocol-pinned (see the constants above): the canonical
        // BTC-pegged asset MUST use Bitcoin's 8 decimals and its 21M ceiling. This is the
        // single chokepoint every registration path funnels through, so no register_tx —
        // whoever sends it — can mint a `zBTC` with a looser cap that could go unbacked.
        if canon == canonical_ticker(ZBTC_TICKER) {
            if decimals != ZBTC_DECIMALS || max_supply != ZBTC_MAX_SUPPLY {
                return Err(format!(
                    "'{ZBTC_TICKER}' is protocol-pinned to {ZBTC_DECIMALS} decimals and a hard \
                     {ZBTC_MAX_SUPPLY} base-unit cap (21M) — it cannot be registered with other values"
                ));
            }
            // zBTC must have a mint authority (in production: SPV sentinel). Without this,
            // discretionary M-of-N minting of the peg ticker is possible at the core layer.
            if authority.is_none() {
                return Err(format!(
                    "'{ZBTC_TICKER}' requires a mint authority (SPV reserve commitment); \
                     discretionary minting of the Bitcoin peg is forbidden"
                ));
            }
        }
        if self.by_ticker.contains_key(&canon) {
            return Err(format!("ticker '{ticker}' is already registered"));
        }
        let id = asset_id_for(ticker);
        if id == NATIVE_ASSET || self.by_id.contains_key(&id) {
            return Err(format!("asset id collision for '{ticker}' — pick another ticker"));
        }
        // Uniqueness is keyed on the canonical (case-insensitive) form; the display
        // ticker keeps the first registrant's original spelling.
        self.by_ticker.insert(canon, id);
        self.by_id.insert(
            id,
            AssetMeta {
                asset_id: id,
                ticker: ticker.to_string(),
                decimals,
                authority,
                minted: 0,
                max_supply,
                authority_epoch: 0,
            },
        );
        Ok(id)
    }

    pub fn asset_of(&self, ticker: &str) -> Option<u64> {
        self.by_ticker.get(&canonical_ticker(ticker)).copied()
    }
    pub fn meta(&self, asset_id: u64) -> Option<&AssetMeta> {
        self.by_id.get(&asset_id)
    }
    pub fn is_registered(&self, asset_id: u64) -> bool {
        asset_id == NATIVE_ASSET || self.by_id.contains_key(&asset_id)
    }
    pub fn ticker_taken(&self, ticker: &str) -> bool {
        self.by_ticker.contains_key(&canonical_ticker(ticker))
    }
    pub fn count(&self) -> usize {
        self.by_id.len()
    }
    pub fn list(&self) -> Vec<&AssetMeta> {
        self.by_id.values().collect()
    }

    /// Record `amount` newly minted of `asset_id` (bridge / controlled mint).
    /// Rejects an unregistered asset, or any mint that would push `minted` past the
    /// asset's declared `max_supply` (H2: the hard supply ceiling). This is the
    /// single point where supply increases, so enforcing here makes
    /// `minted <= max_supply` an inviolable consensus invariant.
    pub fn record_mint(&mut self, asset_id: u64, amount: u64) -> Result<(), String> {
        let m = self.by_id.get_mut(&asset_id).ok_or("asset not registered")?;
        let next = m.minted.checked_add(amount).ok_or("mint supply overflow")?;
        if next > m.max_supply {
            return Err(format!(
                "mint of {amount} exceeds '{}' max supply {} (minted {})",
                m.ticker, m.max_supply, m.minted
            ));
        }
        m.minted = next;
        Ok(())
    }

    /// Rotate an asset's mint authority to `new_commitment`, advancing its epoch. The caller
    /// (the node) must have ALREADY verified a threshold signature from the CURRENT authority
    /// over `mint_auth::rotate_message(asset, current_epoch, new_commitment)` — this method is
    /// the state mutation only. This is how a treasury migrates from a single-master key set
    /// to distributed custody, or replaces a compromised/retired signer, with no chain reset.
    pub fn rotate_authority(&mut self, asset_id: u64, new_commitment: Hash) -> Result<(), String> {
        let m = self.by_id.get_mut(&asset_id).ok_or("asset not registered")?;
        if m.authority.is_none() {
            return Err(format!("asset '{}' has no mint authority to rotate", m.ticker));
        }
        m.authority = Some(new_commitment);
        m.authority_epoch += 1;
        Ok(())
    }

    /// The current authority-rotation epoch for `asset_id` (0 if unregistered / never rotated).
    pub fn authority_epoch(&self, asset_id: u64) -> u64 {
        self.by_id.get(&asset_id).map(|m| m.authority_epoch).unwrap_or(0)
    }

    /// The declared hard supply cap for `asset_id` (0 if unregistered).
    pub fn max_supply(&self, asset_id: u64) -> u64 {
        self.by_id.get(&asset_id).map(|m| m.max_supply).unwrap_or(0)
    }
    /// Remaining mintable headroom before the cap (0 if unregistered / at cap).
    pub fn mint_headroom(&self, asset_id: u64) -> u64 {
        self.by_id
            .get(&asset_id)
            .map(|m| m.max_supply.saturating_sub(m.minted))
            .unwrap_or(0)
    }
    pub fn minted(&self, asset_id: u64) -> u64 {
        self.by_id.get(&asset_id).map(|m| m.minted).unwrap_or(0)
    }

    /// Record `amount` of `asset_id` burned (e.g. a zBTC→BTC redemption). Reduces
    /// the tracked supply. Rejects an unregistered asset.
    pub fn record_burn(&mut self, asset_id: u64, amount: u64) -> Result<(), String> {
        let m = self.by_id.get_mut(&asset_id).ok_or("asset not registered")?;
        m.minted = m.minted.saturating_sub(amount);
        Ok(())
    }

    /// A digest of the whole registry, folded into the app_hash so the ticker↔id
    /// mapping and per-asset supply are consensus-agreed.
    pub fn root(&self) -> Hash {
        let mut buf = Vec::new();
        for (id, m) in &self.by_id {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&(m.ticker.len() as u32).to_le_bytes());
            buf.extend_from_slice(m.ticker.as_bytes());
            buf.push(m.decimals);
            match &m.authority {
                Some(a) => {
                    buf.push(1);
                    buf.extend_from_slice(a);
                }
                None => buf.push(0),
            }
            buf.extend_from_slice(&m.minted.to_le_bytes());
            buf.extend_from_slice(&m.max_supply.to_le_bytes());
            buf.extend_from_slice(&m.authority_epoch.to_le_bytes());
        }
        h(b"ZC-ASSETS", &[&buf])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: u64 = 21_000_000 * 100_000_000;

    #[test]
    fn first_mint_wins() {
        let mut r = AssetRegistry::default();
        let auth = Some([7u8; 32]);
        let id = r.register("zBTC", 8, auth, CAP).unwrap();
        assert_eq!(id, asset_id_for("zBTC"));
        assert_ne!(id, NATIVE_ASSET);
        // second registration of the same ticker is rejected
        assert!(r.register("zBTC", 8, auth, CAP).is_err());
        // CASE-INSENSITIVE: a different-cased spelling is the same asset -> rejected,
        // and resolves to the same id.
        assert!(r.register("ZBTC", 8, auth, CAP).is_err());
        assert!(r.register("zbtc", 8, auth, CAP).is_err());
        // zBTC without authority is forbidden
        let mut r2 = AssetRegistry::default();
        assert!(r2.register("zBTC", 8, None, CAP).is_err());
        assert_eq!(r.asset_of("ZBTC"), Some(id));
        assert_eq!(r.asset_of("zbtc"), Some(id));
        assert!(r.ticker_taken("Zbtc"));
        // a different ticker gets a different id
        let id2 = r.register("USDC", 6, None, CAP).unwrap();
        assert_ne!(id, id2);
        assert_eq!(r.count(), 2);
        assert_eq!(r.asset_of("zBTC"), Some(id));
        assert_eq!(r.meta(id).unwrap().decimals, 8);
    }

    #[test]
    fn deterministic_id() {
        // Same ticker -> same id, regardless of registry state / order.
        assert_eq!(asset_id_for("zBTC"), asset_id_for("zBTC"));
        assert_ne!(asset_id_for("zBTC"), asset_id_for("zETH"));
        // Case-insensitive: all spellings share one id.
        assert_eq!(asset_id_for("zBTC"), asset_id_for("ZBTC"));
        assert_eq!(asset_id_for("zBTC"), asset_id_for("zbtc"));
    }

    #[test]
    fn ticker_validation() {
        assert!(valid_ticker("zBTC"));
        assert!(valid_ticker("USDC"));
        assert!(valid_ticker("zETH2"));
        assert!(!valid_ticker("z")); // too short
        assert!(!valid_ticker("TOOLONGTICKER")); // too long
        assert!(!valid_ticker("1BTC")); // must start with a letter
        assert!(!valid_ticker("zB-TC")); // no punctuation
        assert!(!valid_ticker("")); // empty
    }

    #[test]
    fn mint_tracks_supply_and_root_changes() {
        let mut r = AssetRegistry::default();
        let id = r.register("zBTC", 8, Some([1u8; 32]), CAP).unwrap();
        let root0 = r.root();
        r.record_mint(id, 100_000).unwrap();
        assert_eq!(r.minted(id), 100_000);
        assert_ne!(r.root(), root0, "supply change must move the registry root");
        // minting an unregistered asset is rejected
        assert!(r.record_mint(99, 1).is_err());
    }

    #[test]
    fn mint_cap_is_enforced() {
        // H2 regression: a capability holder cannot mint past the declared cap. Uses a
        // non-pinned ticker (zBTC's cap is now protocol-fixed at 21M, see the pin test).
        let mut r = AssetRegistry::default();
        let id = r.register("GOLD", 8, Some([9u8; 32]), 1_000).unwrap();
        r.record_mint(id, 600).unwrap();
        assert!(r.record_mint(id, 500).is_err(), "600+500 > 1000 cap must be rejected");
        assert_eq!(r.minted(id), 600, "a rejected mint must not change supply");
        assert_eq!(r.mint_headroom(id), 400);
        r.record_mint(id, 400).unwrap(); // exactly to the cap is allowed
        assert_eq!(r.mint_headroom(id), 0);
        assert!(r.record_mint(id, 1).is_err(), "no minting past a full cap");
        // a zero-cap asset cannot even be registered
        assert!(r.register("USDC", 6, None, 0).is_err());
    }

    #[test]
    fn zbtc_params_are_protocol_pinned() {
        // The 21M ceiling matches Bitcoin exactly.
        assert_eq!(ZBTC_MAX_SUPPLY, 21_000_000 * 100_000_000);
        // zBTC registered with the pinned params succeeds...
        let mut r = AssetRegistry::default();
        let id = r.register(ZBTC_TICKER, ZBTC_DECIMALS, Some([9u8; 32]), ZBTC_MAX_SUPPLY).unwrap();
        assert_eq!(id, asset_id_for(ZBTC_TICKER));
        // ...but a looser cap is rejected, in ANY casing (identity is case-insensitive),
        assert!(AssetRegistry::default()
            .register("ZBTC", 8, None, ZBTC_MAX_SUPPLY * 2)
            .is_err());
        assert!(AssetRegistry::default()
            .register("zbtc", 8, None, u64::MAX)
            .is_err());
        // ...and wrong decimals are rejected,
        assert!(AssetRegistry::default()
            .register("zBTC", 6, None, ZBTC_MAX_SUPPLY)
            .is_err());
        // ...while an unrelated ticker is unconstrained.
        assert!(AssetRegistry::default().register("GOLD", 8, None, u64::MAX).is_ok());
    }

    #[test]
    fn authority_rotation_advances_epoch_and_root() {
        let mut r = AssetRegistry::default();
        let id = r.register("GOLD", 8, Some([1u8; 32]), CAP).unwrap();
        assert_eq!(r.authority_epoch(id), 0);
        let root0 = r.root();

        // Rotate to a new commitment: authority + epoch both advance, root moves.
        r.rotate_authority(id, [2u8; 32]).unwrap();
        assert_eq!(r.meta(id).unwrap().authority, Some([2u8; 32]));
        assert_eq!(r.authority_epoch(id), 1);
        assert_ne!(r.root(), root0, "a rotation must move the registry root");

        // A second rotation keeps advancing the epoch (so each rotation signs a unique msg).
        r.rotate_authority(id, [3u8; 32]).unwrap();
        assert_eq!(r.authority_epoch(id), 2);

        // Rotating an unregistered asset, or one with no authority, is rejected.
        assert!(r.rotate_authority(999, [4u8; 32]).is_err());
        let noauth = r.register("FREE", 8, None, CAP).unwrap();
        assert!(r.rotate_authority(noauth, [5u8; 32]).is_err());
    }

    #[test]
    fn deterministic_root() {
        let build = || {
            let mut r = AssetRegistry::default();
            r.register("zBTC", 8, Some([1u8; 32]), CAP).unwrap();
            r.register("USDC", 6, Some([7u8; 32]), CAP).unwrap();
            r.record_mint(asset_id_for("zBTC"), 42).unwrap();
            r.root()
        };
        assert_eq!(build(), build());
    }
}
