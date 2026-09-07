//! Trustless staking + block-reward distribution.
//!
//! Validators **bond** ZCRYPT (min [`MIN_STAKE`]) and register a reward address.
//! Over each epoch the node records who **participated** in consensus (signed
//! blocks). At the epoch boundary it distributes the scheduled block reward
//! ([`crate::emission`]) split by **stake × participation**, capped at the
//! remaining mineable budget.
//!
//! Everything here is a deterministic function of consensus-visible inputs
//! (stakes, signatures, height), so every node computes identical results — the
//! staking state is folded into the app_hash and any deviation is rejected by
//! BFT. A validator cannot mint extra: the epoch reward is fixed by height and
//! the split comes from the verifiable signer set.

use std::collections::{BTreeMap, BTreeSet};

use crate::emission;
use crate::hash::Hash;

/// Minimum bond to be a validator: 10,000 ZCRYPT.
pub const MIN_STAKE: u64 = 10_000 * emission::ATOMIC;

/// Slashing penalty for provable equivocation (double-signing): 5% of the offender's
/// stake, permanently burned. `SLASH_NUM / SLASH_DEN`. Integer math ⇒ deterministic.
/// Slashing hits a validator's own stake **and** every coin delegated to it — delegators
/// share the risk of the validator they back, which is what makes delegated stake real
/// security rather than free voting power.
pub const SLASH_NUM: u64 = 5;
pub const SLASH_DEN: u64 = 100;

/// Validator commission on the rewards earned by **delegated** stake: the operator keeps
/// `COMMISSION_NUM / COMMISSION_DEN` of a delegator's share as payment for running the
/// node; the rest flows to the delegator. Applied only to the delegated portion — the
/// validator always keeps 100% of the reward on its own self-bonded stake. A fixed
/// protocol rate (per-validator rates are a later refinement). Integer math ⇒ deterministic.
pub const COMMISSION_NUM: u64 = 10;
pub const COMMISSION_DEN: u64 = 100;
/// Commission is now PER-VALIDATOR (basis points, see [`Validator::commission_bps`]); this
/// is the default a validator gets if it does not specify one (the historical 10%). Full
/// scale is 10,000 bps = 100%.
pub const DEFAULT_COMMISSION_BPS: u16 = (COMMISSION_NUM * 10_000 / COMMISSION_DEN) as u16;
pub const MAX_COMMISSION_BPS: u16 = 10_000;

/// Unbonding period: how long a validator's stake stays **locked** after it unbonds
/// before it is released. Measured in seconds of consensus (BFT) block time so it is a
/// true wall-clock delay regardless of block rate. 10 days — long enough that any
/// misbehavior from the validator's active period can still be caught while the stake
/// is frozen (the window slashing will punish through, once slashing exists).
pub const UNBONDING_PERIOD_SECS: u64 = 10 * 24 * 60 * 60; // 10 days

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Validator {
    /// The validator's own bonded (self-)stake.
    pub stake: u64,
    /// Total stake **delegated** to this validator by others. The validator's voting
    /// power is `stake + delegated`; the per-delegator detail lives in
    /// [`Staking::delegations`]. Folded into [`Staking::root`].
    #[serde(default)]
    pub delegated: u64,
    pub reward_address: Hash,
    /// The full CometBFT consensus public key (ed25519, 32 bytes in production). The
    /// map is keyed by the shorter CometBFT *address* (so reward participation matches
    /// `decided_last_commit`), but the full key is needed to build the block-producing
    /// validator-set updates CometBFT applies. Folded into [`Staking::root`], so the
    /// exact validator → voting-power mapping is part of the consensus app_hash.
    #[serde(default)]
    pub consensus_pubkey: Vec<u8>,
    /// The validator's chosen COMMISSION on delegators' rewards, in basis points
    /// (0..=10000 = 0%..100%). The operator keeps this fraction of a delegator's reward
    /// as payment for running the node; the delegator receives the rest. Set by the
    /// validator when it bonds, so validators compete on commission. Folded into
    /// [`Staking::root`] (consensus state). Defaults to [`DEFAULT_COMMISSION_BPS`].
    #[serde(default)]
    pub commission_bps: u16,
}

/// A single delegation: one delegator's stake pledged toward one validator. Keyed in
/// [`Staking::delegations`] by `(validator_id, delegator_id)`. The stake counts toward
/// the validator's voting power and earns the delegator a share of that validator's
/// rewards (net of commission); on undelegation or a slash it unwinds to
/// `reward_address` through the normal unbonding queue.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Delegation {
    pub stake: u64,
    pub reward_address: Hash,
}

/// A validator's stake in the process of unbonding: removed from the active set
/// immediately (it stops producing blocks the moment it unbonds), but the stake stays
/// **locked** until `release_time` — a wall-clock delay of [`UNBONDING_PERIOD_SECS`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Unbonding {
    pub validator_id: Vec<u8>,
    pub stake: u64,
    pub reward_address: Hash,
    /// BFT block-time (unix seconds) at which the stake becomes releasable.
    pub release_time: u64,
}

#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct Staking {
    /// consensus pubkey (opaque bytes) -> validator
    validators: BTreeMap<Vec<u8>, Validator>,
    /// Stakes that have unbonded and are frozen until their `release_time`. Part of the
    /// consensus state (folded into [`Staking::root`]).
    #[serde(default)]
    unbonding: Vec<Unbonding>,
    /// Validators permanently banned for provable misbehavior (equivocation). They are
    /// ejected, cannot re-bond, and are never slashed twice. Consensus state.
    #[serde(default)]
    tombstoned: BTreeSet<Vec<u8>>,
    /// Delegations keyed by `(validator_id, delegator_id)`. Each delegator's stake is
    /// pledged toward a validator, boosts that validator's voting power, earns a share
    /// of its rewards, and shares its slashing risk. Consensus state (folded into
    /// [`Staking::root`]); the per-validator total is mirrored in [`Validator::delegated`].
    #[serde(default)]
    delegations: BTreeMap<(Vec<u8>, Vec<u8>), Delegation>,
    /// blocks signed this epoch, per validator
    participation: BTreeMap<Vec<u8>, u64>,
    /// reward address -> *unclaimed* accrued balance (atomic units). Debited when
    /// a validator claims rewards into spendable coinbase coins.
    rewards: BTreeMap<Hash, u64>,
    /// reward address -> **lifetime** block rewards ever credited (atomic units).
    /// Never debited: claims move value out of `rewards` but leave this untouched,
    /// and returned unbonded stake (which flows through `rewards`) is NOT counted —
    /// this is pure earnings, the number an explorer shows as "rewards accumulated".
    /// Consensus state (folded into [`Staking::root`]).
    #[serde(default)]
    earned: BTreeMap<Hash, u64>,
    /// reward address -> next coinbase coin index (monotonic, so claimed-coin
    /// commitments never collide across repeated claims).
    claim_index: BTreeMap<Hash, u64>,
    /// total rewards claimed into coins so far (moved out of `rewards` into the
    /// note tree). For accounting only; issuance is `foundation + emitted`.
    claimed: u64,
    /// sum of all stakes
    total_staked: u64,
    /// total block rewards emitted so far (for the mineable cap)
    emitted: u64,
    foundation_minted: bool,
    /// The foundation's reward address, set once at genesis. Foundation claims are
    /// gated by the on-chain vesting schedule ([`emission::foundation_vested`])
    /// rather than a pre-credited balance. Consensus state.
    #[serde(default)]
    foundation_addr: Hash,
    /// Foundation value claimed into coins so far (≤ vested(height) always).
    #[serde(default)]
    foundation_claimed: u64,
    /// Bridge fees accrued but not yet distributed, per asset id. Filled by
    /// [`Staking::accrue_bridge_fee`] as zBTC (and other bridged assets) mints mature,
    /// drained by [`Staking::distribute_fees`] at each epoch into `fee_rewards`.
    #[serde(default)]
    fee_pool: BTreeMap<u64, u64>,
    /// (reward address, asset id) -> claimable bridge-fee balance. The staker analogue of
    /// `rewards`, but denominated in the bridged asset rather than ZCRYPT: this is the
    /// real, asset-denominated yield that ties staking demand to bridge volume.
    #[serde(default)]
    fee_rewards: BTreeMap<(Hash, u64), u64>,
    /// (reward address, asset id) -> next claimed-coin index, so repeated fee claims
    /// never collide (mirrors `claim_index` for ZCRYPT rewards).
    #[serde(default)]
    fee_claim_index: BTreeMap<(Hash, u64), u64>,
    /// (reward address, asset id) -> **lifetime** bridge fees ever credited (the
    /// fee analogue of `earned`: never debited by claims). Consensus state.
    #[serde(default)]
    fee_earned: BTreeMap<(Hash, u64), u64>,
    /// Monotonic per-signer-key nonce for signature-only staking txs (UNBOND / UNDELEGATE).
    /// Those txs are NOT coin-backed, so without a nonce a captured signature could be
    /// replayed to force-eject a validator/delegator that later re-bonded. The signer includes
    /// the current nonce in the signed message; consensus accepts it only if it equals the
    /// stored value, then increments — so every such tx is single-use. Keyed by the 32-byte
    /// ed25519 signer pubkey. (BOND/DELEGATE need no nonce: their pledged-coin nullifier
    /// already makes them single-use.) Consensus state (folded into [`Staking::root`]).
    #[serde(default)]
    auth_nonce: BTreeMap<[u8; 32], u64>,
}

impl Staking {
    /// Bond (or re-bond) a validator with `stake` and a reward address. `validator_id`
    /// is the reward-matching identity (the CometBFT address in production — what
    /// appears in `decided_last_commit`); `consensus_pubkey` is the full ed25519 key
    /// used to build the block-producing validator-set update. Rejects a stake below
    /// the minimum.
    pub fn bond(
        &mut self,
        validator_id: Vec<u8>,
        consensus_pubkey: Vec<u8>,
        stake: u64,
        reward_address: Hash,
        commission_bps: u16,
    ) -> Result<(), String> {
        if commission_bps > MAX_COMMISSION_BPS {
            return Err(format!("commission {commission_bps} bps exceeds 100% ({MAX_COMMISSION_BPS} bps)"));
        }
        if self.tombstoned.contains(&validator_id) {
            return Err("validator is tombstoned (slashed for misbehavior) and cannot re-bond".to_string());
        }
        if stake < MIN_STAKE {
            return Err(format!(
                "stake {stake} is below the minimum {MIN_STAKE} ({} ZCRYPT)",
                MIN_STAKE / emission::ATOMIC
            ));
        }
        // A stake can never exceed the total supply — beyond that it is a
        // self-declared fiction whose only effect is overflowing `total_staked`
        // (M5: an unchecked `+=` panics in a debug build → chain halt, or wraps in
        // release → corrupt reward weighting). Reject it and use checked arithmetic.
        if stake > emission::TOTAL_SUPPLY {
            return Err(format!("stake {stake} exceeds total supply"));
        }
        let prev = self.validators.get(&validator_id).map(|v| v.stake).unwrap_or(0);
        // Re-bonding overwrites the Validator record, so carry its accumulated delegated
        // total across (delegators are unaffected by the operator changing its self-bond).
        let delegated = self.validators.get(&validator_id).map(|v| v.delegated).unwrap_or(0);
        let new_total = self
            .total_staked
            .checked_sub(prev)
            .and_then(|t| t.checked_add(stake))
            .ok_or("stake accounting overflow")?;
        self.total_staked = new_total;
        self.validators
            .insert(validator_id, Validator { stake, delegated, reward_address, consensus_pubkey, commission_bps });
        Ok(())
    }

    /// Unbond a validator; returns the released stake.
    /// Begin unbonding a validator at block time `now` (unix seconds). It leaves the
    /// active set immediately (stops earning + is dropped from the block-producing set),
    /// but its stake is **locked in the unbonding queue** until `now + UNBONDING_PERIOD`.
    /// Returns the `release_time` at which the stake becomes releasable.
    pub fn unbond(&mut self, pubkey: &[u8], now: u64) -> Result<u64, String> {
        let v = self.validators.remove(pubkey).ok_or("not a bonded validator")?;
        self.total_staked -= v.stake;
        self.participation.remove(pubkey);
        let release_time = now.saturating_add(UNBONDING_PERIOD_SECS);
        // Unbonding is gasless (a staking action) — the full stake returns after the wait.
        self.unbonding.push(Unbonding {
            validator_id: pubkey.to_vec(),
            stake: v.stake,
            reward_address: v.reward_address,
            release_time,
        });
        // Cascade: a validator leaving the set unwinds every delegation to it — each
        // delegator's stake moves into the unbonding queue and returns to them after the
        // normal wait (they backed a validator that is now gone).
        let keys: Vec<(Vec<u8>, Vec<u8>)> = self
            .delegations
            .keys()
            .filter(|(vid, _)| vid == pubkey)
            .cloned()
            .collect();
        for key in keys {
            let d = self.delegations.remove(&key).expect("key just enumerated");
            self.total_staked -= d.stake;
            self.unbonding.push(Unbonding {
                validator_id: pubkey.to_vec(),
                stake: d.stake,
                reward_address: d.reward_address,
                release_time,
            });
        }
        Ok(release_time)
    }

    /// **Delegate** `stake` toward an existing bonded validator on behalf of a delegator
    /// (`delegator_id`, an ed25519-key-derived identity), returning any accrued stake +
    /// rewards to `reward_address`. Increases the validator's voting power immediately and
    /// entitles the delegator to a share of its rewards (net of [`COMMISSION_NUM`]). The
    /// target must be a live, non-tombstoned validator. Adds to an existing delegation
    /// from the same delegator. Coin-backed at the node layer (the stake is a real burned
    /// pledge), so this only touches the ledger.
    pub fn delegate(
        &mut self,
        validator_id: Vec<u8>,
        delegator_id: Vec<u8>,
        stake: u64,
        reward_address: Hash,
    ) -> Result<(), String> {
        if stake == 0 {
            return Err("delegation must be a positive stake".to_string());
        }
        if stake > emission::TOTAL_SUPPLY {
            return Err(format!("delegation {stake} exceeds total supply"));
        }
        if self.tombstoned.contains(&validator_id) {
            return Err("cannot delegate to a tombstoned validator".to_string());
        }
        // The target must already be a bonded validator (you cannot delegate to a key that
        // is not producing blocks — that stake would secure nothing).
        if !self.validators.contains_key(&validator_id) {
            return Err("delegation target is not a bonded validator".to_string());
        }
        self.total_staked = self
            .total_staked
            .checked_add(stake)
            .ok_or("stake accounting overflow")?;
        let v = self.validators.get_mut(&validator_id).expect("checked above");
        v.delegated = v.delegated.checked_add(stake).ok_or("delegation overflow")?;
        let e = self
            .delegations
            .entry((validator_id, delegator_id))
            .or_insert(Delegation { stake: 0, reward_address });
        e.stake = e.stake.checked_add(stake).ok_or("delegation overflow")?;
        e.reward_address = reward_address;
        Ok(())
    }

    /// **Undelegate** a delegator's entire delegation from `validator_id` at block time
    /// `now`. The stake leaves the validator's voting power immediately but is **locked in
    /// the unbonding queue** for [`UNBONDING_PERIOD_SECS`] (the same delay validators
    /// serve — so a delegator cannot dodge a slash by undelegating the instant their
    /// validator misbehaves), then returns to the delegation's reward address as a
    /// claimable balance. Returns the `release_time`.
    pub fn undelegate(&mut self, validator_id: &[u8], delegator_id: &[u8], now: u64) -> Result<u64, String> {
        let key = (validator_id.to_vec(), delegator_id.to_vec());
        let d = self.delegations.remove(&key).ok_or("no such delegation")?;
        self.total_staked -= d.stake;
        if let Some(v) = self.validators.get_mut(validator_id) {
            v.delegated -= d.stake;
        }
        let release_time = now.saturating_add(UNBONDING_PERIOD_SECS);
        // Undelegation is gasless (a staking action) — the full stake returns after the wait.
        self.unbonding.push(Unbonding {
            validator_id: validator_id.to_vec(),
            stake: d.stake,
            reward_address: d.reward_address,
            release_time,
        });
        Ok(release_time)
    }

    /// The stake `delegator_id` currently has delegated to `validator_id` (0 if none).
    pub fn delegation_of(&self, validator_id: &[u8], delegator_id: &[u8]) -> u64 {
        self.delegations
            .get(&(validator_id.to_vec(), delegator_id.to_vec()))
            .map(|d| d.stake)
            .unwrap_or(0)
    }

    /// All delegations to `validator_id` as `(delegator_id, stake, reward_address)`.
    pub fn delegations_of(&self, validator_id: &[u8]) -> Vec<(Vec<u8>, u64, Hash)> {
        self.delegations
            .iter()
            .filter(|((vid, _), _)| vid == validator_id)
            .map(|((_, did), d)| (did.clone(), d.stake, d.reward_address))
            .collect()
    }

    /// Total stake delegated to `validator_id` (mirrors [`Validator::delegated`]).
    pub fn delegated_to(&self, validator_id: &[u8]) -> u64 {
        self.validators.get(validator_id).map(|v| v.delegated).unwrap_or(0)
    }

    /// Release every unbonding stake whose `release_time` has passed at block time
    /// `now`, **crediting the freed stake back to its reward address as a claimable
    /// balance** — the validator withdraws it into a spendable coin via the normal
    /// `CLAIM` flow, exactly like a block reward. This is the return leg of coin-backed
    /// staking: the value the `BOND` burned out of the shielded pool comes back here.
    /// Deterministic (BFT time + committed queue), so every node releases the same
    /// entries at the same block. Returns the total stake released this call.
    pub fn release_matured_unbonding(&mut self, now: u64) -> u64 {
        let mut released = 0u64;
        let mut credits: Vec<(Hash, u64)> = Vec::new();
        self.unbonding.retain(|u| {
            if u.release_time <= now {
                released += u.stake;
                credits.push((u.reward_address, u.stake));
                false // drop (released)
            } else {
                true // still locked
            }
        });
        for (addr, amt) in credits {
            // Returned stake is NOT new issuance (it was burned out of circulation on
            // BOND and is merely coming back), so this does not touch `emitted`.
            *self.rewards.entry(addr).or_default() += amt;
        }
        released
    }

    /// **Slash** a validator for provable misbehavior (equivocation / double-signing):
    /// burn `SLASH_NUM/SLASH_DEN` of its stake — permanently destroyed, never returned —
    /// then eject and **tombstone** it (it stops producing blocks and can never re-bond).
    ///
    /// Crucially, this hits BOTH the validator's active stake AND any stake it already
    /// moved into the unbonding queue — the 10-day unbonding period exists precisely so
    /// a validator that misbehaves and then unbonds is still punishable. Idempotent per
    /// validator (the tombstone prevents double-slashing the same offender). `now` is
    /// BFT block time. Deterministic (integer math + committed state). Returns the total
    /// stake burned.
    pub fn slash(&mut self, validator_id: &[u8], now: u64) -> u64 {
        if self.tombstoned.contains(validator_id) {
            return 0; // already punished — never slash twice for the same offender
        }
        let mut burned = 0u64;
        // 1) Stake already unbonding: slash each existing entry's remaining amount.
        for u in self.unbonding.iter_mut().filter(|u| u.validator_id == validator_id) {
            let cut = u.stake * SLASH_NUM / SLASH_DEN;
            burned += cut;
            u.stake -= cut;
        }
        // 2) Active stake: eject, burn the fraction, and unbond the remainder so the
        //    honest 95% still returns to the operator after the normal wait.
        if let Some(v) = self.validators.remove(validator_id) {
            self.total_staked -= v.stake;
            self.participation.remove(validator_id);
            let cut = v.stake * SLASH_NUM / SLASH_DEN;
            burned += cut;
            let remainder = v.stake - cut;
            if remainder > 0 {
                self.unbonding.push(Unbonding {
                    validator_id: validator_id.to_vec(),
                    stake: remainder,
                    reward_address: v.reward_address,
                    release_time: now.saturating_add(UNBONDING_PERIOD_SECS),
                });
            }
        }
        // 3) Active delegations to this validator: each delegator shares the slash — burn
        //    the fraction of their delegation, unbond the remainder back to them. (Stake
        //    they had *already* undelegated is sitting in the queue and was hit by step 1.)
        let keys: Vec<(Vec<u8>, Vec<u8>)> = self
            .delegations
            .keys()
            .filter(|(vid, _)| vid == validator_id)
            .cloned()
            .collect();
        for key in keys {
            let d = self.delegations.remove(&key).expect("key just enumerated");
            self.total_staked -= d.stake;
            let cut = d.stake * SLASH_NUM / SLASH_DEN;
            burned += cut;
            let remainder = d.stake - cut;
            if remainder > 0 {
                self.unbonding.push(Unbonding {
                    validator_id: validator_id.to_vec(),
                    stake: remainder,
                    reward_address: d.reward_address,
                    release_time: now.saturating_add(UNBONDING_PERIOD_SECS),
                });
            }
        }
        self.tombstoned.insert(validator_id.to_vec());
        burned
    }

    /// Whether a validator has been tombstoned (permanently banned for misbehavior).
    pub fn is_tombstoned(&self, validator_id: &[u8]) -> bool {
        self.tombstoned.contains(validator_id)
    }

    /// Total stake currently frozen in the unbonding queue (not active, not yet released).
    pub fn total_unbonding(&self) -> u64 {
        self.unbonding.iter().map(|u| u.stake).sum()
    }

    /// Pending unbonding entries for `validator_id` as `(stake, release_time)`.
    pub fn unbonding_of(&self, validator_id: &[u8]) -> Vec<(u64, u64)> {
        self.unbonding
            .iter()
            .filter(|u| u.validator_id == validator_id)
            .map(|u| (u.stake, u.release_time))
            .collect()
    }

    /// Pending unbonding entries whose stake returns to `reward` — i.e. what a specific
    /// staker (validator OR delegator) can see as THEIR own unbonding schedule: each
    /// `(stake, release_time)`. Keyed by reward address so a delegator can look up its own
    /// unbondings without knowing every validator it delegated to.
    pub fn unbonding_by_reward(&self, reward: &Hash) -> Vec<(u64, u64)> {
        self.unbonding
            .iter()
            .filter(|u| &u.reward_address == reward)
            .map(|u| (u.stake, u.release_time))
            .collect()
    }

    pub fn is_validator(&self, pubkey: &[u8]) -> bool {
        self.validators.contains_key(pubkey)
    }
    pub fn stake_of(&self, pubkey: &[u8]) -> u64 {
        self.validators.get(pubkey).map(|v| v.stake).unwrap_or(0)
    }
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }
    pub fn total_staked(&self) -> u64 {
        self.total_staked
    }
    pub fn emitted(&self) -> u64 {
        self.emitted
    }
    /// Unclaimed reward balance for `addr` (atomic units).
    pub fn reward_balance(&self, addr: &Hash) -> u64 {
        *self.rewards.get(addr).unwrap_or(&0)
    }
    /// **Lifetime** block rewards ever credited to `addr` (atomic units): unaffected
    /// by claims, and excludes returned unbonded stake. The explorer's
    /// "rewards accumulated" number.
    pub fn earned_of(&self, addr: &Hash) -> u64 {
        *self.earned.get(addr).unwrap_or(&0)
    }
    /// Lifetime bridge fees credited to `addr` as `(asset_id, amount)` per asset.
    pub fn fee_earned_of(&self, addr: &Hash) -> Vec<(u64, u64)> {
        self.fee_earned
            .iter()
            .filter(|((a, _), amt)| a == addr && **amt > 0)
            .map(|((_, asset), amt)| (*asset, *amt))
            .collect()
    }
    /// Blocks `validator_id` has signed so far in the **current** epoch (resets to 0
    /// at each epoch boundary when rewards distribute).
    pub fn participation_of(&self, validator_id: &[u8]) -> u64 {
        *self.participation.get(validator_id).unwrap_or(&0)
    }
    /// All bonded validators as `(validator_id, &Validator)` in deterministic
    /// (BTreeMap key) order — the read-only view an explorer or RPC layer uses.
    pub fn validators(&self) -> impl Iterator<Item = (&Vec<u8>, &Validator)> {
        self.validators.iter()
    }
    /// Total value issued as of `height` = the foundation's **vested** amount +
    /// all block rewards distributed. Claim-invariant (claiming moves value from
    /// the ledger into coins, it does not create or destroy any) and monotonic in
    /// height as the vesting schedule unlocks. Never exceeds
    /// [`emission::TOTAL_SUPPLY`].
    pub fn total_issued(&self, height: u64) -> u64 {
        (if self.foundation_minted { emission::foundation_vested(height) } else { 0 }) + self.emitted
    }
    /// Total rewards claimed into spendable coins so far.
    pub fn claimed(&self) -> u64 {
        self.claimed
    }

    /// The index the *next* claimed coin for `addr` will use (0 if none claimed
    /// yet). Read-only; the owner uses it to reconstruct coins it just claimed.
    pub fn claim_index_of(&self, addr: &Hash) -> u64 {
        *self.claim_index.get(addr).unwrap_or(&0)
    }

    /// Reserve the next coinbase coin index for `addr` (monotonic per reward
    /// address). Used by the node when minting claimed reward coins.
    pub fn take_claim_index(&mut self, addr: &Hash) -> u64 {
        let e = self.claim_index.entry(*addr).or_default();
        let i = *e;
        *e += 1;
        i
    }

    /// Debit `amount` (atomic units) from `addr`'s unclaimed reward balance.
    /// Rejects a claim that exceeds the balance or is zero.
    pub fn debit_reward(&mut self, addr: &Hash, amount: u64) -> Result<(), String> {
        let bal = self.reward_balance(addr);
        if amount == 0 {
            return Err("nothing to claim".to_string());
        }
        if amount > bal {
            return Err(format!("claim {amount} exceeds unclaimed reward balance {bal}"));
        }
        let e = self.rewards.get_mut(addr).expect("balance checked above");
        *e -= amount;
        if *e == 0 {
            self.rewards.remove(addr);
        }
        self.claimed += amount;
        Ok(())
    }

    /// Validators in deterministic order as `(consensus_pubkey, stake)` — the ABCI
    /// app diffs this across a block to build CometBFT validator-set updates, so
    /// bonding/unbonding actually adds/removes block producers. Deterministic order
    /// (the map is keyed by the CometBFT address, a `BTreeMap`), so every node
    /// produces identical updates.
    pub fn validator_set(&self) -> Vec<(Vec<u8>, u64)> {
        self.validators
            .values()
            .map(|v| (v.consensus_pubkey.clone(), v.stake + v.delegated))
            .collect()
    }

    /// Like [`Self::validator_set`] but also each validator's commission (basis points):
    /// `(consensus_pubkey, stake + delegated, commission_bps)`. For the public validator
    /// listing so delegators can compare commissions.
    pub fn validator_set_full(&self) -> Vec<(Vec<u8>, u64, u16)> {
        self.validators
            .values()
            .map(|v| (v.consensus_pubkey.clone(), v.stake + v.delegated, v.commission_bps))
            .collect()
    }

    /// Record the validators that signed a block.
    pub fn record_block(&mut self, signers: &[Vec<u8>]) {
        for s in signers {
            if self.validators.contains_key(s) {
                *self.participation.entry(s.clone()).or_default() += 1;
            }
        }
    }

    /// Register the one-time foundation allocation (20%) to `foundation_address`
    /// (genesis). Nothing is credited up front: the allocation unlocks on the
    /// on-chain [`emission::foundation_vested`] schedule and is claimed against
    /// it. Returns the allocation size (0 if already registered).
    pub fn mint_foundation(&mut self, foundation_address: Hash) -> u64 {
        if self.foundation_minted {
            return 0;
        }
        self.foundation_minted = true;
        self.foundation_addr = foundation_address;
        emission::FOUNDATION
    }

    /// The foundation's registered reward address ([0;32] before genesis).
    pub fn foundation_addr(&self) -> Hash {
        self.foundation_addr
    }

    /// Foundation value claimed into coins so far.
    pub fn foundation_claimed(&self) -> u64 {
        self.foundation_claimed
    }

    /// Foundation value vested by `height` but not yet claimed — the amount the
    /// foundation address may claim right now.
    pub fn foundation_claimable(&self, height: u64) -> u64 {
        if !self.foundation_minted {
            return 0;
        }
        emission::foundation_vested(height).saturating_sub(self.foundation_claimed)
    }

    /// Everything `addr` can claim at `height`: its accrued staking rewards, plus
    /// — for the foundation address only — the vested, unclaimed foundation tranche.
    pub fn claimable_of(&self, addr: &Hash, height: u64) -> u64 {
        let foundation = if self.foundation_minted && *addr == self.foundation_addr {
            self.foundation_claimable(height)
        } else {
            0
        };
        self.reward_balance(addr) + foundation
    }

    /// Debit `amount` from what `addr` can claim at `height`: staking rewards
    /// first, then (for the foundation address) the vested foundation tranche.
    /// Rejects a zero claim or one exceeding [`Self::claimable_of`] — in
    /// particular, the foundation can never claim ahead of its schedule.
    pub fn debit_claimable(&mut self, addr: &Hash, amount: u64, height: u64) -> Result<(), String> {
        if amount == 0 {
            return Err("nothing to claim".to_string());
        }
        let total = self.claimable_of(addr, height);
        if amount > total {
            return Err(format!("claim {amount} exceeds claimable balance {total}"));
        }
        let from_rewards = amount.min(self.reward_balance(addr));
        if from_rewards > 0 {
            self.debit_reward(addr, from_rewards)?;
        }
        let from_foundation = amount - from_rewards;
        if from_foundation > 0 {
            self.foundation_claimed += from_foundation;
            self.claimed += from_foundation;
        }
        Ok(())
    }

    /// Distribute the epoch reward at `height`, capped at the remaining mineable budget,
    /// then reset participation. Returns the amount distributed. Deterministic in the
    /// consensus inputs.
    ///
    /// Each validator's slice is weighted by **total voting power** `(stake + delegated) ×
    /// blocks signed`. That slice is then split: the operator keeps 100% of the reward on
    /// its own self-bonded stake plus a [`COMMISSION_NUM`] commission on the delegated
    /// portion; the remainder of the delegated reward flows to each delegator pro-rata by
    /// their delegation. Integer-division dust stays unminted, so the total distributed
    /// never exceeds the scheduled reward.
    /// Split `amount` across reward addresses by this epoch's weight
    /// = (self-stake + delegated) × blocks signed, applying validator commission and
    /// delegator pro-rata exactly as the block reward does. Returns `(credits, total)`;
    /// an empty result means no one participated (caller must not distribute). Pure over
    /// committed state, so ZCRYPT rewards and bridge fees share one splitting rule.
    fn credits_by_weight(&self, amount: u64) -> (Vec<(Hash, u64)>, u64) {
        if amount == 0 {
            return (Vec::new(), 0);
        }
        let weights: Vec<(Vec<u8>, u128)> = self
            .validators
            .iter()
            .map(|(pk, v)| {
                let part = *self.participation.get(pk).unwrap_or(&0) as u128;
                (pk.clone(), (v.stake as u128 + v.delegated as u128) * part)
            })
            .collect();
        let total_weight: u128 = weights.iter().map(|(_, w)| *w).sum();
        if total_weight == 0 {
            return (Vec::new(), 0);
        }
        let mut credits: Vec<(Hash, u64)> = Vec::new();
        for (pk, w) in &weights {
            if *w == 0 {
                continue;
            }
            let v = self.validators.get(pk).expect("from validators");
            let r_v = (amount as u128 * *w / total_weight) as u64;
            if r_v == 0 {
                continue;
            }
            let total_stake_v = v.stake as u128 + v.delegated as u128;
            if v.delegated == 0 {
                credits.push((v.reward_address, r_v));
                continue;
            }
            // Per-validator commission (basis points): the operator's cut of the slice.
            let commission = (r_v as u128 * v.commission_bps as u128 / 10_000) as u64;
            let rest = r_v - commission;
            let self_share = (rest as u128 * v.stake as u128 / total_stake_v) as u64;
            credits.push((v.reward_address, commission + self_share));
            for ((_, _), d) in self.delegations.iter().filter(|((vid, _), _)| vid == pk) {
                let ds = (rest as u128 * d.stake as u128 / total_stake_v) as u64;
                if ds > 0 {
                    credits.push((d.reward_address, ds));
                }
            }
        }
        let total: u64 = credits.iter().map(|(_, a)| *a).sum();
        (credits, total)
    }

    pub fn distribute_epoch(&mut self, height: u64) -> u64 {
        let reward = emission::epoch_reward(height)
            .min(emission::MINEABLE.saturating_sub(self.emitted));
        let (credits, distributed) = self.credits_by_weight(reward);
        if distributed == 0 {
            // no reward this epoch, or no one participated (never over-mints)
            self.participation.clear();
            return 0;
        }
        for (addr, amt) in credits {
            *self.rewards.entry(addr).or_default() += amt;
            // Lifetime earnings ledger: credited here (real block rewards) and only
            // here — returned unbonded stake never inflates it.
            *self.earned.entry(addr).or_default() += amt;
        }
        self.emitted += distributed;
        self.participation.clear();
        distributed
    }

    /// Accrue a bridge fee of `amount` in the bridged `asset_id` into the undistributed
    /// pool. Called by the node as an SPV mint MATURES, so a reorg-voided mint (which
    /// never matures) never contributes a fee; the fee is a portion of value that was
    /// already minted and fully backed 1:1, redirected from the recipient to stakers.
    pub fn accrue_bridge_fee(&mut self, asset_id: u64, amount: u64) {
        if amount > 0 {
            *self.fee_pool.entry(asset_id).or_default() += amount;
        }
    }

    /// Distribute all accrued bridge fees to stakers by the current epoch weight (the same
    /// split as [`Self::distribute_epoch`]), moving them from `fee_pool` into per-staker,
    /// per-asset `fee_rewards`. Any remainder that cannot be split (no participation this
    /// epoch, or rounding dust) stays in the pool for the next epoch. Call each epoch,
    /// BEFORE `distribute_epoch` clears participation. Returns total distributed.
    pub fn distribute_fees(&mut self) -> u64 {
        let assets: Vec<u64> = self.fee_pool.iter().filter(|(_, v)| **v > 0).map(|(a, _)| *a).collect();
        let mut total = 0u64;
        for asset in assets {
            let pool = *self.fee_pool.get(&asset).unwrap_or(&0);
            let (credits, distributed) = self.credits_by_weight(pool);
            if distributed == 0 {
                continue; // carry this asset's pool to the next epoch
            }
            for (addr, amt) in credits {
                *self.fee_rewards.entry((addr, asset)).or_default() += amt;
                *self.fee_earned.entry((addr, asset)).or_default() += amt;
            }
            *self.fee_pool.get_mut(&asset).unwrap() -= distributed; // keep rounding dust
            total += distributed;
        }
        total
    }

    /// A reward address's claimable bridge-fee balance in `asset_id`.
    pub fn claimable_fee(&self, addr: &Hash, asset_id: u64) -> u64 {
        *self.fee_rewards.get(&(*addr, asset_id)).unwrap_or(&0)
    }

    /// Debit `amount` of claimed bridge fee for `(addr, asset_id)` (the node then mints the
    /// matching asset coins). Rejects an over-claim.
    pub fn debit_fee(&mut self, addr: &Hash, asset_id: u64, amount: u64) -> Result<(), String> {
        let bal = self.fee_rewards.entry((*addr, asset_id)).or_default();
        if amount == 0 || amount > *bal {
            return Err(format!("fee claim {amount} exceeds claimable {bal}"));
        }
        *bal -= amount;
        Ok(())
    }

    /// The next coinbase index for a fee claim on `(addr, asset_id)`, then advance it.
    pub fn take_fee_claim_index(&mut self, addr: &Hash, asset_id: u64) -> u64 {
        let e = self.fee_claim_index.entry((*addr, asset_id)).or_default();
        let i = *e;
        *e += 1;
        i
    }
    pub fn fee_claim_index_of(&self, addr: &Hash, asset_id: u64) -> u64 {
        *self.fee_claim_index.get(&(*addr, asset_id)).unwrap_or(&0)
    }

    /// A 32-byte digest of the staking state, folded into the app_hash so the
    /// whole reward mechanism is consensus-agreed.
    pub fn root(&self) -> Hash {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.total_staked.to_le_bytes());
        buf.extend_from_slice(&self.emitted.to_le_bytes());
        buf.extend_from_slice(&self.claimed.to_le_bytes());
        buf.push(self.foundation_minted as u8);
        // The foundation's identity and how much of its vesting schedule it has
        // consumed are consensus state — all nodes must agree on both.
        buf.extend_from_slice(&self.foundation_addr);
        buf.extend_from_slice(&self.foundation_claimed.to_le_bytes());
        for (id, v) in &self.validators {
            buf.extend_from_slice(&(id.len() as u32).to_le_bytes());
            buf.extend_from_slice(id);
            buf.extend_from_slice(&v.stake.to_le_bytes());
            // Delegated total is part of the validator's committed voting power.
            buf.extend_from_slice(&v.delegated.to_le_bytes());
            buf.extend_from_slice(&v.reward_address);
            // The full consensus pubkey determines each validator's block-producing
            // voting power, so it is part of the consensus-agreed validator set.
            buf.extend_from_slice(&(v.consensus_pubkey.len() as u32).to_le_bytes());
            buf.extend_from_slice(&v.consensus_pubkey);
            // Commission drives reward/fee splits — consensus-critical.
            buf.extend_from_slice(&v.commission_bps.to_le_bytes());
        }
        // Epoch participation counters drive credits_by_weight until distribute clears them.
        for (id, n) in &self.participation {
            buf.extend_from_slice(&(id.len() as u32).to_le_bytes());
            buf.extend_from_slice(id);
            buf.extend_from_slice(&n.to_le_bytes());
        }
        for (addr, amt) in &self.rewards {
            buf.extend_from_slice(addr);
            buf.extend_from_slice(&amt.to_le_bytes());
        }
        for (addr, idx) in &self.claim_index {
            buf.extend_from_slice(addr);
            buf.extend_from_slice(&idx.to_le_bytes());
        }
        // The unbonding queue (frozen stakes + their release times) is consensus state
        // — every node must agree on what is locked and when it releases.
        for u in &self.unbonding {
            buf.extend_from_slice(&(u.validator_id.len() as u32).to_le_bytes());
            buf.extend_from_slice(&u.validator_id);
            buf.extend_from_slice(&u.stake.to_le_bytes());
            buf.extend_from_slice(&u.reward_address);
            buf.extend_from_slice(&u.release_time.to_le_bytes());
        }
        // Tombstoned (slashed) validators — consensus-agreed so all nodes reject their
        // re-bond identically.
        for id in &self.tombstoned {
            buf.extend_from_slice(&(id.len() as u32).to_le_bytes());
            buf.extend_from_slice(id);
        }
        // Delegations (who backs whom, and where their stake+rewards return) — consensus
        // state, so every node agrees on voting-power contributions and reward splits.
        for ((vid, did), d) in &self.delegations {
            buf.extend_from_slice(&(vid.len() as u32).to_le_bytes());
            buf.extend_from_slice(vid);
            buf.extend_from_slice(&(did.len() as u32).to_le_bytes());
            buf.extend_from_slice(did);
            buf.extend_from_slice(&d.stake.to_le_bytes());
            buf.extend_from_slice(&d.reward_address);
        }
        // Bridge fee state (accrued pool + per-staker per-asset claimable + indices) is
        // consensus state: every node must agree on how much bridge yield each staker is
        // owed, in each asset. BTreeMaps iterate in deterministic key order.
        for (asset, amt) in &self.fee_pool {
            buf.extend_from_slice(&asset.to_le_bytes());
            buf.extend_from_slice(&amt.to_le_bytes());
        }
        for ((addr, asset), amt) in &self.fee_rewards {
            buf.extend_from_slice(addr);
            buf.extend_from_slice(&asset.to_le_bytes());
            buf.extend_from_slice(&amt.to_le_bytes());
        }
        for ((addr, asset), idx) in &self.fee_claim_index {
            buf.extend_from_slice(addr);
            buf.extend_from_slice(&asset.to_le_bytes());
            buf.extend_from_slice(&idx.to_le_bytes());
        }
        // Lifetime earnings ledgers (block rewards + bridge fees) are consensus state
        // like every other credit map: all nodes must agree on what each address has
        // ever been paid, since the explorer/API serves it as an on-chain fact.
        for (addr, amt) in &self.earned {
            buf.extend_from_slice(addr);
            buf.extend_from_slice(&amt.to_le_bytes());
        }
        for ((addr, asset), amt) in &self.fee_earned {
            buf.extend_from_slice(addr);
            buf.extend_from_slice(&asset.to_le_bytes());
            buf.extend_from_slice(&amt.to_le_bytes());
        }
        // Replay-protection nonces are consensus state (all nodes must agree which
        // UNBOND/UNDELEGATE signatures are already spent). BTreeMap → deterministic order.
        for (pk, n) in &self.auth_nonce {
            buf.extend_from_slice(pk);
            buf.extend_from_slice(&n.to_le_bytes());
        }
        crate::hash::h(b"ZC-STAKE", &[&buf])
    }

    /// The current replay-protection nonce a UNBOND/UNDELEGATE from `signer_pk` must carry
    /// (0 if the key has never signed one). See [`Self::auth_nonce`] field.
    pub fn auth_nonce(&self, signer_pk: &[u8; 32]) -> u64 {
        self.auth_nonce.get(signer_pk).copied().unwrap_or(0)
    }

    /// Advance `signer_pk`'s nonce after a successful signature-only staking tx, so the exact
    /// signature can never be replayed.
    pub fn bump_auth_nonce(&mut self, signer_pk: &[u8; 32]) {
        *self.auth_nonce.entry(*signer_pk).or_insert(0) += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Hash {
        [n; 32]
    }
    // A validator's reward-matching id (CometBFT address, 20 bytes in production).
    fn pk(n: u8) -> Vec<u8> {
        vec![n; 20]
    }
    // Its full consensus pubkey (ed25519, 32 bytes in production).
    fn cpk(n: u8) -> Vec<u8> {
        vec![n; 32]
    }
    // Bond helper: id and consensus-pubkey derived from the same scalar.
    fn bond(s: &mut Staking, n: u8, stake: u64, reward: Hash) -> Result<(), String> {
        s.bond(pk(n), cpk(n), stake, reward, DEFAULT_COMMISSION_BPS)
    }

    #[test]
    fn bond_enforces_minimum() {
        let mut s = Staking::default();
        assert!(bond(&mut s, 1, MIN_STAKE - 1, addr(1)).is_err());
        assert!(bond(&mut s, 1, MIN_STAKE, addr(1)).is_ok());
        assert_eq!(s.validator_count(), 1);
        assert_eq!(s.total_staked(), MIN_STAKE);
        // validator_set exposes the full consensus pubkey (for CometBFT updates).
        assert_eq!(s.validator_set(), vec![(cpk(1), MIN_STAKE)]);
    }

    #[test]
    fn rewards_split_by_stake_times_participation() {
        let mut s = Staking::default();
        // A: 2× the stake of B
        bond(&mut s, 1, 20_000 * emission::ATOMIC, addr(1)).unwrap();
        bond(&mut s, 2, 10_000 * emission::ATOMIC, addr(2)).unwrap();
        // one epoch, both sign every block
        for _ in 0..emission::EPOCH {
            s.record_block(&[pk(1), pk(2)]);
        }
        let scheduled = emission::epoch_reward(emission::EPOCH);
        let paid = s.distribute_epoch(emission::EPOCH);
        // paid equals the schedule up to per-validator integer-division dust
        assert!(paid <= scheduled && scheduled - paid <= s.validator_count() as u64, "paid {paid} vs {scheduled}");
        // A has 2× stake, same participation -> ~2× reward
        let ra = s.reward_balance(&addr(1));
        let rb = s.reward_balance(&addr(2));
        assert!(ra > rb);
        assert!((ra as i128 - 2 * rb as i128).abs() <= 2, "A≈2×B: {ra} vs {rb}");
    }

    #[test]
    fn no_participation_no_reward() {
        let mut s = Staking::default();
        bond(&mut s, 1, MIN_STAKE, addr(1)).unwrap();
        // validator bonded but signed nothing this epoch
        let paid = s.distribute_epoch(emission::EPOCH);
        assert_eq!(paid, 0);
        assert_eq!(s.emitted(), 0);
    }

    #[test]
    fn participation_weights_reward() {
        let mut s = Staking::default();
        // equal stake, but A signs every block, B only half
        bond(&mut s, 1, MIN_STAKE, addr(1)).unwrap();
        bond(&mut s, 2, MIN_STAKE, addr(2)).unwrap();
        for i in 0..emission::EPOCH {
            if i % 2 == 0 {
                s.record_block(&[pk(1), pk(2)]);
            } else {
                s.record_block(&[pk(1)]);
            }
        }
        s.distribute_epoch(emission::EPOCH);
        // A signed 100, B signed 50 -> A gets ~2× B
        let ra = s.reward_balance(&addr(1));
        let rb = s.reward_balance(&addr(2));
        assert!((ra as i128 - 2 * rb as i128).abs() <= 2, "{ra} vs {rb}");
    }

    #[test]
    fn deterministic() {
        let run = || {
            let mut s = Staking::default();
            bond(&mut s, 1, 15_000 * emission::ATOMIC, addr(1)).unwrap();
            bond(&mut s, 2, 11_000 * emission::ATOMIC, addr(2)).unwrap();
            for _ in 0..emission::EPOCH {
                s.record_block(&[pk(1), pk(2)]);
            }
            s.distribute_epoch(emission::EPOCH);
            s.root()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn never_exceeds_total_supply() {
        let mut s = Staking::default();
        bond(&mut s, 1, MIN_STAKE, addr(1)).unwrap();
        s.mint_foundation(addr(99));
        // grind many epochs across several halvings
        let mut h = emission::EPOCH;
        for _ in 0..2000 {
            for _ in 0..emission::EPOCH {
                s.record_block(&[pk(1)]);
            }
            s.distribute_epoch(h);
            h += emission::EPOCH;
            assert!(s.total_issued(h) <= emission::TOTAL_SUPPLY, "over-minted at height {h}");
            assert!(s.emitted() <= emission::MINEABLE);
        }
        // foundation registered once; nothing pre-credited, claimable follows the schedule
        assert_eq!(s.reward_balance(&addr(99)), 0);
        assert_eq!(s.foundation_claimable(0), emission::FOUNDATION_LIQUID);
        assert_eq!(s.foundation_claimable(u64::MAX), emission::FOUNDATION);
        assert!(s.total_issued(u64::MAX) <= emission::TOTAL_SUPPLY);
        assert_eq!(s.mint_foundation(addr(99)), 0); // idempotent
    }

    #[test]
    fn foundation_claims_follow_the_vesting_schedule() {
        let mut s = Staking::default();
        s.mint_foundation(addr(7));

        // genesis: only the liquid tranche is claimable
        assert_eq!(s.claimable_of(&addr(7), 0), emission::FOUNDATION_LIQUID);
        // claiming ahead of the schedule is rejected
        assert!(s.debit_claimable(&addr(7), emission::FOUNDATION_LIQUID + 1, 0).is_err());
        // the liquid tranche claims fine, and is then exhausted until the cliff
        s.debit_claimable(&addr(7), emission::FOUNDATION_LIQUID, 0).unwrap();
        assert_eq!(s.claimable_of(&addr(7), emission::VESTING_CLIFF - 1), 0);
        assert!(s.debit_claimable(&addr(7), 1, emission::VESTING_CLIFF - 1).is_err());

        // at the cliff: 25% cumulative minus what was already taken
        let at_cliff = emission::VESTING_CLIFF_AMOUNT - emission::FOUNDATION_LIQUID;
        assert_eq!(s.claimable_of(&addr(7), emission::VESTING_CLIFF), at_cliff);
        s.debit_claimable(&addr(7), at_cliff, emission::VESTING_CLIFF).unwrap();

        // fully vested: the remainder claims out to exactly the full allocation
        let rest = emission::FOUNDATION - emission::VESTING_CLIFF_AMOUNT;
        let end = emission::VESTING_CLIFF + emission::VESTING_MONTHS * emission::BLOCKS_PER_MONTH;
        assert_eq!(s.claimable_of(&addr(7), end), rest);
        s.debit_claimable(&addr(7), rest, end).unwrap();
        assert_eq!(s.foundation_claimed(), emission::FOUNDATION);
        assert_eq!(s.claimable_of(&addr(7), u64::MAX), 0);

        // a non-foundation address never sees the foundation tranche
        assert_eq!(s.claimable_of(&addr(8), u64::MAX), 0);
    }

    #[test]
    fn foundation_claims_stack_with_staking_rewards() {
        // The foundation address can also earn ordinary staking rewards; both pools
        // are claimable together and the rewards pool is debited first.
        let mut s = Staking::default();
        s.mint_foundation(addr(1));
        bond(&mut s, 1, MIN_STAKE, addr(1)).unwrap();
        for _ in 0..emission::EPOCH {
            s.record_block(&[pk(1)]);
        }
        s.distribute_epoch(emission::EPOCH);
        let accrued = s.reward_balance(&addr(1));
        assert!(accrued > 0);
        assert_eq!(
            s.claimable_of(&addr(1), emission::EPOCH),
            accrued + emission::FOUNDATION_LIQUID
        );
        // claim everything: rewards drain first, the rest comes from the vested tranche
        s.debit_claimable(&addr(1), accrued + emission::FOUNDATION_LIQUID, emission::EPOCH).unwrap();
        assert_eq!(s.reward_balance(&addr(1)), 0);
        assert_eq!(s.foundation_claimed(), emission::FOUNDATION_LIQUID);
        assert_eq!(s.claimable_of(&addr(1), emission::EPOCH), 0);
    }

    #[test]
    fn unbond_locks_stake_for_the_unbonding_period() {
        let mut s = Staking::default();
        bond(&mut s, 1, MIN_STAKE, addr(1)).unwrap();
        let now = 1_000_000u64;
        // Unbonding leaves the ACTIVE set immediately (no longer producing/earning)...
        let release = s.unbond(&pk(1), now).unwrap();
        assert_eq!(s.validator_count(), 0, "out of the active set at once");
        assert_eq!(s.total_staked(), 0, "no longer counted as active stake");
        // ...but the stake is LOCKED in the unbonding queue for 10 days (unbonding is gasless).
        assert_eq!(release, now + UNBONDING_PERIOD_SECS);
        assert_eq!(s.total_unbonding(), MIN_STAKE, "stake is frozen, not returned");
        assert_eq!(s.unbonding_of(&pk(1)), vec![(MIN_STAKE, release)]);

        // Releasing before maturity does nothing.
        assert_eq!(s.release_matured_unbonding(now + UNBONDING_PERIOD_SECS - 1), 0);
        assert_eq!(s.total_unbonding(), MIN_STAKE, "still locked one second early");

        // At (and after) the release time, the full stake is released and becomes claimable.
        assert_eq!(s.release_matured_unbonding(now + UNBONDING_PERIOD_SECS), MIN_STAKE);
        assert_eq!(s.total_unbonding(), 0, "released after the 10-day wait");
        assert!(s.unbonding_of(&pk(1)).is_empty());
        assert_eq!(s.reward_balance(&addr(1)), MIN_STAKE, "full stake is claimable back");
    }

    #[test]
    fn slashing_burns_stake_ejects_and_tombstones() {
        let mut s = Staking::default();
        let stake = 20_000 * emission::ATOMIC;
        bond(&mut s, 1, stake, addr(1)).unwrap();
        let now = 500u64;

        // Slash for double-signing: 5% burned, ejected, 95% unbonds, tombstoned.
        let burned = s.slash(&pk(1), now);
        assert_eq!(burned, stake * SLASH_NUM / SLASH_DEN, "5% burned");
        assert_eq!(s.validator_count(), 0, "ejected from the active set");
        assert_eq!(s.total_staked(), 0);
        assert!(s.is_tombstoned(&pk(1)));
        // The honest 95% is unbonding and returns after the normal wait.
        let remainder = stake - burned;
        assert_eq!(s.total_unbonding(), remainder);
        assert_eq!(s.unbonding_of(&pk(1)), vec![(remainder, now + UNBONDING_PERIOD_SECS)]);

        // The burned 5% is GONE — releasing later only returns the 95%.
        s.release_matured_unbonding(now + UNBONDING_PERIOD_SECS);
        assert_eq!(s.reward_balance(&addr(1)), remainder, "only the un-slashed stake returns");

        // A tombstoned validator can never re-bond, and is never slashed twice.
        assert!(bond(&mut s, 1, stake, addr(1)).is_err(), "tombstoned cannot re-bond");
        assert_eq!(s.slash(&pk(1), now), 0, "no double-slash");
    }

    #[test]
    fn slashing_also_hits_stake_already_unbonding() {
        // A validator that misbehaves then quickly unbonds must still be punished — the
        // stake sitting in the unbonding queue is slashed too.
        let mut s = Staking::default();
        let stake = 10_000 * emission::ATOMIC;
        bond(&mut s, 1, stake, addr(1)).unwrap();
        let now = 100u64;
        s.unbond(&pk(1), now).unwrap();
        assert_eq!(s.total_unbonding(), stake);
        // Evidence arrives after the unbond: slash the queued stake.
        let burned = s.slash(&pk(1), now + 10);
        assert_eq!(burned, stake * SLASH_NUM / SLASH_DEN);
        assert_eq!(s.total_unbonding(), stake - burned, "queued stake was slashed");
    }

    // A delegator's id (a 20-byte ed25519-derived identity in production).
    fn del(n: u8) -> Vec<u8> {
        vec![n; 20]
    }

    #[test]
    fn delegation_boosts_power_and_splits_rewards() {
        let mut s = Staking::default();
        let self_stake = 10_000 * emission::ATOMIC;
        let del_stake = 10_000 * emission::ATOMIC;
        bond(&mut s, 1, self_stake, addr(1)).unwrap();
        // A delegator backs validator 1 (returns go to addr(50)).
        s.delegate(pk(1), del(50), del_stake, addr(50)).unwrap();
        // Voting power and total stake now reflect self + delegated.
        assert_eq!(s.validator_set(), vec![(cpk(1), self_stake + del_stake)]);
        assert_eq!(s.delegated_to(&pk(1)), del_stake);
        assert_eq!(s.delegation_of(&pk(1), &del(50)), del_stake);
        assert_eq!(s.total_staked(), self_stake + del_stake);

        // One epoch, the validator signs every block.
        for _ in 0..emission::EPOCH {
            s.record_block(&[pk(1)]);
        }
        let paid = s.distribute_epoch(emission::EPOCH);
        let val = s.reward_balance(&addr(1));
        let deleg = s.reward_balance(&addr(50));
        // Delegator earns the delegated stake's share net of the 10% commission:
        // rest = paid×0.9, delegator share = rest×(del/(self+del)) = paid×0.45.
        assert!(deleg > 0, "delegator earns a reward share");
        assert!(val > deleg, "validator keeps commission + its own stake's reward");
        assert!(val + deleg <= paid && paid - (val + deleg) <= 3, "{val}+{deleg} vs {paid}");
        let expected_deleg = paid * 45 / 100;
        assert!((deleg as i128 - expected_deleg as i128).abs() <= 3, "deleg {deleg} ≈ {expected_deleg}");
    }

    #[test]
    fn per_validator_commission_lets_validators_compete() {
        // Two identical validators differing ONLY in commission. The delegator to the
        // lower-commission validator keeps more of the reward — the competitive lever.
        let mut s = Staking::default();
        let st = 10_000 * emission::ATOMIC;
        s.bond(pk(1), cpk(1), st, addr(1), 0).unwrap(); // 0% commission
        s.bond(pk(2), cpk(2), st, addr(2), 5_000).unwrap(); // 50% commission
        s.delegate(pk(1), del(51), st, addr(51)).unwrap();
        s.delegate(pk(2), del(52), st, addr(52)).unwrap();
        for _ in 0..emission::EPOCH {
            s.record_block(&[pk(1), pk(2)]);
        }
        s.distribute_epoch(emission::EPOCH);
        let low = s.reward_balance(&addr(51)); // delegated to the 0% validator
        let high = s.reward_balance(&addr(52)); // delegated to the 50% validator
        assert!(low > high, "delegator to the lower-commission validator earns more: {low} vs {high}");
        // 0% → delegator keeps ~half the slice; 50% → ~a quarter. So low ≈ 2×high.
        assert!(high > 0 && low >= 2 * high - 4, "0% deleg {low} ≈ 2× the 50% deleg {high}");
    }

    #[test]
    fn undelegate_locks_then_returns_to_delegator() {
        let mut s = Staking::default();
        bond(&mut s, 1, MIN_STAKE, addr(1)).unwrap();
        // A delegation can be below MIN_STAKE — only a validator's self-bond needs the min.
        let ds = 5_000 * emission::ATOMIC;
        s.delegate(pk(1), del(50), ds, addr(50)).unwrap();
        let now = 2_000u64;
        let release = s.undelegate(&pk(1), &del(50), now).unwrap();
        assert_eq!(release, now + UNBONDING_PERIOD_SECS);
        assert_eq!(s.delegation_of(&pk(1), &del(50)), 0, "delegation removed");
        assert_eq!(s.delegated_to(&pk(1)), 0, "voting power dropped");
        // Undelegation is gasless — the full delegation returns after the wait.
        assert_eq!(s.total_unbonding(), ds, "locked in the queue");
        // Nothing before maturity; returns to the delegator's reward address after the wait.
        assert_eq!(s.release_matured_unbonding(release - 1), 0);
        assert_eq!(s.release_matured_unbonding(release), ds);
        assert_eq!(s.reward_balance(&addr(50)), ds);
        // Double-undelegate rejected.
        assert!(s.undelegate(&pk(1), &del(50), now).is_err());
    }

    #[test]
    fn slashing_hits_delegators_too() {
        let mut s = Staking::default();
        let self_stake = 10_000 * emission::ATOMIC;
        let ds = 10_000 * emission::ATOMIC;
        bond(&mut s, 1, self_stake, addr(1)).unwrap();
        s.delegate(pk(1), del(50), ds, addr(50)).unwrap();
        let now = 300u64;
        let burned = s.slash(&pk(1), now);
        // 5% of BOTH the self-stake and the delegation is burned.
        assert_eq!(burned, self_stake * SLASH_NUM / SLASH_DEN + ds * SLASH_NUM / SLASH_DEN);
        assert!(s.is_tombstoned(&pk(1)));
        assert_eq!(s.delegated_to(&pk(1)), 0);
        assert_eq!(s.delegation_of(&pk(1), &del(50)), 0, "delegation ejected");
        // Each side's un-slashed 95% unbonds and returns to its own address.
        s.release_matured_unbonding(now + UNBONDING_PERIOD_SECS);
        assert_eq!(s.reward_balance(&addr(1)), self_stake - self_stake * SLASH_NUM / SLASH_DEN);
        assert_eq!(s.reward_balance(&addr(50)), ds - ds * SLASH_NUM / SLASH_DEN, "delegator lost 5%");
    }

    #[test]
    fn unbond_cascades_delegations_back_to_delegators() {
        let mut s = Staking::default();
        bond(&mut s, 1, MIN_STAKE, addr(1)).unwrap();
        let ds = 7_000 * emission::ATOMIC;
        s.delegate(pk(1), del(50), ds, addr(50)).unwrap();
        let now = 400u64;
        let release = s.unbond(&pk(1), now).unwrap();
        // Validator gone; its delegation unwound into the queue too.
        assert_eq!(s.validator_count(), 0);
        assert_eq!(s.delegation_of(&pk(1), &del(50)), 0);
        // Gasless: the validator's own stake and the cascaded delegation both return in full.
        assert_eq!(s.total_unbonding(), MIN_STAKE + ds);
        s.release_matured_unbonding(release);
        assert_eq!(s.reward_balance(&addr(1)), MIN_STAKE);
        assert_eq!(s.reward_balance(&addr(50)), ds, "cascaded delegation returns in full");
    }

    #[test]
    fn cannot_delegate_to_missing_or_tombstoned_validator() {
        let mut s = Staking::default();
        // No such validator.
        assert!(s.delegate(pk(1), del(50), MIN_STAKE, addr(50)).is_err());
        bond(&mut s, 1, MIN_STAKE, addr(1)).unwrap();
        s.slash(&pk(1), 0);
        // Tombstoned target rejected.
        assert!(s.delegate(pk(1), del(50), MIN_STAKE, addr(50)).is_err());
    }

    #[test]
    fn lifetime_earned_survives_claims_and_excludes_returned_stake() {
        let mut s = Staking::default();
        bond(&mut s, 1, MIN_STAKE, addr(1)).unwrap();
        for _ in 0..emission::EPOCH {
            s.record_block(&[pk(1)]);
        }
        s.distribute_epoch(emission::EPOCH);
        let accrued = s.reward_balance(&addr(1));
        assert!(accrued > 0);
        // Lifetime earned mirrors what was distributed...
        assert_eq!(s.earned_of(&addr(1)), accrued);
        // ...and claiming everything empties the balance but not the earnings ledger.
        s.debit_reward(&addr(1), accrued).unwrap();
        assert_eq!(s.reward_balance(&addr(1)), 0);
        assert_eq!(s.earned_of(&addr(1)), accrued, "claims never reduce lifetime earnings");
        // Returned unbonded stake flows through `rewards` but is NOT earnings.
        let now = 1_000u64;
        s.unbond(&pk(1), now).unwrap();
        s.release_matured_unbonding(now + UNBONDING_PERIOD_SECS);
        assert_eq!(s.reward_balance(&addr(1)), MIN_STAKE, "stake returned as claimable");
        assert_eq!(s.earned_of(&addr(1)), accrued, "returned stake never inflates earnings");
        // Earnings accumulate across epochs (participation re-recorded each epoch).
        let mut t = Staking::default();
        bond(&mut t, 2, MIN_STAKE, addr(2)).unwrap();
        for _ in 0..emission::EPOCH {
            t.record_block(&[pk(2)]);
        }
        t.distribute_epoch(emission::EPOCH);
        let after_one = t.earned_of(&addr(2));
        assert!(after_one > 0);
        for _ in 0..emission::EPOCH {
            t.record_block(&[pk(2)]);
        }
        t.distribute_epoch(2 * emission::EPOCH);
        assert!(t.earned_of(&addr(2)) > after_one, "earnings accumulate across epochs");
    }

    #[test]
    fn claim_debits_but_issuance_is_invariant() {
        let mut s = Staking::default();
        s.mint_foundation(addr(9));
        bond(&mut s, 1, MIN_STAKE, addr(1)).unwrap();
        for _ in 0..emission::EPOCH {
            s.record_block(&[pk(1)]);
        }
        s.distribute_epoch(emission::EPOCH);
        let accrued = s.reward_balance(&addr(1));
        assert!(accrued > 0);
        let issued_before = s.total_issued(emission::EPOCH);

        // partial claim debits the ledger but does not change total issuance
        s.debit_reward(&addr(1), accrued / 4).unwrap();
        assert_eq!(s.reward_balance(&addr(1)), accrued - accrued / 4);
        assert_eq!(s.total_issued(emission::EPOCH), issued_before, "claiming must not mint/burn");
        assert_eq!(s.claimed(), accrued / 4);

        // over-claim rejected; exact claim empties the balance
        assert!(s.debit_reward(&addr(1), accrued).is_err());
        s.debit_reward(&addr(1), accrued - accrued / 4).unwrap();
        assert_eq!(s.reward_balance(&addr(1)), 0);
        assert_eq!(s.total_issued(emission::EPOCH), issued_before);

        // coin indices are monotonic and unique per address
        assert_eq!(s.take_claim_index(&addr(1)), 0);
        assert_eq!(s.take_claim_index(&addr(1)), 1);
        assert_eq!(s.take_claim_index(&addr(2)), 0);
    }
}
