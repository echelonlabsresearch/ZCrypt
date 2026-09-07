//! Deterministic block-reward emission — trustless issuance.
//!
//! **21,000,000 ZCRYPT** total supply:
//!   * **20% (4,200,000)** foundation allocation, subject to the on-chain
//!     [`foundation_vested`] schedule (50k liquid at genesis, 25% cliff at
//!     month 12, then linear monthly through month 48);
//!   * **80% (16,800,000)** mined as block rewards on a **halving** schedule.
//!
//! The reward — and the foundation's vested amount — is a pure function of block
//! height, so every node computes the same value independently. A validator
//! therefore **cannot invent or inflate rewards**, and the foundation **cannot
//! claim ahead of its schedule** — a block that pays a different amount produces
//! a different app_hash, and CometBFT's BFT agreement rejects it. There is no
//! mint authority: issuance is enforced entirely by the consensus rules here.
//!
//! All time-denominated schedules assume the **1-second target block time**
//! ([`BLOCK_TIME_SECS`]); the consensus layer's `timeout_commit` must match.
//! Reward per block halves every `HALVING_INTERVAL` blocks; the geometric sum of
//! the schedule equals the 16.8M mineable budget (with a hard cap as a backstop).

/// Atomic units per ZCRYPT (6 decimals).
pub const ATOMIC: u64 = 1_000_000;

/// Minimum transaction fee: **0.01 ZCRYPT**. ZCRYPT is the universal gas asset — every
/// action that moves value pays at least this, and the fee is **burned** (removed from
/// supply). Enforced as a consensus rule (not in the circuit, which proves conservation
/// for any fee): a shield spend must carry `fee ≥ MIN_FEE`, and the fee-less
/// administrative actions (claim / unbond / undelegate) debit it from the value they
/// release. A flat floor — a sender may always pay more.
pub const MIN_FEE: u64 = ATOMIC / 100; // 0.01 ZCRYPT = 10,000 atomic units

/// Bridge value-capture fee, in basis points of the bridged amount (10 bps = 0.1%).
/// A small proportional cut of every zBTC mint is retained by the protocol (taken at
/// maturity, in the bridged asset) and distributed to ZCRYPT stakers by the same weight
/// the block reward uses. This is what tethers Bitcoin bridge volume to the token: since
/// the fee cannot be sized in ZCRYPT without a price oracle, it is taken in-asset and
/// paid to stakers as real, asset-denominated yield, so staking demand (and thus locked
/// ZCRYPT supply) grows with bridge throughput rather than bypassing the token. Oracle-
/// free, and it only ever redistributes value that is already fully backed 1:1.
pub const BRIDGE_FEE_BPS: u64 = 10;

/// The protocol's cut of a `value`-unit bridge mint (floor division; zero for dust
/// smaller than `10_000 / BRIDGE_FEE_BPS` base units, which is correct — a fee below one
/// base unit rounds to nothing). The user receives `value - bridge_fee(value)`.
pub fn bridge_fee(value: u64) -> u64 {
    (value as u128 * BRIDGE_FEE_BPS as u128 / 10_000) as u64
}
/// Total supply, in atomic units.
pub const TOTAL_SUPPLY: u64 = 21_000_000 * ATOMIC;
/// Foundation allocation (20%), released on the [`foundation_vested`] schedule.
pub const FOUNDATION: u64 = TOTAL_SUPPLY / 5;
/// Budget mined via block rewards (80% = 16.8M ZCRYPT).
pub const MINEABLE: u64 = TOTAL_SUPPLY - FOUNDATION;

/// Target block time in seconds. Every height-denominated schedule below (halving,
/// vesting) is calibrated to this; the consensus `timeout_commit` must match it.
pub const BLOCK_TIME_SECS: u64 = 1;
/// Blocks per day at the target block time.
pub const BLOCKS_PER_DAY: u64 = 86_400 / BLOCK_TIME_SECS;
/// Blocks per schedule "month" (30 days) at the target block time.
pub const BLOCKS_PER_MONTH: u64 = 30 * BLOCKS_PER_DAY;

/// Initial block reward: 0.14 ZCRYPT. `INITIAL_REWARD·HALVING_INTERVAL·2 = MINEABLE`
/// exactly (before integer-halving truncation).
pub const INITIAL_REWARD: u64 = 140_000;
/// Blocks between halvings: 60,000,000 (~694 days ≈ 1.9 years at 1 s/block).
pub const HALVING_INTERVAL: u64 = 60_000_000;
/// Rewards are distributed once per epoch (every `EPOCH` blocks) to the validators
/// that participated in consensus over that epoch.
pub const EPOCH: u64 = 100;

// ---- foundation vesting ------------------------------------------------------

/// Foundation tranche liquid at genesis: 50,000 ZCRYPT (~1.2% of the allocation),
/// enough to bond initial validators (min bond 10,000) and cover operations.
pub const FOUNDATION_LIQUID: u64 = 50_000 * ATOMIC;
/// Cliff height: month 12 of the schedule (360 days at 1 s/block).
pub const VESTING_CLIFF: u64 = 12 * BLOCKS_PER_MONTH;
/// Cumulative amount vested at the cliff: 25% of the allocation (1,050,000 ZCRYPT,
/// inclusive of the genesis-liquid tranche).
pub const VESTING_CLIFF_AMOUNT: u64 = FOUNDATION / 4;
/// Number of equal monthly unlocks after the cliff (months 13..=48).
pub const VESTING_MONTHS: u64 = 36;
/// Amount unlocked per post-cliff month: 87,500 ZCRYPT exactly.
pub const VESTING_MONTHLY: u64 = (FOUNDATION - VESTING_CLIFF_AMOUNT) / VESTING_MONTHS;

/// Devnet-only acceleration of the vesting **pacing** (never the amounts): the
/// cliff and month lengths are divided by this scale. 1 = the production
/// schedule. Set once at process start, before any consensus processing; it is
/// consensus-critical, so every validator must be configured identically (the
/// ABCI node only honors it in `devnet` builds).
static VESTING_TIME_SCALE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Set the vesting time scale (first call wins; ≥1). Devnet/testing only.
pub fn set_vesting_time_scale(scale: u64) {
    let _ = VESTING_TIME_SCALE.set(scale.max(1));
}

/// The active vesting time scale (1 unless a devnet node accelerated it).
pub fn vesting_time_scale() -> u64 {
    VESTING_TIME_SCALE.get().copied().unwrap_or(1)
}

/// [`foundation_vested`] evaluated with the cliff/month lengths divided by
/// `scale` (floored at one block). Tranche amounts are untouched: the schedule
/// keeps its exact shape, replayed faster.
pub fn foundation_vested_at_scale(height: u64, scale: u64) -> u64 {
    let scale = scale.max(1);
    let cliff = (VESTING_CLIFF / scale).max(1);
    let month = (BLOCKS_PER_MONTH / scale).max(1);
    if height < cliff {
        return FOUNDATION_LIQUID;
    }
    let months_after_cliff = (height - cliff) / month;
    VESTING_CLIFF_AMOUNT
        .saturating_add(months_after_cliff.saturating_mul(VESTING_MONTHLY))
        .min(FOUNDATION)
}

/// Cumulative foundation amount vested (claimable) at `height`, in atomic units.
/// Pure function of height ⇒ consensus-enforced: 50k liquid from genesis, 25% at
/// the month-12 cliff, then 87,500 ZCRYPT each month until fully vested at
/// month 48. Monotonic, never exceeds [`FOUNDATION`].
pub fn foundation_vested(height: u64) -> u64 {
    foundation_vested_at_scale(height, vesting_time_scale())
}

/// The scheduled block reward at `height` (atomic units) — halves each interval,
/// reaching 0 once fully halved out.
pub fn block_reward(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 63 {
        return 0;
    }
    INITIAL_REWARD >> halvings
}

/// The reward paid out at the end of the epoch ending at `height` — the sum of the
/// per-block rewards across that epoch's blocks (all in one halving era in
/// practice, but summed exactly regardless).
pub fn epoch_reward(epoch_end_height: u64) -> u64 {
    let start = epoch_end_height.saturating_sub(EPOCH - 1);
    (start..=epoch_end_height).map(block_reward).sum()
}

/// Total emitted through `height` inclusive (closed-form over halving eras).
/// Never exceeds `MINEABLE`.
pub fn cumulative_emission(height: u64) -> u64 {
    let mut total: u128 = 0;
    let mut h: u64 = 0;
    let mut era: u32 = 0;
    while h <= height && era < 63 {
        let reward = (INITIAL_REWARD >> era) as u128;
        if reward == 0 {
            break;
        }
        let era_end = ((era as u64 + 1) * HALVING_INTERVAL).min(height.saturating_add(1));
        total += reward * (era_end - h) as u128;
        h = era_end;
        era += 1;
    }
    total.min(MINEABLE as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supply_split_is_21m() {
        assert_eq!(TOTAL_SUPPLY, 21_000_000 * ATOMIC);
        assert_eq!(FOUNDATION, 4_200_000 * ATOMIC);
        assert_eq!(MINEABLE, 16_800_000 * ATOMIC);
        assert_eq!(FOUNDATION + MINEABLE, TOTAL_SUPPLY);
    }

    #[test]
    fn reward_halves_each_interval() {
        assert_eq!(block_reward(0), INITIAL_REWARD);
        assert_eq!(block_reward(HALVING_INTERVAL - 1), INITIAL_REWARD);
        assert_eq!(block_reward(HALVING_INTERVAL), INITIAL_REWARD / 2);
        assert_eq!(block_reward(2 * HALVING_INTERVAL), INITIAL_REWARD / 4);
        assert_eq!(block_reward(10 * HALVING_INTERVAL), INITIAL_REWARD >> 10);
    }

    #[test]
    fn total_emission_matches_mineable_budget() {
        // Summing the whole schedule to exhaustion lands on the 16.8M budget
        // (a hair under, from integer-halving truncation) and never over.
        let total = cumulative_emission(u64::MAX);
        assert!(total <= MINEABLE, "must never exceed the mineable cap");
        // within 0.01% of the budget
        let delta = MINEABLE - total;
        assert!(delta * 10_000 < MINEABLE, "emission {total} far from budget {MINEABLE}");
    }

    #[test]
    fn emission_is_monotonic_and_capped() {
        let a = cumulative_emission(HALVING_INTERVAL);
        let b = cumulative_emission(2 * HALVING_INTERVAL);
        assert!(b > a);
        assert!(b <= MINEABLE);
        // ~half the total is emitted in the first halving era
        let first_era = cumulative_emission(HALVING_INTERVAL - 1);
        assert_eq!(first_era, INITIAL_REWARD * HALVING_INTERVAL);
    }

    #[test]
    fn epoch_reward_sums_the_epoch() {
        // early on, all EPOCH blocks are in era 0
        assert_eq!(epoch_reward(EPOCH - 1), INITIAL_REWARD * EPOCH);
        assert_eq!(epoch_reward(EPOCH * 5 - 1), INITIAL_REWARD * EPOCH);
    }

    #[test]
    fn vesting_schedule_shape() {
        // genesis through the cliff: only the liquid tranche
        assert_eq!(foundation_vested(0), 50_000 * ATOMIC);
        assert_eq!(foundation_vested(VESTING_CLIFF - 1), 50_000 * ATOMIC);
        // month-12 cliff: 25% cumulative
        assert_eq!(foundation_vested(VESTING_CLIFF), FOUNDATION / 4);
        assert_eq!(FOUNDATION / 4, 1_050_000 * ATOMIC);
        // one month later: one monthly unlock more
        assert_eq!(
            foundation_vested(VESTING_CLIFF + BLOCKS_PER_MONTH),
            FOUNDATION / 4 + 87_500 * ATOMIC
        );
        // flat between monthly steps
        assert_eq!(
            foundation_vested(VESTING_CLIFF + BLOCKS_PER_MONTH - 1),
            FOUNDATION / 4
        );
        // fully vested at month 48, and stays there
        let end = VESTING_CLIFF + VESTING_MONTHS * BLOCKS_PER_MONTH;
        assert_eq!(foundation_vested(end), FOUNDATION);
        assert_eq!(foundation_vested(end - 1), FOUNDATION - VESTING_MONTHLY);
        assert_eq!(foundation_vested(u64::MAX), FOUNDATION);
    }

    #[test]
    fn vesting_is_monotonic_and_capped() {
        let mut prev = 0;
        // sample across the whole schedule (plus far beyond) in month steps
        for m in 0..60 {
            let v = foundation_vested(m * BLOCKS_PER_MONTH);
            assert!(v >= prev, "vested amount must never decrease");
            assert!(v <= FOUNDATION);
            prev = v;
        }
        // the monthly amounts tile the allocation exactly
        assert_eq!(VESTING_CLIFF_AMOUNT + VESTING_MONTHS * VESTING_MONTHLY, FOUNDATION);
    }

    #[test]
    fn accelerated_schedule_keeps_the_exact_shape() {
        // scale 259_200 → cliff at block 120, one "month" every 10 blocks
        let s = 259_200;
        assert_eq!(foundation_vested_at_scale(0, s), FOUNDATION_LIQUID);
        assert_eq!(foundation_vested_at_scale(119, s), FOUNDATION_LIQUID);
        assert_eq!(foundation_vested_at_scale(120, s), VESTING_CLIFF_AMOUNT);
        assert_eq!(foundation_vested_at_scale(130, s), VESTING_CLIFF_AMOUNT + VESTING_MONTHLY);
        assert_eq!(foundation_vested_at_scale(120 + 36 * 10, s), FOUNDATION);
        // amounts are identical to the production schedule, only pacing changes
        for m in 0..=40u64 {
            assert_eq!(
                foundation_vested_at_scale(120 + m * 10, s),
                foundation_vested_at_scale(VESTING_CLIFF + m * BLOCKS_PER_MONTH, 1)
            );
        }
        // scale 1 is the production schedule
        assert_eq!(foundation_vested_at_scale(VESTING_CLIFF, 1), foundation_vested(VESTING_CLIFF));
    }
}
