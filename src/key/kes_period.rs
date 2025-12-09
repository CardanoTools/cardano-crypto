//! KES period types and utilities
//!
//! This module provides types for handling KES (Key Evolving Signatures) periods,
//! matching the types used in cardano-node and cardano-api.
//!
//! # Overview
//!
//! KES keys have a limited lifetime divided into periods. Each period, the key
//! must be evolved to maintain forward security. The total number of periods
//! depends on the KES algorithm:
//!
//! | Algorithm | Periods | Total Lifetime |
//! |-----------|---------|----------------|
//! | SingleKES | 1 | 1 period |
//! | Sum0KES | 1 | 1 period |
//! | Sum1KES | 2 | 2 periods |
//! | Sum2KES | 4 | 4 periods |
//! | Sum3KES | 8 | 8 periods |
//! | Sum4KES | 16 | 16 periods |
//! | Sum5KES | 32 | 32 periods |
//! | Sum6KES | 64 | 64 periods |
//! | Sum7KES | 128 | 128 periods |
//!
//! In Cardano mainnet, Sum6KES is used with 64 periods.
//!
//! # Examples
//!
//! ```rust
//! use cardano_crypto::key::kes_period::{KESPeriod, kes_period_info};
//!
//! let period: KESPeriod = 0;
//! let info = kes_period_info::<cardano_crypto::Sum6Kes>(period);
//! assert!(info.is_valid);
//! assert_eq!(info.total_periods, 64);
//! ```

use crate::kes::KesAlgorithm;

/// KES period type
///
/// Represents a specific period in the KES key's lifetime.
/// Period 0 is the initial period after key generation.
pub type KESPeriod = u32;

/// Maximum KES period for Sum6KES (mainnet default)
///
/// Sum6KES supports 2^6 = 64 periods (0-63).
pub const KES_MAX_PERIOD_SUM6: KESPeriod = 63;

/// Number of slots per KES period on mainnet
///
/// Each KES period on Cardano mainnet is 129,600 slots (1.5 days).
pub const KES_SLOTS_PER_PERIOD_MAINNET: u64 = 129_600;

/// Number of slots per KES period on testnet/preview
///
/// On testnets, KES periods may be shorter for faster testing.
pub const KES_SLOTS_PER_PERIOD_TESTNET: u64 = 129_600;

/// Information about a KES period
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KESPeriodInfo {
    /// The current period
    pub period: KESPeriod,
    /// Whether the period is valid for the algorithm
    pub is_valid: bool,
    /// Total number of periods supported by the algorithm
    pub total_periods: u32,
    /// Remaining periods (inclusive of current)
    pub remaining_periods: u32,
}

/// Get information about a KES period for a specific algorithm
///
/// # Type Parameters
///
/// * `K` - KES algorithm type (e.g., `Sum6Kes`)
///
/// # Arguments
///
/// * `period` - The period to query
///
/// # Returns
///
/// Information about the period including validity and remaining periods
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::kes_period::kes_period_info;
/// use cardano_crypto::Sum6Kes;
///
/// let info = kes_period_info::<Sum6Kes>(0);
/// assert!(info.is_valid);
/// assert_eq!(info.total_periods, 64);
/// assert_eq!(info.remaining_periods, 64);
///
/// let info = kes_period_info::<Sum6Kes>(63);
/// assert!(info.is_valid);
/// assert_eq!(info.remaining_periods, 1);
///
/// let info = kes_period_info::<Sum6Kes>(64);
/// assert!(!info.is_valid);
/// ```
pub fn kes_period_info<K: KesAlgorithm>(period: KESPeriod) -> KESPeriodInfo {
    let total_periods = K::total_periods() as u32;
    let is_valid = (period as u64) < K::total_periods();
    let remaining_periods = if is_valid {
        total_periods - period
    } else {
        0
    };

    KESPeriodInfo {
        period,
        is_valid,
        total_periods,
        remaining_periods,
    }
}/// Check if a KES period is valid for a specific algorithm
///
/// # Type Parameters
///
/// * `K` - KES algorithm type
///
/// # Arguments
///
/// * `period` - The period to check
///
/// # Returns
///
/// `true` if the period is within the valid range for the algorithm
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::kes_period::is_valid_period;
/// use cardano_crypto::Sum6Kes;
///
/// assert!(is_valid_period::<Sum6Kes>(0));
/// assert!(is_valid_period::<Sum6Kes>(63));
/// assert!(!is_valid_period::<Sum6Kes>(64));
/// ```
pub fn is_valid_period<K: KesAlgorithm>(period: KESPeriod) -> bool {
    (period as u64) < K::total_periods()
}

/// Calculate the slot number from a KES period
///
/// Given a KES period and a starting slot, calculate the slot number
/// when that period begins.
///
/// # Arguments
///
/// * `period` - The KES period
/// * `slots_per_period` - Number of slots per KES period
/// * `start_slot` - The slot when the KES key started (period 0)
///
/// # Returns
///
/// The slot number when the given period begins
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::kes_period::{slot_from_period, KES_SLOTS_PER_PERIOD_MAINNET};
///
/// // Period 0 starts at start_slot
/// assert_eq!(slot_from_period(0, KES_SLOTS_PER_PERIOD_MAINNET, 0), 0);
///
/// // Period 1 starts after one period's worth of slots
/// assert_eq!(slot_from_period(1, KES_SLOTS_PER_PERIOD_MAINNET, 0), 129_600);
/// ```
pub fn slot_from_period(period: KESPeriod, slots_per_period: u64, start_slot: u64) -> u64 {
    start_slot + (period as u64) * slots_per_period
}

/// Calculate the KES period from a slot number
///
/// Given a slot number, calculate which KES period it falls into.
///
/// # Arguments
///
/// * `slot` - The slot number
/// * `slots_per_period` - Number of slots per KES period
/// * `start_slot` - The slot when the KES key started (period 0)
///
/// # Returns
///
/// The KES period for the given slot
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::kes_period::{period_from_slot, KES_SLOTS_PER_PERIOD_MAINNET};
///
/// // Slot 0 is in period 0
/// assert_eq!(period_from_slot(0, KES_SLOTS_PER_PERIOD_MAINNET, 0), 0);
///
/// // Slot 129,599 is still in period 0
/// assert_eq!(period_from_slot(129_599, KES_SLOTS_PER_PERIOD_MAINNET, 0), 0);
///
/// // Slot 129,600 is in period 1
/// assert_eq!(period_from_slot(129_600, KES_SLOTS_PER_PERIOD_MAINNET, 0), 1);
/// ```
pub fn period_from_slot(slot: u64, slots_per_period: u64, start_slot: u64) -> KESPeriod {
    if slot < start_slot {
        0
    } else {
        ((slot - start_slot) / slots_per_period) as KESPeriod
    }
}

/// Calculate when a KES key expires (in slots)
///
/// # Type Parameters
///
/// * `K` - KES algorithm type
///
/// # Arguments
///
/// * `slots_per_period` - Number of slots per KES period
/// * `start_slot` - The slot when the KES key started (period 0)
///
/// # Returns
///
/// The slot number when the KES key expires (first invalid slot)
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::kes_period::{kes_expiry_slot, KES_SLOTS_PER_PERIOD_MAINNET};
/// use cardano_crypto::Sum6Kes;
///
/// // Sum6KES with 64 periods, each 129,600 slots
/// let expiry = kes_expiry_slot::<Sum6Kes>(KES_SLOTS_PER_PERIOD_MAINNET, 0);
/// assert_eq!(expiry, 64 * 129_600); // 8,294,400 slots
/// ```
pub fn kes_expiry_slot<K: KesAlgorithm>(slots_per_period: u64, start_slot: u64) -> u64 {
    start_slot + K::total_periods() * slots_per_period
}

/// Check if a KES key is expired at a given slot
///
/// # Type Parameters
///
/// * `K` - KES algorithm type
///
/// # Arguments
///
/// * `slot` - The current slot
/// * `slots_per_period` - Number of slots per KES period
/// * `start_slot` - The slot when the KES key started (period 0)
///
/// # Returns
///
/// `true` if the KES key is expired at the given slot
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::kes_period::{is_kes_expired, KES_SLOTS_PER_PERIOD_MAINNET};
/// use cardano_crypto::Sum6Kes;
///
/// // Not expired at start
/// assert!(!is_kes_expired::<Sum6Kes>(0, KES_SLOTS_PER_PERIOD_MAINNET, 0));
///
/// // Expired after all periods
/// assert!(is_kes_expired::<Sum6Kes>(64 * 129_600, KES_SLOTS_PER_PERIOD_MAINNET, 0));
/// ```
pub fn is_kes_expired<K: KesAlgorithm>(slot: u64, slots_per_period: u64, start_slot: u64) -> bool {
    slot >= kes_expiry_slot::<K>(slots_per_period, start_slot)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kes::{Sum0Kes, Sum1Kes, Sum6Kes};

    #[test]
    fn test_kes_period_info_sum6() {
        let info = kes_period_info::<Sum6Kes>(0);
        assert!(info.is_valid);
        assert_eq!(info.total_periods, 64);
        assert_eq!(info.remaining_periods, 64);

        let info = kes_period_info::<Sum6Kes>(32);
        assert!(info.is_valid);
        assert_eq!(info.remaining_periods, 32);

        let info = kes_period_info::<Sum6Kes>(63);
        assert!(info.is_valid);
        assert_eq!(info.remaining_periods, 1);

        let info = kes_period_info::<Sum6Kes>(64);
        assert!(!info.is_valid);
        assert_eq!(info.remaining_periods, 0);
    }

    #[test]
    fn test_kes_period_info_sum0() {
        let info = kes_period_info::<Sum0Kes>(0);
        assert!(info.is_valid);
        assert_eq!(info.total_periods, 1);
        assert_eq!(info.remaining_periods, 1);

        let info = kes_period_info::<Sum0Kes>(1);
        assert!(!info.is_valid);
    }

    #[test]
    fn test_kes_period_info_sum1() {
        let info = kes_period_info::<Sum1Kes>(0);
        assert!(info.is_valid);
        assert_eq!(info.total_periods, 2);

        let info = kes_period_info::<Sum1Kes>(1);
        assert!(info.is_valid);

        let info = kes_period_info::<Sum1Kes>(2);
        assert!(!info.is_valid);
    }

    #[test]
    fn test_is_valid_period() {
        assert!(is_valid_period::<Sum6Kes>(0));
        assert!(is_valid_period::<Sum6Kes>(63));
        assert!(!is_valid_period::<Sum6Kes>(64));
        assert!(!is_valid_period::<Sum6Kes>(100));
    }

    #[test]
    fn test_slot_from_period() {
        assert_eq!(slot_from_period(0, 129_600, 0), 0);
        assert_eq!(slot_from_period(1, 129_600, 0), 129_600);
        assert_eq!(slot_from_period(2, 129_600, 0), 259_200);

        // With non-zero start slot
        assert_eq!(slot_from_period(0, 129_600, 1000), 1000);
        assert_eq!(slot_from_period(1, 129_600, 1000), 130_600);
    }

    #[test]
    fn test_period_from_slot() {
        assert_eq!(period_from_slot(0, 129_600, 0), 0);
        assert_eq!(period_from_slot(129_599, 129_600, 0), 0);
        assert_eq!(period_from_slot(129_600, 129_600, 0), 1);
        assert_eq!(period_from_slot(259_199, 129_600, 0), 1);
        assert_eq!(period_from_slot(259_200, 129_600, 0), 2);

        // With non-zero start slot
        assert_eq!(period_from_slot(1000, 129_600, 1000), 0);
        assert_eq!(period_from_slot(130_599, 129_600, 1000), 0);
        assert_eq!(period_from_slot(130_600, 129_600, 1000), 1);
    }

    #[test]
    fn test_kes_expiry_slot() {
        let expiry = kes_expiry_slot::<Sum6Kes>(129_600, 0);
        assert_eq!(expiry, 64 * 129_600);

        let expiry = kes_expiry_slot::<Sum1Kes>(129_600, 0);
        assert_eq!(expiry, 2 * 129_600);

        // With non-zero start
        let expiry = kes_expiry_slot::<Sum6Kes>(129_600, 1000);
        assert_eq!(expiry, 1000 + 64 * 129_600);
    }

    #[test]
    fn test_is_kes_expired() {
        // Not expired at start
        assert!(!is_kes_expired::<Sum6Kes>(0, 129_600, 0));

        // Not expired just before expiry
        assert!(!is_kes_expired::<Sum6Kes>(64 * 129_600 - 1, 129_600, 0));

        // Expired at expiry slot
        assert!(is_kes_expired::<Sum6Kes>(64 * 129_600, 129_600, 0));

        // Expired well after
        assert!(is_kes_expired::<Sum6Kes>(100 * 129_600, 129_600, 0));
    }

    #[test]
    fn test_kes_constants() {
        assert_eq!(KES_MAX_PERIOD_SUM6, 63);
        assert_eq!(KES_SLOTS_PER_PERIOD_MAINNET, 129_600);
    }
}
