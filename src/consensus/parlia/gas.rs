//! Gas-limit calculation and validation for Parlia (BSC).
//! Mirrors Go reference implementation in `bsc_official/core/block_validator.go`.


/// Minimum allowed gas-limit (same as `params.MinGasLimit`).
pub const MIN_GAS_LIMIT: u64 = 5_000;

/// Bound divisor before Lorentz.
pub const DIVISOR_BEFORE_LORENTZ: u64 = 256;
/// Bound divisor starting from Lorentz (incl. Maxwell).
pub const DIVISOR_AFTER_LORENTZ: u64 = 1024;

/// Returns the gas-limit bound divisor for the given `epoch_len`.
#[inline]
pub const fn divisor_for_epoch(epoch_len: u64) -> u64 {
    if epoch_len >= 500 { DIVISOR_AFTER_LORENTZ } else { DIVISOR_BEFORE_LORENTZ }
}

/// Computes the allowed delta (`Δ`) for the next block.
#[inline]
pub const fn allowed_delta(parent_gas_limit: u64, divisor: u64) -> u64 {
    parent_gas_limit / divisor - 1
}

/// Validate the `gas_limit` of `header` against its parent.
///
/// * `epoch_len` – current epoch length (200 / 500 / 1000) to decide Lorentz.
/// * Returns `Ok(())` if valid otherwise an error string.
pub fn validate_gas_limit(
    parent_gas_limit: u64,
    gas_limit: u64,
    epoch_len: u64,
) -> Result<(), &'static str> {
    // Hard cap 2^63-1 (same as go-ethereum) but we use u64 range check implicitly.
    let divisor = divisor_for_epoch(epoch_len);
    let delta = allowed_delta(parent_gas_limit, divisor);

    // Gas-limit must be within parent ± delta and above minimum.
    if gas_limit < MIN_GAS_LIMIT {
        return Err("gas_limit below minimum");
    }

    let diff = if parent_gas_limit > gas_limit {
        parent_gas_limit - gas_limit
    } else {
        gas_limit - parent_gas_limit
    };

    if diff >= delta {
        return Err("gas_limit change exceeds bound");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta_before_lorentz() {
        let parent = 30_000_000u64;
        let d = allowed_delta(parent, DIVISOR_BEFORE_LORENTZ);
        assert_eq!(d, parent / 256 - 1);
    }

    #[test]
    fn test_validation_pass() {
        let parent = 30_000_000u64;
        let delta = allowed_delta(parent, DIVISOR_AFTER_LORENTZ);
        let ok = parent + delta - 1;
        assert!(validate_gas_limit(parent, ok, 500).is_ok());
    }

    #[test]
    fn test_validation_fail() {
        let parent = 30_000_000u64;
        let delta = allowed_delta(parent, DIVISOR_AFTER_LORENTZ);
        let bad = parent + delta;
        assert!(validate_gas_limit(parent, bad, 1000).is_err());
    }
} 