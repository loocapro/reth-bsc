//! Parlia/BSC consensus constants for header `extraData` parsing.
//! Values copied from the Go reference (`parlia.go`).

use alloy_primitives::U256;

/// Fixed 32-byte vanity prefix present in every header.
pub const EXTRA_VANITY: usize = 32;
/// Fixed 65-byte ECDSA signature suffix (r,s,v).
pub const EXTRA_SEAL: usize = 65;
/// 1-byte length field preceding validator bytes since Luban.
pub const VALIDATOR_NUMBER_SIZE: usize = 1;
/// Size of each validator address (20 bytes) before Luban.
pub const VALIDATOR_BYTES_LEN_BEFORE_LUBAN: usize = 20;
/// Size of each validator consensus address (20) + vote address (48) after Luban.
pub const VALIDATOR_BYTES_LEN_AFTER_LUBAN: usize = 68;
/// 1-byte turnLength suffix added in Bohr.
pub const TURN_LENGTH_SIZE: usize = 1;

/// Difficulty for in-turn block (when it's the proposer's turn)
pub const DIFF_INTURN: U256 = U256::from_limbs([2, 0, 0, 0]);
/// Difficulty for out-of-turn block (when it's not the proposer's turn)
pub const DIFF_NOTURN: U256 = U256::from_limbs([1, 0, 0, 0]); 