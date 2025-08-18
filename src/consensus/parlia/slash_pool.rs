use once_cell::sync::Lazy;
use std::sync::Mutex;
use alloy_primitives::Address;

// Global in‐memory pool of slashing evidences collected by the header
// validator during block import. The executor will drain this list at the
// end of block execution and translate each entry into a slash system
// transaction that gets executed in the EVM.
static SLASH_POOL: Lazy<Mutex<Vec<Address>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Report a validator that must be slashed.
///
/// The same address will be stored only once per block to avoid duplicate
/// system-transactions.
pub fn report(validator: Address) {
    let mut pool = SLASH_POOL.lock().expect("slash pool poisoned");
    if !pool.contains(&validator) {
        pool.push(validator);
    }
}

/// Drains all pending slashing evidences, returning the list. The returned
/// vector has no particular ordering guarantee.
pub fn drain() -> Vec<Address> {
    SLASH_POOL
        .lock()
        .expect("slash pool poisoned")
        .drain(..)
        .collect()
} 