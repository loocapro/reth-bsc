use std::collections::{BTreeMap, HashMap};

//use crate::consensus::parlia::TURN_LENGTH_SIZE;

use super::vote::{VoteAddress, VoteAttestation, VoteData};
use alloy_primitives::{Address, BlockNumber, B256};
use serde::{Deserialize, Serialize};
use reth_db::table::{Compress, Decompress};
use reth_db::DatabaseError;

/// Number of blocks after which we persist snapshots to DB.
pub const CHECKPOINT_INTERVAL: u64 = 1024;

// ---------------------------------------------------------------------------
// Hard-fork constants (kept in sync with bsc_official/parlia.go)
// ---------------------------------------------------------------------------

/// Default settings prior to Lorentz.
pub const DEFAULT_EPOCH_LENGTH: u64 = 200;
pub const DEFAULT_TURN_LENGTH: u8 = 1;

/// Lorentz hard-fork parameters.
pub const LORENTZ_EPOCH_LENGTH: u64 = 500;
pub const LORENTZ_TURN_LENGTH: u8 = 8;

/// Maxwell hard-fork parameters.
pub const MAXWELL_EPOCH_LENGTH: u64 = 1000;
pub const MAXWELL_TURN_LENGTH: u8 = 16;

pub const DEFAULT_BLOCK_INTERVAL: u64 = 3000;   // 3000 ms
pub const LORENTZ_BLOCK_INTERVAL: u64 = 1500;   // 1500 ms
pub const MAXWELL_BLOCK_INTERVAL: u64 = 750;   //  750 ms

/// `ValidatorInfo` holds metadata for a validator at a given epoch.
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// 1-based index (offset by +1) within `validators` list.
    pub index: u64,
    /// Validator's BLS vote address (optional before Bohr upgrade; zero bytes if unknown).
    pub vote_addr: VoteAddress,
}

/// In-memory snapshot of Parlia epoch state.
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Current epoch length. (200 for legacy, changes after Bohr).
    pub epoch_num: u64,
    /// Block number of the epoch boundary.
    pub block_number: BlockNumber,
    /// Hash of that block.
    pub block_hash: B256,
    /// Sorted validator set (ascending by address).
    pub validators: Vec<Address>,
    /// Extra information about validators (index + vote addr).
    pub validators_map: HashMap<Address, ValidatorInfo>,
    /// Map of recent proposers: block → proposer address.
    pub recent_proposers: BTreeMap<BlockNumber, Address>,
    /// Latest vote data attested by the validator set.
    pub vote_data: VoteData,
    /// Configurable turn-length (default = 1 before Bohr).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_length: Option<u8>,

    /// Expected block interval in milliseconds.
    pub block_interval: u64,
}

impl Snapshot {
    /// Creates a new empty snapshot with given validators.
    /// Create a brand-new snapshot at an epoch boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mut validators: Vec<Address>,
        block_number: BlockNumber,
        block_hash: B256,
        epoch_num: u64,
        vote_addrs: Option<Vec<VoteAddress>>, // one-to-one with `validators`
    ) -> Self {
        // Ensure epoch_num is never zero to prevent division by zero errors
        let epoch_num = if epoch_num == 0 { DEFAULT_EPOCH_LENGTH } else { epoch_num };
        
        // Keep validators sorted.
        validators.sort();

        let mut validators_map = HashMap::new();
        if let Some(vote_addrs) = vote_addrs {
            assert_eq!(
                validators.len(),
                vote_addrs.len(),
                "validators and vote_addrs length not equal",
            );

            for (i, v) in validators.iter().enumerate() {
                let info = ValidatorInfo { index: i as u64 + 1, vote_addr: vote_addrs[i] };
                validators_map.insert(*v, info);
            }
        } else {
            // Pre-Bohr, vote addresses are unknown.
            for v in &validators {
                validators_map.insert(*v, Default::default());
            }
        }

        Self {
            epoch_num,
            block_number,
            block_hash,
            validators,
            validators_map,
            recent_proposers: Default::default(),
            vote_data: Default::default(),
            turn_length: Some(DEFAULT_TURN_LENGTH),
            block_interval: DEFAULT_BLOCK_INTERVAL,
        }
    }

    /// Apply the next block to the snapshot
    #[allow(clippy::too_many_arguments)]
    pub fn apply<H, ChainSpec>(
        &self,
        validator: Address,
        next_header: &H,
        mut new_validators: Vec<Address>,
        vote_addrs: Option<Vec<VoteAddress>>,
        attestation: Option<VoteAttestation>,
        turn_length: Option<u8>,
        chain_spec: &ChainSpec,
    ) -> Option<Self>
    where
        H: alloy_consensus::BlockHeader + alloy_primitives::Sealable,
        ChainSpec: crate::hardforks::BscHardforks,
    {
        let block_number = next_header.number();
        if self.block_number + 1 != block_number {
            return None; // non-continuous block
        }

        // Clone base.
        let mut snap = self.clone();
        snap.block_hash = next_header.hash_slow();
        snap.block_number = block_number;

        // Maintain recent proposer window.
        let limit = self.miner_history_check_len() + 1;
        if block_number >= limit {
            snap.recent_proposers.remove(&(block_number - limit));
        }

        // Validate proposer belongs to validator set and hasn't over-proposed.
        if !snap.validators.contains(&validator) {
            return None;
        }

        let header_timestamp = next_header.timestamp();
        let is_bohr = chain_spec.is_bohr_active_at_timestamp(header_timestamp);
        if is_bohr {
            if snap.sign_recently(validator) {
                tracing::warn!("Failed to apply block due to over-proposed, validator: {:?}, block_number: {:?}", validator, block_number);
                return None;
            }
        } else {
            for (_, &v) in &snap.recent_proposers {
                if v == validator {
                    tracing::warn!("Failed to apply block due to over-proposed, validator: {:?}, block_number: {:?}", validator, block_number);
                    return None;
                }
            }
        }
        snap.update_attestation(next_header, attestation);
        snap.recent_proposers.insert(block_number, validator);

        let is_maxwell_active = chain_spec.is_maxwell_active_at_timestamp(header_timestamp);
        if is_maxwell_active {
            let latest_finalized_block_number = snap.get_finalized_number();
			// BEP-524: Clear entries up to the latest finalized block
			let blocks_to_remove: Vec<u64> = snap.recent_proposers.keys()
				.filter(|&&block_number| block_number <= latest_finalized_block_number)
				.copied()
				.collect();
			for block_number in blocks_to_remove {
				snap.recent_proposers.remove(&block_number);
			}
        }

        let is_lorentz_active = chain_spec.is_lorentz_active_at_timestamp(header_timestamp);
        if is_maxwell_active {
            snap.block_interval = MAXWELL_BLOCK_INTERVAL;
        } else if is_lorentz_active {
            snap.block_interval = LORENTZ_BLOCK_INTERVAL;
        }

        let epoch_length = snap.epoch_num;
        let next_block_number = block_number + 1;
        if snap.epoch_num == DEFAULT_EPOCH_LENGTH && is_lorentz_active && next_block_number % LORENTZ_EPOCH_LENGTH == 0 {
            snap.epoch_num = LORENTZ_EPOCH_LENGTH;
        }
        if snap.epoch_num == LORENTZ_EPOCH_LENGTH && is_maxwell_active && next_block_number % MAXWELL_EPOCH_LENGTH == 0 {
            snap.epoch_num = MAXWELL_EPOCH_LENGTH;
        }

        // change validator set
        let epoch_key = u64::MAX - block_number / epoch_length;
        if !new_validators.is_empty() && (!is_bohr || !snap.recent_proposers.contains_key(&epoch_key)) {
            // Epoch change driven by new validator set / checkpoint header.
            new_validators.sort();
            if let Some(tl) = turn_length { snap.turn_length = Some(tl) }

            if is_bohr {
                // BEP-404: Clear Miner History when Switching Validators Set
                snap.recent_proposers = Default::default();
                snap.recent_proposers.insert(epoch_key, Address::default());
            } else {
                let old_limit = (snap.validators.len() / 2 + 1) as usize;
                let new_limit = (new_validators.len() / 2 + 1) as usize;
                if new_limit < old_limit {
                    for i in 0..(old_limit - new_limit) {
                        snap.recent_proposers.remove(&(block_number as u64 - new_limit as u64 - i as u64));
                    }
                }
            }

            // Build new validators map.
            let mut validators_map = HashMap::new();
            if let Some(vote_addrs) = vote_addrs {
                assert_eq!(
                    new_validators.len(),
                    vote_addrs.len(),
                    "validators and vote_addrs length not equal",
                );

                for (i, v) in new_validators.iter().enumerate() {
                    validators_map.insert(*v, ValidatorInfo { index: i as u64 + 1, vote_addr: vote_addrs[i] });
                }
            } else {
                for v in &new_validators { validators_map.insert(*v, Default::default()); }
            }
            snap.validators = new_validators;
            snap.validators_map = validators_map;
        }
        Some(snap)
    }

    pub fn update_attestation<H>(&mut self, header: &H, attestation: Option<VoteAttestation>)
    where
        H: alloy_consensus::BlockHeader + alloy_primitives::Sealable,
    {
        if let Some(att) = attestation {
            let target_number = att.data.target_number;
            let target_hash = att.data.target_hash;
            if target_number+1 != header.number() || target_hash != header.parent_hash() {
                tracing::warn!("Failed to update attestation, target_number: {:?}, target_hash: {:?}, header_number: {:?}, header_parent_hash: {:?}", target_number, target_hash, header.number(), header.parent_hash());
                return;
            }
            if att.data.source_number+1 != att.data.target_number {
                self.vote_data.target_number = att.data.target_number;
                self.vote_data.target_hash = att.data.target_hash;
            } else {
                self.vote_data = att.data;
            }
        }
    }

    /// Returns `true` if `proposer` is in-turn according to snapshot rules.
    pub fn is_inturn(&self, proposer: Address) -> bool { 
        let inturn_val = self.inturn_validator();
        let is_inturn = inturn_val == proposer;
        
        if !is_inturn {
            tracing::debug!(
                "🎯 [BSC] is_inturn check: proposer=0x{:x}, inturn_validator=0x{:x}, is_inturn={}, validators={:?}",
                proposer, inturn_val, is_inturn, self.validators
            );
        }
        
        is_inturn
    }

    /// Number of blocks to look back when checking proposer history.
    pub fn miner_history_check_len(&self) -> u64 {
        let turn = u64::from(self.turn_length.unwrap_or(1));
        (self.validators.len() / 2 + 1) as u64 * turn - 1
    }

    /// Validator that should propose the **next** block.
    pub fn inturn_validator(&self) -> Address {
        let turn_length = u64::from(self.turn_length.unwrap_or(DEFAULT_TURN_LENGTH));
        let next_block = self.block_number + 1;
        let offset = (next_block / turn_length) as usize % self.validators.len();
        let next_validator = self.validators[offset];
        
        tracing::debug!(
            "inturn_validator debug info, snapshot_block={}, next_block={}, turn_length={}, offset={}, validators_len={}, next_validator=0x{:x}",
            self.block_number, next_block, turn_length, offset, self.validators.len(), next_validator
        );
        
        next_validator
    }

    /// Returns index in `validators` for `validator` if present.
    pub fn index_of(&self, validator: Address) -> Option<usize> {
        self.validators.iter().position(|&v| v == validator)
    }

    /// Count how many times each validator has signed in the recent window.
    pub fn count_recent_proposers(&self) -> HashMap<Address, u8> {
        let left_bound = if self.block_number > self.miner_history_check_len() {
            self.block_number - self.miner_history_check_len()
        } else { 0 };
        let mut counts = HashMap::new();
        for (&block, &v) in &self.recent_proposers {
            if block <= left_bound || v == Address::default() { continue; }
            *counts.entry(v).or_insert(0) += 1;
        }
        counts
    }

    /// Returns `true` if `validator` has signed too many blocks recently.
    pub fn sign_recently(&self, validator: Address) -> bool {
        self.sign_recently_by_counts(validator, &self.count_recent_proposers())
    }

    /// Helper that takes pre-computed counts.
    pub fn sign_recently_by_counts(&self, validator: Address, counts: &HashMap<Address, u8>) -> bool {
        if let Some(&times) = counts.get(&validator) {
            let allowed = u64::from(self.turn_length.unwrap_or(1));
            if u64::from(times) >= allowed { 
                tracing::warn!("Recently signed, validator: {:?}, block_number: {:?}, times: {:?}, allowed: {:?}", validator, self.block_number, times, allowed);
                return true; 
            }
        }
        false
    }

    pub fn get_finalized_number(&self) -> BlockNumber {
        if self.vote_data.source_number > 0 {
            self.vote_data.source_number
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// DB compression helpers (same approach as reth-bsc-trail)
// ---------------------------------------------------------------------------

impl Compress for Snapshot {
    type Compressed = Vec<u8>;

    fn compress(self) -> Self::Compressed { serde_cbor::to_vec(&self).expect("serialize Snapshot") }

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let bytes = self.clone().compress();
        buf.put_slice(&bytes);
    }
}

impl Decompress for Snapshot {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        serde_cbor::from_slice(value).map_err(|_| DatabaseError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    fn addr(n: u64) -> Address {
        // simple helper to create distinct addresses with different last byte.
        Address::repeat_byte((n & 0xff) as u8)
    }

    #[test]
    fn sign_recently_detects_over_propose() {
        // three validators
        let validators = vec![addr(1), addr(2), addr(3)];
        let mut snap = Snapshot::new(validators.clone(), 0, B256::ZERO, DEFAULT_EPOCH_LENGTH, None);

        // simulate that validator 1 proposed previous block 0
        snap.recent_proposers.insert(1, addr(1));
        snap.block_number = 1;

        // now at block 1, same validator proposes again -> should be flagged
        assert!(snap.sign_recently(addr(1)));
        // other validator should be fine
        assert!(!snap.sign_recently(addr(2)));
    }

    #[test]
    fn sign_recently_allows_within_limit() {
        let validators = vec![addr(1), addr(2), addr(3)];
        let snap = Snapshot::new(validators, 0, B256::ZERO, DEFAULT_EPOCH_LENGTH, None);
        // no recent entries, validator should be allowed
        assert!(!snap.sign_recently(addr(1)));
    }

    #[test]
    fn test_snapshot_new_with_zero_epoch_num() {
        // Test that creating a snapshot with epoch_num = 0 defaults to DEFAULT_EPOCH_LENGTH
        let validators = vec![address!("0x1234567890123456789012345678901234567890")];
        let block_hash = b256!("0x1234567890123456789012345678901234567890123456789012345678901234");
        
        let snapshot = Snapshot::new(validators.clone(), 0, block_hash, 0, None);
        
        // Should default to DEFAULT_EPOCH_LENGTH, not 0
        assert_eq!(snapshot.epoch_num, DEFAULT_EPOCH_LENGTH);
        assert_ne!(snapshot.epoch_num, 0, "epoch_num should never be zero to prevent division by zero");
    }

    #[test]
    fn test_snapshot_new_with_valid_epoch_num() {
        // Test that creating a snapshot with valid epoch_num preserves the value
        let validators = vec![address!("0x1234567890123456789012345678901234567890")];
        let block_hash = b256!("0x1234567890123456789012345678901234567890123456789012345678901234");
        let custom_epoch = 500u64;
        
        let snapshot = Snapshot::new(validators.clone(), 0, block_hash, custom_epoch, None);
        
        // Should preserve the custom epoch value
        assert_eq!(snapshot.epoch_num, custom_epoch);
    }

    #[test]
    fn test_snapshot_apply_no_division_by_zero() {
        // Test that applying a snapshot with epoch operations doesn't cause division by zero
        let validators = vec![address!("0x1234567890123456789012345678901234567890")];
        let block_hash = b256!("0x1234567890123456789012345678901234567890123456789012345678901234");
        
        // Create snapshot with epoch_num = 0 (should be fixed to DEFAULT_EPOCH_LENGTH)
        let snapshot = Snapshot::new(validators.clone(), 0, block_hash, 0, None);
        
        // Create a mock header for apply operation
        struct MockHeader {
            number: u64,
            beneficiary: Address,
            extra_data: alloy_primitives::Bytes,
        }
        
        impl alloy_consensus::BlockHeader for MockHeader {
            fn number(&self) -> u64 { self.number }
            fn beneficiary(&self) -> Address { self.beneficiary }
            fn gas_limit(&self) -> u64 { 8000000 }
            fn gas_used(&self) -> u64 { 0 }
            fn timestamp(&self) -> u64 { 1000000 }
            fn extra_data(&self) -> &alloy_primitives::Bytes { &self.extra_data }
            fn base_fee_per_gas(&self) -> Option<u64> { None }
            fn difficulty(&self) -> alloy_primitives::U256 { alloy_primitives::U256::from(1) }
            fn transactions_root(&self) -> alloy_primitives::B256 { alloy_primitives::B256::ZERO }
            fn state_root(&self) -> alloy_primitives::B256 { alloy_primitives::B256::ZERO }
            fn receipts_root(&self) -> alloy_primitives::B256 { alloy_primitives::B256::ZERO }
            fn logs_bloom(&self) -> alloy_primitives::Bloom { alloy_primitives::Bloom::ZERO }
            fn parent_hash(&self) -> alloy_primitives::B256 { alloy_primitives::B256::ZERO }
            fn ommers_hash(&self) -> alloy_primitives::B256 { alloy_primitives::B256::ZERO }
            fn withdrawals_root(&self) -> Option<alloy_primitives::B256> { None }
            fn mix_hash(&self) -> Option<alloy_primitives::B256> { None }
            fn nonce(&self) -> Option<alloy_primitives::FixedBytes<8>> { None }
            fn blob_gas_used(&self) -> Option<u64> { None }
            fn excess_blob_gas(&self) -> Option<u64> { None }
            fn parent_beacon_block_root(&self) -> Option<alloy_primitives::B256> { None }
            fn requests_hash(&self) -> Option<alloy_primitives::B256> { None }
        }
        
        impl alloy_primitives::Sealable for MockHeader {
            fn hash_slow(&self) -> alloy_primitives::B256 {
                alloy_primitives::keccak256(format!("mock_header_{}", self.number))
            }
        }
        
        let header = MockHeader {
            number: 1,
            beneficiary: validators[0],
            extra_data: alloy_primitives::Bytes::new(),
        };
        
        // Create a mock chain spec for testing
        use crate::chainspec::{bsc_testnet, BscChainSpec};
        let chain_spec = BscChainSpec::from(bsc_testnet());
        
        // This should not panic due to division by zero
        let result = snapshot.apply(
            validators[0],
            &header,
            vec![], // new_validators
            None,   // vote_addrs
            None,   // attestation
            None,   // turn_length
            &chain_spec,
        );
        
        assert!(result.is_some(), "Apply should succeed without division by zero");
        let new_snapshot = result.unwrap();
        assert_eq!(new_snapshot.block_number, 1);
        assert_ne!(new_snapshot.epoch_num, 0, "Applied snapshot should maintain non-zero epoch_num");
    }

    #[test]
    fn test_inturn_validator_no_division_by_zero() {
        // Test that inturn_validator calculation doesn't cause division by zero
        let validators = vec![
            address!("0x1234567890123456789012345678901234567890"),
            address!("0x2345678901234567890123456789012345678901"),
        ];
        let block_hash = b256!("0x1234567890123456789012345678901234567890123456789012345678901234");
        
        // Create snapshot with epoch_num = 0 (should be fixed)
        let snapshot = Snapshot::new(validators.clone(), 0, block_hash, 0, None);
        
        // This should not panic
        let inturn = snapshot.inturn_validator();
        assert!(validators.contains(&inturn), "Should return a valid validator");
    }

    #[test]
    fn test_miner_history_check_len_no_division_by_zero() {
        // Test that miner_history_check_len calculation works correctly
        let validators = vec![
            address!("0x1234567890123456789012345678901234567890"),
            address!("0x2345678901234567890123456789012345678901"),
        ];
        let block_hash = b256!("0x1234567890123456789012345678901234567890123456789012345678901234");
        
        let snapshot = Snapshot::new(validators.clone(), 0, block_hash, 0, None);
        
        // This should not panic and should return a reasonable value
        let check_len = snapshot.miner_history_check_len();
        assert!(check_len > 0, "Check length should be positive");
    }
} 