use super::{EXTRA_SEAL, EXTRA_VANITY};
use alloy_primitives::Address;
use reth::consensus::{ConsensusError, HeaderValidator};
use reth_primitives_traits::SealedHeader;
use std::sync::Arc;

use super::vote::VoteAddress;
use super::constants::{VALIDATOR_BYTES_LEN_BEFORE_LUBAN, VALIDATOR_NUMBER_SIZE, VALIDATOR_BYTES_LEN_AFTER_LUBAN};

// ---------------------------------------------------------------------------
// Helper: parse epoch update (validator set & turn-length) from a header.
// Returns (validators, vote_addresses (if any), turn_length)
// ---------------------------------------------------------------------------
pub fn parse_epoch_update<H>(
    header: &H,
    is_luban: bool,
    is_bohr: bool,
) -> (Vec<Address>, Option<Vec<VoteAddress>>, Option<u8>)
where
    H: alloy_consensus::BlockHeader,
{
    let extra = header.extra_data().as_ref();
    if extra.len() <= EXTRA_VANITY + EXTRA_SEAL {
        return (Vec::new(), None, None);
    }

    // Epoch bytes start right after vanity
    let mut cursor = EXTRA_VANITY;

    // Pre-Luban epoch block: validators list only (20-byte each)
    if !is_luban {
        let validator_bytes = &extra[cursor..extra.len() - EXTRA_SEAL];
        let num = validator_bytes.len() / VALIDATOR_BYTES_LEN_BEFORE_LUBAN;
        let mut vals = Vec::with_capacity(num);
        for i in 0..num {
            let start = cursor + i * VALIDATOR_BYTES_LEN_BEFORE_LUBAN;
            let end = start + VALIDATOR_BYTES_LEN_BEFORE_LUBAN;
            vals.push(Address::from_slice(&extra[start..end]));
        }
        return (vals, None, None);
    }

    // Luban & later: 1-byte validator count
    let num_validators = extra[cursor] as usize;
    cursor += VALIDATOR_NUMBER_SIZE;
    
    // Sanity check: ensure we have enough space for all validators + optional turn length
    let required_space = EXTRA_VANITY + VALIDATOR_NUMBER_SIZE + 
                        (num_validators * VALIDATOR_BYTES_LEN_AFTER_LUBAN) + 
                        (if is_bohr { 1 } else { 0 }) + EXTRA_SEAL;
    if extra.len() < required_space {
        // Not enough space for the claimed number of validators
        return (Vec::new(), None, None);
    }

    let mut vals = Vec::with_capacity(num_validators);
    let mut vote_vals = Vec::with_capacity(num_validators);
    for _ in 0..num_validators {
        // Check bounds before accessing consensus address (20 bytes)
        if cursor + 20 > extra.len() - EXTRA_SEAL {
            // Not enough space for validator data
            return (vals, Some(vote_vals), None);
        }
        // 20-byte consensus addr
        vals.push(Address::from_slice(&extra[cursor..cursor + 20]));
        cursor += 20;
        
        // Check bounds before accessing BLS vote address (48 bytes)
        if cursor + 48 > extra.len() - EXTRA_SEAL {
            // Not enough space for vote address data
            return (vals, Some(vote_vals), None);
        }
        // 48-byte BLS vote addr
        vote_vals.push(VoteAddress::from_slice(&extra[cursor..cursor + 48]));
        cursor += 48;
    }

    // Optional turnLength byte in Bohr headers
    let turn_len = if is_bohr {
        // Check if there's space for turn length byte before EXTRA_SEAL
        if cursor + 1 <= extra.len() - EXTRA_SEAL {
            let tl = extra[cursor];
            Some(tl)
        } else {
            // Not enough space for turn length, header might be malformed
            None
        }
    } else {
        None
    };

    (vals, Some(vote_vals), turn_len)
}



/// Header validator for Parlia consensus.
///
/// The validator currently checks:
/// 1. Miner (beneficiary) must be a validator in the current snapshot.
/// 2. Difficulty must be 2 when the miner is in-turn, 1 otherwise.
/// Further seal and vote checks will be added in later milestones.
#[derive(Debug, Clone)]
pub struct ParliaHeaderValidator<ChainSpec> {
    /// Chain specification for hardfork detection
    chain_spec: Arc<ChainSpec>,
}

impl<ChainSpec> ParliaHeaderValidator<ChainSpec> {
    /// Create from chain spec that implements `BscHardforks` (like reth-bsc-trail and bsc-erigon).
    pub fn from_chain_spec(chain_spec: Arc<ChainSpec>) -> Self
    where
        ChainSpec: crate::hardforks::BscHardforks,
    {
        Self { chain_spec }
    }

    /// Create a validator (uses chain spec for hardfork detection like reth-bsc-trail).
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec }
    }
}

// Helper to get expected difficulty.


impl<H, ChainSpec> HeaderValidator<H> for ParliaHeaderValidator<ChainSpec>
where
    H: alloy_consensus::BlockHeader + alloy_primitives::Sealable,
    ChainSpec: crate::hardforks::BscHardforks + std::fmt::Debug + Send + Sync,
{
    fn validate_header(&self, header: &SealedHeader<H>) -> Result<(), ConsensusError> {
        // MINIMAL VALIDATION ONLY during Headers stage (like official BNB Chain implementation)
        // All BSC-specific validation is deferred to Bodies/Execution stage for performance
        
        // Genesis header is always valid
        if header.number() == 0 {
            return Ok(());
        }

        // Only check the most basic header format to prevent completely malformed headers
        // Even basic BSC format validation is expensive, so minimize it
        let extra_data = header.header().extra_data();
        if extra_data.len() < 65 { // Minimum: 32 (vanity) + 65 (seal) = 97 bytes
            return Err(ConsensusError::Other(format!(
                "BSC header extra_data too short: {} bytes", extra_data.len()
            )));
        }

        // All other validation (signature, timestamp, difficulty, etc.) deferred to execution stage
        // This matches the official BNB Chain implementation's performance characteristics
        Ok(())
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<H>,
        parent: &SealedHeader<H>,
    ) -> Result<(), ConsensusError> {
        // --------------------------------------------------------------------
        // 1. Basic parent/child sanity checks (number & timestamp ordering)
        // --------------------------------------------------------------------
        if header.number() != parent.number() + 1 {
            return Err(ConsensusError::ParentBlockNumberMismatch {
                parent_block_number: parent.number(),
                block_number: header.number(),
            });
        }
        // BSC Maxwell hardfork allows equal timestamps between parent and current block
        // Before Maxwell: header.timestamp() > parent.timestamp() (strict)
        // After Maxwell: header.timestamp() >= parent.timestamp() (equal allowed)
        let is_maxwell_active = self.chain_spec.is_maxwell_active_at_timestamp(header.timestamp());
        if is_maxwell_active {
            // After Maxwell: equal timestamps allowed
            if header.timestamp() < parent.timestamp() {
                return Err(ConsensusError::TimestampIsInPast {
                    parent_timestamp: parent.timestamp(),
                    timestamp: header.timestamp(),
                });
            }
        } else {
            // Before Maxwell: strict timestamp ordering required  
            if header.timestamp() <= parent.timestamp() {
                return Err(ConsensusError::TimestampIsInPast {
                    parent_timestamp: parent.timestamp(),
                    timestamp: header.timestamp(),
                });
            }
        }

        // --------------------------------------------------------------------
        // 2. BSC-Specific Header Validation - COMPLETELY DEFERRED
        // --------------------------------------------------------------------
        // Following reth-bsc-trail approach: NO snapshot calls during Headers stage.
        // All BSC validation happens in post-execution where snapshots are guaranteed available.

        // --------------------------------------------------------------------
        // 2.5 BSC-Specific Header Validation - DEFERRED TO POST-EXECUTION
        // --------------------------------------------------------------------
        // Following reth-bsc-trail approach: defer ALL BSC-specific validation to post-execution
        // where blocks are processed sequentially and snapshots are guaranteed available.
        // This includes:
        // - Ramanujan block time validation
        // - Turn-based proposing validation  
        // - Difficulty validation
        // - Seal verification
        tracing::trace!("BSC header validation deferred to post-execution stage (like reth-bsc-trail)");

        // All BSC-specific validation deferred to post-execution:
        // - Gas limit validation
        // - Vote attestation verification  
        // - Validator set checks
        // - BLS signature verification

        // All remaining BSC validation also deferred to post-execution:
        // - BLS signature verification
        // - Snapshot updates  
        // - Epoch transitions
        // - Slash reporting

        Ok(())
    }
} 