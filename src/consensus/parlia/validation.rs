//! BSC consensus validation logic ported from reth-bsc-trail
//! 
//! This module contains the pre-execution and post-execution validation
//! logic that was missing from our initial implementation.

use super::snapshot::Snapshot;
use crate::hardforks::BscHardforks;
use alloy_primitives::{Address, B256, U256};
use alloy_consensus::BlockHeader;
use reth::consensus::ConsensusError;
use reth_chainspec::EthChainSpec;
use reth_primitives_traits::SealedHeader;
use std::collections::HashMap;
use std::sync::Arc;
use alloy_primitives::hex;

/// BSC consensus validator that implements the missing pre/post execution logic
#[derive(Debug, Clone)]
pub struct BscConsensusValidator<ChainSpec> {
    chain_spec: Arc<ChainSpec>,
}

impl<ChainSpec> BscConsensusValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + BscHardforks,
{
    /// Create a new BSC consensus validator
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec }
    }

    /// Verify cascading fields before block execution
    /// This is the main pre-execution validation entry point
    pub fn verify_cascading_fields(
        &self,
        header: &SealedHeader,
        parent: &SealedHeader,
        ancestor: Option<&HashMap<B256, SealedHeader>>,
        snap: &Snapshot,
    ) -> Result<(), ConsensusError> {
        self.verify_block_time_for_ramanujan(snap, header, parent)?;
        self.verify_vote_attestation(snap, header, parent, ancestor)?;
        self.verify_seal(snap, header)?;
        Ok(())
    }

    /// Verify block time for Ramanujan fork
    /// After Ramanujan activation, blocks must respect specific timing rules
    fn verify_block_time_for_ramanujan(
        &self,
        snapshot: &Snapshot,
        header: &SealedHeader,
        parent: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        if self.chain_spec.is_ramanujan_active_at_block(header.number()) {
            let block_interval = snapshot.block_interval;
            let back_off_time = self.calculate_back_off_time(snapshot, header);
            
            if header.timestamp() < parent.timestamp() + block_interval + back_off_time {
                return Err(ConsensusError::Other(format!(
                    "Block time validation failed for Ramanujan fork: block {} timestamp {} too early",
                    header.number(),
                    header.timestamp()
                )));
            }
        }
        Ok(())
    }

    /// Calculate back-off time based on validator turn status
    fn calculate_back_off_time(&self, snapshot: &Snapshot, header: &SealedHeader) -> u64 {
        let validator = header.beneficiary();
        let is_inturn = snapshot.inturn_validator() == validator;
        
        if is_inturn {
            0
        } else {
            // Out-of-turn validators must wait longer
            let turn_length = snapshot.turn_length.unwrap_or(1) as u64;
            turn_length * snapshot.block_interval / 2
        }
    }

    /// Verify vote attestation (currently placeholder - actual BLS verification already implemented)
    fn verify_vote_attestation(
        &self,
        _snapshot: &Snapshot,
        _header: &SealedHeader,
        _parent: &SealedHeader,
        _ancestor: Option<&HashMap<B256, SealedHeader>>,
    ) -> Result<(), ConsensusError> {
        // Note: Vote attestation verification is already implemented in our header validator
        // This is a placeholder for any additional vote attestation checks that might be needed
        Ok(())
    }

    /// Verify ECDSA signature seal
    /// This checks that the header was signed by the expected validator
    fn verify_seal(&self, snapshot: &Snapshot, header: &SealedHeader) -> Result<(), ConsensusError> {
        let proposer = self.recover_proposer_from_seal(header)?;
        
        if proposer != header.beneficiary() {
            return Err(ConsensusError::Other(format!(
                "Wrong header signer: expected {}, got {}",
                header.beneficiary(),
                proposer
            )));
        }

        if !snapshot.validators.contains(&proposer) {
            return Err(ConsensusError::Other(format!(
                "Signer {} not authorized",
                proposer
            )));
        }

        if snapshot.sign_recently(proposer) {
            return Err(ConsensusError::Other(format!(
                "Signer {} over limit",
                proposer
            )));
        }

        // Check difficulty matches validator turn status
        let is_inturn = snapshot.inturn_validator() == proposer;
        let expected_difficulty = if is_inturn { 2u64 } else { 1u64 };
        
        if header.difficulty() != U256::from(expected_difficulty) {
            return Err(ConsensusError::Other(format!(
                "Invalid difficulty: expected {}, got {}",
                expected_difficulty,
                header.difficulty()
            )));
        }

        Ok(())
    }


    
    /// Recover proposer address from header seal (ECDSA signature recovery)
    /// Following bsc-erigon's approach exactly
    pub fn recover_proposer_from_seal(&self, header: &SealedHeader) -> Result<Address, ConsensusError> {
        use secp256k1::{ecdsa::{RecoverableSignature, RecoveryId}, Message, SECP256K1};
        
        // Extract seal from extra data (last 65 bytes) - matching bsc-erigon extraSeal
        let extra_data = &header.extra_data();
        if extra_data.len() < 65 {
            return Err(ConsensusError::Other("Invalid seal: extra data too short".into()));
        }
        
        let signature = &extra_data[extra_data.len() - 65..];
        
        // Create the seal hash for signature verification (matching bsc-erigon's SealHash)
        let seal_hash = self.calculate_seal_hash(header);
        let message = Message::from_digest(seal_hash.0);
        
        // DEBUG: Add detailed logging for signature extraction
        tracing::debug!(
            "🔐 [BSC] Signature extraction for block {}: extra_data_len={}, signature_len={}, signature_hex={}",
            header.number(),
            extra_data.len(),
            signature.len(),
            hex::encode(signature)
        );
        
        // DEBUG: Extra verification of slice bounds
        let expected_signature_start = extra_data.len() - 65;
        tracing::debug!(
            "🔐 [BSC] Signature slice bounds for block {}: expected_start={}, actual_slice_len={}, extra_last_10_bytes={}",
            header.number(),
            expected_signature_start,
            signature.len(),
            hex::encode(&extra_data[extra_data.len().saturating_sub(10)..])
        );
        
        // Parse signature: 64 bytes + 1 recovery byte
        if signature.len() != 65 {
            return Err(ConsensusError::Other(format!("Invalid signature length: expected 65, got {}", signature.len()).into()));
        }
        
        let sig_bytes = &signature[..64];
        let recovery_id = signature[64];
        
        // DEBUG: Verify the slicing worked correctly
        tracing::debug!(
            "🔐 [BSC] Signature parsing for block {}: sig_bytes_len={}, recovery_id={}, sig_bytes_hex={}",
            header.number(),
            sig_bytes.len(),
            recovery_id,
            hex::encode(sig_bytes)
        );
        
        // (Removed duplicate debug line - using the new one above instead)
        
        // Handle recovery ID (bsc-erigon compatible)
        let recovery_id = RecoveryId::from_i32(recovery_id as i32)
            .map_err(|_| ConsensusError::Other("Invalid recovery ID".into()))?;
            
        let recoverable_sig = RecoverableSignature::from_compact(sig_bytes, recovery_id)
            .map_err(|_| ConsensusError::Other("Invalid signature format".into()))?;
        
        // Recover public key and derive address (matching bsc-erigon's crypto.Keccak256)
        let public_key = SECP256K1.recover_ecdsa(&message, &recoverable_sig)
            .map_err(|_| ConsensusError::Other("Failed to recover public key".into()))?;
            
        // Convert to address: keccak256(pubkey[1:])[12:]
        use alloy_primitives::keccak256;
        let public_key_bytes = public_key.serialize_uncompressed();
        let hash = keccak256(&public_key_bytes[1..]); // Skip 0x04 prefix
        let address = Address::from_slice(&hash[12..]);
        
        tracing::debug!(
            "🔐 [BSC] Seal recovery result for block {}: recovered_address={}, expected_miner={}, match={}",
            header.number(),
            address,
            header.beneficiary(),
            address == header.beneficiary()
        );
        
        Ok(address)
    }
    
    /// Calculate seal hash for BSC headers (matching bsc-erigon's EncodeSigHeader exactly)
    fn calculate_seal_hash(&self, header: &SealedHeader) -> alloy_primitives::B256 {
        use alloy_primitives::keccak256;
        
        // Use the exact same approach as bsc-erigon's EncodeSigHeader
        const EXTRA_SEAL: usize = 65;
        
        let chain_id = self.chain_spec.chain().id();
        let extra_data = &header.extra_data();
        
        // Extract extra data without the seal (matching bsc-erigon line 1761)
        let extra_without_seal = if extra_data.len() >= EXTRA_SEAL {
            &extra_data[..extra_data.len() - EXTRA_SEAL]
        } else {
            extra_data
        };
        
        // Encode directly as slice like bsc-erigon does (NOT using SealContent struct)
        // This matches bsc-erigon's EncodeSigHeader function exactly
        
        // Create a custom struct that exactly matches bsc-erigon's field ordering
        #[derive(alloy_rlp::RlpEncodable)]
        struct HeaderForSeal {
            chain_id: u64,
            parent_hash: alloy_primitives::B256,
            ommers_hash: alloy_primitives::B256,
            beneficiary: alloy_primitives::Address,
            state_root: alloy_primitives::B256,
            transactions_root: alloy_primitives::B256,
            receipts_root: alloy_primitives::B256,
            logs_bloom: alloy_primitives::Bloom,
            difficulty: alloy_primitives::U256,
            number: u64,
            gas_limit: u64,
            gas_used: u64,
            timestamp: u64,
            extra_data: alloy_primitives::Bytes,
            mix_hash: alloy_primitives::B256,
            nonce: u64,
        }
        
        let header_for_seal = HeaderForSeal {
            chain_id,
            parent_hash: header.parent_hash(),
            ommers_hash: header.ommers_hash(),
            beneficiary: header.beneficiary(),
            state_root: header.state_root(),
            transactions_root: header.transactions_root(),
            receipts_root: header.receipts_root(),
            logs_bloom: header.logs_bloom(),
            difficulty: header.difficulty(),
            number: header.number(),
            gas_limit: header.gas_limit(),
            gas_used: header.gas_used(),
            timestamp: header.timestamp(),
            extra_data: alloy_primitives::Bytes::from(extra_without_seal.to_vec()),
            mix_hash: header.mix_hash().unwrap_or_default(),
            nonce: header.nonce().unwrap_or_default().into(),
        };
        
        // Debug logging for seal hash calculation
        tracing::debug!(
            "🔐 [BSC] Seal hash calculation for block {}: chain_id={}, extra_len={}, extra_without_seal_len={}",
            header.number(),
            chain_id,
            extra_data.len(),
            extra_without_seal.len()
        );
        
        let encoded = alloy_rlp::encode(&header_for_seal);
        let result = keccak256(&encoded);
        
        tracing::debug!(
            "🔐 [BSC] Seal hash result for block {}: hash={:?}, encoded_len={}",
            header.number(),
            result,
            encoded.len()
        );
        
        result
    }
}

/// Post-execution validation logic
impl<ChainSpec> BscConsensusValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + BscHardforks,
{
    /// Verify validators at epoch boundaries
    /// This checks that the validator set in the header matches the expected set
    pub fn verify_validators(
        &self,
        current_validators: Option<(Vec<Address>, HashMap<Address, super::vote::VoteAddress>)>,
        header: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        let number = header.number();
        
        // Only check at epoch boundaries
        if number % 200 != 0 {  // BSC epoch is 200 blocks
            return Ok(());
        }

        let (mut validators, vote_addrs_map) = current_validators
            .ok_or_else(|| ConsensusError::Other("Invalid current validators data".to_string()))?;
            
        validators.sort();
        
        // For post-Luban blocks, extract validator bytes from header and compare
        if self.chain_spec.is_luban_active_at_block(number) {
            let validator_bytes: Vec<u8> = validators
                .iter()
                .flat_map(|v| {
                    let mut bytes = v.to_vec();
                    if let Some(vote_addr) = vote_addrs_map.get(v) {
                        bytes.extend_from_slice(vote_addr.as_ref());
                    }
                    bytes
                })
                .collect();
                
            // Extract expected bytes from header extra data
            let expected = self.get_validator_bytes_from_header(header)?;
            
            if validator_bytes != expected {
                return Err(ConsensusError::Other(format!(
                    "Validator set mismatch at block {}",
                    number
                )));
            }
        }
        
        Ok(())
    }



    /// Extract validator bytes from header extra data
    fn get_validator_bytes_from_header(&self, header: &SealedHeader) -> Result<Vec<u8>, ConsensusError> {
        let extra_data = header.extra_data();
        const EXTRA_VANITY_LEN: usize = 32;
        const EXTRA_SEAL_LEN: usize = 65;
        
        if extra_data.len() <= EXTRA_VANITY_LEN + EXTRA_SEAL_LEN {
            return Ok(Vec::new());
        }
        
        let validator_bytes_len = extra_data.len() - EXTRA_VANITY_LEN - EXTRA_SEAL_LEN;
        let validator_bytes = extra_data[EXTRA_VANITY_LEN..EXTRA_VANITY_LEN + validator_bytes_len].to_vec();
        
        Ok(validator_bytes)
    }
} 