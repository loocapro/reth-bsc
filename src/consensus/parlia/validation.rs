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
        
        // Parse signature: 64 bytes + 1 recovery byte
        let sig_bytes = &signature[..64];
        let recovery_id = signature[64];
        
        // DEBUG: Add detailed logging for signature recovery
        tracing::debug!(
            "🔐 [BSC] Seal recovery for block {}: extra_data_len={}, seal_hash={:?}, recovery_id={}, sig_bytes_len={}, expected_miner={}",
            header.number(),
            extra_data.len(),
            seal_hash,
            recovery_id,
            sig_bytes.len(),
            header.beneficiary()
        );
        
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
        
        // Create a vector of all the fields to encode (matching Go's []interface{})
        let fields = vec![
            alloy_rlp::encode(&chain_id),
            alloy_rlp::encode(&header.parent_hash()),
            alloy_rlp::encode(&header.ommers_hash()),
            alloy_rlp::encode(&header.beneficiary()),
            alloy_rlp::encode(&header.state_root()),
            alloy_rlp::encode(&header.transactions_root()),
            alloy_rlp::encode(&header.receipts_root()),
            alloy_rlp::encode(&header.logs_bloom()),
            alloy_rlp::encode(&header.difficulty()),
            alloy_rlp::encode(&header.number()),
            alloy_rlp::encode(&header.gas_limit()),
            alloy_rlp::encode(&header.gas_used()),
            alloy_rlp::encode(&header.timestamp()),
            alloy_rlp::encode(&alloy_primitives::Bytes::from(extra_without_seal.to_vec())),
            alloy_rlp::encode(&header.mix_hash().unwrap_or_default()),
            alloy_rlp::encode(&header.nonce().unwrap_or_default()),
        ];
        
        // Debug logging for seal hash calculation
        tracing::debug!(
            "🔐 [BSC] Seal hash calculation for block {}: chain_id={}, extra_len={}, extra_without_seal_len={}",
            header.number(),
            chain_id,
            extra_data.len(),
            extra_without_seal.len()
        );
        
        // Encode the list of fields (matching bsc-erigon's []interface{} encoding)
        let encoded = alloy_rlp::encode(&fields);
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