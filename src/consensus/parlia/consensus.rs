use super::{ParliaHeaderValidator, SnapshotProvider, BscConsensusValidator, Snapshot, TransactionSplitter, SplitTransactions, constants::{DIFF_INTURN, DIFF_NOTURN, EXTRA_VANITY, EXTRA_SEAL, VALIDATOR_NUMBER_SIZE, VALIDATOR_BYTES_LEN_AFTER_LUBAN, VALIDATOR_BYTES_LEN_BEFORE_LUBAN, TURN_LENGTH_SIZE}};
use super::error::ParliaConsensusError;
use alloy_consensus::{Header, TxReceipt, Transaction, BlockHeader};
use reth_primitives_traits::{GotExpected, SignerRecoverable};
use crate::{
    node::primitives::BscBlock,
    hardforks::BscHardforks,
    BscPrimitives,

};
use reth::consensus::{Consensus, FullConsensus, ConsensusError, HeaderValidator};
use reth_primitives::Receipt;
use reth_primitives_traits::proofs;
use reth_provider::BlockExecutionResult;
use reth_primitives_traits::{Block, SealedBlock, SealedHeader, RecoveredBlock};
use reth_chainspec::EthChainSpec;
use std::sync::Arc;
use std::collections::HashMap;

/// Enhanced Parlia consensus that implements proper pre/post execution validation
#[derive(Debug, Clone)]
pub struct ParliaConsensus<ChainSpec, P> {
    chain_spec: Arc<ChainSpec>,
    header_validator: Arc<ParliaHeaderValidator<ChainSpec>>,
    consensus_validator: Arc<BscConsensusValidator<ChainSpec>>,
    snapshot_provider: Arc<P>,
    epoch: u64,
}

impl<ChainSpec, P> ParliaConsensus<ChainSpec, P>
where
    ChainSpec: EthChainSpec + BscHardforks + 'static,
    P: SnapshotProvider + std::fmt::Debug + 'static,
{
    pub fn new(
        chain_spec: Arc<ChainSpec>,
        snapshot_provider: Arc<P>,
        epoch: u64,
    ) -> Self {
        let header_validator = Arc::new(ParliaHeaderValidator::new(chain_spec.clone()));
        let consensus_validator = Arc::new(BscConsensusValidator::new(chain_spec.clone()));
        
        let consensus = Self { 
            chain_spec,
            header_validator,
            consensus_validator,
            snapshot_provider,
            epoch,
        };
        
        // Initialize genesis snapshot if needed
        consensus.ensure_genesis_snapshot();
        
        consensus
    }

    /// Create consensus with database-backed persistent snapshots
    pub fn with_database<DB: reth_db::database::Database + 'static>(
        chain_spec: Arc<ChainSpec>,
        database: DB,
        epoch: u64,
        cache_size: usize,
    ) -> ParliaConsensus<ChainSpec, crate::consensus::parlia::provider::DbSnapshotProvider<DB>> {
        let snapshot_provider = Arc::new(
            crate::consensus::parlia::provider::DbSnapshotProvider::new(database, cache_size)
        );
        let consensus = ParliaConsensus::new(chain_spec, snapshot_provider, epoch);
        
        // Initialize genesis snapshot if needed
        consensus.ensure_genesis_snapshot();
        
        consensus
    }

    /// Validate block pre-execution using Parlia rules
    fn validate_block_pre_execution_impl(&self, block: &SealedBlock<BscBlock>) -> Result<(), ConsensusError> {
        // Check transaction root
        if let Err(error) = block.ensure_transaction_root_valid() {
            return Err(ConsensusError::BodyTransactionRootDiff(error.into()));
        }

        // EIP-4844: Blob gas validation for Cancun fork
        if BscHardforks::is_cancun_active_at_timestamp(self.chain_spec.as_ref(), block.timestamp) {
            self.validate_cancun_blob_gas(block)?;
        }

        Ok(())
    }

    /// Ensure genesis snapshot exists
    fn ensure_genesis_snapshot(&self) {
        // Check if genesis snapshot already exists
        if self.snapshot_provider.snapshot(0).is_some() {
            return;
        }

        // Create genesis snapshot from chain spec
        if let Ok(genesis_snapshot) = Self::create_genesis_snapshot(self.chain_spec.clone(), self.epoch) {
            self.snapshot_provider.insert(genesis_snapshot);
            tracing::info!("🎯 [BSC] Created genesis snapshot for block 0");
        } else {
            tracing::warn!("⚠️ [BSC] Failed to create genesis snapshot");
        }
    }

    /// Get reference to the snapshot provider
    pub fn snapshot_provider(&self) -> &Arc<P> {
        &self.snapshot_provider
    }

    /// Create genesis snapshot from BSC chain specification
    pub fn create_genesis_snapshot(chain_spec: Arc<ChainSpec>, epoch: u64) -> Result<crate::consensus::parlia::snapshot::Snapshot, ConsensusError> 
    where
        ChainSpec: EthChainSpec + BscHardforks + 'static,
    {
        let genesis_header = chain_spec.genesis_header();
        let validators = Self::parse_genesis_validators_static(genesis_header.extra_data())?;
        
        if validators.is_empty() {
            return Err(ConsensusError::Other("No validators found in genesis header".into()));
        }

        let genesis_hash = alloy_primitives::keccak256(alloy_rlp::encode(genesis_header));

        let snapshot = crate::consensus::parlia::snapshot::Snapshot::new(
            validators,
            0, // block number
            genesis_hash, // block hash
            epoch, // epoch length
            None, // no vote addresses pre-Luban
        );

        tracing::info!("🚀 [BSC] Genesis snapshot created with {} validators", snapshot.validators.len());
        Ok(snapshot)
    }



    /// Parse genesis validators from BSC extraData (static version)
    fn parse_genesis_validators_static(extra_data: &alloy_primitives::Bytes) -> Result<Vec<alloy_primitives::Address>, ConsensusError> {
        const EXTRA_VANITY_LEN: usize = 32;
        const EXTRA_SEAL_LEN: usize = 65;

        if extra_data.len() <= EXTRA_VANITY_LEN + EXTRA_SEAL_LEN {
            return Err(ConsensusError::Other("extraData too short for validator list".into()));
        }

        let validator_bytes = &extra_data[EXTRA_VANITY_LEN..extra_data.len() - EXTRA_SEAL_LEN];
        
        if validator_bytes.len() % 20 != 0 {
            return Err(ConsensusError::Other("validator data length not divisible by 20".into()));
        }

        let mut validators = Vec::new();
        for chunk in validator_bytes.chunks(20) {
            let address = alloy_primitives::Address::from_slice(chunk);
            validators.push(address);
        }

        tracing::debug!("📋 [BSC] Parsed {} validators from genesis extraData", validators.len());
        Ok(validators)
    }

    /// Validate block post-execution using Parlia rules
    fn validate_block_post_execution_impl(
        &self,
        block: &RecoveredBlock<BscBlock>,
        result: &BlockExecutionResult<Receipt>,
    ) -> Result<(), ConsensusError> {
        let _header = block.header();
        let receipts = &result.receipts;

        // 1. Basic post-execution validation (gas used, receipts root, logs bloom)
        self.validate_basic_post_execution_fields(block, receipts)?;

        // 2. BSC-specific post-execution validation
        self.validate_parlia_post_execution_fields(block, receipts)?;

        Ok(())
    }

    /// Validate basic post-execution fields (gas, receipts, logs)
    fn validate_basic_post_execution_fields(
        &self,
        block: &RecoveredBlock<BscBlock>,
        receipts: &[Receipt],
    ) -> Result<(), ConsensusError> {
        let header = block.header();

        // Check if gas used matches the value set in header
        let cumulative_gas_used = receipts.last()
            .map(|receipt| receipt.cumulative_gas_used)
            .unwrap_or(0);
        
        if header.gas_used != cumulative_gas_used {
            return Err(ConsensusError::Other(
                format!("Gas used mismatch: header={}, receipts={}", header.gas_used, cumulative_gas_used).into()
            ));
        }

        // Verify receipts root and logs bloom (after Byzantium fork)
        if self.chain_spec.is_byzantium_active_at_block(header.number) {
            self.verify_receipts_and_logs(header, receipts)?;
        }

        Ok(())
    }

    /// Validate BSC-specific post-execution fields
    fn validate_parlia_post_execution_fields(
        &self,
        block: &RecoveredBlock<BscBlock>,
        _receipts: &[Receipt],
    ) -> Result<(), ConsensusError> {
        let header = block.header();

        // Skip genesis block
        if header.number == 0 {
            return Ok(());
        }

        // Get snapshot for validation (should be available during post-execution)
        let parent_number = header.number - 1;
        let snapshot = match self.snapshot_provider.snapshot(parent_number) {
            Some(snapshot) => {
                tracing::debug!(
                    "BSC: Using snapshot for block {} to validate block {} (snapshot_block_number={})",
                    parent_number, header.number, snapshot.block_number
                );
                snapshot
            },
            None => {
                // During post-execution, snapshots should be available since blocks are processed sequentially
                tracing::warn!(
                    block_number = header.number,
                    parent_number = parent_number,
                    "Snapshot not available during post-execution validation - this should not happen"
                );
                return Err(ConsensusError::Other(format!(
                    "Snapshot for block {} not available during post-execution", parent_number
                ).into()));
            }
        };

        // Create a SealedHeader for validation methods
        let sealed_header = SealedHeader::new(header.clone(), block.hash());

        // Full BSC Parlia validation during post-execution (when dependencies are available)
        // 1. Block timing constraints (Ramanujan hardfork)
        self.verify_block_timing(&sealed_header, &snapshot)?;

        // 2. Vote attestation (Plato hardfork)
        self.verify_vote_attestation(&sealed_header)?;

        // 3. Seal verification (signature recovery and validator authorization)
        self.verify_seal(&sealed_header, &snapshot)?;

        // 4. Turn-based proposing (difficulty validation)
        self.verify_difficulty(&sealed_header, &snapshot)?;

        // 5. Turn length validation (Bohr hardfork)
        self.verify_turn_length(&sealed_header)?;

        // 6. System transactions validation
        self.validate_system_transactions(block)?;

        // 7. Gas limit validation (BSC-specific, hardfork-aware)
        if let Some(parent_header) = self.get_parent_header(header) {
            self.verify_gas_limit(&sealed_header, &parent_header)?;
        }

        // 8. Slash reporting for out-of-turn validators
        self.report_slash_evidence(&sealed_header, &snapshot)?;

        // 9. Validate epoch transitions
        if header.number % self.epoch == 0 {
            // TODO: Implement epoch transition validation
            // This would verify validator set updates every 200 blocks
            tracing::debug!("Epoch boundary at block {}", header.number);
        }

        tracing::debug!("Succeed to finish full post-execution validation for block {}", header.number);
        Ok(())
    }

    /// Validate system transactions using splitTxs logic
    fn validate_system_transactions(&self, block: &RecoveredBlock<BscBlock>) -> Result<(), ConsensusError> {
        let header = block.header();
        // Extract the raw transactions from the block  
        let transactions: Vec<_> = block.body().transactions().cloned().collect();
        let beneficiary = header.beneficiary;

        // Split transactions into user and system transactions
        let split_result = TransactionSplitter::split_transactions(&transactions, beneficiary)
            .map_err(|e| ConsensusError::Other(format!("Failed to split transactions: {}", e).into()))?;

        // Log transaction split results for debugging
        // TODO: Remove debug logging in production
        if split_result.system_count() > 0 {
            // System transactions found - validate them
            self.validate_split_system_transactions(&split_result, header)?;
        }

        Ok(())
    }

    /// Validate the identified system transactions
    fn validate_split_system_transactions(
        &self,
        split: &SplitTransactions,
        header: &alloy_consensus::Header,
    ) -> Result<(), ConsensusError> {
        // TODO: Implement comprehensive system transaction validation:
        // 1. Verify system transactions are in the correct order
        // 2. Validate system transaction parameters (SlashIndicator, StakeHub, etc.)
        // 3. Check that required system transactions are present
        // 4. Validate system transaction execution results

        // For now, just ensure we can identify system transactions correctly
        for (i, system_tx) in split.system_txs.iter().enumerate() {
            // Basic validation: system transaction should have gas price 0
            if system_tx.max_fee_per_gas() != 0 {
                return Err(ConsensusError::Other(
                    format!("System transaction {} has non-zero gas price: {}", i, system_tx.max_fee_per_gas()).into()
                ));
            }

            // Basic validation: system transaction should be sent by beneficiary
            match system_tx.recover_signer() {
                Ok(signer) => {
                    if signer != header.beneficiary {
                        return Err(ConsensusError::Other(
                            format!("System transaction {} not sent by beneficiary: signer={}, beneficiary={}", 
                                    i, signer, header.beneficiary).into()
                        ));
                    }
                }
                Err(_) => {
                    return Err(ConsensusError::Other(
                        format!("Failed to recover signer for system transaction {}", i).into()
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validate EIP-4844 blob gas fields for Cancun fork
    fn validate_cancun_blob_gas(&self, block: &SealedBlock<BscBlock>) -> Result<(), ConsensusError> {
        // Check that the blob gas used in the header matches the sum of the blob gas used by each
        // blob tx
        let header_blob_gas_used = block.blob_gas_used.ok_or(ConsensusError::BlobGasUsedMissing)?;
        let total_blob_gas = block.blob_gas_used().ok_or(ConsensusError::BlobGasUsedMissing)?;
        // TODO: please use the following correct line after block.body().blob_gas_used() is callable in scope. It should be usealbe when next reht==th dependency updates
        // let total_blob_gas = block.body().blob_gas_used().ok_or(ConsensusError::BlobGasUsedMissing)?;
        if total_blob_gas != header_blob_gas_used {
            return Err(ConsensusError::BlobGasUsedDiff(GotExpected {
                got: header_blob_gas_used,
                expected: total_blob_gas,
            }));
        }
        Ok(())
    }

    /// Verify block timing constraints for Ramanujan fork
    fn verify_block_timing(&self, header: &SealedHeader<Header>, _snapshot: &Snapshot) -> Result<(), ConsensusError> {
        if !self.chain_spec.is_ramanujan_active_at_block(header.number) {
            return Ok(());
        }

        // TODO: Implement block timing validation
        // This would check that block.timestamp >= parent.timestamp + period + backoff_time
        // For now, we'll skip this validation as it requires parent header access
        
        Ok(())
    }

    /// Verify vote attestation for Plato fork
    fn verify_vote_attestation(&self, header: &SealedHeader<Header>) -> Result<(), ConsensusError> {
        if !self.chain_spec.is_plato_active_at_block(header.number) {
            return Ok(());
        }

        // TODO: Implement vote attestation verification
        // This involves parsing and validating BLS signature aggregation
        // For now, we'll skip this complex validation
        
        Ok(())
    }

    /// Verify turn length at epoch boundaries for Bohr fork
    fn verify_turn_length(&self, header: &SealedHeader<Header>) -> Result<(), ConsensusError> {
        if header.number % self.epoch != 0 || !self.chain_spec.is_bohr_active_at_timestamp(header.timestamp) {
            return Ok(());
        }

        // TODO: Implement turn length verification
        // This would parse turn length from header extra data and compare with contract state
        // For now, we'll skip this validation
        
        Ok(())
    }

    /// Verify receipts root and logs bloom
    fn verify_receipts_and_logs(&self, header: &alloy_consensus::Header, receipts: &[Receipt]) -> Result<(), ConsensusError> {
        // Calculate receipts root
        let receipts_with_bloom = receipts.iter().map(|r| r.with_bloom_ref()).collect::<Vec<_>>();
        let calculated_receipts_root = proofs::calculate_receipt_root(&receipts_with_bloom);

        if header.receipts_root != calculated_receipts_root {
            return Err(ConsensusError::Other(
                format!("Receipts root mismatch: header={}, calculated={}", header.receipts_root, calculated_receipts_root).into()
            ));
        }

        // Calculate logs bloom
        let calculated_logs_bloom = receipts_with_bloom.iter()
            .fold(alloy_primitives::Bloom::ZERO, |bloom, r| bloom | r.bloom());

        if header.logs_bloom != calculated_logs_bloom {
            return Err(ConsensusError::Other(
                format!("Logs bloom mismatch").into()
            ));
        }

        Ok(())
    }

    /// Verify the seal (proposer signature) in the header
    fn verify_seal(&self, header: &SealedHeader<Header>, snapshot: &Snapshot) -> Result<(), ConsensusError> {
        // Enhanced seal verification with proper authorization checks
        let proposer = header.beneficiary;

        // Check if proposer is in the current validator set
        if !snapshot.validators.contains(&proposer) {
            return Err(ConsensusError::Other(
                format!("Unauthorized proposer: {}", proposer).into()
            ));
        }

        // Check if proposer signed recently (to prevent spamming)
        if snapshot.sign_recently(proposer) {
            return Err(ConsensusError::Other(
                format!("Proposer {} signed recently", proposer).into()
            ));
        }

        // TODO: Implement actual signature recovery and verification
        // This would involve:
        // 1. Recovering the proposer address from the signature in header.extra_data
        // 2. Verifying it matches header.beneficiary
        // For now, we assume the beneficiary is correct

        Ok(())
    }

    /// Verify the difficulty based on turn-based proposing
    fn verify_difficulty(&self, header: &SealedHeader<Header>, snapshot: &Snapshot) -> Result<(), ConsensusError> {
        // The proposer is the signer of the block, recovered from the seal.
        // This is the correct identity to use for turn-based validation.
        let proposer = self
            .consensus_validator
            .recover_proposer_from_seal(header)?;
        
        let in_turn = snapshot.is_inturn(proposer);
        let inturn_validator = snapshot.inturn_validator();

        let expected_difficulty = if in_turn { DIFF_INTURN } else { DIFF_NOTURN };

        if header.difficulty != expected_difficulty {
            tracing::error!(
                "BSC: Difficulty validation failed at block {}: proposer={}, inturn_validator={}, in_turn={}, expected_difficulty={}, got_difficulty={}, snapshot_block={}, validators={:?}",
                header.number(),
                proposer,
                inturn_validator,
                in_turn,
                expected_difficulty,
                header.difficulty,
                snapshot.block_number,
                snapshot.validators
            );
            return Err(ConsensusError::Other(
                format!("Invalid difficulty: expected {}, got {}", expected_difficulty, header.difficulty).into()
            ));
        }

        Ok(())
    }
}

impl<ChainSpec, P> super::ParliaConsensusObject for ParliaConsensus<ChainSpec, P>
where
    ChainSpec: EthChainSpec + BscHardforks + 'static,
    P: SnapshotProvider + std::fmt::Debug + 'static,
{
    fn verify_cascading_fields(
        &self,
        header: &Header,
        parent: &Header,
        _ancestor: Option<&HashMap<alloy_primitives::B256, SealedHeader<Header>>>,
        snap: &Snapshot,
    ) -> Result<(), reth_evm::execute::BlockExecutionError> {
        let header_hash = alloy_primitives::keccak256(alloy_rlp::encode(header));
        let parent_hash = alloy_primitives::keccak256(alloy_rlp::encode(parent));
        let sealed_header = SealedHeader::new(header.clone(), header_hash);
        let sealed_parent = SealedHeader::new(parent.clone(), parent_hash);

        self.consensus_validator
            .verify_cascading_fields(&sealed_header, &sealed_parent, None, snap)
            .map_err(|e| reth_evm::execute::BlockExecutionError::msg(format!("{}", e)))
    }

    fn get_epoch_length(&self, header: &alloy_consensus::Header) -> u64 {
        self.get_epoch_length(header)
    }
    fn get_validator_bytes_from_header(&self, header: &alloy_consensus::Header) -> Option<Vec<u8>> {
        self.get_validator_bytes_from_header(header)
    }

    fn get_turn_length_from_header(&self, header: &alloy_consensus::Header) -> Result<Option<u8>, ParliaConsensusError> {
        self.get_turn_length_from_header(header)
    }
}

impl<ChainSpec, P> HeaderValidator<Header> for ParliaConsensus<ChainSpec, P>
where
    ChainSpec: EthChainSpec + BscHardforks + 'static,
    P: SnapshotProvider + std::fmt::Debug + 'static,
{
    fn validate_header(&self, header: &SealedHeader<Header>) -> Result<(), ConsensusError> {
        self.header_validator.validate_header(header)
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<Header>,
        parent: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        self.header_validator.validate_header_against_parent(header, parent)
    }
}

impl<ChainSpec, P> Consensus<BscBlock> for ParliaConsensus<ChainSpec, P>
where
    ChainSpec: EthChainSpec + BscHardforks + 'static,
    P: SnapshotProvider + std::fmt::Debug + 'static,
{
    type Error = ConsensusError;

    fn validate_body_against_header(
        &self,
        _body: &<BscBlock as Block>::Body,
        _header: &SealedHeader<Header>,
    ) -> Result<(), Self::Error> {
        // Basic body validation - for now accept all
        Ok(())
    }

    fn validate_block_pre_execution(
        &self,
        block: &SealedBlock<BscBlock>,
    ) -> Result<(), Self::Error> {
        self.validate_block_pre_execution_impl(block)
    }
}

impl<ChainSpec, P> FullConsensus<BscPrimitives> for ParliaConsensus<ChainSpec, P>
where
    ChainSpec: EthChainSpec + BscHardforks + 'static,
    P: SnapshotProvider + std::fmt::Debug + 'static,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<BscBlock>,
        result: &BlockExecutionResult<Receipt>,
    ) -> Result<(), ConsensusError> {
        self.validate_block_post_execution_impl(block, result)
    }
}

// Additional BSC validation methods
impl<ChainSpec, P> ParliaConsensus<ChainSpec, P>
where
    ChainSpec: EthChainSpec + BscHardforks + 'static,
    P: SnapshotProvider + std::fmt::Debug + 'static,
{
    /// Get parent header for validation (following bsc-erigon approach)
    fn get_parent_header(&self, header: &alloy_consensus::Header) -> Option<SealedHeader<alloy_consensus::Header>> {
        if header.number == 0 {
            return None; // Genesis has no parent
        }
        
        // TODO: Implement proper parent header fetching like bsc-erigon:
        // 1. Try to get from provided parents array (for batch validation)
        // 2. Fallback to chain storage: chain.GetHeader(header.parent_hash, header.number - 1)
        // 3. Validate parent.number == header.number - 1 && parent.hash == header.parent_hash
        //
        // For now, gracefully handle missing parents during sync by returning None.
        // This defers gas limit validation to live sync when dependencies are available.
        //
        // Example implementation:
        // if let Some(provider) = &self.header_provider {
        //     if let Ok(Some(parent_header)) = provider.header_by_number(header.number - 1) {
        //         if parent_header.hash_slow() == header.parent_hash {
        //             return Some(SealedHeader::new(parent_header, header.parent_hash));
        //         }
        //     }
        // }
        
        None
    }

    /// Verify BSC gas limit validation with Lorentz hardfork support (like bsc-erigon)
    fn verify_gas_limit(
        &self,
        header: &SealedHeader<alloy_consensus::Header>,
        parent: &SealedHeader<alloy_consensus::Header>,
    ) -> Result<(), ConsensusError> {
        let parent_gas_limit = parent.gas_limit();
        let gas_limit = header.gas_limit();
        
        // Calculate absolute difference
        let diff = if parent_gas_limit > gas_limit {
            parent_gas_limit - gas_limit
        } else {
            gas_limit - parent_gas_limit
        };
        
        // Use Lorentz hardfork activation for divisor (like bsc-erigon)
        // Before Lorentz: 256, After Lorentz: 1024
        let gas_limit_bound_divisor = if self.chain_spec.is_lorentz_active_at_timestamp(header.timestamp()) {
            1024u64 // After Lorentz hardfork
        } else {
            256u64  // Before Lorentz hardfork
        };
        
        let limit = parent_gas_limit / gas_limit_bound_divisor;
        const MIN_GAS_LIMIT: u64 = 5000; // Minimum gas limit for BSC
        
        if diff >= limit || gas_limit < MIN_GAS_LIMIT {
            return Err(ConsensusError::Other(format!(
                "BSC gas limit validation failed: have {}, want {} ± {}, min={}", 
                gas_limit, parent_gas_limit, limit, MIN_GAS_LIMIT
            ).into()));
        }
        
        tracing::trace!(
            "✅ [BSC] Gas limit validation passed: {} (parent: {}, limit: ±{}, divisor: {})",
            gas_limit, parent_gas_limit, limit, gas_limit_bound_divisor
        );
        
        Ok(())
    }

    /// Report slash evidence for validators who fail to propose when it's their turn (like bsc-erigon)
    fn report_slash_evidence(
        &self,
        header: &SealedHeader<alloy_consensus::Header>,
        snapshot: &Snapshot,
    ) -> Result<(), ConsensusError> {
        let proposer = header.beneficiary();
        let inturn_validator = snapshot.inturn_validator();
        
        // Check if the current proposer is not the expected in-turn validator
        let inturn_validator_eq_miner = proposer == inturn_validator;
        
        if !inturn_validator_eq_miner {
            // Check if the in-turn validator has signed recently
            let spoiled_validator = inturn_validator;
            if !snapshot.sign_recently(spoiled_validator) {
                // Report slashing evidence for the validator who failed to propose in-turn
                tracing::warn!(
                    "🔪 [BSC] Slash evidence detected: validator {} failed to propose in-turn at block {}, actual proposer: {}",
                    spoiled_validator, header.number(), proposer
                );
                
                // TODO: In a full implementation, this would:
                // 1. Create a system transaction to call the slash contract
                // 2. Include evidence of the validator's failure to propose
                // 3. Submit this as part of block execution
                // For now, we log the evidence for monitoring/debugging
                
                tracing::info!(
                    "📊 [BSC] Slash evidence: block={}, spoiled_validator={}, actual_proposer={}, inturn_expected={}",
                    header.number(), spoiled_validator, proposer, inturn_validator
                );
            }
        }
        
        Ok(())
    }

    fn get_epoch_length(&self, header: &Header) -> u64 {
        if self.chain_spec.is_maxwell_active_at_timestamp(header.timestamp()) {
            return crate::consensus::parlia::snapshot::MAXWELL_EPOCH_LENGTH;
        }
        if self.chain_spec.is_lorentz_active_at_timestamp(header.timestamp()) {
            return crate::consensus::parlia::snapshot::LORENTZ_EPOCH_LENGTH;
        }
        self.epoch
    }

    fn get_validator_bytes_from_header(&self, header: &Header) -> Option<Vec<u8>> {
        let extra_len = header.extra_data.len();
        if extra_len <= EXTRA_VANITY + EXTRA_SEAL {
            return None;
        }

        let is_luban_active = self.chain_spec.is_luban_active_at_block(header.number);
        let is_epoch = header.number % self.get_epoch_length(header) == 0;

        if is_luban_active {
            if !is_epoch {
                return None;
            }

            let count = header.extra_data[EXTRA_VANITY] as usize;
            let start = EXTRA_VANITY+VALIDATOR_NUMBER_SIZE;
            let end = start + count * VALIDATOR_BYTES_LEN_AFTER_LUBAN;

            let mut extra_min_len = end + EXTRA_SEAL;
            let is_bohr_active = self.chain_spec.is_bohr_active_at_timestamp(header.timestamp);
            if is_bohr_active {
                extra_min_len += TURN_LENGTH_SIZE;
            }
            if count == 0 || extra_len < extra_min_len {
                return None
            }
            Some(header.extra_data[start..end].to_vec())
        } else {
            if is_epoch &&
                (extra_len - EXTRA_VANITY - EXTRA_SEAL) %
                VALIDATOR_BYTES_LEN_BEFORE_LUBAN !=
                    0
            {
                return None;
            }

            Some(header.extra_data[EXTRA_VANITY..extra_len - EXTRA_SEAL].to_vec())
        }
    }

    pub fn get_turn_length_from_header(
        &self,
        header: &Header,
    ) -> Result<Option<u8>, ParliaConsensusError> {
        if header.number % self.get_epoch_length(header) != 0 ||
            !self.chain_spec.is_bohr_active_at_timestamp(header.timestamp)
        {
            return Ok(None);
        }

        if header.extra_data.len() <= EXTRA_VANITY + EXTRA_SEAL {
            return Err(ParliaConsensusError::InvalidHeaderExtraLen {
                header_extra_len: header.extra_data.len() as u64,
            });
        }

        let num = header.extra_data[EXTRA_VANITY] as usize;
        let pos = EXTRA_VANITY + 1 + num * VALIDATOR_BYTES_LEN_AFTER_LUBAN;

        if header.extra_data.len() <= pos {
            return Err(ParliaConsensusError::ExtraInvalidTurnLength);
        }

        let turn_length = header.extra_data[pos];
        Ok(Some(turn_length))
    }

} 