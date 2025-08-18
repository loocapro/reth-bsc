use super::executor::BscBlockExecutor;
use crate::evm::transaction::BscTxEnv;
use reth_chainspec::{EthChainSpec, EthereumHardforks, Hardforks};
use reth_evm::{eth::receipt_builder::ReceiptBuilder, execute::BlockExecutionError, Database, Evm, FromRecoveredTx, FromTxWithEncoded, IntoTxEnv};
use reth_primitives::TransactionSigned;
use reth_revm::State;
use revm::{
    context::{BlockEnv, TxEnv},
    primitives::{Address, Bytes, TxKind, U256},
};
use alloy_consensus::TxReceipt;
use crate::consensus::parlia::VoteAddress;
use crate::consensus::parlia::util::is_breathe_block;
use crate::system_contracts::feynman_fork::ValidatorElectionInfo;
use std::collections::HashMap;


impl<'a, DB, EVM, Spec, R: ReceiptBuilder> BscBlockExecutor<'a, EVM, Spec, R>
where
    DB: Database + 'a,
    EVM: Evm<
        DB = &'a mut State<DB>,
        Tx: FromRecoveredTx<R::Transaction>
                + FromRecoveredTx<TransactionSigned>
                + FromTxWithEncoded<TransactionSigned>,
    >,
    Spec: EthereumHardforks + crate::hardforks::BscHardforks + EthChainSpec + Hardforks + Clone,
    R: ReceiptBuilder<Transaction = TransactionSigned, Receipt: TxReceipt>,
    <R as ReceiptBuilder>::Transaction: Unpin + From<TransactionSigned>,
    <EVM as alloy_evm::Evm>::Tx: FromTxWithEncoded<<R as ReceiptBuilder>::Transaction>,
    BscTxEnv: IntoTxEnv<<EVM as alloy_evm::Evm>::Tx>,
    R::Transaction: Into<TransactionSigned>,
{
    /// check the new block, pre check and prepare some intermediate data for commit parlia snapshot in finish function.
    /// depends on parlia, header and snapshot.
    pub(crate) fn check_new_block(&mut self, block: &BlockEnv) -> Result<(), BlockExecutionError> {
        let block_number = block.number.to::<u64>();
        tracing::info!("Check new block, block_number: {}", block_number);

        let header = self
            .snapshot_provider
            .as_ref()
            .unwrap()
            .get_checkpoint_header(block_number)
            .ok_or(BlockExecutionError::msg("Failed to get header from snapshot provider"))?;
        self.inner_ctx.header = Some(header.clone());

        let parent_header = self
            .snapshot_provider
            .as_ref()
            .unwrap()
            .get_checkpoint_header(block_number - 1)
            .ok_or(BlockExecutionError::msg("Failed to get parent header from snapshot provider"))?;

        let snap = self
            .snapshot_provider
            .as_ref()
            .unwrap()
            .snapshot(block_number-1)
            .ok_or(BlockExecutionError::msg("Failed to get snapshot from snapshot provider"))?;
        self.inner_ctx.snap = Some(snap.clone());

        // Delegate to Parlia consensus object; no ancestors available here, pass None
        // TODO: move this part logic codes to executor to ensure parlia is lightly.
        let verify_res = self
            .parlia_consensus
            .as_ref()
            .unwrap()
            .verify_cascading_fields(&header, &parent_header, None, &snap);

        // TODO: remove this part, just for debug.
        if let Err(err) = verify_res {
            let proposer = header.beneficiary;
            let is_inturn = snap.is_inturn(proposer);
            let expected_difficulty: u64 = if is_inturn { 2 } else { 1 };
            let recent_counts = snap.count_recent_proposers();

            tracing::error!(
                target: "bsc::pre_execution",
                error = ?err,
                block_number = header.number,
                parent_number = parent_header.number,
                header_timestamp = header.timestamp,
                parent_timestamp = parent_header.timestamp,
                proposer = %format!("0x{:x}", proposer),
                validators_len = snap.validators.len(),
                epoch_len = snap.epoch_num,
                turn_length = snap.turn_length.map(|v| v as u64),
                block_interval = snap.block_interval,
                is_inturn,
                expected_difficulty,
                header_difficulty = %format!("{}", header.difficulty),
                miner_history_check_len = snap.miner_history_check_len(),
                recent_proposers = %format!("{:?}", snap.recent_proposers),
                recent_counts = %format!("{:?}", recent_counts),
                "Consensus verify_cascading_fields failed with detailed diagnostics"
            );

            return Err(err);
        }

        let epoch_length = self.parlia_consensus.as_ref().unwrap().get_epoch_length(&header);
        if header.number % epoch_length == 0 {
            let (validator_set, vote_addresses) = self.get_current_validators(block_number)?;
            tracing::info!("validator_set: {:?}, vote_addresses: {:?}", validator_set, vote_addresses);
            
            let vote_addrs_map = if vote_addresses.is_empty() {
                HashMap::new()
            } else {
                validator_set
                    .iter()
                    .copied()
                    .zip(vote_addresses)
                    .collect::<std::collections::HashMap<_, _>>()
            };
            tracing::info!("vote_addrs_map: {:?}", vote_addrs_map);
            self.inner_ctx.current_validators = Some((validator_set, vote_addrs_map));
        }
    
        if self.spec.is_feynman_active_at_timestamp(header.timestamp) &&
            !self.spec.is_feynman_transition_at_timestamp(header.timestamp, parent_header.timestamp) &&
            is_breathe_block(parent_header.timestamp, header.timestamp)
        {
            let (to, data) = self.system_contracts.get_max_elected_validators();
            let bz = self.eth_call(to, data)?;
            let max_elected_validators = self.system_contracts.unpack_data_into_max_elected_validators(bz.as_ref());
            tracing::info!("max_elected_validators: {:?}", max_elected_validators);
            self.inner_ctx.max_elected_validators = Some(max_elected_validators);

            let (to, data) = self.system_contracts.get_validator_election_info();
            let bz = self.eth_call(to, data)?;

            let (validators, voting_powers, vote_addrs, total_length) =
                self.system_contracts.unpack_data_into_validator_election_info(bz.as_ref());

            let total_length = total_length.to::<u64>() as usize;
            if validators.len() != total_length ||
                voting_powers.len() != total_length ||
                vote_addrs.len() != total_length
            {
                return Err(BlockExecutionError::msg("Failed to get top validators"));
            }

            let validator_election_info: Vec<ValidatorElectionInfo> = validators
                .into_iter()
                .zip(voting_powers)
                .zip(vote_addrs)
                .map(|((validator, voting_power), vote_addr)| ValidatorElectionInfo {
                    address: validator,
                    voting_power,
                    vote_address: vote_addr,
                })
                .collect();
            tracing::info!("validator_election_info: {:?}", validator_election_info);
            self.inner_ctx.validators_election_info = Some(validator_election_info);
        }

        Ok(())
    }

    fn get_current_validators(&mut self, block_number: u64) -> Result<(Vec<Address>, Vec<VoteAddress>), BlockExecutionError> {
        if self.spec.is_luban_active_at_block(block_number) {
            let (to, data) = self.system_contracts.get_current_validators();
            let output = self.eth_call(to, data)?;
            Ok(self.system_contracts.unpack_data_into_validator_set(&output))
        } else {
            let (to, data) = self.system_contracts.get_current_validators_before_luban(block_number);
            let output = self.eth_call(to, data)?;
            let validator_set = self.system_contracts.unpack_data_into_validator_set_before_luban(&output);
            Ok((validator_set, Vec::new()))
        }
    }

    pub(crate) fn eth_call(&mut self, to: Address, data: Bytes) -> Result<Bytes, BlockExecutionError> {
        let tx_env = BscTxEnv {
            base: TxEnv {
                caller: Address::default(),
                kind: TxKind::Call(to),
                nonce: 0,
                gas_limit: self.evm.block().gas_limit,
                value: U256::ZERO,
                data: data.clone(),
                gas_price: 0,
                chain_id: Some(self.spec.chain().id()),
                gas_priority_fee: None,
                access_list: Default::default(),
                blob_hashes: Vec::new(),
                max_fee_per_blob_gas: 0,
                tx_type: 0,
                authorization_list: Default::default(),
            },
            is_system_transaction: false,
        };

        let result_and_state = self.evm.transact(tx_env).map_err(|err| BlockExecutionError::other(err))?;
        if !result_and_state.result.is_success() {
            tracing::error!("Failed to eth call, to: {:?}, data: {:?}", to, data);
            return Err(BlockExecutionError::msg("ETH call failed"));
        }
        let output = result_and_state.result.output().ok_or(BlockExecutionError::msg("ETH call output is None"))?;
        Ok(output.clone())
    }


}