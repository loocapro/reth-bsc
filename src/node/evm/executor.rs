use super::patch::{
    patch_chapel_after_tx, patch_chapel_before_tx, patch_mainnet_after_tx, patch_mainnet_before_tx,
};
use crate::{
    consensus::{MAX_SYSTEM_REWARD, SYSTEM_ADDRESS, SYSTEM_REWARD_PERCENT, parlia::{HertzPatchManager, VoteAddress, Snapshot}},
    evm::transaction::BscTxEnv,
    hardforks::BscHardforks,
    system_contracts::{
        feynman_fork::ValidatorElectionInfo,
        get_upgrade_system_contracts, is_system_transaction, SystemContract, STAKE_HUB_CONTRACT,
        SYSTEM_REWARD_CONTRACT,
    },
};
use alloy_consensus::{Header, Transaction, TxReceipt};
use alloy_eips::{eip7685::Requests, Encodable2718};
use alloy_evm::{block::{ExecutableTx, StateChangeSource}, eth::receipt_builder::ReceiptBuilderCtx};
use alloy_primitives::{uint, Address, TxKind, U256, BlockNumber, Bytes};
use alloy_sol_macro::sol;
use alloy_sol_types::SolCall;
use reth_chainspec::{EthChainSpec, EthereumHardforks, Hardforks};
use reth_evm::{
    block::{BlockValidationError, CommitChanges},
    eth::{receipt_builder::ReceiptBuilder, EthBlockExecutionCtx},
    execute::{BlockExecutionError, BlockExecutor},
    system_calls::SystemCaller,
    Database, Evm, FromRecoveredTx, FromTxWithEncoded, IntoTxEnv, OnStateHook, RecoveredTx,
};
use reth_primitives::TransactionSigned;
use reth_primitives_traits::SignerRecoverable;
use reth_provider::BlockExecutionResult;
use reth_revm::State;
use revm::{
    context::{
        result::{ExecutionResult, ResultAndState},
        TxEnv,
    },
    state::Bytecode,
    Database as _, DatabaseCommit,
};
use tracing::{debug, trace, warn};
use alloy_eips::eip2935::{HISTORY_STORAGE_ADDRESS, HISTORY_STORAGE_CODE};
use alloy_primitives::keccak256;
use std::{collections::HashMap, sync::Arc};
use crate::consensus::parlia::SnapshotProvider;

/// Helper type for the input of post execution.
#[allow(clippy::type_complexity)]
#[derive(Debug, Clone)]
pub(crate) struct InnerExecutionContext {
    pub(crate) current_validators: Option<(Vec<Address>, HashMap<Address, VoteAddress>)>,
    pub(crate) max_elected_validators: Option<U256>,
    pub(crate) validators_election_info: Option<Vec<ValidatorElectionInfo>>,
    pub(crate) snap: Option<Snapshot>,
    pub(crate) header: Option<Header>,
}

pub struct BscBlockExecutor<'a, EVM, Spec, R: ReceiptBuilder>
where
    Spec: EthChainSpec,
{
    /// Reference to the specification object.
    pub(super) spec: Spec,
    /// Inner EVM.
    pub(super) evm: EVM,
    /// Gas used in the block.
    gas_used: u64,
    /// Receipts of executed transactions.
    receipts: Vec<R::Receipt>,
    /// System txs
    system_txs: Vec<R::Transaction>,
    /// Receipt builder.
    receipt_builder: R,
    /// System contracts used to trigger fork specific logic.
    pub(super) system_contracts: SystemContract<Spec>,
    /// Hertz patch manager for mainnet compatibility
    /// TODO: refine later.
    #[allow(dead_code)]
    hertz_patch_manager: HertzPatchManager,
    /// Context for block execution.
    _ctx: EthBlockExecutionCtx<'a>,
    /// Utility to call system caller.
    system_caller: SystemCaller<Spec>,
    /// State hook.
    hook: Option<Box<dyn OnStateHook>>,
    /// Snapshot provider for accessing Parlia validator snapshots.
    pub(super) snapshot_provider: Option<Arc<dyn SnapshotProvider + Send + Sync>>,
    /// Parlia consensus instance used (optional during execution).
    pub(super) parlia_consensus: Option<Arc<dyn crate::consensus::parlia::ParliaConsensusObject + Send + Sync>>,
    /// Inner execution context.
    pub(super) inner_ctx: InnerExecutionContext,
}

impl<'a, DB, EVM, Spec, R: ReceiptBuilder> BscBlockExecutor<'a, EVM, Spec, R>
where
    DB: Database + 'a,
    EVM: Evm<
        DB = &'a mut State<DB>,
        Tx: FromRecoveredTx<R::Transaction>
                + FromRecoveredTx<TransactionSigned>
                + FromTxWithEncoded<TransactionSigned>,
    >,
    Spec: EthereumHardforks + BscHardforks + EthChainSpec + Hardforks + Clone,
    R: ReceiptBuilder<Transaction = TransactionSigned, Receipt: TxReceipt>,
    <R as ReceiptBuilder>::Transaction: Unpin + From<TransactionSigned>,
    <EVM as alloy_evm::Evm>::Tx: FromTxWithEncoded<<R as ReceiptBuilder>::Transaction>,
    BscTxEnv: IntoTxEnv<<EVM as alloy_evm::Evm>::Tx>,
    R::Transaction: Into<TransactionSigned>,
{
    /// Creates a new BscBlockExecutor.
    pub fn new(
        evm: EVM,
        _ctx: EthBlockExecutionCtx<'a>,
        spec: Spec,
        receipt_builder: R,
        system_contracts: SystemContract<Spec>,
    ) -> Self {
        // Determine if this is mainnet for Hertz patches
        let is_mainnet = spec.chain().id() == 56; // BSC mainnet chain ID
        let hertz_patch_manager = HertzPatchManager::new(is_mainnet);

        let spec_clone = spec.clone();
        Self {
            spec,
            evm,
            gas_used: 0,
            receipts: vec![],
            system_txs: vec![],
            receipt_builder,
            system_contracts,
            hertz_patch_manager,
            _ctx,
            system_caller: SystemCaller::new(spec_clone),
            hook: None,
            snapshot_provider: crate::shared::get_snapshot_provider().cloned(),
            parlia_consensus: crate::shared::get_parlia_consensus().cloned(),
            inner_ctx: InnerExecutionContext {
                current_validators: None,
                max_elected_validators: None,
                validators_election_info: None,
                snap: None,
                header: None,
            },
        }
    }



    /// Applies system contract upgrades if the Feynman fork is not yet active.
    fn upgrade_contracts(&mut self) -> Result<(), BlockExecutionError> {
        let contracts = get_upgrade_system_contracts(
            &self.spec,
            self.evm.block().number.to(),
            self.evm.block().timestamp.to(),
            self.evm.block().timestamp.to::<u64>() - 3_000, /* TODO: how to get parent block
                                                             * timestamp? */
        )
        .map_err(|_| BlockExecutionError::msg("Failed to get upgrade system contracts"))?;

        for (address, maybe_code) in contracts {
            if let Some(code) = maybe_code {
                self.upgrade_system_contract(address, code)?;
            }
        }

        Ok(())
    }

    /// Initializes the feynman contracts
    fn initialize_feynman_contracts(
        &mut self,
        beneficiary: Address,
    ) -> Result<(), BlockExecutionError> {
        // Exit early if contracts are already initialized
        if !self
            .evm
            .db_mut()
            .storage(STAKE_HUB_CONTRACT, U256::ZERO)
            .map_err(BlockExecutionError::other)?
            .is_zero()
        {
            return Ok(());
        }

        let txs = self.system_contracts.feynman_contracts_txs();
        for tx in txs {
            self.transact_system_tx(&tx, beneficiary)?;
        }
        Ok(())
    }

    /// Initializes the genesis contracts
    fn deploy_genesis_contracts(
        &mut self,
        beneficiary: Address,
    ) -> Result<(), BlockExecutionError> {
        debug!("🏗️  [BSC] deploy_genesis_contracts: beneficiary={:?}, block={}", beneficiary, self.evm.block().number);
        let txs = self.system_contracts.genesis_contracts_txs();
        trace!("🏗️  [BSC] deploy_genesis_contracts: created {} genesis txs", txs.len());

        for (i, tx) in txs.iter().enumerate() {
            trace!("🏗️  [BSC] deploy_genesis_contracts: executing genesis tx {}/{}: hash={:?}, to={:?}, value={}, gas_limit={}", 
                i + 1, txs.len(), tx.hash(), tx.to(), tx.value(), tx.gas_limit());
            self.transact_system_tx(tx, beneficiary)?;
        }
        trace!("🏗️  [BSC] deploy_genesis_contracts: completed all {} genesis txs", txs.len());
        Ok(())
    }

    pub(crate) fn transact_system_tx(
        &mut self,
        tx: &TransactionSigned,
        sender: Address,
    ) -> Result<(), BlockExecutionError> {
        trace!("Start to transact_system_tx: sender={:?}, tx_hash={:?}, to={:?}, value={}, gas_limit={}", 
            sender, tx.hash(), tx.to(), tx.value(), tx.gas_limit());

        // TODO: Consensus handle reverting slashing system txs (they shouldnt be in the block)
        // https://github.com/bnb-chain/reth/blob/main/crates/bsc/evm/src/execute.rs#L602

        let account = self
            .evm
            .db_mut()
            .basic(sender)
            .map_err(BlockExecutionError::other)?
            .unwrap_or_default();

        trace!("transact_system_tx: sender account balance={}, nonce={}", account.balance, account.nonce);

        let tx_env = BscTxEnv {
            base: TxEnv {
                caller: sender,
                kind: TxKind::Call(tx.to().unwrap()),
                nonce: account.nonce,
                gas_limit: u64::MAX / 2,
                value: tx.value(),
                data: tx.input().clone(),
                // Setting the gas price to zero enforces that no value is transferred as part of
                // the call, and that the call will not count against the block's
                // gas limit
                gas_price: 0,
                // The chain ID check is not relevant here and is disabled if set to None
                chain_id: Some(self.spec.chain().id()),
                // Setting the gas priority fee to None ensures the effective gas price is
                //derived         // from the `gas_price` field, which we need to be zero
                gas_priority_fee: None,
                access_list: Default::default(),
                // blob fields can be None for this tx
                blob_hashes: Vec::new(),
                max_fee_per_blob_gas: 0,
                tx_type: 0,
                authorization_list: Default::default(),
            },
            is_system_transaction: true,
        };

        trace!("transact_system_tx: TxEnv gas_price={}, gas_limit={}, is_system_transaction={}",
            tx_env.base.gas_price, tx_env.base.gas_limit, tx_env.is_system_transaction);

        let result_and_state = self.evm.transact(tx_env).map_err(BlockExecutionError::other)?;

        let ResultAndState { result, state } = result_and_state;

        if let Some(hook) = &mut self.hook {
            hook.on_state(StateChangeSource::Transaction(self.receipts.len()), &state);
        } 

        let tx = tx.clone();
        let gas_used = result.gas_used();
        trace!("⚙️  [BSC] transact_system_tx: completed, gas_used={}, result={:?}", gas_used, result);
        self.gas_used += gas_used;
        self.receipts.push(self.receipt_builder.build_receipt(ReceiptBuilderCtx {
            tx: &tx,
            evm: &self.evm,
            result,
            state: &state,
            cumulative_gas_used: self.gas_used,
        }));
        self.evm.db_mut().commit(state);

        Ok(())
    }

    /// Replaces the code of a system contract in state.
    fn upgrade_system_contract(
        &mut self,
        address: Address,
        code: Bytecode,
    ) -> Result<(), BlockExecutionError> {
        let account =
            self.evm.db_mut().load_cache_account(address).map_err(BlockExecutionError::other)?;

        let mut info = account.account_info().unwrap_or_default();
        info.code_hash = code.hash_slow();
        info.code = Some(code);

        let transition = account.change(info, Default::default());
        self.evm.db_mut().apply_transition(vec![(address, transition)]);
        Ok(())
    }

    /// Handle slash system tx
    fn handle_slash_tx(&mut self, tx: &TransactionSigned) -> Result<(), BlockExecutionError> {
        sol!(
            function slash(
                address amounts,
            );
        );

        let input = tx.input();
        let is_slash_tx = input.len() >= 4 && input[..4] == slashCall::SELECTOR;

        if is_slash_tx {
            // DEBUG: Uncomment to trace slash transaction processing
        // debug!("⚔️  [BSC] handle_slash_tx: processing slash tx, hash={:?}", tx.hash());
            let signer = tx.recover_signer().map_err(BlockExecutionError::other)?;
            self.transact_system_tx(tx, signer)?;
        }

        Ok(())
    }

    /// Handle finality reward system tx.
    /// Activated by <https://github.com/bnb-chain/BEPs/blob/master/BEPs/BEP-319.md>
    /// at <https://www.bnbchain.org/en/blog/announcing-v1-2-9-a-significant-hard-fork-release-for-bsc-mainnet>
    fn handle_finality_reward_tx(
        &mut self,
        tx: &TransactionSigned,
    ) -> Result<(), BlockExecutionError> {
        sol!(
            function distributeFinalityReward(
                address[] validators,
                uint256[] weights
            );
        );

        let input = tx.input();
        let is_finality_reward_tx =
            input.len() >= 4 && input[..4] == distributeFinalityRewardCall::SELECTOR;

        if is_finality_reward_tx {
            debug!("🏆 [BSC] handle_finality_reward_tx: processing finality reward tx, hash={:?}", tx.hash());
            let signer = tx.recover_signer().map_err(BlockExecutionError::other)?;
            self.transact_system_tx(tx, signer)?;
        }

        Ok(())
    }

    /// Handle update validatorsetv2 system tx.
    /// Activated by <https://github.com/bnb-chain/BEPs/pull/294>
    fn handle_update_validator_set_v2_tx(
        &mut self,
        tx: &TransactionSigned,
    ) -> Result<(), BlockExecutionError> {
        sol!(
            function updateValidatorSetV2(
                address[] _consensusAddrs,
                uint64[] _votingPowers,
                bytes[] _voteAddrs
            );
        );

        let input = tx.input();
        let is_update_validator_set_v2_tx =
            input.len() >= 4 && input[..4] == updateValidatorSetV2Call::SELECTOR;

        if is_update_validator_set_v2_tx {
    
            let signer = tx.recover_signer().map_err(BlockExecutionError::other)?;
            self.transact_system_tx(tx, signer)?;
        }

        Ok(())
    }

    /// Distributes block rewards to the validator.
    fn distribute_block_rewards(&mut self, validator: Address) -> Result<(), BlockExecutionError> {
        trace!("💰 [BSC] distribute_block_rewards: validator={:?}, block={}", validator, self.evm.block().number);
        
        let system_account = self
            .evm
            .db_mut()
            .load_cache_account(SYSTEM_ADDRESS)
            .map_err(BlockExecutionError::other)?;

        if system_account.account.is_none() ||
            system_account.account.as_ref().unwrap().info.balance == U256::ZERO
        {
            trace!("💰 [BSC] distribute_block_rewards: no system balance to distribute");
            return Ok(());
        }

        let (mut block_reward, mut transition) = system_account.drain_balance();
        trace!("💰 [BSC] distribute_block_rewards: drained system balance={}", block_reward);
        transition.info = None;
        self.evm.db_mut().apply_transition(vec![(SYSTEM_ADDRESS, transition)]);
        let balance_increment = vec![(validator, block_reward)];

        self.evm
            .db_mut()
            .increment_balances(balance_increment)
            .map_err(BlockExecutionError::other)?;

        let system_reward_balance = self
            .evm
            .db_mut()
            .basic(SYSTEM_REWARD_CONTRACT)
            .map_err(BlockExecutionError::other)?
            .unwrap_or_default()
            .balance;

        trace!("💰 [BSC] distribute_block_rewards: system_reward_balance={}", system_reward_balance);

        // Kepler introduced a max system reward limit, so we need to pay the system reward to the
        // system contract if the limit is not exceeded.
        if !self.spec.is_kepler_active_at_timestamp(self.evm.block().timestamp.to()) &&
            system_reward_balance < U256::from(MAX_SYSTEM_REWARD)
        {
            let reward_to_system = block_reward >> SYSTEM_REWARD_PERCENT;
            trace!("💰 [BSC] distribute_block_rewards: reward_to_system={}", reward_to_system);
            if reward_to_system > 0 {
                let tx = self.system_contracts.pay_system_tx(reward_to_system);
                trace!("💰 [BSC] distribute_block_rewards: created pay_system_tx, hash={:?}, value={}", tx.hash(), tx.value());
                self.transact_system_tx(&tx, validator)?;
            }

            block_reward -= reward_to_system;
        }

        let tx = self.system_contracts.pay_validator_tx(validator, block_reward);
        trace!("💰 [BSC] distribute_block_rewards: created pay_validator_tx, hash={:?}, value={}", tx.hash(), tx.value());
        self.transact_system_tx(&tx, validator)?;
        Ok(())
    }

    pub(crate) fn apply_history_storage_account(
        &mut self,
        block_number: BlockNumber,
    ) -> Result<bool, BlockExecutionError> {
        debug!(
            "Apply history storage account {:?} at height {:?}",
            HISTORY_STORAGE_ADDRESS, block_number
        );

        let account = self.evm.db_mut().load_cache_account(HISTORY_STORAGE_ADDRESS).map_err(|err| {
            BlockExecutionError::other(err)
        })?;

        let mut new_info = account.account_info().unwrap_or_default();
        new_info.code_hash = keccak256(HISTORY_STORAGE_CODE.clone());
        new_info.code = Some(Bytecode::new_raw(Bytes::from_static(&HISTORY_STORAGE_CODE)));
        new_info.nonce = 1_u64;
        new_info.balance = U256::ZERO;

        let transition = account.change(new_info, Default::default());
        self.evm.db_mut().apply_transition(vec![(HISTORY_STORAGE_ADDRESS, transition)]);
        Ok(true)
    }
}

// Note: Storage patch application function is available for future use
// Currently, Hertz patches are applied through the existing patch system

impl<'a, DB, E, Spec, R> BlockExecutor for BscBlockExecutor<'a, E, Spec, R>
where
    DB: Database + 'a,
    E: Evm<
        DB = &'a mut State<DB>,
        Tx: FromRecoveredTx<R::Transaction>
                + FromRecoveredTx<TransactionSigned>
                + FromTxWithEncoded<TransactionSigned>,
    >,
    Spec: EthereumHardforks + BscHardforks + EthChainSpec + Hardforks,
    R: ReceiptBuilder<Transaction = TransactionSigned, Receipt: TxReceipt>,
    <R as ReceiptBuilder>::Transaction: Unpin + From<TransactionSigned>,
    <E as alloy_evm::Evm>::Tx: FromTxWithEncoded<<R as ReceiptBuilder>::Transaction>,
    BscTxEnv: IntoTxEnv<<E as alloy_evm::Evm>::Tx>,
    R::Transaction: Into<TransactionSigned>,
{
    type Transaction = TransactionSigned;
    type Receipt = R::Receipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        // pre check and prepare some intermediate data for commit parlia snapshot in finish function.
        let block_env = self.evm.block().clone();
        self.check_new_block(&block_env)?;

        // set state clear flag if the block is after the Spurious Dragon hardfork.
        let state_clear_flag = self.spec.is_spurious_dragon_active_at_block(self.evm.block().number.to());
        self.evm.db_mut().set_state_clear_flag(state_clear_flag);

        if !self.spec.is_feynman_active_at_timestamp(self.evm.block().timestamp.to()) {
            self.upgrade_contracts()?;
        }

        // enable BEP-440/EIP-2935 for historical block hashes from state.
        if self.spec.is_prague_transition_at_timestamp(self.evm.block().timestamp.to(), self.evm.block().timestamp.to::<u64>() - 3) {
            self.apply_history_storage_account(self.evm.block().number.to::<u64>())?;
        }
        if self.spec.is_prague_active_at_timestamp(self.evm.block().timestamp.to()) {
            self.system_caller.apply_blockhashes_contract_call(self._ctx.parent_hash, &mut self.evm)?;
        }

        Ok(())
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        _tx: impl ExecutableTx<Self>,
        _f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        unimplemented!();
    }

    fn execute_transaction_with_result_closure(
        &mut self,
        tx: impl ExecutableTx<Self>
            + IntoTxEnv<<E as alloy_evm::Evm>::Tx>
            + RecoveredTx<TransactionSigned>,
        f: impl for<'b> FnOnce(&'b ExecutionResult<<E as alloy_evm::Evm>::HaltReason>),
    ) -> Result<u64, BlockExecutionError> {
        // Check if it's a system transaction
        let signer = tx.signer();
        let is_system = is_system_transaction(tx.tx(), *signer, self.evm.block().beneficiary);
        
        // DEBUG: Uncomment to trace transaction execution details
        // debug!("🔍 [BSC] execute_transaction_with_result_closure: tx_hash={:?}, signer={:?}, beneficiary={:?}, is_system={}, to={:?}, value={}, gas_limit={}, max_fee_per_gas={}", 
        //     tx.tx().hash(), signer, self.evm.block().beneficiary, is_system, tx.tx().to(), tx.tx().value(), tx.tx().gas_limit(), tx.tx().max_fee_per_gas());

        if is_system {
            // DEBUG: Uncomment to trace system transaction handling
            // debug!("⚙️  [BSC] execute_transaction_with_result_closure: queuing system tx for later execution");
            self.system_txs.push(tx.tx().clone());
            return Ok(0);
        }

        // DEBUG: Uncomment to trace regular transaction execution
        // debug!("🚀 [BSC] execute_transaction_with_result_closure: executing regular tx, block_gas_used={}, block_gas_limit={}, available_gas={}", 
        //     self.gas_used, self.evm.block().gas_limit, self.evm.block().gas_limit - self.gas_used);

        // Apply Hertz patches before transaction execution
        // Note: Hertz patches are implemented in the existing patch system
        // The HertzPatchManager is available for future enhanced patching
        
        // apply patches before (legacy - keeping for compatibility)
        patch_mainnet_before_tx(tx.tx(), self.evm.db_mut())?;
        patch_chapel_before_tx(tx.tx(), self.evm.db_mut())?;

        let block_available_gas = self.evm.block().gas_limit - self.gas_used;
        if tx.tx().gas_limit() > block_available_gas {
            warn!("❌ [BSC] execute_transaction_with_result_closure: tx gas limit {} exceeds available block gas {}", 
                tx.tx().gas_limit(), block_available_gas);
            return Err(BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                transaction_gas_limit: tx.tx().gas_limit(),
                block_available_gas,
            }
            .into());
        }
        
        trace!("🔥 [BSC] execute_transaction_with_result_closure: calling EVM transact for regular tx");
        let result_and_state = self
            .evm
            .transact(tx)
            .map_err(|err| {
                warn!("❌ [BSC] execute_transaction_with_result_closure: EVM transact failed: {:?}", err);
                BlockExecutionError::evm(err, tx.tx().trie_hash())
            })?;
        let ResultAndState { result, state } = result_and_state;

        f(&result);

        // Call state hook if it exists, passing the evmstate
        if let Some(hook) = &mut self.hook {
            let mut temp_state = state.clone();
            temp_state.remove(&SYSTEM_ADDRESS);
            hook.on_state(StateChangeSource::Transaction(self.receipts.len()), &temp_state);
        }

        let gas_used = result.gas_used();
        trace!("✅ [BSC] execute_transaction_with_result_closure: tx completed, gas_used={}, result={:?}", gas_used, result);
        self.gas_used += gas_used;
        self.receipts.push(self.receipt_builder.build_receipt(ReceiptBuilderCtx {
            tx: tx.tx(),
            evm: &self.evm,
            result,
            state: &state,
            cumulative_gas_used: self.gas_used,
        }));
        self.evm.db_mut().commit(state);

        // Apply Hertz patches after transaction execution
        // Note: Hertz patches are implemented in the existing patch system
        // The HertzPatchManager is available for future enhanced patching
        
        // apply patches after (legacy - keeping for compatibility)
        patch_mainnet_after_tx(tx.tx(), self.evm.db_mut())?;
        patch_chapel_after_tx(tx.tx(), self.evm.db_mut())?;

        Ok(gas_used)
    }



    fn finish(
        mut self,
    ) -> Result<(Self::Evm, BlockExecutionResult<R::Receipt>), BlockExecutionError> {
        // If first block deploy genesis contracts
        if self.evm.block().number == uint!(1U256) {
            self.deploy_genesis_contracts(self.evm.block().beneficiary)?;
        }

        if self.spec.is_feynman_active_at_timestamp(self.evm.block().timestamp.to()) {
            self.upgrade_contracts()?;
        }
        if self.spec.is_feynman_active_at_timestamp(self.evm.block().timestamp.to()) &&
            !self
                .spec
                .is_feynman_active_at_timestamp(self.evm.block().timestamp.to::<u64>() - 100)
        {
            self.initialize_feynman_contracts(self.evm.block().beneficiary)?;
        }

        self.finalize_new_block(&self.evm.block().clone())?;


        // Prepare system transactions list and append slash transactions collected from consensus.
        let mut system_txs = self.system_txs.clone();

        // Drain slashing evidence collected by header-validation for this block.
        for spoiled in crate::consensus::parlia::slash_pool::drain() {
            use alloy_sol_macro::sol;
            use alloy_sol_types::SolCall;
            use crate::system_contracts::SLASH_CONTRACT;
            sol!(
                function slash(address);
            );
            let input = slashCall(spoiled).abi_encode();
            let tx = reth_primitives::TransactionSigned::new_unhashed(
                reth_primitives::Transaction::Legacy(alloy_consensus::TxLegacy {
                    chain_id: Some(self.spec.chain().id()),
                    nonce: 0,
                    gas_limit: u64::MAX / 2,
                    gas_price: 0,
                    value: alloy_primitives::U256::ZERO,
                    input: alloy_primitives::Bytes::from(input),
                    to: alloy_primitives::TxKind::Call(Address::from(*SLASH_CONTRACT)),
                }),
                alloy_primitives::Signature::new(Default::default(), Default::default(), false),
            );
            // DEBUG: Uncomment to trace slash transaction creation
            // debug!("⚔️  [BSC] finish: added slash tx for spoiled validator {:?}", spoiled);
            system_txs.push(tx);
        }

        // DEBUG: Uncomment to trace system transaction processing
        // debug!("🎯 [BSC] finish: processing {} system txs for slash handling", system_txs.len());
        let system_txs_for_slash = system_txs.clone();
        for (_i, tx) in system_txs_for_slash.iter().enumerate() {
            // DEBUG: Uncomment to trace individual slash transaction handling
            // debug!("⚔️  [BSC] finish: handling slash tx {}/{}: hash={:?}", i + 1, system_txs_for_slash.len(), tx.hash());
            self.handle_slash_tx(tx)?;
        }


        // ---- post-system-tx handling ---------------------------------
        self.distribute_block_rewards(self.evm.block().beneficiary)?;

        if self.spec.is_plato_active_at_block(self.evm.block().number.to()) {
            for (_i, tx) in system_txs.iter().enumerate() {
                self.handle_finality_reward_tx(tx)?;
            }
        }

        // TODO: add breathe check and polish it later.
        let system_txs_v2 = self.system_txs.clone();
        for (_i, tx) in system_txs_v2.iter().enumerate() {
            self.handle_update_validator_set_v2_tx(tx)?;
        }

        // TODO:
        // Consensus: Slash validator if not in turn
        
        // -----------------------------------------------------------------
        // reth-bsc-trail PATTERN: Create current snapshot from parent snapshot after execution
        // Get parent snapshot at start, apply current block changes, cache current snapshot
        // -----------------------------------------------------------------
        let current_block_number = self.evm.block().number.to::<u64>();
        if let Some(provider) = crate::shared::get_snapshot_provider() {
            // Get parent snapshot (like reth-bsc-trail does)
            let parent_number = current_block_number.saturating_sub(1);
            if let Some(parent_snapshot) = provider.snapshot(parent_number) {
                // Create current snapshot by applying current block to parent snapshot (like reth-bsc-trail does)
                // We need to create a simple header for snapshot application
                let current_block = self.evm.block();
                
                // Create a minimal header for snapshot application
                // Note: We only need the essential fields for snapshot application
                let header = alloy_consensus::Header {
                    parent_hash: alloy_primitives::B256::ZERO, // Not used in snapshot.apply
                    beneficiary: current_block.beneficiary,
                    state_root: alloy_primitives::B256::ZERO, // Not used in snapshot.apply
                    transactions_root: alloy_primitives::B256::ZERO, // Not used in snapshot.apply
                    receipts_root: alloy_primitives::B256::ZERO, // Not used in snapshot.apply
                    logs_bloom: alloy_primitives::Bloom::ZERO, // Not used in snapshot.apply
                    difficulty: current_block.difficulty,
                    number: current_block.number.to::<u64>(),
                    gas_limit: current_block.gas_limit,
                    gas_used: self.gas_used, // Use actual gas used from execution
                    timestamp: current_block.timestamp.to::<u64>(),
                    extra_data: alloy_primitives::Bytes::new(), // Will be filled from actual block data
                    mix_hash: alloy_primitives::B256::ZERO, // Not used in snapshot.apply
                    nonce: alloy_primitives::B64::ZERO, // Not used in snapshot.apply
                    base_fee_per_gas: Some(current_block.basefee),
                    withdrawals_root: None, // Not used in snapshot.apply
                    blob_gas_used: None, // Not used in snapshot.apply
                    excess_blob_gas: None, // Not used in snapshot.apply
                    parent_beacon_block_root: None, // Not used in snapshot.apply
                    ommers_hash: alloy_primitives::B256::ZERO, // Not used in snapshot.apply
                    requests_hash: None, // Not used in snapshot.apply
                };
                
                // Check for epoch boundary and parse validator updates (exactly like reth-bsc-trail does)
                let epoch_num = parent_snapshot.epoch_num;
                let miner_check_len = parent_snapshot.miner_history_check_len();
                let is_epoch_boundary = current_block_number > 0 && 
                    current_block_number % epoch_num == miner_check_len;
                
                let (new_validators, vote_addrs, turn_length) = if is_epoch_boundary {
                    // Epoch boundary detected during execution
                    
                    // Find the checkpoint header (miner_check_len blocks back, like reth-bsc-trail does)
                    let checkpoint_block_number = current_block_number - miner_check_len;
                    // Looking for validator updates in checkpoint block
                    
                    // Use the global snapshot provider to access header data
                    if let Some(provider) = crate::shared::get_snapshot_provider() {
                        // Try to get the checkpoint header from the same provider that has database access
                        match provider.get_checkpoint_header(checkpoint_block_number) {
                            Some(checkpoint_header) => {
                                // Successfully fetched checkpoint header
                                
                                // Parse validator set from checkpoint header (like reth-bsc-trail does)
                                let parsed = crate::consensus::parlia::validator::parse_epoch_update(&checkpoint_header, 
                                    self.spec.is_luban_active_at_block(checkpoint_block_number),
                                    self.spec.is_bohr_active_at_timestamp(checkpoint_header.timestamp)
                                );
                                
                                // Validator set parsed from checkpoint header
                                
                                parsed
                            },
                            None => {
                                tracing::warn!("⚠️ [BSC] Checkpoint header for block {} not found via snapshot provider", checkpoint_block_number);
                                (Vec::new(), None, None)
                            }
                        }
                    } else {
                        tracing::error!("❌ [BSC] No global snapshot provider available for header fetching");
                        (Vec::new(), None, None)
                    }
                } else {
                    (Vec::new(), None, None)
                };

                // Get current header and parse attestation
                let current_header = provider.get_checkpoint_header(current_block_number);
                let (apply_header, attestation) = if let Some(current_header) = current_header {
                    let attestation = crate::consensus::parlia::attestation::parse_vote_attestation_from_header(
                        &current_header,
                        parent_snapshot.epoch_num,
                        self.spec.is_luban_active_at_block(current_block_number),
                        self.spec.is_bohr_active_at_timestamp(current_header.timestamp)
                    );
                    (current_header, attestation)
                } else {
                    // Fallback to the constructed header if we can't get the real one
                    (header, None)
                };

                // Apply current block to parent snapshot (like reth-bsc-trail does)
                if let Some(current_snapshot) = parent_snapshot.apply(
                    current_block.beneficiary, // proposer
                    &apply_header,
                    new_validators, // parsed validators from checkpoint header
                    vote_addrs, // parsed vote addresses from checkpoint header
                    attestation, // parsed attestation from header
                    turn_length, // parsed turn length from checkpoint header
                    &self.spec,
                ) {
                    // Cache the current snapshot immediately (like reth-bsc-trail does)
                    provider.insert(current_snapshot.clone());
                    
                    // Log only for major checkpoints to reduce spam
                    if current_block_number % (crate::consensus::parlia::snapshot::CHECKPOINT_INTERVAL * 10) == 0 {
                        tracing::info!("📦 [BSC] Created checkpoint snapshot for block {}", current_block_number);
                    }
                } else {
                    tracing::error!("❌ [BSC] Failed to apply block {} to parent snapshot", current_block_number);
                }
            } else {
                tracing::warn!("⚠️ [BSC] Parent snapshot not available for block {} during execution", current_block_number);
            }
        } else {
            tracing::warn!("⚠️ [BSC] No snapshot provider available during execution for block {}", current_block_number);
        }

        Ok((
            self.evm,
            BlockExecutionResult {
                receipts: self.receipts,
                requests: Requests::default(),
                gas_used: self.gas_used,
            },
        ))
    }

    fn set_state_hook(&mut self, _hook: Option<Box<dyn OnStateHook>>) {
        self.hook = _hook;
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        &mut self.evm
    }

    fn evm(&self) -> &Self::Evm {
        &self.evm
    }

}