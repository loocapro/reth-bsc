use super::{executor::BscBlockExecutor, factory::BscEvmFactory};
use crate::{
    chainspec::BscChainSpec,
    evm::{spec::BscSpecId, transaction::BscTxEnv},
    hardforks::BscHardforks,
    system_contracts::SystemContract,
    BscPrimitives,
};
use alloy_consensus::{BlockHeader, Header, TxReceipt};
use alloy_primitives::{Log, U256};
use reth_chainspec::{EthChainSpec, EthereumHardforks, Hardforks};
use reth_ethereum_forks::EthereumHardfork;
use reth_evm::{
    block::{BlockExecutorFactory, BlockExecutorFor},
    eth::{receipt_builder::ReceiptBuilder, EthBlockExecutionCtx},
    ConfigureEvm, EvmEnv, EvmFactory, ExecutionCtxFor, FromRecoveredTx, FromTxWithEncoded,
    IntoTxEnv, NextBlockEnvAttributes,
};
use reth_evm_ethereum::{EthBlockAssembler, RethReceiptBuilder};
use reth_primitives::{BlockTy, HeaderTy, SealedBlock, SealedHeader, TransactionSigned};
use reth_revm::State;
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::block::BlobExcessGasAndPrice,
    primitives::hardfork::SpecId,
    Inspector,
};
use std::{borrow::Cow, convert::Infallible, sync::Arc};

/// Ethereum-related EVM configuration.
#[derive(Debug, Clone)]
pub struct BscEvmConfig {
    /// Inner [`BscBlockExecutorFactory`].
    pub executor_factory:
        BscBlockExecutorFactory<RethReceiptBuilder, Arc<BscChainSpec>, BscEvmFactory>,
    /// Ethereum block assembler.
    pub block_assembler: EthBlockAssembler<BscChainSpec>,
}

impl BscEvmConfig {
    /// Creates a new Ethereum EVM configuration with the given chain spec.
    pub fn new(chain_spec: Arc<BscChainSpec>) -> Self {
        Self::bsc(chain_spec)
    }

    /// Creates a new Ethereum EVM configuration.
    pub fn bsc(chain_spec: Arc<BscChainSpec>) -> Self {
        Self::new_with_evm_factory(chain_spec, BscEvmFactory::default())
    }
}

impl BscEvmConfig {
    /// Creates a new Ethereum EVM configuration with the given chain spec and EVM factory.
    pub fn new_with_evm_factory(chain_spec: Arc<BscChainSpec>, evm_factory: BscEvmFactory) -> Self {
        Self {
            block_assembler: EthBlockAssembler::new(chain_spec.clone()),
            executor_factory: BscBlockExecutorFactory::new(
                RethReceiptBuilder::default(),
                chain_spec,
                evm_factory,
            ),
        }
    }

    /// Returns the chain spec associated with this configuration.
    pub const fn chain_spec(&self) -> &Arc<BscChainSpec> {
        self.executor_factory.spec()
    }
}

/// Ethereum block executor factory.
#[derive(Debug, Clone, Default, Copy)]
pub struct BscBlockExecutorFactory<
    R = RethReceiptBuilder,
    Spec = Arc<BscChainSpec>,
    EvmFactory = BscEvmFactory,
> {
    /// Receipt builder.
    receipt_builder: R,
    /// Chain specification.
    spec: Spec,
    /// EVM factory.
    evm_factory: EvmFactory,
}

impl<R, Spec, EvmFactory> BscBlockExecutorFactory<R, Spec, EvmFactory> {
    /// Creates a new [`BscBlockExecutorFactory`] with the given spec, [`EvmFactory`], and
    /// [`ReceiptBuilder`].
    pub const fn new(receipt_builder: R, spec: Spec, evm_factory: EvmFactory) -> Self {
        Self { receipt_builder, spec, evm_factory }
    }

    /// Exposes the receipt builder.
    pub const fn receipt_builder(&self) -> &R {
        &self.receipt_builder
    }

    /// Exposes the chain specification.
    pub const fn spec(&self) -> &Spec {
        &self.spec
    }
}

impl<R, Spec, EvmF> BlockExecutorFactory for BscBlockExecutorFactory<R, Spec, EvmF>
where
    R: ReceiptBuilder<Transaction = TransactionSigned, Receipt: TxReceipt<Log = Log>>,
    Spec: EthereumHardforks + BscHardforks + EthChainSpec + Hardforks + Clone,
    EvmF: EvmFactory<Tx: FromRecoveredTx<TransactionSigned> + FromTxWithEncoded<TransactionSigned>>,
    R::Transaction: From<TransactionSigned> + Clone,
    Self: 'static,
    BscTxEnv<TxEnv>: IntoTxEnv<<EvmF as EvmFactory>::Tx>,
    R::Receipt: serde::Serialize,
{
    type EvmFactory = EvmF;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = TransactionSigned;
    type Receipt = R::Receipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: <Self::EvmFactory as EvmFactory>::Evm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: alloy_evm::Database + 'a,
        I: Inspector<<Self::EvmFactory as EvmFactory>::Context<&'a mut State<DB>>> + 'a,
    {
        BscBlockExecutor::new(
            evm,
            ctx,
            self.spec().clone(),
            self.receipt_builder(),
            SystemContract::new(self.spec().clone()),
        )
    }
}

const EIP1559_INITIAL_BASE_FEE: u64 = 0;

impl ConfigureEvm for BscEvmConfig
where
    Self: Send + Sync + Unpin + Clone + 'static,
{
    type Primitives = BscPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = BscBlockExecutorFactory;
    type BlockAssembler = Self;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self
    }

    fn evm_env(&self, header: &Header) -> EvmEnv<BscSpecId> {
        let blob_params = self.chain_spec().blob_params_at_timestamp(header.timestamp);
        let spec = revm_spec_by_timestamp_and_block_number(
            self.chain_spec().clone(),
            header.timestamp(),
            header.number(),
        );

        // configure evm env based on parent block
        let mut cfg_env =
            CfgEnv::new().with_chain_id(self.chain_spec().chain().id()).with_spec(spec);

        if let Some(blob_params) = &blob_params {
            cfg_env.set_blob_max_count(blob_params.max_blob_count);
        }

        // derive the EIP-4844 blob fees from the header's `excess_blob_gas` and the current
        // blobparams
        let blob_excess_gas_and_price =
            header.excess_blob_gas.zip(blob_params).map(|(excess_blob_gas, params)| {
                let blob_gasprice = params.calc_blob_fee(excess_blob_gas);
                BlobExcessGasAndPrice { excess_blob_gas, blob_gasprice }
            });

        let eth_spec = spec.into_eth_spec();

        let block_env = BlockEnv {
            number: header.number(),
            beneficiary: header.beneficiary(),
            timestamp: header.timestamp(),
            difficulty: if eth_spec >= SpecId::MERGE { U256::ZERO } else { header.difficulty() },
            prevrandao: if eth_spec >= SpecId::MERGE { header.mix_hash() } else { None },
            gas_limit: header.gas_limit(),
            basefee: header.base_fee_per_gas().unwrap_or_default(),
            blob_excess_gas_and_price,
        };

        EvmEnv { cfg_env, block_env }
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnv<BscSpecId>, Self::Error> {
        // ensure we're not missing any timestamp based hardforks
        let spec_id = revm_spec_by_timestamp_and_block_number(
            self.chain_spec().clone(),
            attributes.timestamp,
            parent.number() + 1,
        );

        // configure evm env based on parent block
        let cfg_env =
            CfgEnv::new().with_chain_id(self.chain_spec().chain().id()).with_spec(spec_id);

        // if the parent block did not have excess blob gas (i.e. it was pre-cancun), but it is
        // cancun now, we need to set the excess blob gas to the default value(0)
        let blob_excess_gas_and_price = parent
            .maybe_next_block_excess_blob_gas(
                self.chain_spec().blob_params_at_timestamp(attributes.timestamp),
            )
            .or_else(|| (spec_id.into_eth_spec().is_enabled_in(SpecId::CANCUN)).then_some(0))
            .map(|gas| BlobExcessGasAndPrice::new(gas, false));

        let mut basefee = parent.next_block_base_fee(
            self.chain_spec().base_fee_params_at_timestamp(attributes.timestamp),
        );

        let mut gas_limit = U256::from(parent.gas_limit);

        // If we are on the London fork boundary, we need to multiply the parent's gas limit by the
        // elasticity multiplier to get the new gas limit.
        if self
            .chain_spec()
            .inner
            .fork(EthereumHardfork::London)
            .transitions_at_block(parent.number + 1)
        {
            let elasticity_multiplier = self
                .chain_spec()
                .base_fee_params_at_timestamp(attributes.timestamp)
                .elasticity_multiplier;

            // multiply the gas limit by the elasticity multiplier
            gas_limit *= U256::from(elasticity_multiplier);

            // set the base fee to the initial base fee from the EIP-1559 spec
            basefee = Some(EIP1559_INITIAL_BASE_FEE)
        }

        let block_env = BlockEnv {
            number: parent.number() + 1,
            beneficiary: attributes.suggested_fee_recipient,
            timestamp: attributes.timestamp,
            difficulty: U256::ZERO,
            prevrandao: Some(attributes.prev_randao),
            gas_limit: attributes.gas_limit,
            // calculate basefee based on parent block's gas usage
            basefee: basefee.unwrap_or_default(),
            // calculate excess gas based on parent block's blob gas usage
            blob_excess_gas_and_price,
        };

        Ok(EvmEnv { cfg_env, block_env })
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<BlockTy<Self::Primitives>>,
    ) -> ExecutionCtxFor<'a, Self> {
        EthBlockExecutionCtx {
            parent_hash: block.header().parent_hash,
            parent_beacon_block_root: block.header().parent_beacon_block_root,
            ommers: &block.body().ommers,
            withdrawals: block.body().withdrawals.as_ref().map(Cow::Borrowed),
        }
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<HeaderTy<Self::Primitives>>,
        attributes: Self::NextBlockEnvCtx,
    ) -> ExecutionCtxFor<'_, Self> {
        EthBlockExecutionCtx {
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            ommers: &[],
            withdrawals: attributes.withdrawals.map(Cow::Owned),
        }
    }
}

/// Map the latest active hardfork at the given timestamp or block number to a [`BscSpecId`].
pub fn revm_spec_by_timestamp_and_block_number(
    chain_spec: impl BscHardforks,
    timestamp: u64,
    block_number: u64,
) -> BscSpecId {
    if chain_spec.is_lorentz_active_at_timestamp(timestamp) {
        BscSpecId::LORENTZ
    } else if chain_spec.is_pascal_active_at_timestamp(timestamp) {
        BscSpecId::PASCAL
    } else if chain_spec.is_bohr_active_at_timestamp(timestamp) {
        BscSpecId::BOHR
    } else if chain_spec.is_haber_fix_active_at_timestamp(timestamp) {
        BscSpecId::HABER_FIX
    } else if chain_spec.is_haber_active_at_timestamp(timestamp) {
        BscSpecId::HABER
    } else if chain_spec.is_feynman_fix_active_at_timestamp(timestamp) {
        BscSpecId::FEYNMAN_FIX
    } else if chain_spec.is_feynman_active_at_timestamp(timestamp) {
        BscSpecId::FEYNMAN
    } else if chain_spec.is_kepler_active_at_timestamp(timestamp) {
        BscSpecId::KEPLER
    } else if chain_spec.is_hertz_fix_active_at_block(block_number) {
        BscSpecId::HERTZ_FIX
    } else if chain_spec.is_hertz_active_at_block(block_number) {
        BscSpecId::HERTZ
    } else if chain_spec.is_plato_active_at_block(block_number) {
        BscSpecId::PLATO
    } else if chain_spec.is_luban_active_at_block(block_number) {
        BscSpecId::LUBAN
    } else if chain_spec.is_planck_active_at_block(block_number) {
        BscSpecId::PLANCK
    } else if chain_spec.is_gibbs_active_at_block(block_number) {
        BscSpecId::GIBBS
    } else if chain_spec.is_moran_active_at_block(block_number) {
        BscSpecId::MORAN
    } else if chain_spec.is_nano_active_at_block(block_number) {
        BscSpecId::NANO
    } else if chain_spec.is_euler_active_at_block(block_number) {
        BscSpecId::EULER
    } else if chain_spec.is_bruno_active_at_block(block_number) {
        BscSpecId::BRUNO
    } else if chain_spec.is_mirror_sync_active_at_block(block_number) {
        BscSpecId::MIRROR_SYNC
    } else if chain_spec.is_niels_active_at_block(block_number) {
        BscSpecId::NIELS
    } else if chain_spec.is_ramanujan_active_at_block(block_number) {
        BscSpecId::RAMANUJAN
    } else {
        BscSpecId::FRONTIER
    }
}
