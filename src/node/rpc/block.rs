use crate::{
    chainspec::BscChainSpec,
    node::rpc::{BscEthApi, BscNodeCore},
    BscBlock, BscPrimitives,
};
use alloy_consensus::BlockHeader;
use alloy_primitives::B256;
use reth::{
    api::NodeTypes,
    builder::FullNodeComponents,
    primitives::{Receipt, SealedHeader, TransactionMeta, TransactionSigned},
    providers::{BlockReaderIdExt, ProviderHeader, ReceiptProvider, TransactionsProvider},
    rpc::{
        eth::EthApiTypes,
        server_types::eth::{error::FromEvmError, EthApiError, EthReceiptBuilder, PendingBlock},
        types::{BlockId, TransactionReceipt},
    },
    transaction_pool::{PoolTransaction, TransactionPool},
};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_primitives_traits::SignerRecoverable;
use reth_provider::{
    BlockReader, ChainSpecProvider, HeaderProvider, ProviderBlock, ProviderReceipt, ProviderTx,
    StateProviderFactory,
};
use reth_rpc_eth_api::{
    helpers::{EthBlocks, LoadBlock, LoadPendingBlock, LoadReceipt, SpawnBlocking},
    types::RpcTypes,
    FromEthApiError, RpcConvert, RpcNodeCore, RpcNodeCoreExt, RpcReceipt,
};
use std::borrow::Cow;

impl<N> EthBlocks for BscEthApi<N>
where
    Self: LoadBlock<
        Error = EthApiError,
        NetworkTypes: RpcTypes<Receipt = TransactionReceipt>,
        Provider: BlockReader<Transaction = TransactionSigned, Receipt = Receipt>,
    >,
    N: BscNodeCore<Provider: ChainSpecProvider<ChainSpec = BscChainSpec> + HeaderProvider>,
{
    async fn block_receipts(
        &self,
        block_id: BlockId,
    ) -> Result<Option<Vec<RpcReceipt<Self::NetworkTypes>>>, Self::Error>
    where
        Self: LoadReceipt,
    {
        if let Some((block, receipts)) = self.load_block_and_receipts(block_id).await? {
            let block_number = block.number();
            let base_fee = block.base_fee_per_gas();
            let block_hash = block.hash();
            let excess_blob_gas = block.excess_blob_gas();
            let timestamp = block.timestamp();
            let blob_params = self.provider().chain_spec().blob_params_at_timestamp(timestamp);

            return block
                .transactions_recovered()
                .zip(receipts.iter())
                .enumerate()
                .map(|(idx, (tx, receipt))| {
                    let meta = TransactionMeta {
                        tx_hash: *tx.tx_hash(),
                        index: idx as u64,
                        block_hash,
                        block_number,
                        base_fee,
                        excess_blob_gas,
                        timestamp,
                    };
                    Ok(EthReceiptBuilder::new(
                        tx,
                        meta,
                        Cow::Borrowed(receipt),
                        &receipts,
                        blob_params,
                    )
                    .build())
                })
                .collect::<Result<Vec<_>, Self::Error>>()
                .map(Some)
        }

        Ok(None)
    }
}

impl<N> LoadBlock for BscEthApi<N>
where
    Self: LoadPendingBlock
        + SpawnBlocking
        + RpcNodeCoreExt<
            Pool: TransactionPool<
                Transaction: PoolTransaction<Consensus = ProviderTx<Self::Provider>>,
            >,
        >,
    N: BscNodeCore,
{
}

impl<N> LoadPendingBlock for BscEthApi<N>
where
    Self: SpawnBlocking
        + EthApiTypes<
            NetworkTypes: RpcTypes<
                Header = alloy_rpc_types_eth::Header<ProviderHeader<Self::Provider>>,
            >,
            Error: FromEvmError<Self::Evm>,
            RpcConvert: RpcConvert<Network = Self::NetworkTypes>,
        >,
    N: RpcNodeCore<
        Provider: BlockReaderIdExt<
            Transaction = TransactionSigned,
            Block = BscBlock,
            Receipt = Receipt,
            Header = alloy_consensus::Header,
        > + ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks>
                      + StateProviderFactory,
        Pool: TransactionPool<Transaction: PoolTransaction<Consensus = ProviderTx<N::Provider>>>,
        Evm: ConfigureEvm<Primitives = BscPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
{
    #[inline]
    fn pending_block(
        &self,
    ) -> &tokio::sync::Mutex<
        Option<PendingBlock<ProviderBlock<Self::Provider>, ProviderReceipt<Self::Provider>>>,
    > {
        self.inner.eth_api.pending_block()
    }

    fn next_env_attributes(
        &self,
        parent: &SealedHeader<ProviderHeader<Self::Provider>>,
    ) -> Result<<Self::Evm as reth_evm::ConfigureEvm>::NextBlockEnvCtx, Self::Error> {
        Ok(NextBlockEnvAttributes {
            timestamp: parent.timestamp().saturating_add(12),
            suggested_fee_recipient: parent.beneficiary(),
            prev_randao: B256::random(),
            gas_limit: parent.gas_limit(),
            parent_beacon_block_root: parent.parent_beacon_block_root(),
            withdrawals: None,
        })
    }
}

impl<N> LoadReceipt for BscEthApi<N>
where
    Self: Send + Sync,
    N: FullNodeComponents<Types: NodeTypes<ChainSpec = BscChainSpec>>,
    Self::Provider:
        TransactionsProvider<Transaction = TransactionSigned> + ReceiptProvider<Receipt = Receipt>,
{
    async fn build_transaction_receipt(
        &self,
        tx: TransactionSigned,
        meta: TransactionMeta,
        receipt: Receipt,
    ) -> Result<RpcReceipt<Self::NetworkTypes>, Self::Error> {
        let hash = meta.block_hash;
        // get all receipts for the block
        let all_receipts = self
            .cache()
            .get_receipts(hash)
            .await
            .map_err(Self::Error::from_eth_err)?
            .ok_or(EthApiError::HeaderNotFound(hash.into()))?;
        let blob_params = self.provider().chain_spec().blob_params_at_timestamp(meta.timestamp);

        Ok(EthReceiptBuilder::new(
            // Note: we assume this transaction is valid, because it's mined and therefore valid
            tx.try_into_recovered_unchecked()?.as_recovered_ref(),
            meta,
            Cow::Borrowed(&receipt),
            &all_receipts,
            blob_params,
        )
        .build())
    }
}
