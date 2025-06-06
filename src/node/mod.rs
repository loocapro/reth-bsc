use crate::{
    chainspec::BscChainSpec,
    node::{
        primitives::BscPrimitives,
        rpc::{
            engine_api::{
                builder::BscEngineApiBuilder, payload::BscPayloadTypes,
                validator::BscEngineValidatorBuilder,
            },
            BscEthApiBuilder,
        },
        storage::BscStorage,
    },
    BscBlock, BscBlockBody,
};
use consensus::BscConsensusBuilder;
use engine::BscPayloadServiceBuilder;
use evm::BscExecutorBuilder;
use network::BscNetworkBuilder;
use reth::{
    api::{FullNodeComponents, FullNodeTypes, NodeTypes},
    builder::{
        components::ComponentsBuilder, rpc::RpcAddOns, DebugNode, Node, NodeAdapter,
        NodeComponentsBuilder,
    },
};
use reth_engine_primitives::BeaconConsensusEngineHandle;
use reth_node_ethereum::node::EthereumPoolBuilder;
use reth_primitives::BlockBody;
use reth_provider::providers::ProviderFactoryBuilder;
use reth_trie_db::MerklePatriciaTrie;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

pub mod cli;
pub mod consensus;
pub mod engine;
pub mod evm;
pub mod network;
pub mod primitives;
pub mod rpc;
pub mod storage;

/// Bsc addons configuring RPC types
pub type BscNodeAddOns<N> =
    RpcAddOns<N, BscEthApiBuilder, BscEngineValidatorBuilder, BscEngineApiBuilder>;

/// Type configuration for a regular BSC node.
#[derive(Debug, Clone)]
pub struct BscNode {
    engine_handle_rx:
        Arc<Mutex<Option<oneshot::Receiver<BeaconConsensusEngineHandle<BscPayloadTypes>>>>>,
}

impl BscNode {
    pub fn new() -> (Self, oneshot::Sender<BeaconConsensusEngineHandle<BscPayloadTypes>>) {
        let (tx, rx) = oneshot::channel();
        (Self { engine_handle_rx: Arc::new(Mutex::new(Some(rx))) }, tx)
    }
}

impl BscNode {
    pub fn components<Node>(
        &self,
    ) -> ComponentsBuilder<
        Node,
        EthereumPoolBuilder,
        BscPayloadServiceBuilder,
        BscNetworkBuilder,
        BscExecutorBuilder,
        BscConsensusBuilder,
    >
    where
        Node: FullNodeTypes<Types = Self>,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(EthereumPoolBuilder::default())
            .executor(BscExecutorBuilder::default())
            .payload(BscPayloadServiceBuilder::default())
            .network(BscNetworkBuilder { engine_handle_rx: self.engine_handle_rx.clone() })
            .consensus(BscConsensusBuilder::default())
    }

    pub fn provider_factory_builder() -> ProviderFactoryBuilder<Self> {
        ProviderFactoryBuilder::default()
    }
}

impl NodeTypes for BscNode {
    type Primitives = BscPrimitives;
    type ChainSpec = BscChainSpec;
    type StateCommitment = MerklePatriciaTrie;
    type Storage = BscStorage;
    type Payload = BscPayloadTypes;
}

impl<N> Node<N> for BscNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        BscPayloadServiceBuilder,
        BscNetworkBuilder,
        BscExecutorBuilder,
        BscConsensusBuilder,
    >;

    type AddOns = BscNodeAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components(self)
    }

    fn add_ons(&self) -> Self::AddOns {
        BscNodeAddOns::default()
    }
}

impl<N> DebugNode<N> for BscNode
where
    N: FullNodeComponents<Types = Self>,
{
    type RpcBlock = alloy_rpc_types::Block;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> BscBlock {
        let alloy_rpc_types::Block { header, transactions, withdrawals, .. } = rpc_block;
        BscBlock {
            header: header.inner,
            body: BscBlockBody {
                inner: BlockBody {
                    transactions: transactions
                        .into_transactions()
                        .map(|tx| tx.inner.into_inner().into())
                        .collect(),
                    ommers: Default::default(),
                    withdrawals,
                },
                sidecars: None,
            },
        }
    }
}
