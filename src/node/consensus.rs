use crate::{
    node::BscNode, 
    BscPrimitives,
    consensus::parlia::{ParliaConsensus, provider::EnhancedDbSnapshotProvider, EPOCH},
};
use reth::{
    api::FullNodeTypes,
    builder::{components::ConsensusBuilder, BuilderContext},
    consensus::{ConsensusError, FullConsensus},
};

use std::sync::Arc;
use reth_chainspec::EthChainSpec;


/// A basic Bsc consensus builder.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct BscConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for BscConsensusBuilder
where
    Node: FullNodeTypes<Types = BscNode>,
{
    type Consensus = Arc<dyn FullConsensus<BscPrimitives, Error = ConsensusError>>;

    /// return a parlia consensus instance, automatically called by the ComponentsBuilder framework.
    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        let snapshot_provider = try_create_ondemand_snapshots(ctx)
            .unwrap_or_else(|e| {
                panic!("Failed to initialize on-demand MDBX snapshots: {}", e);
            });
        
        let consensus_concrete: ParliaConsensus<_, _> = ParliaConsensus::new(
            ctx.chain_spec(),
            snapshot_provider.clone(),
            EPOCH, // BSC epoch length (200 blocks)
        );

        // Store the snapshot provider globally so RPC can access it
        let _ = crate::shared::set_snapshot_provider(
            snapshot_provider as Arc<dyn crate::consensus::parlia::SnapshotProvider + Send + Sync>,
        );

        // Store consensus globally for RPC access as a trait object that also exposes validator API
        let consensus_obj_global: Arc<dyn crate::consensus::parlia::ParliaConsensusObject + Send + Sync> = Arc::new(consensus_concrete.clone());
        let _ = crate::shared::set_parlia_consensus(consensus_obj_global);

        // Return the consensus as FullConsensus for the builder API
        let consensus_obj: Arc<dyn FullConsensus<BscPrimitives, Error = ConsensusError>> = Arc::new(consensus_concrete);
        Ok(consensus_obj)
    }
}

/// Attempts to create on-demand snapshots using a separate database instance
/// and access to the blockchain provider for header lookups
/// 
/// This follows a safe pattern where we create a separate database connection
/// for snapshot storage, avoiding the need for unsafe access to provider internals.
fn try_create_ondemand_snapshots<Node>(
    ctx: &BuilderContext<Node>,
) -> eyre::Result<Arc<EnhancedDbSnapshotProvider<Arc<reth_db::DatabaseEnv>, Node::Provider>>>
where
    Node: FullNodeTypes<Types = BscNode>,
{
    // Create a separate database instance for snapshot storage in its own directory
    // This avoids conflicts with the main database
    let datadir = ctx.config().datadir.clone();
    let main_dir = datadir.resolve_datadir(ctx.chain_spec().chain());
    let db_path = main_dir.data_dir().join("parlia_snapshots");
    
    // Initialize our own database instance for snapshot storage
    use reth_db::{init_db, mdbx::DatabaseArguments};
    
    let snapshot_db = Arc::new(init_db(
        &db_path,
        DatabaseArguments::new(Default::default())
    ).map_err(|e| eyre::eyre!("Failed to initialize snapshot database: {}", e))?);
    
    tracing::info!("Succeed to create a separate database instance for persistent snapshots");
    
    // Get access to the blockchain provider for header lookups
    let blockchain_provider = Arc::new(ctx.provider().clone());
    
    // Create EnhancedDbSnapshotProvider with backward walking capability (reth-bsc-trail/bsc-erigon style)
    let snapshot_provider = Arc::new(EnhancedDbSnapshotProvider::new(
        snapshot_db,
        2048, // Production LRU cache size
        blockchain_provider,
        ctx.chain_spec().clone(),
    ));
    
    tracing::info!("Succeed to create EnhancedDbSnapshotProvider with backward walking capability");
    
    Ok(snapshot_provider)
}
