use clap::{Args, Parser};
use reth::builder::NodeHandle;
use reth_bsc::{
    chainspec::parser::BscChainSpecParser,
    consensus::ParliaConsensus,
    node::{
        cli::Cli, network::block_import::service::ImportService as BlockImportService, BscNode,
    },
};
use std::sync::Arc;
use tracing::error;

// We use jemalloc for performance reasons
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// No Additional arguments
#[derive(Debug, Clone, Copy, Default, Args)]
#[non_exhaustive]
struct NoArgs;

fn main() -> eyre::Result<()> {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    Cli::<BscChainSpecParser, NoArgs>::parse().run(|builder, _| async move {
        let NodeHandle { node, node_exit_future: exit_future } =
            builder.node(BscNode::default()).launch().await?;
        let provider = node.provider.clone();
        let consensus = Arc::new(ParliaConsensus { provider });
        let (service, _) = BlockImportService::new(consensus, node.beacon_engine_handle.clone());

        node.task_executor.spawn(async move {
            if let Err(e) = service.await {
                error!("Import service error: {}", e);
            }
        });

        exit_future.await
    })?;
    Ok(())
}
