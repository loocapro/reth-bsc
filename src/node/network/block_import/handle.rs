use std::task::{Context, Poll};

use reth_engine_primitives::EngineTypes;
use reth_network::import::BlockImportError;
use reth_network_api::PeerId;
use reth_payload_primitives::PayloadTypes;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::service::{BlockMsg, ImportEvent, IncomingBlock, Outcome};

/// A handle for interacting with the block import service.
///
/// This handle provides a bidirectional communication channel with the
/// [`super::service::ImportService`]:
/// - Blocks can be sent to the service for import via [`send_block`](ImportHandle::send_block)
/// - Import outcomes can be received via [`poll_outcome`](ImportHandle::poll_outcome)`
#[derive(Debug)]
pub struct ImportHandle {
    /// Send the new block to the service
    to_import: UnboundedSender<IncomingBlock>,
    /// Receive the event(Announcement/Outcome) of the import
    import_outcome: UnboundedReceiver<ImportEvent>,
}

impl ImportHandle {
    /// Create a new handle with the provided channels
    pub fn new(
        to_import: UnboundedSender<IncomingBlock>,
        import_outcome: UnboundedReceiver<ImportEvent>,
    ) -> Self {
        Self { to_import, import_outcome }
    }

    /// Sends the block to import to the service.
    /// Returns a [`BlockImportError`] if the channel to the import service is closed.
    pub fn send_block(&self, block: BlockMsg, peer_id: PeerId) -> Result<(), BlockImportError> {
        self.to_import
            .send((block, peer_id))
            .map_err(|_| BlockImportError::Other("block import service channel closed".into()))
    }

    /// Poll for the next import event
    pub fn poll_outcome(&mut self, cx: &mut Context<'_>) -> Poll<Option<ImportEvent>> {
        self.import_outcome.poll_recv(cx)
    }
}
