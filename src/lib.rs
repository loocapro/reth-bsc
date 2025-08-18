pub mod chainspec;
pub mod consensus;
pub mod evm;
mod hardforks;
pub mod node;
pub mod rpc;
pub mod shared;
pub use node::primitives::BscPrimitives;
// Re-export the BSC-specific block types so modules can `use crate::{BscBlock, BscBlockBody, …}`
pub use node::primitives::{BscBlock, BscBlockBody, BscBlobTransactionSidecar};
mod system_contracts;
pub use system_contracts::SLASH_CONTRACT;
#[path = "system_contracts/tx_maker_ext.rs"]
mod system_tx_ext;
#[allow(unused_imports)]
pub use system_tx_ext::*;
