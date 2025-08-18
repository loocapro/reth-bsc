
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObject};
use serde::{Deserialize, Serialize};

use crate::consensus::parlia::{Snapshot, SnapshotProvider};

use std::sync::Arc;

/// Validator information in the snapshot (matches BSC official format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    #[serde(rename = "index:omitempty")]
    pub index: u64,
    pub vote_address: Vec<u8>, // 48-byte vote address array as vec for serde compatibility
}

impl Default for ValidatorInfo {
    fn default() -> Self {
        Self {
            index: 0,
            vote_address: vec![0; 48], // All zeros as shown in BSC example
        }
    }
}

/// Official BSC Parlia snapshot response structure matching bsc-erigon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotResult {
    pub number: u64,
    pub hash: String,
    pub epoch_length: u64,
    pub block_interval: u64,
    pub turn_length: u8,
    pub validators: std::collections::HashMap<String, ValidatorInfo>,
    pub recents: std::collections::HashMap<String, String>,
    pub recent_fork_hashes: std::collections::HashMap<String, String>,
    #[serde(rename = "attestation:omitempty")]
    pub attestation: Option<serde_json::Value>,
}

impl From<Snapshot> for SnapshotResult {
    fn from(snapshot: Snapshot) -> Self {
        // Convert validators to the expected format: address -> ValidatorInfo
        let validators: std::collections::HashMap<String, ValidatorInfo> = snapshot
            .validators
            .iter()
            .map(|addr| {
                (
                    format!("0x{:040x}", addr), // 40-char hex address
                    ValidatorInfo::default(),
                )
            })
            .collect();

        // Convert recent proposers to string format: block_number -> address
        let recents: std::collections::HashMap<String, String> = snapshot
            .recent_proposers
            .iter()
            .map(|(block_num, addr)| {
                (
                    block_num.to_string(),
                    format!("0x{:040x}", addr),
                )
            })
            .collect();

        // Generate recent fork hashes (simplified - all zeros like in BSC example)
        let recent_fork_hashes: std::collections::HashMap<String, String> = snapshot
            .recent_proposers
            .keys()
            .map(|block_num| {
                (
                    block_num.to_string(),
                    "00000000".to_string(), // Simplified fork hash
                )
            })
            .collect();

        Self {
            number: snapshot.block_number,
            hash: format!("0x{:064x}", snapshot.block_hash),
            epoch_length: 200, // BSC epoch length
            block_interval: 3000, // BSC block interval in milliseconds
            turn_length: snapshot.turn_length.unwrap_or(1),
            validators,
            recents,
            recent_fork_hashes,
            attestation: None,
        }
    }
}

/// Parlia snapshot RPC API (matches BSC official standard)
#[rpc(server, namespace = "parlia")]
pub trait ParliaApi {
    /// Get snapshot at a specific block (official BSC API method)
    /// Params: block number as hex string (e.g., "0x123132")
    #[method(name = "getSnapshot")]
    async fn get_snapshot(&self, block_number: String) -> RpcResult<Option<SnapshotResult>>;
}

/// Implementation of the Parlia snapshot RPC API
pub struct ParliaApiImpl<P: SnapshotProvider> {
    /// Snapshot provider for accessing validator snapshots
    snapshot_provider: Arc<P>,
}

/// Wrapper for trait object to work around Sized requirement
pub struct DynSnapshotProvider {
    inner: Arc<dyn SnapshotProvider + Send + Sync>,
}

impl DynSnapshotProvider {
    pub fn new(provider: Arc<dyn SnapshotProvider + Send + Sync>) -> Self {
        Self { inner: provider }
    }
}

impl SnapshotProvider for DynSnapshotProvider {
    fn snapshot(&self, block_number: u64) -> Option<crate::consensus::parlia::snapshot::Snapshot> {
        self.inner.snapshot(block_number)
    }

    fn insert(&self, snapshot: crate::consensus::parlia::snapshot::Snapshot) {
        self.inner.insert(snapshot)
    }
    
    fn get_checkpoint_header(&self, block_number: u64) -> Option<alloy_consensus::Header> {
        self.inner.get_checkpoint_header(block_number)
    }
}

/// Convenience type alias for ParliaApiImpl using the wrapper
pub type ParliaApiDyn = ParliaApiImpl<DynSnapshotProvider>;

impl<P: SnapshotProvider> ParliaApiImpl<P> {
    /// Create a new Parlia API instance
    pub fn new(snapshot_provider: Arc<P>) -> Self {
        Self { snapshot_provider }
    }
}

#[async_trait::async_trait]
impl<P: SnapshotProvider + Send + Sync + 'static> ParliaApiServer for ParliaApiImpl<P> {
    /// Get snapshot at a specific block (matches BSC official API.GetSnapshot)
    /// Accepts block number as hex string like "0x123132"
    async fn get_snapshot(&self, block_number: String) -> RpcResult<Option<SnapshotResult>> {
        // parlia_getSnapshot called
        
        // Parse hex block number (like BSC API does)
        let block_num = if block_number.starts_with("0x") {
            match u64::from_str_radix(&block_number[2..], 16) {
                Ok(num) => {
                    // Parsed hex block number
                    num
                },
                Err(e) => {
                    tracing::error!("❌ [BSC-RPC] Failed to parse hex block number '{}': {}", block_number, e);
                    return Err(ErrorObject::owned(
                        -32602, 
                        "Invalid block number format", 
                        None::<()>
                    ).into());
                }
            }
        } else {
            match block_number.parse::<u64>() {
                Ok(num) => {
                    // Parsed decimal block number
                    num
                },
                Err(e) => {
                    tracing::error!("❌ [BSC-RPC] Failed to parse decimal block number '{}': {}", block_number, e);
                    return Err(ErrorObject::owned(
                        -32602, 
                        "Invalid block number format", 
                        None::<()>
                    ).into());
                }
            }
        };
        
        // Querying snapshot provider
        
        // Get snapshot from provider (equivalent to api.parlia.snapshot call in BSC)
        match self.snapshot_provider.snapshot(block_num) {
            Some(snapshot) => {
                tracing::info!("✅ [BSC-RPC] Found snapshot for block {}: validators={}, epoch_num={}, block_hash=0x{:x}", 
                    block_num, snapshot.validators.len(), snapshot.epoch_num, snapshot.block_hash);
                let result: SnapshotResult = snapshot.into();
                // Snapshot result prepared
                Ok(Some(result))
            },
            None => {
                tracing::warn!("⚠️ [BSC-RPC] No snapshot found for block {}", block_num);
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chainspec::{bsc_testnet, BscChainSpec};
    use crate::consensus::parlia::provider::EnhancedDbSnapshotProvider;
    use reth_db::test_utils::create_test_rw_db;
    use reth_provider::test_utils::NoopProvider;


    #[tokio::test]
    async fn test_snapshot_api() {
        // Build an EnhancedDbSnapshotProvider backed by a temp DB and noop header provider
        let db = create_test_rw_db();
        let header_provider = Arc::new(NoopProvider::default());
        let chain_spec = Arc::new(BscChainSpec::from(bsc_testnet()));
        let snapshot_provider = Arc::new(EnhancedDbSnapshotProvider::new(
            db.clone(),
            2048,
            header_provider,
            chain_spec,
        ));
        
        // Insert a test snapshot
        let mut test_snapshot = Snapshot::default();
        test_snapshot.block_number = 100;
        test_snapshot.validators = vec![alloy_primitives::Address::random(), alloy_primitives::Address::random()];
        test_snapshot.epoch_num = 200;
        test_snapshot.turn_length = Some(1);
        snapshot_provider.insert(test_snapshot.clone());

        let api = ParliaApiImpl::new(snapshot_provider);
        
        // Test snapshot retrieval with hex block number (BSC official format)
        let result = api.get_snapshot("0x64".to_string()).await.unwrap(); // 0x64 = 100
        assert!(result.is_some());
        
        let snapshot_result = result.unwrap();
        assert_eq!(snapshot_result.number, 100);
        assert_eq!(snapshot_result.validators.len(), 2);
        assert_eq!(snapshot_result.epoch_length, 200);
        assert_eq!(snapshot_result.turn_length, 1);
        
        // Test with decimal format too
        let result = api.get_snapshot("100".to_string()).await.unwrap();
        assert!(result.is_some());
    }
}