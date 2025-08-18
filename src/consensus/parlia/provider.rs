use super::snapshot::Snapshot;
use parking_lot::RwLock;
use std::sync::Arc;
use reth_provider::{HeaderProvider, BlockReader};
use crate::chainspec::BscChainSpec;
use crate::hardforks::BscHardforks;


/// Trait for creating snapshots on-demand when parent snapshots are missing
/// This will be removed in favor of integrating the logic into DbSnapshotProvider
pub trait OnDemandSnapshotCreator {
    /// Create a snapshot for the given block by working backwards to find an existing snapshot
    /// and then building forward
    fn create_snapshot_on_demand(&self, target_block_number: u64) -> Option<Snapshot>;
}

// ---------------------------------------------------------------------------
// MDBX‐backed snapshot provider with LRU front‐cache
// ---------------------------------------------------------------------------

use reth_db::{Database, DatabaseError};
use reth_db::table::{Compress, Decompress};
use reth_db::models::ParliaSnapshotBlob;
use reth_db::transaction::{DbTx, DbTxMut};
use reth_db::cursor::DbCursorRO;
use schnellru::{ByLength, LruMap};

pub trait SnapshotProvider: Send + Sync {
    /// Returns the snapshot that is valid for the given `block_number` (usually parent block).
    fn snapshot(&self, block_number: u64) -> Option<Snapshot>;

    /// Inserts (or replaces) the snapshot in the provider.
    fn insert(&self, snapshot: Snapshot);
    
    /// Fetches header by block number for checkpoint parsing (like reth-bsc-trail's get_header_by_hash)
    fn get_checkpoint_header(&self, block_number: u64) -> Option<alloy_consensus::Header>;
}

/// `DbSnapshotProvider` wraps an MDBX database; it keeps a small in-memory LRU to avoid hitting
/// storage for hot epochs. The DB layer persists snapshots as CBOR blobs via the `ParliaSnapshots`
/// table that is already defined in `db.rs`.
/// 
/// Enhanced to include backward walking logic like reth-bsc-trail and bsc-erigon.
#[derive(Debug)]
pub struct DbSnapshotProvider<DB: Database> {
    db: DB,
    /// Front cache keyed by *block number*.
    cache: RwLock<LruMap<u64, Snapshot, ByLength>>,
}

/// Enhanced version with backward walking capability
#[derive(Debug)]
pub struct EnhancedDbSnapshotProvider<DB: Database, Provider> {
    base: DbSnapshotProvider<DB>,
    /// Header provider for backward walking
    header_provider: Arc<Provider>,
    /// Chain spec for genesis snapshot creation
    chain_spec: Arc<BscChainSpec>,
}

impl<DB: Database> DbSnapshotProvider<DB> {
    pub fn new(db: DB, capacity: usize) -> Self {
        Self { 
            db, 
            cache: RwLock::new(LruMap::new(ByLength::new(capacity as u32))),
        }
    }
}

impl<DB: Database, Provider> EnhancedDbSnapshotProvider<DB, Provider> 
where
    Provider: HeaderProvider<Header = alloy_consensus::Header> + BlockReader + Send + Sync + 'static,
{
    pub fn new(
        db: DB, 
        capacity: usize, 
        header_provider: Arc<Provider>,
        chain_spec: Arc<BscChainSpec>,
    ) -> Self {
        Self { 
            base: DbSnapshotProvider::new(db, capacity),
            header_provider,
            chain_spec,
        }
    }
}

impl<DB: Database + Clone> Clone for DbSnapshotProvider<DB> {
    fn clone(&self) -> Self {
        // Create a new instance with the same database but a fresh cache
        Self::new(self.db.clone(), 2048)
    }
}

impl<DB: Database + Clone, Provider: Clone> Clone for EnhancedDbSnapshotProvider<DB, Provider> {
    fn clone(&self) -> Self {
        Self {
            base: self.base.clone(),
            header_provider: self.header_provider.clone(),
            chain_spec: self.chain_spec.clone(),
        }
    }
}

impl<DB: Database> DbSnapshotProvider<DB> {
    fn load_from_db(&self, block_number: u64) -> Option<Snapshot> {
        let tx = self.db.tx().ok()?;
        
        // Try to get the exact snapshot for the requested block number
        if let Ok(Some(raw_blob)) = tx.get::<crate::consensus::parlia::db::ParliaSnapshots>(block_number) {
            let raw = &raw_blob.0;
            if let Ok(decoded) = Snapshot::decompress(raw) {
                tracing::debug!("Succeed to find snapshot for block {} from DB (snapshot_block={})", block_number, decoded.block_number);
                return Some(decoded);
            }
        }
        
        tracing::debug!("Failed to find snapshot for block {}, searching for fallback...", block_number);
        
        // If exact snapshot not found, look for the most recent snapshot before this block
        let mut cursor = tx
            .cursor_read::<crate::consensus::parlia::db::ParliaSnapshots>()
            .ok()?;
        let mut iter = cursor.walk_range(..block_number).ok()?;
        let mut last: Option<Snapshot> = None;
        let mut found_count = 0;
        
        while let Some(Ok((db_block_num, raw_blob))) = iter.next() {
            let raw = &raw_blob.0;
            if let Ok(decoded) = Snapshot::decompress(raw) {
                found_count += 1;
                tracing::trace!("Scan snapshot in DB, block {} -> snapshot_block {}", db_block_num, decoded.block_number);
                last = Some(decoded);
            }
        }
        
        if let Some(ref snap) = last {
            tracing::debug!("Succeed to find fallback snapshot for block {} at block {} in DB (searched {} snapshots)", block_number, snap.block_number, found_count);
        } else {
            tracing::debug!("Failed to find snapshot for block {} from DB", block_number);
        }
        last
    }

    fn persist_to_db(&self, snap: &Snapshot) -> Result<(), DatabaseError> {
        let tx = self.db.tx_mut()?;
        tx.put::<crate::consensus::parlia::db::ParliaSnapshots>(snap.block_number, ParliaSnapshotBlob(snap.clone().compress()))?;
        tx.commit()?;
        tracing::debug!("Succeed to insert snapshot block {} to DB", snap.block_number);
        Ok(())
    }
}

impl<DB: Database + 'static> SnapshotProvider for DbSnapshotProvider<DB> {
    fn snapshot(&self, block_number: u64) -> Option<Snapshot> {
        // fast path: cache
        {
            let mut guard = self.cache.write();
            if let Some(snap) = guard.get(&block_number) {
                return Some(snap.clone());
            }
        }

        // slow path: DB scan
        let snap = self.load_from_db(block_number)?;
        self.cache.write().insert(block_number, snap.clone());
        Some(snap)
    }

    fn insert(&self, snapshot: Snapshot) {
        // update cache
        self.cache.write().insert(snapshot.block_number, snapshot.clone());
        // Persist only at checkpoint boundaries to reduce I/O.
        if snapshot.block_number % crate::consensus::parlia::snapshot::CHECKPOINT_INTERVAL == 0 {
            match self.persist_to_db(&snapshot) {
                Ok(()) => {
                    tracing::debug!("Succeed to persist snapshot for block {} to DB", snapshot.block_number);
                },
                Err(e) => {
                    tracing::error!("Failed to persist snapshot for block {} to DB due to {:?}", snapshot.block_number, e);
                }
            }
        }
    }
    
    fn get_checkpoint_header(&self, _block_number: u64) -> Option<alloy_consensus::Header> {
        tracing::info!("Get checkpoint header for block {} in DbSnapshotProvider", _block_number);
        // DbSnapshotProvider doesn't have access to headers
        unimplemented!("DbSnapshotProvider doesn't have access to headers");
    }
}

// Simplified version based on reth-bsc-trail's approach - much faster and simpler
impl<DB: Database + 'static, Provider> SnapshotProvider for EnhancedDbSnapshotProvider<DB, Provider> 
where
    Provider: HeaderProvider<Header = alloy_consensus::Header> + BlockReader + Send + Sync + 'static,
{
    fn snapshot(&self, block_number: u64) -> Option<Snapshot> {
        // Early return for cached snapshots to avoid expensive computation
        {
            let mut cache_guard = self.base.cache.write();
            if let Some(cached_snap) = cache_guard.get(&block_number) {
                tracing::debug!("Succeed to query snapshot from cache, request {} -> found snapshot for block {}", block_number, cached_snap.block_number);
                return Some(cached_snap.clone());
            }
        }
        
        // Cache miss, starting backward walking

        // simple backward walking + proper epoch updates
        let mut current_block = block_number;
        let mut headers_to_apply = Vec::new();

        // 1. Backward walking loop 
        let base_snapshot = loop {
            // Check cache first (need write lock for LRU get operation)
            {
                let mut cache_guard = self.base.cache.write();
                if let Some(snap) = cache_guard.get(&current_block) {
                    break snap.clone();
                }
            }

            // Check database at checkpoint intervals (every 1024 blocks)
            if current_block % crate::consensus::parlia::snapshot::CHECKPOINT_INTERVAL == 0 {
                if let Some(snap) = self.base.load_from_db(current_block) {
                    tracing::debug!("🔍 [BSC] Found checkpoint snapshot in DB: block {} -> snapshot_block {}", current_block, snap.block_number);
                    if snap.block_number == current_block {
                        // Only use the snapshot if it's actually for the requested block
                        self.base.cache.write().insert(current_block, snap.clone());
                        break snap;
                    } else {
                        tracing::warn!("🚨 [BSC] DB returned wrong snapshot: requested block {} but got snapshot for block {} - this indicates the snapshot hasn't been created yet", current_block, snap.block_number);
                        // Don't break here - continue backward walking to find a valid parent snapshot
                    }
                } else {
                    tracing::debug!("🔍 [BSC] No checkpoint snapshot found in DB for block {}", current_block);
                }
            }

            // Genesis handling - create genesis snapshot 
            if current_block == 0 {
                tracing::debug!("🚀 [BSC] Creating genesis snapshot for backward walking");
                if let Ok(genesis_snap) = crate::consensus::parlia::ParliaConsensus::<BscChainSpec, DbSnapshotProvider<DB>>::create_genesis_snapshot(
                    self.chain_spec.clone(),
                    crate::consensus::parlia::EPOCH
                ) {
                    self.base.cache.write().insert(0, genesis_snap.clone());
                    break genesis_snap;
                } else {
                    tracing::error!("❌ [BSC] Failed to create genesis snapshot");
                    return None;
                }
            }

                            // Collect header for forward application - fail if not available 
                if let Ok(Some(header)) = self.header_provider.header_by_number(current_block) {
                    headers_to_apply.push(header);
                    current_block = current_block.saturating_sub(1);
                } else {
                    // Header not available - this is common during Bodies stage validation
                    // where headers might not be available in dependency order.
                    // Fail gracefully to defer validation to Execution stage.
                    if block_number % 100000 == 0 { // only log every 100k blocks to reduce spam
                        tracing::debug!("🔄 [BSC] Header {} not available for snapshot creation (block {}), deferring to execution stage", current_block, block_number);
                    }
                    return None;
                }
        };

        // 2. Apply headers forward with epoch updates 
        headers_to_apply.reverse();
        let mut working_snapshot = base_snapshot;

        for (_index, header) in headers_to_apply.iter().enumerate() {
            // Check for epoch boundary (following reth-bsc-trail pattern)
            let epoch_remainder = header.number % working_snapshot.epoch_num;
            let miner_check_len = working_snapshot.miner_history_check_len();
            let is_epoch_boundary = header.number > 0 && epoch_remainder == miner_check_len;
            
            let (new_validators, vote_addrs, turn_length) = if is_epoch_boundary {
                // Epoch boundary detected
                
                // Parse validator set from checkpoint header (miner_check_len blocks back, like reth-bsc-trail)
                let checkpoint_block_number = header.number - miner_check_len;
                // Looking for validator updates in checkpoint block
                
                // Find the checkpoint header in our headers_to_apply list
                // Checking available headers for checkpoint parsing
                
                let checkpoint_header = headers_to_apply.iter()
                    .find(|h| h.number == checkpoint_block_number);
                
                if let Some(checkpoint_header) = checkpoint_header {
                    let parsed = super::validator::parse_epoch_update(checkpoint_header, 
                        self.chain_spec.is_luban_active_at_block(checkpoint_header.number),
                        self.chain_spec.is_bohr_active_at_timestamp(checkpoint_header.timestamp)
                    );                    
                    parsed
                } else {
                    tracing::warn!("⚠️ [BSC] Checkpoint header for block {} not found in headers_to_apply list", checkpoint_block_number);
                    (Vec::new(), None, None)
                }
            } else {
                (Vec::new(), None, None)
            };

            // Parse attestation from header for vote tracking
            let attestation = super::attestation::parse_vote_attestation_from_header(
                header,
                working_snapshot.epoch_num,
                self.chain_spec.is_luban_active_at_block(header.number),
                self.chain_spec.is_bohr_active_at_timestamp(header.timestamp)
            );

            // Apply header to snapshot (now determines hardfork activation internally)
            working_snapshot = match working_snapshot.apply(
                header.beneficiary,
                header,
                new_validators,
                vote_addrs,
                attestation,
                turn_length,
                &*self.chain_spec,
            ) {
                Some(snap) => snap,
                None => {
                    if header.number % 100000 == 0 { // only log every 100k blocks to reduce spam
                        tracing::debug!("Failed to apply header {} to snapshot during Bodies stage", header.number);
                    }
                    return None;
                }
            };

            self.base.cache.write().insert(working_snapshot.block_number, working_snapshot.clone());
            if working_snapshot.block_number % crate::consensus::parlia::snapshot::CHECKPOINT_INTERVAL == 0 {
                tracing::debug!("Succeed to rebuild snapshot for block {} to DB", working_snapshot.block_number);
                self.base.insert(working_snapshot.clone());
            }
        }

        // Created snapshot via backward walking
        Some(working_snapshot)
    }

    fn insert(&self, snapshot: Snapshot) {
        self.base.insert(snapshot);
    }
    
    fn get_checkpoint_header(&self, block_number: u64) -> Option<alloy_consensus::Header> {
        tracing::info!("Get checkpoint header for block {} in enhanced snapshot provider", block_number);
        // Use the provider to fetch header from database (like reth-bsc-trail's get_header_by_hash)
        use reth_provider::HeaderProvider;
        match self.header_provider.header_by_number(block_number) {
            Ok(header) => {
                tracing::info!("Succeed to fetch header{} for block {} in enhanced snapshot provider", header.is_none(),block_number);
                header
            },
            Err(e) => {
                tracing::error!("Failed to fetch header for block {}: {:?}", block_number, e);
                None
            }
        }
    }
}
