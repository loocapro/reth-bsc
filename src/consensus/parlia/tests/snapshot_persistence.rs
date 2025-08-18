//! Unit tests for Parlia snapshot database persistence and retrieval.

use super::super::{
    provider::DbSnapshotProvider,
    snapshot::Snapshot,
    provider::SnapshotProvider,
};
use alloy_primitives::{Address, B256};
use reth_db::{init_db, mdbx::DatabaseArguments, Database, transaction::DbTx, cursor::DbCursorRO};
use std::sync::Arc;

/// Test snapshot database persistence and retrieval functionality
#[test]
fn test_snapshot_database_persistence() -> eyre::Result<()> {
    // Initialize test database
    let db_path = std::env::temp_dir().join(format!("bsc_test_db_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&db_path)?;
    
    let database = Arc::new(init_db(&db_path, DatabaseArguments::new(Default::default()))?);
    
    // Cleanup guard to ensure database is removed even if test fails
    let _cleanup_guard = TestCleanup { path: db_path.clone() };
    
    // Create DbSnapshotProvider
    let provider = DbSnapshotProvider::new(database.clone(), 256);
    
    // Create test snapshots at checkpoint intervals
    let mut test_snapshots = Vec::new();
    for i in 0..5 {
        let block_number = (i + 1) * 1024; // Checkpoint intervals
        let mut snapshot = Snapshot::default();
        snapshot.block_number = block_number;
        snapshot.block_hash = B256::random();
        snapshot.validators = vec![
            Address::random(),
            Address::random(), 
            Address::random(),
        ];
        snapshot.epoch_num = 200;
        snapshot.turn_length = Some(1);
        
        test_snapshots.push(snapshot);
    }
    
    // Insert snapshots
    for snapshot in &test_snapshots {
        provider.insert(snapshot.clone());
    }
    
    // Verify snapshots can be retrieved
    for expected in &test_snapshots {
        let retrieved = provider.snapshot(expected.block_number)
            .expect(&format!("Snapshot at block {} should exist", expected.block_number));
        
        assert_eq!(retrieved.block_number, expected.block_number);
        assert_eq!(retrieved.block_hash, expected.block_hash);
        assert_eq!(retrieved.validators.len(), expected.validators.len());
        assert_eq!(retrieved.epoch_num, expected.epoch_num);
        assert_eq!(retrieved.turn_length, expected.turn_length);
    }
    
    Ok(())
}

/// Test range queries (finding nearest snapshots)
#[test]
fn test_snapshot_range_queries() -> eyre::Result<()> {
    let db_path = std::env::temp_dir().join(format!("bsc_test_db_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&db_path)?;
    
    let database = Arc::new(init_db(&db_path, DatabaseArguments::new(Default::default()))?);
    let _cleanup_guard = TestCleanup { path: db_path.clone() };
    
    let provider = DbSnapshotProvider::new(database.clone(), 256);
    
    // Insert snapshots at blocks 1024, 2048, 3072, 4096, 5120
    for i in 1..=5 {
        let block_number = i * 1024;
        let mut snapshot = Snapshot::default();
        snapshot.block_number = block_number;
        snapshot.block_hash = B256::random();
        snapshot.validators = vec![Address::random(); 3];
        snapshot.epoch_num = 200;
        
        provider.insert(snapshot);
    }
    
    // Test range queries - should find nearest predecessor
    let test_cases = vec![
        (500, None),           // Before first snapshot
        (1000, None),          // Just before first snapshot  
        (1024, Some(1024)),    // Exact match
        (1500, Some(1024)),    // Between snapshots - should find 1024
        (2048, Some(2048)),    // Exact match
        (3000, Some(2048)),    // Should find nearest predecessor (2048)
        (5120, Some(5120)),    // Last snapshot
        (6000, Some(5120)),    // After last snapshot - should find 5120
    ];
    
    for (query_block, expected_block) in test_cases {
        let result = provider.snapshot(query_block);
        match expected_block {
            Some(expected) => {
                let snapshot = result.expect(&format!("Should find snapshot for block {}", query_block));
                assert_eq!(snapshot.block_number, expected,
                    "Query for block {} should return snapshot at block {}, got {}", 
                    query_block, expected, snapshot.block_number);
            }
            None => {
                assert!(result.is_none(), 
                    "Query for block {} should return None, got snapshot at block {}", 
                    query_block, result.map(|s| s.block_number).unwrap_or(0));
            }
        }
    }
    
    Ok(())
}

/// Test direct database table access
#[test]
fn test_direct_database_access() -> eyre::Result<()> {
    let db_path = std::env::temp_dir().join(format!("bsc_test_db_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&db_path)?;
    
    let database = Arc::new(init_db(&db_path, DatabaseArguments::new(Default::default()))?);
    let _cleanup_guard = TestCleanup { path: db_path.clone() };
    
    let provider = DbSnapshotProvider::new(database.clone(), 256);
    
    // Insert test snapshots
    let snapshot_count = 3;
    for i in 1..=snapshot_count {
        let block_number = i * 1024;
        let mut snapshot = Snapshot::default();
        snapshot.block_number = block_number;
        snapshot.block_hash = B256::random();
        snapshot.validators = vec![Address::random(); 3];
        snapshot.epoch_num = 200;
        
        provider.insert(snapshot);
    }
    
    // Check raw database table
    let tx = database.tx()?;
    let mut cursor = tx.cursor_read::<crate::consensus::parlia::db::ParliaSnapshots>()?;
    let mut count = 0;
    
    for item in cursor.walk(None)? {
        let (_key, _value) = item?;
        count += 1;
    }
    
    assert_eq!(count, snapshot_count, 
        "Database should contain {} snapshot entries, found {}", 
        snapshot_count, count);
    
    Ok(())
}

/// Test snapshot provider cache behavior
#[test]
fn test_snapshot_cache_behavior() -> eyre::Result<()> {
    let db_path = std::env::temp_dir().join(format!("bsc_test_db_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&db_path)?;
    
    let database = Arc::new(init_db(&db_path, DatabaseArguments::new(Default::default()))?);
    let _cleanup_guard = TestCleanup { path: db_path.clone() };
    
    // Small cache size to test eviction
    let provider = DbSnapshotProvider::new(database.clone(), 2);
    
    // Insert more snapshots than cache size
    for i in 1..=5 {
        let block_number = i * 1024;
        let mut snapshot = Snapshot::default();
        snapshot.block_number = block_number;
        snapshot.block_hash = B256::random();
        snapshot.validators = vec![Address::random(); 3];
        snapshot.epoch_num = 200;
        
        provider.insert(snapshot);
    }
    
    // All snapshots should still be retrievable (from DB if not in cache)
    for i in 1..=5 {
        let block_number = i * 1024;
        let snapshot = provider.snapshot(block_number)
            .expect(&format!("Snapshot at block {} should be retrievable", block_number));
        assert_eq!(snapshot.block_number, block_number);
    }
    
    Ok(())
}

/// RAII guard to cleanup test database directory
struct TestCleanup {
    path: std::path::PathBuf,
}

impl Drop for TestCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
