//! Parlia snapshot database table definitions.
//!
//! Stored value is the CBOR‐compressed `Snapshot` blob returned by
//! `Compress` implementation.

use reth_db::table::Table;

/// Table: epoch boundary block number (u64) -> compressed snapshot bytes.
#[derive(Debug)]
pub struct ParliaSnapshots;

impl Table for ParliaSnapshots {
    const NAME: &'static str = "ParliaSnapshots";
    const DUPSORT: bool = false;
    type Key = u64;
    /// Raw compressed bytes produced by `Snapshot::compress()`.
    type Value = reth_db::models::ParliaSnapshotBlob;
} 