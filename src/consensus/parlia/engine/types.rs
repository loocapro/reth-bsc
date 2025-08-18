//! Type definitions for the Parlia engine
//! 
//! Ported from reth-bsc-trail with minimal adaptations for current Reth

use alloy_primitives::{BlockHash, BlockNumber, B256};
use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
    ExecutionPayloadV1, PayloadAttributes,
};
use reth_engine_primitives::{
    EngineApiMessageVersion, EngineObjectValidationError, EngineTypes, EngineValidator,
    PayloadOrAttributes, PayloadTypes,
};
use reth_primitives::{BlockBody, SealedHeader};
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
};

/// The types used in the BSC Parlia consensus engine.
#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct BscEngineTypes<T: PayloadTypes = BscPayloadTypes> {
    _marker: PhantomData<T>,
}

impl<T: PayloadTypes> PayloadTypes for BscEngineTypes<T> {
    type BuiltPayload = T::BuiltPayload;
    type PayloadAttributes = T::PayloadAttributes;
    type PayloadBuilderAttributes = T::PayloadBuilderAttributes;
}

impl<T: PayloadTypes> EngineTypes for BscEngineTypes<T>
where
    T::BuiltPayload: TryInto<ExecutionPayloadV1>
        + TryInto<ExecutionPayloadEnvelopeV2>
        + TryInto<ExecutionPayloadEnvelopeV3>
        + TryInto<ExecutionPayloadEnvelopeV4>,
{
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
}

/// A default payload type for [`BscEngineTypes`]
#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct BscPayloadTypes;

impl PayloadTypes for BscPayloadTypes {
    type BuiltPayload = reth_payload_primitives::BuiltPayload; // Use default for now
    type PayloadAttributes = PayloadAttributes;
    type PayloadBuilderAttributes = reth_payload_primitives::PayloadBuilderAttributes; // Use default for now
}

/// Validator for the BSC engine API.
#[derive(Debug, Clone)]
pub struct BscEngineValidator {}

impl<Types> EngineValidator<Types> for BscEngineValidator
where
    Types: EngineTypes<PayloadAttributes = PayloadAttributes>,
{
    fn validate_version_specific_fields(
        &self,
        _version: EngineApiMessageVersion,
        _payload_or_attrs: PayloadOrAttributes<'_, PayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        Ok(())
    }

    fn ensure_well_formed_attributes(
        &self,
        _version: EngineApiMessageVersion,
        _attributes: &PayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        Ok(())
    }
}

/// Storage cache size
const STORAGE_CACHE_NUM: usize = 1000;

/// In memory storage for the chain the parlia engine task cache.
#[derive(Debug, Clone)]
pub struct Storage {
    inner: std::sync::Arc<tokio::sync::RwLock<StorageInner>>,
}

impl Storage {
    /// Initializes the [Storage] with the given best block. This should be initialized with the
    /// highest block in the chain, if there is a chain already stored on-disk.
    pub fn new(
        best_block: SealedHeader,
        finalized_hash: Option<B256>,
        safe_hash: Option<B256>,
    ) -> Self {
        let best_finalized_hash = finalized_hash.unwrap_or_default();
        let best_safe_hash = safe_hash.unwrap_or_default();

        let mut storage = StorageInner {
            best_hash: best_block.hash(),
            best_block: best_block.number,
            best_header: best_block.clone(),
            headers: LimitedHashSet::new(STORAGE_CACHE_NUM),
            hash_to_number: LimitedHashSet::new(STORAGE_CACHE_NUM),
            bodies: LimitedHashSet::new(STORAGE_CACHE_NUM),
            best_finalized_hash,
            best_safe_hash,
        };
        storage.headers.put(best_block.number, best_block.clone());
        storage.hash_to_number.put(best_block.hash(), best_block.number);
        Self { inner: std::sync::Arc::new(tokio::sync::RwLock::new(storage)) }
    }

    /// Returns the write lock of the storage
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, StorageInner> {
        self.inner.write().await
    }

    /// Returns the read lock of the storage
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, StorageInner> {
        self.inner.read().await
    }
}

/// In-memory storage for the chain the parlia engine task cache.
#[derive(Debug)]
pub struct StorageInner {
    /// Headers buffered for download.
    pub headers: LimitedHashSet<BlockNumber, SealedHeader>,
    /// A mapping between block hash and number.
    pub hash_to_number: LimitedHashSet<BlockHash, BlockNumber>,
    /// Bodies buffered for download.
    pub bodies: LimitedHashSet<BlockHash, BlockBody>,
    /// Tracks best block
    pub best_block: u64,
    /// Tracks hash of best block
    pub best_hash: B256,
    /// The best header in the chain
    pub best_header: SealedHeader,
    /// Tracks hash of best finalized block
    pub best_finalized_hash: B256,
    /// Tracks hash of best safe block
    pub best_safe_hash: B256,
}

impl StorageInner {
    /// Returns the matching header if it exists.
    pub fn header_by_hash_or_number(
        &self,
        hash_or_num: alloy_eips::BlockHashOrNumber,
    ) -> Option<SealedHeader> {
        let num = match hash_or_num {
            alloy_eips::BlockHashOrNumber::Hash(hash) => self.hash_to_number.get(&hash).copied()?,
            alloy_eips::BlockHashOrNumber::Number(num) => num,
        };
        self.headers.get(&num).cloned()
    }

    /// Inserts a new header+body pair
    pub fn insert_new_block(&mut self, header: SealedHeader, body: BlockBody) {
        self.best_hash = header.hash();
        self.best_block = header.number;
        self.best_header = header.clone();

        tracing::trace!(target: "parlia::client", num=self.best_block, hash=?self.best_hash, "inserting new block");
        self.headers.put(header.number, header);
        self.bodies.put(self.best_hash, body);
        self.hash_to_number.put(self.best_hash, self.best_block);
    }

    /// Inserts a new header
    pub fn insert_new_header(&mut self, header: SealedHeader) {
        self.best_hash = header.hash();
        self.best_block = header.number;
        self.best_header = header.clone();

        tracing::trace!(target: "parlia::client", num=self.best_block, hash=?self.best_hash, "inserting new header");
        self.headers.put(header.number, header);
        self.hash_to_number.put(self.best_hash, self.best_block);
    }

    /// Inserts new finalized and safe hash
    pub fn insert_finalized_and_safe_hash(&mut self, finalized: B256, safe: B256) {
        self.best_finalized_hash = finalized;
        self.best_safe_hash = safe;
    }

    /// Cleans the caches
    pub fn clean_caches(&mut self) {
        self.headers = LimitedHashSet::new(STORAGE_CACHE_NUM);
        self.hash_to_number = LimitedHashSet::new(STORAGE_CACHE_NUM);
        self.bodies = LimitedHashSet::new(STORAGE_CACHE_NUM);
    }
}

#[derive(Debug)]
pub struct LimitedHashSet<K, V> {
    map: HashMap<K, V>,
    queue: VecDeque<K>,
    capacity: usize,
}

impl<K, V> LimitedHashSet<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    pub fn new(capacity: usize) -> Self {
        Self { map: HashMap::new(), queue: VecDeque::new(), capacity }
    }

    pub fn put(&mut self, key: K, value: V) {
        if self.map.len() >= self.capacity {
            if let Some(old_key) = self.queue.pop_front() {
                self.map.remove(&old_key);
            }
        }
        self.map.insert(key.clone(), value);
        self.queue.push_back(key);
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }
}