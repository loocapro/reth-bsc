use alloy_primitives::{keccak256, BlockNumber, B256, FixedBytes};
use alloy_rlp::{RlpDecodable, RlpEncodable, Decodable};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Max length allowed for the `extra` field of a [`VoteAttestation`].
pub const MAX_ATTESTATION_EXTRA_LENGTH: usize = 256;

/// Bit-set type marking validators that participated in a vote attestation.
///
/// Currently BSC supports at most 64 validators so a single `u64` is enough.
/// Should the validator set grow we need to change this to `U256` or similar.
pub type ValidatorsBitSet = u64;

/// 48-byte BLS public key of a validator.
pub type VoteAddress = FixedBytes<48>;

/// 96-byte aggregated BLS signature.
pub type VoteSignature = FixedBytes<96>;

/// `VoteData` represents one voting range that validators cast votes for fast-finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
pub struct VoteData {
    /// The source block number (latest justified checkpoint).
    pub source_number: BlockNumber,
    /// The hash of the source block.
    pub source_hash: B256,
    /// The target block number this vote wants to justify/finalise.
    pub target_number: BlockNumber,
    /// The hash of the target block.
    pub target_hash: B256,
}

impl VoteData {
    /// Returns the Keccak-256 hash of the RLP-encoded `VoteData`.
    pub fn hash(&self) -> B256 { keccak256(alloy_rlp::encode(self)) }
}

/// `VoteEnvelope` represents a single signed vote from one validator.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
pub struct VoteEnvelope {
    /// Validator's BLS public key.
    pub vote_address: VoteAddress,
    /// Validator's BLS signature over the `data` field.
    pub signature: VoteSignature,
    /// The vote data.
    pub data: VoteData,
}

impl VoteEnvelope {
    /// Returns the Keccak-256 hash of the RLP-encoded envelope.
    pub fn hash(&self) -> B256 { keccak256(alloy_rlp::encode(self)) }
}

/// `VoteAttestation` is the aggregated vote of a super-majority of validators.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
pub struct VoteAttestation {
    /// Bit-set of validators that participated (see [`ValidatorsBitSet`]).
    pub vote_address_set: ValidatorsBitSet,
    /// Aggregated BLS signature of the envelopes.
    pub agg_signature: VoteSignature,
    /// The common vote data all validators signed.
    pub data: VoteData,
    /// Reserved for future use.
    pub extra: Bytes,
}

impl VoteAttestation {
    /// Decode a RLP‐encoded attestation.
    pub fn decode_rlp(bytes: &[u8]) -> alloy_rlp::Result<Self> {
        Self::decode(&mut &*bytes)
    }
} 