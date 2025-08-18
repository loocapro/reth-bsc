use alloy_primitives::BlockNumber;

/// Parlia consensus error.
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum ParliaConsensusError {
    /// Error when header extra vanity is missing
    #[error("missing header extra vanity")]
    ExtraVanityMissing,

    /// Error when header extra signature is missing
    #[error("missing header extra signature")]
    ExtraSignatureMissing,

    /// Error when header extra length is invalid
    #[error("header extra length {header_extra_len} is invalid")]
    InvalidHeaderExtraLen {
        /// The validator bytes length
        header_extra_len: u64,
    },

    /// Error when header extra validator bytes length is invalid
    #[error("header extra validator bytes length {validator_bytes_len} is invalid")]
    InvalidHeaderExtraValidatorBytesLen {
        /// Is epoch
        is_epoch: bool,
        /// The validator bytes length
        validator_bytes_len: usize,
    },

    /// Error when the header is not in epoch
    #[error("{block_number} is not in epoch")]
    NotInEpoch {
        /// The block number
        block_number: BlockNumber,
    },

    /// Error when encountering a abi decode inner error
    #[error("abi decode inner error")]
    ABIDecodeInnerError,

    /// Error when encountering a recover ecdsa inner error
    #[error("recover ecdsa inner error")]
    RecoverECDSAInnerError,

    /// Error when header extra turn is invalid
    #[error("invalid turnLength")]
    ExtraInvalidTurnLength,
}