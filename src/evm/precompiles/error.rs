use revm::precompile::PrecompileError;

/// BSC specific precompile errors.
#[derive(Debug, PartialEq)]
pub enum BscPrecompileError {
    /// The cometbft validation input is invalid.
    InvalidInput,
    /// The cometbft apply block failed.
    CometBftApplyBlockFailed,
    /// The cometbft consensus state encoding failed.
    CometBftEncodeConsensusStateFailed,
}

impl From<BscPrecompileError> for PrecompileError {
    fn from(error: BscPrecompileError) -> Self {
        match error {
            BscPrecompileError::InvalidInput => PrecompileError::Other("invalid input".to_string()),
            BscPrecompileError::CometBftApplyBlockFailed => {
                PrecompileError::Other("apply block failed".to_string())
            }
            BscPrecompileError::CometBftEncodeConsensusStateFailed => {
                PrecompileError::Other("encode consensus state failed".to_string())
            }
        }
    }
}
