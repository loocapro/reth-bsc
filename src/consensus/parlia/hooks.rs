//! Reward distribution and slashing hooks for Parlia execution.
//!
//! These hooks are called from the EVM executor before and after user transactions
//! are processed so we can insert system‐transactions (rewards, slashing) and
//! keep the snapshot up-to-date.

use alloy_primitives::{Address, U256};
use bytes::Bytes;
use once_cell::sync::Lazy;
use super::snapshot::Snapshot;

// Import canonical addresses from `system_contracts` crate to avoid duplication.

/// StakeHub contract address (system reward pool).
/// `0x0000000000000000000000000000000000002000` on BSC main-net/test-net.
pub const STAKE_HUB_CONTRACT: Address = Address::repeat_byte(0x20); // 0x…2000

/// Slash contract address parsed from the canonical hex string constant.
pub static SLASH_CONTRACT: Lazy<Address> = Lazy::new(|| {
    // Hardcode the known slash contract address
    Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x01])
});

/// Base block reward (wei). Mainnet uses 2 BNB.
pub static BASE_BLOCK_REWARD: Lazy<U256> = Lazy::new(|| U256::from(2_000_000_000_000_000_000u128));

/// Result returned from the pre-execution hook.
#[derive(Debug)]
pub struct PreExecOutput<Tx> {
    pub system_txs: Vec<Tx>,
    /// Gas that must be reserved for system txs.
    pub reserved_gas: u64,
}

impl<Tx> Default for PreExecOutput<Tx> {
    fn default() -> Self {
        Self { system_txs: Vec::new(), reserved_gas: 0 }
    }
}

/// Called before user transactions are executed.
pub trait PreExecutionHook<Tx> {
    fn on_pre_execution(&self, snapshot: &Snapshot, header_beneficiary: Address, in_turn: bool) -> PreExecOutput<Tx>;
}

/// Called after all user transactions were executed.
pub trait PostExecutionHook {
    fn on_post_execution(&self, snapshot: &mut Snapshot);
}

/// Concrete implementation used by the node.
pub struct ParliaHooks;

impl ParliaHooks {
    /// Builds a zero-value, zero-gas system‐transaction transferring the reward
    /// from StakeHub to `beneficiary`.
    fn reward_tx<TxMaker>(maker: &TxMaker, beneficiary: Address, amount: U256) -> TxMaker::Tx
    where
        TxMaker: SystemTxMaker,
    {
        maker.make_system_tx(STAKE_HUB_CONTRACT, beneficiary, Bytes::new(), amount)
    }

    /// Builds a slashing transaction that moves `amount` into the SlashContract.
    fn slash_tx<TxMaker>(maker: &TxMaker, amount: U256) -> TxMaker::Tx
    where
        TxMaker: SystemTxMaker,
    {
        maker.make_system_tx(STAKE_HUB_CONTRACT, *SLASH_CONTRACT, Bytes::new(), amount)
    }
}

/// Small trait that abstracts over whatever concrete type constructs a signed
/// system-transaction for the execution layer.
pub trait SystemTxMaker {
    type Tx;
    fn make_system_tx(&self, from: Address, to: Address, data: Bytes, value: U256) -> Self::Tx;
}

// The actual hook implementation will be added once we wire `SystemTxMaker`
// with the executor’s concrete transaction type.

impl<Tx, Maker> PreExecutionHook<Tx> for (ParliaHooks, Maker)
where
    Maker: SystemTxMaker<Tx = Tx>,
{
    fn on_pre_execution(&self, snapshot: &Snapshot, beneficiary: Address, in_turn: bool) -> PreExecOutput<Tx> {
        let maker = &self.1;
        let mut out: PreExecOutput<Tx> = Default::default();

        // Determine reward amount.
        let mut reward = BASE_BLOCK_REWARD.clone(); // adjust variable type
        if in_turn {
            reward = reward.saturating_mul(U256::from(2u64));
        }

        // If proposer already over-proposed, send reward to slash contract instead.
        if snapshot.sign_recently(beneficiary) {
            let tx = ParliaHooks::slash_tx(maker, reward);
            out.system_txs.push(tx);
        } else {
            let tx = ParliaHooks::reward_tx(maker, beneficiary, reward);
            out.system_txs.push(tx);
        }
        out
    }
}

impl PostExecutionHook for ParliaHooks {
    fn on_post_execution(&self, _snapshot: &mut Snapshot) {
        // For now snapshot update is handled earlier in the header-validator;
        // we might persist here in future milestones.
    }
} 