use alloy_primitives::{Address, Signature, TxKind, U256};
use bytes::Bytes;
use alloy_consensus::TxLegacy;
use reth_chainspec::EthChainSpec;
use reth_primitives::{Transaction, TransactionSigned};

use crate::consensus::parlia::hooks::SystemTxMaker;
use crate::system_contracts::SystemContract;



impl<Spec: EthChainSpec> SystemTxMaker for SystemContract<Spec> {
    type Tx = TransactionSigned;

    fn make_system_tx(
        &self,
        _from: Address,
        to: Address,
        data: Bytes,
        value: U256,
    ) -> Self::Tx {
        let signature = Signature::new(Default::default(), Default::default(), false);
        TransactionSigned::new_unhashed(
            Transaction::Legacy(TxLegacy {
                chain_id: None,
                nonce: 0,
                gas_limit: u64::MAX / 2,
                gas_price: 0,
                value,
                input: alloy_primitives::Bytes::from(data),
                to: TxKind::Call(to),
            }),
            signature,
        )
    }
}

// Provide SystemTxMaker for shared reference as well so we can pass &SystemContract.
impl<'a, Spec: EthChainSpec> SystemTxMaker for &'a SystemContract<Spec> {
    type Tx = TransactionSigned;

    fn make_system_tx(
        &self,
        _from: Address,
        to: Address,
        data: bytes::Bytes,
        value: U256,
    ) -> Self::Tx {
        let signature = Signature::new(Default::default(), Default::default(), false);
        TransactionSigned::new_unhashed(
            Transaction::Legacy(TxLegacy {
                chain_id: None,
                nonce: 0,
                gas_limit: u64::MAX / 2,
                gas_price: 0,
                value,
                input: alloy_primitives::Bytes::from(data),
                to: TxKind::Call(to),
            }),
            signature,
        )
    }
} 