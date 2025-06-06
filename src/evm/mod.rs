pub mod api;
mod handler;
pub mod precompiles;
pub mod spec;
pub mod transaction;

#[cfg(test)]
mod tests {
    use crate::{
        chainspec::{bsc::bsc_mainnet, BscChainSpec},
        evm::{
            api::{
                ctx::{BscContext, DefaultBsc},
                BscEvmInner,
            },
            spec::BscSpecId,
            transaction::BscTxEnv,
        },
        node::{evm::BscEvm, BscNode},
    };
    use alloy_evm::Evm;
    use alloy_primitives::{address, bytes, fixed_bytes, TxKind, U256};
    use alloy_rpc_types::AccessList;
    use reth_provider::providers::ReadOnlyConfig;
    use reth_revm::{database::StateProviderDatabase, State};
    use revm::{
        context::{result::ExecutionResult, BlockEnv, TxEnv},
        context_interface::block::BlobExcessGasAndPrice,
        inspector::NoOpInspector,
        DatabaseCommit,
    };

    #[test]
    fn test_can_execute() -> Result<(), Box<dyn std::error::Error>> {
        let datadir = "/Users/lucaprovini/Library/Application Support/reth/bsc/db";
        let spec = BscChainSpec { inner: bsc_mainnet() };
        let factory = BscNode::provider_factory_builder()
            .open_read_only(spec.into(), ReadOnlyConfig::from_db_dir(datadir))?;

        let provider = factory.latest()?;

        let db = State::builder().with_database(StateProviderDatabase::new(&provider)).build();

        let inner = BscEvmInner::new(BscContext::bsc().with_db(db), NoOpInspector {});
        let mut evm = BscEvm { inner, inspect: false };
        evm.ctx_mut().cfg.chain_id = 56;
        evm.ctx_mut().cfg.spec = BscSpecId::LATEST;
        evm.ctx_mut().cfg.blob_max_count = None;

        evm.ctx_mut().block = BlockEnv {
            number: 897030,
            beneficiary: address!("0xb8f7166496996a7da21cf1f1b04d9b3e26a3d077"),
            timestamp: 1601362870,
            gas_limit: 30000000,
            basefee: 0,
            difficulty: U256::from(0),
            prevrandao: Some(fixed_bytes!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )),
            blob_excess_gas_and_price: None,
        };

        let tx1 = BscTxEnv {
            base: TxEnv {
                tx_type: 0,
                caller: address!("0xe9996fcc821b7299b0304cf6d783bae56092273e"),
                gas_limit: 224494,
                gas_price: 40000000000,
                kind: TxKind::Call(address!("0x20ec291bb8459b6145317e7126532ce7ece5056f")),
                value: U256::from(0),
                data: bytes!(
                    "0xf3fef3a3000000000000000000000000e02df9e3e622debdd69fb838bb799e3f168902c5000000000000000000000000000000000000000000000a968163f0a57b400000"
                ),
                nonce: 296,
                chain_id: Some(56),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            is_system_transaction: false,
        };

        let tx2 = BscTxEnv {
            base: TxEnv {
                tx_type: 0,
                caller: address!("0x716342594dd0c6dd2efdd719153696c67760f461"),
                gas_limit: 201939,
                gas_price: 20000000000,
                kind: TxKind::Call(address!("0x20ec291bb8459b6145317e7126532ce7ece5056f")),
                value: U256::from(0),
                data: bytes!(
                    "0xf3fef3a3000000000000000000000000e02df9e3e622debdd69fb838bb799e3f168902c500000000000000000000000000000000000000000000046ee5cdbf05a68d00c5"
                ),
                nonce: 157,
                chain_id: Some(56),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            is_system_transaction: false,
        };

        let tx3 = BscTxEnv {
            base: TxEnv {
                tx_type: 0,
                caller: address!("0xcc7bc84f0c8f26bad7afbe7185b72fc0a0cf39e3"),
                gas_limit: 207128,
                gas_price: 20000000000,
                kind: TxKind::Call(address!("0xe4ae305ebe1abe663f261bc00534067c80ad677c")),
                value: U256::from(0),
                data: bytes!(
                    "0xa9059cbb000000000000000000000000631fc1ea2270e98fbd9d92658ece0f5a269aa161000000000000000000000000000000000000000000000331f95a6764cc46e81d"
                ),
                nonce: 5,
                chain_id: Some(56),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            is_system_transaction: false,
        };

        let tx4 = BscTxEnv {
            base: TxEnv {
                tx_type: 0,
                caller: address!("0x91b728f3259a36b13c54b48384ecccf4accfb77d"),
                gas_limit: 72302,
                gas_price: 20000000000,
                kind: TxKind::Call(address!("0x55d398326f99059ff775485246999027b3197955")),
                value: U256::from(0),
                data: bytes!(
                    "0xa9059cbb000000000000000000000000631fc1ea2270e98fbd9d92658ece0f5a269aa16100000000000000000000000000000000000000000000131071cd2b2e726e3714"
                ),
                nonce: 20,
                chain_id: Some(56),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            is_system_transaction: false,
        };

        let tx5 = BscTxEnv {
            base: TxEnv {
                tx_type: 0,
                caller: address!("0x8a4968a7cf956e943107fa8236a4754e418b70a2"),
                gas_limit: 221481,
                gas_price: 20000000000,
                kind: TxKind::Call(address!("0x05ff2b0db69458a0750badebc4f9e13add608c7f")),
                value: U256::from(603869498436796878639_u128),
                data: bytes!(
                    "0xf305d719000000000000000000000000ad6caeb32cd2c308980a548bd0bc5aa4306c6c1800000000000000000000000000000000000000000000008cf2c691688517000000000000000000000000000000000000000000000000008c3e5c9d7b3281200000000000000000000000000000000000000000000000002092788cd7f57d46250000000000000000000000008a4968a7cf956e943107fa8236a4754e418b70a2000000000000000000000000000000000000000000000000000000005f72e05e"
                ),
                nonce: 257,
                chain_id: Some(56),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            is_system_transaction: false,
        };

        let tx6 = BscTxEnv {
            base: TxEnv {
                tx_type: 0,
                caller: address!("0x8f76c99c3e96371edeffe35657137a5236646512"),
                gas_limit: 222456,
                gas_price: 20000000000,
                kind: TxKind::Call(address!("0x05ff2b0db69458a0750badebc4f9e13add608c7f")),
                value: U256::from(37102801020856960437_u128),
                data: bytes!(
                    "0xf305d7190000000000000000000000003ee2200efb3400fabb9aacf31297cbdd1d435d4700000000000000000000000000000000000000000000021e118d28e88104000000000000000000000000000000000000000000000000020dce770147edc90000000000000000000000000000000000000000000000000001f37528ebc1930aa70000000000000000000000008f76c99c3e96371edeffe35657137a5236646512000000000000000000000000000000000000000000000000000000005f72e046"
                ),
                nonce: 850,
                chain_id: Some(56),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            is_system_transaction: false,
        };

        let tx7 = BscTxEnv {
            base: TxEnv {
                tx_type: 0,
                caller: address!("0x97a7afa71130d375dcd2e5daf7fab427ac6ca6b3"),
                gas_limit: 170082,
                gas_price: 20000000000,
                kind: TxKind::Call(address!("0x6714c1992e6805e0ad0b750c2c826b0b2ea8f3cd")),
                value: U256::from(0),
                data: bytes!("0x3d18b912"),
                nonce: 93,
                chain_id: Some(56),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            is_system_transaction: false,
        };

        let tx8 = BscTxEnv {
            base: TxEnv {
                tx_type: 0,
                caller: address!("0xf44e3c4fbe55eed49610203a54d658f30a6e94b1"),
                gas_limit: 207128,
                gas_price: 20000000000,
                kind: TxKind::Call(address!("0xe4ae305ebe1abe663f261bc00534067c80ad677c")),
                value: U256::from(0),
                data: bytes!(
                    "0xa9059cbb000000000000000000000000631fc1ea2270e98fbd9d92658ece0f5a269aa161000000000000000000000000000000000000000000000393250942981efc940f"
                ),
                nonce: 2,
                chain_id: Some(56),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            is_system_transaction: false,
        };

        let tx9 = BscTxEnv {
            base: TxEnv {
                tx_type: 0,
                caller: address!("0x2fd222f4760818c7c8c971c2bb266ea1c78cb96b"),
                gas_limit: 159416,
                gas_price: 20000000000,
                kind: TxKind::Call(address!("0x73feaa1ee314f8c655e354234017be2193c9e24e")),
                value: U256::from(0),
                data: bytes!(
                    "0x41441d3b0000000000000000000000000000000000000000000000009164517d3b8bb8ce"
                ),
                nonce: 42,
                chain_id: Some(56),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            is_system_transaction: false,
        };

        let tx10 = BscTxEnv {
            base: TxEnv {
                tx_type: 0,
                caller: address!("0xd2c751a85ea62e972453d911e32eae423215fbdc"),
                gas_limit: 161830,
                gas_price: 20000000000,
                kind: TxKind::Call(address!("0x05ff2b0db69458a0750badebc4f9e13add608c7f")),
                value: U256::from(95328924251408761_u128),
                data: bytes!(
                    "0xfb3bdb410000000000000000000000000000000000000000000000001bc16d674ec800000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000d2c751a85ea62e972453d911e32eae423215fbdc000000000000000000000000000000000000000000000000000000005f72e05b0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c0000000000000000000000000e09fabb73bd3ade0a17ecc321fd13a19e81ce82"
                ),
                nonce: 2,
                chain_id: Some(56),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            is_system_transaction: false,
        };

        let tx11 = BscTxEnv {
            base: TxEnv {
                tx_type: 0,
                caller: address!("0x234cdbaeb6218608476e48dc799b8e4a9f829e35"),
                gas_limit: 686670,
                gas_price: 20000000000,
                kind: TxKind::Call(address!("0x7145319189629afcf31754d8ac459265fca4cf91")),
                value: U256::from(0),
                data: bytes!(
                    "0xbca8b2500000000000000000000000000000000000000000000002241e5001a0469c0000"
                ),
                nonce: 31,
                chain_id: Some(56),
                access_list: AccessList::default(),
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: 0,
                authorization_list: vec![],
            },
            is_system_transaction: false,
        };

        let transactions = vec![tx1]; // tx2, tx3, tx4, tx5, tx6, tx7, tx8, tx9, tx10, tx11

        for (i, tx) in transactions.iter().enumerate() {
            let result = evm.transact(tx.clone()).unwrap();
            let (gas_used, gas_refunded) = match &result.result {
                ExecutionResult::Success { gas_used, gas_refunded, .. } => {
                    (*gas_used, *gas_refunded)
                }
                ExecutionResult::Revert { gas_used, .. } => (*gas_used, 0),
                ExecutionResult::Halt { gas_used, .. } => (*gas_used, 0),
            };
            dbg!(i, gas_used, gas_refunded, gas_used + gas_refunded, result.result.is_success());
            evm.db_mut().commit(result.state);
        }

        Ok(())
    }
}
