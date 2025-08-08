//! Unit test to reproduce the seal recovery issue for block 43132201

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, U256, Bytes, hex};
use reth_bsc::consensus::parlia::validation::BscConsensusValidator;
use reth_bsc::chainspec::{BscChainSpec, bsc_testnet};
use reth_primitives_traits::SealedHeader;
use reth_chainspec::EthChainSpec;
use std::str::FromStr;
use std::sync::Arc;

/// Test to reproduce the seal recovery issue for block 43132201
#[test]
fn test_seal_recovery_block_43132201() {
    // Block 43132201 data from BSC testnet
    let block_number = 43132201u64;
    let expected_miner = Address::from_str("0x1a3d9d7a717d64e6088ac937d5aacdd3e20ca963").unwrap();
    let wrong_recovered = Address::from_str("0x95A216f51940259C488A686f5145dA1b1a82afD6").unwrap();
    
    // Actual extraData from block 43132201
    let extra_data_hex = "0xd98301040d846765746889676f312e32312e3132856c696e757800000299d9bcf8b381fbb86084e92b477453ef7a021ebec2fe433dfb431ecf6fd1b5386e208a3055e3c0b5cc651852bb4c75a9c68c073c324dad308d018f3e6119415c54f47c6e6c1b603f311c29e8eadd6b55870f2ada055be8b3a776650ad6241bb7a763a66508e6563faaf84c8402922527a05a0a26c82e1d42ca0918957533e1ac5a97bf2d53837ce122944e7bd3189643508402922528a0f337513acca19fa58981201bcb8cb2c56cf3afece07c25e85b2cbbb2a1d2331280a021739230c7e8e9793d6a254992d1ac0401ff68da7a820398fc94a7a8667cdd4ba5b068b15acb1a33353779111ce635afb5eff4acef9a0b9eb5cf3d58b4a63600";
    let extra_data = Bytes::from(hex::decode(&extra_data_hex[2..]).unwrap());
    
    // Create a mock header with the actual block data
    let header = Header {
        parent_hash: B256::from_str("0xf337513acca19fa58981201bcb8cb2c56cf3afece07c25e85b2cbbb2a1d23312").unwrap(),
        ommers_hash: B256::from_str("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap(), // Standard empty uncle hash
        beneficiary: expected_miner, // This should be the miner
        state_root: B256::from_str("0x2e9793d6a254992d1ac0401ff68da7a820398fc94a7a8667cdd4ba5b068b15acb").unwrap(), // Mock state root
        transactions_root: B256::from_str("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap(), // Empty tx root
        receipts_root: B256::from_str("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap(), // Empty receipt root
        logs_bloom: Default::default(),
        difficulty: U256::from(2), // Should be 2 for in-turn
        number: block_number,
        gas_limit: 30000000,
        gas_used: 0,
        timestamp: 1705554750, // Mock timestamp
        extra_data,
        mix_hash: B256::ZERO,
        nonce: 0u64.into(),
        base_fee_per_gas: Some(1000000000),
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
        requests_hash: None,
    };
    
    let block_hash = B256::from_str("0x42e36cb84f8101382ac947a453e1cacade3966a8b4a5353ca76a389c5b28772c").unwrap();
    let sealed_header = SealedHeader::new(header, block_hash);
    
    // Create BSC consensus validator
    let chain_spec = Arc::new(BscChainSpec { 
        inner: bsc_testnet() 
    });
    let validator = BscConsensusValidator::new(chain_spec);
    
    // Test seal recovery
    println!("🔍 Testing seal recovery for block {}", block_number);
    println!("Expected miner: {}", expected_miner);
    println!("Wrong recovered: {}", wrong_recovered);
    
    match validator.recover_proposer_from_seal(&sealed_header) {
        Ok(recovered_address) => {
            println!("✅ Recovered address: {}", recovered_address);
            
            if recovered_address == expected_miner {
                println!("🎉 SUCCESS: Recovered address matches expected miner!");
            } else if recovered_address == wrong_recovered {
                println!("❌ REPRODUCED: Got the wrong recovered address!");
                panic!("Seal recovery returned wrong address: expected {}, got {}", expected_miner, recovered_address);
            } else {
                println!("❓ UNEXPECTED: Got a different address entirely: {}", recovered_address);
                panic!("Unexpected recovered address: {}", recovered_address);
            }
        }
        Err(e) => {
            println!("💥 ERROR: Failed to recover proposer: {:?}", e);
            panic!("Seal recovery failed: {:?}", e);
        }
    }
}

#[test]
fn test_debug_seal_hash_calculation() {
    // Same setup as above but focus on seal hash calculation
    let block_number = 43132201u64;
    let expected_miner = Address::from_str("0x1a3d9d7a717d64e6088ac937d5aacdd3e20ca963").unwrap();
    
    let extra_data_hex = "0xd98301040d846765746889676f312e32312e3132856c696e757800000299d9bcf8b381fbb86084e92b477453ef7a021ebec2fe433dfb431ecf6fd1b5386e208a3055e3c0b5cc651852bb4c75a9c68c073c324dad308d018f3e6119415c54f47c6e6c1b603f311c29e8eadd6b55870f2ada055be8b3a776650ad6241bb7a763a66508e6563faaf84c8402922527a05a0a26c82e1d42ca0918957533e1ac5a97bf2d53837ce122944e7bd3189643508402922528a0f337513acca19fa58981201bcb8cb2c56cf3afece07c25e85b2cbbb2a1d2331280a021739230c7e8e9793d6a254992d1ac0401ff68da7a820398fc94a7a8667cdd4ba5b068b15acb1a33353779111ce635afb5eff4acef9a0b9eb5cf3d58b4a63600";
    let extra_data = Bytes::from(hex::decode(&extra_data_hex[2..]).unwrap());
    
    // Print signature details
    let signature_start = extra_data.len() - 65;
    let signature = &extra_data[signature_start..];
    
    println!("🔐 Block {} signature analysis:", block_number);
    println!("ExtraData length: {}", extra_data.len());
    println!("Signature (last 65 bytes): {}", hex::encode(signature));
    println!("Recovery ID: {}", signature[64]);
    
    // Test chain ID
    let chain_spec = Arc::new(BscChainSpec { 
        inner: bsc_testnet() 
    });
    println!("Chain ID: {}", chain_spec.chain().id());
    
    // TODO: Add actual seal hash calculation and compare with expected
}
