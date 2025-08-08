#!/usr/bin/env cargo-script

//! Simple debug script for block 43132201 seal recovery issue
//! Run with: cargo run --bin debug_seal_43132201

use alloy_consensus::{Header, BlockHeader};
use alloy_primitives::{Address, B256, U256, Bytes, hex, Bloom};
use std::str::FromStr;
use std::sync::Arc;

fn main() {
    println!("🔍 Debugging seal recovery for block 43132201");
    
    // Actual block data from BSC testnet for block 43132201
    test_block_43132201();
}

fn test_block_43132201() {
    println!("=== TESTING BLOCK 43132201 WITH REAL BSC CONSENSUS VALIDATOR ===");
    
    // Real block data from BSC testnet block 43132201
    let expected_miner = Address::from_str("0x1a3d9d7a717d64e6088ac937d5aacdd3e20ca963").unwrap();
    let wrong_recovered = Address::from_str("0x95A216f51940259C488A686f5145dA1b1a82afD6").unwrap();
    
    println!("Expected miner: {}", expected_miner);
    println!("Wrong recovered: {}", wrong_recovered);
    
    // Create the exact header data from your EC2 node
    let header = Header {
        parent_hash: B256::from_str("0xf337513acca19fa58981201bcb8cb2c56cf3afece07c25e85b2cbbb2a1d23312").unwrap(),
        ommers_hash: B256::from_str("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap(),
        beneficiary: expected_miner,
        state_root: B256::from_str("0xd9382782278ef90f5e4ecd54434c4382a792ba9fb470636528c16e4f4720e09b").unwrap(),
        transactions_root: B256::from_str("0xce21b4817bb3e7d57449fd327c5fb3081585b7be8212c65cee93bd033b38fac5").unwrap(),
        receipts_root: B256::from_str("0x4fda1f67ddcd586290f023346407e46fe2cffd5c4e7360100dbcb084d862d6dc").unwrap(),
        logs_bloom: Bloom::from_str("0x06000000000000000000004000000000000000000000000000000000000000000000180000220000000000000000000000080080000000000000000000000000000028000000000000000000000000002010000000000000000000000080000000080020800200000000100008000000080000000000000002000000000008000000000000000000008000000000000000000400000000000008040000000220000000000000002008001000028000000000010000000000000000000000000000040000001000000000000000100000200000000004000000104002000000000008000000000000010100040000110000009000000000004000000000080000").unwrap(),
        difficulty: U256::from(2),
        number: 43132201,
        gas_limit: 70000000, // 0x42c1d80
        gas_used: 321004,    // 0x4e5ec
        timestamp: 1724395524, // 0x66c3f004
        extra_data: Bytes::from(hex::decode("d98301040d846765746889676f312e32312e3132856c696e757800000299d9bcf8b381fbb86084e92b477453ef7a021ebec2fe433dfb431ecf6fd1b5386e208a3055e3c0b5cc651852bb4c75a9c68c073c324dad308d018f3e6119415c54f47c6e6c1b603f311c29e8eadd6b55870f2ada055be8b3a776650ad6241bb7a763a66508e6563faaf84c8402922527a05a0a26c82e1d42ca0918957533e1ac5a97bf2d53837ce122944e7bd3189643508402922528a0f337513acca19fa58981201bcb8cb2c56cf3afece07c25e85b2cbbb2a1d2331280a021739230c7e8e9793d6a254992d1ac0401ff68da7a820398fc94a7a8667cdd4ba5b068b15acb1a33353779111ce635afb5eff4acef9a0b9eb5cf3d58b4a63600").unwrap()),
        mix_hash: B256::ZERO, // From your data: 0x0000...
        nonce: 0u64.into(),   // From your data: 0x0000...
        base_fee_per_gas: Some(0),
        withdrawals_root: Some(B256::from_str("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap()),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::ZERO),
        requests_hash: None,
    };
    
    let block_hash = B256::from_str("0x42e36cb84f8101382ac947a453e1cacade3966a8b4a5353ca76a389c5b28772c").unwrap();
    let sealed_header = reth_primitives_traits::SealedHeader::new(header, block_hash);
    
    // Test with real BSC consensus validator
    test_with_real_bsc_validator(sealed_header, expected_miner, wrong_recovered);
}

fn test_with_real_bsc_validator(
    sealed_header: reth_primitives_traits::SealedHeader<Header>, 
    expected_miner: Address,
    wrong_recovered: Address
) {
    use reth_bsc::consensus::parlia::validation::BscConsensusValidator;
    use reth_bsc::chainspec::{BscChainSpec, bsc_testnet};
    
    println!("\n🔍 Testing with real BscConsensusValidator...");
    
    // Create the exact same validator your node uses
    let chain_spec = Arc::new(BscChainSpec { 
        inner: bsc_testnet() 
    });
    let validator = BscConsensusValidator::new(chain_spec);
    
    // Debug the seal hash calculation details
    println!("🔧 Debugging seal hash calculation...");
    println!("Block number: {}", sealed_header.number());
    println!("Chain ID: 97 (BSC testnet)");
    println!("ExtraData length: {}", sealed_header.extra_data().len());
    
    // Call the exact same function that's failing in your node
    match validator.recover_proposer_from_seal(&sealed_header) {
        Ok(recovered_address) => {
            println!("✅ Recovered address: {}", recovered_address);
            
            if recovered_address == expected_miner {
                println!("🎉 SUCCESS: Recovered address matches expected miner!");
            } else if recovered_address == wrong_recovered {
                println!("❌ REPRODUCED: Got the wrong recovered address! This confirms the bug.");
                println!("   Expected: {}", expected_miner);
                println!("   Got:      {}", recovered_address);
                println!("   This proves the seal hash calculation is incorrect.");
            } else {
                println!("❓ UNEXPECTED: Got a completely different address: {}", recovered_address);
                println!("   Expected: {}", expected_miner);
                println!("   Node got: {}", wrong_recovered);  
                println!("   Test got: {}", recovered_address);
                println!("   All three are different! This suggests a data construction issue.");
            }
        }
        Err(e) => {
            println!("💥 ERROR: Failed to recover proposer: {:?}", e);
        }
    }
    
    // Let's also manually inspect the signature data
    println!("\n🔍 Manual signature inspection:");
    let extra_data = sealed_header.extra_data();
    let signature_start = extra_data.len() - 65;
    let signature = &extra_data[signature_start..];
    println!("Signature bytes: {}", hex::encode(signature));
    println!("Recovery ID: {}", signature[64]);
    
    // Show beneficiary vs recovered  
    println!("Header beneficiary: {}", sealed_header.beneficiary());
    println!("BSC official miner: {}", expected_miner);
}
