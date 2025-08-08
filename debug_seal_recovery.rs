#!/usr/bin/env rust-script

//! Debug script to test seal recovery for block 43132201
//! Run with: cargo run --bin debug_seal_recovery

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, U256};
use reth_primitives_traits::SealedHeader;
use std::str::FromStr;

// Simulate the BscConsensusValidator seal recovery
fn debug_seal_recovery() {
    // Block 43132201 data from the BSC testnet
    let extra_data = "0xd98301040d846765746889676f312e32312e3132856c696e757800000299d9bcf8b381fbb86084e92b477453ef7a021ebec2fe433dfb431ecf6fd1b5386e208a3055e3c0b5cc651852bb4c75a9c68c073c324dad308d018f3e6119415c54f47c6e6c1b603f311c29e8eadd6b55870f2ada055be8b3a776650ad6241bb7a763a66508e6563faaf84c8402922527a05a0a26c82e1d42ca0918957533e1ac5a97bf2d53837ce122944e7bd3189643508402922528a0f337513acca19fa58981201bcb8cb2c56cf3afece07c25e85b2cbbb2a1d2331280a021739230c7e8e9793d6a254992d1ac0401ff68da7a820398fc94a7a8667cdd4ba5b068b15acb1a33353779111ce635afb5eff4acef9a0b9eb5cf3d58b4a63600";
    
    let expected_miner = Address::from_str("0x1a3d9d7a717d64e6088ac937d5aacdd3e20ca963").unwrap();
    let recovered_miner = Address::from_str("0x95A216f51940259C488A686f5145dA1b1a82afD6").unwrap();
    
    println!("🔍 Block 43132201 Seal Recovery Debug");
    println!("Expected miner: {}", expected_miner);
    println!("Your recovered: {}", recovered_miner);
    println!("ExtraData: {}", extra_data);
    
    // Parse extraData 
    let extra_bytes = hex::decode(&extra_data[2..]).expect("Invalid hex");
    let signature_start = extra_bytes.len() - 65;
    let signature = &extra_bytes[signature_start..];
    
    println!("🔐 Signature bytes (last 65): {}", hex::encode(signature));
    println!("Recovery ID: {}", signature[64]);
    
    // TODO: Add actual seal hash calculation and recovery here
    // This would require implementing the same logic as your BscConsensusValidator
}

fn main() {
    debug_seal_recovery();
}
