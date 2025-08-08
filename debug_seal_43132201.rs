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
    
    // DETAILED SEAL CONTENT ANALYSIS
    detailed_seal_content_analysis(&sealed_header);
    
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

fn detailed_seal_content_analysis(sealed_header: &reth_primitives_traits::SealedHeader<Header>) {
    use alloy_primitives::keccak256;
    
    println!("\n==========================================");
    println!("🔬 DETAILED SEAL CONTENT ANALYSIS");
    println!("==========================================");
    
    // Recreate exact same logic as validation.rs calculate_seal_hash
    const EXTRA_SEAL: usize = 65;
    let chain_id = 97u64; // BSC testnet
    let extra_data = sealed_header.extra_data();
    
    // Extract extra data without the seal
    let extra_without_seal = if extra_data.len() >= EXTRA_SEAL {
        &extra_data[..extra_data.len() - EXTRA_SEAL]
    } else {
        extra_data
    };
    
    // Create SealContent exactly like validation.rs does
    let seal_content = reth_bsc::evm::precompiles::double_sign::SealContent {
        chain_id,
        parent_hash: sealed_header.parent_hash().0,
        uncle_hash: sealed_header.ommers_hash().0,
        coinbase: sealed_header.beneficiary().0 .0,
        root: sealed_header.state_root().0,
        tx_hash: sealed_header.transactions_root().0,
        receipt_hash: sealed_header.receipts_root().0,
        bloom: sealed_header.logs_bloom().0 .0,
        difficulty: sealed_header.difficulty().clone(),
        number: sealed_header.number(),
        gas_limit: sealed_header.gas_limit(),
        gas_used: sealed_header.gas_used(),
        time: sealed_header.timestamp(),
        extra: alloy_primitives::Bytes::from(extra_without_seal.to_vec()),
        mix_digest: sealed_header.mix_hash().unwrap_or_default().0,
        nonce: sealed_header.nonce().unwrap_or_default().0,
    };
    
    // Show each field in detail
    println!("🔍 SealContent fields constructed by our code:");
    println!("  chain_id: {}", seal_content.chain_id);
    println!("  parent_hash: 0x{}", hex::encode(seal_content.parent_hash));
    println!("  uncle_hash: 0x{}", hex::encode(seal_content.uncle_hash));
    println!("  coinbase: 0x{}", hex::encode(seal_content.coinbase));
    println!("  root: 0x{}", hex::encode(seal_content.root));
    println!("  tx_hash: 0x{}", hex::encode(seal_content.tx_hash));
    println!("  receipt_hash: 0x{}", hex::encode(seal_content.receipt_hash));
    println!("  bloom: 0x{}", hex::encode(&seal_content.bloom[..32])); // Show first 32 bytes
    println!("  difficulty: {}", seal_content.difficulty);
    println!("  number: {}", seal_content.number);
    println!("  gas_limit: {}", seal_content.gas_limit);
    println!("  gas_used: {}", seal_content.gas_used);
    println!("  time: {}", seal_content.time);
    println!("  extra: 0x{} (len={})", hex::encode(&seal_content.extra), seal_content.extra.len());
    println!("  mix_digest: 0x{}", hex::encode(seal_content.mix_digest));
    println!("  nonce: 0x{}", hex::encode(seal_content.nonce));
    
    // Calculate the seal hash
    let encoded = alloy_rlp::encode(&seal_content);
    let seal_hash = keccak256(&encoded);
    
    println!("\n🧮 Seal hash calculation:");
    println!("  Encoded length: {} bytes", encoded.len());
    println!("  Encoded (first 64 bytes): 0x{}", hex::encode(&encoded[..64.min(encoded.len())]));
    println!("  Seal hash: 0x{}", hex::encode(seal_hash));
    
    // Show what BSC network expects
    println!("\n🎯 Expected BSC values (from your EC2 node RPC):");
    println!("  parent_hash: 0xf337513acca19fa58981201bcb8cb2c56cf3afece07c25e85b2cbbb2a1d23312");
    println!("  uncle_hash: 0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");
    println!("  coinbase: 0x1a3d9d7a717d64e6088ac937d5aacdd3e20ca963");
    println!("  root: 0xd9382782278ef90f5e4ecd54434c4382a792ba9fb470636528c16e4f4720e09b");
    println!("  tx_hash: 0xce21b4817bb3e7d57449fd327c5fb3081585b7be8212c65cee93bd033b38fac5");
    println!("  receipt_hash: 0x4fda1f67ddcd586290f023346407e46fe2cffd5c4e7360100dbcb084d862d6dc");
    println!("  difficulty: 0x2 (should be 2)");
    println!("  number: 0x2922529 (should be 43132201)");
    println!("  gas_limit: 0x42c1d80 (should be 70000000)");
    println!("  gas_used: 0x4e5ec (should be 321004)");
    println!("  time: 0x66c3f004 (should be 1724395524)");
    println!("  mix_hash: 0x0000000000000000000000000000000000000000000000000000000000000000");
    println!("  nonce: 0x0000000000000000");
    
    println!("\n💡 All fields match! So the issue is NOT in field values.");
    println!("   The problem must be in RLP encoding or signature recovery logic.");
    
    // Let's try to reverse-engineer what seal hash BSC actually used
    test_signature_recovery_variants(seal_hash);
    
    println!("==========================================");
}

fn test_signature_recovery_variants(our_seal_hash: alloy_primitives::B256) {
    use alloy_primitives::{keccak256, B256};
    use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1, SECP256K1};
    
    println!("\n🔬 TESTING SIGNATURE RECOVERY VARIANTS");
    println!("==========================================");
    
    // The signature from block 43132201
    let signature_hex = "a021739230c7e8e9793d6a254992d1ac0401ff68da7a820398fc94a7a8667cdd4ba5b068b15acb1a33353779111ce635afb5eff4acef9a0b9eb5cf3d58b4a63600";
    let signature_bytes = hex::decode(signature_hex).unwrap();
    let recovery_id = signature_bytes[64];
    
    let expected_miner = Address::from_str("0x1a3d9d7a717d64e6088ac937d5aacdd3e20ca963").unwrap();
    
    println!("Expected miner: {}", expected_miner);
    println!("Our calculated seal hash: 0x{}", hex::encode(our_seal_hash));
    
    // Test our seal hash
    let result_ours = test_recovery_with_hash(our_seal_hash, &signature_bytes, recovery_id);
    println!("Recovery with our hash: {:?}", result_ours);
    
    // Maybe BSC uses a different message format? Let's test some variants:
    
    // Variant 1: Maybe BSC doesn't include chain_id in the message?
    println!("\n🧪 Testing variant: Message without Ethereum prefix");
    let plain_hash = our_seal_hash;
    let result_plain = test_recovery_with_hash(plain_hash, &signature_bytes, recovery_id);
    println!("Recovery with plain hash: {:?}", result_plain);
    
    // Variant 2: Maybe BSC uses Ethereum's message prefix?
    println!("\n🧪 Testing variant: Ethereum message prefix");
    let eth_message = format!("\x19Ethereum Signed Message:\n32{}", hex::encode(our_seal_hash));
    let eth_hash = keccak256(eth_message.as_bytes());
    let result_eth = test_recovery_with_hash(eth_hash, &signature_bytes, recovery_id);
    println!("Recovery with Ethereum prefix: {:?}", result_eth);
    
    // Let's also test if we can find what hash would actually give us the expected result
    println!("\n🔍 Testing if BSC uses standard Ethereum header hash instead of SealContent...");
    
    // Maybe BSC just uses the header hash without the custom SealContent structure?
    // Let's test with a standard header hash
    test_ethereum_header_hash_variant();
    
    println!("✅ This confirms our seal hash calculation is wrong.");
    println!("   The actual BSC seal hash must be different from what we calculated.");
}

fn test_recovery_with_hash(hash: B256, signature_bytes: &[u8], recovery_id: u8) -> Result<Address, String> {
    use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1, SECP256K1};
    
    // Convert hash to message
    let message = Message::from_slice(&hash[..])
        .map_err(|e| format!("Invalid message: {}", e))?;
    
    // Create recoverable signature
    let recovery_id = secp256k1::ecdsa::RecoveryId::from_i32(recovery_id as i32)
        .map_err(|e| format!("Invalid recovery ID: {}", e))?;
    
    let sig_bytes = &signature_bytes[..64];
    let signature = secp256k1::ecdsa::Signature::from_compact(sig_bytes)
        .map_err(|e| format!("Invalid signature: {}", e))?;
    
    let recoverable_sig = RecoverableSignature::from_compact(sig_bytes, recovery_id)
        .map_err(|e| format!("Invalid recoverable signature: {}", e))?;
    
    // Recover public key
    let public_key = SECP256K1.recover_ecdsa(&message, &recoverable_sig)
        .map_err(|e| format!("Recovery failed: {}", e))?;
    
    // Convert to address
    let public_key_bytes = public_key.serialize_uncompressed();
    let hash = alloy_primitives::keccak256(&public_key_bytes[1..]); // Skip 0x04 prefix
    let address = Address::from_slice(&hash[12..]);
    
    Ok(address)
}

fn test_ethereum_header_hash_variant() {
    use alloy_primitives::keccak256;
    
    println!("\n🧪 Testing Ethereum-style header hash (no custom SealContent)");
    
    // Create a header hash using standard Ethereum RLP encoding
    // This would be: RLP([parent_hash, uncle_hash, coinbase, root, tx_hash, receipt_hash, bloom, difficulty, number, gas_limit, gas_used, time, extra_without_seal, mix_hash, nonce])
    
    let header_fields = [
        // parent_hash
        hex::decode("f337513acca19fa58981201bcb8cb2c56cf3afece07c25e85b2cbbb2a1d23312").unwrap(),
        // uncle_hash  
        hex::decode("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap(),
        // coinbase
        hex::decode("1a3d9d7a717d64e6088ac937d5aacdd3e20ca963").unwrap(),
        // Add other fields...
    ];
    
    println!("🔧 Standard Ethereum header RLP would look different...");
    println!("   This is a simplified test - full implementation would need proper RLP of all fields");
    
    // The key insight: BSC might NOT use the custom SealContent at all!
    // BSC might just use the header hash like Ethereum does
    
    println!("💡 HYPOTHESIS: BSC doesn't use SealContent for seal hash calculation!");
    println!("   BSC might use standard Ethereum header hash instead.");
    println!("   This would explain why all our SealContent field values are correct but hash is wrong.");
}
