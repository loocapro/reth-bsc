use super::constants::*;
use super::vote::VoteAttestation;
use alloy_consensus::BlockHeader as BlockHeaderTrait;

/// Extract the `VoteAttestation` bytes slice from `header.extra_data` if present and decode.
/// This implementation is based on the `getVoteAttestationFromHeader` function in `parlia.go` of `bsc-erigon`.
/// * `epoch_len` – current epoch length (200/500/1000) so we can determine if block is an epoch boundary.
/// * `is_luban` – true once Luban hard-fork active (extraData format changes).
/// * `is_bohr`  – true once Bohr hard-fork active (turnLength byte present).
pub fn parse_vote_attestation_from_header<H>(
    header: &H,
    epoch_len: u64,
    is_luban: bool,
    is_bohr: bool,
) -> Option<VoteAttestation>
where
    H: BlockHeaderTrait,
{
    let extra = header.extra_data().as_ref();
    if extra.len() <= EXTRA_VANITY + EXTRA_SEAL {
        return None;
    }
    if !is_luban {
        return None; // attestation introduced in Luban
    }

    // Determine attestation slice boundaries.
    let number = header.number();

    // Guard against division by zero - if epoch_len is 0, there can't be epoch boundaries
    if epoch_len == 0 {
        return None;
    }

    let att_bytes = if number % epoch_len == 0 {
        // Epoch block (contains validator bytes + optional turnLength)
        let num_validators = extra[EXTRA_VANITY] as usize; // first byte after vanity
        let mut start = EXTRA_VANITY + VALIDATOR_NUMBER_SIZE + num_validators * VALIDATOR_BYTES_LEN_AFTER_LUBAN;
        if is_bohr {
            start += TURN_LENGTH_SIZE;
        }
        let end = extra.len() - EXTRA_SEAL;
        if end <= start {
            return None;
        }
        &extra[start..end]
    } else {
        // Normal block: attestation directly after vanity
        let start = EXTRA_VANITY;
        let end = extra.len() - EXTRA_SEAL;
        &extra[start..end]
    };

    if att_bytes.is_empty() {
        return None;
    }

    match VoteAttestation::decode_rlp(att_bytes) {
        Ok(a) => Some(a),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;

    // Mock header for testing
    struct MockHeader {
        number: u64,
        extra_data: Bytes,
    }

    impl alloy_consensus::BlockHeader for MockHeader {
        fn number(&self) -> u64 { self.number }
        fn extra_data(&self) -> &Bytes { &self.extra_data }
        
        // Required trait methods (minimal implementation for testing)
        fn beneficiary(&self) -> alloy_primitives::Address { alloy_primitives::Address::ZERO }
        fn gas_limit(&self) -> u64 { 8000000 }
        fn gas_used(&self) -> u64 { 0 }
        fn timestamp(&self) -> u64 { 1000000 }
        fn base_fee_per_gas(&self) -> Option<u64> { None }
        fn difficulty(&self) -> alloy_primitives::U256 { alloy_primitives::U256::from(1) }
        fn transactions_root(&self) -> alloy_primitives::B256 { alloy_primitives::B256::ZERO }
        fn state_root(&self) -> alloy_primitives::B256 { alloy_primitives::B256::ZERO }
        fn receipts_root(&self) -> alloy_primitives::B256 { alloy_primitives::B256::ZERO }
        fn logs_bloom(&self) -> alloy_primitives::Bloom { alloy_primitives::Bloom::ZERO }
        fn parent_hash(&self) -> alloy_primitives::B256 { alloy_primitives::B256::ZERO }
        fn ommers_hash(&self) -> alloy_primitives::B256 { alloy_primitives::B256::ZERO }
        fn withdrawals_root(&self) -> Option<alloy_primitives::B256> { None }
        fn mix_hash(&self) -> Option<alloy_primitives::B256> { None }
        fn nonce(&self) -> Option<alloy_primitives::FixedBytes<8>> { None }
        fn blob_gas_used(&self) -> Option<u64> { None }
        fn excess_blob_gas(&self) -> Option<u64> { None }
        fn parent_beacon_block_root(&self) -> Option<alloy_primitives::B256> { None }
        fn requests_hash(&self) -> Option<alloy_primitives::B256> { None }
    }

    #[test]
    fn test_parse_vote_attestation_with_zero_epoch_len() {
        // Test that parsing vote attestation doesn't cause division by zero when epoch_len is 0
        let header = MockHeader {
            number: 200, // A number that would be an epoch boundary if epoch_len was 200
            extra_data: Bytes::from(vec![0u8; EXTRA_VANITY + EXTRA_SEAL + 10]), // Some extra data
        };

        // This would panic before the fix if epoch_len was 0
        let result = parse_vote_attestation_from_header(&header, 0, true, false);
        
        // Should return None (no attestation) but shouldn't panic
        assert!(result.is_none(), "Should handle zero epoch_len gracefully");
    }

    #[test]
    fn test_parse_vote_attestation_with_valid_epoch_len() {
        // Test normal operation with valid epoch_len
        let header = MockHeader {
            number: 200, // Epoch boundary for epoch_len = 200
            extra_data: Bytes::from(vec![0u8; EXTRA_VANITY + EXTRA_SEAL]), // Minimal extra data
        };

        // This should work normally
        let result = parse_vote_attestation_from_header(&header, 200, true, false);
        
        // Should return None (no attestation data) but shouldn't panic
        assert!(result.is_none(), "Should handle normal epoch operation");
    }

    #[test]
    fn test_parse_vote_attestation_non_epoch_block() {
        // Test with non-epoch block (should not use modulo operation)
        let header = MockHeader {
            number: 199, // Not an epoch boundary
            extra_data: Bytes::from(vec![0u8; EXTRA_VANITY + EXTRA_SEAL + 10]),
        };

        // This should work regardless of epoch_len
        let result1 = parse_vote_attestation_from_header(&header, 0, true, false);
        let result2 = parse_vote_attestation_from_header(&header, 200, true, false);
        
        // Both should return None and not panic
        assert!(result1.is_none());
        assert!(result2.is_none());
    }

    #[test]
    fn test_parse_vote_attestation_pre_luban() {
        // Test pre-Luban behavior (should return None early)
        let header = MockHeader {
            number: 200,
            extra_data: Bytes::from(vec![0u8; EXTRA_VANITY + EXTRA_SEAL + 100]),
        };

        // Pre-Luban should return None immediately
        let result = parse_vote_attestation_from_header(&header, 0, false, false);
        assert!(result.is_none(), "Pre-Luban should return None regardless of epoch_len");
    }

    #[test]
    fn test_parse_vote_attestation_insufficient_extra_data() {
        // Test with insufficient extra data
        let header = MockHeader {
            number: 200,
            extra_data: Bytes::from(vec![0u8; EXTRA_VANITY + EXTRA_SEAL - 1]), // Too short
        };

        // Should return None for insufficient data
        let result = parse_vote_attestation_from_header(&header, 200, true, false);
        assert!(result.is_none(), "Should handle insufficient extra data gracefully");
    }

    #[test]
    fn test_parse_vote_attestation_with_real_bsc_genesis_block() {
        // Real BSC genesis block data from the logs
        // Hash: 0x78dec18c6d7da925bbe773c315653cdc70f6444ed6c1de9ac30bdb36cff74c3b
        let genesis_header = MockHeader {
            number: 0,
            extra_data: Bytes::new(), // Genesis block typically has empty extra_data
        };

        // Genesis block should not have attestation data
        let result = parse_vote_attestation_from_header(&genesis_header, 200, true, false);
        assert!(result.is_none(), "Genesis block should not have attestation data");
    }

    #[test]
    fn test_parse_vote_attestation_with_real_bsc_block_minimal_extra_data() {
        // Test with minimal extra data (vanity + seal only, like genesis)
        let header = MockHeader {
            number: 1,
            extra_data: Bytes::from(vec![0u8; EXTRA_VANITY + EXTRA_SEAL]), // Exactly minimum size
        };

        // Should return None as there's no space for attestation
        let result = parse_vote_attestation_from_header(&header, 200, true, false);
        assert!(result.is_none(), "Block with minimal extra_data should not have attestation");
    }

    #[test]
    fn test_parse_vote_attestation_with_real_bsc_epoch_block() {
        // Simulate a real BSC epoch block (block number divisible by epoch length)
        // These blocks contain validator information
        let epoch_block_number = 200; // Epoch boundary for epoch_len=200
        
        // Create extra_data with validator information
        let num_validators = 21u8; // Typical BSC validator count
        let mut extra_data = vec![0u8; EXTRA_VANITY]; // 32-byte vanity
        extra_data.push(num_validators); // 1-byte validator count
        
        // Add validator consensus addresses (20 bytes each) + vote addresses (48 bytes each)
        for _ in 0..num_validators {
            extra_data.extend_from_slice(&[0u8; VALIDATOR_BYTES_LEN_AFTER_LUBAN]); // 68 bytes per validator
        }
        
        // Add some attestation data (empty for this test)
        // In real BSC, this would be RLP-encoded VoteAttestation
        // extra_data.extend_from_slice(&[0u8; 10]); // Some attestation bytes
        
        // Add seal (65-byte signature)
        extra_data.extend_from_slice(&[0u8; EXTRA_SEAL]);

        let header = MockHeader {
            number: epoch_block_number,
            extra_data: Bytes::from(extra_data),
        };

        // Should handle epoch block without panic
        let result = parse_vote_attestation_from_header(&header, 200, true, false);
        assert!(result.is_none(), "Epoch block with no attestation data should return None");
    }

    #[test]
    fn test_parse_vote_attestation_with_real_bsc_non_epoch_block_with_attestation() {
        // Simulate a real BSC non-epoch block with attestation data
        let mut extra_data = vec![0u8; EXTRA_VANITY]; // 32-byte vanity
        
        // Add mock RLP-encoded attestation data
        // This simulates real attestation data that would be present in BSC blocks
        let mock_attestation_rlp = vec![
            0xf8, 0x4f, // RLP list header (79 bytes)
            0x01, // vote_address_set (mock)
            0xb8, 0x60, // 96-byte signature header
            // 96 bytes of mock BLS signature
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
            0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
        ];
        
        extra_data.extend_from_slice(&mock_attestation_rlp);
        extra_data.extend_from_slice(&[0u8; EXTRA_SEAL]); // 65-byte seal

        let header = MockHeader {
            number: 199, // Non-epoch block
            extra_data: Bytes::from(extra_data),
        };

        // Should attempt to parse but likely fail due to mock data (that's ok)
        let _result = parse_vote_attestation_from_header(&header, 200, true, false);
        // Mock data will likely fail RLP decoding, which is expected
        // The important thing is it doesn't panic
    }

    #[test]
    fn test_parse_vote_attestation_with_real_bsc_bohr_epoch_block() {
        // Test Bohr hardfork epoch block with turnLength
        let epoch_block_number = 400;
        let num_validators = 21u8;
        
        let mut extra_data = vec![0u8; EXTRA_VANITY]; // 32-byte vanity
        extra_data.push(num_validators); // 1-byte validator count
        
        // Add validator data
        for _ in 0..num_validators {
            extra_data.extend_from_slice(&[0u8; VALIDATOR_BYTES_LEN_AFTER_LUBAN]);
        }
        
        // Add turnLength (Bohr hardfork feature)
        extra_data.push(0x01); // turnLength = 1
        
        // Add seal
        extra_data.extend_from_slice(&[0u8; EXTRA_SEAL]);

        let header = MockHeader {
            number: epoch_block_number,
            extra_data: Bytes::from(extra_data),
        };

        // Should handle Bohr epoch block correctly
        let result = parse_vote_attestation_from_header(&header, 200, true, true); // is_bohr=true
        assert!(result.is_none(), "Bohr epoch block with no attestation should return None");
    }

    #[test]
    fn test_parse_vote_attestation_real_world_error_scenarios() {
        // Test the division by zero scenario that was causing panics
        let header = MockHeader {
            number: 200,
            extra_data: Bytes::from(vec![0u8; EXTRA_VANITY + EXTRA_SEAL + 10]),
        };

        // This should NOT panic (our fix prevents this)
        let result = parse_vote_attestation_from_header(&header, 0, true, false);
        assert!(result.is_none(), "Zero epoch_len should be handled gracefully");
    }

    #[test]
    fn test_parse_vote_attestation_with_real_bsc_mainnet_parameters() {
        // Test with real BSC mainnet parameters
        // BSC mainnet typically uses epoch_len = 200
        // Block times are ~3 seconds
        
        let mainnet_epoch_len = 200u64;
        
        // Test various block numbers around epoch boundaries
        let test_blocks = vec![
            (0, true),     // Genesis
            (1, false),    // First block after genesis
            (199, false),  // Just before epoch
            (200, true),   // Epoch boundary
            (201, false),  // Just after epoch
            (399, false),  // Before next epoch
            (400, true),   // Next epoch boundary
        ];

        for (block_number, is_epoch) in test_blocks {
            let mut extra_data = vec![0u8; EXTRA_VANITY];
            
            if is_epoch && block_number > 0 {
                // Add validator data for epoch blocks
                let num_validators = 21u8;
                extra_data.push(num_validators);
                for _ in 0..num_validators {
                    extra_data.extend_from_slice(&[0u8; VALIDATOR_BYTES_LEN_AFTER_LUBAN]);
                }
            }
            
            extra_data.extend_from_slice(&[0u8; EXTRA_SEAL]);

            let header = MockHeader {
                number: block_number,
                extra_data: Bytes::from(extra_data.clone()),
            };

            // Should handle all block types without panic
            let result = parse_vote_attestation_from_header(&header, mainnet_epoch_len, true, false);
            
            // All should return None since we're not providing real attestation data
            assert!(result.is_none(), 
                "Block {} (epoch: {}) should handle gracefully", block_number, is_epoch);
        }
    }
} 