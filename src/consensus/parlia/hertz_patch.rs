//! Hertz hard fork patches for BSC mainnet compatibility
//! 
//! These patches fix specific state inconsistencies that occurred on BSC mainnet
//! during the Hertz upgrade. They apply storage patches at specific transaction hashes.

use alloy_primitives::{address, b256, Address, B256, U256};
use std::collections::HashMap;
use std::str::FromStr;
use once_cell::sync::Lazy;

/// Storage patch definition
#[derive(Debug, Clone)]
pub struct StoragePatch {
    /// Contract address to patch
    pub address: Address,
    /// Storage key-value pairs to apply
    pub storage: HashMap<U256, U256>,
}

/// Mainnet patches to apply before transaction execution
pub static MAINNET_PATCHES_BEFORE_TX: Lazy<HashMap<B256, StoragePatch>> = Lazy::new(|| {
    HashMap::from([
        // Patch 1: BlockNum 33851236, txIndex 89
        (
            b256!("7eba4edc7c1806d6ee1691d43513838931de5c94f9da56ec865721b402f775b0"),
            StoragePatch {
                address: address!("0000000000000000000000000000000000001004"),
                storage: HashMap::from([
                    (
                        U256::from_str("0x2872a065b21b3a75885a33b3c310b5e9b1b1b8db7cfd838c324835d39b8b5e7b").unwrap(),
                        U256::from(1u64),
                    ),
                    (
                        U256::from_str("0x9c6806a4d6a99e4869b9a4aaf80b0a3bf5f5240a1d6032ed82edf0e86f2a2467").unwrap(),
                        U256::from(1u64),
                    ),
                    (
                        U256::from_str("0xe8480d613bbf3b979aee2de4487496167735bb73df024d988e1795b3c7fa559a").unwrap(),
                        U256::from(1u64),
                    ),
                    (
                        U256::from_str("0xebfaec01f898f7f0e2abdb4b0aee3dfbf5ec2b287b1e92f9b62940f85d5f5bac").unwrap(),
                        U256::from(1u64),
                    ),
                ]),
            }
        ),
    ])
});

/// Mainnet patches to apply after transaction execution
pub static MAINNET_PATCHES_AFTER_TX: Lazy<HashMap<B256, StoragePatch>> = Lazy::new(|| {
    HashMap::from([
        // Patch 1: BlockNum 35547779, txIndex 196
        (
            b256!("7ce9a3cf77108fcc85c1e84e88e363e3335eca515dfcf2feb2011729878b13a7"),
            StoragePatch {
                address: address!("89791428868131eb109e42340ad01eb8987526b2"),
                storage: HashMap::from([(
                    U256::from_str("0xf1e9242398de526b8dd9c25d38e65fbb01926b8940377762d7884b8b0dcdc3b0").unwrap(),
                    U256::from_str("0x0000000000000000000000000000000000000000000000f6a7831804efd2cd0a").unwrap(),
                )]),
            },
        ),
        // Patch 2: BlockNum 35548081, txIndex 486
        (
            b256!("e3895eb95605d6b43ceec7876e6ff5d1c903e572bf83a08675cb684c047a695c"),
            StoragePatch {
                address: address!("89791428868131eb109e42340ad01eb8987526b2"),
                storage: HashMap::from([(
                    U256::from_str("0xf1e9242398de526b8dd9c25d38e65fbb01926b8940377762d7884b8b0dcdc3b0").unwrap(),
                    U256::from_str("0x0000000000000000000000000000000000000000000000114be8ecea72b64003").unwrap(),
                )]),
            },
        ),
    ])
});

/// Chapel testnet patches to apply after transaction execution
pub static CHAPEL_PATCHES_AFTER_TX: Lazy<HashMap<B256, StoragePatch>> = Lazy::new(|| {
    HashMap::from([
        // Patch 1: BlockNum 35547779, txIndex 196 (testnet version)
        (
            b256!("7ce9a3cf77108fcc85c1e84e88e363e3335eca515dfcf2feb2011729878b13a7"),
            StoragePatch {
                address: address!("89791428868131eb109e42340ad01eb8987526b2"),
                storage: HashMap::from([(
                    U256::from_str("0xf1e9242398de526b8dd9c25d38e65fbb01926b8940377762d7884b8b0dcdc3b0").unwrap(),
                    U256::ZERO, // Testnet uses zero value
                )]),
            },
        ),
        // Patch 2: BlockNum 35548081, txIndex 486 (testnet version)
        (
            b256!("e3895eb95605d6b43ceec7876e6ff5d1c903e572bf83a08675cb684c047a695c"),
            StoragePatch {
                address: address!("89791428868131eb109e42340ad01eb8987526b2"),
                storage: HashMap::from([(
                    U256::from_str("0xf1e9242398de526b8dd9c25d38e65fbb01926b8940377762d7884b8b0dcdc3b0").unwrap(),
                    U256::ZERO, // Testnet uses zero value
                )]),
            },
        ),
    ])
});

/// Hertz patch manager for applying state patches
#[derive(Debug, Clone)]
pub struct HertzPatchManager {
    is_mainnet: bool,
}

impl HertzPatchManager {
    /// Create a new Hertz patch manager
    pub fn new(is_mainnet: bool) -> Self {
        Self { is_mainnet }
    }

    /// Apply patches before transaction execution
    pub fn patch_before_tx(&self, tx_hash: B256) -> Option<&StoragePatch> {
        if self.is_mainnet {
            MAINNET_PATCHES_BEFORE_TX.get(&tx_hash)
        } else {
            // No before-tx patches for testnet currently
            None
        }
    }

    /// Apply patches after transaction execution
    pub fn patch_after_tx(&self, tx_hash: B256) -> Option<&StoragePatch> {
        if self.is_mainnet {
            MAINNET_PATCHES_AFTER_TX.get(&tx_hash)
        } else {
            CHAPEL_PATCHES_AFTER_TX.get(&tx_hash)
        }
    }

    /// Check if a transaction hash needs patching
    pub fn needs_patch(&self, tx_hash: B256) -> bool {
        self.patch_before_tx(tx_hash).is_some() || self.patch_after_tx(tx_hash).is_some()
    }

    /// Get all patch transaction hashes for debugging
    pub fn get_all_patch_hashes(&self) -> Vec<B256> {
        let mut hashes = Vec::new();
        
        if self.is_mainnet {
            hashes.extend(MAINNET_PATCHES_BEFORE_TX.keys());
            hashes.extend(MAINNET_PATCHES_AFTER_TX.keys());
        } else {
            hashes.extend(CHAPEL_PATCHES_AFTER_TX.keys());
        }
        
        hashes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_patches_exist() {
        let manager = HertzPatchManager::new(true);
        let patch_hashes = manager.get_all_patch_hashes();
        assert!(!patch_hashes.is_empty(), "Mainnet should have patches");
    }

    #[test]
    fn test_chapel_patches_exist() {
        let manager = HertzPatchManager::new(false);
        let patch_hashes = manager.get_all_patch_hashes();
        assert!(!patch_hashes.is_empty(), "Chapel should have patches");
    }

    #[test]
    fn test_specific_mainnet_patch() {
        let manager = HertzPatchManager::new(true);
        let tx_hash = b256!("7eba4edc7c1806d6ee1691d43513838931de5c94f9da56ec865721b402f775b0");
        
        assert!(manager.needs_patch(tx_hash));
        let patch = manager.patch_before_tx(tx_hash).unwrap();
        assert_eq!(patch.address, address!("0000000000000000000000000000000000001004"));
        assert!(!patch.storage.is_empty());
    }
} 