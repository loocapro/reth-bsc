# Reth @ BSC

A BSC-compatible Reth client implementation. This project is **not** a fork of Reth, but rather an extension that leverages Reth's powerful `NodeBuilder` API to provide BSC compatibility.

## About

This project aims to bring Reth's high-performance Ethereum client capabilities to the BSC network. By utilizing Reth's modular architecture and NodeBuilder API, we're building a BSC-compatible client that maintains compatibility with Reth's ecosystem while adding BSC-specific features.

## Current Status

- Historical Sync ✅
- BSC Pectra Support ✅
- Live Sync ✅
- Run as validator ❌ (soon)

### Sync Status (as of September 1st, 2025)

- **BSC Mainnet**: Synced to the tip ✅ (9.6TB disk required for archival node)
- **BSC Testnet**: Synced to the tip ✅ (780GB disk required for archival node)

## Getting Started

Refer to the [Reth documentation](https://reth.rs/) for general guidance on running a node and be sure to
add these 2 cli required to start reth-bsc:     
```bash
--chain bsc \
--db.max-size 7TB
```

## Contributing

We welcome community contributions! Whether you're interested in helping with historical sync implementation, BSC Pectra support, or live sync functionality, your help is valuable. Please feel free to open issues or submit pull requests. You can reach out to me on [Telegram](https://t.me/loocapro).

## Disclaimer

This project is experimental and under active development. Use at your own risk.

## Credits

This project is inspired by and builds upon the work of:

- [BNB Chain Reth](https://github.com/bnb-chain/reth) - The original BSC implementation of Reth
- The Reth team, especially [@mattsse](https://github.com/mattsse) for their invaluable contributions to the Reth ecosystem
