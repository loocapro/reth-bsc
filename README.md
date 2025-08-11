# Reth @ BSC

A BSC-compatible Reth client implementation. This project is **not** a fork of Reth, but rather an extension that leverages Reth's powerful `NodeBuilder` API to provide BSC compatibility.

## About

This project aims to bring Reth's high-performance Ethereum client capabilities to the BSC network. By utilizing Reth's modular architecture and NodeBuilder API, we're building a BSC-compatible client that maintains compatibility with Reth's ecosystem while adding BSC-specific features.

## Current Status

This is a **Work in Progress** project that requires community contributions to achieve the following goals:

- [ ] Historical Sync
- ✅ BSC Pectra Support
- [ ] Live Sync

### Sync Status (as of August 5, 2025)

- **BSC Mainnet**: Synced to block 42,159,275 and still syncing 🔄 (11TB disk usage)
- **BSC Testnet**: Synced to the tip ✅ (780GB disk usage)

## Getting Started

Refer to the [Reth documentation](https://reth.rs/) for general guidance on running a node. Note that some BSC-specific configurations may be required.

### Historical Sync

To trigger historical sync, follow these steps:

1. Build the release version:

```bash
cargo build --bin reth-bsc --release
```

2. Run the node with logging enabled:

```bash
RUST_LOG=info ./target/release/reth-bsc node \
    --chain bsc \
    --debug.tip "" # set the tip to the block you want to sync to
```

## Contributing

We welcome community contributions! Whether you're interested in helping with historical sync implementation, BSC Pectra support, or live sync functionality, your help is valuable. Please feel free to open issues or submit pull requests. You can reach out to me on [Telegram](https://t.me/loocapro).

## Disclaimer

This project is experimental and under active development. Use at your own risk.

## Credits

This project is inspired by and builds upon the work of:

- [BNB Chain Reth](https://github.com/bnb-chain/reth) - The original BSC implementation of Reth
- The Reth team, especially [@mattsse](https://github.com/mattsse) for their invaluable contributions to the Reth ecosystem
