cargo clean && cargo update

if [ "$(uname)" == "Linux" ]; then
    RUSTFLAGS='-C link-arg=-lgcc' cargo build --bin reth-bsc --release
elif [ "$(uname)" == "Darwin" ]; then
    cargo build --bin reth-bsc --release
fi


# Custom: Only BSC debug + general warnings
#RUST_LOG=warn,reth_bsc::node::evm::executor=debug ./target/release/reth-bsc

# tip_block=0x8b841b96cb2863e21d9b87ba086e405684b8657e2d1b9ec75d6b70bb25725684 # 10k
# tip_block=0xd16058f981cd556bf454a4c422cb10fd5a3c7938b232be433c6ccf3f08ef506e # 100k
# tip_block=0xba9cdb86dd5bbb14d395240f1429c2099d82372dda3e9d97b9e596eb042fb280 # 300k

# 
# tip_block=0x2c64b38b7a25ddcb7636b81dbefbabd191c128e29acca82b4a7ff7cbe5f2f934 # 30k
# tip_block=0x32ba3474696050e50e21b53b2a29b38180ddaf92605b667ec4537cd81ac5bade # 1000k
# tip_block=0x9bd5a954c1f9c9f5d035d016cc35eb6376ae4dc4fb6ee44a139b432e170687be # 5000k


#tip_block=0xa63e13e2c00f22120498a51ef66683e5f892112aa1bd5d8e6f8f82a54b43bafa # 20k


# tip_block=0xb230ec6bfd3348dff7ae9af62d8d2fb25a2ff3781c770b3fcf75a186e6ddc1bd # 25M

# tip_block=0x1253e0b2342239c7e042d87d75974e7824c5503cd2ec34bfc7f5a8b25a1c36b1 # 35M
# tip_block=0xb74e00072b7aa7720f547c4ec3075b1f7310f98a2d8b3323289ad66927010dfa # 47M 


tip_block=0xb74e00072b7aa7720f547c4ec3075b1f7310f98a2d8b3323289ad66927010dfa # 45M 




tip_block=0xb5ddf3dcb55cf5013110acd3c6c8eaffe5c996e7d3c9d4803e36e9efccdbce47 # 43150000


RUST_LOG=INFO ./target/release/reth-bsc node \
    --chain=bsc-testnet \
    --http --http.api="eth, net, txpool, web3, rpc" \
    --datadir=./target/data_dir/bsc-testnet/data_dir \
    --log.file.directory ./target/data_dir/bsc-testnet/logs \
    --trusted-peers=enode://428b12bcbbe4f607f6d83f91decbce549be5f0819d793ac32b0c7280f159dbb6125837b24d39ad1d568bc42d35e0754600429ea48044a44555e8af2113084ec7@18.181.52.189:30311,enode://28daea97a03f0bff6f061c3fbb2e7b61d61b8683240eb03310dfa2fd1d56f3551f714bb09515c3e389bae6ff11bd85e45075460408696f5f9a782b9ffb66e1d1@34.242.33.165:30311 \
    --metrics 0.0.0.0:6060 \
    --debug.tip $tip_block 