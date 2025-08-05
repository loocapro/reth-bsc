#![allow(unused)]
use alloy_chains::Chain;
use core::any::Any;
use reth_chainspec::ForkCondition;
use reth_ethereum_forks::{hardfork, ChainHardforks, EthereumHardfork, Hardfork};
use revm::primitives::hardfork::SpecId;

hardfork!(
    /// The name of a bsc hardfork.
    ///
    /// When building a list of hardforks for a chain, it's still expected to mix with [`EthereumHardfork`].
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Default)]
    BscHardfork {
        /// Initial hardfork of BSC.
        Frontier,
        /// BSC `Ramanujan` hardfork
        Ramanujan,
        /// BSC `Niels` hardfork
        Niels,
        /// BSC `MirrorSync` hardfork
        MirrorSync,
        /// BSC `Bruno` hardfork
        Bruno,
        /// BSC `Euler` hardfork
        Euler,
        /// BSC `Nano` hardfork
        Nano,
        /// BSC `Moran` hardfork
        Moran,
        /// BSC `Gibbs` hardfork
        Gibbs,
        /// BSC `Planck` hardfork
        Planck,
        /// BSC `Luban` hardfork
        Luban,
        /// BSC `Plato` hardfork
        Plato,
        /// BSC `Hertz` hardfork
        Hertz,
        /// BSC `HertzFix` hardfork
        HertzFix,
        /// BSC `Kepler` hardfork
        Kepler,
        /// BSC `Feynman` hardfork
        Feynman,
        /// BSC `FeynmanFix` hardfork
        FeynmanFix,
        /// BSC `Cancun` hardfork
        Cancun,
        /// BSC `Haber` hardfork
        Haber,
        /// BSC `HaberFix` hardfork
        HaberFix,
        /// BSC `Bohr` hardfork
        Bohr,
        /// BSC `Pascal` hardfork
        Pascal,
        /// BSC `Lorentz` hardfork
        Lorentz,
        /// BSC `Maxwell` hardfork
        #[default]
        Maxwell,
    }
);

impl BscHardfork {
    /// Bsc mainnet list of hardforks.
    pub fn bsc_mainnet() -> ChainHardforks {
        ChainHardforks::new(vec![
            (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::SpuriousDragon.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Constantinople.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Petersburg.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::MuirGlacier.boxed(), ForkCondition::Block(0)),
            (Self::Ramanujan.boxed(), ForkCondition::Block(0)),
            (Self::Niels.boxed(), ForkCondition::Block(0)),
            (Self::MirrorSync.boxed(), ForkCondition::Block(5184000)),
            (Self::Bruno.boxed(), ForkCondition::Block(13082000)),
            (Self::Euler.boxed(), ForkCondition::Block(18907621)),
            (Self::Nano.boxed(), ForkCondition::Block(21962149)),
            (Self::Moran.boxed(), ForkCondition::Block(22107423)),
            (Self::Gibbs.boxed(), ForkCondition::Block(23846001)),
            (Self::Planck.boxed(), ForkCondition::Block(27281024)),
            (Self::Luban.boxed(), ForkCondition::Block(29020050)),
            (Self::Plato.boxed(), ForkCondition::Block(30720096)),
            (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(31302048)),
            (EthereumHardfork::London.boxed(), ForkCondition::Block(31302048)),
            (Self::Hertz.boxed(), ForkCondition::Block(31302048)),
            (Self::HertzFix.boxed(), ForkCondition::Block(34140700)),
            (EthereumHardfork::Shanghai.boxed(), ForkCondition::Timestamp(1705996800)), /* 2024-01-23 08:00:00 AM UTC */
            (Self::Kepler.boxed(), ForkCondition::Timestamp(1705996800)), /* 2024-01-23 08:00:00
                                                                           * AM UTC */
            (Self::Feynman.boxed(), ForkCondition::Timestamp(1713419340)), /* 2024-04-18
                                                                            * 05:49:00 AM UTC */
            (Self::FeynmanFix.boxed(), ForkCondition::Timestamp(1713419340)), /* 2024-04-18 05:49:00 AM UTC */
            (EthereumHardfork::Cancun.boxed(), ForkCondition::Timestamp(1718863500)), /* 2024-06-20 06:05:00 AM UTC */
            (Self::Cancun.boxed(), ForkCondition::Timestamp(1718863500)), /* 2024-06-20 06:05:00
                                                                           * AM UTC */
            (Self::Haber.boxed(), ForkCondition::Timestamp(1718863500)), /* 2024-06-20 06:05:00
                                                                          * AM UTC */
            (Self::HaberFix.boxed(), ForkCondition::Timestamp(1727316120)), /* 2024-09-26 02:02:00 AM UTC */
            (Self::Bohr.boxed(), ForkCondition::Timestamp(1727317200)),     /* 2024-09-26
                                                                             * 02:20:00
                                                                             * AM UTC */
            (EthereumHardfork::Prague.boxed(), ForkCondition::Timestamp(1742436600)), /* 2025-03-20 02:10:00 AM UTC */
            (Self::Pascal.boxed(), ForkCondition::Timestamp(1742436600)), /* 2025-03-20 02:10:00
                                                                           * AM UTC */
            (Self::Lorentz.boxed(), ForkCondition::Timestamp(1745903100)), /* 2025-04-29
                                                                            * 05:05:00 AM UTC */
            (Self::Maxwell.boxed(), ForkCondition::Timestamp(1751250600)), /* 2025-06-30
                                                                            * 02:30:00 AM UTC */
        ])
    }

    /// Bsc testnet list of hardforks.
    pub fn bsc_testnet() -> ChainHardforks {
        ChainHardforks::new(vec![
            (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::SpuriousDragon.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Constantinople.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Petersburg.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::MuirGlacier.boxed(), ForkCondition::Block(0)),
            (Self::Ramanujan.boxed(), ForkCondition::Block(1010000)),
            (Self::Niels.boxed(), ForkCondition::Block(1014369)),
            (Self::MirrorSync.boxed(), ForkCondition::Block(5582500)),
            (Self::Bruno.boxed(), ForkCondition::Block(13837000)),
            (Self::Euler.boxed(), ForkCondition::Block(19203503)),
            (Self::Gibbs.boxed(), ForkCondition::Block(22800220)),
            (Self::Nano.boxed(), ForkCondition::Block(23482428)),
            (Self::Moran.boxed(), ForkCondition::Block(23603940)),
            (Self::Planck.boxed(), ForkCondition::Block(28196022)),
            (Self::Luban.boxed(), ForkCondition::Block(29295050)),
            (Self::Plato.boxed(), ForkCondition::Block(29861024)),
            (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(31103030)),
            (EthereumHardfork::London.boxed(), ForkCondition::Block(31103030)),
            (Self::Hertz.boxed(), ForkCondition::Block(31103030)),
            (Self::HertzFix.boxed(), ForkCondition::Block(35682300)),
            (EthereumHardfork::Shanghai.boxed(), ForkCondition::Timestamp(1702972800)),
            (Self::Kepler.boxed(), ForkCondition::Timestamp(1702972800)),
            (Self::Feynman.boxed(), ForkCondition::Timestamp(1710136800)),
            (Self::FeynmanFix.boxed(), ForkCondition::Timestamp(1711342800)),
            (EthereumHardfork::Cancun.boxed(), ForkCondition::Timestamp(1713330442)),
            (Self::Cancun.boxed(), ForkCondition::Timestamp(1713330442)),
            (Self::Haber.boxed(), ForkCondition::Timestamp(1716962820)),
            (Self::HaberFix.boxed(), ForkCondition::Timestamp(1719986788)),
            (Self::Bohr.boxed(), ForkCondition::Timestamp(1724116996)),
            (EthereumHardfork::Prague.boxed(), ForkCondition::Timestamp(1740452880)),
            (Self::Pascal.boxed(), ForkCondition::Timestamp(1740452880)),
            (Self::Lorentz.boxed(), ForkCondition::Timestamp(1744097580)),
            (Self::Maxwell.boxed(), ForkCondition::Timestamp(1748243100)),
        ])
    }

    /// Bsc qa list of hardforks.
    pub fn bsc_qa() -> ChainHardforks {
        ChainHardforks::new(vec![
            (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::SpuriousDragon.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Constantinople.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Petersburg.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
            (EthereumHardfork::MuirGlacier.boxed(), ForkCondition::Block(0)),
            (Self::Ramanujan.boxed(), ForkCondition::Block(0)),
            (Self::Niels.boxed(), ForkCondition::Block(0)),
            (Self::MirrorSync.boxed(), ForkCondition::Block(1)),
            (Self::Bruno.boxed(), ForkCondition::Block(1)),
            (Self::Euler.boxed(), ForkCondition::Block(2)),
            (Self::Nano.boxed(), ForkCondition::Block(3)),
            (Self::Moran.boxed(), ForkCondition::Block(3)),
            (Self::Gibbs.boxed(), ForkCondition::Block(4)),
            (Self::Planck.boxed(), ForkCondition::Block(5)),
            (Self::Luban.boxed(), ForkCondition::Block(6)),
            (Self::Plato.boxed(), ForkCondition::Block(7)),
            (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(8)),
            (EthereumHardfork::London.boxed(), ForkCondition::Block(8)),
            (Self::Hertz.boxed(), ForkCondition::Block(8)),
            (Self::HertzFix.boxed(), ForkCondition::Block(8)),
            (EthereumHardfork::Shanghai.boxed(), ForkCondition::Timestamp(1722442622)),
            (Self::Kepler.boxed(), ForkCondition::Timestamp(1722442622)),
            (Self::Feynman.boxed(), ForkCondition::Timestamp(1722442622)),
            (Self::FeynmanFix.boxed(), ForkCondition::Timestamp(1722442622)),
            (EthereumHardfork::Cancun.boxed(), ForkCondition::Timestamp(1722442622)),
            (Self::Cancun.boxed(), ForkCondition::Timestamp(1722442622)),
            (Self::Haber.boxed(), ForkCondition::Timestamp(1722442622)),
            (Self::HaberFix.boxed(), ForkCondition::Timestamp(1722442622)),
            (Self::Bohr.boxed(), ForkCondition::Timestamp(1722444422)),
        ])
    }
}

/// Match helper method since it's not possible to match on `dyn Hardfork`
fn match_hardfork<H, HF, BHF>(fork: H, hardfork_fn: HF, bsc_hardfork_fn: BHF) -> Option<u64>
where
    H: Hardfork,
    HF: Fn(&EthereumHardfork) -> Option<u64>,
    BHF: Fn(&BscHardfork) -> Option<u64>,
{
    let fork: &dyn Any = &fork;
    if let Some(fork) = fork.downcast_ref::<EthereumHardfork>() {
        return hardfork_fn(fork)
    }
    fork.downcast_ref::<BscHardfork>().and_then(bsc_hardfork_fn)
}

impl From<BscHardfork> for SpecId {
    fn from(spec: BscHardfork) -> Self {
        match spec {
            BscHardfork::Frontier |
            BscHardfork::Ramanujan |
            BscHardfork::Niels |
            BscHardfork::MirrorSync |
            BscHardfork::Bruno |
            BscHardfork::Euler |
            BscHardfork::Gibbs |
            BscHardfork::Nano |
            BscHardfork::Moran |
            BscHardfork::Planck |
            BscHardfork::Luban |
            BscHardfork::Plato => SpecId::MUIR_GLACIER,
            BscHardfork::Hertz | BscHardfork::HertzFix => SpecId::LONDON,
            BscHardfork::Kepler | BscHardfork::Feynman | BscHardfork::FeynmanFix => {
                SpecId::SHANGHAI
            }
            BscHardfork::Cancun |
            BscHardfork::Haber |
            BscHardfork::HaberFix |
            BscHardfork::Bohr => SpecId::CANCUN,
            BscHardfork::Pascal | BscHardfork::Lorentz | BscHardfork::Maxwell => SpecId::PRAGUE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chainspec::{bsc::bsc_mainnet, bsc_chapel::bsc_testnet};

    #[test]
    fn test_hardfork_activation_order_differences() {
        // Test the critical difference between mainnet and testnet activation orders
        // This demonstrates why the order in revm_spec_by_timestamp_and_block_number matters

        // Mainnet activation blocks (from the code):
        // Euler: 18907621, Nano: 21962149, Moran: 22107423, Gibbs: 23846001
        // Order: Gibbs -> Moran -> Nano -> Euler (newest to oldest)

        // Testnet activation blocks (from the code):
        // Euler: 19203503, Gibbs: 22800220, Nano: 23482428, Moran: 23603940
        // Order: Moran -> Nano -> Gibbs -> Euler (newest to oldest)

        // Test mainnet chain spec
        let mainnet_spec = crate::chainspec::BscChainSpec::from(bsc_mainnet());

        // Test blocks around the critical transition points
        // Block 23846000: Should be Moran (before Gibbs activation)
        assert_eq!(
            crate::node::evm::config::revm_spec_by_timestamp_and_block_number(
                mainnet_spec.clone(),
                1700000000, // Some timestamp
                23846000
            ),
            BscHardfork::Moran
        );

        // Block 23846001: Should be Gibbs (Gibbs activation block)
        assert_eq!(
            crate::node::evm::config::revm_spec_by_timestamp_and_block_number(
                mainnet_spec.clone(),
                1700000000, // Some timestamp
                23846001
            ),
            BscHardfork::Gibbs
        );

        // Block 22107422: Should be Nano (before Moran activation)
        assert_eq!(
            crate::node::evm::config::revm_spec_by_timestamp_and_block_number(
                mainnet_spec.clone(),
                1700000000, // Some timestamp
                22107422
            ),
            BscHardfork::Nano
        );

        // Block 22107423: Should be Moran (Moran activation block)
        assert_eq!(
            crate::node::evm::config::revm_spec_by_timestamp_and_block_number(
                mainnet_spec.clone(),
                1700000000, // Some timestamp
                22107423
            ),
            BscHardfork::Moran
        );

        // Test testnet chain spec
        let testnet_spec = crate::chainspec::BscChainSpec::from(bsc_testnet());

        // Test blocks around the critical transition points for testnet
        // Block 23603939: Should be Nano (before Moran activation)
        assert_eq!(
            crate::node::evm::config::revm_spec_by_timestamp_and_block_number(
                testnet_spec.clone(),
                1700000000, // Some timestamp
                23603939
            ),
            BscHardfork::Nano
        );

        // Block 23603940: Should be Moran (Moran activation block)
        assert_eq!(
            crate::node::evm::config::revm_spec_by_timestamp_and_block_number(
                testnet_spec.clone(),
                1700000000, // Some timestamp
                23603940
            ),
            BscHardfork::Moran
        );

        // Block 23482427: Should be Gibbs (before Nano activation)
        assert_eq!(
            crate::node::evm::config::revm_spec_by_timestamp_and_block_number(
                testnet_spec.clone(),
                1700000000, // Some timestamp
                23482427
            ),
            BscHardfork::Gibbs
        );

        // Block 23482428: Should be Nano (Nano activation block)
        assert_eq!(
            crate::node::evm::config::revm_spec_by_timestamp_and_block_number(
                testnet_spec.clone(),
                1700000000, // Some timestamp
                23482428
            ),
            BscHardfork::Nano
        );
    }
}
