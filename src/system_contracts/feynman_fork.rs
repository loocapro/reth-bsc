use std::{cmp::Ordering, collections::BinaryHeap};

use alloy_primitives::{Address, U256};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorElectionInfo {
    pub address: Address,
    pub voting_power: U256,
    pub vote_address: Vec<u8>,
}

/// Helper type for the output of `get_top_validators_by_voting_power`
#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct ElectedValidators {
    pub validators: Vec<Address>,
    pub voting_powers: Vec<u64>,
    pub vote_addrs: Vec<Vec<u8>>,
}

impl Ord for ValidatorElectionInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.voting_power.cmp(&other.voting_power) {
            // If the voting power is the same, we compare the address as string.
            Ordering::Equal => other.address.to_string().cmp(&self.address.to_string()),
            other => other,
        }
    }
}

impl PartialOrd for ValidatorElectionInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[allow(dead_code)]
pub fn get_top_validators_by_voting_power(
    validators: Vec<ValidatorElectionInfo>,
    max_elected_validators: U256,
) -> ElectedValidators {
    let mut validator_heap: BinaryHeap<ValidatorElectionInfo> = BinaryHeap::new();
    for info in validators {
        if info.voting_power > U256::ZERO {
            validator_heap.push(info);
        }
    }

    let top_n = max_elected_validators.to::<u64>() as usize;
    let top_n = if top_n > validator_heap.len() { validator_heap.len() } else { top_n };

    let mut e_validators = Vec::with_capacity(top_n);
    let mut e_voting_powers = Vec::with_capacity(top_n);
    let mut e_vote_addrs = Vec::with_capacity(top_n);

    for _ in 0..top_n {
        if let Some(item) = validator_heap.pop() {
            e_validators.push(item.address);
            // as the decimal in BNB Beacon Chain is 1e8 and in BNB Smart Chain is 1e18, we need to
            // divide it by 1e10
            e_voting_powers.push((item.voting_power / U256::from(10u64.pow(10))).to::<u64>());
            e_vote_addrs.push(item.vote_address);
        }
    }

    ElectedValidators {
        validators: e_validators,
        voting_powers: e_voting_powers,
        vote_addrs: e_vote_addrs,
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::hex;

    use super::*;

    #[test]
    fn validator_heap() {
        let test_cases = vec![
            (
                "normal case",
                2,
                vec![
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(1),
                        voting_power: U256::from(300) * U256::from(10u64.pow(10)),
                        vote_address: hex::decode("0x01").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(2),
                        voting_power: U256::from(200) * U256::from(10u64.pow(10)),
                        vote_address: hex::decode("0x02").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(3),
                        voting_power: U256::from(100) * U256::from(10u64.pow(10)),
                        vote_address: hex::decode("0x03").unwrap(),
                    },
                ],
                vec![Address::with_last_byte(1), Address::with_last_byte(2)],
            ),
            (
                "same voting power",
                2,
                vec![
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(1),
                        voting_power: U256::from(300) * U256::from(10u64.pow(10)),
                        vote_address: hex::decode("0x01").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(2),
                        voting_power: U256::from(100) * U256::from(10u64.pow(10)),
                        vote_address: hex::decode("0x02").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(3),
                        voting_power: U256::from(100) * U256::from(10u64.pow(10)),
                        vote_address: hex::decode("0x03").unwrap(),
                    },
                ],
                vec![Address::with_last_byte(1), Address::with_last_byte(2)],
            ),
            (
                "zero voting power and k > len(validators)",
                5,
                vec![
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(1),
                        voting_power: U256::from(300) * U256::from(10u64.pow(10)),
                        vote_address: hex::decode("0x01").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(2),
                        voting_power: U256::ZERO,
                        vote_address: hex::decode("0x02").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(3),
                        voting_power: U256::ZERO,
                        vote_address: hex::decode("0x03").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(4),
                        voting_power: U256::ZERO,
                        vote_address: hex::decode("0x04").unwrap(),
                    },
                ],
                vec![Address::with_last_byte(1)],
            ),
            (
                "zero voting power and k < len(validators)",
                5,
                vec![
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(1),
                        voting_power: U256::from(300) * U256::from(10u64.pow(10)),
                        vote_address: hex::decode("0x01").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(2),
                        voting_power: U256::ZERO,
                        vote_address: hex::decode("0x02").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(3),
                        voting_power: U256::ZERO,
                        vote_address: hex::decode("0x03").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(4),
                        voting_power: U256::ZERO,
                        vote_address: hex::decode("0x04").unwrap(),
                    },
                ],
                vec![Address::with_last_byte(1)],
            ),
            (
                "all zero voting power",
                2,
                vec![
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(1),
                        voting_power: U256::ZERO,
                        vote_address: hex::decode("0x01").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(2),
                        voting_power: U256::ZERO,
                        vote_address: hex::decode("0x02").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(3),
                        voting_power: U256::ZERO,
                        vote_address: hex::decode("0x03").unwrap(),
                    },
                    ValidatorElectionInfo {
                        address: Address::with_last_byte(4),
                        voting_power: U256::ZERO,
                        vote_address: hex::decode("0x04").unwrap(),
                    },
                ],
                vec![],
            ),
        ];

        for (description, k, validators, expected) in test_cases {
            let eligible_validators =
                get_top_validators_by_voting_power(validators, U256::from(k)).validators;

            assert_eq!(eligible_validators.len(), expected.len(), "case: {}", description);
            for i in 0..expected.len() {
                assert_eq!(eligible_validators[i], expected[i], "case: {}", description);
            }
        }
    }
}