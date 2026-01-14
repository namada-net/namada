use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::ethereum_events::EthereumEvent;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_vote_ext::ethereum_events::MultiSignedEthEvent;

use crate::protocol::transactions::votes::{Votes, dedupe};

/// Represents an Ethereum event being seen by some validators
#[derive(
    Debug,
    Clone,
    Ord,
    PartialOrd,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct EthMsgUpdate {
    /// The event being seen.
    pub body: EthereumEvent,
    /// New votes for this event.
    // NOTE(feature = "abcipp"): This can just become BTreeSet<Address> because
    // BlockHeight will always be the previous block
    pub seen_by: Votes,
}

impl From<MultiSignedEthEvent> for EthMsgUpdate {
    fn from(
        MultiSignedEthEvent { event, signers }: MultiSignedEthEvent,
    ) -> Self {
        Self {
            body: event,
            seen_by: dedupe(signers),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use namada_core::address;
    use namada_core::chain::BlockHeight;
    use namada_core::ethereum_events::testing::{
        arbitrary_nonce, arbitrary_single_transfer,
    };

    use super::*;

    #[test]
    /// Tests [`From<MultiSignedEthEvent>`] for [`EthMsgUpdate`]
    fn test_from_multi_signed_eth_event_for_eth_msg_update() {
        let sole_validator = address::testing::established_address_1();
        let receiver = address::testing::established_address_2();
        let event = arbitrary_single_transfer(arbitrary_nonce(), receiver);
        let with_signers = MultiSignedEthEvent {
            event: event.clone(),
            signers: BTreeSet::from([(
                sole_validator.clone(),
                BlockHeight(100),
            )]),
        };
        let expected = EthMsgUpdate {
            body: event,
            seen_by: Votes::from([(sole_validator, BlockHeight(100))]),
        };

        let update: EthMsgUpdate = with_signers.into();

        assert_eq!(update, expected);
    }

    #[test]
    /// Test that `From<MultiSignedEthEvent>` for `EthMsgUpdate` does in fact
    /// dedupe votes
    fn test_from_multi_signed_eth_event_for_eth_msg_update_dedupes() {
        let validator_1 = address::testing::established_address_1();
        let validator_2 = address::testing::established_address_2();
        let signers = BTreeSet::from([
            (validator_1.clone(), BlockHeight(100)),
            (validator_2.clone(), BlockHeight(200)),
            (validator_1, BlockHeight(300)),
            (validator_2, BlockHeight(400)),
        ]);

        let event = arbitrary_single_transfer(
            arbitrary_nonce(),
            address::testing::established_address_3(),
        );
        let with_signers = MultiSignedEthEvent {
            event: event.clone(),
            signers: signers.clone(),
        };

        let update: EthMsgUpdate = with_signers.into();

        assert_eq!(
            update,
            EthMsgUpdate {
                body: event,
                seen_by: dedupe(signers),
            }
        );
    }
}
