//! Contains types necessary for processing Ethereum events
//! in vote extensions.

use std::collections::BTreeSet;
use std::ops::Deref;

use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::chain::BlockHeight;
use namada_core::collections::HashMap;
use namada_core::ethereum_events::EthereumEvent;
use namada_core::key::common::{self, Signature};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_tx::Signed;

/// Type alias for an [`EthereumEventsVext`].
pub type Vext = EthereumEventsVext;

/// Represents a [`Vext`] signed by some validator, with
/// a Namada protocol key.
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshSchema,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct SignedVext(pub Signed<Vext>);

impl Deref for SignedVext {
    type Target = Signed<Vext>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Signed<Vext>> for SignedVext {
    fn from(value: Signed<Vext>) -> Self {
        Self(value)
    }
}

/// Represents a set of [`EthereumEvent`] instances seen by some validator.
///
/// This struct will be created and signed over by each consensus validator,
/// to be included as a vote extension at the end of a Tendermint PreCommit
/// phase.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct EthereumEventsVext {
    /// The block height for which this [`Vext`] was made.
    pub block_height: BlockHeight,
    /// The address of the validator who submitted the vote extension.
    // NOTE: The validator's established address was included as a workaround
    // for `namada#200`, which prevented us from mapping a CometBFT validator
    // address to a Namada address. Since then, we have committed to keeping
    // this `validator_addr` field.
    pub validator_addr: Address,
    /// The new ethereum events seen. These should be
    /// deterministically ordered.
    pub ethereum_events: Vec<EthereumEvent>,
}

impl Vext {
    /// Creates a [`Vext`] without any Ethereum events.
    pub fn empty(block_height: BlockHeight, validator_addr: Address) -> Self {
        Self {
            block_height,
            ethereum_events: Vec::new(),
            validator_addr,
        }
    }

    /// Sign a [`Vext`] with a validator's `signing_key`,
    /// and return the signed data.
    pub fn sign(self, signing_key: &common::SecretKey) -> Signed<Self> {
        Signed::new(signing_key, self)
    }
}

/// Aggregates an Ethereum event with the corresponding
/// validators who saw this event.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct MultiSignedEthEvent {
    /// The Ethereum event that was signed.
    pub event: EthereumEvent,
    /// List of addresses of validators who signed this event
    /// and block height at which they signed it
    pub signers: BTreeSet<(Address, BlockHeight)>,
}

/// Type alias for an [`EthereumEventsVextDigest`].
pub type VextDigest = EthereumEventsVextDigest;

/// Compresses a set of signed [`Vext`] instances, to save
/// space on a block.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct EthereumEventsVextDigest {
    /// The signatures, signing address, and signing block height
    /// of each [`Vext`]
    pub signatures: HashMap<(Address, BlockHeight), Signature>,
    /// The events that were reported
    pub events: Vec<MultiSignedEthEvent>,
}

impl VextDigest {
    /// Build a singleton [`VextDigest`], from the provided [`Vext`].
    #[inline]
    pub fn singleton(ext: Signed<Vext>) -> VextDigest {
        VextDigest {
            signatures: HashMap::from([(
                (ext.data.validator_addr.clone(), ext.data.block_height),
                ext.sig,
            )]),
            events: ext
                .data
                .ethereum_events
                .into_iter()
                .map(|event| MultiSignedEthEvent {
                    event,
                    signers: BTreeSet::from([(
                        ext.data.validator_addr.clone(),
                        ext.data.block_height,
                    )]),
                })
                .collect(),
        }
    }

    /// Decompresses a set of signed [`Vext`] instances.
    pub fn decompress(self, _: BlockHeight) -> Vec<Signed<Vext>> {
        let VextDigest { signatures, events } = self;

        let mut extensions = vec![];

        for (validator, sig) in signatures.into_iter() {
            let mut ext = Vext::empty(validator.1, validator.0.clone());

            for event in events.iter() {
                if event.signers.contains(&validator) {
                    ext.ethereum_events.push(event.event.clone());
                }
            }

            ext.ethereum_events.sort();

            let signed = Signed::new_from(ext, sig);
            extensions.push(signed);
        }
        extensions
    }
}

#[cfg(test)]
mod tests {
    use namada_core::ethereum_events::Uint;
    use namada_core::hash::Hash;
    use namada_core::{address, key};

    use super::*;

    /// Test the hashing of an Ethereum event
    #[test]
    fn test_ethereum_event_hash() {
        let nonce = Uint::from(123u64);
        let event = EthereumEvent::TransfersToNamada {
            nonce,
            transfers: vec![],
        };
        let hash = event.hash().unwrap();

        assert_eq!(
            hash,
            Hash([
                94, 131, 116, 129, 41, 204, 178, 144, 24, 8, 185, 16, 103, 236,
                209, 191, 20, 89, 145, 17, 41, 233, 31, 98, 185, 6, 217, 204,
                80, 38, 224, 23
            ])
        );
    }

    /// Test decompression of a set of Ethereum events
    #[test]
    fn test_decompress_ethereum_events() {
        // we need to construct a `Vec<Signed<Vext>>`
        let sk_1 = key::testing::keypair_1();
        let sk_2 = key::testing::keypair_2();

        let last_block_height = BlockHeight(123);

        let ev_1 = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
        };
        let ev_2 = EthereumEvent::TransfersToEthereum {
            nonce: 2u64.into(),
            transfers: vec![],
            relayer: address::testing::established_address_1(),
        };

        let validator_1 = address::testing::established_address_1();
        let validator_2 = address::testing::established_address_2();

        let ext = |validator: Address| -> Vext {
            let mut ext = Vext::empty(last_block_height, validator);

            ext.ethereum_events.push(ev_1.clone());
            ext.ethereum_events.push(ev_2.clone());
            ext.ethereum_events.sort();

            ext
        };

        // assume both v1 and v2 saw the same events,
        // so each of them signs `ext` with their respective sk
        let ext_1 = Signed::new(&sk_1, ext(validator_1.clone()));
        let ext_2 = Signed::new(&sk_2, ext(validator_2.clone()));
        let ext_3 = Signed::new(&sk_1, {
            let mut ext = Vext::empty(
                BlockHeight(last_block_height.0 - 1),
                validator_1.clone(),
            );
            ext.ethereum_events.push(ev_1.clone());
            ext.ethereum_events.push(ev_2.clone());
            ext.ethereum_events.sort();
            ext
        });

        let ext = [ext_1, ext_2, ext_3];

        // we have the `Signed<Vext>` instances we need,
        // let us now compress them into a single `VextDigest`
        let signatures: HashMap<_, _> = [
            ((validator_1.clone(), last_block_height), ext[0].sig.clone()),
            ((validator_2.clone(), last_block_height), ext[1].sig.clone()),
            (
                (validator_1.clone(), BlockHeight(last_block_height.0 - 1)),
                ext[2].sig.clone(),
            ),
        ]
        .into_iter()
        .collect();

        let signers = {
            let mut s = BTreeSet::new();
            s.insert((validator_1.clone(), last_block_height));
            s.insert((
                validator_1.clone(),
                BlockHeight(last_block_height.0 - 1),
            ));
            s.insert((validator_2, last_block_height));
            s
        };
        let events = vec![
            MultiSignedEthEvent {
                event: ev_1,
                signers: signers.clone(),
            },
            MultiSignedEthEvent {
                event: ev_2,
                signers,
            },
        ];

        let digest = VextDigest { events, signatures };

        // finally, decompress the `VextDigest` back into a
        // `Vec<Signed<Vext>>`
        let decompressed = digest
            .decompress(last_block_height)
            .into_iter()
            .collect::<Vec<Signed<Vext>>>();

        assert_eq!(decompressed.len(), ext.len());
        for vext in decompressed.into_iter() {
            assert!(ext.contains(&vext));
            if vext.data.validator_addr == validator_1 {
                assert!(vext.verify(&sk_1.to_public()).is_ok())
            } else {
                assert!(vext.verify(&sk_2.to_public()).is_ok())
            }
        }
    }
}
