//! Extend Tendermint votes with Ethereum events seen by a quorum of validators.

use std::collections::BTreeMap;

use namada_sdk::collections::HashMap;
use namada_vote_ext::ethereum_events::MultiSignedEthEvent;

use super::*;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Checks the channel from the Ethereum oracle monitoring
    /// the fullnode and retrieves all seen Ethereum events.
    pub fn new_ethereum_events(&mut self) -> Vec<EthereumEvent> {
        let queries = self.state.ethbridge_queries();
        match &mut self.mode {
            ShellMode::Validator {
                eth_oracle:
                    Some(EthereumOracleChannels {
                        ethereum_receiver, ..
                    }),
                ..
            } => {
                ethereum_receiver.fill_queue(|event| {
                    queries.validate_eth_event_nonce(event)
                });
                ethereum_receiver.get_events()
            }
            _ => vec![],
        }
    }

    /// Takes an iterator over Ethereum events vote extension instances,
    /// and returns another iterator. The latter yields
    /// valid Ethereum events vote extensions, or the reason why these
    /// are invalid, in the form of a `VoteExtensionError`.
    #[inline]
    pub fn validate_eth_events_vext_list<'iter>(
        &'iter self,
        vote_extensions: impl IntoIterator<Item = Signed<ethereum_events::Vext>>
        + 'iter,
    ) -> impl Iterator<
        Item = std::result::Result<
            Signed<ethereum_events::Vext>,
            VoteExtensionError,
        >,
    > + 'iter {
        vote_extensions.into_iter().map(|vote_extension| {
            validate_eth_events_vext::<_, _, governance::Store<_>>(
                &self.state,
                &vote_extension,
                self.state.in_mem().get_last_block_height(),
            )?;
            Ok(vote_extension)
        })
    }

    /// Takes a list of signed Ethereum events vote extensions,
    /// and filters out invalid instances.
    #[inline]
    pub fn filter_invalid_eth_events_vexts<'iter>(
        &'iter self,
        vote_extensions: impl IntoIterator<Item = Signed<ethereum_events::Vext>>
        + 'iter,
    ) -> impl Iterator<Item = Signed<ethereum_events::Vext>> + 'iter {
        self.validate_eth_events_vext_list(vote_extensions)
            .filter_map(|ext| ext.ok())
    }

    /// Compresses a set of signed Ethereum events into a single
    /// [`ethereum_events::VextDigest`], whilst filtering invalid
    /// [`Signed<ethereum_events::Vext>`] instances in the process.
    ///
    /// When vote extensions are being used, this performs a check
    /// that at least 2/3 of the validators by voting power have
    /// included ethereum events in their vote extension.
    pub fn compress_ethereum_events(
        &self,
        vote_extensions: Vec<Signed<ethereum_events::Vext>>,
    ) -> Option<ethereum_events::VextDigest> {
        #[allow(clippy::question_mark)]
        if self.state.in_mem().last_block.is_none() {
            return None;
        }

        let mut event_observers = BTreeMap::new();
        let mut signatures = HashMap::new();

        for vote_extension in
            self.filter_invalid_eth_events_vexts(vote_extensions)
        {
            let validator_addr = vote_extension.data.validator_addr;
            let block_height = vote_extension.data.block_height;

            // register all ethereum events seen by `validator_addr`
            for ev in vote_extension.data.ethereum_events {
                let signers =
                    event_observers.entry(ev).or_insert_with(BTreeSet::new);
                signers.insert((validator_addr.clone(), block_height));
            }

            // register the signature of `validator_addr`
            let addr = validator_addr.clone();
            let sig = vote_extension.sig;

            let key = (addr, block_height);
            tracing::debug!(
                ?key,
                ?sig,
                ?validator_addr,
                "Inserting signature into ethereum_events::VextDigest"
            );
            if let Some(existing_sig) = signatures.insert(key, sig.clone()) {
                tracing::warn!(
                    ?sig,
                    ?existing_sig,
                    ?validator_addr,
                    "Overwrote old signature from validator while \
                     constructing ethereum_events::VextDigest - maybe private \
                     key of validator is being used by multiple nodes?"
                );
            }
        }

        let events: Vec<MultiSignedEthEvent> = event_observers
            .into_iter()
            .map(|(event, signers)| MultiSignedEthEvent { event, signers })
            .collect();

        Some(ethereum_events::VextDigest { events, signatures })
    }
}

#[allow(clippy::cast_possible_truncation)]
#[cfg(test)]
mod test_vote_extensions {
    use namada_sdk::address::testing::gen_established_address;
    use namada_sdk::eth_bridge::EthBridgeQueries;
    use namada_sdk::eth_bridge::storage::bridge_pool;
    use namada_sdk::eth_bridge::storage::eth_bridge_queries::is_bridge_comptime_enabled;
    use namada_sdk::eth_bridge::test_utils::GovStore;
    use namada_sdk::ethereum_events::{
        EthAddress, EthereumEvent, TransferToEthereum, Uint,
    };
    use namada_sdk::hash::Hash;
    use namada_sdk::key::*;
    use namada_sdk::proof_of_stake::queries::get_consensus_validator_from_protocol_pk;
    use namada_sdk::proof_of_stake::storage::{
        consensus_validator_set_handle,
        read_consensus_validator_set_addresses_with_stake, read_pos_params,
    };
    use namada_sdk::proof_of_stake::types::WeightedValidator;
    use namada_sdk::state::collections::lazy_map::{NestedSubKey, SubKey};
    use namada_sdk::storage::{Epoch, InnerEthEventsQueue, StorageWrite};
    use namada_sdk::tendermint::abci::types::VoteInfo;
    use namada_sdk::{governance, tendermint};
    use namada_vote_ext::ethereum_events;

    use super::validate_eth_events_vext;
    use crate::shell::FinalizeBlockRequest;
    use crate::shell::test_utils::*;

    /// Test validating Ethereum events.
    #[test]
    fn test_eth_event_validate() {
        let (mut shell, _, _, _) = setup();
        let nonce: Uint = 10u64.into();

        // write bp nonce to storage
        shell
            .state
            .write(&bridge_pool::get_nonce_key(), nonce)
            .expect("Test failed");

        // write nam nonce to the eth events queue
        shell
            .state
            .in_mem_mut()
            .eth_events_queue
            .transfers_to_namada = InnerEthEventsQueue::new_at(nonce);

        // eth transfers with the same nonce as the bp nonce in storage are
        // valid
        shell
            .state
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToEthereum {
                nonce,
                transfers: vec![],
                relayer: gen_established_address(),
            })
            .then_some(())
            .ok_or(())
            .expect("Test failed");

        // eth transfers with different nonces are invalid
        shell
            .state
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToEthereum {
                nonce: nonce + 1,
                transfers: vec![],
                relayer: gen_established_address(),
            })
            .then_some(())
            .ok_or(())
            .expect_err("Test failed");
        shell
            .state
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToEthereum {
                nonce: nonce - 1,
                transfers: vec![],
                relayer: gen_established_address(),
            })
            .then_some(())
            .ok_or(())
            .expect_err("Test failed");

        // nam transfers with nonces >= the nonce in storage are valid
        shell
            .state
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToNamada {
                nonce,
                transfers: vec![],
            })
            .then_some(())
            .ok_or(())
            .expect("Test failed");
        shell
            .state
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToNamada {
                nonce: nonce + 5,
                transfers: vec![],
            })
            .then_some(())
            .ok_or(())
            .expect("Test failed");

        // nam transfers with lower nonces are invalid
        shell
            .state
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToNamada {
                nonce: nonce - 1,
                transfers: vec![],
            })
            .then_some(())
            .ok_or(())
            .expect_err("Test failed");
        shell
            .state
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToNamada {
                nonce: nonce - 2,
                transfers: vec![],
            })
            .then_some(())
            .ok_or(())
            .expect_err("Test failed");
    }

    /// Test that we successfully receive ethereum events
    /// from the channel to fullnode process
    ///
    /// We further check that ledger side buffering is done if multiple
    /// events are in the channel and that queueing and de-duplicating is
    /// done
    #[test]
    fn test_get_eth_events() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (mut shell, _, oracle, _) = setup();
        let event_1 = EthereumEvent::TransfersToEthereum {
            nonce: 0.into(),
            transfers: vec![TransferToEthereum {
                amount: 100.into(),
                asset: EthAddress([1; 20]),
                receiver: EthAddress([2; 20]),
                checksum: Hash::default(),
            }],
            relayer: gen_established_address(),
        };
        let event_2 = EthereumEvent::TransfersToEthereum {
            nonce: 1.into(),
            transfers: vec![TransferToEthereum {
                amount: 100.into(),
                asset: EthAddress([1; 20]),
                receiver: EthAddress([2; 20]),
                checksum: Hash::default(),
            }],
            relayer: gen_established_address(),
        };
        let event_3 = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![],
        };
        let event_4 = EthereumEvent::TransfersToNamada {
            nonce: 1.into(),
            transfers: vec![],
        };

        // send valid events
        tokio_test::block_on(oracle.send(event_1.clone()))
            .expect("Test failed");
        tokio_test::block_on(oracle.send(event_3.clone()))
            .expect("Test failed");

        let got_events: [EthereumEvent; 2] =
            shell.new_ethereum_events().try_into().expect("Test failed");
        let expected_events: Vec<_> = std::collections::BTreeSet::from([
            event_1.clone(),
            event_3.clone(),
        ])
        .into_iter()
        .collect();
        assert_eq!(expected_events, got_events);

        // we cannot get two transfer to ethereum events within
        // the same block height on ethereum. this is because we
        // require a confirmation eth event on namada to increment
        // the bridge pool nonce. this event should get ignored
        tokio_test::block_on(oracle.send(event_2)).expect("Test failed");

        // check that we queue and de-duplicate events
        tokio_test::block_on(oracle.send(event_3.clone()))
            .expect("Test failed");
        tokio_test::block_on(oracle.send(event_4.clone()))
            .expect("Test failed");

        let got_events: [EthereumEvent; 3] =
            shell.new_ethereum_events().try_into().expect("Test failed");
        let expected_events: Vec<_> =
            std::collections::BTreeSet::from([event_1, event_3, event_4])
                .into_iter()
                .collect();
        assert_eq!(expected_events, got_events);
    }

    /// Test that Ethereum events signed by a non-validator are rejected
    #[test]
    fn test_eth_events_must_be_signed_by_validator() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (shell, _, _, _) = setup_at_height(3u64);
        let signing_key = gen_keypair();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        #[allow(clippy::redundant_clone)]
        let ethereum_events = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 0.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                    checksum: Hash::default(),
                }],
                relayer: gen_established_address(),
            }],
            block_height: shell.get_current_decision_height(),
            validator_addr: address.clone(),
        }
        .sign(&signing_key);
        assert!(
            validate_eth_events_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &ethereum_events,
                shell.get_current_decision_height(),
            )
            .is_err()
        )
    }

    /// Test that validation of Ethereum events cast during the
    /// previous block are accepted for the current block. This
    /// should pass even if the epoch changed resulting in a
    /// change to the validator set.
    #[test]
    fn test_validate_eth_events_vexts() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (mut shell, _recv, _, _oracle_control_recv) = setup_at_height(3u64);
        let signing_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let signed_height = shell.get_current_decision_height();
        let vote_ext = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 0.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                    checksum: Hash::default(),
                }],
                relayer: gen_established_address(),
            }],
            block_height: signed_height,
            validator_addr: address,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));

        assert_eq!(shell.state.in_mem().get_current_epoch().0.0, 0);
        // remove all validators of the next epoch
        let validators_handle = consensus_validator_set_handle().at(&1.into());
        let consensus_in_mem = validators_handle
            .iter(&shell.state)
            .expect("Test failed")
            .map(|val| {
                let (
                    NestedSubKey::Data {
                        key: stake,
                        nested_sub_key: SubKey::Data(position),
                    },
                    ..,
                ) = val.expect("Test failed");
                (stake, position)
            })
            .collect::<Vec<_>>();
        for (val_stake, val_position) in consensus_in_mem.into_iter() {
            validators_handle
                .at(&val_stake)
                .remove(&mut shell.state, &val_position)
                .expect("Test failed");
        }
        // we advance forward to the next epoch
        let consensus_set: Vec<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.state,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let params =
            read_pos_params::<_, governance::Store<_>>(&shell.state).unwrap();
        let val1 = consensus_set[0].clone();
        let pkh1 = get_pkh_from_address(
            &shell.state,
            &params,
            val1.address.clone(),
            Epoch::default(),
        );
        let votes = vec![VoteInfo {
            validator: crate::tendermint::abci::types::Validator {
                address: pkh1,
                power: (u128::try_from(val1.bonded_stake).expect("Test failed")
                    as u64)
                    .try_into()
                    .unwrap(),
            },
            sig_info:
                crate::tendermint::abci::types::BlockSignatureInfo::LegacySigned,
        }];
        let req = FinalizeBlockRequest {
            proposer_address: tendermint::account::Id::try_from(pkh1.to_vec())
                .unwrap(),
            decided_last_commit: crate::tendermint::abci::types::CommitInfo {
                round: 0u8.into(),
                votes,
            },
            ..Default::default()
        };
        assert_eq!(shell.start_new_epoch(Some(req)).0, 1);
        assert!(
            get_consensus_validator_from_protocol_pk::<_, GovStore<_>>(
                &shell.state,
                &signing_key.ref_to(),
                None
            )
            .unwrap()
            .is_none()
        );
        let prev_epoch =
            Epoch(shell.state.in_mem().get_current_epoch().0.0 - 1);
        assert!(
            get_consensus_validator_from_protocol_pk::<_, GovStore<_>>(
                &shell.state,
                &signing_key.ref_to(),
                Some(prev_epoch)
            )
            .unwrap()
            .is_some()
        );

        assert!(
            validate_eth_events_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &vote_ext,
                signed_height
            )
            .is_ok()
        );
    }

    /// Test for ABCI++ that an [`ethereum_events::Vext`] that incorrectly
    /// labels what block it was included on in a vote extension is
    /// rejected. For ABCI+, test that it is rejected if the block height is
    /// greater than latest block height.
    #[test]
    fn reject_incorrect_block_number() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (shell, _, _, _) = setup_at_height(3u64);
        let address = shell.mode.get_validator_address().unwrap().clone();
        #[allow(clippy::redundant_clone)]
        let mut ethereum_events = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 0.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                    checksum: Hash::default(),
                }],
                relayer: gen_established_address(),
            }],
            block_height: shell.state.in_mem().get_last_block_height(),
            validator_addr: address.clone(),
        };

        ethereum_events.block_height =
            shell.state.in_mem().get_last_block_height() + 1;
        let signed_vext = ethereum_events
            .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(
            validate_eth_events_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &signed_vext,
                shell.state.in_mem().get_last_block_height()
            )
            .is_err()
        )
    }

    /// Test if we reject Ethereum events vote extensions
    /// issued at genesis
    #[test]
    fn test_reject_genesis_vexts() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (shell, _, _, _) = setup();
        let address = shell.mode.get_validator_address().unwrap().clone();
        #[allow(clippy::redundant_clone)]
        let vote_ext = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 0.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                    checksum: Hash::default(),
                }],
                relayer: gen_established_address(),
            }],
            block_height: shell.state.in_mem().get_last_block_height(),
            validator_addr: address.clone(),
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));

        assert!(
            validate_eth_events_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &vote_ext,
                shell.state.in_mem().get_last_block_height()
            )
            .is_err()
        )
    }
}
