//! Extend Tendermint votes with validator set updates, to be relayed to
//! Namada's Ethereum bridge smart contracts.

use namada_sdk::collections::HashMap;

use super::*;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Takes an iterator over validator set update vote extension instances,
    /// and returns another iterator. The latter yields
    /// valid validator set update vote extensions, or the reason why these
    /// are invalid, in the form of a `VoteExtensionError`.
    #[inline]
    pub fn validate_valset_upd_vext_list(
        &self,
        vote_extensions: impl IntoIterator<Item = validator_set_update::SignedVext>
        + 'static,
    ) -> impl Iterator<
        Item = std::result::Result<
            validator_set_update::SignedVext,
            VoteExtensionError,
        >,
    > + '_ {
        vote_extensions.into_iter().map(|vote_extension| {
            validate_valset_upd_vext::<_, _, governance::Store<_>>(
                &self.state,
                &vote_extension,
                self.state.in_mem().get_current_epoch().0,
            )?;
            Ok(vote_extension)
        })
    }

    /// Takes a list of signed validator set update vote extensions,
    /// and filters out invalid instances.
    #[inline]
    pub fn filter_invalid_valset_upd_vexts(
        &self,
        vote_extensions: impl IntoIterator<Item = validator_set_update::SignedVext>
        + 'static,
    ) -> impl Iterator<Item = validator_set_update::SignedVext> + '_ {
        self.validate_valset_upd_vext_list(vote_extensions)
            .filter_map(|ext| ext.ok())
    }

    /// Compresses a set of signed validator set update vote extensions into a
    /// single [`validator_set_update::VextDigest`], whilst filtering
    /// invalid [`validator_set_update::SignedVext`] instances in the
    /// process.
    pub fn compress_valset_updates(
        &self,
        vote_extensions: Vec<validator_set_update::SignedVext>,
    ) -> Option<validator_set_update::VextDigest> {
        #[allow(clippy::question_mark)]
        if self.state.in_mem().last_block.is_none() {
            return None;
        }

        let mut voting_powers = None;
        let mut signatures = HashMap::new();

        for validator_set_update::SignedVext(mut vote_extension) in
            self.filter_invalid_valset_upd_vexts(vote_extensions)
        {
            if voting_powers.is_none() {
                voting_powers = Some(std::mem::take(
                    &mut vote_extension.data.voting_powers,
                ));
            }

            let validator_addr = vote_extension.data.validator_addr;
            let signing_epoch = vote_extension.data.signing_epoch;

            // register the signature of `validator_addr`
            let addr = validator_addr.clone();
            let sig = vote_extension.sig.clone();

            tracing::debug!(
                ?sig,
                ?signing_epoch,
                %validator_addr,
                "Inserting signature into validator_set_update::VextDigest"
            );
            if let Some(existing_sig) = signatures.insert(addr, sig) {
                tracing::warn!(
                    sig = ?vote_extension.sig,
                    ?existing_sig,
                    ?validator_addr,
                    ?signing_epoch,
                    "Overwrote old signature from validator while \
                     constructing validator_set_update::VextDigest - maybe \
                     private key of validator is being used by multiple nodes?"
                );
            }
        }

        let voting_powers = voting_powers.unwrap_or_default();

        Some(validator_set_update::VextDigest {
            signatures,
            voting_powers,
        })
    }
}

#[allow(clippy::cast_possible_truncation)]
#[cfg(test)]
mod test_vote_extensions {
    use namada_apps_lib::wallet;
    use namada_sdk::eth_bridge::EthBridgeQueries;
    use namada_sdk::eth_bridge::storage::eth_bridge_queries::is_bridge_comptime_enabled;
    use namada_sdk::eth_bridge::test_utils::GovStore;
    use namada_sdk::key::RefTo;
    use namada_sdk::proof_of_stake::Epoch;
    use namada_sdk::proof_of_stake::queries::get_consensus_validator_from_protocol_pk;
    use namada_sdk::proof_of_stake::storage::{
        consensus_validator_set_handle,
        read_consensus_validator_set_addresses_with_stake, read_pos_params,
    };
    use namada_sdk::proof_of_stake::types::WeightedValidator;
    use namada_sdk::state::collections::lazy_map::{NestedSubKey, SubKey};
    use namada_sdk::tendermint::abci::types::VoteInfo;
    use namada_sdk::{governance, tendermint};
    use namada_vote_ext::validator_set_update;

    use super::validate_valset_upd_vext;
    use crate::shell::FinalizeBlockRequest;
    use crate::shell::test_utils::{self, get_pkh_from_address};

    /// Test if a [`validator_set_update::Vext`] that incorrectly labels what
    /// epoch it was included on in a vote extension is rejected
    #[test]
    fn test_reject_incorrect_epoch() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (shell, _recv, _, _) = test_utils::setup();
        let validator_addr =
            shell.mode.get_validator_address().unwrap().clone();

        let eth_bridge_key =
            shell.mode.get_eth_bridge_keypair().expect("Test failed");

        let signing_epoch = shell.state.in_mem().get_current_epoch().0;
        let next_epoch = signing_epoch.next();

        let voting_powers = {
            shell
                .state
                .ethbridge_queries()
                .get_consensus_eth_addresses::<governance::Store<_>>(next_epoch)
                .map(|(eth_addr_book, _, voting_power)| {
                    (eth_addr_book, voting_power)
                })
                .collect()
        };
        #[allow(clippy::redundant_clone)]
        let validator_set_update = validator_set_update::Vext {
            voting_powers,
            validator_addr: validator_addr.clone(),
            // invalid epoch
            signing_epoch: next_epoch,
        }
        .sign(eth_bridge_key);
        assert!(
            validate_valset_upd_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &validator_set_update,
                signing_epoch,
            )
            .is_err()
        )
    }

    /// Test that validator set update vote extensions signed by
    /// a non-validator are rejected
    #[test]
    fn test_valset_upd_must_be_signed_by_validator() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (shell, _recv, _, _) = test_utils::setup();
        let (eth_bridge_key, _protocol_key, validator_addr) = {
            let bertha_key = wallet::defaults::bertha_keypair();
            let bertha_addr = wallet::defaults::bertha_address();
            (test_utils::gen_secp256k1_keypair(), bertha_key, bertha_addr)
        };
        let signing_epoch = shell.state.in_mem().get_current_epoch().0;
        let voting_powers = {
            let next_epoch = signing_epoch.next();
            shell
                .state
                .ethbridge_queries()
                .get_consensus_eth_addresses::<governance::Store<_>>(next_epoch)
                .map(|(eth_addr_book, _, voting_power)| {
                    (eth_addr_book, voting_power)
                })
                .collect()
        };
        #[allow(clippy::redundant_clone)]
        let validator_set_update = validator_set_update::Vext {
            voting_powers,
            signing_epoch,
            validator_addr: validator_addr.clone(),
        }
        .sign(&eth_bridge_key);
        assert!(
            validate_valset_upd_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &validator_set_update,
                signing_epoch,
            )
            .is_err()
        );
    }

    /// Test the validation of a validator set update emitted for
    /// some epoch `E`. The test should pass even if the epoch
    /// changed to some epoch `E': E' > E`, resulting in a
    /// change to the validator set.
    #[test]
    fn test_validate_valset_upd_vexts() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (mut shell, _recv, _, _oracle_control_recv) = test_utils::setup();

        // validators from the current epoch sign over validator
        // set of the next epoch
        let signing_epoch = shell.state.in_mem().get_current_epoch().0;
        assert_eq!(signing_epoch.0, 0);

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

        // sign validator set update
        let protocol_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let eth_bridge_key = shell
            .mode
            .get_eth_bridge_keypair()
            .expect("Test failed")
            .clone();
        let validator_addr = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let voting_powers = {
            let next_epoch = signing_epoch.next();
            shell
                .state
                .ethbridge_queries()
                .get_consensus_eth_addresses::<governance::Store<_>>(next_epoch)
                .map(|(eth_addr_book, _, voting_power)| {
                    (eth_addr_book, voting_power)
                })
                .collect()
        };
        let vote_ext = validator_set_update::Vext {
            voting_powers,
            signing_epoch,
            validator_addr,
        }
        .sign(&eth_bridge_key);
        assert!(vote_ext.data.voting_powers.is_empty());

        // we advance forward to the next epoch
        let params =
            read_pos_params::<_, governance::Store<_>>(&shell.state).unwrap();
        let mut consensus_set: Vec<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.state,
                0.into(),
            )
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(consensus_set.len(), 1);
        let val1 = consensus_set.remove(0);
        let pkh1 = get_pkh_from_address(
            &shell.state,
            &params,
            val1.address,
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
                &protocol_key.ref_to(),
                None
            )
            .unwrap()
            .is_none()
        );
        let prev_epoch = shell.state.in_mem().get_current_epoch().0 - 1;
        assert!(
            get_consensus_validator_from_protocol_pk::<_, GovStore<_>>(
                &shell.state,
                &protocol_key.ref_to(),
                Some(prev_epoch)
            )
            .unwrap()
            .is_some()
        );

        // check validation of the vext passes
        assert!(
            validate_valset_upd_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &vote_ext,
                signing_epoch
            )
            .is_ok()
        );
    }

    /// Test if a [`validator_set_update::Vext`] with an incorrect signature
    /// is rejected
    #[test]
    fn test_reject_bad_signatures() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (shell, _recv, _, _) = test_utils::setup();
        let validator_addr =
            shell.mode.get_validator_address().unwrap().clone();

        let eth_bridge_key =
            shell.mode.get_eth_bridge_keypair().expect("Test failed");

        let signing_epoch = shell.state.in_mem().get_current_epoch().0;
        #[allow(clippy::redundant_clone)]
        let validator_set_update = {
            let voting_powers = {
                let next_epoch = signing_epoch.next();
                shell
                    .state
                    .ethbridge_queries()
                    .get_consensus_eth_addresses::<governance::Store<_>>(
                        next_epoch,
                    )
                    .map(|(eth_addr_book, _, voting_power)| {
                        (eth_addr_book, voting_power)
                    })
                    .collect()
            };
            let mut ext = validator_set_update::Vext {
                voting_powers,
                signing_epoch,
                validator_addr: validator_addr.clone(),
            }
            .sign(eth_bridge_key);
            ext.0.sig = test_utils::invalidate_signature(ext.0.sig);
            Some(ext)
        };
        assert!(
            validate_valset_upd_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &validator_set_update.unwrap(),
                signing_epoch,
            )
            .is_err()
        );
    }
}
