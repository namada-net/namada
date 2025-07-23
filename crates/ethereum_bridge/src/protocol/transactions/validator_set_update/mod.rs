//! Code for handling validator set update protocol txs.

use eyre::Result;
use namada_core::address::Address;
use namada_core::chain::{BlockHeight, Epoch};
use namada_core::collections::{HashMap, HashSet};
use namada_core::key::common;
use namada_core::token::Amount;
use namada_state::{DBIter, DBRead, StorageHasher, WlState};
use namada_systems::governance;
use namada_tx::data::BatchedTxResult;
use namada_vote_ext::validator_set_update;

use super::ChangedKeys;
use crate::protocol::transactions::utils;
use crate::protocol::transactions::votes::update::NewVotes;
use crate::protocol::transactions::votes::{self, Votes};
use crate::storage::eth_bridge_queries::{EthBridgeQueries, SendValsetUpd};
use crate::storage::proof::EthereumProof;
use crate::storage::vote_tallies;

impl utils::GetVoters for (&validator_set_update::VextDigest, BlockHeight) {
    #[inline]
    fn get_voters(self) -> HashSet<(Address, BlockHeight)> {
        // votes were cast at the 2nd block height of the ext's signing epoch
        let (ext, epoch_2nd_height) = self;
        ext.signatures
            .keys()
            .cloned()
            .zip(std::iter::repeat(epoch_2nd_height))
            .collect()
    }
}

/// Sign the next set of validators, and return the associated
/// vote extension protocol transaction.
pub fn sign_validator_set_update<'db, D, H, Gov>(
    state: &WlState<'db, D, H>,
    validator_addr: &Address,
    eth_hot_key: &common::SecretKey,
) -> Option<validator_set_update::SignedVext>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<'db, D, H>>,
{
    state
        .ethbridge_queries()
        .must_send_valset_upd(SendValsetUpd::Now)
        .then(|| {
            let next_epoch = state.in_mem().get_current_epoch().0.next();

            let voting_powers = state
                .ethbridge_queries()
                .get_consensus_eth_addresses::<Gov>(next_epoch)
                .map(|(eth_addr_book, _, voting_power)| {
                    (eth_addr_book, voting_power)
                })
                .collect();

            let ext = validator_set_update::Vext {
                voting_powers,
                validator_addr: validator_addr.clone(),
                signing_epoch: state.in_mem().get_current_epoch().0,
            };

            ext.sign(eth_hot_key)
        })
}

/// Aggregate validators' votes
pub fn aggregate_votes<'db, D, H, Gov>(
    state: &mut WlState<'db, D, H>,
    ext: validator_set_update::VextDigest,
    signing_epoch: Epoch,
) -> Result<BatchedTxResult>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<'db, D, H>>,
{
    if ext.signatures.is_empty() {
        tracing::debug!("Ignoring empty validator set update");
        return Ok(Default::default());
    }

    tracing::info!(
        num_votes = ext.signatures.len(),
        "Aggregating new votes for validator set update"
    );

    let epoch_2nd_height = state
        .in_mem()
        .block
        .pred_epochs
        .get_start_height_of_epoch(signing_epoch)
        // NOTE: The only way this can fail is if validator set updates do not
        // reach a `seen` state before the relevant epoch data is purged from
        // Namada. In most scenarios, we should reach a complete proof before
        // the end of an epoch, and even if we cross an epoch boundary without
        // a complete proof, we should get one shortly after.
        .expect("The first block height of the signing epoch should be known")
        .next_height();
    let voting_powers =
        utils::get_voting_powers(state, (&ext, epoch_2nd_height))?;
    let changed_keys = apply_update::<'db, D, H, Gov>(
        state,
        ext,
        signing_epoch,
        epoch_2nd_height,
        voting_powers,
    )?;

    Ok(BatchedTxResult {
        changed_keys,
        ..Default::default()
    })
}

fn apply_update<'db, D, H, Gov>(
    state: &mut WlState<'db, D, H>,
    ext: validator_set_update::VextDigest,
    signing_epoch: Epoch,
    epoch_2nd_height: BlockHeight,
    voting_powers: HashMap<(Address, BlockHeight), Amount>,
) -> Result<ChangedKeys>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<'db, D, H>>,
{
    let next_epoch = {
        // proofs should be written to the sub-key space of the next epoch.
        // this way, we do, for instance, an RPC call to `E=2` to query a
        // validator set proof for epoch 2 signed by validators of epoch 1.
        signing_epoch.next()
    };
    let valset_upd_keys = vote_tallies::Keys::from(&next_epoch);
    let maybe_proof = 'check_storage: {
        let Some(seen) =
            votes::storage::maybe_read_seen(state, &valset_upd_keys)?
        else {
            break 'check_storage None;
        };
        if seen {
            tracing::debug!("Validator set update tally is already seen");
            return Ok(ChangedKeys::default());
        }
        let proof = votes::storage::read_body(state, &valset_upd_keys)?;
        Some(proof)
    };

    let mut seen_by = Votes::default();
    for address in ext.signatures.keys().cloned() {
        if let Some(present) = seen_by.insert(address, epoch_2nd_height) {
            // TODO(namada#770): this shouldn't be happening in any case and we
            // should be refactoring to get rid of `BlockHeight`
            tracing::warn!(?present, "Duplicate vote in digest");
        }
    }

    let (tally, proof, changed, confirmed, already_present) = if let Some(
        mut proof,
    ) = maybe_proof
    {
        tracing::debug!(
            %valset_upd_keys.prefix,
            "Validator set update votes already in storage",
        );
        let new_votes = NewVotes::new(seen_by, &voting_powers)?;
        let (tally, changed) = votes::update::calculate::<'db, _, _, Gov, _>(
            state,
            &valset_upd_keys,
            new_votes,
        )?;
        if changed.is_empty() {
            return Ok(changed);
        }
        let confirmed = tally.seen && changed.contains(&valset_upd_keys.seen());
        proof.attach_signature_batch(ext.signatures.into_iter().map(
            |(addr, sig)| {
                (
                    state
                        .ethbridge_queries()
                        .get_eth_addr_book::<Gov>(&addr, Some(signing_epoch))
                        .expect("All validators should have eth keys"),
                    sig,
                )
            },
        ));
        (tally, proof, changed, confirmed, true)
    } else {
        tracing::debug!(
            %valset_upd_keys.prefix,
            ?ext.voting_powers,
            "New validator set update vote aggregation started"
        );
        let tally =
            votes::calculate_new::<D, H, Gov>(state, seen_by, &voting_powers)?;
        let mut proof = EthereumProof::new(ext.voting_powers);
        proof.attach_signature_batch(ext.signatures.into_iter().map(
            |(addr, sig)| {
                (
                    state
                        .ethbridge_queries()
                        .get_eth_addr_book::<Gov>(&addr, Some(signing_epoch))
                        .expect("All validators should have eth keys"),
                    sig,
                )
            },
        ));
        let changed = valset_upd_keys.into_iter().collect();
        let confirmed = tally.seen;
        (tally, proof, changed, confirmed, false)
    };

    tracing::debug!(
        ?tally,
        ?proof,
        "Applying validator set update state changes"
    );
    votes::storage::write(
        state,
        &valset_upd_keys,
        &proof,
        &tally,
        already_present,
    )?;

    if confirmed {
        tracing::debug!(
            %valset_upd_keys.prefix,
            "Acquired complete proof on validator set update"
        );
    }

    Ok(changed)
}

#[cfg(test)]
mod test_valset_upd_state_changes {
    use namada_core::address;
    use namada_core::voting_power::FractionalVotingPower;
    use namada_proof_of_stake::queries::{
        get_total_voting_power, read_validator_stake,
    };
    use namada_state::StorageRead;
    use namada_vote_ext::validator_set_update::VotingPowersMap;

    use super::*;
    use crate::test_utils::{self, GovStore};

    /// Test that if a validator set update becomes "seen", then
    /// it should have a complete proof backing it up in storage.
    #[test]
    fn test_seen_has_complete_proof() {
        let (mut state, keys) = test_utils::setup_default_storage();

        let last_height = state.in_mem().get_last_block_height();
        let signing_epoch = state
            .get_epoch_at_height(last_height)
            .unwrap()
            .expect("The epoch of the last block height should be known");

        let tx_result = aggregate_votes::<_, _, GovStore<_>>(
            &mut state,
            validator_set_update::VextDigest::singleton(
                validator_set_update::Vext {
                    voting_powers: VotingPowersMap::new(),
                    validator_addr: address::testing::established_address_1(),
                    signing_epoch,
                }
                .sign(
                    &keys
                        .get(&address::testing::established_address_1())
                        .expect("Test failed")
                        .eth_bridge,
                ),
            ),
            signing_epoch,
        )
        .expect("Test failed");

        // let's make sure we updated storage
        assert!(!tx_result.changed_keys.is_empty());

        let valset_upd_keys = vote_tallies::Keys::from(&signing_epoch.next());

        assert!(tx_result.changed_keys.contains(&valset_upd_keys.body()));
        assert!(tx_result.changed_keys.contains(&valset_upd_keys.seen()));
        assert!(tx_result.changed_keys.contains(&valset_upd_keys.seen_by()));
        assert!(
            tx_result
                .changed_keys
                .contains(&valset_upd_keys.voting_power())
        );

        // check if the valset upd is marked as "seen"
        let tally = votes::storage::read(&state, &valset_upd_keys)
            .expect("Test failed");
        assert!(tally.seen);

        // read the proof in storage and make sure its signature is
        // from the configured validator
        let proof = votes::storage::read_body(&state, &valset_upd_keys)
            .expect("Test failed");
        assert_eq!(proof.data, VotingPowersMap::new());

        let mut proof_sigs: Vec<_> = proof.signatures.into_keys().collect();
        assert_eq!(proof_sigs.len(), 1);

        let addr_book = proof_sigs.pop().expect("Test failed");
        assert_eq!(
            addr_book,
            state
                .ethbridge_queries()
                .get_eth_addr_book::<GovStore<_>>(
                    &address::testing::established_address_1(),
                    Some(signing_epoch)
                )
                .expect("Test failed")
        );

        // since only one validator is configured, we should
        // have reached a complete proof
        let total_voting_power =
            get_total_voting_power::<_, GovStore<_>>(&state, signing_epoch);
        let validator_voting_power = read_validator_stake::<_, GovStore<_>>(
            &state,
            &address::testing::established_address_1(),
            signing_epoch,
        )
        .expect("Test failed");
        let voting_power = FractionalVotingPower::new(
            validator_voting_power.into(),
            total_voting_power.into(),
        )
        .expect("Test failed");

        assert!(voting_power > FractionalVotingPower::TWO_THIRDS);
    }

    /// Test that if a validator set update is not "seen" yet, then
    /// it should never have a complete proof backing it up in storage.
    #[test]
    fn test_not_seen_has_incomplete_proof() {
        let (mut state, keys) =
            test_utils::setup_storage_with_validators(HashMap::from_iter([
                // the first validator has exactly 2/3 of the total stake
                (
                    address::testing::established_address_1(),
                    Amount::native_whole(50_000),
                ),
                (
                    address::testing::established_address_2(),
                    Amount::native_whole(25_000),
                ),
            ]));

        let last_height = state.in_mem().get_last_block_height();
        let signing_epoch = state
            .get_epoch_at_height(last_height)
            .unwrap()
            .expect("The epoch of the last block height should be known");

        let tx_result = aggregate_votes::<_, _, GovStore<_>>(
            &mut state,
            validator_set_update::VextDigest::singleton(
                validator_set_update::Vext {
                    voting_powers: VotingPowersMap::new(),
                    validator_addr: address::testing::established_address_1(),
                    signing_epoch,
                }
                .sign(
                    &keys
                        .get(&address::testing::established_address_1())
                        .expect("Test failed")
                        .eth_bridge,
                ),
            ),
            signing_epoch,
        )
        .expect("Test failed");

        // let's make sure we updated storage
        assert!(!tx_result.changed_keys.is_empty());

        let valset_upd_keys = vote_tallies::Keys::from(&signing_epoch.next());

        assert!(tx_result.changed_keys.contains(&valset_upd_keys.body()));
        assert!(tx_result.changed_keys.contains(&valset_upd_keys.seen()));
        assert!(tx_result.changed_keys.contains(&valset_upd_keys.seen_by()));
        assert!(
            tx_result
                .changed_keys
                .contains(&valset_upd_keys.voting_power())
        );

        // assert the validator set update is not "seen" yet
        let tally = votes::storage::read(&state, &valset_upd_keys)
            .expect("Test failed");
        assert!(!tally.seen);

        // read the proof in storage and make sure its signature is
        // from the configured validator
        let proof = votes::storage::read_body(&state, &valset_upd_keys)
            .expect("Test failed");
        assert_eq!(proof.data, VotingPowersMap::new());

        let mut proof_sigs: Vec<_> = proof.signatures.into_keys().collect();
        assert_eq!(proof_sigs.len(), 1);

        let addr_book = proof_sigs.pop().expect("Test failed");
        assert_eq!(
            addr_book,
            state
                .ethbridge_queries()
                .get_eth_addr_book::<GovStore<_>>(
                    &address::testing::established_address_1(),
                    Some(signing_epoch)
                )
                .expect("Test failed")
        );

        // make sure we do not have a complete proof yet
        let total_voting_power =
            get_total_voting_power::<_, GovStore<_>>(&state, signing_epoch);
        let validator_voting_power = read_validator_stake::<_, GovStore<_>>(
            &state,
            &address::testing::established_address_1(),
            signing_epoch,
        )
        .expect("Test failed");
        let voting_power = FractionalVotingPower::new(
            validator_voting_power.into(),
            total_voting_power.into(),
        )
        .expect("Test failed");

        assert!(voting_power <= FractionalVotingPower::TWO_THIRDS);
    }
}
