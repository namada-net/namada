//! Code for handling Ethereum events protocol txs.

mod eth_msgs;
mod events;

use std::collections::BTreeSet;

use borsh::BorshDeserialize;
use eth_msgs::EthMsgUpdate;
use eyre::Result;
use namada_core::address::Address;
use namada_core::chain::{BlockHeight, Epoch};
use namada_core::collections::{HashMap, HashSet};
use namada_core::ethereum_events::EthereumEvent;
use namada_core::key::common;
use namada_core::storage::Key;
use namada_core::token::Amount;
use namada_proof_of_stake::storage::read_owned_pos_params;
use namada_state::tx_queue::ExpiredTx;
use namada_state::{DBIter, DBRead, StorageHasher, WlState};
use namada_systems::governance;
use namada_tx::data::BatchedTxResult;
use namada_vote_ext::ethereum_events::{MultiSignedEthEvent, SignedVext, Vext};

use super::ChangedKeys;
use crate::event::EthBridgeEvent;
use crate::protocol::transactions::utils;
use crate::protocol::transactions::votes::update::NewVotes;
use crate::protocol::transactions::votes::{self, calculate_new};
use crate::storage::eth_bridge_queries::EthBridgeQueries;
use crate::storage::vote_tallies::{self, Keys};

impl utils::GetVoters for &HashSet<EthMsgUpdate> {
    #[inline]
    fn get_voters(self) -> HashSet<(Address, BlockHeight)> {
        self.iter().fold(HashSet::new(), |mut voters, update| {
            voters.extend(update.seen_by.clone());
            voters
        })
    }
}

/// Sign the given Ethereum events, and return the associated
/// vote extension protocol transaction.
///
/// __INVARIANT__: Assume `ethereum_events` are sorted in ascending
/// order.
pub fn sign_ethereum_events<D, H>(
    state: &WlState<'_, D, H>,
    validator_addr: &Address,
    protocol_key: &common::SecretKey,
    ethereum_events: Vec<EthereumEvent>,
) -> Option<SignedVext>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if !state.ethbridge_queries().is_bridge_active() {
        return None;
    }

    let ext = Vext {
        block_height: state.in_mem().get_last_block_height(),
        validator_addr: validator_addr.clone(),
        ethereum_events,
    };
    if !ext.ethereum_events.is_empty() {
        tracing::info!(
            new_ethereum_events.len = ext.ethereum_events.len(),
            ?ext.block_height,
            "Voting for new Ethereum events"
        );
        tracing::debug!("New Ethereum events - {:#?}", ext.ethereum_events);
    }

    Some(ext.sign(protocol_key).into())
}

/// Applies derived state changes to storage, based on Ethereum `events` which
/// were newly seen by some consensus validator(s).
///
/// For `events` which have been seen by enough voting power (`>= 2/3`), extra
/// state changes may take place, such as minting of wrapped ERC20s.
///
/// This function is deterministic based on some existing blockchain state and
/// the passed `events`.
pub fn apply_derived_tx<'db, D, H, Gov>(
    state: &mut WlState<'db, D, H>,
    events: Vec<MultiSignedEthEvent>,
) -> Result<BatchedTxResult>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<'db, D, H>>,
{
    let mut changed_keys = timeout_events::<D, H, Gov>(state)?;
    if events.is_empty() {
        return Ok(BatchedTxResult {
            changed_keys,
            ..Default::default()
        });
    }
    tracing::info!(
        ethereum_events = events.len(),
        "Applying state updates derived from Ethereum events found in \
         protocol transaction"
    );

    let updates = events
        .into_iter()
        .filter_map(|multisigned| {
            // NB: discard events with outdated nonces
            state
                .ethbridge_queries()
                .validate_eth_event_nonce(&multisigned.event)
                .then(|| EthMsgUpdate::from(multisigned))
        })
        .collect();

    let voting_powers = utils::get_voting_powers(state, &updates)?;

    let (mut apply_updates_keys, eth_bridge_events) =
        apply_updates::<D, H, Gov>(state, updates, voting_powers)?;
    changed_keys.append(&mut apply_updates_keys);

    Ok(BatchedTxResult {
        changed_keys,
        events: eth_bridge_events
            .into_iter()
            .map(|event| event.into())
            .collect(),
        ..Default::default()
    })
}

/// Apply votes to Ethereum events in storage and act on any events which are
/// confirmed.
///
/// The `voting_powers` map must contain a voting power for all
/// `(Address, BlockHeight)`s that occur in any of the `updates`.
pub(super) fn apply_updates<'db, D, H, Gov>(
    state: &mut WlState<'db, D, H>,
    updates: HashSet<EthMsgUpdate>,
    voting_powers: HashMap<(Address, BlockHeight), Amount>,
) -> Result<(ChangedKeys, BTreeSet<EthBridgeEvent>)>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<'db, D, H>>,
{
    tracing::debug!(
        updates.len = updates.len(),
        ?voting_powers,
        "Applying Ethereum state update transaction"
    );

    let mut changed_keys = BTreeSet::default();
    let mut tx_events = BTreeSet::default();
    let mut confirmed = vec![];
    for update in updates {
        // The order in which updates are applied to storage does not matter.
        // The final storage state will be the same regardless.
        let (mut changed, newly_confirmed) =
            apply_update::<D, H, Gov>(state, update.clone(), &voting_powers)?;
        changed_keys.append(&mut changed);
        if newly_confirmed {
            confirmed.push(update.body);
        }
    }
    if confirmed.is_empty() {
        tracing::debug!("No events were newly confirmed");
        return Ok((changed_keys, tx_events));
    }
    tracing::debug!(n = confirmed.len(), "Events were newly confirmed",);

    // Right now, the order in which events are acted on does not matter.
    // For `TransfersToNamada` events, they can happen in any order.
    for event in confirmed {
        let (mut changed, mut new_tx_events) = events::act_on(state, event)?;
        changed_keys.append(&mut changed);
        tx_events.append(&mut new_tx_events);
    }
    Ok((changed_keys, tx_events))
}

/// Apply an [`EthMsgUpdate`] to storage. Returns any keys changed and whether
/// the event was newly seen.
///
/// The `voting_powers` map must contain a voting power for all
/// `(Address, BlockHeight)`s that occur in `update`.
fn apply_update<'db, D, H, Gov>(
    state: &mut WlState<'db, D, H>,
    update: EthMsgUpdate,
    voting_powers: &HashMap<(Address, BlockHeight), Amount>,
) -> Result<(ChangedKeys, bool)>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<'db, D, H>>,
{
    let eth_msg_keys = vote_tallies::Keys::from(&update.body);
    let exists_in_storage = if let Some(seen) =
        votes::storage::maybe_read_seen(state, &eth_msg_keys)?
    {
        if seen {
            tracing::debug!(?update, "Ethereum event is already seen");
            return Ok((ChangedKeys::default(), false));
        }
        true
    } else {
        false
    };

    let (vote_tracking, changed, confirmed, already_present) =
        if !exists_in_storage {
            tracing::debug!(%eth_msg_keys.prefix, "Ethereum event not seen before by any validator");
            let vote_tracking = calculate_new::<D, H, Gov>(
                state,
                update.seen_by,
                voting_powers,
            )?;
            let changed = eth_msg_keys.into_iter().collect();
            let confirmed = vote_tracking.seen;
            (vote_tracking, changed, confirmed, false)
        } else {
            tracing::debug!(
                %eth_msg_keys.prefix,
                "Ethereum event already exists in storage",
            );
            let new_votes =
                NewVotes::new(update.seen_by.clone(), voting_powers)?;
            let (vote_tracking, changed) =
                votes::update::calculate::<D, H, Gov, _>(
                    state,
                    &eth_msg_keys,
                    new_votes,
                )?;
            if changed.is_empty() {
                return Ok((changed, false));
            }
            let confirmed =
                vote_tracking.seen && changed.contains(&eth_msg_keys.seen());
            (vote_tracking, changed, confirmed, true)
        };

    votes::storage::write(
        state,
        &eth_msg_keys,
        &update.body,
        &vote_tracking,
        already_present,
    )?;

    Ok((changed, confirmed))
}

fn timeout_events<'db, D, H, Gov>(
    state: &mut WlState<'db, D, H>,
) -> Result<ChangedKeys>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<'db, D, H>>,
{
    let mut changed = ChangedKeys::new();
    for keys in get_timed_out_eth_events(state)? {
        tracing::debug!(
            %keys.prefix,
            "Ethereum event timed out",
        );
        if let Some(event) =
            votes::storage::delete::<D, H, Gov, _>(state, &keys)?
        {
            tracing::debug!(
                %keys.prefix,
                "Queueing Ethereum event for retransmission",
            );
            // NOTE: if we error out in the `ethereum_bridge` crate,
            // currently there is no way to reset the expired txs queue
            // to its previous state. this shouldn't be a big deal, as
            // replaying ethereum events has no effect on the ledger.
            // however, we may need to revisit this code if we ever
            // implement slashing on double voting of ethereum events.
            state
                .in_mem_mut()
                .expired_txs_queue
                .push(ExpiredTx::EthereumEvent(event));
        }
        changed.extend(keys.clone().into_iter());
    }

    Ok(changed)
}

fn get_timed_out_eth_events<D, H>(
    state: &mut WlState<'_, D, H>,
) -> Result<Vec<Keys<EthereumEvent>>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let unbonding_len = read_owned_pos_params(state)?.unbonding_len;
    let current_epoch = state.in_mem().last_epoch;
    if current_epoch.0 <= unbonding_len {
        return Ok(Vec::new());
    }

    let timeout_epoch = Epoch(
        current_epoch
            .0
            .checked_sub(unbonding_len)
            .expect("Cannot underflow - checked above"),
    );
    let prefix = vote_tallies::eth_msgs_prefix();
    let mut cur_keys: Option<Keys<EthereumEvent>> = None;
    let mut is_timed_out = false;
    let mut is_seen = false;
    let mut results = Vec::new();
    for (key, val, _) in votes::storage::iter_prefix(state, &prefix)? {
        let key = Key::parse(key).expect("The key should be parsable");
        if let Some(keys) = vote_tallies::eth_event_keys(&key) {
            match &cur_keys {
                Some(prev_keys) => {
                    if *prev_keys != keys {
                        // check the previous keys since we found new keys
                        if is_timed_out && !is_seen {
                            results.push(prev_keys.clone());
                        }
                        is_timed_out = false;
                        is_seen = false;
                        cur_keys = Some(keys);
                    }
                }
                None => cur_keys = Some(keys),
            }

            if vote_tallies::is_epoch_key(&key) {
                let inserted_epoch = Epoch::try_from_slice(&val[..])
                    .expect("Decoding Epoch failed");
                if inserted_epoch <= timeout_epoch {
                    is_timed_out = true;
                }
            }

            if vote_tallies::is_seen_key(&key) {
                is_seen = bool::try_from_slice(&val[..])
                    .expect("Decoding boolean failed");
            }
        }
    }
    // check the last one
    if let Some(cur_keys) = cur_keys {
        if is_timed_out && !is_seen {
            results.push(cur_keys);
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use namada_core::address;
    use namada_core::ethereum_events::TransferToNamada;
    use namada_core::ethereum_events::testing::{
        DAI_ERC20_ETH_ADDRESS, arbitrary_amount, arbitrary_eth_address,
        arbitrary_nonce, arbitrary_single_transfer,
    };
    use namada_core::voting_power::FractionalVotingPower;
    use namada_state::testing::TestState;
    use namada_storage::StorageRead;

    use super::*;
    use crate::protocol::transactions::utils::GetVoters;
    use crate::protocol::transactions::votes::{
        EpochedVotingPower, EpochedVotingPowerExt, Votes,
    };
    use crate::storage::wrapped_erc20s;
    use crate::test_utils::{self, GovStore};
    use crate::token::storage_key::{balance_key, minted_balance_key};

    /// All kinds of [`Keys`].
    enum KeyKind {
        Body,
        Seen,
        SeenBy,
        VotingPower,
        Epoch,
    }

    #[test]
    /// Test applying a `TransfersToNamada` batch containing a single transfer
    fn test_apply_single_transfer() -> Result<()> {
        let (sole_validator, validator_stake) = test_utils::default_validator();
        let receiver = address::testing::established_address_2();

        let amount = arbitrary_amount();
        let asset = arbitrary_eth_address();
        let body = EthereumEvent::TransfersToNamada {
            nonce: arbitrary_nonce(),
            transfers: vec![TransferToNamada {
                amount,
                asset,
                receiver: receiver.clone(),
            }],
        };
        let update = EthMsgUpdate {
            body: body.clone(),
            seen_by: Votes::from([(sole_validator.clone(), BlockHeight(100))]),
        };
        let updates = HashSet::from_iter(vec![update]);
        let voting_powers = HashMap::from_iter(vec![(
            (sole_validator.clone(), BlockHeight(100)),
            validator_stake,
        )]);
        let (mut state, _) = test_utils::setup_default_storage();
        test_utils::whitelist_tokens(
            &mut state,
            [(
                DAI_ERC20_ETH_ADDRESS,
                test_utils::WhitelistMeta {
                    cap: Amount::max(),
                    denom: 18,
                },
            )],
        );

        let (changed_keys, _) = apply_updates::<_, _, GovStore<_>>(
            &mut state,
            updates,
            voting_powers,
        )?;

        let eth_msg_keys: vote_tallies::Keys<EthereumEvent> = (&body).into();
        let wrapped_erc20_token = wrapped_erc20s::token(&asset);
        assert_eq!(
            BTreeSet::from_iter(vec![
                eth_msg_keys.body(),
                eth_msg_keys.seen(),
                eth_msg_keys.seen_by(),
                eth_msg_keys.voting_power(),
                eth_msg_keys.voting_started_epoch(),
                balance_key(&wrapped_erc20_token, &receiver),
                minted_balance_key(&wrapped_erc20_token),
            ]),
            changed_keys
        );

        let stored_body: EthereumEvent =
            state.read(&eth_msg_keys.body())?.expect("Test failed");
        assert_eq!(stored_body, body);

        let seen: bool =
            state.read(&eth_msg_keys.seen())?.expect("Test failed");
        assert!(seen);

        let seen_by: Votes =
            state.read(&eth_msg_keys.seen_by())?.expect("Test failed");
        assert_eq!(seen_by, Votes::from([(sole_validator, BlockHeight(100))]));

        let voting_power = state
            .read::<EpochedVotingPower>(&eth_msg_keys.voting_power())?
            .expect("Test failed")
            .fractional_stake::<_, _, GovStore<_>>(&state);
        assert_eq!(voting_power, FractionalVotingPower::WHOLE);

        let epoch: Epoch = state
            .read(&eth_msg_keys.voting_started_epoch())?
            .expect("Test failed");
        assert_eq!(epoch, Epoch(0));

        let wrapped_erc20_balance: Amount = state
            .read(&balance_key(&wrapped_erc20_token, &receiver))?
            .expect("Test failed");
        assert_eq!(wrapped_erc20_balance, amount);

        let wrapped_erc20_supply: Amount = state
            .read(&minted_balance_key(&wrapped_erc20_token))?
            .expect("Test failed");
        assert_eq!(wrapped_erc20_supply, amount);

        Ok(())
    }

    #[test]
    /// Test applying a single transfer via `apply_derived_tx`, where an event
    /// has enough voting power behind it for it to be applied at the same time
    /// that it is recorded in storage
    fn test_apply_derived_tx_new_event_mint_immediately() {
        let sole_validator = address::testing::established_address_2();
        let (mut state, _) =
            test_utils::setup_storage_with_validators(HashMap::from_iter(
                vec![(sole_validator.clone(), Amount::native_whole(100))],
            ));
        test_utils::whitelist_tokens(
            &mut state,
            [(
                DAI_ERC20_ETH_ADDRESS,
                test_utils::WhitelistMeta {
                    cap: Amount::max(),
                    denom: 18,
                },
            )],
        );
        let receiver = address::testing::established_address_1();

        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![TransferToNamada {
                amount: Amount::from(100),
                asset: DAI_ERC20_ETH_ADDRESS,
                receiver: receiver.clone(),
            }],
        };

        let result = apply_derived_tx::<_, _, GovStore<_>>(
            &mut state,
            vec![MultiSignedEthEvent {
                event: event.clone(),
                signers: BTreeSet::from([(sole_validator, BlockHeight(100))]),
            }],
        );

        let tx_result = match result {
            Ok(tx_result) => tx_result,
            Err(err) => panic!("unexpected error: {:#?}", err),
        };

        let eth_msg_keys = vote_tallies::Keys::from(&event);
        let dai_token = wrapped_erc20s::token(&DAI_ERC20_ETH_ADDRESS);
        assert_eq!(
            tx_result.changed_keys,
            BTreeSet::from_iter(vec![
                eth_msg_keys.body(),
                eth_msg_keys.seen(),
                eth_msg_keys.seen_by(),
                eth_msg_keys.voting_power(),
                eth_msg_keys.voting_started_epoch(),
                balance_key(&dai_token, &receiver),
                minted_balance_key(&dai_token),
            ])
        );
        assert!(tx_result.vps_result.accepted_vps.is_empty());
        assert!(tx_result.vps_result.rejected_vps.is_empty());
        assert!(tx_result.vps_result.errors.is_empty());
        assert!(tx_result.initialized_accounts.is_empty());
    }

    /// Test calling apply_derived_tx for an event that isn't backed by enough
    /// voting power to be acted on immediately
    #[test]
    fn test_apply_derived_tx_new_event_dont_mint() {
        let validator_a = address::testing::established_address_2();
        let validator_b = address::testing::established_address_3();
        let (mut state, _) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), Amount::native_whole(100)),
                (validator_b, Amount::native_whole(100)),
            ]),
        );
        let receiver = address::testing::established_address_1();

        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![TransferToNamada {
                amount: Amount::from(100),
                asset: DAI_ERC20_ETH_ADDRESS,
                receiver,
            }],
        };

        let result = apply_derived_tx::<_, _, GovStore<_>>(
            &mut state,
            vec![MultiSignedEthEvent {
                event: event.clone(),
                signers: BTreeSet::from([(validator_a, BlockHeight(100))]),
            }],
        );
        let tx_result = match result {
            Ok(tx_result) => tx_result,
            Err(err) => panic!("unexpected error: {:#?}", err),
        };

        let eth_msg_keys = vote_tallies::Keys::from(&event);
        assert_eq!(
            tx_result.changed_keys,
            BTreeSet::from_iter(vec![
                eth_msg_keys.body(),
                eth_msg_keys.seen(),
                eth_msg_keys.seen_by(),
                eth_msg_keys.voting_power(),
                eth_msg_keys.voting_started_epoch(),
            ]),
            "The Ethereum event should have been recorded, but no minting \
             should have happened yet as it has only been seen by 1/2 the \
             voting power so far"
        );
    }

    #[test]
    /// Test that attempts made to apply duplicate
    /// [`MultiSignedEthEvent`]s in a single [`apply_derived_tx`] call don't
    /// result in duplicate votes in storage.
    pub fn test_apply_derived_tx_duplicates() -> Result<()> {
        let validator_a = address::testing::established_address_2();
        let validator_b = address::testing::established_address_3();
        let (mut state, _) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), Amount::native_whole(100)),
                (validator_b, Amount::native_whole(100)),
            ]),
        );

        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![TransferToNamada {
                amount: Amount::from(100),
                asset: DAI_ERC20_ETH_ADDRESS,
                receiver: address::testing::established_address_1(),
            }],
        };
        // two votes for the same event from validator A
        let signers = BTreeSet::from([(validator_a.clone(), BlockHeight(100))]);
        let multisigned = MultiSignedEthEvent {
            event: event.clone(),
            signers,
        };

        let multisigneds = vec![multisigned.clone(), multisigned];

        let result =
            apply_derived_tx::<_, _, GovStore<_>>(&mut state, multisigneds);
        let tx_result = match result {
            Ok(tx_result) => tx_result,
            Err(err) => panic!("unexpected error: {:#?}", err),
        };

        let eth_msg_keys = vote_tallies::Keys::from(&event);
        assert_eq!(
            tx_result.changed_keys,
            BTreeSet::from_iter(vec![
                eth_msg_keys.body(),
                eth_msg_keys.seen(),
                eth_msg_keys.seen_by(),
                eth_msg_keys.voting_power(),
                eth_msg_keys.voting_started_epoch(),
            ]),
            "One vote for the Ethereum event should have been recorded",
        );

        let seen_by: Votes =
            state.read(&eth_msg_keys.seen_by())?.expect("Test failed");
        assert_eq!(seen_by, Votes::from([(validator_a, BlockHeight(100))]));

        let voting_power = state
            .read::<EpochedVotingPower>(&eth_msg_keys.voting_power())?
            .expect("Test failed")
            .fractional_stake::<_, _, GovStore<_>>(&state);
        assert_eq!(voting_power, FractionalVotingPower::HALF);

        Ok(())
    }

    #[test]
    /// Assert we don't return anything if we try to get the votes for an empty
    /// set of updates
    pub fn test_get_votes_for_updates_empty() {
        let updates = HashSet::new();
        assert!(updates.get_voters().is_empty());
    }

    #[test]
    /// Test that we correctly get the votes from a set of updates
    pub fn test_get_votes_for_events() {
        let updates = HashSet::from([
            EthMsgUpdate {
                body: arbitrary_single_transfer(
                    1.into(),
                    address::testing::established_address_1(),
                ),
                seen_by: Votes::from([
                    (
                        address::testing::established_address_1(),
                        BlockHeight(100),
                    ),
                    (
                        address::testing::established_address_2(),
                        BlockHeight(102),
                    ),
                ]),
            },
            EthMsgUpdate {
                body: arbitrary_single_transfer(
                    2.into(),
                    address::testing::established_address_2(),
                ),
                seen_by: Votes::from([
                    (
                        address::testing::established_address_1(),
                        BlockHeight(101),
                    ),
                    (
                        address::testing::established_address_3(),
                        BlockHeight(100),
                    ),
                ]),
            },
        ]);
        let voters = updates.get_voters();
        assert_eq!(
            voters,
            HashSet::from([
                (address::testing::established_address_1(), BlockHeight(100)),
                (address::testing::established_address_1(), BlockHeight(101)),
                (address::testing::established_address_2(), BlockHeight(102)),
                (address::testing::established_address_3(), BlockHeight(100))
            ])
        )
    }

    #[test]
    /// Test that timed out events are deleted
    pub fn test_timeout_events() {
        let validator_a = address::testing::established_address_2();
        let validator_b = address::testing::established_address_3();
        let (mut state, _) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), Amount::native_whole(100)),
                (validator_b, Amount::native_whole(100)),
            ]),
        );
        let receiver = address::testing::established_address_1();

        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![TransferToNamada {
                amount: Amount::from(100),
                asset: DAI_ERC20_ETH_ADDRESS,
                receiver: receiver.clone(),
            }],
        };
        let _result = apply_derived_tx::<_, _, GovStore<_>>(
            &mut state,
            vec![MultiSignedEthEvent {
                event: event.clone(),
                signers: BTreeSet::from([(
                    validator_a.clone(),
                    BlockHeight(100),
                )]),
            }],
        );
        let prev_keys = vote_tallies::Keys::from(&event);

        // commit then update the epoch
        state.commit_block().unwrap();
        let unbonding_len = namada_proof_of_stake::storage::read_pos_params::<
            _,
            GovStore<_>,
        >(&state)
        .expect("Test failed")
        .unbonding_len
            + 1;
        state.in_mem_mut().last_epoch =
            state.in_mem().last_epoch + unbonding_len;
        state.in_mem_mut().block.epoch = state.in_mem().last_epoch + 1_u64;

        let new_event = EthereumEvent::TransfersToNamada {
            nonce: 1.into(),
            transfers: vec![TransferToNamada {
                amount: Amount::from(100),
                asset: DAI_ERC20_ETH_ADDRESS,
                receiver,
            }],
        };
        let result = apply_derived_tx::<_, _, GovStore<_>>(
            &mut state,
            vec![MultiSignedEthEvent {
                event: new_event.clone(),
                signers: BTreeSet::from([(validator_a, BlockHeight(100))]),
            }],
        );
        let tx_result = match result {
            Ok(tx_result) => tx_result,
            Err(err) => panic!("unexpected error: {:#?}", err),
        };

        let new_keys = vote_tallies::Keys::from(&new_event);
        assert_eq!(
            tx_result.changed_keys,
            BTreeSet::from_iter(vec![
                prev_keys.body(),
                prev_keys.seen(),
                prev_keys.seen_by(),
                prev_keys.voting_power(),
                prev_keys.voting_started_epoch(),
                new_keys.body(),
                new_keys.seen(),
                new_keys.seen_by(),
                new_keys.voting_power(),
                new_keys.voting_started_epoch(),
            ]),
            "New event should be inserted and the previous one should be \
             deleted",
        );
        assert!(
            state
                .read::<EthereumEvent>(&prev_keys.body())
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .read::<EthereumEvent>(&new_keys.body())
                .unwrap()
                .is_some()
        );
    }

    /// Helper fn to [`test_timeout_events_before_state_upds`].
    fn check_event_keys<T, F>(
        keys: &Keys<T>,
        state: &TestState,
        result: Result<BatchedTxResult>,
        mut assert: F,
    ) where
        F: FnMut(KeyKind, Option<Vec<u8>>),
    {
        let tx_result = match result {
            Ok(tx_result) => tx_result,
            Err(err) => panic!("unexpected error: {:#?}", err),
        };
        assert(KeyKind::Body, state.read_bytes(&keys.body()).unwrap());
        assert(KeyKind::Seen, state.read_bytes(&keys.seen()).unwrap());
        assert(KeyKind::SeenBy, state.read_bytes(&keys.seen_by()).unwrap());
        assert(
            KeyKind::VotingPower,
            state.read_bytes(&keys.voting_power()).unwrap(),
        );
        assert(
            KeyKind::Epoch,
            state.read_bytes(&keys.voting_started_epoch()).unwrap(),
        );
        assert_eq!(
            tx_result.changed_keys,
            BTreeSet::from_iter([
                keys.body(),
                keys.seen(),
                keys.seen_by(),
                keys.voting_power(),
                keys.voting_started_epoch(),
            ]),
        );
    }

    /// Test that we time out events before we do any state update
    /// on them. This should prevent double voting from rebonded
    /// validators.
    #[test]
    fn test_timeout_events_before_state_upds() {
        let validator_a = address::testing::established_address_2();
        let validator_b = address::testing::established_address_3();
        let (mut state, _) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), Amount::native_whole(100)),
                (validator_b.clone(), Amount::native_whole(100)),
            ]),
        );

        let receiver = address::testing::established_address_1();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![TransferToNamada {
                amount: Amount::from(100),
                asset: DAI_ERC20_ETH_ADDRESS,
                receiver,
            }],
        };
        let keys = vote_tallies::Keys::from(&event);

        let result = apply_derived_tx::<_, _, GovStore<_>>(
            &mut state,
            vec![MultiSignedEthEvent {
                event: event.clone(),
                signers: BTreeSet::from([(validator_a, BlockHeight(100))]),
            }],
        );
        check_event_keys(&keys, &state, result, |key_kind, value| {
            match (key_kind, value) {
                (_, None) => panic!("Test failed"),
                (KeyKind::VotingPower, Some(power)) => {
                    let power = EpochedVotingPower::try_from_slice(&power)
                        .expect("Test failed")
                        .fractional_stake::<_, _, GovStore<_>>(&state);
                    assert_eq!(power, FractionalVotingPower::HALF);
                }
                (_, Some(_)) => {}
            }
        });

        // commit then update the epoch
        state.commit_block().unwrap();
        let unbonding_len = namada_proof_of_stake::storage::read_pos_params::<
            _,
            GovStore<_>,
        >(&state)
        .expect("Test failed")
        .unbonding_len
            + 1;
        state.in_mem_mut().last_epoch =
            state.in_mem().last_epoch + unbonding_len;
        state.in_mem_mut().block.epoch = state.in_mem().last_epoch + 1_u64;

        let result = apply_derived_tx::<_, _, GovStore<_>>(
            &mut state,
            vec![MultiSignedEthEvent {
                event,
                signers: BTreeSet::from([(validator_b, BlockHeight(100))]),
            }],
        );
        check_event_keys(&keys, &state, result, |key_kind, value| {
            match (key_kind, value) {
                (_, None) => panic!("Test failed"),
                (KeyKind::VotingPower, Some(power)) => {
                    let power = EpochedVotingPower::try_from_slice(&power)
                        .expect("Test failed")
                        .fractional_stake::<_, _, GovStore<_>>(&state);
                    assert_eq!(power, FractionalVotingPower::HALF);
                }
                (_, Some(_)) => {}
            }
        });
    }

    /// Test that [`MultiSignedEthEvent`]s with outdated nonces do
    /// not result in votes in storage.
    #[test]
    fn test_apply_derived_tx_outdated_nonce() -> Result<()> {
        let (mut state, _) = test_utils::setup_default_storage();

        let new_multisigned = |nonce: u64| {
            let (validator, _) = test_utils::default_validator();
            let event = EthereumEvent::TransfersToNamada {
                nonce: nonce.into(),
                transfers: vec![TransferToNamada {
                    amount: Amount::from(100),
                    asset: DAI_ERC20_ETH_ADDRESS,
                    receiver: validator.clone(),
                }],
            };
            let signers = BTreeSet::from([(validator, BlockHeight(100))]);
            (
                MultiSignedEthEvent {
                    event: event.clone(),
                    signers,
                },
                event,
            )
        };
        macro_rules! nonce_ok {
            ($nonce:expr) => {
                let (multisigned, event) = new_multisigned($nonce);
                let tx_result = apply_derived_tx::<_, _, GovStore<_>>(
                    &mut state,
                    vec![multisigned],
                )?;

                let eth_msg_keys = vote_tallies::Keys::from(&event);
                assert!(
                    tx_result.changed_keys.contains(&eth_msg_keys.seen()),
                    "The Ethereum event should have been seen",
                );
                assert_eq!(
                    state.ethbridge_queries().get_next_nam_transfers_nonce(),
                    ($nonce + 1).into(),
                    "The transfers to Namada nonce should have been \
                     incremented",
                );
            };
        }
        macro_rules! nonce_err {
            ($nonce:expr) => {
                let (multisigned, event) = new_multisigned($nonce);
                let tx_result = apply_derived_tx::<_, _, GovStore<_>>(
                    &mut state,
                    vec![multisigned],
                )?;

                let eth_msg_keys = vote_tallies::Keys::from(&event);
                assert!(
                    !tx_result.changed_keys.contains(&eth_msg_keys.seen()),
                    "The Ethereum event should have been ignored",
                );
                assert_eq!(
                    state.ethbridge_queries().get_next_nam_transfers_nonce(),
                    NEXT_NONCE_TO_PROCESS.into(),
                    "The transfers to Namada nonce should not have changed",
                );
            };
        }

        // update storage with valid events
        const NEXT_NONCE_TO_PROCESS: u64 = 3;
        for nonce in 0..NEXT_NONCE_TO_PROCESS {
            nonce_ok!(nonce);
        }

        // attempts to replay events with older nonces should
        // result in the events getting ignored
        for nonce in 0..NEXT_NONCE_TO_PROCESS {
            nonce_err!(nonce);
        }

        // process new valid event
        nonce_ok!(NEXT_NONCE_TO_PROCESS);

        Ok(())
    }
}
