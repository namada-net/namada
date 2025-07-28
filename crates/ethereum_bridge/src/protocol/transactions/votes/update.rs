use std::collections::BTreeSet;

use borsh::BorshDeserialize;
use eyre::{Result, eyre};
use namada_core::address::Address;
use namada_core::chain::BlockHeight;
use namada_core::collections::{HashMap, HashSet};
use namada_core::token;
use namada_state::{DBIter, DBRead, StorageHasher, StorageRead, WlState};
use namada_systems::governance;

use super::{ChangedKeys, EpochedVotingPowerExt, Tally, Votes};
use crate::storage::vote_tallies;

/// Wraps all the information about new votes to be applied to some existing
/// tally in storage.
pub(in super::super) struct NewVotes {
    inner: HashMap<Address, (BlockHeight, token::Amount)>,
}

impl NewVotes {
    /// Constructs a new [`NewVotes`].
    ///
    /// For all `votes` provided, a corresponding [`token::Amount`] must
    /// be provided in `voting_powers` also, otherwise an error will be
    /// returned.
    pub fn new(
        votes: Votes,
        voting_powers: &HashMap<(Address, BlockHeight), token::Amount>,
    ) -> Result<Self> {
        let mut inner = HashMap::default();
        for vote in votes {
            let voting_power = match voting_powers.get(&vote) {
                Some(voting_power) => voting_power,
                None => {
                    let (address, block_height) = vote;
                    return Err(eyre!(
                        "No voting power provided for vote by validator \
                         {address} at block height {block_height}"
                    ));
                }
            };
            let (address, block_height) = vote;
            _ = inner.insert(address, (block_height, voting_power.to_owned()));
        }
        Ok(Self { inner })
    }

    pub fn voters(&self) -> BTreeSet<Address> {
        self.inner.keys().cloned().collect()
    }

    /// Consumes `self` and returns a [`NewVotes`] with any addresses from
    /// `voters` removed, as well as the set of addresses that were actually
    /// removed. Useful for removing voters who have already voted for
    /// something.
    pub fn without_voters<'a>(
        self,
        voters: impl IntoIterator<Item = &'a Address>,
    ) -> (Self, HashSet<&'a Address>) {
        let mut inner = self.inner;
        let mut removed = HashSet::default();
        for voter in voters {
            if inner.swap_remove(voter).is_some() {
                removed.insert(voter);
            }
        }
        (Self { inner }, removed)
    }
}

impl IntoIterator for NewVotes {
    type IntoIter = namada_core::collections::hash_set::IntoIter<Self::Item>;
    type Item = (Address, BlockHeight, token::Amount);

    fn into_iter(self) -> Self::IntoIter {
        let items: HashSet<_> = self
            .inner
            .into_iter()
            .map(|(address, (block_height, stake))| {
                (address, block_height, stake)
            })
            .collect();
        items.into_iter()
    }
}

/// Calculate an updated [`Tally`] based on one that is in storage under `keys`,
/// with new votes from `vote_info` applied, as well as the storage keys that
/// would change. If [`Tally`] is already `seen = true` in storage, then no
/// votes from `vote_info` should be applied, and the returned changed keys will
/// be empty.
pub(in super::super) fn calculate<'db, D, H, Gov, T>(
    state: &mut WlState<'db, D, H>,
    keys: &vote_tallies::Keys<T>,
    vote_info: NewVotes,
) -> Result<(Tally, ChangedKeys)>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<'db, D, H>>,
    T: BorshDeserialize,
{
    tracing::info!(
        ?keys.prefix,
        validators = ?vote_info.voters(),
        "Calculating validators' votes applied to an existing tally"
    );
    let tally_pre = super::storage::read(state, keys)?;
    if tally_pre.seen {
        return Ok((tally_pre, ChangedKeys::default()));
    }

    let (vote_info, duplicate_voters) =
        vote_info.without_voters(tally_pre.seen_by.keys());
    for voter in duplicate_voters {
        tracing::info!(
            ?keys.prefix,
            ?voter,
            "Ignoring duplicate voter"
        );
    }
    let tally_post = apply::<D, H, Gov>(state, &tally_pre, vote_info)
        .expect("We deduplicated voters already, so this should never error");

    let changed_keys = keys_changed(keys, &tally_pre, &tally_post);

    if tally_post.seen {
        tracing::info!(
            ?keys.prefix,
            "Tally has been seen by a quorum of validators",
        );
    } else {
        tracing::debug!(
            ?keys.prefix,
            "Tally is not yet seen by a quorum of validators",
        );
    };

    tracing::debug!(
        ?tally_pre,
        ?tally_post,
        "Calculated and validated vote tracking updates",
    );
    Ok((tally_post, changed_keys))
}

/// Takes an existing [`Tally`] and calculates the new [`Tally`] based on new
/// voters from `vote_info`. An error is returned if any validator which
/// previously voted is present in `vote_info`.
fn apply<'db, D, H, Gov>(
    state: &WlState<'db, D, H>,
    tally: &Tally,
    vote_info: NewVotes,
) -> Result<Tally>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<'db, D, H>>,
{
    // TODO(namada#1305): remove the clone here
    let mut voting_power_post = tally.voting_power.clone();
    let mut seen_by_post = tally.seen_by.clone();
    for (validator, vote_height, voting_power) in vote_info {
        if let Some(already_voted_height) =
            seen_by_post.insert(validator.clone(), vote_height)
        {
            return Err(eyre!(
                "Validator {validator} had already voted at height \
                 {already_voted_height}",
            ));
        };
        let epoch = state
            .get_epoch_at_height(vote_height)
            .unwrap()
            .expect("The queried epoch should be known");
        let aggregated = voting_power_post
            .entry(epoch)
            .or_insert_with(token::Amount::zero);
        *aggregated = aggregated
            .checked_add(voting_power)
            .ok_or_else(|| eyre!("Aggregated voting power overflow"))?;
    }

    let seen_post = voting_power_post.has_majority_quorum::<D, H, Gov>(state);

    Ok(Tally {
        voting_power: voting_power_post,
        seen_by: seen_by_post,
        seen: seen_post,
    })
}

/// Straightforwardly calculates the keys that changed between `pre` and `post`.
fn keys_changed<T>(
    keys: &vote_tallies::Keys<T>,
    pre: &Tally,
    post: &Tally,
) -> ChangedKeys {
    let mut changed_keys = ChangedKeys::default();
    if pre.seen != post.seen {
        changed_keys.insert(keys.seen());
    };
    if pre.voting_power != post.voting_power {
        changed_keys.insert(keys.voting_power());
    };
    if pre.seen_by != post.seen_by {
        changed_keys.insert(keys.seen_by());
    };
    changed_keys
}

#[allow(clippy::arithmetic_side_effects)]
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use namada_core::address;
    use namada_core::ethereum_events::EthereumEvent;
    use namada_core::voting_power::FractionalVotingPower;
    use namada_state::testing::{TestFullAccessState, TestState};

    use self::helpers::{TallyParams, default_event, default_total_stake};
    use super::*;
    use crate::protocol::transactions::votes::{self, EpochedVotingPower};
    use crate::test_utils::{self, GovStore};

    mod helpers {
        use namada_proof_of_stake::storage::total_consensus_stake_handle;
        use test_utils::GovStore;

        use super::*;

        /// Default amount of staked NAM to be used in tests.
        pub(super) fn default_total_stake() -> token::Amount {
            // 1000 NAM
            token::Amount::native_whole(1_000)
        }

        /// Returns an arbitrary piece of data that can have votes tallied
        /// against it.
        pub(super) fn default_event() -> EthereumEvent {
            EthereumEvent::TransfersToNamada {
                nonce: 0.into(),
                transfers: vec![],
            }
        }

        /// Parameters to construct a test [`Tally`].
        pub(super) struct TallyParams<'a> {
            /// Handle to storage.
            pub state: &'a mut TestState,
            /// The event to be voted on.
            pub event: &'a EthereumEvent,
            /// Votes from the given validators at the given block height.
            ///
            /// The voting power of each validator is expressed as a fraction
            /// of the provided `total_stake` parameter.
            pub votes: HashSet<(Address, BlockHeight, token::Amount)>,
            /// The [`token::Amount`] staked at epoch 0.
            pub total_stake: token::Amount,
        }

        impl TallyParams<'_> {
            /// Write an initial [`Tally`] to storage.
            pub(super) fn setup(self) -> Result<Tally> {
                let Self {
                    state,
                    event,
                    votes,
                    total_stake,
                } = self;

                let keys = vote_tallies::Keys::from(event);
                let seen_voting_power: token::Amount = votes
                    .iter()
                    .map(|(_, _, voting_power)| *voting_power)
                    .sum();
                let tally = Tally {
                    voting_power: get_epoched_voting_power(seen_voting_power),
                    seen_by: votes
                        .into_iter()
                        .map(|(addr, height, _)| (addr, height))
                        .collect(),
                    seen: seen_voting_power
                        > FractionalVotingPower::TWO_THIRDS * total_stake,
                };
                votes::storage::write(state, &keys, event, &tally, false)?;
                total_consensus_stake_handle().set::<_, GovStore<_>>(
                    state,
                    total_stake,
                    0u64.into(),
                    0,
                )?;
                Ok(tally)
            }
        }
    }

    #[test]
    fn test_vote_info_new_empty() -> Result<()> {
        let voting_powers = HashMap::default();

        let vote_info = NewVotes::new(Votes::default(), &voting_powers)?;

        assert!(vote_info.voters().is_empty());
        assert_eq!(vote_info.into_iter().count(), 0);
        Ok(())
    }

    #[test]
    fn test_vote_info_new_single_voter() -> Result<()> {
        let validator = address::testing::established_address_1();
        let vote_height = BlockHeight(100);
        let voting_power =
            FractionalVotingPower::ONE_THIRD * default_total_stake();
        let vote = (validator.clone(), vote_height);
        let votes = Votes::from([vote.clone()]);
        let voting_powers = HashMap::from([(vote, voting_power)]);

        let vote_info = NewVotes::new(votes, &voting_powers)?;

        assert_eq!(vote_info.voters(), BTreeSet::from([validator.clone()]));
        let votes: BTreeSet<_> = vote_info.into_iter().collect();
        assert_eq!(
            votes,
            BTreeSet::from([(validator, vote_height, voting_power)]),
        );
        Ok(())
    }

    #[test]
    fn test_vote_info_new_error() -> Result<()> {
        let votes = Votes::from([(
            address::testing::established_address_1(),
            BlockHeight(100),
        )]);
        let voting_powers = HashMap::default();

        let result = NewVotes::new(votes, &voting_powers);

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_vote_info_without_voters() -> Result<()> {
        let validator = address::testing::established_address_1();
        let vote_height = BlockHeight(100);
        let voting_power =
            FractionalVotingPower::ONE_THIRD * default_total_stake();
        let vote = (validator.clone(), vote_height);
        let votes = Votes::from([vote.clone()]);
        let voting_powers = HashMap::from([(vote, voting_power)]);
        let vote_info = NewVotes::new(votes, &voting_powers)?;

        let (vote_info, removed) = vote_info.without_voters(vec![&validator]);

        assert!(vote_info.voters().is_empty());
        assert_eq!(removed, HashSet::from([&validator]));
        Ok(())
    }

    #[test]
    fn test_vote_info_remove_non_dupe() -> Result<()> {
        let validator = address::testing::established_address_1();
        let new_validator = address::testing::established_address_2();
        let vote_height = BlockHeight(100);
        let voting_power =
            FractionalVotingPower::ONE_THIRD * default_total_stake();
        let vote = (validator.clone(), vote_height);
        let votes = Votes::from([vote.clone()]);
        let voting_powers = HashMap::from([(vote, voting_power)]);
        let vote_info = NewVotes::new(votes, &voting_powers)?;

        let (vote_info, removed) =
            vote_info.without_voters(vec![&new_validator]);

        assert!(removed.is_empty());
        assert_eq!(vote_info.voters(), BTreeSet::from([validator]));
        Ok(())
    }

    #[test]
    fn test_apply_duplicate_votes() -> Result<()> {
        let (mut state, _) = test_utils::setup_default_storage();
        let wl_state = state.restrict_writes_to_write_log();

        let validator = address::testing::established_address_1();
        let already_voted_height = BlockHeight(100);

        let event = default_event();
        let tally_pre = TallyParams {
            total_stake: default_total_stake(),
            state: &mut wl_state,
            event: &event,
            votes: HashSet::from([(
                validator.clone(),
                already_voted_height,
                FractionalVotingPower::ONE_THIRD * default_total_stake(),
            )]),
        }
        .setup()?;

        let votes = Votes::from([(validator.clone(), BlockHeight(1000))]);
        let voting_powers = HashMap::from([(
            (validator, BlockHeight(1000)),
            FractionalVotingPower::ONE_THIRD * default_total_stake(),
        )]);
        let vote_info = NewVotes::new(votes, &voting_powers)?;

        let result =
            apply::<_, _, GovStore<_>>(&wl_state, &tally_pre, vote_info);

        assert!(result.is_err());
        Ok(())
    }

    /// Tests that an unchanged tally is returned if the tally as in storage is
    /// already recorded as having been seen.
    #[test]
    fn test_calculate_already_seen() -> Result<()> {
        let (mut state, _) = test_utils::setup_default_storage();
        let wl_state = state.restrict_writes_to_write_log();

        let event = default_event();
        let keys = vote_tallies::Keys::from(&event);
        let tally_pre = TallyParams {
            total_stake: default_total_stake(),
            state: &mut wl_state,
            event: &event,
            votes: HashSet::from([(
                address::testing::established_address_1(),
                BlockHeight(10),
                // this is > 2/3
                FractionalVotingPower::new_u64(3, 4)? * default_total_stake(),
            )]),
        }
        .setup()?;

        let validator = address::testing::established_address_2();
        let vote_height = BlockHeight(100);
        let voting_power =
            FractionalVotingPower::new_u64(1, 4)? * default_total_stake();
        let vote = (validator, vote_height);
        let votes = Votes::from([vote.clone()]);
        let voting_powers = HashMap::from([(vote, voting_power)]);
        let vote_info = NewVotes::new(votes, &voting_powers)?;

        let (tally_post, changed_keys) =
            calculate::<_, _, GovStore<_>, _>(&mut wl_state, &keys, vote_info)?;

        assert_eq!(tally_post, tally_pre);
        assert!(changed_keys.is_empty());
        Ok(())
    }

    /// Tests that an unchanged tally is returned if no votes are passed.
    #[test]
    fn test_calculate_empty() -> Result<()> {
        let (mut state, _) = test_utils::setup_default_storage();
        let wl_state = state.restrict_writes_to_write_log();

        let event = default_event();
        let keys = vote_tallies::Keys::from(&event);
        let tally_pre = TallyParams {
            total_stake: default_total_stake(),
            state: &mut wl_state,
            event: &event,
            votes: HashSet::from([(
                address::testing::established_address_1(),
                BlockHeight(10),
                FractionalVotingPower::ONE_THIRD * default_total_stake(),
            )]),
        }
        .setup()?;
        let vote_info = NewVotes::new(Votes::default(), &HashMap::default())?;

        let (tally_post, changed_keys) =
            calculate::<_, _, GovStore<_>, _>(&mut wl_state, &keys, vote_info)?;

        assert_eq!(tally_post, tally_pre);
        assert!(changed_keys.is_empty());
        Ok(())
    }

    /// Tests the case where a single vote is applied, and the tally is still
    /// not yet seen.
    #[test]
    fn test_calculate_one_vote_not_seen() -> Result<()> {
        let (mut state, _) = test_utils::setup_default_storage();
        let wl_state = state.restrict_writes_to_write_log();

        let event = default_event();
        let keys = vote_tallies::Keys::from(&event);
        let _tally_pre = TallyParams {
            total_stake: default_total_stake(),
            state: &mut wl_state,
            event: &event,
            votes: HashSet::from([(
                address::testing::established_address_1(),
                BlockHeight(10),
                FractionalVotingPower::ONE_THIRD * default_total_stake(),
            )]),
        }
        .setup()?;

        let validator = address::testing::established_address_2();
        let vote_height = BlockHeight(100);
        let voting_power =
            FractionalVotingPower::ONE_THIRD * default_total_stake();
        let vote = (validator, vote_height);
        let votes = Votes::from([vote.clone()]);
        let voting_powers = HashMap::from([(vote.clone(), voting_power)]);
        let vote_info = NewVotes::new(votes, &voting_powers)?;

        let (tally_post, changed_keys) =
            calculate::<_, _, GovStore<_>, _>(&mut wl_state, &keys, vote_info)?;

        assert_eq!(
            tally_post,
            Tally {
                voting_power: get_epoched_voting_power(
                    FractionalVotingPower::TWO_THIRDS * default_total_stake(),
                ),
                seen_by: BTreeMap::from([
                    (address::testing::established_address_1(), 10.into()),
                    vote,
                ]),
                seen: false,
            }
        );
        assert_eq!(
            changed_keys,
            BTreeSet::from([keys.voting_power(), keys.seen_by()])
        );
        Ok(())
    }

    /// Tests the case where a single vote is applied, and the tally is now
    /// seen.
    #[test]
    fn test_calculate_one_vote_seen() -> Result<()> {
        let (mut state, _) = test_utils::setup_default_storage();
        let wl_state = state.restrict_writes_to_write_log();

        let first_vote_stake =
            FractionalVotingPower::ONE_THIRD * default_total_stake();
        let second_vote_stake =
            FractionalVotingPower::ONE_THIRD * default_total_stake();
        let total_stake = first_vote_stake + second_vote_stake;

        let event = default_event();
        let keys = vote_tallies::Keys::from(&event);
        let _tally_pre = TallyParams {
            total_stake,
            state: &mut wl_state,
            event: &event,
            votes: HashSet::from([(
                address::testing::established_address_1(),
                BlockHeight(10),
                first_vote_stake,
            )]),
        }
        .setup()?;

        let validator = address::testing::established_address_2();
        let vote_height = BlockHeight(100);
        let vote = (validator, vote_height);
        let votes = Votes::from([vote.clone()]);
        let voting_powers = HashMap::from([(vote.clone(), second_vote_stake)]);
        let vote_info = NewVotes::new(votes, &voting_powers)?;

        let (tally_post, changed_keys) =
            calculate::<_, _, GovStore<_>, _>(&mut wl_state, &keys, vote_info)?;

        assert_eq!(
            tally_post,
            Tally {
                voting_power: get_epoched_voting_power(total_stake),
                seen_by: BTreeMap::from([
                    (address::testing::established_address_1(), 10.into()),
                    vote,
                ]),
                seen: true,
            }
        );
        assert_eq!(
            changed_keys,
            BTreeSet::from([keys.voting_power(), keys.seen_by(), keys.seen()])
        );
        Ok(())
    }

    #[test]
    fn test_keys_changed_all() -> Result<()> {
        let voting_power_a =
            FractionalVotingPower::ONE_THIRD * default_total_stake();
        let voting_power_b =
            FractionalVotingPower::TWO_THIRDS * default_total_stake();

        let seen_a = false;
        let seen_b = true;

        let seen_by_a = BTreeMap::from([(
            address::testing::established_address_1(),
            BlockHeight(10),
        )]);
        let seen_by_b = BTreeMap::from([(
            address::testing::established_address_2(),
            BlockHeight(20),
        )]);

        let event = default_event();
        let keys = vote_tallies::Keys::from(&event);
        let pre = Tally {
            voting_power: get_epoched_voting_power(voting_power_a),
            seen: seen_a,
            seen_by: seen_by_a,
        };
        let post = Tally {
            voting_power: get_epoched_voting_power(voting_power_b),
            seen: seen_b,
            seen_by: seen_by_b,
        };
        let changed_keys = keys_changed(&keys, &pre, &post);

        assert_eq!(
            changed_keys,
            BTreeSet::from([keys.seen(), keys.seen_by(), keys.voting_power()])
        );
        Ok(())
    }

    #[test]
    fn test_keys_changed_none() -> Result<()> {
        let seen = false;
        let seen_by = BTreeMap::from([(
            address::testing::established_address_1(),
            BlockHeight(10),
        )]);

        let event = default_event();
        let keys = vote_tallies::Keys::from(&event);
        let pre = Tally {
            voting_power: get_epoched_voting_power(
                FractionalVotingPower::ONE_THIRD * default_total_stake(),
            ),
            seen,
            seen_by,
        };
        #[allow(clippy::redundant_clone)]
        let post = pre.clone();
        let changed_keys = keys_changed(&keys, &pre, &post);

        assert!(changed_keys.is_empty());
        Ok(())
    }

    fn get_epoched_voting_power(thus_far: token::Amount) -> EpochedVotingPower {
        EpochedVotingPower::from([(0.into(), thus_far)])
    }
}
