//! Logic and data types relating to tallying validators' votes for pieces of
//! data stored in the ledger, where those pieces of data should only be acted
//! on once they have received enough votes
use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::{Result, eyre};
use namada_core::address::Address;
use namada_core::chain::{BlockHeight, Epoch};
use namada_core::collections::HashMap;
use namada_core::token;
use namada_core::voting_power::FractionalVotingPower;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_proof_of_stake::queries::get_total_voting_power;
use namada_state::{DBIter, DBRead, StorageHasher, StorageRead, WlState};
use namada_systems::governance;

use super::{ChangedKeys, read};

pub(super) mod storage;
pub(super) mod update;

/// The addresses of validators that voted for something, and the block
/// heights at which they voted.
///
/// We use a [`BTreeMap`] to enforce that a validator (as uniquely identified by
/// an [`Address`]) may vote at most once, their vote must be associated with a
/// specific [`BlockHeight`]. Their voting power at that block height is what is
/// used when calculating whether something has enough voting power behind it or
/// not.
pub type Votes = BTreeMap<Address, BlockHeight>;

/// The voting power behind a tally aggregated over multiple epochs.
pub type EpochedVotingPower = BTreeMap<Epoch, token::Amount>;

/// Extension methods for [`EpochedVotingPower`] instances.
pub trait EpochedVotingPowerExt {
    /// Query the stake of the most secure [`Epoch`] referenced by an
    /// [`EpochedVotingPower`]. This translates to the [`Epoch`] with
    /// the most staked tokens.
    fn epoch_max_voting_power<'db, D, H, Gov>(
        &self,
        state: &WlState<'db, D, H>,
    ) -> Option<token::Amount>
    where
        D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
        Gov: governance::Read<WlState<'db, D, H>>;

    /// Fetch the sum of the stake tallied on an
    /// [`EpochedVotingPower`].
    fn tallied_stake(&self) -> token::Amount;

    /// Fetch the sum of the stake tallied on an
    /// [`EpochedVotingPower`], as a fraction over
    /// the maximum stake seen in the epochs voted on.
    #[inline]
    fn fractional_stake<'db, D, H, Gov>(
        &self,
        state: &WlState<'db, D, H>,
    ) -> FractionalVotingPower
    where
        D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
        Gov: governance::Read<WlState<'db, D, H>>,
    {
        let Some(max_voting_power) =
            self.epoch_max_voting_power::<_, _, Gov>(state)
        else {
            return FractionalVotingPower::NULL;
        };
        FractionalVotingPower::new(
            self.tallied_stake().into(),
            max_voting_power.into(),
        )
        .unwrap()
    }

    /// Check if the [`Tally`] associated with an [`EpochedVotingPower`]
    /// can be considered `seen`.
    #[inline]
    fn has_majority_quorum<'db, D, H, Gov>(
        &self,
        state: &WlState<'db, D, H>,
    ) -> bool
    where
        D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
        Gov: governance::Read<WlState<'db, D, H>>,
    {
        let Some(max_voting_power) =
            self.epoch_max_voting_power::<_, _, Gov>(state)
        else {
            return false;
        };
        // NB: Preserve the safety property of the Tendermint protocol across
        // all the epochs we vote on.
        //
        // PROOF: We calculate the maximum amount of tokens S_max staked on
        // one of the epochs the tally occurred in. At most F = 1/3 * S_max
        // of the combined stake can be Byzantine, for the protocol to uphold
        // its linearizability property whilst remaining "secure" against
        // arbitrarily faulty nodes. Therefore, we can consider a tally secure
        // if has accumulated an amount of stake greater than the threshold
        // stake of S_max - F = 2/3 S_max.
        let threshold = FractionalVotingPower::TWO_THIRDS
            .checked_mul_amount(max_voting_power)
            .expect("Cannot overflow");
        self.tallied_stake() > threshold
    }
}

impl EpochedVotingPowerExt for EpochedVotingPower {
    fn epoch_max_voting_power<'db, D, H, Gov>(
        &self,
        state: &WlState<'db, D, H>,
    ) -> Option<token::Amount>
    where
        D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
        Gov: governance::Read<WlState<'db, D, H>>,
    {
        self.keys()
            .copied()
            .map(|epoch| get_total_voting_power::<_, Gov>(state, epoch))
            .max()
    }

    fn tallied_stake(&self) -> token::Amount {
        token::Amount::sum(self.values().copied())
            .expect("Talling stake shouldn't overflow")
    }
}

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
/// Represents all the information needed to tally a piece of data that may be
/// voted for over multiple epochs
pub struct Tally {
    /// The total voting power that's voted for this event across all epochs.
    pub voting_power: EpochedVotingPower,
    /// The votes which have been counted towards `voting_power`. Note that
    /// validators may submit multiple votes at different block heights for
    /// the same thing, but ultimately only one vote per validator will be
    /// used when tallying voting power.
    pub seen_by: Votes,
    /// Whether this event has been acted on or not - this should only ever
    /// transition from `false` to `true`, once there is enough voting power.
    pub seen: bool,
}

/// Calculate a new [`Tally`] based on some validators' fractional voting powers
/// as specific block heights
pub fn calculate_new<'db, D, H, Gov>(
    state: &WlState<'db, D, H>,
    seen_by: Votes,
    voting_powers: &HashMap<(Address, BlockHeight), token::Amount>,
) -> Result<Tally>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<'db, D, H>>,
{
    let mut seen_by_voting_power = EpochedVotingPower::new();
    for (validator, block_height) in seen_by.iter() {
        match voting_powers
            .get(&(validator.to_owned(), block_height.to_owned()))
        {
            Some(&voting_power) => {
                let epoch = state
                    .get_epoch_at_height(*block_height)
                    .unwrap()
                    .expect("The queried epoch should be known");
                let aggregated = seen_by_voting_power
                    .entry(epoch)
                    .or_insert_with(token::Amount::zero);
                *aggregated = aggregated
                    .checked_add(voting_power)
                    .ok_or_else(|| eyre!("Aggregated voting power overflow"))?;
            }
            None => {
                return Err(eyre!(
                    "voting power was not provided for validator {}",
                    validator
                ));
            }
        };
    }

    let newly_confirmed =
        seen_by_voting_power.has_majority_quorum::<D, H, Gov>(state);
    Ok(Tally {
        voting_power: seen_by_voting_power,
        seen_by,
        seen: newly_confirmed,
    })
}

/// Deterministically constructs a [`Votes`] map from a set of validator
/// addresses and the block heights they signed something at.
///
/// We arbitrarily take the earliest block height for each validator address
/// encountered.
pub fn dedupe(signers: BTreeSet<(Address, BlockHeight)>) -> Votes {
    signers.into_iter().rev().collect()
}

#[cfg(test)]
mod tests {
    use namada_core::address;
    use namada_proof_of_stake::parameters::OwnedPosParams;
    use namada_proof_of_stake::storage::{
        read_consensus_validator_set_addresses_with_stake, write_pos_params,
    };

    use super::*;
    use crate::test_utils::{self, GovStore};

    #[test]
    fn test_dedupe_empty() {
        let signers = BTreeSet::new();

        let deduped = dedupe(signers);

        assert_eq!(deduped, Votes::new());
    }

    #[test]
    fn test_dedupe_single_vote() {
        let sole_validator = address::testing::established_address_1();
        let votes = [(sole_validator, BlockHeight(100))];
        let signers = BTreeSet::from(votes.clone());

        let deduped = dedupe(signers);

        assert_eq!(deduped, Votes::from(votes));
    }

    #[test]
    fn test_dedupe_multiple_votes_same_voter() {
        let sole_validator = address::testing::established_address_1();
        let earliest_vote_height = 100;
        let earliest_vote =
            (sole_validator.clone(), BlockHeight(earliest_vote_height));
        let votes = [
            earliest_vote.clone(),
            (
                sole_validator.clone(),
                BlockHeight(earliest_vote_height + 1),
            ),
            (sole_validator, BlockHeight(earliest_vote_height + 100)),
        ];
        let signers = BTreeSet::from(votes);

        let deduped = dedupe(signers);

        assert_eq!(deduped, Votes::from([earliest_vote]));
    }

    #[test]
    fn test_dedupe_multiple_votes_multiple_voters() {
        let validator_1 = address::testing::established_address_1();
        let validator_2 = address::testing::established_address_2();
        let validator_1_earliest_vote_height = 100;
        let validator_1_earliest_vote = (
            validator_1.clone(),
            BlockHeight(validator_1_earliest_vote_height),
        );
        let validator_2_earliest_vote_height = 200;
        let validator_2_earliest_vote = (
            validator_2.clone(),
            BlockHeight(validator_2_earliest_vote_height),
        );
        let votes = [
            validator_1_earliest_vote.clone(),
            (
                validator_1.clone(),
                BlockHeight(validator_1_earliest_vote_height + 1),
            ),
            (
                validator_1,
                BlockHeight(validator_1_earliest_vote_height + 100),
            ),
            validator_2_earliest_vote.clone(),
            (
                validator_2.clone(),
                BlockHeight(validator_2_earliest_vote_height + 1),
            ),
            (
                validator_2,
                BlockHeight(validator_2_earliest_vote_height + 100),
            ),
        ];
        let signers = BTreeSet::from(votes);

        let deduped = dedupe(signers);

        assert_eq!(
            deduped,
            Votes::from([validator_1_earliest_vote, validator_2_earliest_vote])
        );
    }

    /// Test that voting on a tally during a single epoch does
    /// not require any storage reads, and goes through the
    /// fast path of the algorithm.
    #[test]
    fn test_tally_vote_single_epoch() {
        let (_, dummy_validator_stake) = test_utils::default_validator();
        let (dummy_storage, _) = test_utils::setup_default_storage();

        let aggregated = EpochedVotingPower::from([(
            0.into(),
            FractionalVotingPower::HALF * dummy_validator_stake,
        )]);
        assert_eq!(
            aggregated.fractional_stake::<_, _, GovStore<_>>(&dummy_storage),
            FractionalVotingPower::HALF
        );
    }

    /// Test that voting on a tally across epoch boundaries accounts
    /// for the maximum voting power attained along those epochs.
    #[test]
    fn test_voting_across_epoch_boundaries() {
        // the validators that will vote in the tally
        let validator_1 = address::testing::established_address_1();
        let validator_1_stake = token::Amount::native_whole(100);

        let validator_2 = address::testing::established_address_2();
        let validator_2_stake = token::Amount::native_whole(100);

        let validator_3 = address::testing::established_address_3();
        let validator_3_stake = token::Amount::native_whole(100);

        let total_stake =
            validator_1_stake + validator_2_stake + validator_3_stake;

        // start epoch 0 with validator 1
        let (mut state, _) = test_utils::setup_storage_with_validators(
            HashMap::from([(validator_1.clone(), validator_1_stake)]),
        );

        // update the pos params
        let params = OwnedPosParams {
            pipeline_len: 1,
            ..Default::default()
        };
        write_pos_params(&mut state, &params).expect("Test failed");

        // insert validators 2 and 3 at epoch 1
        test_utils::append_validators_to_storage(
            &mut state,
            HashMap::from([
                (validator_2.clone(), validator_2_stake),
                (validator_3.clone(), validator_3_stake),
            ]),
        );

        // query validators to make sure they were inserted correctly
        let query_validators = |epoch: u64| {
            read_consensus_validator_set_addresses_with_stake(
                &state,
                epoch.into(),
            )
            .unwrap()
            .into_iter()
            .map(|validator| (validator.address, validator.bonded_stake))
            .collect::<HashMap<_, _>>()
        };
        let epoch_0_validators = query_validators(0);
        let epoch_1_validators = query_validators(1);
        assert_eq!(
            epoch_0_validators,
            HashMap::from([(validator_1.clone(), validator_1_stake)])
        );
        assert_eq!(
            get_total_voting_power::<_, GovStore<_>>(&state, 0.into()),
            validator_1_stake,
        );
        assert_eq!(
            epoch_1_validators,
            HashMap::from([
                (validator_1, validator_1_stake),
                (validator_2, validator_2_stake),
                (validator_3, validator_3_stake),
            ])
        );
        assert_eq!(
            get_total_voting_power::<_, GovStore<_>>(&state, 1.into()),
            total_stake,
        );

        // check that voting works as expected
        let aggregated = EpochedVotingPower::from([
            (0.into(), FractionalVotingPower::ONE_THIRD * total_stake),
            (1.into(), FractionalVotingPower::ONE_THIRD * total_stake),
        ]);
        assert_eq!(
            aggregated.fractional_stake::<_, _, GovStore<_>>(&state),
            FractionalVotingPower::TWO_THIRDS
        );
    }
}
