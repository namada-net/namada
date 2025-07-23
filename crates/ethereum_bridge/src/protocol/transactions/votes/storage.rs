use eyre::{Result, WrapErr};
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::hints;
use namada_core::storage::Key;
use namada_core::voting_power::FractionalVotingPower;
use namada_state::{DBIter, DBRead, PrefixIter, StorageHasher, WlState};
use namada_storage::{StorageRead, StorageWrite};
use namada_systems::governance;

use super::{EpochedVotingPower, EpochedVotingPowerExt, Tally, Votes};
use crate::storage::vote_tallies;

pub fn write<D, H, T>(
    state: &mut WlState<'_, D, H>,
    keys: &vote_tallies::Keys<T>,
    body: &T,
    tally: &Tally,
    already_present: bool,
) -> Result<()>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshSerialize,
{
    state.write(&keys.body(), body)?;
    state.write(&keys.seen(), tally.seen)?;
    state.write(&keys.seen_by(), tally.seen_by.clone())?;
    state.write(&keys.voting_power(), tally.voting_power.clone())?;
    if !already_present {
        // add the current epoch for the inserted event
        state.write(
            &keys.voting_started_epoch(),
            state.in_mem().get_current_epoch().0,
        )?;
    }
    Ok(())
}

/// Delete a tally from storage, and return the associated value of
/// type `T` being voted on, in case it has accumulated more than 1/3
/// of fractional voting power behind it.
#[must_use = "The storage value returned by this function must be used"]
pub fn delete<'db, D, H, Gov, T>(
    state: &mut WlState<'db, D, H>,
    keys: &vote_tallies::Keys<T>,
) -> Result<Option<T>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    Gov: governance::Read<WlState<'db, D, H>>,
    T: BorshDeserialize,
{
    let opt_body = {
        let voting_power: EpochedVotingPower =
            super::read::value(state, &keys.voting_power())?;

        if hints::unlikely(
            voting_power.fractional_stake::<D, H, Gov>(state)
                > FractionalVotingPower::ONE_THIRD,
        ) {
            let body: T = super::read::value(state, &keys.body())?;
            Some(body)
        } else {
            None
        }
    };
    state.delete(&keys.body())?;
    state.delete(&keys.seen())?;
    state.delete(&keys.seen_by())?;
    state.delete(&keys.voting_power())?;
    state.delete(&keys.voting_started_epoch())?;
    Ok(opt_body)
}

pub fn read<D, H, T>(
    state: &WlState<'_, D, H>,
    keys: &vote_tallies::Keys<T>,
) -> Result<Tally>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let seen: bool = super::read::value(state, &keys.seen())?;
    let seen_by: Votes = super::read::value(state, &keys.seen_by())?;
    let voting_power: EpochedVotingPower =
        super::read::value(state, &keys.voting_power())?;

    Ok(Tally {
        voting_power,
        seen_by,
        seen,
    })
}

pub fn iter_prefix<'a, D, H>(
    state: &'a WlState<'_, D, H>,
    prefix: &Key,
) -> Result<PrefixIter<'a, D>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    state
        .iter_prefix(prefix)
        .context("Failed to iterate over the given storage prefix")
}

#[inline]
pub fn read_body<D, H, T>(
    state: &WlState<'_, D, H>,
    keys: &vote_tallies::Keys<T>,
) -> Result<T>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshDeserialize,
{
    super::read::value(state, &keys.body())
}

#[inline]
pub fn maybe_read_seen<D, H, T>(
    state: &WlState<'_, D, H>,
    keys: &vote_tallies::Keys<T>,
) -> Result<Option<bool>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshDeserialize,
{
    super::read::maybe_value(state, &keys.seen())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use assert_matches::assert_matches;
    use namada_core::ethereum_events::EthereumEvent;

    use super::*;
    use crate::test_utils::{self, GovStore};

    #[test]
    fn test_delete_expired_tally() {
        let (mut state, _) = test_utils::setup_default_storage();
        let (validator, validator_voting_power) =
            test_utils::default_validator();

        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![],
        };
        let keys = vote_tallies::Keys::from(&event);

        // write some random ethereum event's tally to storage
        // with >1/3 voting power behind it
        let mut tally = Tally {
            voting_power: EpochedVotingPower::from([(
                0.into(),
                // store only half of the available voting power,
                // which is >1/3 but <=2/3
                FractionalVotingPower::HALF * validator_voting_power,
            )]),
            seen_by: BTreeMap::from([(validator, 1.into())]),
            seen: false,
        };
        assert!(write(&mut state, &keys, &event, &tally, false).is_ok());

        // delete the tally and check that the body is returned
        let opt_body =
            delete::<_, _, GovStore<_>, _>(&mut state, &keys).unwrap();
        assert_matches!(opt_body, Some(e) if e == event);

        // now, we write another tally, with <=1/3 voting power
        tally.voting_power =
            EpochedVotingPower::from([(0.into(), 1u64.into())]);
        assert!(write(&mut state, &keys, &event, &tally, false).is_ok());

        // delete the tally and check that no body is returned
        let opt_body =
            delete::<_, _, GovStore<_>, _>(&mut state, &keys).unwrap();
        assert_matches!(opt_body, None);
    }

    #[test]
    fn test_write_tally() {
        let (mut state, _) = test_utils::setup_default_storage();
        let (validator, validator_voting_power) =
            test_utils::default_validator();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![],
        };
        let keys = vote_tallies::Keys::from(&event);
        let tally = Tally {
            voting_power: EpochedVotingPower::from([(
                0.into(),
                validator_voting_power,
            )]),
            seen_by: BTreeMap::from([(validator, 10.into())]),
            seen: false,
        };

        let result = write(&mut state, &keys, &event, &tally, false);

        assert!(result.is_ok());
        let body = state.read(&keys.body()).unwrap();
        assert_eq!(body, Some(event));
        let seen = state.read(&keys.seen()).unwrap();
        assert_eq!(seen, Some(tally.seen));
        let seen_by = state.read(&keys.seen_by()).unwrap();
        assert_eq!(seen_by, Some(tally.seen_by));
        let voting_power = state.read(&keys.voting_power()).unwrap();
        assert_eq!(voting_power, Some(tally.voting_power));
        let epoch = state.read(&keys.voting_started_epoch()).unwrap();
        assert_eq!(epoch, Some(state.in_mem().get_current_epoch().0));
    }

    #[test]
    fn test_read_tally() {
        let (mut state, _) = test_utils::setup_default_storage();
        let (validator, validator_voting_power) =
            test_utils::default_validator();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![],
        };
        let keys = vote_tallies::Keys::from(&event);
        let tally = Tally {
            voting_power: EpochedVotingPower::from([(
                0.into(),
                validator_voting_power,
            )]),
            seen_by: BTreeMap::from([(validator, 10.into())]),
            seen: false,
        };
        state.write(&keys.body(), &event).unwrap();
        state.write(&keys.seen(), tally.seen).unwrap();
        state.write(&keys.seen_by(), &tally.seen_by).unwrap();
        state
            .write(&keys.voting_power(), &tally.voting_power)
            .unwrap();
        state
            .write(
                &keys.voting_started_epoch(),
                state.in_mem().get_block_height().0,
            )
            .unwrap();

        let result = read(&state, &keys);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), tally);
    }
}
