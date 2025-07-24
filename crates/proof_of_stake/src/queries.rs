//! Queriezzz

use std::cmp;
use std::collections::BTreeMap;

use borsh::BorshDeserialize;
use namada_core::address::Address;
use namada_core::chain::Epoch;
use namada_core::collections::{HashMap, HashSet};
use namada_core::dec::Dec;
use namada_core::key::common;
use namada_core::token;
use namada_systems::governance;

use crate::lazy_map::{NestedSubKey, SubKey};
use crate::slashing::{find_validator_slashes, get_slashed_amount};
use crate::storage::{
    bond_handle, delegation_targets_handle,
    read_consensus_validator_set_addresses, read_pos_params, unbond_handle,
    validator_eth_hot_key_handle,
};
use crate::types::{
    BondDetails, BondId, BondsAndUnbondsDetail, BondsAndUnbondsDetails,
    DelegationEpochs, Slash, UnbondDetails,
};
use crate::{
    Error, PosParams, Result, StorageRead, iter_prefix_bytes, raw_bond_amount,
    storage_key,
};

/// Find all validators to which a given bond `owner` (or source) has a
/// delegation
pub fn find_delegation_validators<S>(
    storage: &S,
    owner: &Address,
    epoch: &Epoch,
) -> Result<HashSet<Address>>
where
    S: StorageRead,
{
    let validators = delegation_targets_handle(owner);
    if validators.is_empty(storage)? {
        return Ok(HashSet::new());
    }

    let mut delegation_targets = HashSet::new();

    for validator in validators.iter(storage)? {
        let (
            val,
            DelegationEpochs {
                prev_ranges,
                last_range: (last_start, last_end),
            },
        ) = validator?;

        // Now determine if the validator held a bond from delegator at epoch
        if *epoch >= last_start {
            // the `last_range` will tell us if there was a bond
            if let Some(end) = last_end {
                if *epoch < end {
                    delegation_targets.insert(val);
                }
            } else {
                // this bond is currently held
                delegation_targets.insert(val);
            }
        } else {
            // need to search through the `prev_ranges` now
            for (start, end) in prev_ranges.iter().rev() {
                if *epoch >= *start {
                    if *epoch < *end {
                        delegation_targets.insert(val);
                    }
                    break;
                }
            }
        }
    }

    Ok(delegation_targets)
}

/// Find all validators to which a given bond `owner` (or source) has a
/// delegation with the amount
pub fn find_delegations<S, Gov>(
    storage: &S,
    owner: &Address,
    epoch: &Epoch,
) -> Result<HashMap<Address, token::Amount>>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let validators = delegation_targets_handle(owner);
    if validators.is_empty(storage)? {
        return Ok(HashMap::new());
    }

    let mut delegations = HashMap::<Address, token::Amount>::new();

    for validator in validators.iter(storage)? {
        let (
            val,
            DelegationEpochs {
                prev_ranges,
                last_range: (last_start, last_end),
            },
        ) = validator?;

        let bond_amount = raw_bond_amount::<S, Gov>(
            storage,
            &BondId {
                source: owner.clone(),
                validator: val.clone(),
            },
            *epoch,
        )?;

        // Now determine if the validator held a bond from delegator at epoch
        if *epoch >= last_start {
            // the `last_range` will tell us if there was a bond
            if let Some(end) = last_end {
                if *epoch < end {
                    // this bond was previously held
                    delegations.insert(val, bond_amount);
                }
            } else {
                // this bond is currently held
                delegations.insert(val, bond_amount);
            }
        } else {
            // need to search through the `prev_ranges` now
            for (start, end) in prev_ranges.iter().rev() {
                if *epoch >= *start {
                    if *epoch < *end {
                        delegations.insert(val, bond_amount);
                    }
                    break;
                }
            }
        }
    }
    Ok(delegations)
}

/// Find if the given source address has any bonds.
pub fn has_bonds<S, Gov>(storage: &S, source: &Address) -> Result<bool>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let max_epoch = Epoch(u64::MAX);
    let delegations = find_delegations::<S, Gov>(storage, source, &max_epoch)?;
    Ok(!delegations.values().all(token::Amount::is_zero))
}

/// Find raw bond deltas for the given source and validator address.
pub fn find_bonds<S>(
    storage: &S,
    source: &Address,
    validator: &Address,
) -> Result<BTreeMap<Epoch, token::Amount>>
where
    S: StorageRead,
{
    bond_handle(source, validator)
        .get_data_handler()
        .iter(storage)?
        .collect()
}

/// Find raw unbond deltas for the given source and validator address.
pub fn find_unbonds<S>(
    storage: &S,
    source: &Address,
    validator: &Address,
) -> Result<BTreeMap<(Epoch, Epoch), token::Amount>>
where
    S: StorageRead,
{
    unbond_handle(source, validator)
        .iter(storage)?
        .map(|next_result| {
            let (
                NestedSubKey::Data {
                    key: start_epoch,
                    nested_sub_key: SubKey::Data(withdraw_epoch),
                },
                amount,
            ) = next_result?;
            Ok(((start_epoch, withdraw_epoch), amount))
        })
        .collect()
}

/// Collect the details of all bonds and unbonds that match the source and
/// validator arguments.
///
/// If either source or validator is `None`, then grab the
/// information for all sources or validators, respectively.
pub fn bonds_and_unbonds<S, Gov>(
    storage: &S,
    source: Option<Address>,
    validator: Option<Address>,
) -> Result<BondsAndUnbondsDetails>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let params = read_pos_params::<S, Gov>(storage)?;

    match (source.clone(), validator.clone()) {
        (Some(source), Some(validator)) => {
            find_bonds_and_unbonds_details(storage, &params, source, validator)
        }
        _ => {
            get_multiple_bonds_and_unbonds(storage, &params, source, validator)
        }
    }
}

fn get_multiple_bonds_and_unbonds<S>(
    storage: &S,
    params: &PosParams,
    source: Option<Address>,
    validator: Option<Address>,
) -> Result<BondsAndUnbondsDetails>
where
    S: StorageRead,
{
    debug_assert!(
        source.is_none() || validator.is_none(),
        "Use `find_bonds_and_unbonds_details` when full bond ID is known"
    );
    let mut slashes_cache = HashMap::<Address, Vec<Slash>>::new();
    // Applied slashes grouped by validator address
    let mut applied_slashes = HashMap::<Address, Vec<Slash>>::new();

    // TODO: if validator is `Some`, look-up all its bond owners (including
    // self-bond, if any) first

    let prefix = match source.as_ref() {
        Some(source) => storage_key::bonds_for_source_prefix(source),
        None => storage_key::bonds_prefix(),
    };
    // We have to iterate raw bytes, cause the epoched data `last_update` field
    // gets matched here too
    let mut raw_bonds =
        iter_prefix_bytes(storage, prefix)?.filter_map(|result| {
            if let Ok((key, val_bytes)) = result {
                if let Some((bond_id, start)) = storage_key::is_bond_key(&key) {
                    if source.is_some()
                        && source.as_ref().unwrap() != &bond_id.source
                    {
                        return None;
                    }
                    if validator.is_some()
                        && validator.as_ref().unwrap() != &bond_id.validator
                    {
                        return None;
                    }
                    let change: token::Amount =
                        BorshDeserialize::try_from_slice(&val_bytes).ok()?;
                    if change.is_zero() {
                        return None;
                    }
                    return Some((bond_id, start, change));
                }
            }
            None
        });

    let prefix = match source.as_ref() {
        Some(source) => storage_key::unbonds_for_source_prefix(source),
        None => storage_key::unbonds_prefix(),
    };
    let mut raw_unbonds =
        iter_prefix_bytes(storage, prefix)?.filter_map(|result| {
            if let Ok((key, val_bytes)) = result {
                if let Some((bond_id, start, withdraw)) =
                    storage_key::is_unbond_key(&key)
                {
                    if source.is_some()
                        && source.as_ref().unwrap() != &bond_id.source
                    {
                        return None;
                    }
                    if validator.is_some()
                        && validator.as_ref().unwrap() != &bond_id.validator
                    {
                        return None;
                    }
                    match (source.clone(), validator.clone()) {
                        (None, Some(validator)) => {
                            if bond_id.validator != validator {
                                return None;
                            }
                        }
                        (Some(owner), None) => {
                            if owner != bond_id.source {
                                return None;
                            }
                        }
                        _ => {}
                    }
                    let amount: token::Amount =
                        BorshDeserialize::try_from_slice(&val_bytes).ok()?;
                    return Some((bond_id, start, withdraw, amount));
                }
            }
            None
        });

    let mut bonds_and_unbonds =
        HashMap::<BondId, (Vec<BondDetails>, Vec<UnbondDetails>)>::new();

    raw_bonds.try_for_each(|(bond_id, start, change)| {
        if !slashes_cache.contains_key(&bond_id.validator) {
            let slashes = find_validator_slashes(storage, &bond_id.validator)?;
            slashes_cache.insert(bond_id.validator.clone(), slashes);
        }
        let slashes = slashes_cache
            .get(&bond_id.validator)
            .expect("We must have inserted it if it's not cached already");
        let validator = bond_id.validator.clone();
        let (bonds, _unbonds) = bonds_and_unbonds.entry(bond_id).or_default();
        bonds.push(make_bond_details(
            params,
            &validator,
            change,
            start,
            slashes,
            &mut applied_slashes,
        ));
        Ok::<_, Error>(())
    })?;

    raw_unbonds.try_for_each(|(bond_id, start, withdraw, amount)| {
        if !slashes_cache.contains_key(&bond_id.validator) {
            let slashes = find_validator_slashes(storage, &bond_id.validator)?;
            slashes_cache.insert(bond_id.validator.clone(), slashes);
        }
        let slashes = slashes_cache
            .get(&bond_id.validator)
            .expect("We must have inserted it if it's not cached already");
        let validator = bond_id.validator.clone();
        let (_bonds, unbonds) = bonds_and_unbonds.entry(bond_id).or_default();
        unbonds.push(make_unbond_details(
            params,
            &validator,
            amount,
            (start, withdraw),
            slashes,
            &mut applied_slashes,
        ));
        Ok::<_, Error>(())
    })?;

    Ok(bonds_and_unbonds
        .into_iter()
        .map(|(bond_id, (bonds, unbonds))| {
            let details = BondsAndUnbondsDetail {
                bonds,
                unbonds,
                slashes: applied_slashes
                    .get(&bond_id.validator)
                    .cloned()
                    .unwrap_or_default(),
            };
            (bond_id, details)
        })
        .collect())
}

fn find_bonds_and_unbonds_details<S>(
    storage: &S,
    params: &PosParams,
    source: Address,
    validator: Address,
) -> Result<BondsAndUnbondsDetails>
where
    S: StorageRead,
{
    let slashes = find_validator_slashes(storage, &validator)?;
    let mut applied_slashes = HashMap::<Address, Vec<Slash>>::new();

    let bonds = find_bonds(storage, &source, &validator)?
        .into_iter()
        .filter(|(_start, amount)| *amount > token::Amount::zero())
        .map(|(start, amount)| {
            make_bond_details(
                params,
                &validator,
                amount,
                start,
                &slashes,
                &mut applied_slashes,
            )
        })
        .collect();

    let unbonds = find_unbonds(storage, &source, &validator)?
        .into_iter()
        .map(|(epoch_range, change)| {
            make_unbond_details(
                params,
                &validator,
                change,
                epoch_range,
                &slashes,
                &mut applied_slashes,
            )
        })
        .collect();

    let details = BondsAndUnbondsDetail {
        bonds,
        unbonds,
        slashes: applied_slashes.get(&validator).cloned().unwrap_or_default(),
    };
    let bond_id = BondId { source, validator };
    Ok(HashMap::from_iter([(bond_id, details)]))
}

fn make_bond_details(
    params: &PosParams,
    validator: &Address,
    deltas_sum: token::Amount,
    start: Epoch,
    slashes: &[Slash],
    applied_slashes: &mut HashMap<Address, Vec<Slash>>,
) -> BondDetails {
    let prev_applied_slashes = applied_slashes
        .clone()
        .get(validator)
        .cloned()
        .unwrap_or_default();

    let mut slash_rates_by_epoch = BTreeMap::<Epoch, Dec>::new();

    let validator_slashes =
        applied_slashes.entry(validator.clone()).or_default();
    for slash in slashes {
        if slash.epoch >= start {
            let cur_rate = slash_rates_by_epoch.entry(slash.epoch).or_default();
            *cur_rate = cmp::min(
                Dec::one(),
                cur_rate.checked_add(slash.rate).unwrap_or_else(Dec::one),
            );

            if !prev_applied_slashes.iter().any(|s| s == slash) {
                validator_slashes.push(slash.clone());
            }
        }
    }

    let slashed_amount = if slash_rates_by_epoch.is_empty() {
        None
    } else {
        let amount_after_slashing =
            get_slashed_amount(params, deltas_sum, &slash_rates_by_epoch)
                .unwrap();
        Some(
            deltas_sum
                .checked_sub(amount_after_slashing)
                .unwrap_or_default(),
        )
    };

    BondDetails {
        start,
        amount: deltas_sum,
        slashed_amount,
    }
}

fn make_unbond_details(
    params: &PosParams,
    validator: &Address,
    amount: token::Amount,
    (start, withdraw): (Epoch, Epoch),
    slashes: &[Slash],
    applied_slashes: &mut HashMap<Address, Vec<Slash>>,
) -> UnbondDetails {
    let prev_applied_slashes = applied_slashes
        .clone()
        .get(validator)
        .cloned()
        .unwrap_or_default();
    let mut slash_rates_by_epoch = BTreeMap::<Epoch, Dec>::new();

    let validator_slashes =
        applied_slashes.entry(validator.clone()).or_default();
    for slash in slashes {
        if slash.epoch >= start
            && slash.epoch
                < withdraw
                    .checked_sub(
                        params
                            .unbonding_len
                            .checked_add(params.cubic_slashing_window_length)
                            .expect("Cannot overflow"),
                    )
                    .unwrap_or_default()
        {
            let cur_rate = slash_rates_by_epoch.entry(slash.epoch).or_default();
            *cur_rate = cmp::min(
                Dec::one(),
                cur_rate.checked_add(slash.rate).unwrap_or_else(Dec::one),
            );

            if !prev_applied_slashes.iter().any(|s| s == slash) {
                validator_slashes.push(slash.clone());
            }
        }
    }

    let slashed_amount = if slash_rates_by_epoch.is_empty() {
        None
    } else {
        let amount_after_slashing =
            get_slashed_amount(params, amount, &slash_rates_by_epoch).unwrap();
        Some(
            amount
                .checked_sub(amount_after_slashing)
                .unwrap_or_default(),
        )
    };

    UnbondDetails {
        start,
        withdraw,
        amount,
        slashed_amount,
    }
}

/// Lookup the total voting power for an epoch.
pub fn get_total_voting_power<S, Gov>(
    storage: &S,
    epoch: Epoch,
) -> token::Amount
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let params =
        read_pos_params::<S, Gov>(storage).expect("PoS params must be present");
    crate::get_total_consensus_stake(storage, epoch, &params)
        .expect("Total consensus stake must always be available")
}

/// Find the protocol key of the given validator address at the given epoch.
pub fn get_validator_protocol_key<S, Gov>(
    storage: &S,
    addr: &Address,
    epoch: Epoch,
) -> Result<Option<common::PublicKey>>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let params =
        read_pos_params::<S, Gov>(storage).expect("PoS params must be present");
    let protocol_keys = crate::validator_protocol_key_handle(addr);
    protocol_keys.get(storage, epoch, &params)
}

/// Get a validator's Ethereum hot key from storage at the given epoch.
pub fn get_validator_eth_hot_key<S, Gov>(
    storage: &S,
    validator: &Address,
    epoch: Epoch,
) -> Result<Option<common::PublicKey>>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let params =
        read_pos_params::<S, Gov>(storage).expect("PoS params must be present");
    validator_eth_hot_key_handle(validator).get(storage, epoch, &params)
}

/// Read PoS validator's stake (sum of deltas).
/// For non-validators and validators with `0` stake, this returns the default -
/// `token::Amount::zero()`.
pub fn read_validator_stake<S, Gov>(
    storage: &S,
    validator: &Address,
    epoch: Epoch,
) -> Result<token::Amount>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let params =
        read_pos_params::<S, Gov>(storage).expect("PoS params must be present");
    crate::storage::read_validator_stake(storage, &params, validator, epoch)
}

/// Lookup data about a validator from their protocol signing key.
pub fn get_consensus_validator_from_protocol_pk<S, Gov>(
    storage: &S,
    pk: &common::PublicKey,
    epoch: Option<Epoch>,
) -> Result<Option<Address>>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let params = crate::read_pos_params::<S, Gov>(storage)?;
    let epoch = epoch.map(Ok).unwrap_or_else(|| storage.get_block_epoch())?;

    let address = read_consensus_validator_set_addresses(storage, epoch)?
        .iter()
        .find(|validator| {
            let protocol_keys = crate::validator_protocol_key_handle(validator);
            match protocol_keys.get(storage, epoch, &params) {
                Ok(Some(key)) => key == *pk,
                _ => false,
            }
        })
        .cloned();
    Ok(address)
}
