//! Slashing tingzzzz

use std::cmp::{self, Reverse};
use std::collections::{BTreeMap, BTreeSet};

use borsh::BorshDeserialize;
use namada_core::address::Address;
use namada_core::arith::{self, checked};
use namada_core::chain::{BlockHeight, Epoch};
use namada_core::collections::HashMap;
use namada_core::dec::Dec;
use namada_core::key::tm_raw_hash_to_string;
use namada_core::tendermint::abci::types::{Misbehavior, MisbehaviorKind};
use namada_core::token;
use namada_events::EmitEvents;
use namada_systems::governance;

use crate::event::PosEvent;
use crate::lazy_map::{Collectable, NestedMap, NestedSubKey, SubKey};
use crate::storage::{
    enqueued_slashes_handle, read_pos_params, read_validator_last_slash_epoch,
    read_validator_stake, total_bonded_handle, total_unbonded_handle,
    update_total_deltas, update_validator_deltas,
    validator_outgoing_redelegations_handle, validator_slashes_handle,
    validator_state_handle, validator_total_redelegated_bonded_handle,
    validator_total_redelegated_unbonded_handle,
    write_validator_last_slash_epoch,
};
use crate::types::{
    EagerRedelegatedBondsMap, ResultSlashing, Slash, SlashType, SlashedAmount,
    Slashes, TotalRedelegatedUnbonded, ValidatorState,
};
use crate::validator_set_update::update_validator_set;
use crate::{
    EagerRedelegatedUnbonds, Error, FoldRedelegatedBondsResult, LazyMap,
    OptionExt, OwnedPosParams, PosParams, Result, ResultExt, StorageRead,
    StorageWrite, fold_and_slash_redelegated_bonds, get_total_consensus_stake,
    iter_prefix_bytes, jail_validator, storage, storage_key, types,
};

/// Apply PoS slashes from the evidence
pub(crate) fn record_slashes_from_evidence<S, Gov>(
    storage: &mut S,
    byzantine_validators: Vec<Misbehavior>,
    pos_params: &PosParams,
    current_epoch: Epoch,
    validator_set_update_epoch: Epoch,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
    Gov: governance::Read<S>,
{
    if !byzantine_validators.is_empty() {
        let pred_epochs = storage.get_pred_epochs()?;
        for evidence in byzantine_validators {
            // dbg!(&evidence);
            tracing::info!("Processing evidence {evidence:?}.");
            let evidence_height = u64::from(evidence.height);
            let evidence_epoch =
                match pred_epochs.get_epoch(BlockHeight(evidence_height)) {
                    Some(epoch) => epoch,
                    None => {
                        tracing::error!(
                            "Couldn't find epoch for evidence block height {}",
                            evidence_height
                        );
                        continue;
                    }
                };
            // Disregard evidences that should have already been processed
            // at this time
            if checked!(
                evidence_epoch + pos_params.slash_processing_epoch_offset()
                    - pos_params.cubic_slashing_window_length
            )? <= current_epoch
            {
                tracing::info!(
                    "Skipping outdated evidence from epoch {evidence_epoch}"
                );
                continue;
            }
            let slash_type = match evidence.kind {
                MisbehaviorKind::DuplicateVote => {
                    types::SlashType::DuplicateVote
                }
                MisbehaviorKind::LightClientAttack => {
                    types::SlashType::LightClientAttack
                }
                MisbehaviorKind::Unknown => {
                    tracing::error!("Unknown evidence: {:#?}", evidence);
                    continue;
                }
            };
            let validator_raw_hash =
                tm_raw_hash_to_string(evidence.validator.address);
            let validator = match storage::find_validator_by_raw_hash(
                storage,
                &validator_raw_hash,
            )? {
                Some(validator) => validator,
                None => {
                    tracing::error!(
                        "Cannot find validator's address from raw hash {}",
                        validator_raw_hash
                    );
                    continue;
                }
            };
            // Check if we're gonna switch to a new epoch after a delay
            tracing::info!(
                "Slashing {} for {} in epoch {}, block height {} (current \
                 epoch = {}, validator set update epoch = \
                 {validator_set_update_epoch})",
                validator,
                slash_type,
                evidence_epoch,
                evidence_height,
                current_epoch
            );
            if let Err(err) = slash::<S, Gov>(
                storage,
                pos_params,
                current_epoch,
                evidence_epoch,
                evidence_height,
                slash_type,
                &validator,
                validator_set_update_epoch,
            ) {
                tracing::error!("Error in slashing: {}", err);
            }
        }
    }
    Ok(())
}

/// Record a slash for a misbehavior that has been received from Tendermint and
/// then jail the validator, removing it from the validator set. The slash rate
/// will be computed at a later epoch.
#[allow(clippy::too_many_arguments)]
pub fn slash<S, Gov>(
    storage: &mut S,
    params: &PosParams,
    current_epoch: Epoch,
    evidence_epoch: Epoch,
    evidence_block_height: impl Into<u64>,
    slash_type: SlashType,
    validator: &Address,
    validator_set_update_epoch: Epoch,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
    Gov: governance::Read<S>,
{
    let evidence_block_height: u64 = evidence_block_height.into();
    let slash = Slash {
        epoch: evidence_epoch,
        block_height: evidence_block_height,
        r#type: slash_type,
        rate: Dec::zero(), // Let the rate be 0 initially before processing
    };
    // Need `+1` because we process at the beginning of a new epoch
    let processing_epoch =
        checked!(evidence_epoch + params.slash_processing_epoch_offset())?;

    // Add the slash to the list of enqueued slashes to be processed at a later
    // epoch. If a slash at the same block height already exists, return early.
    let enqueued = enqueued_slashes_handle()
        .get_data_handler()
        .at(&processing_epoch)
        .at(validator);
    if enqueued.contains(storage, &evidence_block_height)? {
        return Ok(());
    } else {
        enqueued.insert(storage, evidence_block_height, slash)?;
    }

    // Update the most recent slash (infraction) epoch for the validator
    let last_slash_epoch = read_validator_last_slash_epoch(storage, validator)?;
    if last_slash_epoch.is_none()
        || evidence_epoch.0 > last_slash_epoch.unwrap_or_default().0
    {
        write_validator_last_slash_epoch(storage, validator, evidence_epoch)?;
    }

    // Jail the validator and update validator sets
    jail_validator::<S, Gov>(
        storage,
        params,
        validator,
        current_epoch,
        validator_set_update_epoch,
    )?;

    // No other actions are performed here until the epoch in which the slash is
    // processed.

    Ok(())
}

/// Process enqueued slashes that were discovered earlier.
///
/// This function is called upon a new epoch. The final slash rate considering
/// according to the cubic slashing rate is computed. Then, each slash is
/// recorded in storage along with its computed rate, and stake is deducted from
/// the affected validators.
pub fn process_slashes<S, Gov>(
    storage: &mut S,
    events: &mut impl EmitEvents,
    current_epoch: Epoch,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
    Gov: governance::Read<S>,
{
    let params = read_pos_params::<S, Gov>(storage)?;

    if current_epoch.0 < params.slash_processing_epoch_offset() {
        return Ok(());
    }
    let infraction_epoch =
        checked!(current_epoch - params.slash_processing_epoch_offset())?;

    // Slashes to be processed in the current epoch
    let enqueued_slashes = enqueued_slashes_handle().at(&current_epoch);
    if enqueued_slashes.is_empty(storage)? {
        return Ok(());
    }
    tracing::debug!(
        "Processing slashes at the beginning of epoch {} (committed in epoch \
         {})",
        current_epoch,
        infraction_epoch
    );

    // Compute the cubic slash rate
    let cubic_slash_rate =
        compute_cubic_slash_rate(storage, &params, infraction_epoch)?;

    // Collect the enqueued slashes and update their rates
    let mut eager_validator_slashes: BTreeMap<Address, Vec<Slash>> =
        BTreeMap::new();
    let mut eager_validator_slash_rates: HashMap<Address, Dec> = HashMap::new();

    // `slashPerValidator` and `slashesMap` while also updating in storage
    for enqueued_slash in enqueued_slashes.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: validator,
                nested_sub_key: _,
            },
            enqueued_slash,
        ) = enqueued_slash?;
        debug_assert_eq!(enqueued_slash.epoch, infraction_epoch);

        let slash_rate = cmp::min(
            Dec::one(),
            cmp::max(
                enqueued_slash.r#type.get_slash_rate(&params),
                cubic_slash_rate,
            ),
        );
        let updated_slash = Slash {
            epoch: enqueued_slash.epoch,
            block_height: enqueued_slash.block_height,
            r#type: enqueued_slash.r#type,
            rate: slash_rate,
        };

        let cur_slashes = eager_validator_slashes
            .entry(validator.clone())
            .or_default();
        cur_slashes.push(updated_slash);
        let cur_rate =
            eager_validator_slash_rates.entry(validator).or_default();
        let new_rate = checked!(cur_rate + slash_rate)?;
        *cur_rate = cmp::min(Dec::one(), new_rate);
    }

    // Update the epochs of enqueued slashes in storage
    enqueued_slashes_handle().update_data(storage, &params, current_epoch)?;

    // `resultSlashing`
    let mut map_validator_slash: EagerRedelegatedBondsMap = BTreeMap::new();
    for (validator, slash_rate) in eager_validator_slash_rates {
        process_validator_slash(
            storage,
            &params,
            &validator,
            slash_rate,
            current_epoch,
            &mut map_validator_slash,
        )?;
    }
    tracing::debug!("Slashed amounts for validators: {map_validator_slash:#?}");

    // Now update the remaining parts of storage

    // Write slashes themselves into storage
    for (validator, slashes) in eager_validator_slashes {
        let validator_slashes = validator_slashes_handle(&validator);
        for slash in slashes {
            validator_slashes.push(storage, slash)?;
        }
    }

    // Update the validator stakes
    for (validator, slash_amounts) in map_validator_slash {
        let mut slash_acc = token::Amount::zero();

        // Update validator sets first because it needs to be able to read
        // validator stake before we make any changes to it
        for (&epoch, &slash_amount) in &slash_amounts {
            let is_jailed_or_inactive = matches!(
                validator_state_handle(&validator)
                    .get(storage, epoch, &params)?
                    .unwrap(),
                ValidatorState::Jailed | ValidatorState::Inactive
            );
            if !is_jailed_or_inactive {
                update_validator_set::<S, Gov>(
                    storage,
                    &params,
                    &validator,
                    checked!(-slash_amount.change())?,
                    epoch,
                    Some(0),
                )?;

                events.emit(PosEvent::Slash {
                    validator: validator.clone(),
                    amount: slash_amount,
                });
            }
        }
        // Then update validator and total deltas
        for (epoch, slash_amount) in slash_amounts {
            let slash_delta = checked!(slash_amount - slash_acc)?;
            checked!(slash_acc += slash_delta)?;

            let neg_slash_delta = checked!(-slash_delta.change())?;
            update_validator_deltas::<S, Gov>(
                storage,
                &params,
                &validator,
                neg_slash_delta,
                epoch,
                Some(0),
            )?;

            let is_jailed_or_inactive = matches!(
                validator_state_handle(&validator)
                    .get(storage, epoch, &params)?
                    .unwrap(),
                ValidatorState::Jailed | ValidatorState::Inactive
            );
            update_total_deltas::<S, Gov>(
                storage,
                &params,
                neg_slash_delta,
                epoch,
                Some(0),
                !is_jailed_or_inactive,
            )?;
        }

        // TODO: should we clear some storage here as is done in Quint??
        // Possibly make the `unbonded` LazyMaps epoched so that it is done
        // automatically?
    }

    Ok(())
}

/// Slash a redelegated bond on a destination validator.
///
/// In the context of a redelegation, the function computes how much a validator
/// (the destination validator of the redelegation) should be slashed due to the
/// misbehaving of a second validator (the source validator of the
/// redelegation). The function computes how much the validator would be
/// slashed at all epochs between the current epoch (curEpoch) + 1 and the
/// current epoch + 1 + PIPELINE_OFFSET, accounting for any tokens of the
/// redelegation already unbonded.
///
/// - `src_validator` - the source validator
/// - `outgoing_redelegations` - a map from pair of epochs to int that includes
///   all the redelegations from the source validator to the destination
///   validator.
///     - The outer key is epoch at which the bond started at the source
///       validator.
///     - The inner key is epoch at which the redelegation started (the epoch at
///       which was issued).
/// - `slashes` a list of slashes of the source validator.
/// - `dest_total_redelegated_unbonded` - a map of unbonded redelegated tokens
///   at the destination validator.
/// - `slash_rate` - the rate of the slash being processed.
/// - `dest_slashed_amounts` - a map from epoch to already processed slash
///   amounts.
///
/// Adds any newly processed slash amount to `dest_slashed_amounts`.
#[allow(clippy::too_many_arguments)]
pub fn slash_validator_redelegation<S>(
    storage: &S,
    params: &OwnedPosParams,
    src_validator: &Address,
    current_epoch: Epoch,
    outgoing_redelegations: &NestedMap<Epoch, LazyMap<Epoch, token::Amount>>,
    slashes: &Slashes,
    dest_total_redelegated_unbonded: &TotalRedelegatedUnbonded,
    slash_rate: Dec,
    dest_slashed_amounts: &mut BTreeMap<Epoch, token::Amount>,
) -> Result<()>
where
    S: StorageRead,
{
    let infraction_epoch =
        checked!(current_epoch - params.slash_processing_epoch_offset())?;

    for res in outgoing_redelegations.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: bond_start,
                nested_sub_key: SubKey::Data(redel_start),
            },
            amount,
        ) = res?;

        if params.in_redelegation_slashing_window(
            infraction_epoch,
            redel_start,
            params.redelegation_end_epoch_from_start(redel_start),
        ) && bond_start <= infraction_epoch
        {
            slash_redelegation(
                storage,
                params,
                amount,
                bond_start,
                params.redelegation_end_epoch_from_start(redel_start),
                src_validator,
                current_epoch,
                slashes,
                dest_total_redelegated_unbonded,
                slash_rate,
                dest_slashed_amounts,
            )?;
        }
    }

    Ok(())
}

/// Slash a redelegated bond.
///
/// Computes how many tokens will be slashed from a redelegated bond,
/// considering that the bond may have been completely or partially unbonded and
/// that the source validator may have misbehaved within the redelegation
/// slashing window.
#[allow(clippy::too_many_arguments)]
pub fn slash_redelegation<S>(
    storage: &S,
    params: &OwnedPosParams,
    amount: token::Amount,
    bond_start: Epoch,
    redel_bond_start: Epoch,
    src_validator: &Address,
    current_epoch: Epoch,
    slashes: &Slashes,
    total_redelegated_unbonded: &TotalRedelegatedUnbonded,
    slash_rate: Dec,
    slashed_amounts: &mut BTreeMap<Epoch, token::Amount>,
) -> Result<()>
where
    S: StorageRead,
{
    tracing::debug!(
        "\nSlashing redelegation amount {} - bond start {} and \
         redel_bond_start {} - at rate {}\n",
        amount.to_string_native(),
        bond_start,
        redel_bond_start,
        slash_rate
    );

    let infraction_epoch =
        checked!(current_epoch - params.slash_processing_epoch_offset())?;

    // Slash redelegation destination validator from the next epoch only
    // as they won't be jailed
    let set_update_epoch = current_epoch.next();

    let redelegated_unbonded: Vec<token::Amount> =
        Epoch::iter_bounds_inclusive(infraction_epoch.next(), set_update_epoch)
            .map(|epoch| {
                let redelegated_unbonded = total_redelegated_unbonded
                    .at(&epoch)
                    .at(&redel_bond_start)
                    .at(src_validator)
                    .get(storage, &bond_start)?
                    .unwrap_or_default();
                Ok::<_, Error>(redelegated_unbonded)
            })
            .collect::<Result<_>>()?;
    let mut init_tot_unbonded =
        token::Amount::sum(redelegated_unbonded.into_iter())
            .ok_or_err_msg("token amount overflow")?;

    for epoch in Epoch::iter_range(set_update_epoch, params.pipeline_len) {
        let updated_total_unbonded = {
            let redelegated_unbonded = total_redelegated_unbonded
                .at(&epoch)
                .at(&redel_bond_start)
                .at(src_validator)
                .get(storage, &bond_start)?
                .unwrap_or_default();
            checked!(init_tot_unbonded + redelegated_unbonded)?
        };

        let list_slashes = slashes
            .iter(storage)?
            .map(Result::unwrap)
            .filter(|slash| {
                params.in_redelegation_slashing_window(
                    slash.epoch,
                    params.redelegation_start_epoch_from_end(redel_bond_start),
                    redel_bond_start,
                ) && bond_start <= slash.epoch
                    && slash.epoch.unchecked_add(params.slash_processing_epoch_offset())
                    // We're looking for slashes that were processed before or in the epoch
                    // in which slashes that are currently being processed
                    // occurred. Because we're slashing in the beginning of an
                    // epoch, we're also taking slashes that were processed in
                    // the infraction epoch as they would still be processed
                    // before any infraction occurred.
                        <= infraction_epoch
            })
            .collect::<Vec<_>>();

        let slashable_amount = amount
            .checked_sub(updated_total_unbonded)
            .unwrap_or_default();

        let slashed =
            apply_list_slashes(params, list_slashes.iter(), slashable_amount)?
                .mul_ceil(slash_rate)?;

        let list_slashes = slashes
            .iter(storage)?
            .map(Result::unwrap)
            .filter(|slash| {
                params.in_redelegation_slashing_window(
                    slash.epoch,
                    params.redelegation_start_epoch_from_end(redel_bond_start),
                    redel_bond_start,
                ) && bond_start <= slash.epoch
            })
            .collect::<Vec<_>>();

        let slashable_stake =
            apply_list_slashes(params, list_slashes.iter(), slashable_amount)?
                .mul_ceil(slash_rate)?;

        init_tot_unbonded = updated_total_unbonded;
        let to_slash = cmp::min(slashed, slashable_stake);
        if !to_slash.is_zero() {
            let map_value = slashed_amounts.entry(epoch).or_default();
            *map_value = checked!(map_value + to_slash)?;
        }
    }

    Ok(())
}

/// Compute slash amounts for a validator.
///
/// Computes for a given validator and a slash how much should be slashed at all
/// epochs between the current epoch (curEpoch) + 1 and the current epoch + 1 +
/// PIPELINE_OFFSET, accounting for any tokens already unbonded.
///
/// - `validator` - the misbehaving validator.
/// - `slash_rate` - the rate of the slash being processed.
/// - `slashed_amounts_map` - a map from epoch to already processed slash
///   amounts.
///
/// Returns a map that adds any newly processed slash amount to
/// `slashed_amounts_map`.
// `def slashValidator`
pub fn slash_validator<S>(
    storage: &S,
    params: &OwnedPosParams,
    validator: &Address,
    slash_rate: Dec,
    current_epoch: Epoch,
    slashed_amounts_map: &BTreeMap<Epoch, token::Amount>,
) -> Result<BTreeMap<Epoch, token::Amount>>
where
    S: StorageRead,
{
    tracing::debug!("Slashing validator {} at rate {}", validator, slash_rate);
    let infraction_epoch =
        checked!(current_epoch - params.slash_processing_epoch_offset())?;

    let total_unbonded = total_unbonded_handle(validator);
    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(validator);
    let total_bonded = total_bonded_handle(validator);
    let total_redelegated_bonded =
        validator_total_redelegated_bonded_handle(validator);

    let mut slashed_amounts = slashed_amounts_map.clone();

    let mut tot_bonds = total_bonded
        .get_data_handler()
        .iter(storage)?
        .map(Result::unwrap)
        .filter(|&(epoch, bonded)| {
            epoch <= infraction_epoch && bonded > 0.into()
        })
        .collect::<BTreeMap<_, _>>();

    let mut redelegated_bonds = tot_bonds
        .keys()
        .filter(|&epoch| {
            !total_redelegated_bonded
                .at(epoch)
                .is_empty(storage)
                .unwrap()
        })
        .map(|epoch| {
            let tot_redel_bonded = total_redelegated_bonded
                .at(epoch)
                .collect_map(storage)
                .unwrap();
            (*epoch, tot_redel_bonded)
        })
        .collect::<BTreeMap<_, _>>();

    let mut sum = token::Amount::zero();

    let eps = current_epoch
        .iter_range(params.pipeline_len)
        .collect::<Vec<_>>();
    for epoch in eps.into_iter().rev() {
        let amount = tot_bonds.iter().try_fold(
            token::Amount::zero(),
            |acc, (bond_start, bond_amount)| {
                let slashed = compute_slash_bond_at_epoch(
                    storage,
                    params,
                    validator,
                    epoch,
                    infraction_epoch,
                    *bond_start,
                    *bond_amount,
                    redelegated_bonds.get(bond_start),
                    slash_rate,
                )?;
                Ok::<token::Amount, Error>(checked!(acc + slashed)?)
            },
        )?;

        let new_bonds = total_unbonded.at(&epoch);
        tot_bonds = new_bonds
            .collect_map(storage)
            .unwrap()
            .into_iter()
            .filter(|(ep, _)| *ep <= infraction_epoch)
            .collect::<BTreeMap<_, _>>();

        let new_redelegated_bonds = tot_bonds
            .keys()
            .filter(|&ep| {
                !total_redelegated_unbonded.at(ep).is_empty(storage).unwrap()
            })
            .map(|ep| {
                (
                    *ep,
                    total_redelegated_unbonded
                        .at(&epoch)
                        .at(ep)
                        .collect_map(storage)
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        redelegated_bonds = new_redelegated_bonds;

        // `newSum`
        checked!(sum += amount)?;

        // `newSlashesMap`
        let cur = slashed_amounts.entry(epoch).or_default();
        *cur = checked!(cur + sum)?;
    }
    // Hack - should this be done differently? (think this is safe)
    let pipeline_epoch = checked!(current_epoch + params.pipeline_len)?;
    let last_amt = slashed_amounts
        .get(
            &pipeline_epoch
                .prev()
                .expect("Pipeline epoch must have prev"),
        )
        .cloned()
        .unwrap();
    slashed_amounts.insert(pipeline_epoch, last_amt);

    Ok(slashed_amounts)
}

/// Get the remaining token amount in a bond after applying a set of slashes.
///
/// - `validator` - the bond's validator
/// - `epoch` - the latest slash epoch to consider.
/// - `start` - the start epoch of the bond
/// - `redelegated_bonds`
pub fn compute_bond_at_epoch<S>(
    storage: &S,
    params: &OwnedPosParams,
    validator: &Address,
    epoch: Epoch,
    start: Epoch,
    amount: token::Amount,
    redelegated_bonds: Option<&EagerRedelegatedBondsMap>,
) -> Result<token::Amount>
where
    S: StorageRead,
{
    let list_slashes = validator_slashes_handle(validator)
        .iter(storage)?
        .map(Result::unwrap)
        .filter(|slash| {
            start <= slash.epoch
                && slash
                    .epoch
                    .unchecked_add(params.slash_processing_epoch_offset())
                    <= epoch
        })
        .collect::<Vec<_>>();

    let slash_epoch_filter = |e: Epoch| {
        e.unchecked_add(params.slash_processing_epoch_offset()) <= epoch
    };

    let result_fold = redelegated_bonds
        .map(|redelegated_bonds| {
            fold_and_slash_redelegated_bonds(
                storage,
                params,
                redelegated_bonds,
                start,
                list_slashes.iter(),
                slash_epoch_filter,
            )
        })
        .transpose()?
        .unwrap_or_default();

    let total_not_redelegated =
        checked!(amount - result_fold.total_redelegated)?;
    let after_not_redelegated =
        apply_list_slashes(params, list_slashes.iter(), total_not_redelegated)?;

    Ok(checked!(
        after_not_redelegated + result_fold.total_after_slashing
    )?)
}

/// Uses `fn compute_bond_at_epoch` to compute the token amount to slash in
/// order to prevent overslashing.
#[allow(clippy::too_many_arguments)]
pub fn compute_slash_bond_at_epoch<S>(
    storage: &S,
    params: &OwnedPosParams,
    validator: &Address,
    epoch: Epoch,
    infraction_epoch: Epoch,
    bond_start: Epoch,
    bond_amount: token::Amount,
    redelegated_bonds: Option<&EagerRedelegatedBondsMap>,
    slash_rate: Dec,
) -> Result<token::Amount>
where
    S: StorageRead,
{
    let amount_due = compute_bond_at_epoch(
        storage,
        params,
        validator,
        infraction_epoch,
        bond_start,
        bond_amount,
        redelegated_bonds,
    )?
    .mul_ceil(slash_rate)?;
    let slashable_amount = compute_bond_at_epoch(
        storage,
        params,
        validator,
        epoch,
        bond_start,
        bond_amount,
        redelegated_bonds,
    )?;
    Ok(cmp::min(amount_due, slashable_amount))
}

/// Find slashes applicable to a validator with inclusive `start` and exclusive
/// `end` epoch.
#[allow(dead_code)]
pub fn find_slashes_in_range<S>(
    storage: &S,
    start: Epoch,
    end: Option<Epoch>,
    validator: &Address,
) -> Result<BTreeMap<Epoch, Dec>>
where
    S: StorageRead,
{
    let mut slashes = BTreeMap::<Epoch, Dec>::new();
    for slash in validator_slashes_handle(validator).iter(storage)? {
        let slash = slash?;
        if start <= slash.epoch
            && end.map(|end| slash.epoch < end).unwrap_or(true)
        {
            let cur_rate = slashes.entry(slash.epoch).or_default();
            let new_rate = checked!(cur_rate + slash.rate)?;
            *cur_rate = cmp::min(new_rate, Dec::one());
        }
    }
    Ok(slashes)
}

/// Computes how much remains from an amount of tokens after applying a list of
/// slashes.
///
/// - `slashes` - a list of slashes ordered by misbehaving epoch.
/// - `amount` - the amount of slashable tokens.
// `def applyListSlashes`
pub fn apply_list_slashes<'a>(
    params: &OwnedPosParams,
    slashes: impl Iterator<Item = &'a Slash>,
    amount: token::Amount,
) -> std::result::Result<token::Amount, arith::Error> {
    let mut final_amount = amount;
    let mut computed_slashes = BTreeMap::<Epoch, token::Amount>::new();
    for slash in slashes {
        let slashed_amount =
            compute_slashable_amount(params, slash, amount, &computed_slashes)?;
        final_amount =
            final_amount.checked_sub(slashed_amount).unwrap_or_default();
        computed_slashes.insert(slash.epoch, slashed_amount);
    }
    Ok(final_amount)
}

/// Computes how much is left from a bond or unbond after applying a slash given
/// that a set of slashes may have been previously applied.
// `def computeSlashableAmount`
pub fn compute_slashable_amount(
    params: &OwnedPosParams,
    slash: &Slash,
    amount: token::Amount,
    computed_slashes: &BTreeMap<Epoch, token::Amount>,
) -> std::result::Result<token::Amount, arith::Error> {
    let updated_amount = computed_slashes
        .iter()
        .filter(|(epoch, _)| {
            // Keep slashes that have been applied and processed before the
            // current slash occurred. We use `<=` because slashes processed at
            // `slash.epoch` (at the start of the epoch) are also processed
            // before this slash occurred.
            epoch.unchecked_add(params.slash_processing_epoch_offset())
                <= slash.epoch
        })
        .fold(amount, |acc, (_, &amnt)| {
            acc.checked_sub(amnt).unwrap_or_default()
        });
    updated_amount.mul_ceil(slash.rate)
}

/// Find all slashes and the associated validators in the PoS system
pub fn find_all_slashes<S>(storage: &S) -> Result<HashMap<Address, Vec<Slash>>>
where
    S: StorageRead,
{
    let mut slashes: HashMap<Address, Vec<Slash>> = HashMap::new();
    let slashes_iter = iter_prefix_bytes(
        storage,
        storage_key::slashes_prefix(),
    )?
    .filter_map(|result| {
        if let Ok((key, val_bytes)) = result {
            if let Some(validator) = storage_key::is_validator_slashes_key(&key)
            {
                let slash: Slash =
                    BorshDeserialize::try_from_slice(&val_bytes).ok()?;
                return Some((validator, slash));
            }
        }
        None
    });

    slashes_iter.for_each(|(address, slash)| match slashes.get(&address) {
        Some(vec) => {
            let mut vec = vec.clone();
            vec.push(slash);
            slashes.insert(address, vec);
        }
        None => {
            slashes.insert(address, vec![slash]);
        }
    });
    Ok(slashes)
}

/// Collect the details of all of the enqueued slashes to be processed in future
/// epochs into a nested map
pub fn find_all_enqueued_slashes<S>(
    storage: &S,
    epoch: Epoch,
) -> Result<HashMap<Address, BTreeMap<Epoch, Vec<Slash>>>>
where
    S: StorageRead,
{
    let mut enqueued = HashMap::<Address, BTreeMap<Epoch, Vec<Slash>>>::new();
    for res in enqueued_slashes_handle().get_data_handler().iter(storage)? {
        let (
            NestedSubKey::Data {
                key: processing_epoch,
                nested_sub_key:
                    NestedSubKey::Data {
                        key: address,
                        nested_sub_key: _,
                    },
            },
            slash,
        ) = res?;
        if processing_epoch <= epoch {
            continue;
        }

        let slashes = enqueued
            .entry(address)
            .or_default()
            .entry(processing_epoch)
            .or_default();
        slashes.push(slash);
    }
    Ok(enqueued)
}

/// Find PoS slashes applied to a validator, if any
pub fn find_validator_slashes<S>(
    storage: &S,
    validator: &Address,
) -> Result<Vec<Slash>>
where
    S: StorageRead,
{
    validator_slashes_handle(validator).iter(storage)?.collect()
}

/// Compute a token amount after slashing, given the initial amount and a set of
/// slashes. It is assumed that the input `slashes` are those committed while
/// the `amount` was contributing to voting power.
pub fn get_slashed_amount(
    params: &PosParams,
    amount: token::Amount,
    slashes: &BTreeMap<Epoch, Dec>,
) -> Result<token::Amount> {
    let mut updated_amount = amount;
    let mut computed_amounts = Vec::<SlashedAmount>::new();

    for (&infraction_epoch, &slash_rate) in slashes {
        let mut computed_to_remove = BTreeSet::<Reverse<usize>>::new();
        for (ix, slashed_amount) in computed_amounts.iter().enumerate() {
            // Update amount with slashes that happened more than unbonding_len
            // epochs before this current slash
            if checked!(
                slashed_amount.epoch + params.slash_processing_epoch_offset()
            )? <= infraction_epoch
            {
                updated_amount = updated_amount
                    .checked_sub(slashed_amount.amount)
                    .unwrap_or_default();
                computed_to_remove.insert(Reverse(ix));
            }
        }
        // Invariant: `computed_to_remove` must be in reverse ord to avoid
        // left-shift of the `computed_amounts` after call to `remove`
        // invalidating the rest of the indices.
        for item in computed_to_remove {
            computed_amounts.remove(item.0);
        }
        computed_amounts.push(SlashedAmount {
            amount: updated_amount.mul_ceil(slash_rate)?,
            epoch: infraction_epoch,
        });
    }

    let total_computed_amounts = token::Amount::sum(
        computed_amounts.into_iter().map(|slashed| slashed.amount),
    )
    .ok_or_err_msg("token amount overflow")?;

    let final_amount = updated_amount
        .checked_sub(total_computed_amounts)
        .unwrap_or_default();

    Ok(final_amount)
}

/// Compute the total amount of tokens from a set of unbonds, both redelegated
/// and not, after applying slashes. Used in `unbond_tokens`.
// `def computeAmountAfterSlashingUnbond`
pub fn compute_amount_after_slashing_unbond<S>(
    storage: &S,
    params: &OwnedPosParams,
    unbonds: &BTreeMap<Epoch, token::Amount>,
    redelegated_unbonds: &EagerRedelegatedUnbonds,
    slashes: Vec<Slash>,
) -> Result<ResultSlashing>
where
    S: StorageRead,
{
    let mut result_slashing = ResultSlashing::default();
    for (&start_epoch, amount) in unbonds {
        // `val listSlashes`
        let list_slashes: Vec<Slash> = slashes
            .iter()
            .filter(|slash| slash.epoch >= start_epoch)
            .cloned()
            .collect();
        // `val resultFold`
        let result_fold = if let Some(redelegated_unbonds) =
            redelegated_unbonds.get(&start_epoch)
        {
            fold_and_slash_redelegated_bonds(
                storage,
                params,
                redelegated_unbonds,
                start_epoch,
                list_slashes.iter(),
                |_| true,
            )?
        } else {
            FoldRedelegatedBondsResult::default()
        };
        // `val totalNoRedelegated`
        let total_not_redelegated = amount
            .checked_sub(result_fold.total_redelegated)
            .unwrap_or_default();
        // `val afterNoRedelegated`
        let after_not_redelegated = apply_list_slashes(
            params,
            list_slashes.iter(),
            total_not_redelegated,
        )?;
        // `val amountAfterSlashing`
        let amount_after_slashing =
            checked!(after_not_redelegated + result_fold.total_after_slashing)?;
        // Accumulation step
        result_slashing.sum =
            checked!(result_slashing.sum + amount_after_slashing)?;
        result_slashing
            .epoch_map
            .insert(start_epoch, amount_after_slashing);
    }
    Ok(result_slashing)
}

/// Compute the total amount of tokens from a set of unbonds, both redelegated
/// and not, after applying slashes. Used in `withdraw_tokens`.
// `def computeAmountAfterSlashingWithdraw`
pub fn compute_amount_after_slashing_withdraw<S>(
    storage: &S,
    params: &OwnedPosParams,
    unbonds_and_redelegated_unbonds: &BTreeMap<
        (Epoch, Epoch),
        (token::Amount, EagerRedelegatedBondsMap),
    >,
    slashes: Vec<Slash>,
) -> Result<ResultSlashing>
where
    S: StorageRead,
{
    let mut result_slashing = ResultSlashing::default();

    for ((start_epoch, withdraw_epoch), (amount, redelegated_unbonds)) in
        unbonds_and_redelegated_unbonds.iter()
    {
        // TODO: check if slashes in the same epoch can be
        // folded into one effective slash
        let end_epoch = checked!(
            withdraw_epoch
                - params.unbonding_len
                - params.cubic_slashing_window_length
        )?;
        // Find slashes that apply to `start_epoch..end_epoch`
        let list_slashes = slashes
            .iter()
            .filter(|slash| {
                // Started before the slash occurred
                start_epoch <= &slash.epoch
                    // Ends after the slash
                    && end_epoch > slash.epoch
            })
            .cloned()
            .collect::<Vec<_>>();

        // Find the sum and the sum after slashing of the redelegated unbonds
        let result_fold = fold_and_slash_redelegated_bonds(
            storage,
            params,
            redelegated_unbonds,
            *start_epoch,
            list_slashes.iter(),
            |_| true,
        )?;

        // Unbond amount that didn't come from a redelegation
        let total_not_redelegated =
            checked!(amount - result_fold.total_redelegated)?;
        // Find how much remains after slashing non-redelegated amount
        let after_not_redelegated = apply_list_slashes(
            params,
            list_slashes.iter(),
            total_not_redelegated,
        )?;

        // Add back the unbond and redelegated unbond amount after slashing
        let amount_after_slashing =
            checked!(after_not_redelegated + result_fold.total_after_slashing)?;

        result_slashing.sum =
            checked!(result_slashing.sum + amount_after_slashing)?;
        result_slashing
            .epoch_map
            .insert(*start_epoch, amount_after_slashing);
    }

    Ok(result_slashing)
}

/// Process a slash by (i) slashing the misbehaving validator; and (ii) any
/// validator to which it has redelegated some tokens and the slash misbehaving
/// epoch is within the redelegation slashing window.
///
/// `validator` - the misbehaving validator.
/// `slash_rate` - the slash rate.
/// `slashed_amounts_map` - a map from validator address to a map from epoch to
/// already processed slash amounts.
///
/// Adds any newly processed slash amount of any involved validator to
/// `slashed_amounts_map`.
// Quint `processSlash`
fn process_validator_slash<S>(
    storage: &mut S,
    params: &PosParams,
    validator: &Address,
    slash_rate: Dec,
    current_epoch: Epoch,
    slashed_amount_map: &mut EagerRedelegatedBondsMap,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    // `resultSlashValidator
    let result_slash = slash_validator(
        storage,
        params,
        validator,
        slash_rate,
        current_epoch,
        &slashed_amount_map
            .get(validator)
            .cloned()
            .unwrap_or_default(),
    )?;

    // `updatedSlashedAmountMap`
    let validator_slashes =
        slashed_amount_map.entry(validator.clone()).or_default();
    *validator_slashes = result_slash;

    // `outgoingRedelegation`
    let outgoing_redelegations =
        validator_outgoing_redelegations_handle(validator);

    // Final loop in `processSlash`
    let dest_validators = outgoing_redelegations
        .iter(storage)?
        .map(|res| {
            let (
                NestedSubKey::Data {
                    key: dest_validator,
                    nested_sub_key: _,
                },
                _redelegation,
            ) = res?;
            Ok(dest_validator)
        })
        .collect::<Result<BTreeSet<_>>>()?;

    for dest_validator in dest_validators {
        let to_modify = slashed_amount_map
            .entry(dest_validator.clone())
            .or_default();

        tracing::debug!(
            "Slashing {} redelegation to {}",
            validator,
            &dest_validator
        );

        // `slashValidatorRedelegation`
        slash_validator_redelegation(
            storage,
            params,
            validator,
            current_epoch,
            &outgoing_redelegations.at(&dest_validator),
            &validator_slashes_handle(validator),
            &validator_total_redelegated_unbonded_handle(&dest_validator),
            slash_rate,
            to_modify,
        )?;
    }

    Ok(())
}

/// Calculate the cubic slashing rate using all slashes within a window around
/// the given infraction epoch. There is no cap on the rate applied within this
/// function.
fn compute_cubic_slash_rate<S>(
    storage: &S,
    params: &PosParams,
    infraction_epoch: Epoch,
) -> Result<Dec>
where
    S: StorageRead,
{
    tracing::debug!(
        "Computing the cubic slash rate for infraction epoch \
         {infraction_epoch}."
    );
    let mut sum_vp_fraction = Dec::zero();
    let (start_epoch, end_epoch) =
        params.cubic_slash_epoch_window(infraction_epoch);

    for epoch in Epoch::iter_bounds_inclusive(start_epoch, end_epoch) {
        let consensus_stake =
            Dec::try_from(get_total_consensus_stake(storage, epoch, params)?)
                .into_storage_result()?;
        tracing::debug!(
            "Total consensus stake in epoch {}: {}",
            epoch,
            consensus_stake
        );
        let processing_epoch =
            checked!(epoch + params.slash_processing_epoch_offset())?;
        let slashes = enqueued_slashes_handle().at(&processing_epoch);
        let infracting_stake =
            slashes.iter(storage)?.try_fold(Dec::zero(), |acc, res| {
                let (
                    NestedSubKey::Data {
                        key: validator,
                        nested_sub_key: _,
                    },
                    _slash,
                ) = res?;

                let validator_stake =
                    read_validator_stake(storage, params, &validator, epoch)?;
                // tracing::debug!("Val {} stake: {}", &validator,
                // validator_stake);

                let stake =
                    Dec::try_from(validator_stake).into_storage_result()?;
                Ok::<Dec, Error>(checked!(acc + stake)?)
            })?;
        sum_vp_fraction =
            checked!(sum_vp_fraction + (infracting_stake / consensus_stake))?;
    }
    let nine = Dec::from(9_u64);
    let cubic_rate = checked!(nine * sum_vp_fraction * sum_vp_fraction)?;
    tracing::debug!("Cubic slash rate: {}", cubic_rate);
    Ok(cubic_rate)
}
