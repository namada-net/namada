//! PoS functions for reading and writing to storage and lazy collection handles
//! associated with given `storage_key`s.

use std::collections::BTreeSet;

use namada_account::protocol_pk_key;
use namada_core::address::Address;
use namada_core::arith::checked;
use namada_core::chain::Epoch;
use namada_core::collections::HashSet;
use namada_core::dec::Dec;
use namada_core::key::{common, tm_consensus_key_raw_hash};
use namada_core::token;
use namada_systems::governance;

use crate::lazy_map::NestedSubKey;
use crate::storage_key::consensus_keys_key;
use crate::types::{
    BelowCapacityValidatorSets, BondId, Bonds, CommissionRates,
    ConsensusValidatorSets, DelegationTargets, DelegatorRedelegatedBonded,
    DelegatorRedelegatedUnbonded, EpochedSlashes, IncomingRedelegations,
    LivenessMissedVotes, LivenessSumMissedVotes, OutgoingRedelegations,
    ReverseOrdTokenAmount, RewardsAccumulator, RewardsProducts, Slashes,
    TotalConsensusStakes, TotalDeltas, TotalRedelegatedBonded,
    TotalRedelegatedUnbonded, Unbonds, ValidatorAddresses,
    ValidatorConsensusKeys, ValidatorDeltas, ValidatorEthColdKeys,
    ValidatorEthHotKeys, ValidatorMetaData, ValidatorProtocolKeys,
    ValidatorSetPositions, ValidatorState, ValidatorStates,
    ValidatorTotalUnbonded, WeightedValidator,
};
use crate::{
    LazyCollection, LazySet, MetadataError, OwnedPosParams, PosParams, Result,
    StorageRead, StorageWrite, storage_key,
};

// ---- Storage handles ----

/// Get the storage handle to the epoched consensus validator set
pub fn consensus_validator_set_handle() -> ConsensusValidatorSets {
    let key = storage_key::consensus_validator_set_key();
    ConsensusValidatorSets::open(key)
}

/// Get the storage handle to the epoched below-capacity validator set
pub fn below_capacity_validator_set_handle() -> BelowCapacityValidatorSets {
    let key = storage_key::below_capacity_validator_set_key();
    BelowCapacityValidatorSets::open(key)
}

/// Get the storage handle to a PoS validator's consensus key (used for
/// signing block votes).
pub fn validator_consensus_key_handle(
    validator: &Address,
) -> ValidatorConsensusKeys {
    let key = storage_key::validator_consensus_key_key(validator);
    ValidatorConsensusKeys::open(key)
}

/// Get the storage handle to a PoS validator's protocol key key.
pub fn validator_protocol_key_handle(
    validator: &Address,
) -> ValidatorProtocolKeys {
    let key = protocol_pk_key(validator);
    ValidatorProtocolKeys::open(key)
}

/// Get the storage handle to a PoS validator's eth hot key.
pub fn validator_eth_hot_key_handle(
    validator: &Address,
) -> ValidatorEthHotKeys {
    let key = storage_key::validator_eth_hot_key_key(validator);
    ValidatorEthHotKeys::open(key)
}

/// Get the storage handle to a PoS validator's eth cold key.
pub fn validator_eth_cold_key_handle(
    validator: &Address,
) -> ValidatorEthColdKeys {
    let key = storage_key::validator_eth_cold_key_key(validator);
    ValidatorEthColdKeys::open(key)
}

/// Get the storage handle to the total consensus validator stake
pub fn total_consensus_stake_handle() -> TotalConsensusStakes {
    let key = storage_key::total_consensus_stake_key();
    TotalConsensusStakes::open(key)
}

/// Get the storage handle to a PoS validator's state
pub fn validator_state_handle(validator: &Address) -> ValidatorStates {
    let key = storage_key::validator_state_key(validator);
    ValidatorStates::open(key)
}

/// Get the storage handle to a PoS validator's deltas
pub fn validator_deltas_handle(validator: &Address) -> ValidatorDeltas {
    let key = storage_key::validator_deltas_key(validator);
    ValidatorDeltas::open(key)
}

/// Get the storage handle to the total deltas
pub fn total_deltas_handle() -> TotalDeltas {
    let key = storage_key::total_deltas_key();
    TotalDeltas::open(key)
}

/// Get the storage handle to the set of all validators
pub fn validator_addresses_handle() -> ValidatorAddresses {
    let key = storage_key::validator_addresses_key();
    ValidatorAddresses::open(key)
}

/// Get the storage handle to a PoS validator's commission rate
pub fn validator_commission_rate_handle(
    validator: &Address,
) -> CommissionRates {
    let key = storage_key::validator_commission_rate_key(validator);
    CommissionRates::open(key)
}

/// Get the storage handle to a bond, which is dynamically updated with when
/// unbonding
pub fn bond_handle(source: &Address, validator: &Address) -> Bonds {
    let bond_id = BondId {
        source: source.clone(),
        validator: validator.clone(),
    };
    let key = storage_key::bond_key(&bond_id);
    Bonds::open(key)
}

/// Get the storage handle to a validator's total bonds, which are not updated
/// due to unbonding
pub fn total_bonded_handle(validator: &Address) -> Bonds {
    let key = storage_key::validator_total_bonded_key(validator);
    Bonds::open(key)
}

/// Get the storage handle to an unbond
pub fn unbond_handle(source: &Address, validator: &Address) -> Unbonds {
    let bond_id = BondId {
        source: source.clone(),
        validator: validator.clone(),
    };
    let key = storage_key::unbond_key(&bond_id);
    Unbonds::open(key)
}

/// Get the storage handle to a validator's total-unbonded map
pub fn total_unbonded_handle(validator: &Address) -> ValidatorTotalUnbonded {
    let key = storage_key::validator_total_unbonded_key(validator);
    ValidatorTotalUnbonded::open(key)
}

/// Get the storage handle to a PoS validator's deltas
pub fn validator_set_positions_handle() -> ValidatorSetPositions {
    let key = storage_key::validator_set_positions_key();
    ValidatorSetPositions::open(key)
}

/// Get the storage handle to a PoS validator's slashes
pub fn validator_slashes_handle(validator: &Address) -> Slashes {
    let key = storage_key::validator_slashes_key(validator);
    Slashes::open(key)
}

/// Get the storage handle to list of all slashes to be processed and ultimately
/// placed in the `validator_slashes_handle`
pub fn enqueued_slashes_handle() -> EpochedSlashes {
    let key = storage_key::enqueued_slashes_key();
    EpochedSlashes::open(key)
}

/// Get the storage handle to the rewards accumulator for the consensus
/// validators in a given epoch
pub fn rewards_accumulator_handle() -> RewardsAccumulator {
    let key = storage_key::consensus_validator_rewards_accumulator_key();
    RewardsAccumulator::open(key)
}

/// Get the storage handle to a validator's rewards products
pub fn validator_rewards_products_handle(
    validator: &Address,
) -> RewardsProducts {
    let key = storage_key::validator_rewards_product_key(validator);
    RewardsProducts::open(key)
}

/// Get the storage handle to a validator's incoming redelegations
pub fn validator_incoming_redelegations_handle(
    validator: &Address,
) -> IncomingRedelegations {
    let key = storage_key::validator_incoming_redelegations_key(validator);
    IncomingRedelegations::open(key)
}

/// Get the storage handle to a validator's outgoing redelegations
pub fn validator_outgoing_redelegations_handle(
    validator: &Address,
) -> OutgoingRedelegations {
    let key = storage_key::validator_outgoing_redelegations_key(validator);
    OutgoingRedelegations::open(key)
}

/// Get the storage handle to a validator's total redelegated bonds
pub fn validator_total_redelegated_bonded_handle(
    validator: &Address,
) -> TotalRedelegatedBonded {
    let key = storage_key::validator_total_redelegated_bonded_key(validator);
    TotalRedelegatedBonded::open(key)
}

/// Get the storage handle to a validator's outgoing redelegations
pub fn validator_total_redelegated_unbonded_handle(
    validator: &Address,
) -> TotalRedelegatedUnbonded {
    let key = storage_key::validator_total_redelegated_unbonded_key(validator);
    TotalRedelegatedUnbonded::open(key)
}

/// Get the storage handle to a delegator's redelegated bonds information
pub fn delegator_redelegated_bonds_handle(
    delegator: &Address,
) -> DelegatorRedelegatedBonded {
    let key = storage_key::delegator_redelegated_bonds_key(delegator);
    DelegatorRedelegatedBonded::open(key)
}

/// Get the storage handle to a delegator's redelegated unbonds information
pub fn delegator_redelegated_unbonds_handle(
    delegator: &Address,
) -> DelegatorRedelegatedUnbonded {
    let key = storage_key::delegator_redelegated_unbonds_key(delegator);
    DelegatorRedelegatedUnbonded::open(key)
}

/// Get the storage handle to the missed votes for liveness tracking
pub fn liveness_missed_votes_handle() -> LivenessMissedVotes {
    let key = storage_key::liveness_missed_votes_key();
    LivenessMissedVotes::open(key)
}

/// Get the storage handle to the sum of missed votes for liveness tracking
pub fn liveness_sum_missed_votes_handle() -> LivenessSumMissedVotes {
    let key = storage_key::liveness_sum_missed_votes_key();
    LivenessSumMissedVotes::open(key)
}

/// Get the storage handle to the total active deltas
pub fn total_active_deltas_handle() -> TotalDeltas {
    let key = storage_key::total_active_deltas_key();
    TotalDeltas::open(key)
}

/// Get the storage handle to the delegation targets map
pub fn delegation_targets_handle(delegator: &Address) -> DelegationTargets {
    let key = storage_key::delegation_targets_key(delegator);
    DelegationTargets::open(key)
}

// ---- Storage read + write ----

/// Read owned PoS parameters
pub fn read_owned_pos_params<S>(storage: &S) -> Result<OwnedPosParams>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::params_key())?
        .expect("PosParams should always exist in storage after genesis"))
}

/// Read PoS parameters
pub fn read_pos_params<S, Gov>(storage: &S) -> Result<PosParams>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let params = read_owned_pos_params(storage)?;
    read_non_pos_owned_params::<S, Gov>(storage, params)
}

/// Read non-PoS-owned parameters to add them to `OwnedPosParams` to construct
/// `PosParams`.
pub fn read_non_pos_owned_params<S, Gov>(
    storage: &S,
    owned: OwnedPosParams,
) -> Result<PosParams>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let max_proposal_period = Gov::max_proposal_period(storage)?;
    Ok(PosParams {
        owned,
        max_proposal_period,
    })
}

/// Write PoS parameters
pub fn write_pos_params<S>(
    storage: &mut S,
    params: &OwnedPosParams,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::params_key();
    storage.write(&key, params)
}

/// Get the validator address given the raw hash of the Tendermint consensus key
pub fn find_validator_by_raw_hash<S>(
    storage: &S,
    raw_hash: impl AsRef<str>,
) -> Result<Option<Address>>
where
    S: StorageRead,
{
    let key = storage_key::validator_address_raw_hash_key(raw_hash);
    storage.read(&key)
}

/// Write PoS validator's address raw hash.
pub fn write_validator_address_raw_hash<S>(
    storage: &mut S,
    validator: &Address,
    consensus_key: &common::PublicKey,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let raw_hash = tm_consensus_key_raw_hash(consensus_key);
    storage.write(
        &storage_key::validator_address_raw_hash_key(raw_hash),
        validator,
    )
}

/// Read PoS validator's max commission rate change.
pub fn read_validator_max_commission_rate_change<S>(
    storage: &S,
    validator: &Address,
) -> Result<Option<Dec>>
where
    S: StorageRead,
{
    let key = storage_key::validator_max_commission_rate_change_key(validator);
    storage.read(&key)
}

/// Write PoS validator's max commission rate change.
pub fn write_validator_max_commission_rate_change<S>(
    storage: &mut S,
    validator: &Address,
    change: Dec,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::validator_max_commission_rate_change_key(validator);
    storage.write(&key, change)
}

/// Read the most recent slash epoch for the given epoch
pub fn read_validator_last_slash_epoch<S>(
    storage: &S,
    validator: &Address,
) -> Result<Option<Epoch>>
where
    S: StorageRead,
{
    let key = storage_key::validator_last_slash_key(validator);
    storage.read(&key)
}

/// Write the most recent slash epoch for the given epoch
pub fn write_validator_last_slash_epoch<S>(
    storage: &mut S,
    validator: &Address,
    epoch: Epoch,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::validator_last_slash_key(validator);
    storage.write(&key, epoch)
}

/// Read last block proposer address.
pub fn read_last_block_proposer_address<S>(
    storage: &S,
) -> Result<Option<Address>>
where
    S: StorageRead,
{
    let key = storage_key::last_block_proposer_key();
    storage.read(&key)
}

/// Write last block proposer address.
pub fn write_last_block_proposer_address<S>(
    storage: &mut S,
    address: Address,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::last_block_proposer_key();
    storage.write(&key, address)
}

/// Read last epoch's staked ratio.
pub fn read_last_staked_ratio<S>(storage: &S) -> Result<Option<Dec>>
where
    S: StorageRead,
{
    let key = storage_key::last_staked_ratio_key();
    storage.read(&key)
}

/// Write last epoch's staked ratio.
pub fn write_last_staked_ratio<S>(storage: &mut S, ratio: Dec) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::last_staked_ratio_key();
    storage.write(&key, ratio)
}

/// Read last epoch's PoS inflation amount.
pub fn read_last_pos_inflation_amount<S>(
    storage: &S,
) -> Result<Option<token::Amount>>
where
    S: StorageRead,
{
    let key = storage_key::last_pos_inflation_amount_key();
    storage.read(&key)
}

/// Write last epoch's pos inflation amount.
pub fn write_last_pos_inflation_amount<S>(
    storage: &mut S,
    inflation: token::Amount,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::last_pos_inflation_amount_key();
    storage.write(&key, inflation)
}

/// Read the validator state
pub fn read_validator_state<S, Gov>(
    storage: &S,
    validator: &Address,
    epoch: Epoch,
) -> Result<Option<ValidatorState>>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let params = read_pos_params::<S, Gov>(storage)?;
    validator_state_handle(validator).get(storage, epoch, &params)
}

/// Read PoS validator's delta value.
pub fn read_validator_deltas_value<S>(
    storage: &S,
    validator: &Address,
    epoch: &namada_core::chain::Epoch,
) -> Result<Option<token::Change>>
where
    S: StorageRead,
{
    let handle = validator_deltas_handle(validator);
    handle.get_delta_val(storage, *epoch)
}

/// Read PoS validator's stake (sum of deltas).
/// For non-validators and validators with `0` stake, this returns the default -
/// `token::Amount::zero()`.
pub fn read_validator_stake<S>(
    storage: &S,
    params: &PosParams,
    validator: &Address,
    epoch: namada_core::chain::Epoch,
) -> Result<token::Amount>
where
    S: StorageRead,
{
    let handle = validator_deltas_handle(validator);
    let amount = handle
        .get_sum(storage, epoch, params)?
        .map(|change| {
            debug_assert!(change.non_negative());
            token::Amount::from_change(change)
        })
        .unwrap_or_default();
    Ok(amount)
}

/// Add or remove PoS validator's stake delta value
pub fn update_validator_deltas<S, Gov>(
    storage: &mut S,
    params: &OwnedPosParams,
    validator: &Address,
    delta: token::Change,
    current_epoch: namada_core::chain::Epoch,
    offset_opt: Option<u64>,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
    Gov: governance::Read<S>,
{
    let handle = validator_deltas_handle(validator);
    let offset = offset_opt.unwrap_or(params.pipeline_len);
    let offset_epoch = checked!(current_epoch + offset)?;
    let val = handle
        .get_delta_val(storage, offset_epoch)?
        .unwrap_or_default();
    handle.set::<S, Gov>(
        storage,
        val.checked_add(delta)
            .expect("Validator deltas updated amount should not overflow"),
        current_epoch,
        offset,
    )
}

/// Read PoS total stake (sum of deltas).
pub fn read_total_stake<S>(
    storage: &S,
    params: &PosParams,
    epoch: namada_core::chain::Epoch,
) -> Result<token::Amount>
where
    S: StorageRead,
{
    let handle = total_deltas_handle();
    let amnt = handle
        .get_sum(storage, epoch, params)?
        .map(|change| {
            debug_assert!(change.non_negative());
            token::Amount::from_change(change)
        })
        .unwrap_or_default();
    Ok(amnt)
}

/// Read PoS total stake (sum of deltas).
pub fn read_total_active_stake<S>(
    storage: &S,
    params: &PosParams,
    epoch: namada_core::chain::Epoch,
) -> Result<token::Amount>
where
    S: StorageRead,
{
    let handle = total_active_deltas_handle();
    let amnt = handle
        .get_sum(storage, epoch, params)?
        .map(|change| {
            debug_assert!(change.non_negative());
            token::Amount::from_change(change)
        })
        .unwrap_or_default();
    Ok(amnt)
}

/// Read all addresses from consensus validator set.
pub fn read_consensus_validator_set_addresses<S>(
    storage: &S,
    epoch: namada_core::chain::Epoch,
) -> Result<HashSet<Address>>
where
    S: StorageRead,
{
    consensus_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .map(|res| res.map(|(_sub_key, address)| address))
        .collect()
}

/// Read all addresses from below-capacity validator set.
pub fn read_below_capacity_validator_set_addresses<S>(
    storage: &S,
    epoch: namada_core::chain::Epoch,
) -> Result<HashSet<Address>>
where
    S: StorageRead,
{
    below_capacity_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .map(|res| res.map(|(_sub_key, address)| address))
        .collect()
}

/// Read all addresses from the below-threshold set
pub fn read_below_threshold_validator_set_addresses<S, Gov>(
    storage: &S,
    epoch: namada_core::chain::Epoch,
) -> Result<HashSet<Address>>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let params = read_pos_params::<S, Gov>(storage)?;
    Ok(validator_addresses_handle()
        .at(&epoch)
        .iter(storage)?
        .map(Result::unwrap)
        .filter(|address| {
            matches!(
                validator_state_handle(address).get(storage, epoch, &params),
                Ok(Some(ValidatorState::BelowThreshold))
            )
        })
        .collect())
}

/// Read all addresses from consensus validator set with their stake.
pub fn read_consensus_validator_set_addresses_with_stake<S>(
    storage: &S,
    epoch: namada_core::chain::Epoch,
) -> Result<BTreeSet<WeightedValidator>>
where
    S: StorageRead,
{
    consensus_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .map(|res| {
            res.map(
                |(
                    NestedSubKey::Data {
                        key: bonded_stake,
                        nested_sub_key: _,
                    },
                    address,
                )| {
                    WeightedValidator {
                        address,
                        bonded_stake,
                    }
                },
            )
        })
        .collect()
}

/// Count the number of consensus validators
pub fn get_num_consensus_validators<S>(
    storage: &S,
    epoch: namada_core::chain::Epoch,
) -> Result<u64>
where
    S: StorageRead,
{
    Ok(consensus_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .count() as u64)
}

/// Read all addresses from below-capacity validator set with their stake.
pub fn read_below_capacity_validator_set_addresses_with_stake<S>(
    storage: &S,
    epoch: namada_core::chain::Epoch,
) -> Result<BTreeSet<WeightedValidator>>
where
    S: StorageRead,
{
    below_capacity_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .map(|res| {
            res.map(
                |(
                    NestedSubKey::Data {
                        key: ReverseOrdTokenAmount(bonded_stake),
                        nested_sub_key: _,
                    },
                    address,
                )| {
                    WeightedValidator {
                        address,
                        bonded_stake,
                    }
                },
            )
        })
        .collect()
}

/// Read all validator addresses.
pub fn read_all_validator_addresses<S>(
    storage: &S,
    epoch: namada_core::chain::Epoch,
) -> Result<HashSet<Address>>
where
    S: StorageRead,
{
    validator_addresses_handle()
        .at(&epoch)
        .iter(storage)?
        .collect()
}

/// Update PoS total deltas.
/// Note: for EpochedDelta, write the value to change storage by
pub fn update_total_deltas<S, Gov>(
    storage: &mut S,
    params: &OwnedPosParams,
    delta: token::Change,
    current_epoch: namada_core::chain::Epoch,
    offset_opt: Option<u64>,
    update_active_voting_power: bool,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
    Gov: governance::Read<S>,
{
    let offset = offset_opt.unwrap_or(params.pipeline_len);
    let total_deltas = total_deltas_handle();
    let offset_epoch = checked!(current_epoch + offset)?;

    // Update total deltas
    let total_deltas_val = total_deltas
        .get_delta_val(storage, offset_epoch)?
        .unwrap_or_default();
    total_deltas.set::<S, Gov>(
        storage,
        total_deltas_val
            .checked_add(delta)
            .expect("Total deltas updated amount should not overflow"),
        current_epoch,
        offset,
    )?;

    // Update total active voting power
    if update_active_voting_power {
        update_total_active_deltas::<S, Gov>(
            storage,
            params,
            delta,
            current_epoch,
            offset_opt,
        )?;
    }

    Ok(())
}

/// Update PoS total active deltas.
pub fn update_total_active_deltas<S, Gov>(
    storage: &mut S,
    params: &OwnedPosParams,
    delta: token::Change,
    current_epoch: namada_core::chain::Epoch,
    offset_opt: Option<u64>,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
    Gov: governance::Read<S>,
{
    let offset = offset_opt.unwrap_or(params.pipeline_len);

    let total_active_deltas = total_active_deltas_handle();
    let offset_epoch = checked!(current_epoch + offset)?;

    let active_delta = total_active_deltas
        .get_delta_val(storage, offset_epoch)?
        .unwrap_or_default();
    total_active_deltas.set::<S, Gov>(
        storage,
        active_delta.checked_add(delta).expect(
            "Total active voting power updated amount should not overflow",
        ),
        current_epoch,
        offset,
    )
}

/// Read PoS validator's email.
pub fn read_validator_email<S>(
    storage: &S,
    validator: &Address,
) -> Result<Option<String>>
where
    S: StorageRead,
{
    storage.read(&storage_key::validator_email_key(validator))
}

/// Write PoS validator's email. The email cannot be removed, so an empty string
/// will result in an error.
pub fn write_validator_email<S>(
    storage: &mut S,
    validator: &Address,
    email: &String,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::validator_email_key(validator);
    if email.is_empty() {
        Err(MetadataError::CannotRemoveEmail.into())
    } else {
        storage.write(&key, email)
    }
}

/// Read PoS validator's description.
pub fn read_validator_description<S>(
    storage: &S,
    validator: &Address,
) -> Result<Option<String>>
where
    S: StorageRead,
{
    storage.read(&storage_key::validator_description_key(validator))
}

/// Write PoS validator's description. If the provided arg is an empty string,
/// remove the data.
pub fn write_validator_description<S>(
    storage: &mut S,
    validator: &Address,
    description: &String,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::validator_description_key(validator);
    if description.is_empty() {
        storage.delete(&key)
    } else {
        storage.write(&key, description)
    }
}

/// Read PoS validator's website.
pub fn read_validator_website<S>(
    storage: &S,
    validator: &Address,
) -> Result<Option<String>>
where
    S: StorageRead,
{
    storage.read(&storage_key::validator_website_key(validator))
}

/// Write PoS validator's website. If the provided arg is an empty string,
/// remove the data.
pub fn write_validator_website<S>(
    storage: &mut S,
    validator: &Address,
    website: &String,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::validator_website_key(validator);
    if website.is_empty() {
        storage.delete(&key)
    } else {
        storage.write(&key, website)
    }
}

/// Read PoS validator's discord handle.
pub fn read_validator_discord_handle<S>(
    storage: &S,
    validator: &Address,
) -> Result<Option<String>>
where
    S: StorageRead,
{
    storage.read(&storage_key::validator_discord_key(validator))
}

/// Write PoS validator's discord handle. If the provided arg is an empty
/// string, remove the data.
pub fn write_validator_discord_handle<S>(
    storage: &mut S,
    validator: &Address,
    discord_handle: &String,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::validator_discord_key(validator);
    if discord_handle.is_empty() {
        storage.delete(&key)
    } else {
        storage.write(&key, discord_handle)
    }
}

/// Read PoS validator's avatar.
pub fn read_validator_avatar<S>(
    storage: &S,
    validator: &Address,
) -> Result<Option<String>>
where
    S: StorageRead,
{
    storage.read(&storage_key::validator_avatar_key(validator))
}

/// Write PoS validator's avatar. If the provided arg is an empty
/// string, remove the data.
pub fn write_validator_avatar<S>(
    storage: &mut S,
    validator: &Address,
    avatar: &String,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::validator_avatar_key(validator);
    if avatar.is_empty() {
        storage.delete(&key)
    } else {
        storage.write(&key, avatar)
    }
}

/// Read PoS validator's name.
pub fn read_validator_name<S>(
    storage: &S,
    validator: &Address,
) -> Result<Option<String>>
where
    S: StorageRead,
{
    storage.read(&storage_key::validator_name_key(validator))
}

/// Write PoS validator's name. If the provided arg is an empty
/// string, remove the data.
pub fn write_validator_name<S>(
    storage: &mut S,
    validator: &Address,
    validator_name: &String,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::validator_name_key(validator);
    if validator_name.is_empty() {
        storage.delete(&key)
    } else {
        storage.write(&key, validator_name)
    }
}
/// Write validator's metadata.
pub fn write_validator_metadata<S>(
    storage: &mut S,
    validator: &Address,
    metadata: &ValidatorMetaData,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    // Email is the only required field in the metadata
    write_validator_email(storage, validator, &metadata.email)?;

    if let Some(description) = metadata.description.as_ref() {
        write_validator_description(storage, validator, description)?;
    }
    if let Some(website) = metadata.website.as_ref() {
        write_validator_website(storage, validator, website)?;
    }
    if let Some(discord) = metadata.discord_handle.as_ref() {
        write_validator_discord_handle(storage, validator, discord)?;
    }
    if let Some(avatar) = metadata.avatar.as_ref() {
        write_validator_avatar(storage, validator, avatar)?;
    }
    if let Some(name) = metadata.name.as_ref() {
        write_validator_name(storage, validator, name)?;
    }
    Ok(())
}

/// Read validator's metadata.
pub fn read_validator_metadata<S>(
    storage: &S,
    validator: &Address,
) -> Result<Option<ValidatorMetaData>>
where
    S: StorageRead,
{
    let email = read_validator_email(storage, validator)?;
    let description = read_validator_description(storage, validator)?;
    let website = read_validator_website(storage, validator)?;
    let discord_handle = read_validator_discord_handle(storage, validator)?;
    let avatar = read_validator_avatar(storage, validator)?;
    let name = read_validator_name(storage, validator)?;

    // Email is the only required field for a validator in storage
    match email {
        Some(email) => Ok(Some(ValidatorMetaData {
            email,
            description,
            website,
            discord_handle,
            avatar,
            name,
        })),
        None => Ok(None),
    }
}

/// Get the last epoch in which rewards were claimed from storage, if any
pub fn get_last_reward_claim_epoch<S>(
    storage: &S,
    delegator: &Address,
    validator: &Address,
) -> Result<Option<Epoch>>
where
    S: StorageRead,
{
    let key =
        storage_key::last_pos_reward_claim_epoch_key(delegator, validator);
    storage.read(&key)
}

/// Write the last epoch in which rewards were claimed for the
/// delegator-validator pair
pub fn write_last_reward_claim_epoch<S>(
    storage: &mut S,
    delegator: &Address,
    validator: &Address,
    epoch: Epoch,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key =
        storage_key::last_pos_reward_claim_epoch_key(delegator, validator);
    storage.write(&key, epoch)
}

/// Check if the given consensus key is already being used to ensure uniqueness.
///
/// If it's not being used, it will be inserted into the set that's being used
/// for this. If it's already used, this will return an Error.
pub fn try_insert_consensus_key<S>(
    storage: &mut S,
    consensus_key: &common::PublicKey,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = consensus_keys_key();
    LazySet::open(key).try_insert(storage, consensus_key.clone())
}

/// Get the unique set of consensus keys in storage
pub fn get_consensus_key_set<S>(
    storage: &S,
) -> Result<BTreeSet<common::PublicKey>>
where
    S: StorageRead,
{
    let key = consensus_keys_key();
    let lazy_set = LazySet::<common::PublicKey>::open(key);
    Ok(lazy_set.iter(storage)?.map(Result::unwrap).collect())
}

/// Check if the given consensus key is already being used to ensure uniqueness.
pub fn is_consensus_key_used<S>(
    storage: &S,
    consensus_key: &common::PublicKey,
) -> Result<bool>
where
    S: StorageRead,
{
    let key = consensus_keys_key();
    let handle = LazySet::open(key);
    handle.contains(storage, consensus_key)
}

/// Find a consensus key of a validator account.
pub fn get_consensus_key<S, Gov>(
    storage: &S,
    addr: &Address,
    epoch: Epoch,
) -> Result<Option<common::PublicKey>>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    let params = read_pos_params::<S, Gov>(storage)?;
    validator_consensus_key_handle(addr).get(storage, epoch, &params)
}
