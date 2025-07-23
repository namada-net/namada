//! Queries router and handlers for PoS validity predicate

use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::address::Address;
use namada_core::arith::{self, checked};
use namada_core::chain::Epoch;
use namada_core::collections::{HashMap, HashSet};
use namada_core::key::{common, tm_consensus_key_raw_hash};
use namada_core::token;
use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::queries::{
    find_delegation_validators, find_delegations,
};
use namada_proof_of_stake::rewards::read_rewards_counter;
use namada_proof_of_stake::slashing::{
    find_all_enqueued_slashes, find_all_slashes,
};
use namada_proof_of_stake::storage::{
    bond_handle, get_consensus_key, get_last_reward_claim_epoch,
    liveness_sum_missed_votes_handle, read_all_validator_addresses,
    read_below_capacity_validator_set_addresses_with_stake,
    read_consensus_validator_set_addresses,
    read_consensus_validator_set_addresses_with_stake, read_pos_params,
    read_total_active_stake, read_total_stake, read_validator_last_slash_epoch,
    read_validator_max_commission_rate_change, read_validator_metadata,
    read_validator_stake, unbond_handle, validator_commission_rate_handle,
    validator_incoming_redelegations_handle, validator_slashes_handle,
};
pub use namada_proof_of_stake::types::ValidatorStateInfo;
use namada_proof_of_stake::types::{
    BondId, BondsAndUnbondsDetail, BondsAndUnbondsDetails, CommissionPair,
    LivenessInfo, Slash, ValidatorLiveness, ValidatorMetaData,
    WeightedValidator,
};
use namada_proof_of_stake::{bond_amount, query_reward_tokens};
use namada_state::{DBIter, DBRead, KeySeg, StorageHasher, StorageRead};
use namada_storage::collections::lazy_map;
use namada_storage::{OptionExt, ResultExt};

use crate::governance;
use crate::queries::types::RequestCtx;
use crate::queries::{RequestQuery, shell};

// PoS validity predicate queries
router! {POS,
    ( "validator" ) = {
        ( "is_validator" / [addr: Address] ) -> bool = is_validator,

        ( "consensus_key" / [addr: Address] ) -> Option<common::PublicKey> = consensus_key,

        ( "addresses" / [epoch: opt Epoch] )
            -> HashSet<Address> = validator_addresses,

        ( "liveness_info" ) -> LivenessInfo = liveness_info,

        ( "stake" / [validator: Address] / [epoch: opt Epoch] )
            -> Option<token::Amount> = validator_stake,

        ( "slashes" / [validator: Address] )
            -> Vec<Slash> = validator_slashes,

        ( "commission" / [validator: Address] / [epoch: opt Epoch] )
            -> CommissionPair = validator_commission,

        ( "metadata" / [validator: Address] )
            -> Option<ValidatorMetaData> = validator_metadata,

        ( "state" / [validator: Address] / [epoch: opt Epoch] )
            -> ValidatorStateInfo = validator_state,

        ( "incoming_redelegation" / [src_validator: Address] / [delegator: Address] )
            -> Option<Epoch> = validator_incoming_redelegation,

        ( "last_infraction_epoch" / [validator: Address] )
            -> Option<Epoch> = validator_last_infraction_epoch,
    },

    ( "validator_set" ) = {
        ( "consensus" / [epoch: opt Epoch] )
            -> BTreeSet<WeightedValidator> = consensus_validator_set,

        ( "below_capacity" / [epoch: opt Epoch] )
            -> BTreeSet<WeightedValidator> = below_capacity_validator_set,
    },

    ( "pos_params") -> PosParams = pos_params,

    ( "total_stake" / [epoch: opt Epoch] )
        -> token::Amount = total_stake,

    ( "total_active_voting_power" / [epoch: opt Epoch] )
        -> token::Amount = total_active_voting_power,

    ( "delegations" / [owner: Address] / [epoch: opt Epoch] )
        -> HashSet<Address> = delegation_validators,

    ( "delegations_at" / [owner: Address] / [epoch: opt Epoch] )
        -> HashMap<Address, token::Amount> = delegations,

    ( "bond_deltas" / [source: Address] / [validator: Address] )
        -> HashMap<Epoch, token::Change> = bond_deltas,

    ( "bond" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = bond,

    ( "rewards" / [validator: Address] / [source: opt Address] / [epoch: opt Epoch] )
        -> token::Amount = rewards,

    ( "bond_with_slashing" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = bond_with_slashing,

    ( "unbond" / [source: Address] / [validator: Address] )
        -> HashMap<(Epoch, Epoch), token::Amount> = unbond,

    ( "unbond_with_slashing" / [source: Address] / [validator: Address] )
        -> HashMap<(Epoch, Epoch), token::Amount> = unbond_with_slashing,

    ( "withdrawable_tokens" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = withdrawable_tokens,

    // NOTE: The literal "to" between source and validator is needed because
    // they are both optional and have the same types so when only one is
    // specified, without the  separator it wouldn't be clear which one (and
    // would always parse as `source`)
    ( "bonds_and_unbonds" / [source: opt Address] / "to" / [validator: opt Address] )
        -> BondsAndUnbondsDetails = bonds_and_unbonds,

    ( "enqueued_slashes" )
        -> HashMap<Address, BTreeMap<Epoch, Vec<Slash>>> = enqueued_slashes,

    ( "all_slashes" ) -> HashMap<Address, Vec<Slash>> = slashes,

    ( "is_delegator" / [addr: Address ] / [epoch: opt Epoch] ) -> bool = is_delegator,

    ( "validator_by_tm_addr" / [tm_addr: String] )
        -> Option<Address> = validator_by_tm_addr,

    ( "consensus_keys" ) -> BTreeSet<common::PublicKey> = consensus_key_set,

    ( "has_bonds" / [source: Address] )
        -> bool = has_bonds,

}

/// Enriched bonds data with extra information calculated from the data queried
/// from the node.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, BorshSchema)]
pub struct Enriched<T> {
    /// The queried data
    pub data: T,
    /// Sum of the bond amounts
    pub bonds_total: token::Amount,
    /// Sum of the bond slashed amounts
    pub bonds_total_slashed: token::Amount,
    /// Sum of the unbond amounts
    pub unbonds_total: token::Amount,
    /// Sum of the unbond slashed amounts
    pub unbonds_total_slashed: token::Amount,
    /// Sum of the withdrawable amounts
    pub total_withdrawable: token::Amount,
}

/// Bonds and unbonds with all details (slashes and rewards, if any) grouped by
/// their bond IDs enriched with extra information calculated from the data
/// queried from the node.
pub type EnrichedBondsAndUnbondsDetails =
    Enriched<HashMap<BondId, EnrichedBondsAndUnbondsDetail>>;

/// Bonds and unbonds with all details (slashes and rewards, if any) enriched
/// with extra information calculated from the data queried from the node.
pub type EnrichedBondsAndUnbondsDetail = Enriched<BondsAndUnbondsDetail>;

impl<T> Enriched<T> {
    /// The bonds amount reduced by slashes
    pub fn bonds_total_active(&self) -> Option<token::Amount> {
        self.bonds_total.checked_sub(self.bonds_total_slashed)
    }

    /// The unbonds amount reduced by slashes
    pub fn unbonds_total_active(&self) -> Option<token::Amount> {
        self.unbonds_total.checked_sub(self.unbonds_total_slashed)
    }
}

// Handlers that implement the functions via `trait StorageRead`:

/// Get the PoS parameters
fn pos_params<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<PosParams>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_pos_params::<_, governance::Store<_>>(ctx.state)
}

/// Find if the given address belongs to a validator account.
fn is_validator<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    addr: Address,
) -> namada_storage::Result<bool>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::is_validator(ctx.state, &addr)
}

/// Find a consensus key of a validator account.
fn consensus_key<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    addr: Address,
) -> namada_storage::Result<Option<common::PublicKey>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let current_epoch = ctx.state.in_mem().last_epoch;
    namada_proof_of_stake::storage::get_consensus_key::<_, governance::Store<_>>(
        ctx.state,
        &addr,
        current_epoch,
    )
}

/// Find if the given address is a delegator
fn is_delegator<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    addr: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<bool>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::is_delegator(ctx.state, &addr, epoch)
}

/// Get all the validator known addresses. These validators may be in any state,
/// e.g. consensus, below-capacity, inactive or jailed.
fn validator_addresses<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Option<Epoch>,
) -> namada_storage::Result<HashSet<Address>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    read_all_validator_addresses(ctx.state, epoch)
}

/// Get liveness information for all consensus validators in the current epoch.
fn liveness_info<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<LivenessInfo>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = ctx.state.in_mem().last_epoch;
    let consensus_validators =
        read_consensus_validator_set_addresses(ctx.state, epoch)?;
    let params = read_pos_params::<_, governance::Store<_>>(ctx.state)?;

    let mut result = Vec::with_capacity(consensus_validators.len());
    for validator in consensus_validators {
        if let Some(pubkey) = get_consensus_key::<_, governance::Store<_>>(
            ctx.state, &validator, epoch,
        )? {
            let comet_address = tm_consensus_key_raw_hash(&pubkey);
            let sum_liveness_handle = liveness_sum_missed_votes_handle();
            let missed_votes = sum_liveness_handle
                .get(ctx.state, &validator)?
                .unwrap_or_default();
            result.push(ValidatorLiveness {
                native_address: validator,
                comet_address,
                missed_votes,
            })
        };
    }

    Ok(LivenessInfo {
        liveness_window_len: params.liveness_window_check,
        liveness_threshold: params.liveness_threshold,
        validators: result,
    })
}

/// Get the validator commission rate and max commission rate change per epoch
fn validator_commission<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<CommissionPair>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    let params = read_pos_params::<_, governance::Store<_>>(ctx.state)?;
    let commission_rate = validator_commission_rate_handle(&validator)
        .get(ctx.state, epoch, &params)?;
    let max_commission_change_per_epoch =
        read_validator_max_commission_rate_change(ctx.state, &validator)?;

    Ok(CommissionPair {
        commission_rate,
        max_commission_change_per_epoch,
        epoch,
    })
}

/// Get the validator metadata
fn validator_metadata<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
) -> namada_storage::Result<Option<ValidatorMetaData>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_validator_metadata(ctx.state, &validator)
}

/// Get the validator state
fn validator_state<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<ValidatorStateInfo>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    let state = namada_proof_of_stake::storage::read_validator_state::<
        _,
        governance::Store<_>,
    >(ctx.state, &validator, epoch)?;
    Ok((state, epoch))
}

/// Get the validator state
fn validator_last_infraction_epoch<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
) -> namada_storage::Result<Option<Epoch>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_validator_last_slash_epoch(ctx.state, &validator)
}

/// Get the total stake of a validator at the given epoch or current when
/// `None`. The total stake is a sum of validator's self-bonds and delegations
/// to their address.
/// Returns `None` when the given address is not a validator address. For a
/// validator with `0` stake, this returns `Ok(token::Amount::zero())`.
fn validator_stake<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<Option<token::Amount>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    let params = read_pos_params::<_, governance::Store<_>>(ctx.state)?;
    if namada_proof_of_stake::is_validator(ctx.state, &validator)? {
        let stake =
            read_validator_stake(ctx.state, &params, &validator, epoch)?;
        Ok(Some(stake))
    } else {
        Ok(None)
    }
}

/// Get the incoming redelegation epoch for a source validator - delegator pair,
/// if there is any.
fn validator_incoming_redelegation<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    src_validator: Address,
    delegator: Address,
) -> namada_storage::Result<Option<Epoch>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let handle = validator_incoming_redelegations_handle(&src_validator);
    handle.get(ctx.state, &delegator)
}

/// Get all the validator in the consensus set with their bonded stake.
fn consensus_validator_set<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Option<Epoch>,
) -> namada_storage::Result<BTreeSet<WeightedValidator>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    read_consensus_validator_set_addresses_with_stake(ctx.state, epoch)
}

/// Get all the validator in the below-capacity set with their bonded stake.
fn below_capacity_validator_set<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Option<Epoch>,
) -> namada_storage::Result<BTreeSet<WeightedValidator>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    read_below_capacity_validator_set_addresses_with_stake(ctx.state, epoch)
}

/// Get the total stake in PoS system at the given epoch or current when `None`.
fn total_stake<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Option<Epoch>,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    let params = read_pos_params::<_, governance::Store<_>>(ctx.state)?;
    read_total_stake(ctx.state, &params, epoch)
}

/// Get the total active voting power in PoS system at the given epoch or
/// current when `None`.
fn total_active_voting_power<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Option<Epoch>,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    let params = read_pos_params::<_, governance::Store<_>>(ctx.state)?;
    read_total_active_stake(ctx.state, &params, epoch)
}

fn bond_deltas<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
    validator: Address,
) -> namada_storage::Result<HashMap<Epoch, token::Amount>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    bond_handle(&source, &validator).to_hashmap(ctx.state)
}

/// Find the sum of bond amount up the given epoch when `Some`, or up to the
/// pipeline length parameter offset otherwise
fn bond<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let params = read_pos_params::<_, governance::Store<_>>(ctx.state)?;
    let epoch = epoch.unwrap_or(
        ctx.state
            .in_mem()
            .last_epoch
            .unchecked_add(params.pipeline_len),
    );

    let handle = bond_handle(&source, &validator);
    handle
        .get_sum(ctx.state, epoch, &params)?
        .ok_or_err_msg("Cannot find bond")
}

fn bond_with_slashing<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    let bond_id = BondId { source, validator };

    bond_amount::<_, governance::Store<_>>(ctx.state, &bond_id, epoch)
}

fn unbond<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
    validator: Address,
) -> namada_storage::Result<HashMap<(Epoch, Epoch), token::Amount>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let handle = unbond_handle(&source, &validator);
    let iter = handle.iter(ctx.state)?;
    iter.map(|next_result| {
        next_result.map(
            |(
                lazy_map::NestedSubKey::Data {
                    key: withdraw_epoch,
                    nested_sub_key: lazy_map::SubKey::Data(bond_epoch),
                },
                amount,
            )| ((bond_epoch, withdraw_epoch), amount),
        )
    })
    .collect()
}

fn unbond_with_slashing<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
    validator: Address,
) -> namada_storage::Result<HashMap<(Epoch, Epoch), token::Amount>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    // TODO slashes
    let handle = unbond_handle(&source, &validator);
    let iter = handle.iter(ctx.state)?;
    iter.map(|next_result| {
        next_result.map(
            |(
                lazy_map::NestedSubKey::Data {
                    key: bond_epoch,
                    nested_sub_key: lazy_map::SubKey::Data(withdraw_epoch),
                },
                amount,
            )| ((bond_epoch, withdraw_epoch), amount),
        )
    })
    .collect()
}

fn withdrawable_tokens<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);

    let handle = unbond_handle(&source, &validator);
    let mut total = token::Amount::zero();
    for result in handle.iter(ctx.state)? {
        let (
            lazy_map::NestedSubKey::Data {
                key: _start,
                nested_sub_key: lazy_map::SubKey::Data(withdrawable),
            },
            amount,
        ) = result?;
        if epoch >= withdrawable {
            checked!(total += amount)?;
        }
    }
    Ok(total)
}

fn rewards<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
    source: Option<Address>,
    epoch: Option<Epoch>,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let reward_tokens = query_reward_tokens::<_, governance::Store<_>>(
        ctx.state,
        source.as_ref(),
        &validator,
        epoch.unwrap_or(ctx.state.in_mem().last_epoch),
    )?;

    match epoch {
        None => Ok(reward_tokens),
        Some(epoch) => {
            // When querying by epoch, since query_reward_tokens includes
            // rewards_counter not based on epoch, we need to
            // subtract it and instead add the rewards_counter from
            // the height of the epoch we are querying.
            let source = source.unwrap_or_else(|| validator.clone());
            let rewards_counter_last_epoch =
                read_rewards_counter(ctx.state, &source, &validator)?;

            let rewards_counter_at_epoch =
                get_rewards_counter_at_epoch(ctx, &source, &validator, epoch)?;

            // Add before subtracting because Amounts are unsigned
            checked!(
                reward_tokens + rewards_counter_at_epoch
                    - rewards_counter_last_epoch
            )
            .into_storage_result()
        }
    }
}

fn get_rewards_counter_at_epoch<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: &Address,
    validator: &Address,
    epoch: Epoch,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    // Do this first so that we return an error if an invalid epoch is requested
    let queried_height = ctx
        .state
        .get_epoch_start_height(epoch)?
        .ok_or(namada_storage::Error::new_const("Epoch not found"))?;

    let storage_key = namada_proof_of_stake::storage_key::rewards_counter_key(
        source, validator,
    );

    // Shortcut: avoid costly lookup of non-existent storage key in history
    // by first checking to see if it currently exists in memory or has ever
    // been claimed before querying by height.
    if !ctx.state.has_key(&storage_key)?
        && get_last_reward_claim_epoch(ctx.state, source, validator)?.is_none()
    {
        return Ok(token::Amount::zero());
    }

    let query = RequestQuery {
        height: queried_height.try_into().into_storage_result()?,
        prove: false,
        data: Default::default(),
        path: Default::default(),
    };

    let value = shell::storage_value(ctx, &query, storage_key)?;
    if value.data.is_empty() {
        Ok(token::Amount::zero())
    } else {
        token::Amount::try_from_slice(&value.data).into_storage_result()
    }
}

fn bonds_and_unbonds<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Option<Address>,
    validator: Option<Address>,
) -> namada_storage::Result<BondsAndUnbondsDetails>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::queries::bonds_and_unbonds::<_, governance::Store<_>>(
        ctx.state, source, validator,
    )
}

/// Find all the validator addresses to whom the given `owner` address has
/// some delegation in any epoch
fn delegation_validators<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    owner: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<HashSet<Address>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    find_delegation_validators(ctx.state, &owner, &epoch)
}

/// Find all the validator addresses to whom the given `owner` address has
/// some delegation in any epoch
fn delegations<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    owner: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<HashMap<Address, token::Amount>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch: Epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    find_delegations::<_, governance::Store<_>>(ctx.state, &owner, &epoch)
}

/// Validator slashes
fn validator_slashes<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
) -> namada_storage::Result<Vec<Slash>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let slash_handle = validator_slashes_handle(&validator);
    slash_handle.iter(ctx.state)?.collect()
}

/// All slashes
fn slashes<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<HashMap<Address, Vec<Slash>>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    find_all_slashes(ctx.state)
}

/// Enqueued slashes
fn enqueued_slashes<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<HashMap<Address, BTreeMap<Epoch, Vec<Slash>>>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let current_epoch = ctx.state.in_mem().last_epoch;
    find_all_enqueued_slashes(ctx.state, current_epoch)
}

/// Native validator address by looking up the Tendermint address
fn validator_by_tm_addr<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    tm_addr: String,
) -> namada_storage::Result<Option<Address>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    // Sanitize the input to make sure it doesn't crash in
    // `namada_proof_of_stake::storage_key::validator_address_raw_hash_key`
    if namada_storage::DbKeySeg::parse(tm_addr.clone()).is_err() {
        return Err(namada_storage::Error::new_const(
            "Invalid Tendermint address",
        ));
    }
    namada_proof_of_stake::storage::find_validator_by_raw_hash(
        ctx.state, tm_addr,
    )
}

/// Native validator address by looking up the Tendermint address
fn consensus_key_set<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<BTreeSet<common::PublicKey>>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::storage::get_consensus_key_set(ctx.state)
}

/// Find if the given source address has any bonds.
fn has_bonds<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
) -> namada_storage::Result<bool>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::queries::has_bonds::<_, governance::Store<_>>(
        ctx.state, &source,
    )
}

/// Client-only methods for the router type are composed from router functions.
pub mod client_only_methods {
    use namada_io::Client;

    use super::*;
    use crate::queries::RPC;

    impl Pos {
        /// Get bonds and unbonds with all details (slashes and rewards, if any)
        /// grouped by their bond IDs, enriched with extra information
        /// calculated from the data.
        pub async fn enriched_bonds_and_unbonds<CLIENT>(
            &self,
            client: &CLIENT,
            current_epoch: Epoch,
            source: &Option<Address>,
            validator: &Option<Address>,
        ) -> Result<EnrichedBondsAndUnbondsDetails, <CLIENT as Client>::Error>
        where
            CLIENT: Client + Sync,
        {
            let data = RPC
                .vp()
                .pos()
                .bonds_and_unbonds(client, source, validator)
                .await?;
            Ok(enrich_bonds_and_unbonds(current_epoch, data)
                .map_err(std::io::Error::other)?)
        }
    }
}

/// Calculate extra information from the bonds and unbonds details.
fn enrich_bonds_and_unbonds(
    current_epoch: Epoch,
    bonds_and_unbonds: BondsAndUnbondsDetails,
) -> Result<EnrichedBondsAndUnbondsDetails, arith::Error> {
    let mut bonds_total: token::Amount = 0.into();
    let mut bonds_total_slashed: token::Amount = 0.into();
    let mut unbonds_total: token::Amount = 0.into();
    let mut unbonds_total_slashed: token::Amount = 0.into();
    let mut total_withdrawable: token::Amount = 0.into();

    let enriched_details: HashMap<BondId, EnrichedBondsAndUnbondsDetail> =
        bonds_and_unbonds
            .into_iter()
            .map(|(bond_id, detail)| {
                let mut bond_total: token::Amount = 0.into();
                let mut bond_total_slashed: token::Amount = 0.into();
                let mut unbond_total: token::Amount = 0.into();
                let mut unbond_total_slashed: token::Amount = 0.into();
                let mut withdrawable: token::Amount = 0.into();

                for bond in &detail.bonds {
                    let slashed_bond = bond.slashed_amount.unwrap_or_default();
                    checked!(bond_total += bond.amount)?;
                    checked!(bond_total_slashed += slashed_bond)?;
                }
                for unbond in &detail.unbonds {
                    let slashed_unbond =
                        unbond.slashed_amount.unwrap_or_default();
                    checked!(unbond_total += unbond.amount)?;
                    checked!(unbond_total_slashed += slashed_unbond)?;

                    if current_epoch >= unbond.withdraw {
                        checked!(
                            withdrawable += unbond.amount - slashed_unbond
                        )?;
                    }
                }

                checked!(bonds_total += bond_total)?;
                checked!(bonds_total_slashed += bond_total_slashed)?;
                checked!(unbonds_total += unbond_total)?;
                checked!(unbonds_total_slashed += unbond_total_slashed)?;
                checked!(total_withdrawable += withdrawable)?;

                let enriched_detail = EnrichedBondsAndUnbondsDetail {
                    data: detail,
                    bonds_total: bond_total,
                    bonds_total_slashed: bond_total_slashed,
                    unbonds_total: unbond_total,
                    unbonds_total_slashed: unbond_total_slashed,
                    total_withdrawable: withdrawable,
                };
                Ok::<_, arith::Error>((bond_id, enriched_detail))
            })
            .collect::<Result<
                HashMap<BondId, EnrichedBondsAndUnbondsDetail>,
                arith::Error,
            >>()?;
    Ok(EnrichedBondsAndUnbondsDetails {
        data: enriched_details,
        bonds_total,
        bonds_total_slashed,
        unbonds_total,
        unbonds_total_slashed,
        total_withdrawable,
    })
}

#[cfg(test)]
mod test {
    use namada_core::chain::Epoch;
    use namada_core::{address, token};
    use namada_state::StorageWrite;

    use super::*;
    use crate::queries::testing::TestClient;
    use crate::queries::{RPC, RequestCtx, RequestQuery, Router};

    #[tokio::test]
    async fn test_validator_by_tm_addr_sanitized_input() {
        let client = TestClient::new(POS);

        // Test request with an invalid path - the trailing slash ends up being
        // part of the input where in `fn validator_by_tm_addr` the
        // parameter will be:
        // `tm_addr = "52894D2ABA1614EF24CC1DDAE127A7A2386DE3BB/"`
        let request = RequestQuery {
            path: "/validator_by_tm_addr/\
                   52894D2ABA1614EF24CC1DDAE127A7A2386DE3BB/"
                .to_owned(),
            data: Default::default(),
            height: 0_u32.into(),
            prove: Default::default(),
        };
        let ctx = RequestCtx {
            event_log: &client.event_log,
            state: &client.state,
            vp_wasm_cache: (),
            tx_wasm_cache: (),
            storage_read_past_height_limit: None,
        };
        let result = POS.handle(ctx, &request);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid Tendermint address")
        )
    }

    // Helpers for test_rewards_query
    mod helpers {
        use super::*;

        pub fn init_validator<RPC: Router>(
            client: &mut TestClient<RPC>,
        ) -> (Address, namada_proof_of_stake::PosParams) {
            let genesis_validator =
                namada_proof_of_stake::test_utils::get_dummy_genesis_validator(
                );
            let validator_address = genesis_validator.address.clone();

            let params =
                namada_proof_of_stake::test_utils::test_init_genesis::<
                    _,
                    namada_parameters::Store<_>,
                    governance::Store<_>,
                    namada_token::Store<_>,
                >(
                    &mut client.state,
                    namada_proof_of_stake::OwnedPosParams::default(),
                    std::iter::once(genesis_validator),
                    Epoch(0),
                )
                .expect("Test initialization failed");

            (validator_address, params)
        }

        pub fn setup_delegator<RPC: Router>(
            client: &mut TestClient<RPC>,
            validator_address: &Address,
            bond_amount: token::Amount,
        ) -> Address {
            let delegator = address::testing::established_address_2();

            // Credit tokens to delegator
            let native_token = client.state.get_native_token().unwrap();
            StorageWrite::write(
                &mut client.state,
                &namada_token::storage_key::balance_key(
                    &native_token,
                    &delegator,
                ),
                bond_amount,
            )
            .expect("Credit tokens failed");

            // Bond tokens from delegator to validator
            namada_proof_of_stake::bond_tokens::<
                _,
                governance::Store<_>,
                namada_token::Store<_>,
            >(
                &mut client.state,
                Some(&delegator),
                validator_address,
                bond_amount,
                Epoch(1),
                Some(0),
            )
            .expect("Bonding tokens failed");

            delegator
        }

        pub fn init_state<RPC: Router>(
            client: &mut TestClient<RPC>,
            bond_amount: token::Amount,
        ) -> (Address, Address, token::Amount) {
            let (validator, _params) = init_validator(client);
            let delegator = setup_delegator(client, &validator, bond_amount);

            // Initialize the predecessor epochs
            client
                .state
                .in_mem_mut()
                .block
                .pred_epochs
                .new_epoch(0.into());

            (validator, delegator, bond_amount)
        }

        pub fn advance_epoch<RPC: Router>(
            client: &mut TestClient<RPC>,
            validator_delegator: &(Address, Address),
            reward: &(Option<token::Amount>, Option<token::Amount>),
        ) -> Epoch {
            let (validator, delegator) = validator_delegator;
            let (validator_reward, delegator_reward) = reward;
            let current_epoch = client.state.in_mem().last_epoch;
            let next_epoch = current_epoch.next();
            let height = client.state.in_mem().block.height;

            // Advance block height and epoch
            let next_height = height + 1;
            client
                .state
                .in_mem_mut()
                .begin_block(next_height)
                .expect("Test failed");
            client.state.in_mem_mut().block.epoch = next_epoch;
            client.state.in_mem_mut().block.height = next_height;
            client
                .state
                .in_mem_mut()
                .block
                .pred_epochs
                .new_epoch(next_height);

            // Add rewards
            if let Some(rewards_amount) = delegator_reward {
                namada_proof_of_stake::rewards::add_rewards_to_counter(
                    &mut client.state,
                    delegator,
                    validator,
                    *rewards_amount,
                )
                .expect("Adding delegator rewards failed");
            }

            if let Some(rewards_amount) = validator_reward {
                namada_proof_of_stake::rewards::add_rewards_to_counter(
                    &mut client.state,
                    validator,
                    validator,
                    *rewards_amount,
                )
                .expect("Adding validator rewards failed");
            }

            client.state.commit_block().expect("Test failed");

            next_epoch
        }
    }

    #[tokio::test]
    async fn test_rewards_query() {
        // Initialize test client
        let mut client = TestClient::new(RPC);

        // We will be reusing this route frequently, so alias it here
        let pos = RPC.vp().pos();

        // Set up validator
        let (validator, delegator, _params) =
            helpers::init_state(&mut client, token::Amount::native_whole(100));

        let bond = (validator.clone(), delegator.clone());
        let reward = (None, None);

        // Advance to next epoch without rewards
        let epoch = helpers::advance_epoch(&mut client, &bond, &reward);
        assert_eq!(epoch, Epoch(1));

        // Test querying rewards (should be 0)
        let result = pos
            .rewards(&client, &validator, &Some(delegator.clone()), &None)
            .await
            .expect("Rewards query failed");
        assert_eq!(result, token::Amount::zero());

        let result = pos
            .rewards(
                &client,
                &validator,
                &Some(delegator.clone()),
                &Some(epoch),
            )
            .await
            .expect("Rewards query failed");
        assert_eq!(result, token::Amount::zero());

        let result = pos
            .rewards(&client, &validator, &None, &None)
            .await
            .expect("Rewards query failed");
        assert_eq!(result, token::Amount::zero());

        // Advance to next epoch with some rewards
        let val_reward_epoch_2 = token::Amount::native_whole(5);
        let del_reward_epoch_2 = token::Amount::native_whole(7);
        let reward_epoch_2 =
            (Some(val_reward_epoch_2), Some(del_reward_epoch_2));
        let epoch = helpers::advance_epoch(&mut client, &bond, &reward_epoch_2);
        assert_eq!(epoch, Epoch(2));

        // Query latest rewards for delegator
        let result = pos
            .rewards(&client, &validator, &Some(delegator.clone()), &None)
            .await
            .expect("Rewards query failed");
        assert_eq!(result, del_reward_epoch_2);

        // Query latest rewards for validator
        let result = pos
            .rewards(&client, &validator, &None, &None)
            .await
            .expect("Rewards query failed");
        assert_eq!(result, val_reward_epoch_2);

        // Query delegator rewards at specific epoch
        let result = pos
            .rewards(
                &client,
                &validator,
                &Some(delegator.clone()),
                &Some(epoch),
            )
            .await
            .expect("Rewards query failed");
        assert_eq!(result, del_reward_epoch_2);

        // Query validator rewards at specific epoch
        let result = pos
            .rewards(&client, &validator, &None, &Some(epoch))
            .await
            .expect("Rewards query failed");
        assert_eq!(result, val_reward_epoch_2);

        // Ensure no rewards at previous epoch
        let result = pos
            .rewards(
                &client,
                &validator,
                &Some(delegator.clone()),
                &epoch.prev(),
            )
            .await
            .expect("Rewards query failed");
        assert_eq!(result, token::Amount::zero());

        let result = pos
            .rewards(&client, &validator, &None, &epoch.prev())
            .await
            .expect("Rewards query failed");
        assert_eq!(result, token::Amount::zero());

        // Advance to another epoch with more rewards
        let val_reward_epoch_3 = token::Amount::native_whole(9);
        let del_reward_epoch_3 = token::Amount::native_whole(11);
        let reward_epoch_3 =
            (Some(val_reward_epoch_3), Some(del_reward_epoch_3));
        let epoch = helpers::advance_epoch(&mut client, &bond, &reward_epoch_3);
        assert_eq!(epoch, Epoch(3));

        // Query latest rewards
        let result = pos
            .rewards(&client, &validator, &Some(delegator.clone()), &None)
            .await
            .expect("Rewards query failed");
        assert_eq!(result, del_reward_epoch_3 + del_reward_epoch_2);

        let result = pos
            .rewards(&client, &validator, &None, &None)
            .await
            .expect("Rewards query failed");
        assert_eq!(result, val_reward_epoch_3 + val_reward_epoch_2);

        // Query rewards at specific epoch
        let result = pos
            .rewards(
                &client,
                &validator,
                &Some(delegator.clone()),
                &Some(epoch),
            )
            .await
            .expect("Rewards query failed");
        assert_eq!(result, del_reward_epoch_3 + del_reward_epoch_2);

        let result = pos
            .rewards(&client, &validator, &None, &Some(epoch))
            .await
            .expect("Rewards query failed");
        assert_eq!(result, val_reward_epoch_3 + val_reward_epoch_2);

        // Query at previous epoch
        let result = pos
            .rewards(
                &client,
                &validator,
                &Some(delegator.clone()),
                &epoch.prev(),
            )
            .await
            .expect("Rewards query failed");
        assert_eq!(result, del_reward_epoch_2);

        let result = pos
            .rewards(&client, &validator, &None, &epoch.prev())
            .await
            .expect("Rewards query failed");
        assert_eq!(result, val_reward_epoch_2);

        // Simulate rewards claim, then query again at previous epoch
        let height = client.state.in_mem().block.height;
        client
            .state
            .in_mem_mut()
            .begin_block(height + 1)
            .expect("Test failed");
        client.state.in_mem_mut().block.height = height + 1;

        let claimed = namada_proof_of_stake::claim_reward_tokens::<
            _,
            governance::Store<_>,
            namada_token::Store<_>,
        >(
            &mut client.state, Some(&delegator), &validator, epoch
        )
        .expect("Claiming rewards failed");

        assert_eq!(claimed, del_reward_epoch_3 + del_reward_epoch_2);

        let claimed_validator =
            namada_proof_of_stake::claim_reward_tokens::<
                _,
                governance::Store<_>,
                namada_token::Store<_>,
            >(&mut client.state, None, &validator, epoch)
            .expect("Claiming validator rewards failed");

        assert_eq!(claimed_validator, val_reward_epoch_3 + val_reward_epoch_2);

        // Commit the block
        client.state.commit_block().expect("Test failed");

        // Expect rewards to now report 0 when not specifying epcoh
        let result = pos
            .rewards(&client, &validator, &Some(delegator.clone()), &None)
            .await
            .expect("Rewards query failed");
        assert_eq!(result, token::Amount::zero());

        let result = pos
            .rewards(&client, &validator, &None, &None)
            .await
            .expect("Rewards query failed");
        assert_eq!(result, token::Amount::zero());

        // But when querying at the current epoch, the claimable rewards should
        // still be reported
        let result = pos
            .rewards(
                &client,
                &validator,
                &Some(delegator.clone()),
                &Some(epoch),
            )
            .await
            .expect("Rewards query failed");
        assert_eq!(result, del_reward_epoch_3 + del_reward_epoch_2);

        let result = pos
            .rewards(&client, &validator, &None, &Some(epoch))
            .await
            .expect("Rewards query failed");
        assert_eq!(result, val_reward_epoch_3 + val_reward_epoch_2);
    }
}
