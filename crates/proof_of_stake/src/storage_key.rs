//! Proof-of-Stake storage keys and storage integration.

use namada_core::address::Address;
use namada_core::storage::DbKeySeg;
use namada_macros::StorageKeys;

use super::ADDRESS;
use crate::types::BondId;
use crate::{Epoch, Key, KeySeg, epoched, lazy_map, lazy_vec};

#[derive(StorageKeys)]
struct Params {
    proposal: &'static str,
    max_validator_slots: &'static str,
    pipeline_len: &'static str,
    unbonding_len: &'static str,
    tm_votes_per_token: &'static str,
    block_proposer_reward: &'static str,
    block_vote_reward: &'static str,
    max_inflation_rate: &'static str,
    target_staked_ratio: &'static str,
    duplicate_vote_min_slash_rate: &'static str,
    light_client_attack_min_slash_rate: &'static str,
    cubic_slashing_window_length: &'static str,
    validator_stake_threshold: &'static str,
    liveness_window_check: &'static str,
    liveness_threshold: &'static str,
    rewards_gain_p: &'static str,
    rewards_gain_d: &'static str,
}

const PARAMS_STORAGE_KEY: &str = "params";
const VALIDATOR_ADDRESSES_KEY: &str = "validator_addresses";
#[allow(missing_docs)]
pub const VALIDATOR_STORAGE_PREFIX: &str = "validator";
const VALIDATOR_ADDRESS_RAW_HASH: &str = "address_raw_hash";
const VALIDATOR_CONSENSUS_KEY_STORAGE_KEY: &str = "consensus_key";
const VALIDATOR_ETH_COLD_KEY_STORAGE_KEY: &str = "eth_cold_key";
const VALIDATOR_ETH_HOT_KEY_STORAGE_KEY: &str = "eth_hot_key";
const VALIDATOR_STATE_STORAGE_KEY: &str = "state";
const VALIDATOR_DELTAS_STORAGE_KEY: &str = "deltas";
const VALIDATOR_COMMISSION_RATE_STORAGE_KEY: &str = "commission_rate";
const VALIDATOR_MAX_COMMISSION_CHANGE_STORAGE_KEY: &str =
    "max_commission_rate_change";
const VALIDATOR_REWARDS_PRODUCT_KEY: &str = "validator_rewards_product";
const VALIDATOR_LAST_KNOWN_PRODUCT_EPOCH_KEY: &str =
    "last_known_rewards_product_epoch";
const SLASHES_PREFIX: &str = "slash";
const ENQUEUED_SLASHES_KEY: &str = "enqueued_slashes";
const VALIDATOR_LAST_SLASH_EPOCH: &str = "last_slash_epoch";
const BOND_STORAGE_KEY: &str = "bond";
const UNBOND_STORAGE_KEY: &str = "unbond";
const VALIDATOR_TOTAL_BONDED_STORAGE_KEY: &str = "total_bonded";
const VALIDATOR_TOTAL_UNBONDED_STORAGE_KEY: &str = "total_unbonded";
const VALIDATOR_SETS_STORAGE_PREFIX: &str = "validator_sets";
const CONSENSUS_VALIDATOR_SET_STORAGE_KEY: &str = "consensus";
const BELOW_CAPACITY_VALIDATOR_SET_STORAGE_KEY: &str = "below_capacity";
const TOTAL_CONSENSUS_STAKE_STORAGE_KEY: &str = "total_consensus_stake";
const TOTAL_DELTAS_STORAGE_KEY: &str = "total_deltas";
const VALIDATOR_SET_POSITIONS_KEY: &str = "validator_set_positions";
const CONSENSUS_KEYS: &str = "consensus_keys";
const LAST_BLOCK_PROPOSER_STORAGE_KEY: &str = "last_block_proposer";
const CONSENSUS_VALIDATOR_SET_ACCUMULATOR_STORAGE_KEY: &str =
    "validator_rewards_accumulator";
const LAST_REWARD_CLAIM_EPOCH: &str = "last_reward_claim_epoch";
const REWARDS_COUNTER_KEY: &str = "validator_rewards_commissions";
const VALIDATOR_INCOMING_REDELEGATIONS_KEY: &str = "incoming_redelegations";
const VALIDATOR_OUTGOING_REDELEGATIONS_KEY: &str = "outgoing_redelegations";
const VALIDATOR_TOTAL_REDELEGATED_BONDED_KEY: &str = "total_redelegated_bonded";
const VALIDATOR_TOTAL_REDELEGATED_UNBONDED_KEY: &str =
    "total_redelegated_unbonded";
const DELEGATOR_REDELEGATED_BONDS_KEY: &str = "delegator_redelegated_bonds";
const DELEGATOR_REDELEGATED_UNBONDS_KEY: &str = "delegator_redelegated_unbonds";
const VALIDATOR_EMAIL_KEY: &str = "email";
const VALIDATOR_DESCRIPTION_KEY: &str = "description";
const VALIDATOR_WEBSITE_KEY: &str = "website";
const VALIDATOR_DISCORD_KEY: &str = "discord_handle";
const VALIDATOR_AVATAR_KEY: &str = "avatar";
const VALIDATOR_NAME_KEY: &str = "name";
const LIVENESS_PREFIX: &str = "liveness";
const LIVENESS_MISSED_VOTES: &str = "missed_votes";
const LIVENESS_MISSED_VOTES_SUM: &str = "sum_missed_votes";
const LAST_STAKED_RATIO_KEY: &str = "last_staked_ratio";
const LAST_POS_INFLATION_AMOUNT_KEY: &str = "last_inflation_amount";
const TOTAL_ACTIVE_DELTAS_KEY: &str = "total_active_deltas";
const DELEGATION_TARGETS_PREFIX: &str = "delegation_targets";

/// Is the given key a PoS storage key?
pub fn is_pos_key(key: &Key) -> bool {
    match &key.segments.first() {
        Some(DbKeySeg::AddressSeg(addr)) => addr == &ADDRESS,
        _ => false,
    }
}

/// Storage key prefix for PoS parameters.
///
/// Each param is stored in a key derived for `Params`.
pub fn params_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&PARAMS_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Proposal param storage key
pub fn param_proposal_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.proposal.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Max validator slots param storage key
pub fn param_max_validator_slots_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.max_validator_slots.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Pipeline length param storage key
pub fn param_pipeline_len_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.pipeline_len.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Unbonding length param storage key
pub fn param_unbonding_len_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.unbonding_len.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Tendermint votes per token param storage key
pub fn param_tm_votes_per_token_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.tm_votes_per_token.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Block proposer reward param storage key
pub fn param_block_proposer_reward_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.block_proposer_reward.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Block vote reward param storage key
pub fn param_block_vote_reward_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.block_vote_reward.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Max inflation rate param storage key
pub fn param_max_inflation_rate_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.max_inflation_rate.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Target staked ratio param storage key
pub fn param_target_staked_ratio_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.target_staked_ratio.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Duplicate vote minimum slash rate param storage key
pub fn param_duplicate_vote_min_slash_rate_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.duplicate_vote_min_slash_rate.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Light client attack minimum slash rate param storage key
pub fn param_light_client_attack_min_slash_rate_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.light_client_attack_min_slash_rate.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Cubic slashing window length param storage key
pub fn param_cubic_slashing_window_length_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.cubic_slashing_window_length.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Validator stake threshold param storage key
pub fn param_validator_stake_threshold_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.validator_stake_threshold.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Liveness window check param storage key
pub fn param_liveness_window_check_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.liveness_window_check.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Liveness threshold param storage key
pub fn param_liveness_threshold_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.liveness_threshold.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Rewards gain P param storage key
pub fn param_rewards_gain_p_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.rewards_gain_p.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Rewards gain D param storage key
pub fn param_rewards_gain_d_key() -> Key {
    params_prefix()
        .push(&Params::VALUES.rewards_gain_d.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for PoS parameters?
pub fn is_params_key(key: &Key) -> bool {
    matches!(
        &key.segments[..],
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(key),
            DbKeySeg::StringSeg(_sub_key),
        ] if addr == &ADDRESS && key == PARAMS_STORAGE_KEY
    )
}

/// Storage key prefix for validator data.
fn validator_prefix(validator: &Address) -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&VALIDATOR_STORAGE_PREFIX.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&validator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Storage key for validator's address raw hash for look-up from raw hash of an
/// address to address.
pub fn validator_address_raw_hash_key(raw_hash: impl AsRef<str>) -> Key {
    let raw_hash = raw_hash.as_ref().to_owned();
    Key::from(ADDRESS.to_db_key())
        .push(&VALIDATOR_ADDRESS_RAW_HASH.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&raw_hash)
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's address raw hash?
pub fn is_validator_address_raw_hash_key(key: &Key) -> Option<&str> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(raw_hash),
        ] if addr == &ADDRESS && prefix == VALIDATOR_ADDRESS_RAW_HASH => {
            Some(raw_hash)
        }
        _ => None,
    }
}

/// Storage key for validator's consensus key.
pub fn validator_consensus_key_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_CONSENSUS_KEY_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's consensus key?
pub fn is_validator_consensus_key_key(key: &Key) -> Option<&Address> {
    if key.segments.len() >= 4 {
        match &key.segments[..4] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(validator),
                DbKeySeg::StringSeg(key),
            ] if addr == &ADDRESS
                && prefix == VALIDATOR_STORAGE_PREFIX
                && key == VALIDATOR_CONSENSUS_KEY_STORAGE_KEY =>
            {
                Some(validator)
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Storage key for validator's eth cold key.
pub fn validator_eth_cold_key_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_ETH_COLD_KEY_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's eth cold key?
pub fn is_validator_eth_cold_key_key(key: &Key) -> Option<&Address> {
    if key.segments.len() >= 4 {
        match &key.segments[..4] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(validator),
                DbKeySeg::StringSeg(key),
            ] if addr == &ADDRESS
                && prefix == VALIDATOR_STORAGE_PREFIX
                && key == VALIDATOR_ETH_COLD_KEY_STORAGE_KEY =>
            {
                Some(validator)
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Storage key for validator's eth hot key.
pub fn validator_eth_hot_key_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_ETH_HOT_KEY_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's eth hot key?
pub fn is_validator_eth_hot_key_key(key: &Key) -> Option<&Address> {
    if key.segments.len() >= 4 {
        match &key.segments[..4] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(validator),
                DbKeySeg::StringSeg(key),
            ] if addr == &ADDRESS
                && prefix == VALIDATOR_STORAGE_PREFIX
                && key == VALIDATOR_ETH_HOT_KEY_STORAGE_KEY =>
            {
                Some(validator)
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Storage key for validator's commission rate.
pub fn validator_commission_rate_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_COMMISSION_RATE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's commission rate?
pub fn is_validator_commission_rate_key(key: &Key) -> Option<&Address> {
    if key.segments.len() >= 4 {
        match &key.segments[..4] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(validator),
                DbKeySeg::StringSeg(key),
            ] if addr == &ADDRESS
                && prefix == VALIDATOR_STORAGE_PREFIX
                && key == VALIDATOR_COMMISSION_RATE_STORAGE_KEY =>
            {
                Some(validator)
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Storage key for validator's maximum commission rate change per epoch.
pub fn validator_max_commission_rate_change_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_MAX_COMMISSION_CHANGE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's maximum commission rate change per epoch?
pub fn is_validator_max_commission_rate_change_key(
    key: &Key,
) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(key),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_MAX_COMMISSION_CHANGE_STORAGE_KEY =>
        {
            Some(validator)
        }
        _ => None,
    }
}

/// Is storage key for some piece of validator metadata?
pub fn is_validator_metadata_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(metadata),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && matches!(
                metadata.as_str(),
                VALIDATOR_EMAIL_KEY
                    | VALIDATOR_DESCRIPTION_KEY
                    | VALIDATOR_WEBSITE_KEY
                    | VALIDATOR_DISCORD_KEY
                    | VALIDATOR_AVATAR_KEY
                    | VALIDATOR_NAME_KEY
            ) =>
        {
            Some(validator)
        }
        _ => None,
    }
}

/// Storage key for validator's rewards products.
pub fn validator_rewards_product_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_REWARDS_PRODUCT_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's rewards products?
pub fn is_validator_rewards_product_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(key),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_REWARDS_PRODUCT_KEY =>
        {
            Some(validator)
        }
        _ => None,
    }
}

/// Storage prefix for rewards counter.
pub fn rewards_counter_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&REWARDS_COUNTER_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for rewards counter.
pub fn rewards_counter_key(source: &Address, validator: &Address) -> Key {
    rewards_counter_prefix()
        .push(&source.to_db_key())
        .expect("Cannot obtain a storage key")
        .push(&validator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Is the storage key for rewards counter?
pub fn is_rewards_counter_key(key: &Key) -> Option<BondId> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(key),
            DbKeySeg::AddressSeg(source),
            DbKeySeg::AddressSeg(validator),
        ] if addr == &ADDRESS && key == REWARDS_COUNTER_KEY => Some(BondId {
            source: source.clone(),
            validator: validator.clone(),
        }),
        _ => None,
    }
}

/// Storage key for a validator's incoming redelegations, where the prefixed
/// validator is the destination validator.
pub fn validator_incoming_redelegations_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_INCOMING_REDELEGATIONS_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for a validator's outgoing redelegations, where the prefixed
/// validator is the source validator.
pub fn validator_outgoing_redelegations_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_OUTGOING_REDELEGATIONS_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for validator's total-redelegated-bonded amount to track for
/// slashing
pub fn validator_total_redelegated_bonded_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_TOTAL_REDELEGATED_BONDED_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for validator's total-redelegated-unbonded amount to track for
/// slashing
pub fn validator_total_redelegated_unbonded_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_TOTAL_REDELEGATED_UNBONDED_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is the storage key's prefix matching one of validator's:
///
/// - incoming or outgoing redelegations
/// - total redelegated bonded or unbond amounts
pub fn is_validator_redelegations_key(key: &Key) -> bool {
    if key.segments.len() >= 4 {
        match &key.segments[..4] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(val_prefix),
                DbKeySeg::AddressSeg(_validator),
                DbKeySeg::StringSeg(prefix),
            ] => {
                addr == &ADDRESS
                    && val_prefix == VALIDATOR_STORAGE_PREFIX
                    && (prefix == VALIDATOR_INCOMING_REDELEGATIONS_KEY
                        || prefix == VALIDATOR_OUTGOING_REDELEGATIONS_KEY
                        || prefix == VALIDATOR_TOTAL_REDELEGATED_BONDED_KEY
                        || prefix == VALIDATOR_TOTAL_REDELEGATED_UNBONDED_KEY)
            }
            _ => false,
        }
    } else {
        false
    }
}

/// Storage key prefix for all delegators' redelegated bonds.
pub fn delegator_redelegated_bonds_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&DELEGATOR_REDELEGATED_BONDS_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for a particular delegator's redelegated bond information.
pub fn delegator_redelegated_bonds_key(delegator: &Address) -> Key {
    delegator_redelegated_bonds_prefix()
        .push(&delegator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Storage key prefix for all delegators' redelegated unbonds.
pub fn delegator_redelegated_unbonds_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&DELEGATOR_REDELEGATED_UNBONDS_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for a particular delegator's redelegated unbond information.
pub fn delegator_redelegated_unbonds_key(delegator: &Address) -> Key {
    delegator_redelegated_unbonds_prefix()
        .push(&delegator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Is the storage key's prefix matching delegator's total redelegated bonded or
/// unbond amounts? If so, returns the delegator's address.
pub fn is_delegator_redelegations_key(key: &Key) -> Option<&Address> {
    if key.segments.len() >= 3 {
        match &key.segments[..3] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(delegator),
            ] if addr == &ADDRESS
                && (prefix == DELEGATOR_REDELEGATED_BONDS_KEY
                    || prefix == DELEGATOR_REDELEGATED_UNBONDS_KEY) =>
            {
                Some(delegator)
            }

            _ => None,
        }
    } else {
        None
    }
}

/// Storage key for validator's last known rewards product epoch.
pub fn validator_last_known_product_epoch_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_LAST_KNOWN_PRODUCT_EPOCH_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's last known rewards product epoch?
pub fn is_validator_last_known_product_epoch_key(
    key: &Key,
) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(key),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_LAST_KNOWN_PRODUCT_EPOCH_KEY =>
        {
            Some(validator)
        }
        _ => None,
    }
}

/// Storage key for validator's consensus key.
pub fn validator_state_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_STATE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's state?
pub fn is_validator_state_key(key: &Key) -> Option<(&Address, Epoch)> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(key),
            DbKeySeg::StringSeg(lazy_map),
            DbKeySeg::StringSeg(data),
            DbKeySeg::StringSeg(epoch),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_STATE_STORAGE_KEY
            && lazy_map == epoched::LAZY_MAP_SUB_KEY
            && data == lazy_map::DATA_SUBKEY =>
        {
            let epoch = Epoch::parse(epoch.clone())
                .expect("Should be able to parse the epoch");
            Some((validator, epoch))
        }
        _ => None,
    }
}

/// Is storage key for a validator state's last update or oldest epoch?
pub fn is_validator_state_epoched_meta_key(key: &Key) -> bool {
    if key.segments.len() >= 5 {
        match &key.segments[..5] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(_validator),
                DbKeySeg::StringSeg(key),
                DbKeySeg::StringSeg(data),
            ] => {
                addr == &ADDRESS
                    && prefix == VALIDATOR_STORAGE_PREFIX
                    && key == VALIDATOR_STATE_STORAGE_KEY
                    && (data == epoched::LAST_UPDATE_SUB_KEY
                        || data == epoched::OLDEST_EPOCH_SUB_KEY)
            }
            _ => false,
        }
    } else {
        false
    }
}

/// Storage key for validator's deltas.
pub fn validator_deltas_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_DELTAS_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's total deltas?
pub fn is_validator_deltas_key(key: &Key) -> bool {
    if key.segments.len() >= 4 {
        match &key.segments[..4] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(_validator),
                DbKeySeg::StringSeg(key),
            ] => {
                addr == &ADDRESS
                    && prefix == VALIDATOR_STORAGE_PREFIX
                    && key == VALIDATOR_DELTAS_STORAGE_KEY
            }
            _ => false,
        }
    } else {
        false
    }
}

/// Storage prefix for all active validators (consensus, below-capacity,
/// below-threshold, inactive, jailed)
pub fn validator_addresses_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&VALIDATOR_ADDRESSES_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is the storage key a prefix for all active validators?
pub fn is_validator_addresses_key(key: &Key) -> bool {
    if key.segments.len() >= 2 {
        match &key.segments[..2] {
            [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(prefix)] => {
                addr == &ADDRESS && prefix == VALIDATOR_ADDRESSES_KEY
            }
            _ => false,
        }
    } else {
        false
    }
}

/// Storage prefix for slashes.
pub fn slashes_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&SLASHES_PREFIX.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for all slashes.
pub fn enqueued_slashes_key() -> Key {
    // slashes_prefix()
    Key::from(ADDRESS.to_db_key())
        .push(&ENQUEUED_SLASHES_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for validator's slashes.
pub fn validator_slashes_key(validator: &Address) -> Key {
    slashes_prefix()
        .push(&validator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for a validator's slashes
pub fn is_validator_slashes_key(key: &Key) -> Option<Address> {
    if key.segments.len() >= 5 {
        match &key.segments[..5] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(validator),
                DbKeySeg::StringSeg(data),
                DbKeySeg::StringSeg(_index),
            ] if addr == &ADDRESS
                && prefix == SLASHES_PREFIX
                && data == lazy_vec::DATA_SUBKEY =>
            {
                Some(validator.clone())
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Storage key for the last (most recent) epoch in which a slashable offense
/// was detected for a given validator
pub fn validator_last_slash_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_LAST_SLASH_EPOCH.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key prefix for all bonds.
pub fn bonds_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&BOND_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key prefix for all bonds of the given source address.
pub fn bonds_for_source_prefix(source: &Address) -> Key {
    bonds_prefix()
        .push(&source.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Storage key for a bond with the given ID (source and validator).
pub fn bond_key(bond_id: &BondId) -> Key {
    bonds_for_source_prefix(&bond_id.source)
        .push(&bond_id.validator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for a bond? Returns the bond ID and bond start epoch if so.
pub fn is_bond_key(key: &Key) -> Option<(BondId, Epoch)> {
    if key.segments.len() >= 7 {
        match &key.segments[..7] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(source),
                DbKeySeg::AddressSeg(validator),
                DbKeySeg::StringSeg(lazy_map),
                DbKeySeg::StringSeg(data),
                DbKeySeg::StringSeg(epoch_str),
            ] if addr == &ADDRESS
                && prefix == BOND_STORAGE_KEY
                && lazy_map == epoched::LAZY_MAP_SUB_KEY
                && data == lazy_map::DATA_SUBKEY =>
            {
                let start = Epoch::parse(epoch_str.clone()).ok()?;
                Some((
                    BondId {
                        source: source.clone(),
                        validator: validator.clone(),
                    },
                    start,
                ))
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Is storage key for a bond last update or oldest epoch? Returns the bond ID
/// if so.
pub fn is_bond_epoched_meta_key(key: &Key) -> Option<BondId> {
    if key.segments.len() >= 5 {
        match &key.segments[..5] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(source),
                DbKeySeg::AddressSeg(validator),
                DbKeySeg::StringSeg(data),
            ] if addr == &ADDRESS
                && prefix == BOND_STORAGE_KEY
                && (data == epoched::LAST_UPDATE_SUB_KEY
                    || data == epoched::OLDEST_EPOCH_SUB_KEY) =>
            {
                Some(BondId {
                    source: source.clone(),
                    validator: validator.clone(),
                })
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Storage key for the total bonds for a given validator.
pub fn validator_total_bonded_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_TOTAL_BONDED_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is the storage key for the total bonds or unbonds for a validator?
pub fn is_validator_total_bond_or_unbond_key(key: &Key) -> bool {
    if key.segments.len() >= 4 {
        match &key.segments[..4] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(val_prefix),
                DbKeySeg::AddressSeg(_validator),
                DbKeySeg::StringSeg(prefix),
            ] => {
                addr == &ADDRESS
                    && val_prefix == VALIDATOR_STORAGE_PREFIX
                    && (prefix == VALIDATOR_TOTAL_BONDED_STORAGE_KEY
                        || prefix == VALIDATOR_TOTAL_UNBONDED_STORAGE_KEY)
            }
            _ => false,
        }
    } else {
        false
    }
}

/// Storage key prefix for all unbonds.
pub fn unbonds_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&UNBOND_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key prefix for all unbonds of the given source address.
pub fn unbonds_for_source_prefix(source: &Address) -> Key {
    unbonds_prefix()
        .push(&source.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Storage key for an unbond with the given ID (source and validator).
pub fn unbond_key(bond_id: &BondId) -> Key {
    unbonds_for_source_prefix(&bond_id.source)
        .push(&bond_id.validator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for an unbond? Returns the bond ID and unbond start and
/// withdraw epoch if it is.
pub fn is_unbond_key(key: &Key) -> Option<(BondId, Epoch, Epoch)> {
    if key.segments.len() >= 8 {
        match &key.segments[..8] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(source),
                DbKeySeg::AddressSeg(validator),
                DbKeySeg::StringSeg(data_1),
                DbKeySeg::StringSeg(start_epoch_str),
                DbKeySeg::StringSeg(data_2),
                DbKeySeg::StringSeg(withdraw_epoch_str),
            ] if addr == &ADDRESS
                && prefix == UNBOND_STORAGE_KEY
                && data_1 == lazy_map::DATA_SUBKEY
                && data_2 == lazy_map::DATA_SUBKEY =>
            {
                let withdraw = Epoch::parse(withdraw_epoch_str.clone()).ok()?;
                let start = Epoch::parse(start_epoch_str.clone()).ok()?;
                Some((
                    BondId {
                        source: source.clone(),
                        validator: validator.clone(),
                    },
                    start,
                    withdraw,
                ))
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Storage key for validator's total-unbonded amount to track for slashing
pub fn validator_total_unbonded_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_TOTAL_UNBONDED_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage prefix for validator sets.
pub fn validator_sets_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&VALIDATOR_SETS_STORAGE_PREFIX.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for consensus validator set
pub fn consensus_validator_set_key() -> Key {
    validator_sets_prefix()
        .push(&CONSENSUS_VALIDATOR_SET_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for below-capacity validator set
pub fn below_capacity_validator_set_key() -> Key {
    validator_sets_prefix()
        .push(&BELOW_CAPACITY_VALIDATOR_SET_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for the consensus validator set?
pub fn is_consensus_validator_set_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key), DbKeySeg::StringSeg(set_type), DbKeySeg::StringSeg(lazy_map), DbKeySeg::StringSeg(data), DbKeySeg::StringSeg(_epoch), DbKeySeg::StringSeg(_), DbKeySeg::StringSeg(_amount), DbKeySeg::StringSeg(_), DbKeySeg::StringSeg(_position)] if addr == &ADDRESS && key == VALIDATOR_SETS_STORAGE_PREFIX && set_type == CONSENSUS_VALIDATOR_SET_STORAGE_KEY && lazy_map == epoched::LAZY_MAP_SUB_KEY && data == lazy_map::DATA_SUBKEY)
}

/// Is storage key for the below-capacity validator set?
pub fn is_below_capacity_validator_set_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key), DbKeySeg::StringSeg(set_type), DbKeySeg::StringSeg(lazy_map), DbKeySeg::StringSeg(data), DbKeySeg::StringSeg(_epoch), DbKeySeg::StringSeg(_), DbKeySeg::StringSeg(_amount), DbKeySeg::StringSeg(_), DbKeySeg::StringSeg(_position)] if addr == &ADDRESS && key == VALIDATOR_SETS_STORAGE_PREFIX && set_type == BELOW_CAPACITY_VALIDATOR_SET_STORAGE_KEY && lazy_map == epoched::LAZY_MAP_SUB_KEY && data == lazy_map::DATA_SUBKEY)
}

/// Storage key for total consensus stake
pub fn total_consensus_stake_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&TOTAL_CONSENSUS_STAKE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a total consensus stake key")
}

/// Is storage key for the total consensus stake?
pub fn is_total_consensus_stake_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(key)
            ] if addr == &ADDRESS && key == TOTAL_CONSENSUS_STAKE_STORAGE_KEY)
}

/// Storage key for total deltas of all validators.
pub fn total_deltas_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&TOTAL_DELTAS_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for total deltas of all validators?
pub fn is_total_deltas_key(key: &Key) -> bool {
    if key.segments.len() >= 2 {
        match &key.segments[..2] {
            [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(prefix)] => {
                addr == &ADDRESS && prefix == TOTAL_DELTAS_STORAGE_KEY
            }
            _ => false,
        }
    } else {
        false
    }
}

/// Storage key for block proposer address of the previous block.
pub fn last_block_proposer_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&LAST_BLOCK_PROPOSER_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for block proposer address of the previous block?
pub fn is_last_block_proposer_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)] if addr == &ADDRESS && key == LAST_BLOCK_PROPOSER_STORAGE_KEY)
}

/// Storage key for the consensus validator set rewards accumulator.
pub fn consensus_validator_rewards_accumulator_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&CONSENSUS_VALIDATOR_SET_ACCUMULATOR_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for the consensus validator set?
pub fn is_consensus_validator_set_accumulator_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(key),
        ] if addr == &ADDRESS
            && key == CONSENSUS_VALIDATOR_SET_ACCUMULATOR_STORAGE_KEY)
}

/// Storage prefix for epoch at which an account last claimed PoS inflationary
/// rewards.
pub fn last_pos_reward_claim_epoch_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&LAST_REWARD_CLAIM_EPOCH.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for epoch at which an account last claimed PoS inflationary
/// rewards.
pub fn last_pos_reward_claim_epoch_key(
    delegator: &Address,
    validator: &Address,
) -> Key {
    last_pos_reward_claim_epoch_prefix()
        .push(&delegator.to_db_key())
        .expect("Cannot obtain a storage key")
        .push(&validator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Is the storage key for epoch at which an account last claimed PoS
/// inflationary rewards? Return the bond ID if so.
pub fn is_last_pos_reward_claim_epoch_key(key: &Key) -> Option<BondId> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(key),
            DbKeySeg::AddressSeg(source),
            DbKeySeg::AddressSeg(validator),
        ] if addr == &ADDRESS && key == LAST_REWARD_CLAIM_EPOCH => {
            Some(BondId {
                source: source.clone(),
                validator: validator.clone(),
            })
        }
        _ => None,
    }
}

/// Get validator address from bond key
pub fn get_validator_address_from_bond(key: &Key) -> Option<Address> {
    match key.get_at(3) {
        Some(segment) => match segment {
            DbKeySeg::AddressSeg(addr) => Some(addr.clone()),
            DbKeySeg::StringSeg(_) => None,
        },
        None => None,
    }
}

/// Storage key for validator set positions
pub fn validator_set_positions_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&VALIDATOR_SET_POSITIONS_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is the storage key for validator set positions?
pub fn is_validator_set_positions_key(key: &Key) -> bool {
    if key.segments.len() >= 2 {
        match &key.segments[..2] {
            [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(prefix)] => {
                addr == &ADDRESS && prefix == VALIDATOR_SET_POSITIONS_KEY
            }
            _ => false,
        }
    } else {
        false
    }
}

/// Storage key for consensus keys set.
pub fn consensus_keys_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&CONSENSUS_KEYS.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for consensus keys set?
pub fn is_consensus_keys_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)] if addr == &ADDRESS && key == CONSENSUS_KEYS)
}

/// Storage key for a validator's email
pub fn validator_email_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_EMAIL_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for a validator's description
pub fn validator_description_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_DESCRIPTION_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for a validator's website
pub fn validator_website_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_WEBSITE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for a validator's discord handle
pub fn validator_discord_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_DISCORD_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for a validator's avatar
pub fn validator_avatar_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_AVATAR_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for a validator's name
pub fn validator_name_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_NAME_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage prefix for the liveness data of the cosnensus validator set.
pub fn liveness_data_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&LIVENESS_PREFIX.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for the liveness records.
pub fn liveness_missed_votes_key() -> Key {
    liveness_data_prefix()
        .push(&LIVENESS_MISSED_VOTES.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for the liveness data.
pub fn liveness_sum_missed_votes_key() -> Key {
    liveness_data_prefix()
        .push(&LIVENESS_MISSED_VOTES_SUM.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for the last epoch's staked ratio.
pub fn last_staked_ratio_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&LAST_STAKED_RATIO_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for the last epoch's PoS inflation amount.
pub fn last_pos_inflation_amount_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&LAST_POS_INFLATION_AMOUNT_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for total active deltas (Consensus, Below-Capacity, and
/// Below-threshold validators).
pub fn total_active_deltas_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&TOTAL_ACTIVE_DELTAS_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for total active deltas?
pub fn is_total_active_deltas_key(key: &Key) -> bool {
    if key.segments.len() >= 2 {
        match &key.segments[..2] {
            [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(prefix)] => {
                addr == &ADDRESS && prefix == TOTAL_ACTIVE_DELTAS_KEY
            }
            _ => false,
        }
    } else {
        false
    }
}

/// Storage prefix for the delegation targets.
pub fn delegation_targets_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&DELEGATION_TARGETS_PREFIX.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for the delegation targets of a delegator.
pub fn delegation_targets_key(delegator: &Address) -> Key {
    delegation_targets_prefix()
        .push(&delegator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for the delegation targets of a delegator?
pub fn is_delegation_targets_key(key: &Key) -> bool {
    if key.segments.len() >= 3 {
        match &key.segments[..3] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(_delegator),
            ] => addr == &ADDRESS && prefix == DELEGATION_TARGETS_PREFIX,
            _ => false,
        }
    } else {
        false
    }
}
