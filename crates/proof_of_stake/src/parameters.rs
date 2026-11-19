//! Proof-of-Stake system parameters

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::arith::checked;
use namada_core::chain::Epoch;
use namada_core::dec::Dec;
use namada_core::token;
use namada_core::uint::Uint;
#[cfg(test)]
use namada_governance::parameters::GovernanceParameters;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_state::{Result, StorageRead, StorageWrite};
use serde::Serialize;
use thiserror::Error;

use crate::storage_key;

/// Proof-of-Stake system parameters. This includes parameters that are used in
/// PoS but are read from other accounts storage (governance).
#[derive(
    Debug, Clone, BorshDeserialize, BorshDeserializer, BorshSerialize, Serialize,
)]
pub struct PosParams {
    /// PoS-owned params
    pub owned: OwnedPosParams,
    /// Governance param - Maximum proposal voting period in epochs.
    /// This param is stored in governance.
    pub max_proposal_period: u64,
}

/// Proof-of-Stake system parameters owned by the PoS address, set at genesis
/// and can only be changed via governance
#[derive(
    Debug, Clone, BorshDeserialize, BorshDeserializer, BorshSerialize, Serialize,
)]
pub struct OwnedPosParams {
    /// A maximum number of consensus validators
    pub max_validator_slots: u64,
    /// Any change applied during an epoch `n` will become active at the
    /// beginning of epoch `n + pipeline_len`.
    pub pipeline_len: u64,
    /// How many epochs after a committed fault a validator can be slashed.
    /// If a fault is detected in epoch `n`, it can slashed up until the end of
    /// `n + slashable_period_len` epoch.
    /// The value must be greater or equal to `pipeline_len`.
    pub unbonding_len: u64,
    /// The voting power per fundamental unit of the staking token (namnam).
    /// Used in validators' voting power calculation to interface with
    /// tendermint.
    pub tm_votes_per_token: Dec,
    /// Amount of tokens rewarded to a validator for proposing a block
    pub block_proposer_reward: Dec,
    /// Amount of tokens rewarded to each validator that voted on a block
    /// proposal
    pub block_vote_reward: Dec,
    /// Maximum staking rewards rate per annum
    pub max_inflation_rate: Dec,
    /// Target ratio of staked NAM tokens to total NAM tokens
    pub target_staked_ratio: Dec,
    /// Fraction of validator's stake that should be slashed on a duplicate
    /// vote.
    pub duplicate_vote_min_slash_rate: Dec,
    /// Fraction of validator's stake that should be slashed on a light client
    /// attack.
    pub light_client_attack_min_slash_rate: Dec,
    /// Number of epochs above and below (separately) the current epoch to
    /// consider when doing cubic slashing
    pub cubic_slashing_window_length: u64,
    /// The minimum amount of bonded tokens that a validator needs to be in
    /// either the `consensus` or `below_capacity` validator sets
    pub validator_stake_threshold: token::Amount,
    /// The length, in blocks, of the sliding window for consensus validators
    /// inactivity verification
    pub liveness_window_check: u64,
    /// The minimum required activity of consesus validators, in percentage,
    /// over the `liveness_window_check`
    pub liveness_threshold: Dec,
    /// PoS gain p (read only)
    pub rewards_gain_p: Dec,
    /// PoS gain d (read only)
    pub rewards_gain_d: Dec,
}

/// Read "max_validator_slots" parameter
pub fn read_max_validator_slots_param<S>(storage: &S) -> Result<u64>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_max_validator_slots_key())?
        .expect("Required \"max_validator_slots\" param"))
}

/// Read "pipeline_len" parameter
pub fn read_pipeline_len_param<S>(storage: &S) -> Result<u64>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_pipeline_len_key())?
        .expect("Required \"pipeline_len\" param"))
}

/// Read "unbonding_len" parameter
pub fn read_unbonding_len_param<S>(storage: &S) -> Result<u64>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_unbonding_len_key())?
        .expect("Required \"unbonding_len\" param"))
}

/// Read "tm_votes_per_token" parameter
pub fn read_tm_votes_per_token_param<S>(storage: &S) -> Result<Dec>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_tm_votes_per_token_key())?
        .expect("Required \"tm_votes_per_token\" param"))
}

/// Read "block_proposer_reward" parameter
pub fn read_block_proposer_reward_param<S>(storage: &S) -> Result<Dec>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_block_proposer_reward_key())?
        .expect("Required \"block_proposer_reward\" param"))
}

/// Read "block_vote_reward" parameter
pub fn read_block_vote_reward_param<S>(storage: &S) -> Result<Dec>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_block_vote_reward_key())?
        .expect("Required \"block_vote_reward\" param"))
}

/// Read "max_inflation_rate" parameter
pub fn read_max_inflation_rate_param<S>(storage: &S) -> Result<Dec>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_max_inflation_rate_key())?
        .expect("Required \"max_inflation_rate\" param"))
}

/// Read "target_staked_ratio" parameter
pub fn read_target_staked_ratio_param<S>(storage: &S) -> Result<Dec>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_target_staked_ratio_key())?
        .expect("Required \"target_staked_ratio\" param"))
}

/// Read "duplicate_vote_min_slash_rate" parameter
pub fn read_duplicate_vote_min_slash_rate_param<S>(storage: &S) -> Result<Dec>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_duplicate_vote_min_slash_rate_key())?
        .expect("Required \"duplicate_vote_min_slash_rate\" param"))
}

/// Read "light_client_attack_min_slash_rate" parameter
pub fn read_light_client_attack_min_slash_rate_param<S>(
    storage: &S,
) -> Result<Dec>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_light_client_attack_min_slash_rate_key())?
        .expect("Required \"light_client_attack_min_slash_rate\" param"))
}

/// Read "cubic_slashing_window_length" parameter
pub fn read_cubic_slashing_window_length_param<S>(storage: &S) -> Result<u64>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_cubic_slashing_window_length_key())?
        .expect("Required \"cubic_slashing_window_length\" param"))
}

/// Read "validator_stake_threshold" parameter
pub fn read_validator_stake_threshold_param<S>(
    storage: &S,
) -> Result<token::Amount>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_validator_stake_threshold_key())?
        .expect("Required \"validator_stake_threshold\" param"))
}

/// Read "liveness_window_check" parameter
pub fn read_liveness_window_check_param<S>(storage: &S) -> Result<u64>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_liveness_window_check_key())?
        .expect("Required \"liveness_window_check\" param"))
}

/// Read "liveness_threshold" parameter
pub fn read_liveness_threshold_param<S>(storage: &S) -> Result<Dec>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_liveness_threshold_key())?
        .expect("Required \"liveness_threshold\" param"))
}

/// Read "rewards_gain_p" parameter
pub fn read_rewards_gain_p_param<S>(storage: &S) -> Result<Dec>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_rewards_gain_p_key())?
        .expect("Required \"rewards_gain_p\" param"))
}

/// Read "rewards_gain_d" parameter
pub fn read_rewards_gain_d_param<S>(storage: &S) -> Result<Dec>
where
    S: StorageRead,
{
    Ok(storage
        .read(&storage_key::param_rewards_gain_d_key())?
        .expect("Required \"rewards_gain_d\" param"))
}

/// Write "max_validator_slots" parameter
pub fn write_max_validator_slots_param<S>(
    storage: &mut S,
    value: u64,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_max_validator_slots_key(), value)
}

/// Write "pipeline_len" parameter
pub fn write_pipeline_len_param<S>(storage: &mut S, value: u64) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_pipeline_len_key(), value)
}

/// Write "unbonding_len" parameter
pub fn write_unbonding_len_param<S>(storage: &mut S, value: u64) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_unbonding_len_key(), value)
}

/// Write "tm_votes_per_token" parameter
pub fn write_tm_votes_per_token_param<S>(
    storage: &mut S,
    value: Dec,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_tm_votes_per_token_key(), value)
}

/// Write "block_proposer_reward" parameter
pub fn write_block_proposer_reward_param<S>(
    storage: &mut S,
    value: Dec,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_block_proposer_reward_key(), value)
}

/// Write "block_vote_reward" parameter
pub fn write_block_vote_reward_param<S>(
    storage: &mut S,
    value: Dec,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_block_vote_reward_key(), value)
}

/// Write "max_inflation_rate" parameter
pub fn write_max_inflation_rate_param<S>(
    storage: &mut S,
    value: Dec,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_max_inflation_rate_key(), value)
}

/// Write "target_staked_ratio" parameter
pub fn write_target_staked_ratio_param<S>(
    storage: &mut S,
    value: Dec,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_target_staked_ratio_key(), value)
}

/// Write "duplicate_vote_min_slash_rate" parameter
pub fn write_duplicate_vote_min_slash_rate_param<S>(
    storage: &mut S,
    value: Dec,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(
        &storage_key::param_duplicate_vote_min_slash_rate_key(),
        value,
    )
}

/// Write "light_client_attack_min_slash_rate" parameter
pub fn write_light_client_attack_min_slash_rate_param<S>(
    storage: &mut S,
    value: Dec,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(
        &storage_key::param_light_client_attack_min_slash_rate_key(),
        value,
    )
}

/// Write "cubic_slashing_window_length" parameter
pub fn write_cubic_slashing_window_length_param<S>(
    storage: &mut S,
    value: u64,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(
        &storage_key::param_cubic_slashing_window_length_key(),
        value,
    )
}

/// Write "validator_stake_threshold" parameter
pub fn write_validator_stake_threshold_param<S>(
    storage: &mut S,
    value: token::Amount,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_validator_stake_threshold_key(), value)
}

/// Write "liveness_window_check" parameter
pub fn write_liveness_window_check_param<S>(
    storage: &mut S,
    value: u64,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_liveness_window_check_key(), value)
}

/// Write "liveness_threshold" parameter
pub fn write_liveness_threshold_param<S>(
    storage: &mut S,
    value: Dec,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_liveness_threshold_key(), value)
}

/// Write "rewards_gain_p" parameter
pub fn write_rewards_gain_p_param<S>(storage: &mut S, value: Dec) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_rewards_gain_p_key(), value)
}

/// Write "rewards_gain_d" parameter
pub fn write_rewards_gain_d_param<S>(storage: &mut S, value: Dec) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    storage.write(&storage_key::param_rewards_gain_d_key(), value)
}

impl Default for OwnedPosParams {
    fn default() -> Self {
        Self {
            max_validator_slots: 100,
            pipeline_len: 2,
            unbonding_len: 21,
            // 1 voting power per 1 fundamental token (10^6 per NAM or 1 per
            // namnam)
            tm_votes_per_token: Dec::one(),
            block_proposer_reward: Dec::new(125, 3).expect("Test failed"),
            block_vote_reward: Dec::new(1, 1).expect("Test failed"),
            // PoS inflation of 10%
            max_inflation_rate: Dec::new(1, 1).expect("Test failed"),
            // target staked ratio of 2/3
            target_staked_ratio: Dec::new(6667, 4).expect("Test failed"),
            // slash 0.1%
            duplicate_vote_min_slash_rate: Dec::new(1, 3).expect("Test failed"),
            // slash 0.1%
            light_client_attack_min_slash_rate: Dec::new(1, 3)
                .expect("Test failed"),
            cubic_slashing_window_length: 1,
            validator_stake_threshold: token::Amount::native_whole(1_u64),
            liveness_window_check: 10_000,
            liveness_threshold: Dec::new(9, 1).expect("Test failed"),
            rewards_gain_p: Dec::from_str("0.25").expect("Test failed"),
            rewards_gain_d: Dec::from_str("0.25").expect("Test failed"),
        }
    }
}

#[cfg(test)]
impl Default for PosParams {
    fn default() -> Self {
        let owned = OwnedPosParams::default();
        let gov = GovernanceParameters::default();
        Self {
            owned,
            max_proposal_period: gov.max_proposal_period,
        }
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error(
        "Maximum total voting power is too large: got {0}, expected at most \
         {MAX_TOTAL_VOTING_POWER}"
    )]
    TotalVotingPowerTooLarge(Uint),
    #[error("Votes per token cannot be greater than 1, got {0}")]
    VotesPerTokenGreaterThanOne(Dec),
    #[error("Liveness threshold cannot be greater than 1, got {0}")]
    LivenessThresholdGreaterThanOne(Dec),
    #[error("Pipeline length must be >= 2, got {0}")]
    PipelineLenTooShort(u64),
    #[error(
        "Unbonding length must be > pipeline length. Got unbonding: {0}, \
         pipeline: {1}"
    )]
    UnbondingLenTooShort(u64, u64),
}

/// The maximum string length of any validator metadata
pub const MAX_VALIDATOR_METADATA_LEN: u64 = 500;

/// The number of fundamental units per whole token of the native staking token
pub const TOKENS_PER_NAM: u64 = 1_000_000;

/// From Tendermint: <https://github.com/tendermint/tendermint/blob/master/spec/abci/apps.md#updating-the-validator-set>
const MAX_TOTAL_VOTING_POWER: i64 = i64::MAX / 8;

/// Assuming token amount is `u64` in micro units.
const TOKEN_MAX_AMOUNT: u64 = u64::MAX / TOKENS_PER_NAM;

impl OwnedPosParams {
    /// Validate PoS parameters values. Returns an empty list if the values are
    /// valid.
    #[must_use]
    pub fn validate(&self) -> Vec<ValidationError> {
        let mut errors = vec![];

        if self.pipeline_len < 2 {
            errors
                .push(ValidationError::PipelineLenTooShort(self.pipeline_len));
        }

        if self.pipeline_len >= self.unbonding_len {
            errors.push(ValidationError::UnbondingLenTooShort(
                self.unbonding_len,
                self.pipeline_len,
            ))
        }

        // Check maximum total voting power cannot get larger than what
        // Tendermint allows
        let max_total_voting_power = checked!(
            self.tm_votes_per_token
                * TOKEN_MAX_AMOUNT
                * self.max_validator_slots
        )
        .expect("Must be able to calculate max total voting power")
        .to_uint()
        .expect("Cannot fail");
        match i64::try_from(max_total_voting_power) {
            Ok(max_total_voting_power_i64) => {
                if max_total_voting_power_i64 > MAX_TOTAL_VOTING_POWER {
                    errors.push(ValidationError::TotalVotingPowerTooLarge(
                        max_total_voting_power,
                    ))
                }
            }
            Err(_) => errors.push(ValidationError::TotalVotingPowerTooLarge(
                max_total_voting_power,
            )),
        }

        // Check that there is no more than 1 vote per token
        if self.tm_votes_per_token > Dec::one() {
            errors.push(ValidationError::VotesPerTokenGreaterThanOne(
                self.tm_votes_per_token,
            ))
        }

        if self.liveness_threshold > Dec::one() {
            errors.push(ValidationError::LivenessThresholdGreaterThanOne(
                self.liveness_threshold,
            ))
        }

        errors
    }

    /// Get the epoch offset from which an unbonded bond can withdrawn
    pub fn withdrawable_epoch_offset(&self) -> u64 {
        checked!(
            self.pipeline_len
                + self.unbonding_len
                + self.cubic_slashing_window_length
        )
        .expect("Params addition must not overflow")
    }

    /// Get the epoch offset for processing slashes
    pub fn slash_processing_epoch_offset(&self) -> u64 {
        checked!(self.unbonding_len + self.cubic_slashing_window_length + 1)
            .expect("Params addition must not overflow")
    }

    /// Get the first and the last epoch of a cubic slash window.
    pub fn cubic_slash_epoch_window(
        &self,
        infraction_epoch: Epoch,
    ) -> (Epoch, Epoch) {
        let start = infraction_epoch
            .saturating_sub(Epoch(self.cubic_slashing_window_length));
        let end =
            infraction_epoch.unchecked_add(self.cubic_slashing_window_length);
        (start, end)
    }

    /// Get the redelegation end epoch from the start epoch
    pub fn redelegation_end_epoch_from_start(&self, end: Epoch) -> Epoch {
        end.unchecked_add(self.pipeline_len)
    }

    /// Get the redelegation start epoch from the end epoch
    pub fn redelegation_start_epoch_from_end(&self, end: Epoch) -> Epoch {
        end.checked_sub(self.pipeline_len)
            .expect("End epoch is always gt. pipeline")
    }

    /// Determine if the infraction is in the lazy slashing window for a
    /// redelegation source validator. Any source validator slashes that
    /// were processed before redelegation was applied will be applied
    /// eagerly on the redelegation amount, so this function will only return
    /// `true` for applicable infractions that were processed after
    /// the redelegation was applied.
    ///
    /// The `redel_start` is the epoch in which the redelegation was applied and
    /// `redel_end` the epoch in which it no longer contributed to source
    /// validator's stake.
    pub fn in_redelegation_slashing_window(
        &self,
        infraction_epoch: Epoch,
        redel_start: Epoch,
        redel_end: Epoch,
    ) -> bool {
        let processing_epoch = infraction_epoch
            .unchecked_add(self.slash_processing_epoch_offset());
        redel_start < processing_epoch && infraction_epoch < redel_end
    }

    /// A test helper to add the default gov params to PoS params.
    #[cfg(test)]
    pub fn with_default_gov_params(self) -> PosParams {
        let gov = GovernanceParameters::default();
        PosParams {
            owned: self,
            max_proposal_period: gov.max_proposal_period,
        }
    }

    /// A test helper to add the default gov params to PoS params.
    #[cfg(test)]
    pub fn with_gov_params(self, gov: &GovernanceParameters) -> PosParams {
        PosParams {
            owned: self,
            max_proposal_period: gov.max_proposal_period,
        }
    }
}

impl std::ops::Deref for PosParams {
    type Target = OwnedPosParams;

    fn deref(&self) -> &Self::Target {
        &self.owned
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use testing::arb_pos_params;

    use super::*;

    proptest! {
        #[test]
        fn test_validate_arb_pos_params(pos_params in arb_pos_params(None)) {
            let errors = pos_params.validate();
            assert!(
                errors.is_empty(),
                "Arbitrary PoS parameters must be valid, `validate()` failed. \
                Parameters {:#?}\nErrors: {:#?}",
                pos_params,
                errors
            );
        }
    }
}

/// Testing helpers
#[allow(clippy::arithmetic_side_effects)]
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use proptest::prelude::*;

    use super::*;

    prop_compose! {
        /// Generate arbitrary valid ([`PosParams::validate`]) PoS parameters.
        pub fn arb_pos_params(num_max_validator_slots: Option<u64>)
            (pipeline_len in Just(2))
            (max_validator_slots in 3..num_max_validator_slots.unwrap_or(128),
            // `unbonding_len` > `pipeline_len`
            unbonding_len in pipeline_len + 1..pipeline_len + 8,
            pipeline_len in Just(pipeline_len),
            tm_votes_per_token in 1..10_001_i128)
            -> OwnedPosParams {
            OwnedPosParams {
                max_validator_slots,
                pipeline_len,
                unbonding_len,
                tm_votes_per_token: Dec::new(tm_votes_per_token, 4).expect("Test failed"),
                // The rest of the parameters that are not being used in the PoS
                // VP are constant for now
                ..Default::default()
            }
        }
    }

    /// Get an arbitrary rate - a Dec value between 0 and 1 inclusive, with
    /// some fixed precision
    pub fn arb_rate() -> impl Strategy<Value = Dec> {
        (0..=100_000_i128)
            .prop_map(|num| Dec::new(num, 5).expect("Test failed"))
    }
}
