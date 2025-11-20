//! Test PoS transitions with a state machine

#![allow(clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::{AddAssign, Deref};
use std::{cmp, mem};

use assert_matches::assert_matches;
use derivative::Derivative;
use itertools::Itertools;
use namada_core::address::{self, Address};
use namada_core::chain::Epoch;
use namada_core::collections::HashSet;
use namada_core::dec::Dec;
use namada_core::key;
use namada_core::key::common::PublicKey;
use namada_core::token::Change;
use namada_governance::parameters::GovernanceParameters;
use namada_state::testing::TestState;
use namada_trans_token::{self as token, read_balance};
use proptest::prelude::*;
use proptest::test_runner::Config;
use proptest_state_machine::{
    ReferenceStateMachine, StateMachineTest, prop_state_machine,
};
// Use `RUST_LOG=info` (or another tracing level) and `--nocapture` to see
// `tracing` logs from tests
use test_log::test;
use yansi::Paint;

use super::helpers::advance_epoch;
use super::utils::DbgPrintDiff;
use crate::lazy_map::{NestedSubKey, SubKey};
use crate::parameters::PosParams;
use crate::parameters::testing::arb_rate;
use crate::slashing::find_slashes_in_range;
use crate::storage::{
    enqueued_slashes_handle, read_all_validator_addresses,
    read_below_capacity_validator_set_addresses,
    read_below_capacity_validator_set_addresses_with_stake,
    read_consensus_validator_set_addresses_with_stake,
};
use crate::tests::helpers::arb_params_and_genesis_validators;
use crate::tests::utils::pause_for_enter;
use crate::tests::{
    GovStore, become_validator, bond_tokens, find_delegations, process_slashes,
    read_below_threshold_validator_set_addresses, read_pos_params,
    redelegate_tokens, slash, unbond_tokens, unjail_validator, withdraw_tokens,
};
use crate::types::{
    BondId, GenesisValidator, ReverseOrdTokenAmount, Slash, SlashType,
    ValidatorState, WeightedValidator,
};
use crate::{
    RedelegationError, StorageRead, below_capacity_validator_set_handle,
    bond_handle, consensus_validator_set_handle,
    delegator_redelegated_bonds_handle, validator_deltas_handle,
    validator_slashes_handle, validator_state_handle,
};

prop_state_machine! {
    #![proptest_config(Config {
        cases: 2,
        .. Config::default()
    })]
    #[ignore]
    #[test]
    /// A `StateMachineTest` implemented on `PosState`
    fn pos_state_machine_test_v2(sequential 1000 => ConcretePosState);
}

/// Abstract representation of a state of PoS system
#[derive(Clone, Derivative)]
#[derivative(Debug)]
struct AbstractPosState {
    /// Current epoch
    epoch: Epoch,
    /// Parameters
    params: PosParams,
    /// Governance parameters used to construct `params`
    gov_params: GovernanceParameters,
    /// Genesis validators
    #[derivative(Debug = "ignore")]
    genesis_validators: Vec<GenesisValidator>,
    /// Records of bonds, unbonds, withdrawal and redelegations with slashes,
    /// if any
    validator_records: BTreeMap<Address, ValidatorRecords>,
    /// Validator stakes. These are NOT deltas.
    /// Pipelined.
    validator_stakes: BTreeMap<Epoch, BTreeMap<Address, token::Change>>,
    /// Consensus validator set. Pipelined.
    consensus_set: BTreeMap<Epoch, BTreeMap<token::Amount, VecDeque<Address>>>,
    /// Below-capacity validator set. Pipelined.
    below_capacity_set:
        BTreeMap<Epoch, BTreeMap<ReverseOrdTokenAmount, VecDeque<Address>>>,
    /// Below-threshold validator set. Pipelined.
    below_threshold_set: BTreeMap<Epoch, HashSet<Address>>,
    /// Validator states. Pipelined.
    validator_states: BTreeMap<Epoch, BTreeMap<Address, ValidatorState>>,
    /// Validator slashes post-processing
    validator_slashes: BTreeMap<Address, Vec<Slash>>,
    /// Enqueued slashes pre-processing
    enqueued_slashes: BTreeMap<Epoch, BTreeMap<Address, Vec<Slash>>>,
    /// The last epoch in which a validator committed an infraction
    validator_last_slash_epochs: BTreeMap<Address, Epoch>,
}

impl AbstractPosState {
    /// Copy validator sets and validator states at the given epoch from its
    /// predecessor
    fn copy_discrete_epoched_data(&mut self, epoch: Epoch) {
        let prev_epoch = epoch.prev().unwrap();
        // Copy the non-delta data from the last epoch into the new one
        self.consensus_set.insert(
            epoch,
            self.consensus_set.get(&prev_epoch).unwrap().clone(),
        );
        self.below_capacity_set.insert(
            epoch,
            self.below_capacity_set.get(&prev_epoch).unwrap().clone(),
        );
        self.below_threshold_set.insert(
            epoch,
            self.below_threshold_set.get(&prev_epoch).unwrap().clone(),
        );
        self.validator_states.insert(
            epoch,
            self.validator_states.get(&prev_epoch).unwrap().clone(),
        );
        self.validator_stakes.insert(
            epoch,
            self.validator_stakes.get(&prev_epoch).unwrap().clone(),
        );
    }

    /// Add a bond.
    fn bond(
        &mut self,
        BondId { source, validator }: &BondId,
        amount: token::Amount,
    ) {
        let start = self.pipeline();

        let records = self.records_mut(validator, source);
        let bond_at_start = records.bonds.entry(start).or_default();
        bond_at_start.tokens.amount += amount;

        let change = amount.change();
        let pipeline_state = self
            .validator_states
            .get(&start)
            .unwrap()
            .get(validator)
            .unwrap();
        // Validator sets need to be updated before total stake
        if *pipeline_state != ValidatorState::Jailed {
            self.update_validator_sets(validator, change, self.pipeline());
        }
        self.update_validator_total_stake(validator, change, self.pipeline());
    }

    /// Unbond a bond.
    fn unbond(
        &mut self,
        BondId { source, validator }: &BondId,
        amount: token::Amount,
    ) {
        // Last epoch in which it contributes to stake
        let end = self.pipeline().prev().unwrap();
        let withdrawable_epoch =
            self.epoch + self.params.withdrawable_epoch_offset();
        let pipeline_len = self.params.pipeline_len;

        let records = self.records_mut(validator, source);
        // The amount requested is before any slashing that may be applicable
        let mut to_unbond = amount;
        let mut amount_after_slashing = token::Amount::zero();

        'bonds_iter: for (&start, bond) in records.bonds.iter_mut().rev() {
            // In every loop, try to unbond redelegations first. We have to
            // go in reverse order of the start epoch to match the order of
            // unbond in the implementation.
            for (dest_validator, redelegs) in bond.incoming_redelegs.iter_mut()
            {
                let _redeleg_epoch = start - pipeline_len;

                for (&src_bond_start, redeleg) in
                    redelegs.tokens.iter_mut().rev()
                {
                    let amount_before_slashing =
                        redeleg.amount_before_slashing();

                    let unbonded = if to_unbond >= amount_before_slashing {
                        // Unbond the whole bond
                        to_unbond -= amount_before_slashing;
                        amount_after_slashing += redeleg.amount;

                        mem::take(redeleg)
                    } else {
                        // We have to divide this bond in case there are slashes
                        let unbond_slash = to_unbond
                            .mul_ceil(redeleg.slash_rates_sum())
                            .unwrap();
                        let to_unbond_after_slash = to_unbond - unbond_slash;

                        to_unbond = token::Amount::zero();
                        amount_after_slashing += to_unbond_after_slash;

                        redeleg.amount -= to_unbond_after_slash;
                        let removed_slashes =
                            redeleg.subtract_slash(unbond_slash);

                        TokensWithSlashes {
                            amount: to_unbond_after_slash,
                            slashes: removed_slashes,
                        }
                    };

                    let unbond =
                        bond.unbonds.entry(end).or_insert_with(|| Unbond {
                            withdrawable_epoch,
                            tokens: Default::default(),
                            incoming_redelegs: Default::default(),
                        });
                    debug_assert_eq!(
                        unbond.withdrawable_epoch,
                        withdrawable_epoch
                    );
                    let redeleg_unbond = unbond
                        .incoming_redelegs
                        .entry(dest_validator.clone())
                        .or_default();
                    let redeleg_unbond_tokens = redeleg_unbond
                        .tokens
                        .entry(src_bond_start)
                        .or_default();
                    redeleg_unbond_tokens.amount += unbonded.amount;
                    redeleg_unbond_tokens.add_slashes(&unbonded.slashes);

                    // Stop once all is unbonded
                    if to_unbond.is_zero() {
                        break 'bonds_iter;
                    }
                }
            }

            // Then try to unbond regular bonds
            if !to_unbond.is_zero() {
                let amount_before_slashing =
                    bond.tokens.amount_before_slashing();

                let unbonded = if to_unbond >= amount_before_slashing {
                    // Unbond the whole bond
                    to_unbond -= amount_before_slashing;
                    amount_after_slashing += bond.tokens.amount;

                    mem::take(&mut bond.tokens)
                } else {
                    // We have to divide this bond in case there are slashes
                    let unbond_slash = to_unbond
                        .mul_ceil(bond.tokens.slash_rates_sum())
                        .unwrap();
                    let to_unbond_after_slash = to_unbond - unbond_slash;

                    to_unbond = token::Amount::zero();
                    amount_after_slashing += to_unbond_after_slash;

                    bond.tokens.amount -= to_unbond_after_slash;
                    let removed_slashes =
                        bond.tokens.subtract_slash(unbond_slash);

                    TokensWithSlashes {
                        amount: to_unbond_after_slash,
                        slashes: removed_slashes,
                    }
                };

                let unbond =
                    bond.unbonds.entry(end).or_insert_with(|| Unbond {
                        withdrawable_epoch,
                        tokens: Default::default(),
                        incoming_redelegs: Default::default(),
                    });
                debug_assert_eq!(unbond.withdrawable_epoch, withdrawable_epoch);
                unbond.tokens.amount += unbonded.amount;
                unbond.tokens.add_slashes(&unbonded.slashes);

                // Stop once all is unbonded
                if to_unbond.is_zero() {
                    break;
                }
            }
        }
        assert!(to_unbond.is_zero());

        let pipeline_state = self
            .validator_states
            .get(&self.pipeline())
            .unwrap()
            .get(validator)
            .unwrap();
        if *pipeline_state != ValidatorState::Jailed {
            self.update_validator_sets(
                validator,
                -amount_after_slashing.change(),
                self.pipeline(),
            );
        }
        self.update_validator_total_stake(
            validator,
            -amount_after_slashing.change(),
            self.pipeline(),
        );
    }

    /// Redelegate a bond.
    fn redelegate(
        &mut self,
        BondId { source, validator }: &BondId,
        new_validator: &Address,
        amount: token::Amount,
    ) {
        // Last epoch in which it contributes to stake of thhe source validator
        let current_epoch = self.epoch;
        let pipeline = self.pipeline();
        let src_end = pipeline.prev().unwrap();
        let withdrawable_epoch_offset = self.params.withdrawable_epoch_offset();
        let pipeline_len = self.params.pipeline_len;

        let records = self.records_mut(validator, source);

        // The amount requested is before any slashing that may be applicable
        let mut to_unbond = amount;
        let mut amount_after_slashing = token::Amount::zero();
        // Keyed by redelegation src bond start epoch
        let mut dest_incoming_redelegs =
            BTreeMap::<Epoch, TokensWithSlashes>::new();

        'bonds_iter: for (&start, bond) in records.bonds.iter_mut().rev() {
            // In every loop, try to redelegate redelegations first. We have to
            // go in reverse order of the start epoch to match the order of
            // redelegation in the implementation.
            for (_src_validator, redelegs) in
                bond.incoming_redelegs.iter_mut().rev()
            {
                let _redeleg_epoch = start - pipeline_len;

                for (_src_bond_start, redeleg) in
                    redelegs.tokens.iter_mut().rev()
                {
                    let amount_before_slashing =
                        redeleg.amount_before_slashing();

                    // No chained redelegations
                    if Epoch(
                        start.0.checked_sub(pipeline_len).unwrap_or_default(),
                    ) + withdrawable_epoch_offset
                        <= current_epoch
                    {
                        let unbonded = if to_unbond >= amount_before_slashing {
                            // Unbond the whole bond
                            to_unbond -= amount_before_slashing;
                            amount_after_slashing += redeleg.amount;

                            mem::take(redeleg)
                        } else {
                            // We have to divide this bond in case there are
                            // slashes
                            let unbond_slash = to_unbond
                                .mul_ceil(redeleg.slash_rates_sum())
                                .unwrap();
                            let to_unbond_after_slash =
                                to_unbond - unbond_slash;

                            to_unbond = token::Amount::zero();
                            amount_after_slashing += to_unbond_after_slash;

                            redeleg.amount -= to_unbond_after_slash;
                            let removed_slashes =
                                redeleg.subtract_slash(unbond_slash);

                            TokensWithSlashes {
                                amount: to_unbond_after_slash,
                                slashes: removed_slashes,
                            }
                        };

                        let outgoing_redeleg = bond
                            .outgoing_redelegs
                            .entry(src_end)
                            .or_default()
                            .entry(new_validator.clone())
                            .or_default();

                        outgoing_redeleg.amount += unbonded.amount;
                        outgoing_redeleg.add_slashes(&unbonded.slashes);

                        let redeleg =
                            dest_incoming_redelegs.entry(start).or_default();
                        redeleg.amount += unbonded.amount;
                        redeleg.add_slashes(&unbonded.slashes);

                        // Stop once all is unbonded
                        if to_unbond.is_zero() {
                            break 'bonds_iter;
                        }
                    }
                }
            }

            // Then try to redelegate regular bonds
            if !to_unbond.is_zero() {
                let amount_before_slashing =
                    bond.tokens.amount_before_slashing();

                let unbonded = if to_unbond >= amount_before_slashing {
                    // Unbond the whole bond
                    to_unbond -= amount_before_slashing;
                    amount_after_slashing += bond.tokens.amount;

                    mem::take(&mut bond.tokens)
                } else {
                    // We have to divide this bond in case there are slashes
                    let unbond_slash = to_unbond
                        .mul_ceil(bond.tokens.slash_rates_sum())
                        .unwrap();
                    let to_unbond_after_slash = to_unbond - unbond_slash;

                    to_unbond = token::Amount::zero();
                    amount_after_slashing += to_unbond_after_slash;

                    bond.tokens.amount -= to_unbond_after_slash;
                    let removed_slashes =
                        bond.tokens.subtract_slash(unbond_slash);

                    TokensWithSlashes {
                        amount: to_unbond_after_slash,
                        slashes: removed_slashes,
                    }
                };

                let outgoing_redeleg = bond
                    .outgoing_redelegs
                    .entry(src_end)
                    .or_default()
                    .entry(new_validator.clone())
                    .or_default();
                outgoing_redeleg.amount += unbonded.amount;
                outgoing_redeleg.add_slashes(&unbonded.slashes);
                let dest_incoming_redeleg =
                    dest_incoming_redelegs.entry(start).or_default();
                dest_incoming_redeleg.amount += unbonded.amount;
                dest_incoming_redeleg.add_slashes(&unbonded.slashes);
            }
            // Stop once all is unbonded
            if to_unbond.is_zero() {
                break;
            }
        }
        assert!(to_unbond.is_zero());

        // Record the incoming redelegations on destination validator
        let dest_records = self.records_mut(new_validator, source);
        let redeleg = dest_records
            .bonds
            .entry(pipeline)
            .or_default()
            .incoming_redelegs
            .entry(validator.clone())
            .or_default();
        for (start, inc_redeleg) in dest_incoming_redelegs {
            let redeleg_tokens = redeleg.tokens.entry(start).or_default();
            redeleg_tokens.amount += inc_redeleg.amount;
            redeleg_tokens.add_slashes(&inc_redeleg.slashes);
        }

        // Update stake of src validator
        let src_pipeline_state = self
            .validator_states
            .get(&self.pipeline())
            .unwrap()
            .get(validator)
            .unwrap();
        if *src_pipeline_state != ValidatorState::Jailed {
            self.update_validator_sets(
                validator,
                -amount_after_slashing.change(),
                self.pipeline(),
            );
        }
        self.update_validator_total_stake(
            validator,
            -amount_after_slashing.change(),
            self.pipeline(),
        );

        // Update stake of dest validator
        let dest_pipeline_state = self
            .validator_states
            .get(&self.pipeline())
            .unwrap()
            .get(new_validator)
            .unwrap();
        if *dest_pipeline_state != ValidatorState::Jailed {
            self.update_validator_sets(
                new_validator,
                amount_after_slashing.change(),
                self.pipeline(),
            );
        }
        self.update_validator_total_stake(
            new_validator,
            amount_after_slashing.change(),
            self.pipeline(),
        );
    }

    /// Withdraw all unbonds that can be withdrawn.
    fn withdraw(&mut self, BondId { source, validator }: &BondId) {
        let epoch = self.epoch;
        let records = self.records_mut(validator, source);
        let mut to_store = BTreeMap::<Epoch, TokensWithSlashes>::new();
        for (_start, bond) in records.bonds.iter_mut() {
            bond.unbonds.retain(|_end, unbond| {
                let is_withdrawable = unbond.withdrawable_epoch <= epoch;
                if is_withdrawable {
                    let withdrawn = to_store.entry(epoch).or_default();
                    withdrawn.amount += unbond.tokens.amount;
                    withdrawn.add_slashes(&unbond.tokens.slashes);
                    for redeleg in unbond.incoming_redelegs.values() {
                        for tokens in redeleg.tokens.values() {
                            withdrawn.amount += tokens.amount;
                            withdrawn.add_slashes(&tokens.slashes);
                        }
                    }
                }
                !is_withdrawable
            })
        }
        records.withdrawn.extend(to_store);
    }

    /// Get or insert default mutable records
    fn records_mut(
        &mut self,
        validator: &Address,
        source: &Address,
    ) -> &mut Records {
        self.validator_records
            .entry(validator.clone())
            .or_default()
            .per_source
            .entry(source.clone())
            .or_default()
    }

    /// Get records
    fn records(
        &self,
        validator: &Address,
        source: &Address,
    ) -> Option<&Records> {
        self.validator_records
            .get(validator)
            .and_then(|records| records.per_source.get(source))
    }

    /// Update validator's total stake with bonded or unbonded change at the
    /// pipeline epoch
    fn update_validator_total_stake(
        &mut self,
        validator: &Address,
        change: token::Change,
        epoch: Epoch,
    ) {
        let total_stakes = self
            .validator_stakes
            .entry(epoch)
            .or_default()
            .entry(validator.clone())
            .or_default();
        tracing::debug!("TOTAL {validator} stakes before {}", total_stakes);
        *total_stakes += change;
        tracing::debug!("TOTAL {validator} stakes after {}", total_stakes);
    }

    /// Update validator in sets with bonded or unbonded change (should be
    /// called with epoch at pipeline) or slashes.
    fn update_validator_sets(
        &mut self,
        validator: &Address,
        change: token::Change,
        epoch: Epoch,
    ) {
        let consensus_set = self.consensus_set.entry(epoch).or_default();
        let below_cap_set = self.below_capacity_set.entry(epoch).or_default();
        let below_thresh_set =
            self.below_threshold_set.entry(epoch).or_default();

        let validator_stakes = self.validator_stakes.get(&epoch).unwrap();
        let validator_states = self.validator_states.get_mut(&epoch).unwrap();

        let state_pre = validator_states.get(validator).unwrap();

        let this_val_stake_pre = *validator_stakes.get(validator).unwrap();
        let this_val_stake_post =
            token::Amount::from_change(this_val_stake_pre + change);
        let this_val_stake_pre = token::Amount::from_change(this_val_stake_pre);

        let threshold = self.params.validator_stake_threshold;
        if this_val_stake_pre < threshold && this_val_stake_post < threshold {
            // Validator is already below-threshold and will remain there, so do
            // nothing
            debug_assert!(below_thresh_set.contains(validator));
            return;
        }

        match state_pre {
            ValidatorState::Consensus => {
                // tracing::debug!("Validator initially in consensus");
                // Remove from the prior stake
                let vals = consensus_set.entry(this_val_stake_pre).or_default();
                // dbg!(&vals);
                vals.retain(|addr| addr != validator);
                // dbg!(&vals);

                if vals.is_empty() {
                    consensus_set.remove(&this_val_stake_pre);
                }

                // If posterior stake is below threshold, place into the
                // below-threshold set
                if this_val_stake_post < threshold {
                    below_thresh_set.insert(validator.clone());
                    validator_states.insert(
                        validator.clone(),
                        ValidatorState::BelowThreshold,
                    );

                    // Promote the next below-cap validator if there is one
                    if let Some(mut max_below_cap) = below_cap_set.last_entry()
                    {
                        let max_below_cap_stake = *max_below_cap.key();
                        let vals = max_below_cap.get_mut();
                        let promoted_val = vals.pop_front().unwrap();
                        // Remove the key if there's nothing left
                        if vals.is_empty() {
                            below_cap_set.remove(&max_below_cap_stake);
                        }

                        consensus_set
                            .entry(max_below_cap_stake.0)
                            .or_default()
                            .push_back(promoted_val.clone());
                        validator_states
                            .insert(promoted_val, ValidatorState::Consensus);
                    }

                    return;
                }

                // If unbonding, check the max below-cap validator's state if we
                // need to do a swap
                if change < token::Change::zero() {
                    if let Some(mut max_below_cap) = below_cap_set.last_entry()
                    {
                        let max_below_cap_stake = *max_below_cap.key();
                        if max_below_cap_stake.0 > this_val_stake_post {
                            // Swap this validator with the max below-cap
                            let vals = max_below_cap.get_mut();
                            let first_val = vals.pop_front().unwrap();
                            // Remove the key if there's nothing left
                            if vals.is_empty() {
                                below_cap_set.remove(&max_below_cap_stake);
                            }
                            // Do the swap in the validator sets
                            consensus_set
                                .entry(max_below_cap_stake.0)
                                .or_default()
                                .push_back(first_val.clone());
                            below_cap_set
                                .entry(this_val_stake_post.into())
                                .or_default()
                                .push_back(validator.clone());

                            // Change the validator states
                            validator_states
                                .insert(first_val, ValidatorState::Consensus);
                            validator_states.insert(
                                validator.clone(),
                                ValidatorState::BelowCapacity,
                            );

                            // And we're done here
                            return;
                        }
                    }
                }

                // Insert with the posterior stake
                consensus_set
                    .entry(this_val_stake_post)
                    .or_default()
                    .push_back(validator.clone());
            }
            ValidatorState::BelowCapacity => {
                // tracing::debug!("Validator initially in below-cap");

                // Remove from the prior stake
                let vals =
                    below_cap_set.entry(this_val_stake_pre.into()).or_default();
                vals.retain(|addr| addr != validator);
                if vals.is_empty() {
                    below_cap_set.remove(&this_val_stake_pre.into());
                }

                // If posterior stake is below threshold, place into the
                // below-threshold set
                if this_val_stake_post < threshold {
                    below_thresh_set.insert(validator.clone());
                    validator_states.insert(
                        validator.clone(),
                        ValidatorState::BelowThreshold,
                    );
                    return;
                }

                // If bonding, check the min consensus validator's state if we
                // need to do a swap
                if change >= token::Change::zero() {
                    // dbg!(&consensus_set);
                    if let Some(mut min_consensus) = consensus_set.first_entry()
                    {
                        // dbg!(&min_consensus);
                        let min_consensus_stake = *min_consensus.key();
                        if this_val_stake_post > min_consensus_stake {
                            // Swap this validator with the max consensus
                            let vals = min_consensus.get_mut();
                            let last_val = vals.pop_back().unwrap();
                            // Remove the key if there's nothing left
                            if vals.is_empty() {
                                consensus_set.remove(&min_consensus_stake);
                            }
                            // Do the swap in the validator sets
                            below_cap_set
                                .entry(min_consensus_stake.into())
                                .or_default()
                                .push_back(last_val.clone());
                            consensus_set
                                .entry(this_val_stake_post)
                                .or_default()
                                .push_back(validator.clone());

                            // Change the validator states
                            validator_states.insert(
                                validator.clone(),
                                ValidatorState::Consensus,
                            );
                            validator_states.insert(
                                last_val,
                                ValidatorState::BelowCapacity,
                            );

                            // And we're done here
                            return;
                        }
                    }
                }

                // Insert with the posterior stake
                below_cap_set
                    .entry(this_val_stake_post.into())
                    .or_default()
                    .push_back(validator.clone());
            }
            ValidatorState::BelowThreshold => {
                // We know that this validator will be promoted into one of the
                // higher sets, so first remove from the below-threshold set.
                below_thresh_set.swap_remove(validator);

                let num_consensus =
                    consensus_set.iter().fold(0, |sum, (_, validators)| {
                        sum + validators.len() as u64
                    });
                if num_consensus < self.params.max_validator_slots {
                    // Place the validator directly into the consensus set
                    consensus_set
                        .entry(this_val_stake_post)
                        .or_default()
                        .push_back(validator.clone());
                    validator_states
                        .insert(validator.clone(), ValidatorState::Consensus);
                    return;
                }
                // Determine which set to place the validator into
                if let Some(mut min_consensus) = consensus_set.first_entry() {
                    // dbg!(&min_consensus);
                    let min_consensus_stake = *min_consensus.key();
                    if this_val_stake_post > min_consensus_stake {
                        // Swap this validator with the max consensus
                        let vals = min_consensus.get_mut();
                        let last_val = vals.pop_back().unwrap();
                        // Remove the key if there's nothing left
                        if vals.is_empty() {
                            consensus_set.remove(&min_consensus_stake);
                        }
                        // Do the swap in the validator sets
                        below_cap_set
                            .entry(min_consensus_stake.into())
                            .or_default()
                            .push_back(last_val.clone());
                        consensus_set
                            .entry(this_val_stake_post)
                            .or_default()
                            .push_back(validator.clone());

                        // Change the validator states
                        validator_states.insert(
                            validator.clone(),
                            ValidatorState::Consensus,
                        );
                        validator_states
                            .insert(last_val, ValidatorState::BelowCapacity);
                    } else {
                        // Place the validator into the below-capacity set
                        below_cap_set
                            .entry(this_val_stake_post.into())
                            .or_default()
                            .push_back(validator.clone());
                        validator_states.insert(
                            validator.clone(),
                            ValidatorState::BelowCapacity,
                        );
                    }
                }
            }
            ValidatorState::Inactive => {
                panic!("unexpected state")
            }
            ValidatorState::Jailed => {
                panic!("unexpected state (jailed)")
            }
        }
    }

    fn process_enqueued_slashes(&mut self) {
        let slashes_this_epoch = self
            .enqueued_slashes
            .get(&self.epoch)
            .cloned()
            .unwrap_or_default();
        if !slashes_this_epoch.is_empty() {
            let infraction_epoch = self.epoch
                - self.params.unbonding_len
                - self.params.cubic_slashing_window_length
                - 1;

            let cubic_rate = self.cubic_slash_rate();
            for (validator, slashes) in slashes_this_epoch {
                // Slash this validator on it's full stake at infration
                self.slash_a_validator(
                    &validator,
                    &slashes,
                    infraction_epoch,
                    cubic_rate,
                );
            }
        }
    }

    fn slash_a_validator(
        &mut self,
        validator: &Address,
        slashes: &[Slash],
        infraction_epoch: Epoch,
        cubic_rate: Dec,
    ) {
        let current_epoch = self.epoch;
        let mut total_rate = Dec::zero();

        for slash in slashes {
            debug_assert_eq!(slash.epoch, infraction_epoch);
            let rate =
                cmp::max(slash.r#type.get_slash_rate(&self.params), cubic_rate);
            let processed_slash = Slash {
                epoch: slash.epoch,
                block_height: slash.block_height,
                r#type: slash.r#type,
                rate,
            };
            let cur_slashes =
                self.validator_slashes.entry(validator.clone()).or_default();
            cur_slashes.push(processed_slash.clone());

            total_rate += rate;
        }
        total_rate = cmp::min(total_rate, Dec::one());
        tracing::debug!("Total rate: {}", total_rate);

        // Find validator stakes before slashing for up to pipeline epoch
        let mut validator_stakes_pre =
            BTreeMap::<Epoch, BTreeMap<Address, token::Amount>>::new();
        for epoch in
            Epoch::iter_bounds_inclusive(current_epoch, self.pipeline())
        {
            for (validator, records) in &self.validator_records {
                let stake = records.stake(epoch);
                validator_stakes_pre
                    .entry(epoch)
                    .or_default()
                    .insert(validator.clone(), stake);
            }
        }

        let mut redelegations_to_slash = BTreeMap::<
            Address,
            BTreeMap<Address, BTreeMap<Epoch, BTreeMap<Epoch, TokensSlash>>>,
        >::new();
        for (addr, records) in self.validator_records.iter_mut() {
            if addr == validator {
                for (source, records) in records.per_source.iter_mut() {
                    // Apply slashes on non-redelegated bonds
                    records.slash(total_rate, infraction_epoch, current_epoch);

                    // Slash tokens in the outgoing redelegation records for
                    // this validator
                    for (&start, bond) in records.bonds.iter_mut() {
                        for (&end, redelegs) in
                            bond.outgoing_redelegs.iter_mut()
                        {
                            if start <= infraction_epoch
                                && end >= infraction_epoch
                            {
                                for (dest, tokens) in redelegs.iter_mut() {
                                    let slashed = tokens.slash(
                                        total_rate,
                                        infraction_epoch,
                                        current_epoch,
                                    );
                                    // Store the redelegation slashes to apply
                                    // on destination validator
                                    *redelegations_to_slash
                                        .entry(dest.clone())
                                        .or_default()
                                        .entry(source.clone())
                                        .or_default()
                                        .entry(
                                            // start epoch of redelegation
                                            end.next(),
                                        )
                                        .or_default()
                                        // redelegation src bond start epoch
                                        .entry(start)
                                        .or_default() += TokensSlash {
                                        amount: slashed,
                                        rate: total_rate,
                                    };
                                }
                            }
                        }
                    }
                }
            }
        }
        // Apply redelegation slashes on destination validator
        for (dest_validator, redelegations) in redelegations_to_slash {
            for (source, tokens) in redelegations {
                for (redelegation_start, slashes) in tokens {
                    for (src_bond_start, slash) in slashes {
                        let records = self
                            .validator_records
                            .get_mut(&dest_validator)
                            .unwrap()
                            .per_source
                            .get_mut(&source)
                            .unwrap();
                        records.subtract_redelegation_slash(
                            validator,
                            src_bond_start,
                            redelegation_start,
                            slash,
                            current_epoch,
                        );
                    }
                }
            }
        }

        // Find validator stakes after slashing for up to pipeline epoch
        let mut validator_stakes_post =
            BTreeMap::<Epoch, BTreeMap<Address, token::Amount>>::new();
        for epoch in
            Epoch::iter_bounds_inclusive(current_epoch, self.pipeline())
        {
            for (validator, records) in &self.validator_records {
                let stake = records.stake(epoch);
                validator_stakes_post
                    .entry(epoch)
                    .or_default()
                    .insert(validator.clone(), stake);
            }
        }

        // Apply the difference in stakes to validator_stakes, states and deltas
        for epoch in
            Epoch::iter_bounds_inclusive(current_epoch, self.pipeline())
        {
            for (validator_to_update, &stake_post) in
                validator_stakes_post.get(&epoch).unwrap()
            {
                let stake_pre = validator_stakes_pre
                    .get(&epoch)
                    .unwrap()
                    .get(validator_to_update)
                    .cloned()
                    .unwrap_or_default();
                let change = stake_post.change() - stake_pre.change();

                if !change.is_zero() {
                    let state = self
                        .validator_states
                        .get(&epoch)
                        .unwrap()
                        .get(validator_to_update)
                        .unwrap();
                    // Validator sets need to be updated before total
                    // stake
                    if *state != ValidatorState::Jailed {
                        self.update_validator_sets(
                            validator_to_update,
                            change,
                            epoch,
                        );
                    }
                    self.update_validator_total_stake(
                        validator_to_update,
                        change,
                        epoch,
                    );
                }
            }
        }
    }

    /// Get the pipeline epoch
    fn pipeline(&self) -> Epoch {
        self.epoch + self.params.pipeline_len
    }

    /// Check if the given address is of a known validator
    fn is_validator(&self, validator: &Address, epoch: Epoch) -> bool {
        self.validator_states
            .get(&epoch)
            .unwrap()
            .keys()
            .any(|val| val == validator)
    }

    fn is_in_consensus_w_info(
        &self,
        validator: &Address,
        epoch: Epoch,
    ) -> Option<(usize, token::Amount)> {
        for (stake, vals) in self.consensus_set.get(&epoch).unwrap() {
            if let Some(index) = vals.iter().position(|val| val == validator) {
                return Some((index, *stake));
            }
        }
        None
    }

    fn is_in_below_capacity_w_info(
        &self,
        validator: &Address,
        epoch: Epoch,
    ) -> Option<(usize, token::Amount)> {
        for (stake, vals) in self.below_capacity_set.get(&epoch).unwrap() {
            if let Some(index) = vals.iter().position(|val| val == validator) {
                return Some((index, (*stake).into()));
            }
        }
        None
    }

    fn is_in_below_threshold(&self, validator: &Address, epoch: Epoch) -> bool {
        self.below_threshold_set
            .get(&epoch)
            .unwrap()
            .iter()
            .any(|val| val == validator)
    }

    /// Find the sum of bonds that can be unbonded. The returned amounts are
    /// prior to slashing.
    fn unbondable_bonds(&self) -> BTreeMap<BondId, token::Amount> {
        let mut sums = BTreeMap::<BondId, token::Amount>::new();
        for (validator, records) in &self.validator_records {
            for (source, record) in &records.per_source {
                let unbondable = sums
                    .entry(BondId {
                        source: source.clone(),
                        validator: validator.clone(),
                    })
                    .or_default();
                // Add bonds and incoming redelegations
                for (&start, bond) in &record.bonds {
                    *unbondable += bond.tokens.amount_before_slashing();
                    for redeleg in bond.incoming_redelegs.values() {
                        let redeleg_epoch = start - self.params.pipeline_len;
                        *unbondable += redeleg
                            .amount_before_slashing_after_redeleg(
                                redeleg_epoch,
                            );
                    }
                }
            }
        }
        // Filter out any 0s.
        sums.retain(|_id, tokens| !tokens.is_zero());
        sums
    }

    /// Find the sum of bonds that can be redelegated. The returned amounts are
    /// prior to slashing.
    fn redelegatable_bonds(&self) -> BTreeMap<BondId, token::Amount> {
        let mut sums = BTreeMap::<BondId, token::Amount>::new();
        for (validator, records) in &self.validator_records {
            for (source, record) in &records.per_source {
                // Self-bonds cannot be redelegated
                if validator != source {
                    let unbondable = sums
                        .entry(BondId {
                            source: source.clone(),
                            validator: validator.clone(),
                        })
                        .or_default();
                    // Add bonds
                    for (&start, bond) in &record.bonds {
                        *unbondable += bond.tokens.amount_before_slashing();
                        // Add redelegations
                        for redeleg in bond.incoming_redelegs.values() {
                            // No chained redelegations
                            if Epoch(
                                start
                                    .0
                                    .checked_sub(self.params.pipeline_len)
                                    .unwrap_or_default(),
                            ) + self.params.withdrawable_epoch_offset()
                                <= self.epoch
                            {
                                *unbondable += redeleg.amount_before_slashing();
                            }
                        }
                    }
                }
            }
        }
        // Filter out any 0s.
        sums.retain(|_id, tokens| !tokens.is_zero());
        sums
    }

    fn unchainable_redelegations(&self) -> BTreeSet<BondId> {
        let mut unchainable = BTreeSet::new();
        for records in self.validator_records.values() {
            for (owner, records) in &records.per_source {
                for bond in records.bonds.values() {
                    for (&end, redelegs) in &bond.outgoing_redelegs {
                        // If the outgoing redelegation is still slashable for
                        // source validator ...
                        if end + self.params.slash_processing_epoch_offset()
                            > self.epoch
                        {
                            // ... it cannot be redelegated for now
                            for (dest_validator, tokens) in redelegs {
                                if !tokens.is_zero() {
                                    unchainable.insert(BondId {
                                        source: owner.clone(),
                                        validator: dest_validator.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        unchainable
    }

    /// Find the sums of withdrawable unbonds
    fn withdrawable_unbonds(&self) -> BTreeMap<BondId, token::Amount> {
        let mut withdrawable = BTreeMap::<BondId, token::Amount>::new();
        for (validator, records) in &self.validator_records {
            for (source, records) in &records.per_source {
                for bond in records.bonds.values() {
                    for unbond in bond.unbonds.values() {
                        if unbond.withdrawable_epoch <= self.epoch {
                            let entry = withdrawable
                                .entry(BondId {
                                    source: source.clone(),
                                    validator: validator.clone(),
                                })
                                .or_default();
                            // Add withdrawable unbonds including redelegations
                            *entry += unbond.amount_before_slashing();
                        }
                    }
                }
            }
        }
        withdrawable
    }

    fn existing_bond_ids(&self) -> Vec<BondId> {
        let mut ids = Vec::new();
        for (validator, records) in &self.validator_records {
            for source in records.per_source.keys() {
                ids.push(BondId {
                    source: source.clone(),
                    validator: validator.clone(),
                });
            }
        }
        ids
    }

    /// Compute the cubic slashing rate for the current epoch
    fn cubic_slash_rate(&self) -> Dec {
        let infraction_epoch = self.epoch
            - self.params.unbonding_len
            - 1_u64
            - self.params.cubic_slashing_window_length;
        tracing::debug!("Infraction epoch: {}", infraction_epoch);
        let window_width = self.params.cubic_slashing_window_length;
        let epoch_start = Epoch::from(
            infraction_epoch
                .0
                .checked_sub(window_width)
                .unwrap_or_default(),
        );
        let epoch_end = infraction_epoch + window_width;

        // Calculate cubic slashing rate with the abstract state
        let mut vp_frac_sum = Dec::zero();
        for epoch in Epoch::iter_bounds_inclusive(epoch_start, epoch_end) {
            let consensus_stake =
                self.consensus_set.get(&epoch).unwrap().iter().fold(
                    token::Amount::zero(),
                    |sum, (val_stake, validators)| {
                        sum + *val_stake * validators.len() as u64
                    },
                );
            tracing::debug!(
                "Consensus stake in epoch {}: {}",
                epoch,
                consensus_stake.to_string_native()
            );

            let processing_epoch = epoch
                + self.params.unbonding_len
                + 1_u64
                + self.params.cubic_slashing_window_length;
            let enqueued_slashes = self.enqueued_slashes.get(&processing_epoch);
            if let Some(enqueued_slashes) = enqueued_slashes {
                for (validator, slashes) in enqueued_slashes.iter() {
                    let val_stake = token::Amount::from_change(
                        self.validator_stakes
                            .get(&epoch)
                            .unwrap()
                            .get(validator)
                            .cloned()
                            .unwrap_or_default(),
                    );
                    tracing::debug!(
                        "Val {} stake epoch {}: {}",
                        &validator,
                        epoch,
                        val_stake.to_string_native(),
                    );
                    vp_frac_sum += Dec::from(slashes.len())
                        * Dec::try_from(val_stake).unwrap()
                        / Dec::try_from(consensus_stake).unwrap();
                }
            }
        }
        let vp_frac_sum = cmp::min(Dec::one(), vp_frac_sum);
        tracing::debug!("vp_frac_sum: {}", vp_frac_sum);

        cmp::min(
            Dec::new(9, 0).unwrap() * vp_frac_sum * vp_frac_sum,
            Dec::one(),
        )
    }

    fn debug_validators(&self) {
        let current_epoch = self.epoch;
        for epoch in
            Epoch::iter_bounds_inclusive(current_epoch, self.pipeline())
        {
            let mut min_consensus = token::Amount::from(u64::MAX);
            let consensus = self.consensus_set.get(&epoch).unwrap();
            for (amount, vals) in consensus {
                if *amount < min_consensus {
                    min_consensus = *amount;
                }
                for val in vals {
                    let deltas_stake = self
                        .validator_stakes
                        .get(&epoch)
                        .unwrap()
                        .get(val)
                        .unwrap();
                    let val_state = self
                        .validator_states
                        .get(&epoch)
                        .unwrap()
                        .get(val)
                        .unwrap();
                    debug_assert_eq!(
                        *amount,
                        token::Amount::from_change(*deltas_stake)
                    );
                    debug_assert_eq!(*val_state, ValidatorState::Consensus);
                }
            }
            let mut max_bc = token::Amount::zero();
            let bc = self.below_capacity_set.get(&epoch).unwrap();
            for (amount, vals) in bc {
                if token::Amount::from(*amount) > max_bc {
                    max_bc = token::Amount::from(*amount);
                }
                for val in vals {
                    let deltas_stake = self
                        .validator_stakes
                        .get(&epoch)
                        .unwrap()
                        .get(val)
                        .cloned()
                        .unwrap_or_default();
                    let val_state = self
                        .validator_states
                        .get(&epoch)
                        .unwrap()
                        .get(val)
                        .unwrap();
                    debug_assert_eq!(
                        token::Amount::from(*amount),
                        token::Amount::from_change(deltas_stake)
                    );
                    debug_assert_eq!(*val_state, ValidatorState::BelowCapacity);
                }
            }
            if max_bc > min_consensus {
                tracing::debug!(
                    "min_consensus = {}, max_bc = {}",
                    min_consensus.to_string_native(),
                    max_bc.to_string_native()
                );
            }
            assert!(min_consensus >= max_bc);

            for addr in self.below_threshold_set.get(&epoch).unwrap() {
                let state = self
                    .validator_states
                    .get(&epoch)
                    .unwrap()
                    .get(addr)
                    .unwrap();

                assert_eq!(*state, ValidatorState::BelowThreshold);
            }

            for addr in self
                .validator_states
                .get(&epoch)
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>()
            {
                if let (None, None, false) = (
                    self.is_in_consensus_w_info(&addr, epoch),
                    self.is_in_below_capacity_w_info(&addr, epoch),
                    self.is_in_below_threshold(&addr, epoch),
                ) {
                    assert_eq!(
                        self.validator_states
                            .get(&epoch)
                            .unwrap()
                            .get(&addr)
                            .cloned(),
                        Some(ValidatorState::Jailed)
                    );
                }
            }
        }
    }

    fn is_chained_redelegation(
        unchainable_redelegations: &BTreeSet<BondId>,
        delegator: &Address,
        src_validator: &Address,
    ) -> bool {
        unchainable_redelegations.contains(&BondId {
            source: delegator.clone(),
            validator: src_validator.clone(),
        })
    }
}

#[derive(Clone, Debug, Default)]
struct ValidatorRecords {
    /// All records to a validator that contribute to its
    /// [`ValidatorBonds::stake`]. For self-bonds the key is a validator
    /// and for delegations a delegator.
    per_source: BTreeMap<Address, Records>,
}

impl ValidatorRecords {
    /// Validator's stake is a sum of bond amounts with any slashing applied.
    fn stake(&self, epoch: Epoch) -> token::Amount {
        let mut total = token::Amount::zero();
        for bonds in self.per_source.values() {
            total += bonds.amount(epoch);
        }
        total
    }

    /// Find how much slash rounding error at most can be tolerated for slashes
    /// that were processed before or at the given epoch on a total validator's
    /// stake vs sum of slashes on bond deltas, unbonded, withdrawn or
    /// redelegated bonds.
    ///
    /// We allow `n - 1` slash rounding error for `n` number of slashes in
    /// unique epochs for bonds, unbonds and withdrawals. The bond deltas,
    /// unbonds and withdrawals are slashed individually and so their total
    /// slashed may be more than the slash on a sum of total validator's
    /// stake.
    fn slash_round_err_tolerance(&self, epoch: Epoch) -> token::Amount {
        let mut unique_count = 0_u64;
        for record in self.per_source.values() {
            unique_count += record.num_of_slashes(epoch);
        }
        token::Amount::from(unique_count.checked_sub(1).unwrap_or_default())
    }
}

#[derive(Clone, Debug, Default)]
struct Records {
    /// Key is a bond start epoch (when it first contributed to voting power)
    /// The value contains the sum of all the bonds started at the same epoch.
    bonds: BTreeMap<Epoch, Bond>,
    /// Withdrawn tokens in the epoch
    withdrawn: BTreeMap<Epoch, TokensWithSlashes>,
}

impl Records {
    /// Sum of bond amounts with any slashes that were processed before or at
    /// the given epoch applied.
    fn amount(&self, epoch: Epoch) -> token::Amount {
        let Records {
            bonds,
            withdrawn: _,
        } = self;
        let mut total = token::Amount::zero();
        for (&start, bond) in bonds {
            if start <= epoch {
                // Bonds
                total += bond.tokens.amount;
                // Add back any slashes that were processed after the given
                // epoch
                total += bond.tokens.slashes_sum_after_epoch(epoch);

                for (&end, unbond) in &bond.unbonds {
                    if end >= epoch {
                        // Unbonds
                        total += unbond.tokens.amount;
                        total += unbond.tokens.slashes_sum_after_epoch(epoch);

                        // Unbonded incoming redelegations
                        for redelegs in unbond.incoming_redelegs.values() {
                            for tokens in redelegs.tokens.values() {
                                total += tokens.amount;
                                total += tokens.slashes_sum_after_epoch(epoch);
                            }
                        }
                    }
                }

                // Outgoing redelegations
                for (&end, redelegs) in &bond.outgoing_redelegs {
                    if end >= epoch {
                        for tokens in redelegs.values() {
                            total += tokens.amount;
                            total += tokens.slashes_sum_after_epoch(epoch);
                        }
                    }
                }

                // Incoming redelegations
                for redelegs in bond.incoming_redelegs.values() {
                    for tokens in redelegs.tokens.values() {
                        total += tokens.amount;
                        total += tokens.slashes_sum_after_epoch(epoch);
                    }
                }
            }
        }
        total
    }

    fn slash(
        &mut self,
        rate: Dec,
        infraction_epoch: Epoch,
        processing_epoch: Epoch,
    ) {
        for (&start, bond) in self.bonds.iter_mut() {
            if start <= infraction_epoch {
                bond.slash(rate, infraction_epoch, processing_epoch);

                for (&end, unbond) in bond.unbonds.iter_mut() {
                    if end >= infraction_epoch {
                        unbond.slash(rate, infraction_epoch, processing_epoch);
                    }
                }
            }
        }
    }

    fn subtract_redelegation_slash(
        &mut self,
        src_validator: &Address,
        src_bond_start: Epoch,
        redelegation_start: Epoch,
        mut to_sub: TokensSlash,
        processing_epoch: Epoch,
    ) {
        // Slash redelegation destination on the next epoch
        let slash_epoch = processing_epoch.next();
        let bond = self.bonds.get_mut(&redelegation_start).unwrap();
        for unbond in bond.unbonds.values_mut() {
            if let Some(redeleg) =
                unbond.incoming_redelegs.get_mut(src_validator)
            {
                if let Some(tokens) = redeleg.tokens.get_mut(&src_bond_start) {
                    if tokens.amount >= to_sub.amount {
                        tokens.amount -= to_sub.amount;
                        *tokens.slashes.entry(slash_epoch).or_default() +=
                            to_sub;
                        return;
                    } else {
                        to_sub.amount -= tokens.amount;
                        *tokens.slashes.entry(slash_epoch).or_default() +=
                            TokensSlash {
                                amount: tokens.amount,
                                rate: to_sub.rate,
                            };
                        tokens.amount = token::Amount::zero();
                    }
                }
            }
        }
        let redeleg = bond.incoming_redelegs.get_mut(src_validator).unwrap();
        if let Some(tokens) = redeleg.tokens.get_mut(&src_bond_start) {
            tokens.amount -= to_sub.amount;
            *tokens.slashes.entry(slash_epoch).or_default() += to_sub;
        } else {
            debug_assert!(to_sub.amount.is_zero());
        }
    }

    /// Find how much slash rounding error at most can be tolerated for slashes
    /// that were processed before or at the given epoch on a bond's amount vs
    /// sum of slashes on bond deltas, unbonded, withdrawn or redelegated
    /// bonds.
    ///
    /// We allow `n - 1` slash rounding error for `n` number of slashes (`fn
    /// num_of_slashes`) in unique epochs for bonds, unbonds and
    /// withdrawals. The bond deltas, unbonds and withdrawals are slashed
    /// individually and so their total slashed may be more than the slash
    /// on a sum of a bond's total amount.
    fn slash_round_err_tolerance(&self, epoch: Epoch) -> token::Amount {
        token::Amount::from(
            self.num_of_slashes(epoch)
                .checked_sub(1)
                .unwrap_or_default(),
        )
    }

    /// Get the number of slashes in unique epochs that were processed before or
    /// at the given epoch for all bonds, unbonds, redelegs, unbonded redelegs
    /// and withdrawn tokens.
    fn num_of_slashes(&self, epoch: Epoch) -> u64 {
        let mut unique_count = 0_u64;
        for bond in self.bonds.values() {
            unique_count += bond.tokens.num_of_slashes(epoch);
            for redeleg in bond.incoming_redelegs.values() {
                for tokens in redeleg.tokens.values() {
                    unique_count += tokens.num_of_slashes(epoch);
                }
            }
            for unbond in bond.unbonds.values() {
                unique_count += unbond.tokens.num_of_slashes(epoch);
                for redeleg in unbond.incoming_redelegs.values() {
                    for tokens in redeleg.tokens.values() {
                        unique_count += tokens.num_of_slashes(epoch);
                    }
                }
            }
        }
        for withdrawn in self.withdrawn.values() {
            unique_count += withdrawn.num_of_slashes(epoch);
        }
        unique_count
    }
}

#[derive(Clone, Debug, Default)]
struct Bond {
    /// Bonded amount is the amount that's been bonded originally, reduced by
    /// unbonding or slashing, if any. Incoming redelegations are recorded
    /// separately.
    tokens: TokensWithSlashes,
    /// Incoming redelegations contribute to the stake of this validator.
    /// Their sum is not included in the `tokens` field.
    incoming_redelegs: BTreeMap<Address, IncomingRedeleg>,
    /// Key is end epoch in which the unbond last contributed to stake of the
    /// validator.
    unbonds: BTreeMap<Epoch, Unbond>,
    /// The outer key is an end epoch of the redelegated bond in which the bond
    /// last contributed to voting power of this validator (the source). The
    /// inner key is the redelegation destination validator.
    ///
    /// After a redelegation a bond transferred to destination validator is
    /// liable for slashes on a source validator (key in the map) from the
    /// Bond's `start` to key's `end` epoch.
    outgoing_redelegs: BTreeMap<Epoch, BTreeMap<Address, TokensWithSlashes>>,
}

impl Bond {
    fn slash(
        &mut self,
        rate: Dec,
        infraction_epoch: Epoch,
        processing_epoch: Epoch,
    ) {
        self.tokens.slash(rate, infraction_epoch, processing_epoch);
        for (_src, redeleg) in self.incoming_redelegs.iter_mut() {
            for tokens in redeleg.tokens.values_mut() {
                tokens.slash(rate, infraction_epoch, processing_epoch);
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
struct IncomingRedeleg {
    /// Total amount with all slashes keyed by redelegation source bond start
    tokens: BTreeMap<Epoch, TokensWithSlashes>,
}
impl IncomingRedeleg {
    /// Get the token amount before any slashes that were processed after the
    /// redelegation epoch.
    fn amount_before_slashing_after_redeleg(
        &self,
        redeleg_epoch: Epoch,
    ) -> token::Amount {
        self.tokens
            .values()
            .map(|tokens| {
                tokens.amount_before_slashing_after_redeleg(redeleg_epoch)
            })
            .sum()
    }

    // Get the token amount before any slashing.
    fn amount_before_slashing(&self) -> token::Amount {
        self.tokens
            .values()
            .map(TokensWithSlashes::amount_before_slashing)
            .sum()
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
struct TokensWithSlashes {
    /// Token amount after any applicable slashing
    amount: token::Amount,
    /// Total amount that's been slashed associated with the epoch in which the
    /// slash was processed.
    slashes: BTreeMap<Epoch, TokensSlash>,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct TokensSlash {
    amount: token::Amount,
    rate: Dec,
}

impl AddAssign for TokensSlash {
    fn add_assign(&mut self, rhs: Self) {
        self.amount += rhs.amount;
        // Cap the rate at 1
        self.rate = cmp::min(Dec::one(), self.rate + rhs.rate);
    }
}

impl TokensWithSlashes {
    /// Slash on original amount before slashes that were processed after the
    /// infraction epoch. Returns the slashed amount.
    fn slash(
        &mut self,
        rate: Dec,
        infraction_epoch: Epoch,
        processing_epoch: Epoch,
    ) -> token::Amount {
        // Add back slashes to slashable amount that didn't affect this epoch
        // (applied after infraction epoch)
        let slashable_amount =
            self.amount + self.slashes_sum_after_epoch(infraction_epoch);
        let amount =
            cmp::min(slashable_amount.mul_ceil(rate).unwrap(), self.amount);
        if !amount.is_zero() {
            self.amount -= amount;
            let slash = self.slashes.entry(processing_epoch).or_default();
            *slash += TokensSlash { amount, rate };
        }
        amount
    }

    /// Add the given slashes at their epochs.
    fn add_slashes(&mut self, slashes: &BTreeMap<Epoch, TokensSlash>) {
        for (&epoch, slash) in slashes {
            *self.slashes.entry(epoch).or_default() += slash.clone();
        }
    }

    /// Subtract the given slash amount in order of the epochs. Returns the
    /// removed slashes.
    fn subtract_slash(
        &mut self,
        mut to_slash: token::Amount,
    ) -> BTreeMap<Epoch, TokensSlash> {
        let mut removed = BTreeMap::new();
        self.slashes.retain(|&epoch, slash| {
            if to_slash.is_zero() {
                return true;
            }
            if slash.amount > to_slash {
                slash.amount -= to_slash;
                removed.insert(
                    epoch,
                    TokensSlash {
                        amount: to_slash,
                        rate: slash.rate,
                    },
                );
                to_slash = token::Amount::zero();
                true
            } else {
                to_slash -= slash.amount;
                removed.insert(epoch, slash.clone());
                false
            }
        });
        removed
    }

    /// Get the token amount before any slashing.
    fn amount_before_slashing(&self) -> token::Amount {
        self.amount + self.slashes_sum()
    }

    /// Get the token amount before any slashes that were processed after the
    /// redelegation epoch.
    fn amount_before_slashing_after_redeleg(
        &self,
        redeleg_epoch: Epoch,
    ) -> token::Amount {
        let mut amount = self.amount;
        for (&processed_epoch, slash) in &self.slashes {
            if processed_epoch > redeleg_epoch {
                amount += slash.amount;
            }
        }
        amount
    }

    /// Get a sum of all slash amounts.
    fn slashes_sum(&self) -> token::Amount {
        self.slashes
            .values()
            .map(|TokensSlash { amount, rate: _ }| *amount)
            .sum()
    }

    /// Get a sum of all slash rates, capped at 1.
    fn slash_rates_sum(&self) -> Dec {
        cmp::min(
            Dec::one(),
            self.slashes
                .values()
                .map(|TokensSlash { amount: _, rate }| *rate)
                .sum(),
        )
    }

    /// Get a sum of all slashes that were processed after the given epoch.
    fn slashes_sum_after_epoch(&self, epoch: Epoch) -> token::Amount {
        let mut sum = token::Amount::zero();
        for (&processed_epoch, slash) in &self.slashes {
            if processed_epoch > epoch {
                sum += slash.amount;
            }
        }
        sum
    }

    /// Is the sum of tokens and slashed tokens zero? I.e. Are there no tokens?
    fn is_zero(&self) -> bool {
        self.amount.is_zero() && self.slashes_sum().is_zero()
    }

    /// Get the number of slashes in unique epochs that were processed before or
    /// at the given epoch.
    fn num_of_slashes(&self, epoch: Epoch) -> u64 {
        self.slashes
            .keys()
            .filter(|&&processed| processed <= epoch)
            .count() as u64
    }
}

#[derive(Clone, Debug, Default)]
struct Unbond {
    /// A first epoch from which the unbond is withdrawable.
    withdrawable_epoch: Epoch,
    /// Bonded amount is the amount that's been bonded originally, reduced by
    /// unbonding or slashing, if any.
    tokens: TokensWithSlashes,
    incoming_redelegs: BTreeMap<Address, IncomingRedeleg>,
}

impl Unbond {
    /// Get the total unbonded amount before slashing, including any unbonded
    /// redelegations.
    fn amount_before_slashing(&self) -> token::Amount {
        self.tokens.amount_before_slashing()
            + self
                .incoming_redelegs
                .iter()
                .fold(token::Amount::zero(), |acc, (_src, redeleg)| {
                    acc + redeleg.amount_before_slashing()
                })
    }

    fn slash(
        &mut self,
        rate: Dec,
        infraction_epoch: Epoch,
        processing_epoch: Epoch,
    ) {
        self.tokens.slash(rate, infraction_epoch, processing_epoch);
        for (_src, redeleg) in self.incoming_redelegs.iter_mut() {
            for tokens in redeleg.tokens.values_mut() {
                tokens.slash(rate, infraction_epoch, processing_epoch);
            }
        }
    }
}

/// The PoS system under test
#[derive(Derivative)]
#[derivative(Debug)]
struct ConcretePosState {
    /// Storage - contains all the PoS state
    s: TestState,
    /// Last reference state in debug format to print changes after transitions
    #[derivative(Debug = "ignore")]
    last_state_diff: DbgPrintDiff<AbstractPosState>,
}

/// State machine transitions
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Derivative)]
#[derivative(Debug)]
enum Transition {
    NextEpoch,
    InitValidator {
        address: Address,
        #[derivative(Debug = "ignore")]
        consensus_key: PublicKey,
        #[derivative(Debug = "ignore")]
        protocol_key: PublicKey,
        #[derivative(Debug = "ignore")]
        eth_cold_key: PublicKey,
        #[derivative(Debug = "ignore")]
        eth_hot_key: PublicKey,
        commission_rate: Dec,
        max_commission_rate_change: Dec,
    },
    Bond {
        id: BondId,
        amount: token::Amount,
    },
    Unbond {
        id: BondId,
        amount: token::Amount,
    },
    Withdraw {
        id: BondId,
    },
    Redelegate {
        /// A chained redelegation must fail
        is_chained: bool,
        id: BondId,
        new_validator: Address,
        amount: token::Amount,
    },
    Misbehavior {
        address: Address,
        slash_type: SlashType,
        infraction_epoch: Epoch,
        height: u64,
    },
    UnjailValidator {
        address: Address,
    },
}

impl StateMachineTest for ConcretePosState {
    type Reference = AbstractPosState;
    type SystemUnderTest = Self;

    fn init_test(
        initial_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) -> Self::SystemUnderTest {
        tracing::debug!("New test case");
        tracing::debug!(
            "Genesis validators: {:#?}",
            initial_state
                .genesis_validators
                .iter()
                .map(|val| &val.address)
                .collect::<Vec<_>>()
        );
        let mut s = TestState::default();
        initial_state.gov_params.init_storage(&mut s).unwrap();
        crate::tests::init_genesis_helper(
            &mut s,
            &initial_state.params,
            initial_state.genesis_validators.clone().into_iter(),
            initial_state.epoch,
        )
        .unwrap();
        let last_state_diff = DbgPrintDiff::new().store(initial_state);
        Self { s, last_state_diff }
    }

    fn apply(
        mut state: Self::SystemUnderTest,
        ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        transition: <Self::Reference as ReferenceStateMachine>::Transition,
    ) -> Self::SystemUnderTest {
        tracing::debug!(
            "{} {:#?}",
            Paint::green("Transition").underline(),
            Paint::yellow(&transition)
        );

        if false {
            // NOTE: enable to capture and print ref state diff
            let new_diff =
                state.last_state_diff.print_diff_and_store(ref_state);
            state.last_state_diff = new_diff;
        }

        pause_for_enter();

        let params = read_pos_params(&state.s).unwrap();
        let pos_balance = read_balance(
            &state.s,
            &state.s.in_mem().native_token,
            &crate::ADDRESS,
        )
        .unwrap();
        tracing::debug!("PoS balance: {}", pos_balance.to_string_native());
        match transition {
            Transition::NextEpoch => {
                tracing::debug!("\nCONCRETE Next epoch");
                advance_epoch(&mut state.s, &params);

                // Need to apply some slashing
                let current_epoch = state.s.in_mem().block.epoch;
                process_slashes(
                    &mut state.s,
                    &mut namada_events::testing::VoidEventSink,
                    current_epoch,
                )
                .unwrap();

                let params = read_pos_params(&state.s).unwrap();
                state.check_next_epoch_post_conditions(&params);
            }
            Transition::InitValidator {
                address,
                consensus_key,
                protocol_key,
                eth_cold_key,
                eth_hot_key,
                commission_rate,
                max_commission_rate_change,
            } => {
                tracing::debug!("\nCONCRETE Init validator");
                let current_epoch = state.current_epoch();

                become_validator(
                    &mut state.s,
                    crate::BecomeValidator {
                        params: &params,
                        address: &address,
                        consensus_key: &consensus_key,
                        protocol_key: &protocol_key,
                        eth_cold_key: &eth_cold_key,
                        eth_hot_key: &eth_hot_key,
                        current_epoch,
                        commission_rate,
                        max_commission_rate_change,
                        metadata: Default::default(),
                        offset_opt: None,
                    },
                )
                .unwrap();

                let params = read_pos_params(&state.s).unwrap();
                state.check_init_validator_post_conditions(
                    current_epoch,
                    &params,
                    &address,
                )
            }
            Transition::Bond { id, amount } => {
                tracing::debug!("\nCONCRETE Bond");
                let current_epoch = state.current_epoch();
                let pipeline = current_epoch + params.pipeline_len;
                let validator_stake_before_bond_cur =
                    crate::read_validator_stake(
                        &state.s,
                        &params,
                        &id.validator,
                        current_epoch,
                    )
                    .unwrap();
                let validator_stake_before_bond_pipeline =
                    crate::read_validator_stake(
                        &state.s,
                        &params,
                        &id.validator,
                        pipeline,
                    )
                    .unwrap();

                // Credit tokens to ensure we can apply the bond
                let native_token = state.s.get_native_token().unwrap();
                let pos = address::POS;
                token::credit_tokens(
                    &mut state.s,
                    &native_token,
                    &id.source,
                    amount,
                )
                .unwrap();

                let src_balance_pre =
                    token::read_balance(&state.s, &native_token, &id.source)
                        .unwrap();
                let pos_balance_pre =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();

                // This must be ensured by both transitions generator and
                // pre-conditions!
                assert!(
                    crate::is_validator(&state.s, &id.validator).unwrap(),
                    "{} is not a validator",
                    id.validator
                );

                // Apply the bond
                bond_tokens(
                    &mut state.s,
                    Some(&id.source),
                    &id.validator,
                    amount,
                    current_epoch,
                    None,
                )
                .unwrap();

                let params = read_pos_params(&state.s).unwrap();
                state.check_bond_post_conditions(
                    current_epoch,
                    &params,
                    id.clone(),
                    amount,
                    validator_stake_before_bond_cur,
                    validator_stake_before_bond_pipeline,
                );

                let src_balance_post =
                    token::read_balance(&state.s, &native_token, &id.source)
                        .unwrap();
                let pos_balance_post =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();

                // Post-condition: PoS balance should increase
                assert!(pos_balance_pre < pos_balance_post);
                // Post-condition: The difference in PoS balance should be the
                // same as in the source
                assert_eq!(
                    pos_balance_post - pos_balance_pre,
                    src_balance_pre - src_balance_post
                );
            }
            Transition::Unbond { id, amount } => {
                tracing::debug!("\nCONCRETE Unbond");
                let current_epoch = state.current_epoch();
                let pipeline = current_epoch + params.pipeline_len;
                let native_token = state.s.get_native_token().unwrap();
                let pos = address::POS;
                let src_balance_pre =
                    token::read_balance(&state.s, &native_token, &id.source)
                        .unwrap();
                let pos_balance_pre =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();

                let validator_stake_before_unbond_cur =
                    crate::read_validator_stake(
                        &state.s,
                        &params,
                        &id.validator,
                        current_epoch,
                    )
                    .unwrap();
                let validator_stake_before_unbond_pipeline =
                    crate::read_validator_stake(
                        &state.s,
                        &params,
                        &id.validator,
                        pipeline,
                    )
                    .unwrap();

                // Apply the unbond
                unbond_tokens(
                    &mut state.s,
                    Some(&id.source),
                    &id.validator,
                    amount,
                    current_epoch,
                    false,
                )
                .unwrap();

                let params = read_pos_params(&state.s).unwrap();
                state.check_unbond_post_conditions(
                    current_epoch,
                    &params,
                    id.clone(),
                    amount,
                    validator_stake_before_unbond_cur,
                    validator_stake_before_unbond_pipeline,
                );

                let src_balance_post =
                    token::read_balance(&state.s, &native_token, &id.source)
                        .unwrap();
                let pos_balance_post =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();

                // Post-condition: PoS balance should not change
                assert_eq!(pos_balance_pre, pos_balance_post);
                // Post-condition: Source balance should not change
                assert_eq!(src_balance_post, src_balance_pre);

                // Check that the bonds are the same
                // let abs_bonds = ref_state.bonds.get(&id).cloned().unwrap();
                // let conc_bonds = crate::bond_handle(&id.source,
                // &id.validator)     .get_data_handler()
                //     .collect_map(&state.s)
                //     .unwrap();
                // assert_eq!(abs_bonds, conc_bonds);

                // // Check that the unbond records are the same
                // // TODO: figure out how we get entries with 0 amount in the
                // // abstract version (and prevent)
                // let mut abs_unbond_records = ref_state
                //     .unbond_records
                //     .get(&id.validator)
                //     .cloned()
                //     .unwrap();
                // abs_unbond_records.retain(|_, inner_map| {
                //     inner_map.retain(|_, value| !value.is_zero());
                //     !inner_map.is_empty()
                // });
                // let conc_unbond_records =
                //     crate::total_unbonded_handle(&id.validator)
                //         .collect_map(&state.s)
                //         .unwrap();
                // assert_eq!(abs_unbond_records, conc_unbond_records);
            }
            Transition::Withdraw {
                id: BondId { source, validator },
            } => {
                tracing::debug!("\nCONCRETE Withdraw");
                let current_epoch = state.current_epoch();
                let native_token = state.s.get_native_token().unwrap();
                let pos = address::POS;
                // TODO: add back when slash pool is being used again
                // let slash_pool = address::POS_SLASH_POOL;
                let src_balance_pre =
                    token::read_balance(&state.s, &native_token, &source)
                        .unwrap();
                let pos_balance_pre =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();
                // let slash_balance_pre =
                //     token::read_balance(&state.s, &native_token, &slash_pool)
                //         .unwrap();

                // Apply the withdrawal
                let withdrawn = withdraw_tokens(
                    &mut state.s,
                    Some(&source),
                    &validator,
                    current_epoch,
                )
                .unwrap();

                let src_balance_post =
                    token::read_balance(&state.s, &native_token, &source)
                        .unwrap();
                let pos_balance_post =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();
                // let slash_balance_post =
                //     token::read_balance(&state.s, &native_token, &slash_pool)
                //         .unwrap();

                // Post-condition: PoS balance should decrease or not change if
                // nothing was withdrawn
                assert!(pos_balance_pre >= pos_balance_post);

                // Post-condition: The difference in PoS balance should be equal
                // to the sum of the difference in the source and the difference
                // in the slash pool
                // TODO: needs slash pool
                // assert_eq!(
                //     pos_balance_pre - pos_balance_post,
                //     src_balance_post - src_balance_pre + slash_balance_post
                //         - slash_balance_pre
                // );

                // Post-condition: The increment in source balance should be
                // equal to the withdrawn amount
                assert_eq!(src_balance_post - src_balance_pre, withdrawn);

                // Post-condition: The amount withdrawn must match reference
                // state withdrawal
                let records = ref_state.records(&validator, &source).unwrap();
                let max_slash_round_err =
                    records.slash_round_err_tolerance(current_epoch);
                let ref_withdrawn =
                    records.withdrawn.get(&current_epoch).unwrap().amount;
                assert!(
                    ref_withdrawn <= withdrawn
                        && withdrawn <= ref_withdrawn + max_slash_round_err,
                    "Expected to withdraw from validator {validator} owner \
                     {source} amount {} ({}), but withdrawn {}.",
                    ref_withdrawn.to_string_native(),
                    if max_slash_round_err.is_zero() {
                        "no slashing rounding error expected".to_string()
                    } else {
                        format!(
                            "max slashing rounding error +{}",
                            max_slash_round_err.to_string_native()
                        )
                    },
                    withdrawn.to_string_native(),
                );
            }
            Transition::Redelegate {
                is_chained,
                id,
                new_validator,
                amount,
            } => {
                tracing::debug!("\nCONCRETE Redelegate");

                let current_epoch = state.current_epoch();
                let pipeline = current_epoch + params.pipeline_len;

                // Read data prior to applying the transition
                let native_token = state.s.get_native_token().unwrap();
                let pos = address::POS;
                let pos_balance_pre =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();

                // Read validator's redelegations and bonds to find how much of
                // them is slashed
                let mut amount_after_slash = token::Amount::zero();
                let mut to_redelegate = amount;

                let redelegations_handle =
                    delegator_redelegated_bonds_handle(&id.source)
                        .at(&id.validator);

                let bonds: Vec<Result<_, _>> =
                    bond_handle(&id.source, &id.validator)
                        .get_data_handler()
                        .iter(&state.s)
                        .unwrap()
                        .collect();
                'bonds_loop: for res in bonds.into_iter().rev() {
                    let (bond_start, bond_delta) = res.unwrap();

                    // Find incoming redelegations at this bond start epoch as a
                    // redelegation end epoch (the epoch in which it stopped to
                    // contributing to src)
                    let redeleg_end = bond_start;
                    let redeleg_start =
                        params.redelegation_start_epoch_from_end(redeleg_end);
                    let redelegations: Vec<_> = redelegations_handle
                        .at(&redeleg_end)
                        .iter(&state.s)
                        .unwrap()
                        .collect();
                    // Iterate incoming redelegations first
                    for res in redelegations.into_iter().rev() {
                        let (
                            NestedSubKey::Data {
                                key: src_validator,
                                nested_sub_key:
                                    SubKey::Data(redeleg_src_bond_start),
                            },
                            delta,
                        ) = res.unwrap();

                        // Apply slashes on this delta, if any
                        let mut this_amount_after_slash = delta;

                        // Find redelegation source validator's slashes
                        let slashes = find_slashes_in_range(
                            &state.s,
                            redeleg_src_bond_start,
                            Some(redeleg_end),
                            &src_validator,
                        )
                        .unwrap();
                        for (slash_epoch, rate) in slashes {
                            // Only apply slashes that weren't processed before
                            // redelegation as those are applied eagerly
                            if slash_epoch
                                + params.slash_processing_epoch_offset()
                                > redeleg_start
                            {
                                let slash = delta.mul_ceil(rate).unwrap();
                                this_amount_after_slash =
                                    this_amount_after_slash
                                        .checked_sub(slash)
                                        .unwrap_or_default();
                            }
                        }
                        // Find redelegation destination validator's slashes
                        let slashes = find_slashes_in_range(
                            &state.s,
                            redeleg_end,
                            None,
                            &id.validator,
                        )
                        .unwrap();
                        for (_slash_epoch, rate) in slashes {
                            let slash = delta.mul_ceil(rate).unwrap();
                            this_amount_after_slash = this_amount_after_slash
                                .checked_sub(slash)
                                .unwrap_or_default();
                        }

                        if to_redelegate >= delta {
                            amount_after_slash += this_amount_after_slash;
                            to_redelegate -= delta;
                        } else {
                            // We have to divide this bond in case there are
                            // slashes
                            let slash_ratio =
                                Dec::try_from(this_amount_after_slash).unwrap()
                                    / Dec::try_from(delta).unwrap();
                            amount_after_slash += slash_ratio * to_redelegate;
                            to_redelegate = token::Amount::zero();
                        }

                        if to_redelegate.is_zero() {
                            break 'bonds_loop;
                        }
                    }

                    // Then if there's still something to redelegate, unbond the
                    // regular bonds
                    if !to_redelegate.is_zero() {
                        // Apply slashes on this bond delta, if any
                        let mut this_amount_after_slash = bond_delta;

                        // Find validator's slashes
                        let slashes = find_slashes_in_range(
                            &state.s,
                            bond_start,
                            None,
                            &id.validator,
                        )
                        .unwrap();
                        for (_slash_epoch, rate) in slashes {
                            let slash = bond_delta.mul_ceil(rate).unwrap();
                            this_amount_after_slash = this_amount_after_slash
                                .checked_sub(slash)
                                .unwrap_or_default();
                        }

                        if to_redelegate >= bond_delta {
                            amount_after_slash += this_amount_after_slash;
                            to_redelegate -= bond_delta;
                        } else {
                            // We have to divide this bond in case there are
                            // slashes
                            let slash_ratio =
                                Dec::try_from(this_amount_after_slash).unwrap()
                                    / Dec::try_from(bond_delta).unwrap();
                            amount_after_slash += slash_ratio * to_redelegate;
                            to_redelegate = token::Amount::zero();
                        }
                        if to_redelegate.is_zero() {
                            break;
                        }
                    }
                }

                // Read src validator stakes
                let src_validator_stake_cur_pre = crate::read_validator_stake(
                    &state.s,
                    &params,
                    &id.validator,
                    current_epoch,
                )
                .unwrap();
                let src_validator_stake_pipeline_pre =
                    crate::read_validator_stake(
                        &state.s,
                        &params,
                        &id.validator,
                        pipeline,
                    )
                    .unwrap();

                // Read dest validator stakes
                let dest_validator_stake_cur_pre = crate::read_validator_stake(
                    &state.s,
                    &params,
                    &new_validator,
                    current_epoch,
                )
                .unwrap();
                let dest_validator_stake_pipeline_pre =
                    crate::read_validator_stake(
                        &state.s,
                        &params,
                        &new_validator,
                        pipeline,
                    )
                    .unwrap();

                // Find delegations
                let delegations_pre =
                    find_delegations(&state.s, &id.source, &pipeline).unwrap();

                // Apply redelegation
                let result = redelegate_tokens(
                    &mut state.s,
                    &id.source,
                    &id.validator,
                    &new_validator,
                    current_epoch,
                    amount,
                );

                if !amount.is_zero() && is_chained {
                    assert!(result.is_err());
                    let err = result.unwrap_err();
                    let err_str = err.to_string();
                    assert_matches!(
                        err.downcast::<RedelegationError>().unwrap().deref(),
                        RedelegationError::IsChainedRedelegation,
                        "A chained redelegation must be rejected, got \
                         {err_str}",
                    );
                } else {
                    result.unwrap();

                    // Post-condition: PoS balance is unchanged
                    let pos_balance_post =
                        token::read_balance(&state.s, &native_token, &pos)
                            .unwrap();
                    assert_eq!(pos_balance_pre, pos_balance_post);

                    // Post-condition: Source validator stake at current epoch
                    // is unchanged
                    let src_validator_stake_cur_post =
                        crate::read_validator_stake(
                            &state.s,
                            &params,
                            &id.validator,
                            current_epoch,
                        )
                        .unwrap();
                    assert_eq!(
                        src_validator_stake_cur_pre,
                        src_validator_stake_cur_post
                    );

                    // Post-condition: Source validator stake at pipeline epoch
                    // is reduced by the redelegation amount

                    // TODO: shouldn't this be reduced by the redelegation
                    // amount post-slashing tho?
                    //   NOTE: We changed it to reduce it, check again later
                    let src_validator_stake_pipeline_post =
                        crate::read_validator_stake(
                            &state.s,
                            &params,
                            &id.validator,
                            pipeline,
                        )
                        .unwrap();
                    let max_slash_round_err = ref_state
                        .validator_records
                        .get(&id.validator)
                        .map(|r| r.slash_round_err_tolerance(current_epoch))
                        .unwrap_or_default();
                    let expected_new_stake = src_validator_stake_pipeline_pre
                        .checked_sub(amount_after_slash)
                        .unwrap_or_default();
                    assert!(
                        src_validator_stake_pipeline_post
                            <= expected_new_stake + max_slash_round_err
                            && expected_new_stake
                                <= src_validator_stake_pipeline_post
                                    + max_slash_round_err,
                        "Expected src validator {} stake after redelegation \
                         at pipeline to be equal to {} ({}), got {}.",
                        id.validator,
                        expected_new_stake.to_string_native(),
                        if max_slash_round_err.is_zero() {
                            "no slashing rounding error expected".to_string()
                        } else {
                            format!(
                                "max slashing rounding error +-{}",
                                max_slash_round_err.to_string_native()
                            )
                        },
                        src_validator_stake_pipeline_post.to_string_native()
                    );

                    // Post-condition: Destination validator stake at current
                    // epoch is unchanged
                    let dest_validator_stake_cur_post =
                        crate::read_validator_stake(
                            &state.s,
                            &params,
                            &new_validator,
                            current_epoch,
                        )
                        .unwrap();
                    assert_eq!(
                        dest_validator_stake_cur_pre,
                        dest_validator_stake_cur_post
                    );

                    // Post-condition: Destination validator stake at pipeline
                    // epoch is increased by the redelegation amount, less any
                    // slashes
                    let expected_new_stake =
                        dest_validator_stake_pipeline_pre + amount_after_slash;
                    let dest_validator_stake_pipeline_post =
                        crate::read_validator_stake(
                            &state.s,
                            &params,
                            &new_validator,
                            pipeline,
                        )
                        .unwrap();
                    assert!(
                        expected_new_stake
                            <= dest_validator_stake_pipeline_post
                                + max_slash_round_err
                            && dest_validator_stake_pipeline_post
                                <= expected_new_stake + max_slash_round_err,
                        "Expected dest validator {} stake after redelegation \
                         at pipeline to be equal to {} ({}), got {}.",
                        new_validator,
                        expected_new_stake.to_string_native(),
                        if max_slash_round_err.is_zero() {
                            "no slashing rounding error expected".to_string()
                        } else {
                            format!(
                                "max slashing rounding error +-{}",
                                max_slash_round_err.to_string_native()
                            )
                        },
                        dest_validator_stake_pipeline_post.to_string_native()
                    );

                    // Post-condition: The difference at pipeline in src
                    // validator stake is equal to negative difference in dest
                    // validator.
                    assert_eq!(
                        src_validator_stake_pipeline_pre
                            - src_validator_stake_pipeline_post,
                        dest_validator_stake_pipeline_post
                            - dest_validator_stake_pipeline_pre
                    );

                    // Post-condition: The delegator's delegations should be
                    // updated with redelegation. For the source reduced by the
                    // redelegation amount and for the destination increased by
                    // the redelegation amount, less any slashes.
                    let delegations_post =
                        find_delegations(&state.s, &id.source, &pipeline)
                            .unwrap();
                    let src_delegation_pre = delegations_pre
                        .get(&id.validator)
                        .cloned()
                        .unwrap_or_default();
                    let src_delegation_post = delegations_post
                        .get(&id.validator)
                        .cloned()
                        .unwrap_or_default();
                    assert_eq!(
                        src_delegation_pre - src_delegation_post,
                        amount
                    );
                    let dest_delegation_pre = delegations_pre
                        .get(&new_validator)
                        .cloned()
                        .unwrap_or_default();
                    let dest_delegation_post = delegations_post
                        .get(&new_validator)
                        .cloned()
                        .unwrap_or_default();
                    let dest_delegation_diff =
                        dest_delegation_post - dest_delegation_pre;
                    assert!(
                        amount_after_slash
                            <= dest_delegation_diff + max_slash_round_err
                            && dest_delegation_diff
                                <= amount_after_slash + max_slash_round_err,
                        "Expected redelegation by {} to be increased by to {} \
                         ({}), but it increased by {}.",
                        id.source,
                        amount_after_slash.to_string_native(),
                        if max_slash_round_err.is_zero() {
                            "no slashing rounding error expected".to_string()
                        } else {
                            format!(
                                "max slashing rounding error +-{}",
                                max_slash_round_err.to_string_native()
                            )
                        },
                        dest_delegation_diff.to_string_native(),
                    );
                }
            }
            Transition::Misbehavior {
                address,
                slash_type,
                infraction_epoch,
                height,
            } => {
                tracing::debug!("\nCONCRETE Misbehavior");
                let current_epoch = state.current_epoch();
                // Record the slash evidence
                slash(
                    &mut state.s,
                    &params,
                    current_epoch,
                    infraction_epoch,
                    height,
                    slash_type,
                    &address,
                    current_epoch.next(),
                )
                .unwrap();

                // Apply some post-conditions
                let params = read_pos_params(&state.s).unwrap();
                state.check_misbehavior_post_conditions(
                    &params,
                    current_epoch,
                    infraction_epoch,
                    height,
                    slash_type,
                    &address,
                );

                // TODO: Any others?
            }
            Transition::UnjailValidator { address } => {
                tracing::debug!("\nCONCRETE UnjailValidator");
                let current_epoch = state.current_epoch();

                // Unjail the validator
                unjail_validator(&mut state.s, &address, current_epoch)
                    .unwrap();

                // Post-conditions
                let params = read_pos_params(&state.s).unwrap();
                state.check_unjail_validator_post_conditions(&params, &address);
            }
        }
        state
    }

    fn check_invariants(
        state: &Self::SystemUnderTest,
        ref_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) {
        let current_epoch = state.current_epoch();
        let params = read_pos_params(&state.s).unwrap();
        state.check_global_post_conditions(&params, current_epoch, ref_state);
    }
}

impl ConcretePosState {
    fn current_epoch(&self) -> Epoch {
        self.s.in_mem().block.epoch
    }

    fn check_next_epoch_post_conditions(&self, params: &PosParams) {
        let pipeline = self.current_epoch() + params.pipeline_len;
        let before_pipeline = pipeline.prev().unwrap();

        // Post-condition: Consensus validator sets at pipeline offset
        // must be the same as at the epoch before it.
        let consensus_set_before_pipeline =
            read_consensus_validator_set_addresses_with_stake(
                &self.s,
                before_pipeline,
            )
            .unwrap();
        let consensus_set_at_pipeline =
            read_consensus_validator_set_addresses_with_stake(
                &self.s, pipeline,
            )
            .unwrap();
        itertools::assert_equal(
            consensus_set_before_pipeline.into_iter().sorted(),
            consensus_set_at_pipeline.into_iter().sorted(),
        );

        // Post-condition: Below-capacity validator sets at pipeline
        // offset must be the same as at the epoch before it.
        let below_cap_before_pipeline =
            read_below_capacity_validator_set_addresses_with_stake(
                &self.s,
                before_pipeline,
            )
            .unwrap();
        let below_cap_at_pipeline =
            read_below_capacity_validator_set_addresses_with_stake(
                &self.s, pipeline,
            )
            .unwrap();
        itertools::assert_equal(
            below_cap_before_pipeline.into_iter().sorted(),
            below_cap_at_pipeline.into_iter().sorted(),
        );

        // TODO: post-conditions for processing of slashes, just throwing things
        // here atm
        let slashed_validators = enqueued_slashes_handle()
            .at(&self.current_epoch())
            .iter(&self.s)
            .unwrap()
            .map(|a| {
                let (
                    NestedSubKey::Data {
                        key: address,
                        nested_sub_key: _,
                    },
                    _b,
                ) = a.unwrap();
                address
            })
            .collect::<HashSet<Address>>();

        for validator in &slashed_validators {
            assert!(
                !validator_slashes_handle(validator)
                    .is_empty(&self.s)
                    .unwrap()
            );
            assert_eq!(
                validator_state_handle(validator)
                    .get(&self.s, self.current_epoch(), params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
        }
    }

    fn check_bond_post_conditions(
        &self,
        submit_epoch: Epoch,
        params: &PosParams,
        id: BondId,
        amount: token::Amount,
        validator_stake_before_bond_cur: token::Amount,
        validator_stake_before_bond_pipeline: token::Amount,
    ) {
        let pipeline = submit_epoch + params.pipeline_len;

        let cur_stake = crate::read_validator_stake(
            &self.s,
            params,
            &id.validator,
            submit_epoch,
        )
        .unwrap();

        // Post-condition: the validator stake at the current epoch should not
        // change
        assert_eq!(cur_stake, validator_stake_before_bond_cur);

        let stake_at_pipeline = crate::read_validator_stake(
            &self.s,
            params,
            &id.validator,
            pipeline,
        )
        .unwrap();

        // Post-condition: the validator stake at the pipeline should be
        // incremented by the bond amount
        assert_eq!(
            stake_at_pipeline,
            validator_stake_before_bond_pipeline + amount
        );

        self.check_bond_and_unbond_post_conditions(
            submit_epoch,
            params,
            id,
            stake_at_pipeline,
        );
    }

    fn check_unbond_post_conditions(
        &self,
        submit_epoch: Epoch,
        params: &PosParams,
        id: BondId,
        amount: token::Amount,
        validator_stake_before_unbond_cur: token::Amount,
        validator_stake_before_unbond_pipeline: token::Amount,
    ) {
        let pipeline = submit_epoch + params.pipeline_len;

        let cur_stake = crate::read_validator_stake(
            &self.s,
            params,
            &id.validator,
            submit_epoch,
        )
        .unwrap();

        // Post-condition: the validator stake at the current epoch should not
        // change
        assert_eq!(cur_stake, validator_stake_before_unbond_cur);

        let stake_at_pipeline = crate::read_validator_stake(
            &self.s,
            params,
            &id.validator,
            pipeline,
        )
        .unwrap();

        // Post-condition: the validator stake at the pipeline should be
        // decremented at most by the bond amount (because slashing can reduce
        // the actual amount unbonded)
        //
        // TODO: is this a weak assertion here? Seems cumbersome to calculate
        // the exact amount considering the slashing applied can be complicated
        assert!(
            stake_at_pipeline
                >= validator_stake_before_unbond_pipeline
                    .checked_sub(amount)
                    .unwrap_or_default()
        );

        self.check_bond_and_unbond_post_conditions(
            submit_epoch,
            params,
            id,
            stake_at_pipeline,
        );
    }

    /// These post-conditions apply to bonding and unbonding
    fn check_bond_and_unbond_post_conditions(
        &self,
        submit_epoch: Epoch,
        params: &PosParams,
        id: BondId,
        stake_at_pipeline: token::Amount,
    ) {
        let pipeline = submit_epoch + params.pipeline_len;
        // Read the consensus sets data using iterator
        let num_in_consensus = crate::consensus_validator_set_handle()
            .at(&pipeline)
            .iter(&self.s)
            .unwrap()
            .map(|res| res.unwrap())
            .filter(|(_keys, addr)| addr == &id.validator)
            .count();

        let num_in_below_cap = crate::below_capacity_validator_set_handle()
            .at(&pipeline)
            .iter(&self.s)
            .unwrap()
            .map(|res| res.unwrap())
            .filter(|(_keys, addr)| addr == &id.validator)
            .count();

        let num_in_below_thresh =
            read_below_threshold_validator_set_addresses(&self.s, pipeline)
                .unwrap()
                .into_iter()
                .filter(|addr| addr == &id.validator)
                .count();

        let num_occurrences =
            num_in_consensus + num_in_below_cap + num_in_below_thresh;
        let validator_is_jailed = crate::validator_state_handle(&id.validator)
            .get(&self.s, pipeline, params)
            .unwrap()
            == Some(ValidatorState::Jailed);

        // Post-condition: There must only be one instance of this validator in
        // the consensus + below-cap sets with some stake across all
        // validator sets, OR there are no instances and this validator is
        // jailed
        assert!(
            num_occurrences == 1
                || (num_occurrences == 0 && validator_is_jailed)
        );

        let consensus_set = read_consensus_validator_set_addresses_with_stake(
            &self.s, pipeline,
        )
        .unwrap();
        let below_cap_set =
            read_below_capacity_validator_set_addresses_with_stake(
                &self.s, pipeline,
            )
            .unwrap();
        let below_thresh_set =
            read_below_threshold_validator_set_addresses(&self.s, pipeline)
                .unwrap();
        let weighted = WeightedValidator {
            bonded_stake: stake_at_pipeline,
            address: id.validator,
        };
        let consensus_val = consensus_set.get(&weighted);
        let below_cap_val = below_cap_set.get(&weighted);
        let below_thresh_val = below_thresh_set.get(&weighted.address);

        // Post-condition: The validator should be updated in exactly once in
        // the validator sets
        let jailed_condition = validator_is_jailed
            && consensus_val.is_none()
            && below_cap_val.is_none()
            && below_thresh_val.is_none();

        let mut num_sets = i32::from(consensus_val.is_some());
        num_sets += i32::from(below_cap_val.is_some());
        num_sets += i32::from(below_thresh_val.is_some());

        assert!(num_sets == 1 || jailed_condition);

        // Post-condition: The stake of the validators in the consensus set is
        // greater than or equal to below-capacity validators
        for WeightedValidator {
            bonded_stake: consensus_stake,
            address: consensus_addr,
        } in consensus_set.iter()
        {
            for WeightedValidator {
                bonded_stake: below_cap_stake,
                address: below_cap_addr,
            } in below_cap_set.iter()
            {
                assert!(
                    consensus_stake >= below_cap_stake,
                    "Consensus validator {consensus_addr} with stake {} and \
                     below-capacity {below_cap_addr} with stake {} should be \
                     swapped.",
                    consensus_stake.to_string_native(),
                    below_cap_stake.to_string_native()
                );
            }
        }
    }

    fn check_init_validator_post_conditions(
        &self,
        submit_epoch: Epoch,
        params: &PosParams,
        address: &Address,
    ) {
        let pipeline = submit_epoch + params.pipeline_len;

        // Post-condition: the validator should not be in the validator set
        // until the pipeline epoch
        for epoch in submit_epoch.iter_range(params.pipeline_len) {
            assert!(
                !crate::read_consensus_validator_set_addresses(&self.s, epoch)
                    .unwrap()
                    .contains(address)
            );
            assert!(
                !read_below_capacity_validator_set_addresses(&self.s, epoch)
                    .unwrap()
                    .contains(address)
            );
            assert!(
                !read_below_threshold_validator_set_addresses(&self.s, epoch)
                    .unwrap()
                    .contains(address)
            );
            assert!(
                !read_all_validator_addresses(&self.s, epoch)
                    .unwrap()
                    .contains(address)
            );
        }
        let in_consensus =
            crate::read_consensus_validator_set_addresses(&self.s, pipeline)
                .unwrap()
                .contains(address);
        let in_bc =
            read_below_capacity_validator_set_addresses(&self.s, pipeline)
                .unwrap()
                .contains(address);
        let in_below_thresh =
            read_below_threshold_validator_set_addresses(&self.s, pipeline)
                .unwrap()
                .contains(address);

        assert!(in_below_thresh && !in_consensus && !in_bc);
    }

    fn check_misbehavior_post_conditions(
        &self,
        params: &PosParams,
        current_epoch: Epoch,
        infraction_epoch: Epoch,
        infraction_height: u64,
        slash_type: SlashType,
        validator: &Address,
    ) {
        tracing::debug!(
            "\nChecking misbehavior post conditions for validator: \n{}",
            validator
        );

        // Validator state jailed and validator removed from the consensus set
        // starting at the next epoch
        for offset in 1..=params.pipeline_len {
            // dbg!(
            //     crate::read_consensus_validator_set_addresses_with_stake(
            //         &self.s,
            //         current_epoch + offset
            //     )
            //     .unwrap()
            // );
            assert_eq!(
                validator_state_handle(validator)
                    .get(&self.s, current_epoch + offset, params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            let in_consensus = consensus_validator_set_handle()
                .at(&(current_epoch + offset))
                .iter(&self.s)
                .unwrap()
                .any(|res| {
                    let (_, val_address) = res.unwrap();
                    // dbg!(&val_address);
                    val_address == validator.clone()
                });
            assert!(!in_consensus);
        }

        // `enqueued_slashes` contains the slash element just added
        let processing_epoch = infraction_epoch
            + params.unbonding_len
            + 1_u64
            + params.cubic_slashing_window_length;
        let slash = enqueued_slashes_handle()
            .at(&processing_epoch)
            .at(validator)
            .get(&self.s, &infraction_height)
            .unwrap();
        if let Some(slash) = slash {
            assert_eq!(slash.epoch, infraction_epoch);
            assert_eq!(slash.r#type, slash_type);
            assert_eq!(slash.rate, Dec::zero());
        } else {
            panic!("Could not find the slash enqueued");
        }

        // TODO: Any others?
    }

    fn check_unjail_validator_post_conditions(
        &self,
        params: &PosParams,
        validator: &Address,
    ) {
        let current_epoch = self.s.in_mem().block.epoch;

        // Make sure the validator is not in either set until the pipeline epoch
        for epoch in current_epoch.iter_range(params.pipeline_len) {
            let in_consensus = consensus_validator_set_handle()
                .at(&epoch)
                .iter(&self.s)
                .unwrap()
                .any(|res| {
                    let (_, val_address) = res.unwrap();
                    val_address == validator.clone()
                });

            let in_bc = below_capacity_validator_set_handle()
                .at(&epoch)
                .iter(&self.s)
                .unwrap()
                .any(|res| {
                    let (_, val_address) = res.unwrap();
                    val_address == validator.clone()
                });
            assert!(!in_consensus && !in_bc);

            let val_state = validator_state_handle(validator)
                .get(&self.s, epoch, params)
                .unwrap();
            assert_eq!(val_state, Some(ValidatorState::Jailed));
        }
        let pipeline_epoch = current_epoch + params.pipeline_len;

        let num_in_consensus = consensus_validator_set_handle()
            .at(&pipeline_epoch)
            .iter(&self.s)
            .unwrap()
            .map(|res| res.unwrap())
            .filter(|(_keys, addr)| addr == validator)
            .count();

        let num_in_bc = below_capacity_validator_set_handle()
            .at(&pipeline_epoch)
            .iter(&self.s)
            .unwrap()
            .map(|res| res.unwrap())
            .filter(|(_keys, addr)| addr == validator)
            .count();

        let num_in_bt = read_below_threshold_validator_set_addresses(
            &self.s,
            pipeline_epoch,
        )
        .unwrap()
        .into_iter()
        .filter(|addr| addr == validator)
        .count();

        let num_occurrences = num_in_consensus + num_in_bc + num_in_bt;
        assert_eq!(num_occurrences, 1);

        let val_state = validator_state_handle(validator)
            .get(&self.s, current_epoch + params.pipeline_len, params)
            .unwrap();
        assert!(
            val_state == Some(ValidatorState::Consensus)
                || val_state == Some(ValidatorState::BelowCapacity)
                || val_state == Some(ValidatorState::BelowThreshold)
        );
    }

    fn check_global_post_conditions(
        &self,
        params: &PosParams,
        current_epoch: Epoch,
        ref_state: &AbstractPosState,
    ) {
        // Ensure that every validator in each set has the proper state
        for epoch in Epoch::iter_bounds_inclusive(
            current_epoch,
            current_epoch + params.pipeline_len,
        ) {
            tracing::debug!("Epoch {epoch}");
            let mut vals = HashSet::<Address>::new();
            for WeightedValidator {
                bonded_stake,
                address: validator,
            } in read_consensus_validator_set_addresses_with_stake(
                &self.s, epoch,
            )
            .unwrap()
            {
                let deltas_stake = validator_deltas_handle(&validator)
                    .get_sum(&self.s, epoch, params)
                    .unwrap()
                    .unwrap_or_default();
                let max_slash_round_err = ref_state
                    .validator_records
                    .get(&validator)
                    .unwrap()
                    .slash_round_err_tolerance(epoch);
                let ref_stake = ref_state
                    .validator_stakes
                    .get(&epoch)
                    .unwrap()
                    .get(&validator)
                    .cloned()
                    .unwrap();
                let conc_stake = bonded_stake.change();
                let max_err_msg = if max_slash_round_err.is_zero() {
                    "no error expected".to_string()
                } else {
                    format!(
                        "max err +-{}",
                        max_slash_round_err.to_string_native()
                    )
                };
                tracing::debug!(
                    "Consensus val {}, set stake: {}, deltas: {}, ref: {}, \
                     {max_err_msg}",
                    &validator,
                    conc_stake.to_string_native(),
                    deltas_stake.to_string_native(),
                    ref_stake.to_string_native(),
                );
                assert!(!deltas_stake.is_negative());
                assert_eq!(conc_stake, deltas_stake);
                assert!(
                    ref_stake <= conc_stake + max_slash_round_err.change()
                        && conc_stake
                            <= ref_stake + max_slash_round_err.change(),
                    "Expected {} ({max_err_msg}), got {}.",
                    ref_stake.to_string_native(),
                    conc_stake.to_string_native()
                );

                let state = crate::validator_state_handle(&validator)
                    .get(&self.s, epoch, params)
                    .unwrap();

                assert_eq!(state, Some(ValidatorState::Consensus));
                assert_eq!(
                    state.unwrap(),
                    ref_state
                        .validator_states
                        .get(&epoch)
                        .unwrap()
                        .get(&validator)
                        .cloned()
                        .unwrap()
                );
                assert!(!vals.contains(&validator));
                vals.insert(validator);
            }
            for WeightedValidator {
                bonded_stake,
                address: validator,
            } in read_below_capacity_validator_set_addresses_with_stake(
                &self.s, epoch,
            )
            .unwrap()
            {
                let deltas_stake = validator_deltas_handle(&validator)
                    .get_sum(&self.s, epoch, params)
                    .unwrap()
                    .unwrap_or_default();
                let max_slash_round_err = ref_state
                    .validator_records
                    .get(&validator)
                    .unwrap()
                    .slash_round_err_tolerance(epoch);
                let ref_stake = ref_state
                    .validator_stakes
                    .get(&epoch)
                    .unwrap()
                    .get(&validator)
                    .cloned()
                    .unwrap();
                let conc_stake = bonded_stake.change();
                let max_err_msg = if max_slash_round_err.is_zero() {
                    "no error expected".to_string()
                } else {
                    format!(
                        "max err +-{}",
                        max_slash_round_err.to_string_native()
                    )
                };
                tracing::debug!(
                    "Below-cap val {}, set stake: {}, deltas: {}, ref: {}, \
                     {max_err_msg}",
                    &validator,
                    conc_stake.to_string_native(),
                    deltas_stake.to_string_native(),
                    ref_stake.to_string_native(),
                );
                assert_eq!(conc_stake, deltas_stake);
                assert!(
                    conc_stake <= ref_stake + max_slash_round_err.change()
                        && ref_stake
                            <= conc_stake + max_slash_round_err.change(),
                    "Expected {} ({max_err_msg}), got {}.",
                    ref_stake.to_string_native(),
                    bonded_stake.to_string_native()
                );

                let state = crate::validator_state_handle(&validator)
                    .get(&self.s, epoch, params)
                    .unwrap();
                // if state.is_none() {
                //     dbg!(
                //         crate::validator_state_handle(&validator)
                //             .get(&self.s, current_epoch, params)
                //             .unwrap()
                //     );
                //     dbg!(
                //         crate::validator_state_handle(&validator)
                //             .get(&self.s, current_epoch.next(), params)
                //             .unwrap()
                //     );
                //     dbg!(
                //         crate::validator_state_handle(&validator)
                //             .get(&self.s, current_epoch.next(), params)
                //             .unwrap()
                //     );
                // }
                assert_eq!(state, Some(ValidatorState::BelowCapacity));
                assert_eq!(
                    state.unwrap(),
                    ref_state
                        .validator_states
                        .get(&epoch)
                        .unwrap()
                        .get(&validator)
                        .cloned()
                        .unwrap()
                );
                assert!(!vals.contains(&validator));
                vals.insert(validator);
            }

            for validator in
                read_below_threshold_validator_set_addresses(&self.s, epoch)
                    .unwrap()
            {
                let conc_stake = validator_deltas_handle(&validator)
                    .get_sum(&self.s, epoch, params)
                    .unwrap()
                    .unwrap_or_default();

                let state = crate::validator_state_handle(&validator)
                    .get(&self.s, epoch, params)
                    .unwrap()
                    .unwrap();

                assert_eq!(state, ValidatorState::BelowThreshold);
                assert_eq!(
                    state,
                    ref_state
                        .validator_states
                        .get(&epoch)
                        .unwrap()
                        .get(&validator)
                        .cloned()
                        .unwrap()
                );
                let max_slash_round_err = ref_state
                    .validator_records
                    .get(&validator)
                    .map(|r| r.slash_round_err_tolerance(epoch))
                    .unwrap_or_default();
                let ref_stake = ref_state
                    .validator_stakes
                    .get(&epoch)
                    .unwrap()
                    .get(&validator)
                    .cloned()
                    .unwrap();
                let max_err_msg = if max_slash_round_err.is_zero() {
                    "no error expected".to_string()
                } else {
                    format!(
                        "max err +-{}",
                        max_slash_round_err.to_string_native()
                    )
                };
                tracing::debug!(
                    "Below-thresh val {}, deltas: {}, ref: {}, {max_err_msg})",
                    &validator,
                    conc_stake.to_string_native(),
                    ref_stake.to_string_native(),
                );
                assert!(
                    conc_stake <= ref_stake + max_slash_round_err.change()
                        && ref_stake
                            <= conc_stake + max_slash_round_err.change(),
                    "Expected {} ({max_err_msg}), got {}.",
                    ref_stake.to_string_native(),
                    conc_stake.to_string_native()
                );
                assert!(!vals.contains(&validator));
                vals.insert(validator);
            }

            // Jailed validators not in a set
            let all_validators =
                read_all_validator_addresses(&self.s, epoch).unwrap();

            for val in all_validators {
                let state = validator_state_handle(&val)
                    .get(&self.s, epoch, params)
                    .unwrap()
                    .unwrap();

                if state == ValidatorState::Jailed {
                    assert_eq!(
                        state,
                        ref_state
                            .validator_states
                            .get(&epoch)
                            .unwrap()
                            .get(&val)
                            .cloned()
                            .unwrap()
                    );
                    let conc_stake = validator_deltas_handle(&val)
                        .get_sum(&self.s, epoch, params)
                        .unwrap()
                        .unwrap_or_default();
                    let max_slash_round_err = ref_state
                        .validator_records
                        .get(&val)
                        .map(|r| r.slash_round_err_tolerance(epoch))
                        .unwrap_or_default();
                    let max_err_msg = if max_slash_round_err.is_zero() {
                        "no error expected".to_string()
                    } else {
                        format!(
                            "max err +-{}",
                            max_slash_round_err.to_string_native()
                        )
                    };
                    let ref_stake = ref_state
                        .validator_stakes
                        .get(&epoch)
                        .unwrap()
                        .get(&val)
                        .cloned()
                        .unwrap();
                    tracing::debug!(
                        "Jailed val {}, deltas: {}, ref: {}, {max_err_msg}",
                        &val,
                        conc_stake.to_string_native(),
                        ref_stake.to_string_native(),
                    );

                    assert_eq!(
                        state,
                        ref_state
                            .validator_states
                            .get(&epoch)
                            .unwrap()
                            .get(&val)
                            .cloned()
                            .unwrap()
                    );
                    assert!(
                        conc_stake <= ref_stake + max_slash_round_err.change()
                            && ref_stake
                                <= conc_stake + max_slash_round_err.change(),
                        "Expected {} ({}), got {}.",
                        ref_stake.to_string_native(),
                        max_err_msg,
                        conc_stake.to_string_native()
                    );
                    assert!(!vals.contains(&val));
                }
            }
        }

        // Check that validator stakes are matching ref_state
        for (validator, records) in &ref_state.validator_records {
            // On every epoch from current up to pipeline
            for epoch in current_epoch.iter_range(params.pipeline_len) {
                let ref_stake = records.stake(epoch);
                let conc_stake = crate::read_validator_stake(
                    &self.s, params, validator, epoch,
                )
                .unwrap();
                let max_slash_round_err =
                    records.slash_round_err_tolerance(epoch);
                assert!(
                    ref_stake <= conc_stake + max_slash_round_err
                        && conc_stake <= ref_stake + max_slash_round_err,
                    "Stake for validator {validator} in epoch {epoch} is not \
                     matched against reference stake. Expected {} ({}), got \
                     {}.",
                    ref_stake.to_string_native(),
                    if max_slash_round_err.is_zero() {
                        "no slashing rounding error expected".to_string()
                    } else {
                        format!(
                            "max slashing rounding error +-{}",
                            max_slash_round_err.to_string_native()
                        )
                    },
                    conc_stake.to_string_native()
                );
            }
        }
        // TODO: expand above to include jailed validators

        for (validator, records) in &ref_state.validator_records {
            for (source, records) in &records.per_source {
                let bond_id = BondId {
                    source: source.clone(),
                    validator: validator.clone(),
                };
                for epoch in current_epoch.iter_range(params.pipeline_len) {
                    let max_slash_round_err =
                        records.slash_round_err_tolerance(epoch);
                    let conc_bond_amount =
                        crate::bond_amount::<_, GovStore<_>>(
                            &self.s, &bond_id, epoch,
                        )
                        .unwrap();
                    let ref_bond_amount = records.amount(epoch);
                    assert!(
                        ref_bond_amount
                            <= conc_bond_amount + max_slash_round_err
                            && conc_bond_amount
                                <= ref_bond_amount + max_slash_round_err,
                        "Slashed `bond_amount` for validator {validator} in \
                         epoch {epoch} is not matched against reference \
                         state. Expected {} ({}), got {}.",
                        ref_bond_amount.to_string_native(),
                        if max_slash_round_err.is_zero() {
                            "no slashing rounding error expected".to_string()
                        } else {
                            format!(
                                "max slashing rounding error +-{}",
                                max_slash_round_err.to_string_native()
                            )
                        },
                        conc_bond_amount.to_string_native()
                    );
                }
            }
        }
    }
}

impl ReferenceStateMachine for AbstractPosState {
    type State = Self;
    type Transition = Transition;

    fn init_state() -> BoxedStrategy<Self::State> {
        tracing::debug!("\nInitializing abstract state machine");
        arb_params_and_genesis_validators(Some(8), 8..10)
            .prop_map(|(params, genesis_validators)| {
                let epoch = Epoch::default();
                let gov_params = GovernanceParameters::default();
                let params = params.with_gov_params(&gov_params);
                let mut state = Self {
                    epoch,
                    params,
                    gov_params,
                    genesis_validators: genesis_validators
                        .into_iter()
                        // Sorted by stake to fill in the consensus set first
                        .sorted_by(|a, b| Ord::cmp(&a.tokens, &b.tokens))
                        .rev()
                        .collect(),
                    validator_records: Default::default(),
                    validator_stakes: Default::default(),
                    consensus_set: Default::default(),
                    below_capacity_set: Default::default(),
                    below_threshold_set: Default::default(),
                    validator_states: Default::default(),
                    validator_slashes: Default::default(),
                    enqueued_slashes: Default::default(),
                    validator_last_slash_epochs: Default::default(),
                };

                for GenesisValidator {
                    address,
                    tokens,
                    consensus_key: _,
                    protocol_key: _,
                    eth_cold_key: _,
                    eth_hot_key: _,
                    commission_rate: _,
                    max_commission_rate_change: _,
                    metadata: _,
                } in state.genesis_validators.clone()
                {
                    let records = state.records_mut(&address, &address);
                    let bond_at_start = records.bonds.entry(epoch).or_default();
                    bond_at_start.tokens.amount = tokens;

                    let total_stakes =
                        state.validator_stakes.entry(epoch).or_default();
                    total_stakes
                        .insert(address.clone(), token::Change::from(tokens));

                    let consensus_set =
                        state.consensus_set.entry(epoch).or_default();
                    let consensus_vals_len = consensus_set
                        .values()
                        .map(|validators| validators.len() as u64)
                        .sum();

                    if tokens < state.params.validator_stake_threshold {
                        state
                            .below_threshold_set
                            .entry(epoch)
                            .or_default()
                            .insert(address.clone());
                        state
                            .validator_states
                            .entry(epoch)
                            .or_default()
                            .insert(address, ValidatorState::BelowThreshold);
                    } else if state.params.max_validator_slots
                        > consensus_vals_len
                    {
                        state
                            .validator_states
                            .entry(epoch)
                            .or_default()
                            .insert(address.clone(), ValidatorState::Consensus);
                        consensus_set
                            .entry(tokens)
                            .or_default()
                            .push_back(address);
                    } else {
                        state
                            .validator_states
                            .entry(epoch)
                            .or_default()
                            .insert(
                                address.clone(),
                                ValidatorState::BelowCapacity,
                            );
                        let below_cap_set =
                            state.below_capacity_set.entry(epoch).or_default();
                        below_cap_set
                            .entry(ReverseOrdTokenAmount(tokens))
                            .or_default()
                            .push_back(address)
                    };
                }
                // Ensure that below-capacity and below-threshold sets are
                // initialized even if empty
                state.below_capacity_set.entry(epoch).or_default();
                state.below_threshold_set.entry(epoch).or_default();

                // Copy validator sets up to pipeline epoch
                for epoch in epoch.next().iter_range(state.params.pipeline_len)
                {
                    state.copy_discrete_epoched_data(epoch)
                }
                state
            })
            .boxed()
    }

    // TODO: allow bonding to jailed val
    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        // Let preconditions filter out what unbonds are not allowed
        let unbondable =
            state.unbondable_bonds().into_iter().collect::<Vec<_>>();
        let redelegatable =
            state.redelegatable_bonds().into_iter().collect::<Vec<_>>();

        let withdrawable =
            state.withdrawable_unbonds().into_iter().collect::<Vec<_>>();

        let eligible_for_unjail = state
            .validator_states
            .get(&state.pipeline())
            .unwrap()
            .iter()
            .filter_map(|(addr, &val_state)| {
                let last_slash_epoch =
                    state.validator_last_slash_epochs.get(addr);

                if let Some(last_slash_epoch) = last_slash_epoch {
                    if val_state == ValidatorState::Jailed
                        // `last_slash_epoch` must be unbonding_len + window_width or more epochs
                        // before the current
                        && state.epoch.0 - last_slash_epoch.0
                            > state.params.unbonding_len + state.params.cubic_slashing_window_length
                    {
                        return Some(addr.clone());
                    }
                }
                None
            })
            .collect::<Vec<_>>();

        // Transitions that can be applied if there are no bonds and unbonds
        let basic = prop_oneof![
            4 => Just(Transition::NextEpoch),
            6 => add_arb_bond_amount(state.clone()),
            5 => arb_delegation(state.clone()),
            3 => arb_self_bond(state.clone()),
            1 => (
                address::testing::arb_established_address(),
                key::testing::arb_common_keypair(),
                key::testing::arb_common_keypair(),
                key::testing::arb_common_secp256k1_keypair(),
                key::testing::arb_common_secp256k1_keypair(),
                arb_rate(),
                arb_rate(),
            )
                .prop_map(
                    |(
                        addr,
                        consensus_key,
                        protocol_key,
                        eth_hot_key,
                        eth_cold_key,
                        commission_rate,
                        max_commission_rate_change,
                    )| {
                        Transition::InitValidator {
                            address: Address::Established(addr),
                            consensus_key: consensus_key.to_public(),
                            protocol_key: protocol_key.to_public(),
                            eth_hot_key: eth_hot_key.to_public(),
                            eth_cold_key: eth_cold_key.to_public(),
                            commission_rate,
                            max_commission_rate_change,
                        }
                    },
                ),
            1 => arb_slash(state.clone()),
        ];

        // Add unjailing, if any eligible
        let transitions = if eligible_for_unjail.is_empty() {
            basic.boxed()
        } else {
            prop_oneof![
                // basic 6x more likely as it's got 6 cases
                6 => basic,
                1 => prop::sample::select(eligible_for_unjail).prop_map(|address| {
                    Transition::UnjailValidator { address }
                })
            ]
            .boxed()
        };

        // Add unbonds, if any
        let transitions = if unbondable.is_empty() {
            transitions
        } else {
            let arb_unbondable = prop::sample::select(unbondable);
            let arb_unbond =
                arb_unbondable.prop_flat_map(move |(id, bonds_sum)| {
                    let bonds_sum: i128 =
                        TryFrom::try_from(bonds_sum.change()).unwrap();
                    (0..bonds_sum).prop_map(move |to_unbond| {
                        let id = id.clone();
                        let amount =
                            token::Amount::from_change(Change::from(to_unbond));
                        Transition::Unbond { id, amount }
                    })
                });
            prop_oneof![
                7 => transitions,
                1 => arb_unbond,
            ]
            .boxed()
        };

        // Add withdrawals, if any
        let transitions = if withdrawable.is_empty() {
            transitions
        } else {
            let arb_withdrawable = prop::sample::select(withdrawable);
            let arb_withdrawal = arb_withdrawable
                .prop_map(|(id, _)| Transition::Withdraw { id });

            prop_oneof![
                8 => transitions,
                1 => arb_withdrawal,
            ]
            .boxed()
        };

        // Add redelegations, if any
        if redelegatable.is_empty() {
            transitions
        } else {
            let arb_redelegatable = prop::sample::select(redelegatable);
            let validators = state
                .validator_states
                .get(&state.pipeline())
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            let unchainable_redelegations = state.unchainable_redelegations();
            let arb_redelegation =
                arb_redelegatable.prop_flat_map(move |(id, deltas_sum)| {
                    let deltas_sum =
                        i128::try_from(deltas_sum.change()).unwrap();
                    // Generate an amount to redelegate, up to the sum
                    assert!(
                        deltas_sum > 0,
                        "Bond {id} deltas_sum must be non-zero"
                    );
                    let arb_amount = (0..deltas_sum).prop_map(|to_unbond| {
                        token::Amount::from_change(Change::from(to_unbond))
                    });
                    // Generate a new validator for redelegation
                    let current_validator = id.validator.clone();
                    let new_validators = validators
                        .iter()
                        // The validator must be other than the current
                        .filter(|validator| *validator != &current_validator)
                        .cloned()
                        .collect::<Vec<_>>();
                    let arb_new_validator =
                        prop::sample::select(new_validators);
                    let unchainable_redelegations =
                        unchainable_redelegations.clone();
                    (arb_amount, arb_new_validator).prop_map(
                        move |(amount, new_validator)| Transition::Redelegate {
                            is_chained: Self::is_chained_redelegation(
                                &unchainable_redelegations,
                                &id.source,
                                &id.validator,
                            ),
                            id: id.clone(),
                            new_validator,
                            amount,
                        },
                    )
                });
            prop_oneof![
                9 => transitions,
                // Cranked up to make redelegations more common
                15 => arb_redelegation,
            ]
            .boxed()
        }
    }

    fn apply(
        mut state: Self::State,
        transition: &Self::Transition,
    ) -> Self::State {
        match transition {
            Transition::NextEpoch => {
                state.epoch = state.epoch.next();
                tracing::debug!("Starting epoch {}", state.epoch);

                // Copy the non-delta data into pipeline epoch from its pred.
                state.copy_discrete_epoched_data(state.pipeline());

                // Process slashes enqueued for the new epoch
                state.process_enqueued_slashes();

                // print-out the state
                state.debug_validators();
            }
            Transition::InitValidator {
                address,
                consensus_key: _,
                protocol_key: _,
                eth_cold_key: _,
                eth_hot_key: _,
                commission_rate: _,
                max_commission_rate_change: _,
            } => {
                let pipeline: Epoch = state.pipeline();

                // Initialize the stake at pipeline
                state
                    .validator_stakes
                    .entry(pipeline)
                    .or_default()
                    .insert(address.clone(), 0_i128.into());

                // Insert into the below-threshold set at pipeline since the
                // initial stake is 0
                state
                    .below_threshold_set
                    .entry(pipeline)
                    .or_default()
                    .insert(address.clone());
                state
                    .validator_states
                    .entry(pipeline)
                    .or_default()
                    .insert(address.clone(), ValidatorState::BelowThreshold);

                state.debug_validators();
            }
            Transition::Bond { id, amount } => {
                if !amount.is_zero() {
                    state.bond(id, *amount);
                    state.debug_validators();
                }
            }
            Transition::Unbond { id, amount } => {
                if !amount.is_zero() {
                    state.unbond(id, *amount);
                    state.debug_validators();
                }
            }
            Transition::Withdraw { id } => {
                state.withdraw(id);
            }
            Transition::Redelegate {
                is_chained,
                id,
                new_validator,
                amount,
            } => {
                if *is_chained {
                    return state;
                }
                if !amount.is_zero() {
                    state.redelegate(id, new_validator, *amount);
                    state.debug_validators();
                }
            }
            Transition::Misbehavior {
                address,
                slash_type,
                infraction_epoch,
                height,
            } => {
                let current_epoch = state.epoch;
                let processing_epoch = *infraction_epoch
                    + state.params.unbonding_len
                    + 1_u64
                    + state.params.cubic_slashing_window_length;
                let slash = Slash {
                    epoch: *infraction_epoch,
                    block_height: *height,
                    r#type: *slash_type,
                    rate: Dec::zero(),
                };

                // Enqueue the slash for future processing
                state
                    .enqueued_slashes
                    .entry(processing_epoch)
                    .or_default()
                    .entry(address.clone())
                    .or_default()
                    .push(slash);

                // Remove the validator from either the consensus or
                // below-capacity set and place it into the jailed validator set

                // Remove from the validator set starting at the next epoch and
                // up thru the pipeline
                for offset in 1..=state.params.pipeline_len {
                    let real_stake = token::Amount::from_change(
                        state
                            .validator_stakes
                            .get(&(current_epoch + offset))
                            .unwrap()
                            .get(address)
                            .cloned()
                            .unwrap_or_default(),
                    );

                    if let Some((index, stake)) = state
                        .is_in_consensus_w_info(address, current_epoch + offset)
                    {
                        debug_assert_eq!(stake, real_stake);

                        let vals = state
                            .consensus_set
                            .entry(current_epoch + offset)
                            .or_default()
                            .entry(stake)
                            .or_default();
                        let removed = vals.remove(index);
                        debug_assert_eq!(removed, Some(address.clone()));
                        if vals.is_empty() {
                            state
                                .consensus_set
                                .entry(current_epoch + offset)
                                .or_default()
                                .remove(&stake);
                        }

                        // At pipeline epoch, if was consensus, replace it with
                        // a below-capacity validator
                        if offset == state.params.pipeline_len {
                            let below_cap_pipeline = state
                                .below_capacity_set
                                .entry(current_epoch + offset)
                                .or_default();

                            if let Some(mut max_below_cap) =
                                below_cap_pipeline.last_entry()
                            {
                                let max_bc_stake = *max_below_cap.key();
                                let vals = max_below_cap.get_mut();
                                let first_val = vals.pop_front().unwrap();
                                if vals.is_empty() {
                                    below_cap_pipeline.remove(&max_bc_stake);
                                }
                                state
                                    .consensus_set
                                    .entry(current_epoch + offset)
                                    .or_default()
                                    .entry(max_bc_stake.into())
                                    .or_default()
                                    .push_back(first_val.clone());
                                state
                                    .validator_states
                                    .entry(current_epoch + offset)
                                    .or_default()
                                    .insert(
                                        first_val.clone(),
                                        ValidatorState::Consensus,
                                    );
                            }
                        }
                    } else if let Some((index, stake)) = state
                        .is_in_below_capacity_w_info(
                            address,
                            current_epoch + offset,
                        )
                    {
                        debug_assert_eq!(stake, real_stake);

                        let vals = state
                            .below_capacity_set
                            .entry(current_epoch + offset)
                            .or_default()
                            .entry(stake.into())
                            .or_default();

                        let removed = vals.remove(index);
                        debug_assert_eq!(removed, Some(address.clone()));
                        if vals.is_empty() {
                            state
                                .below_capacity_set
                                .entry(current_epoch + offset)
                                .or_default()
                                .remove(&stake.into());
                        }
                    } else if state
                        .is_in_below_threshold(address, current_epoch + offset)
                    {
                        let removed = state
                            .below_threshold_set
                            .entry(current_epoch + offset)
                            .or_default()
                            .swap_remove(address);
                        debug_assert!(removed);
                    } else {
                        // Just make sure the validator is already jailed
                        debug_assert_eq!(
                            state
                                .validator_states
                                .get(&(current_epoch + offset))
                                .unwrap()
                                .get(address)
                                .cloned()
                                .unwrap(),
                            ValidatorState::Jailed
                        );
                    }

                    state
                        .validator_states
                        .entry(current_epoch + offset)
                        .or_default()
                        .insert(address.clone(), ValidatorState::Jailed);
                }

                // Update the most recent infraction epoch for the validator
                if let Some(last_epoch) =
                    state.validator_last_slash_epochs.get(address)
                {
                    if infraction_epoch > last_epoch {
                        state
                            .validator_last_slash_epochs
                            .insert(address.clone(), *infraction_epoch);
                    }
                } else {
                    state
                        .validator_last_slash_epochs
                        .insert(address.clone(), *infraction_epoch);
                }

                state.debug_validators();
            }
            Transition::UnjailValidator { address } => {
                let pipeline_epoch = state.pipeline();
                let consensus_set_pipeline =
                    state.consensus_set.entry(pipeline_epoch).or_default();
                let pipeline_stake = state
                    .validator_stakes
                    .get(&pipeline_epoch)
                    .unwrap()
                    .get(address)
                    .cloned()
                    .unwrap_or_default();
                let validator_states_pipeline =
                    state.validator_states.entry(pipeline_epoch).or_default();

                // Insert the validator back into the appropriate validator set
                // and update its state
                let num_consensus = consensus_set_pipeline
                    .iter()
                    .fold(0, |sum, (_, validators)| {
                        sum + validators.len() as u64
                    });

                if pipeline_stake
                    < state.params.validator_stake_threshold.change()
                {
                    // Place into the below-threshold set
                    let below_threshold_set_pipeline = state
                        .below_threshold_set
                        .entry(pipeline_epoch)
                        .or_default();
                    below_threshold_set_pipeline.insert(address.clone());
                    validator_states_pipeline.insert(
                        address.clone(),
                        ValidatorState::BelowThreshold,
                    );
                } else if num_consensus < state.params.max_validator_slots {
                    // Place directly into the consensus set
                    debug_assert!(
                        state
                            .below_capacity_set
                            .get(&pipeline_epoch)
                            .unwrap()
                            .is_empty()
                    );
                    consensus_set_pipeline
                        .entry(token::Amount::from_change(pipeline_stake))
                        .or_default()
                        .push_back(address.clone());
                    validator_states_pipeline
                        .insert(address.clone(), ValidatorState::Consensus);
                } else if let Some(mut min_consensus) =
                    consensus_set_pipeline.first_entry()
                {
                    let below_capacity_set_pipeline = state
                        .below_capacity_set
                        .entry(pipeline_epoch)
                        .or_default();

                    let min_consensus_stake = *min_consensus.key();
                    if pipeline_stake > min_consensus_stake.change() {
                        // Place into the consensus set and demote the last
                        // min_consensus validator
                        let min_validators = min_consensus.get_mut();
                        let last_val = min_validators.pop_back().unwrap();
                        // Remove the key if there's nothing left
                        if min_validators.is_empty() {
                            consensus_set_pipeline.remove(&min_consensus_stake);
                        }
                        // Do the swap
                        below_capacity_set_pipeline
                            .entry(min_consensus_stake.into())
                            .or_default()
                            .push_back(last_val.clone());
                        validator_states_pipeline
                            .insert(last_val, ValidatorState::BelowCapacity);

                        consensus_set_pipeline
                            .entry(token::Amount::from_change(pipeline_stake))
                            .or_default()
                            .push_back(address.clone());
                        validator_states_pipeline
                            .insert(address.clone(), ValidatorState::Consensus);
                    } else {
                        // Just place into the below-capacity set
                        below_capacity_set_pipeline
                            .entry(
                                token::Amount::from_change(pipeline_stake)
                                    .into(),
                            )
                            .or_default()
                            .push_back(address.clone());
                        validator_states_pipeline.insert(
                            address.clone(),
                            ValidatorState::BelowCapacity,
                        );
                    }
                } else {
                    panic!("Should not reach here I don't think")
                }
                state.debug_validators();
            }
        }

        state
    }

    fn preconditions(
        state: &Self::State,
        transition: &Self::Transition,
    ) -> bool {
        match transition {
            // TODO: should there be any slashing preconditions for `NextEpoch`?
            Transition::NextEpoch => true,
            Transition::InitValidator {
                address,
                consensus_key: _,
                protocol_key: _,
                eth_cold_key: _,
                eth_hot_key: _,
                commission_rate: _,
                max_commission_rate_change: _,
            } => {
                let pipeline = state.pipeline();
                // The address must not belong to an existing validator
                !state.is_validator(address, pipeline) &&
                   // There must be no delegations from this address
                   !state.unbondable_bonds().into_iter().any(|(id, _sum)|
                        &id.source == address)
            }
            Transition::Bond { id, amount: _ } => {
                let pipeline = state.pipeline();
                // The validator must be known
                if !state.is_validator(&id.validator, pipeline) {
                    return false;
                }

                id.validator == id.source
                        // If it's not a self-bond, the source must not be a validator
                        || !state.is_validator(&id.source, pipeline)
            }
            Transition::Unbond { id, amount } => {
                let pipeline = state.pipeline();

                let is_unbondable = state
                    .unbondable_bonds()
                    .get(id)
                    .map(|sum| sum >= amount)
                    .unwrap_or_default();

                // The validator must not be frozen currently
                let is_frozen = if let Some(last_epoch) =
                    state.validator_last_slash_epochs.get(&id.validator)
                {
                    *last_epoch
                        + state.params.unbonding_len
                        + 1u64
                        + state.params.cubic_slashing_window_length
                        > state.epoch
                } else {
                    false
                };

                // if is_frozen {
                //     tracing::debug!(
                //         "\nVALIDATOR {} IS FROZEN - CANNOT UNBOND\n",
                //         &id.validator
                //     );
                // }

                // The validator must be known
                state.is_validator(&id.validator, pipeline)
                    // The amount must be available to unbond and the validator not jailed
                    && is_unbondable && !is_frozen
            }
            Transition::Withdraw { id } => {
                let pipeline = state.pipeline();

                let is_withdrawable = state
                    .withdrawable_unbonds()
                    .get(id)
                    .map(|amount| *amount > token::Amount::zero())
                    .unwrap_or_default();

                // The validator must not be jailed currently
                let is_jailed = state
                    .validator_states
                    .get(&state.epoch)
                    .unwrap()
                    .get(&id.validator)
                    .cloned()
                    == Some(ValidatorState::Jailed);

                // The validator must be known
                state.is_validator(&id.validator, pipeline)
                    // The amount must be available to unbond
                    && is_withdrawable && !is_jailed
            }
            Transition::Redelegate {
                is_chained,
                id,
                new_validator,
                amount,
            } => {
                let pipeline = state.pipeline();

                if *is_chained {
                    Self::is_chained_redelegation(
                        &state.unchainable_redelegations(),
                        &id.source,
                        new_validator,
                    )
                } else {
                    // The src and dest validator must be known
                    if !state.is_validator(&id.validator, pipeline)
                        || !state.is_validator(new_validator, pipeline)
                    {
                        return false;
                    }

                    // The amount must be available to redelegate
                    if !state
                        .unbondable_bonds()
                        .get(id)
                        .map(|sum| sum >= amount)
                        .unwrap_or_default()
                    {
                        return false;
                    }

                    // The src validator must not be frozen
                    if let Some(last_epoch) =
                        state.validator_last_slash_epochs.get(&id.validator)
                    {
                        if *last_epoch
                            + state.params.unbonding_len
                            + 1u64
                            + state.params.cubic_slashing_window_length
                            > state.epoch
                        {
                            return false;
                        }
                    }

                    // The dest validator must not be frozen
                    if let Some(last_epoch) =
                        state.validator_last_slash_epochs.get(new_validator)
                    {
                        if *last_epoch
                            + state.params.unbonding_len
                            + 1u64
                            + state.params.cubic_slashing_window_length
                            > state.epoch
                        {
                            return false;
                        }
                    }

                    true
                }
            }
            Transition::Misbehavior {
                address,
                slash_type: _,
                infraction_epoch,
                height: _,
            } => {
                let is_validator =
                    state.is_validator(address, *infraction_epoch);

                // The infraction epoch cannot be in the future or more than
                // unbonding_len epochs in the past
                let current_epoch = state.epoch;
                let valid_epoch = *infraction_epoch <= current_epoch
                    && current_epoch.0 - infraction_epoch.0
                        <= state.params.unbonding_len;

                // Only misbehave when there is more than 3 validators that's
                // not jailed, so there's always at least one honest left
                let enough_honest_validators = || {
                    let num_of_honest = state
                        .validator_states
                        .get(&state.pipeline())
                        .unwrap()
                        .iter()
                        .filter(|(_addr, val_state)| match val_state {
                            ValidatorState::Consensus
                            | ValidatorState::BelowCapacity => true,
                            ValidatorState::Inactive
                            | ValidatorState::Jailed
                            // Below threshold cannot be in consensus
                            | ValidatorState::BelowThreshold => false,
                        })
                        .count();

                    // Find the number of enqueued slashes to unique validators
                    let num_of_enquequed_slashes = state
                        .enqueued_slashes
                        .iter()
                        // find all validators with any enqueued slashes
                        .fold(BTreeSet::new(), |mut acc, (&epoch, slashes)| {
                            if epoch > current_epoch {
                                acc.extend(slashes.keys().cloned());
                            }
                            acc
                        })
                        .len();

                    num_of_honest - num_of_enquequed_slashes > 3
                };

                // Ensure that the validator is in consensus when it misbehaves
                // TODO: possibly also test allowing below-capacity validators
                // tracing::debug!("\nVal to possibly misbehave: {}", &address);
                let state_at_infraction = state
                    .validator_states
                    .get(infraction_epoch)
                    .unwrap()
                    .get(address);
                if state_at_infraction.is_none() {
                    // Figure out why this happening
                    tracing::debug!(
                        "State is None at Infraction epoch {}",
                        infraction_epoch
                    );
                    for epoch in Epoch::iter_bounds_inclusive(
                        infraction_epoch.next(),
                        state.epoch,
                    ) {
                        let state_ep = state
                            .validator_states
                            .get(infraction_epoch)
                            .unwrap()
                            .get(address)
                            .cloned();
                        tracing::debug!(
                            "State at epoch {} is {:?}",
                            epoch,
                            state_ep
                        );
                    }
                }

                let can_misbehave = state_at_infraction.cloned()
                    == Some(ValidatorState::Consensus);

                is_validator
                    && valid_epoch
                    && enough_honest_validators()
                    && can_misbehave

                // TODO: any others conditions?
            }
            Transition::UnjailValidator { address } => {
                // Validator address must be jailed thru the pipeline epoch
                for epoch in
                    Epoch::iter_bounds_inclusive(state.epoch, state.pipeline())
                {
                    if state
                        .validator_states
                        .get(&epoch)
                        .unwrap()
                        .get(address)
                        .cloned()
                        .unwrap()
                        != ValidatorState::Jailed
                    {
                        return false;
                    }
                }
                // Most recent misbehavior is >= unbonding_len epochs away from
                // current epoch
                if let Some(last_slash_epoch) =
                    state.validator_last_slash_epochs.get(address)
                {
                    if state.epoch.0 - last_slash_epoch.0
                        < state.params.unbonding_len
                    {
                        return false;
                    }
                }

                true
                // TODO: any others?
            }
        }
    }
}

/// Arbitrary bond transition that adds tokens to an existing bond
fn add_arb_bond_amount(
    state: AbstractPosState,
) -> impl Strategy<Value = Transition> {
    let bond_ids = state.existing_bond_ids();
    let arb_bond_id = prop::sample::select(bond_ids);
    (arb_bond_id, arb_bond_amount())
        .prop_map(|(id, amount)| Transition::Bond { id, amount })
}

/// Arbitrary delegation to one of the validators
fn arb_delegation(
    state: AbstractPosState,
) -> impl Strategy<Value = Transition> {
    // Bond is allowed to any validator in any set - including jailed validators
    let validators = state
        .validator_states
        .get(&state.pipeline())
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let validator_vec = validators.clone().into_iter().collect::<Vec<_>>();
    let arb_source = address::testing::arb_non_internal_address()
        .prop_filter("Must be a non-validator address", move |addr| {
            !validators.contains(addr)
        });
    let arb_validator = prop::sample::select(validator_vec);
    (arb_source, arb_validator, arb_bond_amount()).prop_map(
        |(source, validator, amount)| Transition::Bond {
            id: BondId { source, validator },
            amount,
        },
    )
}

/// Arbitrary validator self-bond
fn arb_self_bond(state: AbstractPosState) -> impl Strategy<Value = Transition> {
    // Bond is allowed to any validator in any set - including jailed validators
    let validator_vec = state
        .validator_states
        .get(&state.pipeline())
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let arb_validator = prop::sample::select(validator_vec);
    (arb_validator, arb_bond_amount()).prop_map(|(validator, amount)| {
        Transition::Bond {
            id: BondId {
                source: validator.clone(),
                validator,
            },
            amount,
        }
    })
}

// Bond up to 10 tokens (in micro units) to avoid overflows
pub fn arb_bond_amount() -> impl Strategy<Value = token::Amount> {
    (1_u64..10).prop_map(|val| token::Amount::from_uint(val, 0).unwrap())
}

/// Arbitrary validator misbehavior
fn arb_slash(state: AbstractPosState) -> impl Strategy<Value = Transition> {
    let validators = state.consensus_set.iter().fold(
        Vec::new(),
        |mut acc, (_epoch, vals)| {
            for vals in vals.values() {
                for validator in vals {
                    acc.push(validator.clone());
                }
            }
            acc
        },
    );
    let current_epoch = state.epoch.0;

    let arb_validator = prop::sample::select(validators);
    let slash_types =
        vec![SlashType::LightClientAttack, SlashType::DuplicateVote];
    let arb_type = prop::sample::select(slash_types);
    let arb_epoch = (current_epoch
        .checked_sub(state.params.unbonding_len)
        .unwrap_or_default()..=current_epoch)
        .prop_map(Epoch::from);
    let arb_height = 0_u64..10_000_u64;

    (arb_validator, arb_type, arb_epoch, arb_height).prop_map(
        |(validator, slash_type, infraction_epoch, height)| {
            Transition::Misbehavior {
                address: validator,
                slash_type,
                infraction_epoch,
                height,
            }
        },
    )
}
