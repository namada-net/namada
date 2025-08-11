//! PoS system tests

#![allow(clippy::arithmetic_side_effects, clippy::cast_sign_loss)]

use std::collections::BTreeMap;

use assert_matches::assert_matches;
use namada_core::address::Address;
use namada_core::chain::{BlockHeight, Epoch};
use namada_core::collections::HashSet;
use namada_core::dec::Dec;
use namada_core::key::RefTo;
use namada_core::key::testing::{common_sk_from_simple_seed, gen_keypair};
use namada_core::{address, key};
use namada_state::testing::TestFullAccessState;
use namada_trans_token::{
    self as token, credit_tokens, get_effective_total_native_supply,
    read_balance,
};
use proptest::prelude::*;
use proptest::test_runner::Config;
// Use `RUST_LOG=info` (or another tracing level) and `--nocapture` to see
// `tracing` logs from tests
use test_log::test;

use crate::epoched::EpochOffset;
use crate::lazy_map::Collectable;
use crate::parameters::OwnedPosParams;
use crate::parameters::testing::arb_pos_params;
use crate::queries::find_delegation_validators;
use crate::rewards::{
    PosRewardsCalculator, log_block_rewards_aux,
    update_rewards_products_and_mint_inflation,
};
use crate::storage::{
    delegation_targets_handle, get_consensus_key_set,
    liveness_sum_missed_votes_handle,
    read_consensus_validator_set_addresses_with_stake, read_total_stake,
    read_validator_deltas_value, rewards_accumulator_handle,
    total_deltas_handle,
};
use crate::tests::helpers::{
    advance_epoch, arb_genesis_validators, arb_params_and_genesis_validators,
    get_genesis_validators,
};
use crate::tests::{
    GovStore, bond_amount, bond_tokens, bonds_and_unbonds,
    change_consensus_key, find_delegations, process_slashes,
    read_below_threshold_validator_set_addresses, redelegate_tokens, slash,
    test_init_genesis, unbond_tokens, unjail_validator, withdraw_tokens,
};
use crate::types::{
    BondDetails, BondId, BondsAndUnbondsDetails, GenesisValidator, SlashType,
    UnbondDetails, ValidatorState, VoteInfo, WeightedValidator,
    into_tm_voting_power,
};
use crate::{
    StorageRead, below_capacity_validator_set_handle, bond_handle,
    consensus_validator_set_handle, is_delegator, is_validator,
    jail_for_liveness, read_validator_stake, staking_token_address,
    unbond_handle, validator_consensus_key_handle,
    validator_set_positions_handle, validator_state_handle,
};

proptest! {
    // Generate arb valid input for `test_test_init_genesis_aux`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_test_init_genesis(

    (pos_params, genesis_validators) in arb_params_and_genesis_validators(Some(5), 1..10),
    start_epoch in (0_u64..1000).prop_map(Epoch),

    ) {
        test_test_init_genesis_aux(pos_params, start_epoch, genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_bonds_aux`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_bonds(

    (pos_params, genesis_validators) in arb_params_and_genesis_validators(Some(5), 1..3),

    ) {
        test_bonds_aux(pos_params, genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_unjail_validator_aux`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_unjail_validator(
        (pos_params, genesis_validators)
            in arb_params_and_genesis_validators(Some(4),6..9)
    ) {
        test_unjail_validator_aux(pos_params,
            genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_unslashed_bond_amount_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_unslashed_bond_amount(

    genesis_validators in arb_genesis_validators(4..5, None),

    ) {
        test_unslashed_bond_amount_aux(genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_log_block_rewards_aux_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_log_block_rewards_aux(
        genesis_validators in arb_genesis_validators(4..10, None),
        params in arb_pos_params(Some(5))

    ) {
        test_log_block_rewards_aux_aux(genesis_validators, params)
    }
}

proptest! {
    // Generate arb valid input for `test_update_rewards_products_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_update_rewards_products(
        genesis_validators in arb_genesis_validators(4..10, None),

    ) {
        test_update_rewards_products_aux(genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_consensus_key_change`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_consensus_key_change(

    genesis_validators in arb_genesis_validators(1..2, None),

    ) {
        test_consensus_key_change_aux(genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_is_delegator`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_is_delegator(

    genesis_validators in arb_genesis_validators(2..3, None),

    ) {
        test_is_delegator_aux(genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_jail_for_liveness_aux`
    #![proptest_config(Config {
        .. Config::default()
    })]
    #[test]
    fn test_jail_for_liveness(
        genesis_validators in arb_genesis_validators(4..12, None),
    ) {
        test_jail_for_liveness_aux(genesis_validators)
    }
}

/// Test genesis initialization
fn test_test_init_genesis_aux(
    params: OwnedPosParams,
    start_epoch: Epoch,
    mut validators: Vec<GenesisValidator>,
) {
    // println!(
    //     "Test inputs: {params:?}, {start_epoch}, genesis validators: \
    //      {validators:#?}"
    // );
    let mut state = TestFullAccessState::default();
    state.in_mem_mut().block.epoch = start_epoch;
    let mut s = state.restrict_writes_to_write_log();

    validators.sort_by(|a, b| b.tokens.cmp(&a.tokens));
    let params = test_init_genesis(
        &mut s,
        params,
        validators.clone().into_iter(),
        start_epoch,
    )
    .unwrap();

    let mut bond_details = bonds_and_unbonds(&s, None, None).unwrap();
    assert!(bond_details.iter().all(|(_id, details)| {
        details.unbonds.is_empty() && details.slashes.is_empty()
    }));

    for (i, validator) in validators.into_iter().enumerate() {
        let addr = &validator.address;
        let self_bonds = bond_details
            .swap_remove(&BondId {
                source: addr.clone(),
                validator: addr.clone(),
            })
            .unwrap();
        assert_eq!(self_bonds.bonds.len(), 1);
        assert_eq!(
            self_bonds.bonds[0],
            BondDetails {
                start: start_epoch,
                amount: validator.tokens,
                slashed_amount: None,
            }
        );

        let state = validator_state_handle(&validator.address)
            .get(&s, start_epoch, &params)
            .unwrap();
        if (i as u64) < params.max_validator_slots
            && validator.tokens >= params.validator_stake_threshold
        {
            // should be in consensus set
            let handle = consensus_validator_set_handle().at(&start_epoch);
            assert!(handle.at(&validator.tokens).iter(&s).unwrap().any(
                |result| {
                    let (_pos, addr) = result.unwrap();
                    addr == validator.address
                }
            ));
            assert_eq!(state, Some(ValidatorState::Consensus));
        } else if validator.tokens >= params.validator_stake_threshold {
            // Should be in below-capacity set if its tokens are greater than
            // `validator_stake_threshold`
            let handle = below_capacity_validator_set_handle().at(&start_epoch);
            assert!(handle.at(&validator.tokens.into()).iter(&s).unwrap().any(
                |result| {
                    let (_pos, addr) = result.unwrap();
                    addr == validator.address
                }
            ));
            assert_eq!(state, Some(ValidatorState::BelowCapacity));
        } else {
            // Should be in below-threshold
            let bt_addresses =
                read_below_threshold_validator_set_addresses(&s, start_epoch)
                    .unwrap();
            assert!(
                bt_addresses
                    .into_iter()
                    .any(|addr| { addr == validator.address })
            );
            assert_eq!(state, Some(ValidatorState::BelowThreshold));
        }
    }
}

/// Test bonding
/// NOTE: copy validator sets each time we advance the epoch
fn test_bonds_aux(params: OwnedPosParams, validators: Vec<GenesisValidator>) {
    // This can be useful for debugging:
    // params.pipeline_len = 2;
    // params.unbonding_len = 4;
    // println!("\nTest inputs: {params:?}, genesis validators:
    // {validators:#?}");
    let mut state = TestFullAccessState::default();
    let mut s = state.restrict_writes_to_write_log();

    // Genesis
    let start_epoch = s.in_mem().block.epoch;
    let mut current_epoch = s.in_mem().block.epoch;
    let params = test_init_genesis(
        &mut s,
        params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    state.commit_block().unwrap();
    let mut s = state.restrict_writes_to_write_log();

    // Advance to epoch 1
    current_epoch = advance_epoch(&mut s, &params);
    let self_bond_epoch = current_epoch;

    let validator = validators.first().unwrap();

    // Read some data before submitting bond
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let staking_token = staking_token_address(&s);
    let pos_balance_pre = s
        .read::<token::Amount>(&token::storage_key::balance_key(
            &staking_token,
            &crate::ADDRESS,
        ))
        .unwrap()
        .unwrap_or_default();
    let total_stake_before =
        read_total_stake(&s, &params, pipeline_epoch).unwrap();

    // Self-bond
    let amount_self_bond = token::Amount::from_uint(100_500_000, 0).unwrap();
    credit_tokens(&mut s, &staking_token, &validator.address, amount_self_bond)
        .unwrap();
    bond_tokens(
        &mut s,
        None,
        &validator.address,
        amount_self_bond,
        current_epoch,
        None,
    )
    .unwrap();

    // Check the bond delta
    let self_bond = bond_handle(&validator.address, &validator.address);
    let delta = self_bond.get_delta_val(&s, pipeline_epoch).unwrap();
    assert_eq!(delta, Some(amount_self_bond));

    // Check the validator in the validator set
    let set =
        read_consensus_validator_set_addresses_with_stake(&s, pipeline_epoch)
            .unwrap();
    assert!(set.into_iter().any(
        |WeightedValidator {
             bonded_stake,
             address,
         }| {
            address == validator.address
                && bonded_stake == validator.tokens + amount_self_bond
        }
    ));

    let val_deltas =
        read_validator_deltas_value(&s, &validator.address, &pipeline_epoch)
            .unwrap();
    assert_eq!(val_deltas, Some(amount_self_bond.change()));

    let total_deltas_handle = total_deltas_handle();
    assert_eq!(
        current_epoch,
        total_deltas_handle.get_last_update(&s).unwrap().unwrap()
    );
    let total_stake_after =
        read_total_stake(&s, &params, pipeline_epoch).unwrap();
    assert_eq!(total_stake_before + amount_self_bond, total_stake_after);

    // Check bond details after self-bond
    let self_bond_id = BondId {
        source: validator.address.clone(),
        validator: validator.address.clone(),
    };
    let check_bond_details = |ix, bond_details: BondsAndUnbondsDetails| {
        println!("Check index {ix}");
        let details = bond_details.get(&self_bond_id).unwrap();
        assert_eq!(
            details.bonds.len(),
            2,
            "Contains genesis and newly added self-bond"
        );
        // dbg!(&details.bonds);
        assert_eq!(
            details.bonds[0],
            BondDetails {
                start: start_epoch,
                amount: validator.tokens,
                slashed_amount: None
            },
        );
        assert_eq!(
            details.bonds[1],
            BondDetails {
                start: pipeline_epoch,
                amount: amount_self_bond,
                slashed_amount: None
            },
        );
    };
    // Try to call it with different combinations of owner/validator args
    check_bond_details(0, bonds_and_unbonds(&s, None, None).unwrap());
    check_bond_details(
        1,
        bonds_and_unbonds(&s, Some(validator.address.clone()), None).unwrap(),
    );
    check_bond_details(
        2,
        bonds_and_unbonds(&s, None, Some(validator.address.clone())).unwrap(),
    );
    check_bond_details(
        3,
        bonds_and_unbonds(
            &s,
            Some(validator.address.clone()),
            Some(validator.address.clone()),
        )
        .unwrap(),
    );

    // Get a non-validating account with tokens
    let delegator = address::testing::gen_implicit_address();
    let amount_del = token::Amount::from_uint(201_000_000, 0).unwrap();
    credit_tokens(&mut s, &staking_token, &delegator, amount_del).unwrap();
    let balance_key =
        token::storage_key::balance_key(&staking_token, &delegator);
    let balance = s
        .read::<token::Amount>(&balance_key)
        .unwrap()
        .unwrap_or_default();
    assert_eq!(balance, amount_del);

    // Advance to epoch 3
    advance_epoch(&mut s, &params);
    current_epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = current_epoch + params.pipeline_len;

    // Delegation
    let delegation_epoch = current_epoch;
    bond_tokens(
        &mut s,
        Some(&delegator),
        &validator.address,
        amount_del,
        current_epoch,
        None,
    )
    .unwrap();
    let val_stake_pre = read_validator_stake(
        &s,
        &params,
        &validator.address,
        pipeline_epoch.prev().unwrap(),
    )
    .unwrap();
    let val_stake_post =
        read_validator_stake(&s, &params, &validator.address, pipeline_epoch)
            .unwrap();
    assert_eq!(validator.tokens + amount_self_bond, val_stake_pre);
    assert_eq!(
        validator.tokens + amount_self_bond + amount_del,
        val_stake_post
    );
    let delegation = bond_handle(&delegator, &validator.address);
    assert_eq!(
        delegation
            .get_sum(&s, pipeline_epoch.prev().unwrap(), &params)
            .unwrap()
            .unwrap_or_default(),
        token::Amount::zero()
    );
    assert_eq!(
        delegation
            .get_sum(&s, pipeline_epoch, &params)
            .unwrap()
            .unwrap_or_default(),
        amount_del
    );

    // Check delegation bonds details after delegation
    let delegation_bond_id = BondId {
        source: delegator.clone(),
        validator: validator.address.clone(),
    };
    let check_bond_details = |ix, bond_details: BondsAndUnbondsDetails| {
        println!("Check index {ix}");
        assert_eq!(bond_details.len(), 1);
        let details = bond_details.get(&delegation_bond_id).unwrap();
        assert_eq!(details.bonds.len(), 1,);
        // dbg!(&details.bonds);
        assert_eq!(
            details.bonds[0],
            BondDetails {
                start: pipeline_epoch,
                amount: amount_del,
                slashed_amount: None
            },
        );
    };
    // Try to call it with different combinations of owner/validator args
    check_bond_details(
        0,
        bonds_and_unbonds(&s, Some(delegator.clone()), None).unwrap(),
    );
    check_bond_details(
        1,
        bonds_and_unbonds(
            &s,
            Some(delegator.clone()),
            Some(validator.address.clone()),
        )
        .unwrap(),
    );

    // Check all bond details (self-bonds and delegation)
    let check_bond_details = |ix, bond_details: BondsAndUnbondsDetails| {
        println!("Check index {ix}");
        let self_bond_details = bond_details.get(&self_bond_id).unwrap();
        let delegation_details = bond_details.get(&delegation_bond_id).unwrap();
        assert_eq!(
            self_bond_details.bonds.len(),
            2,
            "Contains genesis and newly added self-bond"
        );
        assert_eq!(
            self_bond_details.bonds[0],
            BondDetails {
                start: start_epoch,
                amount: validator.tokens,
                slashed_amount: None
            },
        );
        assert_eq!(self_bond_details.bonds[1].amount, amount_self_bond);
        assert_eq!(
            delegation_details.bonds[0],
            BondDetails {
                start: pipeline_epoch,
                amount: amount_del,
                slashed_amount: None
            },
        );
    };
    // Try to call it with different combinations of owner/validator args
    check_bond_details(0, bonds_and_unbonds(&s, None, None).unwrap());
    check_bond_details(
        1,
        bonds_and_unbonds(&s, None, Some(validator.address.clone())).unwrap(),
    );

    // Advance to epoch 5
    for _ in 0..2 {
        current_epoch = advance_epoch(&mut s, &params);
    }
    let pipeline_epoch = current_epoch + params.pipeline_len;

    // Unbond the self-bond with an amount that will remove all of the self-bond
    // executed after genesis and some of the genesis bond
    let amount_self_unbond: token::Amount =
        amount_self_bond + (validator.tokens / 2);
    // When the difference is 0, only the non-genesis self-bond is unbonded
    let unbonded_genesis_self_bond =
        amount_self_unbond - amount_self_bond != token::Amount::zero();

    let self_unbond_epoch = s.in_mem().block.epoch;

    unbond_tokens(
        &mut s,
        None,
        &validator.address,
        amount_self_unbond,
        current_epoch,
        false,
    )
    .unwrap();

    let val_stake_pre = read_validator_stake(
        &s,
        &params,
        &validator.address,
        pipeline_epoch.prev().unwrap(),
    )
    .unwrap();

    let val_stake_post =
        read_validator_stake(&s, &params, &validator.address, pipeline_epoch)
            .unwrap();

    let val_delta =
        read_validator_deltas_value(&s, &validator.address, &pipeline_epoch)
            .unwrap();
    let unbond = unbond_handle(&validator.address, &validator.address);

    assert_eq!(val_delta, Some(-amount_self_unbond.change()));
    assert_eq!(
        unbond
            .at(&Epoch::default())
            .get(
                &s,
                &(pipeline_epoch
                    + params.unbonding_len
                    + params.cubic_slashing_window_length)
            )
            .unwrap(),
        if unbonded_genesis_self_bond {
            Some(amount_self_unbond - amount_self_bond)
        } else {
            None
        }
    );
    assert_eq!(
        unbond
            .at(&(self_bond_epoch + params.pipeline_len))
            .get(
                &s,
                &(pipeline_epoch
                    + params.unbonding_len
                    + params.cubic_slashing_window_length)
            )
            .unwrap(),
        Some(amount_self_bond)
    );
    assert_eq!(
        val_stake_pre,
        validator.tokens + amount_self_bond + amount_del
    );
    assert_eq!(
        val_stake_post,
        validator.tokens + amount_self_bond + amount_del - amount_self_unbond
    );

    // Check all bond and unbond details (self-bonds and delegation)
    let check_bond_details = |ix, bond_details: BondsAndUnbondsDetails| {
        println!("Check index {ix}");
        // dbg!(&bond_details);
        assert_eq!(bond_details.len(), 2);
        let self_bond_details = bond_details.get(&self_bond_id).unwrap();
        let delegation_details = bond_details.get(&delegation_bond_id).unwrap();
        assert_eq!(
            self_bond_details.bonds.len(),
            1,
            "Contains only part of the genesis bond now"
        );
        assert_eq!(
            self_bond_details.bonds[0],
            BondDetails {
                start: start_epoch,
                amount: validator.tokens + amount_self_bond
                    - amount_self_unbond,
                slashed_amount: None
            },
        );
        assert_eq!(
            delegation_details.bonds[0],
            BondDetails {
                start: delegation_epoch + params.pipeline_len,
                amount: amount_del,
                slashed_amount: None
            },
        );
        assert_eq!(
            self_bond_details.unbonds.len(),
            if unbonded_genesis_self_bond { 2 } else { 1 },
            "Contains a full unbond of the last self-bond and an unbond from \
             the genesis bond"
        );
        if unbonded_genesis_self_bond {
            assert_eq!(
                self_bond_details.unbonds[0],
                UnbondDetails {
                    start: start_epoch,
                    withdraw: self_unbond_epoch
                        + params.pipeline_len
                        + params.unbonding_len
                        + params.cubic_slashing_window_length,
                    amount: amount_self_unbond - amount_self_bond,
                    slashed_amount: None
                }
            );
        }
        assert_eq!(
            self_bond_details.unbonds[usize::from(unbonded_genesis_self_bond)],
            UnbondDetails {
                start: self_bond_epoch + params.pipeline_len,
                withdraw: self_unbond_epoch
                    + params.pipeline_len
                    + params.unbonding_len
                    + params.cubic_slashing_window_length,
                amount: amount_self_bond,
                slashed_amount: None
            }
        );
    };
    check_bond_details(
        0,
        bonds_and_unbonds(&s, None, Some(validator.address.clone())).unwrap(),
    );

    // Unbond delegation
    let amount_undel = token::Amount::from_uint(1_000_000, 0).unwrap();
    unbond_tokens(
        &mut s,
        Some(&delegator),
        &validator.address,
        amount_undel,
        current_epoch,
        false,
    )
    .unwrap();

    let val_stake_pre = read_validator_stake(
        &s,
        &params,
        &validator.address,
        pipeline_epoch.prev().unwrap(),
    )
    .unwrap();
    let val_stake_post =
        read_validator_stake(&s, &params, &validator.address, pipeline_epoch)
            .unwrap();
    let val_delta =
        read_validator_deltas_value(&s, &validator.address, &pipeline_epoch)
            .unwrap();
    let unbond = unbond_handle(&delegator, &validator.address);

    assert_eq!(
        val_delta,
        Some(-(amount_self_unbond + amount_undel).change())
    );
    assert_eq!(
        unbond
            .at(&(delegation_epoch + params.pipeline_len))
            .get(
                &s,
                &(pipeline_epoch
                    + params.unbonding_len
                    + params.cubic_slashing_window_length)
            )
            .unwrap(),
        Some(amount_undel)
    );
    assert_eq!(
        val_stake_pre,
        validator.tokens + amount_self_bond + amount_del
    );
    assert_eq!(
        val_stake_post,
        validator.tokens + amount_self_bond - amount_self_unbond + amount_del
            - amount_undel
    );

    let withdrawable_offset = params.unbonding_len
        + params.pipeline_len
        + params.cubic_slashing_window_length;

    // Advance to withdrawable epoch
    for _ in 0..withdrawable_offset {
        current_epoch = advance_epoch(&mut s, &params);
    }

    let pos_balance = s
        .read::<token::Amount>(&token::storage_key::balance_key(
            &staking_token,
            &crate::ADDRESS,
        ))
        .unwrap();

    assert_eq!(
        Some(pos_balance_pre + amount_self_bond + amount_del),
        pos_balance
    );

    // Withdraw the self-unbond
    withdraw_tokens(&mut s, None, &validator.address, current_epoch).unwrap();
    let unbond = unbond_handle(&validator.address, &validator.address);
    let unbond_iter = unbond.iter(&s).unwrap().next();
    assert!(unbond_iter.is_none());

    let pos_balance = s
        .read::<token::Amount>(&token::storage_key::balance_key(
            &staking_token,
            &crate::ADDRESS,
        ))
        .unwrap();
    assert_eq!(
        Some(
            pos_balance_pre + amount_self_bond - amount_self_unbond
                + amount_del
        ),
        pos_balance
    );

    // Withdraw the delegation unbond
    withdraw_tokens(
        &mut s,
        Some(&delegator),
        &validator.address,
        current_epoch,
    )
    .unwrap();
    let unbond = unbond_handle(&delegator, &validator.address);
    let unbond_iter = unbond.iter(&s).unwrap().next();
    assert!(unbond_iter.is_none());

    let pos_balance = s
        .read::<token::Amount>(&token::storage_key::balance_key(
            &staking_token,
            &crate::ADDRESS,
        ))
        .unwrap();
    assert_eq!(
        Some(
            pos_balance_pre + amount_self_bond - amount_self_unbond
                + amount_del
                - amount_undel
        ),
        pos_balance
    );
}

fn test_unjail_validator_aux(
    params: OwnedPosParams,
    mut validators: Vec<GenesisValidator>,
) {
    // println!("\nTest inputs: {params:?}, genesis validators:
    // {validators:#?}");
    let mut state = TestFullAccessState::default();
    let mut s = state.restrict_writes_to_write_log();

    // Find the validator with the most stake and 100x his stake to keep the
    // cubic slash rate small
    let num_vals = validators.len();
    validators.sort_by_key(|a| a.tokens);
    validators[num_vals - 1].tokens = validators[num_vals - 1].tokens * 100;

    // Get second highest stake validator to misbehave
    let val_addr = &validators[num_vals - 2].address;
    // let val_tokens = validators[num_vals - 2].tokens;

    // Genesis
    let mut current_epoch = s.in_mem().block.epoch;
    let params = test_init_genesis(
        &mut s,
        params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    state.commit_block().unwrap();
    let mut s = state.restrict_writes_to_write_log();

    current_epoch = advance_epoch(&mut s, &params);
    process_slashes(
        &mut s,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    // Discover first slash
    let slash_0_evidence_epoch = current_epoch;
    let evidence_block_height = BlockHeight(0); // doesn't matter for slashing logic
    let slash_0_type = SlashType::DuplicateVote;
    slash(
        &mut s,
        &params,
        current_epoch,
        slash_0_evidence_epoch,
        evidence_block_height,
        slash_0_type,
        val_addr,
        current_epoch.next(),
    )
    .unwrap();

    let val_stake =
        crate::read_validator_stake(&s, &params, val_addr, current_epoch)
            .unwrap();
    let state = validator_state_handle(val_addr)
        .get(&s, current_epoch, &params)
        .unwrap()
        .unwrap();
    if val_stake >= params.validator_stake_threshold {
        assert_matches!(
            state,
            ValidatorState::Consensus | ValidatorState::BelowCapacity
        );
    } else {
        assert_eq!(state, ValidatorState::BelowThreshold);
    };

    for epoch in Epoch::iter_bounds_inclusive(
        current_epoch.next(),
        current_epoch + params.pipeline_len,
    ) {
        // Check the validator state
        assert_eq!(
            validator_state_handle(val_addr)
                .get(&s, epoch, &params)
                .unwrap(),
            Some(ValidatorState::Jailed)
        );
        // Check the validator set positions
        assert!(
            validator_set_positions_handle()
                .at(&epoch)
                .get(&s, val_addr)
                .unwrap()
                .is_none(),
        );
    }

    // Advance past an epoch in which we can unbond
    let unfreeze_epoch =
        slash_0_evidence_epoch + params.slash_processing_epoch_offset();
    while current_epoch < unfreeze_epoch + 4u64 {
        current_epoch = advance_epoch(&mut s, &params);
        process_slashes(
            &mut s,
            &mut namada_events::testing::VoidEventSink,
            current_epoch,
        )
        .unwrap();
    }

    // Unjail the validator
    unjail_validator(&mut s, val_addr, current_epoch).unwrap();

    // Check the validator state
    for epoch in
        Epoch::iter_bounds_inclusive(current_epoch, current_epoch.next())
    {
        assert_eq!(
            validator_state_handle(val_addr)
                .get(&s, epoch, &params)
                .unwrap(),
            Some(ValidatorState::Jailed)
        );
    }
    let val_stake = crate::read_validator_stake(
        &s,
        &params,
        val_addr,
        current_epoch + params.pipeline_len,
    )
    .unwrap();
    let state = validator_state_handle(val_addr)
        .get(&s, current_epoch + params.pipeline_len, &params)
        .unwrap()
        .unwrap();
    if val_stake >= params.validator_stake_threshold {
        assert_matches!(
            state,
            ValidatorState::Consensus | ValidatorState::BelowCapacity
        );
        assert!(
            validator_set_positions_handle()
                .at(&(current_epoch + params.pipeline_len))
                .get(&s, val_addr)
                .unwrap()
                .is_some(),
        );
    } else {
        assert_eq!(state, ValidatorState::BelowThreshold);
    };

    // Advance another epoch
    current_epoch = advance_epoch(&mut s, &params);
    process_slashes(
        &mut s,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    let second_att = unjail_validator(&mut s, val_addr, current_epoch);
    assert!(second_att.is_err());
}

fn test_unslashed_bond_amount_aux(validators: Vec<GenesisValidator>) {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    // Genesis
    let mut current_epoch = storage.in_mem().block.epoch;
    let params = test_init_genesis(
        &mut storage,
        params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    state.commit_block().unwrap();
    let mut storage = state.restrict_writes_to_write_log();

    let validator1 = validators[0].address.clone();
    let validator2 = validators[1].address.clone();

    // Get a delegator with some tokens
    let staking_token = staking_token_address(&storage);
    let delegator = address::testing::gen_implicit_address();
    let del_balance = token::Amount::from_uint(1_000_000, 0).unwrap();
    credit_tokens(&mut storage, &staking_token, &delegator, del_balance)
        .unwrap();

    // Bond to validator 1
    bond_tokens(
        &mut storage,
        Some(&delegator),
        &validator1,
        10_000.into(),
        current_epoch,
        None,
    )
    .unwrap();

    // Unbond some from validator 1
    unbond_tokens(
        &mut storage,
        Some(&delegator),
        &validator1,
        1_342.into(),
        current_epoch,
        false,
    )
    .unwrap();

    // Redelegate some from validator 1 -> 2
    redelegate_tokens(
        &mut storage,
        &delegator,
        &validator1,
        &validator2,
        current_epoch,
        1_875.into(),
    )
    .unwrap();

    // Unbond some from validator 2
    unbond_tokens(
        &mut storage,
        Some(&delegator),
        &validator2,
        584.into(),
        current_epoch,
        false,
    )
    .unwrap();

    // Advance an epoch
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    // Bond to validator 1
    bond_tokens(
        &mut storage,
        Some(&delegator),
        &validator1,
        384.into(),
        current_epoch,
        None,
    )
    .unwrap();

    // Unbond some from validator 1
    unbond_tokens(
        &mut storage,
        Some(&delegator),
        &validator1,
        144.into(),
        current_epoch,
        false,
    )
    .unwrap();

    // Redelegate some from validator 1 -> 2
    redelegate_tokens(
        &mut storage,
        &delegator,
        &validator1,
        &validator2,
        current_epoch,
        3_448.into(),
    )
    .unwrap();

    // Unbond some from validator 2
    unbond_tokens(
        &mut storage,
        Some(&delegator),
        &validator2,
        699.into(),
        current_epoch,
        false,
    )
    .unwrap();

    // Advance an epoch
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    // Bond to validator 1
    bond_tokens(
        &mut storage,
        Some(&delegator),
        &validator1,
        4_384.into(),
        current_epoch,
        None,
    )
    .unwrap();

    // Redelegate some from validator 1 -> 2
    redelegate_tokens(
        &mut storage,
        &delegator,
        &validator1,
        &validator2,
        current_epoch,
        1_008.into(),
    )
    .unwrap();

    // Unbond some from validator 2
    unbond_tokens(
        &mut storage,
        Some(&delegator),
        &validator2,
        3_500.into(),
        current_epoch,
        false,
    )
    .unwrap();

    // Checks
    let val1_init_stake = validators[0].tokens;

    for epoch in Epoch::iter_bounds_inclusive(
        Epoch(0),
        current_epoch + params.pipeline_len,
    ) {
        #[allow(clippy::disallowed_methods)]
        let amount = bond_amount(
            &storage,
            &BondId {
                source: delegator.clone(),
                validator: validator1.clone(),
            },
            epoch,
        )
        .unwrap_or_default();

        let val_stake =
            crate::read_validator_stake(&storage, &params, &validator1, epoch)
                .unwrap();
        // dbg!(&amount);
        assert_eq!(val_stake - val1_init_stake, amount);
    }
}

fn test_log_block_rewards_aux_aux(
    validators: Vec<GenesisValidator>,
    params: OwnedPosParams,
) {
    tracing::info!(
        "New case with {} validators: {:#?}",
        validators.len(),
        validators
            .iter()
            .map(|v| (&v.address, v.tokens.to_string_native()))
            .collect::<Vec<_>>()
    );
    let mut state = TestFullAccessState::default();
    let mut s = state.restrict_writes_to_write_log();
    // Init genesis
    let current_epoch = s.in_mem().block.epoch;
    let params = test_init_genesis(
        &mut s,
        params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    state.commit_block().unwrap();
    let mut s = state.restrict_writes_to_write_log();

    let total_stake =
        crate::get_total_consensus_stake(&s, current_epoch, &params).unwrap();
    let consensus_set =
        crate::read_consensus_validator_set_addresses(&s, current_epoch)
            .unwrap();
    let proposer_address = consensus_set.iter().next().unwrap().clone();

    tracing::info!(
            ?params.block_proposer_reward,
            ?params.block_vote_reward,
    );
    tracing::info!(?proposer_address,);

    // Rewards accumulator should be empty at first
    let rewards_handle = rewards_accumulator_handle();
    assert!(rewards_handle.is_empty(&s).unwrap());

    let mut last_rewards = BTreeMap::default();

    let num_blocks = 100;
    // Loop through `num_blocks`, log rewards & check results
    for i in 0..num_blocks {
        tracing::info!("");
        tracing::info!("Block {}", i + 1);

        // A helper closure to prepare minimum required votes
        let prep_votes = |epoch| {
            // Ceil of 2/3 of total stake
            let min_required_votes =
                total_stake.mul_ceil(Dec::two() / 3).unwrap();

            let mut total_votes = token::Amount::zero();
            let mut non_voters = HashSet::<Address>::default();
            let mut prep_vote = |validator| {
                // Add validator vote if it's in consensus set and if we don't
                // yet have min required votes
                if consensus_set.contains(validator)
                    && total_votes < min_required_votes
                {
                    let stake =
                        read_validator_stake(&s, &params, validator, epoch)
                            .unwrap();
                    total_votes += stake;
                    let validator_vp =
                        into_tm_voting_power(params.tm_votes_per_token, stake)
                            as u64;
                    tracing::info!("Validator {validator} signed");
                    Some(VoteInfo {
                        validator_address: validator.clone(),
                        validator_vp,
                    })
                } else {
                    non_voters.insert(validator.clone());
                    None
                }
            };

            let votes: Vec<VoteInfo> = validators
                .iter()
                .rev()
                .filter_map(|validator| prep_vote(&validator.address))
                .collect();
            (votes, total_votes, non_voters)
        };

        let (votes, signing_stake, non_voters) = prep_votes(current_epoch);
        log_block_rewards_aux::<_, GovStore<_>>(
            &mut s,
            current_epoch,
            &proposer_address,
            votes.clone(),
        )
        .unwrap();

        assert!(!rewards_handle.is_empty(&s).unwrap());

        let rewards_calculator = PosRewardsCalculator {
            proposer_reward: params.block_proposer_reward,
            signer_reward: params.block_vote_reward,
            signing_stake,
            total_stake,
        };
        let coeffs = rewards_calculator.get_reward_coeffs().unwrap();
        tracing::info!(?coeffs);

        // Check proposer reward
        let stake =
            read_validator_stake(&s, &params, &proposer_address, current_epoch)
                .unwrap();
        let proposer_signing_reward = votes.iter().find_map(|vote| {
            if vote.validator_address == proposer_address {
                let signing_fraction = Dec::try_from(stake).unwrap()
                    / Dec::try_from(signing_stake).unwrap();
                Some(coeffs.signer_coeff * signing_fraction)
            } else {
                None
            }
        });
        let expected_proposer_rewards = last_rewards.get(&proposer_address).copied().unwrap_or_default() +
        // Proposer reward
        coeffs.proposer_coeff
        // Consensus validator reward
        + (coeffs.active_val_coeff
                    * (Dec::try_from(stake).unwrap() / Dec::try_from(total_stake).unwrap()))
        // Signing reward (if proposer voted)
        + proposer_signing_reward
            .unwrap_or_default();
        tracing::info!(
            "Expected proposer rewards: {expected_proposer_rewards}. Signed \
             block: {}",
            proposer_signing_reward.is_some()
        );
        assert_eq!(
            rewards_handle.get(&s, &proposer_address).unwrap(),
            Some(expected_proposer_rewards)
        );

        // Check voters rewards
        for VoteInfo {
            validator_address, ..
        } in votes.iter()
        {
            // Skip proposer, in case voted - already checked
            if validator_address == &proposer_address {
                continue;
            }

            let stake = read_validator_stake(
                &s,
                &params,
                validator_address,
                current_epoch,
            )
            .unwrap();
            let signing_fraction = Dec::try_from(stake).unwrap()
                / Dec::try_from(signing_stake).unwrap();
            let expected_signer_rewards = last_rewards
                .get(validator_address)
                .copied()
                .unwrap_or_default()
                + coeffs.signer_coeff * signing_fraction
                + (coeffs.active_val_coeff
                    * (Dec::try_from(stake).unwrap()
                        / Dec::try_from(total_stake).unwrap()));
            tracing::info!(
                "Expected signer {validator_address} rewards: \
                 {expected_signer_rewards}"
            );
            assert_eq!(
                rewards_handle.get(&s, validator_address).unwrap(),
                Some(expected_signer_rewards)
            );
        }

        // Check non-voters rewards, if any
        for address in non_voters {
            // Skip proposer, in case it didn't vote - already checked
            if address == proposer_address {
                continue;
            }

            if consensus_set.contains(&address) {
                let stake =
                    read_validator_stake(&s, &params, &address, current_epoch)
                        .unwrap();
                let expected_non_signer_rewards =
                    last_rewards.get(&address).copied().unwrap_or_default()
                        + coeffs.active_val_coeff
                            * (Dec::try_from(stake).unwrap()
                                / Dec::try_from(total_stake).unwrap());
                tracing::info!(
                    "Expected non-signer {address} rewards: \
                     {expected_non_signer_rewards}"
                );
                assert_eq!(
                    rewards_handle.get(&s, &address).unwrap(),
                    Some(expected_non_signer_rewards)
                );
            } else {
                let last_reward = last_rewards.get(&address).copied();
                assert_eq!(
                    rewards_handle.get(&s, &address).unwrap(),
                    last_reward
                );
            }
        }
        state.commit_block().unwrap();
        s = state.restrict_writes_to_write_log();

        last_rewards = rewards_accumulator_handle().collect_map(&s).unwrap();

        let rewards_sum: Dec = last_rewards.values().copied().sum();
        let expected_sum = Dec::one() * (i as u64 + 1);
        let err_tolerance = Dec::new(1, 9).unwrap();
        let fail_msg = format!(
            "Expected rewards sum at block {} to be {expected_sum}, got \
             {rewards_sum}. Error tolerance {err_tolerance}.",
            i + 1
        );
        assert!(expected_sum <= rewards_sum + err_tolerance, "{fail_msg}");
        assert!(rewards_sum <= expected_sum, "{fail_msg}");
    }
}

fn test_update_rewards_products_aux(validators: Vec<GenesisValidator>) {
    tracing::info!(
        "New case with {} validators: {:#?}",
        validators.len(),
        validators
            .iter()
            .map(|v| (&v.address, v.tokens.to_string_native()))
            .collect::<Vec<_>>()
    );
    let mut state = TestFullAccessState::default();
    let mut s = state.restrict_writes_to_write_log();
    // Init genesis
    let current_epoch = s.in_mem().block.epoch;
    let params = OwnedPosParams::default();
    let params = test_init_genesis(
        &mut s,
        params,
        validators.into_iter(),
        current_epoch,
    )
    .unwrap();
    state.commit_block().unwrap();
    let mut s = state.restrict_writes_to_write_log();

    let staking_token = staking_token_address(&s);
    let consensus_set =
        crate::read_consensus_validator_set_addresses(&s, current_epoch)
            .unwrap();

    // Start a new epoch
    let current_epoch = advance_epoch(&mut s, &params);

    // Read some data before applying rewards
    let pos_balance_pre =
        read_balance(&s, &staking_token, &address::POS).unwrap();
    let pgf_balance_pre =
        read_balance(&s, &staking_token, &address::PGF).unwrap();

    let num_consensus_validators = consensus_set.len() as u64;
    let accum_val = Dec::one() / num_consensus_validators;
    let num_blocks_in_last_epoch = 1000;

    // Assign some reward accumulator values to consensus validator
    for validator in &consensus_set {
        rewards_accumulator_handle()
            .insert(
                &mut s,
                validator.clone(),
                accum_val * num_blocks_in_last_epoch,
            )
            .unwrap();
    }

    let total_native_tokens = get_effective_total_native_supply(&s).unwrap();

    // Distribute inflation into rewards
    let last_epoch = current_epoch.prev().unwrap();
    let inflation = token::Amount::native_whole(10_000_000);
    update_rewards_products_and_mint_inflation::<_, token::Store<_>>(
        &mut s,
        &params,
        last_epoch,
        num_blocks_in_last_epoch,
        inflation,
        &staking_token,
        total_native_tokens,
    )
    .unwrap();

    let pos_balance_post =
        read_balance(&s, &staking_token, &address::POS).unwrap();
    let pgf_balance_post =
        read_balance(&s, &staking_token, &address::PGF).unwrap();

    assert_eq!(
        pos_balance_pre + pgf_balance_pre + inflation,
        pos_balance_post + pgf_balance_post,
        "Expected inflation to be minted to PoS and left-over amount to PGF"
    );

    let pos_credit = pos_balance_post - pos_balance_pre;
    let gov_credit = pgf_balance_post - pgf_balance_pre;
    assert!(
        pos_credit > gov_credit,
        "PoS must receive more tokens than Gov, but got {} in PoS and {} in \
         Gov",
        pos_credit.to_string_native(),
        gov_credit.to_string_native()
    );

    // Rewards accumulator must be cleared out
    let rewards_handle = rewards_accumulator_handle();
    assert!(rewards_handle.is_empty(&s).unwrap());
}

fn test_consensus_key_change_aux(validators: Vec<GenesisValidator>) {
    assert_eq!(validators.len(), 1);

    let params = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };
    let validator = validators[0].address.clone();

    // println!("\nTest inputs: {params:?}, genesis validators:
    // {validators:#?}");
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();

    // Genesis
    let mut current_epoch = storage.in_mem().block.epoch;
    let params = test_init_genesis(
        &mut storage,
        params,
        validators.into_iter(),
        current_epoch,
    )
    .unwrap();
    state.commit_block().unwrap();
    let mut storage = state.restrict_writes_to_write_log();

    // Check that there is one consensus key in the network
    let consensus_keys = get_consensus_key_set(&storage).unwrap();
    assert_eq!(consensus_keys.len(), 1);
    let ck = consensus_keys.first().cloned().unwrap();
    let og_ck = validator_consensus_key_handle(&validator)
        .get(&storage, current_epoch, &params)
        .unwrap()
        .unwrap();
    assert_eq!(ck, og_ck);

    // Attempt to change to a new secp256k1 consensus key (disallowed)
    let secp_ck = gen_keypair::<key::secp256k1::SigScheme>();
    let secp_ck = key::common::SecretKey::Secp256k1(secp_ck).ref_to();
    let res =
        change_consensus_key(&mut storage, &validator, &secp_ck, current_epoch);
    assert!(res.is_err());

    // Change consensus keys
    let ck_2 = common_sk_from_simple_seed(1).ref_to();
    change_consensus_key(&mut storage, &validator, &ck_2, current_epoch)
        .unwrap();

    // Check that there is a new consensus key
    let consensus_keys = get_consensus_key_set(&storage).unwrap();
    assert_eq!(consensus_keys.len(), 2);

    for epoch in current_epoch.iter_range(params.pipeline_len) {
        let ck = validator_consensus_key_handle(&validator)
            .get(&storage, epoch, &params)
            .unwrap()
            .unwrap();
        assert_eq!(ck, og_ck);
    }
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let ck = validator_consensus_key_handle(&validator)
        .get(&storage, pipeline_epoch, &params)
        .unwrap()
        .unwrap();
    assert_eq!(ck, ck_2);

    // Advance to the pipeline epoch
    loop {
        current_epoch = advance_epoch(&mut storage, &params);
        if current_epoch == pipeline_epoch {
            break;
        }
    }

    // Check the consensus keys again
    let consensus_keys = get_consensus_key_set(&storage).unwrap();
    assert_eq!(consensus_keys.len(), 2);

    for epoch in current_epoch.iter_range(params.pipeline_len + 1) {
        let ck = validator_consensus_key_handle(&validator)
            .get(&storage, epoch, &params)
            .unwrap()
            .unwrap();
        assert_eq!(ck, ck_2);
    }

    // Now change the consensus key again and bond in the same epoch
    let ck_3 = common_sk_from_simple_seed(3).ref_to();
    change_consensus_key(&mut storage, &validator, &ck_3, current_epoch)
        .unwrap();

    let staking_token = storage.in_mem().native_token.clone();
    let amount_del = token::Amount::native_whole(5);
    credit_tokens(&mut storage, &staking_token, &validator, amount_del)
        .unwrap();
    bond_tokens(
        &mut storage,
        None,
        &validator,
        token::Amount::native_whole(1),
        current_epoch,
        None,
    )
    .unwrap();

    // Check consensus keys again
    let consensus_keys = get_consensus_key_set(&storage).unwrap();
    assert_eq!(consensus_keys.len(), 3);

    for epoch in current_epoch.iter_range(params.pipeline_len) {
        let ck = validator_consensus_key_handle(&validator)
            .get(&storage, epoch, &params)
            .unwrap()
            .unwrap();
        assert_eq!(ck, ck_2);
    }
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let ck = validator_consensus_key_handle(&validator)
        .get(&storage, pipeline_epoch, &params)
        .unwrap()
        .unwrap();
    assert_eq!(ck, ck_3);

    // Advance to the pipeline epoch to ensure that the validator set updates to
    // tendermint will work
    loop {
        current_epoch = advance_epoch(&mut storage, &params);
        if current_epoch == pipeline_epoch {
            break;
        }
    }
    assert_eq!(current_epoch.0, 2 * params.pipeline_len);
}

fn test_is_delegator_aux(mut validators: Vec<GenesisValidator>) {
    validators.sort_by(|a, b| b.tokens.cmp(&a.tokens));

    let validator1 = validators[0].address.clone();
    let validator2 = validators[1].address.clone();

    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    // Genesis
    let mut current_epoch = storage.in_mem().block.epoch;
    let params = test_init_genesis(
        &mut storage,
        params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    storage.commit_block().unwrap();

    // Get delegators with some tokens
    let staking_token = staking_token_address(&storage);
    let delegator1 = address::testing::gen_implicit_address();
    let delegator2 = address::testing::gen_implicit_address();
    let del_balance = token::Amount::native_whole(1000);
    credit_tokens(&mut storage, &staking_token, &delegator1, del_balance)
        .unwrap();
    credit_tokens(&mut storage, &staking_token, &delegator2, del_balance)
        .unwrap();

    // Advance to epoch 1
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    // Delegate in epoch 1 to validator1
    let del1_epoch = current_epoch;
    bond_tokens(
        &mut storage,
        Some(&delegator1),
        &validator1,
        1000.into(),
        current_epoch,
        None,
    )
    .unwrap();

    // Advance to epoch 2
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    // Delegate in epoch 2 to validator2
    let del2_epoch = current_epoch;
    bond_tokens(
        &mut storage,
        Some(&delegator2),
        &validator2,
        1000.into(),
        current_epoch,
        None,
    )
    .unwrap();

    // Checks
    assert!(is_validator(&storage, &validator1).unwrap());
    assert!(is_validator(&storage, &validator2).unwrap());
    assert!(!is_delegator(&storage, &validator1, None).unwrap());
    assert!(!is_delegator(&storage, &validator2, None).unwrap());

    assert!(!is_validator(&storage, &delegator1).unwrap());
    assert!(!is_validator(&storage, &delegator2).unwrap());
    assert!(is_delegator(&storage, &delegator1, None).unwrap());
    assert!(is_delegator(&storage, &delegator2, None).unwrap());

    for epoch in Epoch::default().iter_range(del1_epoch.0 + params.pipeline_len)
    {
        assert!(!is_delegator(&storage, &delegator1, Some(epoch)).unwrap());
    }
    assert!(
        is_delegator(
            &storage,
            &delegator1,
            Some(del1_epoch + params.pipeline_len)
        )
        .unwrap()
    );
    for epoch in Epoch::default().iter_range(del2_epoch.0 + params.pipeline_len)
    {
        assert!(!is_delegator(&storage, &delegator2, Some(epoch)).unwrap());
    }
    assert!(
        is_delegator(
            &storage,
            &delegator2,
            Some(del2_epoch + params.pipeline_len)
        )
        .unwrap()
    );
}

/// A test that jailing for liveness has a deterministic result
fn test_jail_for_liveness_aux(validators: Vec<GenesisValidator>) {
    let params = OwnedPosParams {
        max_validator_slots: 2,
        liveness_window_check: 1,
        liveness_threshold: Dec::one(),
        ..Default::default()
    };
    // 1 missed vote with the above params should get validators jailed
    let missed_votes = 1_u64;

    // Open 2 states
    let mut state = TestFullAccessState::default();
    let mut state_clone = TestFullAccessState::default();

    // Apply the same changes to each storage
    for s in [&mut state, &mut state_clone] {
        let mut wl_state = s.restrict_writes_to_write_log();
        // Genesis
        let current_epoch = s.in_mem().block.epoch;
        let jail_epoch = current_epoch.next();
        let params = test_init_genesis(
            &mut wl_state,
            params.clone(),
            validators.clone().into_iter(),
            current_epoch,
        )
        .unwrap();
        s.commit_block().unwrap();
        let mut wl_state = s.restrict_writes_to_write_log();

        // Add missed votes to about half of the validators
        let half_len = validators.len() / 2;
        let validators_who_missed_votes: Vec<_> =
            validators.iter().take(half_len).collect();

        for GenesisValidator { address, .. } in &validators_who_missed_votes {
            liveness_sum_missed_votes_handle()
                .insert(&mut wl_state, address.clone(), missed_votes)
                .unwrap();
        }

        jail_for_liveness::<_, GovStore<_>>(
            &mut wl_state,
            &params,
            current_epoch,
            jail_epoch,
        )
        .unwrap();

        for GenesisValidator { address, .. } in &validators_who_missed_votes {
            let state_jail_epoch = validator_state_handle(address)
                .get(&mut wl_state, jail_epoch, &params)
                .unwrap()
                .expect("Validator should have a state for the jail epoch");
            assert_eq!(state_jail_epoch, ValidatorState::Jailed);
        }
    }

    // Assert that the changes from `jail_for_liveness` are the same
    pretty_assertions::assert_eq!(&state.write_log(), &state_clone.write_log());
}

#[test]
fn test_delegation_targets() {
    let stakes = vec![
        token::Amount::native_whole(1),
        token::Amount::native_whole(2),
    ];
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let mut current_epoch = storage.in_mem().block.epoch;
    let params = OwnedPosParams::default();

    let genesis_validators = get_genesis_validators(2, stakes.clone());
    let validator1 = genesis_validators[0].address.clone();
    let validator2 = genesis_validators[1].address.clone();

    let delegator = address::testing::gen_implicit_address();
    let staking_token = staking_token_address(&storage);
    credit_tokens(
        &mut storage,
        &staking_token,
        &delegator,
        token::Amount::native_whole(20),
    )
    .unwrap();
    credit_tokens(
        &mut storage,
        &staking_token,
        &validator2,
        token::Amount::native_whole(20),
    )
    .unwrap();

    let params = test_init_genesis(
        &mut storage,
        params,
        genesis_validators.into_iter(),
        current_epoch,
    )
    .unwrap();

    println!("\nValidator1: {:?}", validator1);
    println!("Validator2: {:?}", validator2);
    println!("Delegator: {:?}\n", delegator);

    // Check initial delegation targets
    for epoch in Epoch::iter_bounds_inclusive(
        current_epoch,
        current_epoch + params.pipeline_len,
    ) {
        let delegatees1 =
            find_delegation_validators(&storage, &validator1, &epoch).unwrap();
        let delegatees2 =
            find_delegation_validators(&storage, &validator2, &epoch).unwrap();
        assert_eq!(delegatees1.len(), 1);
        assert_eq!(delegatees2.len(), 1);
        assert!(delegatees1.contains(&validator1));
        assert!(delegatees2.contains(&validator2));
    }

    // Advance to epoch 1 and check if the delegation targets are properly
    // updated in the absence of bonds
    current_epoch = advance_epoch(&mut storage, &params);
    for epoch in Epoch::iter_bounds_inclusive(
        Epoch::default(),
        current_epoch + params.pipeline_len,
    ) {
        let delegatees1 =
            find_delegation_validators(&storage, &validator1, &epoch).unwrap();
        let delegatees2 =
            find_delegation_validators(&storage, &validator2, &epoch).unwrap();
        assert_eq!(delegatees1.len(), 1);
        assert_eq!(delegatees2.len(), 1);
        assert!(delegatees1.contains(&validator1));
        assert!(delegatees2.contains(&validator2));
    }

    // Bond from a delegator to validator1 in epoch 1
    bond_tokens(
        &mut storage,
        Some(&delegator),
        &validator1,
        token::Amount::native_whole(3),
        current_epoch,
        None,
    )
    .unwrap();

    // Completely self-unbond from validator2
    unbond_tokens(
        &mut storage,
        None,
        &validator2,
        stakes[1],
        current_epoch,
        false,
    )
    .unwrap();

    // Check the delegation targets now
    let pipeline_epoch = current_epoch + params.pipeline_len;
    for epoch in Epoch::iter_bounds_inclusive(
        Epoch::default(),
        pipeline_epoch.prev().unwrap(),
    ) {
        let delegatees1 =
            find_delegation_validators(&storage, &validator1, &epoch).unwrap();
        let delegatees2 =
            find_delegation_validators(&storage, &validator2, &epoch).unwrap();
        assert_eq!(delegatees1.len(), 1);
        assert_eq!(delegatees2.len(), 1);
        assert!(delegatees1.contains(&validator1));
        assert!(delegatees2.contains(&validator2));
    }

    let delegatees1 =
        find_delegation_validators(&storage, &validator1, &pipeline_epoch)
            .unwrap();
    assert_eq!(delegatees1.len(), 1);
    assert!(delegatees1.contains(&validator1));

    let delegatees2 =
        find_delegation_validators(&storage, &validator2, &pipeline_epoch)
            .unwrap();
    assert!(delegatees2.is_empty());

    let del_delegatees =
        find_delegation_validators(&storage, &delegator, &pipeline_epoch)
            .unwrap();
    assert_eq!(del_delegatees.len(), 1);
    assert!(del_delegatees.contains(&validator1));

    // Advance to epoch 3
    advance_epoch(&mut storage, &params);
    current_epoch = advance_epoch(&mut storage, &params);

    // Bond from delegator to validator1
    bond_tokens(
        &mut storage,
        Some(&delegator),
        &validator1,
        token::Amount::native_whole(3),
        current_epoch,
        None,
    )
    .unwrap();

    // Bond from delegator to validator2
    bond_tokens(
        &mut storage,
        Some(&delegator),
        &validator2,
        token::Amount::native_whole(3),
        current_epoch,
        None,
    )
    .unwrap();

    // Checks
    let pipeline_epoch = current_epoch + params.pipeline_len;

    // Up to epoch 2
    for epoch in Epoch::iter_bounds_inclusive(
        Epoch::default(),
        current_epoch.prev().unwrap(),
    ) {
        let delegatees1 =
            find_delegation_validators(&storage, &validator1, &epoch).unwrap();
        let delegatees2 =
            find_delegation_validators(&storage, &validator2, &epoch).unwrap();
        let del_delegatees =
            find_delegation_validators(&storage, &delegator, &epoch).unwrap();
        assert_eq!(delegatees1.len(), 1);
        assert_eq!(delegatees2.len(), 1);
        assert!(delegatees1.contains(&validator1));
        assert!(delegatees2.contains(&validator2));
        assert!(del_delegatees.is_empty());
    }

    // Epochs 3-4
    for epoch in Epoch::iter_bounds_inclusive(
        current_epoch,
        pipeline_epoch.prev().unwrap(),
    ) {
        let delegatees1 =
            find_delegation_validators(&storage, &validator1, &epoch).unwrap();
        let delegatees2 =
            find_delegation_validators(&storage, &validator2, &epoch).unwrap();
        let del_delegatees =
            find_delegation_validators(&storage, &delegator, &epoch).unwrap();
        assert_eq!(delegatees1.len(), 1);
        assert!(delegatees2.is_empty());
        assert_eq!(del_delegatees.len(), 1);
        assert!(delegatees1.contains(&validator1));
        assert!(del_delegatees.contains(&validator1));
    }

    // Epoch 5 (pipeline)
    let delegatees1 =
        find_delegation_validators(&storage, &validator1, &pipeline_epoch)
            .unwrap();
    let delegatees2 =
        find_delegation_validators(&storage, &validator2, &pipeline_epoch)
            .unwrap();
    let del_delegatees =
        find_delegation_validators(&storage, &delegator, &pipeline_epoch)
            .unwrap();
    assert_eq!(delegatees1.len(), 1);
    assert!(delegatees2.is_empty());
    assert_eq!(del_delegatees.len(), 2);
    assert!(delegatees1.contains(&validator1));
    assert!(del_delegatees.contains(&validator1));
    assert!(del_delegatees.contains(&validator2));

    // Advance to epoch 4 and self-bond from validator2 again
    current_epoch = advance_epoch(&mut storage, &params);
    bond_tokens(
        &mut storage,
        None,
        &validator2,
        token::Amount::native_whole(1),
        current_epoch,
        None,
    )
    .unwrap();

    let pipeline_epoch = current_epoch + params.pipeline_len;

    // Check at pipeline epoch 6
    let delegatees1 =
        find_delegation_validators(&storage, &validator1, &pipeline_epoch)
            .unwrap();
    let delegatees2 =
        find_delegation_validators(&storage, &validator2, &pipeline_epoch)
            .unwrap();
    let del_delegatees =
        find_delegation_validators(&storage, &delegator, &pipeline_epoch)
            .unwrap();
    assert_eq!(delegatees1.len(), 1);
    assert_eq!(delegatees2.len(), 1);
    assert_eq!(del_delegatees.len(), 2);
    assert!(delegatees1.contains(&validator1));
    assert!(delegatees2.contains(&validator2));
    assert!(del_delegatees.contains(&validator1));
    assert!(del_delegatees.contains(&validator2));

    // Check everything again including the raw bond amount this time

    // Up to epoch 2
    for epoch in Epoch::iter_bounds_inclusive(Epoch::default(), Epoch(2)) {
        let delegatees1 =
            find_delegations(&storage, &validator1, &epoch).unwrap();
        let delegatees2 =
            find_delegations(&storage, &validator2, &epoch).unwrap();
        let del_delegatees =
            find_delegations(&storage, &delegator, &epoch).unwrap();
        assert_eq!(delegatees1.len(), 1);
        assert_eq!(delegatees2.len(), 1);
        assert!(del_delegatees.is_empty());
        assert_eq!(delegatees1.get(&validator1).unwrap(), &stakes[0]);
        assert_eq!(delegatees2.get(&validator2).unwrap(), &stakes[1]);
    }

    // Epochs 3-4
    for epoch in Epoch::iter_bounds_inclusive(Epoch(3), Epoch(4)) {
        let delegatees1 =
            find_delegations(&storage, &validator1, &epoch).unwrap();
        let delegatees2 =
            find_delegations(&storage, &validator2, &epoch).unwrap();
        let del_delegatees =
            find_delegations(&storage, &delegator, &epoch).unwrap();
        assert_eq!(delegatees1.len(), 1);
        assert!(delegatees2.is_empty());
        assert_eq!(del_delegatees.len(), 1);
        assert_eq!(
            delegatees1.get(&validator1).unwrap(),
            &token::Amount::native_whole(1)
        );
        assert_eq!(
            del_delegatees.get(&validator1).unwrap(),
            &token::Amount::native_whole(3)
        );
    }

    // Epoch 5
    let delegatees1 =
        find_delegations(&storage, &validator1, &Epoch(5)).unwrap();
    let delegatees2 =
        find_delegations(&storage, &validator2, &Epoch(5)).unwrap();
    let del_delegatees =
        find_delegations(&storage, &delegator, &Epoch(5)).unwrap();
    assert_eq!(delegatees1.len(), 1);
    assert!(delegatees2.is_empty());
    assert_eq!(del_delegatees.len(), 2);
    assert_eq!(
        delegatees1.get(&validator1).unwrap(),
        &token::Amount::native_whole(1)
    );
    assert_eq!(
        del_delegatees.get(&validator1).unwrap(),
        &token::Amount::native_whole(6)
    );
    assert_eq!(
        del_delegatees.get(&validator2).unwrap(),
        &token::Amount::native_whole(3)
    );

    // Epoch 6
    let delegatees1 =
        find_delegations(&storage, &validator1, &Epoch(6)).unwrap();
    let delegatees2 =
        find_delegations(&storage, &validator2, &Epoch(6)).unwrap();
    let del_delegatees =
        find_delegations(&storage, &delegator, &Epoch(6)).unwrap();
    assert_eq!(delegatees1.len(), 1);
    assert_eq!(delegatees2.len(), 1);
    assert_eq!(del_delegatees.len(), 2);
    assert_eq!(
        delegatees1.get(&validator1).unwrap(),
        &token::Amount::native_whole(1)
    );
    assert_eq!(
        delegatees2.get(&validator2).unwrap(),
        &token::Amount::native_whole(1)
    );
    assert_eq!(
        del_delegatees.get(&validator1).unwrap(),
        &token::Amount::native_whole(6)
    );
    assert_eq!(
        del_delegatees.get(&validator2).unwrap(),
        &token::Amount::native_whole(3)
    );

    // Advance enough epochs for a relevant action to prune old data
    let num_to_advance =
        crate::epoched::OffsetMaxProposalPeriodOrSlashProcessingLenPlus::value(
            &params,
        );
    for _ in 0..num_to_advance {
        advance_epoch(&mut storage, &params);
    }
    current_epoch = storage.in_mem().block.epoch;

    // Redelegate fully from validator1 to validator2
    redelegate_tokens(
        &mut storage,
        &delegator,
        &validator1,
        &validator2,
        current_epoch,
        token::Amount::native_whole(6),
    )
    .unwrap();

    let de_d1 = delegation_targets_handle(&delegator)
        .get(&storage, &validator1)
        .unwrap()
        .unwrap();
    let de_d2 = delegation_targets_handle(&delegator)
        .get(&storage, &validator2)
        .unwrap()
        .unwrap();
    assert!(de_d1.prev_ranges.is_empty());
    assert_eq!(
        de_d1.last_range.1,
        Some(current_epoch + params.pipeline_len)
    );
    assert!(de_d2.prev_ranges.is_empty());
    assert!(de_d2.last_range.1.is_none());

    // Fully self-unbond validator2 to see if old data is pruned
    unbond_tokens(
        &mut storage,
        None,
        &validator2,
        token::Amount::native_whole(1),
        current_epoch,
        false,
    )
    .unwrap();

    let de_2 = delegation_targets_handle(&validator2)
        .get(&storage, &validator2)
        .unwrap()
        .unwrap();
    assert!(de_2.prev_ranges.is_empty());
    assert_eq!(de_2.last_range.1, Some(current_epoch + params.pipeline_len));

    // Self-bond validator2 to check that no data is pushed to `prev_ranges`
    bond_tokens(
        &mut storage,
        None,
        &validator2,
        token::Amount::native_whole(2),
        current_epoch,
        None,
    )
    .unwrap();

    let de_2 = delegation_targets_handle(&validator2)
        .get(&storage, &validator2)
        .unwrap()
        .unwrap();
    assert!(de_2.prev_ranges.is_empty());
    assert_eq!(de_2.last_range.1, None);
}
