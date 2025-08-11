#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::ops::Deref;
use std::str::FromStr;

use assert_matches::assert_matches;
use namada_core::address::testing::{
    established_address_1, established_address_2,
};
use namada_core::address::{self, Address};
use namada_core::chain::{BlockHeight, Epoch};
use namada_core::dec::Dec;
use namada_core::key::RefTo;
use namada_core::key::testing::{keypair_1, keypair_2, keypair_3};
use namada_core::token::NATIVE_MAX_DECIMAL_PLACES;
use namada_state::testing::{TestFullAccessState, TestState};
use namada_trans_token::{self as token, credit_tokens, read_balance};
use proptest::prelude::*;
use proptest::test_runner::Config;
// Use `RUST_LOG=info` (or another tracing level) and `--nocapture` to see
// `tracing` logs from tests
use test_log::test;

use crate::lazy_map::Collectable;
use crate::storage::{
    bond_handle, delegator_redelegated_bonds_handle,
    delegator_redelegated_unbonds_handle, enqueued_slashes_handle,
    read_total_stake, read_validator_stake, total_bonded_handle,
    total_unbonded_handle, unbond_handle,
    validator_incoming_redelegations_handle,
    validator_outgoing_redelegations_handle, validator_slashes_handle,
    validator_total_redelegated_bonded_handle,
    validator_total_redelegated_unbonded_handle,
};
use crate::tests::helpers::{
    advance_epoch, arb_genesis_validators, arb_redelegation_amounts,
    test_slashes_with_unbonding_params,
};
use crate::tests::{
    bond_amount, bond_tokens, bonds_and_unbonds, process_slashes,
    redelegate_tokens, slash, test_init_genesis, unbond_tokens,
    withdraw_tokens,
};
use crate::types::{BondId, GenesisValidator, Slash, SlashType};
use crate::{
    OwnedPosParams, RedelegationError, StorageRead, staking_token_address,
};

proptest! {
    // Generate arb valid input for `test_simple_redelegation_aux`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_simple_redelegation(

    genesis_validators in arb_genesis_validators(2..4, None),
    (amount_delegate, amount_redelegate, amount_unbond) in arb_redelegation_amounts(20)

    ) {
        test_simple_redelegation_aux(genesis_validators, amount_delegate, amount_redelegate, amount_unbond)
    }
}

fn test_simple_redelegation_aux(
    mut validators: Vec<GenesisValidator>,
    amount_delegate: token::Amount,
    amount_redelegate: token::Amount,
    amount_unbond: token::Amount,
) {
    validators.sort_by(|a, b| b.tokens.cmp(&a.tokens));

    let src_validator = validators[0].address.clone();
    let dest_validator = validators[1].address.clone();

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

    // Get a delegator with some tokens
    let staking_token = staking_token_address(&storage);
    let delegator = address::testing::gen_implicit_address();
    let del_balance = token::Amount::from_uint(1_000_000, 0).unwrap();
    credit_tokens(&mut storage, &staking_token, &delegator, del_balance)
        .unwrap();

    // Ensure that we cannot redelegate with the same src and dest validator
    let err = redelegate_tokens(
        &mut storage,
        &delegator,
        &src_validator,
        &src_validator,
        current_epoch,
        amount_redelegate,
    )
    .unwrap_err();
    let err_str = err.to_string();
    assert_matches!(
        err.downcast::<RedelegationError>().unwrap().deref(),
        RedelegationError::RedelegationSrcEqDest,
        "Redelegation with the same src and dest validator must be rejected, \
         got {err_str}",
    );

    for _ in 0..5 {
        current_epoch = advance_epoch(&mut storage, &params);
        process_slashes(
            &mut storage,
            &mut namada_events::testing::VoidEventSink,
            current_epoch,
        )
        .unwrap();
    }

    let init_epoch = current_epoch;

    // Delegate in epoch 1 to src_validator
    bond_tokens(
        &mut storage,
        Some(&delegator),
        &src_validator,
        amount_delegate,
        current_epoch,
        None,
    )
    .unwrap();

    // Advance three epochs
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    // Redelegate in epoch 3
    redelegate_tokens(
        &mut storage,
        &delegator,
        &src_validator,
        &dest_validator,
        current_epoch,
        amount_redelegate,
    )
    .unwrap();

    // Dest val

    // Src val

    // Checks
    let redelegated = delegator_redelegated_bonds_handle(&delegator)
        .at(&dest_validator)
        .at(&(current_epoch + params.pipeline_len))
        .at(&src_validator)
        .get(&storage, &(init_epoch + params.pipeline_len))
        .unwrap()
        .unwrap();
    assert_eq!(redelegated, amount_redelegate);

    let redel_start_epoch =
        validator_incoming_redelegations_handle(&dest_validator)
            .get(&storage, &delegator)
            .unwrap()
            .unwrap();
    assert_eq!(redel_start_epoch, current_epoch + params.pipeline_len);

    let redelegated = validator_outgoing_redelegations_handle(&src_validator)
        .at(&dest_validator)
        .at(&current_epoch.prev().unwrap())
        .get(&storage, &current_epoch)
        .unwrap()
        .unwrap();
    assert_eq!(redelegated, amount_redelegate);

    // Advance three epochs
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    // Unbond in epoch 5 from dest_validator
    let _ = unbond_tokens(
        &mut storage,
        Some(&delegator),
        &dest_validator,
        amount_unbond,
        current_epoch,
        false,
    )
    .unwrap();

    let bond_start = init_epoch + params.pipeline_len;
    let redelegation_end = bond_start + params.pipeline_len + 1u64;
    let unbond_end =
        redelegation_end + params.withdrawable_epoch_offset() + 1u64;
    let unbond_materialized = redelegation_end + params.pipeline_len + 1u64;

    // Checks
    let redelegated_remaining = delegator_redelegated_bonds_handle(&delegator)
        .at(&dest_validator)
        .at(&redelegation_end)
        .at(&src_validator)
        .get(&storage, &bond_start)
        .unwrap()
        .unwrap_or_default();
    assert_eq!(redelegated_remaining, amount_redelegate - amount_unbond);

    let redel_unbonded = delegator_redelegated_unbonds_handle(&delegator)
        .at(&dest_validator)
        .at(&redelegation_end)
        .at(&unbond_end)
        .at(&src_validator)
        .get(&storage, &bond_start)
        .unwrap()
        .unwrap();
    assert_eq!(redel_unbonded, amount_unbond);

    let total_redel_unbonded =
        validator_total_redelegated_unbonded_handle(&dest_validator)
            .at(&unbond_materialized)
            .at(&redelegation_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
            .unwrap();
    assert_eq!(total_redel_unbonded, amount_unbond);

    // Advance to withdrawal epoch
    loop {
        current_epoch = advance_epoch(&mut storage, &params);
        process_slashes(
            &mut storage,
            &mut namada_events::testing::VoidEventSink,
            current_epoch,
        )
        .unwrap();
        if current_epoch == unbond_end {
            break;
        }
    }

    // Withdraw
    withdraw_tokens(
        &mut storage,
        Some(&delegator),
        &dest_validator,
        current_epoch,
    )
    .unwrap();

    assert!(
        delegator_redelegated_unbonds_handle(&delegator)
            .at(&dest_validator)
            .is_empty(&storage)
            .unwrap()
    );

    let delegator_balance = storage
        .read::<token::Amount>(&token::storage_key::balance_key(
            &staking_token,
            &delegator,
        ))
        .unwrap()
        .unwrap_or_default();
    assert_eq!(
        delegator_balance,
        del_balance - amount_delegate + amount_unbond
    );
}

proptest! {
    // Generate arb valid input for `test_slashes_with_unbonding_aux`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_slashes_with_unbonding(
        (params, genesis_validators, unbond_delay)
            in test_slashes_with_unbonding_params()
    ) {
        test_slashes_with_unbonding_aux(
            params, genesis_validators, unbond_delay)
    }
}

fn test_slashes_with_unbonding_aux(
    mut params: OwnedPosParams,
    validators: Vec<GenesisValidator>,
    unbond_delay: u64,
) {
    // This can be useful for debugging:
    params.pipeline_len = 2;
    params.unbonding_len = 4;
    // println!("\nTest inputs: {params:?}, genesis validators:
    // {validators:#?}");
    let mut state = TestFullAccessState::default();
    let mut s = state.restrict_writes_to_write_log();

    // Find the validator with the least stake to avoid the cubic slash rate
    // going to 100%
    let validator =
        itertools::Itertools::sorted_by_key(validators.iter(), |v| v.tokens)
            .next()
            .unwrap();
    let val_addr = &validator.address;
    let val_tokens = validator.tokens;

    // Genesis
    // let start_epoch = s.in_mem().block.epoch;
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
    // let slash_0_processing_epoch =
    //     slash_0_evidence_epoch + params.slash_processing_epoch_offset();
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

    // Advance to an epoch in which we can unbond
    let unfreeze_epoch =
        slash_0_evidence_epoch + params.slash_processing_epoch_offset();
    while current_epoch < unfreeze_epoch {
        current_epoch = advance_epoch(&mut s, &params);
        process_slashes(
            &mut s,
            &mut namada_events::testing::VoidEventSink,
            current_epoch,
        )
        .unwrap();
    }

    // Advance more epochs randomly from the generated delay
    for _ in 0..unbond_delay {
        current_epoch = advance_epoch(&mut s, &params);
    }

    // Unbond half of the tokens
    let unbond_amount = Dec::new(5, 1).unwrap() * val_tokens;
    let unbond_epoch = current_epoch;
    unbond_tokens(&mut s, None, val_addr, unbond_amount, unbond_epoch, false)
        .unwrap();

    // Discover second slash
    let slash_1_evidence_epoch = current_epoch;
    // Ensure that both slashes happen before `unbond_epoch + pipeline`
    let _slash_1_processing_epoch =
        slash_1_evidence_epoch + params.slash_processing_epoch_offset();
    let evidence_block_height = BlockHeight(0); // doesn't matter for slashing logic
    let slash_1_type = SlashType::DuplicateVote;
    slash(
        &mut s,
        &params,
        current_epoch,
        slash_1_evidence_epoch,
        evidence_block_height,
        slash_1_type,
        val_addr,
        current_epoch.next(),
    )
    .unwrap();

    // Advance to an epoch in which we can withdraw
    let withdraw_epoch = unbond_epoch + params.withdrawable_epoch_offset();
    while current_epoch < withdraw_epoch {
        current_epoch = advance_epoch(&mut s, &params);
        process_slashes(
            &mut s,
            &mut namada_events::testing::VoidEventSink,
            current_epoch,
        )
        .unwrap();
    }
    let token = staking_token_address(&s);
    let val_balance_pre = read_balance(&s, &token, val_addr).unwrap();

    let bond_id = BondId {
        source: val_addr.clone(),
        validator: val_addr.clone(),
    };
    let binding = bonds_and_unbonds(&s, None, Some(val_addr.clone())).unwrap();
    let details = binding.get(&bond_id).unwrap();
    let exp_withdraw_from_details = details.unbonds[0].amount
        - details.unbonds[0].slashed_amount.unwrap_or_default();

    withdraw_tokens(&mut s, None, val_addr, current_epoch).unwrap();

    let val_balance_post = read_balance(&s, &token, val_addr).unwrap();
    let withdrawn_tokens = val_balance_post - val_balance_pre;

    assert_eq!(exp_withdraw_from_details, withdrawn_tokens);

    let slash_rate_0 = validator_slashes_handle(val_addr)
        .get(&s, 0)
        .unwrap()
        .unwrap()
        .rate;
    let slash_rate_1 = validator_slashes_handle(val_addr)
        .get(&s, 1)
        .unwrap()
        .unwrap()
        .rate;

    let expected_withdrawn_amount = Dec::try_from(
        unbond_amount
            .mul_floor(
                (Dec::one() - slash_rate_1) * (Dec::one() - slash_rate_0),
            )
            .unwrap(),
    )
    .unwrap();
    // Allow some rounding error, 1 NAMNAM per each slash
    let rounding_error_tolerance =
        Dec::new(2, NATIVE_MAX_DECIMAL_PLACES).unwrap();
    assert!(
        expected_withdrawn_amount
            .abs_diff(Dec::try_from(withdrawn_tokens).unwrap())
            .unwrap()
            <= rounding_error_tolerance
    );

    // TODO: finish once implemented
    // let slash_0 = decimal_mult_amount(slash_rate_0, val_tokens);
    // let slash_1 = decimal_mult_amount(slash_rate_1, val_tokens - slash_0);
    // let expected_slash_pool = slash_0 + slash_1;
    // let slash_pool_balance =
    //     read_balance(&s, &token, &SLASH_POOL_ADDRESS).unwrap();
    // assert_eq!(expected_slash_pool, slash_pool_balance);
}

proptest! {
    // Generate arb valid input for `test_simple_redelegation_aux`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_redelegation_with_slashing(

    genesis_validators in arb_genesis_validators(2..4, None),
    (amount_delegate, amount_redelegate, amount_unbond) in arb_redelegation_amounts(20)

    ) {
        test_redelegation_with_slashing_aux(genesis_validators, amount_delegate, amount_redelegate, amount_unbond)
    }
}

fn test_redelegation_with_slashing_aux(
    mut validators: Vec<GenesisValidator>,
    amount_delegate: token::Amount,
    amount_redelegate: token::Amount,
    amount_unbond: token::Amount,
) {
    validators.sort_by(|a, b| b.tokens.cmp(&a.tokens));

    let src_validator = validators[0].address.clone();
    let dest_validator = validators[1].address.clone();

    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        unbonding_len: 4,
        // Avoid empty consensus set by removing the threshold
        validator_stake_threshold: token::Amount::zero(),
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

    // Get a delegator with some tokens
    let staking_token = staking_token_address(&storage);
    let delegator = address::testing::gen_implicit_address();
    let del_balance = token::Amount::from_uint(1_000_000, 0).unwrap();
    credit_tokens(&mut storage, &staking_token, &delegator, del_balance)
        .unwrap();

    for _ in 0..5 {
        current_epoch = advance_epoch(&mut storage, &params);
        process_slashes(
            &mut storage,
            &mut namada_events::testing::VoidEventSink,
            current_epoch,
        )
        .unwrap();
    }

    let init_epoch = current_epoch;

    // Delegate in epoch 5 to src_validator
    bond_tokens(
        &mut storage,
        Some(&delegator),
        &src_validator,
        amount_delegate,
        current_epoch,
        None,
    )
    .unwrap();

    // Advance three epochs
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    // Redelegate in epoch 8
    redelegate_tokens(
        &mut storage,
        &delegator,
        &src_validator,
        &dest_validator,
        current_epoch,
        amount_redelegate,
    )
    .unwrap();

    // Checks
    let redelegated = delegator_redelegated_bonds_handle(&delegator)
        .at(&dest_validator)
        .at(&(current_epoch + params.pipeline_len))
        .at(&src_validator)
        .get(&storage, &(init_epoch + params.pipeline_len))
        .unwrap()
        .unwrap();
    assert_eq!(redelegated, amount_redelegate);

    let redel_start_epoch =
        validator_incoming_redelegations_handle(&dest_validator)
            .get(&storage, &delegator)
            .unwrap()
            .unwrap();
    assert_eq!(redel_start_epoch, current_epoch + params.pipeline_len);

    let redelegated = validator_outgoing_redelegations_handle(&src_validator)
        .at(&dest_validator)
        .at(&current_epoch.prev().unwrap())
        .get(&storage, &current_epoch)
        .unwrap()
        .unwrap();
    assert_eq!(redelegated, amount_redelegate);

    // Advance three epochs
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    // Unbond in epoch 11 from dest_validator
    let _ = unbond_tokens(
        &mut storage,
        Some(&delegator),
        &dest_validator,
        amount_unbond,
        current_epoch,
        false,
    )
    .unwrap();

    // Advance one epoch
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    // Discover evidence
    slash(
        &mut storage,
        &params,
        current_epoch,
        init_epoch + 2 * params.pipeline_len,
        0u64,
        SlashType::DuplicateVote,
        &src_validator,
        current_epoch.next(),
    )
    .unwrap();

    let bond_start = init_epoch + params.pipeline_len;
    let redelegation_end = bond_start + params.pipeline_len + 1u64;
    let unbond_end =
        redelegation_end + params.withdrawable_epoch_offset() + 1u64;
    let unbond_materialized = redelegation_end + params.pipeline_len + 1u64;

    // Checks
    let redelegated_remaining = delegator_redelegated_bonds_handle(&delegator)
        .at(&dest_validator)
        .at(&redelegation_end)
        .at(&src_validator)
        .get(&storage, &bond_start)
        .unwrap()
        .unwrap_or_default();
    assert_eq!(redelegated_remaining, amount_redelegate - amount_unbond);

    let redel_unbonded = delegator_redelegated_unbonds_handle(&delegator)
        .at(&dest_validator)
        .at(&redelegation_end)
        .at(&unbond_end)
        .at(&src_validator)
        .get(&storage, &bond_start)
        .unwrap()
        .unwrap();
    assert_eq!(redel_unbonded, amount_unbond);

    let total_redel_unbonded =
        validator_total_redelegated_unbonded_handle(&dest_validator)
            .at(&unbond_materialized)
            .at(&redelegation_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
            .unwrap();
    assert_eq!(total_redel_unbonded, amount_unbond);

    // Advance to withdrawal epoch
    loop {
        current_epoch = advance_epoch(&mut storage, &params);
        process_slashes(
            &mut storage,
            &mut namada_events::testing::VoidEventSink,
            current_epoch,
        )
        .unwrap();
        if current_epoch == unbond_end {
            break;
        }
    }

    // Withdraw
    withdraw_tokens(
        &mut storage,
        Some(&delegator),
        &dest_validator,
        current_epoch,
    )
    .unwrap();

    assert!(
        delegator_redelegated_unbonds_handle(&delegator)
            .at(&dest_validator)
            .is_empty(&storage)
            .unwrap()
    );

    let delegator_balance = storage
        .read::<token::Amount>(&token::storage_key::balance_key(
            &staking_token,
            &delegator,
        ))
        .unwrap()
        .unwrap_or_default();
    assert_eq!(delegator_balance, del_balance - amount_delegate);
}

proptest! {
    // Generate arb valid input for `test_chain_redelegations_aux`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_chain_redelegations(

    genesis_validators in arb_genesis_validators(3..4, None),

    ) {
        test_chain_redelegations_aux(genesis_validators)
    }
}

fn test_chain_redelegations_aux(mut validators: Vec<GenesisValidator>) {
    validators.sort_by(|a, b| b.tokens.cmp(&a.tokens));

    let src_validator = validators[0].address.clone();
    let _init_stake_src = validators[0].tokens;
    let dest_validator = validators[1].address.clone();
    let _init_stake_dest = validators[1].tokens;
    let dest_validator_2 = validators[2].address.clone();
    let _init_stake_dest_2 = validators[2].tokens;

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

    // Get a delegator with some tokens
    let staking_token = staking_token_address(&storage);
    let delegator = address::testing::gen_implicit_address();
    let del_balance = token::Amount::from_uint(1_000_000, 0).unwrap();
    credit_tokens(&mut storage, &staking_token, &delegator, del_balance)
        .unwrap();

    // Delegate in epoch 0 to src_validator
    let bond_amount: token::Amount = 100.into();
    bond_tokens(
        &mut storage,
        Some(&delegator),
        &src_validator,
        bond_amount,
        current_epoch,
        None,
    )
    .unwrap();

    let bond_start = current_epoch + params.pipeline_len;

    // Advance one epoch
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    // Redelegate in epoch 1 to dest_validator
    let redel_amount_1: token::Amount = 58.into();
    redelegate_tokens(
        &mut storage,
        &delegator,
        &src_validator,
        &dest_validator,
        current_epoch,
        redel_amount_1,
    )
    .unwrap();

    let redel_start = current_epoch;
    let redel_end = current_epoch + params.pipeline_len;

    // Checks ----------------

    // Dest validator should have an incoming redelegation
    let incoming_redelegation =
        validator_incoming_redelegations_handle(&dest_validator)
            .get(&storage, &delegator)
            .unwrap();
    assert_eq!(incoming_redelegation, Some(redel_end));

    // Src validator should have an outoging redelegation
    let outgoing_redelegation =
        validator_outgoing_redelegations_handle(&src_validator)
            .at(&dest_validator)
            .at(&bond_start)
            .get(&storage, &redel_start)
            .unwrap();
    assert_eq!(outgoing_redelegation, Some(redel_amount_1));

    // Delegator should have redelegated bonds
    let del_total_redelegated_bonded =
        delegator_redelegated_bonds_handle(&delegator)
            .at(&dest_validator)
            .at(&redel_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
            .unwrap_or_default();
    assert_eq!(del_total_redelegated_bonded, redel_amount_1);

    // There should be delegator bonds for both src and dest validators
    let bonded_src = bond_handle(&delegator, &src_validator);
    let bonded_dest = bond_handle(&delegator, &dest_validator);
    assert_eq!(
        bonded_src
            .get_delta_val(&storage, bond_start)
            .unwrap()
            .unwrap_or_default(),
        bond_amount - redel_amount_1
    );
    assert_eq!(
        bonded_dest
            .get_delta_val(&storage, redel_end)
            .unwrap()
            .unwrap_or_default(),
        redel_amount_1
    );

    // The dest validator should have total redelegated bonded tokens
    let dest_total_redelegated_bonded =
        validator_total_redelegated_bonded_handle(&dest_validator)
            .at(&redel_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
            .unwrap_or_default();
    assert_eq!(dest_total_redelegated_bonded, redel_amount_1);

    // The dest validator's total bonded should have an entry for the genesis
    // bond and the redelegation
    let dest_total_bonded = total_bonded_handle(&dest_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    assert!(
        dest_total_bonded.len() == 2
            && dest_total_bonded.contains_key(&Epoch::default())
    );
    assert_eq!(
        dest_total_bonded
            .get(&redel_end)
            .cloned()
            .unwrap_or_default(),
        redel_amount_1
    );

    // The src validator should have a total bonded entry for the original bond
    // accounting for the redelegation
    assert_eq!(
        total_bonded_handle(&src_validator)
            .get_delta_val(&storage, bond_start)
            .unwrap()
            .unwrap_or_default(),
        bond_amount - redel_amount_1
    );

    // The src validator should have a total unbonded entry due to the
    // redelegation
    let src_total_unbonded = total_unbonded_handle(&src_validator)
        .at(&redel_end)
        .get(&storage, &bond_start)
        .unwrap()
        .unwrap_or_default();
    assert_eq!(src_total_unbonded, redel_amount_1);

    // Attempt to redelegate in epoch 3 to dest_validator
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    let redel_amount_2: token::Amount = 23.into();
    let redel_att = redelegate_tokens(
        &mut storage,
        &delegator,
        &dest_validator,
        &dest_validator_2,
        current_epoch,
        redel_amount_2,
    );
    assert!(redel_att.is_err());

    // Advance to right before the redelegation can be redelegated again
    assert_eq!(redel_end, current_epoch);
    let epoch_can_redel =
        redel_end.prev().unwrap() + params.slash_processing_epoch_offset();
    loop {
        current_epoch = advance_epoch(&mut storage, &params);
        process_slashes(
            &mut storage,
            &mut namada_events::testing::VoidEventSink,
            current_epoch,
        )
        .unwrap();
        if current_epoch == epoch_can_redel.prev().unwrap() {
            break;
        }
    }

    // Attempt to redelegate in epoch before we actually are able to
    let redel_att = redelegate_tokens(
        &mut storage,
        &delegator,
        &dest_validator,
        &dest_validator_2,
        current_epoch,
        redel_amount_2,
    );
    assert!(redel_att.is_err());

    // Advance one more epoch
    current_epoch = advance_epoch(&mut storage, &params);
    process_slashes(
        &mut storage,
        &mut namada_events::testing::VoidEventSink,
        current_epoch,
    )
    .unwrap();

    // Redelegate from dest_validator to dest_validator_2 now
    redelegate_tokens(
        &mut storage,
        &delegator,
        &dest_validator,
        &dest_validator_2,
        current_epoch,
        redel_amount_2,
    )
    .unwrap();

    let redel_2_start = current_epoch;
    let redel_2_end = current_epoch + params.pipeline_len;

    // Checks -----------------------------------

    // Both the dest validator and dest validator 2 should have incoming
    // redelegations
    let incoming_redelegation_1 =
        validator_incoming_redelegations_handle(&dest_validator)
            .get(&storage, &delegator)
            .unwrap();
    assert_eq!(incoming_redelegation_1, Some(redel_end));
    let incoming_redelegation_2 =
        validator_incoming_redelegations_handle(&dest_validator_2)
            .get(&storage, &delegator)
            .unwrap();
    assert_eq!(incoming_redelegation_2, Some(redel_2_end));

    // Both the src validator and dest validator should have outgoing
    // redelegations
    let outgoing_redelegation_1 =
        validator_outgoing_redelegations_handle(&src_validator)
            .at(&dest_validator)
            .at(&bond_start)
            .get(&storage, &redel_start)
            .unwrap();
    assert_eq!(outgoing_redelegation_1, Some(redel_amount_1));

    let outgoing_redelegation_2 =
        validator_outgoing_redelegations_handle(&dest_validator)
            .at(&dest_validator_2)
            .at(&redel_end)
            .get(&storage, &redel_2_start)
            .unwrap();
    assert_eq!(outgoing_redelegation_2, Some(redel_amount_2));

    // All three validators should have bonds
    let bonded_dest2 = bond_handle(&delegator, &dest_validator_2);
    assert_eq!(
        bonded_src
            .get_delta_val(&storage, bond_start)
            .unwrap()
            .unwrap_or_default(),
        bond_amount - redel_amount_1
    );
    assert_eq!(
        bonded_dest
            .get_delta_val(&storage, redel_end)
            .unwrap()
            .unwrap_or_default(),
        redel_amount_1 - redel_amount_2
    );
    assert_eq!(
        bonded_dest2
            .get_delta_val(&storage, redel_2_end)
            .unwrap()
            .unwrap_or_default(),
        redel_amount_2
    );

    // There should be no unbond entries
    let unbond_src = unbond_handle(&delegator, &src_validator);
    let unbond_dest = unbond_handle(&delegator, &dest_validator);
    assert!(unbond_src.is_empty(&storage).unwrap());
    assert!(unbond_dest.is_empty(&storage).unwrap());

    // The dest validator should have some total unbonded due to the second
    // redelegation
    let dest_total_unbonded = total_unbonded_handle(&dest_validator)
        .at(&redel_2_end)
        .get(&storage, &redel_end)
        .unwrap();
    assert_eq!(dest_total_unbonded, Some(redel_amount_2));

    // Delegator should have redelegated bonds due to both redelegations
    let del_redelegated_bonds = delegator_redelegated_bonds_handle(&delegator);
    assert_eq!(
        Some(redel_amount_1 - redel_amount_2),
        del_redelegated_bonds
            .at(&dest_validator)
            .at(&redel_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
    );
    assert_eq!(
        Some(redel_amount_2),
        del_redelegated_bonds
            .at(&dest_validator_2)
            .at(&redel_2_end)
            .at(&dest_validator)
            .get(&storage, &redel_end)
            .unwrap()
    );

    // Delegator redelegated unbonds should be empty
    assert!(
        delegator_redelegated_unbonds_handle(&delegator)
            .is_empty(&storage)
            .unwrap()
    );

    // Both the dest validator and dest validator 2 should have total
    // redelegated bonds
    let dest_redelegated_bonded =
        validator_total_redelegated_bonded_handle(&dest_validator)
            .at(&redel_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
            .unwrap_or_default();
    let dest2_redelegated_bonded =
        validator_total_redelegated_bonded_handle(&dest_validator_2)
            .at(&redel_2_end)
            .at(&dest_validator)
            .get(&storage, &redel_end)
            .unwrap()
            .unwrap_or_default();
    assert_eq!(dest_redelegated_bonded, redel_amount_1 - redel_amount_2);
    assert_eq!(dest2_redelegated_bonded, redel_amount_2);

    // Total redelegated unbonded should be empty for src_validator and
    // dest_validator_2
    assert!(
        validator_total_redelegated_unbonded_handle(&dest_validator_2)
            .is_empty(&storage)
            .unwrap()
    );
    assert!(
        validator_total_redelegated_unbonded_handle(&src_validator)
            .is_empty(&storage)
            .unwrap()
    );

    // The dest_validator should have total_redelegated unbonded
    let tot_redel_unbonded =
        validator_total_redelegated_unbonded_handle(&dest_validator)
            .at(&redel_2_end)
            .at(&redel_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
            .unwrap_or_default();
    assert_eq!(tot_redel_unbonded, redel_amount_2);
}

proptest! {
    // Generate arb valid input for `test_overslashing_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_overslashing(

    genesis_validators in arb_genesis_validators(4..5, None),

    ) {
        test_overslashing_aux(genesis_validators)
    }
}

/// Test precisely that we are not overslashing, as originally discovered by Tomas in this issue: https://github.com/informalsystems/partnership-heliax/issues/74
fn test_overslashing_aux(mut validators: Vec<GenesisValidator>) {
    assert_eq!(validators.len(), 4);

    let params = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    let offending_stake = token::Amount::native_whole(110);
    let other_stake = token::Amount::native_whole(100);

    // Set stakes so we know we will get a slashing rate between 0.5 -1.0
    validators[0].tokens = offending_stake;
    validators[1].tokens = other_stake;
    validators[2].tokens = other_stake;
    validators[3].tokens = other_stake;

    // Get the offending validator
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
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    state.commit_block().unwrap();
    let mut storage = state.restrict_writes_to_write_log();

    // Get a delegator with some tokens
    let staking_token = storage.in_mem().native_token.clone();
    let delegator = address::testing::gen_implicit_address();
    let amount_del = token::Amount::native_whole(5);
    credit_tokens(&mut storage, &staking_token, &delegator, amount_del)
        .unwrap();

    // Delegate tokens in epoch 0 to validator
    bond_tokens(
        &mut storage,
        Some(&delegator),
        &validator,
        amount_del,
        current_epoch,
        None,
    )
    .unwrap();

    let self_bond_epoch = current_epoch;
    let delegation_epoch = current_epoch + params.pipeline_len;

    // Advance to pipeline epoch
    for _ in 0..params.pipeline_len {
        current_epoch = advance_epoch(&mut storage, &params);
    }
    assert_eq!(delegation_epoch, current_epoch);

    // Find a misbehavior committed in epoch 0
    slash(
        &mut storage,
        &params,
        current_epoch,
        self_bond_epoch,
        0_u64,
        SlashType::DuplicateVote,
        &validator,
        current_epoch.next(),
    )
    .unwrap();

    // Find a misbehavior committed in current epoch
    slash(
        &mut storage,
        &params,
        current_epoch,
        delegation_epoch,
        0_u64,
        SlashType::DuplicateVote,
        &validator,
        current_epoch.next(),
    )
    .unwrap();

    let processing_epoch_1 =
        self_bond_epoch + params.slash_processing_epoch_offset();
    let processing_epoch_2 =
        delegation_epoch + params.slash_processing_epoch_offset();

    // Advance to processing epoch 1
    loop {
        current_epoch = advance_epoch(&mut storage, &params);
        process_slashes(
            &mut storage,
            &mut namada_events::testing::VoidEventSink,
            current_epoch,
        )
        .unwrap();
        if current_epoch == processing_epoch_1 {
            break;
        }
    }

    let total_stake_1 = offending_stake + other_stake * 3;
    let stake_frac = Dec::try_from(offending_stake).unwrap()
        / Dec::try_from(total_stake_1).unwrap();
    let slash_rate_1 = Dec::from_str("9.0").unwrap() * stake_frac * stake_frac;

    let exp_slashed_1 = offending_stake.mul_ceil(slash_rate_1).unwrap();

    // Check that the proper amount was slashed
    let epoch = current_epoch.next();
    let validator_stake =
        read_validator_stake(&storage, &params, &validator, epoch).unwrap();
    let exp_validator_stake = offending_stake - exp_slashed_1 + amount_del;
    assert_eq!(validator_stake, exp_validator_stake);

    let total_stake = read_total_stake(&storage, &params, epoch).unwrap();
    let exp_total_stake =
        offending_stake - exp_slashed_1 + amount_del + other_stake * 3;
    assert_eq!(total_stake, exp_total_stake);

    let self_bond_id = BondId {
        source: validator.clone(),
        validator: validator.clone(),
    };
    let amount = bond_amount(&storage, &self_bond_id, epoch).unwrap();
    let exp_bond_amount = offending_stake - exp_slashed_1;
    assert_eq!(amount, exp_bond_amount);

    // Advance to processing epoch 2
    loop {
        current_epoch = advance_epoch(&mut storage, &params);
        process_slashes(
            &mut storage,
            &mut namada_events::testing::VoidEventSink,
            current_epoch,
        )
        .unwrap();
        if current_epoch == processing_epoch_2 {
            break;
        }
    }

    let total_stake_2 = offending_stake + amount_del + other_stake * 3;
    let stake_frac = Dec::try_from(offending_stake + amount_del).unwrap()
        / Dec::try_from(total_stake_2).unwrap();
    let slash_rate_2 = Dec::from_str("9.0").unwrap() * stake_frac * stake_frac;

    let exp_slashed_from_delegation =
        amount_del.mul_ceil(slash_rate_2).unwrap();

    // Check that the proper amount was slashed. We expect that all of the
    // validator self-bond has been slashed and some of the delegation has been
    // slashed due to the second infraction.
    let epoch = current_epoch.next();

    let validator_stake =
        read_validator_stake(&storage, &params, &validator, epoch).unwrap();
    let exp_validator_stake = amount_del - exp_slashed_from_delegation;
    assert_eq!(validator_stake, exp_validator_stake);

    let total_stake = read_total_stake(&storage, &params, epoch).unwrap();
    let exp_total_stake =
        amount_del - exp_slashed_from_delegation + other_stake * 3;
    assert_eq!(total_stake, exp_total_stake);

    let delegation_id = BondId {
        source: delegator.clone(),
        validator: validator.clone(),
    };
    let delegation_amount =
        bond_amount(&storage, &delegation_id, epoch).unwrap();
    let exp_del_amount = amount_del - exp_slashed_from_delegation;
    assert_eq!(delegation_amount, exp_del_amount);

    let self_bond_amount = bond_amount(&storage, &self_bond_id, epoch).unwrap();
    let exp_bond_amount = token::Amount::zero();
    assert_eq!(self_bond_amount, exp_bond_amount);
}

proptest! {
    // Generate arb valid input for `test_slashed_bond_amount_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_slashed_bond_amount(

    genesis_validators in arb_genesis_validators(4..5, None),

    ) {
        test_slashed_bond_amount_aux(genesis_validators)
    }
}

fn test_slashed_bond_amount_aux(validators: Vec<GenesisValidator>) {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        unbonding_len: 4,
        validator_stake_threshold: token::Amount::zero(),
        ..Default::default()
    };

    let init_tot_stake = validators
        .clone()
        .into_iter()
        .fold(token::Amount::zero(), |acc, v| acc + v.tokens);
    let val1_init_stake = validators[0].tokens;

    let mut validators = validators;
    validators[0].tokens = (init_tot_stake - val1_init_stake) / 30;

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

    // Advance an epoch to 1
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

    // Advance an epoch to ep 2
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

    // Advance two epochs to ep 4
    for _ in 0..2 {
        current_epoch = advance_epoch(&mut storage, &params);
        process_slashes(
            &mut storage,
            &mut namada_events::testing::VoidEventSink,
            current_epoch,
        )
        .unwrap();
    }

    // Find some slashes committed in various epochs
    slash(
        &mut storage,
        &params,
        current_epoch,
        Epoch(1),
        1_u64,
        SlashType::DuplicateVote,
        &validator1,
        current_epoch,
    )
    .unwrap();
    slash(
        &mut storage,
        &params,
        current_epoch,
        Epoch(2),
        1_u64,
        SlashType::DuplicateVote,
        &validator1,
        current_epoch,
    )
    .unwrap();
    slash(
        &mut storage,
        &params,
        current_epoch,
        Epoch(2),
        1_u64,
        SlashType::DuplicateVote,
        &validator1,
        current_epoch,
    )
    .unwrap();
    slash(
        &mut storage,
        &params,
        current_epoch,
        Epoch(3),
        1_u64,
        SlashType::DuplicateVote,
        &validator1,
        current_epoch,
    )
    .unwrap();

    // Advance such that these slashes are all processed
    for _ in 0..params.slash_processing_epoch_offset() {
        current_epoch = advance_epoch(&mut storage, &params);
        process_slashes(
            &mut storage,
            &mut namada_events::testing::VoidEventSink,
            current_epoch,
        )
        .unwrap();
    }

    let pipeline_epoch = current_epoch + params.pipeline_len;

    #[allow(clippy::disallowed_methods)]
    let del_bond_amount = bond_amount(
        &storage,
        &BondId {
            source: delegator.clone(),
            validator: validator1.clone(),
        },
        pipeline_epoch,
    )
    .unwrap_or_default();

    #[allow(clippy::disallowed_methods)]
    let self_bond_amount = bond_amount(
        &storage,
        &BondId {
            source: validator1.clone(),
            validator: validator1.clone(),
        },
        pipeline_epoch,
    )
    .unwrap_or_default();

    let val_stake =
        read_validator_stake(&storage, &params, &validator1, pipeline_epoch)
            .unwrap();

    let diff = val_stake - self_bond_amount - del_bond_amount;
    assert!(diff <= 2.into());
}

#[test]
fn test_one_slash_per_block_height() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        unbonding_len: 4,
        validator_stake_threshold: token::Amount::zero(),
        ..Default::default()
    };

    let validator1 = established_address_1();
    let validator2 = established_address_2();

    let gen_validators = [
        GenesisValidator {
            address: validator1.clone(),
            tokens: 100.into(),
            consensus_key: keypair_1().ref_to(),
            protocol_key: keypair_3().ref_to(),
            eth_cold_key: keypair_3().ref_to(),
            eth_hot_key: keypair_3().ref_to(),
            commission_rate: Default::default(),
            max_commission_rate_change: Default::default(),
            metadata: Default::default(),
        },
        GenesisValidator {
            address: validator2.clone(),
            tokens: 100.into(),
            consensus_key: keypair_2().ref_to(),
            protocol_key: keypair_3().ref_to(),
            eth_cold_key: keypair_3().ref_to(),
            eth_hot_key: keypair_3().ref_to(),
            commission_rate: Default::default(),
            max_commission_rate_change: Default::default(),
            metadata: Default::default(),
        },
    ];

    // Genesis
    let current_epoch = storage.in_mem().block.epoch;
    let params = test_init_genesis(
        &mut storage,
        params,
        gen_validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    state.commit_block().unwrap();
    let mut storage = state.restrict_writes_to_write_log();

    let enqueued_slashes = enqueued_slashes_handle();

    let slash11 = Slash {
        block_height: 0,
        epoch: 0.into(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::zero(),
    };
    let slash12 = Slash {
        block_height: 0,
        epoch: 0.into(),
        r#type: SlashType::LightClientAttack,
        rate: Dec::zero(),
    };
    let slash13 = Slash {
        block_height: 1,
        epoch: 0.into(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::zero(),
    };
    let slash21 = Slash {
        block_height: 0,
        epoch: 0.into(),
        r#type: SlashType::LightClientAttack,
        rate: Dec::zero(),
    };
    let slash22 = Slash {
        block_height: 0,
        epoch: 0.into(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::zero(),
    };
    let slash23 = Slash {
        block_height: 1,
        epoch: 0.into(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::zero(),
    };

    let processing_epoch =
        current_epoch + params.slash_processing_epoch_offset();
    let enqueue = |stg: &mut TestState, slash: &Slash, validator: &Address| {
        crate::tests::slash(
            stg,
            &params,
            current_epoch,
            slash.epoch,
            slash.block_height,
            slash.r#type,
            validator,
            current_epoch.next(),
        )
        .unwrap();
    };

    // Enqueue some of the slashes
    enqueue(&mut storage, &slash11, &validator1);
    enqueue(&mut storage, &slash21, &validator2);
    enqueue(&mut storage, &slash13, &validator1);
    enqueue(&mut storage, &slash23, &validator2);

    // Check
    let res = enqueued_slashes
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let exp = BTreeMap::from_iter([(
        processing_epoch,
        BTreeMap::from_iter([
            (
                validator1.clone(),
                BTreeMap::from_iter([(0, slash11), (1, slash13)]),
            ),
            (
                validator2.clone(),
                BTreeMap::from_iter([(0, slash21), (1, slash23)]),
            ),
        ]),
    )]);
    assert_eq!(res, exp);

    // Enqueue new slashes
    enqueue(&mut storage, &slash12, &validator1);
    enqueue(&mut storage, &slash22, &validator2);

    // Check that the slashes are still the same now
    let res = enqueued_slashes
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    assert_eq!(res, exp);
}
