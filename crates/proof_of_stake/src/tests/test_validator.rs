#![allow(clippy::arithmetic_side_effects)]

use std::cmp::min;

use namada_core::address::testing::arb_established_address;
use namada_core::address::{self, Address, EstablishedAddressGen};
use namada_core::chain::Epoch;
use namada_core::dec::Dec;
use namada_core::key::testing::{
    arb_common_keypair, common_sk_from_simple_seed,
};
use namada_core::key::{self, RefTo, common};
use namada_core::token;
use namada_state::testing::{TestFullAccessState, TestState};
use namada_trans_token::credit_tokens;
use proptest::prelude::*;
use proptest::test_runner::Config;
// Use `RUST_LOG=info` (or another tracing level) and `--nocapture` to see
// `tracing` logs from tests
use test_log::test;

use crate::epoched::DEFAULT_NUM_PAST_EPOCHS;
use crate::storage::{
    below_capacity_validator_set_handle, bond_handle,
    consensus_validator_set_handle, find_validator_by_raw_hash,
    get_num_consensus_validators,
    read_below_capacity_validator_set_addresses_with_stake,
    read_consensus_validator_set_addresses_with_stake,
    validator_addresses_handle, validator_consensus_key_handle,
    validator_set_positions_handle, write_validator_address_raw_hash,
};
use crate::tests::helpers::{
    advance_epoch, arb_genesis_validators, arb_params_and_genesis_validators,
    get_tendermint_set_updates,
};
use crate::tests::{
    GovStore, become_validator, bond_tokens, change_consensus_key,
    init_genesis_helper, read_below_threshold_validator_set_addresses,
    test_init_genesis, unbond_tokens, update_validator_deltas, withdraw_tokens,
};
use crate::types::{
    ConsensusValidator, GenesisValidator, Position, ReverseOrdTokenAmount,
    ValidatorSetUpdate, WeightedValidator, into_tm_voting_power,
};
use crate::validator_set_update::{
    insert_validator_into_validator_set, update_validator_set,
};
use crate::{
    BecomeValidator, OwnedPosParams, is_validator, lazy_map,
    staking_token_address,
};

proptest! {
    // Generate arb valid input for `test_become_validator_aux`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_become_validator(

    (pos_params, genesis_validators) in arb_params_and_genesis_validators(Some(5), 1..3),
    new_validator in arb_established_address().prop_map(Address::Established),
    new_validator_consensus_key in arb_common_keypair(),

    ) {
        test_become_validator_aux(pos_params, new_validator,
            new_validator_consensus_key, genesis_validators)
    }
}

/// Test validator initialization.
fn test_become_validator_aux(
    params: OwnedPosParams,
    new_validator: Address,
    new_validator_consensus_key: common::SecretKey,
    validators: Vec<GenesisValidator>,
) {
    // println!(
    //     "Test inputs: {params:?}, new validator: {new_validator}, genesis \
    //      validators: {validators:#?}"
    // );

    let mut state = TestFullAccessState::default();
    let mut s = state.restrict_writes_to_write_log();

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

    // Advance to epoch 1
    current_epoch = advance_epoch(&mut s, &params);

    let num_consensus_before =
        get_num_consensus_validators(&s, current_epoch + params.pipeline_len)
            .unwrap();
    let num_validators_over_thresh = validators
        .iter()
        .filter(|validator| {
            validator.tokens >= params.validator_stake_threshold
        })
        .count();

    assert_eq!(
        min(
            num_validators_over_thresh as u64,
            params.max_validator_slots
        ),
        num_consensus_before
    );
    assert!(!is_validator(&s, &new_validator).unwrap());

    // Credit the `new_validator` account
    let staking_token = staking_token_address(&s);
    let amount = token::Amount::from_uint(100_500_000, 0).unwrap();
    // Credit twice the amount as we're gonna bond it in delegation first, then
    // self-bond
    credit_tokens(&mut s, &staking_token, &new_validator, amount * 2).unwrap();

    // Add a delegation from `new_validator` to `genesis_validator`
    let genesis_validator = &validators.first().unwrap().address;
    bond_tokens(
        &mut s,
        Some(&new_validator),
        genesis_validator,
        amount,
        current_epoch,
        None,
    )
    .unwrap();

    let consensus_key = new_validator_consensus_key.to_public();
    let protocol_sk = common_sk_from_simple_seed(0);
    let protocol_key = protocol_sk.to_public();
    let eth_hot_key = key::common::PublicKey::Secp256k1(
        key::testing::gen_keypair::<key::secp256k1::SigScheme>().ref_to(),
    );
    let eth_cold_key = key::common::PublicKey::Secp256k1(
        key::testing::gen_keypair::<key::secp256k1::SigScheme>().ref_to(),
    );

    // Try to become a validator - it should fail as there is a delegation
    let result = become_validator(
        &mut s,
        BecomeValidator {
            params: &params,
            address: &new_validator,
            consensus_key: &consensus_key,
            protocol_key: &protocol_key,
            eth_cold_key: &eth_cold_key,
            eth_hot_key: &eth_hot_key,
            current_epoch,
            commission_rate: Dec::new(5, 2).expect("Dec creation failed"),
            max_commission_rate_change: Dec::new(5, 2)
                .expect("Dec creation failed"),
            metadata: Default::default(),
            offset_opt: None,
        },
    );
    assert!(result.is_err());
    assert!(!is_validator(&s, &new_validator).unwrap());

    // Unbond the delegation
    unbond_tokens(
        &mut s,
        Some(&new_validator),
        genesis_validator,
        amount,
        current_epoch,
        false,
    )
    .unwrap();

    // Try to become a validator account again - it should pass now
    become_validator(
        &mut s,
        BecomeValidator {
            params: &params,
            address: &new_validator,
            consensus_key: &consensus_key,
            protocol_key: &protocol_key,
            eth_cold_key: &eth_cold_key,
            eth_hot_key: &eth_hot_key,
            current_epoch,
            commission_rate: Dec::new(5, 2).expect("Dec creation failed"),
            max_commission_rate_change: Dec::new(5, 2)
                .expect("Dec creation failed"),
            metadata: Default::default(),
            offset_opt: None,
        },
    )
    .unwrap();
    assert!(is_validator(&s, &new_validator).unwrap());

    let num_consensus_after =
        get_num_consensus_validators(&s, current_epoch + params.pipeline_len)
            .unwrap();
    // The new validator is initialized with no stake and thus is in the
    // below-threshold set
    assert_eq!(num_consensus_before, num_consensus_after);

    // Advance to epoch 2
    current_epoch = advance_epoch(&mut s, &params);

    // Self-bond to the new validator
    bond_tokens(&mut s, None, &new_validator, amount, current_epoch, None)
        .unwrap();

    // Check the bond delta
    let bond_handle = bond_handle(&new_validator, &new_validator);
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let delta = bond_handle.get_delta_val(&s, pipeline_epoch).unwrap();
    assert_eq!(delta, Some(amount));

    // Check the validator in the validator set -
    // If the consensus validator slots are full and all the genesis validators
    // have stake GTE the new validator's self-bond amount, the validator should
    // be added to the below-capacity set, or the consensus otherwise
    if params.max_validator_slots <= validators.len() as u64
        && validators
            .iter()
            .all(|validator| validator.tokens >= amount)
    {
        let set = read_below_capacity_validator_set_addresses_with_stake(
            &s,
            pipeline_epoch,
        )
        .unwrap();
        assert!(set.into_iter().any(
            |WeightedValidator {
                 bonded_stake,
                 address,
             }| {
                address == new_validator && bonded_stake == amount
            }
        ));
    } else {
        let set = read_consensus_validator_set_addresses_with_stake(
            &s,
            pipeline_epoch,
        )
        .unwrap();
        assert!(set.into_iter().any(
            |WeightedValidator {
                 bonded_stake,
                 address,
             }| {
                address == new_validator && bonded_stake == amount
            }
        ));
    }

    // Advance to epoch 3
    current_epoch = advance_epoch(&mut s, &params);

    // Unbond the self-bond
    unbond_tokens(&mut s, None, &new_validator, amount, current_epoch, false)
        .unwrap();

    let withdrawable_offset = params.unbonding_len + params.pipeline_len;

    // Advance to withdrawable epoch
    for _ in 0..withdrawable_offset {
        current_epoch = advance_epoch(&mut s, &params);
    }

    // Withdraw the self-bond
    withdraw_tokens(&mut s, None, &new_validator, current_epoch).unwrap();
}

#[test]
fn test_validator_raw_hash() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let address = address::testing::established_address_1();
    let consensus_sk = key::testing::keypair_1();
    let consensus_pk = consensus_sk.to_public();
    let expected_raw_hash = key::tm_consensus_key_raw_hash(&consensus_pk);

    assert!(
        find_validator_by_raw_hash(&storage, &expected_raw_hash)
            .unwrap()
            .is_none()
    );
    write_validator_address_raw_hash(&mut storage, &address, &consensus_pk)
        .unwrap();
    let found =
        find_validator_by_raw_hash(&storage, &expected_raw_hash).unwrap();
    assert_eq!(found, Some(address));
}

#[test]
fn test_validator_sets() {
    let mut state = TestFullAccessState::default();
    let mut s = state.restrict_writes_to_write_log();
    // Only 3 consensus validator slots
    let params = OwnedPosParams {
        max_validator_slots: 3,
        ..Default::default()
    };
    let addr_seed = "seed";
    let mut address_gen = EstablishedAddressGen::new(addr_seed);
    let mut sk_seed = 0;
    let mut gen_validator = || {
        let res = (
            address_gen.generate_address(addr_seed),
            key::testing::common_sk_from_simple_seed(sk_seed).to_public(),
        );
        // bump the sk seed
        sk_seed += 1;
        res
    };

    // Create genesis validators
    let ((val1, pk1), stake1) =
        (gen_validator(), token::Amount::native_whole(1));
    let ((val2, pk2), stake2) =
        (gen_validator(), token::Amount::native_whole(1));
    let ((val3, pk3), stake3) =
        (gen_validator(), token::Amount::native_whole(10));
    let ((val4, pk4), stake4) =
        (gen_validator(), token::Amount::native_whole(1));
    let ((val5, pk5), stake5) =
        (gen_validator(), token::Amount::native_whole(100));
    let ((val6, pk6), stake6) =
        (gen_validator(), token::Amount::native_whole(1));
    let ((val7, pk7), stake7) =
        (gen_validator(), token::Amount::native_whole(1));
    // println!("\nval1: {val1}, {pk1}, {}", stake1.to_string_native());
    // println!("val2: {val2}, {pk2}, {}", stake2.to_string_native());
    // println!("val3: {val3}, {pk3}, {}", stake3.to_string_native());
    // println!("val4: {val4}, {pk4}, {}", stake4.to_string_native());
    // println!("val5: {val5}, {pk5}, {}", stake5.to_string_native());
    // println!("val6: {val6}, {pk6}, {}", stake6.to_string_native());
    // println!("val7: {val7}, {pk7}, {}", stake7.to_string_native());

    let start_epoch = Epoch::default();
    let epoch = start_epoch;

    let protocol_sk_1 = common_sk_from_simple_seed(0);
    let protocol_sk_2 = common_sk_from_simple_seed(1);

    let params = test_init_genesis(
        &mut s,
        params,
        [
            GenesisValidator {
                address: val1.clone(),
                tokens: stake1,
                consensus_key: pk1.clone(),
                protocol_key: protocol_sk_1.to_public(),
                eth_hot_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                eth_cold_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                commission_rate: Dec::new(1, 1).expect("Dec creation failed"),
                max_commission_rate_change: Dec::new(1, 1)
                    .expect("Dec creation failed"),
                metadata: Default::default(),
            },
            GenesisValidator {
                address: val2.clone(),
                tokens: stake2,
                consensus_key: pk2.clone(),
                protocol_key: protocol_sk_2.to_public(),
                eth_hot_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                eth_cold_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                commission_rate: Dec::new(1, 1).expect("Dec creation failed"),
                max_commission_rate_change: Dec::new(1, 1)
                    .expect("Dec creation failed"),
                metadata: Default::default(),
            },
        ]
        .into_iter(),
        epoch,
    )
    .unwrap();

    // A helper to insert a non-genesis validator
    let insert_validator = |s: &mut TestState,
                            addr,
                            pk: &common::PublicKey,
                            stake: token::Amount,
                            epoch: Epoch| {
        insert_validator_into_validator_set::<_, GovStore<_>>(
            s,
            &params,
            addr,
            stake,
            epoch,
            params.pipeline_len,
        )
        .unwrap();

        update_validator_deltas(s, &params, addr, stake.change(), epoch, None)
            .unwrap();

        // Set their consensus key (needed for
        // `validator_set_update_tendermint` fn)
        validator_consensus_key_handle(addr)
            .set::<_, GovStore<_>>(s, pk.clone(), epoch, params.pipeline_len)
            .unwrap();
    };

    // Advance to EPOCH 1
    //
    // We cannot call `get_tendermint_set_updates` for the genesis state as
    // `validator_set_update_tendermint` is only called 2 blocks before the
    // start of an epoch and so we need to give it a predecessor epoch (see
    // `get_tendermint_set_updates`), which we cannot have on the first
    // epoch. In any way, the initial validator set is given to Tendermint
    // from InitChain, so `validator_set_update_tendermint` is
    // not being used for it.
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Insert another validator with the greater stake 10 NAM
    insert_validator(&mut s, &val3, &pk3, stake3, epoch);
    // Insert validator with stake 1 NAM
    insert_validator(&mut s, &val4, &pk4, stake4, epoch);

    // Validator `val3` and `val4` will be added at pipeline offset (2) - epoch
    // 3
    let val3_and_4_epoch = pipeline_epoch;

    let consensus_vals: Vec<_> = consensus_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(consensus_vals.len(), 3);
    assert!(matches!(
        &consensus_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val1 && stake == &stake1 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val2 && stake == &stake2 && *position == Position(1)
    ));
    assert!(matches!(
        &consensus_vals[2],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val3 && stake == &stake3 && *position == Position(0)
    ));

    // Check tendermint validator set updates - there should be none
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    assert!(tm_updates.is_empty());

    // Advance to EPOCH 2
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Insert another validator with a greater stake still 1000 NAM. It should
    // replace 2nd consensus validator with stake 1, which should become
    // below-capacity
    insert_validator(&mut s, &val5, &pk5, stake5, epoch);
    // Validator `val5` will be added at pipeline offset (2) - epoch 4
    let val5_epoch = pipeline_epoch;

    let consensus_vals: Vec<_> = consensus_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(consensus_vals.len(), 3);
    assert!(matches!(
        &consensus_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val1 && stake == &stake1 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val3 && stake == &stake3 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[2],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val5 && stake == &stake5 && *position == Position(0)
    ));

    let below_capacity_vals: Vec<_> = below_capacity_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(below_capacity_vals.len(), 2);
    assert!(matches!(
        &below_capacity_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val4 && stake == &stake4 && *position == Position(0)
    ));
    assert!(matches!(
        &below_capacity_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val2 && stake == &stake2 && *position == Position(1)
    ));

    // Advance to EPOCH 3
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Check tendermint validator set updates
    assert_eq!(
        val3_and_4_epoch, epoch,
        "val3 and val4 are in the validator sets now"
    );
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    // `val4` is newly added below-capacity, must be skipped in updated in TM
    assert_eq!(tm_updates.len(), 1);
    assert_eq!(
        tm_updates[0],
        ValidatorSetUpdate::Consensus(ConsensusValidator {
            consensus_key: pk3,
            bonded_stake: into_tm_voting_power(
                params.tm_votes_per_token,
                stake3
            ),
        })
    );

    // Insert another validator with a stake 1 NAM. It should be added to the
    // below-capacity set
    insert_validator(&mut s, &val6, &pk6, stake6, epoch);
    // Validator `val6` will be added at pipeline offset (2) - epoch 5
    let val6_epoch = pipeline_epoch;

    let below_capacity_vals: Vec<_> = below_capacity_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(below_capacity_vals.len(), 3);
    assert!(matches!(
        &below_capacity_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val4 && stake == &stake4 && *position == Position(0)
    ));
    assert!(matches!(
        &below_capacity_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val2 && stake == &stake2 && *position == Position(1)
    ));
    assert!(matches!(
        &below_capacity_vals[2],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val6 && stake == &stake6 && *position == Position(2)
    ));

    // Advance to EPOCH 4
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Check tendermint validator set updates
    assert_eq!(val5_epoch, epoch, "val5 is in the validator sets now");
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    assert_eq!(tm_updates.len(), 2);
    assert_eq!(
        tm_updates[0],
        ValidatorSetUpdate::Consensus(ConsensusValidator {
            consensus_key: pk5,
            bonded_stake: into_tm_voting_power(
                params.tm_votes_per_token,
                stake5
            ),
        })
    );
    assert_eq!(tm_updates[1], ValidatorSetUpdate::Deactivated(pk2));

    // Unbond some stake from val1, it should be swapped with the greatest
    // below-capacity validator val2 into the below-capacity set. The stake of
    // val1 will go below 1 NAM, which is the validator_stake_threshold, so it
    // will enter the below-threshold validator set.
    let unbond = token::Amount::from_uint(500_000, 0).unwrap();
    // let stake1 = stake1 - unbond;

    // Because `update_validator_set` and `update_validator_deltas` are
    // effective from pipeline offset, we use pipeline epoch for the rest of the
    // checks
    update_validator_set::<_, GovStore<_>>(
        &mut s,
        &params,
        &val1,
        -unbond.change(),
        epoch,
        None,
    )
    .unwrap();
    update_validator_deltas(
        &mut s,
        &params,
        &val1,
        -unbond.change(),
        epoch,
        None,
    )
    .unwrap();
    // Epoch 6
    let val1_unbond_epoch = pipeline_epoch;

    let consensus_vals: Vec<_> = consensus_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(consensus_vals.len(), 3);
    assert!(matches!(
        &consensus_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val4 && stake == &stake4 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val3 && stake == &stake3 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[2],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val5 && stake == &stake5 && *position == Position(0)
    ));

    let below_capacity_vals: Vec<_> = below_capacity_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(below_capacity_vals.len(), 2);
    assert!(matches!(
        &below_capacity_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val2 && stake == &stake2 && *position == Position(1)
    ));
    assert!(matches!(
        &below_capacity_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val6 && stake == &stake6 && *position == Position(2)
    ));

    let below_threshold_vals =
        read_below_threshold_validator_set_addresses(&s, pipeline_epoch)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();

    assert_eq!(below_threshold_vals.len(), 1);
    assert_eq!(&below_threshold_vals[0], &val1);

    // Advance to EPOCH 5
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Check tendermint validator set updates
    assert_eq!(val6_epoch, epoch, "val6 is in the validator sets now");
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    assert!(tm_updates.is_empty());

    // Insert another validator with stake 1 - it should be added to below
    // capacity set
    insert_validator(&mut s, &val7, &pk7, stake7, epoch);
    // Epoch 7
    let val7_epoch = pipeline_epoch;

    let consensus_vals: Vec<_> = consensus_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(consensus_vals.len(), 3);
    assert!(matches!(
        &consensus_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val4 && stake == &stake4 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val3 && stake == &stake3 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[2],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val5 && stake == &stake5 && *position == Position(0)
    ));

    let below_capacity_vals: Vec<_> = below_capacity_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(below_capacity_vals.len(), 3);
    assert!(matches!(
        &below_capacity_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val2 && stake == &stake2 && *position == Position(1)
    ));
    assert!(matches!(
        &below_capacity_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val6 && stake == &stake6 && *position == Position(2)
    ));
    assert!(matches!(
        &below_capacity_vals[2],
        (
            lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
            },
            address
        )
        if address == &val7 && stake == &stake7 && *position == Position(3)
    ));

    let below_threshold_vals =
        read_below_threshold_validator_set_addresses(&s, pipeline_epoch)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();

    assert_eq!(below_threshold_vals.len(), 1);
    assert_eq!(&below_threshold_vals[0], &val1);

    // Advance to EPOCH 6
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Check tendermint validator set updates
    assert_eq!(val1_unbond_epoch, epoch, "val1's unbond is applied now");
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    assert_eq!(tm_updates.len(), 2);
    assert_eq!(
        tm_updates[0],
        ValidatorSetUpdate::Consensus(ConsensusValidator {
            consensus_key: pk4.clone(),
            bonded_stake: into_tm_voting_power(
                params.tm_votes_per_token,
                stake4
            ),
        })
    );
    assert_eq!(tm_updates[1], ValidatorSetUpdate::Deactivated(pk1));

    // Bond some stake to val6, it should be swapped with the lowest
    // consensus validator val2 into the consensus set
    let bond = token::Amount::from_uint(500_000, 0).unwrap();
    let stake6 = stake6 + bond;

    update_validator_set::<_, GovStore<_>>(
        &mut s,
        &params,
        &val6,
        bond.change(),
        epoch,
        None,
    )
    .unwrap();
    update_validator_deltas(&mut s, &params, &val6, bond.change(), epoch, None)
        .unwrap();
    let val6_bond_epoch = pipeline_epoch;

    let consensus_vals: Vec<_> = consensus_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(consensus_vals.len(), 3);
    assert!(matches!(
        &consensus_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val6 && stake == &stake6 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val3 && stake == &stake3 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[2],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val5 && stake == &stake5 && *position == Position(0)
    ));

    let below_capacity_vals: Vec<_> = below_capacity_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(below_capacity_vals.len(), 3);

    assert!(matches!(
        &below_capacity_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val2 && stake == &stake2 && *position == Position(1)
    ));
    assert!(matches!(
        &below_capacity_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val7 && stake == &stake7 && *position == Position(3)
    ));
    assert!(matches!(
        &below_capacity_vals[2],
        (
            lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
            },
            address
        )
        if address == &val4 && stake == &stake4 && *position == Position(4)
    ));

    let below_threshold_vals =
        read_below_threshold_validator_set_addresses(&s, pipeline_epoch)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();

    assert_eq!(below_threshold_vals.len(), 1);
    assert_eq!(&below_threshold_vals[0], &val1);

    // Advance to EPOCH 7
    let epoch = advance_epoch(&mut s, &params);
    assert_eq!(val7_epoch, epoch, "val6 is in the validator sets now");

    // Check tendermint validator set updates
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    assert!(tm_updates.is_empty());

    // Advance to EPOCH 8
    let epoch = advance_epoch(&mut s, &params);

    // Check tendermint validator set updates
    assert_eq!(val6_bond_epoch, epoch, "val5's bond is applied now");
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    // dbg!(&tm_updates);
    assert_eq!(tm_updates.len(), 2);
    assert_eq!(
        tm_updates[0],
        ValidatorSetUpdate::Consensus(ConsensusValidator {
            consensus_key: pk6,
            bonded_stake: into_tm_voting_power(
                params.tm_votes_per_token,
                stake6
            ),
        })
    );
    assert_eq!(tm_updates[1], ValidatorSetUpdate::Deactivated(pk4));

    // Check that the below-capacity validator set was purged for the old epochs
    // but that the consensus_validator_set was not
    let last_epoch = epoch;
    for e in Epoch::iter_bounds_inclusive(
        start_epoch,
        last_epoch
            .saturating_sub(Epoch(DEFAULT_NUM_PAST_EPOCHS))
            .saturating_sub(Epoch(1)),
    ) {
        assert!(
            !consensus_validator_set_handle()
                .at(&e)
                .is_empty(&s)
                .unwrap()
        );
        assert!(
            below_capacity_validator_set_handle()
                .at(&e)
                .is_empty(&s)
                .unwrap()
        );
    }
}

/// When a consensus set validator with 0 voting power adds a bond in the same
/// epoch as another below-capacity set validator with 0 power, but who adds
/// more bonds than the validator who is in the consensus set, they get swapped
/// in the sets. But if both of their new voting powers are still 0 after
/// bonding, the newly below-capacity validator must not be given to tendermint
/// with 0 voting power, because it wasn't it its set before
#[test]
fn test_validator_sets_swap() {
    let mut state = TestFullAccessState::default();
    let mut s = state.restrict_writes_to_write_log();
    // Only 2 consensus validator slots
    let params = OwnedPosParams {
        max_validator_slots: 2,
        // Set the stake threshold to 0 so no validators are in the
        // below-threshold set
        validator_stake_threshold: token::Amount::zero(),
        // Set 0.1 votes per token
        tm_votes_per_token: Dec::new(1, 1).expect("Dec creation failed"),
        ..Default::default()
    };

    let addr_seed = "seed";
    let mut address_gen = EstablishedAddressGen::new(addr_seed);
    let mut sk_seed = 0;
    let mut gen_validator = || {
        let res = (
            address_gen.generate_address(addr_seed),
            key::testing::common_sk_from_simple_seed(sk_seed).to_public(),
        );
        // bump the sk seed
        sk_seed += 1;
        res
    };

    // Start with two genesis validators, one with 1 voting power and other 0
    let epoch = Epoch::default();
    // 1M voting power
    let ((val1, pk1), stake1) =
        (gen_validator(), token::Amount::native_whole(10));
    // 0 voting power
    let ((val2, pk2), stake2) =
        (gen_validator(), token::Amount::from_uint(5, 0).unwrap());
    // 0 voting power
    let ((val3, pk3), stake3) =
        (gen_validator(), token::Amount::from_uint(5, 0).unwrap());
    // println!("val1: {val1}, {pk1}, {}", stake1.to_string_native());
    // println!("val2: {val2}, {pk2}, {}", stake2.to_string_native());
    // println!("val3: {val3}, {pk3}, {}", stake3.to_string_native());

    let protocol_sk_1 = common_sk_from_simple_seed(0);
    let protocol_sk_2 = common_sk_from_simple_seed(1);

    let params = test_init_genesis(
        &mut s,
        params,
        [
            GenesisValidator {
                address: val1,
                tokens: stake1,
                consensus_key: pk1,
                protocol_key: protocol_sk_1.to_public(),
                eth_hot_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                eth_cold_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                commission_rate: Dec::new(1, 1).expect("Dec creation failed"),
                max_commission_rate_change: Dec::new(1, 1)
                    .expect("Dec creation failed"),
                metadata: Default::default(),
            },
            GenesisValidator {
                address: val2.clone(),
                tokens: stake2,
                consensus_key: pk2,
                protocol_key: protocol_sk_2.to_public(),
                eth_hot_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                eth_cold_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                commission_rate: Dec::new(1, 1).expect("Dec creation failed"),
                max_commission_rate_change: Dec::new(1, 1)
                    .expect("Dec creation failed"),
                metadata: Default::default(),
            },
        ]
        .into_iter(),
        epoch,
    )
    .unwrap();

    // A helper to insert a non-genesis validator
    let insert_validator = |s: &mut TestState,
                            addr,
                            pk: &common::PublicKey,
                            stake: token::Amount,
                            epoch: Epoch| {
        insert_validator_into_validator_set::<_, GovStore<_>>(
            s,
            &params,
            addr,
            stake,
            epoch,
            params.pipeline_len,
        )
        .unwrap();

        update_validator_deltas(s, &params, addr, stake.change(), epoch, None)
            .unwrap();

        // Set their consensus key (needed for
        // `validator_set_update_tendermint` fn)
        validator_consensus_key_handle(addr)
            .set::<_, GovStore<_>>(s, pk.clone(), epoch, params.pipeline_len)
            .unwrap();
    };

    // Advance to EPOCH 1
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Insert another validator with 0 voting power
    insert_validator(&mut s, &val3, &pk3, stake3, epoch);

    assert_eq!(stake2, stake3);

    // Add 2 bonds, one for val2 and greater one for val3
    let bonds_epoch_1 = pipeline_epoch;
    let bond2 = token::Amount::from_uint(1, 0).unwrap();
    let stake2 = stake2 + bond2;
    let bond3 = token::Amount::from_uint(4, 0).unwrap();
    let stake3 = stake3 + bond3;

    assert!(stake2 < stake3);
    assert_eq!(into_tm_voting_power(params.tm_votes_per_token, stake2), 0);
    assert_eq!(into_tm_voting_power(params.tm_votes_per_token, stake3), 0);

    update_validator_set::<_, GovStore<_>>(
        &mut s,
        &params,
        &val2,
        bond2.change(),
        epoch,
        None,
    )
    .unwrap();
    update_validator_deltas(
        &mut s,
        &params,
        &val2,
        bond2.change(),
        epoch,
        None,
    )
    .unwrap();

    update_validator_set::<_, GovStore<_>>(
        &mut s,
        &params,
        &val3,
        bond3.change(),
        epoch,
        None,
    )
    .unwrap();
    update_validator_deltas(
        &mut s,
        &params,
        &val3,
        bond3.change(),
        epoch,
        None,
    )
    .unwrap();

    // Advance to EPOCH 2
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Add 2 more bonds, same amount for `val2` and val3`
    let bonds_epoch_2 = pipeline_epoch;
    let bonds = token::Amount::native_whole(1);
    let stake2 = stake2 + bonds;
    let stake3 = stake3 + bonds;
    assert!(stake2 < stake3);
    assert_eq!(
        into_tm_voting_power(params.tm_votes_per_token, stake2),
        into_tm_voting_power(params.tm_votes_per_token, stake3)
    );

    update_validator_set::<_, GovStore<_>>(
        &mut s,
        &params,
        &val2,
        bonds.change(),
        epoch,
        None,
    )
    .unwrap();
    update_validator_deltas(
        &mut s,
        &params,
        &val2,
        bonds.change(),
        epoch,
        None,
    )
    .unwrap();

    update_validator_set::<_, GovStore<_>>(
        &mut s,
        &params,
        &val3,
        bonds.change(),
        epoch,
        None,
    )
    .unwrap();
    update_validator_deltas(
        &mut s,
        &params,
        &val3,
        bonds.change(),
        epoch,
        None,
    )
    .unwrap();

    // Advance to EPOCH 3
    let epoch = advance_epoch(&mut s, &params);

    // Check tendermint validator set updates
    assert_eq!(bonds_epoch_1, epoch);
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    // `val2` must not be given to tendermint - even though it was in the
    // consensus set, its voting power was 0, so it wasn't in TM set before the
    // bond
    assert!(tm_updates.is_empty());

    // Advance to EPOCH 4
    let epoch = advance_epoch(&mut s, &params);

    // Check tendermint validator set updates
    assert_eq!(bonds_epoch_2, epoch);
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    // dbg!(&tm_updates);
    assert_eq!(tm_updates.len(), 1);
    // `val2` must not be given to tendermint as it was and still is below
    // capacity
    assert_eq!(
        tm_updates[0],
        ValidatorSetUpdate::Consensus(ConsensusValidator {
            consensus_key: pk3.clone(),
            bonded_stake: into_tm_voting_power(
                params.tm_votes_per_token,
                stake3
            ),
        })
    );

    // Now give val2 stake such that it bumps val3 out of the consensus set, and
    // also change val2's consensus key
    let pipeline_epoch = epoch + params.pipeline_len;
    let bonds_epoch_3 = pipeline_epoch;
    let bonds = token::Amount::native_whole(1);
    let stake2 = stake2 + bonds;

    update_validator_set::<_, GovStore<_>>(
        &mut s,
        &params,
        &val2,
        bonds.change(),
        epoch,
        None,
    )
    .unwrap();
    update_validator_deltas(
        &mut s,
        &params,
        &val2,
        bonds.change(),
        epoch,
        None,
    )
    .unwrap();

    sk_seed += 1;
    let new_ck2 = key::testing::common_sk_from_simple_seed(sk_seed).to_public();
    change_consensus_key(&mut s, &val2, &new_ck2, epoch).unwrap();

    // Advance to EPOCH 5
    let epoch = advance_epoch(&mut s, &params);

    // Check tendermint validator set updates
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    assert!(tm_updates.is_empty());

    // Advance to EPOCH 6
    let epoch = advance_epoch(&mut s, &params);
    assert_eq!(epoch, bonds_epoch_3);

    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    // dbg!(&tm_updates);
    assert_eq!(tm_updates.len(), 2);
    assert_eq!(
        tm_updates,
        vec![
            ValidatorSetUpdate::Consensus(ConsensusValidator {
                consensus_key: new_ck2,
                bonded_stake: into_tm_voting_power(
                    params.tm_votes_per_token,
                    stake2
                ),
            }),
            ValidatorSetUpdate::Deactivated(pk3),
        ]
    );
}

proptest! {
    // Generate arb valid input for `test_purge_validator_information_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_purge_validator_information(

        genesis_validators in arb_genesis_validators(4..5, None),

    ) {
        test_purge_validator_information_aux( genesis_validators)
    }
}

/// Test validator initialization.
fn test_purge_validator_information_aux(validators: Vec<GenesisValidator>) {
    let owned = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    let mut state = TestFullAccessState::default();
    let mut s = state.restrict_writes_to_write_log();
    let mut current_epoch = s.in_mem().block.epoch;

    // Genesis
    let gov_params = namada_governance::parameters::GovernanceParameters {
        max_proposal_period: 5,
        ..Default::default()
    };

    gov_params.init_storage(&mut s).unwrap();
    let params =
        crate::read_non_pos_owned_params::<_, GovStore<_>>(&s, owned).unwrap();
    init_genesis_helper(&mut s, &params, validators.into_iter(), current_epoch)
        .unwrap();

    state.commit_block().unwrap();
    let mut s = state.restrict_writes_to_write_log();

    let default_past_epochs = 2;
    let consensus_val_set_len =
        gov_params.max_proposal_period + default_past_epochs;

    let consensus_val_set = consensus_validator_set_handle();
    // let below_cap_val_set = below_capacity_validator_set_handle();
    let validator_positions = validator_set_positions_handle();
    let all_validator_addresses = validator_addresses_handle();

    let check_is_data = |storage: &TestState<'_, _, _>, start: Epoch, end: Epoch| {
        for ep in Epoch::iter_bounds_inclusive(start, end) {
            assert!(!consensus_val_set.at(&ep).is_empty(storage).unwrap());
            // assert!(!below_cap_val_set.at(&ep).is_empty(storage).
            // unwrap());
            assert!(!validator_positions.at(&ep).is_empty(storage).unwrap());
            assert!(
                !all_validator_addresses.at(&ep).is_empty(storage).unwrap()
            );
        }
    };

    // Check that there is validator data for epochs 0 - pipeline_len
    check_is_data(&s, current_epoch, Epoch(params.owned.pipeline_len));
    assert_eq!(
        consensus_val_set.get_last_update(&s).unwrap().unwrap(),
        Epoch(0)
    );
    assert_eq!(
        validator_positions.get_last_update(&s).unwrap().unwrap(),
        Epoch(0)
    );
    assert_eq!(
        validator_positions.get_last_update(&s).unwrap().unwrap(),
        Epoch(0)
    );

    // Advance to epoch `default_past_epochs`
    for _ in 0..default_past_epochs {
        current_epoch = advance_epoch(&mut s, &params);
    }
    assert_eq!(s.in_mem().block.epoch.0, default_past_epochs);
    assert_eq!(current_epoch.0, default_past_epochs);

    check_is_data(
        &s,
        Epoch(0),
        Epoch(params.owned.pipeline_len + default_past_epochs),
    );
    assert_eq!(
        consensus_val_set.get_last_update(&s).unwrap().unwrap(),
        Epoch(default_past_epochs)
    );
    assert_eq!(
        validator_positions.get_last_update(&s).unwrap().unwrap(),
        Epoch(default_past_epochs)
    );
    assert_eq!(
        validator_positions.get_last_update(&s).unwrap().unwrap(),
        Epoch(default_past_epochs)
    );

    current_epoch = advance_epoch(&mut s, &params);
    assert_eq!(current_epoch.0, default_past_epochs + 1);

    check_is_data(
        &s,
        Epoch(1),
        Epoch(params.pipeline_len + default_past_epochs + 1),
    );
    assert!(!consensus_val_set.at(&Epoch(0)).is_empty(&s).unwrap());
    assert!(validator_positions.at(&Epoch(0)).is_empty(&s).unwrap());
    assert!(all_validator_addresses.at(&Epoch(0)).is_empty(&s).unwrap());

    // Advance to the epoch `consensus_val_set_len` + 1
    loop {
        assert!(!consensus_val_set.at(&Epoch(0)).is_empty(&s).unwrap());

        current_epoch = advance_epoch(&mut s, &params);
        if current_epoch.0 == consensus_val_set_len + 1 {
            break;
        }
    }

    assert!(consensus_val_set.at(&Epoch(0)).is_empty(&s).unwrap());

    current_epoch = advance_epoch(&mut s, &params);
    for ep in Epoch::default().iter_range(2) {
        assert!(consensus_val_set.at(&ep).is_empty(&s).unwrap());
    }
    for ep in Epoch::iter_bounds_inclusive(
        Epoch(2),
        current_epoch + params.pipeline_len,
    ) {
        assert!(!consensus_val_set.at(&ep).is_empty(&s).unwrap());
    }
}
