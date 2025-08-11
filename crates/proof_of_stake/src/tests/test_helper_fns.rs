#![allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]

use std::collections::{BTreeMap, BTreeSet};

use namada_core::address::testing::{
    established_address_1, established_address_2, established_address_3,
};
use namada_core::chain::Epoch;
use namada_core::dec::Dec;
use namada_core::storage::Key;
use namada_core::token;
use namada_state::testing::TestFullAccessState;

use crate::lazy_map::NestedMap;
use crate::slashing::{
    apply_list_slashes, compute_amount_after_slashing_unbond,
    compute_amount_after_slashing_withdraw, compute_bond_at_epoch,
    compute_slash_bond_at_epoch, compute_slashable_amount, slash_redelegation,
    slash_validator, slash_validator_redelegation,
};
use crate::storage::{
    bond_handle, delegator_redelegated_bonds_handle, total_bonded_handle,
    total_unbonded_handle, validator_outgoing_redelegations_handle,
    validator_slashes_handle, validator_total_redelegated_bonded_handle,
    validator_total_redelegated_unbonded_handle, write_pos_params,
};
use crate::tests::GovStore;
use crate::types::{
    EagerRedelegatedBondsMap, RedelegatedTokens, Slash, SlashType,
};
use crate::{
    EagerRedelegatedUnbonds, FoldRedelegatedBondsResult, LazyCollection,
    ModifiedRedelegation, OwnedPosParams, compute_modified_redelegation,
    compute_new_redelegated_unbonds, find_bonds_to_remove,
    fold_and_slash_redelegated_bonds,
};

/// `iterateBondsUpToAmountTest`
#[test]
fn test_find_bonds_to_remove() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let gov_params =
        namada_governance::parameters::GovernanceParameters::default();
    gov_params.init_storage(&mut storage).unwrap();
    write_pos_params(&mut storage, &OwnedPosParams::default()).unwrap();

    let source = established_address_1();
    let validator = established_address_2();
    let bond_handle = bond_handle(&source, &validator);

    let (e1, e2, e6) = (Epoch(1), Epoch(2), Epoch(6));

    bond_handle
        .set::<_, GovStore<_>>(&mut storage, token::Amount::from(5), e1, 0)
        .unwrap();
    bond_handle
        .set::<_, GovStore<_>>(&mut storage, token::Amount::from(3), e2, 0)
        .unwrap();
    bond_handle
        .set::<_, GovStore<_>>(&mut storage, token::Amount::from(8), e6, 0)
        .unwrap();

    // Test 1
    let bonds_for_removal = find_bonds_to_remove(
        &storage,
        &bond_handle.get_data_handler(),
        token::Amount::from(8),
    )
    .unwrap();
    assert_eq!(
        bonds_for_removal.epochs,
        vec![e6].into_iter().collect::<BTreeSet<Epoch>>()
    );
    assert!(bonds_for_removal.new_entry.is_none());

    // Test 2
    let bonds_for_removal = find_bonds_to_remove(
        &storage,
        &bond_handle.get_data_handler(),
        token::Amount::from(10),
    )
    .unwrap();
    assert_eq!(
        bonds_for_removal.epochs,
        vec![e6].into_iter().collect::<BTreeSet<Epoch>>()
    );
    assert_eq!(
        bonds_for_removal.new_entry,
        Some((Epoch(2), token::Amount::from(1)))
    );

    // Test 3
    let bonds_for_removal = find_bonds_to_remove(
        &storage,
        &bond_handle.get_data_handler(),
        token::Amount::from(11),
    )
    .unwrap();
    assert_eq!(
        bonds_for_removal.epochs,
        vec![e6, e2].into_iter().collect::<BTreeSet<Epoch>>()
    );
    assert!(bonds_for_removal.new_entry.is_none());

    // Test 4
    let bonds_for_removal = find_bonds_to_remove(
        &storage,
        &bond_handle.get_data_handler(),
        token::Amount::from(12),
    )
    .unwrap();
    assert_eq!(
        bonds_for_removal.epochs,
        vec![e6, e2].into_iter().collect::<BTreeSet<Epoch>>()
    );
    assert_eq!(
        bonds_for_removal.new_entry,
        Some((Epoch(1), token::Amount::from(4)))
    );
}

/// `computeModifiedRedelegationTest`
#[test]
fn test_compute_modified_redelegation() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let validator1 = established_address_1();
    let validator2 = established_address_2();
    let owner = established_address_3();
    let outer_epoch = Epoch(0);

    let mut alice = validator1.clone();
    let mut bob = validator2.clone();

    // Ensure a ranking order of alice > bob
    if bob > alice {
        alice = validator2;
        bob = validator1;
    }
    println!("\n\nalice = {}\nbob   = {}\n", &alice, &bob);

    // Fill redelegated bonds in storage
    let redelegated_bonds_map = delegator_redelegated_bonds_handle(&owner)
        .at(&alice)
        .at(&outer_epoch);
    redelegated_bonds_map
        .at(&alice)
        .insert(&mut storage, Epoch(2), token::Amount::from(6))
        .unwrap();
    redelegated_bonds_map
        .at(&alice)
        .insert(&mut storage, Epoch(4), token::Amount::from(7))
        .unwrap();
    redelegated_bonds_map
        .at(&bob)
        .insert(&mut storage, Epoch(1), token::Amount::from(5))
        .unwrap();
    redelegated_bonds_map
        .at(&bob)
        .insert(&mut storage, Epoch(4), token::Amount::from(7))
        .unwrap();

    // Test cases 1 and 2
    let mr1 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        token::Amount::from(25),
    )
    .unwrap();
    let mr2 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        token::Amount::from(30),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        ..Default::default()
    };

    assert_eq!(mr1, exp_mr);
    assert_eq!(mr2, exp_mr);

    // Test case 3
    let mr3 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        token::Amount::from(7),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        validators_to_remove: BTreeSet::from_iter([bob.clone()]),
        validator_to_modify: Some(bob.clone()),
        epochs_to_remove: BTreeSet::from_iter([Epoch(4)]),
        ..Default::default()
    };
    assert_eq!(mr3, exp_mr);

    // Test case 4
    let mr4 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        token::Amount::from(8),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        validators_to_remove: BTreeSet::from_iter([bob.clone()]),
        validator_to_modify: Some(bob.clone()),
        epochs_to_remove: BTreeSet::from_iter([Epoch(1), Epoch(4)]),
        epoch_to_modify: Some(Epoch(1)),
        new_amount: Some(4.into()),
    };
    assert_eq!(mr4, exp_mr);

    // Test case 5
    let mr5 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        12.into(),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        validators_to_remove: BTreeSet::from_iter([bob.clone()]),
        ..Default::default()
    };
    assert_eq!(mr5, exp_mr);

    // Test case 6
    let mr6 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        14.into(),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        validators_to_remove: BTreeSet::from_iter([alice.clone(), bob.clone()]),
        validator_to_modify: Some(alice.clone()),
        epochs_to_remove: BTreeSet::from_iter([Epoch(4)]),
        epoch_to_modify: Some(Epoch(4)),
        new_amount: Some(5.into()),
    };
    assert_eq!(mr6, exp_mr);

    // Test case 7
    let mr7 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        19.into(),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        validators_to_remove: BTreeSet::from_iter([alice.clone(), bob.clone()]),
        validator_to_modify: Some(alice.clone()),
        epochs_to_remove: BTreeSet::from_iter([Epoch(4)]),
        ..Default::default()
    };
    assert_eq!(mr7, exp_mr);

    // Test case 8
    let mr8 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        21.into(),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        validators_to_remove: BTreeSet::from_iter([alice.clone(), bob]),
        validator_to_modify: Some(alice),
        epochs_to_remove: BTreeSet::from_iter([Epoch(2), Epoch(4)]),
        epoch_to_modify: Some(Epoch(2)),
        new_amount: Some(4.into()),
    };
    assert_eq!(mr8, exp_mr);
}

/// `computeBondAtEpochTest`
#[test]
fn test_compute_bond_at_epoch() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        pipeline_len: 2,
        unbonding_len: 4,
        cubic_slashing_window_length: 1,
        ..Default::default()
    };
    let alice = established_address_1();
    let bob = established_address_2();

    // Test 1
    let res = compute_bond_at_epoch(
        &storage,
        &params,
        &bob,
        12.into(),
        3.into(),
        23.into(),
        Some(&Default::default()),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 23.into());

    // Test 2
    validator_slashes_handle(&bob)
        .push(
            &mut storage,
            Slash {
                epoch: 4.into(),
                block_height: 0,
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    let res = compute_bond_at_epoch(
        &storage,
        &params,
        &bob,
        12.into(),
        3.into(),
        23.into(),
        Some(&Default::default()),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 0.into());

    // Test 3
    validator_slashes_handle(&bob).pop(&mut storage).unwrap();
    let mut redel_bonds = EagerRedelegatedBondsMap::default();
    redel_bonds.insert(
        alice.clone(),
        BTreeMap::from_iter([(Epoch(1), token::Amount::from(5))]),
    );
    let res = compute_bond_at_epoch(
        &storage,
        &params,
        &bob,
        12.into(),
        3.into(),
        23.into(),
        Some(&redel_bonds),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 23.into());

    // Test 4
    validator_slashes_handle(&bob)
        .push(
            &mut storage,
            Slash {
                epoch: 4.into(),
                block_height: 0,
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    let res = compute_bond_at_epoch(
        &storage,
        &params,
        &bob,
        12.into(),
        3.into(),
        23.into(),
        Some(&redel_bonds),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 0.into());

    // Test 5
    validator_slashes_handle(&bob).pop(&mut storage).unwrap();
    validator_slashes_handle(&alice)
        .push(
            &mut storage,
            Slash {
                epoch: 6.into(),
                block_height: 0,
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    let res = compute_bond_at_epoch(
        &storage,
        &params,
        &bob,
        12.into(),
        3.into(),
        23.into(),
        Some(&redel_bonds),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 23.into());

    // Test 6
    validator_slashes_handle(&alice).pop(&mut storage).unwrap();
    validator_slashes_handle(&alice)
        .push(
            &mut storage,
            Slash {
                epoch: 4.into(),
                block_height: 0,
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    let res = compute_bond_at_epoch(
        &storage,
        &params,
        &bob,
        18.into(),
        9.into(),
        23.into(),
        Some(&redel_bonds),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 18.into());
}

/// `computeSlashBondAtEpochTest`
#[test]
fn test_compute_slash_bond_at_epoch() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        pipeline_len: 2,
        unbonding_len: 4,
        cubic_slashing_window_length: 1,
        ..Default::default()
    };
    let alice = established_address_1();
    let bob = established_address_2();

    let current_epoch = Epoch(20);
    let infraction_epoch =
        current_epoch - params.slash_processing_epoch_offset();

    let redelegated_bond = BTreeMap::from_iter([(
        alice,
        BTreeMap::from_iter([(infraction_epoch - 4, token::Amount::from(10))]),
    )]);

    // Test 1
    let res = compute_slash_bond_at_epoch(
        &storage,
        &params,
        &bob,
        current_epoch.next(),
        infraction_epoch,
        infraction_epoch - 2,
        30.into(),
        Some(&Default::default()),
        Dec::one(),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 30.into());

    // Test 2
    let res = compute_slash_bond_at_epoch(
        &storage,
        &params,
        &bob,
        current_epoch.next(),
        infraction_epoch,
        infraction_epoch - 2,
        30.into(),
        Some(&redelegated_bond),
        Dec::one(),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 30.into());

    // Test 3
    validator_slashes_handle(&bob)
        .push(
            &mut storage,
            Slash {
                epoch: infraction_epoch.prev().unwrap(),
                block_height: 0,
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    let res = compute_slash_bond_at_epoch(
        &storage,
        &params,
        &bob,
        current_epoch.next(),
        infraction_epoch,
        infraction_epoch - 2,
        30.into(),
        Some(&Default::default()),
        Dec::one(),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 0.into());

    // Test 4
    let res = compute_slash_bond_at_epoch(
        &storage,
        &params,
        &bob,
        current_epoch.next(),
        infraction_epoch,
        infraction_epoch - 2,
        30.into(),
        Some(&redelegated_bond),
        Dec::one(),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 0.into());
}

/// `computeNewRedelegatedUnbondsTest`
#[test]
fn test_compute_new_redelegated_unbonds() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let alice = established_address_1();
    let bob = established_address_2();

    let key = Key::parse("testing").unwrap();
    let redelegated_bonds = NestedMap::<Epoch, RedelegatedTokens>::open(key);

    // Populate the lazy and eager maps
    let (ep1, ep2, ep4, ep5, ep6, ep7) =
        (Epoch(1), Epoch(2), Epoch(4), Epoch(5), Epoch(6), Epoch(7));
    let keys_and_values = vec![
        (ep5, alice.clone(), ep2, 1),
        (ep5, alice.clone(), ep4, 1),
        (ep7, alice.clone(), ep2, 1),
        (ep7, alice.clone(), ep4, 1),
        (ep5, bob.clone(), ep1, 1),
        (ep5, bob.clone(), ep4, 2),
        (ep7, bob.clone(), ep1, 1),
        (ep7, bob.clone(), ep4, 2),
    ];
    let mut eager_map = BTreeMap::<Epoch, EagerRedelegatedBondsMap>::new();
    for (outer_ep, address, inner_ep, amount) in keys_and_values {
        redelegated_bonds
            .at(&outer_ep)
            .at(&address)
            .insert(&mut storage, inner_ep, token::Amount::from(amount))
            .unwrap();
        eager_map
            .entry(outer_ep)
            .or_default()
            .entry(address.clone())
            .or_default()
            .insert(inner_ep, token::Amount::from(amount));
    }

    // Different ModifiedRedelegation objects for testing
    let empty_mr = ModifiedRedelegation::default();
    let all_mr = ModifiedRedelegation {
        epoch: Some(ep7),
        validators_to_remove: BTreeSet::from_iter([alice.clone(), bob.clone()]),
        validator_to_modify: None,
        epochs_to_remove: Default::default(),
        epoch_to_modify: None,
        new_amount: None,
    };
    let mod_val_mr = ModifiedRedelegation {
        epoch: Some(ep7),
        validators_to_remove: BTreeSet::from_iter([alice.clone()]),
        validator_to_modify: None,
        epochs_to_remove: Default::default(),
        epoch_to_modify: None,
        new_amount: None,
    };
    let mod_val_partial_mr = ModifiedRedelegation {
        epoch: Some(ep7),
        validators_to_remove: BTreeSet::from_iter([alice.clone(), bob.clone()]),
        validator_to_modify: Some(bob.clone()),
        epochs_to_remove: BTreeSet::from_iter([ep1]),
        epoch_to_modify: None,
        new_amount: None,
    };
    let mod_epoch_partial_mr = ModifiedRedelegation {
        epoch: Some(ep7),
        validators_to_remove: BTreeSet::from_iter([alice, bob.clone()]),
        validator_to_modify: Some(bob.clone()),
        epochs_to_remove: BTreeSet::from_iter([ep1, ep4]),
        epoch_to_modify: Some(ep4),
        new_amount: Some(token::Amount::from(1)),
    };

    // Test case 1
    let res = compute_new_redelegated_unbonds(
        &storage,
        &redelegated_bonds,
        &Default::default(),
        &empty_mr,
    )
    .unwrap();
    assert_eq!(res, Default::default());

    let set5 = BTreeSet::<Epoch>::from_iter([ep5]);
    let set56 = BTreeSet::<Epoch>::from_iter([ep5, ep6]);

    // Test case 2
    let res = compute_new_redelegated_unbonds(
        &storage,
        &redelegated_bonds,
        &set5,
        &empty_mr,
    )
    .unwrap();
    let mut exp_res = eager_map.clone();
    exp_res.remove(&ep7);
    assert_eq!(res, exp_res);

    // Test case 3
    let res = compute_new_redelegated_unbonds(
        &storage,
        &redelegated_bonds,
        &set56,
        &empty_mr,
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 4
    println!("\nTEST CASE 4\n");
    let res = compute_new_redelegated_unbonds(
        &storage,
        &redelegated_bonds,
        &set56,
        &all_mr,
    )
    .unwrap();
    assert_eq!(res, eager_map);

    // Test case 5
    let res = compute_new_redelegated_unbonds(
        &storage,
        &redelegated_bonds,
        &set56,
        &mod_val_mr,
    )
    .unwrap();
    exp_res = eager_map.clone();
    exp_res.entry(ep7).or_default().remove(&bob);
    assert_eq!(res, exp_res);

    // Test case 6
    let res = compute_new_redelegated_unbonds(
        &storage,
        &redelegated_bonds,
        &set56,
        &mod_val_partial_mr,
    )
    .unwrap();
    exp_res = eager_map.clone();
    exp_res
        .entry(ep7)
        .or_default()
        .entry(bob.clone())
        .or_default()
        .remove(&ep4);
    assert_eq!(res, exp_res);

    // Test case 7
    let res = compute_new_redelegated_unbonds(
        &storage,
        &redelegated_bonds,
        &set56,
        &mod_epoch_partial_mr,
    )
    .unwrap();
    exp_res
        .entry(ep7)
        .or_default()
        .entry(bob)
        .or_default()
        .insert(ep4, token::Amount::from(1));
    assert_eq!(res, exp_res);
}

/// `applyListSlashesTest`
#[test]
fn test_apply_list_slashes() {
    let init_epoch = Epoch(2);
    let params = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };
    // let unbonding_len = 4u64;
    // let cubic_offset = 1u64;

    let slash1 = Slash {
        epoch: init_epoch,
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slash2 = Slash {
        epoch: init_epoch
            + params.unbonding_len
            + params.cubic_slashing_window_length
            + 1u64,
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };

    let list1 = [slash1.clone()];
    let list2 = [slash1.clone(), slash2.clone()];
    let list3 = [slash1.clone(), slash1.clone()];
    let list4 = [slash1.clone(), slash1, slash2];

    let res = apply_list_slashes(&params, [].iter(), token::Amount::from(100))
        .unwrap();
    assert_eq!(res, token::Amount::from(100));

    let res =
        apply_list_slashes(&params, list1.iter(), token::Amount::from(100))
            .unwrap();
    assert_eq!(res, token::Amount::zero());

    let res =
        apply_list_slashes(&params, list2.iter(), token::Amount::from(100))
            .unwrap();
    assert_eq!(res, token::Amount::zero());

    let res =
        apply_list_slashes(&params, list3.iter(), token::Amount::from(100))
            .unwrap();
    assert_eq!(res, token::Amount::zero());

    let res =
        apply_list_slashes(&params, list4.iter(), token::Amount::from(100))
            .unwrap();
    assert_eq!(res, token::Amount::zero());
}

/// `computeSlashableAmountTest`
#[test]
fn test_compute_slashable_amount() {
    let init_epoch = Epoch(2);
    let params = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    let slash1 = Slash {
        epoch: init_epoch
            + params.unbonding_len
            + params.cubic_slashing_window_length,
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };

    let slash2 = Slash {
        epoch: init_epoch
            + params.unbonding_len
            + params.cubic_slashing_window_length
            + 1u64,
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };

    let test_map = vec![(init_epoch, token::Amount::from(50))]
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let res = compute_slashable_amount(
        &params,
        &slash1,
        token::Amount::from(100),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(res, token::Amount::from(100));

    let res = compute_slashable_amount(
        &params,
        &slash2,
        token::Amount::from(100),
        &test_map,
    )
    .unwrap();
    assert_eq!(res, token::Amount::from(50));

    let res = compute_slashable_amount(
        &params,
        &slash1,
        token::Amount::from(100),
        &test_map,
    )
    .unwrap();
    assert_eq!(res, token::Amount::from(100));
}

/// `foldAndSlashRedelegatedBondsMapTest`
#[test]
fn test_fold_and_slash_redelegated_bonds() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };
    let start_epoch = Epoch(7);

    let alice = established_address_1();
    let bob = established_address_2();

    println!("\n\nAlice: {}", alice);
    println!("Bob: {}\n", bob);

    let test_slash = Slash {
        epoch: Default::default(),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };

    let test_data = vec![
        (alice.clone(), vec![(2, 1), (4, 1)]),
        (bob, vec![(1, 1), (4, 2)]),
    ];
    let mut eager_redel_bonds = EagerRedelegatedBondsMap::default();
    for (address, pair) in test_data {
        for (epoch, amount) in pair {
            eager_redel_bonds
                .entry(address.clone())
                .or_default()
                .insert(Epoch(epoch), token::Amount::from(amount));
        }
    }

    // Test case 1
    let res = fold_and_slash_redelegated_bonds(
        &storage,
        &params,
        &eager_redel_bonds,
        start_epoch,
        [].iter(),
        |_| true,
    )
    .unwrap();
    assert_eq!(
        res,
        FoldRedelegatedBondsResult {
            total_redelegated: token::Amount::from(5),
            total_after_slashing: token::Amount::from(5),
        }
    );

    // Test case 2
    let res = fold_and_slash_redelegated_bonds(
        &storage,
        &params,
        &eager_redel_bonds,
        start_epoch,
        [test_slash].iter(),
        |_| true,
    )
    .unwrap();
    assert_eq!(
        res,
        FoldRedelegatedBondsResult {
            total_redelegated: token::Amount::from(5),
            total_after_slashing: token::Amount::zero(),
        }
    );

    // Test case 3
    let alice_slash = Slash {
        epoch: Epoch(6),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    validator_slashes_handle(&alice)
        .push(&mut storage, alice_slash)
        .unwrap();

    let res = fold_and_slash_redelegated_bonds(
        &storage,
        &params,
        &eager_redel_bonds,
        start_epoch,
        [].iter(),
        |_| true,
    )
    .unwrap();
    assert_eq!(
        res,
        FoldRedelegatedBondsResult {
            total_redelegated: token::Amount::from(5),
            total_after_slashing: token::Amount::from(3),
        }
    );
}

/// `slashRedelegationTest`
#[test]
fn test_slash_redelegation() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };
    let alice = established_address_1();

    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(&alice);
    total_redelegated_unbonded
        .at(&Epoch(13))
        .at(&Epoch(10))
        .at(&alice)
        .insert(&mut storage, Epoch(7), token::Amount::from(2))
        .unwrap();

    let slashes = validator_slashes_handle(&alice);

    let mut slashed_amounts_map = BTreeMap::from_iter([
        (Epoch(15), token::Amount::zero()),
        (Epoch(16), token::Amount::zero()),
    ]);
    let empty_slash_amounts = slashed_amounts_map.clone();

    // Test case 1
    slash_redelegation(
        &storage,
        &params,
        token::Amount::from(7),
        Epoch(7),
        Epoch(10),
        &alice,
        Epoch(14),
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(
        slashed_amounts_map,
        BTreeMap::from_iter([
            (Epoch(15), token::Amount::from(5)),
            (Epoch(16), token::Amount::from(5)),
        ])
    );

    // Test case 2
    slashed_amounts_map = empty_slash_amounts.clone();
    slash_redelegation(
        &storage,
        &params,
        token::Amount::from(7),
        Epoch(7),
        Epoch(11),
        &alice,
        Epoch(14),
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(
        slashed_amounts_map,
        BTreeMap::from_iter([
            (Epoch(15), token::Amount::from(7)),
            (Epoch(16), token::Amount::from(7)),
        ])
    );

    // Test case 3
    slashed_amounts_map = BTreeMap::from_iter([
        (Epoch(15), token::Amount::from(2)),
        (Epoch(16), token::Amount::from(3)),
    ]);
    slash_redelegation(
        &storage,
        &params,
        token::Amount::from(7),
        Epoch(7),
        Epoch(10),
        &alice,
        Epoch(14),
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(
        slashed_amounts_map,
        BTreeMap::from_iter([
            (Epoch(15), token::Amount::from(7)),
            (Epoch(16), token::Amount::from(8)),
        ])
    );

    // Test case 4
    slashes
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(8),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    slashed_amounts_map = empty_slash_amounts.clone();
    slash_redelegation(
        &storage,
        &params,
        token::Amount::from(7),
        Epoch(7),
        Epoch(10),
        &alice,
        Epoch(14),
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(slashed_amounts_map, empty_slash_amounts);

    // Test case 5
    slashes.pop(&mut storage).unwrap();
    slashes
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(9),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    slash_redelegation(
        &storage,
        &params,
        token::Amount::from(7),
        Epoch(7),
        Epoch(10),
        &alice,
        Epoch(14),
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(slashed_amounts_map, empty_slash_amounts);

    // Test case 6
    slashes
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(8),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    slash_redelegation(
        &storage,
        &params,
        token::Amount::from(7),
        Epoch(7),
        Epoch(10),
        &alice,
        Epoch(14),
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(slashed_amounts_map, empty_slash_amounts);
}

/// `slashValidatorRedelegationTest`
#[test]
fn test_slash_validator_redelegation() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };
    let gov_params =
        namada_governance::parameters::GovernanceParameters::default();
    gov_params.init_storage(&mut storage).unwrap();
    write_pos_params(&mut storage, &params).unwrap();

    let alice = established_address_1();
    let bob = established_address_2();

    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(&alice);
    total_redelegated_unbonded
        .at(&Epoch(13))
        .at(&Epoch(10))
        .at(&alice)
        .insert(&mut storage, Epoch(7), token::Amount::from(2))
        .unwrap();

    let outgoing_redelegations =
        validator_outgoing_redelegations_handle(&alice).at(&bob);

    let slashes = validator_slashes_handle(&alice);

    let mut slashed_amounts_map = BTreeMap::from_iter([
        (Epoch(15), token::Amount::zero()),
        (Epoch(16), token::Amount::zero()),
    ]);
    let empty_slash_amounts = slashed_amounts_map.clone();

    // Test case 1
    slash_validator_redelegation(
        &storage,
        &params,
        &alice,
        Epoch(14),
        &outgoing_redelegations,
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(slashed_amounts_map, empty_slash_amounts);

    // Test case 2
    total_redelegated_unbonded
        .remove_all(&mut storage, &Epoch(13))
        .unwrap();
    slash_validator_redelegation(
        &storage,
        &params,
        &alice,
        Epoch(14),
        &outgoing_redelegations,
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(slashed_amounts_map, empty_slash_amounts);

    // Test case 3
    total_redelegated_unbonded
        .at(&Epoch(13))
        .at(&Epoch(10))
        .at(&alice)
        .insert(&mut storage, Epoch(7), token::Amount::from(2))
        .unwrap();
    outgoing_redelegations
        .at(&Epoch(6))
        .insert(&mut storage, Epoch(8), token::Amount::from(7))
        .unwrap();
    slash_validator_redelegation(
        &storage,
        &params,
        &alice,
        Epoch(14),
        &outgoing_redelegations,
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(
        slashed_amounts_map,
        BTreeMap::from_iter([
            (Epoch(15), token::Amount::from(7)),
            (Epoch(16), token::Amount::from(7)),
        ])
    );

    // Test case 4
    slashed_amounts_map = empty_slash_amounts.clone();
    outgoing_redelegations
        .remove_all(&mut storage, &Epoch(6))
        .unwrap();
    outgoing_redelegations
        .at(&Epoch(7))
        .insert(&mut storage, Epoch(8), token::Amount::from(7))
        .unwrap();
    slash_validator_redelegation(
        &storage,
        &params,
        &alice,
        Epoch(14),
        &outgoing_redelegations,
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(
        slashed_amounts_map,
        BTreeMap::from_iter([
            (Epoch(15), token::Amount::from(5)),
            (Epoch(16), token::Amount::from(5)),
        ])
    );

    // Test case 5
    slashed_amounts_map = BTreeMap::from_iter([
        (Epoch(15), token::Amount::from(2)),
        (Epoch(16), token::Amount::from(3)),
    ]);
    slash_validator_redelegation(
        &storage,
        &params,
        &alice,
        Epoch(14),
        &outgoing_redelegations,
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(
        slashed_amounts_map,
        BTreeMap::from_iter([
            (Epoch(15), token::Amount::from(7)),
            (Epoch(16), token::Amount::from(8)),
        ])
    );

    // Test case 6
    slashed_amounts_map = empty_slash_amounts.clone();
    slashes
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(8),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    slash_validator_redelegation(
        &storage,
        &params,
        &alice,
        Epoch(14),
        &outgoing_redelegations,
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(slashed_amounts_map, empty_slash_amounts);
}

/// `slashValidatorTest`
#[test]
fn test_slash_validator() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };
    let gov_params =
        namada_governance::parameters::GovernanceParameters::default();
    gov_params.init_storage(&mut storage).unwrap();
    write_pos_params(&mut storage, &params).unwrap();

    let alice = established_address_1();
    let bob = established_address_2();

    let total_bonded = total_bonded_handle(&bob);
    let total_unbonded = total_unbonded_handle(&bob);
    let total_redelegated_bonded =
        validator_total_redelegated_bonded_handle(&bob);
    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(&bob);

    let infraction_stake = token::Amount::from(23);

    let initial_stakes = BTreeMap::from_iter([
        (Epoch(11), infraction_stake),
        (Epoch(12), infraction_stake),
        (Epoch(13), infraction_stake),
    ]);
    let mut exp_res = initial_stakes.clone();

    let current_epoch = Epoch(10);
    let infraction_epoch =
        current_epoch - params.slash_processing_epoch_offset();
    let processing_epoch = current_epoch.next();
    let slash_rate = Dec::one();

    // Test case 1
    total_bonded
        .set::<_, GovStore<_>>(&mut storage, 23.into(), infraction_epoch - 2, 0)
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 2
    total_bonded
        .set::<_, GovStore<_>>(&mut storage, 17.into(), infraction_epoch - 2, 0)
        .unwrap();
    total_unbonded
        .at(&(current_epoch + params.pipeline_len))
        .insert(&mut storage, infraction_epoch - 2, 6.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    exp_res.insert(Epoch(12), 17.into());
    exp_res.insert(Epoch(13), 17.into());
    assert_eq!(res, exp_res);

    // Test case 3
    total_redelegated_bonded
        .at(&infraction_epoch.prev().unwrap())
        .at(&alice)
        .insert(&mut storage, Epoch(2), 5.into())
        .unwrap();
    total_redelegated_bonded
        .at(&infraction_epoch.prev().unwrap())
        .at(&alice)
        .insert(&mut storage, Epoch(3), 1.into())
        .unwrap();

    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 4
    total_unbonded_handle(&bob)
        .at(&(current_epoch + params.pipeline_len))
        .remove(&mut storage, &(infraction_epoch - 2))
        .unwrap();
    total_unbonded_handle(&bob)
        .at(&(current_epoch + params.pipeline_len))
        .insert(&mut storage, infraction_epoch - 1, 6.into())
        .unwrap();
    total_redelegated_unbonded
        .at(&(current_epoch + params.pipeline_len))
        .at(&infraction_epoch.prev().unwrap())
        .at(&alice)
        .insert(&mut storage, Epoch(2), 5.into())
        .unwrap();
    total_redelegated_unbonded
        .at(&(current_epoch + params.pipeline_len))
        .at(&infraction_epoch.prev().unwrap())
        .at(&alice)
        .insert(&mut storage, Epoch(3), 1.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 5
    total_bonded_handle(&bob)
        .set::<_, GovStore<_>>(&mut storage, 19.into(), infraction_epoch - 2, 0)
        .unwrap();
    total_unbonded_handle(&bob)
        .at(&(current_epoch + params.pipeline_len))
        .insert(&mut storage, infraction_epoch - 1, 4.into())
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, Epoch(2), token::Amount::from(1))
        .unwrap();
    total_redelegated_unbonded
        .at(&(current_epoch + params.pipeline_len))
        .at(&infraction_epoch.prev().unwrap())
        .at(&alice)
        .remove(&mut storage, &Epoch(3))
        .unwrap();
    total_redelegated_unbonded
        .at(&(current_epoch + params.pipeline_len))
        .at(&infraction_epoch.prev().unwrap())
        .at(&alice)
        .insert(&mut storage, Epoch(2), 4.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    exp_res.insert(Epoch(12), 19.into());
    exp_res.insert(Epoch(13), 19.into());
    assert_eq!(res, exp_res);

    // Test case 6
    total_unbonded_handle(&bob)
        .remove_all(&mut storage, &(current_epoch + params.pipeline_len))
        .unwrap();
    total_redelegated_unbonded
        .remove_all(&mut storage, &(current_epoch + params.pipeline_len))
        .unwrap();
    total_redelegated_bonded
        .remove_all(&mut storage, &current_epoch)
        .unwrap();
    total_bonded_handle(&bob)
        .set::<_, GovStore<_>>(&mut storage, 23.into(), infraction_epoch - 2, 0)
        .unwrap();
    total_bonded_handle(&bob)
        .set::<_, GovStore<_>>(&mut storage, 6.into(), current_epoch, 0)
        .unwrap();

    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    exp_res = initial_stakes;
    assert_eq!(res, exp_res);

    // Test case 7
    total_bonded
        .get_data_handler()
        .remove(&mut storage, &current_epoch)
        .unwrap();
    total_unbonded
        .at(&current_epoch.next())
        .insert(&mut storage, current_epoch, 6.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 8
    total_bonded
        .get_data_handler()
        .insert(&mut storage, current_epoch, 3.into())
        .unwrap();
    total_unbonded
        .at(&current_epoch.next())
        .insert(&mut storage, current_epoch, 3.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 9
    total_unbonded
        .remove_all(&mut storage, &current_epoch.next())
        .unwrap();
    total_bonded
        .set::<_, GovStore<_>>(&mut storage, 6.into(), current_epoch, 0)
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 2.into(), 5.into())
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 3.into(), 1.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 10
    total_redelegated_bonded
        .remove_all(&mut storage, &current_epoch)
        .unwrap();
    total_bonded
        .get_data_handler()
        .remove(&mut storage, &current_epoch)
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 2.into(), 5.into())
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 3.into(), 1.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 11
    total_bonded
        .set::<_, GovStore<_>>(&mut storage, 2.into(), current_epoch, 0)
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 2.into(), 4.into())
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch)
        .at(&alice)
        .remove(&mut storage, &3.into())
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 2.into(), 1.into())
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 3.into(), 1.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 12
    total_bonded
        .set::<_, GovStore<_>>(&mut storage, 6.into(), current_epoch, 0)
        .unwrap();
    total_bonded
        .set::<_, GovStore<_>>(&mut storage, 2.into(), current_epoch.next(), 0)
        .unwrap();
    total_redelegated_bonded
        .remove_all(&mut storage, &current_epoch)
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch.next())
        .at(&alice)
        .insert(&mut storage, 2.into(), 1.into())
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch.next())
        .at(&alice)
        .insert(&mut storage, 3.into(), 1.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 13
    validator_slashes_handle(&bob)
        .push(
            &mut storage,
            Slash {
                epoch: infraction_epoch.prev().unwrap(),
                block_height: 0,
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    total_redelegated_unbonded
        .remove_all(&mut storage, &current_epoch.next())
        .unwrap();
    total_bonded
        .get_data_handler()
        .remove(&mut storage, &current_epoch.next())
        .unwrap();
    total_redelegated_bonded
        .remove_all(&mut storage, &current_epoch.next())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    exp_res.insert(Epoch(11), 0.into());
    exp_res.insert(Epoch(12), 0.into());
    exp_res.insert(Epoch(13), 0.into());
    assert_eq!(res, exp_res);
}

/// `computeAmountAfterSlashingUnbondTest`
#[test]
fn test_compute_amount_after_slashing_unbond() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    // Test data
    let alice = established_address_1();
    let bob = established_address_2();
    let unbonds: BTreeMap<Epoch, token::Amount> = BTreeMap::from_iter([
        ((Epoch(2)), token::Amount::from(5)),
        ((Epoch(4)), token::Amount::from(6)),
    ]);
    let redelegated_unbonds: EagerRedelegatedUnbonds = BTreeMap::from_iter([(
        Epoch(2),
        BTreeMap::from_iter([(
            alice.clone(),
            BTreeMap::from_iter([(Epoch(1), token::Amount::from(1))]),
        )]),
    )]);

    // Test case 1
    let slashes = vec![];
    let result = compute_amount_after_slashing_unbond(
        &storage,
        &params,
        &unbonds,
        &redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 11.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 5.into()), (4.into(), 6.into())],
    );

    // Test case 2
    let bob_slash = Slash {
        epoch: Epoch(5),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slashes = vec![bob_slash.clone()];
    validator_slashes_handle(&bob)
        .push(&mut storage, bob_slash)
        .unwrap();
    let result = compute_amount_after_slashing_unbond(
        &storage,
        &params,
        &unbonds,
        &redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 0.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 0.into()), (4.into(), 0.into())],
    );

    // Test case 3
    let alice_slash = Slash {
        epoch: Epoch(0),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slashes = vec![alice_slash.clone()];
    validator_slashes_handle(&alice)
        .push(&mut storage, alice_slash)
        .unwrap();
    validator_slashes_handle(&bob).pop(&mut storage).unwrap();
    let result = compute_amount_after_slashing_unbond(
        &storage,
        &params,
        &unbonds,
        &redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 11.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 5.into()), (4.into(), 6.into())],
    );

    // Test case 4
    let alice_slash = Slash {
        epoch: Epoch(1),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slashes = vec![alice_slash.clone()];
    validator_slashes_handle(&alice).pop(&mut storage).unwrap();
    validator_slashes_handle(&alice)
        .push(&mut storage, alice_slash)
        .unwrap();
    let result = compute_amount_after_slashing_unbond(
        &storage,
        &params,
        &unbonds,
        &redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 10.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 4.into()), (4.into(), 6.into())],
    );
}

/// `computeAmountAfterSlashingWithdrawTest`
#[test]
fn test_compute_amount_after_slashing_withdraw() {
    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let params = OwnedPosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    // Test data
    let alice = established_address_1();
    let bob = established_address_2();
    let unbonds_and_redelegated_unbonds: BTreeMap<
        (Epoch, Epoch),
        (token::Amount, EagerRedelegatedBondsMap),
    > = BTreeMap::from_iter([
        (
            (Epoch(2), Epoch(20)),
            (
                // unbond
                token::Amount::from(5),
                // redelegations
                BTreeMap::from_iter([(
                    alice.clone(),
                    BTreeMap::from_iter([(Epoch(1), token::Amount::from(1))]),
                )]),
            ),
        ),
        (
            (Epoch(4), Epoch(20)),
            (
                // unbond
                token::Amount::from(6),
                // redelegations
                BTreeMap::default(),
            ),
        ),
    ]);

    // Test case 1
    let slashes = vec![];
    let result = compute_amount_after_slashing_withdraw(
        &storage,
        &params,
        &unbonds_and_redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 11.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 5.into()), (4.into(), 6.into())],
    );

    // Test case 2
    let bob_slash = Slash {
        epoch: Epoch(5),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slashes = vec![bob_slash.clone()];
    validator_slashes_handle(&bob)
        .push(&mut storage, bob_slash)
        .unwrap();
    let result = compute_amount_after_slashing_withdraw(
        &storage,
        &params,
        &unbonds_and_redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 0.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 0.into()), (4.into(), 0.into())],
    );

    // Test case 3
    let alice_slash = Slash {
        epoch: Epoch(0),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slashes = vec![alice_slash.clone()];
    validator_slashes_handle(&alice)
        .push(&mut storage, alice_slash)
        .unwrap();
    validator_slashes_handle(&bob).pop(&mut storage).unwrap();
    let result = compute_amount_after_slashing_withdraw(
        &storage,
        &params,
        &unbonds_and_redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 11.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 5.into()), (4.into(), 6.into())],
    );

    // Test case 4
    let alice_slash = Slash {
        epoch: Epoch(1),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slashes = vec![alice_slash.clone()];
    validator_slashes_handle(&alice).pop(&mut storage).unwrap();
    validator_slashes_handle(&alice)
        .push(&mut storage, alice_slash)
        .unwrap();
    let result = compute_amount_after_slashing_withdraw(
        &storage,
        &params,
        &unbonds_and_redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 10.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 4.into()), (4.into(), 6.into())],
    );
}

/// SM test case 1 from Brent
#[test]
fn test_from_sm_case_1() {
    use namada_core::address::testing::established_address_4;

    let mut state = TestFullAccessState::default();
    let mut storage = state.restrict_writes_to_write_log();
    let gov_params =
        namada_governance::parameters::GovernanceParameters::default();
    gov_params.init_storage(&mut storage).unwrap();
    write_pos_params(&mut storage, &OwnedPosParams::default()).unwrap();

    let validator = established_address_1();
    let redeleg_src_1 = established_address_2();
    let redeleg_src_2 = established_address_3();
    let owner = established_address_4();
    let unbond_amount = token::Amount::from(3130688);
    println!(
        "Owner: {owner}\nValidator: {validator}\nRedeleg src 1: \
         {redeleg_src_1}\nRedeleg src 2: {redeleg_src_2}"
    );

    // Validator's incoming redelegations
    let outer_epoch_1 = Epoch(27);
    // from redeleg_src_1
    let epoch_1_redeleg_1 = token::Amount::from(8516);
    // from redeleg_src_2
    let epoch_1_redeleg_2 = token::Amount::from(5704386);
    let outer_epoch_2 = Epoch(30);
    // from redeleg_src_2
    let epoch_2_redeleg_2 = token::Amount::from(1035191);

    // Insert the data - bonds and redelegated bonds
    let bonds_handle = bond_handle(&owner, &validator);
    bonds_handle
        .add::<_, GovStore<_>>(
            &mut storage,
            epoch_1_redeleg_1 + epoch_1_redeleg_2,
            outer_epoch_1,
            0,
        )
        .unwrap();
    bonds_handle
        .add::<_, GovStore<_>>(
            &mut storage,
            epoch_2_redeleg_2,
            outer_epoch_2,
            0,
        )
        .unwrap();

    let redelegated_bonds_map_1 = delegator_redelegated_bonds_handle(&owner)
        .at(&validator)
        .at(&outer_epoch_1);
    redelegated_bonds_map_1
        .at(&redeleg_src_1)
        .insert(&mut storage, Epoch(14), epoch_1_redeleg_1)
        .unwrap();
    redelegated_bonds_map_1
        .at(&redeleg_src_2)
        .insert(&mut storage, Epoch(18), epoch_1_redeleg_2)
        .unwrap();
    let redelegated_bonds_map_1 = delegator_redelegated_bonds_handle(&owner)
        .at(&validator)
        .at(&outer_epoch_1);

    let redelegated_bonds_map_2 = delegator_redelegated_bonds_handle(&owner)
        .at(&validator)
        .at(&outer_epoch_2);
    redelegated_bonds_map_2
        .at(&redeleg_src_2)
        .insert(&mut storage, Epoch(18), epoch_2_redeleg_2)
        .unwrap();

    // Find the modified redelegation the same way as `unbond_tokens`
    let bonds_to_unbond = find_bonds_to_remove(
        &storage,
        &bonds_handle.get_data_handler(),
        unbond_amount,
    )
    .unwrap();
    dbg!(&bonds_to_unbond);

    let (new_entry_epoch, new_bond_amount) = bonds_to_unbond.new_entry.unwrap();
    assert_eq!(outer_epoch_1, new_entry_epoch);
    // The modified bond should be sum of all redelegations less the unbonded
    // amount
    assert_eq!(
        epoch_1_redeleg_1 + epoch_1_redeleg_2 + epoch_2_redeleg_2
            - unbond_amount,
        new_bond_amount
    );
    // The current bond should be sum of redelegations from the modified epoch
    let cur_bond_amount = bonds_handle
        .get_delta_val(&storage, new_entry_epoch)
        .unwrap()
        .unwrap_or_default();
    assert_eq!(epoch_1_redeleg_1 + epoch_1_redeleg_2, cur_bond_amount);

    let mr = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map_1,
        new_entry_epoch,
        cur_bond_amount - new_bond_amount,
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(27)),
        validators_to_remove: BTreeSet::from_iter([redeleg_src_2.clone()]),
        validator_to_modify: Some(redeleg_src_2),
        epochs_to_remove: BTreeSet::from_iter([Epoch(18)]),
        epoch_to_modify: Some(Epoch(18)),
        new_amount: Some(token::Amount::from(3608889)),
    };

    pretty_assertions::assert_eq!(mr, exp_mr);
}
