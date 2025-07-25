//! # PoS validity predicate tests
//!
//! The testing strategy is heavily relying on
//! [proptest state machine testing](https://github.com/AltSysrq/proptest/pull/257)
//! together with
//! [higher-order strategies](https://altsysrq.github.io/proptest-book/proptest/tutorial/higher-order.html).
//!
//! The system is being tested with arbitrary valid PoS parameters, arbitrary
//! valid initial state and:
//!
//! 1. One or more arbitrary valid transition. The happy path, these are very
//!    simple. We just test that they get accepted.
//! 1. One or more arbitrary valid transition, modified to make at least one of
//!    them invalid. Must be rejected.
//! 1. Arbitrary invalid storage modification. Must be rejected.
//!
//! The order of the arbitrary valid transitions is important as their storage
//! changes are accumulative, the same way they would be when applied in a
//! transaction. So for example we can initialize a validator account and bond
//! some tokens to it in the same transaction, but we cannot bond tokens to a
//! validator account before it's initialized.
//!
//! ## Pos Parameters
//!
//! Arbitrary valid PoS parameters are provided from its module via
//! [`namada_tx_prelude::proof_of_stake::parameters::testing::arb_pos_params`].
//!
//! ## Valid transitions
//!
//! The list below includes state requirements and the storage key changes
//! expected for a valid transition. Valid transitions can be composed into an
//! ordered sequence. The composed transitions must still be a valid transition,
//! provided all the state requirements are valid (a transition may depend on
//! the modifications of its predecessor transition).
//!
//! The PoS storage modifications are modelled using
//! `testing::PosStorageChange`.
//!
//! - Bond: Requires a validator account in the state (the `#{validator}`
//!   segments in the keys below).
//!     - `#{PoS}/bond/#{owner}/#{validator}`
//!     - `#{PoS}/total_deltas`
//!     - `#{PoS}/validator_set`
//!     - `#{PoS}/validator/#{validator}/deltas`
//!     - `#{staking_token}/balance/#{PoS}`
//!
//!
//! - Unbond: Requires a bond in the state (the `#{owner}` and `#{validator}`
//!   segments in the keys below must be the owner and a validator of an
//!   existing bond). The bond's total amount must be greater or equal to the
//!   amount that is being unbonded.
//!     - `#{PoS}/bond/#{owner}/#{validator}`
//!     - `#{PoS}/unbond/#{owner}/#{validator}`
//!     - `#{PoS}/total_deltas`
//!     - `#{PoS}/validator_set`
//!     - `#{PoS}/validator/#{validator}/deltas`
//!
//! - Withdraw: Requires a withdrawable unbond in the state (the `#{owner}` and
//!   `#{validator}` segments in the keys below must be the owner and a
//!   validator of an existing withdrawable unbond).
//!     - `#{PoS}/unbond/#{owner}/#{validator}`
//!     - `#{staking_token}/balance/#{PoS}`
//!
//! - Init validator: No state requirements.
//!     - `#{PoS}/validator/#{validator}/address_raw_hash` (the raw_hash is the
//!       validator's address in Tendermint)
//!     - `#{PoS}/validator_set`
//!     - `#{PoS}/validator/#{validator}/consensus_key`
//!     - `#{PoS}/validator/#{validator}/state`
//!     - `#{PoS}/validator/#{validator}/deltas`
//!     - `#{PoS}/validator/#{validator}/commission_rate`
//!     - `#{PoS}/validator/#{validator}/max_commission_rate_change`
//!
//!
//! ## Invalidating transitions
//!
//! To look for vulnerabilities in the VP, we can make arbitrary
//! [`crate::storage::Change`]s to the valid transitions that should
//! invalidate it and check that the VP does no longer accept it. To avoid false
//! positives, we should filter out any modifications that would produce a valid
//! transition.
//!
//! We can do this by generating arbitrary:
//! - storage modifications for any of the storage modifications performed by a
//!   transition
//! - any other storage key used by PoS
//! - any other storage key not used by PoS
//!
//! A modification for integer based values can be addition or subtraction their
//! value.
//!
//! TODOs:
//! - add more invalid PoS changes
//! - add arb invalid storage changes
//! - add slashes
//! - add rewards

use namada_sdk::chain::Epoch;
use namada_sdk::proof_of_stake::parameters::{OwnedPosParams, PosParams};
use namada_sdk::proof_of_stake::test_utils::test_init_genesis as init_genesis;
use namada_sdk::proof_of_stake::types::GenesisValidator;

use crate::tx::tx_host_env;

/// initialize proof-of-stake genesis with the given list of validators and
/// parameters.
pub fn init_pos(
    genesis_validators: &[GenesisValidator],
    params: &OwnedPosParams,
    start_epoch: Epoch,
) -> PosParams {
    tx_host_env::init();

    tx_host_env::with(|tx_env| {
        // Ensure that all the used
        // addresses exist
        let native_token = tx_env.state.in_mem().native_token.clone();
        tx_env.spawn_accounts([&native_token]);
        for validator in genesis_validators {
            tx_env.spawn_accounts([&validator.address]);
            tx_env.init_account_storage(
                &validator.address,
                vec![validator.consensus_key.clone()],
                1,
            )
        }
        tx_env.state.in_mem_mut().block.epoch = start_epoch;
        // Initialize PoS storage
        // tx_env
        //     .state
        //     .init_genesis(params, genesis_validators.iter(), start_epoch)
        //     .unwrap();
        let params = init_genesis::<
            _,
            crate::parameters::Store<_>,
            crate::governance::Store<_>,
            crate::token::Store<_>,
        >(
            &mut tx_env.state,
            params.clone(),
            genesis_validators.iter().cloned(),
            start_epoch,
        )
        .unwrap();

        // Commit changes in WL to genesis state
        tx_env.commit_genesis();
        params
    })
}

#[cfg(test)]
mod tests {

    use std::cell::RefCell;

    use namada_sdk::gas::VpGasMeter;
    use namada_sdk::governance::parameters::GovernanceParameters;
    use namada_sdk::key::common::PublicKey;
    use namada_sdk::validation::PosVp;
    use namada_sdk::{address, token};
    use namada_tx_prelude::Address;
    use namada_tx_prelude::proof_of_stake::parameters::testing::arb_pos_params;
    use proptest::prelude::*;
    use proptest::test_runner::Config;
    use proptest_state_machine::{
        ReferenceStateMachine, StateMachineTest, prop_state_machine,
    };
    use test_log::test;

    use super::testing::{
        InvalidPosAction, ValidPosAction, arb_invalid_pos_action,
        arb_valid_pos_action,
    };
    use super::*;
    use crate::native_vp::TestNativeVpEnv;

    prop_state_machine! {
        #![proptest_config(Config {
            // Instead of the default 256, we only run 5 because otherwise it
            // takes too long and it's preferable to crank up the number of
            // transitions instead, to allow each case to run for more epochs as
            // some issues only manifest once the model progresses further.
            // Additionally, more cases will be explored every time this test is
            // executed in the CI.
            cases: 5,
            verbose: 1,
            .. Config::default()
        })]
        #[test]
        // TODO: To be resumed after the PoS VP update for new storage
        #[ignore]
        /// A `StateMachineTest` implemented on `PosState`
        fn pos_vp_state_machine_test(sequential 1..100 => ConcretePosState);
    }

    /// Abstract representation of a state of PoS system
    #[derive(Clone, Debug)]
    struct AbstractPosState {
        /// Current epoch
        epoch: Epoch,
        /// Parameters
        params: PosParams,
        /// Valid PoS changes in the current transaction
        valid_actions: Vec<ValidPosAction>,
        /// Assuming to be empty in the initial state in
        /// `StateMachineTest::init_test`
        invalid_pos_changes: Vec<InvalidPosAction>,
        /// Empty in the initial state in `StateMachineTest::init_test`
        invalid_arbitrary_changes: crate::storage::Changes,
        /// Valid PoS changes committed to storage
        committed_valid_actions: Vec<ValidPosAction>,
    }

    /// The PoS system under test
    #[derive(Debug)]
    struct ConcretePosState {
        is_current_tx_valid: bool,
    }

    /// State machine transitions
    #[allow(clippy::large_enum_variant)]
    #[derive(Clone, Debug)]
    enum Transition {
        /// Commit all the tx changes already applied in the tx env
        CommitTx,
        /// Switch to a new epoch. This will also commit all the applied valid
        /// transactions.
        NextEpoch,
        /// Valid changes use the current epoch to apply changes correctly
        Valid(ValidPosAction),
        /// Invalid changes with valid data structures
        InvalidPos(InvalidPosAction),
        /// Invalid changes with arbitrary data
        /// TODO: add invalid arb changes
        #[allow(dead_code)]
        InvalidArbitrary(crate::storage::Change),
    }

    impl StateMachineTest for ConcretePosState {
        type Reference = AbstractPosState;
        type SystemUnderTest = Self;

        fn init_test(
            initial_state: &<Self::Reference as ReferenceStateMachine>::State,
        ) -> Self::SystemUnderTest {
            println!();
            println!("New test case");
            // Initialize the transaction env
            init_pos(&[], &initial_state.params, initial_state.epoch);

            // The "genesis" block state
            for change in &initial_state.committed_valid_actions {
                println!("Apply init state change {:#?}", change);
                change.clone().apply(true)
            }
            // Commit the genesis block
            tx_host_env::commit_tx_and_block();

            Self {
                // we only generate and apply valid actions in the initial state
                is_current_tx_valid: true,
            }
        }

        fn apply(
            mut test_state: Self::SystemUnderTest,
            _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
            transition: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            match transition {
                Transition::CommitTx => {
                    if !test_state.is_current_tx_valid {
                        // Clear out the changes
                        tx_host_env::with(|env| {
                            env.state.drop_tx_batch();
                        });
                    }

                    // Commit the last transaction(s) changes, if any
                    tx_host_env::commit_tx_and_block();

                    // Starting a new tx
                    test_state.is_current_tx_valid = true;
                }
                Transition::NextEpoch => {
                    tx_host_env::with(|env| {
                        // Clear out the changes
                        if !test_state.is_current_tx_valid {
                            env.state.drop_tx_batch();
                        }
                        // Also commit the last transaction(s) changes, if any
                        env.commit_tx_and_block();

                        env.state.in_mem_mut().block.epoch =
                            env.state.in_mem().block.epoch.next();
                    });

                    // Starting a new tx
                    test_state.is_current_tx_valid = true;
                }
                Transition::Valid(change) => {
                    change.apply(test_state.is_current_tx_valid);

                    // Post-condition:
                    test_state.validate_transitions();
                }
                Transition::InvalidPos(change) => {
                    test_state.is_current_tx_valid = false;

                    change.apply();

                    // Post-condition:
                    test_state.validate_transitions();
                }
                Transition::InvalidArbitrary(_) => {
                    test_state.is_current_tx_valid = false;

                    // TODO apply

                    // Post-condition:
                    test_state.validate_transitions();

                    // Clear out the invalid changes
                    tx_host_env::with(|env| {
                        env.state.drop_tx_batch();
                    })
                }
            }

            test_state
        }
    }

    impl ReferenceStateMachine for AbstractPosState {
        type State = Self;
        type Transition = Transition;

        fn init_state() -> BoxedStrategy<Self::State> {
            (arb_pos_params(None), 0..100_u64)
                .prop_flat_map(|(params, epoch)| {
                    // We're starting from an empty state
                    let state = vec![];
                    let epoch = Epoch(epoch);
                    let params = PosParams {
                        owned: params,
                        max_proposal_period: GovernanceParameters::default()
                            .max_proposal_period,
                    };
                    arb_valid_pos_action(state.clone()).prop_map(
                        move |valid_action| Self {
                            epoch,
                            params: params.clone(),
                            valid_actions: vec![],
                            invalid_pos_changes: vec![],
                            invalid_arbitrary_changes: vec![],
                            committed_valid_actions: vec![valid_action],
                        },
                    )
                })
                .boxed()
        }

        fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
            let valid_actions = state.all_valid_actions();
            prop_oneof![
                Just(Transition::CommitTx),
                Just(Transition::NextEpoch),
                arb_valid_pos_action(valid_actions.clone())
                    .prop_map(Transition::Valid),
                arb_invalid_pos_action(valid_actions.clone())
                    .prop_map(Transition::InvalidPos),
            ]
            .boxed()
        }

        fn apply(
            mut state: Self::State,
            transition: &Self::Transition,
        ) -> Self::State {
            match transition {
                Transition::CommitTx => {
                    state.commit_tx();
                }
                Transition::NextEpoch => {
                    state.commit_tx();
                    state.epoch = state.epoch.next();
                }
                Transition::Valid(transition) => {
                    state.valid_actions.push(transition.clone());
                }
                Transition::InvalidPos(change) => {
                    state.invalid_pos_changes.push(change.clone());
                }
                Transition::InvalidArbitrary(transition) => {
                    state.invalid_arbitrary_changes.push(transition.clone());
                }
            }
            state
        }

        fn preconditions(
            state: &Self::State,
            transition: &Self::Transition,
        ) -> bool {
            match transition {
                Transition::CommitTx => true,
                Transition::NextEpoch => true,
                Transition::Valid(action) => match action {
                    ValidPosAction::InitValidator {
                        address,
                        consensus_key,
                        commission_rate: _,
                        max_commission_rate_change: _,
                    } => {
                        !state.is_validator(address)
                            && !state.is_used_key(consensus_key)
                    }
                    ValidPosAction::Bond {
                        amount: _,
                        owner: _,
                        validator,
                    } => state.is_validator(validator),
                    ValidPosAction::Unbond {
                        amount,
                        owner,
                        validator,
                    } => {
                        state.is_validator(validator)
                            && state.has_enough_bonds(owner, validator, *amount)
                    }
                    ValidPosAction::Withdraw { owner, validator } => {
                        state.is_validator(validator)
                            && state.has_withdrawable_unbonds(owner, validator)
                    }
                },
                Transition::InvalidPos(_) => true,
                Transition::InvalidArbitrary(_) => true,
            }
        }
    }

    impl ConcretePosState {
        fn validate_transitions(&self) {
            // Use the tx_env to run PoS VP
            let tx_env = tx_host_env::take();

            let gas_meter = RefCell::new(VpGasMeter::new_from_meter(
                &*tx_env.gas_meter.borrow(),
            ));
            let vp_env = TestNativeVpEnv::from_tx_env(tx_env, address::POS);
            let ctx = vp_env.ctx(&gas_meter);
            let result = PosVp::validate_tx(
                &ctx,
                &vp_env.tx_env.batched_tx.to_ref(),
                &vp_env.keys_changed,
                &vp_env.verifiers,
            );

            // Put the tx_env back before checking the result
            tx_host_env::set(vp_env.tx_env);

            // The expected result depends on the current state
            match (self.is_current_tx_valid, result) {
                (true, Ok(())) => {}
                (true, Err(err)) => {
                    // Changes must be accepted
                    panic!(
                        "Validation of valid changes must pass! Got error: \
                         {err}"
                    );
                }
                (false, Err(_)) => {}
                (false, Ok(())) => {
                    // Invalid changes must be rejected
                    panic!("Validation of invalid changes must fail!");
                }
            }
        }
    }

    impl AbstractPosState {
        /// Commit a transaction. This will append the `valid_actions` to the
        /// `committed_valid_actions`, if the transaction is valid, and discard
        /// invalid changes.
        fn commit_tx(&mut self) {
            let valid_actions_to_commit =
                std::mem::take(&mut self.valid_actions);
            if self.invalid_pos_changes.is_empty()
                && self.invalid_arbitrary_changes.is_empty()
            {
                self.committed_valid_actions.extend(valid_actions_to_commit);
            }
            self.invalid_pos_changes = vec![];
            self.invalid_arbitrary_changes = vec![];
        }

        /// Get all the valid actions since genesis
        fn all_valid_actions(&self) -> Vec<ValidPosAction> {
            [
                self.committed_valid_actions.clone(),
                self.valid_actions.clone(),
            ]
            .concat()
        }

        /// Find if the given address is a validator
        fn is_validator(&self, addr: &Address) -> bool {
            self.all_valid_actions().iter().any(|action| match action {
                ValidPosAction::InitValidator { address, .. } => {
                    address == addr
                }
                _ => false,
            })
        }

        /// Find if the given consensus key is already used by any validators
        fn is_used_key(&self, given_consensus_key: &PublicKey) -> bool {
            self.all_valid_actions().iter().any(|action| match action {
                ValidPosAction::InitValidator { consensus_key, .. } => {
                    consensus_key == given_consensus_key
                }
                _ => false,
            })
        }

        /// Find if the given owner and validator has bonds that are greater or
        /// equal to the given amount, so that it can be unbonded.
        /// Note that for self-bonds, `owner == validator`.
        fn has_enough_bonds(
            &self,
            owner: &Address,
            validator: &Address,
            amount: token::Amount,
        ) -> bool {
            let raw_amount: u128 = amount.try_into().unwrap();
            let mut total_bonds: u64 = 0;
            for action in self.all_valid_actions().into_iter() {
                match action {
                    ValidPosAction::Bond {
                        amount,
                        owner: bond_owner,
                        validator: bond_validator,
                    } => {
                        if owner == &bond_owner && validator == &bond_validator
                        {
                            let raw_amount: u128 = amount.try_into().unwrap();
                            total_bonds += raw_amount as u64;
                        }
                    }
                    ValidPosAction::Unbond {
                        amount,
                        owner: bond_owner,
                        validator: bond_validator,
                    } => {
                        if owner == &bond_owner && validator == &bond_validator
                        {
                            let raw_amount: u128 = amount.try_into().unwrap();
                            total_bonds -= raw_amount as u64;
                        }
                    }
                    _ => {}
                }
            }

            total_bonds as u128 >= raw_amount
        }

        /// Find if the given owner and validator has unbonds that are ready to
        /// be withdrawn.
        /// Note that for self-bonds, `owner == validator`.
        fn has_withdrawable_unbonds(
            &self,
            owner: &Address,
            validator: &Address,
        ) -> bool {
            self.all_valid_actions()
                .into_iter()
                .any(|action| match action {
                    ValidPosAction::Unbond {
                        amount: _,
                        owner: bond_owner,
                        validator: bond_validator,
                    } => owner == &bond_owner && validator == &bond_validator,
                    _ => false,
                })
        }
    }
}

/// Testing helpers
pub mod testing {

    use std::cell::RefCell;

    use derivative::Derivative;
    use itertools::Either;
    use namada_sdk::chain::Epoch;
    use namada_sdk::dec::Dec;
    use namada_sdk::gas::{GasMetering, TxGasMeter};
    use namada_sdk::key::RefTo;
    use namada_sdk::key::common::PublicKey;
    use namada_sdk::proof_of_stake::ADDRESS as POS_ADDRESS;
    use namada_sdk::proof_of_stake::epoched::DynEpochOffset;
    use namada_sdk::proof_of_stake::parameters::PosParams;
    use namada_sdk::proof_of_stake::parameters::testing::arb_rate;
    use namada_sdk::proof_of_stake::storage::{
        get_num_consensus_validators, read_pos_params, unbond_handle,
    };
    use namada_sdk::proof_of_stake::types::{BondId, ValidatorState};
    use namada_sdk::token::{Amount, Change};
    use namada_sdk::{address, governance, key, token};
    use namada_tx_prelude::{Address, StorageRead, StorageWrite};
    use namada_vm::host_env::gas_meter::GasMeter;
    use proptest::prelude::*;

    use crate::tx::{self, tx_host_env};

    #[derive(Clone, Debug, Default)]
    pub struct TestValidator {
        pub address: Option<Address>,
        pub stake: Option<token::Amount>,
        /// Balance is a pair of token address and its amount
        pub unstaked_balances: Vec<(Address, token::Amount)>,
    }

    /// The state of PoS storage is made of changes, which must be applied in
    /// the same order to get to the current state.
    pub type PosStorageChanges = Vec<PosStorageChange>;

    #[derive(Clone, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum ValidPosAction {
        InitValidator {
            address: Address,
            consensus_key: PublicKey,
            commission_rate: Dec,
            max_commission_rate_change: Dec,
        },
        Bond {
            amount: token::Amount,
            owner: Address,
            validator: Address,
        },
        Unbond {
            amount: token::Amount,
            owner: Address,
            validator: Address,
        },
        Withdraw {
            owner: Address,
            validator: Address,
        },
    }

    #[derive(Clone, Debug)]
    pub struct InvalidPosAction {
        /// Invalid changes can be applied at arbitrary epochs
        changes: Vec<(Epoch, PosStorageChanges)>,
    }

    /// PoS storage modifications
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub enum PosStorageChange {
        /// Ensure that the account exists when initializing a valid new
        /// validator or delegation from a new owner
        SpawnAccount {
            address: Address,
        },
        /// Add tokens included in a new bond at given offset. Bonded tokens
        /// are added at pipeline offset and unbonded tokens are added as
        /// negative values at unbonding offset.
        Bond {
            owner: Address,
            validator: Address,
            delta: Change,
            offset: DynEpochOffset,
        },
        /// Add tokens unbonded from a bond at unbonding offset
        Unbond {
            owner: Address,
            validator: Address,
            delta: Change,
        },
        /// Withdraw tokens from an unbond at the current epoch
        WithdrawUnbond {
            owner: Address,
            validator: Address,
        },
        TotalDeltas {
            delta: Change,
            offset: Either<DynEpochOffset, Epoch>,
        },
        ValidatorSet {
            validator: Address,
            token_delta: Change,
            offset: DynEpochOffset,
        },
        ValidatorConsensusKey {
            validator: Address,
            #[derivative(Debug = "ignore")]
            pk: PublicKey,
        },
        ValidatorDeltas {
            validator: Address,
            delta: Change,
            offset: DynEpochOffset,
        },
        ValidatorState {
            validator: Address,
            state: ValidatorState,
        },
        StakingTokenPosBalance {
            delta: Change,
        },
        ValidatorAddressRawHash {
            address: Address,
            #[derivative(Debug = "ignore")]
            consensus_key: PublicKey,
        },
        ValidatorCommissionRate {
            address: Address,
            rate: Dec,
        },
        ValidatorMaxCommissionRateChange {
            address: Address,
            change: Dec,
        },
    }

    pub fn arb_valid_pos_action(
        valid_actions: Vec<ValidPosAction>,
    ) -> impl Strategy<Value = ValidPosAction> {
        let validators: Vec<Address> = valid_actions
            .iter()
            .filter_map(|action| match action {
                ValidPosAction::InitValidator { address, .. } => {
                    Some(address.clone())
                }
                _ => None,
            })
            .collect();
        let init_validator = (
            address::testing::arb_established_address(),
            key::testing::arb_common_keypair(),
            arb_rate(),
            arb_rate(),
        )
            .prop_map(
                |(
                    addr,
                    consensus_key,
                    commission_rate,
                    max_commission_rate_change,
                )| {
                    ValidPosAction::InitValidator {
                        address: Address::Established(addr),
                        consensus_key: consensus_key.ref_to(),
                        commission_rate,
                        max_commission_rate_change,
                    }
                },
            );

        if validators.is_empty() {
            // When there is no validator, we can only initialize new ones
            init_validator.boxed()
        } else {
            let arb_validator = proptest::sample::select(validators);
            let arb_validator_or_address = prop_oneof![
                arb_validator.clone(),
                address::testing::arb_established_address()
                    .prop_map(Address::Established),
            ];
            // When there are some validators, but no bonds, we can only add
            // more validators or bonds
            let arb_bond = (
                // We select bond amount safely below the `u64::MAX` to
                // avoid their sums overflowing `u64` in the model
                (0..u64::MAX / 1_000),
                arb_validator_or_address,
                arb_validator,
            )
                .prop_map(|(amount, owner, validator)| ValidPosAction::Bond {
                    amount: Amount::from_uint(amount, 0).unwrap(),
                    owner,
                    validator,
                });
            let current_bonds: Vec<(BondId, token::Amount)> = valid_actions
                .iter()
                .filter_map(|action| match action {
                    ValidPosAction::Bond {
                        amount,
                        owner,
                        validator,
                    } => Some((
                        BondId {
                            source: owner.clone(),
                            validator: validator.clone(),
                        },
                        *amount,
                    )),
                    _ => None,
                })
                .collect();

            if current_bonds.is_empty() {
                prop_oneof![init_validator, arb_bond].boxed()
            } else {
                let arb_current_bond = proptest::sample::select(current_bonds);
                // When there are some validators and bonds, we can also unbond
                // them
                let arb_unbond = arb_current_bond.prop_flat_map(
                    |(bond_id, current_bond_amount)| {
                        let current_bond_amount =
                            <Amount as TryInto<u128>>::try_into(
                                current_bond_amount,
                            )
                            .unwrap() as u64;
                        // Unbond an arbitrary amount up to what's available
                        (0..current_bond_amount).prop_map(move |amount| {
                            ValidPosAction::Unbond {
                                amount: Amount::from_uint(amount, 0).unwrap(),
                                owner: bond_id.source.clone(),
                                validator: bond_id.validator.clone(),
                            }
                        })
                    },
                );

                let withdrawable_unbonds: Vec<BondId> = valid_actions
                    .iter()
                    .filter_map(|action| match action {
                        ValidPosAction::Unbond {
                            amount: _,
                            owner,
                            validator,
                        } => Some(BondId {
                            source: owner.clone(),
                            validator: validator.clone(),
                        }),
                        _ => None,
                    })
                    .collect();

                if withdrawable_unbonds.is_empty() {
                    prop_oneof![init_validator, arb_bond, arb_unbond].boxed()
                } else {
                    // When there are some unbonds, we can try to withdraw them
                    let arb_current_unbond =
                        proptest::sample::select(withdrawable_unbonds);
                    let arb_withdrawal =
                        arb_current_unbond.prop_map(|bond_id| {
                            ValidPosAction::Withdraw {
                                owner: bond_id.source.clone(),
                                validator: bond_id.validator,
                            }
                        });

                    prop_oneof![
                        init_validator,
                        arb_bond,
                        arb_unbond,
                        arb_withdrawal
                    ]
                    .boxed()
                }
            }
        }
    }

    impl ValidPosAction {
        /// Apply a valid PoS storage action. This will use the current epoch
        /// from the tx env to apply the change on epoched data as expected by
        /// the VP.
        pub fn apply(self, is_current_tx_valid: bool) {
            // Read the PoS parameters
            let params =
                read_pos_params::<_, governance::Store<_>>(tx::ctx()).unwrap();

            let current_epoch = tx_host_env::with(|env| {
                // Reset the gas meter on each change, so that we never run
                // out in this test
                let gas_limit = env.gas_meter.borrow().get_gas_limit();
                env.gas_meter =
                    RefCell::new(GasMeter::Native(TxGasMeter::new(
                        gas_limit,
                        namada_sdk::parameters::get_gas_scale(tx::ctx())
                            .unwrap(),
                    )));
                env.state.in_mem().block.epoch
            });
            println!("Current epoch {}", current_epoch);

            let changes = self.into_storage_changes(current_epoch);
            for change in changes {
                apply_pos_storage_change(
                    change,
                    &params,
                    current_epoch,
                    is_current_tx_valid,
                )
            }
        }

        /// Convert a valid PoS action to PoS storage changes
        pub fn into_storage_changes(
            self,
            _current_epoch: Epoch,
        ) -> PosStorageChanges {
            match self {
                ValidPosAction::InitValidator {
                    address,
                    consensus_key,
                    commission_rate,
                    max_commission_rate_change,
                } => {
                    let offset = DynEpochOffset::PipelineLen;
                    vec![
                        PosStorageChange::SpawnAccount {
                            address: address.clone(),
                        },
                        PosStorageChange::ValidatorAddressRawHash {
                            address: address.clone(),
                            consensus_key: consensus_key.clone(),
                        },
                        PosStorageChange::ValidatorSet {
                            validator: address.clone(),
                            token_delta: 0.into(),
                            offset,
                        },
                        PosStorageChange::ValidatorConsensusKey {
                            validator: address.clone(),
                            pk: consensus_key,
                        },
                        PosStorageChange::ValidatorState {
                            validator: address.clone(),
                            state: ValidatorState::Consensus,
                        },
                        PosStorageChange::ValidatorDeltas {
                            validator: address.clone(),
                            delta: 0.into(),
                            offset,
                        },
                        PosStorageChange::ValidatorCommissionRate {
                            address: address.clone(),
                            rate: commission_rate,
                        },
                        PosStorageChange::ValidatorMaxCommissionRateChange {
                            address,
                            change: max_commission_rate_change,
                        },
                    ]
                }
                ValidPosAction::Bond {
                    amount,
                    owner,
                    validator,
                } => {
                    let offset = DynEpochOffset::PipelineLen;
                    let token_delta = amount.change();

                    let mut changes = Vec::with_capacity(10);
                    // ensure that the owner account exists
                    changes.push(PosStorageChange::SpawnAccount {
                        address: owner.clone(),
                    });

                    changes.extend([
                        PosStorageChange::ValidatorSet {
                            validator: validator.clone(),
                            token_delta,
                            offset,
                        },
                        PosStorageChange::TotalDeltas {
                            delta: token_delta,
                            offset: Either::Left(offset),
                        },
                        PosStorageChange::ValidatorDeltas {
                            validator: validator.clone(),
                            delta: token_delta,
                            offset,
                        },
                    ]);

                    changes.extend([
                        PosStorageChange::Bond {
                            owner,
                            validator,
                            delta: token_delta,
                            offset,
                        },
                        PosStorageChange::StakingTokenPosBalance {
                            delta: token_delta,
                        },
                    ]);

                    changes
                }
                ValidPosAction::Unbond {
                    amount,
                    owner,
                    validator,
                } => {
                    let offset = DynEpochOffset::UnbondingLen;
                    let token_delta = -amount.change();

                    let mut changes = Vec::with_capacity(6);

                    changes.extend([
                        PosStorageChange::ValidatorSet {
                            validator: validator.clone(),
                            token_delta,
                            offset,
                        },
                        PosStorageChange::TotalDeltas {
                            delta: token_delta,
                            offset: Either::Left(offset),
                        },
                        PosStorageChange::ValidatorDeltas {
                            validator: validator.clone(),
                            delta: token_delta,
                            offset,
                        },
                    ]);

                    changes.extend([
                        // IMPORTANT: we have to update `Unbond` before we
                        // update `Bond`, because it needs to read the bonds to
                        // apply the unbond correctly.
                        PosStorageChange::Unbond {
                            owner: owner.clone(),
                            validator: validator.clone(),
                            delta: -token_delta,
                        },
                        PosStorageChange::Bond {
                            owner,
                            validator,
                            delta: token_delta,
                            offset,
                        },
                    ]);

                    changes
                }
                ValidPosAction::Withdraw { owner, validator } => {
                    let _unbond = unbond_handle(&owner, &validator);

                    // TODO: fix this with new storage

                    // let unbonds = tx::ctx()
                    //     .read_unbond(&BondId {
                    //         source: owner.clone(),
                    //         validator: validator.clone(),
                    //     })
                    //     .unwrap();

                    // let token_delta: i128 = unbonds
                    //     .and_then(|unbonds| unbonds.get(current_epoch))
                    //     .map(|unbonds| {
                    //         unbonds
                    //             .deltas
                    //             .values()
                    //             .map(token::Amount::change)
                    //             .sum()
                    //     })
                    //     .unwrap_or_default();
                    let token_delta = token::Change::zero();

                    vec![
                        PosStorageChange::WithdrawUnbond { owner, validator },
                        PosStorageChange::StakingTokenPosBalance {
                            delta: -token_delta,
                        },
                    ]
                }
            }
        }
    }

    pub fn apply_pos_storage_change(
        change: PosStorageChange,
        params: &PosParams,
        current_epoch: Epoch,
        // valid changes can make assumptions that are not applicable to
        // invalid changes
        _is_current_tx_valid: bool,
    ) {
        match change {
            PosStorageChange::SpawnAccount { address } => {
                tx_host_env::with(move |env| {
                    env.spawn_accounts([&address]);
                });
            }
            PosStorageChange::Bond {
                owner,
                validator,
                delta: _,
                offset: _,
            } => {
                let _bond_id = BondId {
                    source: owner,
                    validator,
                };
                // let bonds = tx::ctx().read_bond(&bond_id).unwrap();
                // let bonds = if delta >= 0 {
                //     let amount: u64 = delta.try_into().unwrap();
                //     let amount: token::Amount = amount.into();
                //     let mut value = Bond {
                //         pos_deltas: HashMap::default(),
                //         neg_deltas: Default::default(),
                //     };
                //     value
                //         .pos_deltas
                //         .insert(current_epoch + offset.value(params),
                // amount);     match bonds {
                //         Some(mut bonds) => {
                //             // Resize the data if needed (the offset may be
                //             // greater than the default from an invalid PoS
                //             // action)
                //             let required_len =
                //                 offset.value(params) as usize + 1;
                //             if bonds.data.len() < required_len {
                //                 bonds.data.resize_with(
                //                     required_len,
                //                     Default::default,
                //                 );
                //             }
                //             bonds.add_at_offset(
                //                 value,
                //                 current_epoch,
                //                 offset,
                //                 params,
                //             );
                //             bonds
                //         }
                //         None => Bonds::init_at_offset(
                //             value,
                //             current_epoch,
                //             offset,
                //             params,
                //         ),
                //     }
                // } else {
                //     let mut bonds = bonds.unwrap_or_else(|| {
                //         Bonds::init(Default::default(), current_epoch,
                // params)     });
                //     let to_unbond: u64 = (-delta).try_into().unwrap();
                //     let to_unbond: token::Amount = to_unbond.into();

                //     bonds.add_at_offset(
                //         Bond {
                //             pos_deltas: Default::default(),
                //             neg_deltas: to_unbond,
                //         },
                //         current_epoch,
                //         offset,
                //         params,
                //     );
                //     bonds
                // };
                // tx::ctx().write_bond(&bond_id, bonds).unwrap();
            }
            PosStorageChange::Unbond {
                owner: _,
                validator: _,
                delta: _,
            } => {
                // let offset = DynEpochOffset::UnbondingLen;
                // let bond_id = BondId {
                //     source: owner,
                //     validator,
                // };
                // let bonds = tx::ctx().read_bond(&bond_id).unwrap().unwrap();
                // let unbonds = tx::ctx().read_unbond(&bond_id).unwrap();
                // let amount: u64 = delta.try_into().unwrap();
                // let mut to_unbond: token::Amount = amount.into();
                // let mut value = Unbond {
                //     deltas: HashMap::default(),
                // };
                // // Look for bonds from the epoch at unbonding offset to the
                // last // update, until we unbond the full
                // amount let mut bond_epoch =
                //     u64::from(bonds.last_update()) + params.unbonding_len;
                // 'outer: while to_unbond != token::Amount::zero()
                //     && bond_epoch >= bonds.last_update().into()
                // {
                //     if let Some(bond) = bonds.get_delta_at_epoch(bond_epoch)
                // {         for (start_epoch, delta) in
                // &bond.pos_deltas {             if delta >=
                // &to_unbond {
                // value.deltas.insert(                     (
                //                         *start_epoch,
                //                         (current_epoch +
                // offset.value(params)),                     ),
                //                     to_unbond,
                //                 );
                //                 to_unbond = 0.into();
                //                 break 'outer;
                //             } else {
                //                 to_unbond -= *delta;
                //                 value.deltas.insert(
                //                     (
                //                         *start_epoch,
                //                         (current_epoch +
                // offset.value(params)),                     ),
                //                     *delta,
                //                 );
                //             }
                //         }
                //     }
                //     bond_epoch -= 1;
                // }
                // // In a valid tx, the amount must be unbonded fully
                // if is_current_tx_valid {
                //     assert!(to_unbond == 0.into(), "This shouldn't happen");
                // }
                // let unbonds = match unbonds {
                //     Some(mut unbonds) => {
                //         unbonds.add_at_offset(
                //             value,
                //             current_epoch,
                //             offset,
                //             params,
                //         );
                //         unbonds
                //     }
                //     None => Unbonds::init(value, current_epoch, params),
                // };
                // tx::ctx().write_unbond(&bond_id, unbonds).unwrap();
            }
            PosStorageChange::TotalDeltas {
                delta: _,
                offset: _,
            } => {
                // let mut total_deltas =
                // tx::ctx().read_total_deltas().unwrap(); match
                // offset {     Either::Left(offset) => {
                //         total_deltas.add_at_offset(
                //             delta,
                //             current_epoch,
                //             offset,
                //             params,
                //         );
                //     }
                //     Either::Right(epoch) => {
                //         total_deltas.add_at_epoch(
                //             delta,
                //             current_epoch,
                //             epoch,
                //             params,
                //         );
                //     }
                // }
                // tx::ctx().write_total_deltas(total_deltas).unwrap()
            }
            PosStorageChange::ValidatorAddressRawHash {
                address: _,
                consensus_key: _,
            } => {
                // tx::ctx()
                //     .write_validator_address_raw_hash(&address,
                // &consensus_key)     .unwrap();
            }
            PosStorageChange::ValidatorSet {
                validator,
                token_delta,
                offset,
            } => {
                apply_validator_set_change(
                    validator,
                    token_delta,
                    offset,
                    current_epoch,
                    params,
                );
            }
            PosStorageChange::ValidatorConsensusKey {
                validator: _,
                pk: _,
            } => {
                // let consensus_key = tx::ctx()
                //     .read_validator_consensus_key(&validator)
                //     .unwrap()
                //     .map(|mut consensus_keys| {
                //         consensus_keys.set(pk.clone(), current_epoch,
                // params);         consensus_keys
                //     })
                //     .unwrap_or_else(|| {
                //         Epoched::init(pk, current_epoch, params)
                //     });
                // tx::ctx()
                //     .write_validator_consensus_key(&validator, consensus_key)
                //     .unwrap();
            }
            PosStorageChange::ValidatorDeltas {
                validator: _,
                delta: _,
                offset: _,
            } => {
                // let validator_deltas = tx::ctx()
                //     .read_validator_deltas(&validator)
                //     .unwrap()
                //     .map(|mut validator_deltas| {
                //         validator_deltas.add_at_offset(
                //             delta,
                //             current_epoch,
                //             offset,
                //             params,
                //         );
                //         validator_deltas
                //     })
                //     .unwrap_or_else(|| {
                //         EpochedDelta::init_at_offset(
                //             delta,
                //             current_epoch,
                //             DynEpochOffset::PipelineLen,
                //             params,
                //         )
                //     });
                // tx::ctx()
                //     .write_validator_deltas(&validator, validator_deltas)
                //     .unwrap();
            }
            PosStorageChange::ValidatorState {
                validator: _,
                state: _,
            } => {
                // let state = tx::ctx()
                //     .read_validator_state(&validator)
                //     .unwrap()
                //     .map(|mut states| {
                //         states.set(state, current_epoch, params);
                //         states
                //     })
                //     .unwrap_or_else(|| {
                //         Epoched::init_at_genesis(state, current_epoch)
                //     });
                // tx::ctx().write_validator_state(&validator, state).unwrap();
            }
            PosStorageChange::StakingTokenPosBalance { delta } => {
                let balance_key = token::storage_key::balance_key(
                    &tx::ctx().get_native_token().unwrap(),
                    &POS_ADDRESS,
                );
                let mut balance: token::Amount =
                    tx::ctx().read(&balance_key).unwrap().unwrap_or_default();
                if !delta.non_negative() {
                    let to_spend = token::Amount::from_change(delta);
                    balance.spend(&to_spend).unwrap();
                } else {
                    let to_recv = token::Amount::from_change(delta);
                    balance.receive(&to_recv).unwrap();
                }
                tx::ctx().write(&balance_key, balance).unwrap();
            }
            PosStorageChange::WithdrawUnbond {
                owner: _,
                validator: _,
            } => {
                // let bond_id = BondId {
                //     source: owner,
                //     validator,
                // };
                // let mut unbonds =
                //     tx::ctx().read_unbond(&bond_id).unwrap().unwrap();
                // unbonds.delete_current(current_epoch, params);
                // tx::ctx().write_unbond(&bond_id, unbonds).unwrap();
            }
            PosStorageChange::ValidatorCommissionRate {
                address: _,
                rate: _,
            } => {
                // let rates = tx::ctx()
                //     .read_validator_commission_rate(&address)
                //     .unwrap()
                //     .map(|mut rates| {
                //         rates.set(rate, current_epoch, params);
                //         rates
                //     })
                //     .unwrap_or_else(|| {
                //         Epoched::init_at_genesis(rate, current_epoch)
                //     });
                // tx::ctx()
                //     .write_validator_commission_rate(&address, rates)
                //     .unwrap();
            }
            PosStorageChange::ValidatorMaxCommissionRateChange {
                address: _,
                change: _,
            } => {
                // let max_change = tx::ctx()
                //     .read_validator_max_commission_rate_change(&address)
                //     .unwrap()
                //     .unwrap_or(change);
                // tx::ctx()
                //     .write_validator_max_commission_rate_change(
                //         &address, max_change,
                //     )
                //     .unwrap();
            }
        }
    }

    pub fn apply_validator_set_change(
        _validator: Address,
        _token_delta: Change,
        _offset: DynEpochOffset,
        _current_epoch: Epoch,
        _params: &PosParams,
    ) {
        // let validator_deltas =
        //     tx::ctx().read_validator_deltas(&validator).unwrap();
        // let mut validator_set = tx::ctx().read_validator_set().unwrap();
        // validator_set.update_from_offset(
        //     |validator_set, epoch| {
        //         let validator_stake = validator_deltas
        //             .as_ref()
        //             .and_then(|deltas| deltas.get(epoch));
        //         match validator_stake {
        //             Some(validator_stake) => {
        //                 let tokens_pre: u64 =
        //                     validator_stake.try_into().unwrap();
        //                 let tokens_post: u64 =
        //                     (validator_stake +
        // token_delta).try_into().unwrap();                 let
        // weighed_validator_pre = WeightedValidator {
        // bonded_stake: tokens_pre,                     address:
        // validator.clone(),                 };
        //                 let weighed_validator_post = WeightedValidator {
        //                     bonded_stake: tokens_post,
        //                     address: validator.clone(),
        //                 };
        //                 if
        // validator_set.active.contains(&weighed_validator_pre)
        //                 {
        //                     let max_inactive_validator =
        //                         validator_set.inactive.last_shim();
        //                     let max_bonded_stake = max_inactive_validator
        //                         .map(|v| v.bonded_stake)
        //                         .unwrap_or_default();
        //                     if tokens_post < max_bonded_stake {
        //                         let activate_max =
        //                             validator_set.inactive.pop_last_shim();
        //                         let popped = validator_set
        //                             .active
        //                             .remove(&weighed_validator_pre);
        //                         debug_assert!(popped);
        //                         validator_set
        //                             .inactive
        //                             .insert(weighed_validator_post);
        //                         if let Some(activate_max) = activate_max {
        //
        // validator_set.active.insert(activate_max);
        // }                     } else {
        //                         validator_set
        //                             .active
        //                             .remove(&weighed_validator_pre);
        //                         validator_set
        //                             .active
        //                             .insert(weighed_validator_post);
        //                     }
        //                 } else {
        //                     let min_active_validator =
        //                         validator_set.active.first_shim();
        //                     let min_bonded_stake = min_active_validator
        //                         .map(|v| v.bonded_stake)
        //                         .unwrap_or_default();
        //                     if tokens_post > min_bonded_stake {
        //                         let deactivate_min =
        //                             validator_set.active.pop_first_shim();
        //                         let popped = validator_set
        //                             .inactive
        //                             .remove(&weighed_validator_pre);
        //                         debug_assert!(popped);
        //                         validator_set
        //                             .active
        //                             .insert(weighed_validator_post);
        //                         if let Some(deactivate_min) = deactivate_min
        // {                             validator_set
        //                                 .inactive
        //                                 .insert(deactivate_min);
        //                         }
        //                     } else {
        //                         validator_set
        //                             .inactive
        //                             .remove(&weighed_validator_pre);
        //                         validator_set
        //                             .inactive
        //                             .insert(weighed_validator_post);
        //                     }
        //                 }
        //             }
        //             None => {
        //                 let tokens: u64 = token_delta.try_into().unwrap();
        //                 let weighed_validator = WeightedValidator {
        //                     bonded_stake: tokens,
        //                     address: validator.clone(),
        //                 };
        //                 if has_vacant_active_validator_slots(
        //                     params,
        //                     current_epoch,
        //                 ) {
        //                     validator_set.active.insert(weighed_validator);
        //                 } else {
        //                     validator_set.inactive.insert(weighed_validator);
        //                 }
        //             }
        //         }
        //     },
        //     current_epoch,
        //     offset,
        //     params,
        // );
        // // println!("Write validator set {:#?}", validator_set);
        // tx::ctx().write_validator_set(validator_set).unwrap();
    }

    pub fn arb_invalid_pos_action(
        valid_actions: Vec<ValidPosAction>,
    ) -> impl Strategy<Value = InvalidPosAction> {
        let arb_epoch = 0..10_000_u64;
        proptest::collection::vec(
            (arb_epoch, arb_invalid_pos_storage_changes(valid_actions)),
            1..=8,
        )
        .prop_map(|changes| InvalidPosAction {
            changes: changes
                .into_iter()
                .map(|(epoch, changes)| (Epoch(epoch), changes))
                .collect(),
        })
    }

    pub fn arb_invalid_pos_storage_changes(
        valid_actions: Vec<ValidPosAction>,
    ) -> impl Strategy<Value = PosStorageChanges> {
        let validators: Vec<Address> = valid_actions
            .iter()
            .filter_map(|action| match action {
                ValidPosAction::InitValidator { address, .. } => {
                    Some(address.clone())
                }
                _ => None,
            })
            .collect();

        let arb_address = address::testing::arb_established_address()
            .prop_map(Address::Established);
        let arb_address_or_validator = if validators.is_empty() {
            // When there is no validator, we can only initialize new ones
            arb_address.boxed()
        } else {
            let arb_validator = proptest::sample::select(validators);
            prop_oneof![arb_validator, arb_address].boxed()
        };

        let arb_offset = prop_oneof![
            Just(DynEpochOffset::PipelineLen),
            Just(DynEpochOffset::UnbondingLen)
        ];

        // any u64 but `0`
        let arb_delta =
            prop_oneof![(-(u32::MAX as i128)..0), (1..=u32::MAX as i128),];

        prop_oneof![
            (
                arb_address_or_validator.clone(),
                arb_address_or_validator,
                arb_offset,
                arb_delta,
            )
                .prop_map(|(validator, owner, offset, delta)| {
                    vec![
                        // We have to ensure that the addresses exists
                        PosStorageChange::SpawnAccount {
                            address: validator.clone(),
                        },
                        PosStorageChange::SpawnAccount {
                            address: owner.clone(),
                        },
                        PosStorageChange::Bond {
                            owner,
                            validator,
                            delta: delta.into(),
                            offset,
                        },
                    ]
                })
        ]
    }

    impl InvalidPosAction {
        /// Apply an invalid PoS storage action.
        pub fn apply(self) {
            // Read the PoS parameters
            let params =
                read_pos_params::<_, governance::Store<_>>(tx::ctx()).unwrap();

            for (epoch, changes) in self.changes {
                for change in changes {
                    apply_pos_storage_change(change, &params, epoch, false);
                }
            }
        }
    }

    /// Find if there are any vacant consensus validator slots
    pub fn has_vacant_consensus_validator_slots(
        params: &PosParams,
        current_epoch: Epoch,
    ) -> bool {
        let num_consensus_validators =
            get_num_consensus_validators(tx::ctx(), current_epoch).unwrap();
        params.max_validator_slots > num_consensus_validators
    }
}
