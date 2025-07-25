//! A tx for a PoS unbond that removes staked tokens from a self-bond or a
//! delegation to be withdrawn in or after unbonding epoch.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let unbond = transaction::pos::Unbond::try_from_slice(&data[..])
        .wrap_err("Failed to decode Unbond tx data")?;

    ctx.unbond_tokens(unbond.source.as_ref(), &unbond.validator, unbond.amount)
        .wrap_err("Failed to unbond tokens")?;

    debug_log!("Unbonded {} from {}", unbond.amount, unbond.validator);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    use namada_tests::log::test;
    use namada_tests::native_vp::TestNativeVpEnv;
    use namada_tests::native_vp::pos::init_pos;
    use namada_tests::tx::*;
    use namada_tests::validation::PosVp;
    use namada_tx_prelude::address::InternalAddress;
    use namada_tx_prelude::chain::ChainId;
    use namada_tx_prelude::dec::Dec;
    use namada_tx_prelude::gas::VpGasMeter;
    use namada_tx_prelude::key::RefTo;
    use namada_tx_prelude::key::testing::arb_common_keypair;
    use namada_tx_prelude::proof_of_stake::parameters::OwnedPosParams;
    use namada_tx_prelude::proof_of_stake::parameters::testing::arb_pos_params;
    use namada_tx_prelude::proof_of_stake::storage::{
        bond_handle, read_consensus_validator_set_addresses_with_stake,
        read_total_stake, read_validator_stake, unbond_handle,
    };
    use namada_tx_prelude::proof_of_stake::types::{
        GenesisValidator, WeightedValidator,
    };
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// In this test we setup the ledger and PoS system with an arbitrary
        /// initial state with 1 genesis validator, a delegation bond if the
        /// unbond is for a delegation, arbitrary PoS parameters, and
        /// we generate an arbitrary unbond that we'd like to apply.
        ///
        /// After we apply the unbond, we check that all the storage values
        /// in PoS system have been updated as expected and then we also check
        /// that this transaction is accepted by the PoS validity predicate.
        #[test]
        fn test_tx_unbond(
        (initial_stake, unbond) in arb_initial_stake_and_unbond(),
        // A key to sign the transaction
        key in arb_common_keypair(),
        pos_params in arb_pos_params(None)) {
            test_tx_unbond_aux(initial_stake, unbond, key, pos_params).unwrap()
        }
    }

    fn test_tx_unbond_aux(
        initial_stake: token::Amount,
        unbond: transaction::pos::Unbond,
        key: key::common::SecretKey,
        pos_params: OwnedPosParams,
    ) -> TxResult {
        // Remove the validator stake threshold for simplicity
        let pos_params = OwnedPosParams {
            validator_stake_threshold: token::Amount::zero(),
            ..pos_params
        };

        dbg!(&initial_stake, &unbond);
        let is_delegation = matches!(
            &unbond.source, Some(source) if *source != unbond.validator);

        let consensus_key = key::testing::keypair_1().ref_to();
        let protocol_key = key::testing::keypair_2().ref_to();

        let eth_cold_key = key::testing::keypair_3().ref_to();
        let eth_hot_key = key::testing::keypair_4().ref_to();
        let commission_rate = Dec::new(5, 2).expect("Cannot fail");
        let max_commission_rate_change = Dec::new(1, 2).expect("Cannot fail");

        let genesis_validators = [GenesisValidator {
            address: unbond.validator.clone(),
            tokens: if is_delegation {
                // If we're unbonding a delegation, we'll give the initial stake
                // to the delegation instead of the validator
                token::Amount::zero()
            } else {
                initial_stake
            },
            consensus_key,
            protocol_key,
            eth_cold_key,
            eth_hot_key,
            commission_rate,
            max_commission_rate_change,
            metadata: Default::default(),
        }];

        let pos_params =
            init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        let native_token = tx_host_env::with(|tx_env| {
            let native_token = tx_env.state.in_mem().native_token.clone();
            if is_delegation {
                let source = unbond.source.as_ref().unwrap();
                tx_env.spawn_accounts([source]);

                // To allow to unbond delegation, there must be a delegation
                // bond first.
                // First, credit the bond's source with the initial stake,
                // before we initialize the bond below
                tx_env.credit_tokens(source, &native_token, initial_stake);
            }
            native_token
        });

        // If delegation, initialize the bond with a delegation from the unbond
        // source, which will become active at pipeline offset. If a self-bond,
        // the bond is already active from genesis.
        if is_delegation {
            ctx().bond_tokens(
                unbond.source.as_ref(),
                &unbond.validator,
                initial_stake,
            )?;
        }
        tx_host_env::commit_tx_and_block();

        let tx_code = vec![];
        let tx_data = unbond.serialize_to_vec();
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(key);
        let signed_tx = tx;

        let unbond_src = unbond
            .source
            .clone()
            .unwrap_or_else(|| unbond.validator.clone());

        // Check that PoS balance is the same as the initial validator stake
        let pos_balance_key = token::storage_key::balance_key(
            &native_token,
            &Address::Internal(InternalAddress::PoS),
        );
        let pos_balance_pre: token::Amount = ctx()
            .read(&pos_balance_key)?
            .expect("PoS must have balance");
        assert_eq!(pos_balance_pre, initial_stake);

        let bond_handle = bond_handle(&unbond_src, &unbond.validator);

        let mut epoched_total_stake_pre: Vec<token::Amount> = Vec::new();
        let mut epoched_validator_stake_pre: Vec<token::Amount> = Vec::new();
        let mut epoched_bonds_pre: Vec<Option<token::Amount>> = Vec::new();
        let mut epoched_validator_set_pre: Vec<BTreeSet<WeightedValidator>> =
            Vec::new();

        for epoch in 0..=pos_params.withdrawable_epoch_offset() {
            epoched_total_stake_pre.push(read_total_stake(
                ctx(),
                &pos_params,
                Epoch(epoch),
            )?);
            epoched_validator_stake_pre.push(read_validator_stake(
                ctx(),
                &pos_params,
                &unbond.validator,
                Epoch(epoch),
            )?);
            epoched_bonds_pre
                .push(bond_handle.get_delta_val(ctx(), Epoch(epoch))?);
            epoched_validator_set_pre.push(
                read_consensus_validator_set_addresses_with_stake(
                    ctx(),
                    Epoch(epoch),
                )?,
            );
        }

        // Apply the unbond tx
        apply_tx(ctx(), signed_tx.batch_first_tx())?;

        // Read the data after the unbond tx is executed.
        // The following storage keys should be updated:
        //     - `#{PoS}/validator/#{validator}/deltas`
        //     - `#{PoS}/total_deltas`
        //     - `#{PoS}/validator_set`

        let mut epoched_bonds_post: Vec<Option<token::Amount>> = Vec::new();
        for epoch in 0..=pos_params.unbonding_len {
            epoched_bonds_post
                .push(bond_handle.get_delta_val(ctx(), Epoch(epoch))?);
        }

        let expected_amount_before_pipeline = if is_delegation {
            // When this is a delegation, there will be no bond until pipeline
            token::Amount::zero()
        } else {
            // Before pipeline offset, there can only be self-bond
            initial_stake
        };

        // Before pipeline offset, there can only be self-bond for genesis
        // validator. In case of a delegation the state is setup so that there
        // is no bond until pipeline offset.
        for epoch in 0..pos_params.pipeline_len {
            assert_eq!(
                read_validator_stake(
                    ctx(),
                    &pos_params,
                    &unbond.validator,
                    Epoch(epoch)
                )?,
                expected_amount_before_pipeline,
                "The validator deltas before the pipeline offset must not \
                 change - checking in epoch: {epoch}"
            );
            assert_eq!(
                read_total_stake(ctx(), &pos_params, Epoch(epoch))?,
                expected_amount_before_pipeline,
                "The total deltas before the pipeline offset must not change \
                 - checking in epoch: {epoch}"
            );
            assert_eq!(
                epoched_validator_set_pre[epoch as usize],
                read_consensus_validator_set_addresses_with_stake(
                    ctx(),
                    Epoch(epoch),
                )?,
                "Validator set before pipeline offset must not change - \
                 checking epoch {epoch}"
            );
        }

        // At and after pipeline offset, there can be either delegation or
        // self-bond, both of which are initialized to the same `initial_stake`
        for epoch in
            pos_params.pipeline_len..=pos_params.withdrawable_epoch_offset()
        {
            assert_eq!(
                read_validator_stake(
                    ctx(),
                    &pos_params,
                    &unbond.validator,
                    Epoch(epoch)
                )?,
                initial_stake - unbond.amount,
                "The validator stake at and after the pipeline offset must \
                 have changed - checking in epoch: {epoch}"
            );
            assert_eq!(
                read_total_stake(ctx(), &pos_params, Epoch(epoch))?,
                (initial_stake - unbond.amount),
                "The total stake at and after the pipeline offset must have \
                 changed - checking in epoch: {epoch}"
            );
            // Only at pipeline because the read won't return anything after
            if epoch == pos_params.pipeline_len {
                assert_ne!(
                    epoched_validator_set_pre[epoch as usize],
                    read_consensus_validator_set_addresses_with_stake(
                        ctx(),
                        Epoch(epoch),
                    )?,
                    "The validator set at and after pipeline offset should \
                     have changed - checking epoch {epoch}"
                );
            }
        }

        // Check that PoS account balance is unchanged by unbond
        let pos_balance_post: token::Amount =
            ctx().read(&pos_balance_key)?.unwrap();
        assert_eq!(
            pos_balance_pre, pos_balance_post,
            "Unbonding should not affect PoS system balance"
        );

        // Check that the unbond doesn't exist until unbonding offset
        let unbond_handle = unbond_handle(&unbond_src, &unbond.validator);
        let start_epoch = if is_delegation {
            // This bond was a delegation
            Epoch::from(pos_params.pipeline_len)
        } else {
            // This bond was a genesis validator self-bond
            Epoch::default()
        };
        let withdrawable_epoch = pos_params.withdrawable_epoch_offset();
        for epoch in 0..withdrawable_epoch {
            assert!(
                unbond_handle
                    .at(&start_epoch)
                    .get(ctx(), &Epoch(epoch))?
                    .is_none(),
                "There should be no unbond until the withdrawable offset - \
                 checking epoch {epoch}"
            );
        }

        // Ensure that the unbond is structured as expected, withdrawable at
        // pipeline + unbonding + cubic_slash_window offsets
        let actual_unbond_amount = unbond_handle
            .at(&start_epoch)
            .get(ctx(), &Epoch(withdrawable_epoch))?;
        assert_eq!(
            actual_unbond_amount,
            Some(unbond.amount),
            "Delegation at pipeline + unbonding + cubic window offset should \
             be equal to the unbonded amount"
        );

        for epoch in start_epoch.0..pos_params.withdrawable_epoch_offset() {
            let bond_amount =
                bond_handle.get_sum(ctx(), Epoch(epoch), &pos_params)?;

            let expected_amount = initial_stake - unbond.amount;
            assert_eq!(
                bond_amount,
                Some(expected_amount),
                "After the tx is applied, the bond should be changed in \
                 place, checking epoch {epoch}"
            );
        }

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
        assert!(
            result.is_ok(),
            "PoS Validity predicate must accept this transaction"
        );
        Ok(())
    }

    /// Generates an initial validator stake and a unbond, while making sure
    /// that the `initial_stake >= unbond.amount`.
    fn arb_initial_stake_and_unbond()
    -> impl Strategy<Value = (token::Amount, transaction::pos::Unbond)> {
        // Generate initial stake
        token::testing::arb_amount_ceiled((i64::MAX / 8) as u64).prop_flat_map(
            |initial_stake| {
                // Use the initial stake to limit the bond amount
                let unbond =
                    arb_unbond(u128::try_from(initial_stake).unwrap() as u64);
                // Use the generated initial stake too too
                (Just(initial_stake), unbond)
            },
        )
    }

    /// Generates an arbitrary unbond, with the amount constrained from above.
    fn arb_unbond(
        max_amount: u64,
    ) -> impl Strategy<Value = transaction::pos::Unbond> {
        (
            address::testing::arb_established_address(),
            prop::option::of(address::testing::arb_non_internal_address()),
            token::testing::arb_amount_non_zero_ceiled(max_amount),
        )
            .prop_map(|(validator, source, amount)| {
                let validator = Address::Established(validator);
                transaction::pos::Unbond {
                    validator,
                    amount,
                    source,
                }
            })
    }
}
