//! A tx for a PoS bond that stakes tokens via a self-bond or delegation.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let bond = transaction::pos::Bond::try_from_slice(&data[..])
        .wrap_err("Failed to decode Bond tx data")?;

    ctx.bond_tokens(bond.source.as_ref(), &bond.validator, bond.amount)
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
    use namada_tx_prelude::address::testing::{
        arb_established_address, arb_non_internal_address,
    };
    use namada_tx_prelude::chain::ChainId;
    use namada_tx_prelude::dec::Dec;
    use namada_tx_prelude::gas::VpGasMeter;
    use namada_tx_prelude::key::RefTo;
    use namada_tx_prelude::key::testing::arb_common_keypair;
    use namada_tx_prelude::proof_of_stake::parameters::OwnedPosParams;
    use namada_tx_prelude::proof_of_stake::parameters::testing::arb_pos_params;
    use namada_tx_prelude::proof_of_stake::storage::{
        bond_handle, read_consensus_validator_set_addresses_with_stake,
        read_total_stake, read_validator_stake,
    };
    use namada_tx_prelude::proof_of_stake::types::{
        GenesisValidator, WeightedValidator,
    };
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// In this test, we setup the ledger and PoS system with an arbitrary
        /// initial stake with 1 genesis validator and arbitrary PoS parameters. We then
        /// generate an arbitrary bond that we'd like to apply.
        ///
        /// After we apply the bond, we check that all the storage values
        /// in the PoS system have been updated as expected, and then we check
        /// that this transaction is accepted by the PoS validity predicate.
        #[test]
        fn test_tx_bond(
            (initial_stake, bond) in arb_initial_stake_and_bond(),
            // A key to sign the transaction
            key in arb_common_keypair(),
            pos_params in arb_pos_params(None)) {
            test_tx_bond_aux(initial_stake, bond, key, pos_params).unwrap()
        }
    }

    fn test_tx_bond_aux(
        initial_stake: token::Amount,
        bond: transaction::pos::Bond,
        key: key::common::SecretKey,
        pos_params: OwnedPosParams,
    ) -> TxResult {
        // Remove the validator stake threshold for simplicity
        let pos_params = OwnedPosParams {
            validator_stake_threshold: token::Amount::zero(),
            ..pos_params
        };

        dbg!(&initial_stake, &bond);
        let is_delegation =
            matches!(&bond.source, Some(source) if *source != bond.validator);
        let consensus_key = key::testing::keypair_1().ref_to();
        let protocol_key = key::testing::keypair_2().ref_to();
        let commission_rate = Dec::new(5, 2).expect("Cannot fail");
        let max_commission_rate_change = Dec::new(1, 2).expect("Cannot fail");
        let eth_cold_key = key::testing::keypair_3().ref_to();
        let eth_hot_key = key::testing::keypair_4().ref_to();

        let genesis_validators = [GenesisValidator {
            address: bond.validator.clone(),
            tokens: initial_stake,
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
            if let Some(source) = &bond.source {
                tx_env.spawn_accounts([source]);
            }

            // Ensure that the bond's source has enough tokens for the bond
            let target = bond.source.as_ref().unwrap_or(&bond.validator);
            let native_token = tx_env.state.in_mem().native_token.clone();
            tx_env.credit_tokens(target, &native_token, bond.amount);
            native_token
        });

        let tx_code = vec![];
        let tx_data = bond.serialize_to_vec();
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(key);

        let signed_tx = tx;

        // Ensure that the initial stake of the sole validator is equal to the
        // PoS account balance
        let pos_balance_key = token::storage_key::balance_key(
            &native_token,
            &Address::Internal(InternalAddress::PoS),
        );
        let pos_balance_pre: token::Amount = ctx()
            .read(&pos_balance_key)
            .unwrap()
            .expect("PoS must have balance");
        assert_eq!(pos_balance_pre, initial_stake);

        // Read some data before the tx is executed
        let mut epoched_total_stake_pre: Vec<token::Amount> = Vec::new();
        let mut epoched_validator_stake_pre: Vec<token::Amount> = Vec::new();
        let mut epoched_validator_set_pre: Vec<BTreeSet<WeightedValidator>> =
            Vec::new();

        for epoch in 0..=pos_params.unbonding_len {
            epoched_total_stake_pre.push(read_total_stake(
                ctx(),
                &pos_params,
                Epoch(epoch),
            )?);
            epoched_validator_stake_pre.push(read_validator_stake(
                ctx(),
                &pos_params,
                &bond.validator,
                Epoch(epoch),
            )?);
            epoched_validator_set_pre.push(
                read_consensus_validator_set_addresses_with_stake(
                    ctx(),
                    Epoch(epoch),
                )?,
            );
        }

        apply_tx(ctx(), signed_tx.batch_first_tx())?;

        // Read the data after the tx is executed.
        let mut epoched_total_stake_post: Vec<token::Amount> = Vec::new();
        let mut epoched_validator_stake_post: Vec<token::Amount> = Vec::new();
        let mut epoched_validator_set_post: Vec<BTreeSet<WeightedValidator>> =
            Vec::new();

        println!("\nFILLING POST STATE\n");

        for epoch in 0..=pos_params.unbonding_len {
            epoched_total_stake_post.push(read_total_stake(
                ctx(),
                &pos_params,
                Epoch(epoch),
            )?);
            epoched_validator_stake_post.push(read_validator_stake(
                ctx(),
                &pos_params,
                &bond.validator,
                Epoch(epoch),
            )?);
            epoched_validator_set_post.push(
                read_consensus_validator_set_addresses_with_stake(
                    ctx(),
                    Epoch(epoch),
                )?,
            );
        }

        // The following storage keys should be updated:

        //     - `#{PoS}/validator/#{validator}/deltas`
        //     - `#{PoS}/total_deltas`
        //     - `#{PoS}/validator_set`

        // Check that the validator set and deltas are unchanged before pipeline
        // length and that they are updated between the pipeline and
        // unbonding lengths
        if bond.amount.is_zero() {
            // None of the optional storage fields should have been updated
            assert_eq!(epoched_validator_set_pre, epoched_validator_set_post);
            assert_eq!(
                epoched_validator_stake_pre,
                epoched_validator_stake_post
            );
            assert_eq!(epoched_total_stake_pre, epoched_total_stake_post);
        } else {
            for epoch in 0..pos_params.pipeline_len as usize {
                assert_eq!(
                    epoched_validator_stake_post[epoch], initial_stake,
                    "The validator deltas before the pipeline offset must not \
                     change - checking in epoch: {epoch}"
                );
                assert_eq!(
                    epoched_total_stake_post[epoch], initial_stake,
                    "The total deltas before the pipeline offset must not \
                     change - checking in epoch: {epoch}"
                );
                assert_eq!(
                    epoched_validator_set_pre[epoch],
                    epoched_validator_set_post[epoch],
                    "Validator set before pipeline offset must not change - \
                     checking epoch {epoch}"
                );
            }
            for epoch in (pos_params.pipeline_len as usize)
                ..=pos_params.unbonding_len as usize
            {
                let expected_stake =
                    initial_stake.change() + bond.amount.change();
                assert_eq!(
                    epoched_validator_stake_post[epoch],
                    token::Amount::from_change(expected_stake),
                    "The total deltas at and after the pipeline offset epoch \
                     must be incremented by the bonded amount - checking in \
                     epoch: {epoch}"
                );
                assert_eq!(
                    epoched_total_stake_post[epoch],
                    token::Amount::from_change(expected_stake),
                    "The total deltas at and after the pipeline offset epoch \
                     must be incremented by the bonded amount - checking in \
                     epoch: {epoch}"
                );
                if epoch == pos_params.pipeline_len as usize {
                    assert_ne!(
                        epoched_validator_set_pre[epoch],
                        epoched_validator_set_post[epoch],
                        "Validator set at and after pipeline offset must have \
                         changed - checking epoch {epoch}"
                    );
                }
            }
        }

        //     - `#{staking_token}/balance/#{PoS}`
        // Check that PoS balance is updated
        let pos_balance_post: token::Amount =
            ctx().read(&pos_balance_key)?.unwrap();
        assert_eq!(pos_balance_pre + bond.amount, pos_balance_post);

        //     - `#{PoS}/bond/#{owner}/#{validator}`
        let bond_src = bond
            .source
            .clone()
            .unwrap_or_else(|| bond.validator.clone());

        let bonds_post = bond_handle(&bond_src, &bond.validator);
        // let bonds_post = ctx().read_bond(&bond_id)?.unwrap();

        if is_delegation {
            // A delegation is applied at pipeline offset
            // Check that bond is empty before pipeline offset
            for epoch in 0..pos_params.pipeline_len {
                let bond =
                    bonds_post.get_sum(ctx(), Epoch(epoch), &pos_params)?;
                assert!(
                    bond.is_none(),
                    "Delegation before pipeline offset should be empty - \
                     checking epoch {epoch}, got {bond:#?}"
                );
            }
            // Check that bond is updated after the pipeline length
            for epoch in pos_params.pipeline_len..=pos_params.unbonding_len {
                let expected_bond_amount = bond.amount;
                let bond =
                    bonds_post.get_sum(ctx(), Epoch(epoch), &pos_params)?;
                assert_eq!(
                    bond,
                    Some(expected_bond_amount),
                    "Delegation at and after pipeline offset should be equal \
                     to the bonded amount - checking epoch {epoch}"
                );
            }
        } else {
            // This is a self-bond
            // Check that a bond already exists from genesis with initial stake
            // for the validator
            for epoch in 0..pos_params.pipeline_len {
                let expected_bond_amount = initial_stake;
                let bond = bonds_post
                    .get_sum(ctx(), Epoch(epoch), &pos_params)
                    .expect("Genesis validator should already have self-bond");
                assert_eq!(
                    bond,
                    Some(expected_bond_amount),
                    "Self-bond before pipeline offset should be equal to the \
                     genesis initial stake - checking epoch {epoch}"
                );
            }
            // Check that the bond is updated after the pipeline length
            for epoch in pos_params.pipeline_len..=pos_params.unbonding_len {
                let expected_bond_amount = initial_stake + bond.amount;
                let bond =
                    bonds_post.get_sum(ctx(), Epoch(epoch), &pos_params)?;
                assert_eq!(
                    bond,
                    Some(expected_bond_amount),
                    "Self-bond at and after pipeline offset should contain \
                     genesis stake and the bonded amount - checking epoch \
                     {epoch}"
                );
            }
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

    prop_compose! {
        /// Generates an initial validator stake and a bond, while making sure
        /// that the `initial_stake + bond.amount <= u64::MAX` to avoid
        /// overflow.
        fn arb_initial_stake_and_bond()
            // Generate initial stake
            (initial_stake in token::testing::arb_amount_ceiled((i64::MAX/8) as u64))
            // Use the initial stake to limit the bond amount
            (bond in arb_bond(((i64::MAX/8) as u64) - u128::try_from(initial_stake).unwrap() as u64),
            // Use the generated initial stake too
            initial_stake in Just(initial_stake),
        ) -> (token::Amount, transaction::pos::Bond) {
            (initial_stake, bond)
        }
    }

    fn arb_bond(
        max_amount: u64,
    ) -> impl Strategy<Value = transaction::pos::Bond> {
        (
            arb_established_address(),
            prop::option::of(arb_non_internal_address()),
            token::testing::arb_amount_non_zero_ceiled(max_amount),
        )
            .prop_map(|(validator, source, amount)| {
                transaction::pos::Bond {
                    validator: Address::Established(validator),
                    amount,
                    source,
                }
            })
    }
}
