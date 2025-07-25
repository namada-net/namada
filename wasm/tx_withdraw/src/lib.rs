//! A tx for a PoS unbond that removes staked tokens from a self-bond or a
//! delegation to be withdrawn in or after unbonding epoch.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let withdraw = transaction::pos::Withdraw::try_from_slice(&data[..])
        .wrap_err("Failed to decode Withdraw tx data")?;

    let slashed = ctx
        .withdraw_tokens(withdraw.source.as_ref(), &withdraw.validator)
        .wrap_err("Failed to withdraw tokens")?;
    if !slashed.is_zero() {
        debug_log!("New withdrawal slashed for {}", slashed.to_string_native());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

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
    use namada_tx_prelude::proof_of_stake::storage::unbond_handle;
    use namada_tx_prelude::proof_of_stake::types::GenesisValidator;
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// In this test we setup the ledger and PoS system with an arbitrary
        /// initial state with 1 genesis validator, a delegation bond if the
        /// withdrawal is for a delegation, arbitrary PoS parameters and
        /// a we generate an arbitrary withdrawal that we'd like to apply.
        ///
        /// After we apply the withdrawal, we're checking that all the storage
        /// values in PoS system have been updated as expected and then we also
        /// check that this transaction is accepted by the PoS validity
        /// predicate.
        #[test]
        fn test_tx_withdraw(
        (initial_stake, unbonded_amount) in arb_initial_stake_and_unbonded_amount(),
        withdraw in arb_withdraw(),
        // A key to sign the transaction
        key in arb_common_keypair(),
        pos_params in arb_pos_params(None)) {
            test_tx_withdraw_aux(initial_stake, unbonded_amount, withdraw, key,
                pos_params).unwrap()
        }
    }

    fn test_tx_withdraw_aux(
        initial_stake: token::Amount,
        unbonded_amount: token::Amount,
        withdraw: transaction::pos::Withdraw,
        key: key::common::SecretKey,
        pos_params: OwnedPosParams,
    ) -> TxResult {
        // Remove the validator stake threshold for simplicity
        let pos_params = OwnedPosParams {
            validator_stake_threshold: token::Amount::zero(),
            ..pos_params
        };

        let is_delegation = matches!(
            &withdraw.source, Some(source) if *source != withdraw.validator);
        let consensus_key = key::testing::keypair_1().ref_to();
        let protocol_key = key::testing::keypair_2().ref_to();

        let eth_cold_key = key::testing::keypair_3().ref_to();
        let eth_hot_key = key::testing::keypair_4().ref_to();
        let commission_rate = Dec::new(5, 2).expect("Cannot fail");
        let max_commission_rate_change = Dec::new(1, 2).expect("Cannot fail");

        let genesis_validators = [GenesisValidator {
            address: withdraw.validator.clone(),
            tokens: if is_delegation {
                // If we're withdrawing a delegation, we'll give the initial
                // stake to the delegation instead of the
                // validator
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
                let source = withdraw.source.as_ref().unwrap();
                tx_env.spawn_accounts([source]);

                // To allow to unbond delegation, there must be a delegation
                // bond first.
                // First, credit the bond's source with the initial stake,
                // before we initialize the bond below
                tx_env.credit_tokens(source, &native_token, initial_stake);
            }
            native_token
        });

        if is_delegation {
            // Initialize the delegation - unlike genesis validator's self-bond,
            // this happens at pipeline offset
            ctx().bond_tokens(
                withdraw.source.as_ref(),
                &withdraw.validator,
                initial_stake,
            )?;
        }

        // Unbond the `unbonded_amount` at the starting epoch 0
        ctx().unbond_tokens(
            withdraw.source.as_ref(),
            &withdraw.validator,
            unbonded_amount,
        )?;

        tx_host_env::commit_tx_and_block();

        // Fast forward to pipeline + unbonding + cubic_slashing_window_length
        // offset epoch so that it's possible to withdraw the unbonded
        // tokens
        tx_host_env::with(|env| {
            for _ in 0..(pos_params.pipeline_len
                + pos_params.unbonding_len
                + pos_params.cubic_slashing_window_length)
            {
                env.state.in_mem_mut().block.epoch =
                    env.state.in_mem().block.epoch.next();
            }
        });
        let bond_epoch = if is_delegation {
            Epoch(pos_params.pipeline_len)
        } else {
            Epoch::default()
        };
        let withdraw_epoch = Epoch(
            pos_params.pipeline_len
                + pos_params.unbonding_len
                + pos_params.cubic_slashing_window_length,
        );

        assert_eq!(
            tx_host_env::with(|env| env.state.in_mem().block.epoch),
            Epoch(
                pos_params.pipeline_len
                    + pos_params.unbonding_len
                    + pos_params.cubic_slashing_window_length
            )
        );

        let tx_code = vec![];
        let tx_data = withdraw.serialize_to_vec();
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(key);
        let signed_tx = tx;

        // Read data before we apply tx:
        let pos_balance_key = token::storage_key::balance_key(
            &native_token,
            &Address::Internal(InternalAddress::PoS),
        );
        let pos_balance_pre: token::Amount = ctx()
            .read(&pos_balance_key)?
            .expect("PoS must have balance");
        assert_eq!(pos_balance_pre, initial_stake);
        let unbond_src = withdraw
            .source
            .clone()
            .unwrap_or_else(|| withdraw.validator.clone());

        let handle = unbond_handle(&unbond_src, &withdraw.validator);

        let unbond_pre =
            handle.at(&bond_epoch).get(ctx(), &withdraw_epoch).unwrap();

        assert_eq!(unbond_pre, Some(unbonded_amount));

        apply_tx(ctx(), signed_tx.batch_first_tx())?;

        // Read the data after the tx is executed
        let unbond_post =
            handle.at(&withdraw_epoch).get(ctx(), &bond_epoch).unwrap();
        assert!(
            unbond_post.is_none(),
            "Because we're withdraw the full unbonded amount, there should be \
             no unbonds left"
        );
        let pos_balance_post: token::Amount = ctx()
            .read(&pos_balance_key)?
            .expect("PoS must have balance");
        assert_eq!(pos_balance_pre - pos_balance_post, unbonded_amount);

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

    fn arb_initial_stake_and_unbonded_amount()
    -> impl Strategy<Value = (token::Amount, token::Amount)> {
        // Generate initial stake
        token::testing::arb_amount_non_zero_ceiled((i64::MAX / 8) as u64)
            .prop_flat_map(|initial_stake| {
                // Use the initial stake to limit the unbonded amount from the
                // stake
                let unbonded_amount =
                    token::testing::arb_amount_non_zero_ceiled(
                        u128::try_from(initial_stake).unwrap() as u64,
                    );
                // Use the generated initial stake too too
                (Just(initial_stake), unbonded_amount)
            })
    }

    fn arb_withdraw() -> impl Strategy<Value = transaction::pos::Withdraw> {
        (
            arb_established_address(),
            prop::option::of(arb_non_internal_address()),
        )
            .prop_map(|(validator, source)| {
                transaction::pos::Withdraw {
                    validator: Address::Established(validator),
                    source,
                }
            })
    }
}
