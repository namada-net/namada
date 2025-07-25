//! A tx for a validator to change their commission rate for PoS rewards.

use namada_tx_prelude::transaction::pos::CommissionChange;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let CommissionChange {
        validator,
        new_rate,
    } = transaction::pos::CommissionChange::try_from_slice(&data[..])
        .wrap_err("Failed to decode CommissionChange value")?;
    ctx.change_validator_commission_rate(&validator, &new_rate)
        .wrap_err("Failed to change validator's commission rate")
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::cmp;

    use namada_tests::log::test;
    use namada_tests::native_vp::TestNativeVpEnv;
    use namada_tests::native_vp::pos::init_pos;
    use namada_tests::tx::*;
    use namada_tests::validation::PosVp;
    use namada_tx_prelude::address::testing::arb_established_address;
    use namada_tx_prelude::chain::ChainId;
    use namada_tx_prelude::dec::{Dec, POS_DECIMAL_PRECISION};
    use namada_tx_prelude::gas::VpGasMeter;
    use namada_tx_prelude::key::RefTo;
    use namada_tx_prelude::key::testing::arb_common_keypair;
    use namada_tx_prelude::proof_of_stake::parameters::OwnedPosParams;
    use namada_tx_prelude::proof_of_stake::parameters::testing::arb_pos_params;
    use namada_tx_prelude::proof_of_stake::storage::validator_commission_rate_handle;
    use namada_tx_prelude::proof_of_stake::types::GenesisValidator;
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// In this test we setup the ledger and PoS system with an arbitrary
        /// initial state with 1 genesis validator and arbitrary PoS parameters.
        /// We then generate an validator commission rate change that we'd like
        /// to apply.
        ///
        /// After we apply the tx, we check that all the storage values
        /// in PoS system have been updated as expected and then we also check
        /// that this transaction is accepted by the PoS validity predicate.
        #[test]
        fn test_tx_change_validator_commissions(
            (initial_rate, max_change, commission_change) in arb_commission_info(),
            // A key to sign the transaction
            key in arb_common_keypair(),
            pos_params in arb_pos_params(None)) {
            test_tx_change_validator_commission_aux(
                initial_rate, max_change, commission_change, key, pos_params).unwrap()
        }
    }

    fn test_tx_change_validator_commission_aux(
        initial_rate: Dec,
        max_change: Dec,
        commission_change: transaction::pos::CommissionChange,
        key: key::common::SecretKey,
        pos_params: OwnedPosParams,
    ) -> TxResult {
        let consensus_key = key::testing::keypair_1().ref_to();
        let protocol_key = key::testing::keypair_2().ref_to();

        let eth_hot_key = key::common::PublicKey::Secp256k1(
            key::testing::gen_keypair::<key::secp256k1::SigScheme>().ref_to(),
        );
        let eth_cold_key = key::common::PublicKey::Secp256k1(
            key::testing::gen_keypair::<key::secp256k1::SigScheme>().ref_to(),
        );
        let genesis_validators = [GenesisValidator {
            address: commission_change.validator.clone(),
            tokens: token::Amount::from_uint(1_000_000, 0).unwrap(),
            consensus_key,
            protocol_key,
            commission_rate: initial_rate,
            max_commission_rate_change: max_change,
            eth_hot_key,
            eth_cold_key,
            metadata: Default::default(),
        }];

        let pos_params =
            init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        let tx_code = vec![];
        let tx_data = commission_change.serialize_to_vec();
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(tx_code, None)
            .add_serialized_data(tx_data)
            .sign_wrapper(key);

        let signed_tx = tx;

        // Read the data before the tx is executed
        let commission_rate_handle =
            validator_commission_rate_handle(&commission_change.validator);

        let mut commission_rates_pre = Vec::<Option<Dec>>::new();
        for epoch in Epoch::default().iter_range(pos_params.unbonding_len + 1) {
            commission_rates_pre.push(commission_rate_handle.get(
                ctx(),
                epoch,
                &pos_params,
            )?)
        }

        assert_eq!(commission_rates_pre[0], Some(initial_rate));

        apply_tx(ctx(), signed_tx.batch_first_tx())?;

        // Read the data after the tx is executed

        // The following storage keys should be updated:

        //     - `#{PoS}/validator/#{validator}/commission_rate`

        // Before pipeline, the commission rates should not change
        for epoch in 0..pos_params.pipeline_len {
            assert_eq!(
                commission_rates_pre[epoch as usize],
                commission_rate_handle.get(ctx(), Epoch(epoch), &pos_params)?,
                "The commission rates before the pipeline offset must not \
                 change - checking in epoch: {epoch}"
            );
            assert_eq!(
                Some(initial_rate),
                commission_rate_handle.get(ctx(), Epoch(epoch), &pos_params)?,
                "The commission rates before the pipeline offset must not \
                 change - checking in epoch: {epoch}"
            );
        }

        // After pipeline, the commission rates should have changed
        for epoch in pos_params.pipeline_len..=pos_params.unbonding_len {
            assert_eq!(
                Some(commission_change.new_rate),
                commission_rate_handle.get(ctx(), Epoch(epoch), &pos_params)?,
                "The commission rate after the pipeline offset must be the \
                 new_rate - checking in epoch: {epoch}"
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

    fn arb_rate(min: Dec, max: Dec) -> impl Strategy<Value = Dec> {
        let int_min: i128 = (min * scale()).try_into().unwrap();
        let int_max: i128 = (max * scale()).try_into().unwrap();
        (int_min..=int_max).prop_map(|num| {
            Dec::new(num, POS_DECIMAL_PRECISION).unwrap() / scale()
        })
    }

    fn arb_new_rate(
        rate_pre: Dec,
        max_change: Dec,
    ) -> impl Strategy<Value = Dec> {
        assert!(max_change > Dec::zero());
        // Arbitrary non-zero change
        let arb_change = |ceil: Dec| {
            // Clamp the `ceil` to `max_change` and convert to an int
            let ceil = (cmp::min(max_change, ceil) * scale()).abs().as_u128();
            (1..ceil).prop_map(|c|
                // Convert back from an int
                 Dec::new(c as i128, POS_DECIMAL_PRECISION).unwrap() / scale())
        };

        // Addition
        let arb_add = || {
            arb_change(
                // Addition must not go over 1
                Dec::one() - rate_pre,
            )
            .prop_map(move |c| rate_pre + c)
        };
        // Subtraction
        let arb_sub = || {
            arb_change(
                // Sub must not go below 0
                rate_pre,
            )
            .prop_map(move |c| rate_pre - c)
        };

        // Add or subtract from the previous rate
        if rate_pre == Dec::zero() {
            arb_add().boxed()
        } else if rate_pre == Dec::one() {
            arb_sub().boxed()
        } else {
            prop_oneof![arb_add(), arb_sub()].boxed()
        }
    }

    fn arb_commission_change(
        rate_pre: Dec,
        max_change: Dec,
    ) -> impl Strategy<Value = transaction::pos::CommissionChange> {
        (
            arb_established_address(),
            if max_change.is_zero() {
                Just(Dec::zero()).boxed()
            } else {
                arb_new_rate(rate_pre, max_change).boxed()
            },
        )
            .prop_map(|(validator, new_rate)| {
                transaction::pos::CommissionChange {
                    validator: Address::Established(validator),
                    new_rate,
                }
            })
    }

    fn arb_commission_info()
    -> impl Strategy<Value = (Dec, Dec, transaction::pos::CommissionChange)>
    {
        let min = Dec::zero();
        let max = Dec::one();
        let non_zero_min = Dec::one() / scale();
        (arb_rate(min, max), arb_rate(non_zero_min, max)).prop_flat_map(
            |(rate, max_change)| {
                (
                    Just(rate),
                    Just(max_change),
                    arb_commission_change(rate, max_change),
                )
            },
        )
    }

    fn scale() -> Dec {
        Dec::new(100_000, 0).unwrap()
    }
}
