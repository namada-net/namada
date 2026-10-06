//! Regression tests for the unbacked stake forgery attack: an allowlisted
//! `tx_bond` naming the PoS internal address (`#PoS`) as the bond source.
//!
//! The token transfer of such a bond is a no-op transfer from `#PoS` to
//! `#PoS`, so no balance changes, while the bond, the validator deltas and the
//! total stake are still written. The bond is "authorized" only because the
//! tx adds `#PoS` to the verifiers set, and `#PoS`'s VP is the PoS VP itself.
//! The PoS VP must reject any bond whose source is an internal address.
//!
//! The defense lives in the native PoS VP only, so that the wasm txs are left
//! unchanged. These tests run the real `tx_bond.wasm`.

#[cfg(test)]
mod pos_unbacked_bond_tests {
    use std::cell::RefCell;

    use namada_apps_lib::wasm_loader;
    use namada_sdk::address::testing::established_address_2;
    use namada_sdk::address::{self, Address, InternalAddress};
    use namada_sdk::chain::ChainId;
    use namada_sdk::gas::VpGasMeter;
    use namada_sdk::proof_of_stake::OwnedPosParams;
    use namada_sdk::proof_of_stake::storage::{
        read_pos_params, read_total_stake,
    };
    use namada_sdk::proof_of_stake::test_utils::get_dummy_genesis_validator;
    use namada_sdk::storage::Epoch;
    use namada_sdk::token::{self, Amount};
    use namada_sdk::tx::data::pos::Bond;
    use namada_sdk::tx::{TX_BOND_WASM, Tx};
    use namada_sdk::validation::PosVp;

    use crate::native_vp::{TestNativeVpEnv, sign_tx, wasm_dir};
    use crate::tx::TestTxEnv;

    const EPOCH: Epoch = Epoch(1);

    /// Set up a tx env with PoS genesis and a single validator, whose address
    /// is returned
    fn init_tx_env() -> (TestTxEnv, Address) {
        let mut tx_env = TestTxEnv::default();
        namada_sdk::parameters::init_test_storage(&mut tx_env.state).unwrap();
        token::write_denom(
            &mut tx_env.state,
            &address::testing::nam(),
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();
        tx_env.state.in_mem_mut().block.epoch = EPOCH;
        let validator = get_dummy_genesis_validator();
        let validator_address = validator.address.clone();
        namada_sdk::proof_of_stake::test_utils::test_init_genesis::<
            _,
            namada_sdk::parameters::Store<_>,
            namada_sdk::governance::Store<_>,
            namada_sdk::token::Store<_>,
        >(
            &mut tx_env.state,
            OwnedPosParams::default(),
            std::iter::once(validator),
            EPOCH,
        )
        .unwrap();
        tx_env.state.commit_tx_batch();
        tx_env.state.commit_block().unwrap();
        tx_env.spawn_accounts([&validator_address]);
        (tx_env, validator_address)
    }

    /// Run the given bond through the real `tx_bond.wasm`, then the PoS VP
    fn run_bond(
        mut tx_env: TestTxEnv,
        bond: Bond,
    ) -> (TestTxEnv, namada_sdk::state::Result<()>) {
        let wasm_code =
            wasm_loader::read_wasm_or_exit(wasm_dir(), TX_BOND_WASM);
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(wasm_code, None).add_data(bond);
        sign_tx(&mut tx);
        tx_env.batched_tx = tx.batch_first_tx();
        tx_env
            .execute_tx()
            .expect("wasm tx execution should succeed");

        let gas_meter = RefCell::new(VpGasMeter::new_from_meter(
            &*tx_env.gas_meter.borrow(),
        ));
        let vp_env = TestNativeVpEnv::from_tx_env(
            tx_env,
            Address::Internal(InternalAddress::PoS),
        );
        let ctx = vp_env.ctx(&gas_meter);
        let result = PosVp::validate_tx(
            &ctx,
            &vp_env.tx_env.batched_tx.to_ref(),
            ctx.keys_changed,
            ctx.verifiers,
        );
        (vp_env.tx_env, result)
    }

    /// Read the total stake at the pipeline epoch, where new bonds land
    fn pipeline_total_stake(tx_env: &TestTxEnv) -> Amount {
        let params = read_pos_params::<_, namada_sdk::governance::Store<_>>(
            &tx_env.state,
        )
        .unwrap();
        read_total_stake(&tx_env.state, &params, EPOCH + params.pipeline_len)
            .unwrap()
    }

    /// A bond from the PoS address itself creates unbacked stake in the wasm
    /// tx, which the PoS VP must reject
    #[test]
    fn test_pos_bond_from_pos_address_rejected() {
        let (tx_env, validator) = init_tx_env();
        let stake_pre = pipeline_total_stake(&tx_env);
        let forged = Amount::native_whole(1_000_000);

        let (tx_env, result) = run_bond(
            tx_env,
            Bond {
                validator,
                amount: forged,
                source: Some(Address::Internal(InternalAddress::PoS)),
            },
        );

        // The wasm tx wrote the forged stake without moving any token
        assert_eq!(
            pipeline_total_stake(&tx_env),
            stake_pre.checked_add(forged).unwrap()
        );

        let err = result.expect_err(
            "PoS VP must reject a bond whose source is the PoS address",
        );
        assert!(
            err.to_string()
                .contains("Bond cannot be authorized by internal address"),
            "unexpected rejection reason: {err}"
        );
    }

    /// A regular delegation must still be accepted by the PoS VP
    #[test]
    fn test_pos_bond_from_delegator_allowed() {
        let (mut tx_env, validator) = init_tx_env();
        let delegator = established_address_2();
        let amount = Amount::native_whole(1_000);
        tx_env.spawn_accounts([&delegator]);
        tx_env.credit_tokens(&delegator, &address::testing::nam(), amount);

        let (_tx_env, result) = run_bond(
            tx_env,
            Bond {
                validator,
                amount,
                source: Some(delegator),
            },
        );
        result.expect("PoS VP must accept a regular delegation");
    }
}
