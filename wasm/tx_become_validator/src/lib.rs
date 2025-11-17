//! A tx to initialize a new validator account with a given public keys and a
//! validity predicates.

use booleans::ResultBoolExt;
use namada_tx_prelude::transaction::pos::BecomeValidator;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let become_validator = BecomeValidator::try_from_slice(&data[..])
        .wrap_err("Failed to decode BecomeValidator tx data")?;
    debug_log!("apply_tx called to init a new validator account");

    // Check that the tx has been signed with all the keys to be used for the
    // validator account
    let all_pks = vec![
        become_validator.consensus_key.clone(),
        key::common::PublicKey::Secp256k1(
            become_validator.eth_cold_key.clone(),
        ),
        key::common::PublicKey::Secp256k1(become_validator.eth_hot_key.clone()),
        become_validator.protocol_key.clone(),
    ];
    verify_signatures_of_pks(&tx_data.tx, all_pks).ext_true_or_else(|| {
        const ERR_MSG: &str = "Keys ownership signature verification failed";
        debug_log!("{ERR_MSG}");
        Error::new_const(ERR_MSG)
    })?;

    // Register the validator in PoS
    let validator_address = ctx
        .become_validator(become_validator)
        .wrap_err("Validator creation failed")?;

    debug_log!("Created validator {validator_address}");
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
    use namada_tx_prelude::account::AccountPublicKeysMap;
    use namada_tx_prelude::address::testing::{
        established_address_1, established_address_2,
    };
    use namada_tx_prelude::chain::ChainId;
    use namada_tx_prelude::dec::{Dec, POS_DECIMAL_PRECISION};
    use namada_tx_prelude::gas::VpGasMeter;
    use namada_tx_prelude::key::{RefTo, common};
    use namada_tx_prelude::proof_of_stake::parameters::OwnedPosParams;
    use namada_tx_prelude::proof_of_stake::types::GenesisValidator;

    use super::*;

    /// Test that a valid signed tx_become_validator is accepted by PoS VP
    #[test]
    fn test_valid_become_validator_accepted() {
        init_tx_env_with_pos();

        let validator = established_address_2();
        tx_host_env::with(|tx_env| {
            tx_env.spawn_accounts([validator.clone()]);
        });
        let account_key = key::testing::keypair_1();
        let consensus_key = key::testing::keypair_2();
        let protocol_key = key::testing::keypair_3();

        let eth_hot_key =
            key::testing::gen_keypair::<key::secp256k1::SigScheme>();
        let eth_cold_key =
            key::testing::gen_keypair::<key::secp256k1::SigScheme>();
        let become_validator = BecomeValidator {
            address: validator.clone(),
            consensus_key: consensus_key.to_public(),
            eth_cold_key: eth_cold_key.ref_to(),
            eth_hot_key: eth_hot_key.ref_to(),
            protocol_key: protocol_key.to_public(),
            commission_rate: Dec::new(5, 2).expect("Cannot fail"),
            max_commission_rate_change: Dec::new(1, 2).expect("Cannot fail"),
            email: "bang@my.bong".to_owned(),
            description: None,
            website: None,
            discord_handle: None,
            avatar: None,
            name: None,
        };

        apply_become_validator_tx(
            become_validator,
            account_key,
            vec![
                consensus_key,
                protocol_key,
                common::SecretKey::Secp256k1(eth_hot_key),
                common::SecretKey::Secp256k1(eth_cold_key),
            ],
        )
        .unwrap();

        let result = run_pos_vp();
        assert!(
            result.is_ok(),
            "PoS Validity predicate must accept this transaction, but got \
             {result:?}",
        );
    }

    /// Test that tx_become_validator missing a signature for one of its keys
    /// fails
    #[test]
    fn test_become_validator_missing_sig_fails() {
        // Remove one of the 4 other keys used for the validator from tx auth
        for removed_key_ix in 0..4 {
            init_tx_env_with_pos();

            let validator = established_address_2();
            tx_host_env::with(|tx_env| {
                tx_env.spawn_accounts([validator.clone()]);
            });
            let account_key = key::testing::keypair_1();
            let consensus_key = key::testing::keypair_2();
            let protocol_key = key::testing::keypair_3();

            let eth_hot_key =
                key::testing::gen_keypair::<key::secp256k1::SigScheme>();
            let eth_cold_key =
                key::testing::gen_keypair::<key::secp256k1::SigScheme>();
            let become_validator = BecomeValidator {
                address: validator.clone(),
                consensus_key: consensus_key.to_public(),
                eth_cold_key: eth_cold_key.ref_to(),
                eth_hot_key: eth_hot_key.ref_to(),
                protocol_key: protocol_key.to_public(),
                commission_rate: Dec::new(5, 2).unwrap(),
                max_commission_rate_change: Dec::new(1, 2).unwrap(),
                email: "bang@my.bong".to_owned(),
                description: None,
                website: None,
                discord_handle: None,
                avatar: None,
                name: None,
            };

            let mut other_keys = vec![
                consensus_key,
                protocol_key,
                common::SecretKey::Secp256k1(eth_hot_key),
                common::SecretKey::Secp256k1(eth_cold_key),
            ];
            other_keys.remove(removed_key_ix);

            let result = apply_become_validator_tx(
                become_validator,
                account_key,
                other_keys,
            );

            assert!(result.is_err(), "Tx should fail, but got {result:?}",);
        }
    }

    /// Check that invalid commission rates are rejected by PoS VP.
    #[test]
    fn test_invalid_commission_rate_rejected() {
        for commission_rate in
            [-Dec::one(), -(Dec::new(1, POS_DECIMAL_PRECISION).unwrap())]
        {
            init_tx_env_with_pos();

            let validator = established_address_2();
            tx_host_env::with(|tx_env| {
                tx_env.spawn_accounts([validator.clone()]);
            });
            let account_key = key::testing::keypair_1();
            let consensus_key = key::testing::keypair_2();
            let protocol_key = key::testing::keypair_3();

            let eth_hot_key =
                key::testing::gen_keypair::<key::secp256k1::SigScheme>();
            let eth_cold_key =
                key::testing::gen_keypair::<key::secp256k1::SigScheme>();
            let become_validator = BecomeValidator {
                address: validator.clone(),
                consensus_key: consensus_key.to_public(),
                eth_cold_key: eth_cold_key.ref_to(),
                eth_hot_key: eth_hot_key.ref_to(),
                protocol_key: protocol_key.to_public(),
                commission_rate,
                max_commission_rate_change: Dec::one(),
                email: "bang@my.bong".to_owned(),
                description: None,
                website: None,
                discord_handle: None,
                avatar: None,
                name: None,
            };

            apply_become_validator_tx(
                become_validator,
                account_key,
                vec![
                    consensus_key,
                    protocol_key,
                    common::SecretKey::Secp256k1(eth_hot_key),
                    common::SecretKey::Secp256k1(eth_cold_key),
                ],
            )
            .unwrap();

            let result = run_pos_vp();
            assert!(
                result.is_err(),
                "PoS Validity predicate must reject this transaction, but got \
                 {result:?}",
            );
        }
    }

    /// Init tx env with a single genesis PoS validator
    fn init_tx_env_with_pos() {
        tx_host_env::init();

        let pos_params = OwnedPosParams::default();
        let genesis_validators = [GenesisValidator {
            address: established_address_1(),
            tokens: pos_params.validator_stake_threshold,
            consensus_key: key::testing::keypair_1().ref_to(),
            protocol_key: key::testing::keypair_2().ref_to(),
            commission_rate: Dec::new(5, 2).unwrap(),
            max_commission_rate_change: Dec::new(1, 2).unwrap(),
            eth_cold_key: key::testing::keypair_3().ref_to(),
            eth_hot_key: key::testing::keypair_4().ref_to(),
            metadata: Default::default(),
        }];

        let _pos_params =
            init_pos(&genesis_validators[..], &pos_params, Epoch(0));
    }

    /// Apply the become_validator tx in `tx_host_env`
    fn apply_become_validator_tx(
        become_validator: BecomeValidator,
        account_key: common::SecretKey,
        other_keys: Vec<common::SecretKey>,
    ) -> TxResult {
        let tx_data = become_validator.serialize_to_vec();
        let mut tx = Tx::new(ChainId::default(), None);

        let tx_code = vec![];
        tx.add_code(tx_code, None).add_serialized_data(tx_data);

        let pks_map = AccountPublicKeysMap::from_iter(
            other_keys
                .iter()
                .map(common::SecretKey::to_public)
                .collect::<Vec<_>>(),
        );
        tx.sign_raw(other_keys, pks_map, None);

        tx.sign_wrapper(account_key.clone());

        let tx = tx.batch_first_tx();
        // Put the tx inside the tx_env - it's needed for sig verification
        tx_host_env::with(|tx_env| {
            tx_env.batched_tx = tx.clone();
        });
        apply_tx(ctx(), tx)
    }

    /// Use the `tx_host_env` to run PoS VP
    fn run_pos_vp() -> TxResult {
        let tx_env = tx_host_env::take();
        let gas_meter = RefCell::new(VpGasMeter::new_from_meter(
            &*tx_env.gas_meter.borrow(),
        ));
        let vp_env = TestNativeVpEnv::from_tx_env(tx_env, address::POS);
        let ctx = vp_env.ctx(&gas_meter);
        PosVp::validate_tx(
            &ctx,
            &vp_env.tx_env.batched_tx.to_ref(),
            &vp_env.keys_changed,
            &vp_env.verifiers,
        )
    }
}
