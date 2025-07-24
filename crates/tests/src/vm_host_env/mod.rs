//! VM host environment integration tests.
//!
//! You can enable logging with the `RUST_LOG` environment variable, e.g.:
//!
//! `RUST_LOG=debug cargo test`.
//!
//! Because the test runner captures the standard output from the test, this
//! will only print logging from failed tests. To avoid that, use the
//! `--nocapture` argument. Also, because by default the tests run in parallel,
//! it is better to select a single test, e.g.:
//!
//! `RUST_LOG=debug cargo test test_tx_read_write -- --nocapture`

#[cfg(test)]
pub mod ibc;
pub mod tx;
pub mod vp;

#[cfg(test)]
mod tests {

    use std::collections::BTreeSet;
    use std::panic;

    use itertools::Itertools;
    use namada_core::chain::testing::get_dummy_header;
    use namada_sdk::account::pks_handle;
    use namada_sdk::borsh::BorshSerializeExt;
    use namada_sdk::collections::HashSet;
    use namada_sdk::hash::Hash;
    use namada_sdk::ibc::context::nft_transfer_mod::testing::DummyNftTransferModule;
    use namada_sdk::ibc::context::transfer_mod::testing::DummyTransferModule;
    use namada_sdk::ibc::primitives::ToProto;
    use namada_sdk::ibc::{
        Error as IbcActionError, storage as ibc_storage, trace as ibc_trace,
    };
    use namada_sdk::key::*;
    use namada_sdk::storage::{self, BlockHeight, Key, KeySeg};
    use namada_sdk::time::DateTimeUtc;
    use namada_sdk::token::{self, Amount};
    use namada_sdk::tx::Tx;
    use namada_sdk::{address, key};
    use namada_test_utils::TestWasms;
    use namada_tx_env::TxEnv;
    use namada_tx_prelude::address::InternalAddress;
    use namada_tx_prelude::chain::ChainId;
    use namada_tx_prelude::{Address, BatchedTx, StorageRead, StorageWrite};
    use namada_vp_prelude::account::AccountPublicKeysMap;
    use namada_vp_prelude::{VpEnv, sha256};
    use prost::Message;
    use test_log::test;

    use super::{ibc, tx, vp};
    use crate::tx::{TestTxEnv, tx_host_env};
    use crate::vp::{TestVpEnv, vp_host_env};

    #[test]
    fn test_tx_read_write() {
        // The environment must be initialized first
        tx_host_env::init();

        let key = storage::Key::parse("key").unwrap();
        let read_value: Option<String> = tx::ctx().read(&key).unwrap();
        assert_eq!(
            None, read_value,
            "Trying to read a key that doesn't exists shouldn't find any value"
        );

        // Write some value
        let value = "test".repeat(4);
        tx::ctx().write(&key, value.clone()).unwrap();

        let read_value: Option<String> = tx::ctx().read(&key).unwrap();
        assert_eq!(
            Some(value),
            read_value,
            "After a value has been written, we should get back the same \
             value when we read it"
        );

        let value = vec![1_u8; 1000];
        tx::ctx().write(&key, value.clone()).unwrap();
        let read_value: Option<Vec<u8>> = tx::ctx().read(&key).unwrap();
        assert_eq!(
            Some(value),
            read_value,
            "Writing to an existing key should override the previous value"
        );
    }

    #[test]
    fn test_tx_has_key() {
        // The environment must be initialized first
        tx_host_env::init();

        let key = storage::Key::parse("key").unwrap();
        assert!(
            !tx::ctx().has_key(&key).unwrap(),
            "Before a key-value is written, its key shouldn't be found"
        );

        // Write some value
        let value = "test".to_string();
        tx::ctx().write(&key, value).unwrap();

        assert!(
            tx::ctx().has_key(&key).unwrap(),
            "After a key-value has been written, its key should be found"
        );
    }

    #[test]
    fn test_tx_delete() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        let test_account = address::testing::established_address_1();
        env.spawn_accounts([&test_account]);
        tx_host_env::set(env);

        // Trying to delete a key that doesn't exists should be a no-op
        let key = storage::Key::parse("key").unwrap();
        tx::ctx().delete(&key).unwrap();

        let value = "test".to_string();
        tx::ctx().write(&key, value).unwrap();
        assert!(
            tx::ctx().has_key(&key).unwrap(),
            "After a key-value has been written, its key should be found"
        );

        // Then delete it
        tx::ctx().delete(&key).unwrap();

        assert!(
            !tx::ctx().has_key(&key).unwrap(),
            "After a key has been deleted, its key shouldn't be found"
        );

        // Trying to delete a validity predicate should fail
        let key = storage::Key::validity_predicate(&test_account);
        assert!(
            panic::catch_unwind(|| { tx::ctx().delete(&key).unwrap() })
                .err()
                .map(|a| a.downcast_ref::<String>().cloned().unwrap())
                .unwrap()
                .contains("CannotDeleteVp")
        );
    }

    #[test]
    fn test_tx_iter_prefix() {
        // The environment must be initialized first
        tx_host_env::init();

        let empty_key = storage::Key::parse("empty").unwrap();
        let mut iter =
            namada_tx_prelude::iter_prefix_bytes(tx::ctx(), empty_key).unwrap();
        assert!(
            iter.next().is_none(),
            "Trying to iter a prefix that doesn't have any matching keys \
             should yield an empty iterator."
        );

        let prefix = storage::Key::parse("prefix").unwrap();
        // We'll write sub-key in some random order to check prefix iter's order
        let sub_keys = [2_i32, 1, i32::MAX, -1, 260, -2, i32::MIN, 5, 0];

        // Write the values directly into the storage first
        tx_host_env::with(|env| {
            for i in sub_keys.iter() {
                let key = prefix.push(i).unwrap();
                env.state.write(&key, i).unwrap();
            }
        });

        // Then try to iterate over their prefix
        let iter = namada_tx_prelude::iter_prefix(tx::ctx(), prefix.clone())
            .unwrap()
            .map(Result::unwrap);

        // The order has to be sorted by sub-key value
        let expected = sub_keys
            .iter()
            .sorted()
            .map(|i| (prefix.push(i).unwrap(), *i));
        itertools::assert_equal(iter, expected);
    }

    #[test]
    fn test_tx_insert_verifier() {
        // The environment must be initialized first
        tx_host_env::init();

        assert!(
            tx_host_env::with(|env| env.verifiers.is_empty()),
            "pre-condition"
        );
        let verifier = address::testing::established_address_1();
        tx::ctx().insert_verifier(&verifier).unwrap();
        assert!(
            tx_host_env::with(|env| env.verifiers.contains(&verifier)),
            "The verifier should have been inserted"
        );
        assert_eq!(
            tx_host_env::with(|env| env.verifiers.len()),
            1,
            "There should be only one verifier inserted"
        );
    }

    #[test]
    #[should_panic]
    fn test_tx_init_account_with_invalid_vp() {
        // The environment must be initialized first
        tx_host_env::init();

        let code = vec![];
        tx::ctx().init_account(code, &None, &[]).unwrap();
    }

    #[test]
    fn test_tx_init_account_with_valid_vp() {
        // The environment must be initialized first
        tx_host_env::init();

        let code = TestWasms::VpAlwaysTrue.read_bytes();
        let code_hash = Hash::sha256(&code);
        tx_host_env::with(|env| {
            // store wasm code
            let key = Key::wasm_code(&code_hash);
            env.state.write(&key, &code).unwrap();
        });
        tx::ctx().init_account(code_hash, &None, &[]).unwrap();
    }

    /// Test that a tx updating validity predicate that is not in the allowlist
    /// fails.
    #[test]
    #[should_panic = "DisallowedVp"]
    fn test_tx_update_vp_not_allowed_rejected() {
        // Initialize a tx environment
        tx_host_env::init();

        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = keypair.ref_to();
        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        let vp_hash = sha256(&vp_code);

        tx_host_env::with(|tx_env| {
            // let mut tx_env = TestTxEnv::default();
            tx_env.init_parameters(
                None,
                Some(vec!["some_hash".to_string()]),
                None,
            );

            // Spawn the accounts to be able to modify their storage
            tx_env.spawn_accounts([&vp_owner]);
            tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);
        });

        // Update VP in a transaction.
        // Panics only due to unwrap in `native_host_fn!` test macro
        tx::ctx()
            .update_validity_predicate(&vp_owner, vp_hash, &None)
            .unwrap()
    }

    /// Test that a tx writing validity predicate that is not in the allowlist
    /// directly to storage fails
    #[test]
    #[should_panic = "DisallowedVp"]
    fn test_tx_write_vp_not_allowed_rejected() {
        // Initialize a tx environment
        tx_host_env::init();

        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = keypair.ref_to();
        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        let vp_hash = sha256(&vp_code);

        tx_host_env::with(|tx_env| {
            // let mut tx_env = TestTxEnv::default();
            tx_env.init_parameters(
                None,
                Some(vec!["some_hash".to_string()]),
                None,
            );

            // Spawn the accounts to be able to modify their storage
            tx_env.spawn_accounts([&vp_owner]);
            tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);
        });

        // Writing the VP to storage directly should fail
        let vp_key = Key::validity_predicate(&vp_owner);
        tx::ctx().write(&vp_key, vp_hash).unwrap();
    }

    /// Test that a tx initializing a new account with validity predicate that
    /// is not in the allowlist fails
    #[test]
    #[should_panic = "DisallowedVp"]
    fn test_tx_init_vp_not_allowed_rejected() {
        // Initialize a tx environment
        tx_host_env::init();

        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = keypair.ref_to();
        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        let vp_hash = sha256(&vp_code);

        tx_host_env::with(|tx_env| {
            // let mut tx_env = TestTxEnv::default();
            tx_env.init_parameters(
                None,
                Some(vec!["some_hash".to_string()]),
                None,
            );

            // Spawn the accounts to be able to modify their storage
            tx_env.spawn_accounts([&vp_owner]);
            tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);
        });

        // Initializing a new account with the VP should fail
        tx::ctx().init_account(vp_hash, &None, &[]).unwrap();
    }

    #[test]
    fn test_tx_get_metadata() {
        // The environment must be initialized first
        tx_host_env::init();

        assert_eq!(
            tx::ctx().get_chain_id().unwrap(),
            tx_host_env::with(|env| env.state.in_mem().get_chain_id().0)
        );
        assert_eq!(
            tx::ctx().get_block_height().unwrap(),
            tx_host_env::with(|env| env.state.in_mem().get_block_height().0)
        );
        assert_eq!(
            tx::ctx().get_block_epoch().unwrap(),
            tx_host_env::with(|env| env.state.in_mem().get_current_epoch().0)
        );
        assert_eq!(
            tx::ctx().get_native_token().unwrap(),
            tx_host_env::with(|env| env.state.in_mem().native_token.clone())
        );
    }

    #[test]
    fn test_tx_get_pred_epochs() {
        // The environment must be initialized first
        tx_host_env::init();

        let pred_epochs = tx::ctx().get_pred_epochs().unwrap();
        let expected =
            tx_host_env::take().state.in_mem().block.pred_epochs.clone();
        assert_eq!(expected, pred_epochs);
    }

    /// An example how to write a VP host environment integration test
    #[test]
    fn test_vp_host_env() {
        let value = "test".to_string();
        let addr = address::testing::established_address_1();
        let key = storage::Key::from(addr.to_db_key());
        // We can write some data from a transaction
        vp_host_env::init_from_tx(addr, TestTxEnv::default(), |_addr| {
            tx::ctx().write(&key, &value).unwrap();
        });

        let read_pre_value: Option<String> = vp::CTX.read_pre(&key).unwrap();
        assert_eq!(None, read_pre_value);
        let read_post_value: Option<String> = vp::CTX.read_post(&key).unwrap();
        assert_eq!(Some(value), read_post_value);
    }

    #[test]
    fn test_vp_read_and_has_key() {
        let mut tx_env = TestTxEnv::default();

        let addr = address::testing::established_address_1();
        let addr_key = storage::Key::from(addr.to_db_key());

        // Write some value to storage ...
        let existing_key =
            addr_key.join(&Key::parse("existing_key_raw").unwrap());
        let existing_value = vec![2_u8; 1000];
        tx_env.state.write(&existing_key, &existing_value).unwrap();
        // ... and commit it
        tx_env.state.commit_tx_batch();

        // In a transaction, write override the existing key's value and add
        // another key-value
        let override_value = "override".to_string();
        let new_key = addr_key.join(&Key::parse("new_key").unwrap());
        let new_value = "vp".repeat(4);

        // Initialize the VP environment via a transaction
        vp_host_env::init_from_tx(addr, tx_env, |_addr| {
            // Override the existing key
            tx::ctx().write(&existing_key, &override_value).unwrap();

            // Write the new key-value
            tx::ctx().write(&new_key, new_value.clone()).unwrap();
        });

        assert!(
            vp::CTX.has_key_pre(&existing_key).unwrap(),
            "The existing key before transaction should be found"
        );
        let pre_existing_value: Option<Vec<u8>> =
            vp::CTX.read_pre(&existing_key).unwrap();
        assert_eq!(
            Some(existing_value),
            pre_existing_value,
            "The existing value read from state before transaction should be \
             unchanged"
        );

        assert!(
            !vp::CTX.has_key_pre(&new_key).unwrap(),
            "The new key before transaction shouldn't be found"
        );
        let pre_new_value: Option<Vec<u8>> =
            vp::CTX.read_pre(&new_key).unwrap();
        assert_eq!(
            None, pre_new_value,
            "The new value read from state before transaction shouldn't yet \
             exist"
        );

        assert!(
            vp::CTX.has_key_post(&existing_key).unwrap(),
            "The existing key after transaction should still be found"
        );
        let post_existing_value: Option<String> =
            vp::CTX.read_post(&existing_key).unwrap();
        assert_eq!(
            Some(override_value),
            post_existing_value,
            "The existing value read from state after transaction should be \
             overridden"
        );

        assert!(
            vp::CTX.has_key_post(&new_key).unwrap(),
            "The new key after transaction should be found"
        );
        let post_new_value: Option<String> =
            vp::CTX.read_post(&new_key).unwrap();
        assert_eq!(
            Some(new_value),
            post_new_value,
            "The new value read from state after transaction should have a \
             value equal to the one written in the transaction"
        );
    }

    #[test]
    fn test_vp_iter_prefix() {
        let mut tx_env = TestTxEnv::default();

        let addr = address::testing::established_address_1();
        let addr_key = storage::Key::from(addr.to_db_key());

        let prefix = addr_key.join(&Key::parse("prefix").unwrap());
        // We'll write sub-key in some random order to check prefix iter's order
        let sub_keys = [2_i32, 1, i32::MAX, -1, 260, -2, i32::MIN, 5, 0];

        // Write some values to storage ...
        for i in sub_keys.iter() {
            let key = prefix.push(i).unwrap();
            tx_env.state.write(&key, i).unwrap();
        }
        // ... and commit them
        tx_env.state.commit_tx_batch();

        // In a transaction, write override the existing key's value and add
        // another key-value
        let existing_key = prefix.push(&5).unwrap();
        let new_key = prefix.push(&11).unwrap();

        // Initialize the VP environment via a transaction
        vp_host_env::init_from_tx(addr, tx_env, |_addr| {
            // Override one of the existing keys
            tx::ctx().write(&existing_key, 100_i32).unwrap();

            // Write the new key-value under the same prefix
            tx::ctx().write(&new_key, 11_i32).unwrap();
        });

        let ctx_pre = vp::CTX.pre();
        let iter_pre = namada_vp_prelude::iter_prefix(&ctx_pre, prefix.clone())
            .unwrap()
            .map(|item| item.unwrap());

        // The order in pre has to be sorted by sub-key value
        let expected_pre = sub_keys
            .iter()
            .sorted()
            .map(|i| (prefix.push(i).unwrap(), *i));
        itertools::assert_equal(iter_pre, expected_pre);

        let ctx_post = vp::CTX.post();
        let iter_post =
            namada_vp_prelude::iter_prefix(&ctx_post, prefix.clone())
                .unwrap()
                .map(|item| item.unwrap());

        // The order in post also has to be sorted
        let mut expected_keys = sub_keys.to_vec();
        // Add value from `new_key`
        expected_keys.push(11);
        let expected_post = expected_keys.iter().sorted().map(|i| {
            let val = if *i == 5 { 100 } else { *i };
            (prefix.push(i).unwrap(), val)
        });
        itertools::assert_equal(iter_post, expected_post);
    }

    #[test]
    fn test_vp_verify_tx_signature() {
        let mut env = TestVpEnv::default();

        let addr = address::testing::established_address_1();

        // Write the public key to storage
        let keypair = key::testing::keypair_1();
        let pk = keypair.ref_to();

        let _ = pks_handle(&addr).insert(&mut env.state, 0_u8, pk.clone());

        // Initialize the environment
        vp_host_env::set(env);

        // Use some arbitrary bytes for tx code
        let code = vec![4, 3, 2, 1, 0];
        #[allow(clippy::disallowed_methods)]
        let expiration = Some(DateTimeUtc::now());
        for data in &[
            // Tx with some arbitrary data
            [1, 2, 3, 4].repeat(10),
            // Tx without any data
            vec![],
        ] {
            let keypairs = vec![keypair.clone()];
            let pks_map = AccountPublicKeysMap::from_iter(vec![pk.clone()]);
            let BatchedTx { tx, cmt } = vp_host_env::with(|env| {
                let chain_id = env.state.in_mem().chain_id.clone();
                let mut tx = Tx::new(chain_id, expiration);
                tx.add_code(code.clone(), None)
                    .add_serialized_data(data.to_vec())
                    .sign_raw(keypairs.clone(), pks_map.clone(), None)
                    .sign_wrapper(keypair.clone());
                let batched_tx = tx.batch_first_tx();
                env.batched_tx = batched_tx;
                env.batched_tx.clone()
            });
            assert_eq!(tx.data(&cmt).as_ref(), Some(data));
            assert!(
                tx.verify_signatures(
                    &HashSet::from_iter([tx.header_hash()]),
                    pks_map,
                    &None,
                    1,
                    || Ok(())
                )
                .is_ok()
            );

            let other_keypair = key::testing::keypair_2();
            assert!(
                tx.verify_signatures(
                    &HashSet::from_iter([tx.header_hash()]),
                    AccountPublicKeysMap::from_iter([other_keypair.ref_to()]),
                    &None,
                    1,
                    || Ok(())
                )
                .is_err()
            );
        }
    }

    #[test]
    fn test_vp_get_metadata() {
        // The environment must be initialized first
        vp_host_env::init();

        assert_eq!(
            vp::CTX.get_chain_id().unwrap(),
            vp_host_env::with(|env| env.state.in_mem().get_chain_id().0)
        );
        assert_eq!(
            vp::CTX.get_block_height().unwrap(),
            vp_host_env::with(|env| env.state.in_mem().get_block_height().0)
        );
        assert_eq!(
            vp::CTX.get_block_epoch().unwrap(),
            vp_host_env::with(|env| env.state.in_mem().get_current_epoch().0)
        );
        assert_eq!(
            vp::CTX.get_native_token().unwrap(),
            vp_host_env::with(|env| env.state.in_mem().native_token.clone())
        );
    }

    #[test]
    fn test_vp_eval() {
        // The environment must be initialized first
        vp_host_env::init();

        // evaluating without any code should fail
        let empty_code = Hash::zero();
        let input_data = vec![];
        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(input_data.clone())
            .sign_raw(keypairs.clone(), pks_map.clone(), None)
            .sign_wrapper(keypair.clone());
        let result = vp::CTX.eval(empty_code, tx.batch_ref_first_tx().unwrap());
        assert!(result.is_err());

        // evaluating the VP template which always returns `true` should pass
        let code = TestWasms::VpAlwaysTrue.read_bytes();
        let code_hash = Hash::sha256(&code);
        let code_len = code.len() as u64;
        vp_host_env::with(|env| {
            // store wasm codes
            let key = Key::wasm_code(&code_hash);
            let len_key = Key::wasm_code_len(&code_hash);
            env.state.write(&key, &code).unwrap();
            env.state.write(&len_key, code_len).unwrap();
        });
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code_from_hash(code_hash, None)
            .add_serialized_data(input_data.clone())
            .sign_raw(keypairs.clone(), pks_map.clone(), None)
            .sign_wrapper(keypair.clone());
        let result = vp::CTX.eval(code_hash, tx.batch_ref_first_tx().unwrap());
        assert!(result.is_ok());

        // evaluating the VP template which always returns `false` shouldn't
        // pass
        let code = TestWasms::VpAlwaysFalse.read_bytes();
        let code_hash = Hash::sha256(&code);
        let code_len = code.len() as u64;
        vp_host_env::with(|env| {
            // store wasm codes
            let key = Key::wasm_code(&code_hash);
            let len_key = Key::wasm_code_len(&code_hash);
            env.state.write(&key, &code).unwrap();
            env.state.write(&len_key, code_len).unwrap();
        });
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code_from_hash(code_hash, None)
            .add_serialized_data(input_data)
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        let result = vp::CTX.eval(code_hash, tx.batch_ref_first_tx().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_ibc_client() {
        // The environment must be initialized first
        tx_host_env::init();

        ibc::init_storage();
        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Start a transaction to create a new client
        let msg = ibc::msg_create_client();
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs.clone(), pks_map.clone(), None)
            .sign_wrapper(keypair.clone());

        // create a client with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("creating a client failed");

        // Check
        let mut env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());

        // Commit
        env.commit_tx_and_block();
        // update the block height for the following client update
        env.state.in_mem_mut().begin_block(BlockHeight(2)).unwrap();
        env.state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .unwrap();

        // Start a transaction to update the client
        tx_host_env::set(env);
        let client_id = ibc::client_id();
        let msg = ibc::msg_update_client(client_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        // update the client with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("updating a client failed");

        // Check
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ibc_connection_init_and_open() {
        // The environment must be initialized first
        tx_host_env::init();

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Set the initial state before starting transactions
        ibc::init_storage();
        let (client_id, client_state, writes) = ibc::prepare_client();
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            });
        });

        // Start a transaction for ConnectionOpenInit
        let msg = ibc::msg_connection_open_init(client_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs.clone(), pks_map.clone(), None)
            .sign_wrapper(keypair.clone());
        // init a connection with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("creating a connection failed");

        // Check
        let mut env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());

        // Commit
        env.commit_tx_and_block();
        // for the next block
        env.state.in_mem_mut().begin_block(BlockHeight(2)).unwrap();
        env.state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .unwrap();
        tx_host_env::set(env);

        // Start the next transaction for ConnectionOpenAck
        let conn_id = ibc::ConnectionId::new(0);
        let msg = ibc::msg_connection_open_ack(conn_id, client_state);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        // open the connection with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("opening the connection failed");

        // Check
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ibc_connection_try_and_open() {
        // The environment must be initialized first
        tx_host_env::init();

        // Set the initial state before starting transactions
        ibc::init_storage();

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        let (client_id, client_state, writes) = ibc::prepare_client();
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            })
        });

        // Start a transaction for ConnectionOpenTry
        let msg = ibc::msg_connection_open_try(client_id, client_state);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs.clone(), pks_map.clone(), None)
            .sign_wrapper(keypair.clone());
        // open try a connection with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("creating a connection failed");

        // Check
        let mut env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());

        // Commit
        env.commit_tx_and_block();
        // for the next block
        env.state.in_mem_mut().begin_block(BlockHeight(2)).unwrap();
        env.state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .unwrap();
        tx_host_env::set(env);

        // Start the next transaction for ConnectionOpenConfirm
        let conn_id = ibc::ConnectionId::new(0);
        let msg = ibc::msg_connection_open_confirm(conn_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        // open the connection with the mssage
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("opening the connection failed");

        // Check
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ibc_channel_init_and_open() {
        // The environment must be initialized first
        tx_host_env::init();

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Set the initial state before starting transactions
        ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            });
        });

        // Start a transaction for ChannelOpenInit
        let port_id = ibc::PortId::transfer();
        let msg = ibc::msg_channel_open_init(port_id.clone(), conn_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs.clone(), pks_map.clone(), None)
            .sign_wrapper(keypair.clone());
        // init a channel with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("creating a channel failed");

        // Check
        let mut env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());

        // Commit
        env.commit_tx_and_block();
        // for the next block
        env.state.in_mem_mut().begin_block(BlockHeight(2)).unwrap();
        env.state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .unwrap();
        tx_host_env::set(env);

        // Start the next transaction for ChannelOpenAck
        let channel_id = ibc::ChannelId::new(0);
        let msg = ibc::msg_channel_open_ack(port_id, channel_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        // open the channel with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("opening the channel failed");

        // Check
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ibc_channel_try_and_open() {
        // The environment must be initialized first
        tx_host_env::init();

        // Set the initial state before starting transactions
        ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            });
        });

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Start a transaction for ChannelOpenTry
        let port_id = ibc::PortId::transfer();
        let msg = ibc::msg_channel_open_try(port_id.clone(), conn_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs.clone(), pks_map.clone(), None)
            .sign_wrapper(keypair.clone());
        // try open a channel with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("creating a channel failed");

        // Check
        let mut env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());

        // Commit
        env.commit_tx_and_block();
        // for the next block
        env.state.in_mem_mut().begin_block(BlockHeight(2)).unwrap();
        env.state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .unwrap();
        tx_host_env::set(env);

        // Start the next transaction for ChannelOpenConfirm
        let channel_id = ibc::ChannelId::new(0);
        let msg = ibc::msg_channel_open_confirm(port_id, channel_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        // open a channel with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("opening the channel failed");

        // Check
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ibc_channel_close_init_fail() {
        // The environment must be initialized first
        tx_host_env::init();

        // Set the initial state before starting transactions
        ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id, true);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            });
        });

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Start a transaction to close the channel
        let msg = ibc::msg_channel_close_init(port_id, channel_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        // close the channel with the message
        let mut actions = tx_host_env::ibc::ibc_actions(tx::ctx());
        // the dummy module closes the channel
        let dummy_module = DummyTransferModule {};
        actions.add_transfer_module(dummy_module);
        let dummy_module = DummyNftTransferModule {};
        actions.add_transfer_module(dummy_module);
        actions
            .execute::<token::Transfer>(&tx_data)
            .expect("closing the channel failed");

        // Check
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        // VP should fail because the transfer channel cannot be closed
        assert!(matches!(
            result
                .expect_err("validation succeeded unexpectedly")
                .downcast_ref::<IbcActionError>(),
            Some(IbcActionError::Handler(_)),
        ));
    }

    #[test]
    fn test_ibc_channel_close_confirm() {
        // The environment must be initialized first
        tx_host_env::init();

        // Set the initial state before starting transactions
        ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id, true);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            });
        });

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Start a transaction to close the channel
        let msg = ibc::msg_channel_close_confirm(port_id, channel_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);

        // close the channel with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("closing the channel failed");

        // Check
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ibc_send_token() {
        // The environment must be initialized first
        tx_host_env::init();

        // Set the initial state before starting transactions
        let (token, sender) = ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id, false);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            });
        });

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Start a transaction to send a packet
        let msg =
            ibc::msg_transfer(port_id, channel_id, token.to_string(), &sender);
        let tx_data = msg.serialize_to_vec();

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs.clone(), pks_map.clone(), None)
            .sign_wrapper(keypair.clone());
        // send the token and a packet with the data
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("sending a token failed");

        // Check
        let mut env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
        // Check if the token was escrowed
        let escrow = token::storage_key::balance_key(
            &token,
            &address::Address::Internal(address::InternalAddress::Ibc),
        );
        let token_vp_result = ibc::validate_multitoken_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
            &escrow,
        );
        assert!(token_vp_result.is_ok());

        // Commit
        env.commit_tx_and_block();
        // for the next block
        env.state.in_mem_mut().begin_block(BlockHeight(2)).unwrap();
        env.state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .unwrap();
        tx_host_env::set(env);

        // Start the next transaction for receiving an ack
        let counterparty = ibc::dummy_channel_counterparty();
        let packet = ibc::packet_from_message(
            &msg.message,
            ibc::Sequence::from(1),
            &counterparty,
        );
        let msg = ibc::msg_packet_ack(packet);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        // ack the packet with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("ack failed");

        // Check
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
        // Check the balance
        tx_host_env::set(env);
        let balance_key = token::storage_key::balance_key(&token, &sender);
        let balance: Option<Amount> = tx_host_env::with(|env| {
            env.state.read(&balance_key).expect("read error")
        });
        assert_eq!(
            balance,
            Some(Amount::from_uint(0, ibc::ANY_DENOMINATION).unwrap())
        );
        let escrow_key = token::storage_key::balance_key(
            &token,
            &address::Address::Internal(address::InternalAddress::Ibc),
        );
        let escrow: Option<Amount> = tx_host_env::with(|env| {
            env.state.read(&escrow_key).expect("read error")
        });
        assert_eq!(
            escrow,
            Some(Amount::from_uint(100, ibc::ANY_DENOMINATION).unwrap())
        );
    }

    #[test]
    fn test_ibc_burn_token() {
        // The environment must be initialized first
        tx_host_env::init();

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Set the initial state before starting transactions
        let (token, sender) = ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id, false);
        writes.extend(channel_writes);
        // the origin-specific token
        let denom = format!("{}/{}/{}", port_id, channel_id, token);
        let ibc_token = ibc_trace::ibc_token(&denom);
        let balance_key = token::storage_key::balance_key(&ibc_token, &sender);
        let init_bal = Amount::native_whole(100);
        writes.insert(balance_key.clone(), init_bal.serialize_to_vec());
        let minted_key = token::storage_key::minted_balance_key(&ibc_token);
        writes.insert(minted_key.clone(), init_bal.serialize_to_vec());
        let minter_key = token::storage_key::minter_key(&ibc_token);
        writes.insert(
            minter_key,
            Address::Internal(InternalAddress::Ibc).serialize_to_vec(),
        );
        let mint_amount_key = ibc_storage::mint_amount_key(&ibc_token);
        let init_bal = Amount::native_whole(100);
        writes.insert(mint_amount_key, init_bal.serialize_to_vec());
        writes.insert(minted_key.clone(), init_bal.serialize_to_vec());
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            });
        });

        // Start a transaction to send a packet
        // Set this chain is the sink zone
        let msg = ibc::msg_transfer(port_id, channel_id, denom, &sender);
        let tx_data = msg.serialize_to_vec();

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        // send the token and a packet with the data
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("sending a token failed");

        // Check
        let mut env = tx_host_env::take();
        // The token and sender must be part of the verifier set (checked by
        // MultitokenVp)
        env.verifiers.insert(ibc_token);
        env.verifiers.insert(sender);
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(
            result.is_ok(),
            "Expected VP to accept the tx, got {result:?}"
        );
        // Check if the token was burned
        let result = ibc::validate_multitoken_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
            &minted_key,
        );
        assert!(
            result.is_ok(),
            "Expected VP to accept the tx, got {result:?}"
        );
        // Check the balance
        tx_host_env::set(env);
        let balance: Option<Amount> = tx_host_env::with(|env| {
            env.state.read(&balance_key).expect("read error")
        });
        assert_eq!(balance, Some(Amount::from_u64(0)));
        let minted: Option<Amount> = tx_host_env::with(|env| {
            env.state.read(&minted_key).expect("read error")
        });
        assert_eq!(minted, Some(Amount::from_u64(0)));
    }

    #[test]
    fn test_ibc_receive_token() {
        // The environment must be initialized first
        tx_host_env::init();

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Set the initial state before starting transactions
        let (token, receiver) = ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id, false);
        writes.extend(channel_writes);

        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            });
        });

        // packet
        let packet = ibc::received_packet(
            port_id.clone(),
            channel_id.clone(),
            ibc::Sequence::from(1),
            token.to_string(),
            &receiver,
        );

        // Start a transaction to receive a packet
        let msg = ibc::msg_packet_recv(packet);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        // receive a packet with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("receiving the token failed");

        // Check
        let mut env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
        // Check if the token was minted
        // The token and recevier must be part of the verifier set (checked by
        // MultitokenVp)
        let denom = format!("{}/{}/{}", port_id, channel_id, token);
        let ibc_token = ibc::ibc_token(&denom);
        env.verifiers.insert(ibc_token.clone());
        env.verifiers.insert(receiver.clone());
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(
            result.is_ok(),
            "Expected VP to accept the tx, got {result:?}"
        );
        // Check if the token was minted
        let minted_key = token::storage_key::minted_balance_key(&ibc_token);
        let result = ibc::validate_multitoken_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
            &minted_key,
        );
        assert!(
            result.is_ok(),
            "Expected VP to accept the tx, got {result:?}"
        );
        // Check the balance
        tx_host_env::set(env);
        let key = ibc::balance_key_with_ibc_prefix(denom, &receiver);
        let balance: Option<Amount> =
            tx_host_env::with(|env| env.state.read(&key).expect("read error"));
        assert_eq!(balance, Some(Amount::native_whole(100)));
        let minted: Option<Amount> = tx_host_env::with(|env| {
            env.state.read(&minted_key).expect("read error")
        });
        assert_eq!(minted, Some(Amount::native_whole(100)));
    }

    #[test]
    fn test_ibc_receive_no_token() {
        // The environment must be initialized first
        tx_host_env::init();

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Set the initial state before starting transactions
        let (token, receiver) = ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id, false);
        writes.extend(channel_writes);

        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            });
        });

        // packet with invalid data
        let sequence = ibc::Sequence::from(1);
        let mut packet = ibc::received_packet(
            port_id.clone(),
            channel_id.clone(),
            sequence,
            token.to_string(),
            &receiver,
        );
        packet.data = vec![0];

        // Start a transaction to receive a packet
        let msg = ibc::msg_packet_recv(packet);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        // Receive the packet, but no token is received
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("receiving the token failed");

        // Check if the transaction is valid
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
        // Check if the ack has an error due to the invalid packet data
        tx_host_env::set(env);
        let ack_key = ibc_storage::ack_key(&port_id, &channel_id, sequence);
        let ack = tx_host_env::with(|env| {
            env.state.read_bytes(&ack_key).expect("read error").unwrap()
        });
        let expected_ack =
            Hash::sha256(Vec::<u8>::from(ibc::transfer_ack_with_error()))
                .to_vec();
        assert_eq!(ack, expected_ack);
        // Check if only the ack and the receipt are added
        let receipt_key =
            ibc_storage::receipt_key(&port_id, &channel_id, sequence);
        let changed_keys = tx_host_env::with(|env| {
            env.state
                .write_log()
                .verifiers_and_changed_keys(&BTreeSet::new())
                .1
        });
        let expected_changed_keys = BTreeSet::from([ack_key, receipt_key]);
        assert_eq!(changed_keys, expected_changed_keys);
    }

    #[test]
    fn test_ibc_unescrow_token() {
        // The environment must be initialized first
        tx_host_env::init();

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Set the initial state before starting transactions
        let (token, receiver) = ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id, false);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            });
        });
        // escrow in advance
        let escrow_key = token::storage_key::balance_key(
            &token,
            &address::Address::Internal(address::InternalAddress::Ibc),
        );
        let val = Amount::from_uint(100, ibc::ANY_DENOMINATION).unwrap();
        tx_host_env::with(|env| {
            env.state.write(&escrow_key, val).expect("write error");
        });

        // Set this chain as the source zone
        let counterparty = ibc::dummy_channel_counterparty();
        let denom = format!(
            "{}/{}/{}",
            counterparty.port_id().clone(),
            counterparty.channel_id().unwrap().clone(),
            token
        );
        // packet
        let packet = ibc::received_packet(
            port_id,
            channel_id,
            ibc::Sequence::from(1),
            denom,
            &receiver,
        );

        // Start a transaction to receive a packet
        let msg = ibc::msg_packet_recv(packet);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        // receive a packet with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("receiving a token failed");

        // Check
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
        // Check if the token was unescrowed
        let result = ibc::validate_multitoken_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
            &escrow_key,
        );
        assert!(result.is_ok());
        // Check the balance
        tx_host_env::set(env);
        let key = token::storage_key::balance_key(&token, &receiver);
        let balance: Option<Amount> =
            tx_host_env::with(|env| env.state.read(&key).expect("read error"));
        assert_eq!(
            balance,
            Some(Amount::from_uint(200, ibc::ANY_DENOMINATION).unwrap())
        );
        let escrow: Option<Amount> = tx_host_env::with(|env| {
            env.state.read(&escrow_key).expect("read error")
        });
        assert_eq!(
            escrow,
            Some(Amount::from_uint(0, ibc::ANY_DENOMINATION).unwrap())
        );
    }

    #[test]
    fn test_ibc_unescrow_received_token() {
        // The environment must be initialized first
        tx_host_env::init();

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Set the initial state before starting transactions
        let (token, receiver) = ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id, false);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            });
        });
        // escrow in advance
        let dummy_src_port = "dummy_transfer";
        let dummy_src_channel = "channel_42";
        let denom =
            format!("{}/{}/{}", dummy_src_port, dummy_src_channel, token);
        let escrow_key = ibc::balance_key_with_ibc_prefix(
            denom,
            &address::Address::Internal(address::InternalAddress::Ibc),
        );
        let val = Amount::native_whole(100);
        tx_host_env::with(|env| {
            env.state.write(&escrow_key, val).expect("write error");
        });

        // Set this chain as the source zone
        let counterparty = ibc::dummy_channel_counterparty();
        let denom = format!(
            "{}/{}/{}/{}/{}",
            counterparty.port_id().clone(),
            counterparty.channel_id().unwrap().clone(),
            dummy_src_port,
            dummy_src_channel,
            token
        );
        // packet
        let packet = ibc::received_packet(
            port_id,
            channel_id,
            ibc::Sequence::from(1),
            denom,
            &receiver,
        );

        // Start a transaction to receive a packet
        let msg = ibc::msg_packet_recv(packet);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        // receive a packet with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("receiving a token failed");

        // Check
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
        // Check if the token was unescrowed
        let result = ibc::validate_multitoken_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
            &escrow_key,
        );
        assert!(result.is_ok());
        // Check the balance
        tx_host_env::set(env);
        // without the source trace path
        let denom =
            format!("{}/{}/{}", dummy_src_port, dummy_src_channel, token);
        let key = ibc::balance_key_with_ibc_prefix(denom, &receiver);
        let balance: Option<Amount> =
            tx_host_env::with(|env| env.state.read(&key).expect("read error"));
        assert_eq!(balance, Some(Amount::native_whole(100)));
        let escrow: Option<Amount> = tx_host_env::with(|env| {
            env.state.read(&escrow_key).expect("read error")
        });
        assert_eq!(escrow, Some(Amount::from_u64(0)));
    }

    #[test]
    fn test_ibc_packet_timeout() {
        // The environment must be initialized first
        tx_host_env::init();

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Set the initial state before starting transactions
        let (token, sender) = ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id, true);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            })
        });

        // Start a transaction to send a packet
        let mut msg =
            ibc::msg_transfer(port_id, channel_id, token.to_string(), &sender);
        ibc::set_timeout_timestamp(&mut msg.message);
        let tx_data = msg.serialize_to_vec();
        // send a packet with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("sending a token failed");

        // Commit
        let mut env = tx_host_env::take();
        env.commit_tx_and_block();
        // for the next block
        env.state.in_mem_mut().begin_block(BlockHeight(2)).unwrap();
        env.state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .unwrap();
        tx_host_env::set(env);

        // Start a transaction to notify the timeout
        let counterparty = ibc::dummy_channel_counterparty();
        let packet = ibc::packet_from_message(
            &msg.message,
            ibc::Sequence::from(1),
            &counterparty,
        );
        let msg = ibc::msg_timeout(packet, ibc::Sequence::from(1));
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);

        // timeout the packet
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("timeout failed");

        // Check
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
        // Check if the token was refunded
        let escrow = token::storage_key::balance_key(
            &token,
            &address::Address::Internal(address::InternalAddress::Ibc),
        );
        let result = ibc::validate_multitoken_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
            &escrow,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ibc_timeout_on_close() {
        // The environment must be initialized first
        tx_host_env::init();

        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([
            key::testing::keypair_1().ref_to(),
        ]);

        // Set the initial state before starting transactions
        let (token, sender) = ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id, true);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.write_bytes(&key, &val).expect("write error");
            })
        });

        // Start a transaction to send a packet
        let msg =
            ibc::msg_transfer(port_id, channel_id, token.to_string(), &sender);
        let tx_data = msg.serialize_to_vec();
        // send a packet with the message
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("sending a token failed");

        // Commit
        let mut env = tx_host_env::take();
        env.commit_tx_and_block();
        // for the next block
        env.state.in_mem_mut().begin_block(BlockHeight(2)).unwrap();
        env.state
            .in_mem_mut()
            .set_header(get_dummy_header())
            .unwrap();
        tx_host_env::set(env);

        // Start a transaction to notify the timing-out on closed
        let counterparty = ibc::dummy_channel_counterparty();
        let packet = ibc::packet_from_message(
            &msg.message,
            ibc::Sequence::from(1),
            &counterparty,
        );
        let msg = ibc::msg_timeout_on_close(packet, ibc::Sequence::from(1));
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);

        // timeout the packet
        tx_host_env::ibc::ibc_actions(tx::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("timeout on close failed");

        // Check
        let env = tx_host_env::take();
        let result = ibc::validate_ibc_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
        );
        assert!(result.is_ok());
        // Check if the token was refunded
        let escrow = token::storage_key::balance_key(
            &token,
            &address::Address::Internal(address::InternalAddress::Ibc),
        );
        let result = ibc::validate_multitoken_vp_from_tx(
            &env,
            &tx.batch_ref_first_tx().unwrap(),
            &escrow,
        );
        assert!(result.is_ok());
    }
}
