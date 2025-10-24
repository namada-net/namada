//! Extend Tendermint votes with signatures of the Ethereum
//! bridge pool root and nonce seen by a quorum of validators.
use itertools::Itertools;

use super::*;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Takes an iterator over Bridge pool root vote extension instances,
    /// and returns another iterator. The latter yields
    /// valid Bridge pool root vote extensions, or the reason why these
    /// are invalid, in the form of a `VoteExtensionError`.
    #[inline]
    pub fn validate_bp_roots_vext_list<'iter>(
        &'iter self,
        vote_extensions: impl IntoIterator<Item = Signed<bridge_pool_roots::Vext>>
        + 'iter,
    ) -> impl Iterator<
        Item = std::result::Result<
            Signed<bridge_pool_roots::Vext>,
            VoteExtensionError,
        >,
    > + 'iter {
        vote_extensions.into_iter().map(|vote_extension| {
            validate_bp_roots_vext::<_, _, governance::Store<_>>(
                &self.state,
                &vote_extension,
                self.state.in_mem().get_last_block_height(),
            )?;
            Ok(vote_extension)
        })
    }

    /// Takes a list of signed Bridge pool root vote extensions,
    /// and filters out invalid instances. This also de-duplicates
    /// the iterator to be unique per validator address.
    #[inline]
    pub fn filter_invalid_bp_roots_vexts<'iter>(
        &'iter self,
        vote_extensions: impl IntoIterator<Item = Signed<bridge_pool_roots::Vext>>
        + 'iter,
    ) -> impl Iterator<Item = Signed<bridge_pool_roots::Vext>> + 'iter {
        self.validate_bp_roots_vext_list(vote_extensions)
            .filter_map(|ext| ext.ok())
            .dedup_by(|ext_1, ext_2| {
                ext_1.data.validator_addr == ext_2.data.validator_addr
            })
    }
}

#[allow(clippy::cast_possible_truncation)]
#[cfg(test)]
mod test_bp_vote_extensions {
    use namada_apps_lib::wallet::defaults::{bertha_address, bertha_keypair};
    use namada_sdk::chain::BlockHeight;
    use namada_sdk::eth_bridge::protocol::validation::bridge_pool_roots::validate_bp_roots_vext;
    use namada_sdk::eth_bridge::storage::bridge_pool::get_key_from_hash;
    use namada_sdk::eth_bridge::storage::eth_bridge_queries::{
        EthBridgeQueries, is_bridge_comptime_enabled,
    };
    use namada_sdk::ethereum_events::Uint;
    use namada_sdk::keccak::{KeccakHash, keccak_hash};
    use namada_sdk::key::*;
    use namada_sdk::proof_of_stake::storage::{
        consensus_validator_set_handle,
        read_consensus_validator_set_addresses_with_stake, read_pos_params,
    };
    use namada_sdk::proof_of_stake::types::{
        Position as ValidatorPosition, WeightedValidator,
    };
    use namada_sdk::proof_of_stake::{
        BecomeValidator, Epoch, become_validator,
    };
    use namada_sdk::state::StorageWrite;
    use namada_sdk::tendermint::abci::types::VoteInfo;
    use namada_sdk::tx::Signed;
    use namada_sdk::{governance, tendermint, token};
    use namada_vote_ext::bridge_pool_roots;

    use crate::shell::FinalizeBlockRequest;
    use crate::shell::test_utils::*;

    /// Make Bertha a validator.
    fn add_validator(shell: &mut TestShell) {
        // We make a change so that there Bertha is
        // a validator in the next epoch
        let validators_handle = consensus_validator_set_handle();
        validators_handle
            .at(&1.into())
            .at(&token::Amount::native_whole(100))
            .insert(&mut shell.state, ValidatorPosition(1), bertha_address())
            .expect("Test failed");

        // change pipeline length to 1
        let mut params =
            read_pos_params::<_, governance::Store<_>>(&shell.state).unwrap();
        params.owned.pipeline_len = 1;

        let consensus_key = gen_keypair();
        let protocol_key = bertha_keypair();
        let hot_key = gen_secp256k1_keypair();
        let cold_key = gen_secp256k1_keypair();

        become_validator::<_, governance::Store<_>>(
            &mut shell.state,
            BecomeValidator {
                params: &params,
                address: &bertha_address(),
                consensus_key: &consensus_key.ref_to(),
                protocol_key: &protocol_key.ref_to(),
                eth_hot_key: &hot_key.ref_to(),
                eth_cold_key: &cold_key.ref_to(),
                current_epoch: 0.into(),
                commission_rate: Default::default(),
                max_commission_rate_change: Default::default(),
                metadata: Default::default(),
                offset_opt: None,
            },
        )
        .expect("Test failed");

        // we advance forward to the next epoch
        let consensus_set: Vec<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.state,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let val1 = consensus_set[0].clone();
        let pkh1 = get_pkh_from_address(
            &shell.state,
            &params,
            val1.address.clone(),
            Epoch::default(),
        );
        let votes = vec![VoteInfo {
            validator: crate::tendermint::abci::types::Validator {
                address: pkh1,
                power: (u128::try_from(val1.bonded_stake).expect("Test failed")
                    as u64)
                    .try_into()
                    .unwrap(),
            },
            sig_info:
                crate::tendermint::abci::types::BlockSignatureInfo::LegacySigned,
        }];
        let req = FinalizeBlockRequest {
            proposer_address: tendermint::account::Id::try_from(pkh1.to_vec())
                .unwrap(),
            decided_last_commit: crate::tendermint::abci::types::CommitInfo {
                round: 0u8.into(),
                votes,
            },
            ..Default::default()
        };
        assert_eq!(shell.start_new_epoch(Some(req)).0, 1);

        // Check that Bertha's vote extensions pass validation.
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(&hot_key, to_sign).sig;
        let vote_ext = bridge_pool_roots::Vext {
            block_height: shell.state.in_mem().get_last_block_height(),
            validator_addr: bertha_address(),
            sig,
        }
        .sign(&bertha_keypair());
        shell.state.in_mem_mut().block.height =
            shell.state.in_mem().get_last_block_height();
        shell.commit();
        assert!(
            validate_bp_roots_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &vote_ext.0,
                shell.state.in_mem().get_last_block_height()
            )
            .is_ok()
        );
    }

    /// Test that the function crafting the bridge pool root
    /// vext creates the expected payload. Check that this
    /// payload passes validation.
    #[test]
    fn test_happy_flow() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (mut shell, _broadcaster, _, _oracle_control_recv) =
            setup_at_height(1u64);
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        shell.state.in_mem_mut().block.height =
            shell.state.in_mem().get_last_block_height();
        shell.commit();
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let vote_ext = bridge_pool_roots::Vext {
            block_height: shell.state.in_mem().get_last_block_height(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert_eq!(
            vote_ext.0,
            shell.extend_vote_with_bp_roots().expect("Test failed")
        );
        assert!(
            validate_bp_roots_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &vote_ext.0,
                shell.state.in_mem().get_last_block_height(),
            )
            .is_ok()
        )
    }

    /// Test that we de-duplicate the bridge pool vexts
    /// in a block proposal by validator address.
    #[test]
    fn test_vexts_are_de_duped() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (mut shell, _broadcaster, _, _oracle_control_recv) =
            setup_at_height(1u64);
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        shell.state.in_mem_mut().block.height =
            shell.state.in_mem().get_last_block_height();
        shell.commit();
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let vote_ext = bridge_pool_roots::Vext {
            block_height: shell.state.in_mem().get_last_block_height(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        let valid = shell
            .filter_invalid_bp_roots_vexts(vec![
                vote_ext.0.clone(),
                vote_ext.0.clone(),
            ])
            .collect::<Vec<_>>();
        assert_eq!(valid, vec![vote_ext.0]);
    }

    /// Test that Bridge pool roots signed by a non-validator are rejected
    /// even if the vext is signed by a validator
    #[test]
    fn test_bp_roots_must_be_signed_by_validator() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (mut shell, _broadcaster, _, _oracle_control_recv) =
            setup_at_height(1u64);
        let signing_key = gen_keypair();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        shell.state.in_mem_mut().block.height =
            shell.state.in_mem().get_last_block_height();
        shell.commit();
        let to_sign = get_bp_bytes_to_sign();
        let sig =
            Signed::<_, SignableEthMessage>::new(&signing_key, to_sign).sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.state.in_mem().get_last_block_height(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(
            validate_bp_roots_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &bp_root.0,
                shell.get_current_decision_height(),
            )
            .is_err()
        )
    }

    /// Test that Bridge pool root vext and inner signature
    /// are from the same validator.
    #[test]
    fn test_bp_root_sigs_from_same_validator() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (mut shell, _broadcaster, _, _oracle_control_recv) =
            setup_at_height(3u64);
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        add_validator(&mut shell);
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.state.in_mem().get_last_block_height(),
            validator_addr: address,
            sig,
        }
        .sign(&bertha_keypair());
        assert!(
            validate_bp_roots_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &bp_root.0,
                shell.state.in_mem().get_last_block_height()
            )
            .is_err()
        )
    }

    fn reject_incorrect_block_number(height: BlockHeight, shell: &TestShell) {
        let address = shell.mode.get_validator_address().unwrap().clone();
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: height,
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));

        assert!(
            validate_bp_roots_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &bp_root.0,
                shell.state.in_mem().get_last_block_height()
            )
            .is_err()
        )
    }

    /// Test that an [`bridge_pool_roots::Vext`] that labels its included
    /// block height as greater than the latest block height is rejected.
    #[test]
    fn test_block_height_too_high() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (shell, _, _, _) = setup_at_height(3u64);
        reject_incorrect_block_number(
            shell.state.in_mem().get_last_block_height() + 1,
            &shell,
        );
    }

    /// Test if we reject Bridge pool roots vote extensions
    /// issued at genesis.
    #[test]
    fn test_reject_genesis_vexts() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (shell, _, _, _) = setup();
        reject_incorrect_block_number(0.into(), &shell);
    }

    /// Test that a bridge pool root vext is rejected
    /// if the nonce is incorrect.
    #[test]
    fn test_incorrect_nonce() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (shell, _, _, _) = setup();
        let address = shell.mode.get_validator_address().unwrap().clone();
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.state.in_mem().get_last_block_height(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(
            validate_bp_roots_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &bp_root.0,
                shell.state.in_mem().get_last_block_height()
            )
            .is_err()
        )
    }

    /// Test that a bridge pool root vext is rejected
    /// if the root is incorrect.
    #[test]
    fn test_incorrect_root() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (shell, _, _, _) = setup();
        let address = shell.mode.get_validator_address().unwrap().clone();
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.state.in_mem().get_last_block_height(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(
            validate_bp_roots_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &bp_root.0,
                shell.state.in_mem().get_last_block_height()
            )
            .is_err()
        )
    }

    /// Test that we can verify vext from several block heights
    /// prior.
    #[test]
    fn test_vext_for_old_height() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (mut shell, _recv, _, _oracle_control_recv) = setup_at_height(1u64);
        let address = shell.mode.get_validator_address().unwrap().clone();
        shell.state.in_mem_mut().block.height = 2.into();
        let key = get_key_from_hash(&KeccakHash([1; 32]));
        let height = shell.state.in_mem().block.height;
        shell.state.write(&key, height).expect("Test failed");
        shell.commit();
        assert_eq!(
            shell
                .state
                .ethbridge_queries()
                .get_bridge_pool_root_at_height(2.into())
                .unwrap(),
            KeccakHash([1; 32])
        );
        shell.state.in_mem_mut().block.height = 3.into();
        shell.state.delete(&key).expect("Test failed");
        let key = get_key_from_hash(&KeccakHash([2; 32]));
        let height = shell.state.in_mem().block.height;
        shell.state.write(&key, height).expect("Test failed");
        shell.commit();
        assert_eq!(
            shell
                .state
                .ethbridge_queries()
                .get_bridge_pool_root_at_height(3.into())
                .unwrap(),
            KeccakHash([2; 32])
        );
        let to_sign = keccak_hash([[1; 32], Uint::from(0).to_bytes()].concat());
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: 2.into(),
            validator_addr: address.clone(),
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(
            validate_bp_roots_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &bp_root.0,
                shell.get_current_decision_height()
            )
            .is_ok()
        );
        let to_sign = keccak_hash([[2; 32], Uint::from(0).to_bytes()].concat());
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: 3.into(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(
            validate_bp_roots_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &bp_root.0,
                shell.get_current_decision_height()
            )
            .is_ok()
        );
    }

    /// Test that if the wrong block height is given for the provided root,
    /// we reject.
    #[test]
    fn test_wrong_height_for_root() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }
        let (mut shell, _recv, _, _oracle_control_recv) = setup_at_height(1u64);
        let address = shell.mode.get_validator_address().unwrap().clone();
        shell.state.in_mem_mut().block.height = 2.into();
        let key = get_key_from_hash(&KeccakHash([1; 32]));
        let height = shell.state.in_mem().block.height;
        shell.state.write(&key, height).expect("Test failed");
        shell.commit();
        assert_eq!(
            shell
                .state
                .ethbridge_queries()
                .get_bridge_pool_root_at_height(2.into())
                .unwrap(),
            KeccakHash([1; 32])
        );
        shell.state.in_mem_mut().block.height = 3.into();
        shell.state.delete(&key).expect("Test failed");
        let key = get_key_from_hash(&KeccakHash([2; 32]));
        let height = shell.state.in_mem().block.height;
        shell.state.write(&key, height).expect("Test failed");
        shell.commit();
        assert_eq!(
            shell
                .state
                .ethbridge_queries()
                .get_bridge_pool_root_at_height(3.into())
                .unwrap(),
            KeccakHash([2; 32])
        );
        let to_sign = keccak_hash([[1; 32], Uint::from(0).to_bytes()].concat());
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: 3.into(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(
            validate_bp_roots_vext::<_, _, governance::Store<_>>(
                &shell.state,
                &bp_root.0,
                shell.get_current_decision_height()
            )
            .is_err()
        );
    }
}
