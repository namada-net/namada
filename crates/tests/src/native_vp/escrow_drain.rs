//! Regression tests for the escrow drain attacks described in `exploits/`.
//!
//! - Escrowdrian: a plain, allowlisted `tx_transfer` whose `sources` map names
//!   the PoS internal address (`#PoS`) as the owner can drain the staking
//!   escrow. The Multitoken VP must reject any native token debit from a
//!   protocol-owned account (`#PoS`, `#Governance`) that isn't backed by a
//!   matching protocol action.
//! - IBC escrow drain: a `tx_ibc` carrying an inner Namada `Transfer` that
//!   names the IBC escrow (`#IBC`) as its source can drain the escrow with a
//!   zero-amount packet. The IBC VP must reject any escrow balance change that
//!   isn't reproduced by the protocol's pseudo-execution of the IBC message.
//!
//! These tests run the real wasm transactions through the wasm engine where
//! possible, so they keep passing (and keep proving coverage) even after the
//! wasm-level guards are removed and the VP-level defenses remain.

#[cfg(test)]
mod escrow_drain_tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use namada_apps_lib::wasm_loader;
    use namada_sdk::account::AccountPublicKeysMap;
    use namada_sdk::address::testing::established_address_1;
    use namada_sdk::address::{self, Address, InternalAddress};
    use namada_sdk::chain::ChainId;
    use namada_sdk::gas::VpGasMeter;
    use namada_sdk::ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
    use namada_sdk::ibc::apps::transfer::types::packet::PacketData;
    use namada_sdk::ibc::apps::transfer::types::{Memo, PrefixedCoin};
    use namada_sdk::ibc::core::channel::types::timeout::{
        TimeoutHeight, TimeoutTimestamp,
    };
    use namada_sdk::ibc::primitives::Timestamp;
    use namada_sdk::ibc::{IBC_ESCROW_ADDRESS, MsgTransfer};
    use namada_sdk::key::{self, RefTo};
    use namada_sdk::proof_of_stake::OwnedPosParams;
    use namada_sdk::proof_of_stake::test_utils::get_dummy_genesis_validator;
    use namada_sdk::storage::Epoch;
    use namada_sdk::token::{self, Amount, Transfer};
    use namada_sdk::tx::{TX_IBC_WASM, TX_TRANSFER_WASM, Tx};
    use namada_sdk::validation::{MultitokenVp, PosVp};
    use namada_tx_prelude::BorshSerializeExt;

    use crate::native_vp::TestNativeVpEnv;
    use crate::tx::{TestTxEnv, tx_host_env};
    use crate::vm_host_env::ibc;

    /// Gets the absolute path to wasm directory
    fn wasm_dir() -> PathBuf {
        let mut current_path = std::env::current_dir()
            .expect("Current directory should exist")
            .canonicalize()
            .expect("Current directory should exist");
        while current_path.file_name().unwrap() != "tests" {
            current_path.pop();
        }
        // Two-dirs up to root
        current_path.pop();
        current_path.pop();
        current_path.join("wasm")
    }

    fn sign_tx(tx: &mut Tx) {
        let keypair = key::testing::keypair_1();
        let pks_map = AccountPublicKeysMap::from_iter([keypair.ref_to()]);
        tx.sign_raw(vec![keypair.clone()], pks_map, None)
            .sign_wrapper(keypair);
    }

    /// Build the Escrowdrian attack payload: a plain transparent transfer
    /// whose only source is the PoS internal account.
    fn pos_drain_transfer(
        native_token: &Address,
        attacker: &Address,
        drain: Amount,
    ) -> Transfer {
        let pos = Address::Internal(InternalAddress::PoS);
        Transfer {
            sources: BTreeMap::from([(
                token::Account {
                    owner: pos,
                    token: native_token.clone(),
                },
                drain.native_denominated(),
            )]),
            targets: BTreeMap::from([(
                token::Account {
                    owner: attacker.clone(),
                    token: native_token.clone(),
                },
                drain.native_denominated(),
            )]),
            shielded_section_hash: None,
        }
    }

    /// Run the Escrowdrian attack through the real `tx_transfer.wasm` and
    /// check that the Multitoken VP rejects the unauthorized debit of the
    /// PoS escrow.
    #[test]
    fn test_pos_escrow_drain_blocked() {
        let native_token = address::testing::nam();
        let attacker = established_address_1();
        let pos = Address::Internal(InternalAddress::PoS);
        let drain = Amount::native_whole(50_000);

        let mut tx_env = TestTxEnv::default();
        namada_sdk::parameters::init_test_storage(&mut tx_env.state).unwrap();
        token::write_denom(
            &mut tx_env.state,
            &native_token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();
        // Initialize PoS genesis so that the PoS VP can run over the state
        tx_env.state.in_mem_mut().block.epoch = Epoch(1);
        namada_sdk::proof_of_stake::test_utils::test_init_genesis::<
            _,
            namada_sdk::parameters::Store<_>,
            namada_sdk::governance::Store<_>,
            namada_sdk::token::Store<_>,
        >(
            &mut tx_env.state,
            OwnedPosParams::default(),
            std::iter::once(get_dummy_genesis_validator()),
            Epoch(1),
        )
        .unwrap();
        tx_env.state.commit_tx_batch();
        tx_env.state.commit_block().unwrap();
        tx_env.spawn_accounts([&attacker]);
        // Fund the staking escrow
        tx_env.credit_tokens(&pos, &native_token, drain);

        // Build the attack tx: a single allowlisted `tx_transfer` with
        // `sources = {(#PoS, NAM): X}` signed only by the attacker
        let transfer = pos_drain_transfer(&native_token, &attacker, drain);
        let wasm_code =
            wasm_loader::read_wasm_or_exit(wasm_dir(), TX_TRANSFER_WASM);
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(wasm_code, None).add_data(transfer);
        sign_tx(&mut tx);
        tx_env.batched_tx = tx.batch_first_tx();

        // The wasm tx itself must succeed: `tx_transfer` has no guard against
        // internal addresses as sources, the defense lives in the VPs
        tx_env
            .execute_tx()
            .expect("wasm tx execution should succeed");

        // The Multitoken VP must reject: the PoS account is protocol-owned,
        // and the tx carries no PoS action to justify the debit
        let gas_meter = RefCell::new(VpGasMeter::new_from_meter(
            &*tx_env.gas_meter.borrow(),
        ));
        let vp_env = TestNativeVpEnv::from_tx_env(
            tx_env,
            Address::Internal(InternalAddress::Multitoken),
        );
        let ctx = vp_env.ctx(&gas_meter);
        let result = MultitokenVp::validate_tx(
            &ctx,
            &vp_env.tx_env.batched_tx.to_ref(),
            ctx.keys_changed,
            ctx.verifiers,
        );
        let err = result.expect_err(
            "Multitoken VP must reject the unauthorized debit of the PoS \
             escrow",
        );
        assert!(
            err.to_string().contains("isn't allowed"),
            "unexpected rejection reason: {err}"
        );

        // The PoS VP must also reject: the escrow balance decreased without
        // any Withdraw or ClaimRewards action
        let tx_env = vp_env.tx_env;
        let gas_meter = RefCell::new(VpGasMeter::new_from_meter(
            &*tx_env.gas_meter.borrow(),
        ));
        let vp_env = TestNativeVpEnv::from_tx_env(tx_env, pos);
        let ctx = vp_env.ctx(&gas_meter);
        let result = PosVp::validate_tx(
            &ctx,
            &vp_env.tx_env.batched_tx.to_ref(),
            ctx.keys_changed,
            ctx.verifiers,
        );
        let err = result.expect_err(
            "PoS VP must reject the unauthorized debit of the PoS escrow",
        );
        assert!(
            err.to_string()
                .contains("PoS balance decreased without any Withdraw or"),
            "unexpected rejection reason: {err}"
        );
    }

    /// Set up the IBC state (client, connection, channel) with a funded
    /// escrow, and build the drain attack message: an ICS20 `MsgTransfer`
    /// whose packet declares zero units and whose inner Namada transfer
    /// moves the escrow's full balance to the attacker.
    fn ibc_drain_setup(
        attacker: &Address,
        drain: Amount,
    ) -> (Address, Vec<u8>) {
        tx_host_env::init();

        let (token, _account) = ibc::init_storage();
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id, false);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            tx_host_env::with(|env| {
                env.state.db_write(&key, val.clone()).expect("write error");
            });
        });

        // Fund the IBC escrow
        tx_host_env::with(|env| {
            env.spawn_accounts([attacker]);
            let escrow_key =
                token::storage_key::balance_key(&token, &IBC_ESCROW_ADDRESS);
            env.state
                .db_write(&escrow_key, drain.serialize_to_vec())
                .unwrap();
        });

        // Zero-amount packet: the handler's own escrow move becomes a no-op
        let timestamp =
            (Timestamp::now() + core::time::Duration::from_secs(100)).unwrap();
        let message = IbcMsgTransfer {
            port_id_on_a: port_id,
            chan_id_on_a: channel_id,
            packet_data: PacketData {
                token: PrefixedCoin {
                    denom: token.to_string().parse().expect("invalid denom"),
                    amount: Amount::zero().into(),
                },
                sender: attacker.to_string().into(),
                receiver: attacker.to_string().into(),
                memo: Memo::from("".to_string()),
            },
            timeout_height_on_b: TimeoutHeight::Never,
            timeout_timestamp_on_b: TimeoutTimestamp::At(timestamp),
        };
        // Inner transfer: drain the entire escrow to the attacker
        let msg = MsgTransfer {
            message,
            transfer: Some(Transfer {
                sources: BTreeMap::from([(
                    token::Account {
                        owner: IBC_ESCROW_ADDRESS,
                        token: token.clone(),
                    },
                    drain.native_denominated(),
                )]),
                targets: BTreeMap::from([(
                    token::Account {
                        owner: attacker.clone(),
                        token: token.clone(),
                    },
                    drain.native_denominated(),
                )]),
                shielded_section_hash: None,
            }),
        };
        (token, msg.serialize_to_vec())
    }

    /// Check that the IBC VP rejects the drain: the pseudo-execution of the
    /// IBC message (which only runs the protocol handler, a no-op on a
    /// zero-amount packet) shows no escrow balance change, but the actual
    /// state has one produced by the inner transfer.
    #[test]
    fn test_ibc_escrow_drain_blocked_by_vp() {
        let attacker = established_address_1();
        let drain = Amount::native_whole(1_000);
        let (_token, tx_data) = ibc_drain_setup(&attacker, drain);

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone());
        sign_tx(&mut tx);
        let batched_tx = tx.batch_first_tx();
        tx_host_env::with(|env| {
            env.batched_tx = batched_tx.clone();
        });

        // 1. Run the IBC handler (what `tx_ibc.wasm` does first): the
        //    zero-amount packet makes its own escrow move a no-op
        let data = tx_host_env::ibc::ibc_actions(tx_host_env::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect("IBC handler should accept a zero-amount packet");

        // 2. Apply the client-supplied inner transfer verbatim (what
        //    `tx_ibc.wasm` does next, simulating the wasm without the
        //    escrow-address guard)
        let transfers =
            data.transparent.expect("inner transfer must be present");
        let transparent =
            transfers.transparent_part().expect("must be transparent");
        tx_host_env::token::apply_transparent_transfers(
            tx_host_env::ctx(),
            transparent,
        )
        .expect("applying the inner transfer should succeed");

        // 3. The IBC VP must reject the escrow balance change
        let env = tx_host_env::take();
        let result =
            ibc::validate_ibc_vp_from_tx(&env, &env.batched_tx.to_ref());
        assert!(
            result.is_err(),
            "IBC VP must reject the escrow drain, got: {result:?}"
        );
    }

    /// Run the full attack through the real `tx_ibc.wasm` via the wasm
    /// engine. The attack must be blocked somewhere in the pipeline: either
    /// the wasm-level guard rejects the tx, or the tx goes through and the
    /// IBC VP rejects the resulting state changes.
    #[test]
    fn test_ibc_escrow_drain_full_pipeline() {
        let attacker = established_address_1();
        let drain = Amount::native_whole(1_000);
        let (_token, tx_data) = ibc_drain_setup(&attacker, drain);

        let wasm_code = wasm_loader::read_wasm_or_exit(wasm_dir(), TX_IBC_WASM);
        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(wasm_code, None).add_serialized_data(tx_data);
        sign_tx(&mut tx);
        let batched_tx = tx.batch_first_tx();
        tx_host_env::with(|env| {
            env.batched_tx = batched_tx.clone();
        });

        let mut tx_env = tx_host_env::take();
        match tx_env.execute_tx() {
            Ok(()) => {
                // The wasm allowed the tx (no escrow guard): the IBC VP
                // must reject the unauthorized escrow balance change
                let result = ibc::validate_ibc_vp_from_tx(
                    &tx_env,
                    &tx_env.batched_tx.to_ref(),
                );
                assert!(
                    result.is_err(),
                    "IBC VP must reject the escrow drain, got: {result:?}"
                );
            }
            Err(_err) => {
                // The wasm-level escrow guard rejected the tx: the attack
                // is blocked before any state change is applied
            }
        }
    }
}
