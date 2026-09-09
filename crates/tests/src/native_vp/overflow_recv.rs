//! Regression tests for the IBC overflow-receive vulnerability.
//!
//! The overflow-receive middleware pays out the overflow (the packet
//! amount minus the memo's `shielded_amount`) to the memo's
//! `overflow_receiver` *eagerly, before* dispatching the shrunken packet
//! downstream, and never reverts that payout when the downstream
//! shielded-recv middleware returns an error acknowledgement. A
//! transparent packet receiver forces that error ack deterministically,
//! and the relayed error ack refunds the full pre-split amount on the
//! source chain — so the attacker keeps the remainder *and* gets
//! refunded:
//!
//! - mint variant (foreign token arriving): the remainder is freshly minted,
//!   unbacked vouchers;
//! - unescrow variant (a home token returning): the remainder is paid out of
//!   the real IBC escrow.
//!
//! The IBC VP pseudo-executes against the bare transfer module, so any
//! state change only the middleware stack can produce (the eager
//! payout, the shielded-recv error ack) can never be reproduced, and
//! the attack is rejected at the VP. These tests run the attack through
//! the middleware-wired execution path (which still performs the eager
//! payout) and assert the IBC VP rejection, mirroring
//! `escrow_drain.rs`.

#[cfg(test)]
mod overflow_recv_tests {
    use std::str::FromStr;

    use namada_sdk::account::AccountPublicKeysMap;
    use namada_sdk::address::Address;
    use namada_sdk::borsh::BorshSerializeExt;
    use namada_sdk::chain::ChainId;
    use namada_sdk::ibc::apps::transfer::types::packet::PacketData;
    use namada_sdk::ibc::primitives::ToProto;
    use namada_sdk::ibc::storage::ack_key;
    use namada_sdk::ibc::{IbcShieldingData, NamadaMemo, NamadaMemoData};
    use namada_sdk::key::{self, RefTo};
    use namada_sdk::state::{StorageRead, StorageWrite};
    use namada_sdk::string_encoding::StringEncoded;
    use namada_sdk::token::{self, Amount};
    use namada_sdk::tx::Tx;
    use prost::Message;

    use crate::tx::{TestTxEnv, tx_host_env};
    use crate::vm_host_env::ibc::{self, ChannelId, Packet, PortId, Sequence};

    /// Hex of a borsh-serialized empty MASPv5 transaction, used as the
    /// `shielding_data` of the crafted overflow-recv memo. The memo must
    /// *parse* for the middleware stack to consume it, but the shielding
    /// data is never applied (the shielded-recv middleware error-acks the
    /// packet before any MASP handling).
    const EMPTY_MASP_TX_HEX: &str = concat!(
        "02000000", // MASPV5_TX_VERSION
        "0A27A726", // MASPV5_VERSION_GROUP_ID
        "A675FFE9", // BranchId::MASP (0xe9ff75a6 LE)
        "00000000", // lock_time
        "00000000", // expiry_height
        "00",       // transparent vin (CompactSize 0)
        "00",       // transparent vout
        "00",       // sapling spends
        "00",       // sapling converts
        "00",       // sapling outputs
    );

    /// Attack parameters shared by both variants: send `ATTACK_AMOUNT`
    /// with a `shielded_amount` of 1, so the overflow remainder is
    /// `ATTACK_AMOUNT - 1`. Kept under the 100-token mint rate limit
    /// configured by `ibc::init_storage` so that the rate-limit checks
    /// don't confound the VP rejection.
    const ATTACK_AMOUNT: u64 = 90;
    const SHIELDED_AMOUNT: u64 = 1;

    /// Craft the `namada.osmosis_swap` memo driving the attack.
    fn overflow_recv_memo(overflow_receiver: &Address) -> String {
        let shielding_data = StringEncoded::new(
            IbcShieldingData::from_str(EMPTY_MASP_TX_HEX)
                .expect("empty MASP tx fixture must parse"),
        );
        let data = NamadaMemoData::OsmosisSwap {
            shielding_data,
            shielded_amount: Amount::from_u64(SHIELDED_AMOUNT),
            overflow_receiver: overflow_receiver.clone(),
        };
        serde_json::to_string(&NamadaMemo { namada: data })
            .expect("overflow memo encode failed")
    }

    /// Set up IBC state (client/connection/channel) and return the test
    /// token address plus the port and channel ids.
    fn setup_ibc_state() -> (Address, PortId, ChannelId) {
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
                env.state.write_bytes(&key, &val).expect("write error");
            });
        });
        (token, port_id, channel_id)
    }

    /// Build a receive-side packet carrying the crafted `osmosis_swap`
    /// memo, with `denom` as the transferred token, an amount of
    /// `ATTACK_AMOUNT` and a transparent (non-MASP) receiver that forces
    /// the shielded-recv error ack.
    fn attack_packet(
        port_id: PortId,
        channel_id: ChannelId,
        denom: String,
        attacker: &Address,
    ) -> Packet {
        let mut packet = ibc::received_packet(
            port_id,
            channel_id,
            Sequence::from(1),
            denom,
            attacker,
        );
        // Override the amount and the memo for the attack.
        let mut data: PacketData =
            serde_json::from_slice(&packet.data).expect("packet data parses");
        data.token.amount = Amount::from_u64(ATTACK_AMOUNT).into();
        data.memo = overflow_recv_memo(attacker).into();
        packet.data = serde_json::to_vec(&data).expect("packet data encodes");
        packet
    }

    /// Receive `packet` via a real `MsgRecvPacket` through the IBC actions
    /// (what `tx_ibc.wasm` runs), and return the env for the VP check.
    fn recv_via_ibc_actions(packet: Packet) -> TestTxEnv {
        let keypair = key::testing::keypair_1();
        let keypairs = vec![keypair.clone()];
        let pks_map = AccountPublicKeysMap::from_iter([keypair.ref_to()]);

        let msg = ibc::msg_packet_recv(packet);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");

        let mut tx = Tx::new(ChainId::default(), None);
        tx.add_code(vec![], None)
            .add_serialized_data(tx_data.clone())
            .sign_raw(keypairs, pks_map, None)
            .sign_wrapper(keypair);
        let batched_tx = tx.batch_first_tx();
        tx_host_env::with(|env| {
            env.batched_tx = batched_tx.clone();
        });

        tx_host_env::ibc::ibc_actions(tx_host_env::ctx())
            .execute::<token::Transfer>(&tx_data)
            .expect(
                "receiving the attack packet must not error at the protocol \
                 level (the failure is carried in the ack)",
            );
        tx_host_env::take()
    }

    /// The deterministic error ack the shielded-recv middleware constructs
    /// for a non-MASP packet receiver
    /// (`crates/ibc/src/context/middlewares/shielded_recv.rs`), committed
    /// as `AcknowledgementCommitment` = sha256(ack bytes)
    /// (ibc-core-channel-types `commitment.rs`).
    fn expected_error_ack_commitment(receiver: &Address) -> Vec<u8> {
        let msg = format!(
            "Shielded receive error: Address {receiver} is not the MASP"
        );
        let ack_bytes = format!(r#"{{"error":"{msg}"}}"#);
        namada_sdk::hash::Hash::sha256(ack_bytes.as_bytes())
            .0
            .to_vec()
    }

    /// Mint variant: a foreign token arrives over the channel (its denom
    /// has no local prefix), so the overflow middleware mints the
    /// remainder as fresh vouchers to the attacker and the shielded-recv
    /// middleware error-acks the shrunken packet. The state change can't
    /// be reproduced by the bare-transfer-module pseudo-execution, so the
    /// IBC VP must reject the tx.
    #[test]
    fn test_overflow_recv_mint_attack_rejected_by_vp() {
        let attacker = namada_sdk::address::testing::established_address_1();
        let base_token = "uchungus".to_string();

        let (_token, port_id, channel_id) = setup_ibc_state();
        tx_host_env::with(|env| {
            env.spawn_accounts([&attacker]);
        });

        let packet = attack_packet(
            port_id.clone(),
            channel_id.clone(),
            base_token,
            &attacker,
        );

        let env = recv_via_ibc_actions(packet);

        // The error ack must be committed for the source chain to relay it
        // back and refund the (full) packet amount.
        let stored_ack_commitment: Option<Vec<u8>> = env
            .state
            .read_bytes(&ack_key(&port_id, &channel_id, Sequence::from(1)))
            .expect("read error");
        assert_eq!(
            stored_ack_commitment.as_deref(),
            Some(expected_error_ack_commitment(&attacker).as_slice()),
            "the shielded-recv error ack must be committed"
        );

        let result =
            ibc::validate_ibc_vp_from_tx(&env, &env.batched_tx.to_ref());
        assert!(
            result.is_err(),
            "IBC VP must reject the overflow-receive mint attack, got: \
             {result:?}"
        );
    }

    /// Unescrow variant: a Namada-originated token returns over the
    /// channel (its denom starts with the source-end prefix), so the
    /// overflow middleware unescrows the remainder out of the funded IBC
    /// escrow to the attacker and the shielded-recv middleware error-acks
    /// the shrunken packet. The IBC VP must reject the tx.
    #[test]
    fn test_overflow_recv_unescrow_attack_rejected_by_vp() {
        let attacker = namada_sdk::address::testing::established_address_1();

        let (token, port_id, channel_id) = setup_ibc_state();
        tx_host_env::with(|env| {
            env.spawn_accounts([&attacker]);
        });

        // Fund the IBC escrow with the base token, and craft a returning
        // denom: its trace carries the *source*-end prefix, so
        // `is_receiver_chain_source` selects the unescrow branch.
        let escrow_funding = Amount::native_whole(1_000);
        let escrow_key = token::storage_key::balance_key(
            &token,
            &namada_sdk::ibc::IBC_ESCROW_ADDRESS,
        );
        tx_host_env::with(|env| {
            env.state
                .db_write(&escrow_key, escrow_funding.serialize_to_vec())
                .unwrap();
        });
        let returning_denom = format!("{}/{}/{}", port_id, channel_id, token);

        let packet = attack_packet(
            port_id.clone(),
            channel_id.clone(),
            returning_denom,
            &attacker,
        );

        let env = recv_via_ibc_actions(packet);

        let result =
            ibc::validate_ibc_vp_from_tx(&env, &env.batched_tx.to_ref());
        assert!(
            result.is_err(),
            "IBC VP must reject the overflow-receive unescrow attack, got: \
             {result:?}"
        );
    }
}
