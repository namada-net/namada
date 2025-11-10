//! By default, these tests will run in release mode. This can be disabled
//! by setting environment variable `NAMADA_E2E_DEBUG=true`. For debugging,
//! you'll typically also want to set `RUST_BACKTRACE=1`, e.g.:
//!
//! ```ignore,shell
//! NAMADA_E2E_DEBUG=true RUST_BACKTRACE=1 cargo test e2e::ibc_tests -- --test-threads=1 --nocapture
//! ```
//!
//! To keep the temporary files created by a test, use env var
//! `NAMADA_E2E_KEEP_TEMP=true`.

use core::str::FromStr;
use core::time::Duration;
use std::fs::File;
use std::path::{Path, PathBuf};

use base64::prelude::{BASE64_STANDARD, Engine};
use color_eyre::eyre::Result;
use eyre::{WrapErr, eyre};
use ibc_middleware_packet_forward::ForwardMetadata;
use itertools::Either;
use namada_apps_lib::client::rpc::query_storage_value_bytes;
use namada_apps_lib::config::ethereum_bridge;
use namada_apps_lib::config::genesis::templates;
use namada_apps_lib::tendermint_rpc::{Client, HttpClient, Url};
use namada_core::masp::PaymentAddress;
use namada_sdk::address::MASP;
use namada_sdk::chain::Epoch;
use namada_sdk::governance::cli::onchain::PgfFunding;
use namada_sdk::governance::pgf::ADDRESS as PGF_ADDRESS;
use namada_sdk::governance::storage::proposal::{PGFIbcTarget, PGFTarget};
use namada_sdk::ibc::IbcShieldingData;
use namada_sdk::ibc::apps::nft_transfer::types::{
    PORT_ID_STR as NFT_PORT_ID, VERSION as NFT_CHANNEL_VERSION,
};
use namada_sdk::ibc::apps::transfer::types::{
    PORT_ID_STR as FT_PORT_ID, VERSION as FT_CHANNEL_VERSION,
};
use namada_sdk::ibc::clients::tendermint::client_state::ClientState as TmClientState;
use namada_sdk::ibc::core::client::types::Height;
use namada_sdk::ibc::core::host::types::identifiers::{
    ChannelId, ClientId, PortId,
};
use namada_sdk::ibc::primitives::proto::Any;
use namada_sdk::ibc::storage::*;
use namada_sdk::ibc::trace::ibc_token;
use namada_sdk::token::Amount;
use namada_test_utils::TestWasms;
use prost::Message;
use serde_json::json;
use setup::constants::*;
use sha2::{Digest, Sha256};

use crate::e2e::helpers::{
    epoch_sleep, epochs_per_year_from_min_duration, find_address,
    find_cosmos_address, find_payment_address, get_actor_rpc,
    get_cosmos_gov_address, get_cosmos_rpc_address, get_epoch,
};
use crate::e2e::ledger_tests::{
    start_namada_ledger_node_wait_wasm, write_json_file,
};
use crate::e2e::setup::{
    self, Bin, CosmosChainType, ENV_VAR_COSMWASM_CONTRACT_DIR, NamadaCmd, Test,
    TestDir, Who, apply_use_device, osmosis_fixtures_dir, run_cosmos_cmd,
    run_cosmos_cmd_homeless, run_hermes_cmd, set_ethereum_bridge_mode,
    setup_cosmos, setup_hermes, sleep, working_dir,
};
use crate::ibc::primitives::Signer;
use crate::strings::TX_APPLIED_SUCCESS;
use crate::{run, run_as};

const IBC_REFUND_TARGET_ALIAS: &str = "ibc-refund-target";
const IBC_CLINET_ID: &str = "07-tendermint-0";
const UPGRADED_CHAIN_ID: &str = "upgraded-chain";
const CW721_WASM: &str = "cw721_base.wasm";
const ICS721_WASM: &str = "ics721_base.wasm";
const NFT_ID: &str = "test_nft";

#[test]
fn ibc_to_and_from_payment_addrs() -> Result<()> {
    const PIPELINE_LEN: u64 = 2;
    const MASP_EPOCH_MULTIPLIER: u64 = 1;

    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(60);
            genesis.parameters.gov_params.min_proposal_grace_epochs = 3;
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis.parameters.pos_params.pipeline_len = PIPELINE_LEN;
            genesis.parameters.parameters.masp_epoch_multiplier =
                MASP_EPOCH_MULTIPLIER;
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) =
        run_namada_cosmos(CosmosChainType::Gaia(None), update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    // Delegate tokens on Namada
    delegate_token(&test)?;
    let rpc = get_actor_rpc(&test, Who::Validator(0));
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let delegated_epoch = epoch + PIPELINE_LEN;

    // Create channel between Namada and Gaia
    let hermes_dir = setup_hermes(&test, &test_gaia)?;
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let port_id_gaia = FT_PORT_ID.parse().unwrap();
    let (channel_id_namada, channel_id_gaia) = create_channel_with_hermes(
        &hermes_dir,
        &test,
        &test_gaia,
        &port_id_namada,
        &port_id_gaia,
    )?;

    // Start relaying
    let hermes = run_hermes(&hermes_dir)?;
    let bg_hermes = hermes.background();

    // Shielding transfer 200 samoleans from Gaia to Namada
    let albert_payment_addr = find_payment_address(&test, AA_PAYMENT_ADDRESS)?;
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        albert_payment_addr.to_string(),
        COSMOS_COIN,
        200,
        &port_id_gaia,
        &channel_id_gaia,
        None,
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_gaia,
        &channel_id_gaia,
        &test_gaia,
    )?;
    let ibc_denom_on_namada =
        format!("{port_id_namada}/{channel_id_namada}/{COSMOS_COIN}");
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 200)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 800)?;

    // Unshielding transfer 100 samoleans from Namada to Gaia
    let gaia_receiver = find_cosmos_address(&test_gaia, COSMOS_USER)?;
    transfer(
        &test,
        A_SPENDING_KEY,
        &gaia_receiver,
        &ibc_denom_on_namada,
        100,
        Some(BERTHA_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 100)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 900)?;

    // Get refunded by unshielding to an invalid address on Gaia
    transfer(
        &test,
        A_SPENDING_KEY,
        "invalid_receiver",
        &ibc_denom_on_namada,
        100,
        Some(BERTHA_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;
    // The balance should not have changed
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 100)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 900)?;

    // Attempt to mint tokens twice, by including both a payment
    // address and a shielding transfer. This should fail.
    let shielding_data = {
        let shielding_data_path = gen_ibc_shielding_data(
            &test,
            AA_PAYMENT_ADDRESS,
            COSMOS_COIN,
            100,
            &port_id_namada,
            &channel_id_namada,
            None,
        )?;
        String::from_utf8(std::fs::read(shielding_data_path)?)?
    };
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        albert_payment_addr.to_string(),
        COSMOS_COIN,
        100,
        &port_id_gaia,
        &channel_id_gaia,
        // NB: stuff the shielding data onto a `Right`
        // variant, to avoid using the MASP transparent
        // address as a receiver, and use the payment
        // address instead
        Some(Either::Right(shielding_data)),
        // NB: add a timeout, to get refunded on Gaia
        Some(Duration::from_secs(10)),
    )?;

    // Check that the VP rejects the received packet
    let mut hermes = bg_hermes.foreground();
    hermes.exp_string("Attempted to mint IBC tokens twice through the MASP")?;
    let bg_hermes = hermes.background();
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_gaia,
        &channel_id_gaia,
        &test_gaia,
    )?;
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 100)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 900)?;

    // Now let's activate rewards for samoleans on Namada
    {
        // Wait for tokens to be delegated, in case
        // they haven't yet
        epoch = get_epoch(&test, &rpc).unwrap();
        while epoch < delegated_epoch {
            epoch = epoch_sleep(&test, &rpc, 120)?;
        }

        // Launch inflation proposal on Namada
        let start_epoch = propose_inflation(&test)?;

        // Vote
        epoch = get_epoch(&test, &rpc).unwrap();
        while epoch < start_epoch {
            epoch = epoch_sleep(&test, &rpc, 120)?;
        }
        submit_votes(&test)?;

        // Wait for grace epoch
        let grace_epoch = start_epoch + 6u64 /* grace epoch offset */;
        epoch = get_epoch(&test, &rpc).unwrap();
        while epoch < grace_epoch {
            epoch = epoch_sleep(&test, &rpc, 120)?;
        }

        // Wait the next masp epoch to update the conversion state
        let new_masp_epoch = grace_epoch + MASP_EPOCH_MULTIPLIER;
        epoch = get_epoch(&test, &rpc).unwrap();
        while epoch < new_masp_epoch {
            epoch = epoch_sleep(&test, &rpc, 120)?;
        }
    }

    // Attempt to mint tokens twice, again, but this time,
    // with rewards activated
    let shielding_data = {
        let shielding_data_path = gen_ibc_shielding_data(
            &test,
            AA_PAYMENT_ADDRESS,
            COSMOS_COIN,
            100,
            &port_id_namada,
            &channel_id_namada,
            None,
        )?;
        String::from_utf8(std::fs::read(shielding_data_path)?)?
    };
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        albert_payment_addr.to_string(),
        COSMOS_COIN,
        100,
        &port_id_gaia,
        &channel_id_gaia,
        Some(Either::Right(shielding_data)),
        Some(Duration::from_secs(10)),
    )?;

    // Check that the VP rejects the received packet
    let mut hermes = bg_hermes.foreground();
    hermes.exp_string("Attempted to mint IBC tokens twice through the MASP")?;
    let _bg_hermes = hermes.background();
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_gaia,
        &channel_id_gaia,
        &test_gaia,
    )?;
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 100)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 900)?;

    // Shielding transfer 100 samoleans from Gaia to Namada (with rewards
    // active)
    let albert_payment_addr = find_payment_address(&test, AA_PAYMENT_ADDRESS)?;
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        albert_payment_addr.to_string(),
        COSMOS_COIN,
        100,
        &port_id_gaia,
        &channel_id_gaia,
        None,
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_gaia,
        &channel_id_gaia,
        &test_gaia,
    )?;
    let ibc_denom_on_namada =
        format!("{port_id_namada}/{channel_id_namada}/{COSMOS_COIN}");
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 200)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 800)?;

    // Check the balance of the minted NAM rewards
    epoch = get_epoch(&test, &rpc).unwrap();
    let new_masp_epoch = epoch + MASP_EPOCH_MULTIPLIER;
    while epoch < new_masp_epoch {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }
    check_inflated_balance(&test, AA_VIEWING_KEY)?;

    Ok(())
}

/// IBC transfer tests:
/// 1. Transparent transfers
///   - Namada -> Gaia -> Namada
///   - Gaia -> Namada -> Gaia
/// 2. Invalid transfers
/// 3. Shielding/Unshielding transfers
///   - Gaia -> Namada -> (shielded transfer) -> Namada -> Gaia
/// 4. Shielding transfer the received token back to a shielded account on
///    Namada
/// 5. Refunding when transfer failure
///   - Ack with an error (invalid receiver)
///   - Timeout
///   - When unshielding transfer failure,
///     - Mint the IBC token for the refund
///     - Unescrow the token for the refund
/// 6. Malformed shielded actions
///   - Missing memo
///   - Wrong memo
#[test]
fn ibc_transfers() -> Result<()> {
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) =
        run_namada_cosmos(CosmosChainType::Gaia(None), update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    let hermes_dir = setup_hermes(&test, &test_gaia)?;
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let port_id_gaia = FT_PORT_ID.parse().unwrap();
    let (channel_id_namada, channel_id_gaia) = create_channel_with_hermes(
        &hermes_dir,
        &test,
        &test_gaia,
        &port_id_namada,
        &port_id_gaia,
    )?;

    // Start relaying
    let hermes = run_hermes(&hermes_dir)?;
    let bg_hermes = hermes.background();

    // 1. Transparent transfers

    // Transfer 2 APFEL from Namada to Gaia
    let gaia_receiver = find_cosmos_address(&test_gaia, COSMOS_USER)?;
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        APFEL,
        2,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;

    check_balance(&test, ALBERT, APFEL, 999_998)?;
    let token_addr = find_address(&test, APFEL)?;
    let ibc_denom_on_gaia =
        format!("{port_id_gaia}/{channel_id_gaia}/{token_addr}");
    check_cosmos_balance(
        &test_gaia,
        COSMOS_USER,
        &ibc_denom_on_gaia,
        2_000_000,
    )?;

    // Transfer 1 APFEL back from Gaia to Namada
    let namada_receiver = find_address(&test, ALBERT)?.to_string();
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        &namada_receiver,
        get_gaia_denom_hash(&ibc_denom_on_gaia),
        1_000_000,
        &port_id_gaia,
        &channel_id_gaia,
        None,
        None,
    )?;
    wait_for_packet_relay(&hermes_dir, &port_id_gaia, &channel_id_gaia, &test)?;

    // Check the balances
    check_balance(&test, ALBERT, APFEL, 999_999)?;
    check_cosmos_balance(
        &test_gaia,
        COSMOS_USER,
        &ibc_denom_on_gaia,
        1_000_000,
    )?;

    // Transfer 200 samoleans from Gaia to Namada
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        &namada_receiver,
        COSMOS_COIN,
        200,
        &port_id_gaia,
        &channel_id_gaia,
        None,
        None,
    )?;
    wait_for_packet_relay(&hermes_dir, &port_id_gaia, &channel_id_gaia, &test)?;

    // Check the token on Namada
    let ibc_denom_on_namada =
        format!("{port_id_namada}/{channel_id_namada}/{COSMOS_COIN}");
    check_balance(&test, ALBERT, &ibc_denom_on_namada, 200)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 800)?;

    // Transfer 100 samoleans back from Namada to Gaia
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        &ibc_denom_on_namada,
        100,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;

    // Check the balances
    check_balance(&test, ALBERT, &ibc_denom_on_namada, 100)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 900)?;

    // 2. Invalid transfers
    try_invalid_transfers(
        &test,
        &gaia_receiver,
        &port_id_namada,
        &channel_id_namada,
    )?;

    // 3. Shielding/Unshielding transfers

    // Shielding transfer 100 samoleans from Gaia to Namada
    let shielding_data_path = gen_ibc_shielding_data(
        &test,
        AA_PAYMENT_ADDRESS,
        COSMOS_COIN,
        100,
        &port_id_namada,
        &channel_id_namada,
        None,
    )?;
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        MASP.to_string(),
        COSMOS_COIN,
        100,
        &port_id_gaia,
        &channel_id_gaia,
        Some(Either::Left(shielding_data_path)),
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_gaia,
        &channel_id_gaia,
        &test_gaia,
    )?;
    // Check the token on Namada
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 100)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 800)?;

    // Shielded transfer 50 samoleans on Namada
    transfer_on_chain(
        &test,
        "transfer",
        A_SPENDING_KEY,
        AB_PAYMENT_ADDRESS,
        &ibc_denom_on_namada,
        50,
        ALBERT_KEY,
        &[],
    )?;
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 50)?;
    check_shielded_balance(&test, AB_VIEWING_KEY, &ibc_denom_on_namada, 50)?;

    // Unshielding transfer 10 samoleans from Namada to Gaia
    transfer(
        &test,
        B_SPENDING_KEY,
        &gaia_receiver,
        &ibc_denom_on_namada,
        10,
        Some(BERTHA_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        true,
        None,
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;
    check_shielded_balance(&test, AB_VIEWING_KEY, &ibc_denom_on_namada, 40)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 810)?;

    // 4. Shielding transfer the received token back to a shielded account on
    //    Namada
    let memo_path = gen_ibc_shielding_data(
        &test,
        AA_PAYMENT_ADDRESS,
        &ibc_denom_on_gaia,
        1,
        &port_id_namada,
        &channel_id_namada,
        None,
    )?;
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        MASP.to_string(),
        get_gaia_denom_hash(&ibc_denom_on_gaia),
        1_000_000,
        &port_id_gaia,
        &channel_id_gaia,
        Some(Either::Left(memo_path)),
        None,
    )?;
    wait_for_packet_relay(&hermes_dir, &port_id_gaia, &channel_id_gaia, &test)?;
    // Check the token on Namada
    check_shielded_balance(&test, AA_VIEWING_KEY, APFEL, 1)?;

    // 5. Refunding when transfer failure

    // Transfer to an invalid receiver address to check the refund for the
    // escrowed token
    transfer(
        &test,
        ALBERT,
        "invalid_receiver",
        APFEL,
        10,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;
    // The balance should not be changed
    check_balance(&test, ALBERT, APFEL, 999_999)?;

    // Stop Hermes for timeout test
    let mut hermes = bg_hermes.foreground();
    hermes.interrupt()?;

    // Transfer will be timed out to check the refund for the burned IBC token
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        &ibc_denom_on_namada,
        10,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        Some(Duration::new(10, 0)),
        None,
        None,
        None,
        false,
        None,
        None,
    )?;
    // wait for the timeout
    sleep(10);

    // Restart relaying
    let hermes = run_hermes(&hermes_dir)?;
    let bg_hermes = hermes.background();

    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;
    // The balance should not be changed
    check_balance(&test, ALBERT, &ibc_denom_on_namada, 100)?;

    // Unshielding transfer to Gaia's invalid account to check the refund for
    // the burned IBC token
    transfer(
        &test,
        A_SPENDING_KEY,
        "invalid_receiver",
        &ibc_denom_on_namada,
        10,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        true,
        None,
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;
    // Check the token has been refunded to the refund target
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 40)?;
    check_balance(&test, IBC_REFUND_TARGET_ALIAS, &ibc_denom_on_namada, 10)?;

    // Stop Hermes for timeout test
    let mut hermes = bg_hermes.foreground();
    hermes.interrupt()?;

    // Unshielding transfer will be timed out to check the refund for the
    // escrowed IBC token
    transfer(
        &test,
        A_SPENDING_KEY,
        &gaia_receiver,
        APFEL,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        Some(Duration::new(10, 0)),
        None,
        None,
        None,
        true,
        None,
        None,
    )?;
    // wait for the timeout
    sleep(10);

    // Restart relaying
    let hermes = run_hermes(&hermes_dir)?;
    let _bg_hermes = hermes.background();

    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;
    // Check the token has been refunded to the refund target
    check_shielded_balance(&test, AA_VIEWING_KEY, APFEL, 0)?;
    check_balance(&test, IBC_REFUND_TARGET_ALIAS, APFEL, 1)?;

    // 6. Malformed shielded actions

    // Check initial balance
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 40)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 810)?;

    // Missing memo
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        MASP.to_string(),
        COSMOS_COIN,
        100,
        &port_id_gaia,
        &channel_id_gaia,
        None,
        // MASP VP shall reject it, make it timeout
        Some(Duration::new(10, 0)),
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;
    // Check the balance didn't change
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 40)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 810)?;

    // Wrong memo (different amount)
    let shielding_data_path = gen_ibc_shielding_data(
        &test,
        AA_PAYMENT_ADDRESS,
        COSMOS_COIN,
        100,
        &port_id_namada,
        &channel_id_namada,
        None,
    )?;
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        MASP.to_string(),
        COSMOS_COIN,
        101,
        &port_id_gaia,
        &channel_id_gaia,
        Some(Either::Left(shielding_data_path)),
        // MASP VP shall reject it, make it timeout
        Some(Duration::new(10, 0)),
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_gaia,
        &channel_id_gaia,
        &test_gaia,
    )?;
    // Check the balances didn't change
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 40)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 810)?;

    Ok(())
}

#[test]
fn ibc_nft_transfers() -> Result<()> {
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, cosmwasm, test, test_cosmwasm) =
        run_namada_cosmos(CosmosChainType::CosmWasm, update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_wasmd = cosmwasm.background();

    let hermes_dir = setup_hermes(&test, &test_cosmwasm)?;
    let port_id_namada: PortId = NFT_PORT_ID.parse().unwrap();

    let (cw721_contract, ics721_contract) =
        initialize_nft_contracts(&test_cosmwasm)?;
    let minter_addr = find_cosmos_address(&test_cosmwasm, COSMOS_USER)?;
    mint_nft(&test_cosmwasm, &cw721_contract, &minter_addr, NFT_ID)?;

    let port_id_cosmwasm =
        get_cosmwasm_port_id(&test_cosmwasm, &ics721_contract)?;
    let (channel_id_namada, channel_id_cosmwasm) = create_channel_with_hermes(
        &hermes_dir,
        &test,
        &test_cosmwasm,
        &port_id_namada,
        &port_id_cosmwasm,
    )?;

    let nft = format!("{cw721_contract}/{NFT_ID}");
    let ibc_trace_on_namada =
        format!("{port_id_namada}/{channel_id_namada}/{nft}");

    // 1. Transparent transfers
    // CosmWasm to Namada
    let namada_receiver = find_address(&test, ALBERT)?.to_string();
    nft_transfer_from_cosmos(
        &test_cosmwasm,
        COSMOS_USER,
        &namada_receiver,
        NFT_ID,
        &cw721_contract,
        &ics721_contract,
        &channel_id_cosmwasm,
        None,
        None,
    )?;
    clear_packet(
        &hermes_dir,
        &port_id_cosmwasm,
        &channel_id_cosmwasm,
        &test_cosmwasm,
    )?;
    check_balance(&test, &namada_receiver, &ibc_trace_on_namada, 1)?;

    // Namada to CosmWasm
    transfer(
        &test,
        ALBERT,
        &minter_addr,
        &ibc_trace_on_namada,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;
    clear_packet(&hermes_dir, &port_id_namada, &channel_id_namada, &test)?;
    check_balance(&test, &namada_receiver, &ibc_trace_on_namada, 0)?;

    // 2. Shielding/Unshielding transfers
    // Shielding transfer
    let shielding_data_path = gen_ibc_shielding_data(
        &test,
        AA_PAYMENT_ADDRESS,
        nft,
        1,
        &port_id_namada,
        &channel_id_namada,
        None,
    )?;
    nft_transfer_from_cosmos(
        &test_cosmwasm,
        COSMOS_USER,
        MASP.to_string(),
        NFT_ID,
        &cw721_contract,
        &ics721_contract,
        &channel_id_cosmwasm,
        Some(shielding_data_path),
        None,
    )?;
    clear_packet(
        &hermes_dir,
        &port_id_cosmwasm,
        &channel_id_cosmwasm,
        &test_cosmwasm,
    )?;
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_trace_on_namada, 1)?;

    // Shielded transfer on Namada
    transfer_on_chain(
        &test,
        "transfer",
        A_SPENDING_KEY,
        AB_PAYMENT_ADDRESS,
        &ibc_trace_on_namada,
        1,
        ALBERT_KEY,
        &[],
    )?;
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_trace_on_namada, 0)?;
    check_shielded_balance(&test, AB_VIEWING_KEY, &ibc_trace_on_namada, 1)?;

    // Unshielding transfer
    transfer(
        &test,
        B_SPENDING_KEY,
        &minter_addr,
        &ibc_trace_on_namada,
        1,
        Some(BERTHA_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        true,
        None,
        None,
    )?;
    clear_packet(&hermes_dir, &port_id_namada, &channel_id_namada, &test)?;
    check_shielded_balance(&test, AB_VIEWING_KEY, &ibc_trace_on_namada, 0)?;

    Ok(())
}

#[test]
fn pgf_over_ibc() -> Result<()> {
    const PIPELINE_LEN: u64 = 5;
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(20);
            // for the trusting period of IBC client
            genesis.parameters.pos_params.pipeline_len = PIPELINE_LEN;
            genesis.parameters.gov_params.min_proposal_grace_epochs = 3;
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) =
        run_namada_cosmos(CosmosChainType::Gaia(None), update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    let hermes_dir = setup_hermes(&test, &test_gaia)?;
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let port_id_gaia: PortId = FT_PORT_ID.parse().unwrap();
    let (channel_id_namada, channel_id_gaia) = create_channel_with_hermes(
        &hermes_dir,
        &test,
        &test_gaia,
        &port_id_namada,
        &port_id_gaia,
    )?;

    // Start relaying
    let hermes = run_hermes(&hermes_dir)?;
    let _bg_hermes = hermes.background();

    // Transfer to PGF account
    transfer_on_chain(
        &test,
        "transparent-transfer",
        ALBERT,
        PGF_ADDRESS.to_string(),
        NAM,
        100,
        ALBERT_KEY,
        &[],
    )?;

    // Proposal on Namada
    // Delegate some token
    delegate_token(&test)?;
    let rpc = get_actor_rpc(&test, Who::Validator(0));
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let delegated = epoch + PIPELINE_LEN;
    while epoch < delegated {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }
    // funding proposal
    let continuous_receiver = find_cosmos_address(&test_gaia, COSMOS_RELAYER)?;
    let retro_receiver = find_cosmos_address(&test_gaia, COSMOS_USER)?;
    let start_epoch = propose_funding(
        &test,
        continuous_receiver,
        retro_receiver,
        &port_id_namada,
        &channel_id_namada,
    )?;
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    // Vote
    while epoch < start_epoch {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }
    submit_votes(&test)?;

    // wait for the grace
    let grace_epoch = start_epoch + 6u64;
    while epoch < grace_epoch {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;

    // Check balances after funding over IBC
    let token_addr = find_address(&test, NAM)?;
    let ibc_denom = format!("{port_id_gaia}/{channel_id_gaia}/{token_addr}");
    check_cosmos_balance(&test_gaia, COSMOS_RELAYER, &ibc_denom, 10_000_000)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, &ibc_denom, 5_000_000)?;

    Ok(())
}

// Test fee payment with an ibc token
//
// 1. Submit governance proposal to allow fee payment with the IBC token
// 2. Transfer some IBC tokens from gaia
// 3. Transparent transfer in Namada with ibc token gas payment
#[test]
fn fee_payment_with_ibc_token() -> Result<()> {
    const PIPELINE_LEN: u64 = 2;
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(30);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis.parameters.gov_params.min_proposal_grace_epochs = 1;
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            // Artificially increase the gas scale to allow for fee payment with
            // the limited ibc tokens available
            genesis.parameters.parameters.gas_scale = 10_000_000;
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) =
        run_namada_cosmos(CosmosChainType::Gaia(None), update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    // Proposal on Namada
    // Delegate some token
    delegate_token(&test)?;
    let rpc = get_actor_rpc(&test, Who::Validator(0));
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let delegated = epoch + PIPELINE_LEN;
    while epoch < delegated {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }
    // ibc gas token proposal on Namada
    let start_epoch = propose_gas_token(&test)?;
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    // Vote
    while epoch < start_epoch {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }
    submit_votes(&test)?;

    // Create an IBC channel while waiting the grace epoch
    let hermes_dir = setup_hermes(&test, &test_gaia)?;
    let port_id_gaia = FT_PORT_ID.parse().unwrap();
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let (channel_id_namada, channel_id_gaia) = create_channel_with_hermes(
        &hermes_dir,
        &test,
        &test_gaia,
        &port_id_namada,
        &port_id_gaia,
    )?;
    let ibc_token_on_namada =
        format!("{port_id_namada}/{channel_id_namada}/{COSMOS_COIN}");
    // Start relaying
    let hermes = run_hermes(&hermes_dir)?;
    let _bg_hermes = hermes.background();

    // wait for the grace
    let grace_epoch = start_epoch + 4u64;
    while epoch < grace_epoch {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }

    // Transfer 250 samoleans from Gaia to Namada
    let namada_receiver = find_address(&test, ALBERT_KEY)?.to_string();
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        &namada_receiver,
        COSMOS_COIN,
        250,
        &port_id_gaia,
        &channel_id_gaia,
        None,
        None,
    )?;
    wait_for_packet_relay(&hermes_dir, &port_id_gaia, &channel_id_gaia, &test)?;

    // Check the token on Namada
    check_balance(&test, ALBERT_KEY, &ibc_token_on_namada, 250)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 750)?;

    // Transparent transfer in Namada paying gas with samoleans
    transfer_on_chain(
        &test,
        "transparent-transfer",
        ALBERT,
        CHRISTEL,
        NAM,
        50,
        ALBERT_KEY,
        &["--gas-token", &ibc_token_on_namada, "--gas-limit", "250"],
    )?;
    check_balance(&test, ALBERT, NAM, 1_999_950)?;
    check_balance(&test, CHRISTEL, NAM, 2_000_050)?;
    check_balance(&test, ALBERT_KEY, &ibc_token_on_namada, 0)?;
    check_balance(&test, "validator-0", &ibc_token_on_namada, 250)?;

    Ok(())
}

/// IBC token inflation test
/// - Propose the inflation of an IBC token received from Gaia
/// - Shielding transfer of the token from Gaia
/// - Check the inflation
#[test]
fn ibc_token_inflation() -> Result<()> {
    const PIPELINE_LEN: u64 = 2;
    const MASP_EPOCH_MULTIPLIER: u64 = 2;
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(60);
            genesis.parameters.parameters.masp_epoch_multiplier =
                MASP_EPOCH_MULTIPLIER;
            genesis.parameters.gov_params.min_proposal_grace_epochs = 3;
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) =
        run_namada_cosmos(CosmosChainType::Gaia(None), update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    // Proposal on Namada
    // Delegate some token
    delegate_token(&test)?;
    let rpc = get_actor_rpc(&test, Who::Validator(0));
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let delegated = epoch + PIPELINE_LEN;
    while epoch < delegated {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }
    // inflation proposal on Namada
    let start_epoch = propose_inflation(&test)?;
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    // Vote
    while epoch < start_epoch {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }
    submit_votes(&test)?;

    // Create an IBC channel while waiting the grace epoch
    let hermes_dir = setup_hermes(&test, &test_gaia)?;
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let port_id_gaia = FT_PORT_ID.parse().unwrap();
    let (channel_id_namada, channel_id_gaia) = create_channel_with_hermes(
        &hermes_dir,
        &test,
        &test_gaia,
        &port_id_namada,
        &port_id_gaia,
    )?;
    // Start relaying
    let hermes = run_hermes(&hermes_dir)?;
    let _bg_hermes = hermes.background();

    // wait for the grace
    let grace_epoch = start_epoch + 6u64;
    while epoch < grace_epoch {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }

    // Check the target balance is zero before the inflation
    check_shielded_balance(&test, AA_VIEWING_KEY, NAM, 0)?;
    // Shielding transfer 1 samoleans from Gaia to Namada
    let shielding_data_path = gen_ibc_shielding_data(
        &test,
        AA_PAYMENT_ADDRESS,
        COSMOS_COIN,
        1,
        &port_id_namada,
        &channel_id_namada,
        None,
    )?;
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        MASP.to_string(),
        COSMOS_COIN,
        1,
        &port_id_gaia,
        &channel_id_gaia,
        Some(Either::Left(shielding_data_path)),
        None,
    )?;
    wait_for_packet_relay(&hermes_dir, &port_id_gaia, &channel_id_gaia, &test)?;

    // wait the next masp epoch to dispense the reward
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let new_epoch = epoch + MASP_EPOCH_MULTIPLIER;
    while epoch < new_epoch {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }

    // Check balances
    check_inflated_balance(&test, AA_VIEWING_KEY)?;

    Ok(())
}

#[test]
fn ibc_upgrade_client() -> Result<()> {
    const UPGRADE_HEIGHT_OFFSET: u64 = 20;

    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) =
        run_namada_cosmos(CosmosChainType::Gaia(None), update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();
    sleep(5);

    let hermes_dir = setup_hermes(&test, &test_gaia)?;
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let port_id_gaia: PortId = FT_PORT_ID.parse().unwrap();
    create_channel_with_hermes(
        &hermes_dir,
        &test,
        &test_gaia,
        &port_id_namada,
        &port_id_gaia,
    )?;

    let height = query_height(&test_gaia)?;
    let upgrade_height = height.revision_height() + UPGRADE_HEIGHT_OFFSET;

    // upgrade proposal
    propose_upgrade_client(&test, &test_gaia, upgrade_height)?;

    // vote
    vote_on_gaia(&test_gaia)?;
    wait_for_pass(&test_gaia)?;

    // wait for the halt height
    let mut height = query_height(&test_gaia)?;
    while height.revision_height() < upgrade_height {
        sleep(5);
        height = query_height(&test_gaia)?;
    }

    // Upgrade the IBC client of Gaia on Namada with Hermes
    upgrade_client(&hermes_dir, test.net.chain_id.to_string(), upgrade_height)?;

    // Check the upgraded client
    let upgraded_client_state =
        get_client_state(&test, &IBC_CLINET_ID.parse().unwrap())?;
    assert_eq!(
        upgraded_client_state.inner().chain_id.as_str(),
        UPGRADED_CHAIN_ID
    );

    Ok(())
}

/// IBC rate limit test
/// 1. Test per-epoch throuput
///   - The per-epoch throughput is 1 NAM
///   - Transfer 1 NAM in an epoch will succeed
///   - Transfer 1 NAM in the same epoch will fail
///   - Transfer 1 NAM in the next epoch will succeed
/// 2. Test the mint limit
///   - The mint limit is 1
///   - Receiving 2 samoleans from Gaia will fail
#[test]
fn ibc_rate_limit() -> Result<()> {
    const DEFAULT_RATE_LIMIT: Amount = Amount::from_u64(1_000_000);
    const DEFAULT_MINT_LIMIT: Amount = Amount::from_u64(1);

    // Mint limit 2 transfer/channel-0/nam, per-epoch throughput limit 1 NAM
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(50);
            genesis.parameters.ibc_params.default_mint_limit =
                DEFAULT_MINT_LIMIT;
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = DEFAULT_RATE_LIMIT;
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) =
        run_namada_cosmos(CosmosChainType::Gaia(None), update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    let hermes_dir = setup_hermes(&test, &test_gaia)?;
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let port_id_gaia: PortId = FT_PORT_ID.parse().unwrap();
    let (channel_id_namada, channel_id_gaia) = create_channel_with_hermes(
        &hermes_dir,
        &test,
        &test_gaia,
        &port_id_namada,
        &port_id_gaia,
    )?;

    // Start relaying
    let rpc = get_actor_rpc(&test, Who::Validator(0));
    let hermes = run_hermes(&hermes_dir)?;
    let _bg_hermes = hermes.background();

    // Query the IBC rate limits
    let ibc_denom =
        format!("{port_id_namada}/{channel_id_namada}/{COSMOS_COIN}");
    // Need the raw address because the token won't be received later in this
    // test
    let cosmos_token_addr = ibc_token(&ibc_denom).to_string();
    for (token, token_alias, mint_limit, rate_limit) in [
        (
            NAM,
            &NAM.to_lowercase(),
            DEFAULT_MINT_LIMIT.to_string_native(),
            DEFAULT_RATE_LIMIT.to_string_native(),
        ),
        (
            &ibc_denom,
            &cosmos_token_addr,
            DEFAULT_MINT_LIMIT.to_string(),
            DEFAULT_RATE_LIMIT.to_string(),
        ),
    ] {
        let tx_args =
            vec!["query-ibc-rate-limits", "--token", token, "--node", &rpc];
        let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
        client.exp_string(&format!(
            "IBC rate limits for token {}:",
            token_alias
        ))?;
        client.exp_string(&format!("Global mint limit: {}", mint_limit))?;
        client.exp_string(&format!(
            "Throughput limit: {} per epoch",
            rate_limit
        ))?;
        client.assert_success();
    }

    // wait for the next epoch
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let next_epoch = epoch.next();
    while epoch <= next_epoch {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }

    // Transfer 1 NAM from Namada to Gaia
    let gaia_receiver = find_cosmos_address(&test_gaia, COSMOS_USER)?;
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        NAM,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;

    // Transfer 1 NAM from Namada to Gaia again will fail
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        NAM,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        // expect an error of the throughput limit
        Some(
            "Transfer exceeding the per-epoch throughput limit is not allowed",
        ),
        None,
        false,
        None,
        None,
    )?;

    // wait for the next epoch
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let next_epoch = epoch.next();
    while epoch <= next_epoch {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }

    // Transfer 1 NAM from Namada to Gaia will succeed in the new epoch
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        NAM,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;

    // wait for the next epoch
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let next_epoch = epoch.next();
    while epoch <= next_epoch {
        sleep(5);
        epoch = get_epoch(&test, &rpc).unwrap();
    }

    // Transfer 2 samoleans from Gaia to Namada will succeed, but Namada can't
    // receive due to the mint limit and the packet will be timed out
    let namada_receiver = find_address(&test, ALBERT)?.to_string();
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        namada_receiver,
        COSMOS_COIN,
        2,
        &port_id_gaia,
        &channel_id_gaia,
        None,
        Some(Duration::new(10, 0)),
    )?;
    wait_for_packet_relay(&hermes_dir, &port_id_gaia, &channel_id_gaia, &test)?;

    // Check if Namada hasn't receive it
    check_balance(&test, ALBERT, cosmos_token_addr, 0)?;

    Ok(())
}

/// Unlimited IBC transfer test
#[test]
fn ibc_unlimited_channel() -> Result<()> {
    const PIPELINE_LEN: u64 = 5;
    // No IBC transfer is allowed first
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(20);
            // for the trusting period of IBC client
            genesis.parameters.pos_params.pipeline_len = PIPELINE_LEN;
            genesis.parameters.gov_params.min_proposal_grace_epochs = 3;
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) =
        run_namada_cosmos(CosmosChainType::Gaia(None), update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    let hermes_dir = setup_hermes(&test, &test_gaia)?;
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let port_id_gaia: PortId = FT_PORT_ID.parse().unwrap();
    let (channel_id_namada, channel_id_gaia) = create_channel_with_hermes(
        &hermes_dir,
        &test,
        &test_gaia,
        &port_id_namada,
        &port_id_gaia,
    )?;

    // Start relaying
    let hermes = run_hermes(&hermes_dir)?;
    let bg_hermes = hermes.background();

    let ibc_denom_on_namada =
        format!("{port_id_namada}/{channel_id_namada}/{COSMOS_COIN}");
    let ibc_token_addr = ibc_token(&ibc_denom_on_namada).to_string();
    let token_addr = find_address(&test, APFEL)?;
    let ibc_denom_on_gaia =
        format!("{port_id_gaia}/{channel_id_gaia}/{token_addr}");

    // Try to transfer from Gaia, but it should be timed out
    let namada_receiver = find_address(&test, ALBERT)?.to_string();
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        &namada_receiver,
        COSMOS_COIN,
        1,
        &port_id_gaia,
        &channel_id_gaia,
        None,
        Some(Duration::new(10, 0)),
    )?;
    wait_for_packet_relay(&hermes_dir, &port_id_gaia, &channel_id_gaia, &test)?;

    // Check if Namada hasn't received it
    check_balance(&test, ALBERT, &ibc_token_addr, 0)?;

    // Try to transfer from Namada, but it should be rejected
    let gaia_receiver = find_cosmos_address(&test_gaia, COSMOS_USER)?;
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        APFEL,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        // expect an error of the throughput limit
        Some(
            "Transfer exceeding the per-epoch throughput limit is not allowed",
        ),
        None,
        false,
        None,
        None,
    )?;

    // Proposal on Namada
    // Delegate some token
    delegate_token(&test)?;
    let rpc = get_actor_rpc(&test, Who::Validator(0));
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    let delegated = epoch + PIPELINE_LEN;
    while epoch < delegated {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }
    // proposal to set the unlimited channel
    let start_epoch = propose_unlimited_channel(&test)?;
    let mut epoch = get_epoch(&test, &rpc).unwrap();
    // Vote
    while epoch < start_epoch {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }
    submit_votes(&test)?;

    // wait for the grace
    let grace_epoch = start_epoch + 6u64;
    while epoch < grace_epoch {
        epoch = epoch_sleep(&test, &rpc, 120)?;
    }

    // Retry transfer from Gaia
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        &namada_receiver,
        COSMOS_COIN,
        1,
        &port_id_gaia,
        &channel_id_gaia,
        None,
        None,
    )?;
    wait_for_packet_relay(&hermes_dir, &port_id_gaia, &channel_id_gaia, &test)?;

    // Check if Namada has received it
    check_balance(&test, ALBERT, &ibc_denom_on_namada, 1)?;

    // Retry transfer from Namada
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        APFEL,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;

    // Check if Gaia has received it
    check_cosmos_balance(
        &test_gaia,
        COSMOS_USER,
        &ibc_denom_on_gaia,
        1_000_000,
    )?;

    // Transfer to an invalid address from Namada
    transfer(
        &test,
        ALBERT,
        "invalid_receiver",
        &ibc_denom_on_namada,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;

    // Check if the token has been refunded by an ack with an error
    check_balance(&test, ALBERT, &ibc_denom_on_namada, 1)?;

    // Stop Hermes for timeout test
    let mut hermes = bg_hermes.foreground();
    hermes.interrupt()?;

    // Timeout transfer from Namada
    transfer(
        &test,
        ALBERT,
        &gaia_receiver,
        &ibc_denom_on_namada,
        1,
        Some(ALBERT_KEY),
        &port_id_namada,
        &channel_id_namada,
        Some(Duration::new(10, 0)),
        None,
        None,
        None,
        false,
        None,
        None,
    )?;
    // wait for the timeout
    sleep(10);

    // Restart relaying
    let hermes = run_hermes(&hermes_dir)?;
    let _bg_hermes = hermes.background();

    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;

    // Check if the token has been refunded
    check_balance(&test, ALBERT, &ibc_denom_on_namada, 1)?;

    Ok(())
}

/// Create a packet forward memo and serialize it
fn packet_forward_memo(
    receiver: Signer,
    port_id: &PortId,
    channel_id: &ChannelId,
    timeout: Option<Duration>,
    next: Option<serde_json::Map<String, serde_json::Value>>,
) -> String {
    serde_json::to_string(&serde_json::Value::Object(
        packet_forward_memo_value(receiver, port_id, channel_id, timeout, next),
    ))
    .expect("Test failed")
}

fn packet_forward_memo_value(
    receiver: Signer,
    port_id: &PortId,
    channel_id: &ChannelId,
    timeout: Option<Duration>,
    next: Option<serde_json::Map<String, serde_json::Value>>,
) -> serde_json::Map<String, serde_json::Value> {
    let value =
        serde_json::to_value(&ibc_middleware_packet_forward::PacketMetadata {
            forward: ForwardMetadata {
                receiver,
                port: port_id.clone(),
                channel: channel_id.clone(),
                timeout: timeout.map(|t| {
                    ibc_middleware_packet_forward::Duration::from_dur(
                        dur::Duration::from_std(t),
                    )
                }),
                retries: Some(0),
                next,
            },
        })
        .expect("Test failed");

    if let serde_json::Value::Object(memo) = value {
        memo
    } else {
        unreachable!()
    }
}

fn shielded_recv_memo_value(
    masp_transfer_path: &Path,
    shielded_amount: Amount,
    overflow_receiver: namada_core::address::Address,
) -> serde_json::Map<String, serde_json::Value> {
    use namada_core::string_encoding::StringEncoded;
    use namada_sdk::ibc::{NamadaMemo, NamadaMemoData};

    let transfer =
        std::fs::read_to_string(masp_transfer_path).expect("Test failed");
    let tx = StringEncoded::new(
        IbcShieldingData::from_str(&transfer).expect("Test failed"),
    );
    #[allow(deprecated)]
    let data = NamadaMemoData::OsmosisSwap {
        shielding_data: tx,
        shielded_amount,
        overflow_receiver,
    };

    let value = serde_json::to_value(&NamadaMemo { namada: data })
        .expect("Test failed");

    if let serde_json::Value::Object(memo) = value {
        memo
    } else {
        unreachable!()
    }
}

/// Test the happy flows of ibc pfm
///
/// Setup: Two instances of Gaia and one
/// Namada instance.
///
/// 1. Test sending a transfer from first cosmos chain to the second via the PFM
///    module on Namada (henceforth denoted "via PFM")
/// 2. Test sending the above transfer back to first cosmos chain via PFM
/// 3. Send wrapped NAM from first cosmos chain to the second via PFM
/// 4. Reverse the transaction in the step above
#[test]
fn ibc_pfm_happy_flows() -> Result<()> {
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia_1, test, test_gaia_1) =
        run_namada_cosmos(CosmosChainType::Gaia(Some(1)), update_genesis)?;

    // set up a second cosmos network
    let test_gaia_2 = setup_cosmos(CosmosChainType::Gaia(Some(2)))?;
    let gaia_2 = run_cosmos(&test_gaia_2, false)?;
    sleep(5);

    let _bg_ledger = ledger.background();
    let _bg_gaia_1 = gaia_1.background();
    let _bg_gaia_2 = gaia_2.background();
    let hermes_gaia1_namada = setup_hermes(&test, &test_gaia_1)?;
    let hermes_namada_gaia2 = setup_hermes(&test, &test_gaia_2)?;
    sleep(5);
    // create hermes relayers for connections between both cosmos chains and
    // namada
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let port_id_gaia_1 = FT_PORT_ID.parse().unwrap();
    let port_id_gaia_2 = FT_PORT_ID.parse().unwrap();

    let (channel_id_gaia_1, channel_id_namada_1) = create_channel_with_hermes(
        &hermes_gaia1_namada,
        &test_gaia_1,
        &test,
        &port_id_namada,
        &port_id_gaia_1,
    )?;
    let (channel_id_gaia_2, channel_id_namada_2) = create_channel_with_hermes(
        &hermes_namada_gaia2,
        &test_gaia_2,
        &test,
        &port_id_namada,
        &port_id_gaia_2,
    )?;

    // Start relaying
    let hermes_1 = run_hermes(&hermes_gaia1_namada)?;
    let hermes_2 = run_hermes(&hermes_namada_gaia2)?;
    let _bg_hermes_1 = hermes_1.background();
    let _bg_hermes_2 = hermes_2.background();

    // ------------------- Step 1. -------------------

    // Bertha is our most trusted intermediary in all things
    let namada_receiver = find_address(&test, BERTHA)?.to_string();
    // this will cause the ibc packet to be forwarded to the second
    // cosmos chain.
    let pfm_memo = packet_forward_memo(
        find_cosmos_address(&test_gaia_2, COSMOS_USER)?.into(),
        &port_id_namada,
        &channel_id_namada_2,
        None,
        None,
    );
    transfer_from_cosmos(
        &test_gaia_1,
        COSMOS_USER,
        &namada_receiver,
        "samoleans",
        10,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        Some(Either::Right(pfm_memo)),
        None,
    )?;
    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_namada,
        &channel_id_namada_1,
        &test,
    )?;
    wait_for_packet_relay(
        &hermes_namada_gaia2,
        &port_id_gaia_2,
        &channel_id_gaia_2,
        &test_gaia_2,
    )?;
    // Check the samoleans have been received on the second cosmos chain
    check_cosmos_balance(
        &test_gaia_2,
        COSMOS_USER,
        format!(
            "transfer/{channel_id_gaia_2}/transfer/{channel_id_namada_1}/\
             samoleans"
        ),
        10,
    )?;

    // Check the samoleans have been sent from the first cosmos chain
    check_cosmos_balance(&test_gaia_1, COSMOS_USER, "samoleans", 1000 - 10)?;

    // ------------------- Step 2. -------------------

    // this will cause the ibc packet to be forwarded to the first
    // cosmos chain.
    let pfm_memo = packet_forward_memo(
        find_cosmos_address(&test_gaia_1, COSMOS_USER)?.into(),
        &port_id_namada,
        &channel_id_namada_1,
        None,
        None,
    );
    transfer_from_cosmos(
        &test_gaia_2,
        COSMOS_USER,
        &namada_receiver,
        format!(
            "transfer/{channel_id_gaia_2}/transfer/{channel_id_namada_1}/\
             samoleans"
        ),
        10,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        Some(Either::Right(pfm_memo)),
        None,
    )?;

    wait_for_packet_relay(
        &hermes_namada_gaia2,
        &port_id_namada,
        &channel_id_namada_2,
        &test,
    )?;
    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        &test_gaia_1,
    )?;

    // Check the samoleans have been received on the fist cosmos chain
    check_cosmos_balance(&test_gaia_1, COSMOS_USER, "samoleans", 1000)?;

    // ------------------- Step 3. -------------------
    let nam_addr = find_address(&test, NAM)?;
    // we first send some NAM to the first cosmos chain.
    let gaia_receiver = find_cosmos_address(&test_gaia_1, COSMOS_USER)?;
    transfer(
        &test,
        BERTHA,
        gaia_receiver,
        NAM,
        20,
        Some(BERTHA_KEY),
        &port_id_namada,
        &channel_id_namada_1,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;

    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        &test_gaia_1,
    )?;

    // Check the NAM have been sent to the first cosmos chain
    check_cosmos_balance(
        &test_gaia_1,
        COSMOS_USER,
        format!("transfer/{channel_id_gaia_1}/{nam_addr}"),
        20_000_000,
    )?;

    // this will cause the ibc packet to be forwarded to the second
    // cosmos chain.
    let pfm_memo = packet_forward_memo(
        find_cosmos_address(&test_gaia_2, COSMOS_USER)?.into(),
        &port_id_namada,
        &channel_id_namada_2,
        None,
        None,
    );

    transfer_from_cosmos(
        &test_gaia_1,
        COSMOS_USER,
        &namada_receiver,
        format!("transfer/{channel_id_gaia_1}/{nam_addr}"),
        10_000_000,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        Some(Either::Right(pfm_memo)),
        None,
    )?;
    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_namada,
        &channel_id_namada_1,
        &test,
    )?;
    wait_for_packet_relay(
        &hermes_namada_gaia2,
        &port_id_gaia_2,
        &channel_id_gaia_2,
        &test_gaia_2,
    )?;
    // Check the NAM have been received on the second cosmos chain
    check_cosmos_balance(
        &test_gaia_2,
        COSMOS_USER,
        format!("transfer/{channel_id_gaia_2}/{nam_addr}"),
        10_000_000,
    )?;

    // Check the NAM have been sent from the first cosmos chain
    check_cosmos_balance(
        &test_gaia_1,
        COSMOS_USER,
        format!("transfer/{channel_id_gaia_1}/{nam_addr}"),
        20_000_000 - 10_000_000,
    )?;

    // ------------------- Step 4. -------------------

    // this will cause the ibc packet to be forwarded to the first
    // cosmos chain.
    let pfm_memo = packet_forward_memo(
        find_cosmos_address(&test_gaia_1, COSMOS_USER)?.into(),
        &port_id_namada,
        &channel_id_namada_1,
        None,
        None,
    );
    transfer_from_cosmos(
        &test_gaia_2,
        COSMOS_USER,
        &namada_receiver,
        format!("transfer/{channel_id_gaia_2}/{nam_addr}"),
        10_000_000,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        Some(Either::Right(pfm_memo)),
        None,
    )?;

    wait_for_packet_relay(
        &hermes_namada_gaia2,
        &port_id_namada,
        &channel_id_namada_2,
        &test,
    )?;
    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        &test_gaia_1,
    )?;

    // Check the NAM have been received on the first cosmos chain
    check_cosmos_balance(
        &test_gaia_1,
        COSMOS_USER,
        format!("transfer/{channel_id_gaia_1}/{nam_addr}"),
        20_000_000,
    )?;

    Ok(())
}

/// Test the flows of ibc pfm where the packet cannot be
/// completed and refunds must be issued.
///
/// Setup: Two instances of Gaia and one
/// Namada instance.
///
/// 1. Test sending a transfer from first cosmos chain to the second via the PFM
///    module on Namada (henceforth denoted "via PFM"), failing on the second
///    cosmos chain due to an error.
/// 2. Same as above except that the failure occurs due to a time-out on the
///    second cosmos chain.
/// 3. Same as the first except that wrapped NAM is sent from the first cosmos
///    chain
/// 4. Same as above except that the failure occurs due to a time-out on the
///    second cosmos chain.
/// 5. Test sending assets from the second cosmos network to the first and then
///    failing to send it back to the second due to an error
/// 6. Same as above except that the failure occurs due to a time-out on the
///    second cosmos chain.
#[test]
fn ibc_pfm_unhappy_flows() -> Result<()> {
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia_1, test, test_gaia_1) =
        run_namada_cosmos(CosmosChainType::Gaia(Some(1)), update_genesis)?;

    // set up a second cosmos network
    let test_gaia_2 = setup_cosmos(CosmosChainType::Gaia(Some(2)))?;
    let gaia_2 = run_cosmos(&test_gaia_2, false)?;
    sleep(5);

    let _bg_ledger = ledger.background();
    let _bg_gaia_1 = gaia_1.background();
    let _bg_gaia_2 = gaia_2.background();
    let hermes_gaia1_namada = setup_hermes(&test, &test_gaia_1)?;
    let hermes_namada_gaia2 = setup_hermes(&test, &test_gaia_2)?;
    sleep(5);
    // create hermes relayers for connections between both cosmos chains and
    // namada
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let port_id_gaia_1 = FT_PORT_ID.parse().unwrap();
    let port_id_gaia_2 = FT_PORT_ID.parse().unwrap();

    let (channel_id_gaia_1, channel_id_namada_1) = create_channel_with_hermes(
        &hermes_gaia1_namada,
        &test_gaia_1,
        &test,
        &port_id_namada,
        &port_id_gaia_1,
    )?;
    let (channel_id_gaia_2, channel_id_namada_2) = create_channel_with_hermes(
        &hermes_namada_gaia2,
        &test_gaia_2,
        &test,
        &port_id_namada,
        &port_id_gaia_2,
    )?;

    // Start relaying
    let hermes_1 = run_hermes(&hermes_gaia1_namada)?;
    let hermes_2 = run_hermes(&hermes_namada_gaia2)?;
    let _bg_hermes_1 = hermes_1.background();
    let bg_hermes_2 = hermes_2.background();

    // ------------------- Step 1. -------------------

    // Bertha is our most trusted intermediary in all things
    let namada_receiver = find_address(&test, BERTHA)?.to_string();
    // this will cause the ibc packet to be forwarded to the second
    // cosmos chain.
    let pfm_memo = packet_forward_memo(
        // NB: since the receiver is invalid, the ICS-20
        // transfer will fail, and the first cosmos chain
        // will receive an ack error
        "Hodor".to_string().into(),
        &port_id_namada,
        &channel_id_namada_2,
        None,
        None,
    );
    transfer_from_cosmos(
        &test_gaia_1,
        COSMOS_USER,
        &namada_receiver,
        "samoleans",
        10,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        Some(Either::Right(pfm_memo)),
        None,
    )?;
    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_namada,
        &channel_id_namada_1,
        &test,
    )?;
    wait_for_packet_relay(
        &hermes_namada_gaia2,
        &port_id_gaia_2,
        &channel_id_gaia_2,
        &test_gaia_2,
    )?;

    // Check the samoleans have been refunded on the first chain
    check_cosmos_balance(&test_gaia_1, COSMOS_USER, "samoleans", 1000)?;

    // ------------------- Step 2. -------------------

    let pfm_memo = packet_forward_memo(
        find_cosmos_address(&test_gaia_1, COSMOS_USER)?.into(),
        &port_id_namada,
        &channel_id_namada_2,
        Some(Duration::new(1, 0)),
        None,
    );
    // Stop Hermes for timeout test
    let mut hermes_2 = bg_hermes_2.foreground();
    hermes_2.interrupt()?;

    transfer_from_cosmos(
        &test_gaia_1,
        COSMOS_USER,
        &namada_receiver,
        "samoleans",
        10,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        Some(Either::Right(pfm_memo)),
        None,
    )?;

    // wait for the timeout
    sleep(10);

    // Restart relaying
    let hermes_2 = run_hermes(&hermes_namada_gaia2)?;
    let bg_hermes_2 = hermes_2.background();

    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_namada,
        &channel_id_namada_1,
        &test,
    )?;
    wait_for_packet_relay(
        &hermes_namada_gaia2,
        &port_id_gaia_2,
        &channel_id_gaia_2,
        &test_gaia_2,
    )?;

    // Check the samoleans have been refunded on the first chain
    check_cosmos_balance(&test_gaia_1, COSMOS_USER, "samoleans", 1000)?;

    // ------------------- Step 3. -------------------

    let nam_addr = find_address(&test, NAM)?;
    // we first send some NAM to the first cosmos chain.
    let gaia_receiver = find_cosmos_address(&test_gaia_1, COSMOS_USER)?;
    transfer(
        &test,
        BERTHA,
        gaia_receiver,
        NAM,
        20,
        Some(BERTHA_KEY),
        &port_id_namada,
        &channel_id_namada_1,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;

    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        &test_gaia_1,
    )?;

    // Check the NAM have been sent to the first cosmos chain
    check_cosmos_balance(
        &test_gaia_1,
        COSMOS_USER,
        format!("transfer/{channel_id_gaia_1}/{nam_addr}"),
        20_000_000,
    )?;

    // this will cause the ibc packet to be forwarded to the second
    // cosmos chain.
    let pfm_memo = packet_forward_memo(
        "Hodor".to_string().into(),
        &port_id_namada,
        &channel_id_namada_2,
        None,
        None,
    );
    transfer_from_cosmos(
        &test_gaia_1,
        COSMOS_USER,
        &namada_receiver,
        format!("transfer/{channel_id_gaia_1}/{nam_addr}"),
        10_000_000,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        Some(Either::Right(pfm_memo)),
        None,
    )?;
    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_namada,
        &channel_id_namada_1,
        &test,
    )?;
    wait_for_packet_relay(
        &hermes_namada_gaia2,
        &port_id_gaia_2,
        &channel_id_gaia_2,
        &test_gaia_2,
    )?;

    // Check the NAM have been refunded on the first chain
    check_cosmos_balance(
        &test_gaia_1,
        COSMOS_USER,
        format!("transfer/{channel_id_gaia_1}/{nam_addr}"),
        20_000_000,
    )?;

    // ------------------- Step 4. -------------------

    let pfm_memo = packet_forward_memo(
        find_cosmos_address(&test_gaia_2, COSMOS_USER)?.into(),
        &port_id_namada,
        &channel_id_namada_2,
        Some(Duration::new(1, 0)),
        None,
    );
    // Stop Hermes for timeout test
    let mut hermes_2 = bg_hermes_2.foreground();
    hermes_2.interrupt()?;

    transfer_from_cosmos(
        &test_gaia_1,
        COSMOS_USER,
        &namada_receiver,
        format!("transfer/{channel_id_gaia_1}/{nam_addr}"),
        10_000_000,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        Some(Either::Right(pfm_memo)),
        None,
    )?;

    // wait for the timeout
    sleep(10);

    // Restart relaying
    let hermes_2 = run_hermes(&hermes_namada_gaia2)?;
    let bg_hermes_2 = hermes_2.background();

    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_namada,
        &channel_id_namada_1,
        &test,
    )?;
    wait_for_packet_relay(
        &hermes_namada_gaia2,
        &port_id_gaia_2,
        &channel_id_gaia_2,
        &test_gaia_2,
    )?;

    // Check the NAM have been refunded on the first chain
    check_cosmos_balance(
        &test_gaia_1,
        COSMOS_USER,
        format!("transfer/{channel_id_gaia_1}/{nam_addr}"),
        20_000_000,
    )?;

    // ------------------- Step 5. -------------------

    // we first send some samoleans to the first cosmos chain from the second.
    let pfm_memo = packet_forward_memo(
        find_cosmos_address(&test_gaia_1, COSMOS_USER)?.into(),
        &port_id_namada,
        &channel_id_namada_1,
        None,
        None,
    );
    transfer_from_cosmos(
        &test_gaia_2,
        COSMOS_USER,
        &namada_receiver,
        "samoleans",
        10,
        &port_id_gaia_2,
        &channel_id_gaia_2,
        Some(Either::Right(pfm_memo)),
        None,
    )?;

    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        &test_gaia_1,
    )?;

    // Check the non-native samoleans have been sent to the first cosmos chain
    check_cosmos_balance(
        &test_gaia_1,
        COSMOS_USER,
        format!(
            "transfer/{channel_id_gaia_1}/transfer/{channel_id_namada_2}/\
             samoleans"
        ),
        10,
    )?;

    // this will cause the ibc packet to be forwarded to the second
    // cosmos chain.
    let pfm_memo = packet_forward_memo(
        "Hodor".to_string().into(),
        &port_id_namada,
        &channel_id_namada_2,
        None,
        None,
    );
    transfer_from_cosmos(
        &test_gaia_1,
        COSMOS_USER,
        &namada_receiver,
        format!(
            "transfer/{channel_id_gaia_1}/transfer/{channel_id_namada_2}/\
             samoleans"
        ),
        10,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        Some(Either::Right(pfm_memo)),
        None,
    )?;
    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_namada,
        &channel_id_namada_1,
        &test,
    )?;
    wait_for_packet_relay(
        &hermes_namada_gaia2,
        &port_id_gaia_2,
        &channel_id_gaia_2,
        &test_gaia_2,
    )?;

    // Check the non-native samoleans have been refunded on the first chain
    check_cosmos_balance(
        &test_gaia_1,
        COSMOS_USER,
        format!(
            "transfer/{channel_id_gaia_1}/transfer/{channel_id_namada_2}/\
             samoleans"
        ),
        10,
    )?;

    // ------------------- Step 6. -------------------
    let pfm_memo = packet_forward_memo(
        find_cosmos_address(&test_gaia_2, COSMOS_USER)?.into(),
        &port_id_namada,
        &channel_id_namada_2,
        Some(Duration::new(1, 0)),
        None,
    );
    // Stop Hermes for timeout test
    let mut hermes_2 = bg_hermes_2.foreground();
    hermes_2.interrupt()?;

    transfer_from_cosmos(
        &test_gaia_1,
        COSMOS_USER,
        &namada_receiver,
        format!(
            "transfer/{channel_id_gaia_1}/transfer/{channel_id_namada_2}/\
             samoleans"
        ),
        10,
        &port_id_gaia_1,
        &channel_id_gaia_1,
        Some(Either::Right(pfm_memo)),
        None,
    )?;

    // wait for the timeout
    sleep(10);

    // Restart relaying
    let hermes_2 = run_hermes(&hermes_namada_gaia2)?;
    let _bg_hermes_2 = hermes_2.background();

    wait_for_packet_relay(
        &hermes_gaia1_namada,
        &port_id_namada,
        &channel_id_namada_1,
        &test,
    )?;
    wait_for_packet_relay(
        &hermes_namada_gaia2,
        &port_id_gaia_2,
        &channel_id_gaia_2,
        &test_gaia_2,
    )?;

    // Check the non-native samoleans have been refunded on the first chain
    check_cosmos_balance(
        &test_gaia_1,
        COSMOS_USER,
        format!(
            "transfer/{channel_id_gaia_1}/transfer/{channel_id_namada_2}/\
             samoleans"
        ),
        10,
    )?;
    Ok(())
}

/// Test that we are able to use the shielded-receive
/// middleware to shield funds specified in the memo
/// message.
#[test]
fn ibc_shielded_recv_middleware_happy_flow() -> Result<()> {
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) =
        run_namada_cosmos(CosmosChainType::Gaia(None), update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();
    sleep(5);

    let hermes_dir = setup_hermes(&test, &test_gaia)?;
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let port_id_gaia = FT_PORT_ID.parse().unwrap();
    let (channel_id_namada, channel_id_gaia) = create_channel_with_hermes(
        &hermes_dir,
        &test,
        &test_gaia,
        &port_id_namada,
        &port_id_gaia,
    )?;

    // Start relaying
    let hermes = run_hermes(&hermes_dir)?;
    let _bg_hermes = hermes.background();

    // 1. Shield 20 NAM to AA_PAYMENT_ADDRESS
    transfer_on_chain(
        &test,
        "shield",
        ALBERT,
        AA_PAYMENT_ADDRESS,
        NAM,
        20,
        ALBERT_KEY,
        &[],
    )?;
    check_shielded_balance(&test, AA_VIEWING_KEY, NAM, 20)?;

    // 2. Unshield from A_SPENDING_KEY to B_SPENDING_KEY,
    // using the packet forward and shielded receive
    // middlewares
    for iter in 1..=2u64 {
        let nam_addr = find_address(&test, NAM)?;
        let overflow_addr = "tnam1qrqzqa0l0rzzrlr20n487l6n865t8ndv6uhseulq";
        let ibc_denom_on_gaia =
            format!("transfer/{channel_id_gaia}/{nam_addr}");
        let memo_path = gen_ibc_shielding_data(
            &test,
            AB_PAYMENT_ADDRESS,
            &ibc_denom_on_gaia,
            8,
            &port_id_namada,
            &channel_id_namada,
            None,
        )?;
        let masp_receiver = match iter {
            // Test addresses encoded using `bech32m`...
            1 => MASP.encode(),
            // ...as well as addresses encoded using `bech32`
            2 => {
                let bech32 = "tnam1pcqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqh8f9c4";
                let addr: namada_core::address::Address =
                    bech32.parse().unwrap();
                assert_eq!(addr, MASP);
                bech32.to_owned()
            }
            _ => unreachable!("there are only 2 iters"),
        };
        let memo = packet_forward_memo(
            masp_receiver.into(),
            &PortId::transfer(),
            &channel_id_namada,
            None,
            Some(shielded_recv_memo_value(
                &memo_path,
                Amount::native_whole(8),
                overflow_addr.parse().unwrap(),
            )),
        );
        transfer(
            &test,
            A_SPENDING_KEY,
            "PacketForwardMiddleware",
            NAM,
            10,
            Some(ALBERT_KEY),
            &PortId::transfer(),
            &channel_id_namada,
            None,
            None,
            None,
            Some(&memo),
            true,
            None,
            None,
        )?;
        wait_for_packet_relay(
            &hermes_dir,
            &port_id_gaia,
            &channel_id_gaia,
            &test,
        )?;

        // Check the token on Namada
        check_shielded_balance(&test, AA_VIEWING_KEY, NAM, 20 - iter * 10)?;
        check_shielded_balance(&test, AB_VIEWING_KEY, NAM, 8 * iter)?;
        check_balance(&test, overflow_addr, NAM, 2 * iter)?;
    }

    Ok(())
}

/// Test that if the received amount underflows the minimum
/// amount, we error out and refund assets.
#[test]
fn ibc_shielded_recv_middleware_unhappy_flow() -> Result<()> {
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) =
        run_namada_cosmos(CosmosChainType::Gaia(None), update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();
    sleep(5);

    let hermes_dir = setup_hermes(&test, &test_gaia)?;
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let port_id_gaia = FT_PORT_ID.parse().unwrap();
    let (channel_id_namada, channel_id_gaia) = create_channel_with_hermes(
        &hermes_dir,
        &test,
        &test_gaia,
        &port_id_namada,
        &port_id_gaia,
    )?;

    // Start relaying
    let hermes = run_hermes(&hermes_dir)?;
    let _bg_hermes = hermes.background();

    let nam_addr = find_address(&test, NAM)?;
    let overflow_addr = "tnam1qrqzqa0l0rzzrlr20n487l6n865t8ndv6uhseulq";
    let ibc_denom_on_gaia = format!("transfer/{channel_id_gaia}/{nam_addr}");
    check_balance(&test, ALBERT, NAM, 2_000_000)?;

    let memo_path = gen_ibc_shielding_data(
        &test,
        AB_PAYMENT_ADDRESS,
        &ibc_denom_on_gaia,
        8,
        &port_id_namada,
        &channel_id_namada,
        None,
    )?;
    let memo = packet_forward_memo(
        MASP.to_string().into(),
        &PortId::transfer(),
        &channel_id_namada,
        None,
        Some(shielded_recv_memo_value(
            &memo_path,
            Amount::native_whole(8),
            overflow_addr.parse().unwrap(),
        )),
    );
    transfer(
        &test,
        ALBERT,
        "PacketForwardMiddleware",
        NAM,
        7,
        Some(ALBERT_KEY),
        &PortId::transfer(),
        &channel_id_namada,
        None,
        None,
        None,
        Some(&memo),
        false,
        None,
        None,
    )?;
    wait_for_packet_relay(&hermes_dir, &port_id_gaia, &channel_id_gaia, &test)?;

    // Check the token on Namada
    check_balance(&test, ALBERT, NAM, 2_000_000)?;
    check_shielded_balance(&test, AB_VIEWING_KEY, NAM, 0)?;
    check_balance(&test, overflow_addr, NAM, 0)?;

    Ok(())
}

fn run_namada_cosmos(
    chain_type: CosmosChainType,
    mut update_genesis: impl FnMut(
        templates::All<templates::Unvalidated>,
        &Path,
    ) -> templates::All<templates::Unvalidated>,
) -> Result<(NamadaCmd, NamadaCmd, Test, Test)> {
    let test = setup::network(&mut update_genesis, None)?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    let ledger = start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?;

    let (cosmos, test_cosmos) = setup_and_boot_cosmos(chain_type)?;

    Ok((ledger, cosmos, test, test_cosmos))
}

fn setup_and_boot_cosmos(
    chain_type: CosmosChainType,
) -> Result<(NamadaCmd, Test)> {
    let test_cosmos = setup_cosmos(chain_type)?;
    let cosmos = run_cosmos(&test_cosmos, true)?;
    Ok((cosmos, test_cosmos))
}

fn create_channel_with_hermes(
    hermes_dir: &TestDir,
    test_a: &Test,
    test_b: &Test,
    port_id_a: &PortId,
    port_id_b: &PortId,
) -> Result<(ChannelId, ChannelId)> {
    let channel_version = if port_id_a.as_str() == NFT_PORT_ID
        || port_id_b.as_str() == NFT_PORT_ID
    {
        NFT_CHANNEL_VERSION
    } else {
        FT_CHANNEL_VERSION
    };

    let args = [
        "create",
        "channel",
        "--a-chain",
        test_a.net.chain_id.as_str(),
        "--b-chain",
        test_b.net.chain_id.as_str(),
        "--a-port",
        port_id_a.as_str(),
        "--b-port",
        port_id_b.as_str(),
        "--channel-version",
        channel_version,
        "--new-client-connection",
        "--yes",
    ];

    let mut hermes = run_hermes_cmd(hermes_dir, args, Some(240))?;
    let (channel_id_a, channel_id_b) =
        get_channel_ids_from_hermes_output(&mut hermes)?;
    hermes.assert_success();

    Ok((channel_id_a, channel_id_b))
}

fn get_channel_ids_from_hermes_output(
    hermes: &mut NamadaCmd,
) -> Result<(ChannelId, ChannelId)> {
    let (_, matched) =
        hermes.exp_regex("channel handshake already finished .*")?;

    let regex = regex::Regex::new(r"channel-[0-9]+").unwrap();
    let mut iter = regex.find_iter(&matched);
    let channel_id_a = iter.next().unwrap().as_str().parse().unwrap();
    let channel_id_b = iter.next().unwrap().as_str().parse().unwrap();

    Ok((channel_id_a, channel_id_b))
}

fn run_hermes(hermes_dir: &TestDir) -> Result<NamadaCmd> {
    let args = ["start"];
    let mut hermes = run_hermes_cmd(hermes_dir, args, Some(40))?;
    hermes.exp_string("Hermes has started")?;
    Ok(hermes)
}

fn run_cosmos(test: &Test, kill: bool) -> Result<NamadaCmd> {
    let chain_type = CosmosChainType::chain_type(test.net.chain_id.as_str())?;
    let cmd_path = chain_type.command_path();
    // cosmos process is sometimes left lingering causing subsequent runs to
    // fail
    if kill {
        std::process::Command::new("pkill")
            .args(["-9", cmd_path])
            .output()
            .unwrap();
    }
    let port_arg = format!("0.0.0.0:{}", chain_type.get_grpc_port_number());
    let args = ["start", "--pruning", "nothing", "--grpc.address", &port_arg];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    cosmos.exp_string("finalized block")?;
    Ok(cosmos)
}

fn wait_for_packet_relay(
    hermes_dir: &TestDir,
    port_id: &PortId,
    channel_id: &ChannelId,
    test: &Test,
) -> Result<()> {
    let args = [
        "--json",
        "query",
        "packet",
        "pending",
        "--chain",
        test.net.chain_id.as_str(),
        "--port",
        port_id.as_str(),
        "--channel",
        channel_id.as_str(),
    ];
    for _ in 0..10 {
        sleep(10);
        let mut hermes = run_hermes_cmd(hermes_dir, args, Some(40))?;
        // Check no pending packet
        if hermes
            .exp_string(
                "\"dst\":{\"unreceived_acks\":[],\"unreceived_packets\":[]},",
            )
            .is_ok()
            && hermes
                .exp_string(
                    "\"src\":{\"unreceived_acks\":[],\"unreceived_packets\":\
                     []}",
                )
                .is_ok()
        {
            return Ok(());
        }
    }
    Err(eyre!("Pending packet is still left"))
}

fn clear_packet(
    hermes_dir: &TestDir,
    port_id: &PortId,
    channel_id: &ChannelId,
    test: &Test,
) -> Result<()> {
    let args = [
        "clear",
        "packets",
        "--chain",
        test.net.chain_id.as_str(),
        "--port",
        port_id.as_str(),
        "--channel",
        channel_id.as_str(),
    ];
    let mut hermes = run_hermes_cmd(hermes_dir, args, Some(40))?;
    hermes.assert_success();

    Ok(())
}

fn upgrade_client(
    hermes_dir: &TestDir,
    host_chain_id: impl AsRef<str>,
    upgrade_height: u64,
) -> Result<()> {
    let args = [
        "upgrade",
        "client",
        "--host-chain",
        host_chain_id.as_ref(),
        "--client",
        "07-tendermint-0",
        "--upgrade-height",
        &upgrade_height.to_string(),
    ];
    let mut hermes = run_hermes_cmd(hermes_dir, args, Some(120))?;
    hermes.exp_string("upgraded-chain")?;
    hermes.assert_success();

    Ok(())
}

fn get_client_state(
    test: &Test,
    client_id: &ClientId,
) -> Result<TmClientState> {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tendermint_url = Url::from_str(&rpc).unwrap();
    let client = HttpClient::new(tendermint_url).unwrap();
    let key = client_state_key(client_id);

    let result = test
        .async_runtime()
        .block_on(query_storage_value_bytes(&client, &key, None, false));
    let cs = match result {
        (Some(v), _) => Any::decode(&v[..])
            .map_err(|e| eyre!("Decoding the client state failed: {}", e))?,
        _ => {
            return Err(eyre!(
                "The client state doesn't exist: client ID {}",
                client_id
            ));
        }
    };

    let client_state = TmClientState::try_from(cs)
        .expect("the state should be a TmClientState");

    Ok(client_state)
}

fn try_invalid_transfers(
    test: &Test,
    receiver: impl AsRef<str>,
    port_id: &PortId,
    channel_id: &ChannelId,
) -> Result<()> {
    // invalid port
    let nam_addr = find_address(test, NAM)?;
    transfer(
        test,
        ALBERT,
        receiver.as_ref(),
        NAM,
        10,
        Some(ALBERT_KEY),
        &"port".parse().unwrap(),
        channel_id,
        None,
        None,
        // the IBC denom can't be parsed when using an invalid port
        Some(&format!("Invalid IBC denom: {nam_addr}")),
        None,
        false,
        None,
        None,
    )?;

    // invalid channel
    transfer(
        test,
        ALBERT,
        receiver.as_ref(),
        NAM,
        10,
        Some(ALBERT_KEY),
        port_id,
        &"channel-42".parse().unwrap(),
        None,
        None,
        Some("No channel end: port transfer, channel channel-42"),
        None,
        false,
        None,
        None,
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn transfer_on_chain(
    test: &Test,
    kind: impl AsRef<str>,
    sender: impl AsRef<str>,
    receiver: impl AsRef<str>,
    token: impl AsRef<str>,
    amount: u64,
    signer: impl AsRef<str>,
    extra_args: &[&str],
) -> Result<()> {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let amount = amount.to_string();
    let mut tx_args = apply_use_device(vec![
        kind.as_ref(),
        "--source",
        sender.as_ref(),
        "--target",
        receiver.as_ref(),
        "--token",
        token.as_ref(),
        "--amount",
        &amount,
        "--signing-keys",
        signer.as_ref(),
        "--node",
        &rpc,
    ]);
    tx_args.extend_from_slice(extra_args);
    let mut client = run!(test, Bin::Client, tx_args, Some(240))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn transfer(
    test: &Test,
    sender: impl AsRef<str>,
    receiver: impl AsRef<str>,
    token: impl AsRef<str>,
    amount: u64,
    signer: Option<&str>,
    port_id: &PortId,
    channel_id: &ChannelId,
    timeout_sec: Option<Duration>,
    shielding_data_path: Option<PathBuf>,
    expected_err: Option<&str>,
    ibc_memo: Option<&str>,
    gen_refund_target: bool,
    frontend_sus_fee: Option<&str>,
    gas_token: Option<&str>,
) -> Result<u32> {
    let rpc = get_actor_rpc(test, Who::Validator(0));

    let channel_id = channel_id.to_string();
    let port_id = port_id.to_string();
    let amount = amount.to_string();
    let mut tx_args = apply_use_device(vec![
        "ibc-transfer",
        "--source",
        sender.as_ref(),
        "--receiver",
        receiver.as_ref(),
        "--token",
        token.as_ref(),
        "--amount",
        &amount,
        "--channel-id",
        &channel_id,
        "--port-id",
        &port_id,
        "--gas-limit",
        "70000",
        "--node",
        &rpc,
    ]);

    if let Some(token) = gas_token {
        tx_args.extend_from_slice(&["--gas-token", token]);
    }

    if let Some(ibc_memo) = ibc_memo {
        tx_args.extend_from_slice(&["--ibc-memo", ibc_memo]);
    }

    if let Some(signer) = signer {
        tx_args.extend_from_slice(&["--signing-keys", signer]);
    }

    let timeout = timeout_sec.unwrap_or_default().as_secs().to_string();
    if timeout_sec.is_some() {
        tx_args.push("--timeout-sec-offset");
        tx_args.push(&timeout);
    }

    let memo = shielding_data_path
        .as_ref()
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_default();
    if shielding_data_path.is_some() {
        tx_args.push("--ibc-shielding-data");
        tx_args.push(&memo);
    }

    if gen_refund_target {
        let mut cmd = run!(
            test,
            Bin::Wallet,
            &[
                "gen",
                "--alias",
                IBC_REFUND_TARGET_ALIAS,
                "--alias-force",
                "--unsafe-dont-encrypt"
            ],
            Some(20),
        )?;
        cmd.assert_success();
        tx_args.push("--refund-target");
        tx_args.push(IBC_REFUND_TARGET_ALIAS);
    }

    if let Some(target) = frontend_sus_fee {
        tx_args.push("--test-frontend-sus-fee");
        tx_args.push(target);
    }

    let mut client = run!(test, Bin::Client, tx_args, Some(300))?;
    match expected_err {
        Some(err) => {
            client.exp_string(err)?;
            Ok(0)
        }
        None => {
            let height = check_tx_height(test, &mut client)?;
            client.exp_string(TX_APPLIED_SUCCESS)?;

            Ok(height)
        }
    }
}

fn delegate_token(test: &Test) -> Result<()> {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tx_args = apply_use_device(vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "900",
        "--node",
        &rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(())
}

fn propose_funding(
    test: &Test,
    continuous_receiver: impl AsRef<str>,
    retro_receiver: impl AsRef<str>,
    src_port_id: &PortId,
    src_channel_id: &ChannelId,
) -> Result<Epoch> {
    let pgf_funding = PgfFunding {
        continuous: vec![PGFTarget::Ibc(PGFIbcTarget {
            amount: Amount::native_whole(10),
            target: continuous_receiver.as_ref().to_string(),
            port_id: src_port_id.clone(),
            channel_id: src_channel_id.clone(),
        })],
        retro: vec![PGFTarget::Ibc(PGFIbcTarget {
            amount: Amount::native_whole(5),
            target: retro_receiver.as_ref().to_string(),
            port_id: src_port_id.clone(),
            channel_id: src_channel_id.clone(),
        })],
    };

    let albert = find_address(test, ALBERT)?;
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let epoch = get_epoch(test, &rpc)?;
    let start_epoch = (epoch.0 + 3) / 3 * 3;
    let proposal_json = serde_json::json!({
        "proposal": {
            "content": {
                "title": "PGF",
                "authors": "test@test.com",
                "discussions-to": "www.github.com/anoma/aip/1",
                "created": "2022-03-10T08:54:37Z",
                "license": "MIT",
                "abstract": "PGF proposal",
                "motivation": "PGF proposal test",
                "details": "PGF proposal",
                "requires": "2"
            },
            "author": albert,
            "voting_start_epoch": start_epoch,
            "voting_end_epoch": start_epoch + 3_u64,
            "activation_epoch": start_epoch + 6_u64,
        },
        "data": pgf_funding,
    });
    let proposal_json_path = test.test_dir.path().join("proposal.json");
    write_json_file(proposal_json_path.as_path(), proposal_json);

    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--pgf-funding",
        "--data-path",
        proposal_json_path.to_str().unwrap(),
        "--node",
        &rpc,
    ]);
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(start_epoch.into())
}

fn propose_inflation(test: &Test) -> Result<Epoch> {
    let albert = find_address(test, ALBERT)?;
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let epoch = get_epoch(test, &rpc)?;
    let start_epoch = (epoch.0 + 3) / 3 * 3;
    let proposal_json = serde_json::json!({
        "proposal": {
            "content": {
                "title": "IBC token inflation",
                "authors": "test@test.com",
                "discussions-to": "www.github.com/anoma/aip/1",
                "created": "2022-03-10T08:54:37Z",
                "license": "MIT",
                "abstract": "IBC token inflation",
                "motivation": "IBC token inflation",
                "details": "IBC token inflation",
                "requires": "2"
            },
            "author": albert,
            "voting_start_epoch": start_epoch,
            "voting_end_epoch": start_epoch + 3_u64,
            "activation_epoch": start_epoch + 6_u64,
        },
        "data": TestWasms::TxProposalIbcTokenInflation.read_bytes()
    });

    let proposal_json_path = test.test_dir.path().join("proposal.json");
    write_json_file(proposal_json_path.as_path(), proposal_json);

    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--data-path",
        proposal_json_path.to_str().unwrap(),
        "--gas-limit",
        "3000000",
        "--node",
        &rpc,
    ]);
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(100))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(start_epoch.into())
}

fn propose_upgrade_client(
    test_namada: &Test,
    test_gaia: &Test,
    upgrade_height: u64,
) -> Result<()> {
    let client_state =
        get_client_state(test_namada, &IBC_CLINET_ID.parse().unwrap())?;
    let mut client_state = client_state.inner().clone();
    client_state.chain_id = UPGRADED_CHAIN_ID.parse().unwrap();
    client_state.latest_height = Height::new(0, upgrade_height + 1).unwrap();
    client_state.zero_custom_fields();
    let any_client_state = Any::from(client_state.clone());

    let proposer = get_cosmos_gov_address(test_gaia)?;

    let proposal_json = serde_json::json!({
          "messages": [
            {
              "@type": "/ibc.core.client.v1.MsgIBCSoftwareUpgrade",
              "plan": {
                "name": "Upgrade",
                "height": upgrade_height,
                "info": ""
              },
              "upgraded_client_state": {
                  "@type": any_client_state.type_url,
                  "chain_id": client_state.chain_id().to_string(),
                  "unbonding_period": format!("{}s", client_state.unbonding_period.as_secs()),
                  "latest_height": client_state.latest_height,
                  "proof_specs": client_state.proof_specs,
                  "upgrade_path": client_state.upgrade_path,
              },
              "signer": proposer
            }
          ],
          "metadata": "ipfs://CID",
          "deposit": "10000000stake",
          "title": "Upgrade",
          "summary": "Upgrade Gaia chain",
          "expedited": false
    });
    let proposal_json_path = test_gaia.test_dir.path().join("proposal.json");
    write_json_file(proposal_json_path.as_path(), proposal_json);

    let rpc = format!("tcp://{}", get_cosmos_rpc_address(test_gaia));
    let submit_proposal_args = vec![
        "tx",
        "gov",
        "submit-proposal",
        proposal_json_path.to_str().unwrap(),
        "--from",
        COSMOS_USER,
        "--gas",
        "250000",
        "--gas-prices",
        "0.001stake",
        "--node",
        &rpc,
        "--keyring-backend",
        "test",
        "--chain-id",
        test_gaia.net.chain_id.as_str(),
        "--yes",
    ];
    let mut gaia = run_cosmos_cmd(test_gaia, submit_proposal_args, Some(40))?;
    gaia.assert_success();
    Ok(())
}

fn propose_gas_token(test: &Test) -> Result<Epoch> {
    let albert = find_address(test, ALBERT)?;
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let epoch = get_epoch(test, &rpc)?;
    let start_epoch = (epoch.0 + 3) / 3 * 3;
    let proposal_json = serde_json::json!({
        "proposal": {
            "content": {
                "title": "IBC token gas",
                "authors": "test@test.com",
                "discussions-to": "www.github.com/anoma/aip/1",
                "created": "2022-03-10T08:54:37Z",
                "license": "MIT",
                "abstract": "IBC token gas",
                "motivation": "IBC token gas",
                "details": "IBC token gas",
                "requires": "2"
            },
            "author": albert,
            "voting_start_epoch": start_epoch,
            "voting_end_epoch": start_epoch + 3_u64,
            "activation_epoch": start_epoch + 4_u64,
        },
        "data": TestWasms::TxProposalTokenGas.read_bytes()
    });

    let proposal_json_path = test.test_dir.path().join("proposal.json");
    write_json_file(proposal_json_path.as_path(), proposal_json);

    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--data-path",
        proposal_json_path.to_str().unwrap(),
        "--gas-limit",
        "2000000",
        "--node",
        &rpc,
    ]);
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(100))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(start_epoch.into())
}

fn propose_unlimited_channel(test: &Test) -> Result<Epoch> {
    let albert = find_address(test, ALBERT)?;
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let epoch = get_epoch(test, &rpc)?;
    let start_epoch = (epoch.0 + 3) / 3 * 3;
    let proposal_json = serde_json::json!({
        "proposal": {
            "content": {
                "title": "IBC unlimited channel",
                "authors": "test@test.com",
                "discussions-to": "www.github.com/anoma/aip/1",
                "created": "2022-03-10T08:54:37Z",
                "license": "MIT",
                "abstract": "IBC unlimited channel",
                "motivation": "IBC unlimited channel",
                "details": "IBC unlimited channel",
                "requires": "2"
            },
            "author": albert,
            "voting_start_epoch": start_epoch,
            "voting_end_epoch": start_epoch + 3_u64,
            "activation_epoch": start_epoch + 6_u64,
        },
        "data": TestWasms::TxProposalIbcUnlimitedChannel.read_bytes()
    });

    let proposal_json_path = test.test_dir.path().join("proposal.json");
    write_json_file(proposal_json_path.as_path(), proposal_json);

    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--data-path",
        proposal_json_path.to_str().unwrap(),
        "--gas-limit",
        "3000000",
        "--node",
        &rpc,
    ]);
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(100))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(start_epoch.into())
}

fn wait_for_pass(test: &Test) -> Result<()> {
    let rpc = format!("tcp://{}", get_cosmos_rpc_address(test));
    let args = ["query", "gov", "proposal", "1", "--node", &rpc];
    for _ in 0..10 {
        sleep(5);
        let mut gaia = run_cosmos_cmd(test, args, Some(40))?;
        let (_, matched) = gaia.exp_regex("status: .*")?;
        if matched.split(' ').next_back().unwrap() == "PROPOSAL_STATUS_PASSED" {
            break;
        }
    }
    Ok(())
}

fn vote_on_gaia(test: &Test) -> Result<()> {
    let rpc = format!("tcp://{}", get_cosmos_rpc_address(test));
    let args = vec![
        "tx",
        "gov",
        "vote",
        "1",
        "yes",
        "--from",
        COSMOS_VALIDATOR,
        "--gas-prices",
        "0.001stake",
        "--node",
        &rpc,
        "--keyring-backend",
        "test",
        "--chain-id",
        test.net.chain_id.as_str(),
        "--yes",
    ];
    let mut gaia = run_cosmos_cmd(test, args, Some(40))?;
    gaia.assert_success();
    Ok(())
}

fn submit_votes(test: &Test) -> Result<()> {
    let rpc = get_actor_rpc(test, Who::Validator(0));

    let submit_proposal_vote = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        "validator-0-validator",
        "--node",
        &rpc,
    ];
    let mut client = run_as!(
        test,
        Who::Validator(0),
        Bin::Client,
        submit_proposal_vote,
        Some(40)
    )?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // Send different yay vote from delegator to check majority on 1/3
    let submit_proposal_vote_delagator = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        BERTHA,
        "--node",
        &rpc,
    ]);
    let mut client =
        run!(test, Bin::Client, submit_proposal_vote_delagator, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn transfer_from_cosmos(
    test: &Test,
    sender: impl AsRef<str>,
    receiver: impl AsRef<str>,
    token: impl AsRef<str>,
    amount: u64,
    port_id: &PortId,
    channel_id: &ChannelId,
    memo: Option<Either<PathBuf, String>>,
    timeout_sec: Option<Duration>,
) -> Result<()> {
    let port_id = port_id.to_string();
    let channel_id = channel_id.to_string();
    let amount = format!("{}{}", amount, token.as_ref());
    let chain_type =
        CosmosChainType::chain_type(test.net.chain_id.as_str()).unwrap();
    let rpc = format!("tcp://127.0.0.1:{}", chain_type.get_rpc_port_number());
    // If the receiver is a payment address we want to mask it to the more
    // general MASP internal address to improve on privacy
    let receiver = match PaymentAddress::from_str(receiver.as_ref()) {
        // assume we have IBC shielding data if the memo is read from the
        // filesystem. in this we override the receiver, setting it to
        // the MASP transparent addr.
        Ok(_) if memo.as_ref().is_some_and(|memo| memo.is_left()) => {
            MASP.to_string()
        }
        // otherwise, we take whatever receiver is specified in the call args.
        _ => receiver.as_ref().to_string(),
    };
    let mut args = vec![
        "tx",
        "ibc-transfer",
        "transfer",
        &port_id,
        &channel_id,
        receiver.as_ref(),
        &amount,
        "--from",
        sender.as_ref(),
        "--gas-prices",
        "0.001stake",
        "--gas",
        "250000",
        "--node",
        &rpc,
        "--keyring-backend",
        "test",
        "--chain-id",
        test.net.chain_id.as_str(),
        "--yes",
    ];

    let is_memo = memo.is_some();
    let memo = memo
        .map(|m| match m {
            Either::Left(path) => {
                std::fs::read_to_string(path).expect("Reading memo file failed")
            }
            Either::Right(memo) => memo,
        })
        .unwrap_or_default();
    if is_memo {
        args.push("--memo");
        args.push(&memo);
    }

    let timeout_nanosec;
    if let Some(d) = timeout_sec {
        timeout_nanosec = d.as_nanos().to_string();

        args.push("--packet-timeout-timestamp");
        args.push(&timeout_nanosec);
        args.push("--packet-timeout-height");
        args.push("0-0");
    }

    let mut gaia = run_cosmos_cmd(test, args, Some(40))?;
    gaia.assert_success();
    Ok(())
}

fn check_tx_height(test: &Test, client: &mut NamadaCmd) -> Result<u32> {
    let (_unread, matched) = client.exp_regex(r"height .*")?;
    // Expecting e.g. "height 1337."
    let height_str = matched
        .trim()
        .split_once(' ')
        .unwrap()
        .1
        .split_once('.')
        .unwrap()
        .0;
    let height: u32 = height_str.parse().unwrap();

    // wait for the next block to use the app hash
    while height as u64 + 1 > query_height(test)?.revision_height() {
        sleep(1);
    }

    Ok(height)
}

fn query_height(test: &Test) -> Result<Height> {
    let rpc = match CosmosChainType::chain_type(test.net.chain_id.as_str()) {
        Ok(_) => format!("http://{}", get_cosmos_rpc_address(test)),
        Err(_) => get_actor_rpc(test, Who::Validator(0)),
    };
    let tendermint_url = Url::from_str(&rpc).unwrap();
    let client = HttpClient::new(tendermint_url).unwrap();

    let status = test
        .async_runtime()
        .block_on(client.status())
        .map_err(|e| eyre!("Getting the status failed: {}", e))?;

    Ok(Height::new(0, status.sync_info.latest_block_height.into()).unwrap())
}

fn check_balance(
    test: &Test,
    owner: impl AsRef<str>,
    token: impl AsRef<str>,
    expected_amount: u64,
) -> Result<()> {
    let rpc = get_actor_rpc(test, Who::Validator(0));

    let query_args = vec![
        "balance",
        "--owner",
        owner.as_ref(),
        "--token",
        token.as_ref(),
        "--node",
        &rpc,
    ];
    let mut client = run!(test, Bin::Client, query_args, Some(40))?;
    let expected =
        format!("{}: {expected_amount}", token.as_ref().to_lowercase());
    client.exp_string(&expected)?;
    client.assert_success();
    Ok(())
}

fn check_shielded_balance(
    test: &Test,
    owner: impl AsRef<str>,
    token: impl AsRef<str>,
    expected_amount: u64,
) -> Result<()> {
    let rpc = get_actor_rpc(test, Who::Validator(0));

    shielded_sync(test, owner.as_ref())?;

    let query_args = vec![
        "balance",
        "--owner",
        owner.as_ref(),
        "--token",
        token.as_ref(),
        "--node",
        &rpc,
    ];
    let mut client = run!(test, Bin::Client, query_args, Some(40))?;
    let expected =
        format!("{}: {expected_amount}", token.as_ref().to_lowercase());
    client.exp_string(&expected)?;
    client.assert_success();
    Ok(())
}

fn get_gaia_denom_hash(denom: impl AsRef<str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(denom.as_ref());
    let hash = hasher.finalize();
    format!("ibc/{hash:X}")
}

fn check_cosmos_balance(
    test: &Test,
    owner: impl AsRef<str>,
    denom: impl AsRef<str>,
    expected_amount: u64,
) -> Result<()> {
    let addr = find_cosmos_address(test, owner)?;
    let chain_type =
        CosmosChainType::chain_type(test.net.chain_id.as_str()).unwrap();
    let rpc = format!("tcp://127.0.0.1:{}", chain_type.get_rpc_port_number());
    let args = ["query", "bank", "balances", &addr, "--node", &rpc];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    cosmos.exp_string(&format!("amount: \"{expected_amount}\""))?;
    let expected_denom = if denom.as_ref().contains('/') {
        get_gaia_denom_hash(denom)
    } else {
        denom.as_ref().to_string()
    };
    cosmos.exp_string(&format!("denom: {expected_denom}"))?;
    Ok(())
}

fn check_inflated_balance(
    test: &Test,
    viewing_key: impl AsRef<str>,
) -> Result<()> {
    shielded_sync(test, viewing_key.as_ref())?;

    let rpc = get_actor_rpc(test, Who::Validator(0));
    let query_args = vec![
        "balance",
        "--owner",
        viewing_key.as_ref(),
        "--token",
        NAM,
        "--node",
        &rpc,
    ];
    let mut client = run!(test, Bin::Client, query_args, Some(100))?;
    let (_, matched) = client.exp_regex("nam: .*")?;
    let regex = regex::Regex::new(r"[0-9]+").unwrap();
    let mut iter = regex.find_iter(&matched);
    let balance: f64 = iter.next().unwrap().as_str().parse().unwrap();
    assert!(balance > 0.0);
    client.assert_success();

    Ok(())
}

fn shielded_sync(test: &Test, viewing_key: impl AsRef<str>) -> Result<()> {
    let rpc = get_actor_rpc(test, Who::Validator(0));
    let tx_args = vec![
        "shielded-sync",
        "--viewing-keys",
        viewing_key.as_ref(),
        "--node",
        &rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(120))?;
    client.assert_success();
    Ok(())
}

/// Get IBC shielding data for the following IBC transfer from the destination
/// chain
fn gen_ibc_shielding_data(
    dst_test: &Test,
    receiver: impl AsRef<str>,
    token: impl AsRef<str>,
    amount: u64,
    port_id: &PortId,
    channel_id: &ChannelId,
    frontend_sus_fee: Option<&str>,
) -> Result<PathBuf> {
    let rpc = get_actor_rpc(dst_test, Who::Validator(0));
    let output_folder = dst_test.test_dir.path().to_string_lossy();

    let amount = amount.to_string();
    let mut args = vec![
        "ibc-gen-shielding",
        "--output-folder-path",
        &output_folder,
        "--target",
        receiver.as_ref(),
        "--token",
        token.as_ref(),
        "--amount",
        &amount,
        "--port-id",
        port_id.as_ref(),
        "--channel-id",
        channel_id.as_ref(),
        "--node",
        &rpc,
    ];
    if let Some(target) = frontend_sus_fee {
        args.push("--test-frontend-sus-fee-ibc");
        args.push(target.as_ref());
    }

    let mut client = run!(dst_test, Bin::Client, args, Some(120))?;
    let (_unread, matched) =
        client.exp_regex("Output IBC shielding transfer .*")?;
    let file_path = matched
        .trim()
        .split(' ')
        .next_back()
        .expect("invalid output");
    client.assert_success();

    Ok(PathBuf::from_str(file_path).expect("invalid file path"))
}

fn initialize_nft_contracts(test: &Test) -> Result<(String, String)> {
    let contract_dir = match std::env::var(ENV_VAR_COSMWASM_CONTRACT_DIR) {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => working_dir(),
    };
    let rpc = format!("tcp://{}", get_cosmos_rpc_address(test));
    let minter_addr = find_cosmos_address(test, COSMOS_USER)?;
    sleep(5);
    // Store cw721 contract
    let cw721_wasm_path =
        contract_dir.join(CW721_WASM).to_string_lossy().to_string();
    let args = vec![
        "tx",
        "wasm",
        "store",
        &cw721_wasm_path,
        "--from",
        COSMOS_USER,
        "--gas",
        "auto",
        "--gas-prices",
        "0.001stake",
        "--gas-adjustment",
        "1.3",
        "--node",
        &rpc,
        "--keyring-backend",
        "test",
        "--chain-id",
        test.net.chain_id.as_str(),
        "--yes",
    ];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    cosmos.exp_eof()?;
    sleep(5);

    // Store ics721 contract
    let ics721_wasm_path =
        contract_dir.join(ICS721_WASM).to_string_lossy().to_string();
    let args = vec![
        "tx",
        "wasm",
        "store",
        &ics721_wasm_path,
        "--from",
        COSMOS_USER,
        "--gas",
        "auto",
        "--gas-prices",
        "0.001stake",
        "--gas-adjustment",
        "1.3",
        "--node",
        &rpc,
        "--keyring-backend",
        "test",
        "--chain-id",
        test.net.chain_id.as_str(),
        "--yes",
    ];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    cosmos.exp_eof()?;
    sleep(1);

    // Instantiate cw721 contract
    let json = serde_json::json!({
        "name": "test_nft",
        "symbol": "NFT",
        "minter": minter_addr
    })
    .to_string();
    let args = vec![
        "tx",
        "wasm",
        "instantiate",
        "1",
        &json,
        "--from",
        COSMOS_USER,
        "--label",
        "cw721",
        "--no-admin",
        "--gas",
        "auto",
        "--gas-prices",
        "0.001stake",
        "--gas-adjustment",
        "1.3",
        "--node",
        &rpc,
        "--keyring-backend",
        "test",
        "--chain-id",
        test.net.chain_id.as_str(),
        "--yes",
    ];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    cosmos.exp_eof()?;
    sleep(1);

    // Instantiate ics721 contract
    let json = serde_json::json!({
        "cw721_base_code_id": 1,
    })
    .to_string();
    let args = vec![
        "tx",
        "wasm",
        "instantiate",
        "2",
        &json,
        "--from",
        COSMOS_USER,
        "--label",
        "ics721",
        "--no-admin",
        "--gas",
        "auto",
        "--gas-prices",
        "0.001stake",
        "--gas-adjustment",
        "1.3",
        "--node",
        &rpc,
        "--keyring-backend",
        "test",
        "--chain-id",
        test.net.chain_id.as_str(),
        "--yes",
    ];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    cosmos.exp_eof()?;

    sleep(1);

    // Check the CW721 contract
    let args = vec![
        "query",
        "wasm",
        "list-contract-by-code",
        "1",
        "--node",
        &rpc,
    ];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    let (_unread, matched) = cosmos.exp_regex("wasm.*")?;
    let cw721_contract = matched.trim().to_string();
    cosmos.exp_eof()?;

    // Check the ICS721 contract
    let args = vec![
        "query",
        "wasm",
        "list-contract-by-code",
        "2",
        "--node",
        &rpc,
    ];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    let (_unread, matched) = cosmos.exp_regex("wasm.*")?;
    let ics721_contract = matched.trim().to_string();
    cosmos.exp_eof()?;

    Ok((cw721_contract, ics721_contract))
}

fn get_cosmwasm_port_id(test: &Test, ics721_contract: &str) -> Result<PortId> {
    let rpc = format!("tcp://{}", get_cosmos_rpc_address(test));
    // Get the port ID
    let args =
        vec!["query", "wasm", "contract", ics721_contract, "--node", &rpc];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    let (_unread, matched) = cosmos.exp_regex("ibc_port_id: wasm.*")?;
    let port_id = matched
        .trim()
        .split(' ')
        .next_back()
        .expect("invalid output");
    cosmos.exp_eof()?;
    port_id
        .parse()
        .map_err(|e| eyre!("Parsing the port ID failed: {}", e))
}

fn mint_nft(
    test: &Test,
    cw721_contract: &str,
    minter_addr: &str,
    token_id: &str,
) -> Result<()> {
    let rpc = format!("tcp://{}", get_cosmos_rpc_address(test));

    // Mint an NFT
    let json = serde_json::json!({
        "mint": {
            "token_id": token_id,
            "owner": minter_addr
        }
    })
    .to_string();
    let args = vec![
        "tx",
        "wasm",
        "execute",
        cw721_contract,
        &json,
        "--from",
        COSMOS_USER,
        "--gas",
        "auto",
        "--gas-prices",
        "0.001stake",
        "--gas-adjustment",
        "1.3",
        "--node",
        &rpc,
        "--keyring-backend",
        "test",
        "--chain-id",
        test.net.chain_id.as_str(),
        "--yes",
    ];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    cosmos.exp_eof()?;
    sleep(1);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn nft_transfer_from_cosmos(
    test: &Test,
    sender: impl AsRef<str>,
    receiver: impl AsRef<str>,
    token_id: impl AsRef<str>,
    cw721_contract: impl AsRef<str>,
    ics721_contract: impl AsRef<str>,
    channel_id: &ChannelId,
    memo_path: Option<PathBuf>,
    timeout_height: Option<u64>,
) -> Result<()> {
    let channel_id = channel_id.to_string();
    let timeout_height = timeout_height.unwrap_or(100000);
    let rpc = format!("tcp://{}", get_cosmos_rpc_address(test));

    let receiver = match PaymentAddress::from_str(receiver.as_ref()) {
        Ok(_) => MASP.to_string(),
        Err(_) => receiver.as_ref().to_string(),
    };

    let memo = memo_path
        .as_ref()
        .map(|path| {
            std::fs::read_to_string(path).expect("Reading memo file failed")
        })
        .unwrap_or_default();

    let msg = serde_json::json!({
        "receiver": receiver,
        "channel_id": channel_id,
        "timeout": {
            "block": {
                "revision": 0,
                "height": timeout_height
                }},
        "memo": memo
    })
    .to_string();
    let encoded_msg = BASE64_STANDARD.encode(&msg);
    let json = serde_json::json!({
        "send_nft": {
            "contract": ics721_contract.as_ref(),
            "token_id": token_id.as_ref(),
            "msg": encoded_msg
        },
    })
    .to_string();

    let args = vec![
        "tx",
        "wasm",
        "execute",
        cw721_contract.as_ref(),
        &json,
        "--from",
        sender.as_ref(),
        "--gas",
        "auto",
        "--gas-prices",
        "0.001stake",
        "--gas-adjustment",
        "1.3",
        "--node",
        &rpc,
        "--keyring-backend",
        "test",
        "--chain-id",
        test.net.chain_id.as_str(),
        "--yes",
    ];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    cosmos.exp_eof()?;
    sleep(1);

    Ok(())
}

// Verify that MASP frontend fees can be paid also when doing IBC transactions,
// specifically an unshielding originating from Namada and a shielding tx
// originating from a foreign chain
#[test]
fn frontend_sus_fee() -> Result<()> {
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (ledger, gaia, test, test_gaia) =
        run_namada_cosmos(CosmosChainType::Gaia(None), update_genesis)?;
    let _bg_ledger = ledger.background();
    let _bg_gaia = gaia.background();

    let hermes_dir = setup_hermes(&test, &test_gaia)?;
    let port_id_namada = FT_PORT_ID.parse().unwrap();
    let port_id_gaia = FT_PORT_ID.parse().unwrap();
    let (channel_id_namada, channel_id_gaia) = create_channel_with_hermes(
        &hermes_dir,
        &test,
        &test_gaia,
        &port_id_namada,
        &port_id_gaia,
    )?;

    // Start relaying
    let hermes = run_hermes(&hermes_dir)?;
    let _bg_hermes = hermes.background();

    // Shielding transfer 100 samoleans from Gaia to Namada (this command will
    // actually add another extra token in the output as the frontend sus fee)
    let shielding_data_path = gen_ibc_shielding_data(
        &test,
        AA_PAYMENT_ADDRESS,
        COSMOS_COIN,
        100,
        &port_id_namada,
        &channel_id_namada,
        Some(AC_PAYMENT_ADDRESS),
    )?;
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        MASP.to_string(),
        COSMOS_COIN,
        // 10 extra tokens for the frontend sus fee
        110,
        &port_id_gaia,
        &channel_id_gaia,
        Some(Either::Left(shielding_data_path)),
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_gaia,
        &channel_id_gaia,
        &test_gaia,
    )?;
    // Check the token on Namada
    let ibc_denom_on_namada =
        format!("{port_id_namada}/{channel_id_namada}/{COSMOS_COIN}");
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 100)?;
    check_shielded_balance(&test, AC_VIEWING_KEY, &ibc_denom_on_namada, 10)?;
    check_balance(&test, ESTER, &ibc_denom_on_namada, 0)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 890)?;

    // Unshielding transfer 10 samoleans from Namada to Gaia with transparent
    // frontend fee
    let gaia_receiver = find_cosmos_address(&test_gaia, COSMOS_USER)?;
    transfer(
        &test,
        A_SPENDING_KEY,
        &gaia_receiver,
        &ibc_denom_on_namada,
        // An extra token will be added to this amount as a frontend masp fee
        10,
        Some(BERTHA_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        true,
        Some(ESTER),
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 89)?;
    check_shielded_balance(&test, AC_VIEWING_KEY, &ibc_denom_on_namada, 10)?;
    check_balance(&test, ESTER, &ibc_denom_on_namada, 1)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 900)?;

    // Unshielding transfer 10 samoleans from Namada to Gaia with shielded
    // frontend fee
    transfer(
        &test,
        A_SPENDING_KEY,
        &gaia_receiver,
        &ibc_denom_on_namada,
        // An extra token will be added to this amount as a frontend masp fee
        10,
        Some(BERTHA_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        true,
        Some(AC_PAYMENT_ADDRESS),
        None,
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 78)?;
    check_shielded_balance(&test, AC_VIEWING_KEY, &ibc_denom_on_namada, 11)?;
    check_balance(&test, ESTER, &ibc_denom_on_namada, 1)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 910)?;

    // Shield 50 nams
    transfer_on_chain(
        &test,
        "shield",
        ALBERT_KEY,
        AA_PAYMENT_ADDRESS,
        NAM,
        50,
        ALBERT_KEY,
        &[],
    )?;
    check_shielded_balance(&test, AA_VIEWING_KEY, NAM, 50)?;
    check_balance(&test, ESTER, NAM, 1000000)?;
    // Unshielding transfer 10 samoleans from Namada to Gaia with transparent
    // frontend fee. Also pay gas fees via the masp and verify that this amount
    // is not subject to frontend masp fees (no recursive fees)
    transfer(
        &test,
        A_SPENDING_KEY,
        &gaia_receiver,
        &ibc_denom_on_namada,
        // An extra token will be added to this amount as a frontend masp fee
        10,
        Some(BERTHA_KEY),
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        None,
        None,
        true,
        Some(ESTER),
        Some(NAM),
    )?;
    wait_for_packet_relay(
        &hermes_dir,
        &port_id_namada,
        &channel_id_namada,
        &test,
    )?;
    check_shielded_balance(&test, AA_VIEWING_KEY, &ibc_denom_on_namada, 67)?;
    check_shielded_balance(&test, AC_VIEWING_KEY, &ibc_denom_on_namada, 11)?;
    check_shielded_balance(&test, AC_VIEWING_KEY, NAM, 0)?;
    check_balance(&test, ESTER, &ibc_denom_on_namada, 2)?;
    check_balance(&test, ESTER, NAM, 1000000)?;
    check_cosmos_balance(&test_gaia, COSMOS_USER, COSMOS_COIN, 920)?;

    // Unshielding transfer more samoleans than available with transparent
    // frontend fee and shielded gas fees. Verify that client checks prevent
    // this
    transfer(
        &test,
        A_SPENDING_KEY,
        &gaia_receiver,
        &ibc_denom_on_namada,
        // An extra 10 tokens will be added to this amount as a frontend masp
        // fee
        100,
        None,
        &port_id_namada,
        &channel_id_namada,
        None,
        None,
        Some(
            "Failed to construct MASP transaction shielded parts: \
             Insufficient funds: 43 \
             tnam1p5n6vw2v870lnjwu7h0l4humkhlf5d78ay693qmv missing",
        ),
        None,
        true,
        Some(ESTER),
        None,
    )?;

    Ok(())
}

/// Basic Osmosis test that checks if the chain has been set up correctly.
#[test]
fn osmosis_basic() -> Result<()> {
    let (osmosis, test_osmosis) =
        setup_and_boot_cosmos(CosmosChainType::Osmosis)?;

    let _bg_osmosis = osmosis.background();
    sleep(5);

    check_cosmos_balance(&test_osmosis, COSMOS_USER, COSMOS_COIN, 1_000)?;

    Ok(())
}

#[test]
fn osmosis_xcs() -> Result<()> {
    // ==========================================================
    // This test requires quite a long setup. Jump to the next
    // occurrence of `SETUP DONE` in order to skip all of this
    // nonsense.
    // ==========================================================

    // Set up a big Cosmos party
    let update_genesis =
        |mut genesis: templates::All<templates::Unvalidated>, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1800);
            genesis.parameters.ibc_params.default_mint_limit =
                Amount::max_signed();
            genesis
                .parameters
                .ibc_params
                .default_per_epoch_throughput_limit = Amount::max_signed();
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        };
    let (namada, gaia, test_namada, test_gaia) =
        run_namada_cosmos(CosmosChainType::Gaia(Some(1)), update_genesis)?;

    let (osmosis, test_osmosis) =
        setup_and_boot_cosmos(CosmosChainType::Osmosis)?;

    let _bg_osmosis = osmosis.background();
    let _bg_ledger = namada.background();
    let _bg_gaia = gaia.background();

    // The MC of the party
    let osmosis_jones = find_cosmos_address(&test_osmosis, COSMOS_USER)?;

    // Everyone shall take a 5 second nap, partied too hard
    // (big up MC Osmosis Jones)
    sleep(5);

    // Create hermes relayers with the following config:
    // =================================================
    //
    // namada -- osmosis -- gaia
    //  \_____________________/

    // Set up initial hermes configs
    let hermes_gaia_namada = setup_hermes(&test_gaia, &test_namada)
        .wrap_err("failed to join thread hermes_gaia_namada")?;
    let hermes_gaia_osmosis = setup_hermes(&test_gaia, &test_osmosis)
        .wrap_err("failed to join thread hermes_gaia_osmosis")?;
    let hermes_namada_osmosis = setup_hermes(&test_namada, &test_osmosis)
        .wrap_err("failed to join thread hermes_namada_osmosis")?;
    std::thread::sleep(Duration::from_secs(5));
    // Set up channels
    let (channel_from_gaia_to_namada, channel_from_namada_to_gaia) =
        create_channel_with_hermes(
            &hermes_gaia_namada,
            &test_gaia,
            &test_namada,
            &PortId::transfer(),
            &PortId::transfer(),
        )?;

    // Osmosis currently uses an older version of the Cosmos SDK
    // that will error if txs are sent too close together. See
    // https://github.com/cosmos/cosmos-sdk/issues/13621
    std::thread::sleep(Duration::from_secs(5));
    let (channel_from_gaia_to_osmosis, channel_from_osmosis_to_gaia) =
        create_channel_with_hermes(
            &hermes_gaia_osmosis,
            &test_gaia,
            &test_osmosis,
            &PortId::transfer(),
            &PortId::transfer(),
        )?;

    let (channel_from_namada_to_osmosis, channel_from_osmosis_to_namada) =
        create_channel_with_hermes(
            &hermes_namada_osmosis,
            &test_namada,
            &test_osmosis,
            &PortId::transfer(),
            &PortId::transfer(),
        )?;

    // Start relaying
    let hermes_1 = run_hermes(&hermes_gaia_namada)?;
    let hermes_2 = run_hermes(&hermes_gaia_osmosis)?;
    let hermes_3 = run_hermes(&hermes_namada_osmosis)?;
    let _bg_hermes_1 = hermes_1.background();
    let _bg_hermes_2 = hermes_2.background();
    let _bg_hermes_3 = hermes_3.background();

    // Transfer assets to Osmosis, in order to create pools

    // Transfer NAM from Namada
    transfer(
        &test_namada,
        ALBERT,
        &osmosis_jones,
        NAM,
        500,
        Some(ALBERT_KEY),
        &PortId::transfer(),
        &channel_from_namada_to_osmosis,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
    )?;
    // Transfer Samoleans from Gaia
    transfer_from_cosmos(
        &test_gaia,
        COSMOS_USER,
        &osmosis_jones,
        COSMOS_COIN,
        500,
        &PortId::transfer(),
        &channel_from_gaia_to_osmosis,
        None,
        None,
    )?;

    // Related to the issue above. In general, it takes osmosis some time
    // to update state. Thus calls to it should be spaced out accordingly.
    std::thread::sleep(Duration::from_secs(5));

    // Check balance of transferred assets on Osmosis
    let nam_token_addr = find_address(&test_namada, NAM)?;
    check_cosmos_balance(
        &test_osmosis,
        COSMOS_USER,
        format!("transfer/{channel_from_osmosis_to_namada}/{nam_token_addr}"),
        500_000_000,
    )?;

    check_cosmos_balance(
        &test_osmosis,
        COSMOS_USER,
        format!("transfer/{channel_from_osmosis_to_gaia}/{COSMOS_COIN}"),
        500,
    )?;

    // Set up contracts on Osmosis
    let rpc_osmosis =
        format!("tcp://{}", get_cosmos_rpc_address(&test_osmosis));

    const CROSSCHAIN_REGISTRY_CODE_ID: &str = "1";
    const SWAPROUTER_CODE_ID: &str = "2";
    const CROSSCHAIN_SWAPS_CODE_ID: &str = "3";

    const CROSSCHAIN_REGISTRY_SHA256_HASH: &str =
        "3a90b1dc50ba2c63c40298b1645f3a56431d895857cab75f97c5b8266f64e4fa";
    const SWAPROUTER_CODE_SHA256_HASH: &str =
        "bd579ce619c16d50118f4a14f98fa1b2724ce11c7de2f8c532a9b2587bd98bbd";
    const CROSSCHAIN_SWAPS_SHA256_HASH: &str =
        "87c3c3422e876f117efc5cda6ae30b4c897054148d424815daeb2b3038ec6cfd";

    // Deploy each contract's wasm bytecode
    for wasm in [
        "crosschain_registry.wasm",
        "swaprouter.wasm",
        "crosschain_swaps.wasm",
    ] {
        let wasm_path = osmosis_fixtures_dir().join("wasm_bytecode").join(wasm);
        let wasm_path_str = wasm_path.to_string_lossy();
        std::thread::sleep(Duration::from_secs(5));
        let args = cosmos_common_args(
            "5000000",
            None,
            test_osmosis.net.chain_id.as_str(),
            &rpc_osmosis,
            vec!["tx", "wasm", "store", &wasm_path_str],
        );
        let mut osmosis_cmd = run_cosmos_cmd(&test_osmosis, args, Some(40))?;
        osmosis_cmd.assert_success();
    }

    // Instantiate `crosschain_registry.wasm`
    let json = format!(r#"{{"owner":"{osmosis_jones}"}}"#);
    std::thread::sleep(Duration::from_secs(5));
    let crosschain_registry_addr = build_contract_addr(
        &test_osmosis,
        CROSSCHAIN_REGISTRY_SHA256_HASH,
        &osmosis_jones,
    )?;
    std::thread::sleep(Duration::from_secs(5));
    let args = cosmos_common_args(
        "2500000",
        Some("0.01stake"),
        test_osmosis.net.chain_id.as_str(),
        &rpc_osmosis,
        vec![
            "tx",
            "wasm",
            "instantiate2",
            CROSSCHAIN_REGISTRY_CODE_ID,
            &json,
            CONTRACT_SALT_HEX,
            "--label",
            "CrosschainRegistry",
            "--no-admin",
            "--hex",
        ],
    );
    let mut osmosis_cmd = run_cosmos_cmd(&test_osmosis, args, Some(40))?;
    osmosis_cmd.assert_success();

    // Instantiate `swaprouter.wasm`
    let json = format!(r#"{{"owner":"{osmosis_jones}"}}"#);
    std::thread::sleep(Duration::from_secs(10));
    let swaprouter_addr = build_contract_addr(
        &test_osmosis,
        SWAPROUTER_CODE_SHA256_HASH,
        &osmosis_jones,
    )?;
    std::thread::sleep(Duration::from_secs(10));
    let args = cosmos_common_args(
        "250000",
        Some("0.01stake"),
        test_osmosis.net.chain_id.as_str(),
        &rpc_osmosis,
        vec![
            "tx",
            "wasm",
            "instantiate2",
            SWAPROUTER_CODE_ID,
            &json,
            CONTRACT_SALT_HEX,
            "--label",
            "SwapRouter",
            "--no-admin",
            "--hex",
        ],
    );
    let mut osmosis_cmd = run_cosmos_cmd(&test_osmosis, args, Some(40))?;
    osmosis_cmd.assert_success();

    // Instantiate `swaprouter.wasm`
    std::thread::sleep(Duration::from_secs(10));
    let json = format!(
        r#"{{"governor":"{osmosis_jones}","swap_contract":"{swaprouter_addr}","registry_contract":"{crosschain_registry_addr}"}}"#
    );
    let crosschain_swaps_addr = build_contract_addr(
        &test_osmosis,
        CROSSCHAIN_SWAPS_SHA256_HASH,
        &osmosis_jones,
    )?;
    std::thread::sleep(Duration::from_secs(10));
    let args = cosmos_common_args(
        "500000",
        Some("0.01stake"),
        test_osmosis.net.chain_id.as_str(),
        &rpc_osmosis,
        vec![
            "tx",
            "wasm",
            "instantiate2",
            CROSSCHAIN_SWAPS_CODE_ID,
            &json,
            CONTRACT_SALT_HEX,
            "--label",
            "CrosschainSwaps",
            "--no-admin",
            "--hex",
        ],
    );

    let mut osmosis_cmd = run_cosmos_cmd(&test_osmosis, args, Some(40))?;
    osmosis_cmd.assert_success();
    std::thread::sleep(Duration::from_secs(5));

    // Modify the bech32 prefixes
    let msg = serde_json::to_string(&json!({
    "modify_bech32_prefixes": {
        "operations": [
            {
                "operation": "set",
                "chain_name": "namada",
                "prefix": "znam"
            },
            {
                "operation": "set",
                "chain_name": "osmosis",
                "prefix": "osmo"
            },
            {
                "operation": "set",
                "chain_name": "gaia",
                "prefix": "cosmo"
            }
        ]
    }}))
    .unwrap();

    let args = cosmos_common_args(
        "5000000",
        Some("0.01stake"),
        test_osmosis.net.chain_id.as_str(),
        &rpc_osmosis,
        vec!["tx", "wasm", "execute", &crosschain_registry_addr, &msg],
    );
    let mut osmosis_cmd = run_cosmos_cmd(&test_osmosis, args, Some(40))?;
    osmosis_cmd.assert_success();
    std::thread::sleep(Duration::from_secs(5));

    // Modify the channel chain links
    let msg = serde_json::to_string(&json!({
    "modify_chain_channel_links": {
        "operations": [
            {
                "operation": "set",
                "source_chain": "namada",
                "destination_chain": "osmosis",
                "channel_id": channel_from_namada_to_osmosis
            },
            {
                "operation": "set",
                "source_chain": "osmosis",
                "destination_chain": "namada",
                "channel_id": channel_from_osmosis_to_namada
            },
            {
                "operation": "set",
                "source_chain": "namada",
                "destination_chain": "gaia",
                "channel_id": channel_from_namada_to_gaia
            },
            {
                "operation": "set",
                "source_chain": "gaia",
                "destination_chain": "namada",
                "channel_id": channel_from_gaia_to_namada
            },
            {
                "operation": "set",
                "source_chain": "gaia",
                "destination_chain": "osmosis",
                "channel_id": channel_from_gaia_to_osmosis
            },
            {
                "operation": "set",
                "source_chain": "osmosis",
                "destination_chain": "gaia",
                "channel_id": channel_from_osmosis_to_gaia
            }
        ]
    }}))
    .unwrap();
    let args = cosmos_common_args(
        "5000000",
        Some("0.01stake"),
        test_osmosis.net.chain_id.as_str(),
        &rpc_osmosis,
        vec!["tx", "wasm", "execute", &crosschain_registry_addr, &msg],
    );
    let mut osmosis_cmd = run_cosmos_cmd(&test_osmosis, args, Some(40))?;
    osmosis_cmd.assert_success();
    std::thread::sleep(Duration::from_secs(5));

    // Enable PFM on gaia and namada
    for (chain, token) in [
        (
            "namada",
            get_gaia_denom_hash(format!(
                "transfer/{channel_from_osmosis_to_namada}/{nam_token_addr}"
            )),
        ),
        (
            "gaia",
            get_gaia_denom_hash(format!(
                "transfer/{channel_from_osmosis_to_gaia}/{COSMOS_COIN}"
            )),
        ),
    ] {
        let msg = format!(r#"{{"propose_pfm": {{"chain": "{chain}"}}}}"#);
        let amount = format!("1{token}");
        let args = cosmos_common_args(
            "5000000",
            Some("0.01stake"),
            test_osmosis.net.chain_id.as_str(),
            &rpc_osmosis,
            vec![
                "tx",
                "wasm",
                "execute",
                &crosschain_registry_addr,
                &msg,
                "--amount",
                &amount,
            ],
        );
        let mut osmosis_cmd = run_cosmos_cmd(&test_osmosis, args, Some(40))?;
        osmosis_cmd.assert_success();
        std::thread::sleep(Duration::from_secs(5));
    }

    wait_for_packet_relay(
        &hermes_namada_osmosis,
        &PortId::transfer(),
        &channel_from_osmosis_to_namada,
        &test_osmosis,
    )?;
    wait_for_packet_relay(
        &hermes_gaia_osmosis,
        &PortId::transfer(),
        &channel_from_osmosis_to_gaia,
        &test_osmosis,
    )?;

    // Check that the PFM was successfully enabled
    // on the contract
    for chain in ["namada", "gaia"] {
        let msg =
            format!(r#"{{"has_packet_forwarding": {{"chain": "{chain}"}}}}"#);
        let args = vec![
            "query",
            "wasm",
            "contract-state",
            "smart",
            &crosschain_registry_addr,
            &msg,
        ];
        let mut osmosis_cmd = run_cosmos_cmd(&test_osmosis, args, Some(40))?;
        osmosis_cmd.exp_string("data: true")?;
    }

    // Create a LP on Osmosis with Samoleans and Nam
    create_pool(
        &test_osmosis,
        &rpc_osmosis,
        &[
            (
                &get_gaia_denom_hash(format!(
                    "transfer/{channel_from_osmosis_to_namada}/\
                     {nam_token_addr}"
                )),
                100,
            ),
            (
                &get_gaia_denom_hash(format!(
                    "transfer/{channel_from_osmosis_to_gaia}/{COSMOS_COIN}"
                )),
                100,
            ),
        ],
    )?;
    run_cosmos_cmd(
        &test_osmosis,
        ["query", "poolmanager", "pool", "1"],
        Some(40),
    )?
    .assert_success();

    // Shield some nam
    let rpc_namada = get_actor_rpc(&test_namada, Who::Validator(0));

    run!(
        &test_namada,
        Bin::Client,
        [
            "shield",
            "--source",
            BERTHA,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--amount",
            "0.000056",
            "--token",
            NAM,
            "--node",
            &rpc_namada,
        ],
        Some(40)
    )?
    .assert_success();

    shielded_sync(&test_namada, AA_VIEWING_KEY)?;

    let query_args = vec![
        "balance",
        "--owner",
        AA_VIEWING_KEY,
        "--token",
        NAM,
        "--node",
        &rpc_namada,
    ];
    let mut client = run!(&test_namada, Bin::Client, query_args, Some(40))?;
    client.exp_string("nam: 0.000056")?;
    client.assert_success();

    // ==========================================================
    // SETUP DONE
    // ==========================================================
    // At this point, we have IBC channels between Osmosis, Gaia
    // and Namada. There is a LP with nam and samoleans, that we
    // can use to swap between the two assets. Moreover, we have
    // shielded some nam tokens.
    // ==========================================================

    // We wish to receive samoleans on namada
    let output_denom_on_namada =
        format!("transfer/{channel_from_namada_to_gaia}/{COSMOS_COIN}");

    // But on osmosis, we will end up with this token
    let output_denom_on_osmosis = get_gaia_denom_hash(format!(
        "transfer/{channel_from_osmosis_to_gaia}/{COSMOS_COIN}"
    ));

    // NOTE: This cfg is only used to disable compiling this code.
    // A separate contract needs to be deployed for transparent
    // swaps, so we won't test it here.
    #[cfg(target_family = "wasm")]
    {
        // Transparently swap samoleans with nam
        let mut cmd = run!(
            &test_namada,
            Bin::Client,
            [
                "osmosis-swap",
                "--osmosis-lcd",
                "http://localhost:1317",
                "--source",
                BERTHA,
                "--token",
                NAM,
                "--amount",
                "0.000064",
                "--channel-id",
                channel_from_namada_to_osmosis.as_ref(),
                "--output-denom",
                &output_denom_on_namada,
                "--local-recovery-addr",
                &osmosis_jones,
                "--swap-contract",
                &crosschain_swaps_addr,
                "--minimum-amount",
                "1",
                "--target",
                BERTHA,
                "--pool-hop",
                &format!("1:{output_denom_on_osmosis}"),
                "--node",
                &rpc_namada,
            ],
            Some(80),
        )?;

        // confirm trade
        cmd.send_line("y")?;
        cmd.assert_success();

        wait_for_packet_relay(
            &hermes_namada_osmosis,
            &PortId::transfer(),
            &channel_from_osmosis_to_namada,
            &test_osmosis,
        )?;
        wait_for_packet_relay(
            &hermes_gaia_namada,
            &PortId::transfer(),
            &channel_from_gaia_to_namada,
            &test_namada,
        )?;

        // Check that the swap worked
        // 39 is derived from the uniswap formula:
        // floor( 100 - (100*100/(100 + 64)) )
        check_balance(
            &test_namada,
            BERTHA,
            format!("transfer/{channel_from_namada_to_gaia}/{COSMOS_COIN}"),
            39,
        )?;
    }

    // Perform a shielded swap of samoleans and nam
    let mut cmd = run!(
        &test_namada,
        Bin::Client,
        [
            "osmosis-swap",
            "--osmosis-lcd",
            "http://localhost:1317",
            "--source",
            A_SPENDING_KEY,
            "--token",
            NAM,
            "--amount",
            "0.000056",
            "--channel-id",
            channel_from_namada_to_osmosis.as_ref(),
            "--output-denom",
            &output_denom_on_namada,
            "--local-recovery-addr",
            &osmosis_jones,
            "--swap-contract",
            &crosschain_swaps_addr,
            "--minimum-amount",
            "10",
            "--target-pa",
            AA_PAYMENT_ADDRESS,
            "--pool-hop",
            &format!("1:{output_denom_on_osmosis}"),
            "--gas-payer",
            ALBERT_KEY,
            "--node",
            &rpc_namada,
            "--gas-limit",
            "500000",
        ],
        Some(40),
    )?;

    // confirm trade
    cmd.send_line("y")?;
    cmd.assert_success();

    wait_for_packet_relay(
        &hermes_namada_osmosis,
        &PortId::transfer(),
        &channel_from_osmosis_to_namada,
        &test_osmosis,
    )?;
    wait_for_packet_relay(
        &hermes_gaia_namada,
        &PortId::transfer(),
        &channel_from_gaia_to_namada,
        &test_namada,
    )?;

    // Check the shielded balance.
    check_shielded_balance(
        &test_namada,
        AA_VIEWING_KEY,
        &output_denom_on_namada,
        35,
    )?;

    Ok(())
}

fn cosmos_common_args<'a>(
    gas: &'a str,
    gas_price: Option<&'a str>,
    chain_id: &'a str,
    rpc: &'a str,
    mut args: Vec<&'a str>,
) -> Vec<&'a str> {
    args.extend_from_slice(&[
        "--from",
        COSMOS_USER,
        "--gas",
        gas,
        "--gas-prices",
        gas_price.unwrap_or("0.01stake"),
        "--node",
        rpc,
        "--keyring-backend",
        "test",
        "--chain-id",
        chain_id,
        "--yes",
    ]);
    args
}

fn build_contract_addr(
    test: &Test,
    wasm_bytecode_hash: &str,
    creator_addr: &str,
) -> Result<String> {
    let osmosis_home = test.test_dir.as_ref().join("osmosis");
    let args = [
        "--home",
        osmosis_home.to_str().unwrap(),
        "query",
        "wasm",
        "build-address",
        wasm_bytecode_hash,
        creator_addr,
        CONTRACT_SALT_HEX,
    ];
    let mut cosmos = run_cosmos_cmd_homeless(test, args, Some(40))?;
    let (_, matched) = cosmos.exp_regex("address: .*\n")?;
    let mut parts = matched.split(':');
    parts.next().unwrap();
    Ok(parts.next().unwrap().trim().to_string())
}

/// Create a liquidity pool on osmosis.
/// All tokens will be 1:1 swappable in the provided
/// denoms.
fn create_pool(
    test: &Test,
    rpc: &str,
    denoms_and_deposits: &[(&str, u64)],
) -> Result<()> {
    let json_path = test.test_dir.path().join("pool.json");
    let mut weights =
        denoms_and_deposits
            .iter()
            .fold(String::new(), |mut acc, (d, _)| {
                acc.push_str(&format!("1{d},"));
                acc
            });
    weights.pop();
    let mut init_deposits =
        denoms_and_deposits
            .iter()
            .fold(String::new(), |mut acc, (d, a)| {
                acc.push_str(&format!("{a}{d},"));
                acc
            });
    init_deposits.pop();
    let pool_json = json!({
        "weights": weights,
        "initial-deposit": init_deposits,
        "swap-fee": "0.001",
        "exit-fee": "0.000"
    });
    let json_file = File::create(&json_path)?;
    serde_json::to_writer(json_file, &pool_json)?;
    let json_path = json_path.to_string_lossy();
    let args = cosmos_common_args(
        "2500000",
        Some("0.01stake"),
        "osmosis",
        rpc,
        vec![
            "tx",
            "poolmanager",
            "create-pool",
            "--pool-file",
            &json_path,
        ],
    );
    let mut osmosis_cmd = run_cosmos_cmd(test, args, Some(40))?;
    osmosis_cmd.assert_success();
    std::thread::sleep(Duration::from_secs(5));
    Ok(())
}

const CONTRACT_SALT_HEX: &str = "01020304";
