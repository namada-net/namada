//! By default, these tests will run in release mode. This can be disabled
//! by setting environment variable `NAMADA_E2E_DEBUG=true`. For debugging,
//! you'll typically also want to set `RUST_BACKTRACE=1`, e.g.:
//!
//! ```ignore,shell
//! NAMADA_E2E_DEBUG=true RUST_BACKTRACE=1 cargo test e2e::ledger_tests -- --test-threads=1 --nocapture
//! ```
//!
//! To keep the temporary files created by a test, use env var
//! `NAMADA_E2E_KEEP_TEMP=true`.
#![allow(clippy::type_complexity)]

use std::env;
use std::fmt::Display;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use namada_apps_lib::cli::context::ENV_VAR_CHAIN_ID;
use namada_apps_lib::client::utils::PRE_GENESIS_DIR;
use namada_apps_lib::config::genesis::chain;
use namada_apps_lib::config::genesis::templates::TokenBalances;
use namada_apps_lib::config::utils::convert_tm_addr_to_socket_addr;
use namada_apps_lib::config::{self, ethereum_bridge};
use namada_apps_lib::tendermint_config::net::Address as TendermintAddress;
use namada_apps_lib::wallet::defaults::is_use_device;
use namada_apps_lib::wallet::{self, Alias};
use namada_core::chain::ChainId;
use namada_core::token::NATIVE_MAX_DECIMAL_PLACES;
use namada_sdk::address::Address;
use namada_sdk::chain::{ChainIdPrefix, Epoch};
use namada_sdk::time::DateTimeUtc;
use namada_sdk::token;
use namada_test_utils::TestWasms;
use serde::Serialize;
use serde_json::json;
use setup::Test;
use setup::constants::*;

use super::helpers::{
    epochs_per_year_from_min_duration, get_height, get_pregenesis_wallet,
    wait_for_block_height, wait_for_wasm_pre_compile,
};
use super::setup::{NamadaCmd, set_ethereum_bridge_mode, working_dir};
use crate::e2e::helpers::{
    epoch_sleep, find_address, find_bonded_stake, get_actor_rpc, get_epoch,
    is_debug_mode, parse_reached_epoch,
};
use crate::e2e::setup::{
    self, Bin, Who, allow_duplicate_ips, apply_use_device, default_port_offset,
    sleep,
};
use crate::hw_wallet_automation::Speculos;
use crate::strings::{
    LEDGER_SHUTDOWN, LEDGER_STARTED, NON_VALIDATOR_NODE, TX_APPLIED_SUCCESS,
    TX_REJECTED, VALIDATOR_NODE,
};
use crate::{LastSignState, hw_wallet_automation, run, run_as};

const ENV_VAR_NAMADA_SEED_NODES: &str = "NAMADA_SEED_NODES";

fn start_namada_ledger_node(
    test: &Test,
    idx: Option<u64>,
    timeout_sec: Option<u64>,
) -> Result<NamadaCmd> {
    let who = match idx {
        Some(idx) => Who::Validator(idx),
        _ => Who::NonValidator,
    };
    let mut node = run_as!(test, who, Bin::Node, &["ledger"], timeout_sec)?;
    node.exp_string(LEDGER_STARTED)?;
    if let Who::Validator(_) = who {
        node.exp_string(VALIDATOR_NODE)?;
    } else {
        node.exp_string(NON_VALIDATOR_NODE)?;
    }
    Ok(node)
}

pub fn start_namada_ledger_node_wait_wasm(
    test: &Test,
    idx: Option<u64>,
    timeout_sec: Option<u64>,
) -> Result<NamadaCmd> {
    let mut node = start_namada_ledger_node(test, idx, timeout_sec)?;
    wait_for_wasm_pre_compile(&mut node)?;
    Ok(node)
}

/// Test that when we "run-ledger" with all the possible command
/// combinations from fresh state, the node starts-up successfully for both a
/// validator and non-validator user.
#[test]
fn run_ledger() -> Result<()> {
    let test = setup::single_node_net()?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    let cmd_combinations = vec![
        (Bin::Node, vec!["ledger"]),
        (Bin::Node, vec!["ledger", "run"]),
        (Bin::Namada, vec!["node", "ledger"]),
    ];

    // Start the ledger as a validator
    for (bin, args) in &cmd_combinations {
        let mut ledger =
            run_as!(test, Who::Validator(0), *bin, args, Some(40))?;
        ledger.exp_string(LEDGER_STARTED)?;
        ledger.exp_string(VALIDATOR_NODE)?;
    }

    // Start the ledger as a non-validator
    for (bin, args) in &cmd_combinations {
        let mut ledger =
            run_as!(test, Who::NonValidator, *bin, args, Some(40))?;
        ledger.exp_string(LEDGER_STARTED)?;
        ledger.exp_string(NON_VALIDATOR_NODE)?;
    }

    Ok(())
}

/// In this test we:
/// 1. Run 2 genesis validator ledger nodes and 1 non-validator node
/// 2. Cross over epoch to check for consensus with multiple nodes
/// 3. Submit a valid token transfer tx
/// 4. Check that all the nodes processed the tx with the same result
#[test]
fn test_node_connectivity_and_consensus() -> Result<()> {
    // Setup 2 genesis validator nodes
    let test = setup::network(
        |genesis, base_dir| {
            setup::set_validators(
                2,
                genesis,
                base_dir,
                default_port_offset,
                vec![],
            )
        },
        None,
    )?;

    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(0));
    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(1));

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(1),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run 2 genesis validator ledger nodes and 1 non-validator node
    let bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();
    let bg_validator_1 =
        start_namada_ledger_node_wait_wasm(&test, Some(1), Some(40))?
            .background();
    let _bg_non_validator =
        start_namada_ledger_node_wait_wasm(&test, None, Some(40))?.background();

    // 2. Cross over epoch to check for consensus with multiple nodes
    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));
    let _ = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // 3. Submit a valid token transfer tx
    let tx_args = apply_use_device(vec![
        "transparent-transfer",
        "--source",
        BERTHA,
        "--target",
        ALBERT,
        "--token",
        NAM,
        "--amount",
        "10.1",
        "--gas-price",
        "0.00090",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_one_rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 4. Check that all the nodes processed the tx with the same result
    let mut validator_0 = bg_validator_0.foreground();
    let mut validator_1 = bg_validator_1.foreground();
    let expected_result = "successful inner txs: 1";
    // We cannot check this on non-validator node as it might sync without
    // applying the tx itself, but its state should be the same, checked below.
    validator_0.exp_string(expected_result)?;
    validator_1.exp_string(expected_result)?;
    let _bg_validator_0 = validator_0.background();
    let _bg_validator_1 = validator_1.background();

    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));
    let non_validator_rpc = get_actor_rpc(&test, Who::NonValidator);

    // Find the block height on the validator
    let after_tx_height = get_height(&test, &validator_0_rpc)?;

    // Wait for the non-validator to be synced to at least the same height
    wait_for_block_height(&test, &non_validator_rpc, after_tx_height, 10)?;

    let query_balance_args = ["balance", "--owner", ALBERT, "--token", NAM];
    for who in
        [Who::Validator(0), Who::Validator(1), Who::NonValidator].into_iter()
    {
        let mut client =
            run_as!(test, who, Bin::Client, query_balance_args, Some(40))?;
        client.exp_string("nam: 2000010.1")?;
        client.assert_success();
    }

    Ok(())
}

/// In this test we:
/// 1. Start up the ledger
/// 2. Kill the tendermint process
/// 3. Check that the node detects this
/// 4. Check that the node shuts down
#[test]
fn test_namada_shuts_down_if_tendermint_dies() -> Result<()> {
    let test = setup::single_node_net()?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let mut ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?;

    // 2. Kill the tendermint node
    sleep(1);
    Command::new("pkill")
        .args(["cometbft"])
        .spawn()
        .expect("Test failed")
        .wait()
        .expect("Test failed");

    // 3. Check that namada detects that the tendermint node is dead
    ledger.exp_string("Tendermint node is no longer running.")?;

    // 4. Check that the ledger node shuts down
    ledger.exp_string(LEDGER_SHUTDOWN)?;
    ledger.exp_eof()?;

    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. Shut it down
/// 3. Run the ledger again, it should load its previous state
/// 4. Shut it down
/// 5. Reset the ledger's state
/// 6. Run the ledger again, it should start from fresh state
/// 7. Shut it down again
/// 8. Do a full reset the ledger's
#[test]
fn run_ledger_load_state_and_reset() -> Result<()> {
    let test = setup::single_node_net()?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let mut ledger = start_namada_ledger_node(&test, Some(0), Some(40))?;

    // There should be no previous state
    ledger.exp_string("No state could be found")?;
    // Wait to commit a block
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    let bg_ledger = ledger.background();
    // Wait for a new epoch
    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));
    epoch_sleep(&test, &validator_one_rpc, 30)?;

    // 2. Shut it down
    let mut ledger = bg_ledger.foreground();
    ledger.interrupt()?;
    // Wait for the node to stop running to finish writing the state and tx
    // queue
    ledger.exp_string(LEDGER_SHUTDOWN)?;
    ledger.exp_eof()?;
    drop(ledger);

    // 3. Run the ledger again, it should load its previous state
    let mut ledger = start_namada_ledger_node(&test, Some(0), Some(40))?;

    // There should be previous state now
    ledger.exp_string("Last state root hash:")?;

    // 4. Shut it down
    ledger.interrupt()?;
    // Wait for it to stop
    ledger.exp_eof()?;
    drop(ledger);

    // 5. Reset the ledger's state
    let mut session = run_as!(
        test,
        Who::Validator(0),
        Bin::Node,
        &["ledger", "reset"],
        Some(10),
    )?;
    session.exp_eof()?;

    // 6. Run the ledger again, it should start from fresh state
    let mut ledger = start_namada_ledger_node(&test, Some(0), Some(40))?;

    // There should be no previous state
    ledger.exp_string("No state could be found")?;
    // Wait to commit a block again
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;

    // 7. Shut it down again
    ledger.interrupt()?;
    // Wait for it to stop
    ledger.exp_eof()?;
    drop(ledger);

    // 8. Do a full reset of the ledger state
    let mut session = run_as!(
        test,
        Who::Validator(0),
        Bin::Node,
        &["ledger", "reset", "--full-reset"],
        Some(10),
    )?;
    session.exp_eof()?;

    let chain_dir = test.get_chain_dir(Who::Validator(0));
    assert!(!chain_dir.exists());

    Ok(())
}

/// This test makes sure the tool for migrating the DB
/// during a hard-fork works correctly.
///
/// 1. Run the ledger node, halting at height 2
/// 2. Update the db
/// 3. Run the ledger node, halting at height 4
/// 4. restart ledge with migrated db
/// 5. Check that a key was changed successfully
#[test]
fn test_db_migration() -> Result<()> {
    let test = setup::single_node_net()?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node, halting at height 6
    let mut ledger = run_as!(
        test,
        Who::Validator(0),
        Bin::Node,
        &["ledger", "run-until", "--block-height", "6", "--halt",],
        Some(40)
    )?;
    // Wait to commit a block
    ledger.exp_string("Reached block height 6, halting the chain.")?;
    ledger.exp_string(LEDGER_SHUTDOWN)?;
    ledger.exp_eof()?;
    drop(ledger);
    let migrations_json_path = working_dir()
        .join("examples")
        .join("migration_example.json");
    let migration_hash = namada_core::hash::Hash::sha256(
        std::fs::read(&migrations_json_path).unwrap(),
    )
    .to_string();
    // 2. Update the db
    let mut ledger = run_as!(
        test,
        Who::Validator(0),
        Bin::Node,
        &[
            "ledger",
            "run",
            "--path",
            migrations_json_path.to_string_lossy().as_ref(),
            "--height",
            "6",
            "--hash",
            &migration_hash
        ],
        Some(30),
    )?;

    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    ledger.interrupt()?;
    ledger.exp_eof()?;

    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, &["ledger"], Some(40))?;
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;

    // 5. Check that a key was changed successfully
    let mut query = run_as!(
        test,
        Who::Validator(0),
        Bin::Client,
        &[
            "balance",
            "--owner",
            "tnam1q9rhgyv3ydq0zu3whnftvllqnvhvhm270qxay5tn",
            "--token",
            "nam"
        ],
        Some(20),
    )?;
    query.exp_regex("nam: 3200000036910")?;
    ledger.interrupt()?;
    Ok(())
}

/// In this test we
///   1. Run the ledger node until a pre-configured height, at which point it
///      should suspend.
///   2. Check that we can still query the ledger.
///   3. Check that we can shutdown the ledger normally afterwards.
#[test]
fn suspend_ledger() -> Result<()> {
    let test = setup::single_node_net()?;
    // 1. Run the ledger node
    let mut ledger = run_as!(
        test,
        Who::Validator(0),
        Bin::Node,
        &["ledger", "run-until", "--block-height", "2", "--suspend",],
        Some(40)
    )?;

    ledger.exp_string(LEDGER_STARTED)?;
    // There should be no previous state
    ledger.exp_string("No state could be found")?;
    // Wait to commit a block
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    ledger.exp_string("Reached block height 2, suspending.")?;
    let bg_ledger = ledger.background();

    // 2. Query the ledger
    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));
    let mut client = run!(
        test,
        Bin::Client,
        &["epoch", "--ledger-address", &validator_one_rpc],
        Some(40)
    )?;
    client.exp_string("Last committed epoch: 0")?;

    // 3. Shut it down
    let mut ledger = bg_ledger.foreground();
    ledger.interrupt()?;
    // Wait for the node to stop running to finish writing the state and tx
    // queue
    ledger.exp_string(LEDGER_SHUTDOWN)?;
    ledger.exp_eof()?;
    Ok(())
}

/// Test that if we configure the ledger to
/// halt at a given height, it does indeed halt.
#[test]
fn stop_ledger_at_height() -> Result<()> {
    let test = setup::single_node_net()?;
    // 1. Run the ledger node
    let mut ledger = run_as!(
        test,
        Who::Validator(0),
        Bin::Node,
        &["ledger", "run-until", "--block-height", "2", "--halt",],
        Some(40)
    )?;

    ledger.exp_string(LEDGER_STARTED)?;
    // There should be no previous state
    ledger.exp_string("No state could be found")?;
    // Wait to commit a block
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    ledger.exp_string("Reached block height 2, halting the chain.")?;
    ledger.exp_eof()?;
    Ok(())
}

/// PoS bonding, unbonding and withdrawal tests. In this test we:
///
/// 1. Run the ledger node with shorter epochs for faster progression
/// 2. Submit a self-bond for the first genesis validator
/// 3. Submit a delegation to the first genesis validator
/// 4. Submit a re-delegation from the first to the second genesis validator
/// 5. Submit an unbond of the self-bond
/// 6. Submit an unbond of the delegation from the first validator
/// 7. Submit an unbond of the re-delegation from the second validator
/// 8. Wait for the unbonding epoch
/// 9. Submit a withdrawal of the self-bond
/// 10. Submit a withdrawal of the delegation
/// 11. Submit an withdrawal of the re-delegation
#[test]
fn pos_bonds() -> Result<()> {
    let pipeline_len = 2;
    let unbonding_len = 4;
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.pos_params.pipeline_len = pipeline_len;
            genesis.parameters.pos_params.unbonding_len = unbonding_len;
            genesis.parameters.parameters.min_num_of_blocks = 6;
            genesis.parameters.parameters.epochs_per_year = 31_536_000;
            let mut genesis = setup::set_validators(
                2,
                genesis,
                base_dir,
                default_port_offset,
                vec![],
            );
            genesis.transactions.bond = Some({
                let wallet = get_pregenesis_wallet(base_dir);
                let validator_1_address = wallet
                    .find_address("validator-1")
                    .expect("Failed to find validator-1 address");
                let mut bonds = genesis.transactions.bond.unwrap();
                bonds
                    .retain(|bond| bond.data.validator != *validator_1_address);
                bonds
            });
            genesis
        },
        None,
    )?;
    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(0));
    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(1));
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // If used, keep Speculos alive for duration of the test
    let _speculos = if hw_wallet_automation::uses_automation() {
        // Gen automation for Speculos
        let automation = hw_wallet_automation::gen_automation_e2e_pos_bonds();
        let json = serde_json::to_vec_pretty(&automation).unwrap();
        let path = test.test_dir.path().join("automation.json");
        std::fs::write(&path, json).unwrap();

        // Start Speculos with the automation
        Some(Speculos::spawn(&path))
    } else {
        None
    };

    // 1. Run the ledger node
    let _bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let rpc = get_actor_rpc(&test, Who::Validator(0));
    wait_for_block_height(&test, &rpc, 2, 30)?;

    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));

    // 2. Submit a self-bond for the first genesis validator
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0-validator",
        "--amount",
        "10000.0",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 3. Submit a delegation to the first genesis validator
    let tx_args = apply_use_device(vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "5000.0",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_0_rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 4. Submit a re-delegation from the first to the second genesis validator
    let tx_args = apply_use_device(vec![
        "redelegate",
        "--source-validator",
        "validator-0",
        "--destination-validator",
        "validator-1",
        "--owner",
        BERTHA,
        "--amount",
        "2500.0",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_0_rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 5. Submit an unbond of the self-bond
    let tx_args = vec![
        "unbond",
        "--validator",
        "validator-0-validator",
        "--amount",
        "5100.0",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client
        .exp_string("Amount 5100.000000 withdrawable starting from epoch ")?;
    client.assert_success();

    // 6. Submit an unbond of the delegation from the first validator
    let tx_args = apply_use_device(vec![
        "unbond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "1600.",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_0_rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    let expected = "Amount 1600.000000 withdrawable starting from epoch ";
    let _ = client.exp_regex(&format!("{expected}.*\n"))?;
    client.assert_success();

    // 7. Submit an unbond of the re-delegation from the second validator
    let tx_args = apply_use_device(vec![
        "unbond",
        "--validator",
        "validator-1",
        "--source",
        BERTHA,
        "--amount",
        "1600.",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_0_rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    let expected = "Amount 1600.000000 withdrawable starting from epoch ";
    let (_unread, matched) = client.exp_regex(&format!("{expected}.*\n"))?;
    let epoch_raw = matched.trim().split_once(expected).unwrap().1;
    let delegation_withdrawable_epoch = Epoch::from_str(epoch_raw).unwrap();
    client.assert_success();

    // 8. Wait for the delegation withdrawable epoch (the self-bond was unbonded
    // before it)
    let epoch = get_epoch(&test, &validator_0_rpc)?;

    println!(
        "Current epoch: {}, earliest epoch for withdrawal: {}",
        epoch, delegation_withdrawable_epoch
    );
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let loop_timeout = Duration::new(120, 0);
    loop {
        if {
            #[allow(clippy::disallowed_methods)]
            Instant::now()
        }
        .duration_since(start)
            > loop_timeout
        {
            panic!(
                "Timed out waiting for epoch: {}",
                delegation_withdrawable_epoch
            );
        }
        let epoch = epoch_sleep(&test, &validator_0_rpc, 40)?;
        if epoch >= delegation_withdrawable_epoch {
            break;
        }
    }

    // 9. Submit a withdrawal of the self-bond
    let tx_args = vec![
        "withdraw",
        "--validator",
        "validator-0-validator",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 10. Submit a withdrawal of the delegation
    let tx_args = apply_use_device(vec![
        "withdraw",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_0_rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 11. Submit an withdrawal of the re-delegation
    let tx_args = apply_use_device(vec![
        "withdraw",
        "--validator",
        "validator-1",
        "--source",
        BERTHA,
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_0_rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    Ok(())
}

/// PoS validator creation test. In this test we:
///
/// 1. Run the ledger node with shorter epochs for faster progression
/// 2. Initialize a new validator account
/// 3. Submit a delegation to the new validator
/// 4. Transfer some NAM to the new validator
/// 5. Submit a self-bond for the new validator
/// 6. Wait for the pipeline epoch
/// 7. Check the new validator's bonded stake
#[test]
fn pos_init_validator() -> Result<()> {
    let pipeline_len = 1;
    let validator_stake = token::Amount::native_whole(100000_u64);
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.parameters.min_num_of_blocks = 4;
            genesis.parameters.parameters.epochs_per_year = 31_536_000;
            genesis.parameters.pos_params.pipeline_len = pipeline_len;
            genesis.parameters.pos_params.unbonding_len = 2;
            let genesis = setup::set_validators(
                1,
                genesis,
                base_dir,
                default_port_offset,
                vec![],
            );
            println!("{:?}", genesis.transactions.bond);
            let stake = genesis
                .transactions
                .bond
                .as_ref()
                .unwrap()
                .iter()
                .map(|bond| {
                    bond.data
                        .amount
                        .increase_precision(NATIVE_MAX_DECIMAL_PLACES.into())
                        .unwrap()
                        .amount()
                })
                .sum::<token::Amount>();
            assert_eq!(
                stake, validator_stake,
                "Assuming this stake, we give the same amount to the new \
                 validator to have half of voting power",
            );
            genesis
        },
        None,
    )?;

    // 1. Run a validator and non-validator ledger node
    let mut validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(60))?;
    let mut non_validator =
        start_namada_ledger_node_wait_wasm(&test, None, Some(60))?;

    // Wait for a first block
    validator_0.exp_string("Committed block hash")?;
    let _bg_validator_0 = validator_0.background();
    non_validator.exp_string("Committed block hash")?;
    let bg_non_validator = non_validator.background();

    let non_validator_rpc = get_actor_rpc(&test, Who::NonValidator);

    // 2. Initialize a new validator account with the non-validator node
    let new_validator = "new-validator";
    let _new_validator_key = format!("{}-key", new_validator);
    let tx_args = apply_use_device(vec![
        "init-validator",
        "--alias",
        new_validator,
        "--name",
        new_validator,
        "--account-keys",
        "bertha-key",
        "--commission-rate",
        "0.05",
        "--max-commission-rate-change",
        "0.01",
        "--email",
        "null@null.net",
        "--signing-keys",
        "bertha-key",
        "--node",
        &non_validator_rpc,
        "--unsafe-dont-encrypt",
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // Stop the non-validator node and run it as the new validator
    let mut non_validator = bg_non_validator.foreground();
    non_validator.interrupt()?;
    non_validator.exp_eof()?;

    // it takes a bit before the node is shutdown. We dont want flasky test.
    if is_debug_mode() {
        sleep(10);
    } else {
        sleep(5);
    }

    let loc = format!("{}:{}", std::file!(), std::line!());
    let validator_1_base_dir = test.get_base_dir(Who::NonValidator);
    let mut validator_1 = setup::run_cmd(
        Bin::Node,
        ["ledger"],
        Some(60),
        &test.working_dir,
        validator_1_base_dir,
        loc,
    )?;

    validator_1.exp_string(LEDGER_STARTED)?;
    validator_1.exp_string(VALIDATOR_NODE)?;
    validator_1.exp_string("Committed block hash")?;
    let _bg_validator_1 = validator_1.background();

    // 3. Submit a delegation to the new validator First, transfer some tokens
    //    to the validator's key for fees:
    let tx_args = apply_use_device(vec![
        "transparent-transfer",
        "--source",
        BERTHA,
        "--target",
        new_validator,
        "--token",
        NAM,
        "--amount",
        "10000.5",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &non_validator_rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    //     Then self-bond the tokens:
    let delegation = 5_u64;
    let delegation_str = &delegation.to_string();
    let tx_args = apply_use_device(vec![
        "bond",
        "--validator",
        new_validator,
        "--source",
        BERTHA,
        "--amount",
        delegation_str,
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &non_validator_rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 4. Transfer some NAM to the new validator
    let validator_stake_str = &validator_stake.to_string_native();
    let tx_args = apply_use_device(vec![
        "transparent-transfer",
        "--source",
        BERTHA,
        "--target",
        new_validator,
        "--token",
        NAM,
        "--amount",
        validator_stake_str,
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &non_validator_rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 5. Submit a self-bond for the new validator
    let tx_args = apply_use_device(vec![
        "bond",
        "--validator",
        new_validator,
        "--amount",
        validator_stake_str,
        "--node",
        &non_validator_rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 6. Wait for the pipeline epoch when the validator's bonded stake should
    // be non-zero
    let epoch = get_epoch(&test, &non_validator_rpc)?;
    let earliest_update_epoch = epoch + pipeline_len;
    println!(
        "Current epoch: {}, earliest epoch with updated bonded stake: {}",
        epoch, earliest_update_epoch
    );
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let loop_timeout = Duration::new(20, 0);
    loop {
        if {
            #[allow(clippy::disallowed_methods)]
            Instant::now()
        }
        .duration_since(start)
            > loop_timeout
        {
            panic!("Timed out waiting for epoch: {}", earliest_update_epoch);
        }
        let epoch = epoch_sleep(&test, &non_validator_rpc, 40)?;
        if epoch >= earliest_update_epoch {
            break;
        }
    }

    // 7. Check the new validator's bonded stake
    let bonded_stake =
        find_bonded_stake(&test, new_validator, &non_validator_rpc)?;
    assert_eq!(
        bonded_stake,
        token::Amount::native_whole(delegation) + validator_stake
    );

    Ok(())
}

/// Test that multiple txs submitted in the same block all get the tx result.
///
/// In this test we:
/// 1. Run the ledger node with 10s consensus timeout
/// 2. Spawn threads each submitting token transfer tx
#[test]
fn ledger_many_txs_in_a_block() -> Result<()> {
    let test = Arc::new(setup::network(
        |genesis, base_dir: &_| {
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        },
        // Set 10s consensus timeout to have more time to submit txs
        Some("10s"),
    )?);

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = Arc::new(get_actor_rpc(&test, Who::Validator(0)));

    // A token transfer tx args
    let tx_args = Arc::new(apply_use_device(vec![
        "transparent-transfer",
        "--source",
        BERTHA,
        "--target",
        ALBERT,
        "--token",
        NAM,
        "--amount",
        "1.01",
        "--signing-keys",
        BERTHA_KEY,
    ]));

    if tx_args.contains(&"--use-device") {
        // Sequentialize transaction signing when hardware wallet is involved
        for _ in 0..4 {
            let mut args = (*tx_args).clone();
            args.push("--node");
            args.push(&*validator_one_rpc);
            let mut client = run!(*test, Bin::Client, args, Some(80))?;
            client.exp_string(TX_APPLIED_SUCCESS)?;
            client.assert_success();
        }
    } else {
        // 2. Spawn threads each submitting token transfer tx
        // We collect to run the threads in parallel.
        #[allow(clippy::needless_collect)]
        let tasks: Vec<std::thread::JoinHandle<_>> = (0..4)
            .map(|_| {
                let test = Arc::clone(&test);
                let validator_one_rpc = Arc::clone(&validator_one_rpc);
                let tx_args = Arc::clone(&tx_args);
                std::thread::spawn(move || {
                    let mut args = (*tx_args).clone();
                    args.push("--node");
                    args.push(&*validator_one_rpc);
                    let mut client = run!(*test, Bin::Client, args, Some(80))?;
                    client.exp_string(TX_APPLIED_SUCCESS)?;
                    client.assert_success();
                    let res: Result<()> = Ok(());
                    res
                })
            })
            .collect();
        for task in tasks.into_iter() {
            task.join().unwrap()?;
        }
    }
    // Wait to commit a block
    let mut ledger = bg_ledger.foreground();
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;

    Ok(())
}

pub fn write_json_file<T>(proposal_path: &std::path::Path, proposal_content: T)
where
    T: Serialize,
{
    let intent_writer = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(proposal_path)
        .unwrap();

    serde_json::to_writer(intent_writer, &proposal_content).unwrap();
}

/// In this test we intentionally make a validator node double sign blocks
/// to test that slashing evidence is received and processed by the ledger
/// correctly:
/// 1. Copy the first genesis validator base-dir
/// 2. Increment its ports and generate new node ID to avoid conflict
/// 3. Run 2 genesis validator ledger nodes
/// 4. Run the copied validator to get it to double vote and sign blocks
/// 5. Wait for double signing evidence
/// 6. Wait for slash processing epoch
/// 7. Make sure the first validator can proceed to the next epoch
#[test]
fn double_signing_gets_slashed() -> Result<()> {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use namada_apps_lib::client;
    use namada_apps_lib::config::Config;
    use namada_sdk::key::{self, SigScheme, ed25519};

    let mut pipeline_len = 0;
    let mut unbonding_len = 0;
    let mut cubic_offset = 0;

    // Setup 2 genesis validator nodes
    let test = setup::network(
        |mut genesis, base_dir| {
            (pipeline_len, unbonding_len, cubic_offset) = (
                genesis.parameters.pos_params.pipeline_len,
                genesis.parameters.pos_params.unbonding_len,
                genesis.parameters.pos_params.cubic_slashing_window_length,
            );
            // Make faster epochs to be more likely to discover boundary issues
            genesis.parameters.parameters.min_num_of_blocks = 2;
            setup::set_validators(
                2,
                genesis,
                base_dir,
                default_port_offset,
                vec![
                    // The duplicate validator who will double sign and get
                    // slashed has less stake so that the 2nd validator has
                    // majority to continue producing blocks
                    token::Amount::native_whole(30_000),
                    token::Amount::native_whole(100_000),
                ],
            )
        },
        // Slow down the blocks to 5s
        Some("5s"),
    )?;

    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(0));
    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(1));

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(1),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );
    println!("pipeline_len: {}", pipeline_len);

    // 1. Copy the first genesis validator base-dir
    let validator_0_base_dir = test.get_base_dir(Who::Validator(0));
    let validator_0_base_dir_copy = test
        .test_dir
        .path()
        .join(test.net.chain_id.as_str())
        .join(client::utils::NET_ACCOUNTS_DIR)
        .join("validator-0-copy")
        .join(namada_apps_lib::config::DEFAULT_BASE_DIR);
    fs_extra::dir::copy(
        validator_0_base_dir,
        &validator_0_base_dir_copy,
        &fs_extra::dir::CopyOptions {
            copy_inside: true,
            ..Default::default()
        },
    )
    .unwrap();

    // 2. Increment its ports and generate new node ID to avoid conflict

    // Same as in `genesis/e2e-tests-single-node.toml` for `validator-0`
    let net_address_0 = SocketAddr::from_str("127.0.0.1:27656").unwrap();
    let net_address_port_0 = net_address_0.port();

    let update_config = |ix: u8, mut config: Config| {
        let first_port = net_address_port_0 + 26 * (ix as u16 + 1);
        let p2p_addr =
            convert_tm_addr_to_socket_addr(&config.ledger.cometbft.p2p.laddr)
                .ip()
                .to_string();

        config.ledger.cometbft.p2p.laddr = TendermintAddress::from_str(
            &format!("{}:{}", p2p_addr, first_port),
        )
        .unwrap();
        let rpc_addr =
            convert_tm_addr_to_socket_addr(&config.ledger.cometbft.rpc.laddr)
                .ip()
                .to_string();
        config.ledger.cometbft.rpc.laddr = TendermintAddress::from_str(
            &format!("{}:{}", rpc_addr, first_port + 1),
        )
        .unwrap();
        let proxy_app_addr =
            convert_tm_addr_to_socket_addr(&config.ledger.cometbft.proxy_app)
                .ip()
                .to_string();
        config.ledger.cometbft.proxy_app = TendermintAddress::from_str(
            &format!("{}:{}", proxy_app_addr, first_port + 2),
        )
        .unwrap();
        config
    };

    let validator_0_copy_config = update_config(
        2,
        Config::load(&validator_0_base_dir_copy, &test.net.chain_id, None),
    );
    validator_0_copy_config
        .write(&validator_0_base_dir_copy, &test.net.chain_id, true)
        .unwrap();

    // Generate a new node key
    use rand::prelude::ThreadRng;
    use rand::thread_rng;

    let mut rng: ThreadRng = thread_rng();
    let node_sk = ed25519::SigScheme::generate(&mut rng);
    let node_sk = key::common::SecretKey::Ed25519(node_sk);
    let tm_home_dir = validator_0_base_dir_copy
        .join(test.net.chain_id.as_str())
        .join("cometbft");
    let _node_pk =
        client::utils::write_tendermint_node_key(&tm_home_dir, node_sk);

    // 3. Run 2 genesis validator ledger nodes
    let _bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();
    let bg_validator_1 =
        start_namada_ledger_node_wait_wasm(&test, Some(1), Some(100))?
            .background();

    // 4. Run the copied validator to get it to double vote and sign blocks
    let loc = format!("{}:{}", std::file!(), std::line!());

    // This node will only connect to `validator_1`, so that nodes
    // `validator_0` and `validator_0_copy` should start double signing
    let mut validator_0_copy = setup::run_cmd(
        Bin::Node,
        ["ledger"],
        Some(40),
        &test.working_dir,
        &validator_0_base_dir_copy,
        loc,
    )?;
    validator_0_copy.exp_string(LEDGER_STARTED)?;
    validator_0_copy.exp_string(VALIDATOR_NODE)?;
    let mut bg_validator_0_copy = validator_0_copy.background();

    // 5. Wait for double signing evidence
    let mut validator_1 = bg_validator_1.foreground();
    const RETRIES: usize = 5;
    for i in 0..=RETRIES {
        if let Err(e) = validator_1.exp_string("Processing evidence") {
            #[allow(clippy::disallowed_methods)]
            let now = DateTimeUtc::now().to_rfc3339();
            println!("Failed to get evidence on {}. try at {now}", i + 1);

            // Often, the `validator_0_copy` detects the duplicate votes and
            // doesn't report them. It then stores the sig in
            // `priv_validator_state.json` which prevents it from attempting to
            // double sign again.
            // To get around it, we try to stop the `validator_1` that owns the
            // consensus so that it stops producing blocks while we're clearing
            // out the signature and restarting the duplicate validator node.
            validator_1.interrupt()?;
            validator_1.exp_string(LEDGER_SHUTDOWN)?;
            validator_1.assert_success();
            drop(validator_1);
            let mut validator_0_copy = bg_validator_0_copy.foreground();
            validator_0_copy.interrupt()?;
            validator_0_copy.exp_string(LEDGER_SHUTDOWN)?;
            validator_0_copy.assert_success();
            drop(validator_0_copy);

            // Clear out last sig
            let chain_dir =
                validator_0_base_dir_copy.join(test.net.chain_id.to_string());
            let validator_state_path =
                chain_dir.join("cometbft/data/priv_validator_state.json");
            if validator_state_path.exists() {
                let bytes = std::fs::read(&validator_state_path).unwrap();
                let mut state: LastSignState =
                    serde_json::from_slice(&bytes).unwrap();
                state.signature = None;
                state.signbytes = None;
                std::fs::write(
                    &validator_state_path,
                    serde_json::to_vec(&state).unwrap(),
                )
                .unwrap()
            }

            if i == RETRIES {
                return Err(e);
            }

            // Restart the nodes
            let loc = format!("{}:{}", std::file!(), std::line!());
            bg_validator_0_copy = setup::run_cmd(
                Bin::Node,
                ["ledger"],
                Some(40),
                &test.working_dir,
                &validator_0_base_dir_copy,
                loc,
            )?
            .background();
            validator_1 = start_namada_ledger_node(&test, Some(1), Some(100))?;
        } else {
            break;
        }
    }
    #[allow(clippy::disallowed_methods)]
    let now = DateTimeUtc::now().to_rfc3339();
    println!("Got evidence at {now}");

    println!("\nPARSING SLASH MESSAGE\n");
    let (_, res) = validator_1
        .exp_regex(r"Slashing [a-z0-9]+ for Duplicate vote in epoch [0-9]+")
        .unwrap();
    println!("\n{res}\n");

    // Stop the duplicate validator to avoid getting any more slashes
    let mut validator_0_copy = bg_validator_0_copy.foreground();
    validator_0_copy.interrupt()?;
    validator_0_copy.assert_success();

    // Wait to commit a block
    validator_1.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    let bg_validator_1 = validator_1.background();

    let exp_processing_epoch =
        Epoch::from_str(res.split(' ').next_back().unwrap()).unwrap()
            + unbonding_len
            + cubic_offset
            + 1u64;

    // Query slashes
    let validator_1_rpc = get_actor_rpc(&test, Who::Validator(1));
    let mut client = run!(
        test,
        Bin::Client,
        &["slashes", "--node", &validator_1_rpc],
        Some(40)
    )?;
    client.exp_string("No processed slashes found")?;
    client.exp_string("Enqueued slashes for future processing")?;
    let (_, res) = client
        .exp_regex(r"To be processed in epoch [0-9]+")
        .unwrap();
    let processing_epoch =
        Epoch::from_str(res.split(' ').next_back().unwrap()).unwrap();

    assert_eq!(processing_epoch, exp_processing_epoch);

    println!("\n{processing_epoch}\n");

    // 6. Wait for slash processing epoch
    loop {
        let epoch = epoch_sleep(&test, &validator_1_rpc, 240)?;
        println!("\nCurrent epoch: {}", epoch);
        if epoch > processing_epoch {
            break;
        }
    }

    let mut client = run!(
        test,
        Bin::Client,
        &[
            "validator-state",
            "--validator",
            "validator-0",
            "--node",
            &validator_1_rpc
        ],
        Some(40)
    )?;
    let _ = client.exp_regex(r"Validator [a-z0-9]+ is jailed").unwrap();

    let mut client = run!(
        test,
        Bin::Client,
        &["slashes", "--node", &validator_1_rpc],
        Some(40)
    )?;
    client.exp_string("Processed slashes:")?;
    client.exp_string("No enqueued slashes found")?;

    let tx_args = vec![
        "unjail-validator",
        "--validator",
        "validator-0-validator",
        "--node",
        &validator_1_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // Wait until pipeline epoch to see if the validator is back in consensus
    let cur_epoch = epoch_sleep(&test, &validator_1_rpc, 240)?;
    loop {
        let epoch = epoch_sleep(&test, &validator_1_rpc, 240)?;
        println!("\nCurrent epoch: {}", epoch);
        if epoch > cur_epoch + pipeline_len + 1u64 {
            break;
        }
    }
    let mut client = run!(
        test,
        Bin::Client,
        &[
            "validator-state",
            "--validator",
            "validator-0",
            "--node",
            &validator_1_rpc
        ],
        Some(40)
    )?;
    let _ = client
        .exp_regex(r"Validator [a-z0-9]+ is in the .* set")
        .unwrap();

    // 7. Make sure the first validator can proceed to the next epoch
    epoch_sleep(&test, &validator_1_rpc, 120)?;

    // Make sure there are no errors
    let mut validator_1 = bg_validator_1.foreground();
    validator_1.interrupt()?;
    // Wait for the node to stop running to finish writing the state and tx
    // queue
    validator_1.exp_string(LEDGER_SHUTDOWN)?;
    validator_1.assert_success();

    Ok(())
}

#[test]
fn test_epoch_sleep() -> Result<()> {
    // Use slightly longer epochs to give us time to sleep
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(30);
            genesis.parameters.parameters.min_num_of_blocks = 1;
            setup::set_validators(1, genesis, base_dir, |_| 0, vec![])
        },
        None,
    )?;

    // 1. Run the ledger node
    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, &["ledger"], Some(40))?;
    wait_for_wasm_pre_compile(&mut ledger)?;

    let _bg_ledger = ledger.background();

    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    // 2. Query the current epoch
    let start_epoch = get_epoch(&test, &validator_one_rpc).unwrap();

    // 3. Use epoch-sleep to sleep for an epoch
    let args = ["utils", "epoch-sleep", "--node", &validator_one_rpc];
    let mut client = run!(test, Bin::Client, &args, None)?;
    let reached_epoch = parse_reached_epoch(&mut client)?;
    client.assert_success();

    // 4. Confirm the current epoch is larger
    // possibly badly, we assume we get here within 30 seconds of the last step
    // should be fine haha (future debuggers: sorry)
    let current_epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    assert!(current_epoch > start_epoch);
    assert_eq!(current_epoch, reached_epoch);

    Ok(())
}

/// Prepare proposal data in the test's temp dir from the given source address.
/// This can be submitted with "init-proposal" command.
pub fn prepare_proposal_data(
    test_dir: impl AsRef<std::path::Path>,
    source: Address,
    data: impl serde::Serialize,
    start_epoch: u64,
) -> PathBuf {
    let valid_proposal_json = json!({
        "proposal": {
            "content": {
                "title": "TheTitle",
                "authors": "test@test.com",
                "discussions-to": "www.github.com/anoma/aip/1",
                "created": "2022-03-10T08:54:37Z",
                "license": "MIT",
                "abstract": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros. Nullam sed ex justo. Ut at placerat ipsum, sit amet rhoncus libero. Sed blandit non purus non suscipit. Phasellus sed quam nec augue bibendum bibendum ut vitae urna. Sed odio diam, ornare nec sapien eget, congue viverra enim.",
                "motivation": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices.",
                "details": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros.",
                "requires": "2"
            },
            "author": source,
            "voting_start_epoch": start_epoch,
            "voting_end_epoch": start_epoch + 12_u64,
            "activation_epoch": start_epoch + 12u64 + 6_u64,
        },
        "data": data
    });

    let valid_proposal_json_path =
        test_dir.as_ref().join("valid_proposal.json");
    write_json_file(valid_proposal_json_path.as_path(), valid_proposal_json);
    valid_proposal_json_path
}

#[test]
fn deactivate_and_reactivate_validator() -> Result<()> {
    let pipeline_len = 2;
    let unbonding_len = 4;
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.pos_params.pipeline_len = pipeline_len;
            genesis.parameters.pos_params.unbonding_len = unbonding_len;
            // genesis.parameters.parameters.min_num_of_blocks = 6;
            // genesis.parameters.parameters.epochs_per_year = 31_536_000;
            let mut genesis = setup::set_validators(
                2,
                genesis,
                base_dir,
                default_port_offset,
                vec![],
            );
            genesis.transactions.bond = Some({
                let wallet = get_pregenesis_wallet(base_dir);
                let validator_1_address = wallet
                    .find_address("validator-1")
                    .expect("Failed to find validator-1 address");
                let mut bonds = genesis.transactions.bond.unwrap();
                bonds
                    .retain(|bond| bond.data.validator != *validator_1_address);
                bonds
            });
            genesis
        },
        None,
    )?;
    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(0));
    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(1));
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(1),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let _bg_validator_1 =
        start_namada_ledger_node_wait_wasm(&test, Some(1), Some(40))?
            .background();

    let validator_1_rpc = get_actor_rpc(&test, Who::Validator(1));

    // Check the state of validator-1
    let tx_args = vec![
        "validator-state",
        "--validator",
        "validator-1",
        "--node",
        &validator_1_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_regex(r"Validator [a-z0-9]+ is in the below-threshold set")?;
    client.assert_success();

    // Deactivate validator-1
    let tx_args = vec![
        "deactivate-validator",
        "--validator",
        "validator-1-validator",
        "--signing-keys",
        "validator-1-balance-key",
        "--node",
        &validator_1_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(1), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    let deactivate_epoch = get_epoch(&test, &validator_1_rpc)?;
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let loop_timeout = Duration::new(120, 0);
    loop {
        if {
            #[allow(clippy::disallowed_methods)]
            Instant::now()
        }
        .duration_since(start)
            > loop_timeout
        {
            panic!(
                "Timed out waiting for epoch: {}",
                deactivate_epoch + pipeline_len
            );
        }
        let epoch = epoch_sleep(&test, &validator_1_rpc, 40)?;
        if epoch >= deactivate_epoch + pipeline_len {
            break;
        }
    }

    // Check the state of validator-0 again
    let tx_args = vec![
        "validator-state",
        "--validator",
        "validator-1",
        "--node",
        &validator_1_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_regex(r"Validator [a-z0-9]+ is inactive")?;
    client.assert_success();

    // Reactivate validator-1
    let tx_args = vec![
        "reactivate-validator",
        "--validator",
        "validator-1-validator",
        "--signing-keys",
        "validator-1-balance-key",
        "--node",
        &validator_1_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(1), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    let reactivate_epoch = get_epoch(&test, &validator_1_rpc)?;
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let loop_timeout = Duration::new(120, 0);
    loop {
        if {
            #[allow(clippy::disallowed_methods)]
            Instant::now()
        }
        .duration_since(start)
            > loop_timeout
        {
            panic!(
                "Timed out waiting for epoch: {}",
                reactivate_epoch + pipeline_len
            );
        }
        let epoch = epoch_sleep(&test, &validator_1_rpc, 40)?;
        if epoch >= reactivate_epoch + pipeline_len {
            break;
        }
    }

    // Check the state of validator-0 again
    let tx_args = vec![
        "validator-state",
        "--validator",
        "validator-1",
        "--node",
        &validator_1_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_regex(r"Validator [a-z0-9]+ is in the below-threshold set")?;
    client.assert_success();

    Ok(())
}

#[test]
fn test_invalid_validator_txs() -> Result<()> {
    let pipeline_len = 2;
    let unbonding_len = 4;
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.pos_params.pipeline_len = pipeline_len;
            genesis.parameters.pos_params.unbonding_len = unbonding_len;
            // genesis.parameters.parameters.min_num_of_blocks = 6;
            // genesis.parameters.parameters.epochs_per_year = 31_536_000;
            let mut genesis = setup::set_validators(
                2,
                genesis,
                base_dir,
                default_port_offset,
                vec![],
            );
            genesis.transactions.bond = Some({
                let wallet = get_pregenesis_wallet(base_dir);
                let validator_1_address = wallet
                    .find_address("validator-1")
                    .expect("Failed to find validator-1 address");
                let mut bonds = genesis.transactions.bond.unwrap();
                bonds
                    .retain(|bond| bond.data.validator != *validator_1_address);
                bonds
            });
            genesis
        },
        None,
    )?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let _bg_validator_1 =
        start_namada_ledger_node_wait_wasm(&test, Some(1), Some(40))?
            .background();

    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));
    let validator_1_rpc = get_actor_rpc(&test, Who::Validator(1));

    // Try to change validator-1 commission rate as validator-0
    let tx_args = vec![
        "change-commission-rate",
        "--validator",
        "validator-1",
        "--commission-rate",
        "0.06",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_REJECTED)?;
    client.assert_success();

    // Try to deactivate validator-1 as validator-0
    let tx_args = vec![
        "deactivate-validator",
        "--validator",
        "validator-1",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_REJECTED)?;
    client.assert_success();

    // Try to change the validator-1 website as validator-0
    let tx_args = vec![
        "change-metadata",
        "--validator",
        "validator-1",
        "--website",
        "theworstvalidator@namada.net",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_REJECTED)?;
    client.assert_success();

    // Deactivate validator-1
    let tx_args = vec![
        "deactivate-validator",
        "--validator",
        "validator-1-validator",
        "--signing-keys",
        "validator-1-balance-key",
        "--node",
        &validator_1_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(1), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    let deactivate_epoch = get_epoch(&test, &validator_1_rpc)?;
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let loop_timeout = Duration::new(120, 0);
    loop {
        if {
            #[allow(clippy::disallowed_methods)]
            Instant::now()
        }
        .duration_since(start)
            > loop_timeout
        {
            panic!(
                "Timed out waiting for epoch: {}",
                deactivate_epoch + pipeline_len
            );
        }
        let epoch = epoch_sleep(&test, &validator_1_rpc, 40)?;
        if epoch >= deactivate_epoch + pipeline_len {
            break;
        }
    }

    // Check the state of validator-1
    let tx_args = vec![
        "validator-state",
        "--validator",
        "validator-1",
        "--node",
        &validator_1_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_regex(r"Validator [a-z0-9]+ is inactive")?;
    client.assert_success();

    // Try to reactivate validator-1 as validator-0
    let tx_args = vec![
        "reactivate-validator",
        "--validator",
        "validator-1",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_REJECTED)?;
    client.assert_success();

    Ok(())
}

/// Test change of consensus key of a validator from consensus set.
///
/// 1. Run 2 genesis validator nodes.
/// 2. Change consensus key of validator-0
/// 3. Check that no new blocks are being created - chain halted because
///    validator-0 consensus change took effect and it cannot sign with the old
///    key anymore
/// 4. Configure validator-0 node with the new key
/// 5. Resume the chain and check that blocks are being created
#[test]
fn change_consensus_key() -> Result<()> {
    let min_num_of_blocks = 6;
    let pipeline_len = 2;
    let test = setup::network(
        |mut genesis, base_dir| {
            genesis.parameters.parameters.min_num_of_blocks = min_num_of_blocks;
            genesis.parameters.parameters.epochs_per_year = 31_536_000;
            genesis.parameters.pos_params.pipeline_len = pipeline_len;
            genesis.parameters.pos_params.unbonding_len = 4;
            setup::set_validators(
                2,
                genesis,
                base_dir,
                default_port_offset,
                vec![],
            )
        },
        None,
    )?;

    for i in 0..2 {
        set_ethereum_bridge_mode(
            &test,
            &test.net.chain_id,
            Who::Validator(i),
            ethereum_bridge::ledger::Mode::Off,
            None,
        );
    }

    // =========================================================================
    // 1. Run 2 genesis validator ledger nodes

    let bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let _bg_validator_1 =
        start_namada_ledger_node_wait_wasm(&test, Some(1), Some(40))?
            .background();

    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));

    // =========================================================================
    // 2. Change consensus key of validator-0

    let tx_args = vec![
        "change-consensus-key",
        "--validator",
        "validator-0-validator",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
        "--unsafe-dont-encrypt",
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // =========================================================================
    // 3. Check that no new blocks are being created - chain halted because
    // validator-0 consensus change took effect and it cannot sign with the old
    // key anymore

    // Wait for the next epoch
    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));
    let _epoch = epoch_sleep(&test, &validator_0_rpc, 30)?;

    // The chain should halt before the following (pipeline) epoch
    let _err_report = epoch_sleep(&test, &validator_0_rpc, 30)
        .expect_err("Chain should halt");

    // Load validator-0 wallet
    println!(
        "{}",
        "Setting up the new validator consensus key in CometBFT...".blue()
    );
    let chain_dir = test.get_chain_dir(Who::Validator(0));
    let mut wallet = namada_apps_lib::wallet::load(&chain_dir).unwrap();

    // =========================================================================
    // 4. Configure validator-0 node with the new key

    // Get the new consensus SK
    let new_key_alias = "validator-0-validator-consensus-key";
    let new_sk = wallet.find_secret_key(new_key_alias, None).unwrap();
    // Write the key to CometBFT dir
    let cometbft_dir = test.get_cometbft_home(Who::Validator(0));
    namada_node::tendermint_node::write_validator_key(cometbft_dir, &new_sk)
        .unwrap();
    println!(
        "{}",
        "Done setting up the new validator consensus key in CometBFT.".blue()
    );

    // =========================================================================
    // 5. Resume the chain and check that blocks are being created

    // Restart validator-0 node
    let mut validator_0 = bg_validator_0.foreground();
    validator_0.interrupt().unwrap();
    // Wait for the node to stop running
    validator_0.exp_string(LEDGER_SHUTDOWN)?;
    validator_0.exp_eof()?;
    drop(validator_0);

    let mut validator_0 = start_namada_ledger_node(&test, Some(0), Some(40))?;
    // Wait to commit a block
    validator_0.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    let _bg_validator_0 = validator_0.background();

    // Continue to make blocks for another epoch
    let _epoch = epoch_sleep(&test, &validator_0_rpc, 40)?;

    Ok(())
}

#[test]
fn proposal_change_shielded_reward() -> Result<()> {
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.gov_params.max_proposal_code_size = 600000;
            setup::set_validators(1, genesis, base_dir, |_| 0u16, vec![])
        },
        None,
    )?;
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let mut ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?;
    ledger.exp_string("Committed block hash")?;
    let bg_ledger = ledger.background();

    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));

    // 1.1 Delegate some token
    let tx_args = apply_use_device(vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "900",
        "--node",
        &validator_0_rpc,
    ]);
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 2. Submit valid proposal
    let albert = find_address(&test, ALBERT)?;
    let valid_proposal_json_path = prepare_proposal_data(
        test.test_dir.path(),
        albert,
        TestWasms::TxProposalMaspRewards.read_bytes(),
        12,
    );
    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    let submit_proposal_args = apply_use_device(vec![
        "init-proposal",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--gas-limit",
        "2000000",
        "--node",
        &validator_one_rpc,
    ]);
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // Wait for the proposal to be committed
    let mut ledger = bg_ledger.foreground();
    ledger.exp_string("Committed block hash")?;
    let _bg_ledger = ledger.background();

    // 3. Query the proposal
    let proposal_query_args = vec![
        "query-proposal",
        "--proposal-id",
        "0",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, proposal_query_args, Some(40))?;
    client.exp_string("Proposal Id: 0")?;
    client.assert_success();

    // 9. Send a yay vote from a validator
    let mut epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    while epoch.0 <= 13 {
        sleep(10);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    let submit_proposal_vote = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        "validator-0-validator",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run_as!(
        test,
        Who::Validator(0),
        Bin::Client,
        submit_proposal_vote,
        Some(15)
    )?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    let submit_proposal_vote_delagator = apply_use_device(vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "nay",
        "--address",
        BERTHA,
        "--node",
        &validator_one_rpc,
    ]);

    let mut client =
        run!(test, Bin::Client, submit_proposal_vote_delagator, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 11. Query the proposal and check the result
    let mut epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    while epoch.0 <= 25 {
        sleep(10);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    let query_proposal = vec![
        "query-proposal-result",
        "--proposal-id",
        "0",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, query_proposal, Some(15))?;
    client.exp_string("Proposal Id: 0")?;
    client.exp_string(
        "Passed with 100000.000000 yay votes, 900.000000 nay votes and \
         0.000000 abstain votes, total voting power: 100900.000000, threshold \
         (fraction) of total voting power needed to tally: 40360.000000 (0.4)",
    )?;
    client.assert_success();

    // 12. Wait proposal grace and check proposal author funds
    let mut epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    while epoch.0 < 31 {
        sleep(10);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, query_balance_args, Some(30))?;
    client.exp_string("nam: 200000")?;
    client.assert_success();

    // 13. Check if governance funds are 0
    let query_balance_args = vec![
        "balance",
        "--owner",
        GOVERNANCE_ADDRESS,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, query_balance_args, Some(30))?;
    client.exp_string("nam: 0")?;
    client.assert_success();

    // 13. Check the shielded rewards token info
    let query_masp_rewards =
        vec!["masp-reward-tokens", "--node", &validator_one_rpc];

    let mut client = run!(test, Bin::Client, query_masp_rewards, Some(30))?;
    client.exp_regex(".*Max reward rate: 0.05.*")?;
    client.assert_success();

    Ok(())
}

/// Test sync with a chain.
///
/// The chain ID must be set via `NAMADA_CHAIN_ID` env var.
/// Additionally, `NAMADA_SEED_NODES` maybe be specified with a comma-separated
/// list of addresses that must be parsable into `TendermintAddress`.
///
/// To run this test use `--ignored`.
#[test]
#[ignore = "This test is only ran when explicitly triggered"]
fn test_sync_chain() -> Result<()> {
    let chain_id_raw = std::env::var(ENV_VAR_CHAIN_ID).unwrap_or_else(|_| {
        panic!("Set `{ENV_VAR_CHAIN_ID}` env var to sync with.")
    });
    let chain_id = ChainId::from_str(chain_id_raw.trim())?;
    let working_dir = setup::working_dir();
    let test_dir = setup::TestDir::new();
    let test = Test {
        working_dir,
        test_dir,
        net: setup::Network { chain_id },
        async_runtime: Default::default(),
    };
    let base_dir = test.test_dir.path();

    // Setup the chain
    let mut join_network = setup::run_cmd(
        Bin::Client,
        ["utils", "join-network", "--chain-id", chain_id_raw.as_str()],
        Some(60),
        &test.working_dir,
        base_dir,
        format!("{}:{}", std::file!(), std::line!()),
    )?;
    join_network.exp_string("Successfully configured for chain")?;
    join_network.assert_success();

    if cfg!(debug_assertions) {
        let res: Result<Vec<TendermintAddress>, _> =
            deserialize_comma_separated_list(
                "tcp://9202be72cfe612af24b43f49f53096fc5512cd7f@194.163.172.\
                 168:26656,tcp://0edfd7e6a1a172864ddb76a10ea77a8bb242759a@65.\
                 21.194.46:36656",
            );
        debug_assert!(res.is_ok(), "Expected Ok, got {res:#?}");
    }
    // Add seed nodes if any given
    if let Ok(seed_nodes) = std::env::var(ENV_VAR_NAMADA_SEED_NODES) {
        let mut config = namada_apps_lib::config::Config::load(
            base_dir,
            &test.net.chain_id,
            None,
        );
        let seed_nodes: Vec<TendermintAddress> =
            deserialize_comma_separated_list(&seed_nodes).unwrap_or_else(
                |_| {
                    panic!(
                        "Invalid `{ENV_VAR_NAMADA_SEED_NODES}` value. Must be \
                         a valid `TendermintAddress`."
                    )
                },
            );
        config.ledger.cometbft.p2p.seeds.extend(seed_nodes);
        config.write(base_dir, &test.net.chain_id, true).unwrap();
    }

    // Start a non-validator node
    let mut ledger = start_namada_ledger_node_wait_wasm(
        &test,
        None,
        // init-chain may take a long time for large setups
        Some(1200),
    )?;
    ledger.exp_string("finalize_block: Block height: 1")?;
    let _bg_ledger = ledger.background();

    // Wait to be synced
    loop {
        let mut client = run!(test, Bin::Client, ["status"], Some(30))?;
        if client.exp_string("catching_up: false").is_ok() {
            println!("Node is synced!");
            break;
        } else {
            let sleep_secs = 300;
            println!("Not synced yet. Sleeping for {sleep_secs} secs.");
            sleep(sleep_secs);
        }
    }

    Ok(())
}

/// Deserialize a comma separated list of types that impl `FromStr` as a `Vec`
/// from a string. Same as `tendermint-config/src/config.rs` list
/// deserialization.
fn deserialize_comma_separated_list<T, E>(
    list: &str,
) -> serde_json::Result<Vec<T>>
where
    T: FromStr<Err = E>,
    E: Display,
{
    use serde::de::Error;

    let mut result = vec![];

    if list.is_empty() {
        return Ok(result);
    }

    for item in list.split(',') {
        result.push(
            item.parse()
                .map_err(|e| serde_json::Error::custom(format!("{e}")))
                .unwrap(),
        );
    }

    Ok(result)
}

#[test]
fn rollback() -> Result<()> {
    let test = setup::network(
        |genesis, base_dir| {
            setup::set_validators(
                1,
                genesis,
                base_dir,
                default_port_offset,
                vec![],
            )
        },
        // slow block production rate
        Some("5s"),
    )?;
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node once
    let mut ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?;

    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    // wait for a commited block
    ledger.exp_regex("Committed block hash: .*,")?;

    let ledger = ledger.background();

    // send a few transactions
    let txs_args = vec![apply_use_device(vec![
        "transparent-transfer",
        "--source",
        BERTHA,
        "--target",
        ALBERT,
        "--token",
        NAM,
        "--amount",
        "10.1",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_one_rpc,
    ])];

    for tx_args in &txs_args {
        let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
        client.exp_string(TX_APPLIED_SUCCESS)?;
        client.assert_success();
    }

    // shut the ledger down
    let mut ledger = ledger.foreground();
    ledger.interrupt()?;
    drop(ledger);

    // restart and take the app hash + height
    // TODO: check that the height matches the one at which the last transaction
    // was applied
    let mut ledger = start_namada_ledger_node(&test, Some(0), Some(40))?;
    let (_, matched_one) =
        ledger.exp_regex("Last state root hash: .*, height: .*")?;

    // wait for a block and stop the ledger
    ledger.exp_regex("Committed block hash: .*,")?;
    ledger.interrupt()?;
    drop(ledger);

    // run rollback
    let mut rollback = run_as!(
        test,
        Who::Validator(0),
        Bin::Node,
        &["ledger", "rollback"],
        Some(40)
    )?;
    rollback.exp_eof().unwrap();

    // restart ledger and check that the app hash is the same as before the
    // rollback
    let mut ledger = start_namada_ledger_node(&test, Some(0), Some(40))?;
    let (_, matched_two) =
        ledger.exp_regex("Last state root hash: .*, height: .*")?;

    assert_eq!(matched_one, matched_two);

    Ok(())
}

/// We test shielding, shielded to shielded and unshielding transfers:
/// 1. Run the ledger node
/// 2. Shield 20 BTC from Albert to PA(A)
/// 3. Transfer 7 BTC from SK(A) to PA(B)
/// 4. Assert BTC balance at VK(A) is 13
/// 5. Unshield 5 BTC from SK(B) to Bertha
/// 6. Assert BTC balance at VK(B) is 2
///
/// NOTE: We need this test to verify the correctness of the proofs generation
/// and verification process because integration tests use mocks.
#[test]
fn masp_txs_and_queries() -> Result<()> {
    // Lengthen epoch to ensure that a transaction can be constructed and
    // submitted within the same block. Necessary to ensure that conversion is
    // not invalidated.
    let test = setup::network(
        |mut genesis, base_dir| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(3600);
            genesis.parameters.parameters.min_num_of_blocks = 1;
            setup::set_validators(
                1,
                genesis,
                base_dir,
                default_port_offset,
                vec![],
            )
        },
        None,
    )?;

    // If used, keep Speculos alive for duration of the test
    let _speculos = if hw_wallet_automation::uses_automation() {
        // Gen automation for Speculos
        let automation =
            hw_wallet_automation::gen_automation_e2e_masp_tx_and_queries();
        let json = serde_json::to_vec_pretty(&automation).unwrap();
        let path = test.test_dir.path().join("automation.json");
        std::fs::write(&path, json).unwrap();

        // Start Speculos with the automation
        Some(Speculos::spawn(&path))
    } else {
        None
    };

    // Run all cmds on the first validator
    let who = Who::Validator(0);
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        who,
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let rpc_address = get_actor_rpc(&test, who);
    wait_for_block_height(&test, &rpc_address, 1, 30)?;

    // add necessary viewing keys to shielded context
    let mut sync = run_as!(
        test,
        who,
        Bin::Client,
        vec![
            "shielded-sync",
            "--viewing-keys",
            AA_VIEWING_KEY,
            AB_VIEWING_KEY,
            "--node",
            &rpc_address,
        ],
        Some(15),
    )?;
    sync.assert_success();
    let txs_args = vec![
        // 2. Shield 20 BTC from Albert to PA(A)
        (
            apply_use_device(vec![
                "shield",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "--shielding-fee-payer",
                ALBERT_KEY,
                "--shielding-token",
                NAM,
                "20",
            ]),
            TX_APPLIED_SUCCESS,
        ),
        // 3. Transfer 7 BTC from SK(A) to PA(B)
        (
            apply_use_device(vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "7",
                "--gas-payer",
                CHRISTEL_KEY,
            ]),
            TX_APPLIED_SUCCESS,
        ),
        // 4. Assert BTC balance at VK(A) is 13
        (
            vec!["balance", "--owner", AA_VIEWING_KEY, "--token", BTC],
            "btc: 13",
        ),
        // 5. Unshield 5 BTC from SK(B) to Bertha
        (
            apply_use_device(vec![
                "unshield",
                "--source",
                B_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                BTC,
                "--amount",
                "5",
                "--gas-payer",
                CHRISTEL_KEY,
            ]),
            TX_APPLIED_SUCCESS,
        ),
        // 6. Assert BTC balance at VK(B) is 2
        (
            vec!["balance", "--owner", AB_VIEWING_KEY, "--token", BTC],
            "btc: 2",
        ),
    ];

    for (tx_args, tx_result) in &txs_args {
        // sync shielded context
        let mut sync = run_as!(
            test,
            who,
            Bin::Client,
            vec!["shielded-sync", "--node", &rpc_address],
            Some(15),
        )?;
        sync.assert_success();
        for &dry_run in &[true, false] {
            if dry_run && is_use_device() {
                continue;
            }
            let tx_args = if dry_run
                && (tx_args[0] == "transfer"
                    || tx_args[0] == "shield"
                    || tx_args[0] == "unshield")
            {
                [tx_args.clone(), vec!["--dry-run"]].concat()
            } else {
                tx_args.clone()
            };
            let mut client =
                run_as!(test, who, Bin::Client, tx_args, Some(720))?;

            client.exp_string(tx_result)?;
        }
    }

    Ok(())
}

/// Test localnet genesis files with `namada node utils test-genesis` command.
#[test]
fn test_localnet_genesis() -> Result<()> {
    let base_dir = setup::TestDir::new();
    let working_dir = working_dir();
    let genesis_path = wallet::defaults::derive_template_dir(&working_dir);
    let wasm_dir = working_dir.join(config::DEFAULT_WASM_DIR);

    // Path to the localnet "pre-genesis" wallet
    let pre_genesis_wallet = genesis_path
        .join("src")
        .join(PRE_GENESIS_DIR)
        .join("wallet.toml");
    // Copy the pre-genesis wallet into the base-dir
    let base_pre_genesis = base_dir.path().join(PRE_GENESIS_DIR);
    std::fs::create_dir(&base_pre_genesis).unwrap();
    std::fs::copy(pre_genesis_wallet, base_pre_genesis.join("wallet.toml"))
        .unwrap();

    let mut test_genesis_result = setup::run_cmd(
        Bin::Node,
        [
            "utils",
            "test-genesis",
            "--path",
            &genesis_path.to_string_lossy(),
            "--wasm-dir",
            &wasm_dir.to_string_lossy(),
            "--check-can-sign",
            // Albert established addr (from `genesis/localnet/balances.toml`)
            "tnam1qxfj3sf6a0meahdu9t6znp05g8zx4dkjtgyn9gfu",
            // Daewon implicit addr (from `genesis/localnet/balances.toml`)
            "tnam1qpca48f45pdtpcz06rue7k4kfdcjrvrux5cr3pwn",
            // Validator account key (from `genesis/localnet/transactions.toml`)
            "tpknam1qpg2tsrplvhu3fd7z7tq5ztc2ne3s7e2ahjl2a2cddufrzdyr752g666ytj",
        ],
        Some(30),
        &working_dir,
        &base_dir,
        format!("{}:{}", std::file!(), std::line!()),
    )?;
    test_genesis_result
        .exp_string("Genesis files were dry-run successfully")?;
    test_genesis_result.exp_string("Able to sign with")?;
    test_genesis_result.exp_string("Able to sign with")?;
    test_genesis_result.exp_string("Able to sign with")?;

    // Use a non-default "NAMADA_GENESIS_TX_CHAIN_ID"
    env::set_var(
        config::genesis::transactions::NAMADA_GENESIS_TX_ENV_VAR,
        "e2e-test-genesis",
    );

    let mut test_genesis_result = setup::run_cmd(
        Bin::Node,
        [
            "utils",
            "test-genesis",
            "--path",
            &genesis_path.to_string_lossy(),
            "--wasm-dir",
            &wasm_dir.to_string_lossy(),
        ],
        Some(30),
        &working_dir,
        &base_dir,
        format!("{}:{}", std::file!(), std::line!()),
    )?;
    // Signature should be invalid now
    test_genesis_result.exp_string("Invalid validator account signature")?;
    test_genesis_result.exp_string("Invalid bond tx signature")?;
    test_genesis_result.exp_string("Invalid bond tx signature")?;
    test_genesis_result.assert_failure();

    Ok(())
}

/// Test change of genesis chain ID via "NAMADA_GENESIS_TX_CHAIN_ID" env var
#[test]
fn test_genesis_chain_id_change() -> Result<()> {
    // Use a non-default "NAMADA_GENESIS_TX_CHAIN_ID"
    env::set_var(
        config::genesis::transactions::NAMADA_GENESIS_TX_ENV_VAR,
        "e2e-test-genesis",
    );

    let working_dir = working_dir();
    let wasm_dir = working_dir.join(config::DEFAULT_WASM_DIR);

    let test = setup::network(
        |mut genesis, base_dir: &_| {
            // Empty the transactions as their signatures are invalid - created
            // with the default genesis chain ID
            genesis.transactions = Default::default();
            genesis.parameters.pgf_params.stewards = Default::default();

            setup::set_validators(1, genesis, base_dir, |_| 0u16, vec![])
        },
        None,
    )
    .unwrap();

    let genesis_templates = test.test_dir.path().join("templates");
    let base_dir = test.get_base_dir(Who::Validator(0));
    let mut test_genesis_result = setup::run_cmd(
        Bin::Node,
        [
            "utils",
            "test-genesis",
            "--path",
            &genesis_templates.to_string_lossy(),
            "--wasm-dir",
            &wasm_dir.to_string_lossy(),
        ],
        Some(30),
        &working_dir,
        &base_dir,
        format!("{}:{}", std::file!(), std::line!()),
    )?;
    test_genesis_result
        .exp_string("Genesis files were dry-run successfully")?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // Unset the chain ID - the transaction signatures have been validated at
    // init-network so we don't need it anymore
    env::remove_var(config::genesis::transactions::NAMADA_GENESIS_TX_ENV_VAR);
    // Start the ledger as a validator
    let _bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let rpc = get_actor_rpc(&test, Who::Validator(0));
    wait_for_block_height(&test, &rpc, 2, 30)?;

    Ok(())
}

/// Test that any changes done to a genesis config after a chain is finalized
/// will make it fail validation.
#[test]
fn test_genesis_manipulation() -> Result<()> {
    let test = setup::single_node_net().unwrap();

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    let chain_dir = test.get_chain_dir(Who::Validator(0));
    let genesis = chain::Finalized::read_toml_files(&chain_dir).unwrap();

    let modified_genesis = [
        {
            let mut genesis = genesis.clone();
            genesis
                .balances
                .token
                .insert(Alias::from("test"), TokenBalances(Default::default()));
            genesis
        },
        {
            let mut genesis = genesis.clone();
            genesis.balances.token.remove(&Alias::from("NAM"));
            genesis
        },
        {
            let mut genesis = genesis.clone();
            genesis.metadata.address_gen = None;
            genesis
        },
        {
            let mut genesis = genesis.clone();
            // Invalid chain ID
            genesis.metadata.chain_id = ChainId("Invalid ID".to_string());
            genesis
        },
        {
            let mut genesis = genesis.clone();
            // Random valid chain ID
            genesis.metadata.chain_id = ChainId::from_genesis(
                ChainIdPrefix::from_str("TEST").unwrap(),
                [1, 2, 3],
            );
            genesis
        },
    ];

    for genesis in modified_genesis {
        // Any modification should invalide the genesis
        assert!(!genesis.is_valid());

        genesis.write_toml_files(&chain_dir).unwrap();

        // A node should fail to start-up
        let result =
            start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40));
        assert!(result.is_err())
    }

    Ok(())
}
