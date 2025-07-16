//! E2E test helpers

use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{env, time};

use borsh::BorshDeserialize;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use data_encoding::HEXLOWER;
use escargot::CargoBuild;
use eyre::eyre;
use namada_apps_lib::cli::context::ENV_VAR_CHAIN_ID;
use namada_apps_lib::config::utils::convert_tm_addr_to_socket_addr;
use namada_apps_lib::config::{Config, TendermintMode};
use namada_core::token::NATIVE_MAX_DECIMAL_PLACES;
use namada_sdk::address::Address;
use namada_sdk::chain::Epoch;
use namada_sdk::key::*;
use namada_sdk::queries::{RPC, Rpc};
use namada_sdk::tendermint_rpc::HttpClient;
use namada_sdk::token;
use namada_sdk::wallet::Wallet;
use namada_sdk::wallet::fs::FsWalletUtils;
use toml::Value;

use super::setup::{
    self, ENV_VAR_DEBUG, ENV_VAR_USE_PREBUILT_BINARIES, NamadaBgCmd, NamadaCmd,
    Test, TestDir, run_cosmos_cmd, sleep,
};
use crate::e2e::setup::{APPS_PACKAGE, Bin, CosmosChainType, Who, constants};
use crate::strings::{LEDGER_STARTED, TX_APPLIED_SUCCESS};
use crate::{run, run_as};

/// Instantiate a new [`HttpClient`] to perform RPC requests with.
#[allow(dead_code)]
pub async fn rpc_client_do<'fut, 'usr, U, A, F, R>(
    ledger_address: &str,
    user_data: U,
    mut action: A,
) -> R
where
    'usr: 'fut,
    U: 'usr,
    A: FnMut(Rpc, HttpClient, U) -> F,
    F: Future<Output = R> + 'fut,
{
    let client =
        HttpClient::new(ledger_address).expect("Invalid ledger address");
    action(RPC, client, user_data).await
}

/// Sets up a test chain with a single validator node running in the background,
/// and returns the [`Test`] handle and [`NamadaBgCmd`] for the validator node.
/// It blocks until the node is ready to receive RPC requests from
/// `namadac`.
#[allow(dead_code)]
pub fn setup_single_node_test() -> Result<(Test, NamadaBgCmd)> {
    let test = setup::single_node_net()?;
    run_single_node_test_from(test)
}

/// Same as [`setup_single_node_test`], but use a pre-existing test directory.
pub fn run_single_node_test_from(test: Test) -> Result<(Test, NamadaBgCmd)> {
    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, &["ledger"], Some(40))?;
    ledger.exp_string(LEDGER_STARTED)?;
    // TODO(namada#867): we only need to wait until the RPC server is available,
    // not necessarily for a block to be committed
    // ledger.exp_string("Starting RPC HTTP server on")?;
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    Ok((test, ledger.background()))
}

/// Initialize an established account.
#[allow(dead_code)]
pub fn init_established_account(
    test: &Test,
    rpc_addr: &str,
    source_alias: &str,
    key_alias: &str,
    established_alias: &str,
) -> Result<()> {
    let init_account_args = vec![
        "init-account",
        "--source",
        source_alias,
        "--public-key",
        key_alias,
        "--alias",
        established_alias,
        "--ledger-address",
        rpc_addr,
    ];
    let mut cmd = run!(test, Bin::Client, init_account_args, Some(40))?;
    cmd.exp_string(TX_APPLIED_SUCCESS)?;
    cmd.assert_success();
    Ok(())
}

/// Find the address of an account by its alias from the wallet
pub fn find_address(test: &Test, alias: impl AsRef<str>) -> Result<Address> {
    let mut find = run!(
        test,
        Bin::Wallet,
        &["find", "--addr", "--alias", alias.as_ref()],
        Some(10)
    )?;
    find.exp_string("Found transparent address:")?;
    let (unread, matched) = find.exp_regex("\".*\": .*")?;
    let address_str = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let address = Address::from_str(address_str).map_err(|e| {
        eyre!(format!(
            "Address: {} parsed from {}, Error: {}\n\nOutput: {}",
            address_str, matched, e, unread
        ))
    })?;
    println!("Found {}", address);
    Ok(address)
}

/// Find the balance of specific token for an account.
#[allow(dead_code)]
pub fn find_balance(
    test: &Test,
    node: Who,
    token: &Address,
    owner: &Address,
) -> Result<token::Amount> {
    let ledger_address = get_actor_rpc(test, node);
    let balance_key = token::storage_key::balance_key(token, owner);
    let mut bytes = run!(
        test,
        Bin::Client,
        &[
            "query-bytes",
            "--storage-key",
            &balance_key.to_string(),
            "--ledger-address",
            &ledger_address,
        ],
        Some(10)
    )?;
    let (_, matched) = bytes.exp_regex("Found data: 0x.*")?;
    let data_str = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1[2..]
        .to_string();
    let amount =
        token::Amount::try_from_slice(&HEXLOWER.decode(data_str.as_bytes())?)?;
    bytes.assert_success();
    Ok(amount)
}

/// Find the address of the node's RPC endpoint.
pub fn get_actor_rpc(test: &Test, who: Who) -> String {
    let base_dir = test.get_base_dir(who);
    let tendermint_mode = match who {
        Who::NonValidator => TendermintMode::Full,
        Who::Validator(_) => TendermintMode::Validator,
    };
    let config =
        Config::load(base_dir, &test.net.chain_id, Some(tendermint_mode));
    let socket_addr =
        convert_tm_addr_to_socket_addr(&config.ledger.cometbft.rpc.laddr);
    format!("http://{}:{}", socket_addr.ip(), socket_addr.port())
}

/// Get a pregenesis wallet.
pub fn get_pregenesis_wallet<P: AsRef<Path>>(
    base_dir_path: P,
) -> Wallet<FsWalletUtils> {
    let mut wallet_store_dir = base_dir_path.as_ref().to_path_buf();
    wallet_store_dir.push("pre-genesis");

    let mut wallet = FsWalletUtils::new(wallet_store_dir);
    wallet.load().expect("Failed to load wallet");

    wallet
}

/// Find the address of an account by its alias from the wallet
#[allow(dead_code)]
pub fn find_keypair(
    test: &Test,
    alias: impl AsRef<str>,
) -> Result<common::SecretKey> {
    let mut find = run!(
        test,
        Bin::Wallet,
        &[
            "find",
            "--keys",
            "--alias",
            alias.as_ref(),
            "--decrypt",
            "--unsafe-show-secret"
        ],
        Some(10)
    )?;
    let (_unread, matched) = find.exp_regex("Public key: .*")?;
    let pk = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let (unread, matched) = find.exp_regex("Secret key: .*")?;
    let sk = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let key = format!("{}{}", sk, pk);
    common::SecretKey::from_str(sk).map_err(|e| {
        eyre!(format!(
            "Key: {} parsed from {}, Error: {}\n\nOutput: {}",
            key, matched, e, unread
        ))
    })
}

/// Find the bonded stake of an account by its alias from the wallet
pub fn find_bonded_stake(
    test: &Test,
    alias: impl AsRef<str>,
    ledger_address: &str,
) -> Result<token::Amount> {
    let mut find = run!(
        test,
        Bin::Client,
        &[
            "bonded-stake",
            "--validator",
            alias.as_ref(),
            "--node",
            ledger_address
        ],
        Some(10)
    )?;
    let (unread, matched) = find.exp_regex("Bonded stake of validator .*")?;
    let bonded_stake_str = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    token::Amount::from_str(bonded_stake_str, NATIVE_MAX_DECIMAL_PLACES)
        .map_err(|e| {
            eyre!(format!(
                "Bonded stake: {} parsed from {}, Error: {}\n\nOutput: {}",
                bonded_stake_str, matched, e, unread
            ))
        })
}

/// Get the last committed epoch.
pub fn get_epoch(test: &Test, ledger_address: &str) -> Result<Epoch> {
    let mut find = run!(
        test,
        Bin::Client,
        &["epoch", "--node", ledger_address],
        Some(20)
    )?;
    let (unread, matched) = find.exp_regex("Last committed epoch: .*")?;
    let epoch_str = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let epoch = u64::from_str(epoch_str).map_err(|e| {
        eyre!(format!(
            "Epoch: {} parsed from {}, Error: {}\n\nOutput: {}",
            epoch_str, matched, e, unread
        ))
    })?;
    Ok(Epoch(epoch))
}

/// Get the last committed block height.
pub fn get_height(test: &Test, ledger_address: &str) -> Result<u64> {
    let mut find = run!(
        test,
        Bin::Client,
        &["block", "--node", ledger_address],
        Some(10)
    )?;
    let (unread, matched) =
        find.exp_regex("Last committed block height: .*")?;
    // Expected `matched` string is e.g.:
    //
    // ```
    // Last committed block height: 4, time: 2022-10-20T10:52:28.828745Z
    // ```
    let height_str = strip_trailing_newline(&matched)
        .trim()
        // Find the height part ...
        .split_once("height: ")
        .unwrap()
        // ... take what's after it ...
        .1
        // ... find the next comma ...
        .rsplit_once(',')
        .unwrap()
        // ... and take what's before it.
        .0;
    u64::from_str(height_str).map_err(|e| {
        eyre!(format!(
            "Height parsing failed from {} trimmed from {}, Error: \
             {}\n\nUnread output: {}",
            height_str, matched, e, unread
        ))
    })
}

/// Sleep until the given height is reached or panic when time out is reached
/// before the height
pub fn wait_for_block_height(
    test: &Test,
    ledger_address: &str,
    height: u64,
    timeout_secs: u64,
) -> Result<()> {
    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();
    let loop_timeout = Duration::new(timeout_secs, 0);
    loop {
        let current = get_height(test, ledger_address)?;
        if current >= height {
            break Ok(());
        }
        #[allow(clippy::disallowed_methods)]
        if Instant::now().duration_since(start) > loop_timeout {
            return Err(eyre!(
                "Timed out waiting for height {height}, current {current}"
            ));
        }
        sleep(1);
    }
}

/// Are the E2E tests be running in debug mode?
pub fn is_debug_mode() -> bool {
    match env::var(ENV_VAR_DEBUG) {
        Ok(val) => !val.eq_ignore_ascii_case("false"),
        _ => false,
    }
}

pub fn generate_bin_command(bin_name: &str, manifest_path: &Path) -> Command {
    let use_prebuilt_binaries = match env::var(ENV_VAR_USE_PREBUILT_BINARIES) {
        Ok(var) => !var.eq_ignore_ascii_case("false"),
        Err(_) => false,
    };

    // Allow to run in debug
    let run_debug = is_debug_mode();

    if !use_prebuilt_binaries {
        let build_cmd = CargoBuild::new()
            .package(APPS_PACKAGE)
            .manifest_path(manifest_path)
            .bin(bin_name);

        let build_cmd = if run_debug {
            build_cmd
        } else {
            // Use the same build settings as `make build-release`
            build_cmd.release()
        };

        #[allow(clippy::disallowed_methods)]
        let now = time::Instant::now();
        // ideally we would print the compile command here, but escargot doesn't
        // implement Display or Debug for CargoBuild
        println!(
            "\n{}: {}",
            "`cargo build` starting".underline().bright_blue(),
            bin_name
        );

        let command = build_cmd.run().unwrap();
        println!(
            "\n{}: {}ms",
            "`cargo build` finished after".underline().bright_blue(),
            now.elapsed().as_millis()
        );

        command.command()
    } else {
        let dir = if run_debug {
            format!("target/debug/{}", bin_name)
        } else {
            format!("target/release/{}", bin_name)
        };
        println!(
            "\n{}: {}",
            "Running prebuilt binaries from".underline().green(),
            dir
        );
        std::process::Command::new(dir)
    }
}

pub(crate) fn strip_trailing_newline(input: &str) -> &str {
    input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(input)
}

/// Sleep until the next epoch starts
pub fn epoch_sleep(
    test: &Test,
    ledger_address: &str,
    timeout_secs: u64,
) -> Result<Epoch> {
    let mut find = run!(
        test,
        Bin::Client,
        &["utils", "epoch-sleep", "--node", ledger_address],
        Some(timeout_secs)
    )?;
    parse_reached_epoch(&mut find)
}

pub fn parse_reached_epoch(find: &mut NamadaCmd) -> Result<Epoch> {
    let (unread, matched) = find.exp_regex("Reached epoch .*")?;
    let epoch_str = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let epoch = u64::from_str(epoch_str).map_err(|e| {
        eyre!(format!(
            "Epoch: {} parsed from {}, Error: {}\n\nOutput: {}",
            epoch_str, matched, e, unread
        ))
    })?;
    Ok(Epoch(epoch))
}

/// Wait for txs and VPs WASM compilations to finish. This is useful to avoid a
/// timeout when submitting a first tx.
pub fn wait_for_wasm_pre_compile(ledger: &mut NamadaCmd) -> Result<()> {
    ledger.exp_string("Finished compiling all")?;
    ledger.exp_string("Finished compiling all")?;
    Ok(())
}

/// Convert epoch `min_duration` in seconds to `epochs_per_year` genesis
/// parameter.
pub fn epochs_per_year_from_min_duration(min_duration: u64) -> u64 {
    60 * 60 * 24 * 365 / min_duration
}

/// Make a Hermes config
pub fn make_hermes_config(
    hermes_dir: &TestDir,
    test_a: &Test,
    test_b: &Test,
    relayer: Option<&str>,
) -> Result<()> {
    let mut config = toml::map::Map::new();

    let mut global = toml::map::Map::new();
    global.insert("log_level".to_owned(), Value::String("debug".to_owned()));
    config.insert("global".to_owned(), Value::Table(global));

    let mut mode = toml::map::Map::new();
    let mut clients = toml::map::Map::new();
    clients.insert("enabled".to_owned(), Value::Boolean(true));
    clients.insert("refresh".to_owned(), Value::Boolean(true));
    clients.insert("misbehaviour".to_owned(), Value::Boolean(true));
    mode.insert("clients".to_owned(), Value::Table(clients));

    let mut connections = toml::map::Map::new();
    connections.insert("enabled".to_owned(), Value::Boolean(false));
    mode.insert("connections".to_owned(), Value::Table(connections));

    let mut channels = toml::map::Map::new();
    channels.insert("enabled".to_owned(), Value::Boolean(false));
    mode.insert("channels".to_owned(), Value::Table(channels));

    let mut packets = toml::map::Map::new();
    packets.insert("enabled".to_owned(), Value::Boolean(true));
    packets.insert("clear_interval".to_owned(), Value::Integer(30));
    packets.insert("clear_on_start".to_owned(), Value::Boolean(true));
    packets.insert("tx_confirmation".to_owned(), Value::Boolean(true));
    mode.insert("packets".to_owned(), Value::Table(packets));

    config.insert("mode".to_owned(), Value::Table(mode));

    let mut telemetry = toml::map::Map::new();
    telemetry.insert("enabled".to_owned(), Value::Boolean(false));
    telemetry.insert("host".to_owned(), Value::String("127.0.0.1".to_owned()));
    telemetry.insert("port".to_owned(), Value::Integer(3001));
    config.insert("telemetry".to_owned(), Value::Table(telemetry));

    let chains = vec![
        match CosmosChainType::chain_type(test_a.net.chain_id.as_str()) {
            Ok(chain_type) => make_hermes_chain_config_for_cosmos(
                hermes_dir, chain_type, test_a, relayer,
            ),
            Err(_) => make_hermes_chain_config(hermes_dir, test_a),
        },
        match CosmosChainType::chain_type(test_b.net.chain_id.as_str()) {
            Ok(chain_type) => make_hermes_chain_config_for_cosmos(
                hermes_dir, chain_type, test_b, relayer,
            ),
            Err(_) => make_hermes_chain_config(hermes_dir, test_b),
        },
    ];

    config.insert("chains".to_owned(), Value::Array(chains));

    let toml_string = toml::to_string(&Value::Table(config)).unwrap();
    let hermes_dir = hermes_dir.as_ref().join("hermes");
    std::fs::create_dir_all(&hermes_dir).unwrap();
    let config_path = hermes_dir.join("config.toml");
    let mut file = File::create(config_path).unwrap();
    file.write_all(toml_string.as_bytes()).map_err(|e| {
        eyre!(format!("Writing a Hermes config failed: {}", e,))
    })?;

    Ok(())
}

fn make_hermes_chain_config(hermes_dir: &TestDir, test: &Test) -> Value {
    let chain_id = test.net.chain_id.as_str();
    let rpc_addr = get_actor_rpc(test, Who::Validator(0));
    let rpc_addr = rpc_addr.strip_prefix("http://").unwrap();

    let mut table = toml::map::Map::new();
    table.insert("mode".to_owned(), Value::String("push".to_owned()));
    let url = format!("ws://{}/websocket", rpc_addr);
    table.insert("url".to_owned(), Value::String(url));
    table.insert("batch_delay".to_owned(), Value::String("500ms".to_owned()));
    let event_source = Value::Table(table);

    let mut chain = toml::map::Map::new();
    chain.insert("id".to_owned(), Value::String(chain_id.to_owned()));
    chain.insert("type".to_owned(), Value::String("Namada".to_owned()));
    chain.insert(
        "rpc_addr".to_owned(),
        Value::String(format!("http://{rpc_addr}")),
    );
    // The grpc isn't used for Namada, but it's required
    chain.insert(
        "grpc_addr".to_owned(),
        Value::String("http://127.0.0.1:9090".to_owned()),
    );
    chain.insert("event_source".to_owned(), event_source);
    chain.insert("account_prefix".to_owned(), Value::String("".to_owned()));
    chain.insert(
        "key_name".to_owned(),
        Value::String(constants::FRANK_KEY.to_owned()),
    );
    chain.insert("store_prefix".to_owned(), Value::String("ibc".to_owned()));
    let mut table = toml::map::Map::new();
    table.insert("price".to_owned(), Value::Float(0.000001));
    std::env::set_var(ENV_VAR_CHAIN_ID, test.net.chain_id.to_string());
    let nam_addr = find_address(test, setup::constants::NAM).unwrap();
    table.insert("denom".to_owned(), Value::String(nam_addr.to_string()));
    chain.insert("gas_price".to_owned(), Value::Table(table));

    chain.insert("max_block_time".to_owned(), Value::String("60s".to_owned()));

    let hermes_dir: &Path = hermes_dir.as_ref();
    let key_dir = hermes_dir.join("hermes/keys");
    chain.insert(
        "key_store_folder".to_owned(),
        Value::String(key_dir.to_string_lossy().to_string()),
    );

    Value::Table(chain)
}

fn make_hermes_chain_config_for_cosmos(
    hermes_dir: &TestDir,
    chain_type: CosmosChainType,
    test: &Test,
    relayer: Option<&str>,
) -> Value {
    let mut table = toml::map::Map::new();
    table.insert("mode".to_owned(), Value::String("push".to_owned()));
    let url = format!(
        "ws://127.0.0.1:{}/websocket",
        chain_type.get_rpc_port_number()
    );
    table.insert("url".to_owned(), Value::String(url));
    table.insert("batch_delay".to_owned(), Value::String("500ms".to_owned()));
    let event_source = Value::Table(table);

    let mut chain = toml::map::Map::new();
    chain.insert(
        "id".to_owned(),
        Value::String(test.net.chain_id.to_string()),
    );
    chain.insert("type".to_owned(), Value::String("CosmosSdk".to_owned()));

    chain.insert(
        "rpc_addr".to_owned(),
        Value::String(format!(
            "http://127.0.0.1:{}",
            chain_type.get_rpc_port_number()
        )),
    );
    chain.insert(
        "grpc_addr".to_owned(),
        Value::String(format!(
            "http://127.0.0.1:{}",
            chain_type.get_grpc_port_number()
        )),
    );

    chain.insert("event_source".to_owned(), event_source);
    chain.insert(
        "account_prefix".to_owned(),
        Value::String(chain_type.account_prefix().to_string()),
    );
    chain.insert(
        "key_name".to_owned(),
        Value::String(relayer.unwrap_or(constants::COSMOS_RELAYER).to_string()),
    );
    let hermes_dir: &Path = hermes_dir.as_ref();
    let key_dir = hermes_dir.join("hermes/keys");
    chain.insert(
        "key_store_folder".to_owned(),
        Value::String(key_dir.to_string_lossy().to_string()),
    );
    chain.insert("store_prefix".to_owned(), Value::String("ibc".to_owned()));
    chain.insert("max_gas".to_owned(), Value::Integer(500_000_000));
    chain.insert("gas_multiplier".to_owned(), Value::Float(2.3));
    let mut table = toml::map::Map::new();
    if let CosmosChainType::Osmosis = chain_type {
        table.insert("price".to_owned(), Value::Float(0.01));
    } else {
        table.insert("price".to_owned(), Value::Float(0.001));
    }
    table.insert("denom".to_owned(), Value::String("stake".to_string()));
    chain.insert("gas_price".to_owned(), Value::Table(table));

    Value::Table(chain)
}

pub fn update_cosmos_config(test: &Test) -> Result<()> {
    let cosmos_dir = test.test_dir.as_ref().join(test.net.chain_id.as_str());
    let config_path = cosmos_dir.join("config/config.toml");
    let s = std::fs::read_to_string(&config_path)
        .expect("Reading Cosmos config failed");
    let mut values = s
        .parse::<toml::Value>()
        .expect("Parsing Cosmos config failed");
    if let Some(consensus) = values.get_mut("consensus") {
        if let Some(timeout_commit) = consensus.get_mut("timeout_commit") {
            *timeout_commit = "1s".into();
        }
        if let Some(timeout_propose) = consensus.get_mut("timeout_propose") {
            *timeout_propose = "1s".into();
        }
    }
    let chain_type =
        CosmosChainType::chain_type(test.net.chain_id.as_str()).unwrap();
    let p2p = values
        .get_mut("p2p")
        .expect("Test failed")
        .as_table_mut()
        .expect("Test failed");
    let Some(laddr) = p2p.get_mut("laddr") else {
        panic!("Test failed")
    };
    *laddr =
        format!("tcp://0.0.0.0:{}", chain_type.get_p2p_port_number()).into();
    let rpc = values
        .get_mut("rpc")
        .expect("Test failed")
        .as_table_mut()
        .expect("Test failed");
    let Some(laddr) = rpc.get_mut("laddr") else {
        panic!("Test failed")
    };
    *laddr =
        format!("tcp://0.0.0.0:{}", chain_type.get_rpc_port_number()).into();

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&config_path)?;
    file.write_all(
        toml::to_string(&values)
            .expect("Values should be converted")
            .as_bytes(),
    )
    .map_err(|e| {
        eyre!(format!("Writing a Cosmos config file failed: {}", e))
    })?;

    let app_path = cosmos_dir.join("config/app.toml");
    let s = std::fs::read_to_string(&app_path)
        .expect("Reading Cosmos app.toml failed");
    let mut values = s
        .parse::<toml::Value>()
        .expect("Parsing Cosmos app.toml failed");
    if let Some(mininum_gas_prices) = values.get_mut("minimum-gas-prices") {
        *mininum_gas_prices = "0.0001stake".into();
    }
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&app_path)?;
    file.write_all(
        toml::to_string(&values)
            .expect("Values should be converted")
            .as_bytes(),
    )
    .map_err(|e| eyre!(format!("Writing a Cosmos app.toml failed: {}", e)))?;

    let genesis_path = cosmos_dir.join("config/genesis.json");
    let s = std::fs::read_to_string(&genesis_path)
        .expect("Reading Cosmos genesis.json failed");
    let mut genesis: serde_json::Value =
        serde_json::from_str(&s).expect("Decoding Cosmos genesis.json failed");
    // gas
    if let Some(min_base_gas_price) =
        genesis.pointer_mut("/app_state/feemarket/params/min_base_gas_price")
    {
        *min_base_gas_price =
            serde_json::Value::String("0.000000000000000001".to_string());
    }
    if let Some(base_gas_price) =
        genesis.pointer_mut("/app_state/feemarket/state/base_gas_price")
    {
        *base_gas_price =
            serde_json::Value::String("0.000000000000000001".to_string());
    }
    // gov
    if let Some(max_deposit_period) =
        genesis.pointer_mut("/app_state/gov/params/max_deposit_period")
    {
        *max_deposit_period = serde_json::Value::String("10s".to_string());
    }
    if let Some(voting_period) =
        genesis.pointer_mut("/app_state/gov/params/voting_period")
    {
        *voting_period = serde_json::Value::String("10s".to_string());
    }

    let file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&genesis_path)?;
    let writer = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &genesis)
        .expect("Writing Cosmos genesis.json failed");

    if matches!(chain_type, CosmosChainType::Osmosis) {
        let client_path = cosmos_dir.join("config/client.toml");
        let s = std::fs::read_to_string(&client_path)
            .expect("Reading Osmosis client config failed");
        let mut values = s
            .parse::<toml::Value>()
            .expect("Parsing Osmosis client config failed");
        let Some(laddr) = values.get_mut("node") else {
            panic!("Test failed")
        };
        *laddr = format!("tcp://0.0.0.0:{}", chain_type.get_rpc_port_number())
            .into();
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&client_path)?;
        file.write_all(
            toml::to_string(&values)
                .expect("Values should be converted")
                .as_bytes(),
        )
        .map_err(|e| {
            eyre!(format!(
                "Writing a  Osmosis client config file failed: {}",
                e
            ))
        })?;
    }

    Ok(())
}

pub fn get_cosmos_rpc_address(test: &Test) -> String {
    let chain_type =
        CosmosChainType::chain_type(test.net.chain_id.as_str()).unwrap();
    format!("127.0.0.1:{}", chain_type.get_rpc_port_number())
}

pub fn find_cosmos_address(
    test: &Test,
    alias: impl AsRef<str>,
) -> Result<String> {
    let args = [
        "keys",
        "--keyring-backend",
        "test",
        "show",
        alias.as_ref(),
        "-a",
    ];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    let chain_type = CosmosChainType::chain_type(test.net.chain_id.as_str())?;
    let regex = format!("{}.*", chain_type.account_prefix());
    let (_, matched) = cosmos.exp_regex(&regex)?;

    Ok(matched.trim().to_string())
}

pub fn get_cosmos_gov_address(test: &Test) -> Result<String> {
    let rpc = format!("tcp://{}", get_cosmos_rpc_address(test));
    let args = ["query", "auth", "module-account", "gov", "--node", &rpc];
    let mut cosmos = run_cosmos_cmd(test, args, Some(40))?;
    let (_, matched) = cosmos.exp_regex("cosmos[a-z0-9]+")?;

    Ok(matched.trim().to_string())
}
