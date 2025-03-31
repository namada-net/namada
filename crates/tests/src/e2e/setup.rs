use std::ffi::OsStr;
use std::fmt::Display;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, thread, time};

use assert_cmd::assert::OutputAssertExt;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use expectrl::process::unix::{PtyStream, UnixProcess};
use expectrl::session::Session;
use expectrl::stream::log::LogStream;
use expectrl::{ControlCode, Eof, WaitStatus};
use eyre::eyre;
use itertools::{Either, Itertools, peek_nth};
use namada_apps_lib::cli::context::ENV_VAR_CHAIN_ID;
use namada_apps_lib::client::utils::{
    self, validator_pre_genesis_dir, validator_pre_genesis_txs_file,
};
use namada_apps_lib::config::genesis::utils::read_toml;
use namada_apps_lib::config::genesis::{templates, transactions};
use namada_apps_lib::config::{Config, ethereum_bridge, genesis};
use namada_apps_lib::wallet::defaults::{derive_template_dir, is_use_device};
use namada_apps_lib::{config, wallet};
use namada_core::address::Address;
use namada_core::collections::HashMap;
use namada_core::key::{RefTo, SchemeType};
use namada_core::string_encoding::StringEncoded;
use namada_core::token::NATIVE_MAX_DECIMAL_PLACES;
use namada_node::tendermint_config::net::Address as TendermintAddress;
use namada_sdk::chain::ChainId;
use namada_sdk::wallet::alias::Alias;
use namada_tx_prelude::token;
use once_cell::sync::Lazy;
use rand::Rng;
use rand::rngs::OsRng;
use tempfile::{TempDir, tempdir, tempdir_in};

use crate::e2e::helpers::{
    find_cosmos_address, generate_bin_command, get_cosmos_rpc_address,
    make_hermes_config, update_cosmos_config,
};

/// For `color_eyre::install`, which fails if called more than once in the same
/// process
pub static INIT: Once = Once::new();

pub const APPS_PACKAGE: &str = "namada_apps_lib";

/// Env. var for running E2E tests in debug mode
pub const ENV_VAR_DEBUG: &str = "NAMADA_E2E_DEBUG";

/// Env. var for keeping temporary files created by the E2E tests
pub const ENV_VAR_KEEP_TEMP: &str = "NAMADA_E2E_KEEP_TEMP";

/// Env. var for temporary path
const ENV_VAR_TEMP_PATH: &str = "NAMADA_E2E_TEMP_PATH";

/// Env. var to use a set of prebuilt binaries. This variable holds the path to
/// a folder.
pub const ENV_VAR_USE_PREBUILT_BINARIES: &str =
    "NAMADA_E2E_USE_PREBUILT_BINARIES";

/// Env. var to set a path to `speculos` executable
pub const ENV_VAR_SPECULOS_PATH: &str = "NAMADA_SPECULOS_PATH";

/// Env. var to set a path to ledger-namada wallet ELF file for `speculos`
pub const ENV_VAR_SPECULOS_APP_ELF: &str = "NAMADA_SPECULOS_APP_ELF";

/// Env. var to set a directory for CosmWasm NFT contracts
pub const ENV_VAR_COSMWASM_CONTRACT_DIR: &str = "NAMADA_COSMWASM_CONTRACT_DIR";

/// An E2E test network.
#[derive(Debug, Clone)]
pub struct Network {
    pub chain_id: ChainId,
}

/// Apply the --use-device flag depending on the environment variables
pub fn apply_use_device(mut tx_args: Vec<&str>) -> Vec<&str> {
    if is_use_device() {
        tx_args.push("--use-device");
    }
    tx_args
}

/// Default functions for offsetting ports when
/// adding multiple validators to a network
pub fn default_port_offset(ix: u8) -> u16 {
    6 * ix as u16
}

/// Update the config of some node `who`.
pub fn update_actor_config<F>(
    test: &Test,
    chain_id: &ChainId,
    who: Who,
    update: F,
) where
    F: FnOnce(&mut Config),
{
    let validator_base_dir = test.get_base_dir(who);
    let mut validator_config =
        Config::load(&validator_base_dir, chain_id, None);
    update(&mut validator_config);
    validator_config
        .write(&validator_base_dir, chain_id, true)
        .unwrap();
}

/// Configure validator p2p settings to allow duplicate ips
pub fn allow_duplicate_ips(test: &Test, chain_id: &ChainId, who: Who) {
    update_actor_config(test, chain_id, who, |config| {
        config.ledger.cometbft.p2p.allow_duplicate_ip = true;
    });
}

/// Configures the Ethereum bridge mode of `who`. This should be done before
/// `who` starts running.
pub fn set_ethereum_bridge_mode(
    test: &Test,
    chain_id: &ChainId,
    who: Who,
    mode: ethereum_bridge::ledger::Mode,
    rpc_endpoint: Option<&str>,
) {
    update_actor_config(test, chain_id, who, |config| {
        config.ledger.ethereum_bridge.mode = mode;
        if let Some(addr) = rpc_endpoint {
            config.ledger.ethereum_bridge.oracle_rpc_endpoint = addr.into();
        }
    });
}

/// Set `num` validators to the genesis config. Note that called from inside
/// the [`network`]'s first argument's closure, e.g. `set_validators(2, _)` will
/// configure a network with 2 validators.
///
/// Default self-bond amount for each validator is 100 000, which can be
/// overridden via the `bonds` argument indexed by the validator number.
///
/// INVARIANT: Do not call this function more than once on the same config.
pub fn set_validators<F>(
    num: u8,
    mut genesis: templates::All<templates::Unvalidated>,
    base_dir: &Path,
    port_offset: F,
    bonds: Vec<token::Amount>,
) -> templates::All<templates::Unvalidated>
where
    F: Fn(u8) -> u16,
{
    //  for each validator:
    // - generate a balance key
    // - assign balance to the key
    // - invoke `init-genesis-validator` signed by balance key to generate
    //   validator pre-genesis wallet signed genesis txs
    // - add txs to genesis templates
    let wallet_path = base_dir.join("pre-genesis");
    for val in 0..num {
        // init validator dir
        let validator_alias = format!("validator-{val}");
        let pre_genesis_path =
            validator_pre_genesis_dir(base_dir, &validator_alias);
        let pre_genesis_tx_path =
            validator_pre_genesis_txs_file(&pre_genesis_path);
        std::fs::create_dir(&pre_genesis_path).unwrap_or_else(|err| {
            panic!(
                "Failed to create the pre-genesis path for {validator_alias}: \
                 {err}"
            );
        });
        let pre_genesis_tx_path_str = pre_genesis_tx_path.to_string_lossy();
        // generate a balance key
        let mut wallet = wallet::load(&wallet_path)
            .expect("Could not locate pre-genesis wallet used for e2e tests.");
        let alias = format!("validator-{val}-balance-key");
        let (alias, sk) = wallet
            .gen_store_secret_key(
                SchemeType::Ed25519,
                Some(alias),
                true,
                None,
                &mut OsRng,
            )
            .unwrap_or_else(|| {
                panic!("Could not generate new key for validator-{}", val)
            });
        println!("alias: {}, pk: {}", alias, sk.ref_to());
        let validator_address = {
            use namada_apps_lib::config::genesis::chain::DeriveEstablishedAddress;
            let pre_genesis_tx = transactions::EstablishedAccountTx {
                vp: "vp_user".to_string(),
                threshold: 1,
                public_keys: vec![StringEncoded::new(sk.ref_to())],
            };
            let address = pre_genesis_tx.derive_established_address();
            println!(
                "Initializing validator {validator_alias} with address \
                 {address}"
            );
            address
        };
        wallet.insert_address(
            validator_alias.clone(),
            Address::Established(validator_address.clone()),
            true,
        );
        wallet::save(&wallet).unwrap();
        // invoke `init-genesis-established-account` to generate a new
        // established account with the generated balance key
        let args = vec![
            "utils",
            "init-genesis-established-account",
            "--aliases",
            &alias,
            "--path",
            &pre_genesis_tx_path_str,
        ];
        let mut init_established_account = run_cmd(
            Bin::Client,
            args,
            Some(5),
            working_dir(),
            base_dir,
            format!("{}:{}", std::file!(), std::line!()),
        )
        .unwrap();
        init_established_account.assert_success();
        // assign balance to the implicit addr (i.e. pubkey) + established acc
        let nam_balances = genesis
            .balances
            .token
            .get_mut(&Alias::from_str("nam").expect("Infallible"))
            .expect("NAM balances should exist in pre-genesis wallet already");
        nam_balances.0.insert(
            (&sk.ref_to()).into(),
            token::DenominatedAmount::new(
                token::Amount::from_uint(1000000, NATIVE_MAX_DECIMAL_PLACES)
                    .unwrap(),
                NATIVE_MAX_DECIMAL_PLACES.into(),
            ),
        );
        nam_balances.0.insert(
            Address::Established(validator_address.clone()),
            token::DenominatedAmount::new(
                token::Amount::from_uint(2000000, NATIVE_MAX_DECIMAL_PLACES)
                    .unwrap(),
                NATIVE_MAX_DECIMAL_PLACES.into(),
            ),
        );
        // invoke `init-genesis-validator` to promote the generated established
        // account to a validator account
        let net_addr = format!("127.0.0.1:{}", 27656 + port_offset(val));
        let validator_address_str = validator_address.to_string();
        let bond_amount = bonds
            .get(usize::from(val))
            .copied()
            .unwrap_or(token::Amount::native_whole(100_000))
            .to_string_native();
        let args = vec![
            "utils",
            "init-genesis-validator",
            "--alias",
            &validator_alias,
            "--address",
            &validator_address_str,
            "--path",
            &pre_genesis_tx_path_str,
            "--net-address",
            &net_addr,
            "--commission-rate",
            "0.05",
            "--max-commission-rate-change",
            "0.01",
            "--email",
            "null@null.net",
            "--self-bond-amount",
            &bond_amount,
            "--unsafe-dont-encrypt",
        ];
        let mut init_genesis_validator = run_cmd(
            Bin::Client,
            args,
            Some(5),
            working_dir(),
            base_dir,
            format!("{}:{}", std::file!(), std::line!()),
        )
        .unwrap();
        init_genesis_validator.assert_success();
        // invoke `sign-genesis-txs` to sign the validator txs with
        // the generated balance key
        let args = vec![
            "utils",
            "sign-genesis-txs",
            "--alias",
            &validator_alias,
            "--path",
            &pre_genesis_tx_path_str,
            "--output",
            &pre_genesis_tx_path_str,
        ];
        let mut sign_pre_genesis_txs = run_cmd(
            Bin::Client,
            args,
            Some(30),
            working_dir(),
            base_dir,
            format!("{}:{}", std::file!(), std::line!()),
        )
        .unwrap();
        sign_pre_genesis_txs.assert_success();
        // initialize the validator
        // add generated txs to genesis
        let pre_genesis_txs =
            read_toml(&pre_genesis_tx_path, "transactions.toml").unwrap();
        genesis.transactions.merge(pre_genesis_txs);
        // move validators generated files to their own base dir
        let validator_base_dir = base_dir
            .join(utils::NET_ACCOUNTS_DIR)
            .join(&validator_alias);
        let src_path = validator_pre_genesis_dir(base_dir, &validator_alias);
        let dest_path =
            validator_pre_genesis_dir(&validator_base_dir, &validator_alias);
        println!(
            "{} for {validator_alias} from {} to {}.",
            "Copying pre-genesis validator-wallet".yellow(),
            src_path.to_string_lossy(),
            dest_path.to_string_lossy(),
        );
        fs::create_dir_all(&dest_path).unwrap();
        fs::rename(src_path, dest_path).unwrap();
    }
    genesis
}

/// Setup a network with a single genesis validator node.
pub fn single_node_net() -> Result<Test> {
    network(
        |genesis, base_dir: &_| {
            set_validators(1, genesis, base_dir, |_| 0u16, vec![])
        },
        None,
    )
}

/// Setup a configurable network.
pub fn network(
    mut update_genesis: impl FnMut(
        templates::All<templates::Unvalidated>,
        &Path,
    ) -> templates::All<templates::Unvalidated>,
    consensus_timeout_commit: Option<&'static str>,
) -> Result<Test> {
    INIT.call_once(|| {
        if let Err(err) = color_eyre::install() {
            eprintln!("Failed setting up colorful error reports {}", err);
        }
    });
    let working_dir = working_dir();
    let test_dir = TestDir::new();

    // Open the source genesis file templates
    let templates_dir = derive_template_dir(&working_dir);
    println!(
        "{} {}.",
        "Loading genesis templates from".yellow(),
        templates_dir.to_string_lossy()
    );
    let mut templates =
        genesis::templates::All::read_toml_files(&templates_dir)
            .unwrap_or_else(|_| {
                panic!(
                    "Missing genesis templates files at {}",
                    templates_dir.to_string_lossy()
                )
            });
    // clear existing validator txs and bonds from genesis
    templates.transactions.validator_account = None;
    templates.transactions.bond = None;

    // Update the templates as needed
    templates.parameters.parameters.vp_allowlist =
        Some(get_all_wasms_hashes(&working_dir, Some("vp_")));
    templates.parameters.parameters.tx_allowlist =
        Some(get_all_wasms_hashes(&working_dir, Some("tx_")));
    // Copy the main wallet from templates dir into the base dir.
    {
        let base_dir = test_dir.path();
        let src_path =
            wallet::wallet_file(templates_dir.join("src").join("pre-genesis"));
        let dest_dir = base_dir.join("pre-genesis");
        let dest_path = wallet::wallet_file(&dest_dir);
        println!(
            "{} from {} to {}.",
            "Copying main pre-genesis wallet into a default non-validator \
             base dir"
                .yellow(),
            src_path.to_string_lossy(),
            dest_path.to_string_lossy(),
        );
        fs::create_dir_all(&dest_dir)?;
        fs::copy(&src_path, &dest_path)?;
    }

    // Run the provided function on it
    let templates = update_genesis(templates, test_dir.path());

    // Write the updated genesis templates to the test dir
    let updated_templates_dir = test_dir.path().join("templates");
    create_dir_all(&updated_templates_dir)?;
    println!(
        "{} {}.",
        "Writing updated genesis templates to".yellow(),
        updated_templates_dir.to_string_lossy()
    );
    templates.write_toml_files(&updated_templates_dir)?;

    // Run `init-network` on the updated templates to generate the finalized
    // genesis config and addresses and update WASM checksums
    let templates_path = updated_templates_dir.to_string_lossy().into_owned();
    println!("{}", "Finalizing network from genesis templates.".yellow());
    let checksums_path = working_dir
        .join("wasm/checksums.json")
        .to_string_lossy()
        .into_owned();
    let genesis_dir = test_dir.path().join("genesis");
    let archive_dir = genesis_dir.to_string_lossy().to_string();
    let mut args = vec![
        "utils",
        "init-network",
        "--templates-path",
        &templates_path,
        "--chain-prefix",
        "e2e-test",
        "--wasm-checksums-path",
        &checksums_path,
        "--genesis-time",
        namada_core::time::test_utils::GENESIS_TIME,
        "--archive-dir",
        &archive_dir,
    ];
    if let Some(consensus_timeout_commit) = consensus_timeout_commit {
        args.push("--consensus-timeout-commit");
        args.push(consensus_timeout_commit)
    }
    let mut init_network = run_cmd(
        Bin::Client,
        args,
        Some(30),
        &working_dir,
        &genesis_dir,
        format!("{}:{}", std::file!(), std::line!()),
    )?;

    // Get the generated chain_id from result of the last command
    let (unread, matched) =
        init_network.exp_regex(r"Derived chain ID: .*\n")?;
    let chain_id_raw =
        matched.trim().split_once("Derived chain ID: ").unwrap().1;
    let chain_id = ChainId::from_str(chain_id_raw.trim())?;
    println!("'init-network' unread output: {}", unread);
    let net = Network { chain_id };
    init_network.assert_success();

    drop(init_network);

    // Set the network archive dir to make it available for `join-network`
    // commands
    unsafe {
        std::env::set_var(
            namada_apps_lib::client::utils::ENV_VAR_NETWORK_CONFIGS_DIR,
            archive_dir,
        )
    };

    let validator_aliases = templates
        .transactions
        .validator_account
        .as_ref()
        .map(|txs| {
            Either::Right(
                // hacky way to get all the validator indexes :-)
                (0..txs.len()).map(|index| format!("validator-{index}")),
            )
        })
        .unwrap_or(Either::Left([].into_iter()));

    // Setup a dir for every validator and non-validator using their
    // pre-genesis wallets
    for alias in validator_aliases {
        let validator_base_dir =
            test_dir.path().join(utils::NET_ACCOUNTS_DIR).join(&alias);

        // Copy the main wallet from templates dir into validator's base dir.
        {
            let dest_dir = validator_base_dir.join("pre-genesis");
            let dest_path = wallet::wallet_file(&dest_dir);
            let base_dir = test_dir.path();
            let src_dir = base_dir.join("pre-genesis");
            let src_path = wallet::wallet_file(&src_dir);
            println!(
                "{} for {alias} from {} to {}.",
                "Copying main pre-genesis wallet".yellow(),
                src_path.to_string_lossy(),
                dest_path.to_string_lossy(),
            );
            fs::create_dir_all(&dest_dir)?;
            fs::copy(&src_path, &dest_path)?;
        }
        println!("{} {}.", "Joining network with ".yellow(), alias);
        let validator_base_dir =
            test_dir.path().join(utils::NET_ACCOUNTS_DIR).join(&alias);
        let mut join_network = run_cmd(
            Bin::Client,
            [
                "utils",
                "join-network",
                "--add-persistent-peers",
                "--chain-id",
                net.chain_id.as_str(),
                "--genesis-validator",
                &alias,
            ],
            Some(5),
            &working_dir,
            &validator_base_dir,
            format!("{}:{}", std::file!(), std::line!()),
        )?;
        join_network.exp_string("Successfully configured for chain")?;
        join_network.assert_success();
        copy_wasm_to_chain_dir(
            &working_dir,
            &validator_base_dir,
            &net.chain_id,
        );
    }

    // Setup a dir for a non-validator using the pre-genesis wallet
    {
        let base_dir = test_dir.path();
        println!(
            "{}.",
            "Joining network with a default non-validator node".yellow()
        );
        let mut join_network = run_cmd(
            Bin::Client,
            [
                "utils",
                "join-network",
                "--add-persistent-peers",
                "--chain-id",
                net.chain_id.as_str(),
            ],
            Some(5),
            &working_dir,
            base_dir,
            format!("{}:{}", std::file!(), std::line!()),
        )?;
        join_network.exp_string("Successfully configured for chain")?;
        join_network.assert_success();

        // Increment the default port, because the default from
        // `DEFAULT_COMETBFT_CONFIG` 26657 is being used by Cosmos
        let mut config = Config::load(base_dir, &net.chain_id, None);

        // For validators the arg is the index of a validator. We usually only
        // have a few of them so `20` shouldn't collide with anything
        let offset = default_port_offset(20);
        let incr_port = |addr: &mut TendermintAddress| {
            if let TendermintAddress::Tcp { port, .. } = addr {
                *port += offset;
            }
        };
        incr_port(&mut config.ledger.cometbft.p2p.laddr);
        incr_port(&mut config.ledger.cometbft.rpc.laddr);
        incr_port(&mut config.ledger.cometbft.proxy_app);
        config.write(base_dir, &net.chain_id, true).unwrap();
    }

    copy_wasm_to_chain_dir(&working_dir, test_dir.path(), &net.chain_id);

    // Set the chain id
    unsafe { std::env::set_var(ENV_VAR_CHAIN_ID, net.chain_id.to_string()) };

    Ok(Test {
        working_dir,
        test_dir,
        net,
        async_runtime: Default::default(),
    })
}

/// Namada binaries
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum Bin {
    Node,
    Client,
    Wallet,
    Relayer,
    Namada,
}

#[derive(Debug)]
pub struct Test {
    /// The dir where the tests run from, usually the repo root dir
    pub working_dir: PathBuf,
    /// Temporary test directory is used as the default base-dir for running
    /// Namada cmds
    pub test_dir: TestDir,
    pub net: Network,
    pub async_runtime: LazyAsyncRuntime,
}

#[derive(Debug)]
pub struct TestDir(Either<TempDir, PathBuf>);

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        match &self.0 {
            Either::Left(temp_dir) => temp_dir.path(),
            Either::Right(path) => path.as_ref(),
        }
    }
}

impl TestDir {
    /// Setup a `TestDir` in a temporary directory. The directory will be
    /// automatically deleted after the test run, unless `ENV_VAR_KEEP_TEMP`
    /// is set to `true`.
    pub fn new() -> Self {
        let keep_temp = match env::var(ENV_VAR_KEEP_TEMP) {
            Ok(val) => !val.eq_ignore_ascii_case("false"),
            _ => false,
        };

        let path_to_tmp = env::var(ENV_VAR_TEMP_PATH);
        let temp_dir: TempDir = match path_to_tmp {
            Ok(path) => tempdir_in(path),
            _ => tempdir(),
        }
        .unwrap();
        if keep_temp {
            let path = temp_dir.into_path();
            println!(
                "{}: \"{}\"",
                "Keeping test directory at".underline().yellow(),
                path.to_string_lossy()
            );
            Self(Either::Right(path))
        } else {
            Self(Either::Left(temp_dir))
        }
    }

    /// Get the [`Path`] to the test directory.
    pub fn path(&self) -> &Path {
        self.as_ref()
    }
}

impl Drop for Test {
    fn drop(&mut self) {
        if let Either::Right(path) = &self.test_dir.0 {
            println!(
                "{}: \"{}\"",
                "Keeping test directory at".underline().yellow(),
                path.to_string_lossy()
            );
        }
    }
}

#[derive(Debug)]
pub struct LazyAsyncRuntime(Lazy<tokio::runtime::Runtime>);

impl Default for LazyAsyncRuntime {
    fn default() -> Self {
        Self(Lazy::new(|| tokio::runtime::Runtime::new().unwrap()))
    }
}

// Internally used macros only for attaching source locations to commands
#[macro_use]
mod macros {
    /// Get an [`NamadaCmd`] to run an Namada binary.
    ///
    /// By default, these will run in release mode. This can be disabled by
    /// setting environment variable `NAMADA_E2E_DEBUG=true`.
    /// On [`NamadaCmd`], you can then call e.g. `exp_string` or `exp_regex` to
    /// look for an expected output from the command.
    ///
    /// Arguments:
    /// - the test [`super::Test`]
    /// - which binary to run [`super::Bin`]
    /// - arguments, which implement `IntoIterator<Item = &str>`, e.g.
    ///   `&["cmd"]`
    /// - optional timeout in seconds `Option<u64>`
    ///
    /// This is a helper macro that adds file and line location to the
    /// [`super::run_cmd`] function call.
    #[macro_export]
    macro_rules! run {
        ($test:expr, $bin:expr, $args:expr, $timeout_sec:expr $(,)?) => {{
            // The file and line will expand to the location that invoked
            // `run_cmd!`
            let loc = format!("{}:{}", std::file!(), std::line!());
            $test.run_cmd($bin, $args, $timeout_sec, loc)
        }};
    }

    /// Get an [`NamadaCmd`] to run an Namada binary.
    ///
    /// By default, these will run in release mode. This can be disabled by
    /// setting environment variable `NAMADA_E2E_DEBUG=true`.
    /// On [`NamadaCmd`], you can then call e.g. `exp_string` or `exp_regex` to
    /// look for an expected output from the command.
    ///
    /// Arguments:
    /// - the test [`super::Test`]
    /// - who to run this command as [`super::Who`]
    /// - which binary to run [`super::Bin`]
    /// - arguments, which implement `IntoIterator<item = &str>`, e.g.
    ///   `&["cmd"]`
    /// - optional timeout in seconds `Option<u64>`
    ///
    /// This is a helper macro that adds file and line location to the
    /// [`super::run_cmd`] function call.
    #[macro_export]
    macro_rules! run_as {
        (
            $test:expr,
            $who:expr,
            $bin:expr,
            $args:expr,
            $timeout_sec:expr $(,)?
        ) => {{
            // The file and line will expand to the location that invoked
            // `run_cmd!`
            let loc = format!("{}:{}", std::file!(), std::line!());
            $test.run_cmd_as($who, $bin, $args, $timeout_sec, loc)
        }};
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Who {
    // A non-validator
    NonValidator,
    // Genesis validator with a given index, starting from `0`
    Validator(u64),
}

impl Test {
    /// Use the `run!` macro instead of calling this method directly to get
    /// automatic source location reporting.
    ///
    /// Get an [`NamadaCmd`] to run an Namada binary. By default, these will run
    /// in release mode. This can be disabled by setting environment
    /// variable `NAMADA_E2E_DEBUG=true`.
    pub fn run_cmd<I, S>(
        &self,
        bin: Bin,
        args: I,
        timeout_sec: Option<u64>,
        loc: String,
    ) -> Result<NamadaCmd>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.run_cmd_as(Who::NonValidator, bin, args, timeout_sec, loc)
    }

    /// Use the `run!` macro instead of calling this method directly to get
    /// automatic source location reporting.
    ///
    /// Get an [`NamadaCmd`] to run an Namada binary. By default, these will run
    /// in release mode. This can be disabled by setting environment
    /// variable `NAMADA_E2E_DEBUG=true`.
    pub fn run_cmd_as<I, S>(
        &self,
        who: Who,
        bin: Bin,
        args: I,
        timeout_sec: Option<u64>,
        loc: String,
    ) -> Result<NamadaCmd>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let base_dir = self.get_base_dir(who);
        run_cmd(bin, args, timeout_sec, &self.working_dir, base_dir, loc)
    }

    pub fn get_base_dir(&self, who: Who) -> PathBuf {
        match who {
            Who::NonValidator => self.test_dir.path().to_owned(),
            Who::Validator(index) => self
                .test_dir
                .path()
                .join(utils::NET_ACCOUNTS_DIR)
                .join(format!("validator-{}", index)),
        }
    }

    pub fn get_chain_dir(&self, who: Who) -> PathBuf {
        self.get_base_dir(who).join(self.net.chain_id.as_str())
    }

    pub fn get_cometbft_home(&self, who: Who) -> PathBuf {
        self.get_chain_dir(who)
            .join(namada_apps_lib::config::COMETBFT_DIR)
    }

    /// Get an async runtime.
    pub fn async_runtime(&self) -> &tokio::runtime::Runtime {
        Lazy::force(&self.async_runtime.0)
    }
}

/// A helper that should be ran on start of every e2e test case.
pub fn working_dir() -> PathBuf {
    let working_dir = fs::canonicalize("../..").unwrap();

    // Check that cometbft is either on $PATH or `COMETBFT` env var is set
    if std::env::var("COMETBFT").is_err() {
        Command::new("which")
            .arg("cometbft")
            .assert()
            .try_success()
            .expect(
                "The env variable COMETBFT must be set and point to a local \
                 build of the cometbft abci++ branch, or the cometbft binary \
                 must be on PATH",
            );
    }
    working_dir
}

/// Return the path to all test fixture.
pub fn fixtures_dir() -> PathBuf {
    let mut dir = working_dir();
    dir.push("crates");
    dir.push("tests");
    dir.push("fixtures");
    dir
}

/// Return the path to all osmosis fixture.
pub fn osmosis_fixtures_dir() -> PathBuf {
    let mut dir = fixtures_dir();
    dir.push("osmosis_data");
    dir
}

/// A command under test
pub struct NamadaCmd {
    pub session: Session<UnixProcess, LogStream<PtyStream, File>>,
    pub cmd_str: String,
    pub log_path: PathBuf,
}

impl Display for NamadaCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\nLogs: {}",
            self.cmd_str,
            self.log_path.to_string_lossy()
        )
    }
}

/// A command under test running on a background thread
pub struct NamadaBgCmd {
    // Option workaround to allow moving the handle out of this object and
    // still implement Drop
    join_handle: Option<std::thread::JoinHandle<Option<NamadaCmd>>>,
    abort_send: std::sync::mpsc::Sender<ControlCode>,
}

impl Drop for NamadaBgCmd {
    fn drop(&mut self) {
        let _ = self.abort_send.send(ControlCode::EndOfText);
    }
}

impl NamadaBgCmd {
    /// Re-gain control of a background command (created with
    /// [`NamadaCmd::background()`]) to check its output.
    pub fn foreground(mut self) -> NamadaCmd {
        self.abort_send.send(ControlCode::Enquiry).unwrap();
        self.join_handle
            .take()
            .expect("Background task should always be present")
            .join()
            .unwrap()
            .expect("Background task has been dropped")
    }
}

impl NamadaCmd {
    /// Keep reading the session's output in a background thread to prevent the
    /// buffer from filling up. Call [`NamadaBgCmd::foreground()`] on the
    /// returned [`NamadaBgCmd`] to stop the loop and return back the original
    /// command.
    pub fn background(self) -> NamadaBgCmd {
        let (abort_send, abort_recv) = std::sync::mpsc::channel();
        let join_handle = std::thread::spawn(move || {
            let mut cmd = self;
            loop {
                match abort_recv.try_recv() {
                    Ok(ControlCode::EndOfText) => {
                        // Terminate the background task
                        let _result = cmd.session.send(ControlCode::EndOfText);
                        return None;
                    }
                    Ok(ControlCode::Enquiry)
                    | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Some(cmd);
                    }
                    Ok(_) | Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
                cmd.session.is_matched(Eof).unwrap();
            }
        });
        NamadaBgCmd {
            join_handle: Some(join_handle),
            abort_send,
        }
    }

    /// Assert that the process exited with success
    pub fn assert_success(&mut self) {
        // Make sure that there is no unread output first
        let _ = self.exp_eof().unwrap();

        let process = self.session.get_process();
        let status = process.wait().unwrap();
        assert_eq!(WaitStatus::Exited(process.pid(), 0), status);
    }

    /// Assert that the process exited with failure
    #[allow(dead_code)]
    pub fn assert_failure(&mut self) {
        // Make sure that there is no unread output first
        let _ = self.exp_eof().unwrap();

        let process = self.session.get_process();
        let status = process.wait().unwrap();
        assert_ne!(WaitStatus::Exited(process.pid(), 0), status);
    }

    /// Wait until provided string is seen on stdout of child process.
    /// Return the yet unread output (without the matched string)
    ///
    /// Wrapper over the inner `PtySession`'s functions with custom error
    /// reporting.
    pub fn exp_string(&mut self, needle: &str) -> Result<String> {
        let found = self
            .session
            .expect(needle)
            .map_err(|e| eyre!(format!("{}\n Needle: {}", e, needle)))?;
        if found.is_empty() {
            Err(eyre!(
                "Expected needle not found\nCommand: {}\n Needle: {}",
                self,
                needle
            ))
        } else {
            String::from_utf8(found.before().to_vec())
                .map_err(|e| eyre!("Error: {}\nCommand: {}", e, self))
        }
    }

    /// Wait until provided regex is seen on stdout of child process.
    /// Return a tuple:
    /// 1. the yet unread output
    /// 2. the matched regex
    ///
    /// Wrapper over the inner `Session`'s functions with custom error
    /// reporting as well as converting bytes back to `String`.
    pub fn exp_regex(&mut self, regex: &str) -> Result<(String, String)> {
        let found = self
            .session
            .expect(expectrl::Regex(regex))
            .map_err(|e| eyre!(format!("{}", e)))?;
        if found.is_empty() {
            Err(eyre!(
                "Expected regex not found: {}\nCommand: {}",
                regex,
                self
            ))
        } else {
            let unread = String::from_utf8(found.before().to_vec())
                .map_err(|e| eyre!("Error: {}\nCommand: {}", e, self))?;
            let matched =
                String::from_utf8(found.matches().next().unwrap().to_vec())
                    .map_err(|e| eyre!("Error: {}\nCommand: {}", e, self))?;
            Ok((unread, matched))
        }
    }

    /// Wait until we see EOF (i.e. child process has terminated)
    /// Return all the yet unread output
    ///
    /// Wrapper over the inner `Session`'s functions with custom error
    /// reporting.
    #[allow(dead_code)]
    pub fn exp_eof(&mut self) -> Result<String> {
        let found = self.session.expect(Eof).map_err(|e| eyre!("{}", e))?;
        if found.is_empty() {
            Err(eyre!("Expected EOF\nCommand: {}", self))
        } else {
            String::from_utf8(found.before().to_vec())
                .map_err(|e| eyre!(format!("Error: {}\nCommand: {}", e, self)))
        }
    }

    /// Send ctrl-c to to interrupt or terminate.
    pub fn interrupt(&mut self) -> Result<()> {
        self.send_control(ControlCode::EndOfText)
    }

    /// Send a control code to the running process and consume resulting output
    /// line (which is empty because echo is off)
    ///
    /// E.g. `send_control(ControlCode::EndOfText)` sends ctrl-c. Upper/smaller
    /// case does not matter.
    ///
    /// Wrapper over the inner `Session`'s functions with custom error
    /// reporting.
    pub fn send_control(&mut self, c: ControlCode) -> Result<()> {
        self.session
            .send(c)
            .map_err(|e| eyre!("Error: {}\nCommand: {}", e, self))
    }

    /// send line to repl (and flush output) and then, if echo_on=true wait for
    /// the input to appear.
    /// Return: number of bytes written
    ///
    /// Wrapper over the inner `Session`'s functions with custom error
    /// reporting.
    pub fn send_line(&mut self, line: &str) -> Result<()> {
        self.session
            .send_line(line)
            .map_err(|e| eyre!("Error: {}\nCommand: {}", e, self))
    }
}

impl Drop for NamadaCmd {
    fn drop(&mut self) {
        // attempt to clean up the process
        println!(
            "{}: {}",
            "> Sending Ctrl+C to command".underline().yellow(),
            self.cmd_str,
        );
        let _result = self.interrupt();
        match self.exp_eof() {
            Err(error) => {
                eprintln!(
                    "\n{}: {}\n{}: {}",
                    "> Error ensuring command is finished".underline().red(),
                    self.cmd_str,
                    "Error".underline().red(),
                    error,
                );
            }
            Ok(output) => {
                println!(
                    "\n{}: {}",
                    "> Command finished".underline().green(),
                    self.cmd_str,
                );
                let output = output.trim();
                if !output.is_empty() {
                    println!(
                        "\n{}: {}\n\n{}",
                        "> Unread output for command".underline().yellow(),
                        self.cmd_str,
                        output
                    );
                } else {
                    println!(
                        "\n{}: {}",
                        "> No unread output for command".underline().green(),
                        self.cmd_str
                    );
                }
            }
        }
    }
}

/// Get a [`Command`] to run an Namada binary. By default, these will run in
/// release mode. This can be disabled by setting environment variable
/// `NAMADA_E2E_DEBUG=true`.
pub fn run_cmd<I, S>(
    bin: Bin,
    args: I,
    timeout_sec: Option<u64>,
    working_dir: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
    loc: String,
) -> Result<NamadaCmd>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut args = peek_nth(args);
    let is_node_ledger = (matches!(bin, Bin::Node)
        && args
            .peek()
            .map(|fst_arg| fst_arg.as_ref() == "ledger")
            .unwrap_or_default())
        || (matches!(bin, Bin::Namada)
            && args
                .peek()
                .map(|fst_arg| fst_arg.as_ref() == "node")
                .unwrap_or_default()
            && args
                .peek_nth(1)
                .map(|snd_arg| snd_arg.as_ref() == "ledger")
                .unwrap_or_default());
    let is_shielded_sync = matches!(bin, Bin::Client)
        && args
            .peek()
            .map(|fst_arg| fst_arg.as_ref() == "shielded-sync")
            .unwrap_or_default();

    // Root cargo workspace manifest path
    let (bin_name, log_level) = match bin {
        Bin::Namada => ("namada", "info"),
        Bin::Node => ("namadan", "info"),
        Bin::Client => (
            "namadac",
            if is_shielded_sync {
                "info"
            } else {
                "tendermint_rpc=debug"
            },
        ),
        Bin::Wallet => ("namadaw", "info"),
        Bin::Relayer => ("namadar", "info"),
    };

    let mut run_cmd = generate_bin_command(
        bin_name,
        &working_dir.as_ref().join("Cargo.toml"),
    );

    if let Bin::Namada = bin {
        // Avoid `namada` running via "cargo" (see `fn handle_subcommand` in
        // crates/apps/src/bin/namada/cli.rs)
        run_cmd.env_remove("CARGO");
    }

    run_cmd
        .env("NAMADA_LOG", log_level)
        .env("NAMADA_CMT_STDOUT", "true")
        .env("CMT_LOG_LEVEL", "info")
        .env("NAMADA_LOG_COLOR", "false")
        .current_dir(working_dir)
        .args(["--base-dir", &base_dir.as_ref().to_string_lossy()]);

    run_cmd.args(args);

    let args: String =
        run_cmd.get_args().map(|s| s.to_string_lossy()).join(" ");
    let cmd_str =
        format!("{} {}", run_cmd.get_program().to_string_lossy(), args);

    let session = Session::spawn(run_cmd).map_err(|e| {
        eyre!(
            "\n\n{}: {}\n{}: {}\n{}: {}",
            "Failed to run".underline().red(),
            cmd_str,
            "Location".underline().red(),
            loc,
            "Error".underline().red(),
            e
        )
    })?;

    let log_path = {
        let mut rng = rand::thread_rng();
        let log_dir = base_dir.as_ref().join("logs");
        fs::create_dir_all(&log_dir)?;
        log_dir.join(format!(
            "{}-{}-{}.log",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros(),
            bin_name,
            rng.r#gen::<u64>()
        ))
    };
    let logger = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&log_path)?;
    let mut session = expectrl::session::log(session, logger).unwrap();

    session.set_expect_timeout(timeout_sec.map(std::time::Duration::from_secs));

    let mut cmd_process = NamadaCmd {
        session,
        cmd_str,
        log_path,
    };

    println!("{}:\n{}", "> Running".underline().green(), &cmd_process);

    if is_node_ledger {
        // When running a node command, we need to wait a bit before checking
        // status
        sleep(1);

        // If the command failed, try print out its output
        if let Ok(WaitStatus::Exited(_, result)) =
            cmd_process.session.get_process().status()
        {
            if result != 0 {
                let output = cmd_process.exp_eof().unwrap_or_else(|err| {
                    format!("No output found, error: {}", err)
                });
                return Err(eyre!(
                    "\n\n{}: {}\n{}: {} \n\n{}: {}",
                    "Failed to run".underline().red(),
                    cmd_process.cmd_str,
                    "Location".underline().red(),
                    loc,
                    "Output".underline().red(),
                    output,
                ));
            }
        }
    }

    Ok(cmd_process)
}

/// Sleep for given `seconds`.
pub fn sleep(seconds: u64) {
    thread::sleep(time::Duration::from_secs(seconds));
}

pub fn setup_hermes(test_a: &Test, test_b: &Test) -> Result<TestDir> {
    let hermes_dir = TestDir::new();

    println!("\n{}", "Setting up Hermes".underline().green(),);
    let chain_name_a =
        CosmosChainType::chain_type(test_a.net.chain_id.as_str())
            .map(|c| c.chain_id())
            .ok();
    let chain_name_b =
        CosmosChainType::chain_type(test_b.net.chain_id.as_str())
            .map(|c| c.chain_id())
            .ok();
    let relayer = chain_name_a
        .zip(chain_name_b)
        .map(|(a, b)| format!("{a}_{b}_relayer"));
    make_hermes_config(
        &hermes_dir,
        test_a,
        test_b,
        relayer.as_ref().map(|s| s.as_ref()),
    )?;

    for test in [test_a, test_b] {
        let chain_id = test.net.chain_id.as_str();
        let chain_dir = test.test_dir.as_ref().join(chain_id);
        match CosmosChainType::chain_type(chain_id) {
            Ok(_) => {
                if let Some(relayer) = relayer.as_ref() {
                    // we create a new relayer for each ibc connection between
                    // to non-Namada chains
                    let key_file =
                        chain_dir.join(format!("{relayer}_seed.json"));
                    let args = [
                        "keys",
                        "add",
                        relayer,
                        "--keyring-backend",
                        "test",
                        "--output",
                        "json",
                    ];
                    let mut cosmos = run_cosmos_cmd(test, args, Some(10))?;
                    let result = cosmos.exp_string("\n")?;
                    let mut file = File::create(&key_file).unwrap();
                    file.write_all(result.as_bytes()).map_err(|e| {
                        eyre!(format!(
                            "Writing a Cosmos key file failed: {}",
                            e
                        ))
                    })?;

                    let account = find_cosmos_address(test, relayer)?;
                    // Add tokens to the new relayer account
                    let args = [
                        "tx",
                        "bank",
                        "send",
                        constants::COSMOS_RELAYER,
                        &account,
                        "500000000stake",
                        "--from",
                        constants::COSMOS_RELAYER,
                        "--gas",
                        "250000",
                        "--gas-prices",
                        "0.01stake",
                        "--node",
                        &format!("http://{}", get_cosmos_rpc_address(test)),
                        "--keyring-backend",
                        "test",
                        "--chain-id",
                        chain_id,
                        "--yes",
                    ];

                    let mut cosmos = run_cosmos_cmd(test, args, Some(10))?;
                    cosmos.assert_success();

                    // add to hermes
                    let args = [
                        "keys",
                        "add",
                        "--chain",
                        chain_id,
                        "--key-file",
                        &key_file.to_string_lossy(),
                        "--key-name",
                        relayer,
                    ];
                    let mut hermes =
                        run_hermes_cmd(&hermes_dir, args, Some(20))?;
                    hermes.assert_success();
                } else {
                    let key_file_path = chain_dir.join(format!(
                        "{}_seed.json",
                        constants::COSMOS_RELAYER
                    ));
                    let args = [
                        "keys",
                        "add",
                        "--chain",
                        chain_id,
                        "--key-file",
                        &key_file_path.to_string_lossy(),
                    ];
                    let mut hermes =
                        run_hermes_cmd(&hermes_dir, args, Some(20))?;
                    hermes.assert_success();
                }
            }
            Err(_) => {
                let key_file_path = wallet::wallet_file(&chain_dir);
                let args = [
                    "keys",
                    "add",
                    "--chain",
                    chain_id,
                    "--key-file",
                    &key_file_path.to_string_lossy(),
                ];
                let mut hermes = run_hermes_cmd(&hermes_dir, args, Some(20))?;
                hermes.assert_success();
            }
        };
    }

    Ok(hermes_dir)
}

pub fn run_hermes_cmd<I, S>(
    hermes_dir: &TestDir,
    args: I,
    timeout_sec: Option<u64>,
) -> Result<NamadaCmd>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut run_cmd = Command::new("hermes");
    let hermes_dir: &Path = hermes_dir.as_ref();
    let hermes_dir = hermes_dir.join("hermes");
    run_cmd.current_dir(hermes_dir.clone());
    let config_path = hermes_dir.join("config.toml");
    run_cmd.args(["--config", &config_path.to_string_lossy()]);
    run_cmd.args(args);

    let args: String =
        run_cmd.get_args().map(|s| s.to_string_lossy()).join(" ");
    let cmd_str =
        format!("{} {}", run_cmd.get_program().to_string_lossy(), args);

    let session = Session::spawn(run_cmd).map_err(|e| {
        eyre!(
            "\n\n{}: {}\n{}: {}",
            "Failed to run Hermes".underline().red(),
            cmd_str,
            "Error".underline().red(),
            e
        )
    })?;

    let log_path = {
        let mut rng = rand::thread_rng();
        let log_dir = hermes_dir.join("logs");
        std::fs::create_dir_all(&log_dir)?;
        log_dir.join(format!(
            "{}-hermes-{}.log",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros(),
            rng.r#gen::<u64>()
        ))
    };
    let logger = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&log_path)?;
    let mut session = expectrl::session::log(session, logger).unwrap();

    session.set_expect_timeout(timeout_sec.map(std::time::Duration::from_secs));

    let cmd_process = NamadaCmd {
        session,
        cmd_str,
        log_path,
    };

    println!("{}:\n{}", "> Running".underline().green(), &cmd_process);

    Ok(cmd_process)
}

#[derive(Clone, Copy, Debug)]
pub enum CosmosChainType {
    Gaia(Option<u64>),
    CosmWasm,
    Osmosis,
}

impl CosmosChainType {
    fn genesis_cmd_args<'a>(&self, mut args: Vec<&'a str>) -> Vec<&'a str> {
        if !matches!(self, CosmosChainType::Osmosis) {
            args.insert(0, "genesis");
        }
        args
    }

    fn add_genesis_account_args<'a>(
        &self,
        account: &'a str,
        coins: &'a str,
    ) -> Vec<&'a str> {
        self.genesis_cmd_args(vec!["add-genesis-account", account, coins])
    }

    fn gentx_args<'a>(
        &self,
        account: &'a str,
        coins: &'a str,
        chain_id: &'a str,
    ) -> Vec<&'a str> {
        self.genesis_cmd_args(vec![
            "gentx",
            account,
            coins,
            "--keyring-backend",
            "test",
            "--chain-id",
            chain_id,
        ])
    }

    fn collect_gentxs_args<'a>(&self) -> Vec<&'a str> {
        self.genesis_cmd_args(vec!["collect-gentxs"])
    }

    pub fn chain_id(&self) -> String {
        match self {
            Self::Gaia(Some(suffix)) => {
                format!("{}{}", constants::GAIA_CHAIN_ID, suffix)
            }
            Self::Gaia(_) => constants::GAIA_CHAIN_ID.to_string(),
            Self::CosmWasm => constants::COSMWASM_CHAIN_ID.to_string(),
            Self::Osmosis => constants::OSMOSIS_CHAIN_ID.to_string(),
        }
    }

    pub fn command_path(&self) -> &str {
        match self {
            Self::Gaia(_) => "gaiad",
            Self::CosmWasm => "wasmd",
            Self::Osmosis => "osmosisd",
        }
    }

    pub fn chain_type(chain_id: &str) -> Result<Self> {
        if chain_id == constants::COSMWASM_CHAIN_ID {
            return Ok(Self::CosmWasm);
        }
        if chain_id == constants::OSMOSIS_CHAIN_ID {
            return Ok(Self::Osmosis);
        }
        match chain_id.strip_prefix(constants::GAIA_CHAIN_ID) {
            Some("") => Ok(Self::Gaia(None)),
            Some(suffix) => {
                Ok(Self::Gaia(Some(suffix.parse().map_err(|_| {
                    eyre!("Unexpected Cosmos chain ID: {chain_id}")
                })?)))
            }
            _ => Err(eyre!("Unexpected Cosmos chain ID: {chain_id}")),
        }
    }

    pub fn account_prefix(&self) -> &str {
        match self {
            Self::Gaia(_) => "cosmos",
            Self::CosmWasm => "wasm",
            Self::Osmosis => "osmo",
        }
    }

    pub fn get_p2p_port_number(&self) -> u64 {
        10_000 + self.get_offset()
    }

    pub fn get_rpc_port_number(&self) -> u64 {
        20_000 + self.get_offset()
    }

    pub fn get_grpc_port_number(&self) -> u64 {
        30_000 + self.get_offset()
    }

    fn get_offset(&self) -> u64 {
        // NB: ensure none of these ever conflict
        match self {
            Self::CosmWasm => 0,
            Self::Osmosis => 1,
            Self::Gaia(None) => 2,
            Self::Gaia(Some(off)) => 3 + *off,
        }
    }
}

pub fn setup_cosmos(chain_type: CosmosChainType) -> Result<Test> {
    let working_dir = working_dir();
    let test_dir = TestDir::new();
    let chain_id = chain_type.chain_id();
    let cosmos_dir = test_dir.as_ref().join(&chain_id);
    let net = Network {
        chain_id: ChainId(chain_id.to_string()),
    };
    let test = Test {
        working_dir,
        test_dir,
        net,
        async_runtime: Default::default(),
    };

    // initialize
    let args = ["--chain-id", &chain_id, "init", &chain_id];
    let mut cosmos = run_cosmos_cmd(&test, args, Some(30))?;
    cosmos.assert_success();

    for role in [
        constants::COSMOS_USER,
        constants::COSMOS_RELAYER,
        constants::COSMOS_VALIDATOR,
    ] {
        let key_file =
            format!("{}/{role}_seed.json", cosmos_dir.to_string_lossy());
        let args = [
            "keys",
            "add",
            role,
            "--keyring-backend",
            "test",
            "--output",
            "json",
        ];
        let mut cosmos = run_cosmos_cmd(&test, args, Some(10))?;
        let result = cosmos.exp_string("\n")?;
        let mut file = File::create(key_file).unwrap();
        file.write_all(result.as_bytes()).map_err(|e| {
            eyre!(format!("Writing a Cosmos key file failed: {}", e))
        })?;
    }

    // Add tokens to a user account
    let account = find_cosmos_address(&test, constants::COSMOS_USER)?;
    let args = if let CosmosChainType::Osmosis = chain_type {
        chain_type.add_genesis_account_args(
            &account,
            "100000000stake,1000samoleans, 10000000000uosmo",
        )
    } else {
        chain_type
            .add_genesis_account_args(&account, "100000000stake,1000samoleans")
    };
    let mut cosmos = run_cosmos_cmd(&test, args, Some(10))?;
    cosmos.assert_success();

    // Add the stake token to the relayer
    let account = find_cosmos_address(&test, constants::COSMOS_RELAYER)?;
    let args =
        chain_type.add_genesis_account_args(&account, "10000000000stake");
    let mut cosmos = run_cosmos_cmd(&test, args, Some(10))?;
    cosmos.assert_success();

    // Add the stake token to the validator
    let validator = find_cosmos_address(&test, constants::COSMOS_VALIDATOR)?;
    let args =
        chain_type.add_genesis_account_args(&validator, "200000000000stake");
    let mut cosmos = run_cosmos_cmd(&test, args, Some(10))?;
    cosmos.assert_success();

    // stake
    let args = chain_type.gentx_args(
        constants::COSMOS_VALIDATOR,
        "100000000000stake",
        &chain_id,
    );
    let mut cosmos = run_cosmos_cmd(&test, args, Some(10))?;
    cosmos.assert_success();

    let args = chain_type.collect_gentxs_args();
    let mut cosmos = run_cosmos_cmd(&test, args, Some(10))?;
    cosmos.assert_success();

    update_cosmos_config(&test)?;

    Ok(test)
}

pub fn run_cosmos_cmd_homeless<I, S>(
    test: &Test,
    args: I,
    timeout_sec: Option<u64>,
) -> Result<NamadaCmd>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let chain_id = test.net.chain_id.as_str();
    let chain_type = CosmosChainType::chain_type(chain_id)?;
    let mut run_cmd = Command::new(chain_type.command_path());
    run_cmd.args(args);

    let args: String =
        run_cmd.get_args().map(|s| s.to_string_lossy()).join(" ");
    let cmd_str =
        format!("{} {}", run_cmd.get_program().to_string_lossy(), args);

    let session = Session::spawn(run_cmd).map_err(|e| {
        eyre!(
            "\n\n{}: {}\n{}: {}",
            "Failed to run Cosmos command".underline().red(),
            cmd_str,
            "Error".underline().red(),
            e
        )
    })?;

    let log_path = {
        let mut rng = rand::thread_rng();
        let log_dir = test.get_base_dir(Who::NonValidator).join("logs");
        std::fs::create_dir_all(&log_dir)?;
        log_dir.join(format!(
            "{}-cosmos-{}.log",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros(),
            rng.r#gen::<u64>()
        ))
    };
    let logger = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&log_path)?;
    let mut session = expectrl::session::log(session, logger).unwrap();

    session.set_expect_timeout(timeout_sec.map(std::time::Duration::from_secs));

    let cmd_process = NamadaCmd {
        session,
        cmd_str,
        log_path,
    };

    println!("{}:\n{}", "> Running".underline().green(), &cmd_process);

    Ok(cmd_process)
}

pub fn run_cosmos_cmd<I, S>(
    test: &Test,
    args: I,
    timeout_sec: Option<u64>,
) -> Result<NamadaCmd>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let chain_id = test.net.chain_id.as_str();
    let chain_type = CosmosChainType::chain_type(chain_id)?;
    let mut run_cmd = Command::new(chain_type.command_path());
    let cosmos_dir = test.test_dir.as_ref().join(chain_id);
    run_cmd.args(["--home", &cosmos_dir.to_string_lossy()]);
    run_cmd.args(args);

    let args: String =
        run_cmd.get_args().map(|s| s.to_string_lossy()).join(" ");
    let cmd_str =
        format!("{} {}", run_cmd.get_program().to_string_lossy(), args);

    let session = Session::spawn(run_cmd).map_err(|e| {
        eyre!(
            "\n\n{}: {}\n{}: {}",
            "Failed to run Cosmos command".underline().red(),
            cmd_str,
            "Error".underline().red(),
            e
        )
    })?;

    let log_path = {
        let mut rng = rand::thread_rng();
        let log_dir = test.get_base_dir(Who::NonValidator).join("logs");
        std::fs::create_dir_all(&log_dir)?;
        log_dir.join(format!(
            "{}-cosmos-{}.log",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros(),
            rng.r#gen::<u64>()
        ))
    };
    let logger = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&log_path)?;
    let mut session = expectrl::session::log(session, logger).unwrap();

    session.set_expect_timeout(timeout_sec.map(std::time::Duration::from_secs));

    let cmd_process = NamadaCmd {
        session,
        cmd_str,
        log_path,
    };

    println!("{}:\n{}", "> Running".underline().green(), &cmd_process);

    Ok(cmd_process)
}

#[allow(dead_code)]
pub mod constants {
    // User addresses aliases
    pub const ALBERT: &str = "Albert";
    pub const ALBERT_KEY: &str = "Albert-key";
    pub const BERTHA: &str = "Bertha";
    pub const BERTHA_KEY: &str = "Bertha-key";
    pub const CHRISTEL: &str = "Christel";
    pub const CHRISTEL_KEY: &str = "Christel-key";
    pub const DAEWON: &str = "Daewon";
    pub const DAEWON_KEY: &str = "Daewon-key";
    pub const ESTER: &str = "Ester";
    pub const MATCHMAKER_KEY: &str = "matchmaker-key";
    // Special user that must be stored unencrypted for IBC tests
    pub const FRANK: &str = "Frank";
    pub const FRANK_KEY: &str = "Frank-key";

    // Shielded spending and viewing keys and payment addresses
    pub const A_SPENDING_KEY: &str = "albert-svk";
    pub const B_SPENDING_KEY: &str = "bertha-svk";
    // A payment address derived from A_SPENDING_KEY
    pub const AA_PAYMENT_ADDRESS: &str = "albert-pa";
    // A payment address derived from B_SPENDING_KEY
    pub const AB_PAYMENT_ADDRESS: &str = "bertha-pa-a";
    // A viewing key derived from B_SPENDING_KEY
    pub const AB_VIEWING_KEY: &str = "bertha-svk";
    // A payment address derived from B_VIEWING_KEY
    pub const BB_PAYMENT_ADDRESS: &str = "bertha-pa-b";
    // A viewing key derived from A_SPENDING_KEY
    pub const AA_VIEWING_KEY: &str = "albert-svk";
    pub const C_SPENDING_KEY: &str = "christel-svk";
    // A viewing key derived from C_SPENDING_KEY
    pub const AC_VIEWING_KEY: &str = "christel-svk";
    // A viewing key derived from C_VIEWING_KEY
    pub const AC_PAYMENT_ADDRESS: &str = "christel-pa";

    //  Native VP aliases
    pub const GOVERNANCE_ADDRESS: &str = "governance";
    pub const MASP: &str = "masp";
    pub const PGF_ADDRESS: &str = "pgf";

    // Fungible token addresses
    pub const NAM: &str = "NAM";
    pub const BTC: &str = "BTC";
    pub const ETH: &str = "ETH";
    pub const DOT: &str = "DOT";

    // Bite-sized tokens
    pub const SCHNITZEL: &str = "Schnitzel";
    pub const APFEL: &str = "Apfel";
    pub const KARTOFFEL: &str = "Kartoffel";

    // Gaia or CosmWasm or Osmosis
    pub const GAIA_CHAIN_ID: &str = "gaia";
    pub const OSMOSIS_CHAIN_ID: &str = "osmosis";
    pub const COSMWASM_CHAIN_ID: &str = "cosmwasm";
    pub const COSMOS_USER: &str = "user";
    pub const COSMOS_RELAYER: &str = "relayer";
    pub const COSMOS_VALIDATOR: &str = "validator";
    pub const COSMOS_COIN: &str = "samoleans";
}

/// Copy WASM files from the `wasm` directory to every node's chain dir.
pub fn copy_wasm_to_chain_dir(
    working_dir: &Path,
    test_dir: &Path,
    chain_id: &ChainId,
    // genesis_validator_keys: impl Iterator<Item = &'a String>,
) {
    // Copy the built WASM files from "wasm" directory in the root of the
    // project.
    let built_wasm_dir = working_dir.join(config::DEFAULT_WASM_DIR);
    let opts = fs_extra::dir::DirOptions { depth: 1 };
    let wasm_files: Vec<_> =
        fs_extra::dir::get_dir_content2(&built_wasm_dir, &opts)
            .unwrap()
            .files
            .into_iter()
            .map(PathBuf::from)
            .filter(|path| {
                matches!(path.extension().and_then(OsStr::to_str), Some("wasm"))
            })
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
    if wasm_files.is_empty() {
        panic!(
            "No WASM files found in {}. Please build or download them them \
             first.",
            built_wasm_dir.to_string_lossy()
        );
    }
    let chain_dir = test_dir.join(chain_id.as_str());
    let target_wasm_dir = chain_dir.join(config::DEFAULT_WASM_DIR);
    for file in &wasm_files {
        std::fs::copy(
            working_dir.join("wasm").join(file),
            target_wasm_dir.join(file),
        )
        .unwrap();
    }
}

pub fn get_all_wasms_hashes(
    working_dir: &Path,
    filter: Option<&str>,
) -> Vec<String> {
    let checksums_path = working_dir.join("wasm/checksums.json");
    let checksums_content = fs::read_to_string(checksums_path).unwrap();
    let checksums: HashMap<String, String> =
        serde_json::from_str(&checksums_content).unwrap();
    let filter_prefix = filter.unwrap_or_default();
    checksums
        .values()
        .filter_map(|wasm| {
            if wasm.contains(filter_prefix) {
                Some(
                    wasm.split('.').collect::<Vec<&str>>()[1]
                        .to_owned()
                        .to_lowercase(),
                )
            } else {
                None
            }
        })
        .collect()
}

/// Get the path to `speculos` executable from [`ENV_VAR_SPECULOS_PATH`] if set,
/// or default to `speculos.py`.
pub fn speculos_path() -> String {
    env::var(ENV_VAR_SPECULOS_PATH)
        .unwrap_or_else(|_| "speculos.py".to_string())
}

/// Get the path to ledger-namada wallet ELF file for `speculos` executable from
/// [`ENV_VAR_SPECULOS_APP_ELF`] if set, or default to `app_s2.elf` in working
/// dir or path.
pub fn speculos_app_elf() -> String {
    env::var(ENV_VAR_SPECULOS_APP_ELF)
        .unwrap_or_else(|_| "app_s2.elf".to_string())
}
