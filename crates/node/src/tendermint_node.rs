use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str::FromStr;

use namada_apps_lib::config;
pub use namada_apps_lib::tendermint_node::*;
use namada_sdk::chain::{BlockHeight, ChainId};
use namada_sdk::parameters::ProposalBytes;
use namada_sdk::time::DateTimeUtc;
use thiserror::Error;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::oneshot::error::RecvError;
use tokio::sync::oneshot::{Receiver, Sender};

use crate::tendermint::validator::Info;
use crate::tendermint::{Genesis, Moniker, PublicKey, block};
use crate::tendermint_config::{Error as TendermintError, TendermintConfig};

/// Env. var to output Tendermint log to stdout
pub const ENV_VAR_TM_STDOUT: &str = "NAMADA_CMT_STDOUT";

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to initialize CometBFT: {0}")]
    Init(std::io::Error),
    #[error("Failed to load CometBFT config file: {0}")]
    LoadConfig(TendermintError),
    #[error("Failed to open CometBFT config for writing: {0}")]
    OpenWriteConfig(std::io::Error),
    #[error("Failed to serialize CometBFT config TOML to string: {0}")]
    ConfigSerializeToml(toml::ser::Error),
    #[error("Failed to write CometBFT config: {0}")]
    WriteConfig(std::io::Error),
    #[error("Failed to start up CometBFT node: {0}")]
    StartUp(std::io::Error),
    #[error("{0}")]
    Runtime(String),
    #[error("Failed to rollback CometBFT state: {0}")]
    RollBack(String),
    #[error("Failed to convert to String: {0:?}")]
    TendermintPath(std::ffi::OsString),
    #[error("Couldn't write {0}")]
    CantWrite(String),
    #[error("Couldn't create {0}")]
    CantCreate(String),
    #[error("Couldn't encode {0}")]
    CantEncode(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Check if the COMET env var has been set and use that as the
/// location of the COMET binary. Otherwise, assume it is on path
///
/// Returns an error if the env var is defined but not a valid Unicode.
fn from_env_or_default() -> Result<String> {
    match std::env::var("COMETBFT") {
        Ok(path) => {
            tracing::info!("Using CometBFT path from env variable: {}", path);
            Ok(path)
        }
        Err(std::env::VarError::NotPresent) => Ok(String::from("cometbft")),
        Err(std::env::VarError::NotUnicode(msg)) => {
            Err(Error::TendermintPath(msg))
        }
    }
}

/// Run the tendermint node.
pub async fn run(
    home_dir: PathBuf,
    chain_id: ChainId,
    genesis_time: DateTimeUtc,
    proxy_app_address: String,
    config: config::Ledger,
    abort_recv: Receiver<Sender<()>>,
    namada_version: &'static str,
) -> Result<()> {
    let (home_dir_string, tendermint_path) = initalize_config(
        home_dir,
        chain_id,
        genesis_time,
        config,
        namada_version,
    )
    .await?;
    let tendermint_node =
        start_node(proxy_app_address, home_dir_string, tendermint_path)?;

    tracing::info!("CometBFT node started");

    handle_node_response(tendermint_node, abort_recv).await
}

/// Setup the tendermint configuration. We return the tendermint path and home
/// directory
async fn initalize_config(
    home_dir: PathBuf,
    chain_id: ChainId,
    genesis_time: DateTimeUtc,
    config: config::Ledger,
    namada_version: &'static str,
) -> Result<(String, String)> {
    let home_dir_string = home_dir.to_string_lossy().to_string();
    let tendermint_path = from_env_or_default()?;
    let mode = config.shell.tendermint_mode.to_str().to_owned();

    // init and run a tendermint node child process
    let output = Command::new(&tendermint_path)
        .args(["init", &mode, "--home", &home_dir_string])
        .output()
        .await
        .map_err(Error::Init)?;
    if !output.status.success() {
        panic!("Tendermint failed to initialize with {:#?}", output);
    }

    write_tm_genesis(&home_dir, chain_id, genesis_time).await?;

    update_tendermint_config(&home_dir, config.cometbft, namada_version)
        .await?;
    Ok((home_dir_string, tendermint_path))
}

/// Startup the node
fn start_node(
    proxy_app_address: String,
    home_dir_string: String,
    tendermint_path: String,
) -> Result<Child> {
    let mut tendermint_node = Command::new(tendermint_path);
    tendermint_node.args([
        "start",
        "--proxy_app",
        &proxy_app_address,
        "--home",
        &home_dir_string,
    ]);

    let log_stdout = match env::var(ENV_VAR_TM_STDOUT) {
        Ok(val) => val.to_ascii_lowercase().trim() == "true",
        _ => false,
    };
    if !log_stdout {
        tendermint_node.stdout(Stdio::null());
    }

    tendermint_node
        .kill_on_drop(true)
        .spawn()
        .map_err(Error::StartUp)
}

/// Handle the node response
async fn handle_node_response(
    mut tendermint_node: Child,
    abort_recv: Receiver<Sender<()>>,
) -> Result<()> {
    tokio::select! {
        status = tendermint_node.wait() => {
            match status {
                Ok(status) => {
                    if status.success() {
                        Ok(())
                    } else {
                        Err(Error::Runtime(status.to_string()))
                    }
                },
                Err(err) => {
                    Err(Error::Runtime(err.to_string()))
                }
            }
        },
        resp_sender = abort_recv => {
            handle_abort(resp_sender, &mut tendermint_node).await;
            Ok(())
        }
    }
}
// Handle tendermint aborting
async fn handle_abort(
    resp_sender: std::result::Result<Sender<()>, RecvError>,
    node: &mut Child,
) {
    match resp_sender {
        Ok(resp_sender) => {
            tracing_kill(node).await;
            resp_sender.send(()).unwrap();
        }
        Err(err) => {
            tracing::error!(
                "The Tendermint abort sender has unexpectedly dropped: {}",
                err
            );
            tracing_kill(node).await;
        }
    }
}

pub fn reset(tendermint_dir: impl AsRef<Path>) -> Result<()> {
    let tendermint_dir = tendermint_dir.as_ref();

    // Delete data dir
    let data_dir = tendermint_dir.join("data");
    std::fs::remove_dir_all(&data_dir)
        .expect("Failed to reset tendermint node's data");

    // Recreate an empty validator state
    std::fs::create_dir(&data_dir).unwrap();
    write_validator_state(tendermint_dir).unwrap();

    Ok(())
}

pub fn rollback(tendermint_dir: impl AsRef<Path>) -> Result<BlockHeight> {
    let tendermint_path = from_env_or_default()?;
    let tendermint_dir = tendermint_dir.as_ref().to_string_lossy();

    // Rollback tendermint state, see https://github.com/tendermint/tendermint/blob/main/cmd/tendermint/commands/rollback.go for details
    // on how the tendermint rollback behaves
    let output = std::process::Command::new(tendermint_path)
        .args([
            "rollback",
            "unsafe-all",
            // NOTE: log config: https://docs.tendermint.com/master/nodes/logging.html#configuring-log-levels
            // "--log-level=\"*debug\"",
            "--home",
            &tendermint_dir,
        ])
        .output()
        .map_err(|e| Error::RollBack(e.to_string()))?;

    // Capture the block height from the output of tendermint rollback
    // Tendermint stdout message: "Rolled
    // back state to height %d and hash %v"
    let output_msg = String::from_utf8(output.stdout)
        .map_err(|e| Error::RollBack(e.to_string()))?;
    let (_, right) = output_msg
        .split_once("Rolled back state to height")
        .ok_or(Error::RollBack(
            "Missing expected block height in tendermint stdout message"
                .to_string(),
        ))?;

    let mut sub = right.split_ascii_whitespace();
    let height = sub.next().ok_or(Error::RollBack(
        "Missing expected block height in tendermint stdout message"
            .to_string(),
    ))?;

    Ok(height
        .parse::<u64>()
        .map_err(|e| Error::RollBack(e.to_string()))?
        .into())
}

async fn update_tendermint_config(
    home_dir: impl AsRef<Path>,
    mut config: TendermintConfig,
    namada_version: &'static str,
) -> Result<()> {
    let path: PathBuf = configuration(home_dir);
    let actual_moniker = config.moniker.to_string();
    let actual_moniker = actual_moniker
        .strip_suffix(namada_version)
        .unwrap_or(&actual_moniker);
    config.moniker =
        Moniker::from_str(&format!("{}-{}", actual_moniker, namada_version))
            .expect("Invalid moniker");

    config.consensus.create_empty_blocks = true;

    // mempool config
    // https://forum.cosmos.network/t/our-understanding-of-the-cosmos-hub-mempool-issues/12040
    {
        // We set this to true as we don't want any invalid tx be re-applied.
        // This also implies that it's not possible for an invalid tx to
        // become valid again in the future.
        config.mempool.keep_invalid_txs_in_cache = false;

        // Hold 50x the max amount of txs in a block.
        #[allow(clippy::arithmetic_side_effects)]
        {
            // Multiply with consts - cannot overflow
            config.mempool.max_txs_bytes = 50 * ProposalBytes::MAX.get();
        }

        // Hold up to 4k txs in the mempool
        config.mempool.size = 4000;
    }

    // Bumped from the default `1_000_000`, because some WASMs can be
    // quite large
    config.rpc.max_body_bytes = 2_000_000;

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .await
        .map_err(Error::OpenWriteConfig)?;
    let config_str =
        toml::to_string(&config).map_err(Error::ConfigSerializeToml)?;
    file.write_all(config_str.as_bytes())
        .await
        .map_err(Error::WriteConfig)
}

async fn write_tm_genesis(
    home_dir: impl AsRef<Path>,
    chain_id: ChainId,
    genesis_time: DateTimeUtc,
) -> Result<()> {
    let path = genesis(home_dir);
    let mut file = File::open(&path).await.unwrap_or_else(|err| {
        panic!(
            "Couldn't open the genesis file at {:?}, error: {}",
            path, err
        )
    });
    let mut file_contents = vec![];
    file.read_to_end(&mut file_contents)
        .await
        .expect("Couldn't read Tendermint genesis file");
    // Set `Option<String>` for the omitted `app_state`
    let mut genesis: Genesis<Option<String>> =
        serde_json::from_slice(&file_contents[..])
            .expect("Couldn't deserialize the genesis file");
    genesis.chain_id =
        FromStr::from_str(chain_id.as_str()).expect("Invalid chain ID");
    genesis.genesis_time = genesis_time
        .try_into()
        .expect("Couldn't convert DateTimeUtc to Tendermint Time");
    if let Some(height) = super::migrating_state() {
        genesis.initial_height = height
            .0
            .try_into()
            .expect("Failed to convert initial genesis height");
    }

    // N.B. Because we give cometbft our genesis validators only after init
    // chain, at this stage, cometbft believes this node is the only
    // validator unless we insert a dummy. If cometbft thinks a node is the
    // only validator, it won't start state sync. These validators are
    // overwritten after init chain is called.
    if genesis.validators.len() < 2 {
        const DUMMY_VALIDATOR: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        genesis.validators.push(Info::new(
            PublicKey::from_raw_ed25519(&DUMMY_VALIDATOR).unwrap(),
            10u32.into(),
        ));
    }
    const EVIDENCE_AND_PROTOBUF_OVERHEAD: u64 = 10 * 1024 * 1024;
    let size = block::Size {
        // maximum size of a serialized Tendermint block.
        // on Namada, we have a hard-cap of 16 MiB (6 MiB max
        // txs in a block + 10 MiB reserved for evidence data,
        // block headers and protobuf serialization overhead).
        // Addition with consts - cannot overflow.
        #[allow(clippy::arithmetic_side_effects)]
        max_bytes: EVIDENCE_AND_PROTOBUF_OVERHEAD + ProposalBytes::MAX.get(),
        // gas is metered app-side, so we disable it
        // at the Tendermint level
        max_gas: -1,
        // This parameter has no value anymore in Tendermint-core
        time_iota_ms: block::Size::default_time_iota_ms(),
    };
    genesis.consensus_params.block = size;

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .await
        .unwrap_or_else(|err| {
            panic!(
                "Couldn't open the genesis file at {:?} for writing, error: {}",
                path, err
            )
        });
    let data = serde_json::to_vec_pretty(&genesis)
        .map_err(|_| Error::CantEncode(GENESIS_FILE))?;
    file.write_all(&data[..]).await.map_err(|err| {
        Error::CantWrite(format!(
            "{} to {}. Caused by {err}",
            GENESIS_FILE,
            path.to_string_lossy()
        ))
    })
}

async fn tracing_kill(node: &mut Child) {
    tracing::info!("Shutting down Tendermint node...");
    node.kill().await.unwrap();
}

fn configuration(home_dir: impl AsRef<Path>) -> PathBuf {
    home_dir.as_ref().join("config").join("config.toml")
}

fn genesis(home_dir: impl AsRef<Path>) -> PathBuf {
    home_dir.as_ref().join("config").join("genesis.json")
}

// Constant strings to avoid repeating our magic words

const GENESIS_FILE: &str = "CometBFT genesis file";
