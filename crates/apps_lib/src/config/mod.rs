//! Node and client configuration

pub mod ethereum_bridge;
pub mod genesis;
pub mod global;
pub mod utils;

use std::fs::{File, create_dir_all};
use std::io::Write;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use namada_sdk::chain::{BlockHeight, ChainId};
use namada_sdk::collections::HashMap;
use namada_sdk::time::Rfc3339String;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cli;
use crate::tendermint_config::{TendermintConfig, TxIndexConfig, TxIndexer};

/// Base directory contains global config and chain directories.
pub const DEFAULT_BASE_DIR: &str = ".namada";
/// Default WASM dir.
pub const DEFAULT_WASM_DIR: &str = "wasm";
/// The WASM checksums file contains the hashes of built WASMs. It is inside the
/// WASM dir.
pub const DEFAULT_WASM_CHECKSUMS_FILE: &str = "checksums.json";
/// Chain-specific Namada configuration. Nested in chain dirs.
pub const FILENAME: &str = "config.toml";
/// Chain-specific CometBFT configuration. Nested in chain dirs.
pub const COMETBFT_DIR: &str = "cometbft";
/// Chain-specific Namada DB. Nested in chain dirs.
pub const DB_DIR: &str = "db";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub wasm_dir: PathBuf,
    pub ledger: Ledger,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorLocalConfig {
    pub accepted_gas_tokens:
        HashMap<namada_sdk::address::Address, namada_sdk::token::Amount>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeLocalConfig {
    pub recheck_process_proposal: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TendermintMode {
    Full,
    Validator,
    Seed,
}

impl TendermintMode {
    pub fn to_str(&self) -> &str {
        match *self {
            TendermintMode::Full => "full",
            TendermintMode::Validator => "validator",
            TendermintMode::Seed => "seed",
        }
    }
}

/// An action to be performed at a
/// certain block height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    /// Stop the chain.
    Halt,
    /// Suspend consensus indefinitely.
    Suspend,
}

/// An action to be performed at a
/// certain block height along with the
/// given height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionAtHeight {
    /// The height at which to take action.
    pub height: BlockHeight,
    /// The action to take.
    pub action: Action,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ledger {
    pub genesis_time: Rfc3339String,
    pub chain_id: ChainId,
    pub shell: Shell,
    pub cometbft: TendermintConfig,
    pub ethereum_bridge: ethereum_bridge::ledger::Config,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Shell {
    pub base_dir: PathBuf,
    /// RocksDB block cache maximum size in bytes.
    /// When not set, defaults to 1/3 of the available memory.
    pub block_cache_bytes: Option<u64>,
    /// VP WASM compilation cache maximum size in bytes.
    /// When not set, defaults to 1/6 of the available memory.
    pub vp_wasm_compilation_cache_bytes: Option<u64>,
    /// Tx WASM compilation in-memory cache maximum size in bytes.
    /// When not set, defaults to 1/6 of the available memory.
    pub tx_wasm_compilation_cache_bytes: Option<u64>,
    /// When set, will limit the how many block heights in the past can the
    /// storage be queried for reading values.
    pub storage_read_past_height_limit: Option<u64>,
    /// Use the [`Ledger::db_dir()`] method to read the value.
    db_dir: PathBuf,
    /// Use the [`Ledger::cometbft_dir()`] method to read the value.
    cometbft_dir: PathBuf,
    /// An optional action to take when a given blockheight is reached.
    pub action_at_height: Option<ActionAtHeight>,
    /// Specify if tendermint is started as validator, fullnode or seednode
    pub tendermint_mode: TendermintMode,
    /// A `tendermint_mode` set on the last node start-up, if any.
    pub last_tendermint_mode: Option<TendermintMode>,
    /// When set, indicates after how many blocks a new snapshot
    /// will be taken (counting from the first block)
    pub blocks_between_snapshots: Option<NonZeroU64>,
    /// Number of snapshots to keep
    pub snapshots_to_keep: Option<NonZeroU64>,
}

impl Ledger {
    pub fn new(
        base_dir: impl AsRef<Path>,
        chain_id: ChainId,
        mode: TendermintMode,
    ) -> Self {
        let mut tendermint_config =
            TendermintConfig::parse_toml(DEFAULT_COMETBFT_CONFIG).unwrap();
        tendermint_config.instrumentation.namespace = "namada_tm".to_string();
        tendermint_config.tx_index = TxIndexConfig {
            indexer: TxIndexer::Null,
        };
        Self {
            genesis_time: Rfc3339String("1970-01-01T00:00:00Z".to_owned()),
            chain_id,
            shell: Shell {
                base_dir: base_dir.as_ref().to_owned(),
                block_cache_bytes: None,
                vp_wasm_compilation_cache_bytes: None,
                tx_wasm_compilation_cache_bytes: None,
                // Default corresponds to 1 hour of past blocks at 1 block/sec
                storage_read_past_height_limit: Some(3600),
                db_dir: DB_DIR.into(),
                cometbft_dir: COMETBFT_DIR.into(),
                action_at_height: None,
                tendermint_mode: mode,
                last_tendermint_mode: None,
                blocks_between_snapshots: None,
                snapshots_to_keep: None,
            },
            cometbft: tendermint_config,
            ethereum_bridge: ethereum_bridge::ledger::Config::default(),
        }
    }

    /// Get the chain directory path
    pub fn chain_dir(&self) -> PathBuf {
        self.shell.base_dir.join(self.chain_id.as_str())
    }

    /// Get the directory path to the DB
    pub fn db_dir(&self) -> PathBuf {
        self.shell.db_dir(&self.chain_id)
    }

    /// Get the directory path to Tendermint
    pub fn cometbft_dir(&self) -> PathBuf {
        self.shell.cometbft_dir(&self.chain_id)
    }
}

impl Shell {
    /// Get the directory path to the DB
    pub fn db_dir(&self, chain_id: &ChainId) -> PathBuf {
        self.base_dir.join(chain_id.as_str()).join(&self.db_dir)
    }

    /// Get the directory path to Tendermint
    pub fn cometbft_dir(&self, chain_id: &ChainId) -> PathBuf {
        self.base_dir
            .join(chain_id.as_str())
            .join(&self.cometbft_dir)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error while reading config: {0}")]
    ReadError(config::ConfigError),
    #[error("Error while deserializing config: {0}")]
    DeserializationError(config::ConfigError),
    #[error("Error while serializing to toml: {0}")]
    TomlError(toml::ser::Error),
    #[error("Error while writing config: {0}")]
    WriteError(std::io::Error),
    #[error("A config file already exists in {0}")]
    AlreadyExistingConfig(PathBuf),
    #[error(
        "Bootstrap peer {0} is not valid. Format needs to be \
         {{protocol}}/{{ip}}/tcp/{{port}}/p2p/{{peerid}}"
    )]
    BadBootstrapPeerFormat(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum SerdeError {
    // This is needed for serde https://serde.rs/error-handling.html
    #[error(
        "Bootstrap peer {0} is not valid. Format needs to be \
         {{protocol}}/{{ip}}/tcp/{{port}}/p2p/{{peerid}}"
    )]
    BadBootstrapPeerFormat(String),
    #[error("{0}")]
    Message(String),
}

impl Config {
    pub fn new(
        base_dir: impl AsRef<Path>,
        chain_id: ChainId,
        mode: TendermintMode,
    ) -> Self {
        Self {
            wasm_dir: DEFAULT_WASM_DIR.into(),
            ledger: Ledger::new(base_dir, chain_id, mode),
        }
    }

    /// Load config from expected path in the `base_dir` or generate a new one
    /// if it doesn't exist. Terminates with an error if the config loading
    /// fails.
    pub fn load(
        base_dir: impl AsRef<Path>,
        chain_id: &ChainId,
        mode: Option<TendermintMode>,
    ) -> Self {
        let base_dir = base_dir.as_ref();
        match Self::read(base_dir, chain_id, mode) {
            Ok(mut config) => {
                config.ledger.shell.base_dir = base_dir.to_path_buf();
                config
            }
            Err(err) => {
                eprintln!(
                    "Tried to read config in {} but failed with: {}",
                    base_dir.display(),
                    err
                );
                cli::safe_exit(1)
            }
        }
    }

    /// Read the config from a file, or generate a default one and write it to
    /// a file if it doesn't already exist. Keys that are expected but not set
    /// in the config file are filled in with default values.
    pub fn read(
        base_dir: &Path,
        chain_id: &ChainId,
        mode: Option<TendermintMode>,
    ) -> Result<Self> {
        let file_path = Self::file_path(base_dir, chain_id);
        let file_name = file_path.to_str().expect("Expected UTF-8 file path");
        let mode = mode.unwrap_or(TendermintMode::Full);
        if !file_path.exists() {
            return Self::generate(base_dir, chain_id, mode, true);
        };
        let defaults = config::Config::try_from(&Self::new(
            base_dir,
            chain_id.clone(),
            mode,
        ))
        .map_err(Error::ReadError)?;
        let builder = config::Config::builder()
            .add_source(defaults)
            .add_source(config::File::with_name(file_name))
            .add_source(
                config::Environment::with_prefix("NAMADA")
                    .prefix_separator("_")
                    .separator("__"),
            );

        let config = builder.build().map_err(Error::ReadError)?;
        config
            .try_deserialize()
            .map_err(Error::DeserializationError)
    }

    /// Generate configuration and write it to a file.
    pub fn generate(
        base_dir: &Path,
        chain_id: &ChainId,
        mode: TendermintMode,
        replace: bool,
    ) -> Result<Self> {
        let config = Config::new(base_dir, chain_id.clone(), mode);
        config.write(base_dir, chain_id, replace)?;
        Ok(config)
    }

    /// Write configuration to a file.
    pub fn write(
        &self,
        base_dir: &Path,
        chain_id: &ChainId,
        replace: bool,
    ) -> Result<()> {
        let file_path = Self::file_path(base_dir, chain_id);
        let file_dir = file_path.parent().unwrap();
        create_dir_all(file_dir).map_err(Error::WriteError)?;
        if file_path.exists() && !replace {
            Err(Error::AlreadyExistingConfig(file_path))
        } else {
            let mut file =
                File::create(file_path).map_err(Error::WriteError)?;
            let toml = toml::ser::to_string(&self).map_err(Error::TomlError)?;
            file.write_all(toml.as_bytes()).map_err(Error::WriteError)
        }
    }

    /// Get the file path to the config
    pub fn file_path(
        base_dir: impl AsRef<Path>,
        chain_id: &ChainId,
    ) -> PathBuf {
        // Join base dir to the chain ID
        base_dir.as_ref().join(chain_id.to_string()).join(FILENAME)
    }
}

pub fn get_default_namada_folder() -> PathBuf {
    if let Some(project_dir) = ProjectDirs::from("", "", "Namada") {
        project_dir.data_local_dir().to_path_buf()
    } else {
        DEFAULT_BASE_DIR.into()
    }
}

// TODO(informalsystems/tendermint-rs#1368): Replaced
// `block_sync` and `blocksync` with `fast_sync` and `fastsync`
pub const DEFAULT_COMETBFT_CONFIG: &str = r#"

# This is a TOML config file.
# For more information, see https://github.com/toml-lang/toml

# NOTE: Any path below can be absolute (e.g. "/var/myawesomeapp/data") or
# relative to the home directory (e.g. "data"). The home directory is
# "$HOME/.cometbft" by default, but could be changed via $CMTHOME env variable
# or --home cmd flag.

#######################################################################
###                   Main Base Config Options                      ###
#######################################################################

# TCP or UNIX socket address of the ABCI application,
# or the name of an ABCI application compiled in with the CometBFT binary
proxy_app = "tcp://127.0.0.1:26658"

# A custom human readable name for this node
moniker = "technodrome"

# If this node is many blocks behind the tip of the chain, BlockSync
# allows them to catchup quickly by downloading blocks in parallel
# and verifying their commits
#
# Deprecated: this key will be removed and BlockSync will be enabled
# unconditionally in the next major release.
fast_sync = true

# Database backend: goleveldb | cleveldb | boltdb | rocksdb | badgerdb
# * goleveldb (github.com/syndtr/goleveldb - most popular implementation)
#   - pure go
#   - stable
# * cleveldb (uses levigo wrapper)
#   - fast
#   - requires gcc
#   - use cleveldb build tag (go build -tags cleveldb)
# * boltdb (uses etcd's fork of bolt - github.com/etcd-io/bbolt)
#   - EXPERIMENTAL
#   - may be faster is some use-cases (random reads - indexer)
#   - use boltdb build tag (go build -tags boltdb)
# * rocksdb (uses github.com/tecbot/gorocksdb)
#   - EXPERIMENTAL
#   - requires gcc
#   - use rocksdb build tag (go build -tags rocksdb)
# * badgerdb (uses github.com/dgraph-io/badger)
#   - EXPERIMENTAL
#   - use badgerdb build tag (go build -tags badgerdb)
db_backend = "goleveldb"

# Database directory
db_dir = "data"

# Output level for logging, including package level options
log_level = "info"

# Output format: 'plain' (colored text) or 'json'
log_format = "plain"

##### additional base config options #####

# Path to the JSON file containing the initial validator set and other meta data
genesis_file = "config/genesis.json"

# Path to the JSON file containing the private key to use as a validator in the consensus protocol
priv_validator_key_file = "config/priv_validator_key.json"

# Path to the JSON file containing the last sign state of a validator
priv_validator_state_file = "data/priv_validator_state.json"

# TCP or UNIX socket address for CometBFT to listen on for
# connections from an external PrivValidator process
priv_validator_laddr = ""

# Path to the JSON file containing the private key to use for node authentication in the p2p protocol
node_key_file = "config/node_key.json"

# Mechanism to connect to the ABCI application: socket | grpc
abci = "socket"

# If true, query the ABCI app on connecting to a new peer
# so the app can decide if we should keep the connection or not
filter_peers = false


#######################################################################
###                 Advanced Configuration Options                  ###
#######################################################################

#######################################################
###       RPC Server Configuration Options          ###
#######################################################
[rpc]

# TCP or UNIX socket address for the RPC server to listen on
laddr = "tcp://127.0.0.1:26657"

# A list of origins a cross-domain request can be executed from
# Default value '[]' disables cors support
# Use '["*"]' to allow any origin
cors_allowed_origins = []

# A list of methods the client is allowed to use with cross-domain requests
cors_allowed_methods = ["HEAD", "GET", "POST", ]

# A list of non simple headers the client is allowed to use with cross-domain requests
cors_allowed_headers = ["Origin", "Accept", "Content-Type", "X-Requested-With", "X-Server-Time", ]

# TCP or UNIX socket address for the gRPC server to listen on
# NOTE: This server only supports /broadcast_tx_commit
grpc_laddr = ""

# Maximum number of simultaneous connections.
# Does not include RPC (HTTP&WebSocket) connections. See max_open_connections
# If you want to accept a larger number than the default, make sure
# you increase your OS limits.
# 0 - unlimited.
# Should be < {ulimit -Sn} - {MaxNumInboundPeers} - {MaxNumOutboundPeers} - {N of wal, db and other open files}
# 1024 - 40 - 10 - 50 = 924 = ~900
grpc_max_open_connections = 900

# Activate unsafe RPC commands like /dial_seeds and /unsafe_flush_mempool
unsafe = false

# Maximum number of simultaneous connections (including WebSocket).
# Does not include gRPC connections. See grpc_max_open_connections
# If you want to accept a larger number than the default, make sure
# you increase your OS limits.
# 0 - unlimited.
# Should be < {ulimit -Sn} - {MaxNumInboundPeers} - {MaxNumOutboundPeers} - {N of wal, db and other open files}
# 1024 - 40 - 10 - 50 = 924 = ~900
max_open_connections = 900

# Maximum number of unique clientIDs that can /subscribe
# If you're using /broadcast_tx_commit, set to the estimated maximum number
# of broadcast_tx_commit calls per block.
max_subscription_clients = 100

# Maximum number of unique queries a given client can /subscribe to
# If you're using GRPC (or Local RPC client) and /broadcast_tx_commit, set to
# the estimated # maximum number of broadcast_tx_commit calls per block.
max_subscriptions_per_client = 5

# Experimental parameter to specify the maximum number of events a node will
# buffer, per subscription, before returning an error and closing the
# subscription. Must be set to at least 100, but higher values will accommodate
# higher event throughput rates (and will use more memory).
experimental_subscription_buffer_size = 200

# Experimental parameter to specify the maximum number of RPC responses that
# can be buffered per WebSocket client. If clients cannot read from the
# WebSocket endpoint fast enough, they will be disconnected, so increasing this
# parameter may reduce the chances of them being disconnected (but will cause
# the node to use more memory).
#
# Must be at least the same as "experimental_subscription_buffer_size",
# otherwise connections could be dropped unnecessarily. This value should
# ideally be somewhat higher than "experimental_subscription_buffer_size" to
# accommodate non-subscription-related RPC responses.
experimental_websocket_write_buffer_size = 200

# If a WebSocket client cannot read fast enough, at present we may
# silently drop events instead of generating an error or disconnecting the
# client.
#
# Enabling this experimental parameter will cause the WebSocket connection to
# be closed instead if it cannot read fast enough, allowing for greater
# predictability in subscription behavior.
experimental_close_on_slow_client = false

# How long to wait for a tx to be committed during /broadcast_tx_commit.
# WARNING: Using a value larger than 10s will result in increasing the
# global HTTP write timeout, which applies to all connections and endpoints.
# See https://github.com/tendermint/tendermint/issues/3435
timeout_broadcast_tx_commit = "10s"

# Maximum size of request body, in bytes
max_body_bytes = 1000000

# Maximum size of request header, in bytes
max_header_bytes = 1048576

# The path to a file containing certificate that is used to create the HTTPS server.
# Might be either absolute path or path related to CometBFT's config directory.
# If the certificate is signed by a certificate authority,
# the certFile should be the concatenation of the server's certificate, any intermediates,
# and the CA's certificate.
# NOTE: both tls_cert_file and tls_key_file must be present for CometBFT to create HTTPS server.
# Otherwise, HTTP server is run.
tls_cert_file = ""

# The path to a file containing matching private key that is used to create the HTTPS server.
# Might be either absolute path or path related to CometBFT's config directory.
# NOTE: both tls-cert-file and tls-key-file must be present for CometBFT to create HTTPS server.
# Otherwise, HTTP server is run.
tls_key_file = ""

# pprof listen address (https://golang.org/pkg/net/http/pprof)
pprof_laddr = ""

#######################################################
###           P2P Configuration Options             ###
#######################################################
[p2p]

# Address to listen for incoming connections
laddr = "tcp://0.0.0.0:26656"

# Address to advertise to peers for them to dial
# If empty, will use the same port as the laddr,
# and will introspect on the listener or use UPnP
# to figure out the address. ip and port are required
# example: 159.89.10.97:26656
external_address = ""

# Comma separated list of seed nodes to connect to
seeds = ""

# Comma separated list of nodes to keep persistent connections to
persistent_peers = ""

# UPNP port forwarding
upnp = false

# Path to address book
addr_book_file = "config/addrbook.json"

# Set true for strict address routability rules
# Set false for private or local networks
addr_book_strict = true

# Maximum number of inbound peers
max_num_inbound_peers = 40

# Maximum number of outbound peers to connect to, excluding persistent peers
max_num_outbound_peers = 10

# List of node IDs, to which a connection will be (re)established ignoring any existing limits
unconditional_peer_ids = ""

# Maximum pause when redialing a persistent peer (if zero, exponential backoff is used)
persistent_peers_max_dial_period = "0s"

# Time to wait before flushing messages out on the connection
flush_throttle_timeout = "100ms"

# Maximum size of a message packet payload, in bytes
max_packet_msg_payload_size = 1024

# Rate at which packets can be sent, in bytes/second
send_rate = 5120000

# Rate at which packets can be received, in bytes/second
recv_rate = 5120000

# Set true to enable the peer-exchange reactor
pex = true

# Seed mode, in which node constantly crawls the network and looks for
# peers. If another node asks it for addresses, it responds and disconnects.
#
# Does not work if the peer-exchange reactor is disabled.
seed_mode = false

# Comma separated list of peer IDs to keep private (will not be gossiped to other peers)
private_peer_ids = ""

# Toggle to disable guard against peers connecting from the same ip.
allow_duplicate_ip = false

# Peer connection configuration.
handshake_timeout = "20s"
dial_timeout = "3s"

#######################################################
###          Mempool Configuration Option          ###
#######################################################
[mempool]

# Mempool version to use:
#   1) "v0" - (default) FIFO mempool.
#   2) "v1" - prioritized mempool (deprecated; will be removed in the next release).
version = "v0"

recheck = true
broadcast = true
wal_dir = ""

# Maximum number of transactions in the mempool
size = 5000

# Limit the total size of all txs in the mempool.
# This only accounts for raw transactions (e.g. given 1MB transactions and
# max_txs_bytes=5MB, mempool will only accept 5 transactions).
max_txs_bytes = 1073741824

# Size of the cache (used to filter transactions we saw earlier) in transactions
cache_size = 10000

# Do not remove invalid transactions from the cache (default: false)
# Set to true if it's not possible for any invalid transaction to become valid
# again in the future.
keep-invalid-txs-in-cache = false

# Maximum size of a single transaction.
# NOTE: the max size of a tx transmitted over the network is {max_tx_bytes}.
max_tx_bytes = 1048576

# Maximum size of a batch of transactions to send to a peer
# Including space needed by encoding (one varint per transaction).
# XXX: Unused due to https://github.com/tendermint/tendermint/issues/5796
max_batch_bytes = 0

# ttl-duration, if non-zero, defines the maximum amount of time a transaction
# can exist for in the mempool.
#
# Note, if ttl-num-blocks is also defined, a transaction will be removed if it
# has existed in the mempool at least ttl-num-blocks number of blocks or if it's
# insertion time into the mempool is beyond ttl-duration.
ttl-duration = "0s"

# ttl-num-blocks, if non-zero, defines the maximum number of blocks a transaction
# can exist for in the mempool.
#
# Note, if ttl-duration is also defined, a transaction will be removed if it
# has existed in the mempool at least ttl-num-blocks number of blocks or if
# it's insertion time into the mempool is beyond ttl-duration.
ttl-num-blocks = 0

#######################################################
###         State Sync Configuration Options        ###
#######################################################
[statesync]
# State sync rapidly bootstraps a new node by discovering, fetching, and restoring a state machine
# snapshot from peers instead of fetching and replaying historical blocks. Requires some peers in
# the network to take and serve state machine snapshots. State sync is not attempted if the node
# has any local state (LastBlockHeight > 0). The node will have a truncated block history,
# starting from the height of the snapshot.
enable = false

# RPC servers (comma-separated) for light client verification of the synced state machine and
# retrieval of state data for node bootstrapping. Also needs a trusted height and corresponding
# header hash obtained from a trusted source, and a period during which validators can be trusted.
#
# For Cosmos SDK-based chains, trust_period should usually be about 2/3 of the unbonding time (~2
# weeks) during which they can be financially punished (slashed) for misbehavior.
rpc_servers = ""
trust_height = 0
trust_hash = ""
trust_period = "168h0m0s"

# Time to spend discovering snapshots before initiating a restore.
discovery_time = "15s"

# Temporary directory for state sync snapshot chunks, defaults to the OS tempdir (typically /tmp).
# Will create a new, randomly named directory within, and remove it when done.
temp_dir = ""

# The timeout duration before re-requesting a chunk, possibly from a different
# peer (default: 1 minute).
chunk_request_timeout = "10s"

# The number of concurrent chunk fetchers to run (default: 1).
chunk_fetchers = "4"

#######################################################
###       Block Sync Configuration Options          ###
#######################################################
[fastsync]

# Block Sync version to use:
#
# In v0.37, v1 and v2 of the block sync protocols were deprecated.
# Please use v0 instead.
#
#   1) "v0" - the default block sync implementation
version = "v0"

#######################################################
###         Consensus Configuration Options         ###
#######################################################
[consensus]

wal_file = "data/cs.wal/wal"

# How long we wait for a proposal block before prevoting nil
timeout_propose = "3s"
# How much timeout_propose increases with each round
timeout_propose_delta = "500ms"
# How long we wait after receiving +2/3 prevotes for “anything” (ie. not a single block or nil)
timeout_prevote = "1s"
# How much the timeout_prevote increases with each round
timeout_prevote_delta = "500ms"
# How long we wait after receiving +2/3 precommits for “anything” (ie. not a single block or nil)
timeout_precommit = "1s"
# How much the timeout_precommit increases with each round
timeout_precommit_delta = "500ms"
# How long we wait after committing a block, before starting on the new
# height (this gives us a chance to receive some more precommits, even
# though we already have +2/3).
timeout_commit = "1s"

# How many blocks to look back to check existence of the node's consensus votes before joining consensus
# When non-zero, the node will panic upon restart
# if the same consensus key was used to sign {double_sign_check_height} last blocks.
# So, validators should stop the state machine, wait for some blocks, and then restart the state machine to avoid panic.
double_sign_check_height = 0

# Make progress as soon as we have all the precommits (as if TimeoutCommit = 0)
skip_timeout_commit = false

# EmptyBlocks mode and possible interval between empty blocks
create_empty_blocks = true
create_empty_blocks_interval = "0s"

# Reactor sleep duration parameters
peer_gossip_sleep_duration = "100ms"
peer_query_maj23_sleep_duration = "2s"

#######################################################
###         Storage Configuration Options           ###
#######################################################
[storage]

# Set to true to discard ABCI responses from the state store, which can save a
# considerable amount of disk space. Set to false to ensure ABCI responses are
# persisted. ABCI responses are required for /block_results RPC queries, and to
# reindex events in the command-line tool.
discard_abci_responses = false

#######################################################
###   Transaction Indexer Configuration Options     ###
#######################################################
[tx_index]

# What indexer to use for transactions
#
# The application will set which txs to index. In some cases a node operator will be able
# to decide which txs to index based on configuration set in the application.
#
# Options:
#   1) "null"
#   2) "kv" (default) - the simplest possible indexer, backed by key-value storage (defaults to levelDB; see DBBackend).
# 		- When "kv" is chosen "tx.height" and "tx.hash" will always be indexed.
#   3) "psql" - the indexer services backed by PostgreSQL.
# When "kv" or "psql" is chosen "tx.height" and "tx.hash" will always be indexed.
indexer = "kv"

# The PostgreSQL connection configuration, the connection format:
#   postgresql://<user>:<password>@<host>:<port>/<db>?<opts>
psql-conn = ""

#######################################################
###       Instrumentation Configuration Options     ###
#######################################################
[instrumentation]

# When true, Prometheus metrics are served under /metrics on
# PrometheusListenAddr.
# Check out the documentation for the list of available metrics.
prometheus = false

# Address to listen for Prometheus collector(s) connections
prometheus_listen_addr = ":26660"

# Maximum number of simultaneous connections.
# If you want to accept a larger number than the default, make sure
# you increase your OS limits.
# 0 - unlimited.
max_open_connections = 3

# Instrumentation namespace
namespace = "cometbft"

"#;

#[cfg(test)]
mod tests {
    use std::env;

    use namada_sdk::chain::ChainId;
    use tempfile::tempdir;

    use super::{Config, DEFAULT_COMETBFT_CONFIG};
    use crate::config::TendermintMode;
    use crate::tendermint_config::TendermintConfig;

    #[test]
    fn test_default_cometbft_config() {
        assert!(TendermintConfig::parse_toml(DEFAULT_COMETBFT_CONFIG).is_ok());
    }

    /// Check that a key-val set from an env var gets applied to a loaded config
    #[test]
    fn test_config_env_var() {
        let base_dir = tempdir().unwrap();
        let chain_id = ChainId("ChainyMcChainFace".to_owned());

        Config::generate(
            base_dir.path(),
            &chain_id,
            TendermintMode::Full,
            true,
        )
        .unwrap();

        let moniker = "moniker_from_env";
        unsafe { env::set_var("NAMADA_LEDGER__COMETBFT__MONIKER", moniker) };
        let config = Config::load(&base_dir, &chain_id, None);

        assert_eq!(config.ledger.cometbft.moniker.as_ref(), moniker);
    }
}
