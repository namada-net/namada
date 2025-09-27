//! The ledger shell connects the ABCI++ interface with the Namada ledger app.
//!
//! Any changes applied before [`Shell::finalize_block`] might have to be
//! reverted, so any changes applied in the methods [`Shell::prepare_proposal`]
//! and [`Shell::process_proposal`] must be also reverted
//! (unless we can simply overwrite them in the next block).
//! More info in <https://github.com/anoma/namada/issues/362>.
pub mod block_alloc;
mod finalize_block;
mod init_chain;
pub use init_chain::InitChainValidation;
use namada_apps_lib::config::NodeLocalConfig;
use namada_sdk::state::StateRead;
use namada_vm::wasm::run::check_tx_allowed;
pub mod prepare_proposal;
use namada_sdk::ibc;
use namada_sdk::state::State;
pub mod process_proposal;
pub(super) mod queries;
mod snapshots;
mod stats;
#[cfg(any(test, feature = "testing"))]
#[allow(dead_code)]
pub mod testing;
mod vote_extensions;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
#[allow(unused_imports)]
use std::rc::Rc;

use namada_apps_lib::wallet::{self, ValidatorData, ValidatorKeys};
use namada_sdk::address::Address;
use namada_sdk::borsh::{BorshDeserialize, BorshSerializeExt};
use namada_sdk::chain::{BlockHeight, ChainId};
use namada_sdk::collections::HashMap;
use namada_sdk::eth_bridge::protocol::validation::bridge_pool_roots::validate_bp_roots_vext;
use namada_sdk::eth_bridge::protocol::validation::ethereum_events::validate_eth_events_vext;
use namada_sdk::eth_bridge::protocol::validation::validator_set_update::validate_valset_upd_vext;
use namada_sdk::eth_bridge::{EthBridgeQueries, EthereumOracleConfig};
use namada_sdk::ethereum_events::EthereumEvent;
use namada_sdk::events::log::EventLog;
use namada_sdk::gas::{Gas, GasMetering, TxGasMeter};
use namada_sdk::hash::Hash;
use namada_sdk::key::*;
use namada_sdk::migrations::ScheduledMigration;
use namada_sdk::parameters::{get_gas_scale, validate_tx_bytes};
use namada_sdk::proof_of_stake::storage::read_pos_params;
use namada_sdk::proof_of_stake::types::{
    ConsensusValidator, ValidatorSetUpdate,
};
use namada_sdk::state::tx_queue::ExpiredTx;
use namada_sdk::state::{
    DB, DBIter, EPOCH_SWITCH_BLOCKS_DELAY, FullAccessState, Sha256Hasher,
    StorageHasher, StorageRead, TempWlState, WlState,
};
use namada_sdk::storage::{Key, TxIndex};
use namada_sdk::tendermint::AppHash;
use namada_sdk::time::DateTimeUtc;
pub use namada_sdk::tx::data::ResultCode;
use namada_sdk::tx::data::{TxType, WrapperTx};
use namada_sdk::tx::{Section, Tx};
use namada_sdk::{
    eth_bridge, governance, hints, migrations, parameters, proof_of_stake,
    token,
};
use namada_vm::wasm::{TxCache, VpCache};
use namada_vm::{WasmCacheAccess, WasmCacheRwAccess};
use namada_vote_ext::EthereumTxData;
use thiserror::Error;
use tokio::sync::mpsc::{Receiver, UnboundedSender};

use super::ethereum_oracle::{self as oracle, last_processed_block};
use crate::config::{self, TendermintMode, ValidatorLocalConfig, genesis};
use crate::protocol::ShellParams;
use crate::shims::abcipp_shim_types::shim;
use crate::shims::abcipp_shim_types::shim::TakeSnapshot;
use crate::shims::abcipp_shim_types::shim::response::TxResult;
use crate::tendermint::abci::{request, response};
use crate::tendermint::{self, validator};
use crate::tendermint_proto::crypto::public_key;
use crate::{protocol, storage, tendermint_node};

/// A cap on a number of tx sections
pub const MAX_TX_SECTIONS_LEN: usize = 10_000;

fn key_to_tendermint(
    pk: &common::PublicKey,
) -> std::result::Result<public_key::Sum, ParsePublicKeyError> {
    match pk {
        common::PublicKey::Ed25519(_) => ed25519::PublicKey::try_from_pk(pk)
            .map(|pk| public_key::Sum::Ed25519(pk.serialize_to_vec())),
        common::PublicKey::Secp256k1(_) => {
            secp256k1::PublicKey::try_from_pk(pk)
                .map(|pk| public_key::Sum::Secp256k1(pk.serialize_to_vec()))
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error removing the DB data: {0}")]
    RemoveDB(std::io::Error),
    #[error("chain ID mismatch: {0}")]
    ChainId(String),
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecoding(namada_sdk::tx::DecodeError),
    #[error("Error trying to apply a transaction: {0}")]
    TxApply(protocol::Error),
    #[error("{0}")]
    Tendermint(tendermint_node::Error),
    #[error("{0}")]
    Ethereum(super::ethereum_oracle::Error),
    #[error("Server error: {0}")]
    TowerServer(String),
    #[error("{0}")]
    Broadcaster(tokio::sync::mpsc::error::TryRecvError),
    #[error("Error executing proposal {0}: {1}")]
    BadProposal(u64, String),
    #[error("Error reading wasm: {0:?}")]
    ReadingWasm(#[from] eyre::Error),
    #[error("Error loading wasm: {0}")]
    LoadingWasm(String),
    #[error("Error reading from or writing to storage: {0}")]
    Storage(#[from] namada_sdk::state::Error),
    #[error("Transaction replay attempt: {0}")]
    ReplayAttempt(String),
    #[error("Error with snapshots: {0}")]
    Snapshot(std::io::Error),
    #[error(
        "Received a finalize request for a block that was rejected by process \
         proposal"
    )]
    RejectedBlockProposal,
    #[error("Received an invalid block proposal")]
    InvalidBlockProposal,
}

impl From<Error> for TxResult {
    fn from(err: Error) -> Self {
        TxResult {
            code: 1,
            info: err.to_string(),
        }
    }
}

pub type ShellResult<T> = std::result::Result<T, Error>;

pub fn reset(config: config::Config, full_reset: bool) -> ShellResult<()> {
    // simply nuke the DB files
    let db_path = &config.ledger.db_dir();
    match std::fs::remove_dir_all(db_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        res => res.map_err(Error::RemoveDB)?,
    };

    if full_reset {
        std::fs::remove_dir_all(config.ledger.chain_dir()).unwrap()
    } else {
        // reset Tendermint state
        tendermint_node::reset(config.ledger.cometbft_dir())
            .map_err(Error::Tendermint)?;
    }
    Ok(())
}

pub fn rollback(config: config::Ledger) -> ShellResult<()> {
    // Rollback Tendermint state
    tracing::info!("Rollback Tendermint state");
    let tendermint_block_height =
        tendermint_node::rollback(config.cometbft_dir())
            .map_err(Error::Tendermint)?;

    // Rollback Namada state
    let db_path = config.shell.db_dir(&config.chain_id);
    let mut db = storage::PersistentDB::open(db_path, None);
    tracing::info!("Rollback Namada state");

    db.rollback(tendermint_block_height)
        .map_err(|e| Error::Storage(namada_sdk::state::Error::new(e)))
}

#[derive(Debug)]
#[allow(dead_code, clippy::large_enum_variant)]
pub(super) enum ShellMode {
    Validator {
        data: ValidatorData,
        broadcast_sender: UnboundedSender<Vec<u8>>,
        eth_oracle: Option<EthereumOracleChannels>,
        validator_local_config: Option<ValidatorLocalConfig>,
        local_config: Option<NodeLocalConfig>,
    },
    Full {
        local_config: Option<NodeLocalConfig>,
    },
    Seed,
}

/// A channel for pulling events from the Ethereum oracle
/// and queueing them up for inclusion in vote extensions
#[derive(Debug)]
pub(super) struct EthereumReceiver {
    channel: Receiver<EthereumEvent>,
    queue: BTreeSet<EthereumEvent>,
}

impl EthereumReceiver {
    /// Create a new [`EthereumReceiver`] from a channel connected
    /// to an Ethereum oracle
    pub fn new(channel: Receiver<EthereumEvent>) -> Self {
        Self {
            channel,
            queue: BTreeSet::new(),
        }
    }

    /// Pull Ethereum events from the oracle and queue them to
    /// be voted on.
    ///
    /// Since vote extensions require ordering of Ethereum
    /// events, we do that here. We also de-duplicate events.
    /// Events may be filtered out of the queue with a provided
    /// predicate.
    pub fn fill_queue<F>(&mut self, mut keep_event: F)
    where
        F: FnMut(&EthereumEvent) -> bool,
    {
        let mut new_events: usize = 0;
        let mut filtered_events: usize = 0;
        while let Ok(eth_event) = self.channel.try_recv() {
            if keep_event(&eth_event) && self.queue.insert(eth_event) {
                new_events =
                    new_events.checked_add(1).expect("Cannot overflow");
            } else {
                filtered_events =
                    filtered_events.checked_add(1).expect("Cannot overflow");
            }
        }
        if new_events
            .checked_add(filtered_events)
            .expect("Cannot overflow")
            > 0
        {
            tracing::info!(
                new_events,
                filtered_events,
                "received Ethereum events"
            );
        }
    }

    /// Get a copy of the queue
    pub fn get_events(&self) -> Vec<EthereumEvent> {
        self.queue.iter().cloned().collect()
    }

    /// Remove the given [`EthereumEvent`] from the queue, if present.
    ///
    /// **INVARIANT:** This method preserves the sorting and de-duplication
    /// of events in the queue.
    pub fn remove_event(&mut self, event: &EthereumEvent) {
        self.queue.remove(event);
    }
}

impl ShellMode {
    /// Get the validator address if ledger is in validator mode
    pub fn get_validator_address(&self) -> Option<&Address> {
        match &self {
            ShellMode::Validator { data, .. } => Some(&data.address),
            _ => None,
        }
    }

    /// Remove an Ethereum event from the internal queue
    pub fn dequeue_eth_event(&mut self, event: &EthereumEvent) {
        if let ShellMode::Validator {
            eth_oracle:
                Some(EthereumOracleChannels {
                    ethereum_receiver, ..
                }),
            ..
        } = self
        {
            ethereum_receiver.remove_event(event);
        }
    }

    /// Get the protocol keypair for this validator.
    pub fn get_protocol_key(&self) -> Option<&common::SecretKey> {
        match self {
            ShellMode::Validator {
                data:
                    ValidatorData {
                        keys:
                            ValidatorKeys {
                                protocol_keypair, ..
                            },
                        ..
                    },
                ..
            } => Some(protocol_keypair),
            _ => None,
        }
    }

    /// Get the Ethereum bridge keypair for this validator.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn get_eth_bridge_keypair(&self) -> Option<&common::SecretKey> {
        match self {
            ShellMode::Validator {
                data:
                    ValidatorData {
                        keys:
                            ValidatorKeys {
                                eth_bridge_keypair, ..
                            },
                        ..
                    },
                ..
            } => Some(eth_bridge_keypair),
            _ => None,
        }
    }

    /// If this node is a validator, broadcast a tx
    /// to the mempool using the broadcaster subprocess
    pub fn broadcast(&self, data: Vec<u8>) {
        if let Self::Validator {
            broadcast_sender, ..
        } = self
        {
            broadcast_sender
                .send(data)
                .expect("The broadcaster should be running for a validator");
        }
    }
}

#[derive(Clone, Debug, Default)]
pub enum MempoolTxType {
    /// A transaction that has not been validated by this node before
    #[default]
    NewTransaction,
    /// A transaction that has been validated at some previous level that may
    /// need to be validated again
    RecheckTransaction,
}

#[derive(Debug)]
pub struct SnapshotSync {
    pub next_chunk: u64,
    pub height: BlockHeight,
    pub expected: Vec<Hash>,
    pub strikes: u64,
    pub snapshot: std::fs::File,
}

#[derive(Debug)]
pub struct Shell<D = storage::PersistentDB, H = Sha256Hasher>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// The id of the current chain
    pub chain_id: ChainId,
    /// The persistent storage with write log
    pub state: FullAccessState<D, H>,
    /// Path to the base directory with DB data and configs
    #[allow(dead_code)]
    pub(crate) base_dir: PathBuf,
    /// Path to the WASM directory for files used in the genesis block.
    pub(super) wasm_dir: PathBuf,
    /// Information about the running shell instance
    pub(crate) mode: ShellMode,
    /// VP WASM compilation cache
    pub vp_wasm_cache: VpCache<WasmCacheRwAccess>,
    /// Tx WASM compilation cache
    pub tx_wasm_cache: TxCache<WasmCacheRwAccess>,
    /// Taken from config `storage_read_past_height_limit`. When set, will
    /// limit the how many block heights in the past can the storage be
    /// queried for reading values.
    storage_read_past_height_limit: Option<u64>,
    /// Log of events emitted by `FinalizeBlock` ABCI calls.
    event_log: EventLog,
    /// A migration that can be scheduled at a given block height
    pub scheduled_migration: Option<ScheduledMigration>,
    /// When set, indicates after how many blocks a new snapshot
    /// will be taken (counting from the first block)
    pub blocks_between_snapshots: Option<NonZeroU64>,
    /// Data for a node downloading and apply snapshots as part of
    /// the fast sync protocol.
    pub syncing: Option<SnapshotSync>,
}

/// Storage key filter to store the diffs into the storage. Return `false` for
/// keys whose diffs shouldn't be stored.
pub fn is_key_diff_storable(key: &namada_sdk::storage::Key) -> bool {
    !(token::storage_key::is_masp_key(key)
        && *key != token::storage_key::masp_convert_anchor_key()
        && *key != token::storage_key::masp_token_map_key()
        && *key != token::storage_key::masp_assets_hash_key()
        && token::storage_key::is_masp_commitment_anchor_key(key).is_none()
        && !token::storage_key::is_masp_base_native_precision_key(key)
        || ibc::storage::is_ibc_counter_key(key)
        || proof_of_stake::storage_key::is_delegation_targets_key(key))
}

/// Channels for communicating with an Ethereum oracle.
#[derive(Debug)]
pub struct EthereumOracleChannels {
    ethereum_receiver: EthereumReceiver,
    control_sender: oracle::control::Sender,
    last_processed_block_receiver: last_processed_block::Receiver,
}

impl EthereumOracleChannels {
    pub fn new(
        events_receiver: Receiver<EthereumEvent>,
        control_sender: oracle::control::Sender,
        last_processed_block_receiver: last_processed_block::Receiver,
    ) -> Self {
        Self {
            ethereum_receiver: EthereumReceiver::new(events_receiver),
            control_sender,
            last_processed_block_receiver,
        }
    }
}

impl Shell<crate::storage::PersistentDB, Sha256Hasher> {
    /// Restore the database with data fetched from the State Sync protocol.
    pub fn restore_database_from_state_sync(&mut self) {
        let Some(syncing) = self.syncing.as_mut() else {
            return;
        };

        let db_block_cache_size_bytes = {
            let config = crate::config::Config::load(
                &self.base_dir,
                &self.chain_id,
                None,
            );

            config.ledger.shell.block_cache_bytes.unwrap_or_else(|| {
                use sysinfo::{MemoryRefreshKind, RefreshKind, System};

                let sys = System::new_with_specifics(
                    RefreshKind::nothing()
                        .with_memory(MemoryRefreshKind::everything()),
                );
                let available_memory_bytes = sys.available_memory();

                available_memory_bytes / 3
            })
        };

        let db_cache = rocksdb::Cache::new_lru_cache(
            usize::try_from(db_block_cache_size_bytes).expect(
                "`db_block_cache_size_bytes` must not exceed `usize::MAX`",
            ),
        );

        self.state
            .db_mut()
            .restore_from((&db_cache, &mut syncing.snapshot))
            .expect("Failed to restore state from snapshot");

        // rebuild the in-memory state
        self.state.load_last_state();
    }
}

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Create a new shell from a path to a database and a chain id. Looks
    /// up the database with this data and tries to load the last state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: config::Ledger,
        wasm_dir: PathBuf,
        broadcast_sender: UnboundedSender<Vec<u8>>,
        eth_oracle: Option<EthereumOracleChannels>,
        db_cache: Option<&D::Cache>,
        scheduled_migration: Option<ScheduledMigration>,
        vp_wasm_compilation_cache: u64,
        tx_wasm_compilation_cache: u64,
    ) -> Self {
        let chain_id = config.chain_id;
        let db_path = config.shell.db_dir(&chain_id);
        let base_dir = config.shell.base_dir;
        let mode = config.shell.tendermint_mode;
        let storage_read_past_height_limit =
            config.shell.storage_read_past_height_limit;
        if !Path::new(&base_dir).is_dir() {
            std::fs::create_dir(&base_dir)
                .expect("Creating directory for Namada should not fail");
        }

        // For tests, fuzzing and benches use hard-coded native token addr ...
        #[cfg(any(test, fuzzing, feature = "benches"))]
        let native_token = {
            let chain_dir = base_dir.join(chain_id.as_str());
            // Use genesis file only if it exists
            if chain_dir
                .join(genesis::templates::TOKENS_FILE_NAME)
                .exists()
            {
                genesis::chain::Finalized::read_native_token(&chain_dir)
                    .expect("Missing genesis files")
            } else {
                namada_sdk::address::testing::nam()
            }
        };
        // ... Otherwise, look it up from the genesis file
        #[cfg(not(any(test, fuzzing, feature = "benches")))]
        let native_token = {
            let chain_dir = base_dir.join(chain_id.as_str());
            genesis::chain::Finalized::read_native_token(&chain_dir)
                .expect("Missing genesis files")
        };

        // load last state from storage
        let state = FullAccessState::open(
            db_path,
            db_cache,
            chain_id.clone(),
            native_token,
            config.shell.storage_read_past_height_limit,
            is_key_diff_storable,
        );
        let vp_wasm_cache_dir =
            base_dir.join(chain_id.as_str()).join("vp_wasm_cache");
        let tx_wasm_cache_dir =
            base_dir.join(chain_id.as_str()).join("tx_wasm_cache");
        // load in keys and address from wallet if mode is set to `Validator`
        let mode = match mode {
            TendermintMode::Validator => {
                #[cfg(not(any(test, fuzzing)))]
                {
                    let wallet_path = &base_dir.join(chain_id.as_str());
                    tracing::debug!(
                        "Loading wallet from {}",
                        wallet_path.to_string_lossy()
                    );
                    let mut wallet = wallet::load(wallet_path)
                        .expect("Validator node must have a wallet");
                    let validator_local_config_path =
                        wallet_path.join("validator_local_config.toml");
                    let local_config_path =
                        wallet_path.join("local_config.toml");

                    let validator_local_config: Option<ValidatorLocalConfig> =
                        if Path::is_file(&validator_local_config_path) {
                            Some(
                                toml::from_str(
                                    &std::fs::read_to_string(
                                        validator_local_config_path,
                                    )
                                    .unwrap(),
                                )
                                .unwrap(),
                            )
                        } else {
                            None
                        };

                    let local_config: Option<NodeLocalConfig> =
                        if Path::is_file(&local_config_path) {
                            Some(
                                toml::from_str(
                                    &std::fs::read_to_string(local_config_path)
                                        .unwrap(),
                                )
                                .unwrap(),
                            )
                        } else {
                            None
                        };

                    wallet
                        .take_validator_data()
                        .map(|data| ShellMode::Validator {
                            data,
                            broadcast_sender,
                            eth_oracle,
                            validator_local_config,
                            local_config,
                        })
                        .expect(
                            "Validator data should have been stored in the \
                             wallet",
                        )
                }
                #[cfg(any(test, fuzzing))]
                {
                    let (protocol_keypair, eth_bridge_keypair) =
                        wallet::defaults::validator_keys();
                    ShellMode::Validator {
                        data: ValidatorData {
                            address: wallet::defaults::validator_address(),
                            keys: ValidatorKeys {
                                protocol_keypair,
                                eth_bridge_keypair,
                            },
                        },
                        broadcast_sender,
                        eth_oracle,
                        validator_local_config: None,
                        local_config: None,
                    }
                }
            }
            TendermintMode::Full => {
                #[cfg(not(test))]
                {
                    let local_config_path = &base_dir
                        .join(chain_id.as_str())
                        .join("local_config.toml");

                    let local_config: Option<NodeLocalConfig> =
                        if Path::is_file(local_config_path) {
                            Some(
                                toml::from_str(
                                    &std::fs::read_to_string(local_config_path)
                                        .unwrap(),
                                )
                                .unwrap(),
                            )
                        } else {
                            None
                        };

                    ShellMode::Full { local_config }
                }
                #[cfg(test)]
                {
                    ShellMode::Full { local_config: None }
                }
            }
            TendermintMode::Seed => ShellMode::Seed,
        };

        if let Some(schedule_migration) = scheduled_migration.as_ref() {
            #[allow(clippy::disallowed_methods)]
            let current = state.get_block_height().unwrap_or_default();
            if schedule_migration.height < current {
                panic!(
                    "Cannot schedule a migration earlier than the latest \
                     block height({})",
                    current
                );
            }
        }

        let mut shell = Self {
            chain_id,
            state,
            base_dir,
            wasm_dir,
            mode,
            vp_wasm_cache: VpCache::new(
                vp_wasm_cache_dir,
                usize::try_from(vp_wasm_compilation_cache).expect(
                    "`vp_wasm_compilation_cache` must not exceed `usize::MAX`",
                ),
            ),
            tx_wasm_cache: TxCache::new(
                tx_wasm_cache_dir,
                usize::try_from(tx_wasm_compilation_cache).expect(
                    "`tx_wasm_compilation_cache` must not exceed `usize::MAX`",
                ),
            ),
            storage_read_past_height_limit,
            // TODO(namada#3237): config event log params
            event_log: EventLog::default(),
            scheduled_migration,
            blocks_between_snapshots: config.shell.blocks_between_snapshots,
            syncing: None,
        };
        shell.update_eth_oracle(&Default::default());
        shell
    }

    /// Return a reference to the [`EventLog`].
    #[inline]
    pub fn event_log(&self) -> &EventLog {
        &self.event_log
    }

    /// Return a mutable reference to the [`EventLog`].
    #[inline]
    pub fn event_log_mut(&mut self) -> &mut EventLog {
        &mut self.event_log
    }

    /// Load the Merkle root hash and the height of the last committed block, if
    /// any. This is returned when ABCI sends an `info` request.
    pub fn last_state(&self, namada_version: &str) -> response::Info {
        let version = namada_version.to_string();
        let consensus_version = namada_sdk::consensus_version();
        let other_data: HashMap<&str, &str> =
            HashMap::from_iter([("libs_version", env!("CARGO_PKG_VERSION"))]);
        let data = serde_json::to_string(&other_data)
            .expect("Must be able to display json");
        let response = response::Info {
            data,
            version,
            app_version: consensus_version,
            ..response::Info::default()
        };
        if crate::migrating_state().is_some() {
            // When migrating state, return a height of 0, such
            // that CometBFT calls InitChain and subsequently
            // updates the apphash in its state.
            return response::Info {
                last_block_height: 0u32.into(),
                ..response
            };
        }
        let mut response = response::Info {
            last_block_height: tendermint::block::Height::from(0_u32),
            ..response
        };
        let result = self.state.in_mem().get_state();

        match result {
            Some((root, height)) => {
                tracing::info!(
                    "Last state root hash: {}, height: {}",
                    root,
                    height
                );
                response.last_block_app_hash =
                    AppHash::try_from(root.0.to_vec())
                        .expect("expected a valid app hash");
                response.last_block_height =
                    height.try_into().expect("Invalid block height");
            }
            None => {
                tracing::info!(
                    "No state could be found, chain is not initialized"
                );
            }
        };

        response
    }

    /// Read the value for a storage key dropping any error
    pub fn read_storage_key<T>(&self, key: &Key) -> Option<T>
    where
        T: Clone + BorshDeserialize,
    {
        let result = self.state.db_read(key);

        match result {
            Ok((bytes, _gas)) => match bytes {
                Some(bytes) => T::try_from_slice(&bytes).ok(),
                None => None,
            },
            Err(_) => None,
        }
    }

    /// Read the bytes for a storage key dropping any error
    pub fn read_storage_key_bytes(&self, key: &Key) -> Option<Vec<u8>> {
        let result = self.state.db_read(key);

        match result {
            Ok((bytes, _gas)) => bytes,
            Err(_) => None,
        }
    }

    /// Get the next epoch for which we can request validator set changed
    pub fn get_validator_set_update_epoch(
        &self,
        current_epoch: namada_sdk::chain::Epoch,
    ) -> namada_sdk::chain::Epoch {
        if let Some(delay) = self.state.in_mem().update_epoch_blocks_delay {
            if delay == EPOCH_SWITCH_BLOCKS_DELAY {
                // If we're about to update validator sets for the
                // upcoming epoch, we can still remove the validator
                current_epoch.next()
            } else {
                // If we're waiting to switch to a new epoch, it's too
                // late to update validator sets
                // on the next epoch, so we need to
                // wait for the one after.
                current_epoch.next().next()
            }
        } else {
            current_epoch.next()
        }
    }

    /// Commit a block. Persist the application state and return the Merkle root
    /// hash.
    pub fn commit(&mut self) -> shim::Response {
        self.bump_last_processed_eth_block();
        let height_to_commit = self.state.in_mem().block.height;

        let migration = match self.scheduled_migration.as_ref() {
            Some(migration) if height_to_commit == migration.height => Some(
                self.scheduled_migration
                    .take()
                    .unwrap()
                    .load_and_validate()
                    .expect("The scheduled migration is not valid."),
            ),
            _ => None,
        };

        self.state
            .commit_block()
            .expect("Encountered a storage error while committing a block");

        if let Some(migration) = migration {
            migrations::commit(&mut self.state, migration);
            self.state
                .update_last_block_merkle_tree()
                .expect("Must update merkle tree after migration");
        }

        let merkle_root = self.state.in_mem().merkle_root();

        tracing::info!(
            "Committed block hash: {merkle_root}, height: {height_to_commit}",
        );

        self.broadcast_queued_txs();
        let take_snapshot = self.check_snapshot_required();

        shim::Response::Commit(
            response::Commit {
                // NB: by passing 0, we forbid CometBFT from deleting
                // data pertaining to past blocks
                retain_height: tendermint::block::Height::from(0_u32),
                // NB: current application hash
                data: merkle_root.0.to_vec().into(),
            },
            take_snapshot,
        )
    }

    /// Check if we have reached a block height at which we should take a
    /// snapshot
    fn check_snapshot_required(&self) -> TakeSnapshot {
        let committed_height = self.state.in_mem().get_last_block_height();
        let take_snapshot = match self.blocks_between_snapshots {
            Some(b) => committed_height.0 % b == 0,
            _ => false,
        };
        if take_snapshot {
            self.state
                .db()
                .path()
                .map(|p| (p, self.state.in_mem().get_last_block_height()))
                .into()
        } else {
            TakeSnapshot::No
        }
    }

    /// Updates the Ethereum oracle's last processed block.
    #[inline]
    fn bump_last_processed_eth_block(&mut self) {
        if let ShellMode::Validator {
            eth_oracle: Some(eth_oracle),
            ..
        } = &self.mode
        {
            // update the oracle's last processed eth block
            let last_processed_block = eth_oracle
                .last_processed_block_receiver
                .borrow()
                .as_ref()
                .cloned();
            if let Some(eth_height) = last_processed_block {
                tracing::info!(
                    "Ethereum oracle's most recently processed Ethereum block \
                     is {}",
                    eth_height
                );
                self.state.in_mem_mut().ethereum_height = Some(eth_height);
            }
        }
    }

    /// Empties all the ledger's queues of transactions to be broadcasted
    /// via CometBFT's P2P network.
    #[inline]
    fn broadcast_queued_txs(&mut self) {
        if let ShellMode::Validator { .. } = &self.mode {
            self.broadcast_protocol_txs();
            self.broadcast_expired_txs();
        }
    }

    /// Broadcast any pending protocol transactions.
    fn broadcast_protocol_txs(&mut self) {
        use crate::shell::vote_extensions::iter_protocol_txs;

        let ext = self.craft_extension();

        let protocol_key = self
            .mode
            .get_protocol_key()
            .expect("Validators should have protocol keys");

        let protocol_txs = iter_protocol_txs(ext).map(|protocol_tx| {
            protocol_tx
                .sign(protocol_key, self.chain_id.clone())
                .to_bytes()
        });

        for tx in protocol_txs {
            self.mode.broadcast(tx);
        }
    }

    /// Broadcast any expired transactions.
    fn broadcast_expired_txs(&mut self) {
        let eth_events = {
            let mut events: Vec<_> = self
                .state
                .in_mem_mut()
                .expired_txs_queue
                .drain()
                .map(|expired_tx| match expired_tx {
                    ExpiredTx::EthereumEvent(event) => event,
                })
                .collect();
            events.sort();
            events
        };
        if hints::likely(eth_events.is_empty()) {
            // more often than not, there won't by any expired
            // Ethereum events to retransmit
            return;
        }
        if let Some(vote_extension) = self.sign_ethereum_events(eth_events) {
            let protocol_key = self
                .mode
                .get_protocol_key()
                .expect("Validators should have protocol keys");

            let signed_tx = EthereumTxData::EthEventsVext(
                namada_vote_ext::ethereum_events::SignedVext(vote_extension),
            )
            .sign(protocol_key, self.chain_id.clone())
            .to_bytes();

            self.mode.broadcast(signed_tx);
        }
    }

    /// If a handle to an Ethereum oracle was provided to the [`Shell`], attempt
    /// to send it an updated configuration, using a configuration
    /// based on Ethereum bridge parameters in blockchain storage.
    ///
    /// This method must be safe to call even before ABCI `InitChain` has been
    /// called (i.e. when storage is empty), as we may want to do this check
    /// every time the shell starts up (including the first time ever at which
    /// time storage will be empty).
    ///
    /// This method is also called during `FinalizeBlock` to update the oracle
    /// if relevant storage changes have occurred. This includes deactivating
    /// and reactivating the bridge.
    fn update_eth_oracle(&mut self, changed_keys: &BTreeSet<Key>) {
        if let ShellMode::Validator {
            eth_oracle: Some(EthereumOracleChannels { control_sender, .. }),
            ..
        } = &mut self.mode
        {
            // We *always* expect a value describing the status of the Ethereum
            // bridge to be present under [`eth_bridge::storage::active_key`],
            // once a chain has been initialized. We need to explicitly check if
            // this key is present here because we may be starting up the shell
            // for the first time ever, in which case the chain hasn't been
            // initialized yet.
            let has_key = self
                .state
                .has_key(&eth_bridge::storage::active_key())
                .expect(
                    "We should always be able to check whether a key exists \
                     in storage or not",
                );
            if !has_key {
                tracing::debug!(
                    "Not starting oracle yet as storage has not been \
                     initialized"
                );
                return;
            }
            let Some(config) = EthereumOracleConfig::read(&self.state) else {
                tracing::debug!(
                    "Not starting oracle as the Ethereum bridge config \
                     couldn't be found in storage"
                );
                return;
            };
            let active = if !self.state.ethbridge_queries().is_bridge_active() {
                if !changed_keys.contains(&eth_bridge::storage::active_key()) {
                    tracing::debug!(
                        "Not starting oracle as the Ethereum bridge is \
                         disabled"
                    );
                    return;
                } else {
                    tracing::debug!(
                        "Disabling oracle as the bridge has been disabled"
                    );
                    false
                }
            } else {
                true
            };

            let start_block = self
                .state
                .in_mem()
                .ethereum_height
                .clone()
                .unwrap_or(config.eth_start_height);
            tracing::info!(
                ?start_block,
                "Found Ethereum height from which the Ethereum oracle should \
                 be updated"
            );
            let config = eth_bridge::oracle::config::Config {
                min_confirmations: config.min_confirmations.into(),
                bridge_contract: config.contracts.bridge.address,
                start_block,
                active,
            };
            tracing::info!(
                ?config,
                "Updating the Ethereum oracle using values from block storage"
            );
            if let Err(error) = control_sender
                .try_send(oracle::control::Command::UpdateConfig(config))
            {
                match error {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                        panic!(
                            "The Ethereum oracle communication channel is \
                             full!"
                        )
                    }
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                        panic!(
                            "The Ethereum oracle can no longer be \
                             communicated with"
                        )
                    }
                }
            }
        }
    }

    /// Validate a transaction request. On success, the transaction will
    /// included in the mempool and propagated to peers, otherwise it will be
    /// rejected.
    pub fn mempool_validate(
        &self,
        tx_bytes: &[u8],
        r#_type: MempoolTxType,
    ) -> response::CheckTx {
        use namada_sdk::tx::data::protocol::ProtocolTxType;
        use namada_vote_ext::ethereum_tx_data_variants;

        let mut response = response::CheckTx::default();

        const VALID_MSG: &str = "Mempool validation passed";
        const INVALID_MSG: &str = "Mempool validation failed";

        // check tx bytes
        //
        // NB: always keep this as the first tx check,
        // as it is a pretty cheap one
        if !validate_tx_bytes(&self.state, tx_bytes.len())
            .expect("Failed to get max tx bytes param from storage")
        {
            response.code = ResultCode::TooLarge.into();
            response.log = format!("{INVALID_MSG}: Tx too large");
            return response;
        }

        // Tx format check
        let tx = match Tx::try_from_bytes(tx_bytes).map_err(Error::TxDecoding) {
            Ok(t) => t,
            Err(msg) => {
                response.code = ResultCode::InvalidTx.into();
                response.log = format!("{INVALID_MSG}: {msg}");
                return response;
            }
        };

        // Tx chain id
        #[cfg(not(fuzzing))]
        if tx.header.chain_id != self.chain_id {
            response.code = ResultCode::InvalidChainId.into();
            response.log = format!(
                "{INVALID_MSG}: Tx carries a wrong chain id: expected {}, \
                 found {}",
                self.chain_id, tx.header.chain_id
            );
            return response;
        }

        // Tx section count check
        #[cfg(any(test, not(feature = "benches")))]
        if tx.sections.len() > MAX_TX_SECTIONS_LEN {
            response.code = ResultCode::InvalidTx.into();
            response.log = format!(
                "{INVALID_MSG}: Tx contains more than {MAX_TX_SECTIONS_LEN} \
                 sections."
            );
            return response;
        }

        // Tx expiration
        if let Some(exp) = tx.header.expiration {
            let last_block_timestamp = self
                .state
                .get_last_block_timestamp()
                .expect("Failed to retrieve last block timestamp");

            if last_block_timestamp > exp {
                response.code = ResultCode::ExpiredTx.into();
                response.log = format!(
                    "{INVALID_MSG}: Tx expired at {exp:#?}, last committed \
                     block time: {last_block_timestamp:#?}",
                );
                return response;
            }
        }

        // Tx signature check
        let tx_type = match tx.validate_tx() {
            Ok(_) => tx.header(),
            Err(msg) => {
                response.code = ResultCode::InvalidSig.into();
                response.log = format!("{INVALID_MSG}: {msg}");
                return response;
            }
        };

        // try to parse a vote extension protocol tx from
        // the provided tx data
        macro_rules! try_vote_extension {
            ($kind:expr, $rsp:expr, $result:expr $(,)?) => {
                match $result {
                    Ok(ext) => ext,
                    Err(err) => {
                        $rsp.code = ResultCode::InvalidVoteExtension.into();
                        $rsp.log = format!(
                            "{INVALID_MSG}: Invalid {} vote extension: {err}",
                            $kind,
                        );
                        return $rsp;
                    }
                }
            };
        }

        match tx_type.tx_type {
            TxType::Protocol(protocol_tx) => match protocol_tx.tx {
                ProtocolTxType::EthEventsVext => {
                    let ext = try_vote_extension!(
                        "Ethereum events",
                        response,
                        ethereum_tx_data_variants::EthEventsVext::try_from(&tx),
                    );
                    if let Err(err) =
                        validate_eth_events_vext::<_, _, governance::Store<_>>(
                            &self.state,
                            &ext.0,
                            self.state.in_mem().get_last_block_height(),
                        )
                    {
                        response.code = ResultCode::InvalidVoteExtension.into();
                        response.log = format!(
                            "{INVALID_MSG}: Invalid Ethereum events vote \
                             extension: {err}",
                        );
                    } else {
                        response.log = String::from(VALID_MSG);
                    }
                }
                ProtocolTxType::BridgePoolVext => {
                    let ext = try_vote_extension!(
                        "Bridge pool roots",
                        response,
                        ethereum_tx_data_variants::BridgePoolVext::try_from(
                            &tx
                        ),
                    );
                    if let Err(err) =
                        validate_bp_roots_vext::<_, _, governance::Store<_>>(
                            &self.state,
                            &ext.0,
                            self.state.in_mem().get_last_block_height(),
                        )
                    {
                        response.code = ResultCode::InvalidVoteExtension.into();
                        response.log = format!(
                            "{INVALID_MSG}: Invalid Bridge pool roots vote \
                             extension: {err}",
                        );
                    } else {
                        response.log = String::from(VALID_MSG);
                    }
                }
                ProtocolTxType::ValSetUpdateVext => {
                    let ext = try_vote_extension!(
                        "validator set update",
                        response,
                        ethereum_tx_data_variants::ValSetUpdateVext::try_from(
                            &tx
                        ),
                    );
                    if let Err(err) =
                        validate_valset_upd_vext::<_, _, governance::Store<_>>(
                            &self.state,
                            &ext,
                            // n.b. only accept validator set updates
                            // issued at the last committed epoch
                            // (signing off on the validators of the
                            // next epoch). at the second height
                            // within an epoch, the new epoch is
                            // committed to storage, so `last_epoch`
                            // reflects the current value of the
                            // epoch.
                            self.state.in_mem().last_epoch,
                        )
                    {
                        response.code = ResultCode::InvalidVoteExtension.into();
                        response.log = format!(
                            "{INVALID_MSG}: Invalid validator set update vote \
                             extension: {err}",
                        );
                    } else {
                        response.log = String::from(VALID_MSG);
                        // validator set update votes should be decided
                        // as soon as possible
                        response.priority = i64::MAX;
                    }
                }
                _ => {
                    response.code = ResultCode::InvalidTx.into();
                    response.log = format!(
                        "{INVALID_MSG}: The given protocol tx cannot be added \
                         to the mempool"
                    );
                }
            },
            TxType::Wrapper(wrapper) => {
                // Get the gas scale first
                let gas_scale = match get_gas_scale(&self.state) {
                    Ok(scale) => scale,
                    Err(_) => {
                        response.code = ResultCode::InvalidTx.into();
                        response.log = "The gas scale could not be found in \
                                        the parameters storage"
                            .to_string();
                        return response;
                    }
                };

                // Validate wrapper first
                // Tx gas limit
                let gas_limit = match wrapper.gas_limit.as_scaled_gas(gas_scale)
                {
                    Ok(value) => value,
                    Err(_) => {
                        response.code = ResultCode::InvalidTx.into();
                        response.log = "The wrapper gas limit overflowed gas \
                                        representation"
                            .to_string();
                        return response;
                    }
                };
                let mut gas_meter = TxGasMeter::new(gas_limit, gas_scale);
                if gas_meter.add_wrapper_gas(tx_bytes).is_err() {
                    response.code = ResultCode::TxGasLimit.into();
                    response.log = format!(
                        "{INVALID_MSG}: Wrapper transaction exceeds its gas \
                         limit"
                    )
                    .to_string();
                    return response;
                }

                // Max block gas
                let max_block_gas =
                    parameters::get_max_block_gas(&self.state).unwrap();
                let block_gas_limit: Gas =
                    Gas::from_whole_units(max_block_gas.into(), gas_scale)
                        .expect("Gas limit from parameter must not overflow");
                if gas_meter.get_gas_limit() > block_gas_limit {
                    response.code = ResultCode::AllocationError.into();
                    response.log = format!(
                        "{INVALID_MSG}: Wrapper transaction exceeds the \
                         maximum block gas limit: {}",
                        max_block_gas
                    );
                    return response;
                }

                // Replay protection
                let wrapper_hash = &tx.header_hash();
                if self.state.has_replay_protection_entry(wrapper_hash).expect(
                    "Error while checking wrapper tx hash key in storage",
                ) {
                    response.code = ResultCode::ReplayTx.into();
                    response.log = format!(
                        "{INVALID_MSG}: Wrapper transaction hash {} already \
                         in storage, replay attempt",
                        wrapper_hash
                    );
                    return response;
                }
                let batch_tx_hash = &tx.raw_header_hash();
                if self
                    .state
                    .has_replay_protection_entry(batch_tx_hash)
                    .expect("Error while checking batch tx hash key in storage")
                {
                    response.code = ResultCode::ReplayTx.into();
                    response.log = format!(
                        "{INVALID_MSG}: Batch transaction hash {} already in \
                         storage, replay attempt",
                        batch_tx_hash
                    );
                    return response;
                }

                // Validate the inner txs after. Even if the batch is non-atomic
                // we still reject it if just one of the inner txs is
                // invalid
                for cmt in tx.commitments() {
                    // Tx allowlist
                    if let Err(err) =
                        check_tx_allowed(&tx.batch_ref_tx(cmt), &self.state)
                    {
                        response.code = ResultCode::TxNotAllowlisted.into();
                        response.log = format!(
                            "{INVALID_MSG}: Wrapper transaction code didn't \
                             pass the allowlist checks {}",
                            err
                        );
                        return response;
                    }
                }

                // This is safe as neither the inner `db` nor `in_mem` are
                // actually mutable, only the `write_log` which is owned by
                // the `TempWlState` struct. The `TempWlState` will be dropped
                // before any other ABCI request is processed.
                let mut temp_state =
                    unsafe { self.state.with_static_temp_write_log() };

                // Validate wrapper fees
                if let Err(e) = mempool_fee_check(
                    &mut ShellParams::new(
                        &RefCell::new(gas_meter),
                        &mut temp_state,
                        &mut self.vp_wasm_cache.clone(),
                        &mut self.tx_wasm_cache.clone(),
                    ),
                    &tx,
                    &wrapper,
                ) {
                    response.code = ResultCode::FeeError.into();
                    response.log = format!("{INVALID_MSG}: {e}");
                    return response;
                }
            }
            TxType::Raw => {
                response.code = ResultCode::InvalidTx.into();
                response.log = format!(
                    "{INVALID_MSG}: Raw transactions cannot be accepted into \
                     the mempool"
                );
            }
        }

        if response.code == ResultCode::Ok.into() {
            response.log = VALID_MSG.into();
        }
        response
    }

    fn get_abci_validator_updates<F, V>(
        &self,
        is_genesis: bool,
        // Generic over the validator conversion from our type to tendermint's,
        // because we're using domain types in InitChain, but FinalizeBlock is
        // shimmed with a different old type. The joy...
        mut validator_conv: F,
    ) -> namada_sdk::state::Result<Vec<V>>
    where
        F: FnMut(common::PublicKey, i64) -> V,
    {
        let (current_epoch, _gas) = self.state.in_mem().get_current_epoch();
        let pos_params =
            read_pos_params::<_, governance::Store<_>>(&self.state)
                .expect("Could not find the PoS parameters");

        let validator_set_update_fn = if is_genesis {
            proof_of_stake::genesis_validator_set_tendermint
        } else {
            proof_of_stake::validator_set_update::validator_set_update_comet
        };

        validator_set_update_fn(
            &self.state,
            &pos_params,
            current_epoch,
            |update| {
                let (consensus_key, power) = match update {
                    ValidatorSetUpdate::Consensus(ConsensusValidator {
                        consensus_key,
                        bonded_stake: power,
                    }) => (consensus_key, power),
                    ValidatorSetUpdate::Deactivated(consensus_key) => {
                        // Any validators that have been dropped from the
                        // consensus set must have voting power set to 0 to
                        // remove them from the consensus set
                        let power = 0_i64;
                        (consensus_key, power)
                    }
                };
                validator_conv(consensus_key, power)
            },
        )
    }

    /// Retrieves the [`BlockHeight`] that is currently being decided.
    #[inline]
    pub fn get_current_decision_height(&self) -> BlockHeight {
        self.state.get_current_decision_height()
    }

    /// Check if we are at a given [`BlockHeight`] offset, `height_offset`,
    /// within the current epoch.
    pub fn is_deciding_offset_within_epoch(&self, height_offset: u64) -> bool {
        self.state.is_deciding_offset_within_epoch(height_offset)
    }
}

/// Checks that neither the wrapper nor the inner transaction batch have already
/// been applied. Requires a [`TempWlState`] to perform the check during
/// block construction and validation
pub fn replay_protection_checks<D, H>(
    wrapper: &Tx,
    temp_state: &mut TempWlState<'_, D, H>,
) -> ShellResult<()>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let batch_tx_hash = wrapper.raw_header_hash();
    // Check the inner tx hash only against the storage, skip the write
    // log
    if temp_state
        .has_committed_replay_protection_entry(&batch_tx_hash)
        .expect("Error while checking inner tx hash key in storage")
    {
        return Err(Error::ReplayAttempt(format!(
            "Batch transaction hash {} already in storage",
            &batch_tx_hash,
        )));
    }

    let wrapper_hash = wrapper.header_hash();
    if temp_state
        .has_replay_protection_entry(&wrapper_hash)
        .expect("Error while checking wrapper tx hash key in storage")
    {
        return Err(Error::ReplayAttempt(format!(
            "Wrapper transaction hash {} already in storage",
            wrapper_hash
        )));
    }

    // Write wrapper hash to WAL
    temp_state
        .write_tx_hash(wrapper_hash)
        .map_err(|e| Error::ReplayAttempt(e.to_string()))
}

// Perform the fee check in mempool
fn mempool_fee_check<D, H, CA>(
    shell_params: &mut ShellParams<'_, TempWlState<'static, D, H>, D, H, CA>,
    tx: &Tx,
    wrapper: &WrapperTx,
) -> ShellResult<()>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
    CA: 'static + WasmCacheAccess + Sync,
{
    let minimum_gas_price =
        parameters::read_gas_cost(shell_params.state, &wrapper.fee.token)
            .expect("Must be able to read gas cost parameter")
            .ok_or(Error::TxApply(protocol::Error::FeeError(format!(
                "The provided {} token is not allowed for fee payment",
                wrapper.fee.token
            ))))?;

    fee_data_check(wrapper, minimum_gas_price, shell_params)?;
    protocol::check_fees(shell_params, tx, wrapper, false)
        .map_err(Error::TxApply)
        .map(|_| ())
}

/// Check the validity of the fee data
pub fn fee_data_check<D, H, CA>(
    wrapper: &WrapperTx,
    minimum_gas_price: token::Amount,
    shell_params: &mut ShellParams<'_, TempWlState<'_, D, H>, D, H, CA>,
) -> ShellResult<()>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
    CA: 'static + WasmCacheAccess + Sync,
{
    match token::denom_to_amount(
        wrapper.fee.amount_per_gas_unit,
        &wrapper.fee.token,
        shell_params.state,
    ) {
        Ok(amount_per_gas_unit) if amount_per_gas_unit < minimum_gas_price => {
            // The fees do not match the minimum required
            return Err(Error::TxApply(protocol::Error::FeeError(format!(
                "Fee amount {:?} does not match the minimum required amount \
                 {:?} for token {}",
                wrapper.fee.amount_per_gas_unit,
                minimum_gas_price,
                wrapper.fee.token
            ))));
        }
        Ok(_) => {}
        Err(err) => {
            return Err(Error::TxApply(protocol::Error::FeeError(format!(
                "The precision of the fee amount {:?} is higher than the \
                 denomination for token {}: {}",
                wrapper.fee.amount_per_gas_unit, wrapper.fee.token, err,
            ))));
        }
    }

    Ok(())
}

/// for the shell
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_wrap)]
#[cfg(any(test, feature = "testing"))]
pub mod test_utils {
    use std::ops::{Deref, DerefMut};

    use data_encoding::HEXUPPER;
    use namada_sdk::ethereum_events::Uint;
    use namada_sdk::events::Event;
    use namada_sdk::hash::Hash;
    use namada_sdk::keccak::KeccakHash;
    use namada_sdk::key::*;
    use namada_sdk::proof_of_stake::parameters::PosParams;
    use namada_sdk::proof_of_stake::storage::validator_consensus_key_handle;
    use namada_sdk::state::mockdb::MockDB;
    use namada_sdk::state::{LastBlock, StorageWrite};
    use namada_sdk::storage::{BlockHeader, Epoch};
    use namada_sdk::tendermint::abci::types::VoteInfo;
    use tempfile::tempdir;
    use tokio::sync::mpsc::{Sender, UnboundedReceiver};

    use super::*;
    use crate::config::ethereum_bridge::ledger::ORACLE_CHANNEL_BUFFER_SIZE;
    use crate::shims::abcipp_shim_types;
    use crate::shims::abcipp_shim_types::shim::request::{
        FinalizeBlock, ProcessedTx,
    };
    use crate::tendermint::abci::types::Misbehavior;
    use crate::tendermint_proto::abci::{
        RequestPrepareProposal, RequestProcessProposal,
    };
    use crate::tendermint_proto::google::protobuf::Timestamp;

    #[derive(Error, Debug)]
    pub enum TestError {
        #[error("Proposal rejected with tx results: {0:?}")]
        #[allow(dead_code)]
        RejectProposal(Vec<ProcessedTx>),
    }

    /// Gets the absolute path to root directory
    pub fn top_level_directory() -> PathBuf {
        let mut current_path = std::env::current_dir()
            .expect("Current directory should exist")
            .canonicalize()
            .expect("Current directory should exist");
        while !current_path.join("rust-toolchain.toml").exists() {
            current_path.pop();
        }
        current_path
    }

    /// Generate a random public/private keypair
    #[inline]
    pub fn gen_keypair() -> common::SecretKey {
        gen_ed25519_keypair()
    }

    /// Generate a random ed25519 public/private keypair
    pub fn gen_ed25519_keypair() -> common::SecretKey {
        use rand::prelude::ThreadRng;
        use rand::thread_rng;

        let mut rng: ThreadRng = thread_rng();
        ed25519::SigScheme::generate(&mut rng).try_to_sk().unwrap()
    }

    /// Generate a random secp256k1 public/private keypair
    pub fn gen_secp256k1_keypair() -> common::SecretKey {
        use rand::prelude::ThreadRng;
        use rand::thread_rng;

        let mut rng: ThreadRng = thread_rng();
        secp256k1::SigScheme::generate(&mut rng)
            .try_to_sk()
            .unwrap()
    }

    /// Invalidate a valid signature `sig`.
    pub fn invalidate_signature(sig: common::Signature) -> common::Signature {
        match sig {
            common::Signature::Ed25519(ed25519::Signature(sig)) => {
                let mut sig_bytes = sig.to_bytes();
                sig_bytes[0] = sig_bytes[0].wrapping_add(1);
                common::Signature::Ed25519(ed25519::Signature(sig_bytes.into()))
            }
            common::Signature::Secp256k1(secp256k1::Signature(
                ref sig,
                ref recovery_id,
            )) => {
                let mut sig_bytes = sig.to_vec();
                let recovery_id_bytes = recovery_id.to_byte();
                sig_bytes[0] = sig_bytes[0].wrapping_add(1);
                let bytes: [u8; 65] =
                    [sig_bytes.as_slice(), &[recovery_id_bytes]]
                        .concat()
                        .try_into()
                        .unwrap();
                common::Signature::Secp256k1((&bytes).try_into().unwrap())
            }
        }
    }

    /// Get the default bridge pool vext bytes to be signed.
    pub fn get_bp_bytes_to_sign() -> KeccakHash {
        use namada_sdk::keccak::{Hasher, Keccak};

        let root = [0; 32];
        let nonce = Uint::from(0).to_bytes();

        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(&root);
        hasher.update(&nonce);
        hasher.finalize(&mut output);

        KeccakHash(output)
    }

    /// A wrapper around the shell that implements
    /// Drop so as to clean up the files that it
    /// generates. Also allows illegal state
    /// modifications for testing purposes
    pub struct TestShell {
        pub shell: Shell<MockDB, Sha256Hasher>,
    }

    impl Deref for TestShell {
        type Target = Shell<MockDB, Sha256Hasher>;

        fn deref(&self) -> &Self::Target {
            &self.shell
        }
    }

    impl DerefMut for TestShell {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.shell
        }
    }

    #[derive(Clone)]
    /// Helper for testing process proposal which has very different
    /// input types depending on whether the ABCI++ feature is on or not.
    pub struct ProcessProposal {
        pub txs: Vec<Vec<u8>>,
    }

    impl TestShell {
        /// Returns a new shell with
        ///    - A broadcast receiver, which will receive any protocol txs sent
        ///      by the shell.
        ///    - A sender that can send Ethereum events into the ledger, mocking
        ///      the Ethereum fullnode process
        ///    - A receiver for control commands sent by the shell to the
        ///      Ethereum oracle
        pub fn new_at_height<H: Into<BlockHeight>>(
            height: H,
        ) -> (
            Self,
            UnboundedReceiver<Vec<u8>>,
            Sender<EthereumEvent>,
            Receiver<oracle::control::Command>,
        ) {
            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            let (eth_sender, eth_receiver) =
                tokio::sync::mpsc::channel(ORACLE_CHANNEL_BUFFER_SIZE);
            let (_, last_processed_block_receiver) =
                last_processed_block::channel();
            let (control_sender, control_receiver) = oracle::control::channel();
            let eth_oracle = EthereumOracleChannels::new(
                eth_receiver,
                control_sender,
                last_processed_block_receiver,
            );
            let base_dir = tempdir().unwrap().as_ref().canonicalize().unwrap();
            let vp_wasm_compilation_cache = 50 * 1024 * 1024; // 50 kiB
            let tx_wasm_compilation_cache = 50 * 1024 * 1024; // 50 kiB
            let mut shell = Shell::<MockDB, Sha256Hasher>::new(
                config::Ledger::new(
                    base_dir,
                    Default::default(),
                    TendermintMode::Validator,
                ),
                top_level_directory().join("wasm"),
                sender,
                Some(eth_oracle),
                None,
                None,
                vp_wasm_compilation_cache,
                tx_wasm_compilation_cache,
            );
            shell.state.in_mem_mut().block.height = height.into();
            (Self { shell }, receiver, eth_sender, control_receiver)
        }

        /// Same as [`TestShell::new_at_height`], but returns a shell at block
        /// height 0.
        #[inline]
        #[allow(dead_code)]
        pub fn new() -> (
            Self,
            UnboundedReceiver<Vec<u8>>,
            Sender<EthereumEvent>,
            Receiver<oracle::control::Command>,
        ) {
            Self::new_at_height(BlockHeight(1))
        }

        /// Forward a InitChain request and expect a success
        pub fn init_chain(
            &mut self,
            req: request::InitChain,
            num_validators: u64,
        ) {
            self.shell
                .init_chain(req, num_validators)
                .expect("Test shell failed to initialize");
        }

        /// Forward a ProcessProposal request and extract the relevant
        /// response data to return
        pub fn process_proposal(
            &self,
            req: ProcessProposal,
        ) -> std::result::Result<Vec<ProcessedTx>, TestError> {
            #[allow(clippy::disallowed_methods)]
            let time = DateTimeUtc::now();
            let (resp, tx_results) =
                self.shell.process_proposal(RequestProcessProposal {
                    txs: req
                        .txs
                        .clone()
                        .into_iter()
                        .map(prost::bytes::Bytes::from)
                        .collect(),
                    proposer_address: HEXUPPER
                        .decode(
                            wallet::defaults::validator_keypair()
                                .to_public()
                                .tm_raw_hash()
                                .as_bytes(),
                        )
                        .unwrap()
                        .into(),
                    time: Some(Timestamp {
                        seconds: time.0.timestamp(),
                        nanos: time.0.timestamp_subsec_nanos() as i32,
                    }),

                    ..Default::default()
                });
            let results = tx_results
                .into_iter()
                .zip(req.txs)
                .map(|(res, tx_bytes)| ProcessedTx {
                    result: res,
                    tx: tx_bytes.into(),
                })
                .collect();
            if resp != tendermint::abci::response::ProcessProposal::Accept {
                Err(TestError::RejectProposal(results))
            } else {
                Ok(results)
            }
        }

        /// Forward a FinalizeBlock request return a vector of
        /// the events created for each transaction
        pub fn finalize_block(
            &mut self,
            req: FinalizeBlock,
        ) -> ShellResult<Vec<Event>> {
            match self.shell.finalize_block(req) {
                Ok(resp) => Ok(resp.events),
                Err(err) => Err(err),
            }
        }

        /// Forward a PrepareProposal request
        pub fn prepare_proposal(
            &self,
            mut req: RequestPrepareProposal,
        ) -> abcipp_shim_types::shim::response::PrepareProposal {
            req.proposer_address = HEXUPPER
                .decode(
                    wallet::defaults::validator_keypair()
                        .to_public()
                        .tm_raw_hash()
                        .as_bytes(),
                )
                .unwrap()
                .into();
            self.shell.prepare_proposal(req)
        }

        /// Start a counter for the next epoch in `num_blocks`.
        pub fn start_new_epoch_in(&mut self, num_blocks: u64) {
            self.state.in_mem_mut().next_epoch_min_start_height =
                self.state.in_mem().get_last_block_height() + num_blocks;
            self.state.in_mem_mut().next_epoch_min_start_time = {
                #[allow(clippy::disallowed_methods)]
                DateTimeUtc::now()
            };
        }

        /// Simultaneously call the `FinalizeBlock` and
        /// `Commit` handlers.
        pub fn finalize_and_commit(&mut self, req: Option<FinalizeBlock>) {
            let mut req = req.unwrap_or_default();
            req.header.time = {
                #[allow(clippy::disallowed_methods)]
                DateTimeUtc::now()
            };

            self.finalize_block(req).expect("Test failed");
            self.commit();
        }

        /// Immediately change to the next epoch.
        pub fn start_new_epoch(&mut self, req: Option<FinalizeBlock>) -> Epoch {
            self.start_new_epoch_in(1);

            let next_epoch_min_start_height =
                self.state.in_mem().next_epoch_min_start_height;
            if let Some(LastBlock { height, .. }) =
                self.state.in_mem_mut().last_block.as_mut()
            {
                *height = next_epoch_min_start_height;
            } else {
                panic!("Test failed");
            }
            self.finalize_and_commit(req.clone());

            for _i in 0..EPOCH_SWITCH_BLOCKS_DELAY {
                self.finalize_and_commit(req.clone());
            }
            self.state.in_mem().get_current_epoch().0
        }
    }

    /// Config parameters to set up a test shell.
    pub struct SetupCfg<H> {
        /// The last committed block height.
        pub last_height: H,
        /// The number of validators to configure
        // in `InitChain`.
        pub num_validators: u64,
        /// Whether to enable the Ethereum oracle or not.
        pub enable_ethereum_oracle: bool,
    }

    impl<H: Default> Default for SetupCfg<H> {
        fn default() -> Self {
            Self {
                last_height: H::default(),
                num_validators: 1,
                enable_ethereum_oracle: true,
            }
        }
    }

    /// Start a new test shell and initialize it. Returns the shell paired with
    /// a broadcast receiver, which will receives any protocol txs sent by the
    /// shell.
    pub fn setup_with_cfg<H: Into<BlockHeight>>(
        SetupCfg {
            last_height,
            num_validators,
            enable_ethereum_oracle,
        }: SetupCfg<H>,
    ) -> (
        TestShell,
        UnboundedReceiver<Vec<u8>>,
        Sender<EthereumEvent>,
        Receiver<oracle::control::Command>,
    ) {
        let (mut test, receiver, eth_sender, control_receiver) =
            TestShell::new_at_height(last_height);
        if !enable_ethereum_oracle {
            if let ShellMode::Validator { eth_oracle, .. } = &mut test.mode {
                // drop the eth oracle event receiver
                _ = eth_oracle.take();
            }
        }
        let req = request::InitChain {
            time: Timestamp {
                seconds: 0,
                nanos: 0,
            }
            .try_into()
            .unwrap(),
            chain_id: ChainId::default().to_string(),
            consensus_params: tendermint::consensus::params::Params {
                block: tendermint::block::Size {
                    max_bytes: 0,
                    max_gas: 0,
                    time_iota_ms: 0,
                },
                evidence: tendermint::evidence::Params {
                    max_age_num_blocks: 0,
                    max_age_duration: tendermint::evidence::Duration(
                        core::time::Duration::MAX,
                    ),
                    max_bytes: 0,
                },
                validator: tendermint::consensus::params::ValidatorParams {
                    pub_key_types: vec![],
                },
                version: None,
                abci: tendermint::consensus::params::AbciParams {
                    vote_extensions_enable_height: None,
                },
            },
            validators: vec![],
            app_state_bytes: vec![].into(),
            initial_height: 1_u32.into(),
        };
        test.init_chain(req, num_validators);
        test.state.commit_block().expect("Test failed");
        (test, receiver, eth_sender, control_receiver)
    }

    /// Same as [`setup_at_height`], but returns a shell at the given block
    /// height, with a single validator.
    #[inline]
    pub fn setup_at_height<H: Into<BlockHeight>>(
        last_height: H,
    ) -> (
        TestShell,
        UnboundedReceiver<Vec<u8>>,
        Sender<EthereumEvent>,
        Receiver<oracle::control::Command>,
    ) {
        let last_height = last_height.into();
        setup_with_cfg(SetupCfg {
            last_height,
            ..Default::default()
        })
    }

    /// Same as [`setup_with_cfg`], but returns a shell at block height 0,
    /// with a single validator.
    #[inline]
    pub fn setup() -> (
        TestShell,
        UnboundedReceiver<Vec<u8>>,
        Sender<EthereumEvent>,
        Receiver<oracle::control::Command>,
    ) {
        setup_with_cfg(SetupCfg::<u64>::default())
    }

    /// This is just to be used in testing. It is not
    /// a meaningful default.
    impl Default for FinalizeBlock {
        fn default() -> Self {
            FinalizeBlock {
                header: BlockHeader {
                    hash: Hash([0; 32]),
                    #[allow(clippy::disallowed_methods)]
                    time: DateTimeUtc::now(),
                    next_validators_hash: Hash([0; 32]),
                },
                block_hash: Hash([0; 32]),
                byzantine_validators: vec![],
                txs: vec![],
                proposer_address: HEXUPPER
                    .decode(
                        wallet::defaults::validator_keypair()
                            .to_public()
                            .tm_raw_hash()
                            .as_bytes(),
                    )
                    .unwrap(),
                height: 0u8.into(),
                decided_last_commit: tendermint::abci::types::CommitInfo {
                    round: 0u8.into(),
                    votes: vec![],
                },
            }
        }
    }

    /// Set the Ethereum bridge to be inactive
    pub fn deactivate_bridge(shell: &mut TestShell) {
        use eth_bridge::storage::active_key;
        use eth_bridge::storage::eth_bridge_queries::EthBridgeStatus;
        shell
            .state
            .write(&active_key(), EthBridgeStatus::Disabled)
            .expect("Test failed");
    }

    pub fn get_pkh_from_address<S>(
        storage: &S,
        params: &PosParams,
        address: Address,
        epoch: Epoch,
    ) -> [u8; 20]
    where
        S: StorageRead,
    {
        let ck = validator_consensus_key_handle(&address)
            .get(storage, epoch, params)
            .unwrap()
            .unwrap();
        let hash_string = tm_consensus_key_raw_hash(&ck);
        let decoded = HEXUPPER.decode(hash_string.as_bytes()).unwrap();
        TryFrom::try_from(decoded).unwrap()
    }

    pub fn next_block_for_inflation(
        shell: &mut TestShell,
        proposer_address: Vec<u8>,
        votes: Vec<VoteInfo>,
        byzantine_validators: Option<Vec<Misbehavior>>,
    ) {
        // Let the header time be always ahead of the next epoch min start time
        let header = BlockHeader {
            time: shell.state.in_mem().next_epoch_min_start_time.next_second(),
            ..Default::default()
        };
        let mut req = FinalizeBlock {
            header,
            proposer_address,
            decided_last_commit: tendermint::abci::types::CommitInfo {
                round: 0u8.into(),
                votes,
            },
            ..Default::default()
        };
        if let Some(byz_vals) = byzantine_validators {
            req.byzantine_validators = byz_vals;
        }
        shell.finalize_block(req).unwrap();
        shell.commit();
    }
}

#[cfg(test)]
mod shell_tests {
    use std::collections::BTreeMap;
    use std::fs::File;

    use eth_bridge::storage::eth_bridge_queries::is_bridge_comptime_enabled;
    use namada_apps_lib::state::StorageWrite;
    use namada_sdk::address;
    use namada_sdk::chain::Epoch;
    use namada_sdk::token::read_denom;
    use namada_sdk::tx::data::Fee;
    use namada_sdk::tx::data::protocol::{ProtocolTx, ProtocolTxType};
    use namada_sdk::tx::{Code, Data, Signed};
    use namada_vote_ext::{
        bridge_pool_roots, ethereum_events, ethereum_tx_data_variants,
    };
    use tempfile::tempdir;
    use {namada_replay_protection as replay_protection, wallet};

    use super::*;
    use crate::shell::test_utils::top_level_directory;
    use crate::shell::token::DenominatedAmount;
    use crate::storage::{DbSnapshot, PersistentDB, SnapshotPath};

    const GAS_LIMIT: u64 = 100_000;

    /// Check that the shell broadcasts validator set updates,
    /// even when the Ethereum oracle is not running (e.g.
    /// because the bridge is disabled).
    #[tokio::test]
    async fn test_broadcast_valset_upd_inspite_oracle_off() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }

        // this height should result in a validator set
        // update being broadcasted
        let (mut shell, mut broadcaster_rx, _, _) =
            test_utils::setup_with_cfg(test_utils::SetupCfg {
                last_height: 1,
                enable_ethereum_oracle: false,
                ..Default::default()
            });

        // broadcast validator set update
        shell.broadcast_protocol_txs();

        // check data inside tx - it should be a validator set update
        // signed at epoch 0
        let signed_valset_upd = loop {
            // attempt to receive validator set update
            let serialized_tx = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                async { broadcaster_rx.recv().await.unwrap() },
            )
            .await
            .unwrap();
            let tx = Tx::try_from_bytes(&serialized_tx[..]).unwrap();

            match ethereum_tx_data_variants::ValSetUpdateVext::try_from(&tx) {
                Ok(signed_valset_upd) => break signed_valset_upd,
                Err(_) => continue,
            }
        };

        assert_eq!(signed_valset_upd.data.signing_epoch, Epoch(0));
    }

    /// Check that broadcasting expired Ethereum events works
    /// as expected.
    #[test]
    fn test_commit_broadcasts_expired_eth_events() {
        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }

        let (mut shell, mut broadcaster_rx, _, _) =
            test_utils::setup_at_height(5);

        // push expired events to queue
        let ethereum_event_0 = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ethereum_event_1 = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
        };
        shell
            .state
            .in_mem_mut()
            .expired_txs_queue
            .push(ExpiredTx::EthereumEvent(ethereum_event_0.clone()));
        shell
            .state
            .in_mem_mut()
            .expired_txs_queue
            .push(ExpiredTx::EthereumEvent(ethereum_event_1.clone()));

        // broadcast them
        shell.broadcast_expired_txs();

        // attempt to receive vote extension tx aggregating
        // all expired events
        let serialized_tx = broadcaster_rx.blocking_recv().unwrap();
        let tx = Tx::try_from_bytes(&serialized_tx[..]).unwrap();

        // check data inside tx
        let vote_extension =
            ethereum_tx_data_variants::EthEventsVext::try_from(&tx).unwrap();
        assert_eq!(
            vote_extension.data.ethereum_events,
            vec![ethereum_event_0, ethereum_event_1]
        );
    }

    /// Test that Ethereum events with outdated nonces are
    /// not validated by `CheckTx`.
    #[test]
    fn test_outdated_nonce_mempool_validate() {
        use namada_sdk::storage::InnerEthEventsQueue;

        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }

        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        shell
            .state
            .in_mem_mut()
            .eth_events_queue
            // sent transfers to namada nonce to 5
            .transfers_to_namada = InnerEthEventsQueue::new_at(5.into());

        let (protocol_key, _) = wallet::defaults::validator_keys();

        // only bad events
        {
            let ethereum_event = EthereumEvent::TransfersToNamada {
                nonce: 3u64.into(),
                transfers: vec![],
            };
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr: wallet::defaults::validator_address(),
                    block_height: LAST_HEIGHT,
                    ethereum_events: vec![ethereum_event],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            let tx = EthereumTxData::EthEventsVext(ext.into())
                .sign(&protocol_key, shell.chain_id.clone())
                .to_bytes();
            let rsp = shell.mempool_validate(&tx, Default::default());
            assert!(
                rsp.code != ResultCode::Ok.into(),
                "Validation should have failed"
            );
        }

        // at least one good event
        {
            let e1 = EthereumEvent::TransfersToNamada {
                nonce: 3u64.into(),
                transfers: vec![],
            };
            let e2 = EthereumEvent::TransfersToNamada {
                nonce: 5u64.into(),
                transfers: vec![],
            };
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr: wallet::defaults::validator_address(),
                    block_height: LAST_HEIGHT,
                    ethereum_events: vec![e1, e2],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            let tx = EthereumTxData::EthEventsVext(ext.into())
                .sign(&protocol_key, shell.chain_id.clone())
                .to_bytes();
            let rsp = shell.mempool_validate(&tx, Default::default());
            assert!(
                rsp.code == ResultCode::Ok.into(),
                "Validation should have passed"
            );
        }
    }

    /// Test that we do not include protocol txs in the mempool,
    /// voting on ethereum events or signing bridge pool roots
    /// and nonces if the bridge is inactive.
    #[test]
    fn test_mempool_filter_protocol_txs_bridge_inactive() {
        let (mut shell, _, _, _) = test_utils::setup_at_height(3);
        test_utils::deactivate_bridge(&mut shell);
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");
        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let eth_vext = EthereumTxData::EthEventsVext(
            ethereum_events::Vext {
                validator_addr: address.clone(),
                block_height: shell.state.in_mem().get_last_block_height(),
                ethereum_events: vec![ethereum_event],
            }
            .sign(protocol_key)
            .into(),
        )
        .sign(protocol_key, shell.chain_id.clone())
        .to_bytes();

        let to_sign = test_utils::get_bp_bytes_to_sign();
        let hot_key = shell.mode.get_eth_bridge_keypair().expect("Test failed");
        let sig = Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig;
        let bp_vext = EthereumTxData::BridgePoolVext(
            bridge_pool_roots::Vext {
                block_height: shell.state.in_mem().get_last_block_height(),
                validator_addr: address,
                sig,
            }
            .sign(protocol_key),
        )
        .sign(protocol_key, shell.chain_id.clone())
        .to_bytes();
        let txs_to_validate = [
            (eth_vext, "Incorrectly validated eth events vext"),
            (bp_vext, "Incorrectly validated bp roots vext"),
        ];
        for (tx_bytes, err_msg) in txs_to_validate {
            let rsp = shell.mempool_validate(&tx_bytes, Default::default());
            assert!(
                rsp.code == ResultCode::InvalidVoteExtension.into(),
                "{err_msg}"
            );
        }
    }

    /// Test if Ethereum events validation behaves as expected,
    /// considering honest validators.
    #[test]
    fn test_mempool_eth_events_vext_normal_op() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        if !is_bridge_comptime_enabled() {
            // NOTE: this test doesn't work if the ethereum bridge
            // is disabled at compile time.
            return;
        }

        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);

        let (protocol_key, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ext = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ethereum_event],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };
        let tx = EthereumTxData::EthEventsVext(ext.into())
            .sign(&protocol_key, shell.chain_id.clone())
            .to_bytes();
        let rsp = shell.mempool_validate(&tx, Default::default());
        assert_eq!(rsp.code, 0.into());
    }

    /// Test if Ethereum events validation fails, if the underlying
    /// protocol transaction type is different from the vote extension
    /// contained in the transaction's data field.
    #[test]
    fn test_mempool_eth_events_vext_data_mismatch() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);

        let (protocol_key, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ext = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ethereum_event],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };
        let tx = {
            let mut tx =
                Tx::from_type(TxType::Protocol(Box::new(ProtocolTx {
                    pk: protocol_key.ref_to(),
                    tx: ProtocolTxType::BridgePoolVext,
                })));
            // invalid tx type, it doesn't match the
            // tx type declared in the header
            tx.set_data(Data::new(ext.serialize_to_vec()));
            tx.sign_wrapper(protocol_key);
            tx
        }
        .to_bytes();
        let rsp = shell.mempool_validate(&tx, Default::default());
        assert_eq!(rsp.code, ResultCode::InvalidVoteExtension.into());
    }

    /// Mempool validation must reject unsigned wrappers
    #[test]
    fn test_missing_signature() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = super::test_utils::gen_keypair();

        let mut unsigned_wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        token::Amount::from_uint(100, 0)
                            .expect("This can't fail"),
                    ),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                0.into(),
            ))));
        unsigned_wrapper.header.chain_id = shell.chain_id.clone();
        unsigned_wrapper
            .set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        unsigned_wrapper
            .set_data(Data::new("transaction data".as_bytes().to_owned()));

        let mut result = shell.mempool_validate(
            unsigned_wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::InvalidSig.into());
        result = shell.mempool_validate(
            unsigned_wrapper.to_bytes().as_ref(),
            MempoolTxType::RecheckTransaction,
        );
        assert_eq!(result.code, ResultCode::InvalidSig.into());
    }

    /// Mempool validation must reject wrappers with an invalid signature
    #[test]
    fn test_invalid_signature() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = super::test_utils::gen_keypair();

        let mut invalid_wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        token::Amount::from_uint(100, 0)
                            .expect("This can't fail"),
                    ),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                0.into(),
            ))));
        invalid_wrapper.header.chain_id = shell.chain_id.clone();
        invalid_wrapper
            .set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        invalid_wrapper
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        invalid_wrapper.sign_wrapper(keypair);

        // we mount a malleability attack to try and remove the fee
        let mut new_wrapper =
            invalid_wrapper.header().wrapper().expect("Test failed");
        new_wrapper.fee.amount_per_gas_unit =
            DenominatedAmount::native(0.into());
        invalid_wrapper.update_header(TxType::Wrapper(Box::new(new_wrapper)));

        let mut result = shell.mempool_validate(
            invalid_wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::InvalidSig.into());
        result = shell.mempool_validate(
            invalid_wrapper.to_bytes().as_ref(),
            MempoolTxType::RecheckTransaction,
        );
        assert_eq!(result.code, ResultCode::InvalidSig.into());
    }

    /// Mempool validation must reject non-wrapper txs
    #[test]
    fn test_wrong_tx_type() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut tx = Tx::new(shell.chain_id.clone(), None);
        tx.add_code("wasm_code".as_bytes().to_owned(), None);

        let result = shell.mempool_validate(
            tx.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::InvalidTx.into());
        assert_eq!(
            result.log,
            "Mempool validation failed: Raw transactions cannot be accepted \
             into the mempool"
        )
    }

    /// Mempool validation must reject already applied wrapper and inner
    /// transactions
    #[test]
    fn test_replay_attack() {
        let (mut shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        token::Amount::from_uint(100, 0)
                            .expect("This can't fail"),
                    ),
                    token: shell.state.in_mem().native_token.clone(),
                },
                wallet::defaults::albert_keypair().ref_to(),
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(wallet::defaults::albert_keypair());

        // Write wrapper hash to storage
        let mut batch = namada_sdk::state::testing::TestState::batch();
        let wrapper_hash = wrapper.header_hash();
        let wrapper_hash_key = replay_protection::current_key(&wrapper_hash);
        shell
            .state
            .write_replay_protection_entry(&mut batch, &wrapper_hash_key)
            .expect("Test failed");

        // Try wrapper tx replay attack
        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::ReplayTx.into());
        assert_eq!(
            result.log,
            format!(
                "Mempool validation failed: Wrapper transaction hash {} \
                 already in storage, replay attempt",
                wrapper_hash
            )
        );

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::RecheckTransaction,
        );
        assert_eq!(result.code, ResultCode::ReplayTx.into());
        assert_eq!(
            result.log,
            format!(
                "Mempool validation failed: Wrapper transaction hash {} \
                 already in storage, replay attempt",
                wrapper_hash
            )
        );

        // Modify wrapper to avoid a replay of it
        wrapper.update_header(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(
                    token::Amount::from_uint(100, 0).expect("This can't fail"),
                ),
                token: shell.state.in_mem().native_token.clone(),
            },
            wallet::defaults::bertha_keypair().ref_to(),
            GAS_LIMIT.into(),
        ))));
        wrapper.sign_wrapper(wallet::defaults::bertha_keypair());
        let batch_hash = wrapper.raw_header_hash();
        // Write batch hash in storage
        let batch_hash_key = replay_protection::current_key(&batch_hash);
        shell
            .state
            .write_replay_protection_entry(&mut batch, &batch_hash_key)
            .expect("Test failed");

        // Try batch replay attack
        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::ReplayTx.into());
        assert_eq!(
            result.log,
            format!(
                "Mempool validation failed: Batch transaction hash {} already \
                 in storage, replay attempt",
                batch_hash
            )
        );

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::RecheckTransaction,
        );
        assert_eq!(result.code, ResultCode::ReplayTx.into());
        assert_eq!(
            result.log,
            format!(
                "Mempool validation failed: Batch transaction hash {} already \
                 in storage, replay attempt",
                batch_hash
            )
        )
    }

    /// Check that a transaction with a wrong chain id gets discarded
    #[test]
    fn test_wrong_chain_id() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = super::test_utils::gen_keypair();

        let wrong_chain_id = ChainId("Wrong chain id".to_string());
        let mut tx = Tx::new(wrong_chain_id.clone(), None);
        tx.add_code("wasm_code".as_bytes().to_owned(), None)
            .add_data("transaction data".as_bytes().to_owned())
            .sign_wrapper(keypair);

        let result = shell.mempool_validate(
            tx.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::InvalidChainId.into());
        assert_eq!(
            result.log,
            format!(
                "Mempool validation failed: Tx carries a wrong chain id: \
                 expected {}, found {}",
                shell.chain_id, wrong_chain_id
            )
        )
    }

    /// Check that an expired transaction gets rejected
    #[test]
    fn test_expired_tx() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = super::test_utils::gen_keypair();

        let mut tx =
            Tx::new(shell.chain_id.clone(), Some(DateTimeUtc::default()));
        tx.add_code("wasm_code".as_bytes().to_owned(), None)
            .add_data("transaction data".as_bytes().to_owned())
            .sign_wrapper(keypair);

        let result = shell.mempool_validate(
            tx.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::ExpiredTx.into());
    }

    /// Check that a tx requiring more gas than the block limit gets rejected
    #[test]
    fn test_exceeding_max_block_gas_tx() {
        let (shell, _recv, _, _) = test_utils::setup();

        let block_gas_limit =
            parameters::get_max_block_gas(&shell.state).unwrap();
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(100.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                (block_gas_limit + 1).into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(keypair);

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::AllocationError.into());
    }

    // Check that a tx requiring more gas than its limit gets rejected
    #[test]
    fn test_exceeding_gas_limit_tx() {
        let (shell, _recv, _, _) = test_utils::setup();
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(100.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                keypair.ref_to(),
                0.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(keypair);

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::TxGasLimit.into());
    }

    // Check that a wrapper using a non-whitelisted token for fee payment is
    // rejected
    #[test]
    fn test_fee_non_whitelisted_token() {
        let (shell, _recv, _, _) = test_utils::setup();
        let apfel_denom = read_denom(&shell.state, &address::testing::apfel())
            .expect("unable to read denomination from storage")
            .expect("unable to find denomination of apfels");

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::new(
                        100.into(),
                        apfel_denom,
                    ),
                    token: address::testing::apfel(),
                },
                wallet::defaults::albert_keypair().ref_to(),
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(wallet::defaults::albert_keypair());

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::FeeError.into());
    }

    // Check that a wrapper using a whitelisted non-native token for fee payment
    // is accepted
    #[test]
    fn test_fee_whitelisted_non_native_token() {
        let (mut shell, _recv, _, _) = test_utils::setup();
        let apfel_denom = read_denom(&shell.state, &address::testing::apfel())
            .expect("unable to read denomination from storage")
            .expect("unable to find denomination of apfels");
        let fee_amount: token::Amount = GAS_LIMIT.into();

        // Credit some tokens for fee payment
        namada_sdk::token::credit_tokens(
            &mut shell.state,
            &address::testing::apfel(),
            &Address::from(&wallet::defaults::albert_keypair().to_public()),
            fee_amount,
        )
        .unwrap();
        let balance = token::read_balance(
            &shell.state,
            &address::testing::apfel(),
            &Address::from(&wallet::defaults::albert_keypair().to_public()),
        )
        .unwrap();
        assert_eq!(balance, fee_amount.clone());

        // Whitelist Apfel for fee payment
        let gas_cost_key = namada_sdk::parameters::storage::get_gas_cost_key();
        let mut gas_prices: BTreeMap<Address, token::Amount> =
            shell.read_storage_key(&gas_cost_key).unwrap();
        gas_prices.insert(address::testing::apfel(), 1.into());
        shell.shell.state.write(&gas_cost_key, gas_prices).unwrap();
        shell.commit();

        // Submit tx
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::new(
                        1.into(),
                        apfel_denom,
                    ),
                    token: address::testing::apfel(),
                },
                wallet::defaults::albert_keypair().ref_to(),
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(wallet::defaults::albert_keypair());

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::Ok.into());
    }

    // Check that a wrapper setting a fee amount lower than the minimum required
    // is rejected
    #[test]
    fn test_fee_wrong_minimum_amount() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(0.into()),
                    token: shell.state.in_mem().native_token.clone(),
                },
                wallet::defaults::albert_keypair().ref_to(),
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(wallet::defaults::albert_keypair());

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::FeeError.into());
    }

    // Check that a wrapper transactions whose fees cannot be paid is rejected
    #[test]
    fn test_insufficient_balance_for_fee() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        1_000_000_000.into(),
                    ),
                    token: shell.state.in_mem().native_token.clone(),
                },
                wallet::defaults::albert_keypair().ref_to(),
                150_000.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(wallet::defaults::albert_keypair());

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::FeeError.into());
    }

    // Check that a fee overflow in the wrapper transaction is rejected
    #[test]
    fn test_wrapper_fee_overflow() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        token::Amount::max(),
                    ),
                    token: shell.state.in_mem().native_token.clone(),
                },
                wallet::defaults::albert_keypair().ref_to(),
                GAS_LIMIT.into(),
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.sign_wrapper(wallet::defaults::albert_keypair());

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::FeeError.into());
    }

    /// Test max tx bytes parameter in CheckTx
    #[test]
    fn test_max_tx_bytes_check_tx() {
        let (shell, _recv, _, _) = test_utils::setup();

        let max_tx_bytes: u32 = {
            let key = parameters::storage::get_max_tx_bytes_key();
            shell
                .state
                .read(&key)
                .expect("Failed to read from storage")
                .expect("Max tx bytes should have been written to storage")
        };

        let new_tx = |size: u32| {
            let keypair = super::test_utils::gen_keypair();
            let mut wrapper =
                Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: DenominatedAmount::native(
                            100.into(),
                        ),
                        token: shell.state.in_mem().native_token.clone(),
                    },
                    keypair.ref_to(),
                    GAS_LIMIT.into(),
                ))));
            wrapper.header.chain_id = shell.chain_id.clone();
            wrapper
                .set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
            wrapper.set_data(Data::new(vec![0; size as usize]));
            wrapper.sign_wrapper(keypair);

            wrapper
        };

        // test a small tx
        let result = shell.mempool_validate(
            new_tx(50).to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert!(result.code != ResultCode::TooLarge.into());

        // max tx bytes + 1, on the other hand, is not
        let result = shell.mempool_validate(
            new_tx(max_tx_bytes + 1).to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::TooLarge.into());
    }

    /// Test max tx sections limit in CheckTx
    #[test]
    fn test_max_tx_sections_check_tx() {
        let (shell, _recv, _, _) = test_utils::setup();

        let new_tx = |num_of_sections: usize| {
            let keypair = super::test_utils::gen_keypair();
            let mut wrapper =
                Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: DenominatedAmount::native(
                            100.into(),
                        ),
                        token: shell.state.in_mem().native_token.clone(),
                    },
                    keypair.ref_to(),
                    (GAS_LIMIT * 10).into(),
                ))));
            wrapper.header.chain_id = shell.chain_id.clone();
            wrapper
                .set_code(Code::new("wasm_code".as_bytes().to_owned(), None));

            // Wrapper sig and header
            const OTHER_SECTIONS: usize = 2;
            for _ in 0..(num_of_sections - OTHER_SECTIONS) {
                wrapper.set_data(Data::new(vec![0]));
            }
            wrapper.sign_wrapper(keypair);

            assert_eq!(wrapper.sections.len(), num_of_sections);
            wrapper
        };

        // test a tx on the limit of number of sections
        let result = shell.mempool_validate(
            new_tx(MAX_TX_SECTIONS_LEN).to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert!(result.code != ResultCode::InvalidTx.into());

        // test a tx exceeding the limit of number of sections
        let result = shell.mempool_validate(
            new_tx(MAX_TX_SECTIONS_LEN + 1).to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, ResultCode::InvalidTx.into());
    }

    /// Test the that the shell can restore it's state
    /// from a snapshot if it is not syncing
    #[test]
    fn test_restore_database_from_snapshot() {
        let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();

        let base_dir = tempdir().unwrap().as_ref().canonicalize().unwrap();
        let vp_wasm_compilation_cache = 50 * 1024 * 1024; // 50 kiB
        let tx_wasm_compilation_cache = 50 * 1024 * 1024; // 50 kiB
        let config = config::Ledger::new(
            base_dir.clone(),
            Default::default(),
            TendermintMode::Validator,
        );
        let mut shell = Shell::<PersistentDB, Sha256Hasher>::new(
            config.clone(),
            top_level_directory().join("wasm"),
            sender,
            None,
            None,
            None,
            vp_wasm_compilation_cache,
            tx_wasm_compilation_cache,
        );
        shell.state.in_mem_mut().block.height = BlockHeight::first();

        shell.state.commit_block().expect("Test failed");
        shell.state.db_mut().flush(true).expect("Test failed");
        let original_root = shell.state.in_mem().merkle_root();
        let snapshot = make_snapshot(config.db_dir(), base_dir);
        shell
            .state
            .write(
                &Key::parse("bing/fucking/bong").expect("Test failed"),
                [1u8; 64],
            )
            .expect("Test failed");
        shell.state.commit_block().expect("Test failed");
        let new_root = shell.state.in_mem().merkle_root();
        assert_ne!(new_root, original_root);

        shell.restore_database_from_state_sync();
        assert_eq!(shell.state.in_mem().merkle_root(), new_root,);
        shell.syncing = Some(SnapshotSync {
            next_chunk: 0,
            height: BlockHeight::first(),
            expected: vec![],
            strikes: 0,
            snapshot,
        });
        shell.restore_database_from_state_sync();
        assert_eq!(shell.state.in_mem().merkle_root(), original_root,);
    }

    /// Helper function for the `test_restore_database_from_snapshot` test
    fn make_snapshot(db_dir: PathBuf, base_dir: PathBuf) -> File {
        let snapshot =
            DbSnapshot(SnapshotPath(base_dir.clone(), BlockHeight::first()));
        std::fs::create_dir_all(base_dir.join("snapshots"))
            .expect("Test failed");
        std::fs::create_dir_all(snapshot.0.base()).expect("Test failed");
        std::fs::create_dir_all(snapshot.0.temp_rocksdb())
            .expect("Test failed");
        for entry in std::fs::read_dir(db_dir).expect("Test failed") {
            let entry = entry.expect("Test failed");
            let dest_file = snapshot
                .0
                .base()
                .join("db")
                .join(entry.file_name().to_string_lossy().to_string());
            std::fs::copy(entry.path(), dest_file).expect("Test failed");
        }
        snapshot.clone().build_tarball().expect("Test failed");
        File::open(snapshot.0.temp_tarball("zst")).expect("Test failed")
    }
}
