//! The persistent storage in RocksDB.
//!
//! The current storage tree is:
//! - `state`: the latest ledger state
//!   - `ethereum_height`: the height of the last eth block processed by the
//!     oracle
//!   - `eth_events_queue`: a queue of confirmed ethereum events to be processed
//!     in order
//!   - `height`: the last committed block height
//!   - `next_epoch_min_start_height`: minimum block height from which the next
//!     epoch can start
//!   - `next_epoch_min_start_time`: minimum block time from which the next
//!     epoch can start
//!   - `update_epoch_blocks_delay`: number of missing blocks before updating
//!     PoS with CometBFT
//!   - `pred`: predecessor values of the top-level keys of the same name
//!     - `next_epoch_min_start_height`
//!     - `next_epoch_min_start_time`
//!     - `commit_only_data_commitment`
//!     - `update_epoch_blocks_delay`
//!   - `conversion_state`: MASP conversion state
//! - `subspace`: accounts sub-spaces
//!   - `{address}/{dyn}`: any byte data associated with accounts
//! - `diffs`: diffs in account subspaces' key-vals modified with `persist_diff
//!   == true`
//!   - `{height}/new/{dyn}`: value set in block height `h`
//!   - `{height}/old/{dyn}`: value from predecessor block height
//! - `rollback`: diffs in account subspaces' key-vals for keys modified with
//!   `persist_diff == false` which are only kept for 1 block to support
//!   rollback
//!   - `{height}/new/{dyn}`: value set in block height `h`
//!   - `{height}/old/{dyn}`: value from predecessor block height
//! - `block`: block state
//!   - `results/{h}`: block results at height `h`
//!   - `h`: for each block at height `h`:
//!     - `tree`: merkle tree
//!       - `root`: root hash
//!       - `store`: the tree's store
//!     - `time`: block time
//!     - `epoch`: block epoch
//!     - `address_gen`: established address generator
//!     - `header`: block's header
//! - `replay_protection`: hashes of processed tx for replay protection purposes
//!     - `current/{hash}`: a hash included in the current block
//!     - `{hash}`: a hash included in previous blocks

use std::fs::File;
use std::io::{BufWriter, Read, Seek, Write};
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

use data_encoding::HEXLOWER;
use itertools::Either;
use namada_replay_protection as replay_protection;
use namada_sdk::arith::checked;
use namada_sdk::borsh::{BorshDeserialize, BorshSerialize, BorshSerializeExt};
use namada_sdk::collections::HashSet;
use namada_sdk::eth_bridge::storage::bridge_pool;
use namada_sdk::eth_bridge::storage::proof::BridgePoolRootProof;
use namada_sdk::gas::Gas;
use namada_sdk::hash::Hash;
use namada_sdk::state::merkle_tree::{
    tree_key_prefix_with_epoch, tree_key_prefix_with_height,
};
use namada_sdk::state::{
    BlockStateRead, BlockStateWrite, DB, DBIter, DBWriteBatch,
    DbError as Error, DbResult as Result, MerkleTreeStoresRead,
    PatternIterator, PrefixIterator, StoreType,
};
use namada_sdk::storage::{
    BLOCK_CF, BlockHeader, BlockHeight, DBUpdateVisitor, DIFFS_CF, DbColFam,
    Epoch, Key, KeySeg, REPLAY_PROTECTION_CF, ROLLBACK_CF, STATE_CF,
    SUBSPACE_CF,
};
use namada_sdk::{decode, encode, ethereum_events};
use rayon::prelude::*;
use regex::Regex;
use rocksdb::{
    BlockBasedOptions, ColumnFamily, ColumnFamilyDescriptor, DBCompactionStyle,
    DBCompressionType, Direction, FlushOptions, IteratorMode, Options,
    ReadOptions, WriteBatch,
};

use crate::config::utils::num_of_threads;

// TODO the DB schema will probably need some kind of versioning

/// Env. var to set a number of Rayon global worker threads
const ENV_VAR_ROCKSDB_COMPACTION_THREADS: &str =
    "NAMADA_ROCKSDB_COMPACTION_THREADS";

const BLOCK_HEIGHT_KEY: &str = "height";
const NEXT_EPOCH_MIN_START_HEIGHT_KEY: &str = "next_epoch_min_start_height";
const NEXT_EPOCH_MIN_START_TIME_KEY: &str = "next_epoch_min_start_time";
const UPDATE_EPOCH_BLOCKS_DELAY_KEY: &str = "update_epoch_blocks_delay";
const COMMIT_ONLY_DATA_KEY: &str = "commit_only_data_commitment";
const CONVERSION_STATE_KEY: &str = "conversion_state";
const ETHEREUM_HEIGHT_KEY: &str = "ethereum_height";
const ETH_EVENTS_QUEUE_KEY: &str = "eth_events_queue";
const RESULTS_KEY_PREFIX: &str = "results";
const PRED_KEY_PREFIX: &str = "pred";

const MERKLE_TREE_ROOT_KEY_SEGMENT: &str = "root";
const MERKLE_TREE_STORE_KEY_SEGMENT: &str = "store";
const BLOCK_HEADER_KEY_SEGMENT: &str = "header";
const BLOCK_TIME_KEY_SEGMENT: &str = "time";
const EPOCH_KEY_SEGMENT: &str = "epoch";
const PRED_EPOCHS_KEY_SEGMENT: &str = "pred_epochs";
const ADDRESS_GEN_KEY_SEGMENT: &str = "address_gen";

const OLD_DIFF_PREFIX: &str = "old";
const NEW_DIFF_PREFIX: &str = "new";

// 10 MB
const MAX_STATE_SYNC_CHUNK_SIZE: usize = 10_000_000;

/// RocksDB handle
#[derive(Debug)]
pub struct RocksDB {
    /// Handle to the db
    inner: ManuallyDrop<rocksdb::DB>,
    /// Indicates if read only
    read_only: bool,
    /// Whether the handle is invalid
    invalid_handle: bool,
}

/// DB Handle for batch writes.
#[derive(Default)]
pub struct RocksDBWriteBatch(WriteBatch);

/// Open RocksDB for the DB
pub fn open(
    path: impl AsRef<Path>,
    read_only: bool,
    cache: Option<&rocksdb::Cache>,
) -> Result<RocksDB> {
    let logical_cores = num_cpus::get();
    let compaction_threads = i32::try_from(num_of_threads(
        ENV_VAR_ROCKSDB_COMPACTION_THREADS,
        // If not set, default to quarter of logical CPUs count
        logical_cores / 4,
    ))?;
    tracing::info!(
        "Using {} compactions threads for RocksDB.",
        compaction_threads
    );

    // DB options
    let mut db_opts = Options::default();

    // This gives `compaction_threads` number to compaction threads and 1 thread
    // for flush background jobs: https://github.com/facebook/rocksdb/blob/17ce1ca48be53ba29138f92dafc9c853d9241377/options/options.cc#L622
    db_opts.increase_parallelism(compaction_threads);

    db_opts.set_bytes_per_sync(1048576);
    set_max_open_files(&mut db_opts);

    // TODO the recommended default `options.compaction_pri =
    // kMinOverlappingRatio` doesn't seem to be available in Rust

    db_opts.create_missing_column_families(true);
    db_opts.create_if_missing(true);
    db_opts.set_atomic_flush(true);

    let mut cfs = Vec::new();
    let mut table_opts = BlockBasedOptions::default();
    table_opts.set_block_size(16 * 1024);
    table_opts.set_cache_index_and_filter_blocks(true);
    table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
    if let Some(cache) = cache {
        table_opts.set_block_cache(cache);
    }
    // latest format versions https://github.com/facebook/rocksdb/blob/d1c510baecc1aef758f91f786c4fbee3bc847a63/include/rocksdb/table.h#L394
    table_opts.set_format_version(5);

    // for subspace (read/update-intensive)
    let mut subspace_cf_opts = Options::default();
    subspace_cf_opts.set_compression_type(DBCompressionType::Zstd);
    subspace_cf_opts.set_compression_options(0, 0, 0, 1024 * 1024);
    // ! recommended initial setup https://github.com/facebook/rocksdb/wiki/Setup-Options-and-Basic-Tuning#other-general-options
    subspace_cf_opts.set_level_compaction_dynamic_level_bytes(true);
    subspace_cf_opts.set_compaction_style(DBCompactionStyle::Level);
    subspace_cf_opts.set_block_based_table_factory(&table_opts);
    cfs.push(ColumnFamilyDescriptor::new(SUBSPACE_CF, subspace_cf_opts));

    // for diffs (insert-intensive)
    let mut diffs_cf_opts = Options::default();
    diffs_cf_opts.set_compression_type(DBCompressionType::Zstd);
    diffs_cf_opts.set_compression_options(0, 0, 0, 1024 * 1024);
    diffs_cf_opts.set_compaction_style(DBCompactionStyle::Level);
    diffs_cf_opts.set_block_based_table_factory(&table_opts);
    cfs.push(ColumnFamilyDescriptor::new(DIFFS_CF, diffs_cf_opts));

    // for non-persisted diffs for rollback (read/update-intensive)
    let mut rollback_cf_opts = Options::default();
    rollback_cf_opts.set_compression_type(DBCompressionType::Zstd);
    rollback_cf_opts.set_compression_options(0, 0, 0, 1024 * 1024);
    rollback_cf_opts.set_compaction_style(DBCompactionStyle::Level);
    rollback_cf_opts.set_block_based_table_factory(&table_opts);
    cfs.push(ColumnFamilyDescriptor::new(ROLLBACK_CF, rollback_cf_opts));

    // for the ledger state (update-intensive)
    let mut state_cf_opts = Options::default();
    // No compression since the size of the state is small
    state_cf_opts.set_level_compaction_dynamic_level_bytes(true);
    state_cf_opts.set_compaction_style(DBCompactionStyle::Level);
    state_cf_opts.set_block_based_table_factory(&table_opts);
    cfs.push(ColumnFamilyDescriptor::new(STATE_CF, state_cf_opts));

    // for blocks (insert-intensive)
    let mut block_cf_opts = Options::default();
    block_cf_opts.set_compression_type(DBCompressionType::Zstd);
    block_cf_opts.set_compression_options(0, 0, 0, 1024 * 1024);
    block_cf_opts.set_compaction_style(DBCompactionStyle::Universal);
    block_cf_opts.set_block_based_table_factory(&table_opts);
    cfs.push(ColumnFamilyDescriptor::new(BLOCK_CF, block_cf_opts));

    // for replay protection (read/insert-intensive)
    let mut replay_protection_cf_opts = Options::default();
    replay_protection_cf_opts.set_compression_type(DBCompressionType::Zstd);
    replay_protection_cf_opts.set_compression_options(0, 0, 0, 1024 * 1024);
    replay_protection_cf_opts.set_level_compaction_dynamic_level_bytes(true);
    // Prioritize minimizing read amplification
    replay_protection_cf_opts.set_compaction_style(DBCompactionStyle::Level);
    replay_protection_cf_opts.set_block_based_table_factory(&table_opts);
    cfs.push(ColumnFamilyDescriptor::new(
        REPLAY_PROTECTION_CF,
        replay_protection_cf_opts,
    ));
    Ok(if read_only {
        RocksDB {
            inner: ManuallyDrop::new(
                rocksdb::DB::open_cf_descriptors_read_only(
                    &db_opts, path, cfs, false,
                )
                .map_err(|e| Error::DBError(e.into_string()))?,
            ),
            invalid_handle: false,
            read_only: true,
        }
    } else {
        RocksDB {
            inner: ManuallyDrop::new(
                rocksdb::DB::open_cf_descriptors(&db_opts, path, cfs)
                    .map_err(|e| Error::DBError(e.into_string()))?,
            ),
            invalid_handle: false,
            read_only: false,
        }
    })
}

impl Drop for RocksDB {
    fn drop(&mut self) {
        if self.invalid_handle {
            return;
        }
        if !self.read_only {
            self.flush(true).expect("flush failed");
        }
        unsafe { ManuallyDrop::drop(&mut self.inner) }
    }
}

impl RocksDB {
    fn get_column_family(&self, cf_name: &str) -> Result<&ColumnFamily> {
        self.inner
            .cf_handle(cf_name)
            .ok_or(Error::DBError("No {cf_name} column family".to_string()))
    }

    fn read_value<T>(
        &self,
        cf: &ColumnFamily,
        key: impl AsRef<str>,
    ) -> Result<Option<T>>
    where
        T: BorshDeserialize,
    {
        self.read_value_bytes(cf, key)?
            .map(|bytes| decode(bytes).map_err(Error::CodingError))
            .transpose()
    }

    fn read_value_bytes(
        &self,
        cf: &ColumnFamily,
        key: impl AsRef<str>,
    ) -> Result<Option<Vec<u8>>> {
        self.inner
            .get_cf(cf, key.as_ref())
            .map_err(|e| Error::DBError(e.into_string()))
    }

    fn add_state_value_to_batch<T>(
        &self,
        cf: &ColumnFamily,
        key: impl AsRef<str>,
        value: &T,
        batch: &mut RocksDBWriteBatch,
    ) -> Result<()>
    where
        T: BorshSerialize,
    {
        if let Some(current_value) = self
            .inner
            .get_cf(cf, key.as_ref())
            .map_err(|e| Error::DBError(e.into_string()))?
        {
            batch.0.put_cf(
                cf,
                format!("{PRED_KEY_PREFIX}/{}", key.as_ref()),
                current_value,
            );
        }
        self.add_value_to_batch(cf, key, value, batch);
        Ok(())
    }

    fn add_value_to_batch<T>(
        &self,
        cf: &ColumnFamily,
        key: impl AsRef<str>,
        value: &T,
        batch: &mut RocksDBWriteBatch,
    ) where
        T: BorshSerialize,
    {
        self.add_value_bytes_to_batch(cf, key, encode(&value), batch)
    }

    fn add_value_bytes_to_batch(
        &self,
        cf: &ColumnFamily,
        key: impl AsRef<str>,
        value: Vec<u8>,
        batch: &mut RocksDBWriteBatch,
    ) {
        batch.0.put_cf(cf, key.as_ref(), value);
    }

    /// Persist the diff of an account subspace key-val under the height where
    /// it was changed in a batch write.
    fn batch_write_subspace_diff(
        &self,
        batch: &mut RocksDBWriteBatch,
        height: BlockHeight,
        key: &Key,
        old_value: Option<&[u8]>,
        new_value: Option<&[u8]>,
        persist_diffs: bool,
    ) -> Result<()> {
        let cf = if persist_diffs {
            self.get_column_family(DIFFS_CF)?
        } else {
            self.get_column_family(ROLLBACK_CF)?
        };
        let (old_val_key, new_val_key) = old_and_new_diff_key(key, height)?;

        if let Some(old_value) = old_value {
            batch.0.put_cf(cf, old_val_key, old_value);
        }

        if let Some(new_value) = new_value {
            batch.0.put_cf(cf, new_val_key, new_value);
        }
        Ok(())
    }

    /// Dump last known block
    pub fn dump_block(
        &self,
        out_file_path: std::path::PathBuf,
        historic: bool,
        height: Option<BlockHeight>,
    ) {
        // Find the last block height
        let state_cf = self
            .get_column_family(STATE_CF)
            .expect("State column family should exist");

        let last_height = self
            .read_value(state_cf, BLOCK_HEIGHT_KEY)
            .expect("Unable to read DB")
            .expect("No block height found");

        let height = height.unwrap_or(last_height);

        let full_path = out_file_path
            .with_file_name(format!(
                "{}_{height}",
                out_file_path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "dump_db".to_string())
            ))
            .with_extension("toml");

        let mut file = File::options()
            .append(true)
            .create_new(true)
            .open(&full_path)
            .expect("Cannot open the output file");

        println!("Will write to {} ...", full_path.to_string_lossy());

        if historic {
            // Dump the keys prepended with the selected block height (includes
            // subspace diff keys)

            // Diffs
            let cf = self
                .get_column_family(DIFFS_CF)
                .expect("Diffs column family should exist");
            let prefix = height.raw();
            self.dump_it(cf, Some(prefix.clone()), &mut file);

            // Block
            let cf = self
                .get_column_family(BLOCK_CF)
                .expect("Block column family should exist");
            self.dump_it(cf, Some(prefix), &mut file);
        }

        // subspace
        if height != last_height {
            // Restoring subspace at specified height
            let restored_subspace = self
                .iter_prefix(None)
                .par_bridge()
                .fold(
                    || "".to_string(),
                    |mut cur, (key, _value, _gas)| match self
                        .read_subspace_val_with_height(
                            &Key::from(key.to_db_key()),
                            height,
                            last_height,
                        )
                        .expect("Unable to find subspace key")
                    {
                        Some(value) => {
                            let val = HEXLOWER.encode(&value);
                            let new_line = format!("\"{key}\" = \"{val}\"\n");
                            cur.push_str(new_line.as_str());
                            cur
                        }
                        None => cur,
                    },
                )
                .reduce(
                    || "".to_string(),
                    |mut a: String, b: String| {
                        a.push_str(&b);
                        a
                    },
                );
            file.write_all(restored_subspace.as_bytes())
                .expect("Unable to write to output file");
        } else {
            // Just dump the current subspace
            let cf = self
                .get_column_family(SUBSPACE_CF)
                .expect("Subspace column family should exist");
            self.dump_it(cf, None, &mut file);
        }

        // replay protection
        // Dump of replay protection keys is possible only at the last height
        if height == last_height {
            let cf = self
                .get_column_family(REPLAY_PROTECTION_CF)
                .expect("Replay protection column family should exist");
            self.dump_it(cf, None, &mut file);
        }

        println!("Done writing to {}", full_path.to_string_lossy());
    }

    /// Dump data
    fn dump_it(
        &self,
        cf: &ColumnFamily,
        prefix: Option<String>,
        file: &mut File,
    ) {
        let read_opts = make_iter_read_opts(prefix.clone());
        let iter = if let Some(prefix) = prefix {
            self.inner.iterator_cf_opt(
                cf,
                read_opts,
                IteratorMode::From(prefix.as_bytes(), Direction::Forward),
            )
        } else {
            self.inner
                .iterator_cf_opt(cf, read_opts, IteratorMode::Start)
        };

        let mut buf = BufWriter::new(file);
        for (key, raw_val, _gas) in PersistentPrefixIterator(
            PrefixIterator::new(iter, String::default()),
            // Empty string to prevent prefix stripping, the prefix is
            // already in the enclosed iterator
        ) {
            let val = HEXLOWER.encode(&raw_val);
            let bytes = format!("\"{key}\" = \"{val}\"\n");
            buf.write_all(bytes.as_bytes())
                .expect("Unable to write to buffer");
        }
        buf.flush().expect("Unable to write to output file");
    }

    /// Create a checkpoint of the state in RocksDB at block height
    /// `block_height`.
    pub fn checkpoint(
        &self,
        base_dir: PathBuf,
        block_height: BlockHeight,
    ) -> Result<DbSnapshot> {
        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.inner)
            .map_err(|e| Error::DBError(e.to_string()))?;
        let snapshot_path = SnapshotPath(base_dir, block_height);
        std::fs::create_dir_all(snapshot_path.base()).or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(Error::DBError(e.to_string()))
            }
        })?;
        checkpoint
            .create_checkpoint(snapshot_path.temp_rocksdb())
            .map_err(|e| Error::DBError(e.to_string()))?;
        Ok(DbSnapshot(snapshot_path))
    }

    /// Rollback to previous block. Given the inner working of tendermint
    /// rollback and of the key structure of Namada, calling rollback more than
    /// once without restarting the chain results in a single rollback.
    pub fn rollback(
        &mut self,
        tendermint_block_height: BlockHeight,
    ) -> Result<()> {
        let last_block = self.read_last_block()?.ok_or(Error::DBError(
            "Missing last block in storage".to_string(),
        ))?;
        tracing::info!(
            "Namada last block height: {}, Tendermint last block height: {}",
            last_block.height,
            tendermint_block_height
        );

        // If the block height to which tendermint rolled back matches the
        // Namada height, there's no need to rollback
        if tendermint_block_height == last_block.height {
            tracing::info!(
                "Namada height already matches the rollback Tendermint \
                 height, no need to rollback."
            );
            return Ok(());
        }

        let mut batch = RocksDB::batch();
        let previous_height =
            last_block.height.prev_height().expect("Must have a pred");

        let state_cf = self.get_column_family(STATE_CF)?;
        // Revert the non-height-prepended metadata storage keys which get
        // updated with every block. Because of the way we save these
        // three keys in storage we can only perform one rollback before
        // restarting the chain
        tracing::info!("Reverting non-height-prepended metadata keys");
        batch
            .0
            .put_cf(state_cf, BLOCK_HEIGHT_KEY, encode(&previous_height));
        for metadata_key in [
            NEXT_EPOCH_MIN_START_HEIGHT_KEY,
            NEXT_EPOCH_MIN_START_TIME_KEY,
            COMMIT_ONLY_DATA_KEY,
            UPDATE_EPOCH_BLOCKS_DELAY_KEY,
        ] {
            let previous_key = format!("{PRED_KEY_PREFIX}/{metadata_key}");
            let previous_value = self
                .read_value_bytes(state_cf, &previous_key)?
                .ok_or(Error::UnknownKey { key: previous_key })?;

            self.add_value_bytes_to_batch(
                state_cf,
                metadata_key,
                previous_value,
                &mut batch,
            );
            // NOTE: we cannot restore the "pred/" keys themselves since we
            // don't have their predecessors in storage, but there's no need to
            // since we cannot do more than one rollback anyway because of
            // CometBFT.
        }

        // Revert conversion state if the epoch had been changed
        if last_block.pred_epochs.get_epoch(previous_height)
            != Some(last_block.epoch)
        {
            let previous_key =
                format!("{PRED_KEY_PREFIX}/{CONVERSION_STATE_KEY}");
            let previous_value = self
                .read_value_bytes(state_cf, &previous_key)?
                .ok_or(Error::UnknownKey { key: previous_key })?;
            self.add_value_bytes_to_batch(
                state_cf,
                CONVERSION_STATE_KEY,
                previous_value,
                &mut batch,
            );
        }

        // Delete block results for the last block
        let block_cf = self.get_column_family(BLOCK_CF)?;
        tracing::info!("Removing last block results");
        batch.0.delete_cf(
            block_cf,
            format!("{RESULTS_KEY_PREFIX}/{}", last_block.height),
        );

        // Restore the state of replay protection to the last block
        let reprot_cf = self.get_column_family(REPLAY_PROTECTION_CF)?;
        tracing::info!("Restoring replay protection state");
        // Remove the "current" tx hashes
        for (ref current_key, _, _) in self.iter_current_replay_protection() {
            batch.0.delete_cf(reprot_cf, current_key);
        }

        // Execute next step in parallel
        let batch = Mutex::new(batch);

        tracing::info!("Restoring previous height subspace diffs");
        self.iter_prefix(None).par_bridge().try_for_each(
            |(key, _value, _gas)| -> Result<()> {
                // Restore previous height diff if present, otherwise delete the
                // subspace key
                let subspace_cf = self.get_column_family(SUBSPACE_CF)?;
                match self.read_subspace_val_with_height(
                    &Key::from(key.to_db_key()),
                    previous_height,
                    last_block.height,
                )? {
                    Some(previous_value) => batch.lock().unwrap().0.put_cf(
                        subspace_cf,
                        &key,
                        previous_value,
                    ),
                    None => {
                        batch.lock().unwrap().0.delete_cf(subspace_cf, &key)
                    }
                }

                Ok(())
            },
        )?;

        let mut batch = batch.into_inner().unwrap();

        let subspace_cf = self.get_column_family(SUBSPACE_CF)?;
        let diffs_cf = self.get_column_family(DIFFS_CF)?;
        // Look for diffs in this block to find what has been deleted
        let diff_new_key_prefix = Key {
            segments: vec![
                last_block.height.to_db_key(),
                NEW_DIFF_PREFIX.to_string().to_db_key(),
            ],
        };
        for (key_str, val, _) in
            iter_diffs_prefix(self, diffs_cf, last_block.height, None, true)
        {
            let key = Key::parse(&key_str).unwrap();
            let diff_new_key = diff_new_key_prefix.join(&key);
            if self.read_subspace_val(&diff_new_key)?.is_none() {
                // If there is no new value, it has been deleted in this
                // block and we have to restore it
                batch.0.put_cf(subspace_cf, key_str, val)
            }
        }

        // Look for non-persisted diffs for rollback
        let rollback_cf = self.get_column_family(ROLLBACK_CF)?;
        // Iterate the old keys first and keep a set of keys that have old val
        let mut keys_with_old_value = HashSet::<String>::new();
        for (key_str, val, _) in
            iter_diffs_prefix(self, rollback_cf, last_block.height, None, true)
        {
            // If there is no new value, it has been deleted in this
            // block and we have to restore it
            keys_with_old_value.insert(key_str.clone());
            batch.0.put_cf(subspace_cf, key_str, val)
        }
        // Then the new keys
        for (key_str, _val, _) in
            iter_diffs_prefix(self, rollback_cf, last_block.height, None, false)
        {
            if !keys_with_old_value.contains(&key_str) {
                // If there was no old value it means that the key was newly
                // written in the last block and we have to delete it
                batch.0.delete_cf(subspace_cf, key_str)
            }
        }

        tracing::info!("Deleting keys prepended with the last height");
        let prefix = last_block.height.to_string();
        let mut delete_keys = |cf: &ColumnFamily| {
            let read_opts = make_iter_read_opts(Some(prefix.clone()));
            let iter = self.inner.iterator_cf_opt(
                cf,
                read_opts,
                IteratorMode::From(prefix.as_bytes(), Direction::Forward),
            );
            for (key, _value, _gas) in PersistentPrefixIterator(
                // Empty prefix string to prevent stripping
                PrefixIterator::new(iter, String::default()),
            ) {
                batch.0.delete_cf(cf, key);
            }
        };
        // Delete any height-prepended key in subspace diffs
        let diffs_cf = self.get_column_family(DIFFS_CF)?;
        delete_keys(diffs_cf);
        // Delete any height-prepended key in the block
        delete_keys(block_cf);

        // Write the batch and persist changes to disk
        tracing::info!("Flushing restored state to disk");
        self.exec_batch(batch)
    }

    #[inline]
    pub fn column_families(&self) -> [(&'static str, &ColumnFamily); 6] {
        DbColFam::all()
            .iter()
            .map(|cf| {
                (
                    *cf,
                    self.get_column_family(cf)
                        .expect("Failed to read column family"),
                )
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "There should be exactly six column families")
            .unwrap()
    }

    /// Read diffs of non-persisted key-vals that are only kept for rollback of
    /// one block height.
    #[cfg(test)]
    pub fn read_rollback_val(
        &self,
        key: &Key,
        height: BlockHeight,
        is_old: bool,
    ) -> Result<Option<Vec<u8>>> {
        let rollback_cf = self.get_column_family(ROLLBACK_CF)?;
        let key = if is_old {
            old_and_new_diff_key(key, height)?.0
        } else {
            old_and_new_diff_key(key, height)?.1
        };

        self.inner
            .get_cf(rollback_cf, key)
            .map_err(|e| Error::DBError(e.into_string()))
    }

    /// Writes an entry directly to a db batch update
    /// directly
    pub fn insert_entry(
        &self,
        batch: &mut RocksDBWriteBatch,
        cf: &DbColFam,
        key: &Key,
        new_value: impl AsRef<[u8]>,
    ) -> Result<()> {
        // NB: the following code only updates values
        // written to at the last committed height
        let val = new_value.as_ref();

        // Write the new key-val in the Db column family
        let cf_name = self.get_column_family(cf.to_str())?;
        self.add_value_bytes_to_batch(
            cf_name,
            key.to_string(),
            val.to_vec(),
            batch,
        );
        Ok(())
    }
}

/// The path to a snapshot.
#[derive(Clone, Debug)]
pub struct SnapshotPath(pub PathBuf, pub BlockHeight);

impl SnapshotPath {
    /// Return the root path where snapshots are stored.
    pub fn snapshot_root_path(mut base_dir: PathBuf) -> PathBuf {
        base_dir.push("snapshots");
        base_dir
    }

    /// Remove all data pertaining to the current snapshot.
    pub fn remove(&self) -> std::io::Result<()> {
        std::fs::remove_dir_all(self.base())
    }

    /// Return the base path associated with this [`SnapshotPath`].
    pub fn base(&self) -> PathBuf {
        let mut buf = Self::snapshot_root_path(self.0.clone());
        let height = self.1.0;
        buf.push(format!("block-{height:016}"));
        buf
    }

    /// Return the chunk hashes path associated with this [`SnapshotPath`].
    pub fn chunk_hashes(&self) -> PathBuf {
        let mut buf = self.base();
        buf.push("chunks-hashed");
        buf
    }

    /// Return the root of the chunk hashes tree path associated with this
    /// [`SnapshotPath`].
    pub fn chunks_root_hash(&self) -> PathBuf {
        let mut buf = self.base();
        buf.push("chunks-root-hash");
        buf
    }

    /// Return the temporary rocksdb path associated with this [`SnapshotPath`].
    pub fn temp_rocksdb(&self) -> PathBuf {
        let mut buf = self.base();
        buf.push("db");
        buf
    }

    /// Return the temporary tarball path associated with this [`SnapshotPath`].
    ///
    /// The value of `compression_extension` should reflect the compression
    /// algorithm used (e.g. `gz` for Gzip).
    pub fn temp_tarball(&self, compression_extension: &str) -> PathBuf {
        let mut buf = self.base();
        buf.push(format!("db.tar.{compression_extension}"));
        buf
    }

    /// Return the path of the chunk `chk` associated with this
    /// [`SnapshotPath`].
    pub fn chunk_with_id(&self, chk: usize) -> PathBuf {
        let mut buf = self.base();
        buf.push(format!("chunk-{chk:032}"));
        buf
    }
}

/// Metadata pertaining to some database snapshot.
#[derive(Debug)]
pub struct DbSnapshotMeta {
    /// The height of the snapshot.
    pub height: BlockHeight,
    /// List of the hashes of all chunks.
    pub chunk_hashes: Vec<Hash>,
    /// Hash of all the chunk hashes, forming a shallow tree.
    pub root_hash: Hash,
}

#[derive(Clone)]
pub struct DbSnapshot(pub SnapshotPath);

impl DbSnapshot {
    /// The magic number referring to the format of the snapshot.
    pub const FORMAT_MAGIC: u32 = 0;

    /// Package and chunk the contents of the db snapshot.
    // NB: passing an owned `self` guarantees we don't attempt to call
    // this method again, which removes the temporary checkpoint dir
    // created by rocksdb
    pub fn package(self) -> std::io::Result<()> {
        self.build_tarball()?;
        self.chunk_snapshot(MAX_STATE_SYNC_CHUNK_SIZE)?;
        Ok(())
    }

    pub fn unpack(
        archive_file: &mut std::fs::File,
        dest: impl AsRef<Path>,
    ) -> std::io::Result<()> {
        use zstd::stream::read::Decoder;

        let file_buf_reader = std::io::BufReader::new(archive_file);
        let zstd_decoder = Decoder::new(file_buf_reader)?;

        let mut archive = tar::Archive::new(zstd_decoder);
        archive.unpack(dest)?;

        Ok(())
    }

    pub(crate) fn build_tarball(&self) -> std::io::Result<()> {
        use zstd::stream::write::Encoder;

        let snapshot_temp_db_path = self.0.temp_rocksdb();

        let mut tar_builder = {
            let file_handle = File::create(self.0.temp_tarball("zst"))?;
            let zstd_encoder = Encoder::new(file_handle, 0)?.auto_finish();
            tar::Builder::new(zstd_encoder)
        };

        // build tarball with rocksdb checkpoint contents
        tar_builder.append_dir_all("db", &snapshot_temp_db_path)?;
        tar_builder.finish()?;
        _ = tar_builder;

        // remove aux checkpoint dir
        std::fs::remove_dir_all(&snapshot_temp_db_path)
    }

    fn chunk_snapshot(&self, max_chunk: usize) -> std::io::Result<()> {
        let tarball_path = self.0.temp_tarball("zst");

        let mut buf = vec![0; max_chunk];
        let mut file = File::open(&tarball_path)?;

        let mut eof = false;
        let mut chunk_hashes = vec![];

        // TODO: we can use tokio here to read chunks
        // in parallel
        //
        // 1. determine tar archive size
        // 2. spawn len / MAX_STATE_SYNC_CHUNK_SIZE tasks
        // 3. spawn one more task if necessary to read chunk smaller than
        //    MAX_STATE_SYNC_CHUNK_SIZE
        // 4. assemble read data (need to store hash of the chunk)

        for chunk_id in 0.. {
            let mut read = 0;

            // read up to `MAX_STATE_SYNC_CHUNK_SIZE` bytes
            while read != max_chunk {
                match file.read(&mut buf[read..]) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => checked!(read += n).unwrap(),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }

            let chunk = &buf[..read];

            std::fs::write(self.0.chunk_with_id(chunk_id), chunk)?;
            chunk_hashes.push(Hash::sha256(chunk));

            if eof {
                break;
            }
        }

        let chunk_hashes = chunk_hashes.serialize_to_vec();
        let hash_of_all_chunks = Hash::sha256(&chunk_hashes);
        let snapshot_hash = Hash::sha256(
            (Self::FORMAT_MAGIC, hash_of_all_chunks).serialize_to_vec(),
        );

        std::fs::remove_file(tarball_path)?;
        std::fs::write(self.0.chunk_hashes(), chunk_hashes)?;
        std::fs::write(self.0.chunks_root_hash(), snapshot_hash)?;

        Ok(())
    }

    /// Keep `number_to_keep` latest snapshots. All others
    /// are deleted.
    pub fn cleanup(
        latest_height: BlockHeight,
        base_dir: &Path,
        number_to_keep: u64,
    ) -> std::io::Result<()> {
        let latest_height = latest_height.0;

        for height in Self::heights_of_stored_snapshots(base_dir)? {
            // this is correct... don't worry about it
            if checked!(height + number_to_keep <= latest_height).unwrap() {
                let snap = SnapshotPath(base_dir.into(), BlockHeight(height));
                snap.remove()?;
            }
        }
        Ok(())
    }

    /// Load the metadata of the given snapshot heights.
    pub fn load_snapshot_metadata(
        base_dir: &Path,
        snapshot_heights: impl IntoIterator<Item = u64>,
    ) -> impl Iterator<Item = std::io::Result<DbSnapshotMeta>> {
        let mut iter = snapshot_heights.into_iter();
        let base_dir = base_dir.to_owned();

        std::iter::from_fn(move || {
            let height = BlockHeight(iter.next()?);

            let load = || {
                let snap = SnapshotPath(base_dir.clone(), height);

                let chunk_hashes = BorshDeserialize::try_from_slice(
                    &std::fs::read(snap.chunk_hashes())?,
                )?;
                let root_hash = BorshDeserialize::try_from_slice(
                    &std::fs::read(snap.chunks_root_hash())?,
                )?;

                Ok(DbSnapshotMeta {
                    height,
                    chunk_hashes,
                    root_hash,
                })
            };

            Some(load())
        })
    }

    /// List all block heights whose state snapshots exist.
    pub fn heights_of_stored_snapshots(
        base_dir: &Path,
    ) -> std::io::Result<Vec<u64>> {
        let snapshot_root = SnapshotPath::snapshot_root_path(base_dir.into());
        let mut heights = vec![];

        for entry in std::fs::read_dir(snapshot_root)? {
            let entry = entry?;
            let entry_path = entry.path();

            if entry_path.is_dir() {
                let Some(file_name) =
                    entry_path.file_name().and_then(|f| f.to_str())
                else {
                    continue;
                };
                let Some(("block", height_str)) = file_name.split_once('-')
                else {
                    continue;
                };
                let Some(height): Option<u64> = height_str.parse().ok() else {
                    continue;
                };
                heights.push(height);
            }
        }

        Ok(heights)
    }

    /// Load the specified chunk of a snapshot at the given block height
    pub fn load_chunk(
        height: BlockHeight,
        chunk: u64,
        base_dir: &Path,
    ) -> std::io::Result<Vec<u8>> {
        let snap = SnapshotPath(base_dir.into(), height);
        #[allow(clippy::cast_possible_truncation)]
        std::fs::read(snap.chunk_with_id(chunk as _))
    }
}

impl DB for RocksDB {
    type Cache = rocksdb::Cache;
    type Migrator = RocksDBUpdateVisitor;
    type RestoreSource<'a> = (&'a rocksdb::Cache, &'a mut std::fs::File);
    type WriteBatch = RocksDBWriteBatch;

    fn open(
        db_path: impl AsRef<std::path::Path>,
        cache: Option<&Self::Cache>,
    ) -> Self {
        open(db_path, false, cache).expect("cannot open the DB")
    }

    fn open_read_only(
        db_path: impl AsRef<std::path::Path>,
        cache: Option<&Self::Cache>,
    ) -> Self {
        open(db_path, true, cache).expect("cannot open the DB")
    }

    fn restore_from(
        &mut self,
        (cache, snapshot): Self::RestoreSource<'_>,
    ) -> Result<()> {
        snapshot.rewind().map_err(|e| {
            Error::DBError(format!("Failed to rewind snapshot file: {e}",))
        })?;

        let db_dir = self.inner.path().to_owned();

        let unpack_dir = db_dir.parent().ok_or_else(|| {
            Error::DBError(format!(
                "Failed to query parent directory of db: {}",
                db_dir.to_string_lossy()
            ))
        })?;

        // NB: close the current database handle.
        // DON'T TRY THIS AT HOME KIDS. we are
        // trained monkeys.
        unsafe {
            self.invalid_handle = true;
            ManuallyDrop::drop(&mut self.inner);
        }

        std::fs::remove_dir_all(&db_dir)
            .expect("Failed to nuke database directory");
        DbSnapshot::unpack(snapshot, unpack_dir)
            .expect("Failed to unpack new db");

        *self = Self::open(db_dir, Some(cache));

        Ok(())
    }

    fn path(&self) -> Option<&Path> {
        Some(self.inner.path())
    }

    fn flush(&self, wait: bool) -> Result<()> {
        let mut flush_opts = FlushOptions::default();
        flush_opts.set_wait(wait);
        let cfs = self
            .column_families()
            .into_iter()
            .map(|(_, cf)| cf)
            .collect::<Vec<_>>();
        // "For manual flush, application has to specify the list of column
        // families to flush atomically" from <https://github.com/facebook/rocksdb/wiki/Atomic-flush>
        self.inner
            .flush_cfs_opt(&cfs, &flush_opts)
            .map_err(|e| Error::DBError(e.into_string()))
    }

    fn read_last_block(&self) -> Result<Option<BlockStateRead>> {
        let state_cf = self.get_column_family(STATE_CF)?;
        let block_cf = self.get_column_family(BLOCK_CF)?;

        // Block height
        let height: BlockHeight =
            match self.read_value(state_cf, BLOCK_HEIGHT_KEY)? {
                Some(h) => h,
                None => return Ok(None),
            };

        // Epoch start height and time
        let next_epoch_min_start_height =
            match self.read_value(state_cf, NEXT_EPOCH_MIN_START_HEIGHT_KEY)? {
                Some(h) => h,
                None => return Ok(None),
            };

        let next_epoch_min_start_time =
            match self.read_value(state_cf, NEXT_EPOCH_MIN_START_TIME_KEY)? {
                Some(t) => t,
                None => return Ok(None),
            };

        let update_epoch_blocks_delay =
            match self.read_value(state_cf, UPDATE_EPOCH_BLOCKS_DELAY_KEY)? {
                Some(d) => d,
                None => return Ok(None),
            };

        let commit_only_data =
            match self.read_value(state_cf, COMMIT_ONLY_DATA_KEY)? {
                Some(d) => d,
                None => return Ok(None),
            };

        let conversion_state =
            match self.read_value(state_cf, CONVERSION_STATE_KEY)? {
                Some(c) => c,
                None => return Ok(None),
            };

        let ethereum_height =
            match self.read_value(state_cf, ETHEREUM_HEIGHT_KEY)? {
                Some(h) => h,
                None => return Ok(None),
            };

        let eth_events_queue =
            match self.read_value(state_cf, ETH_EVENTS_QUEUE_KEY)? {
                Some(q) => q,
                None => return Ok(None),
            };

        // Block results
        let results_key = format!("{RESULTS_KEY_PREFIX}/{}", height.raw());
        let results = match self.read_value(block_cf, results_key)? {
            Some(r) => r,
            None => return Ok(None),
        };

        // Read the block state one by one for simplicity because we need only 5
        // values for now. We can revert to use `iterator_cf_opt` with
        // the prefix to read more state values.
        let prefix = height.raw();

        // Restoring the Merkle tree later

        let time_key = format!("{prefix}/{BLOCK_TIME_KEY_SEGMENT}");
        let time = match self.read_value(block_cf, time_key)? {
            Some(t) => t,
            None => return Ok(None),
        };

        let epoch_key = format!("{prefix}/{EPOCH_KEY_SEGMENT}");
        let epoch = match self.read_value(block_cf, epoch_key)? {
            Some(e) => e,
            None => return Ok(None),
        };

        let pred_epochs_key = format!("{prefix}/{PRED_EPOCHS_KEY_SEGMENT}");
        let pred_epochs = match self.read_value(block_cf, pred_epochs_key)? {
            Some(e) => e,
            None => return Ok(None),
        };

        let address_gen_key = format!("{prefix}/{ADDRESS_GEN_KEY_SEGMENT}");
        let address_gen = match self.read_value(block_cf, address_gen_key)? {
            Some(a) => a,
            None => return Ok(None),
        };

        Ok(Some(BlockStateRead {
            height,
            time,
            epoch,
            pred_epochs,
            results,
            conversion_state,
            next_epoch_min_start_height,
            next_epoch_min_start_time,
            update_epoch_blocks_delay,
            address_gen,
            ethereum_height,
            eth_events_queue,
            commit_only_data,
        }))
    }

    fn add_block_to_batch(
        &self,
        state: BlockStateWrite<'_>,
        batch: &mut Self::WriteBatch,
        is_full_commit: bool,
    ) -> Result<()> {
        let BlockStateWrite {
            merkle_tree_stores,
            header,
            height,
            time,
            epoch,
            pred_epochs,
            next_epoch_min_start_height,
            next_epoch_min_start_time,
            update_epoch_blocks_delay,
            address_gen,
            results,
            conversion_state,
            ethereum_height,
            eth_events_queue,
            commit_only_data,
        }: BlockStateWrite<'_> = state;

        let state_cf = self.get_column_family(STATE_CF)?;

        // Epoch start height and time
        self.add_state_value_to_batch(
            state_cf,
            NEXT_EPOCH_MIN_START_HEIGHT_KEY,
            &next_epoch_min_start_height,
            batch,
        )?;
        self.add_state_value_to_batch(
            state_cf,
            NEXT_EPOCH_MIN_START_TIME_KEY,
            &next_epoch_min_start_time,
            batch,
        )?;

        self.add_state_value_to_batch(
            state_cf,
            UPDATE_EPOCH_BLOCKS_DELAY_KEY,
            &update_epoch_blocks_delay,
            batch,
        )?;

        self.add_state_value_to_batch(
            state_cf,
            COMMIT_ONLY_DATA_KEY,
            &commit_only_data,
            batch,
        )?;

        // Save the conversion state when the epoch is updated
        if is_full_commit {
            self.add_state_value_to_batch(
                state_cf,
                CONVERSION_STATE_KEY,
                &conversion_state,
                batch,
            )?;
        }

        self.add_value_to_batch(
            state_cf,
            ETHEREUM_HEIGHT_KEY,
            &ethereum_height,
            batch,
        );
        self.add_value_to_batch(
            state_cf,
            ETH_EVENTS_QUEUE_KEY,
            &eth_events_queue,
            batch,
        );

        let block_cf = self.get_column_family(BLOCK_CF)?;
        let prefix = height.raw();

        // Merkle tree
        for st in StoreType::iter() {
            if st.is_stored_every_block() || is_full_commit {
                let key_prefix = if st.is_stored_every_block() {
                    tree_key_prefix_with_height(st, height)
                } else {
                    tree_key_prefix_with_epoch(st, epoch)
                };
                let root_key =
                    format!("{key_prefix}/{MERKLE_TREE_ROOT_KEY_SEGMENT}");
                self.add_value_to_batch(
                    block_cf,
                    root_key,
                    merkle_tree_stores.root(st),
                    batch,
                );
                let store_key =
                    format!("{key_prefix}/{MERKLE_TREE_STORE_KEY_SEGMENT}");
                self.add_value_bytes_to_batch(
                    block_cf,
                    store_key,
                    merkle_tree_stores.store(st).encode(),
                    batch,
                );
            }
        }

        // Block header
        if let Some(h) = header {
            let header_key = format!("{prefix}/{BLOCK_HEADER_KEY_SEGMENT}");
            self.add_value_to_batch(block_cf, header_key, &h, batch);
        }
        // Block time
        let time_key = format!("{prefix}/{BLOCK_TIME_KEY_SEGMENT}");
        self.add_value_to_batch(block_cf, time_key, &time, batch);
        // Block epoch
        let epoch_key = format!("{prefix}/{EPOCH_KEY_SEGMENT}");
        self.add_value_to_batch(block_cf, epoch_key, &epoch, batch);
        // Block results
        let results_key = format!("{RESULTS_KEY_PREFIX}/{}", height.raw());
        self.add_value_to_batch(block_cf, results_key, &results, batch);
        // Predecessor block epochs
        let pred_epochs_key = format!("{prefix}/{PRED_EPOCHS_KEY_SEGMENT}");
        self.add_value_to_batch(block_cf, pred_epochs_key, &pred_epochs, batch);
        // Address gen
        let address_gen_key = format!("{prefix}/{ADDRESS_GEN_KEY_SEGMENT}");
        self.add_value_to_batch(block_cf, address_gen_key, &address_gen, batch);

        // Block height
        self.add_value_to_batch(state_cf, BLOCK_HEIGHT_KEY, &height, batch);

        Ok(())
    }

    fn read_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>> {
        let block_cf = self.get_column_family(BLOCK_CF)?;
        let header_key = format!("{}/{BLOCK_HEADER_KEY_SEGMENT}", height.raw());
        self.read_value(block_cf, header_key)
    }

    fn read_merkle_tree_stores(
        &self,
        epoch: Epoch,
        base_height: BlockHeight,
        store_type: Option<StoreType>,
    ) -> Result<Option<MerkleTreeStoresRead>> {
        // Get the latest height at which the tree stores were written
        let block_cf = self.get_column_family(BLOCK_CF)?;
        let mut merkle_tree_stores = MerkleTreeStoresRead::default();
        let store_types = store_type
            .as_ref()
            .map(|st| Either::Left(std::iter::once(st)))
            .unwrap_or_else(|| Either::Right(StoreType::iter()));
        for st in store_types {
            let key_prefix = if st.is_stored_every_block() {
                tree_key_prefix_with_height(st, base_height)
            } else {
                tree_key_prefix_with_epoch(st, epoch)
            };
            let root_key =
                format!("{key_prefix}/{MERKLE_TREE_ROOT_KEY_SEGMENT}");
            match self.read_value(block_cf, root_key)? {
                Some(root) => merkle_tree_stores.set_root(st, root),
                None if store_type.is_some() => return Ok(None),
                _ => continue,
            }

            let store_key =
                format!("{key_prefix}/{MERKLE_TREE_STORE_KEY_SEGMENT}");
            match self.read_value_bytes(block_cf, store_key)? {
                Some(bytes) => {
                    merkle_tree_stores.set_store(st.decode_store(bytes)?)
                }
                None if store_type.is_some() => return Ok(None),
                _ => continue,
            }
        }
        Ok(Some(merkle_tree_stores))
    }

    fn has_replay_protection_entry(
        &self,
        hash: &namada_sdk::hash::Hash,
    ) -> Result<bool> {
        let replay_protection_cf =
            self.get_column_family(REPLAY_PROTECTION_CF)?;

        for key in [
            replay_protection::current_key(hash),
            replay_protection::key(hash),
        ] {
            if self
                .inner
                .get_pinned_cf(replay_protection_cf, key.to_string())
                .map_err(|e| Error::DBError(e.into_string()))?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn read_diffs_val(
        &self,
        key: &Key,
        height: BlockHeight,
        is_old: bool,
    ) -> Result<Option<Vec<u8>>> {
        let diffs_cf = self.get_column_family(DIFFS_CF)?;
        let key = if is_old {
            old_and_new_diff_key(key, height)?.0
        } else {
            old_and_new_diff_key(key, height)?.1
        };
        self.read_value_bytes(diffs_cf, key)
    }

    fn read_subspace_val(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        let subspace_cf = self.get_column_family(SUBSPACE_CF)?;
        self.read_value_bytes(subspace_cf, key.to_string())
    }

    fn read_subspace_val_with_height(
        &self,
        key: &Key,
        height: BlockHeight,
        last_height: BlockHeight,
    ) -> Result<Option<Vec<u8>>> {
        // Check if the value changed at this height
        let diffs_cf = self.get_column_family(DIFFS_CF)?;
        let (old_val_key, new_val_key) = old_and_new_diff_key(key, height)?;

        // If it has a "new" val, it was written at this height
        match self.read_value_bytes(diffs_cf, new_val_key)? {
            Some(new_val) => {
                return Ok(Some(new_val));
            }
            None => {
                // If it has an "old" val, it was deleted at this height
                if self.inner.key_may_exist_cf(diffs_cf, &old_val_key) {
                    // check if it actually exists
                    if self.read_value_bytes(diffs_cf, old_val_key)?.is_some() {
                        return Ok(None);
                    }
                }
            }
        }

        // If the value didn't change at the given height, we try to look for it
        // at successor heights, up to the `last_height`
        let mut raw_height = checked!(height.0 + 1)?;
        loop {
            // Try to find the next diff on this key
            let (old_val_key, new_val_key) =
                old_and_new_diff_key(key, BlockHeight(raw_height))?;
            let old_val = self.read_value_bytes(diffs_cf, &old_val_key)?;
            // If it has an "old" val, it's the one we're looking for
            match old_val {
                Some(bytes) => return Ok(Some(bytes)),
                None => {
                    // Check if the value was created at this height instead,
                    // which would mean that it wasn't present before
                    if self.inner.key_may_exist_cf(diffs_cf, &new_val_key) {
                        // check if it actually exists
                        if self
                            .read_value_bytes(diffs_cf, new_val_key)?
                            .is_some()
                        {
                            return Ok(None);
                        }
                    }

                    if raw_height >= last_height.0 {
                        // Read from latest height
                        return self.read_subspace_val(key);
                    } else {
                        checked!(raw_height += 1)?
                    }
                }
            }
        }
    }

    fn write_subspace_val(
        &mut self,
        height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
        persist_diffs: bool,
    ) -> Result<i64> {
        let mut batch = RocksDB::batch();
        let size_diff = self.batch_write_subspace_val(
            &mut batch,
            height,
            key,
            value,
            persist_diffs,
        )?;
        self.exec_batch(batch)?;
        Ok(size_diff)
    }

    fn delete_subspace_val(
        &mut self,
        height: BlockHeight,
        key: &Key,
        persist_diffs: bool,
    ) -> Result<i64> {
        let mut batch = RocksDB::batch();
        let prev_len = self.batch_delete_subspace_val(
            &mut batch,
            height,
            key,
            persist_diffs,
        )?;
        self.exec_batch(batch)?;
        Ok(prev_len)
    }

    fn batch() -> Self::WriteBatch {
        RocksDBWriteBatch::default()
    }

    fn exec_batch(&self, batch: Self::WriteBatch) -> Result<()> {
        self.inner
            .write(batch.0)
            .map_err(|e| Error::DBError(e.into_string()))
    }

    fn batch_write_subspace_val(
        &self,
        batch: &mut Self::WriteBatch,
        height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
        persist_diffs: bool,
    ) -> Result<i64> {
        let value = value.as_ref();
        let subspace_cf = self.get_column_family(SUBSPACE_CF)?;
        let size_diff =
            match self.read_value_bytes(subspace_cf, key.to_string())? {
                Some(old_value) => {
                    let len = i64::try_from(value.len())?;
                    let old_len = i64::try_from(old_value.len())?;
                    let size_diff = checked!(len - old_len)?;
                    // Persist the previous value
                    self.batch_write_subspace_diff(
                        batch,
                        height,
                        key,
                        Some(&old_value),
                        Some(value),
                        persist_diffs,
                    )?;
                    size_diff
                }
                None => {
                    self.batch_write_subspace_diff(
                        batch,
                        height,
                        key,
                        None,
                        Some(value),
                        persist_diffs,
                    )?;
                    i64::try_from(value.len())?
                }
            };

        // Write the new key-val
        batch.0.put_cf(subspace_cf, key.to_string(), value);

        Ok(size_diff)
    }

    fn batch_delete_subspace_val(
        &self,
        batch: &mut Self::WriteBatch,
        height: BlockHeight,
        key: &Key,
        persist_diffs: bool,
    ) -> Result<i64> {
        let subspace_cf = self.get_column_family(SUBSPACE_CF)?;

        // Check the length of previous value, if any
        let prev_len =
            match self.read_value_bytes(subspace_cf, key.to_string())? {
                Some(prev_value) => {
                    let prev_len = i64::try_from(prev_value.len())?;
                    // Persist the previous value
                    self.batch_write_subspace_diff(
                        batch,
                        height,
                        key,
                        Some(&prev_value),
                        None,
                        persist_diffs,
                    )?;
                    prev_len
                }
                None => 0,
            };

        // Delete the key-val
        batch.0.delete_cf(subspace_cf, key.to_string());

        Ok(prev_len)
    }

    fn prune_merkle_tree_store(
        &mut self,
        batch: &mut Self::WriteBatch,
        store_type: &StoreType,
        pruned_target: Either<BlockHeight, Epoch>,
    ) -> Result<()> {
        let block_cf = self.get_column_family(BLOCK_CF)?;
        let key_prefix = match pruned_target {
            Either::Left(height) => {
                tree_key_prefix_with_height(store_type, height)
            }
            Either::Right(epoch) => {
                tree_key_prefix_with_epoch(store_type, epoch)
            }
        };
        let root_key = format!("{key_prefix}/{MERKLE_TREE_ROOT_KEY_SEGMENT}");
        batch.0.delete_cf(block_cf, root_key);
        let store_key = format!("{key_prefix}/{MERKLE_TREE_STORE_KEY_SEGMENT}");
        batch.0.delete_cf(block_cf, store_key);
        Ok(())
    }

    fn read_bridge_pool_signed_nonce(
        &self,
        height: BlockHeight,
        last_height: BlockHeight,
    ) -> Result<Option<ethereum_events::Uint>> {
        let nonce_key = bridge_pool::get_signed_root_key();
        let bytes = if height == BlockHeight(0) || height >= last_height {
            self.read_subspace_val(&nonce_key)?
        } else {
            self.read_subspace_val_with_height(&nonce_key, height, last_height)?
        };
        match bytes {
            Some(bytes) => {
                let bp_root_proof = BridgePoolRootProof::try_from_slice(&bytes)
                    .map_err(Error::BorshCodingError)?;
                Ok(Some(bp_root_proof.data.1))
            }
            None => Ok(None),
        }
    }

    fn write_replay_protection_entry(
        &mut self,
        batch: &mut Self::WriteBatch,
        key: &Key,
    ) -> Result<()> {
        let replay_protection_cf =
            self.get_column_family(REPLAY_PROTECTION_CF)?;

        self.add_value_bytes_to_batch(
            replay_protection_cf,
            key.to_string(),
            vec![],
            batch,
        );

        Ok(())
    }

    fn move_current_replay_protection_entries(
        &mut self,
        batch: &mut Self::WriteBatch,
    ) -> Result<()> {
        let replay_protection_cf =
            self.get_column_family(REPLAY_PROTECTION_CF)?;
        let stripped_prefix = Some(replay_protection::current_prefix());

        for (ref hash_str, _, _) in iter_prefix(
            self,
            replay_protection_cf,
            stripped_prefix.as_ref(),
            None,
        ) {
            let hash = namada_sdk::hash::Hash::from_str(hash_str)
                .expect("Failed hash conversion");
            let current_key = replay_protection::current_key(&hash);
            let key = replay_protection::key(&hash);

            // Delete the current key and move it to the general bucket
            batch
                .0
                .delete_cf(replay_protection_cf, current_key.to_string());
            batch
                .0
                .put_cf(replay_protection_cf, key.to_string(), vec![]);
        }

        Ok(())
    }

    fn prune_non_persisted_diffs(
        &mut self,
        batch: &mut Self::WriteBatch,
        height: BlockHeight,
    ) -> Result<()> {
        let rollback_cf = self.get_column_family(ROLLBACK_CF)?;

        let diff_old_key_prefix = Key {
            segments: vec![
                height.to_db_key(),
                OLD_DIFF_PREFIX.to_string().to_db_key(),
            ],
        };
        for (key_str, _val, _) in
            iter_prefix(self, rollback_cf, None, Some(&diff_old_key_prefix))
        {
            batch.0.delete_cf(rollback_cf, key_str)
        }

        let diff_new_key_prefix = Key {
            segments: vec![
                height.to_db_key(),
                NEW_DIFF_PREFIX.to_string().to_db_key(),
            ],
        };
        for (key_str, _val, _) in
            iter_prefix(self, rollback_cf, None, Some(&diff_new_key_prefix))
        {
            batch.0.delete_cf(rollback_cf, key_str)
        }
        Ok(())
    }

    #[inline]
    fn overwrite_entry(
        &self,
        batch: &mut Self::WriteBatch,
        cf: &DbColFam,
        key: &Key,
        new_value: impl AsRef<[u8]>,
        persist_diffs: bool,
    ) -> Result<()> {
        self.insert_entry(batch, cf, key, new_value.as_ref())?;
        let state_cf = self.get_column_family(STATE_CF)?;
        let last_height: BlockHeight = self
            .read_value(state_cf, BLOCK_HEIGHT_KEY)?
            .ok_or_else(|| {
                Error::DBError("No block height found".to_string())
            })?;

        // If the CF is subspace, additionally update the diffs
        if persist_diffs && cf == &DbColFam::SUBSPACE {
            let diffs_cf = self.get_column_family(DIFFS_CF)?;
            let diffs_key = Key::from(last_height.to_db_key())
                .with_segment("new".to_owned())
                .join(key)
                .to_string();

            self.add_value_bytes_to_batch(
                diffs_cf,
                diffs_key,
                new_value.as_ref().to_vec(),
                batch,
            );
        }

        Ok(())
    }

    fn migrator() -> Self::Migrator {
        RocksDBUpdateVisitor::default()
    }

    fn update_last_block_merkle_tree(
        &self,
        merkle_tree_stores: namada_vp::state::MerkleTreeStoresWrite<'_>,
        is_full_commit: bool,
    ) -> Result<()> {
        let state_cf = self.get_column_family(STATE_CF)?;
        let block_cf = self.get_column_family(BLOCK_CF)?;

        // Read the last block's height
        let height: BlockHeight =
            self.read_value(state_cf, BLOCK_HEIGHT_KEY)?.unwrap();

        // Read the last block's epoch
        let prefix = height.raw();
        let epoch_key = format!("{prefix}/{EPOCH_KEY_SEGMENT}");
        let epoch = self.read_value(block_cf, epoch_key)?.unwrap();

        let mut batch = RocksDBWriteBatch::default();
        for st in StoreType::iter() {
            if st.is_stored_every_block() || is_full_commit {
                let key_prefix = if st.is_stored_every_block() {
                    tree_key_prefix_with_height(st, height)
                } else {
                    tree_key_prefix_with_epoch(st, epoch)
                };
                let root_key =
                    format!("{key_prefix}/{MERKLE_TREE_ROOT_KEY_SEGMENT}");
                self.add_value_to_batch(
                    block_cf,
                    root_key,
                    merkle_tree_stores.root(st),
                    &mut batch,
                );
                let store_key =
                    format!("{key_prefix}/{MERKLE_TREE_STORE_KEY_SEGMENT}");
                self.add_value_bytes_to_batch(
                    block_cf,
                    store_key,
                    merkle_tree_stores.store(st).encode(),
                    &mut batch,
                );
            }
        }
        self.exec_batch(batch)
    }
}

/// A struct that can visit a set of updates,
/// registering them all in the batch
#[derive(Default)]
pub struct RocksDBUpdateVisitor {
    batch: RocksDBWriteBatch,
}

impl DBUpdateVisitor for RocksDBUpdateVisitor {
    type DB = RocksDB;

    fn read(&self, db: &Self::DB, key: &Key, cf: &DbColFam) -> Option<Vec<u8>> {
        match cf {
            DbColFam::SUBSPACE => db
                .read_subspace_val(key)
                .expect("Failed to read from storage"),
            _ => {
                let cf_str = cf.to_str();
                let cf = db
                    .get_column_family(cf_str)
                    .expect("Failed to read column family from storage");
                db.read_value_bytes(cf, key.to_string())
                    .expect("Failed to get key from storage")
            }
        }
    }

    fn write(
        &mut self,
        db: &Self::DB,
        key: &Key,
        cf: &DbColFam,
        value: impl AsRef<[u8]>,
        persist_diffs: bool,
    ) {
        db.overwrite_entry(&mut self.batch, cf, key, value, persist_diffs)
            .expect("Failed to overwrite a key in storage")
    }

    fn delete(
        &mut self,
        db: &Self::DB,
        key: &Key,
        cf: &DbColFam,
        persist_diffs: bool,
    ) {
        let state_cf = db.get_column_family(STATE_CF).unwrap();
        let last_height: BlockHeight =
            db.read_value(state_cf, BLOCK_HEIGHT_KEY).unwrap().unwrap();
        match cf {
            DbColFam::SUBSPACE => {
                db.batch_delete_subspace_val(
                    &mut self.batch,
                    last_height,
                    key,
                    persist_diffs,
                )
                .expect("Failed to delete key from storage");
            }
            _ => {
                let cf_str = cf.to_str();
                let cf = db
                    .get_column_family(cf_str)
                    .expect("Failed to get read column family from storage");
                self.batch.0.delete_cf(cf, key.to_string());
            }
        };
    }

    fn get_pattern(
        &self,
        db: &Self::DB,
        pattern: Regex,
    ) -> Vec<(String, Vec<u8>)> {
        db.iter_pattern(None, pattern)
            .map(|(k, v, _)| (k, v))
            .collect()
    }

    fn commit(self, db: &Self::DB) -> Result<()> {
        db.exec_batch(self.batch)
    }
}

impl<'iter> DBIter<'iter> for RocksDB {
    type PatternIter = PersistentPatternIterator<'iter>;
    type PrefixIter = PersistentPrefixIterator<'iter>;

    fn iter_prefix(
        &'iter self,
        prefix: Option<&Key>,
    ) -> PersistentPrefixIterator<'iter> {
        iter_subspace_prefix(self, prefix)
    }

    fn iter_pattern(
        &'iter self,
        prefix: Option<&Key>,
        pattern: Regex,
    ) -> PersistentPatternIterator<'iter> {
        iter_subspace_pattern(self, prefix, pattern)
    }

    fn iter_results(&'iter self) -> PersistentPrefixIterator<'iter> {
        let db_prefix = "results/".to_owned();
        let prefix = "results".to_owned();

        let block_cf = self
            .get_column_family(BLOCK_CF)
            .expect("{BLOCK_CF} column family should exist");
        let read_opts = make_iter_read_opts(Some(prefix.clone()));
        let iter = self.inner.iterator_cf_opt(
            block_cf,
            read_opts,
            IteratorMode::From(prefix.as_bytes(), Direction::Forward),
        );
        PersistentPrefixIterator(PrefixIterator::new(iter, db_prefix))
    }

    fn iter_old_diffs(
        &'iter self,
        height: BlockHeight,
        prefix: Option<&'iter Key>,
    ) -> PersistentPrefixIterator<'iter> {
        let diffs_cf = self
            .get_column_family(DIFFS_CF)
            .expect("{DIFFS_CF} column family should exist");
        iter_diffs_prefix(self, diffs_cf, height, prefix, true)
    }

    fn iter_new_diffs(
        &'iter self,
        height: BlockHeight,
        prefix: Option<&'iter Key>,
    ) -> PersistentPrefixIterator<'iter> {
        let diffs_cf = self
            .get_column_family(DIFFS_CF)
            .expect("{DIFFS_CF} column family should exist");
        iter_diffs_prefix(self, diffs_cf, height, prefix, false)
    }

    fn iter_current_replay_protection(&'iter self) -> Self::PrefixIter {
        let replay_protection_cf = self
            .get_column_family(REPLAY_PROTECTION_CF)
            .expect("{REPLAY_PROTECTION_CF} column family should exist");

        let prefix = Some(replay_protection::current_prefix());
        iter_prefix(self, replay_protection_cf, None, prefix.as_ref())
    }
}

fn iter_subspace_prefix<'iter>(
    db: &'iter RocksDB,
    prefix: Option<&Key>,
) -> PersistentPrefixIterator<'iter> {
    let subspace_cf = db
        .get_column_family(SUBSPACE_CF)
        .expect("{SUBSPACE_CF} column family should exist");
    let stripped_prefix = None;
    iter_prefix(db, subspace_cf, stripped_prefix, prefix)
}

fn iter_subspace_pattern<'iter>(
    db: &'iter RocksDB,
    prefix: Option<&Key>,
    pattern: Regex,
) -> PersistentPatternIterator<'iter> {
    let subspace_cf = db
        .get_column_family(SUBSPACE_CF)
        .expect("{SUBSPACE_CF} column family should exist");
    let stripped_prefix = None;
    iter_pattern(db, subspace_cf, stripped_prefix, prefix, pattern)
}

fn iter_diffs_prefix<'a>(
    db: &'a RocksDB,
    cf: &'a ColumnFamily,
    height: BlockHeight,
    prefix: Option<&Key>,
    is_old: bool,
) -> PersistentPrefixIterator<'a> {
    let kind = if is_old {
        OLD_DIFF_PREFIX
    } else {
        NEW_DIFF_PREFIX
    };
    let stripped_prefix = Some(
        Key::from(height.to_db_key())
            .push(&kind.to_string())
            .unwrap(),
    );
    // get keys without the `stripped_prefix`
    iter_prefix(db, cf, stripped_prefix.as_ref(), prefix)
}

/// Create an iterator over key-vals in the given CF matching the given
/// prefix(es). If any, the `stripped_prefix` is matched first and will be
/// removed from the matched keys. If any, the second `prefix` is matched
/// against the stripped keys and remains in the matched keys.
fn iter_prefix<'a>(
    db: &'a RocksDB,
    cf: &'a ColumnFamily,
    stripped_prefix: Option<&Key>,
    prefix: Option<&Key>,
) -> PersistentPrefixIterator<'a> {
    let stripped_prefix = match stripped_prefix {
        Some(p) if !p.is_empty() => format!("{p}/"),
        _ => "".to_owned(),
    };
    let prefix = match prefix {
        Some(p) if !p.is_empty() => {
            format!("{stripped_prefix}{p}/")
        }
        _ => stripped_prefix.clone(),
    };
    let read_opts = make_iter_read_opts(Some(prefix.clone()));
    let iter = db.inner.iterator_cf_opt(
        cf,
        read_opts,
        IteratorMode::From(prefix.as_bytes(), Direction::Forward),
    );
    PersistentPrefixIterator(PrefixIterator::new(iter, stripped_prefix))
}

/// Create an iterator over key-vals in the given CF matching the given
/// pattern(s).
fn iter_pattern<'a>(
    db: &'a RocksDB,
    cf: &'a ColumnFamily,
    stripped_prefix: Option<&Key>,
    prefix: Option<&Key>,
    pattern: Regex,
) -> PersistentPatternIterator<'a> {
    PersistentPatternIterator {
        inner: PatternIterator {
            iter: iter_prefix(db, cf, stripped_prefix, prefix),
            pattern,
        },
    }
}

#[derive(Debug)]
pub struct PersistentPrefixIterator<'a>(
    PrefixIterator<rocksdb::DBIterator<'a>>,
);

impl Iterator for PersistentPrefixIterator<'_> {
    type Item = (String, Vec<u8>, Gas);

    /// Returns the next pair and the gas cost
    fn next(&mut self) -> Option<(String, Vec<u8>, Gas)> {
        loop {
            match self.0.iter.next() {
                Some(result) => {
                    let (key, val) =
                        result.expect("Prefix iterator shouldn't fail");
                    let key = String::from_utf8(key.to_vec())
                        .expect("Cannot convert from bytes to key string");
                    if let Some(k) = key.strip_prefix(&self.0.stripped_prefix) {
                        let gas = k.len().checked_add(val.len())?;
                        return Some((
                            k.to_owned(),
                            val.to_vec(),
                            (gas as u64).into(),
                        ));
                    } else {
                        tracing::warn!(
                            "Unmatched prefix \"{}\" in iterator's key \
                             \"{key}\"",
                            self.0.stripped_prefix
                        );
                    }
                }
                None => return None,
            }
        }
    }
}

#[derive(Debug)]
pub struct PersistentPatternIterator<'a> {
    inner: PatternIterator<PersistentPrefixIterator<'a>>,
}

impl Iterator for PersistentPatternIterator<'_> {
    type Item = (String, Vec<u8>, Gas);

    /// Returns the next pair and the gas cost
    fn next(&mut self) -> Option<(String, Vec<u8>, Gas)> {
        loop {
            let next_result = self.inner.iter.next()?;
            if self.inner.pattern.is_match(&next_result.0) {
                return Some(next_result);
            }
        }
    }
}

/// Make read options for RocksDB iterator with the given prefix
fn make_iter_read_opts(prefix: Option<String>) -> ReadOptions {
    let mut read_opts = ReadOptions::default();
    // don't use the prefix bloom filter
    read_opts.set_total_order_seek(true);

    if let Some(prefix) = prefix {
        let mut upper_prefix = prefix.into_bytes();
        if let Some(last) = upper_prefix.last_mut() {
            *last = last.checked_add(1).expect("cannot overflow");
            read_opts.set_iterate_upper_bound(upper_prefix);
        }
    }

    read_opts
}

impl DBWriteBatch for RocksDBWriteBatch {}

fn old_and_new_diff_key(
    key: &Key,
    height: BlockHeight,
) -> Result<(String, String)> {
    let key_prefix = Key::from(height.to_db_key());
    let old = key_prefix
        .push(&OLD_DIFF_PREFIX.to_owned())
        .map_err(Error::KeyError)?
        .join(key);
    let new = key_prefix
        .push(&NEW_DIFF_PREFIX.to_owned())
        .map_err(Error::KeyError)?
        .join(key);
    Ok((old.to_string(), new.to_string()))
}

/// Try to increase NOFILE limit and set the `max_open_files` limit to it in
/// RocksDB options.
fn set_max_open_files(cf_opts: &mut rocksdb::Options) {
    #[cfg(unix)]
    imp::set_max_open_files(cf_opts);
    // Nothing to do on non-unix
    #[cfg(not(unix))]
    let _ = cf_opts;
}

#[cfg(unix)]
mod imp {
    use rlimit::Resource;

    const DEFAULT_NOFILE_LIMIT: u64 = 16384;

    pub fn set_max_open_files(cf_opts: &mut rocksdb::Options) {
        let max_open_files = match increase_nofile_limit() {
            Ok(max_open_files) => Some(max_open_files),
            Err(err) => {
                tracing::error!("Failed to increase NOFILE limit: {}", err);
                None
            }
        };
        if let Some(max_open_files) =
            max_open_files.and_then(|max| max.try_into().ok())
        {
            cf_opts.set_max_open_files(max_open_files);
        }
    }

    /// Try to increase NOFILE limit and return the current soft limit.
    fn increase_nofile_limit() -> std::io::Result<u64> {
        let (soft, hard) = Resource::NOFILE.get()?;
        tracing::debug!("Current NOFILE limit, soft={}, hard={}", soft, hard);

        let target = std::cmp::min(DEFAULT_NOFILE_LIMIT, hard);
        if soft >= target {
            tracing::debug!(
                "NOFILE limit already large enough, not attempting to increase"
            );
            Ok(soft)
        } else {
            tracing::debug!("Try to increase to {}", target);
            Resource::NOFILE.set(target, target)?;

            let (soft, hard) = Resource::NOFILE.get()?;
            tracing::debug!(
                "Increased NOFILE limit, soft={}, hard={}",
                soft,
                hard
            );
            Ok(soft)
        }
    }
}

#[allow(clippy::arithmetic_side_effects)]
#[cfg(test)]
mod test {
    use namada_apps_lib::collections::HashMap;
    use namada_sdk::address::EstablishedAddressGen;
    use namada_sdk::state::{MerkleTree, Sha256Hasher};
    use namada_sdk::storage::conversion_state::ConversionState;
    use namada_sdk::storage::types::CommitOnlyData;
    use namada_sdk::storage::{BlockResults, Epochs, EthEventsQueue};
    use namada_sdk::time::DateTimeUtc;
    use tempfile::tempdir;

    use super::*;

    /// Test that a block written can be loaded back from DB.
    #[test]
    fn test_load_state() {
        let dir = tempdir().unwrap();
        let db = RocksDB::open(dir.path(), None);

        let mut batch = RocksDB::batch();
        let last_height = BlockHeight::default();
        db.batch_write_subspace_val(
            &mut batch,
            last_height,
            &Key::parse("test").unwrap(),
            vec![1_u8, 1, 1, 1],
            true,
        )
        .unwrap();

        add_block_to_batch(
            &db,
            &mut batch,
            BlockHeight::default(),
            Epoch::default(),
            Epochs::default(),
            &ConversionState::default(),
        )
        .unwrap();
        db.exec_batch(batch).unwrap();

        let _state = db
            .read_last_block()
            .expect("Should be able to read last block")
            .expect("Block should have been written");
    }

    #[test]
    fn test_read() {
        let dir = tempdir().unwrap();
        let mut db = RocksDB::open(dir.path(), None);

        let key = Key::parse("test").unwrap();
        let batch_key = Key::parse("batch").unwrap();

        let mut batch = RocksDB::batch();
        let last_height = BlockHeight(100);
        db.batch_write_subspace_val(
            &mut batch,
            last_height,
            &batch_key,
            vec![1_u8, 1, 1, 1],
            true,
        )
        .unwrap();
        db.exec_batch(batch).unwrap();

        db.write_subspace_val(last_height, &key, vec![1_u8, 1, 1, 0], true)
            .unwrap();

        let mut batch = RocksDB::batch();
        let last_height = BlockHeight(111);
        db.batch_write_subspace_val(
            &mut batch,
            last_height,
            &batch_key,
            vec![2_u8, 2, 2, 2],
            true,
        )
        .unwrap();
        db.exec_batch(batch).unwrap();

        db.write_subspace_val(last_height, &key, vec![2_u8, 2, 2, 0], true)
            .unwrap();

        let prev_value = db
            .read_subspace_val_with_height(
                &batch_key,
                BlockHeight(100),
                last_height,
            )
            .expect("read should succeed");
        assert_eq!(prev_value, Some(vec![1_u8, 1, 1, 1]));
        let prev_value = db
            .read_subspace_val_with_height(&key, BlockHeight(100), last_height)
            .expect("read should succeed");
        assert_eq!(prev_value, Some(vec![1_u8, 1, 1, 0]));

        let updated_value = db
            .read_subspace_val_with_height(
                &batch_key,
                BlockHeight(111),
                last_height,
            )
            .expect("read should succeed");
        assert_eq!(updated_value, Some(vec![2_u8, 2, 2, 2]));
        let updated_value = db
            .read_subspace_val_with_height(&key, BlockHeight(111), last_height)
            .expect("read should succeed");
        assert_eq!(updated_value, Some(vec![2_u8, 2, 2, 0]));

        let latest_value = db
            .read_subspace_val(&batch_key)
            .expect("read should succeed");
        assert_eq!(latest_value, Some(vec![2_u8, 2, 2, 2]));
        let latest_value =
            db.read_subspace_val(&key).expect("read should succeed");
        assert_eq!(latest_value, Some(vec![2_u8, 2, 2, 0]));

        let mut batch = RocksDB::batch();
        let last_height = BlockHeight(222);
        db.batch_delete_subspace_val(&mut batch, last_height, &batch_key, true)
            .unwrap();
        db.exec_batch(batch).unwrap();

        db.delete_subspace_val(last_height, &key, true).unwrap();

        let deleted_value = db
            .read_subspace_val_with_height(
                &batch_key,
                BlockHeight(222),
                last_height,
            )
            .expect("read should succeed");
        assert_eq!(deleted_value, None);
        let deleted_value = db
            .read_subspace_val_with_height(&key, BlockHeight(222), last_height)
            .expect("read should succeed");
        assert_eq!(deleted_value, None);

        let latest_value = db
            .read_subspace_val(&batch_key)
            .expect("read should succeed");
        assert_eq!(latest_value, None);
        let latest_value =
            db.read_subspace_val(&key).expect("read should succeed");
        assert_eq!(latest_value, None);
    }

    #[test]
    fn test_prefix_iter() {
        let dir = tempdir().unwrap();
        let db = RocksDB::open(dir.path(), None);

        let prefix_0 = Key::parse("0").unwrap();
        let key_0_a = prefix_0.push(&"a".to_string()).unwrap();
        let key_0_b = prefix_0.push(&"b".to_string()).unwrap();
        let key_0_c = prefix_0.push(&"c".to_string()).unwrap();
        let prefix_1 = Key::parse("1").unwrap();
        let key_1_a = prefix_1.push(&"a".to_string()).unwrap();
        let key_1_b = prefix_1.push(&"b".to_string()).unwrap();
        let key_1_c = prefix_1.push(&"c".to_string()).unwrap();
        let prefix_01 = Key::parse("01").unwrap();
        let key_01_a = prefix_01.push(&"a".to_string()).unwrap();

        let keys_0 = vec![key_0_a, key_0_b, key_0_c];
        let keys_1 = vec![key_1_a, key_1_b, key_1_c];
        let keys_01 = vec![key_01_a];
        let all_keys = [keys_0.clone(), keys_01, keys_1.clone()].concat();

        // Write the keys
        let mut batch = RocksDB::batch();
        let height = BlockHeight(1);
        for key in &all_keys {
            db.batch_write_subspace_val(&mut batch, height, key, [0_u8], true)
                .unwrap();
        }
        db.exec_batch(batch).unwrap();

        // Prefix "0" shouldn't match prefix "01"
        let itered_keys: Vec<Key> = db
            .iter_prefix(Some(&prefix_0))
            .map(|(key, _val, _)| Key::parse(key).unwrap())
            .collect();
        itertools::assert_equal(keys_0, itered_keys);

        let itered_keys: Vec<Key> = db
            .iter_prefix(Some(&prefix_1))
            .map(|(key, _val, _)| Key::parse(key).unwrap())
            .collect();
        itertools::assert_equal(keys_1, itered_keys);

        let itered_keys: Vec<Key> = db
            .iter_prefix(None)
            .map(|(key, _val, _)| Key::parse(key).unwrap())
            .collect();
        itertools::assert_equal(all_keys, itered_keys);
    }

    #[test]
    fn test_rollback() {
        for persist_diffs in [true, false] {
            println!("Running with persist_diffs: {persist_diffs}");

            let dir = tempdir().unwrap();
            let mut db = RocksDB::open(dir.path(), None);

            // A key that's gonna be added on a second block
            let add_key = Key::parse("add").unwrap();
            // A key that's gonna be deleted on a second block
            let delete_key = Key::parse("delete").unwrap();
            // A key that's gonna be overwritten on a second block
            let overwrite_key = Key::parse("overwrite").unwrap();

            // Write first block
            let mut batch = RocksDB::batch();
            let height_0 = BlockHeight(100);
            let mut pred_epochs = Epochs::default();
            pred_epochs.new_epoch(height_0);
            let conversion_state_0 = ConversionState::default();
            let to_delete_val = vec![1_u8, 1, 0, 0];
            let to_overwrite_val = vec![1_u8, 1, 1, 0];
            db.batch_write_subspace_val(
                &mut batch,
                height_0,
                &delete_key,
                &to_delete_val,
                persist_diffs,
            )
            .unwrap();
            db.batch_write_subspace_val(
                &mut batch,
                height_0,
                &overwrite_key,
                &to_overwrite_val,
                persist_diffs,
            )
            .unwrap();
            for tx in [b"tx1", b"tx2"] {
                db.write_replay_protection_entry(
                    &mut batch,
                    &replay_protection::key(&Hash::sha256(tx)),
                )
                .unwrap();
            }

            for tx in [b"tx3", b"tx4"] {
                db.write_replay_protection_entry(
                    &mut batch,
                    &replay_protection::current_key(&Hash::sha256(tx)),
                )
                .unwrap();
            }

            add_block_to_batch(
                &db,
                &mut batch,
                height_0,
                Epoch(1),
                pred_epochs.clone(),
                &conversion_state_0,
            )
            .unwrap();
            db.exec_batch(batch).unwrap();

            // Write second block
            let mut batch = RocksDB::batch();
            let height_1 = BlockHeight(101);
            pred_epochs.new_epoch(height_1);
            let conversion_state_1 = ConversionState::default();
            let add_val = vec![1_u8, 0, 0, 0];
            let overwrite_val = vec![1_u8, 1, 1, 1];
            db.batch_write_subspace_val(
                &mut batch,
                height_1,
                &add_key,
                &add_val,
                persist_diffs,
            )
            .unwrap();
            db.batch_write_subspace_val(
                &mut batch,
                height_1,
                &overwrite_key,
                &overwrite_val,
                persist_diffs,
            )
            .unwrap();
            db.batch_delete_subspace_val(
                &mut batch,
                height_1,
                &delete_key,
                persist_diffs,
            )
            .unwrap();

            db.move_current_replay_protection_entries(&mut batch)
                .unwrap();

            for tx in [b"tx5", b"tx6"] {
                db.write_replay_protection_entry(
                    &mut batch,
                    &replay_protection::current_key(&Hash::sha256(tx)),
                )
                .unwrap();
            }

            add_block_to_batch(
                &db,
                &mut batch,
                height_1,
                Epoch(2),
                pred_epochs,
                &conversion_state_1,
            )
            .unwrap();
            db.exec_batch(batch).unwrap();

            // Check that the values are as expected from second block
            let added = db.read_subspace_val(&add_key).unwrap();
            assert_eq!(added, Some(add_val));
            let overwritten = db.read_subspace_val(&overwrite_key).unwrap();
            assert_eq!(overwritten, Some(overwrite_val));
            let deleted = db.read_subspace_val(&delete_key).unwrap();
            assert_eq!(deleted, None);

            for tx in [b"tx1", b"tx2", b"tx3", b"tx4", b"tx5", b"tx6"] {
                assert!(
                    db.has_replay_protection_entry(&Hash::sha256(tx)).unwrap()
                );
            }

            // Rollback to the first block height
            db.rollback(height_0).unwrap();

            // Check that the values are back to the state at the first block
            let added = db.read_subspace_val(&add_key).unwrap();
            assert_eq!(added, None);
            let overwritten = db.read_subspace_val(&overwrite_key).unwrap();
            assert_eq!(overwritten, Some(to_overwrite_val));
            let deleted = db.read_subspace_val(&delete_key).unwrap();
            assert_eq!(deleted, Some(to_delete_val));
            // Check the conversion state
            let state_cf = db.get_column_family(STATE_CF).unwrap();
            let conversion_state = db
                .inner
                .get_cf(state_cf, "conversion_state".as_bytes())
                .unwrap()
                .unwrap();
            assert_eq!(conversion_state, encode(&conversion_state_0));
            for tx in [b"tx1", b"tx2", b"tx3", b"tx4"] {
                assert!(
                    db.has_replay_protection_entry(&Hash::sha256(tx)).unwrap()
                );
            }

            for tx in [b"tx5", b"tx6"] {
                assert!(
                    !db.has_replay_protection_entry(&Hash::sha256(tx)).unwrap()
                );
            }
        }
    }

    #[test]
    fn test_diffs() {
        let dir = tempdir().unwrap();
        let mut db = RocksDB::open(dir.path(), None);

        let key_with_diffs = Key::parse("with_diffs").unwrap();
        let key_without_diffs = Key::parse("without_diffs").unwrap();

        let initial_val = vec![1_u8, 1, 0, 0];
        let overwrite_val = vec![1_u8, 1, 1, 0];

        // Write first block
        let mut batch = RocksDB::batch();
        let height_0 = BlockHeight::first();
        db.batch_write_subspace_val(
            &mut batch,
            height_0,
            &key_with_diffs,
            &initial_val,
            true,
        )
        .unwrap();
        db.batch_write_subspace_val(
            &mut batch,
            height_0,
            &key_without_diffs,
            &initial_val,
            false,
        )
        .unwrap();
        db.exec_batch(batch).unwrap();

        {
            let diffs_cf = db.get_column_family(DIFFS_CF).unwrap();
            let rollback_cf = db.get_column_family(ROLLBACK_CF).unwrap();

            // Diffs new key for `key_with_diffs` at height_0 must be
            // present
            let (old_with_h0, new_with_h0) =
                old_and_new_diff_key(&key_with_diffs, height_0).unwrap();
            assert!(db.inner.get_cf(diffs_cf, old_with_h0).unwrap().is_none());
            assert!(db.inner.get_cf(diffs_cf, new_with_h0).unwrap().is_some());

            // Diffs new key for `key_without_diffs` at height_0 must be
            // present
            let (old_wo_h0, new_wo_h0) =
                old_and_new_diff_key(&key_without_diffs, height_0).unwrap();
            assert!(db.inner.get_cf(rollback_cf, old_wo_h0).unwrap().is_none());
            assert!(db.inner.get_cf(rollback_cf, new_wo_h0).unwrap().is_some());
        }

        // Write second block
        let mut batch = RocksDB::batch();
        let height_1 = height_0 + 10u64;
        db.batch_write_subspace_val(
            &mut batch,
            height_1,
            &key_with_diffs,
            &overwrite_val,
            true,
        )
        .unwrap();
        db.batch_write_subspace_val(
            &mut batch,
            height_1,
            &key_without_diffs,
            &overwrite_val,
            false,
        )
        .unwrap();
        db.prune_non_persisted_diffs(&mut batch, height_0).unwrap();
        db.exec_batch(batch).unwrap();

        {
            let diffs_cf = db.get_column_family(DIFFS_CF).unwrap();
            let rollback_cf = db.get_column_family(ROLLBACK_CF).unwrap();

            // Diffs keys for `key_with_diffs` at height_0 must be present
            let (old_with_h0, new_with_h0) =
                old_and_new_diff_key(&key_with_diffs, height_0).unwrap();
            assert!(db.inner.get_cf(diffs_cf, old_with_h0).unwrap().is_none());
            assert!(db.inner.get_cf(diffs_cf, new_with_h0).unwrap().is_some());

            // Diffs keys for `key_without_diffs` at height_0 must be gone
            let (old_wo_h0, new_wo_h0) =
                old_and_new_diff_key(&key_without_diffs, height_0).unwrap();
            assert!(db.inner.get_cf(rollback_cf, old_wo_h0).unwrap().is_none());
            assert!(db.inner.get_cf(rollback_cf, new_wo_h0).unwrap().is_none());

            // Diffs keys for `key_with_diffs` at height_1 must be present
            let (old_with_h1, new_with_h1) =
                old_and_new_diff_key(&key_with_diffs, height_1).unwrap();
            assert!(db.inner.get_cf(diffs_cf, old_with_h1).unwrap().is_some());
            assert!(db.inner.get_cf(diffs_cf, new_with_h1).unwrap().is_some());

            // Diffs keys for `key_without_diffs` at height_1 must be
            // present
            let (old_wo_h1, new_wo_h1) =
                old_and_new_diff_key(&key_without_diffs, height_1).unwrap();
            assert!(db.inner.get_cf(rollback_cf, old_wo_h1).unwrap().is_some());
            assert!(db.inner.get_cf(rollback_cf, new_wo_h1).unwrap().is_some());
        }

        // Write third block
        let mut batch = RocksDB::batch();
        let height_2 = height_1 + 10;
        db.batch_write_subspace_val(
            &mut batch,
            height_2,
            &key_with_diffs,
            &initial_val,
            true,
        )
        .unwrap();
        db.batch_write_subspace_val(
            &mut batch,
            height_2,
            &key_without_diffs,
            &initial_val,
            false,
        )
        .unwrap();
        db.prune_non_persisted_diffs(&mut batch, height_1).unwrap();
        db.exec_batch(batch).unwrap();

        {
            let diffs_cf = db.get_column_family(DIFFS_CF).unwrap();
            let rollback_cf = db.get_column_family(ROLLBACK_CF).unwrap();

            // Diffs keys for `key_with_diffs` at height_1 must be present
            let (old_with_h1, new_with_h1) =
                old_and_new_diff_key(&key_with_diffs, height_1).unwrap();
            assert!(db.inner.get_cf(diffs_cf, old_with_h1).unwrap().is_some());
            assert!(db.inner.get_cf(diffs_cf, new_with_h1).unwrap().is_some());

            // Diffs keys for `key_without_diffs` at height_1 must be gone
            let (old_wo_h1, new_wo_h1) =
                old_and_new_diff_key(&key_without_diffs, height_1).unwrap();
            assert!(db.inner.get_cf(rollback_cf, old_wo_h1).unwrap().is_none());
            assert!(db.inner.get_cf(rollback_cf, new_wo_h1).unwrap().is_none());

            // Diffs keys for `key_with_diffs` at height_2 must be present
            let (old_with_h2, new_with_h2) =
                old_and_new_diff_key(&key_with_diffs, height_2).unwrap();
            assert!(db.inner.get_cf(diffs_cf, old_with_h2).unwrap().is_some());
            assert!(db.inner.get_cf(diffs_cf, new_with_h2).unwrap().is_some());

            // Diffs keys for `key_without_diffs` at height_2 must be
            // present
            let (old_wo_h2, new_wo_h2) =
                old_and_new_diff_key(&key_without_diffs, height_2).unwrap();
            assert!(db.inner.get_cf(rollback_cf, old_wo_h2).unwrap().is_some());
            assert!(db.inner.get_cf(rollback_cf, new_wo_h2).unwrap().is_some());
        }
    }

    /// A test helper to write a block
    fn add_block_to_batch(
        db: &RocksDB,
        batch: &mut RocksDBWriteBatch,
        height: BlockHeight,
        epoch: Epoch,
        pred_epochs: Epochs,
        conversion_state: &ConversionState,
    ) -> Result<()> {
        let merkle_tree = MerkleTree::<Sha256Hasher>::default();
        let merkle_tree_stores = merkle_tree.stores();
        #[allow(clippy::disallowed_methods)]
        let time = DateTimeUtc::now();
        let next_epoch_min_start_height = BlockHeight::default();
        #[allow(clippy::disallowed_methods)]
        let next_epoch_min_start_time = DateTimeUtc::now();
        let update_epoch_blocks_delay = None;
        let address_gen = EstablishedAddressGen::new("whatever");
        let results = BlockResults::default();
        let eth_events_queue = EthEventsQueue::default();
        let commit_only_data = CommitOnlyData::default();
        let block = BlockStateWrite {
            merkle_tree_stores,
            header: None,
            height,
            time,
            epoch,
            results: &results,
            conversion_state,
            pred_epochs: &pred_epochs,
            next_epoch_min_start_height,
            next_epoch_min_start_time,
            update_epoch_blocks_delay,
            address_gen: &address_gen,
            ethereum_height: None,
            eth_events_queue: &eth_events_queue,
            commit_only_data: &commit_only_data,
        };

        db.add_block_to_batch(block, batch, true)
    }

    /// Test that we chunk a file into
    /// pieces respecting the max chunk size.
    #[test]
    fn test_chunking() {
        let temp = tempfile::tempdir().expect("Test failed");
        let base_dir = temp.path().to_path_buf();

        let snap_path = SnapshotPath(base_dir, BlockHeight::first());
        let snapshot_base = snap_path.base().clone();
        std::fs::create_dir_all(&snapshot_base).expect("Test failed");
        let snapshot = DbSnapshot(snap_path);

        let tar = snapshot.0.temp_tarball("zst");
        std::fs::write(tar, vec![16; 21]).expect("Test failed");
        snapshot.chunk_snapshot(10).unwrap();
        let mut file_number = 0;
        for entry in std::fs::read_dir(snapshot_base).expect("Test failed") {
            let entry = entry.expect("Test failed");
            file_number += 1;
            if entry.path().is_file() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let Some(("chunk", chunk_nbr)) = name.split_once('-') else {
                    continue;
                };
                let chunk_nbr = u64::from_str(chunk_nbr).expect("Test failed");
                match chunk_nbr {
                    0 | 1 => assert_eq!(
                        entry.metadata().expect("Test failed").len(),
                        10
                    ),
                    2 => assert_eq!(
                        entry.metadata().expect("Test failed").len(),
                        1
                    ),
                    _ => panic!("Snapshot too chunky"),
                }
            } else {
                panic!("Found unexpected dir in snapshots")
            }
        }
        assert_eq!(file_number, 5)
    }

    /// Test that we correctly delete snapshots
    /// older than a given block height
    #[test]
    fn test_snapshot_cleanup() {
        let temp = tempfile::tempdir().expect("Test failed");
        let base_dir = temp.path().to_path_buf();
        for height in 1..4 {
            let snap_path = SnapshotPath(base_dir.clone(), height.into());
            let snapshot_base = snap_path.base().clone();
            std::fs::create_dir_all(&snapshot_base).expect("Test failed");
        }

        std::fs::write(base_dir.join("big.chungus"), "howdy".as_bytes())
            .expect("Test failed");
        DbSnapshot::cleanup(3.into(), &base_dir, 2).unwrap();
        // Big Chungus lives!!!
        assert_eq!(
            std::fs::read_to_string(base_dir.join("big.chungus"))
                .expect("Test failed"),
            "howdy"
        );

        let heights = {
            let mut h = DbSnapshot::heights_of_stored_snapshots(&base_dir)
                .expect("Test failed");
            h.sort();
            h
        };
        assert_eq!(heights, vec![2, 3]);
    }

    /// Test that taking a snapshot actually
    /// freezes the database in time even if
    /// it is written to.
    #[test]
    fn test_snapshot_creation() {
        let temp = tempfile::tempdir().expect("Test failed");
        let mut db = open(&temp, false, None).expect("Test failed");
        db.write_subspace_val(
            1.into(),
            &Key::parse("bing/fucking/bong").expect("Test failed"),
            [1u8; 64],
            false,
        )
        .expect("Test failed");
        // we need to persist the changes and restart in read-only mode
        // as rocksdb doesn't allow multiple read/write instances
        drop(db);
        let db = open(&temp, true, None).expect("Test failed");
        // freeze the database at this point in time
        let snapshot = db
            .checkpoint(temp.path().to_path_buf(), BlockHeight::first())
            .expect("Test failed");
        let db =
            open(snapshot.0.temp_rocksdb(), true, None).expect("Test failed");

        // write a new entry to the db
        let mut db2 = open(&temp, false, None).expect("Test failed");
        db2.write_subspace_val(
            2.into(),
            &Key::parse("I/AM/BATMAN").expect("Test failed"),
            [2u8; 32],
            false,
        )
        .expect("Test failed");
        // flush the data
        drop(db2);
        let db2 = open(&temp, false, None).expect("Test failed");

        // collect all entries in the snapshot
        let mut snapshot_entries = HashMap::new();
        for (_, cf) in db.column_families() {
            let read_opts = make_iter_read_opts(None);
            let iter =
                db.inner.iterator_cf_opt(cf, read_opts, IteratorMode::Start);

            for (key, raw_val, _gas) in PersistentPrefixIterator(
                PrefixIterator::new(iter, String::default()),
                // Empty string to prevent prefix stripping, the prefix is
                // already in the enclosed iterator
            ) {
                snapshot_entries.insert(key, raw_val);
            }
        }

        // collect ALL entries in the db
        let mut db_entries = HashMap::new();
        for (_, cf) in db2.column_families() {
            let read_opts = make_iter_read_opts(None);
            let iter =
                db2.inner
                    .iterator_cf_opt(cf, read_opts, IteratorMode::Start);

            for (key, raw_val, _gas) in PersistentPrefixIterator(
                PrefixIterator::new(iter, String::default()),
                // Empty string to prevent prefix stripping, the prefix is
                // already in the enclosed iterator
            ) {
                db_entries.insert(key, raw_val);
            }
        }

        let expected_snap = HashMap::from([
            ("bing/fucking/bong".to_string(), vec![1u8; 64]),
            (
                "0000000000002/new/bing/fucking/bong".to_string(),
                vec![1u8; 64],
            ),
        ]);
        assert_eq!(expected_snap, snapshot_entries);
        let expected_db = HashMap::from([
            ("bing/fucking/bong".to_string(), vec![1u8; 64]),
            (
                "0000000000002/new/bing/fucking/bong".to_string(),
                vec![1u8; 64],
            ),
            ("I/AM/BATMAN".to_string(), vec![2u8; 32]),
            ("0000000000004/new/I/AM/BATMAN".to_string(), vec![2u8; 32]),
        ]);
        assert_eq!(expected_db, db_entries);
    }
}
