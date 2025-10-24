//! DB mock for testing

#![allow(clippy::cast_possible_wrap, clippy::arithmetic_side_effects)]

use std::cell::RefCell;
use std::collections::{BTreeMap, btree_map};
use std::path::Path;

use itertools::Either;
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::chain::{BlockHeader, BlockHeight, Epoch};
use namada_core::hash::Hash;
use namada_core::storage::{DbColFam, KEY_SEGMENT_SEPARATOR, Key, KeySeg};
use namada_core::{decode, encode};
use namada_gas::Gas;
use namada_merkle_tree::{
    MerkleTreeStoresRead, MerkleTreeStoresWrite, StoreType,
    tree_key_prefix_with_epoch, tree_key_prefix_with_height,
};
use namada_replay_protection as replay_protection;
use regex::Regex;

use crate::DBUpdateVisitor;
use crate::db::{
    BlockStateRead, BlockStateWrite, DB, DBIter, DBWriteBatch, Error, Result,
};
use crate::types::{KVBytes, PatternIterator, PrefixIterator};

const SUBSPACE_CF: &str = "subspace";

const BLOCK_HEIGHT_KEY: &str = "height";
const NEXT_EPOCH_MIN_START_HEIGHT_KEY: &str = "next_epoch_min_start_height";
const NEXT_EPOCH_MIN_START_TIME_KEY: &str = "next_epoch_min_start_time";
const UPDATE_EPOCH_BLOCKS_DELAY_KEY: &str = "update_epoch_blocks_delay";
const COMMIT_ONLY_DATA_KEY: &str = "commit_only_data_commitment";
const CONVERSION_STATE_KEY: &str = "conversion_state";
const RESULTS_KEY_PREFIX: &str = "results";

const MERKLE_TREE_ROOT_KEY_SEGMENT: &str = "root";
const MERKLE_TREE_STORE_KEY_SEGMENT: &str = "store";
const BLOCK_HEADER_KEY_SEGMENT: &str = "header";
const BLOCK_TIME_KEY_SEGMENT: &str = "time";
const EPOCH_KEY_SEGMENT: &str = "epoch";
const PRED_EPOCHS_KEY_SEGMENT: &str = "pred_epochs";
const ADDRESS_GEN_KEY_SEGMENT: &str = "address_gen";

const OLD_DIFF_PREFIX: &str = "old";
const NEW_DIFF_PREFIX: &str = "new";

/// An in-memory DB for testing.
#[derive(Debug, Default)]
pub struct MockDB(
    // The state is wrapped in `RefCell` to allow modifying it directly from
    // batch write method (which requires immutable self ref).
    RefCell<BTreeMap<String, Vec<u8>>>,
);

// The `MockDB` is not `Sync`, but we're sharing it across threads for reading
// only (for parallelized VP runs). In a different context, this may not be
// safe.
unsafe impl Sync for MockDB {}

/// An in-memory write batch is not needed as it just updates values in memory.
/// It's here to satisfy the storage interface.
#[derive(Debug, Default)]
pub struct MockDBWriteBatch;

impl MockDB {
    fn read_value<T>(&self, key: impl AsRef<str>) -> Result<Option<T>>
    where
        T: BorshDeserialize,
    {
        self.0
            .borrow()
            .get(key.as_ref())
            .map(|bytes| decode(bytes).map_err(Error::CodingError))
            .transpose()
    }

    fn write_value<T>(&self, key: impl AsRef<str>, value: &T)
    where
        T: BorshSerialize,
    {
        self.0
            .borrow_mut()
            .insert(key.as_ref().to_string(), encode(value));
    }
}

/// Source to restore a [`MockDB`] from.
///
/// Since this enum has no variants, you can't
/// actually restore a [`MockDB`] instance.
pub enum MockDBRestoreSource {}

impl DB for MockDB {
    /// There is no cache for MockDB
    type Cache = ();
    type Migrator = ();
    type RestoreSource<'a> = MockDBRestoreSource;
    type WriteBatch = MockDBWriteBatch;

    fn open(_db_path: impl AsRef<Path>, _cache: Option<&Self::Cache>) -> Self {
        Self::default()
    }

    fn open_read_only(
        _db_path: impl AsRef<Path>,
        _cache: Option<&Self::Cache>,
    ) -> Self {
        Self::default()
    }

    fn restore_from(&mut self, source: MockDBRestoreSource) -> Result<()> {
        match source {}
    }

    fn flush(&self, _wait: bool) -> Result<()> {
        Ok(())
    }

    fn read_last_block(&self) -> Result<Option<BlockStateRead>> {
        // Block height
        let height: BlockHeight = match self.read_value(BLOCK_HEIGHT_KEY)? {
            Some(h) => h,
            None => return Ok(None),
        };

        // Epoch start height and time
        let next_epoch_min_start_height =
            match self.read_value(NEXT_EPOCH_MIN_START_HEIGHT_KEY)? {
                Some(h) => h,
                None => return Ok(None),
            };
        let next_epoch_min_start_time =
            match self.read_value(NEXT_EPOCH_MIN_START_TIME_KEY)? {
                Some(t) => t,
                None => return Ok(None),
            };
        let update_epoch_blocks_delay =
            match self.read_value(UPDATE_EPOCH_BLOCKS_DELAY_KEY)? {
                Some(d) => d,
                None => return Ok(None),
            };
        let commit_only_data = match self.read_value(COMMIT_ONLY_DATA_KEY)? {
            Some(d) => d,
            None => return Ok(None),
        };
        let conversion_state = match self.read_value(CONVERSION_STATE_KEY)? {
            Some(c) => c,
            None => return Ok(None),
        };

        // Block results
        let results_key = format!("{RESULTS_KEY_PREFIX}/{}", height.raw());
        let results = match self.read_value(results_key)? {
            Some(r) => r,
            None => return Ok(None),
        };

        let prefix = height.raw();

        let time_key = format!("{prefix}/{BLOCK_TIME_KEY_SEGMENT}");
        let time = match self.read_value(time_key)? {
            Some(t) => t,
            None => return Ok(None),
        };

        let epoch_key = format!("{prefix}/{EPOCH_KEY_SEGMENT}");
        let epoch = match self.read_value(epoch_key)? {
            Some(e) => e,
            None => return Ok(None),
        };

        let pred_epochs_key = format!("{prefix}/{PRED_EPOCHS_KEY_SEGMENT}");
        let pred_epochs = match self.read_value(pred_epochs_key)? {
            Some(e) => e,
            None => return Ok(None),
        };

        let address_gen_key = format!("{prefix}/{ADDRESS_GEN_KEY_SEGMENT}");
        let address_gen = match self.read_value(address_gen_key)? {
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
            commit_only_data,
        }))
    }

    fn add_block_to_batch(
        &self,
        state: BlockStateWrite<'_>,
        _batch: &mut Self::WriteBatch,
        is_full_commit: bool,
    ) -> Result<()> {
        let BlockStateWrite {
            merkle_tree_stores,
            header,
            time,
            height,
            epoch,
            pred_epochs,
            next_epoch_min_start_height,
            next_epoch_min_start_time,
            update_epoch_blocks_delay,
            address_gen,
            results,
            conversion_state,
            commit_only_data,
        }: BlockStateWrite<'_> = state;

        self.write_value(
            NEXT_EPOCH_MIN_START_HEIGHT_KEY,
            &next_epoch_min_start_height,
        );
        self.write_value(
            NEXT_EPOCH_MIN_START_TIME_KEY,
            &next_epoch_min_start_time,
        );
        self.write_value(
            UPDATE_EPOCH_BLOCKS_DELAY_KEY,
            &update_epoch_blocks_delay,
        );
        self.write_value(CONVERSION_STATE_KEY, &conversion_state);
        self.write_value(COMMIT_ONLY_DATA_KEY, &commit_only_data);

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
                self.write_value(root_key, merkle_tree_stores.root(st));
                let store_key =
                    format!("{key_prefix}/{MERKLE_TREE_STORE_KEY_SEGMENT}");
                self.0
                    .borrow_mut()
                    .insert(store_key, merkle_tree_stores.store(st).encode());
            }
        }
        // Block header
        if let Some(h) = header {
            let header_key = format!("{prefix}/{BLOCK_HEADER_KEY_SEGMENT}");
            self.write_value(header_key, &h);
        }
        // Block time
        let time_key = format!("{prefix}/{BLOCK_TIME_KEY_SEGMENT}");
        self.write_value(time_key, &time);
        // Block epoch
        let epoch_key = format!("{prefix}/{EPOCH_KEY_SEGMENT}");
        self.write_value(epoch_key, &epoch);
        // Block results
        let results_key = format!("{RESULTS_KEY_PREFIX}/{}", height.raw());
        self.write_value(results_key, &results);
        // Predecessor block epochs
        let pred_epochs_key = format!("{prefix}/{PRED_EPOCHS_KEY_SEGMENT}");
        self.write_value(pred_epochs_key, &pred_epochs);
        // Address gen
        let address_gen_key = format!("{prefix}/{ADDRESS_GEN_KEY_SEGMENT}");
        self.write_value(address_gen_key, &address_gen);

        // Block height
        self.write_value(BLOCK_HEIGHT_KEY, &height);

        Ok(())
    }

    fn read_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>> {
        let header_key = format!("{}/{BLOCK_HEADER_KEY_SEGMENT}", height.raw());
        self.read_value(header_key)
    }

    fn read_merkle_tree_stores(
        &self,
        epoch: Epoch,
        base_height: BlockHeight,
        store_type: Option<StoreType>,
    ) -> Result<Option<MerkleTreeStoresRead>> {
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
            match self.read_value(root_key)? {
                Some(root) => merkle_tree_stores.set_root(st, root),
                None if store_type.is_some() => return Ok(None),
                _ => continue,
            }
            let store_key =
                format!("{key_prefix}/{MERKLE_TREE_STORE_KEY_SEGMENT}");
            let bytes = self.0.borrow().get(&store_key.to_string()).cloned();
            match bytes {
                Some(b) => merkle_tree_stores.set_store(st.decode_store(b)?),
                None if store_type.is_some() => return Ok(None),
                _ => continue,
            }
        }
        Ok(Some(merkle_tree_stores))
    }

    fn has_replay_protection_entry(&self, hash: &Hash) -> Result<bool> {
        let prefix_key =
            Key::parse("replay_protection").map_err(Error::KeyError)?;
        let key = prefix_key.join(&replay_protection::key(hash));
        let current_key =
            prefix_key.join(&replay_protection::current_key(hash));
        if self.0.borrow().contains_key(&key.to_string())
            || self.0.borrow().contains_key(&current_key.to_string())
        {
            return Ok(true);
        }

        Ok(false)
    }

    fn read_diffs_val(
        &self,
        key: &Key,
        height: BlockHeight,
        is_old: bool,
    ) -> Result<Option<Vec<u8>>> {
        let old_new_seg = if is_old {
            OLD_DIFF_PREFIX
        } else {
            NEW_DIFF_PREFIX
        };

        let prefix = Key::from(height.to_db_key())
            .push(&old_new_seg.to_string().to_db_key())
            .map_err(Error::KeyError)?
            .join(key);

        Ok(self.0.borrow().get(&prefix.to_string()).cloned())
    }

    fn read_subspace_val(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        let key = Key::parse(SUBSPACE_CF).map_err(Error::KeyError)?.join(key);
        Ok(self.0.borrow().get(&key.to_string()).cloned())
    }

    fn read_subspace_val_with_height(
        &self,
        key: &Key,
        height: BlockHeight,
        last_height: BlockHeight,
    ) -> Result<Option<Vec<u8>>> {
        if height == last_height {
            self.read_subspace_val(key)
        } else {
            // Quick-n-dirty implementation for reading subspace value at
            // height:
            // - See if there are any diffs between height+1..last_height.
            // - If so, the first one will provide the value we want as its old
            //   value.
            // - If not, we can just read the value at the latest height.
            for h in (height.0 + 1)..=last_height.0 {
                let old_diff = self.read_diffs_val(key, h.into(), true)?;
                let new_diff = self.read_diffs_val(key, h.into(), false)?;

                match (old_diff, new_diff) {
                    (Some(old_diff), Some(_)) | (Some(old_diff), None) => {
                        // If there is an old diff, it contains the value at the
                        // requested height.
                        return Ok(Some(old_diff));
                    }
                    (None, Some(_)) => {
                        // If there is a new diff but no old diff, there was
                        // no value at the requested height.
                        return Ok(None);
                    }
                    (None, None) => {
                        // If there are no diffs, keep looking.
                        continue;
                    }
                }
            }

            self.read_subspace_val(key)
        }
    }

    fn write_subspace_val(
        &mut self,
        height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
        persist_diffs: bool,
    ) -> Result<i64> {
        // batch_write are directly committed
        self.batch_write_subspace_val(
            &mut MockDBWriteBatch,
            height,
            key,
            value,
            persist_diffs,
        )
    }

    fn delete_subspace_val(
        &mut self,
        height: BlockHeight,
        key: &Key,
        persist_diffs: bool,
    ) -> Result<i64> {
        // batch_delete are directly committed
        self.batch_delete_subspace_val(
            &mut MockDBWriteBatch,
            height,
            key,
            persist_diffs,
        )
    }

    fn batch() -> Self::WriteBatch {
        MockDBWriteBatch
    }

    fn exec_batch(&self, _batch: Self::WriteBatch) -> Result<()> {
        // Nothing to do - in MockDB, batch writes are committed directly from
        // `batch_write_subspace_val` and `batch_delete_subspace_val`.
        Ok(())
    }

    fn batch_write_subspace_val(
        &self,
        _batch: &mut Self::WriteBatch,
        height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
        persist_diffs: bool,
    ) -> Result<i64> {
        let value = value.as_ref();
        let subspace_key =
            Key::parse(SUBSPACE_CF).map_err(Error::KeyError)?.join(key);
        let current_len = value.len() as i64;
        let diff_prefix = Key::from(height.to_db_key());
        let mut db = self.0.borrow_mut();

        // Diffs - Note that this is different from RocksDB that has a separate
        // CF for non-persisted diffs (ROLLBACK_CF)
        let size_diff =
            match db.insert(subspace_key.to_string(), value.to_owned()) {
                Some(prev_value) => {
                    let old_key = diff_prefix
                        .push(&OLD_DIFF_PREFIX.to_string().to_db_key())
                        .unwrap()
                        .join(key);
                    db.insert(old_key.to_string(), prev_value.clone());
                    let new_key = diff_prefix
                        .push(&NEW_DIFF_PREFIX.to_string().to_db_key())
                        .unwrap()
                        .join(key);
                    db.insert(new_key.to_string(), value.to_owned());
                    current_len - prev_value.len() as i64
                }
                None => {
                    let new_key = diff_prefix
                        .push(&NEW_DIFF_PREFIX.to_string().to_db_key())
                        .unwrap()
                        .join(key);
                    db.insert(new_key.to_string(), value.to_owned());
                    current_len
                }
            };

        if !persist_diffs {
            if let Some(pruned_height) = height.0.checked_sub(1) {
                let pruned_key_prefix = Key::from(pruned_height.to_db_key());
                let old_val_key = pruned_key_prefix
                    .push(&NEW_DIFF_PREFIX.to_string().to_db_key())
                    .unwrap()
                    .join(key)
                    .to_string();
                db.remove(&old_val_key);
                let new_val_key = pruned_key_prefix
                    .push(&NEW_DIFF_PREFIX.to_string().to_db_key())
                    .unwrap()
                    .join(key)
                    .to_string();
                db.remove(&new_val_key);
            }
        }

        Ok(size_diff)
    }

    fn batch_delete_subspace_val(
        &self,
        _batch: &mut Self::WriteBatch,
        height: BlockHeight,
        key: &Key,
        persist_diffs: bool,
    ) -> Result<i64> {
        let subspace_key =
            Key::parse(SUBSPACE_CF).map_err(Error::KeyError)?.join(key);
        let diff_prefix = Key::from(height.to_db_key());
        let mut db = self.0.borrow_mut();

        // Diffs - Note that this is different from RocksDB that has a separate
        // CF for non-persisted diffs (ROLLBACK_CF)
        let size_diff = match db.remove(&subspace_key.to_string()) {
            Some(value) => {
                let old_key = diff_prefix
                    .push(&OLD_DIFF_PREFIX.to_string().to_db_key())
                    .unwrap()
                    .join(key);
                db.insert(old_key.to_string(), value.clone());

                if !persist_diffs {
                    if let Some(pruned_height) = height.0.checked_sub(1) {
                        let pruned_key_prefix =
                            Key::from(pruned_height.to_db_key());
                        let old_val_key = pruned_key_prefix
                            .push(&NEW_DIFF_PREFIX.to_string().to_db_key())
                            .unwrap()
                            .join(key)
                            .to_string();
                        db.remove(&old_val_key);
                        let new_val_key = pruned_key_prefix
                            .push(&NEW_DIFF_PREFIX.to_string().to_db_key())
                            .unwrap()
                            .join(key)
                            .to_string();
                        db.remove(&new_val_key);
                    }
                }
                value.len() as i64
            }
            None => 0,
        };

        Ok(size_diff)
    }

    fn prune_merkle_tree_store(
        &mut self,
        _batch: &mut Self::WriteBatch,
        store_type: &StoreType,
        pruned_target: Either<BlockHeight, Epoch>,
    ) -> Result<()> {
        let key_prefix = match pruned_target {
            Either::Left(height) => {
                tree_key_prefix_with_height(store_type, height)
            }
            Either::Right(epoch) => {
                tree_key_prefix_with_epoch(store_type, epoch)
            }
        };
        let root_key = format!("{key_prefix}/{MERKLE_TREE_ROOT_KEY_SEGMENT}");
        self.0.borrow_mut().remove(&root_key);
        let store_key = format!("{key_prefix}/{MERKLE_TREE_STORE_KEY_SEGMENT}");
        self.0.borrow_mut().remove(&store_key);
        Ok(())
    }

    fn write_replay_protection_entry(
        &mut self,
        _batch: &mut Self::WriteBatch,
        key: &Key,
    ) -> Result<()> {
        let key = Key::parse("replay_protection")
            .map_err(Error::KeyError)?
            .join(key);

        match self.0.borrow_mut().insert(key.to_string(), vec![]) {
            Some(_) => Err(Error::DBError(format!(
                "Replay protection key {key} already in storage"
            ))),
            None => Ok(()),
        }
    }

    fn move_current_replay_protection_entries(
        &mut self,
        _batch: &mut Self::WriteBatch,
    ) -> Result<()> {
        let current_key_prefix = Key::parse("replay_protection")
            .map_err(Error::KeyError)?
            .push(&"current".to_string())
            .map_err(Error::KeyError)?;
        let mut target_hashes = vec![];

        for (key, _) in self.0.borrow().iter() {
            if key.starts_with(&current_key_prefix.to_string()) {
                let hash = key
                    .rsplit(KEY_SEGMENT_SEPARATOR)
                    .next_back()
                    .unwrap()
                    .to_string();
                target_hashes.push(hash);
            }
        }

        for hash in target_hashes {
            let current_key =
                current_key_prefix.push(&hash).map_err(Error::KeyError)?;
            let key = Key::parse("replay_protection")
                .map_err(Error::KeyError)?
                .push(&hash)
                .map_err(Error::KeyError)?;

            self.0.borrow_mut().remove(&current_key.to_string());
            self.0.borrow_mut().insert(key.to_string(), vec![]);
        }

        Ok(())
    }

    fn prune_non_persisted_diffs(
        &mut self,
        _batch: &mut Self::WriteBatch,
        _height: BlockHeight,
    ) -> Result<()> {
        // No-op - Note that this is different from RocksDB that has a separate
        // CF for non-persisted diffs (ROLLBACK_CF)
        Ok(())
    }

    fn overwrite_entry(
        &self,
        _batch: &mut Self::WriteBatch,
        _cf: &DbColFam,
        _key: &Key,
        _new_value: impl AsRef<[u8]>,
        _persist_diffs: bool,
    ) -> Result<()> {
        unimplemented!()
    }

    fn migrator() -> Self::Migrator {
        unimplemented!("Migration isn't implemented in MockDB")
    }

    fn update_last_block_merkle_tree(
        &self,
        merkle_tree_stores: MerkleTreeStoresWrite<'_>,
        is_full_commit: bool,
    ) -> Result<()> {
        // Read the last block's height
        let height: BlockHeight = self.read_value(BLOCK_HEIGHT_KEY)?.unwrap();

        // Read the last block's epoch
        let prefix = height.raw();
        let epoch_key = format!("{prefix}/{EPOCH_KEY_SEGMENT}");
        let epoch: Epoch = self.read_value(epoch_key)?.unwrap();

        for st in StoreType::iter() {
            if st.is_stored_every_block() || is_full_commit {
                let key_prefix = if st.is_stored_every_block() {
                    tree_key_prefix_with_height(st, height)
                } else {
                    tree_key_prefix_with_epoch(st, epoch)
                };
                let root_key =
                    format!("{key_prefix}/{MERKLE_TREE_ROOT_KEY_SEGMENT}");
                self.write_value(root_key, merkle_tree_stores.root(st));
                let store_key =
                    format!("{key_prefix}/{MERKLE_TREE_STORE_KEY_SEGMENT}");
                self.0
                    .borrow_mut()
                    .insert(store_key, merkle_tree_stores.store(st).encode());
            }
        }
        Ok(())
    }
}

impl<'iter> DBIter<'iter> for MockDB {
    type PatternIter = MockPatternIterator;
    type PrefixIter = MockPrefixIterator;

    fn iter_prefix(&'iter self, prefix: Option<&Key>) -> MockPrefixIterator {
        let stripped_prefix = "subspace/".to_owned();
        let prefix = format!(
            "{}{}",
            stripped_prefix,
            match prefix {
                Some(prefix) => {
                    if prefix == &Key::default() {
                        prefix.to_string()
                    } else {
                        format!("{prefix}/")
                    }
                }
                None => "".to_string(),
            }
        );
        let iter = self.0.borrow().clone().into_iter();
        MockPrefixIterator::new(MockIterator { prefix, iter }, stripped_prefix)
    }

    fn iter_pattern(
        &'iter self,
        prefix: Option<&Key>,
        pattern: Regex,
    ) -> Self::PatternIter {
        MockPatternIterator {
            inner: PatternIterator {
                iter: self.iter_prefix(prefix),
                pattern,
            },
            finished: false,
        }
    }

    fn iter_results(&'iter self) -> MockPrefixIterator {
        let stripped_prefix = "results/".to_owned();
        let prefix = "results".to_owned();
        let iter = self.0.borrow().clone().into_iter();
        MockPrefixIterator::new(MockIterator { prefix, iter }, stripped_prefix)
    }

    fn iter_old_diffs(
        &self,
        height: BlockHeight,
        prefix: Option<&Key>,
    ) -> MockPrefixIterator {
        // Returns an empty iterator since Mock DB can read only the latest
        // value for now
        let stripped_prefix = format!("{}/old/", height.0.raw());
        let prefix = prefix
            .map(|k| {
                if k == &Key::default() {
                    stripped_prefix.clone()
                } else {
                    format!("{stripped_prefix}{k}/")
                }
            })
            .unwrap_or("".to_string());
        let iter = self.0.borrow().clone().into_iter();
        MockPrefixIterator::new(MockIterator { prefix, iter }, stripped_prefix)
    }

    fn iter_new_diffs(
        &self,
        height: BlockHeight,
        prefix: Option<&Key>,
    ) -> MockPrefixIterator {
        // Returns an empty iterator since Mock DB can read only the latest
        // value for now
        let stripped_prefix = format!("{}/new/", height.0.raw());
        let prefix = prefix
            .map(|k| {
                if k == &Key::default() {
                    stripped_prefix.clone()
                } else {
                    format!("{stripped_prefix}{k}/")
                }
            })
            .unwrap_or("".to_string());
        let iter = self.0.borrow().clone().into_iter();
        MockPrefixIterator::new(MockIterator { prefix, iter }, stripped_prefix)
    }

    fn iter_current_replay_protection(&'iter self) -> Self::PrefixIter {
        let stripped_prefix = format!(
            "replay_protection/{}/",
            replay_protection::current_prefix()
        );
        let prefix = stripped_prefix.clone();
        let iter = self.0.borrow().clone().into_iter();
        MockPrefixIterator::new(MockIterator { prefix, iter }, stripped_prefix)
    }
}

/// A prefix iterator base for the [`MockPrefixIterator`].
#[derive(Debug)]
pub struct MockIterator {
    prefix: String,
    /// The concrete iterator
    pub iter: btree_map::IntoIter<String, Vec<u8>>,
}

/// A prefix iterator for the [`MockDB`].
pub type MockPrefixIterator = PrefixIterator<MockIterator>;

impl Iterator for MockIterator {
    type Item = Result<KVBytes>;

    fn next(&mut self) -> Option<Self::Item> {
        for (key, val) in &mut self.iter {
            if key.starts_with(&self.prefix) {
                return Some(Ok((
                    Box::from(key.as_bytes()),
                    Box::from(val.as_slice()),
                )));
            }
        }
        None
    }
}

impl Iterator for PrefixIterator<MockIterator> {
    type Item = (String, Vec<u8>, Gas);

    /// Returns the next pair and the gas cost
    fn next(&mut self) -> Option<(String, Vec<u8>, Gas)> {
        match self.iter.next() {
            Some(result) => {
                let (key, val) =
                    result.expect("Prefix iterator shouldn't fail");
                let key = String::from_utf8(key.to_vec())
                    .expect("Cannot convert from bytes to key string");
                match key.strip_prefix(&self.stripped_prefix) {
                    Some(k) => {
                        let gas = k.len() + val.len();
                        Some((k.to_owned(), val.to_vec(), (gas as u64).into()))
                    }
                    None => self.next(),
                }
            }
            None => None,
        }
    }
}

/// MockDB pattern iterator
#[derive(Debug)]
pub struct MockPatternIterator {
    inner: PatternIterator<MockPrefixIterator>,
    finished: bool,
}

impl Iterator for MockPatternIterator {
    type Item = (String, Vec<u8>, Gas);

    /// Returns the next pair and the gas cost
    fn next(&mut self) -> Option<(String, Vec<u8>, Gas)> {
        if self.finished {
            return None;
        }
        loop {
            let next_result = self.inner.iter.next()?;
            if self.inner.pattern.is_match(&next_result.0) {
                return Some(next_result);
            } else {
                self.finished = true;
            }
        }
    }
}

impl DBWriteBatch for MockDBWriteBatch {}

impl DBUpdateVisitor for () {
    type DB = crate::mockdb::MockDB;

    fn read(
        &self,
        _db: &Self::DB,
        _key: &Key,
        _cf: &DbColFam,
    ) -> Option<Vec<u8>> {
        unimplemented!()
    }

    fn write(
        &mut self,
        _db: &Self::DB,
        _key: &Key,
        _cf: &DbColFam,
        _value: impl AsRef<[u8]>,
        _persist_diffs: bool,
    ) {
        unimplemented!()
    }

    fn delete(
        &mut self,
        _db: &Self::DB,
        _key: &Key,
        _cf: &DbColFam,
        _persist_diffs: bool,
    ) {
        unimplemented!()
    }

    fn get_pattern(
        &self,
        _db: &Self::DB,
        _pattern: Regex,
    ) -> Vec<(String, Vec<u8>)> {
        unimplemented!()
    }

    fn commit(self, _db: &Self::DB) -> Result<()> {
        unimplemented!()
    }
}
