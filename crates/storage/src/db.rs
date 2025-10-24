use std::fmt::Debug;
use std::num::TryFromIntError;

use itertools::Either;
use namada_core::address::EstablishedAddressGen;
use namada_core::arith;
use namada_core::chain::{BlockHeader, BlockHeight, Epoch, Epochs};
use namada_core::hash::{Error as HashError, Hash};
use namada_core::storage::{BlockResults, DbColFam, Key};
use namada_core::time::DateTimeUtc;
use namada_gas::Gas;
use namada_merkle_tree::{
    Error as MerkleTreeError, MerkleTreeStoresRead, MerkleTreeStoresWrite,
    StoreType,
};
use regex::Regex;
use thiserror::Error;

use crate::conversion_state::ConversionState;
use crate::types::CommitOnlyData;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("TEMPORARY error: {error}")]
    Temporary { error: String },
    #[error("Found an unknown key: {key}")]
    UnknownKey { key: String },
    #[error("Storage key error {0}")]
    KeyError(namada_core::storage::Error),
    #[error("Coding error: {0}")]
    CodingError(#[from] namada_core::DecodeError),
    #[error("Merkle tree error: {0}")]
    MerkleTreeError(#[from] MerkleTreeError),
    #[error("DB error: {0}")]
    DBError(String),
    #[error("Borsh (de)-serialization error: {0}")]
    BorshCodingError(std::io::Error),
    #[error("Merkle tree at the height {height} is not stored")]
    NoMerkleTree { height: BlockHeight },
    #[error("Code hash error: {0}")]
    InvalidCodeHash(HashError),
    #[error("Numeric conversion error: {0}")]
    NumConversionError(#[from] TryFromIntError),
    #[error("Arithmetic {0}")]
    Arith(#[from] arith::Error),
}

/// A result of a function that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// The block's state as stored in the database.
pub struct BlockStateRead {
    /// Height of the block
    pub height: BlockHeight,
    /// Time of the block
    pub time: DateTimeUtc,
    /// Epoch of the block
    pub epoch: Epoch,
    /// Predecessor block epochs
    pub pred_epochs: Epochs,
    /// Minimum block height at which the next epoch may start
    pub next_epoch_min_start_height: BlockHeight,
    /// Minimum block time at which the next epoch may start
    pub next_epoch_min_start_time: DateTimeUtc,
    /// Update epoch delay
    pub update_epoch_blocks_delay: Option<u32>,
    /// Established address generator
    pub address_gen: EstablishedAddressGen,
    /// Results of applying transactions
    pub results: BlockResults,
    /// The conversion state
    pub conversion_state: ConversionState,
    /// Structure holding data that needs to be added to the merkle tree
    pub commit_only_data: CommitOnlyData,
}

/// The block's state to write into the database.
pub struct BlockStateWrite<'a> {
    /// Merkle tree stores
    pub merkle_tree_stores: MerkleTreeStoresWrite<'a>,
    /// Header of the block
    pub header: Option<&'a BlockHeader>,
    /// Height of the block
    pub height: BlockHeight,
    /// Time of the block
    pub time: DateTimeUtc,
    /// Epoch of the block
    pub epoch: Epoch,
    /// Predecessor block epochs
    pub pred_epochs: &'a Epochs,
    /// Minimum block height at which the next epoch may start
    pub next_epoch_min_start_height: BlockHeight,
    /// Minimum block time at which the next epoch may start
    pub next_epoch_min_start_time: DateTimeUtc,
    /// Update epoch delay
    pub update_epoch_blocks_delay: Option<u32>,
    /// Established address generator
    pub address_gen: &'a EstablishedAddressGen,
    /// Results of applying transactions
    pub results: &'a BlockResults,
    /// The conversion state
    pub conversion_state: &'a ConversionState,
    /// Structure holding data that needs to be added to the merkle tree
    pub commit_only_data: &'a CommitOnlyData,
}

/// A database backend.
pub trait DB: Debug {
    /// A DB's cache
    type Cache;
    /// A handle for batch writes
    type WriteBatch: DBWriteBatch;

    /// A type placeholder for DB migration implementation.
    type Migrator: DBUpdateVisitor<DB = Self>;

    /// Source data to restore a database.
    type RestoreSource<'a>;

    /// Open the database from provided path
    fn open(
        db_path: impl AsRef<std::path::Path>,
        cache: Option<&Self::Cache>,
    ) -> Self;

    /// Open read-only database from provided path
    fn open_read_only(
        db_path: impl AsRef<std::path::Path>,
        cache: Option<&Self::Cache>,
    ) -> Self;

    /// Overwrite the contents of the current database
    /// with the data read from `source`.
    fn restore_from(&mut self, source: Self::RestoreSource<'_>) -> Result<()>;

    /// Get the path to the db in the filesystem,
    /// if it exists (the DB may be in-memory only)
    fn path(&self) -> Option<&std::path::Path> {
        None
    }

    /// Flush data on the memory to persistent them
    fn flush(&self, wait: bool) -> Result<()>;

    /// Read the last committed block's metadata
    fn read_last_block(&self) -> Result<Option<BlockStateRead>>;

    /// Write block's metadata. Merkle tree sub-stores are committed only when
    /// `is_full_commit` is `true` (typically on a beginning of a new epoch).
    fn add_block_to_batch(
        &self,
        state: BlockStateWrite<'_>,
        batch: &mut Self::WriteBatch,
        is_full_commit: bool,
    ) -> Result<()>;

    /// Read the block header with the given height from the DB
    fn read_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>>;

    /// Read the merkle tree stores with the given epoch. If a store_type is
    /// given, it reads only the specified tree. Otherwise, it reads all
    /// trees, but some subtrees could be empty if the stores aren't saved.
    fn read_merkle_tree_stores(
        &self,
        epoch: Epoch,
        base_height: BlockHeight,
        store_type: Option<StoreType>,
    ) -> Result<Option<MerkleTreeStoresRead>>;

    /// Check if the given replay protection entry exists
    fn has_replay_protection_entry(&self, hash: &Hash) -> Result<bool>;

    /// Read the latest value for account subspace key from the DB
    fn read_subspace_val(&self, key: &Key) -> Result<Option<Vec<u8>>>;

    /// Read the value for account subspace key at the given height from the DB.
    /// In our `PersistentStorage` (rocksdb), to find a value from arbitrary
    /// height requires looking for diffs from the given `height`, possibly
    /// up to the `last_height`.
    fn read_subspace_val_with_height(
        &self,
        key: &Key,
        height: BlockHeight,
        last_height: BlockHeight,
    ) -> Result<Option<Vec<u8>>>;

    /// Read the value for the account diffs at the corresponding height from
    /// the DB
    fn read_diffs_val(
        &self,
        key: &Key,
        height: BlockHeight,
        is_old: bool,
    ) -> Result<Option<Vec<u8>>>;

    /// Write the value with the given height and account subspace key to the
    /// DB. Returns the size difference from previous value, if any, or the
    /// size of the value otherwise.
    fn write_subspace_val(
        &mut self,
        height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
        persist_diffs: bool,
    ) -> Result<i64>;

    /// Delete the value with the given height and account subspace key from the
    /// DB. Returns the size of the removed value, if any, 0 if no previous
    /// value was found.
    fn delete_subspace_val(
        &mut self,
        height: BlockHeight,
        key: &Key,
        persist_diffs: bool,
    ) -> Result<i64>;

    /// Start write batch.
    fn batch() -> Self::WriteBatch;

    /// Execute write batch.
    fn exec_batch(&self, batch: Self::WriteBatch) -> Result<()>;

    /// Batch write the value with the given height and account subspace key to
    /// the DB. Returns the size difference from previous value, if any, or
    /// the size of the value otherwise.
    fn batch_write_subspace_val(
        &self,
        batch: &mut Self::WriteBatch,
        height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
        persist_diffs: bool,
    ) -> Result<i64>;

    /// Batch delete the value with the given height and account subspace key
    /// from the DB. Returns the size of the removed value, if any, 0 if no
    /// previous value was found.
    fn batch_delete_subspace_val(
        &self,
        batch: &mut Self::WriteBatch,
        height: BlockHeight,
        key: &Key,
        persist_diffs: bool,
    ) -> Result<i64>;

    /// Prune Merkle tree stores at the given epoch
    fn prune_merkle_tree_store(
        &mut self,
        batch: &mut Self::WriteBatch,
        store_type: &StoreType,
        pruned_target: Either<BlockHeight, Epoch>,
    ) -> Result<()>;

    /// Write a replay protection entry
    fn write_replay_protection_entry(
        &mut self,
        batch: &mut Self::WriteBatch,
        key: &Key,
    ) -> Result<()>;

    /// Move the current replay protection bucket to the general one
    fn move_current_replay_protection_entries(
        &mut self,
        batch: &mut Self::WriteBatch,
    ) -> Result<()>;

    /// Prune non-persisted diffs that are only kept for one block for rollback
    fn prune_non_persisted_diffs(
        &mut self,
        batch: &mut Self::WriteBatch,
        height: BlockHeight,
    ) -> Result<()>;

    /// Overwrite a new value in storage, taking into
    /// account values stored at a previous height
    fn overwrite_entry(
        &self,
        batch: &mut Self::WriteBatch,
        cf: &DbColFam,
        key: &Key,
        new_value: impl AsRef<[u8]>,
        persist_diffs: bool,
    ) -> Result<()>;

    /// Get an instance of DB migrator
    fn migrator() -> Self::Migrator;

    /// Update the merkle tree written for the committed last block
    fn update_last_block_merkle_tree(
        &self,
        merkle_tree_stores: MerkleTreeStoresWrite<'_>,
        is_full_commit: bool,
    ) -> Result<()>;
}

/// A CRUD DB access
pub trait DBUpdateVisitor {
    /// The DB type
    type DB;

    /// Try to read key's value from a DB column
    fn read(&self, db: &Self::DB, key: &Key, cf: &DbColFam) -> Option<Vec<u8>>;

    /// Write key's value to a DB column
    fn write(
        &mut self,
        db: &Self::DB,
        key: &Key,
        cf: &DbColFam,
        value: impl AsRef<[u8]>,
        persist_diffs: bool,
    );

    /// Delete key-val
    fn delete(
        &mut self,
        db: &Self::DB,
        key: &Key,
        cf: &DbColFam,
        persist_diffs: bool,
    );

    /// Get key-vals matching the pattern
    fn get_pattern(
        &self,
        db: &Self::DB,
        pattern: Regex,
    ) -> Vec<(String, Vec<u8>)>;

    /// Commit the changes
    fn commit(self, db: &Self::DB) -> Result<()>;
}

/// A database prefix iterator.
pub trait DBIter<'iter> {
    /// Prefix iterator
    type PrefixIter: Debug + Iterator<Item = (String, Vec<u8>, Gas)>;
    /// Pattern iterator
    type PatternIter: Debug + Iterator<Item = (String, Vec<u8>, Gas)>;

    /// WARNING: This only works for values that have been committed to DB.
    /// To be able to see values written or deleted, but not yet committed,
    /// use the `StorageWithWriteLog`.
    ///
    /// Read account subspace key value pairs with the given prefix from the DB,
    /// ordered by the storage keys.
    fn iter_prefix(&'iter self, prefix: Option<&Key>) -> Self::PrefixIter;

    /// WARNING: This only works for values that have been committed to DB.
    /// To be able to see values written or deleted, but not yet committed,
    /// use the `StorageWithWriteLog`.
    ///
    /// Read account subspace key value pairs with the given pattern from the
    /// DB, ordered by the storage keys.
    fn iter_pattern(
        &'iter self,
        prefix: Option<&Key>,
        pattern: Regex,
    ) -> Self::PatternIter;

    /// Read results subspace key value pairs from the DB
    fn iter_results(&'iter self) -> Self::PrefixIter;

    /// Read subspace old diffs at a given height
    fn iter_old_diffs(
        &'iter self,
        height: BlockHeight,
        prefix: Option<&'iter Key>,
    ) -> Self::PrefixIter;

    /// Read subspace new diffs at a given height
    fn iter_new_diffs(
        &'iter self,
        height: BlockHeight,
        prefix: Option<&'iter Key>,
    ) -> Self::PrefixIter;

    /// Read replay protection storage from the current bucket
    fn iter_current_replay_protection(&'iter self) -> Self::PrefixIter;
}

/// Atomic batch write.
pub trait DBWriteBatch {}
