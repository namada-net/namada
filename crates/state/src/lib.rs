//! Ledger's state storage with key-value backed store and a merkle tree

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod in_memory;
pub mod prefix_iter;
mod wl_state;
pub mod write_log;

use std::fmt::Debug;
use std::iter::Peekable;

pub use in_memory::{
    BlockStorage, InMemory, LastBlock, ProcessProposalCachedResult,
};
use namada_core::address::Address;
use namada_core::arith::checked;
use namada_core::chain::ChainId;
pub use namada_core::chain::{
    BLOCK_HASH_LENGTH, BLOCK_HEIGHT_LENGTH, BlockHash, BlockHeader,
    BlockHeight, Epoch, Epochs,
};
use namada_core::eth_bridge_pool::is_pending_transfer_key;
use namada_core::hash::Hash;
pub use namada_core::hash::Sha256Hasher;
pub use namada_core::storage::{
    BlockResults, EPOCH_TYPE_LENGTH, EthEventsQueue, Key, KeySeg, TxIndex,
};
use namada_core::tendermint::merkle::proof::ProofOps;
use namada_gas::{
    Gas, MEMORY_ACCESS_GAS_PER_BYTE, STORAGE_ACCESS_GAS_PER_BYTE,
};
use namada_merkle_tree::Error as MerkleTreeError;
pub use namada_merkle_tree::{
    self as merkle_tree, MembershipProof, MerkleTree, MerkleTreeStoresRead,
    MerkleTreeStoresWrite, StoreRef, StoreType, ics23_specs,
};
pub use namada_storage as storage;
pub use namada_storage::conversion_state::{
    ConversionLeaf, ConversionState, ReadConversionState, WithConversionState,
};
pub use namada_storage::types::{KVBytes, PatternIterator, PrefixIterator};
pub use namada_storage::{
    BlockStateRead, BlockStateWrite, DB, DBIter, DBWriteBatch, DbError,
    DbResult, Error, OptionExt, Result, ResultExt, StorageHasher, StorageRead,
    StorageWrite, collections, iter_prefix, iter_prefix_bytes,
    iter_prefix_with_filter, iter_prefix_with_filter_map, mockdb, tx_queue,
};
use namada_systems::parameters;
use thiserror::Error;
use wl_state::TxWlState;
pub use wl_state::{FullAccessState, TempWlState, WlState};
use write_log::WriteLog;

/// We delay epoch change 2 blocks to keep it in sync with Tendermint, because
/// it has 2 blocks delay on validator set update.
pub const EPOCH_SWITCH_BLOCKS_DELAY: u32 = 2;

/// Common trait for read-only access to write log, DB and in-memory state.
pub trait StateRead: StorageRead + Debug {
    /// DB type
    type D: 'static + DB + for<'iter> DBIter<'iter>;
    /// DB hasher type
    type H: 'static + StorageHasher;

    /// Borrow `WriteLog`
    fn write_log(&self) -> &WriteLog;

    /// Borrow `DB`
    fn db(&self) -> &Self::D;

    /// Borrow `InMemory` state
    fn in_mem(&self) -> &InMemory<Self::H>;

    /// Try to charge a given gas amount. Returns an error on out-of-gas.
    fn charge_gas(&self, gas: Gas) -> Result<()>;

    /// Check if the given key is present in storage. Returns the result and the
    /// gas cost.
    fn db_has_key(&self, key: &storage::Key) -> Result<(bool, Gas)> {
        let len = key.len() as u64;
        Ok((
            self.db().read_subspace_val(key)?.is_some(),
            checked!(len * STORAGE_ACCESS_GAS_PER_BYTE)?.into(),
        ))
    }

    /// Returns a value from the specified subspace and the gas cost
    fn db_read(&self, key: &storage::Key) -> Result<(Option<Vec<u8>>, Gas)> {
        tracing::trace!("storage read key {}", key);

        match self.db().read_subspace_val(key)? {
            Some(v) => {
                let len = checked!(key.len() + v.len())? as u64;
                let gas = checked!(len * STORAGE_ACCESS_GAS_PER_BYTE)?;
                Ok((Some(v), gas.into()))
            }
            None => {
                let len = key.len() as u64;
                let gas = checked!(len * STORAGE_ACCESS_GAS_PER_BYTE)?;
                Ok((None, gas.into()))
            }
        }
    }

    /// WARNING: This only works for values that have been committed to DB.
    /// To be able to see values written or deleted, but not yet committed,
    /// use the `StorageWithWriteLog`.
    ///
    /// Returns a prefix iterator, ordered by storage keys, and the gas cost.
    fn db_iter_prefix(
        &self,
        prefix: &Key,
    ) -> Result<(<Self::D as DBIter<'_>>::PrefixIter, Gas)> {
        let len = prefix.len() as u64;
        Ok((
            self.db().iter_prefix(Some(prefix)),
            checked!(len * STORAGE_ACCESS_GAS_PER_BYTE)?.into(),
        ))
    }

    /// Returns an iterator over the block results
    fn db_iter_results(&self) -> (<Self::D as DBIter<'_>>::PrefixIter, Gas) {
        (self.db().iter_results(), Gas::default())
    }

    /// Get the hash of a validity predicate for the given account address and
    /// the gas cost for reading it.
    fn validity_predicate<Params: parameters::Keys>(
        &self,
        addr: &Address,
    ) -> Result<(Option<Hash>, Gas)> {
        let key = if let Address::Implicit(_) = addr {
            Params::implicit_vp_key()
        } else {
            Key::validity_predicate(addr)
        };
        match self.db_read(&key)? {
            (Some(value), gas) => {
                let vp_code_hash = Hash::try_from(&value[..])?;
                Ok((Some(vp_code_hash), gas))
            }
            (None, gas) => Ok((None, gas)),
        }
    }

    /// Get the block header
    fn get_block_header(
        &self,
        height: Option<BlockHeight>,
    ) -> Result<(Option<BlockHeader>, Gas)> {
        match height {
            Some(h) if h == self.in_mem().get_block_height().0 => {
                let header = self.in_mem().header.clone();
                let gas = if header.is_some() {
                    let len = BlockHeader::encoded_len() as u64;
                    checked!(len * MEMORY_ACCESS_GAS_PER_BYTE)?
                } else {
                    MEMORY_ACCESS_GAS_PER_BYTE
                };
                Ok((header, gas.into()))
            }
            Some(h) => match self.db().read_block_header(h)? {
                Some(header) => {
                    let len = BlockHeader::encoded_len() as u64;
                    let gas = checked!(len * STORAGE_ACCESS_GAS_PER_BYTE)?;
                    Ok((Some(header), gas.into()))
                }
                None => Ok((None, STORAGE_ACCESS_GAS_PER_BYTE.into())),
            },
            None => Ok((
                self.in_mem().header.clone(),
                STORAGE_ACCESS_GAS_PER_BYTE.into(),
            )),
        }
    }
}

/// Common trait for write log, DB and in-memory state.
pub trait State: StateRead + StorageWrite {
    /// Borrow mutable `WriteLog`
    fn write_log_mut(&mut self) -> &mut WriteLog;

    /// Splitting borrow to get mutable reference to `WriteLog`, immutable
    /// reference to the `InMemory` state and DB when in need of both (avoids
    /// complain from the borrow checker)
    fn split_borrow(&mut self)
    -> (&mut WriteLog, &InMemory<Self::H>, &Self::D);

    /// Write the provided tx hash to write log.
    fn write_tx_hash(&mut self, hash: Hash) -> write_log::Result<()> {
        self.write_log_mut().write_tx_hash(hash)
    }
}

/// Perform storage writes and deletions to write-log at tx level.
pub trait TxWrites: StateRead {
    /// Performs storage writes at the tx level of the write-log.
    fn with_tx_writes(&mut self) -> TxWlState<'_, Self::D, Self::H>;
}

/// Implement [`trait StorageRead`] using its [`trait StateRead`]
/// implementation.
#[macro_export]
macro_rules! impl_storage_read {
    ($($type:ty)*) => {
        impl<D, H> StorageRead for $($type)*
        where
            D: 'static + DB + for<'iter> DBIter<'iter>,
            H: 'static + StorageHasher,
        {
            type PrefixIter<'iter> = PrefixIter<'iter, D> where Self: 'iter;

            fn read_bytes(
                &self,
                key: &storage::Key,
            ) -> namada_storage::Result<Option<Vec<u8>>> {
                // try to read from the write log first
                let (log_val, gas) = self.write_log().read(key)?;
                self.charge_gas(gas).into_storage_result()?;
                match &log_val {
                    Some(write_log::StorageModification::Write { value }) => {
                        Ok(Some(value.clone()))
                    }
                    Some(write_log::StorageModification::Delete) => Ok(None),
                    Some(write_log::StorageModification::InitAccount {
                        vp_code_hash,
                    }) => Ok(Some(vp_code_hash.to_vec())),
                    None => {
                        // when not found in write log try to read from the storage
                        let (value, gas) = self.db_read(key).into_storage_result()?;
                        self.charge_gas(gas).into_storage_result()?;
                        Ok(value)
                    }
                }
            }

            fn has_key(&self, key: &storage::Key) -> namada_storage::Result<bool> {
                // try to read from the write log first
                let (log_val, gas) = self.write_log().read(key)?;
                self.charge_gas(gas).into_storage_result()?;
                match log_val {
                    Some(&write_log::StorageModification::Write { .. })
                    | Some(&write_log::StorageModification::InitAccount { .. }) => Ok(true),
                    Some(&write_log::StorageModification::Delete) => {
                        // the given key has been deleted
                        Ok(false)
                    }
                    None => {
                        // when not found in write log try to check the storage
                        let (present, gas) = self.db_has_key(key).into_storage_result()?;
                        self.charge_gas(gas).into_storage_result()?;
                        Ok(present)
                    }
                }
            }

            fn iter_prefix<'iter>(
                &'iter self,
                prefix: &storage::Key,
            ) -> namada_storage::Result<Self::PrefixIter<'iter>> {
                let (iter, gas) =
                    iter_prefix_post(self.write_log(), self.db(), prefix)?;
                self.charge_gas(gas).into_storage_result()?;
                Ok(iter)
            }

            fn iter_next<'iter>(
                &'iter self,
                iter: &mut Self::PrefixIter<'iter>,
            ) -> namada_storage::Result<Option<(String, Vec<u8>)>> {
                iter.next().map(|(key, val, gas)| {
                    self.charge_gas(gas).into_storage_result()?;
                    Ok((key, val))
                }).transpose()
            }

            fn get_chain_id(
                &self,
            ) -> std::result::Result<ChainId, namada_storage::Error> {
                let (chain_id, gas) = self.in_mem().get_chain_id();
                self.charge_gas(gas).into_storage_result()?;
                Ok(chain_id)
            }

            fn get_block_height(
                &self,
            ) -> std::result::Result<BlockHeight, namada_storage::Error> {
                let (height, gas) = self.in_mem().get_block_height();
                self.charge_gas(gas).into_storage_result()?;
                Ok(height)
            }

            fn get_block_header(
                &self,
                height: BlockHeight,
            ) -> std::result::Result<Option<BlockHeader>, namada_storage::Error>
            {
                let (header, gas) =
                    StateRead::get_block_header(self, Some(height)).into_storage_result()?;
                self.charge_gas(gas).into_storage_result()?;
                Ok(header)
            }

            fn get_block_epoch(
                &self,
            ) -> std::result::Result<Epoch, namada_storage::Error> {
                let (epoch, gas) = self.in_mem().get_current_epoch();
                self.charge_gas(gas).into_storage_result()?;
                Ok(epoch)
            }

            fn get_pred_epochs(&self) -> namada_storage::Result<Epochs> {
                self.charge_gas(
                    namada_gas::STORAGE_ACCESS_GAS_PER_BYTE.into(),
                ).into_storage_result()?;
                Ok(self.in_mem().block.pred_epochs.clone())
            }

            fn get_tx_index(
                &self,
            ) -> std::result::Result<storage::TxIndex, namada_storage::Error> {
                self.charge_gas(
                    namada_gas::STORAGE_ACCESS_GAS_PER_BYTE.into(),
                ).into_storage_result()?;
                Ok(self.in_mem().tx_index)
            }

            fn get_native_token(&self) -> namada_storage::Result<Address> {
                self.charge_gas(
                    namada_gas::STORAGE_ACCESS_GAS_PER_BYTE.into(),
                ).into_storage_result()?;
                Ok(self.in_mem().native_token.clone())
            }
        }
    }
}

/// Implement [`trait StorageWrite`] using its [`trait State`] implementation.
#[macro_export]
macro_rules! impl_storage_write {
    ($($type:ty)*) => {
        impl<D, H> StorageWrite for $($type)*
        where
            D: 'static + DB + for<'iter> DBIter<'iter>,
            H: 'static + StorageHasher,
        {
            fn write_bytes(
                &mut self,
                key: &storage::Key,
                val: impl AsRef<[u8]>,
            ) -> namada_storage::Result<()> {
                let (gas, _size_diff) = self
                    .write_log_mut()
                    .write(key, val.as_ref().to_vec())
                    .into_storage_result()?;
                self.charge_gas(gas).into_storage_result()?;
                Ok(())
            }

            fn delete(&mut self, key: &storage::Key) -> namada_storage::Result<()> {
                let (gas, _size_diff) = self
                    .write_log_mut()
                    .delete(key)
                    .into_storage_result()?;
                self.charge_gas(gas).into_storage_result()?;
                Ok(())
            }
        }
    };
}

// Note: `FullAccessState` writes to a write-log at block-level, while all the
// other `StorageWrite` impls write at tx-level.
macro_rules! impl_storage_write_by_protocol {
    ($($type:ty)*) => {
        impl<D, H> StorageWrite for $($type)*
        where
            D: 'static + DB + for<'iter> DBIter<'iter>,
            H: 'static + StorageHasher,
        {
            fn write_bytes(
                &mut self,
                key: &storage::Key,
                val: impl AsRef<[u8]>,
            ) -> namada_storage::Result<()> {
                self
                    .write_log_mut()
                    .protocol_write(key, val.as_ref().to_vec())
                    .into_storage_result()?;
                Ok(())
            }

            fn delete(&mut self, key: &storage::Key) -> namada_storage::Result<()> {
                self
                    .write_log_mut()
                    .protocol_delete(key)
                    .into_storage_result()?;
                Ok(())
            }
        }
    };
}

impl_storage_read!(FullAccessState<D, H>);
impl_storage_read!(WlState<D, H>);
impl_storage_read!(TempWlState<'_, D, H>);
impl_storage_read!(TxWlState<'_, D, H>);
impl_storage_write_by_protocol!(FullAccessState<D, H>);
impl_storage_write_by_protocol!(WlState<D, H>);
impl_storage_write_by_protocol!(TempWlState<'_, D, H>);
impl_storage_write!(TxWlState<'_, D, H>);

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum StateError {
    #[error("Merkle tree at the height {height} is not stored")]
    NoMerkleTree { height: BlockHeight },
    #[error("{0}")]
    Gas(namada_gas::Error),
}

impl From<StateError> for Error {
    fn from(value: StateError) -> Self {
        Error::new(value)
    }
}

/// Prefix iterator for [`StorageRead`] implementations.
#[derive(Debug)]
pub struct PrefixIter<'iter, D>
where
    D: DB + DBIter<'iter>,
{
    /// Peekable storage iterator
    pub storage_iter: Peekable<<D as DBIter<'iter>>::PrefixIter>,
    /// Peekable write log iterator
    pub write_log_iter: Peekable<write_log::PrefixIter>,
}

/// Iterate write-log storage items prior to a tx execution, matching the
/// given prefix. Returns the iterator and gas cost.
pub fn iter_prefix_pre<'a, D>(
    // We cannot use e.g. `&'a State`, because it doesn't live long
    // enough - the lifetime of the `PrefixIter` must depend on the lifetime of
    // references to the `WriteLog` and `DB`.
    write_log: &'a WriteLog,
    db: &'a D,
    prefix: &storage::Key,
) -> namada_storage::Result<(PrefixIter<'a, D>, Gas)>
where
    D: DB + for<'iter> DBIter<'iter>,
{
    let storage_iter = db.iter_prefix(Some(prefix)).peekable();
    let write_log_iter = write_log.iter_prefix_pre(prefix).peekable();
    let len = prefix.len() as u64;
    Ok((
        PrefixIter::<D> {
            storage_iter,
            write_log_iter,
        },
        checked!(len * STORAGE_ACCESS_GAS_PER_BYTE)?.into(),
    ))
}

/// Iterate write-log storage items posterior to a tx execution, matching the
/// given prefix. Returns the iterator and gas cost.
pub fn iter_prefix_post<'a, D>(
    // We cannot use e.g. `&'a State`, because it doesn't live long
    // enough - the lifetime of the `PrefixIter` must depend on the lifetime of
    // references to the `WriteLog` and `DB`.
    write_log: &'a WriteLog,
    db: &'a D,
    prefix: &storage::Key,
) -> namada_storage::Result<(PrefixIter<'a, D>, Gas)>
where
    D: DB + for<'iter> DBIter<'iter>,
{
    let storage_iter = db.iter_prefix(Some(prefix)).peekable();
    let write_log_iter = write_log.iter_prefix_post(prefix).peekable();
    let len = prefix.len() as u64;
    Ok((
        PrefixIter::<D> {
            storage_iter,
            write_log_iter,
        },
        checked!(len * STORAGE_ACCESS_GAS_PER_BYTE)?.into(),
    ))
}

impl<'iter, D> Iterator for PrefixIter<'iter, D>
where
    D: DB + DBIter<'iter>,
{
    type Item = (String, Vec<u8>, Gas);

    fn next(&mut self) -> Option<Self::Item> {
        enum Next {
            ReturnWl { advance_storage: bool },
            ReturnStorage,
        }
        loop {
            let what: Next;
            {
                let storage_peeked = self.storage_iter.peek();
                let wl_peeked = self.write_log_iter.peek();
                match (storage_peeked, wl_peeked) {
                    (None, None) => return None,
                    (None, Some(_)) => {
                        what = Next::ReturnWl {
                            advance_storage: false,
                        };
                    }
                    (Some(_), None) => {
                        what = Next::ReturnStorage;
                    }
                    (Some((storage_key, _, _)), Some((wl_key, _))) => {
                        if wl_key <= storage_key {
                            what = Next::ReturnWl {
                                advance_storage: wl_key == storage_key,
                            };
                        } else {
                            what = Next::ReturnStorage;
                        }
                    }
                }
            }
            match what {
                Next::ReturnWl { advance_storage } => {
                    if advance_storage {
                        let _ = self.storage_iter.next();
                    }

                    if let Some((key, modification)) =
                        self.write_log_iter.next()
                    {
                        match modification {
                            write_log::StorageModification::Write { value } => {
                                let gas = value.len() as u64;
                                return Some((key, value, gas.into()));
                            }
                            write_log::StorageModification::InitAccount {
                                vp_code_hash,
                            } => {
                                let gas = vp_code_hash.len() as u64;
                                return Some((
                                    key,
                                    vp_code_hash.to_vec(),
                                    gas.into(),
                                ));
                            }
                            write_log::StorageModification::Delete => {
                                continue;
                            }
                        }
                    }
                }
                Next::ReturnStorage => {
                    if let Some(next) = self.storage_iter.next() {
                        return Some(next);
                    }
                }
            }
        }
    }
}

/// Helpers for testing components that depend on storage
#[cfg(any(test, feature = "testing"))]
pub mod testing {

    use std::num::NonZeroUsize;

    use clru::CLruCache;
    use namada_core::address;
    use namada_core::address::EstablishedAddressGen;
    use namada_core::time::DateTimeUtc;
    pub use namada_storage::testing::{PrefixIter, *};
    use namada_storage::tx_queue::ExpiredTxsQueue;
    use storage::types::CommitOnlyData;

    use super::mockdb::MockDB;
    use super::*;

    /// A full-access state with a `MockDB` nd sha256 hasher.
    pub type TestState = FullAccessState<MockDB, Sha256Hasher>;

    impl Default for TestState {
        fn default() -> Self {
            Self(WlState {
                write_log: Default::default(),
                db: MockDB::default(),
                in_mem: Default::default(),
                diff_key_filter: diff_all_keys,
            })
        }
    }

    fn diff_all_keys(_key: &storage::Key) -> bool {
        true
    }

    /// In memory State for testing.
    pub type InMemoryState = InMemory<Sha256Hasher>;

    impl Default for InMemoryState {
        fn default() -> Self {
            let chain_id = ChainId::default();
            let tree = MerkleTree::default();
            let block = BlockStorage {
                tree,
                height: BlockHeight::default(),
                epoch: Epoch::default(),
                pred_epochs: Epochs::default(),
                results: BlockResults::default(),
            };
            Self {
                chain_id,
                block,
                header: None,
                last_block: None,
                last_epoch: Epoch::default(),
                next_epoch_min_start_height: BlockHeight::default(),
                #[allow(clippy::disallowed_methods)]
                next_epoch_min_start_time: DateTimeUtc::now(),
                address_gen: EstablishedAddressGen::new(
                    "Test address generator seed",
                ),
                update_epoch_blocks_delay: None,
                tx_index: TxIndex::default(),
                conversion_state: ConversionState::default(),
                expired_txs_queue: ExpiredTxsQueue::default(),
                native_token: address::testing::nam(),
                ethereum_height: None,
                eth_events_queue: EthEventsQueue::default(),
                storage_read_past_height_limit: Some(1000),
                commit_only_data: CommitOnlyData::default(),
                block_proposals_cache: CLruCache::new(
                    NonZeroUsize::new(10).unwrap(),
                ),
            }
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{TimeZone, Utc};
    use merkle_tree::NO_DIFF_KEY_PREFIX;
    use namada_core::address::InternalAddress;
    use namada_core::borsh::{BorshDeserialize, BorshSerializeExt};
    use namada_core::keccak::KeccakHash;
    use namada_core::parameters::{EpochDuration, Parameters};
    use namada_core::storage::DbKeySeg;
    use namada_core::time::{self, DateTimeUtc, Duration};
    use proptest::prelude::*;
    use proptest::test_runner::Config;
    // Use `RUST_LOG=info` (or another tracing level) and `--nocapture` to
    // see `tracing` logs from tests
    use test_log::test;

    use super::testing::*;
    use super::*;

    prop_compose! {
        /// Setup test input data with arbitrary epoch duration, epoch start
        /// height and time, and a block height and time that are greater than
        /// the epoch start height and time, and the change to be applied to
        /// the epoch duration parameters.
        fn arb_and_epoch_duration_start_and_block()
        (
            start_height in 0..1000_u64,
            start_time in 0..10000_i64,
            min_num_of_blocks in 1..10_u64,
            min_duration in 1..100_i64,
        )
        (
            min_num_of_blocks in Just(min_num_of_blocks),
            min_duration in Just(min_duration),
            start_height in Just(start_height),
            start_time in Just(start_time),
            block_height in start_height + 1..(start_height + 2 * min_num_of_blocks),
            block_time in start_time + 1..(start_time + 2 * min_duration),
            // Delta will be applied on the `min_num_of_blocks` parameter
            min_blocks_delta in -(min_num_of_blocks as i64 - 1)..5,
            // Delta will be applied on the `min_duration` parameter
            min_duration_delta in -(min_duration - 1)..50,
        ) -> (EpochDuration, BlockHeight, DateTimeUtc, BlockHeight, DateTimeUtc,
                i64, i64) {
            let epoch_duration = EpochDuration {
                min_num_of_blocks,
                min_duration: Duration::seconds(min_duration).into(),
            };
            (epoch_duration,
                BlockHeight(start_height), Utc.timestamp_opt(start_time, 0).single().expect("expected valid timestamp").into(),
                BlockHeight(block_height), Utc.timestamp_opt(block_time, 0).single().expect("expected valid timestamp").into(),
                min_blocks_delta, min_duration_delta)
        }
    }

    proptest! {
        #![proptest_config(Config {
            cases: 10,
            .. Config::default()
        })]
        /// Test that:
        /// 1. When the minimum blocks have been created since the epoch
        ///    start height and minimum time passed since the epoch start time,
        ///    a new epoch must start.
        /// 2. When the epoch duration parameters change, the current epoch's
        ///    duration doesn't change, but the next one does.
        #[test]
        fn update_epoch_after_its_duration(
            (epoch_duration, start_height, start_time, block_height, block_time,
            min_blocks_delta, min_duration_delta)
            in arb_and_epoch_duration_start_and_block())
        {
            let mut state =TestState::default();
            state.in_mem_mut().next_epoch_min_start_height=
                        start_height + epoch_duration.min_num_of_blocks;
            state.in_mem_mut().next_epoch_min_start_time=
                        start_time + epoch_duration.min_duration;
            let mut parameters = Parameters {
                max_tx_bytes: 1024 * 1024,
                max_proposal_bytes: Default::default(),
                max_block_gas: 20_000_000,
                epoch_duration: epoch_duration.clone(),
                vp_allowlist: vec![],
                tx_allowlist: vec![],
                implicit_vp_code_hash: Some(Hash::zero()),
                epochs_per_year: 100,
                masp_epoch_multiplier: 2,
                masp_fee_payment_gas_limit: 20_000,
                gas_scale: 10_000_000,
                minimum_gas_price: BTreeMap::default(),
                is_native_token_transferable: true,
            };
            // Initialize pred_epochs to the current height
            let height = state.in_mem().block.height;
            state
                .in_mem_mut()
                .block
                .pred_epochs
                .new_epoch(height);

            let epoch_before = state.in_mem().last_epoch;
            assert_eq!(epoch_before, state.in_mem().block.epoch);

            // Try to apply the epoch update
            state.update_epoch(block_height, block_time, &parameters).unwrap();

            // Test for 1.
            if block_height.0 - start_height.0
                >= epoch_duration.min_num_of_blocks
                && time::duration_passed(
                    block_time,
                    start_time,
                    epoch_duration.min_duration,
                )
            {
                // Update will now be enqueued for 2 blocks in the future
                assert_eq!(state.in_mem().block.epoch, epoch_before);
                assert_eq!(state.in_mem().update_epoch_blocks_delay, Some(2));

                let block_height = block_height + 1;
                let block_time = block_time + Duration::seconds(1);
                state.update_epoch(block_height, block_time, &parameters).unwrap();
                assert_eq!(state.in_mem().block.epoch, epoch_before);
                assert_eq!(state.in_mem().update_epoch_blocks_delay, Some(1));

                let block_height = block_height + 1;
                let block_time = block_time + Duration::seconds(1);
                state.update_epoch(block_height, block_time, &parameters).unwrap();
                assert_eq!(state.in_mem().block.epoch, epoch_before.next());
                assert!(state.in_mem().update_epoch_blocks_delay.is_none());

                assert_eq!(state.in_mem().next_epoch_min_start_height,
                    block_height + epoch_duration.min_num_of_blocks);
                assert_eq!(state.in_mem().next_epoch_min_start_time,
                    block_time + epoch_duration.min_duration);
                assert_eq!(
                    state.in_mem().block.pred_epochs.get_epoch(BlockHeight(block_height.0 - 1)),
                    Some(epoch_before));
                assert_eq!(
                    state.in_mem().block.pred_epochs.get_epoch(block_height),
                    Some(epoch_before.next()));
            } else {
                assert!(state.in_mem().update_epoch_blocks_delay.is_none());
                assert_eq!(state.in_mem().block.epoch, epoch_before);
                assert_eq!(
                    state.in_mem().block.pred_epochs.get_epoch(BlockHeight(block_height.0 - 1)),
                    Some(epoch_before));
                assert_eq!(
                    state.in_mem().block.pred_epochs.get_epoch(block_height),
                    Some(epoch_before));
            }
            // Last epoch should only change when the block is committed
            assert_eq!(state.in_mem().last_epoch, epoch_before);

            // Update the epoch duration parameters
            parameters.epoch_duration.min_num_of_blocks =
                (parameters.epoch_duration.min_num_of_blocks as i64 + min_blocks_delta) as u64;
            let min_duration: i64 = parameters.epoch_duration.min_duration.0 as _;
            parameters.epoch_duration.min_duration =
                Duration::seconds(min_duration + min_duration_delta).into();

            // Test for 2.
            let epoch_before = state.in_mem().block.epoch;
            let height_of_update = state.in_mem().next_epoch_min_start_height.0 ;
            let time_of_update = state.in_mem().next_epoch_min_start_time;
            let height_before_update = BlockHeight(height_of_update - 1);
            let height_of_update = BlockHeight(height_of_update);
            let time_before_update = time_of_update - Duration::seconds(1);

            // No update should happen before both epoch duration conditions are
            // satisfied
            state.update_epoch(height_before_update, time_before_update, &parameters).unwrap();
            assert_eq!(state.in_mem().block.epoch, epoch_before);
            assert!(state.in_mem().update_epoch_blocks_delay.is_none());
            state.update_epoch(height_of_update, time_before_update, &parameters).unwrap();
            assert_eq!(state.in_mem().block.epoch, epoch_before);
            assert!(state.in_mem().update_epoch_blocks_delay.is_none());
            state.update_epoch(height_before_update, time_of_update, &parameters).unwrap();
            assert_eq!(state.in_mem().block.epoch, epoch_before);
            assert!(state.in_mem().update_epoch_blocks_delay.is_none());

            // Update should be enqueued for 2 blocks in the future starting at or after this height and time
            state.update_epoch(height_of_update, time_of_update, &parameters).unwrap();
            assert_eq!(state.in_mem().block.epoch, epoch_before);
            assert_eq!(state.in_mem().update_epoch_blocks_delay, Some(2));

            // Increment the block height and time to simulate new blocks now
            let height_of_update = height_of_update + 1;
            let time_of_update = time_of_update + Duration::seconds(1);
            state.update_epoch(height_of_update, time_of_update, &parameters).unwrap();
            assert_eq!(state.in_mem().block.epoch, epoch_before);
            assert_eq!(state.in_mem().update_epoch_blocks_delay, Some(1));

            let height_of_update = height_of_update + 1;
            let time_of_update = time_of_update + Duration::seconds(1);
            state.update_epoch(height_of_update, time_of_update, &parameters).unwrap();
            assert_eq!(state.in_mem().block.epoch, epoch_before.next());
            assert!(state.in_mem().update_epoch_blocks_delay.is_none());
            // The next epoch's minimum duration should change
            assert_eq!(state.in_mem().next_epoch_min_start_height,
                height_of_update + parameters.epoch_duration.min_num_of_blocks);
            assert_eq!(state.in_mem().next_epoch_min_start_time,
                time_of_update + parameters.epoch_duration.min_duration);

            // Increment the block height and time once more to make sure things reset
            let height_of_update = height_of_update + 1;
            let time_of_update = time_of_update + Duration::seconds(1);
            state.update_epoch(height_of_update, time_of_update, &parameters).unwrap();
            assert_eq!(state.in_mem().block.epoch, epoch_before.next());
        }
    }

    fn test_key_1() -> Key {
        Key::parse("testing1").unwrap()
    }

    fn test_key_2() -> Key {
        Key::parse("testing2").unwrap()
    }

    fn diff_key_filter(key: &Key) -> bool {
        key == &test_key_1()
    }

    #[test]
    fn test_writing_without_diffs() {
        let mut state = TestState::default();
        assert_eq!(state.in_mem().block.height.0, 0);

        (state.0.diff_key_filter) = diff_key_filter;

        let key1 = test_key_1();
        let val1 = 1u64;
        let key2 = test_key_2();
        let val2 = 2u64;

        // Standard write of key-val-1
        state.write(&key1, val1).unwrap();

        // Read from State should return val1
        let res = state.read::<u64>(&key1).unwrap().unwrap();
        assert_eq!(res, val1);

        // Read from DB shouldn't return val1 bc the block hasn't been
        // committed
        let (res, _) = state.db_read(&key1).unwrap();
        assert!(res.is_none());

        // Write key-val-2 without merklizing or diffs
        state.write(&key2, val2).unwrap();

        // Read from state should return val2
        let res = state.read::<u64>(&key2).unwrap().unwrap();
        assert_eq!(res, val2);

        // Commit block and storage changes
        state.pre_commit_block().unwrap();
        state.commit_block().unwrap();
        state.in_mem_mut().block.height =
            state.in_mem().block.height.next_height();

        // Read key1 from DB should return val1
        let (res1, _) = state.db_read(&key1).unwrap();
        let res1 = u64::try_from_slice(&res1.unwrap()).unwrap();
        assert_eq!(res1, val1);

        // Check merkle tree inclusion of key-val-1 explicitly
        let is_merklized1 = state.in_mem().block.tree.has_key(&key1).unwrap();
        assert!(is_merklized1);

        // Key2 should be in storage. Confirm by reading from
        // state and also by reading DB subspace directly
        let res2 = state.read::<u64>(&key2).unwrap().unwrap();
        assert_eq!(res2, val2);
        let res2 = state.db().read_subspace_val(&key2).unwrap().unwrap();
        let res2 = u64::try_from_slice(&res2).unwrap();
        assert_eq!(res2, val2);

        // Check merkle tree inclusion of key-val-2 explicitly
        let is_merklized2 = state.in_mem().block.tree.has_key(&key2).unwrap();
        assert!(!is_merklized2);
        let no_diff_key2 =
            Key::from(NO_DIFF_KEY_PREFIX.to_string().to_db_key()).join(&key2);
        let is_merklized2 =
            state.in_mem().block.tree.has_key(&no_diff_key2).unwrap();
        assert!(is_merklized2);

        // Check that the proper diffs exist for key-val-1
        let res1 = state
            .db()
            .read_diffs_val(&key1, Default::default(), true)
            .unwrap();
        assert!(res1.is_none());

        let res1 = state
            .db()
            .read_diffs_val(&key1, Default::default(), false)
            .unwrap()
            .unwrap();
        let res1 = u64::try_from_slice(&res1).unwrap();
        assert_eq!(res1, val1);

        // Check that there are diffs for key-val-2 in block 0, since all keys
        // need to have diffs for at least 1 block for rollback purposes
        let res2 = state
            .db()
            .read_diffs_val(&key2, BlockHeight(0), true)
            .unwrap();
        assert!(res2.is_none());
        let res2 = state
            .db()
            .read_diffs_val(&key2, BlockHeight(0), false)
            .unwrap()
            .unwrap();
        let res2 = u64::try_from_slice(&res2).unwrap();
        assert_eq!(res2, val2);

        // Now delete the keys properly
        state.delete(&key1).unwrap();
        state.delete(&key2).unwrap();

        // Commit the block again
        state.pre_commit_block().unwrap();
        state.commit_block().unwrap();
        state.in_mem_mut().block.height =
            state.in_mem().block.height.next_height();

        // Check the key-vals are removed from the storage subspace
        let res1 = state.read::<u64>(&key1).unwrap();
        let res2 = state.read::<u64>(&key2).unwrap();
        assert!(res1.is_none() && res2.is_none());
        let res1 = state.db().read_subspace_val(&key1).unwrap();
        let res2 = state.db().read_subspace_val(&key2).unwrap();
        assert!(res1.is_none() && res2.is_none());

        // Check that the key-vals don't exist in the merkle tree anymore
        let is_merklized1 = state.in_mem().block.tree.has_key(&key1).unwrap();
        let is_merklized2 =
            state.in_mem().block.tree.has_key(&no_diff_key2).unwrap();
        assert!(!is_merklized1 && !is_merklized2);

        // Check that key-val-1 diffs are properly updated for blocks 0 and 1
        let res1 = state
            .db()
            .read_diffs_val(&key1, BlockHeight(0), true)
            .unwrap();
        assert!(res1.is_none());

        let res1 = state
            .db()
            .read_diffs_val(&key1, BlockHeight(0), false)
            .unwrap()
            .unwrap();
        let res1 = u64::try_from_slice(&res1).unwrap();
        assert_eq!(res1, val1);

        let res1 = state
            .db()
            .read_diffs_val(&key1, BlockHeight(1), true)
            .unwrap()
            .unwrap();
        let res1 = u64::try_from_slice(&res1).unwrap();
        assert_eq!(res1, val1);

        let res1 = state
            .db()
            .read_diffs_val(&key1, BlockHeight(1), false)
            .unwrap();
        assert!(res1.is_none());

        // Check that key-val-2 diffs don't exist for block 0 anymore
        let res2 = state
            .db()
            .read_diffs_val(&key2, BlockHeight(0), true)
            .unwrap();
        assert!(res2.is_none());
        let res2 = state
            .db()
            .read_diffs_val(&key2, BlockHeight(0), false)
            .unwrap();
        assert!(res2.is_none());

        // Check that the block 1 diffs for key-val-2 include an "old" value of
        // val2 and no "new" value
        let res2 = state
            .db()
            .read_diffs_val(&key2, BlockHeight(1), true)
            .unwrap()
            .unwrap();
        let res2 = u64::try_from_slice(&res2).unwrap();
        assert_eq!(res2, val2);
        let res2 = state
            .db()
            .read_diffs_val(&key2, BlockHeight(1), false)
            .unwrap();
        assert!(res2.is_none());
    }

    proptest! {
        // Generate arb valid input for `test_prefix_iters_aux`
        #![proptest_config(Config {
            cases: 10,
            .. Config::default()
        })]
        #[test]
        fn test_prefix_iters(
            key_vals in arb_key_vals(30),
        ) {
            test_prefix_iters_aux(key_vals)
        }
    }

    /// Check the `prefix_iter_pre` and `prefix_iter_post` return expected
    /// values, generated in the input to this function
    fn test_prefix_iters_aux(kvs: Vec<KeyVal<i8>>) {
        let mut s = TestState::default();

        // Partition the tx and storage kvs
        let (tx_kvs, rest): (Vec<_>, Vec<_>) = kvs
            .into_iter()
            .partition(|(_key, val)| matches!(val, Level::TxWriteLog(_)));
        // Partition the kvs to only apply block level first
        let (block_kvs, storage_kvs): (Vec<_>, Vec<_>) = rest
            .into_iter()
            .partition(|(_key, val)| matches!(val, Level::BlockWriteLog(_)));

        // Apply the kvs in order of the levels
        apply_to_state(&mut s, &storage_kvs);
        apply_to_state(&mut s, &block_kvs);
        apply_to_state(&mut s, &tx_kvs);

        // Collect the expected values in prior state - storage level then block
        let mut expected_pre = BTreeMap::new();
        for (key, val) in storage_kvs {
            if let Level::Storage(val) = val {
                expected_pre.insert(key, val);
            }
        }
        for (key, val) in &block_kvs {
            if let Level::BlockWriteLog(WlMod::Write(val)) = val {
                expected_pre.insert(key.clone(), *val);
            }
        }
        for (key, val) in &block_kvs {
            // Deletes have to be applied last
            if let Level::BlockWriteLog(WlMod::Delete) = val {
                expected_pre.remove(key);
            } else if let Level::BlockWriteLog(WlMod::DeletePrefix) = val {
                expected_pre.retain(|expected_key, _val| {
                    // Remove matching prefixes except for VPs
                    expected_key.is_validity_predicate().is_some()
                        || expected_key.split_prefix(key).is_none()
                })
            }
        }

        // Collect the values from prior state prefix iterator
        let (iter_pre, _gas) =
            iter_prefix_pre(s.write_log(), s.db(), &storage::Key::default())
                .unwrap();
        let mut read_pre = BTreeMap::new();
        for (key, val, _gas) in iter_pre {
            let key = storage::Key::parse(key).unwrap();
            let val: i8 = BorshDeserialize::try_from_slice(&val).unwrap();
            read_pre.insert(key, val);
        }

        // A helper for dbg
        let keys_to_string = |kvs: &BTreeMap<storage::Key, i8>| {
            kvs.iter()
                .map(|(key, val)| (key.to_string(), *val))
                .collect::<Vec<_>>()
        };
        dbg!(keys_to_string(&expected_pre), keys_to_string(&read_pre));
        // Clone the prior expected kvs for posterior state check
        let mut expected_post = expected_pre.clone();
        itertools::assert_equal(expected_pre, read_pre);

        // Collect the expected values in posterior state - all the levels
        for (key, val) in &tx_kvs {
            if let Level::TxWriteLog(WlMod::Write(val)) = val {
                expected_post.insert(key.clone(), *val);
            }
        }
        for (key, val) in &tx_kvs {
            // Deletes have to be applied last
            if let Level::TxWriteLog(WlMod::Delete) = val {
                expected_post.remove(key);
            } else if let Level::TxWriteLog(WlMod::DeletePrefix) = val {
                expected_post.retain(|expected_key, _val| {
                    // Remove matching prefixes except for VPs
                    expected_key.is_validity_predicate().is_some()
                        || expected_key.split_prefix(key).is_none()
                })
            }
        }

        // Collect the values from posterior state prefix iterator
        let (iter_post, _gas) =
            iter_prefix_post(s.write_log(), s.db(), &storage::Key::default())
                .unwrap();
        let mut read_post = BTreeMap::new();
        for (key, val, _gas) in iter_post {
            let key = storage::Key::parse(key).unwrap();
            let val: i8 = BorshDeserialize::try_from_slice(&val).unwrap();
            read_post.insert(key, val);
        }
        dbg!(keys_to_string(&expected_post), keys_to_string(&read_post));
        itertools::assert_equal(expected_post, read_post);
    }

    fn apply_to_state(s: &mut TestState, kvs: &[KeyVal<i8>]) {
        // Apply writes first
        for (key, val) in kvs {
            match val {
                Level::TxWriteLog(WlMod::Delete | WlMod::DeletePrefix)
                | Level::BlockWriteLog(WlMod::Delete | WlMod::DeletePrefix) => {
                }
                Level::TxWriteLog(WlMod::Write(val)) => {
                    let _ = s
                        .write_log_mut()
                        .write(key, val.serialize_to_vec())
                        .unwrap();
                }
                Level::BlockWriteLog(WlMod::Write(val)) => {
                    s.write_log_mut()
                        // protocol only writes at block level
                        .protocol_write(key, val.serialize_to_vec())
                        .unwrap();
                }
                Level::Storage(val) => {
                    s.db_write(key, val.serialize_to_vec()).unwrap();
                }
            }
        }
        // Then apply deletions
        for (key, val) in kvs {
            match val {
                Level::TxWriteLog(WlMod::Delete) => {
                    let _ = s.write_log_mut().delete(key).unwrap();
                }
                Level::BlockWriteLog(WlMod::Delete) => {
                    s.delete(key).unwrap();
                }
                Level::TxWriteLog(WlMod::DeletePrefix) => {
                    // Find keys matching the prefix
                    let keys =
                        namada_storage::iter_prefix_bytes(s, key.clone())
                            .unwrap()
                            .map(|res| {
                                let (key, _val) = res.unwrap();
                                key
                            })
                            .collect::<Vec<storage::Key>>();
                    // Delete the matching keys
                    for key in keys {
                        // Skip validity predicates which cannot be deleted
                        if key.is_validity_predicate().is_none() {
                            let _ = s.write_log_mut().delete(&key).unwrap();
                        }
                    }
                }
                Level::BlockWriteLog(WlMod::DeletePrefix) => {
                    s.delete_prefix(key).unwrap();
                }
                _ => {}
            }
        }
    }

    /// WlStorage key written in the write log or storage
    type KeyVal<VAL> = (storage::Key, Level<VAL>);

    /// WlStorage write level
    #[derive(Clone, Copy, Debug)]
    enum Level<VAL> {
        TxWriteLog(WlMod<VAL>),
        BlockWriteLog(WlMod<VAL>),
        Storage(VAL),
    }

    /// Write log modification
    #[derive(Clone, Copy, Debug)]
    enum WlMod<VAL> {
        Write(VAL),
        Delete,
        DeletePrefix,
    }

    fn arb_key_vals(len: usize) -> impl Strategy<Value = Vec<KeyVal<i8>>> {
        // Start with some arb. storage key-vals
        let storage_kvs = prop::collection::vec(
            (storage::testing::arb_key(), any::<i8>()),
            1..len,
        )
        .prop_map(|kvs| {
            kvs.into_iter()
                .map(|(mut key, val)| {
                    if let DbKeySeg::AddressSeg(Address::Internal(
                        InternalAddress::EthBridgePool,
                    )) = key.segments[0]
                    {
                        // This is needed to be able to write this key to DB -
                        // the merkle tree's `BridgePoolTree::parse_key`
                        // requires a `KeccakHash` on the 2nd segment
                        key.segments.insert(
                            1,
                            DbKeySeg::StringSeg(
                                KeccakHash::default().to_string(),
                            ),
                        );
                    }
                    (key, Level::Storage(val))
                })
                .collect::<Vec<_>>()
        });

        // Select some indices to override in write log
        let overrides = prop::collection::vec(
            (any::<prop::sample::Index>(), any::<i8>(), any::<bool>()),
            1..len / 2,
        );

        // Select some indices to delete
        let deletes = prop::collection::vec(
            (any::<prop::sample::Index>(), any::<bool>()),
            1..len / 3,
        );

        // Select some indices to delete prefix
        let delete_prefix = prop::collection::vec(
            (
                any::<prop::sample::Index>(),
                any::<bool>(),
                // An arbitrary number of key segments to drop from a selected
                // key to obtain the prefix. Because `arb_key` generates `2..5`
                // segments, we can drop one less of its upper bound.
                (2_usize..4),
            ),
            1..len / 4,
        );

        // Combine them all together
        (storage_kvs, overrides, deletes, delete_prefix).prop_map(
            |(mut kvs, overrides, deletes, delete_prefix)| {
                for (ix, val, is_tx) in overrides {
                    let (key, _) = ix.get(&kvs);
                    let wl_mod = WlMod::Write(val);
                    let lvl = if is_tx {
                        Level::TxWriteLog(wl_mod)
                    } else {
                        Level::BlockWriteLog(wl_mod)
                    };
                    kvs.push((key.clone(), lvl));
                }
                for (ix, is_tx) in deletes {
                    let (key, _) = ix.get(&kvs);
                    // We have to skip validity predicate keys as they cannot be
                    // deleted
                    if key.is_validity_predicate().is_some() {
                        continue;
                    }
                    let wl_mod = WlMod::Delete;
                    let lvl = if is_tx {
                        Level::TxWriteLog(wl_mod)
                    } else {
                        Level::BlockWriteLog(wl_mod)
                    };
                    kvs.push((key.clone(), lvl));
                }
                for (ix, is_tx, num_of_seg_to_drop) in delete_prefix {
                    let (key, _) = ix.get(&kvs);
                    let wl_mod = WlMod::DeletePrefix;
                    let lvl = if is_tx {
                        Level::TxWriteLog(wl_mod)
                    } else {
                        Level::BlockWriteLog(wl_mod)
                    };
                    // Keep at least one segment
                    let num_of_seg_to_keep = std::cmp::max(
                        1,
                        key.segments
                            .len()
                            .checked_sub(num_of_seg_to_drop)
                            .unwrap_or_default(),
                    );
                    let prefix = storage::Key {
                        segments: key
                            .segments
                            .iter()
                            .take(num_of_seg_to_keep)
                            .cloned()
                            .collect(),
                    };
                    kvs.push((prefix, lvl));
                }
                kvs
            },
        )
    }
}
