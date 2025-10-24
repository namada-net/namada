use std::cmp::Ordering;
use std::ops::{Deref, DerefMut};

use itertools::Either;
use namada_core::address::Address;
use namada_core::arith::checked;
use namada_core::borsh::BorshSerializeExt;
use namada_core::chain::ChainId;
use namada_core::masp::MaspEpoch;
use namada_core::parameters::{EpochDuration, Parameters};
use namada_core::time::DateTimeUtc;
use namada_core::{decode, storage};
use namada_events::{EmitEvents, EventToEmit};
use namada_gas::Gas;
use namada_merkle_tree::NO_DIFF_KEY_PREFIX;
use namada_replay_protection as replay_protection;
use namada_storage::conversion_state::{
    ConversionState, ReadConversionState, WithConversionState,
};
use namada_storage::{
    BlockHeight, BlockStateRead, BlockStateWrite, ResultExt, StorageRead,
};

use crate::in_memory::InMemory;
use crate::write_log::{StorageModification, WriteLog};
use crate::{
    DB, DBIter, EPOCH_SWITCH_BLOCKS_DELAY, Epoch, Error, Hash, Key, KeySeg,
    LastBlock, MembershipProof, MerkleTree, MerkleTreeError, ProofOps, Result,
    STORAGE_ACCESS_GAS_PER_BYTE, State, StateError, StateRead, StorageHasher,
    StoreType, TxWrites, is_pending_transfer_key,
};

/// Owned state with full R/W access.
#[derive(Debug)]
pub struct FullAccessState<D, H>(pub(crate) WlState<D, H>)
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher;

/// State with a write-logged storage.
#[derive(Debug)]
pub struct WlState<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Write log
    pub(crate) write_log: WriteLog,
    /// DB (usually a MockDB or PersistentDB)
    /// In public API this is immutable in WlState (only mutable in
    /// `FullAccessState`).
    pub(crate) db: D,
    /// State in memory
    pub(crate) in_mem: InMemory<H>,
    /// Static diff storage key filter
    pub diff_key_filter: fn(&storage::Key) -> bool,
}

impl<D, H> ReadConversionState for WlState<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    fn conversion_state(&self) -> &ConversionState {
        self.in_mem.get_conversion_state()
    }
}

/// State with a temporary write log. This is used for dry-running txs and ABCI
/// prepare and processs proposal, which must not modify the actual state.
#[derive(Debug)]
pub struct TxWlState<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Write log
    pub(crate) write_log: &'a mut WriteLog,
    // DB
    pub(crate) db: &'a D,
    /// State
    pub(crate) in_mem: &'a InMemory<H>,
}

/// State with a temporary write log. This is used for dry-running txs and ABCI
/// prepare and processs proposal, which must not modify the actual state.
#[derive(Debug)]
pub struct TempWlState<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Write log
    pub(crate) write_log: WriteLog,
    // DB
    pub(crate) db: &'a D,
    /// State
    pub(crate) in_mem: &'a InMemory<H>,
}

impl<D, H> ReadConversionState for TempWlState<'_, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    fn conversion_state(&self) -> &ConversionState {
        self.in_mem.get_conversion_state()
    }
}

impl<D, H> FullAccessState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    /// Mutably borrow write-log
    pub fn write_log_mut(&mut self) -> &mut WriteLog {
        &mut self.0.write_log
    }

    /// Mutably borrow in-memory state
    pub fn in_mem_mut(&mut self) -> &mut InMemory<H> {
        &mut self.0.in_mem
    }

    /// Mutably borrow DB handle
    pub fn db_mut(&mut self) -> &mut D {
        &mut self.0.db
    }

    /// Borrow state with mutable write-log.
    pub fn restrict_writes_to_write_log(&mut self) -> &mut WlState<D, H> {
        &mut self.0
    }

    /// Borrow read-only write-log and state
    pub fn read_only(&self) -> &WlState<D, H> {
        &self.0
    }

    /// Instantiate a full-access state. Loads the last state from a DB, if any.
    pub fn open(
        db_path: impl AsRef<std::path::Path>,
        cache: Option<&D::Cache>,
        chain_id: ChainId,
        native_token: Address,
        storage_read_past_height_limit: Option<u64>,
        diff_key_filter: fn(&storage::Key) -> bool,
    ) -> Self {
        let write_log = WriteLog::default();
        let db = D::open(db_path, cache);
        let in_mem = InMemory::new(
            chain_id,
            native_token,
            storage_read_past_height_limit,
        );
        let mut state = Self(WlState {
            write_log,
            db,
            in_mem,
            diff_key_filter,
        });
        state.load_last_state();
        state
    }

    /// Instantiate a full-access state. Loads the last state from a DB, if any.
    pub fn open_read_only(
        db_path: impl AsRef<std::path::Path>,
        cache: Option<&D::Cache>,
        chain_id: ChainId,
        native_token: Address,
        storage_read_past_height_limit: Option<u64>,
        diff_key_filter: fn(&storage::Key) -> bool,
    ) -> WlState<D, H> {
        let write_log = WriteLog::default();
        let db = D::open_read_only(db_path, cache);
        let in_mem = InMemory::new(
            chain_id,
            native_token,
            storage_read_past_height_limit,
        );
        let mut state = Self(WlState {
            write_log,
            db,
            in_mem,
            diff_key_filter,
        });
        state.load_last_state();
        let Self(read_only) = state;
        read_only
    }

    #[allow(dead_code)]
    /// Check if the given address exists on chain and return the gas cost.
    pub fn db_exists(&self, addr: &Address) -> Result<(bool, Gas)> {
        let key = storage::Key::validity_predicate(addr);
        self.db_has_key(&key)
    }

    /// Initialize a new epoch when the current epoch is finished. Returns
    /// `true` on a new epoch.
    pub fn update_epoch(
        &mut self,
        height: BlockHeight,
        time: DateTimeUtc,
        parameters: &Parameters,
    ) -> Result<bool> {
        match self.in_mem.update_epoch_blocks_delay.as_mut() {
            None => {
                // Check if the new epoch minimum start height and start time
                // have been fulfilled. If so, queue the next
                // epoch to start two blocks into the future so
                // as to align validator set updates + etc with
                // tendermint. This is because tendermint has a two block delay
                // to validator changes.
                let current_epoch_duration_satisfied = height
                    >= self.in_mem.next_epoch_min_start_height
                    && time >= self.in_mem.next_epoch_min_start_time;
                if current_epoch_duration_satisfied {
                    self.in_mem.update_epoch_blocks_delay =
                        Some(EPOCH_SWITCH_BLOCKS_DELAY);
                }
            }
            Some(blocks_until_switch) => {
                *blocks_until_switch = checked!(blocks_until_switch - 1)?;
            }
        };
        let new_epoch =
            matches!(self.in_mem.update_epoch_blocks_delay, Some(0));

        if new_epoch {
            // Reset the delay tracker
            self.in_mem.update_epoch_blocks_delay = None;

            // Begin a new epoch
            self.in_mem.block.epoch = self.in_mem.block.epoch.next();
            let EpochDuration {
                min_num_of_blocks,
                min_duration,
            } = parameters.epoch_duration;
            self.in_mem.next_epoch_min_start_height = height
                .checked_add(min_num_of_blocks)
                .expect("Next epoch min block height shouldn't overflow");
            // Time must not overflow
            #[allow(clippy::arithmetic_side_effects)]
            {
                self.in_mem.next_epoch_min_start_time = time + min_duration;
            }

            self.in_mem.block.pred_epochs.new_epoch(height);
            tracing::info!("Began a new epoch {}", self.in_mem.block.epoch);
        }

        Ok(new_epoch)
    }

    /// Returns `true` if a new masp epoch has begun
    pub fn is_masp_new_epoch(
        &self,
        is_new_epoch: bool,
        masp_epoch_multiplier: u64,
    ) -> Result<bool> {
        let masp_new_epoch = is_new_epoch
            && matches!(
                self.in_mem.block.epoch.checked_rem(masp_epoch_multiplier),
                Some(Epoch(0))
            );

        if masp_new_epoch {
            let masp_epoch = MaspEpoch::try_from_epoch(
                self.in_mem.block.epoch,
                masp_epoch_multiplier,
            )
            .map_err(namada_storage::Error::new_const)?;
            tracing::info!("Began a new masp epoch {masp_epoch}");
        }

        Ok(masp_new_epoch)
    }

    /// Commit the current block's write log to the storage and commit the block
    /// to DB. Starts a new block write log.
    pub fn commit_block(&mut self) -> Result<()> {
        let mut batch = D::batch();
        self.commit_write_log_block(&mut batch)
            .into_storage_result()?;
        self.commit_block_from_batch(batch).into_storage_result()?;

        // Clear the tx gas map
        self.in_mem.commit_only_data.tx_gas = Default::default();

        Ok(())
    }

    /// Pre-commit the current block's write log to the pre-commit merkle tree.
    pub fn pre_commit_block(&mut self) -> Result<()> {
        if self.in_mem.last_epoch != self.in_mem.block.epoch {
            self.in_mem_mut()
                .update_epoch_in_merkle_tree()
                .into_storage_result()?;
        }

        self.pre_commit_write_log_block().into_storage_result()?;
        self.commit_only_data()?;

        Ok(())
    }

    /// Commit the current block's write log to the storage. Starts a new block
    /// write log.
    pub fn commit_write_log_block(
        &mut self,
        batch: &mut D::WriteBatch,
    ) -> Result<()> {
        for (key, entry) in
            std::mem::take(&mut self.0.write_log.block_write_log).into_iter()
        {
            match entry {
                StorageModification::Write { value } => {
                    self.batch_write_subspace_val(batch, &key, value)?;
                }
                StorageModification::Delete => {
                    self.batch_delete_subspace_val(batch, &key)?;
                }
                StorageModification::InitAccount { vp_code_hash } => {
                    self.batch_write_subspace_val(batch, &key, vp_code_hash)?;
                }
            }
        }
        debug_assert!(self.0.write_log.block_write_log.is_empty());

        // Replay protections specifically. Starts with moving the current
        // hashes from the previous block to the general bucket
        self.move_current_replay_protection_entries(batch)?;

        let replay_prot_key = replay_protection::commitment_key();
        let commitment: Hash = self
            .read(&replay_prot_key)
            .expect("Could not read db")
            .unwrap_or_default();
        let new_commitment =
            std::mem::take(&mut self.0.write_log.replay_protection)
                .iter()
                .try_fold(commitment, |mut acc, hash| {
                    self.write_replay_protection_entry(
                        batch,
                        &replay_protection::current_key(hash),
                    )?;
                    acc = acc.concat(hash);
                    Ok::<_, Error>(acc)
                })?;
        self.batch_write_subspace_val(batch, &replay_prot_key, new_commitment)?;

        debug_assert!(self.0.write_log.replay_protection.is_empty());

        if let Some(address_gen) = self.0.write_log.block_address_gen.take() {
            self.0.in_mem.address_gen = address_gen
        }
        Ok(())
    }

    /// Pre-commit the current block's write log to the pre-commit merkle tree
    pub fn pre_commit_write_log_block(&mut self) -> Result<()> {
        let block_height = self.in_mem.block.height;
        for (key, entry) in self.0.write_log.block_write_log.iter() {
            let persist_diffs = (self.diff_key_filter)(key);
            match entry {
                StorageModification::Write { value } => {
                    Self::pre_commit_write_subspace_val(
                        &mut self.0.in_mem.block.tree,
                        block_height,
                        key,
                        value,
                        persist_diffs,
                    )?;
                }
                StorageModification::Delete => {
                    Self::pre_commit_delete_subspace_val(
                        &mut self.0.in_mem.block.tree,
                        key,
                        persist_diffs,
                    )?;
                }
                StorageModification::InitAccount { vp_code_hash } => {
                    Self::pre_commit_write_subspace_val(
                        &mut self.0.in_mem.block.tree,
                        block_height,
                        key,
                        vp_code_hash,
                        persist_diffs,
                    )?;
                }
            }
        }

        let replay_prot_key = replay_protection::commitment_key();
        let commitment: Hash = self
            .read(&replay_prot_key)
            .expect("Could not read db")
            .unwrap_or_default();
        let new_commitment = self
            .0
            .write_log
            .replay_protection
            .iter()
            .fold(commitment, |acc, hash| acc.concat(hash));
        let persist_diffs = (self.diff_key_filter)(&replay_prot_key);
        Self::pre_commit_write_subspace_val(
            &mut self.0.in_mem.block.tree,
            self.0.in_mem.block.height,
            &replay_prot_key,
            new_commitment,
            persist_diffs,
        )?;

        Ok(())
    }

    /// Start write batch.
    pub fn batch() -> D::WriteBatch {
        D::batch()
    }

    /// Execute write batch.
    pub fn exec_batch(&mut self, batch: D::WriteBatch) -> Result<()> {
        Ok(self.db.exec_batch(batch)?)
    }

    /// Batch write the value with the given height and account subspace key to
    /// the DB. Returns the size difference from previous value, if any, or
    /// the size of the value otherwise.
    pub fn batch_write_subspace_val(
        &mut self,
        batch: &mut D::WriteBatch,
        key: &Key,
        value: impl AsRef<[u8]>,
    ) -> Result<i64> {
        let value = value.as_ref();
        let persist_diffs = (self.diff_key_filter)(key);
        Ok(self.db.batch_write_subspace_val(
            batch,
            self.in_mem.block.height,
            key,
            value,
            persist_diffs,
        )?)
    }

    /// Batch delete the value with the given height and account subspace key
    /// from the DB. Returns the size of the removed value, if any, 0 if no
    /// previous value was found.
    pub fn batch_delete_subspace_val(
        &mut self,
        batch: &mut D::WriteBatch,
        key: &Key,
    ) -> Result<i64> {
        let persist_diffs = (self.diff_key_filter)(key);
        Ok(self.db.batch_delete_subspace_val(
            batch,
            self.in_mem.block.height,
            key,
            persist_diffs,
        )?)
    }

    /// Pre-commit write the value with the given height and account subspace
    /// key to the pre-commit merkle tree.
    pub fn pre_commit_write_subspace_val(
        tree: &mut MerkleTree<H>,
        block_height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
        persist_diffs: bool,
    ) -> Result<()> {
        let value = value.as_ref();

        if is_pending_transfer_key(key) {
            // The tree of the bridge pool stores the current height for the
            // pending transfer
            let height = block_height.serialize_to_vec();
            tree.update(key, height)?;
        } else {
            // Update the merkle tree
            if !persist_diffs {
                let prefix =
                    Key::from(NO_DIFF_KEY_PREFIX.to_string().to_db_key());
                tree.update(&prefix.join(key), value)?;
            } else {
                tree.update(key, value)?;
            };
        }
        Ok(())
    }

    /// Pre-commit delete the value with the given height and account subspace
    /// key from the pre-commit merkle tree.
    pub fn pre_commit_delete_subspace_val(
        tree: &mut MerkleTree<H>,
        key: &Key,
        persist_diffs: bool,
    ) -> Result<()> {
        // Update the merkle tree
        if !persist_diffs {
            let prefix = Key::from(NO_DIFF_KEY_PREFIX.to_string().to_db_key());
            tree.delete(&prefix.join(key))?;
        } else {
            tree.delete(key)?;
        }
        Ok(())
    }

    // Prune merkle tree stores. Use after updating self.block.height in the
    // commit.
    fn prune_merkle_tree_stores(
        &mut self,
        is_full_commit: bool,
        batch: &mut D::WriteBatch,
    ) -> Result<()> {
        if let Some(prev_height) = self
            .in_mem
            .block
            .height
            .prev_height()
            .and_then(|h| h.prev_height())
        {
            for st in StoreType::iter().filter(|st| st.is_stored_every_block())
            {
                match st {
                    StoreType::Base => continue,
                    _ => self.0.db.prune_merkle_tree_store(
                        batch,
                        st,
                        Either::Left(prev_height),
                    )?,
                }
            }
        }

        if !is_full_commit {
            return Ok(());
        }

        // Prune non-provable stores at the previous epoch
        if let Some(prev_epoch) = self.in_mem.block.epoch.prev() {
            for st in StoreType::iter_non_provable() {
                self.0.db.prune_merkle_tree_store(
                    batch,
                    st,
                    Either::Right(prev_epoch),
                )?;
            }
        }
        // Prune provable stores
        let oldest_epoch = self.in_mem.get_oldest_epoch();
        if oldest_epoch.0 > 0 {
            // Remove stores at the previous epoch because the Merkle tree
            // stores at the starting height of the epoch would be used to
            // restore stores at a height (> oldest_height) in the epoch
            for st in StoreType::iter_provable() {
                self.db.prune_merkle_tree_store(
                    batch,
                    st,
                    Either::Right(
                        oldest_epoch
                            .prev()
                            .expect("the previous epoch should exist"),
                    ),
                )?;
            }

            // Prune the BridgePool subtree stores with invalid nonce
            let mut epoch = match self.get_oldest_epoch_with_valid_nonce()? {
                Some(epoch) => epoch,
                None => return Ok(()),
            };
            while oldest_epoch < epoch {
                epoch = epoch.prev().unwrap();
                self.db.prune_merkle_tree_store(
                    batch,
                    &StoreType::BridgePool,
                    Either::Right(epoch),
                )?;
            }
        }

        Ok(())
    }

    /// Check it the given transaction's hash is already present in storage
    pub fn has_replay_protection_entry(&self, hash: &Hash) -> Result<bool> {
        Ok(self.db.has_replay_protection_entry(hash)?)
    }

    /// Write the provided tx hash to storage
    pub fn write_replay_protection_entry(
        &mut self,
        batch: &mut D::WriteBatch,
        key: &Key,
    ) -> Result<()> {
        self.db.write_replay_protection_entry(batch, key)?;
        Ok(())
    }

    /// Move the tx hashes from the current bucket to the general one
    pub fn move_current_replay_protection_entries(
        &mut self,
        batch: &mut D::WriteBatch,
    ) -> Result<()> {
        Ok(self.db.move_current_replay_protection_entries(batch)?)
    }

    /// Get oldest epoch which has the valid signed nonce of the bridge pool
    fn get_oldest_epoch_with_valid_nonce(&self) -> Result<Option<Epoch>> {
        let last_height = self.in_mem.get_last_block_height();
        let current_nonce = match self
            .db
            .read_bridge_pool_signed_nonce(last_height, last_height)?
        {
            Some(nonce) => nonce,
            None => return Ok(None),
        };
        let (mut epoch, _) = self.in_mem.get_last_epoch();
        // We don't need to check the older epochs because their Merkle tree
        // snapshots have been already removed
        let oldest_epoch = self.in_mem.get_oldest_epoch();
        // Look up the last valid epoch which has the previous nonce of the
        // current one. It has the previous nonce, but it was
        // incremented during the epoch.
        while 0 < epoch.0 && oldest_epoch <= epoch {
            epoch = epoch.prev().unwrap();
            let height = match self
                .in_mem
                .block
                .pred_epochs
                .get_start_height_of_epoch(epoch)
            {
                Some(h) => h,
                None => continue,
            };
            let nonce = match self
                .db
                .read_bridge_pool_signed_nonce(height, last_height)?
            {
                Some(nonce) => nonce,
                // skip pruning when the old epoch doesn't have the signed nonce
                None => break,
            };
            if nonce < current_nonce {
                break;
            }
        }
        Ok(Some(epoch))
    }

    /// Rebuild full Merkle tree after [`read_last_block()`]
    fn rebuild_full_merkle_tree(
        &self,
        height: BlockHeight,
    ) -> Result<MerkleTree<H>> {
        self.get_merkle_tree(height, None)
    }

    /// Load the full state at the last committed height, if any. Returns the
    /// Merkle root hash and the height of the committed block.
    pub fn load_last_state(&mut self) {
        if let Some(BlockStateRead {
            height,
            time,
            epoch,
            pred_epochs,
            next_epoch_min_start_height,
            next_epoch_min_start_time,
            update_epoch_blocks_delay,
            results,
            address_gen,
            conversion_state,
            ethereum_height,
            eth_events_queue,
            commit_only_data: _, /* Ignore the last tx gas map - we clear it
                                  * out after commit */
        }) = self
            .0
            .db
            .read_last_block()
            .expect("Read block call must not fail")
        {
            {
                let in_mem = &mut self.0.in_mem;
                in_mem.block.height = height;
                in_mem.block.epoch = epoch;
                in_mem.block.results = results;
                in_mem.block.pred_epochs = pred_epochs;
                in_mem.last_block = Some(LastBlock { height, time });
                in_mem.last_epoch = epoch;
                in_mem.next_epoch_min_start_height =
                    next_epoch_min_start_height;
                in_mem.next_epoch_min_start_time = next_epoch_min_start_time;
                in_mem.update_epoch_blocks_delay = update_epoch_blocks_delay;
                in_mem.address_gen = address_gen;
            }

            // Rebuild Merkle tree - requires the values above to be set first
            let tree = self
                .rebuild_full_merkle_tree(height)
                .expect("Merkle tree should be restored");

            tree.validate().unwrap();

            let in_mem = &mut self.0.in_mem;
            in_mem.block.tree = tree;
            in_mem.conversion_state = conversion_state;
            in_mem.ethereum_height = ethereum_height;
            in_mem.eth_events_queue = eth_events_queue;
            tracing::debug!("Loaded storage from DB");
        } else {
            tracing::info!("No state could be found");
        }
    }

    /// Commit the data from in-memory state into the block's merkle tree.
    pub fn commit_only_data(&mut self) -> Result<()> {
        let data = self.in_mem().commit_only_data.serialize();
        self.in_mem_mut()
            .block
            .tree
            .update_commit_data(data)
            .map_err(Into::into)
    }

    /// Persist the block's state from batch writes to the database.
    /// Note that unlike `commit_block` this method doesn't commit the write
    /// log.
    pub fn commit_block_from_batch(
        &mut self,
        mut batch: D::WriteBatch,
    ) -> Result<()> {
        // All states are written only when the first height or a new epoch
        let is_full_commit = self.is_full_commit();

        // For convenience in tests, fill-in a header if it's missing.
        // Normally, the header is added in `FinalizeBlock`.
        #[cfg(any(test, feature = "testing", feature = "benches"))]
        {
            if self.in_mem.header.is_none() {
                self.in_mem.header = Some(namada_core::chain::BlockHeader {
                    hash: Hash::default(),
                    #[allow(clippy::disallowed_methods)]
                    time: DateTimeUtc::now(),
                    next_validators_hash: Hash::default(),
                });
            }
        }

        let state = BlockStateWrite {
            merkle_tree_stores: self.in_mem.block.tree.stores(),
            header: self.in_mem.header.as_ref(),
            height: self.in_mem.block.height,
            time: self
                .in_mem
                .header
                .as_ref()
                .expect("Must have a block header on commit")
                .time,
            epoch: self.in_mem.block.epoch,
            results: &self.in_mem.block.results,
            pred_epochs: &self.in_mem.block.pred_epochs,
            next_epoch_min_start_height: self
                .in_mem
                .next_epoch_min_start_height,
            next_epoch_min_start_time: self.in_mem.next_epoch_min_start_time,
            update_epoch_blocks_delay: self.in_mem.update_epoch_blocks_delay,
            address_gen: &self.in_mem.address_gen,
            conversion_state: &self.in_mem.conversion_state,
            ethereum_height: self.in_mem.ethereum_height.as_ref(),
            eth_events_queue: &self.in_mem.eth_events_queue,
            commit_only_data: &self.in_mem.commit_only_data,
        };
        self.db
            .add_block_to_batch(state, &mut batch, is_full_commit)?;
        let header = self
            .in_mem
            .header
            .take()
            .expect("Must have a block header on commit");
        self.in_mem.last_block = Some(LastBlock {
            height: self.in_mem.block.height,
            time: header.time,
        });
        self.in_mem.last_epoch = self.in_mem.block.epoch;
        // prune old merkle tree stores
        self.prune_merkle_tree_stores(is_full_commit, &mut batch)?;
        // If there's a previous block, prune non-persisted diffs from it
        if let Some(height) = self.in_mem.block.height.prev_height() {
            self.db.prune_non_persisted_diffs(&mut batch, height)?;
        }
        self.db.exec_batch(batch)?;
        Ok(())
    }

    /// A full commit is executed only at the first height or one a new epoch.
    pub fn is_full_commit(&self) -> bool {
        self.in_mem.block.height.0 == 1
            || self.in_mem.last_epoch != self.in_mem.block.epoch
    }

    /// Update the merkle tree written for the committed last block
    pub fn update_last_block_merkle_tree(&self) -> Result<()> {
        let is_full_commit = self.is_full_commit();
        self.db.update_last_block_merkle_tree(
            self.in_mem.block.tree.stores(),
            is_full_commit,
        )?;
        Ok(())
    }
}

impl<D, H> WlState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    /// Borrow write-log
    pub fn write_log(&self) -> &WriteLog {
        &self.write_log
    }

    /// Borrow in-memory state
    pub fn in_mem(&self) -> &InMemory<H> {
        &self.in_mem
    }

    /// Mutably borrow in-memory state
    pub fn in_mem_mut(&mut self) -> &mut InMemory<H> {
        &mut self.in_mem
    }

    /// Borrow DB handle
    pub fn db(&self) -> &D {
        // NOTE: `WlState` must not be allowed mutable access to DB
        &self.db
    }

    /// Mutably borrow write-log
    pub fn write_log_mut(&mut self) -> &mut WriteLog {
        &mut self.write_log
    }

    /// Borrow in-memory state and DB handle with a mutable temporary write-log.
    pub fn with_temp_write_log(&self) -> TempWlState<'_, D, H> {
        TempWlState {
            write_log: WriteLog::default(),
            db: &self.db,
            in_mem: &self.in_mem,
        }
    }

    /// Borrow in-memory state and DB handle with a mutable temporary write-log.
    ///
    /// The lifetime of borrows is unsafely extended to `'static` to allow usage
    /// in node's `dry_run_tx`, which needs a static lifetime to be able to call
    /// protocol's API that is generic over the state with a bound `S: 'static +
    /// State` with a mutable reference to this struct.
    /// Because the lifetime of `S` is invariant w.r.t. `&mut S`
    /// (<https://doc.rust-lang.org/nomicon/subtyping.html>) we are faking a
    /// static lifetime of `S` for `TempWlState`.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that the source `WlState` is not being
    /// accessed mutably before `TempWlState` gets dropped.
    pub unsafe fn with_static_temp_write_log(
        &self,
    ) -> TempWlState<'static, D, H> {
        TempWlState {
            write_log: WriteLog::default(),
            db: unsafe { &*(&self.db as *const _) },
            in_mem: unsafe { &*(&self.in_mem as *const _) },
        }
    }

    /// Commit the current transaction's write log and the entire batch to the
    /// block. Starts a new transaction and batch write log.
    pub fn commit_tx_batch(&mut self) {
        self.write_log.commit_batch_and_current_tx()
    }

    /// Drop the current transaction's write log when it's declined by any of
    /// the triggered validity predicates together with the entire batch. Starts
    /// new transaction and batch write logs.
    pub fn drop_tx_batch(&mut self) {
        self.write_log.drop_batch()
    }

    /// Mark the provided transaction's hash as redundant to prevent committing
    /// it to storage.
    pub fn redundant_tx_hash(
        &mut self,
        hash: &Hash,
    ) -> crate::write_log::Result<()> {
        self.write_log.redundant_tx_hash(hash)
    }

    /// Get the height of the next block
    #[inline]
    pub fn get_current_decision_height(&self) -> BlockHeight {
        self.in_mem
            .get_last_block_height()
            .checked_add(1)
            .expect("Next height shouldn't overflow")
    }

    /// Check if we are at a given [`BlockHeight`] offset, `height_offset`,
    /// within the current epoch.
    pub fn is_deciding_offset_within_epoch(&self, height_offset: u64) -> bool {
        let current_decision_height = self.get_current_decision_height();

        let pred_epochs = &self.in_mem.block.pred_epochs;
        let fst_heights_of_each_epoch = pred_epochs.first_block_heights();

        fst_heights_of_each_epoch
            .last()
            .and_then(|&h| {
                let height_offset_within_epoch =
                    h.checked_add(height_offset)?;
                Some(current_decision_height == height_offset_within_epoch)
            })
            .unwrap_or(false)
    }

    /// Returns a value from the specified subspace at the given height (or the
    /// last committed height when 0) and the gas cost.
    pub fn db_read_with_height(
        &self,
        key: &storage::Key,
        height: BlockHeight,
    ) -> Result<(Option<Vec<u8>>, Gas)> {
        // `0` means last committed height
        if height == BlockHeight(0)
            || height >= self.in_mem().get_last_block_height()
        {
            self.db_read(key)
        } else {
            if !(self.diff_key_filter)(key) {
                return Ok((None, Gas::default()));
            }

            match self.db().read_subspace_val_with_height(
                key,
                height,
                self.in_mem().get_last_block_height(),
            )? {
                Some(v) => {
                    let gas = checked!(key.len() + v.len())? as u64;
                    Ok((
                        Some(v),
                        checked!(gas * STORAGE_ACCESS_GAS_PER_BYTE)?.into(),
                    ))
                }
                None => {
                    let gas = key.len() as u64;
                    Ok((
                        None,
                        checked!(gas * STORAGE_ACCESS_GAS_PER_BYTE)?.into(),
                    ))
                }
            }
        }
    }

    /// Write a value to the specified subspace and returns the gas cost and the
    /// size difference
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(any(test, feature = "testing", feature = "benches"))]
    pub fn db_write(
        &mut self,
        key: &Key,
        value: impl AsRef<[u8]>,
    ) -> Result<(u64, i64)> {
        // Note that this method is the same as `StorageWrite::write_bytes`,
        // but with gas and storage bytes len diff accounting
        tracing::debug!("storage write key {}", key,);
        let value = value.as_ref();
        let persist_diffs = (self.diff_key_filter)(key);

        if is_pending_transfer_key(key) {
            // The tree of the bright pool stores the current height for the
            // pending transfer
            let height = self.in_mem.block.height.serialize_to_vec();
            self.in_mem.block.tree.update(key, height)?;
        } else {
            // Update the merkle tree
            if !persist_diffs {
                let prefix =
                    Key::from(NO_DIFF_KEY_PREFIX.to_string().to_db_key());
                self.in_mem.block.tree.update(&prefix.join(key), value)?;
            } else {
                self.in_mem.block.tree.update(key, value)?;
            }
        }

        let len = value.len();
        let gas =
            (key.len() + len) as u64 * namada_gas::STORAGE_WRITE_GAS_PER_BYTE;
        let size_diff = self.db.write_subspace_val(
            self.in_mem.block.height,
            key,
            value,
            persist_diffs,
        )?;
        Ok((gas, size_diff))
    }

    /// Delete the specified subspace and returns the gas cost and the size
    /// difference
    #[allow(
        clippy::cast_sign_loss,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation
    )]
    #[cfg(any(test, feature = "testing", feature = "benches"))]
    pub fn db_delete(&mut self, key: &Key) -> Result<(u64, i64)> {
        // Note that this method is the same as `StorageWrite::delete`,
        // but with gas and storage bytes len diff accounting
        let mut deleted_bytes_len = 0;
        if self.db_has_key(key)?.0 {
            let persist_diffs = (self.diff_key_filter)(key);
            if !persist_diffs {
                let prefix =
                    Key::from(NO_DIFF_KEY_PREFIX.to_string().to_db_key());
                self.in_mem.block.tree.delete(&prefix.join(key))?;
            } else {
                self.in_mem.block.tree.delete(key)?;
            }
            deleted_bytes_len = self.db.delete_subspace_val(
                self.in_mem.block.height,
                key,
                persist_diffs,
            )?;
        }
        let gas = (key.len() + deleted_bytes_len as usize) as u64
            * namada_gas::STORAGE_WRITE_GAS_PER_BYTE;
        Ok((gas, deleted_bytes_len))
    }

    /// Get a Tendermint-compatible existence proof.
    ///
    /// Proofs from the Ethereum bridge pool are not
    /// Tendermint-compatible. Requesting for a key
    /// belonging to the bridge pool will cause this
    /// method to error.
    pub fn get_existence_proof(
        &self,
        key: &Key,
        value: namada_merkle_tree::StorageBytes<'_>,
        height: BlockHeight,
    ) -> Result<ProofOps> {
        use std::array;

        // `0` means last committed height
        let height = if height == BlockHeight(0) {
            self.in_mem.get_last_block_height()
        } else {
            height
        };

        if height > self.in_mem.get_last_block_height() {
            if let MembershipProof::ICS23(proof) =
                self.in_mem.block.tree.get_sub_tree_existence_proof(
                    array::from_ref(key),
                    vec![value],
                )?
            {
                self.in_mem
                    .block
                    .tree
                    .get_sub_tree_proof(key, proof)
                    .map(Into::into)
                    .map_err(Into::into)
            } else {
                Err(Error::from(MerkleTreeError::TendermintProof))
            }
        } else {
            let (store_type, _) = StoreType::sub_key(key)?;
            let tree = self.get_merkle_tree(height, Some(store_type))?;
            if let MembershipProof::ICS23(proof) = tree
                .get_sub_tree_existence_proof(
                    array::from_ref(key),
                    vec![value],
                )?
            {
                tree.get_sub_tree_proof(key, proof)
                    .map(Into::into)
                    .map_err(Into::into)
            } else {
                Err(Error::from(MerkleTreeError::TendermintProof))
            }
        }
    }

    /// Get the non-existence proof
    pub fn get_non_existence_proof(
        &self,
        key: &Key,
        height: BlockHeight,
    ) -> Result<ProofOps> {
        // `0` means last committed height
        let height = if height == BlockHeight(0) {
            self.in_mem.get_last_block_height()
        } else {
            height
        };

        if height > self.in_mem.get_last_block_height() {
            Err(Error::new_alloc(format!(
                "The block at the height {} hasn't committed yet",
                height,
            )))
        } else {
            let (store_type, _) = StoreType::sub_key(key)?;
            self.get_merkle_tree(height, Some(store_type))?
                .get_non_existence_proof(key)
                .map(Into::into)
                .map_err(Into::into)
        }
    }

    /// Rebuild Merkle tree with diffs in the DB.
    /// Base tree and the specified `store_type` subtree is rebuilt.
    /// If `store_type` isn't given, full Merkle tree is restored.
    pub fn get_merkle_tree(
        &self,
        height: BlockHeight,
        store_type: Option<StoreType>,
    ) -> Result<MerkleTree<H>> {
        // `0` means last committed height
        let height = if height == BlockHeight(0) {
            self.in_mem.get_last_block_height()
        } else {
            height
        };

        let epoch = self
            .in_mem
            .block
            .pred_epochs
            .get_epoch(height)
            .unwrap_or_default();
        let start_height = match store_type {
            // subtree is stored every height
            Some(st) if st.is_stored_every_block() => height,
            // others are stored at the first height of each epoch
            _ => match self
                .in_mem
                .block
                .pred_epochs
                .get_start_height_of_epoch(epoch)
            {
                Some(BlockHeight(0)) => BlockHeight(1),
                Some(height) => height,
                None => BlockHeight(1),
            },
        };
        // Try to read all subtrees, but some subtrees would be stale or empty.
        // They will be rebuild later. That's why the tree isn't validated here.
        let stores = self
            .db
            .read_merkle_tree_stores(epoch, start_height, store_type)?
            .ok_or(StateError::NoMerkleTree { height })?;
        let mut tree = MerkleTree::<H>::new_partial(stores);
        let prefix = store_type.and_then(|st| st.provable_prefix());
        // Restore the tree state with diffs
        let mut target_height = start_height;
        while target_height < height {
            target_height = target_height.next_height();
            let mut old_diff_iter =
                self.db.iter_old_diffs(target_height, prefix.as_ref());
            let mut new_diff_iter =
                self.db.iter_new_diffs(target_height, prefix.as_ref());

            let mut old_diff = old_diff_iter.next();
            let mut new_diff = new_diff_iter.next();
            loop {
                match (&old_diff, &new_diff) {
                    (Some(old), Some(new)) => {
                        let old_key = Key::parse(old.0.clone())
                            .expect("the key should be parsable");
                        let new_key = Key::parse(new.0.clone())
                            .expect("the key should be parsable");

                        // compare keys as String
                        match old.0.cmp(&new.0) {
                            Ordering::Equal => {
                                // the value was updated
                                tree.update(
                                    &new_key,
                                    if is_pending_transfer_key(&new_key) {
                                        target_height.serialize_to_vec()
                                    } else {
                                        new.1.clone()
                                    },
                                )?;
                                old_diff = old_diff_iter.next();
                                new_diff = new_diff_iter.next();
                            }
                            Ordering::Less => {
                                // the value was deleted
                                tree.delete(&old_key)?;
                                old_diff = old_diff_iter.next();
                            }
                            Ordering::Greater => {
                                // the value was inserted
                                tree.update(
                                    &new_key,
                                    if is_pending_transfer_key(&new_key) {
                                        target_height.serialize_to_vec()
                                    } else {
                                        new.1.clone()
                                    },
                                )?;
                                new_diff = new_diff_iter.next();
                            }
                        }
                    }
                    (Some(old), None) => {
                        // the value was deleted
                        let key = Key::parse(old.0.clone())
                            .expect("the key should be parsable");
                        tree.delete(&key)?;

                        old_diff = old_diff_iter.next();
                    }
                    (None, Some(new)) => {
                        // the value was inserted
                        let key = Key::parse(new.0.clone())
                            .expect("the key should be parsable");

                        tree.update(
                            &key,
                            if is_pending_transfer_key(&key) {
                                target_height.serialize_to_vec()
                            } else {
                                new.1.clone()
                            },
                        )?;

                        new_diff = new_diff_iter.next();
                    }
                    (None, None) => break,
                }
            }
        }

        // Restore the base tree and subtrees
        match store_type {
            Some(st) => {
                // It is enough to get the base tree
                let mut stores = self
                    .db
                    .read_merkle_tree_stores(
                        epoch,
                        height,
                        Some(StoreType::Base),
                    )?
                    .ok_or(StateError::NoMerkleTree { height })?;
                let restored_stores = tree.stores();
                stores.set_root(&st, *restored_stores.root(&st));
                stores.set_store(restored_stores.store(&st).to_owned());
                tree = MerkleTree::<H>::new_partial(stores);
            }
            None => {
                // Get the base and subtrees stored in every block
                let mut stores = self
                    .db
                    .read_merkle_tree_stores(epoch, height, None)?
                    .ok_or(StateError::NoMerkleTree { height })?;
                let restored_stores = tree.stores();
                // Set all rebuilt subtrees except for the subtrees stored in
                // every block
                for st in StoreType::iter_subtrees() {
                    if !st.is_stored_every_block() {
                        stores.set_root(st, *restored_stores.root(st));
                        stores.set_store(restored_stores.store(st).to_owned());
                    }
                }
                tree = MerkleTree::<H>::new(stores)?;
            }
        }
        Ok(tree)
    }

    /// Get the timestamp of the last committed block, or the current local
    /// timestamp if no blocks have been produced yet
    pub fn get_last_block_timestamp(&self) -> Result<DateTimeUtc> {
        let last_block_height = self.in_mem.get_last_block_height();

        Ok(self.db.read_block_header(last_block_height)?.map_or_else(
            #[allow(clippy::disallowed_methods)]
            DateTimeUtc::now,
            |header| header.time,
        ))
    }
}

impl<D, H> TempWlState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    /// Borrow write-log
    pub fn write_log(&self) -> &WriteLog {
        &self.write_log
    }

    /// Borrow in-memory state
    pub fn in_mem(&self) -> &InMemory<H> {
        self.in_mem
    }

    /// Borrow DB handle
    pub fn db(&self) -> &D {
        self.db
    }

    /// Mutably borrow write-log
    pub fn write_log_mut(&mut self) -> &mut WriteLog {
        &mut self.write_log
    }

    /// Check if the given tx hash has already been processed
    pub fn has_replay_protection_entry(&self, hash: &Hash) -> Result<bool> {
        if self.write_log.has_replay_protection_entry(hash) {
            return Ok(true);
        }

        self.db()
            .has_replay_protection_entry(hash)
            .map_err(Into::into)
    }

    /// Check if the given tx hash has already been committed to storage
    pub fn has_committed_replay_protection_entry(
        &self,
        hash: &Hash,
    ) -> Result<bool> {
        self.db()
            .has_replay_protection_entry(hash)
            .map_err(Into::into)
    }
}

impl<D, H> StateRead for FullAccessState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type D = D;
    type H = H;

    fn db(&self) -> &D {
        &self.0.db
    }

    fn in_mem(&self) -> &InMemory<Self::H> {
        &self.0.in_mem
    }

    fn write_log(&self) -> &WriteLog {
        &self.0.write_log
    }

    fn charge_gas(&self, _gas: Gas) -> Result<()> {
        Ok(())
    }
}

impl<D, H> State for FullAccessState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn write_log_mut(&mut self) -> &mut WriteLog {
        &mut self.0.write_log
    }

    fn split_borrow(
        &mut self,
    ) -> (&mut WriteLog, &InMemory<Self::H>, &Self::D) {
        (&mut self.0.write_log, &self.0.in_mem, &self.0.db)
    }
}

impl<D, H> EmitEvents for FullAccessState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    #[inline]
    fn emit<E>(&mut self, event: E)
    where
        E: EventToEmit,
    {
        self.write_log_mut().emit_event(event);
    }

    fn emit_many<B, E>(&mut self, event_batch: B)
    where
        B: IntoIterator<Item = E>,
        E: EventToEmit,
    {
        for event in event_batch {
            self.emit(event.into());
        }
    }
}

impl<D, H> ReadConversionState for FullAccessState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn conversion_state(&self) -> &ConversionState {
        &self.in_mem().conversion_state
    }
}

impl<D, H> WithConversionState for FullAccessState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn conversion_state_mut(&mut self) -> &mut ConversionState {
        &mut self.in_mem_mut().conversion_state
    }
}

impl<D, H> StateRead for WlState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type D = D;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        &self.write_log
    }

    fn db(&self) -> &D {
        &self.db
    }

    fn in_mem(&self) -> &InMemory<Self::H> {
        &self.in_mem
    }

    fn charge_gas(&self, _gas: Gas) -> Result<()> {
        Ok(())
    }
}

impl<D, H> State for WlState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn write_log_mut(&mut self) -> &mut WriteLog {
        &mut self.write_log
    }

    fn split_borrow(
        &mut self,
    ) -> (&mut WriteLog, &InMemory<Self::H>, &Self::D) {
        (&mut self.write_log, &self.in_mem, &self.db)
    }
}

impl<D, H> TxWrites for WlState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn with_tx_writes(&mut self) -> TxWlState<'_, Self::D, Self::H> {
        TxWlState {
            write_log: &mut self.write_log,
            db: &self.db,
            in_mem: &self.in_mem,
        }
    }
}

impl<D, H> StateRead for TxWlState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type D = D;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        self.write_log
    }

    fn db(&self) -> &D {
        self.db
    }

    fn in_mem(&self) -> &InMemory<Self::H> {
        self.in_mem
    }

    fn charge_gas(&self, _gas: Gas) -> Result<()> {
        Ok(())
    }
}

impl<D, H> State for TxWlState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn write_log_mut(&mut self) -> &mut WriteLog {
        self.write_log
    }

    fn split_borrow(
        &mut self,
    ) -> (&mut WriteLog, &InMemory<Self::H>, &Self::D) {
        (self.write_log, (self.in_mem), (self.db))
    }
}

impl<D, H> EmitEvents for WlState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    #[inline]
    fn emit<E>(&mut self, event: E)
    where
        E: EventToEmit,
    {
        self.write_log_mut().emit_event(event);
    }

    fn emit_many<B, E>(&mut self, event_batch: B)
    where
        B: IntoIterator<Item = E>,
        E: EventToEmit,
    {
        for event in event_batch {
            self.emit(event.into());
        }
    }
}

impl<D, H> StateRead for TempWlState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type D = D;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        &self.write_log
    }

    fn db(&self) -> &D {
        self.db
    }

    fn in_mem(&self) -> &InMemory<Self::H> {
        self.in_mem
    }

    fn charge_gas(&self, _gas: Gas) -> Result<()> {
        Ok(())
    }
}

impl<D, H> State for TempWlState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn write_log_mut(&mut self) -> &mut WriteLog {
        &mut self.write_log
    }

    fn split_borrow(
        &mut self,
    ) -> (&mut WriteLog, &InMemory<Self::H>, &Self::D) {
        (&mut self.write_log, (self.in_mem), (self.db))
    }
}

impl<D, H> TxWrites for TempWlState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn with_tx_writes(&mut self) -> TxWlState<'_, Self::D, Self::H> {
        TxWlState {
            write_log: &mut self.write_log,
            db: self.db,
            in_mem: self.in_mem,
        }
    }
}

impl<D, H> Deref for FullAccessState<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    type Target = WlState<D, H>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<D, H> DerefMut for FullAccessState<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(any(test, feature = "testing"))]
impl<D, H> namada_tx::action::Read for FullAccessState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type Err = Error;

    fn read_temp<T: namada_core::borsh::BorshDeserialize>(
        &self,
        key: &storage::Key,
    ) -> Result<Option<T>> {
        let (log_val, _) = self.write_log().read_temp(key).unwrap();
        match log_val {
            Some(value) => {
                let value = decode(value)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl<D, H> namada_tx::action::Write for FullAccessState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn write_temp<T: namada_core::borsh::BorshSerialize>(
        &mut self,
        key: &storage::Key,
        val: T,
    ) -> Result<()> {
        let _ = self
            .write_log_mut()
            .write_temp(key, val.serialize_to_vec())?;
        Ok(())
    }
}

impl<D, H> namada_tx::action::Read for WlState<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type Err = Error;

    fn read_temp<T: namada_core::borsh::BorshDeserialize>(
        &self,
        key: &storage::Key,
    ) -> Result<Option<T>> {
        let (log_val, _) = self.write_log().read_temp(key).unwrap();
        match log_val {
            Some(value) => {
                let value = decode(value)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}

impl<D, H> namada_tx::action::Read for TempWlState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type Err = Error;

    fn read_temp<T: namada_core::borsh::BorshDeserialize>(
        &self,
        key: &storage::Key,
    ) -> Result<Option<T>> {
        let (log_val, _) = self.write_log().read_temp(key).unwrap();
        match log_val {
            Some(value) => {
                let value = decode(value)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}
