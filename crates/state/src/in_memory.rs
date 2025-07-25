use std::num::NonZeroUsize;

use clru::CLruCache;
use namada_core::address::{Address, EstablishedAddressGen, InternalAddress};
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::chain::{BLOCK_HEIGHT_LENGTH, CHAIN_ID_LENGTH, ChainId};
use namada_core::hash::Hash;
use namada_core::parameters::{EpochDuration, Parameters};
use namada_core::time::DateTimeUtc;
use namada_core::{encode, ethereum_structs};
use namada_gas::{Gas, MEMORY_ACCESS_GAS_PER_BYTE};
use namada_macros::BorshDeserializer;
use namada_merkle_tree::{MerkleRoot, MerkleTree};
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_storage::conversion_state::ConversionState;
use namada_storage::tx_queue::ExpiredTxsQueue;
use namada_storage::types::CommitOnlyData;
use namada_storage::{
    BlockHeader, BlockHeight, BlockResults, EPOCH_TYPE_LENGTH, Epoch, Epochs,
    EthEventsQueue, Key, KeySeg, StorageHasher, TxIndex,
};

use crate::Result;

/// The ledger's state
#[derive(Debug)]
pub struct InMemory<H>
where
    H: StorageHasher,
{
    /// The ID of the chain
    pub chain_id: ChainId,
    /// The address of the native token - this is not stored in DB, but read
    /// from genesis
    pub native_token: Address,
    /// Block storage data
    pub block: BlockStorage<H>,
    /// During `FinalizeBlock`, this is the header of the block that is
    /// going to be committed. After a block is committed, this is reset to
    /// `None` until the next `FinalizeBlock` phase is reached.
    pub header: Option<BlockHeader>,
    /// The most recently committed block, if any.
    pub last_block: Option<LastBlock>,
    /// The epoch of the most recently committed block. If it is `Epoch(0)`,
    /// then no block may have been committed for this chain yet.
    pub last_epoch: Epoch,
    /// Minimum block height at which the next epoch may start
    pub next_epoch_min_start_height: BlockHeight,
    /// Minimum block time at which the next epoch may start
    pub next_epoch_min_start_time: DateTimeUtc,
    /// The current established address generator
    pub address_gen: EstablishedAddressGen,
    /// We delay the switch to a new epoch by the number of blocks set in here.
    /// This is `Some` when minimum number of blocks has been created and
    /// minimum time has passed since the beginning of the last epoch.
    /// Once the value is `Some(0)`, we're ready to switch to a new epoch and
    /// this is reset back to `None`.
    pub update_epoch_blocks_delay: Option<u32>,
    /// The shielded transaction index
    pub tx_index: TxIndex,
    /// The currently saved conversion state
    pub conversion_state: ConversionState,
    /// Queue of expired transactions that need to be retransmitted.
    ///
    /// These transactions do not need to be persisted, as they are
    /// retransmitted at the **COMMIT** phase immediately following
    /// the block when they were queued.
    pub expired_txs_queue: ExpiredTxsQueue,
    /// The latest block height on Ethereum processed, if
    /// the bridge is enabled.
    pub ethereum_height: Option<ethereum_structs::BlockHeight>,
    /// The queue of Ethereum events to be processed in order.
    pub eth_events_queue: EthEventsQueue,
    /// How many block heights in the past can the storage be queried
    pub storage_read_past_height_limit: Option<u64>,
    /// Data that needs to be committed to the merkle tree
    pub commit_only_data: CommitOnlyData,
    /// Cache of the results of process proposal for the next height to decide.
    /// A LRU cache is used to prevent consuming too much memory at times where
    /// a node cannot make progress and keeps evaluating new proposals. The
    /// different proposed blocks are indexed by their hash. This is used
    /// to avoid running process proposal more than once internally because of
    /// the shim or the recheck option (comet only calls it at most once
    /// for a given height/round)
    pub block_proposals_cache: CLruCache<Hash, ProcessProposalCachedResult>,
}

/// Last committed block
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshDeserializer)]
pub struct LastBlock {
    /// Block height
    pub height: BlockHeight,
    /// Block time
    pub time: DateTimeUtc,
}

/// The result of process proposal that can be cached for future lookup
#[must_use]
#[derive(Debug, Clone)]
pub enum ProcessProposalCachedResult {
    /// The proposed block was accepted by this node with the attached results
    /// for every included tx
    Accepted(Vec<(u32, String)>),
    /// The proposed block was rejected by this node
    Rejected,
}

/// The block storage data
#[derive(Debug)]
pub struct BlockStorage<H: StorageHasher> {
    /// Merkle tree of all the other data in block storage
    pub tree: MerkleTree<H>,
    /// From the start of `FinalizeBlock` until the end of `Commit`, this is
    /// height of the block that is going to be committed. Otherwise, it is the
    /// height of the most recently committed block, or `BlockHeight::sentinel`
    /// (0) if no block has been committed yet.
    pub height: BlockHeight,
    /// From the start of `FinalizeBlock` until the end of `Commit`, this is
    /// height of the block that is going to be committed. Otherwise it is the
    /// epoch of the most recently committed block, or `Epoch(0)` if no block
    /// has been committed yet.
    pub epoch: Epoch,
    /// Results of applying transactions
    pub results: BlockResults,
    /// Predecessor block epochs
    pub pred_epochs: Epochs,
}

impl<H> InMemory<H>
where
    H: StorageHasher,
{
    /// Create a new instance of the state
    pub fn new(
        chain_id: ChainId,
        native_token: Address,
        storage_read_past_height_limit: Option<u64>,
    ) -> Self {
        let block = BlockStorage {
            tree: MerkleTree::default(),
            height: BlockHeight::default(),
            epoch: Epoch::default(),
            pred_epochs: Epochs::default(),
            results: BlockResults::default(),
        };
        InMemory::<H> {
            chain_id,
            block,
            header: None,
            last_block: None,
            last_epoch: Epoch::default(),
            next_epoch_min_start_height: BlockHeight::default(),
            #[allow(clippy::disallowed_methods)]
            next_epoch_min_start_time: DateTimeUtc::now(),
            address_gen: EstablishedAddressGen::new(
                "Privacy is a function of liberty.",
            ),
            update_epoch_blocks_delay: None,
            tx_index: TxIndex::default(),
            conversion_state: ConversionState::default(),
            expired_txs_queue: ExpiredTxsQueue::default(),
            native_token,
            ethereum_height: None,
            eth_events_queue: EthEventsQueue::default(),
            storage_read_past_height_limit,
            commit_only_data: CommitOnlyData::default(),
            block_proposals_cache: CLruCache::new(
                NonZeroUsize::new(10).unwrap(),
            ),
        }
    }

    /// Returns the Merkle root hash and the height of the committed block. If
    /// no block exists, returns None.
    pub fn get_state(&self) -> Option<(MerkleRoot, u64)> {
        if self.block.height.0 != 0 {
            Some((self.block.tree.root(), self.block.height.0))
        } else {
            None
        }
    }

    /// Find the root hash of the merkle tree
    pub fn merkle_root(&self) -> MerkleRoot {
        self.block.tree.root()
    }

    /// Set the block header.
    /// The header is not in the Merkle tree as it's tracked by Tendermint.
    /// Hence, we don't update the tree when this is set.
    pub fn set_header(&mut self, header: BlockHeader) -> Result<()> {
        self.header = Some(header);
        Ok(())
    }

    /// Block data is in the Merkle tree as it's tracked by Tendermint in the
    /// block header. Hence, we don't update the tree when this is set.
    pub fn begin_block(&mut self, height: BlockHeight) -> Result<()> {
        self.block.height = height;
        Ok(())
    }

    /// Store in memory a total gas of a transaction with the given hash.
    pub fn add_tx_gas(&mut self, tx_hash: Hash, gas: Gas) {
        self.commit_only_data.tx_gas.insert(tx_hash, gas.into());
    }

    /// Get the chain ID as a raw string
    pub fn get_chain_id(&self) -> (ChainId, Gas) {
        // Adding consts that cannot overflow
        #[allow(clippy::arithmetic_side_effects)]
        (
            self.chain_id.clone(),
            (CHAIN_ID_LENGTH as u64 * MEMORY_ACCESS_GAS_PER_BYTE).into(),
        )
    }

    /// Get the block height. The height is that of the block to which the
    /// current transaction is being applied if we are in between the
    /// `FinalizeBlock` and the `Commit` phases. For all the other phases we
    /// return the block height of next block that the consensus process
    /// will decide upon (i.e. the block height of the last committed block
    /// + 1)
    pub fn get_block_height(&self) -> (BlockHeight, Gas) {
        let height = match self.header {
            Some(_) => self.block.height,
            // When not finalizing a decided block, increase the block height to
            // match that of the next block that will be proposed
            None => self.block.height.next_height(),
        };
        // Adding consts that cannot overflow
        #[allow(clippy::arithmetic_side_effects)]
        (
            height,
            (BLOCK_HEIGHT_LENGTH as u64 * MEMORY_ACCESS_GAS_PER_BYTE).into(),
        )
    }

    /// Get the current (yet to be committed) block epoch
    pub fn get_current_epoch(&self) -> (Epoch, Gas) {
        // Adding consts that cannot overflow
        #[allow(clippy::arithmetic_side_effects)]
        (
            self.block.epoch,
            (EPOCH_TYPE_LENGTH as u64 * MEMORY_ACCESS_GAS_PER_BYTE).into(),
        )
    }

    /// Get the epoch of the last committed block
    pub fn get_last_epoch(&self) -> (Epoch, Gas) {
        // Adding consts that cannot overflow
        #[allow(clippy::arithmetic_side_effects)]
        (
            self.last_epoch,
            (EPOCH_TYPE_LENGTH as u64 * MEMORY_ACCESS_GAS_PER_BYTE).into(),
        )
    }

    /// Initialize the first epoch. The first epoch begins at genesis time.
    pub fn init_genesis_epoch(
        &mut self,
        initial_height: BlockHeight,
        genesis_time: DateTimeUtc,
        parameters: &Parameters,
    ) -> Result<()> {
        let EpochDuration {
            min_num_of_blocks,
            min_duration,
        } = parameters.epoch_duration;
        self.next_epoch_min_start_height = initial_height
            .checked_add(min_num_of_blocks)
            .expect("Next epoch min block height shouldn't overflow");
        // Time must not overflow
        #[allow(clippy::arithmetic_side_effects)]
        {
            self.next_epoch_min_start_time = genesis_time + min_duration;
        }
        self.block.pred_epochs = Epochs {
            first_block_heights: vec![initial_height],
        };
        self.update_epoch_in_merkle_tree()
    }

    /// Get the current conversions
    pub fn get_conversion_state(&self) -> &ConversionState {
        &self.conversion_state
    }

    /// Update the merkle tree with epoch data
    pub fn update_epoch_in_merkle_tree(&mut self) -> Result<()> {
        let key_prefix: Key =
            Address::Internal(InternalAddress::PoS).to_db_key().into();

        let key = key_prefix.push(&"epoch_start_height".to_string())?;
        self.block
            .tree
            .update(&key, encode(&self.next_epoch_min_start_height))?;

        let key = key_prefix.push(&"epoch_start_time".to_string())?;
        self.block
            .tree
            .update(&key, encode(&self.next_epoch_min_start_time))?;

        let key = key_prefix.push(&"current_epoch".to_string())?;
        self.block.tree.update(&key, encode(&self.block.epoch))?;

        Ok(())
    }

    /// Get the height of the last committed block or 0 if no block has been
    /// committed yet. The first block is at height 1.
    pub fn get_last_block_height(&self) -> BlockHeight {
        self.last_block
            .as_ref()
            .map(|b| b.height)
            .unwrap_or_default()
    }

    /// Get the oldest epoch where we can read a value
    pub fn get_oldest_epoch(&self) -> Epoch {
        let oldest_height = match self.storage_read_past_height_limit {
            Some(limit) if limit < self.get_last_block_height().0 => (self
                .get_last_block_height()
                .0
                .checked_sub(limit)
                .expect("Cannot underflow"))
            .into(),
            _ => BlockHeight(1),
        };
        self.block
            .pred_epochs
            .get_epoch(oldest_height)
            .unwrap_or_default()
    }
}
