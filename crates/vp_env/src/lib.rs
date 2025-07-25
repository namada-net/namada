//! Validity predicate environment contains functions that can be called from
//! inside validity predicates.

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

pub mod collection_validation;

use namada_core::address::Address;
use namada_core::borsh::BorshDeserialize;
use namada_core::chain::ChainId;
pub use namada_core::chain::{BlockHeader, BlockHeight, Epoch, Epochs};
use namada_core::hash::Hash;
use namada_events::{Event, EventType};
use namada_gas::Gas;
pub use namada_storage::{Error, Key, Result, StorageRead, TxIndex};
use namada_tx::BatchedTxRef;

/// Validity predicate's environment is available for native VPs and WASM VPs
pub trait VpEnv<'view>
where
    Self: 'view,
{
    /// Storage read prefix iterator
    type PrefixIter<'iter>
    where
        Self: 'iter;

    /// Type to read storage state before the transaction execution
    type Pre: StorageRead<PrefixIter<'view> = Self::PrefixIter<'view>>;

    /// Type to read storage state after the transaction execution
    type Post: StorageRead<PrefixIter<'view> = Self::PrefixIter<'view>>;

    /// Read storage state before the transaction execution
    fn pre(&'view self) -> Self::Pre;

    /// Read storage state after the transaction execution
    fn post(&'view self) -> Self::Post;

    /// Storage read temporary state Borsh encoded value (after tx execution).
    /// It will try to read from only the write log and then decode it if
    /// found.
    fn read_temp<T: BorshDeserialize>(&self, key: &Key) -> Result<Option<T>>;

    /// Storage read temporary state raw bytes (after tx execution). It will try
    /// to read from only the write log.
    fn read_bytes_temp(&self, key: &Key) -> Result<Option<Vec<u8>>>;

    /// Getting the chain ID.
    fn get_chain_id(&self) -> Result<ChainId>;

    /// Getting the block height. The height is that of the block to which the
    /// current transaction is being applied if we are in between the
    /// `FinalizeBlock` and the `Commit` phases. For all the other phases we
    /// return the block height of next block that the consensus process
    /// will decide upon (i.e. the block height of the last committed block
    /// + 1)
    fn get_block_height(&self) -> Result<BlockHeight>;

    /// Getting the block header.
    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>>;

    /// Getting the block epoch. The epoch is that of the block to which the
    /// current transaction is being applied.
    fn get_block_epoch(&self) -> Result<Epoch>;

    /// Get the shielded transaction index.
    fn get_tx_index(&self) -> Result<TxIndex>;

    /// Get the address of the native token.
    fn get_native_token(&self) -> Result<Address>;

    /// Given the information about predecessor block epochs
    fn get_pred_epochs(&self) -> namada_storage::Result<Epochs>;

    /// Get the events emitted by the current tx.
    fn get_events(&self, event_type: &EventType) -> Result<Vec<Event>>;

    /// Storage prefix iterator, ordered by storage keys. It will try to get an
    /// iterator from the storage.
    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>>;

    /// Evaluate a validity predicate with given data. The address, changed
    /// storage keys and verifiers will have the same values as the input to
    /// caller's validity predicate.
    ///
    /// If the execution fails for whatever reason, this will return `false`.
    /// Otherwise returns the result of evaluation.
    fn eval(&self, vp_code: Hash, input_data: BatchedTxRef<'_>) -> Result<()>;

    /// Get a tx hash
    fn get_tx_code_hash(&self) -> Result<Option<Hash>>;

    /// Charge the provided gas for the current vp
    fn charge_gas(&self, used_gas: Gas) -> Result<()>;

    // ---- Methods below have default implementation via `pre/post` ----

    /// Storage read prior state Borsh encoded value (before tx execution). It
    /// will try to read from the storage and decode it if found.
    fn read_pre<T: BorshDeserialize>(
        &'view self,
        key: &Key,
    ) -> Result<Option<T>> {
        self.pre().read(key)
    }

    /// Storage read prior state raw bytes (before tx execution). It
    /// will try to read from the storage.
    fn read_bytes_pre(&'view self, key: &Key) -> Result<Option<Vec<u8>>> {
        self.pre().read_bytes(key)
    }

    /// Storage read posterior state Borsh encoded value (after tx execution).
    /// It will try to read from the write log first and if no entry found
    /// then from the storage and then decode it if found.
    fn read_post<T: BorshDeserialize>(
        &'view self,
        key: &Key,
    ) -> Result<Option<T>> {
        self.post().read(key)
    }

    /// Storage read posterior state raw bytes (after tx execution). It will try
    /// to read from the write log first and if no entry found then from the
    /// storage.
    fn read_bytes_post(&'view self, key: &Key) -> Result<Option<Vec<u8>>> {
        self.post().read_bytes(key)
    }

    /// Storage `has_key` in prior state (before tx execution). It will try to
    /// read from the storage.
    fn has_key_pre(&'view self, key: &Key) -> Result<bool> {
        self.pre().has_key(key)
    }

    /// Storage `has_key` in posterior state (after tx execution). It will try
    /// to check the write log first and if no entry found then the storage.
    fn has_key_post(&'view self, key: &Key) -> Result<bool> {
        self.post().has_key(key)
    }
}
