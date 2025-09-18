//! Transaction environment contains functions that can be called from
//! inside a tx.

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

pub use namada_core::address::Address;
pub use namada_core::borsh::{
    BorshDeserialize, BorshSerialize, BorshSerializeExt,
};
pub use namada_core::masp::MaspTransaction;
pub use namada_core::storage;
use namada_core::token::DenominatedAmount;
pub use namada_events::{Event, EventToEmit, EventType};
pub use namada_storage::{Result, ResultExt, StorageRead, StorageWrite};

/// Transaction host functions
pub trait TxEnv: StorageRead + StorageWrite {
    /// Storage read temporary state Borsh encoded value (after tx execution).
    /// It will try to read from only the write log and then decode it if
    /// found.
    fn read_temp<T: BorshDeserialize>(
        &self,
        key: &storage::Key,
    ) -> Result<Option<T>> {
        let bytes = self.read_bytes_temp(key)?;
        match bytes {
            Some(bytes) => {
                let val = T::try_from_slice(&bytes).into_storage_result()?;
                Ok(Some(val))
            }
            None => Ok(None),
        }
    }

    /// Storage read temporary state raw bytes (after tx execution). It will try
    /// to read from only the write log.
    fn read_bytes_temp(&self, key: &storage::Key) -> Result<Option<Vec<u8>>>;

    /// Write a temporary value to be encoded with Borsh at the given key to
    /// storage.
    fn write_temp<T: BorshSerialize>(
        &mut self,
        key: &storage::Key,
        val: T,
    ) -> Result<()> {
        let bytes = val.serialize_to_vec();
        self.write_bytes_temp(key, bytes)
    }

    /// Write a temporary value as bytes at the given key to storage.
    fn write_bytes_temp(
        &mut self,
        key: &storage::Key,
        val: impl AsRef<[u8]>,
    ) -> Result<()>;

    /// Insert a verifier address. This address must exist on chain, otherwise
    /// the transaction will be rejected.
    ///
    /// Validity predicates of each verifier addresses inserted in the
    /// transaction will validate the transaction and will receive all the
    /// changed storage keys and initialized accounts in their inputs.
    fn insert_verifier(&mut self, addr: &Address) -> Result<()>;

    /// Initialize a new account generates a new established address and
    /// writes the given code as its validity predicate into the storage.
    fn init_account(
        &mut self,
        code_hash: impl AsRef<[u8]>,
        code_tag: &Option<String>,
        entropy_source: &[u8],
    ) -> Result<Address>;

    /// Update a validity predicate
    fn update_validity_predicate(
        &mut self,
        addr: &Address,
        code: impl AsRef<[u8]>,
        code_tag: &Option<String>,
    ) -> Result<()>;

    /// Emit an [`Event`] from a transaction.
    fn emit_event<E: EventToEmit>(&mut self, event: E) -> Result<()>;

    /// Request to charge the provided amount of gas for the current transaction
    fn charge_gas(&mut self, used_gas: u64) -> Result<()>;

    /// Get events with a given [`EventType`].
    fn get_events(&self, event_type: &EventType) -> Result<Vec<Event>>;

    /// Set the sentinel for an invalid section commitment
    fn set_commitment_sentinel(&mut self);

    /// Update the masp note commitment tree in storage with the new notes
    fn update_masp_note_commitment_tree(
        transaction: &MaspTransaction,
    ) -> Result<bool>;

    /// The amount of the given token needed to pay a MASP shielding fee
    fn get_masp_shielding_fee_amount(
        &self,
        token: &Address,
    ) -> Result<Option<DenominatedAmount>>;
}
