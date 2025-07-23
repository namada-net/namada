//! Write log is temporary storage for modifications performed by a transaction.
//! before they are committed to the ledger's storage.

use std::collections::{BTreeMap, BTreeSet};

use itertools::Itertools;
use namada_core::address::{Address, EstablishedAddressGen};
use namada_core::arith::checked;
use namada_core::collections::{HashMap, HashSet};
use namada_core::hash::Hash;
use namada_core::{arith, storage};
use namada_events::extend::{InnerTxHash, TxHash};
use namada_events::{Event, EventToEmit, EventType};
use namada_gas::{
    Gas, MEMORY_ACCESS_GAS_PER_BYTE, STORAGE_DELETE_GAS_PER_BYTE,
    STORAGE_WRITE_GAS_PER_BYTE,
};
use namada_tx::data::InnerTxId;
use patricia_tree::map::StringPatriciaMap;
use thiserror::Error;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Trying to update a temporary value")]
    UpdateTemporaryValue,
    #[error(
        "Trying to update a validity predicate that a new account that's not \
         yet committed to storage"
    )]
    UpdateVpOfNewAccount,
    #[error("Trying to delete a validity predicate")]
    DeleteVp,
    #[error("Trying to write a temporary value after deleting")]
    WriteTempAfterDelete,
    #[error("Trying to write a temporary value after writing")]
    WriteTempAfterWrite,
    #[error("Replay protection key: {0}")]
    ReplayProtection(String),
    #[error("Arithmetic {0}")]
    Arith(#[from] arith::Error),
    #[error("Sized-diff overflowed")]
    SizeDiffOverflow,
    #[error("Value length overflowed")]
    ValueLenOverflow,
}

impl From<Error> for crate::Error {
    fn from(value: Error) -> Self {
        crate::Error::new(value)
    }
}

/// Result for functions that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// A storage modification
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageModification {
    /// Write a new value
    Write {
        /// Value bytes
        value: Vec<u8>,
    },
    /// Delete an existing key-value
    Delete,
    /// Initialize a new account with established address and a given validity
    /// predicate hash. The key for `InitAccount` inside the [`WriteLog`] must
    /// point to its validity predicate.
    InitAccount {
        /// Validity predicate hash bytes
        vp_code_hash: Hash,
    },
}

/// The write log for a transaction. This allows managing the result of a single
/// inner transaction inside a batch
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TxWriteLog {
    // The generator of established addresses
    address_gen: Option<EstablishedAddressGen>,
    // The storage modifications for the current transaction
    write_log: HashMap<storage::Key, StorageModification>,
    // Temporary key-values for the current transaction that are dropped after
    // tx and its verifying VPs execution is done
    tx_temp_log: HashMap<storage::Key, Vec<u8>>,
    /// The events emitted by the current transaction
    events: WriteLogEvents,
}

impl Default for TxWriteLog {
    fn default() -> Self {
        Self {
            address_gen: None,
            write_log: HashMap::with_capacity(100),
            tx_temp_log: HashMap::with_capacity(1),
            events: WriteLogEvents {
                tree: StringPatriciaMap::new(),
            },
        }
    }
}

/// The write log for an already evaluated transaction of a batch. This allows
/// managing the result of a single inner transaction inside a batch
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchedTxWriteLog {
    // The generator of established addresses
    address_gen: Option<EstablishedAddressGen>,
    // The storage modifications for the transaction
    write_log: HashMap<storage::Key, StorageModification>,
}

/// Log of events in the write log.
#[derive(Debug, Clone)]
pub(crate) struct WriteLogEvents {
    pub tree: StringPatriciaMap<HashSet<Event>>,
}

impl std::cmp::PartialEq for WriteLogEvents {
    fn eq(&self, other: &WriteLogEvents) -> bool {
        if self.tree.len() != other.tree.len() {
            return false;
        }

        self.tree.iter().all(|(event_type, event_set)| {
            other
                .tree
                .get(event_type)
                .map(|other_event_set| event_set == other_event_set)
                .unwrap_or_default()
        })
    }
}

impl std::cmp::Eq for WriteLogEvents {}

/// The write log storage
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteLog {
    /// The generator of established addresses
    pub(crate) block_address_gen: Option<EstablishedAddressGen>,
    /// All the storage modification accepted by validity predicates are stored
    /// in block write-log, before being committed to the storage
    pub(crate) block_write_log: HashMap<storage::Key, StorageModification>,
    /// The write log of the transactions of the current batch
    /// INVARIANT: this has to be sorted by the insertion
    /// order to correctly read values
    pub(crate) batch_write_log: Vec<BatchedTxWriteLog>,
    // The write log of the current active transaction
    pub(crate) tx_write_log: TxWriteLog,
    /// Storage modifications for the replay protection storage, cannot be
    /// managed in the normal write log because we need to commit them
    /// sometimes even on batch failure
    pub(crate) replay_protection: HashSet<Hash>,
}

/// Write log prefix iterator
#[derive(Debug)]
pub struct PrefixIter {
    /// The concrete iterator for modifications sorted by storage keys
    pub iter:
        std::collections::btree_map::IntoIter<String, StorageModification>,
}

impl Iterator for PrefixIter {
    type Item = (String, StorageModification);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl Default for WriteLog {
    fn default() -> Self {
        Self {
            block_address_gen: None,
            block_write_log: HashMap::with_capacity(100_000),
            batch_write_log: Vec::with_capacity(5),
            tx_write_log: Default::default(),
            replay_protection: HashSet::with_capacity(1_000),
        }
    }
}

impl WriteLog {
    /// Read a non-temp value at the given key and return the value and the gas
    /// cost, returns [`None`] if the key is not present in the write log
    pub fn read(
        &self,
        key: &storage::Key,
    ) -> std::result::Result<(Option<&StorageModification>, Gas), arith::Error>
    {
        // try to read from tx write log first
        match self
            .tx_write_log
            .write_log
            .get(key)
            .or_else(|| {
                // If not found, then try to read from batch write log,
                // following the insertion order
                self.batch_write_log
                    .iter()
                    .rev()
                    .find_map(|log| log.write_log.get(key))
            })
            .or_else(|| {
                // if not found, then try to read from block write log
                self.block_write_log.get(key)
            }) {
            Some(v) => {
                let gas = match v {
                    StorageModification::Write { ref value } => {
                        checked!(key.len() + value.len())?
                    }
                    StorageModification::Delete => key.len(),
                    StorageModification::InitAccount { ref vp_code_hash } => {
                        checked!(key.len() + vp_code_hash.len())?
                    }
                } as u64;
                Ok((
                    Some(v),
                    checked!(gas * MEMORY_ACCESS_GAS_PER_BYTE)?.into(),
                ))
            }
            None => {
                let gas = key.len() as u64;
                Ok((None, checked!(gas * MEMORY_ACCESS_GAS_PER_BYTE)?.into()))
            }
        }
    }

    /// Read a value before the latest tx execution at the given key and return
    /// the value and the gas cost, returns [`None`] if the key is not present
    /// in the write log
    pub fn read_pre(
        &self,
        key: &storage::Key,
    ) -> std::result::Result<(Option<&StorageModification>, Gas), arith::Error>
    {
        for bucket in self
            .batch_write_log
            .iter()
            .rev()
            .map(|batch_log| &batch_log.write_log)
            .chain([&self.block_write_log])
        {
            if let Some(v) = bucket.get(key) {
                let gas = match v {
                    StorageModification::Write { ref value } => {
                        checked!(key.len() + value.len())?
                    }
                    StorageModification::Delete => key.len(),
                    StorageModification::InitAccount { ref vp_code_hash } => {
                        checked!(key.len() + vp_code_hash.len())?
                    }
                } as u64;
                return Ok((
                    Some(v),
                    checked!(gas * MEMORY_ACCESS_GAS_PER_BYTE)?.into(),
                ));
            }
        }
        let gas = key.len() as u64;
        Ok((None, checked!(gas * MEMORY_ACCESS_GAS_PER_BYTE)?.into()))
    }

    /// Read a temp value at the given key and return the value and the gas
    /// cost, returns [`None`] if the key is not present in the temp write
    /// log
    pub fn read_temp(
        &self,
        key: &storage::Key,
    ) -> Result<(Option<&Vec<u8>>, Gas)> {
        // try to read from tx write log first
        match self.tx_write_log.tx_temp_log.get(key) {
            Some(value) => {
                let gas = checked!(key.len() + value.len())? as u64;

                Ok((
                    Some(value),
                    checked!(gas * MEMORY_ACCESS_GAS_PER_BYTE)?.into(),
                ))
            }
            None => {
                let gas = key.len() as u64;
                Ok((None, checked!(gas * MEMORY_ACCESS_GAS_PER_BYTE)?.into()))
            }
        }
    }

    /// Write a key and a value and return the gas cost and the size difference
    /// Fails with [`Error::UpdateVpOfNewAccount`] when attempting to update a
    /// validity predicate of a new account that's not yet committed to storage.
    /// Fails with [`Error::UpdateTemporaryValue`] when attempting to update a
    /// temporary value.
    pub fn write(
        &mut self,
        key: &storage::Key,
        value: Vec<u8>,
    ) -> Result<(Gas, i64)> {
        let len = value.len();
        if self.tx_write_log.tx_temp_log.contains_key(key) {
            return Err(Error::UpdateTemporaryValue);
        }
        let len_signed =
            i64::try_from(len).map_err(|_| Error::ValueLenOverflow)?;
        let size_diff = match self.tx_write_log.write_log.get(key) {
            Some(prev) => match prev {
                StorageModification::Write { ref value } => {
                    let val_len = i64::try_from(value.len())
                        .map_err(|_| Error::ValueLenOverflow)?;
                    checked!(len_signed - val_len)?
                }
                StorageModification::Delete => len_signed,
                StorageModification::InitAccount { .. } => {
                    // NOTE: errors from host functions force a shudown of the
                    // wasm environment without the need for cooperation from
                    // the wasm code (tx or vp), so there's no need to return
                    // gas in case of an error because execution will terminate
                    // anyway and this cannot be exploited to keep the vm
                    // running
                    return Err(Error::UpdateVpOfNewAccount);
                }
            },
            // set just the length of the value because we don't know if
            // the previous value exists on the storage
            None => len_signed,
        };

        self.tx_write_log
            .write_log
            .insert(key.clone(), StorageModification::Write { value });

        let gas = checked!(key.len() + len)? as u64;
        Ok((
            checked!(gas * STORAGE_WRITE_GAS_PER_BYTE)?.into(),
            size_diff,
        ))
    }

    /// Write a key and a value.
    /// Fails with [`Error::UpdateVpOfNewAccount`] when attempting to update a
    /// validity predicate of a new account that's not yet committed to storage.
    /// Fails with [`Error::UpdateTemporaryValue`] when attempting to update a
    /// temporary value.
    pub fn protocol_write(
        &mut self,
        key: &storage::Key,
        value: Vec<u8>,
    ) -> Result<()> {
        if self.tx_write_log.tx_temp_log.contains_key(key) {
            return Err(Error::UpdateTemporaryValue);
        }
        if let Some(prev) = self
            .block_write_log
            .insert(key.clone(), StorageModification::Write { value })
        {
            match prev {
                StorageModification::InitAccount { .. } => {
                    return Err(Error::UpdateVpOfNewAccount);
                }
                StorageModification::Write { .. }
                | StorageModification::Delete => {}
            }
        }
        Ok(())
    }

    /// Write a key and a value and return the gas cost and the size difference
    /// Fails with [`Error::WriteTempAfterWrite`] when attempting to update a
    /// temporary value after writing.
    /// Fails with [`Error::UpdateVpOfNewAccount`] when attempting to update a
    /// validity predicate of a new account that's not yet committed to storage.
    /// Fails with [`Error::WriteTempAfterDelete`] when attempting to update a
    /// temporary value after deleting.
    pub fn write_temp(
        &mut self,
        key: &storage::Key,
        value: Vec<u8>,
    ) -> Result<(Gas, i64)> {
        if let Some(prev) = self.tx_write_log.write_log.get(key) {
            match prev {
                StorageModification::Write { .. } => {
                    // Cannot overwrite a write request with a temporary one
                    return Err(Error::WriteTempAfterWrite);
                }
                StorageModification::Delete => {
                    return Err(Error::WriteTempAfterDelete);
                }
                StorageModification::InitAccount { .. } => {
                    return Err(Error::UpdateVpOfNewAccount);
                }
            }
        }

        let len = value.len();
        let len_signed =
            i64::try_from(len).map_err(|_| Error::ValueLenOverflow)?;
        let size_diff = match self.tx_write_log.tx_temp_log.get(key) {
            Some(prev) => {
                let prev_len = i64::try_from(prev.len())
                    .map_err(|_| Error::ValueLenOverflow)?;
                checked!(len_signed - prev_len)?
            }
            // set just the length of the value because we don't know if
            // the previous value exists on the storage
            None => len_signed,
        };

        self.tx_write_log.tx_temp_log.insert(key.clone(), value);

        // Temp writes are not propagated to db so just charge the cost of
        // accessing storage
        let gas = checked!(key.len() + len)? as u64;
        Ok((
            checked!(gas * MEMORY_ACCESS_GAS_PER_BYTE)?.into(),
            size_diff,
        ))
    }

    /// Delete a key and its value, and return the gas cost and the size
    /// difference.
    /// Fails with [`Error::DeleteVp`] for a validity predicate key, which are
    /// not possible to delete.
    pub fn delete(&mut self, key: &storage::Key) -> Result<(Gas, i64)> {
        if key.is_validity_predicate().is_some() {
            return Err(Error::DeleteVp);
        }
        let size_diff = match self.tx_write_log.write_log.get(key) {
            Some(prev) => match prev {
                StorageModification::Write { ref value } => value.len(),
                StorageModification::Delete => 0,
                StorageModification::InitAccount { .. } => {
                    return Err(Error::DeleteVp);
                }
            },
            // set 0 because we don't know if the previous value exists on the
            // storage
            None => 0,
        };

        self.tx_write_log
            .write_log
            .insert(key.clone(), StorageModification::Delete);
        let gas = checked!(key.len() + size_diff)? as u64;
        let size_diff = i64::try_from(size_diff)
            .ok()
            .and_then(i64::checked_neg)
            .ok_or(Error::SizeDiffOverflow)?;
        Ok((
            checked!(gas * STORAGE_DELETE_GAS_PER_BYTE)?.into(),
            size_diff,
        ))
    }

    /// Delete a key and its value.
    /// Fails with [`Error::DeleteVp`] for a validity predicate key, which are
    /// not possible to delete.
    pub fn protocol_delete(&mut self, key: &storage::Key) -> Result<()> {
        if key.is_validity_predicate().is_some() {
            return Err(Error::DeleteVp);
        }
        if let Some(prev) = self
            .block_write_log
            .insert(key.clone(), StorageModification::Delete)
        {
            match prev {
                StorageModification::InitAccount { .. } => {
                    return Err(Error::DeleteVp);
                }
                StorageModification::Write { .. }
                | StorageModification::Delete => {}
            }
        };
        Ok(())
    }

    /// Initialize a new account and return the gas cost.
    pub fn init_account(
        &mut self,
        storage_address_gen: &EstablishedAddressGen,
        vp_code_hash: Hash,
        entropy_source: &[u8],
    ) -> (Address, Gas) {
        // If we've previously generated a new account, we use the local copy of
        // the generator. Otherwise, we create a new copy from the storage
        let address_gen = self
            .tx_write_log
            .address_gen
            .get_or_insert_with(|| storage_address_gen.clone());
        let addr = address_gen.generate_address(entropy_source);
        let key = storage::Key::validity_predicate(&addr);
        let gas = ((key
            .len()
            .checked_add(vp_code_hash.len())
            .expect("Cannot overflow")) as u64)
            .checked_mul(STORAGE_WRITE_GAS_PER_BYTE)
            .expect("Canno overflow");
        self.tx_write_log
            .write_log
            .insert(key, StorageModification::InitAccount { vp_code_hash });
        (addr, gas.into())
    }

    /// Set an event and return the gas cost. Returns `None` on gas u64
    /// overflow.
    pub fn emit_event<E: EventToEmit>(&mut self, event: E) -> Option<Gas> {
        self.emit_event_with_tx_hashes(event, None)
    }

    /// Set an event and return the gas cost.
    ///
    /// Returns `None` on gas u64 overflow. The optional tx hashes
    /// are included as new attributes in the event, free of charge.
    pub fn emit_event_with_tx_hashes<E: EventToEmit>(
        &mut self,
        event: E,
        inner_tx_id: Option<InnerTxId<'_>>,
    ) -> Option<Gas> {
        let mut event = event.into();
        let gas_cost = event.emission_gas_cost(MEMORY_ACCESS_GAS_PER_BYTE);
        if gas_cost.as_ref().is_some() {
            let event_type = event.kind().to_string();
            if !self.tx_write_log.events.tree.contains_key(&event_type) {
                self.tx_write_log
                    .events
                    .tree
                    .insert(&event_type, HashSet::new());
            }
            if let Some(inner_tx_id) = inner_tx_id {
                event.extend(TxHash(inner_tx_id.wrapper_hash()));
                event.extend(InnerTxHash(inner_tx_id.inner_hash()));
            }
            self.tx_write_log
                .events
                .tree
                .get_mut(&event_type)
                .unwrap()
                .insert(event);
        }
        gas_cost.map(|gas| gas.into())
    }

    /// Get the non-temporary storage keys changed and accounts keys initialized
    /// in the current transaction. The account keys point to the validity
    /// predicates of the newly created accounts.
    pub fn get_keys(&self) -> BTreeSet<storage::Key> {
        self.tx_write_log
            .write_log
            .iter()
            .map(|(key, _modification)| key.clone())
            .collect()
    }

    /// Get the storage keys changed in the current transaction (left) and
    /// the addresses of accounts initialized in the current transaction
    /// (right). The first vector excludes keys of validity predicates of
    /// newly initialized accounts, but may include keys of other data
    /// written into newly initialized accounts.
    pub fn get_partitioned_keys(
        &self,
    ) -> (BTreeSet<&storage::Key>, HashSet<&Address>) {
        use itertools::Either;
        self.tx_write_log
            .write_log
            .iter()
            .partition_map(|(key, value)| {
                match (key.is_validity_predicate(), value) {
                    (
                        Some(address),
                        StorageModification::InitAccount { .. },
                    ) => Either::Right(address),
                    _ => Either::Left(key),
                }
            })
    }

    /// Get the addresses of accounts initialized in the current transaction.
    pub fn get_initialized_accounts(&self) -> Vec<Address> {
        self.tx_write_log
            .write_log
            .iter()
            .filter_map(|(key, value)| {
                match (key.is_validity_predicate(), value) {
                    (
                        Some(address),
                        StorageModification::InitAccount { .. },
                    ) => Some(address.clone()),
                    _ => None,
                }
            })
            .collect()
    }

    /// Take the events of the current transaction
    pub fn take_events(&mut self) -> BTreeSet<Event> {
        std::mem::take(&mut self.tx_write_log.events.tree)
            .into_iter()
            .flat_map(|(_, event_set)| event_set)
            .collect()
    }

    /// Get events emitted by the current transaction of
    /// a certain type.
    #[inline]
    pub fn lookup_events_with_prefix<'this, 'ty: 'this>(
        &'this self,
        event_type: &'ty EventType,
    ) -> impl Iterator<Item = &'this Event> + 'this {
        self.tx_write_log
            .events
            .tree
            .iter_prefix(event_type)
            .flat_map(|(_, event_set)| event_set)
    }

    /// Get events emitted by the current transaction of
    /// type `E`.
    #[inline]
    pub fn get_events_of<E: EventToEmit>(
        &self,
    ) -> impl Iterator<Item = &Event> {
        self.tx_write_log
            .events
            .tree
            .iter_prefix(E::DOMAIN)
            .flat_map(|(_, event_set)| event_set)
    }

    /// Get all events emitted by the current transaction.
    #[inline]
    pub fn get_events(&self) -> impl Iterator<Item = &Event> {
        self.tx_write_log.events.tree.values().flatten()
    }

    /// Commit the current transaction's write log to the batch when it's
    /// accepted by all the triggered validity predicates. Starts a new
    /// transaction write log.
    pub fn commit_tx_to_batch(&mut self) {
        let tx_write_log = std::mem::take(&mut self.tx_write_log);
        let batched_log = BatchedTxWriteLog {
            address_gen: tx_write_log.address_gen,
            write_log: tx_write_log.write_log,
        };

        self.batch_write_log.push(batched_log);
    }

    /// Drop the current transaction's write log and IBC events when it's
    /// declined by any of the triggered validity predicates. Starts a new
    /// transaction write log and clears the temp write log.
    pub fn drop_tx(&mut self) {
        self.tx_write_log = Default::default();
    }

    /// Commit the current tx and the entire batch to the block log.
    pub fn commit_batch_and_current_tx(&mut self) {
        self.commit_tx_to_batch();
        self.commit_batch_only();
    }

    /// Commit the entire batch to the block log. Doesn't handle the tx write
    /// log which might still contain some data and needs to be handled
    /// separately.
    pub fn commit_batch_only(&mut self) {
        for log in std::mem::take(&mut self.batch_write_log) {
            self.block_write_log.extend(log.write_log);
            self.block_address_gen = log.address_gen;
        }
    }

    /// Drop the current tx and the entire batch log.
    pub fn drop_batch(&mut self) {
        self.drop_tx();
        self.batch_write_log = Default::default();
    }

    /// Get the verifiers set whose validity predicates should validate the
    /// current transaction changes and the storage keys that have been
    /// modified created, updated and deleted via the write log.
    ///
    /// Note that some storage keys may comprise of multiple addresses, in which
    /// case every address will be included in the verifiers set.
    pub fn verifiers_and_changed_keys(
        &self,
        verifiers_from_tx: &BTreeSet<Address>,
    ) -> (BTreeSet<Address>, BTreeSet<storage::Key>) {
        let changed_keys: BTreeSet<storage::Key> = self.get_keys();
        let initialized_accounts = self.get_initialized_accounts();
        let mut verifiers = verifiers_from_tx.clone();

        // get changed keys grouped by the address
        for key in changed_keys.iter() {
            if let Some(addr) = key.fst_address() {
                // We can skip insert when the address has been added from the
                // Tx above. Also skip if it's an address of a newly initialized
                // account, because anything can be written into an account's
                // storage in the same tx in which it's initialized (there is no
                // VP in the state prior to tx execution).
                if !verifiers_from_tx.contains(addr)
                    && !initialized_accounts.contains(addr)
                {
                    // Add the address as a verifier
                    verifiers.insert(addr.clone());
                }
            }
        }
        (verifiers, changed_keys)
    }

    /// Iterate modifications prior to the current transaction, whose storage
    /// key matches the given prefix, sorted by their storage key.
    pub fn iter_prefix_pre(&self, prefix: &storage::Key) -> PrefixIter {
        let mut matches = BTreeMap::new();

        for (key, modification) in self.block_write_log.iter().chain(
            self.batch_write_log
                .iter()
                .flat_map(|batch_log| batch_log.write_log.iter()),
        ) {
            if key.split_prefix(prefix).is_some() {
                matches.insert(key.to_string(), modification.clone());
            }
        }

        let iter = matches.into_iter();
        PrefixIter { iter }
    }

    /// Iterate modifications posterior of the current tx, whose storage key
    /// matches the given prefix, sorted by their storage key.
    pub fn iter_prefix_post(&self, prefix: &storage::Key) -> PrefixIter {
        let mut matches = BTreeMap::new();

        for (key, modification) in self.block_write_log.iter().chain(
            self.batch_write_log
                .iter()
                .flat_map(|batch_log| batch_log.write_log.iter())
                .chain(self.tx_write_log.write_log.iter()),
        ) {
            if key.split_prefix(prefix).is_some() {
                matches.insert(key.to_string(), modification.clone());
            }
        }

        let iter = matches.into_iter();
        PrefixIter { iter }
    }

    /// Check if the given tx hash has already been processed
    pub fn has_replay_protection_entry(&self, hash: &Hash) -> bool {
        self.replay_protection.contains(hash)
    }

    /// Write the transaction hash
    pub fn write_tx_hash(&mut self, hash: Hash) -> Result<()> {
        if !self.replay_protection.insert(hash) {
            // Cannot write an hash if it's already present in the set
            return Err(Error::ReplayProtection(format!(
                "Requested a write of hash {hash} which has already been \
                 processed"
            )));
        }

        Ok(())
    }

    /// Remove the transaction hash because redundant
    pub(crate) fn redundant_tx_hash(&mut self, hash: &Hash) -> Result<()> {
        if !self.replay_protection.swap_remove(hash) {
            return Err(Error::ReplayProtection(format!(
                "Requested a redundant modification on hash {hash} which is \
                 unknown"
            )));
        }
        Ok(())
    }
}

#[allow(clippy::cast_possible_wrap)]
#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use namada_core::address;
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    use super::*;
    use crate::StateRead;

    #[test]
    fn test_crud_value() {
        let mut write_log = WriteLog::default();
        let key =
            storage::Key::parse("key").expect("cannot parse the key string");

        // read a non-existing key
        let (value, gas) = write_log.read(&key).unwrap();
        assert!(value.is_none());
        assert_eq!(
            gas,
            ((key.len() as u64) * MEMORY_ACCESS_GAS_PER_BYTE).into()
        );

        // delete a non-existing key
        let (gas, diff) = write_log.delete(&key).unwrap();
        assert_eq!(
            gas,
            (key.len() as u64 * STORAGE_DELETE_GAS_PER_BYTE).into()
        );
        assert_eq!(diff, 0);

        // insert a value
        let inserted = "inserted".as_bytes().to_vec();
        let (gas, diff) = write_log.write(&key, inserted.clone()).unwrap();
        assert_eq!(
            gas,
            ((key.len() + inserted.len()) as u64 * STORAGE_WRITE_GAS_PER_BYTE)
                .into()
        );
        assert_eq!(diff, inserted.len() as i64);

        // read the value
        let (value, gas) = write_log.read(&key).unwrap();
        match value.expect("no read value") {
            StorageModification::Write { value } => {
                assert_eq!(*value, inserted)
            }
            _ => panic!("unexpected read result"),
        }
        assert_eq!(
            gas,
            (((key.len() + inserted.len()) as u64)
                * MEMORY_ACCESS_GAS_PER_BYTE)
                .into()
        );

        // update the value
        let updated = "updated".as_bytes().to_vec();
        let (gas, diff) = write_log.write(&key, updated.clone()).unwrap();
        assert_eq!(
            gas,
            ((key.len() + updated.len()) as u64 * STORAGE_WRITE_GAS_PER_BYTE)
                .into()
        );
        assert_eq!(diff, updated.len() as i64 - inserted.len() as i64);

        // delete the key
        let (gas, diff) = write_log.delete(&key).unwrap();
        assert_eq!(
            gas,
            ((key.len() + updated.len()) as u64 * STORAGE_DELETE_GAS_PER_BYTE)
                .into()
        );
        assert_eq!(diff, -(updated.len() as i64));

        // delete the deleted key again
        let (gas, diff) = write_log.delete(&key).unwrap();
        assert_eq!(
            gas,
            (key.len() as u64 * STORAGE_DELETE_GAS_PER_BYTE).into()
        );
        assert_eq!(diff, 0);

        // read the deleted key
        let (value, gas) = write_log.read(&key).unwrap();
        match &value.expect("no read value") {
            StorageModification::Delete => {}
            _ => panic!("unexpected result"),
        }
        assert_eq!(gas, (key.len() as u64 * MEMORY_ACCESS_GAS_PER_BYTE).into());

        // insert again
        let reinserted = "reinserted".as_bytes().to_vec();
        let (gas, diff) = write_log.write(&key, reinserted.clone()).unwrap();
        assert_eq!(
            gas,
            ((key.len() + reinserted.len()) as u64
                * STORAGE_WRITE_GAS_PER_BYTE)
                .into()
        );
        assert_eq!(diff, reinserted.len() as i64);
    }

    #[test]
    fn test_crud_account() {
        let mut write_log = WriteLog::default();
        let address_gen = EstablishedAddressGen::new("test");

        // init
        let init_vp = "initialized".as_bytes().to_vec();
        let vp_hash = Hash::sha256(init_vp);
        let (addr, gas) = write_log.init_account(&address_gen, vp_hash, &[]);
        let vp_key = storage::Key::validity_predicate(&addr);
        assert_eq!(
            gas,
            ((vp_key.len() + vp_hash.len()) as u64
                * STORAGE_WRITE_GAS_PER_BYTE)
                .into()
        );

        // read
        let (value, gas) = write_log.read(&vp_key).unwrap();
        match value.expect("no read value") {
            StorageModification::InitAccount { vp_code_hash } => {
                assert_eq!(*vp_code_hash, vp_hash)
            }
            _ => panic!("unexpected result"),
        }
        assert_eq!(
            gas,
            ((vp_key.len() + vp_hash.len()) as u64
                * MEMORY_ACCESS_GAS_PER_BYTE)
                .into()
        );

        // get all
        let (_changed_keys, init_accounts) = write_log.get_partitioned_keys();
        assert!(init_accounts.contains(&&addr));
        assert_eq!(init_accounts.len(), 1);
    }

    #[test]
    fn test_update_initialized_account_should_fail() {
        let mut write_log = WriteLog::default();
        let address_gen = EstablishedAddressGen::new("test");

        let init_vp = "initialized".as_bytes().to_vec();
        let vp_hash = Hash::sha256(init_vp);
        let (addr, _) = write_log.init_account(&address_gen, vp_hash, &[]);
        let vp_key = storage::Key::validity_predicate(&addr);

        // update should fail
        let updated_vp = "updated".as_bytes().to_vec();
        let updated_vp_hash = Hash::sha256(updated_vp);
        let result = write_log
            .write(&vp_key, updated_vp_hash.to_vec())
            .unwrap_err();
        assert_matches!(result, Error::UpdateVpOfNewAccount);
    }

    #[test]
    fn test_delete_initialized_account_should_fail() {
        let mut write_log = WriteLog::default();
        let address_gen = EstablishedAddressGen::new("test");

        let init_vp = "initialized".as_bytes().to_vec();
        let vp_hash = Hash::sha256(init_vp);
        let (addr, _) = write_log.init_account(&address_gen, vp_hash, &[]);
        let vp_key = storage::Key::validity_predicate(&addr);

        // delete should fail
        let result = write_log.delete(&vp_key).unwrap_err();
        assert_matches!(result, Error::DeleteVp);
    }

    #[test]
    fn test_delete_vp_should_fail() {
        let mut write_log = WriteLog::default();
        let addr = address::testing::established_address_1();
        let vp_key = storage::Key::validity_predicate(&addr);

        // delete should fail
        let result = write_log.delete(&vp_key).unwrap_err();
        assert_matches!(result, Error::DeleteVp);
    }

    #[test]
    fn test_commit() {
        let mut state = crate::testing::TestFullAccessState::default();
        let wl_state = state.restrict_writes_to_write_log();
        let address_gen = EstablishedAddressGen::new("test");

        let key1 =
            storage::Key::parse("key1").expect("cannot parse the key string");
        let key2 =
            storage::Key::parse("key2").expect("cannot parse the key string");
        let key3 =
            storage::Key::parse("key3").expect("cannot parse the key string");
        let key4 =
            storage::Key::parse("key4").expect("cannot parse the key string");

        // initialize an account
        let vp1 = Hash::sha256("vp1".as_bytes());
        let (addr1, _) =
            wl_state.write_log.init_account(&address_gen, vp1, &[]);
        wl_state.write_log.commit_batch_and_current_tx();

        // write values
        let val1 = "val1".as_bytes().to_vec();
        let _ = wl_state.write_log.write(&key1, val1.clone()).unwrap();
        let _ = wl_state.write_log.write(&key2, val1.clone()).unwrap();
        let _ = wl_state.write_log.write(&key3, val1.clone()).unwrap();
        let _ = wl_state.write_log.write_temp(&key4, val1.clone()).unwrap();
        wl_state.write_log.commit_batch_and_current_tx();

        // these values are not written due to drop_tx
        let val2 = "val2".as_bytes().to_vec();
        let _ = wl_state.write_log.write(&key1, val2.clone()).unwrap();
        let _ = wl_state.write_log.write(&key2, val2.clone()).unwrap();
        let _ = wl_state.write_log.write(&key3, val2).unwrap();
        wl_state.write_log.drop_tx();

        // deletes and updates values
        let val3 = "val3".as_bytes().to_vec();
        let _ = wl_state.write_log.delete(&key2).unwrap();
        let _ = wl_state.write_log.write(&key3, val3.clone()).unwrap();
        wl_state.write_log.commit_batch_and_current_tx();

        // commit a block
        state.commit_block().expect("commit failed");
        // update the DB snapshot
        let wl_state = state.restrict_writes_to_write_log();

        let (vp_code_hash, _gas) = wl_state
            .validity_predicate::<namada_parameters::Store<()>>(&addr1)
            .expect("vp read failed");
        assert_eq!(vp_code_hash, Some(vp1));
        let (value, _) = wl_state.db_read(&key1).expect("read failed");
        assert_eq!(value.expect("no read value"), val1);
        let (value, _) = wl_state.db_read(&key2).expect("read failed");
        assert!(value.is_none());
        let (value, _) = wl_state.db_read(&key3).expect("read failed");
        assert_eq!(value.expect("no read value"), val3);
        let (value, _) = wl_state.db_read(&key4).expect("read failed");
        assert_eq!(value, None);
    }

    #[test]
    fn test_replay_protection_commit() {
        let mut state = crate::testing::TestFullAccessState::default();
        let mut wl_state = state.restrict_writes_to_write_log();

        {
            let write_log = wl_state.write_log_mut();
            // write some replay protection keys
            write_log
                .write_tx_hash(Hash::sha256("tx1".as_bytes()))
                .unwrap();
            write_log
                .write_tx_hash(Hash::sha256("tx2".as_bytes()))
                .unwrap();
            write_log
                .write_tx_hash(Hash::sha256("tx3".as_bytes()))
                .unwrap();
        }

        // commit a block
        state.commit_block().expect("commit failed");
        let mut wl_state = state.restrict_writes_to_write_log();

        assert!(wl_state.write_log.replay_protection.is_empty());
        for tx in ["tx1", "tx2", "tx3"] {
            let hash = Hash::sha256(tx.as_bytes());
            assert!(
                wl_state
                    .has_replay_protection_entry(&hash)
                    .expect("read failed")
            );
        }

        {
            let write_log = wl_state.write_log_mut();
            // write some replay protection keys
            write_log
                .write_tx_hash(Hash::sha256("tx4".as_bytes()))
                .unwrap();
            write_log
                .write_tx_hash(Hash::sha256("tx5".as_bytes()))
                .unwrap();
            write_log
                .write_tx_hash(Hash::sha256("tx6".as_bytes()))
                .unwrap();

            // Mark one hash as redundant
            write_log
                .redundant_tx_hash(&Hash::sha256("tx4".as_bytes()))
                .unwrap();
        }

        // commit a block
        state.commit_block().expect("commit failed");
        let mut wl_state = state.restrict_writes_to_write_log();

        assert!(wl_state.write_log.replay_protection.is_empty());
        for tx in ["tx1", "tx2", "tx3", "tx5", "tx6"] {
            assert!(
                wl_state
                    .has_replay_protection_entry(&Hash::sha256(tx.as_bytes()))
                    .expect("read failed")
            );
        }
        assert!(
            !wl_state
                .has_replay_protection_entry(&Hash::sha256("tx4".as_bytes()))
                .expect("read failed")
        );
        {
            let write_log = wl_state.write_log_mut();
            write_log
                .write_tx_hash(Hash::sha256("tx7".as_bytes()))
                .unwrap();

            // mark as redundant a missing hash and check that it fails
            assert!(
                state
                    .write_log
                    .redundant_tx_hash(&Hash::sha256("tx8".as_bytes()))
                    .is_err()
            );

            // Do not assert the state of replay protection because this
            // error will actually trigger a shut down of the node. Also, since
            // we write the values before validating them, the state would be
            // wrong
        }
    }

    // Test that writing a value on top of a temporary write is not allowed
    #[test]
    fn test_write_after_temp_disallowed() {
        let mut state = crate::testing::TestFullAccessState::default();
        let wl_state = state.restrict_writes_to_write_log();

        let key1 =
            storage::Key::parse("key1").expect("cannot parse the key string");
        let val1 = "val1".as_bytes().to_vec();
        // Test from tx_write_log
        let _ = wl_state.write_log.write_temp(&key1, val1.clone()).unwrap();
        assert!(matches!(
            wl_state.write_log.write(&key1, val1.clone()),
            Err(Error::UpdateTemporaryValue)
        ));
    }

    // Test that a temporary write on top of a write is not allowed
    #[test]
    fn test_write_temp_after_write_disallowed() {
        let mut state = crate::testing::TestFullAccessState::default();
        let wl_state = state.restrict_writes_to_write_log();

        let key1 =
            storage::Key::parse("key1").expect("cannot parse the key string");
        let val1 = "val1".as_bytes().to_vec();
        // Test from tx_write_log
        let _ = wl_state.write_log.write(&key1, val1.clone()).unwrap();
        assert!(matches!(
            wl_state.write_log.write_temp(&key1, val1.clone()),
            Err(Error::WriteTempAfterWrite)
        ));
    }

    // Test that a temporary write on top of a delete is not allowed
    #[test]
    fn test_write_temp_after_delete_disallowed() {
        let mut state = crate::testing::TestFullAccessState::default();

        let key1 =
            storage::Key::parse("key1").expect("cannot parse the key string");
        let val1 = "val1".as_bytes().to_vec();
        // Test from tx_write_log
        let _ = state.write_log.delete(&key1).unwrap();
        assert!(matches!(
            state.write_log.write_temp(&key1, val1.clone()),
            Err(Error::WriteTempAfterDelete)
        ));
    }

    prop_compose! {
        fn arb_verifiers_changed_key_tx_all_key()
            (verifiers_from_tx in testing::arb_verifiers_from_tx())
            (tx_write_log in testing::arb_tx_write_log(verifiers_from_tx.clone()),
                verifiers_from_tx in Just(verifiers_from_tx))
        -> (BTreeSet<Address>, HashMap<storage::Key, StorageModification>) {
            (verifiers_from_tx, tx_write_log)
        }
    }

    proptest! {
        #[test]
        fn verifiers_changed_key_tx_all_key(
            (verifiers_from_tx, write_log) in arb_verifiers_changed_key_tx_all_key(),
        ) {
            verifiers_changed_key_tx_all_key_aux(verifiers_from_tx, write_log)
        }

        #[test]
        fn test_batched_txs(modifications in testing::arb_batched_txs()) {
            test_batched_txs_aux(modifications)
        }
    }

    /// Test [`WriteLog::verifiers_changed_keys`] that:
    /// 1. Every address from `verifiers_from_tx` is included in the verifiers
    ///    set.
    /// 2. Every address included in the first segment of changed storage keys
    ///    is included in the verifiers set.
    /// 3. Addresses of newly initialized accounts are not verifiers, so that
    ///    anything can be written into an account's storage in the same tx in
    ///    which it's initialized.
    /// 4. The validity predicates of all the newly initialized accounts are
    ///    included in the changed keys set.
    fn verifiers_changed_key_tx_all_key_aux(
        verifiers_from_tx: BTreeSet<Address>,
        write_log: HashMap<storage::Key, StorageModification>,
    ) {
        let write_log = WriteLog {
            tx_write_log: super::TxWriteLog {
                write_log,
                ..Default::default()
            },
            ..WriteLog::default()
        };

        let (verifiers, changed_keys) =
            write_log.verifiers_and_changed_keys(&verifiers_from_tx);

        println!("verifiers_from_tx {:#?}", verifiers_from_tx);
        for verifier_from_tx in verifiers_from_tx {
            // Test for 1.
            assert!(verifiers.contains(&verifier_from_tx));
        }

        let (_changed_keys, initialized_accounts) =
            write_log.get_partitioned_keys();
        for key in changed_keys.iter() {
            if let Some(addr_from_key) = key.fst_address() {
                if !initialized_accounts.contains(addr_from_key) {
                    // Test for 2.
                    assert!(verifiers.contains(addr_from_key));
                }
            }
        }

        println!("verifiers {:#?}", verifiers);
        println!("changed_keys {:#?}", changed_keys);
        println!("initialized_accounts {:#?}", initialized_accounts);
        for initialized_account in initialized_accounts {
            // Test for 3.
            assert!(!verifiers.contains(initialized_account));
            // Test for 4.
            let vp_key = storage::Key::validity_predicate(initialized_account);
            assert!(changed_keys.contains(&vp_key));
        }
    }

    /// Test that for a batched tx the result of reading modified keys from
    /// write log matches the result of prefix iterators.
    fn test_batched_txs_aux(
        txs: Vec<HashMap<storage::Key, StorageModification>>,
    ) {
        let mut write_log = WriteLog::default();

        for tx in txs {
            // Write tx modifications
            write_log.tx_write_log.write_log = tx;

            // Collect all the keys in batch from previous txs
            let keys: HashSet<storage::Key> = write_log
                .batch_write_log
                .iter()
                .flat_map(|batch| batch.write_log.keys())
                .cloned()
                .collect();

            // Iterate through all the modified keys to check prior state
            for key in keys.clone() {
                // Read the modification associated with this key from prior
                // state
                let (modification, _gas) = write_log.read_pre(&key).unwrap();
                let modification = modification.unwrap();

                // Prefix iter prior state for this key and assert that the
                // values match
                for (key_str, modification_from_iter) in
                    write_log.iter_prefix_pre(&key)
                {
                    assert_eq!(key.to_string(), key_str);
                    assert_eq!(modification, &modification_from_iter);
                }
            }

            // And then commit them to batch
            write_log.commit_tx_to_batch();

            // Collect all the keys in batch and tx logs
            let keys: HashSet<storage::Key> = write_log
                .batch_write_log
                .iter()
                .flat_map(|batch| batch.write_log.keys())
                .chain(write_log.tx_write_log.write_log.keys())
                .cloned()
                .collect();

            // Iterate through all the modified keys again to check posterior
            // state
            for key in keys {
                // Read the modification associated with this key from posterior
                // state
                let (modification, _gas) = write_log.read(&key).unwrap();
                let modification = modification.unwrap();

                // Prefix iter posterior state for this key and assert that the
                // values match
                for (key_str, modification_from_iter) in
                    write_log.iter_prefix_post(&key)
                {
                    assert_eq!(key.to_string(), key_str);
                    assert_eq!(modification, &modification_from_iter);
                }
            }
        }
    }
}

/// Helpers for testing with write log.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use namada_core::address::testing::arb_address;
    use namada_core::hash::HASH_LENGTH;
    use namada_core::storage::testing::arb_key;
    use proptest::collection;
    use proptest::prelude::{Just, Strategy, any, prop_oneof};

    use super::*;

    /// Generate an arbitrary tx write log of [`HashMap<storage::Key,
    /// StorageModification>`].
    pub fn arb_tx_write_log(
        verifiers_from_tx: BTreeSet<Address>,
    ) -> impl Strategy<Value = HashMap<storage::Key, StorageModification>> + 'static
    {
        arb_key().prop_flat_map(move |key| {
            // If the key is a validity predicate key and its owner is in the
            // verifier set, we must not generate `InitAccount` for it.
            let can_init_account = key
                .is_validity_predicate()
                .map(|owner| !verifiers_from_tx.contains(owner))
                .unwrap_or_default();
            collection::hash_map(
                Just(key),
                arb_storage_modification(can_init_account),
                0..100,
            )
            .prop_map(|map| map.into_iter().collect())
        })
    }

    /// Generate modifications for batched txs where each `Vec` entry is
    /// intended to be a single tx and each tx touches the same set of common
    /// keys in addition to some other random keys.
    pub fn arb_batched_txs()
    -> impl Strategy<Value = Vec<HashMap<storage::Key, StorageModification>>>
    + 'static {
        const COMMON_KEYS_LEN: usize = 10;

        let common_keys = collection::vec(arb_key(), COMMON_KEYS_LEN);
        (
            // Generate some keys to be modified by all txs
            common_keys,
            // Vec of txs
            collection::vec(
                // For each common key generate some modifications in each tx
                (
                    collection::vec(
                        arb_storage_modification(false),
                        COMMON_KEYS_LEN,
                    ),
                    // Then add some more random key modification to each tx
                    collection::hash_map(
                        arb_key(),
                        arb_storage_modification(false),
                        1..10,
                    ),
                ),
                1..10,
            ),
        )
            .prop_map(|(common_keys, modifications)| {
                modifications
                    .into_iter()
                    .map(|(common_key_modifications, other_modifications)| {
                        common_keys
                            .clone()
                            .into_iter()
                            .zip(common_key_modifications)
                            .chain(other_modifications)
                            .collect::<HashMap<_, _>>()
                    })
                    .collect::<Vec<_>>()
            })
    }

    /// Generate arbitrary verifiers from tx of [`BTreeSet<Address>`].
    pub fn arb_verifiers_from_tx() -> impl Strategy<Value = BTreeSet<Address>> {
        collection::btree_set(arb_address(), 0..10)
    }

    /// Generate an arbitrary [`StorageModification`].
    pub fn arb_storage_modification(
        can_init_account: bool,
    ) -> impl Strategy<Value = StorageModification> {
        if can_init_account {
            prop_oneof![
                any::<Vec<u8>>()
                    .prop_map(|value| StorageModification::Write { value }),
                Just(StorageModification::Delete),
                any::<[u8; HASH_LENGTH]>().prop_map(|hash| {
                    StorageModification::InitAccount {
                        vp_code_hash: Hash(hash),
                    }
                }),
            ]
            .boxed()
        } else {
            prop_oneof![
                any::<Vec<u8>>()
                    .prop_map(|value| StorageModification::Write { value }),
                Just(StorageModification::Delete),
            ]
            .boxed()
        }
    }
}
