//! Host functions for VPs used for both native and WASM VPs.

use std::cell::RefCell;
use std::fmt::Debug;

use namada_core::address::{Address, ESTABLISHED_ADDRESS_BYTES_LEN};
use namada_core::arith::checked;
use namada_core::chain::{BlockHeader, BlockHeight, ChainId, Epoch, Epochs};
use namada_core::hash::{HASH_LENGTH, Hash};
use namada_core::storage::{Key, TX_INDEX_LENGTH};
use namada_events::{Event, EventTypeBuilder};
use namada_gas::{self as gas, Gas, GasMetering, MEMORY_ACCESS_GAS_PER_BYTE};
use namada_tx::{BatchedTxRef, IndexedTx, Section};
use thiserror::Error;

use crate::state::write_log::WriteLog;
use crate::state::{DB, DBIter, PrefixIter, ResultExt, StateRead, write_log};
pub use crate::state::{Error, Result};

/// These runtime errors will abort VP execution immediately
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("Out of gas: {0}")]
    OutOfGas(gas::Error),
    #[error("Invalid transaction code hash")]
    InvalidCodeHash,
    #[error("No value found in result buffer")]
    NoValueInResultBuffer,
    #[error("The section signature is invalid: {0}")]
    InvalidSectionSignature(String),
}

impl From<RuntimeError> for Error {
    fn from(value: RuntimeError) -> Self {
        Error::new(value)
    }
}

/// VP environment function result
pub type EnvResult<T> = std::result::Result<T, RuntimeError>;

/// Add a gas cost incured in a validity predicate
pub fn add_gas(
    gas_meter: &RefCell<impl GasMetering>,
    used_gas: Gas,
) -> Result<()> {
    gas_meter.borrow_mut().consume(used_gas).map_err(|err| {
        tracing::info!("Stopping VP execution because of gas error: {}", err);
        Error::new(RuntimeError::OutOfGas(err))
    })
}

/// Storage read prior state (before tx execution). It will try to read from the
/// storage.
pub fn read_pre<S>(
    gas_meter: &RefCell<impl GasMetering>,
    state: &S,
    key: &Key,
) -> Result<Option<Vec<u8>>>
where
    S: StateRead + Debug,
{
    let (log_val, gas) =
        state.write_log().read_pre(key).into_storage_result()?;
    add_gas(gas_meter, gas)?;
    match &log_val {
        Some(write_log::StorageModification::Write { value }) => {
            Ok(Some(value.clone()))
        }
        Some(write_log::StorageModification::Delete) => {
            // Given key has been deleted
            Ok(None)
        }
        Some(write_log::StorageModification::InitAccount { vp_code_hash }) => {
            // Read the VP of a new account
            Ok(Some(vp_code_hash.to_vec()))
        }
        None => {
            // When not found in write log, try to read from the storage
            let (value, gas) = state.db_read(key)?;
            add_gas(gas_meter, gas)?;
            Ok(value)
        }
    }
}

/// Storage read posterior state (after tx execution). It will try to read from
/// the write log first and if no entry found then from the storage.
pub fn read_post<S>(
    gas_meter: &RefCell<impl GasMetering>,
    state: &S,
    key: &Key,
) -> Result<Option<Vec<u8>>>
where
    S: StateRead + Debug,
{
    // Try to read from the write log first
    let (log_val, gas) = state.write_log().read(key).into_storage_result()?;
    add_gas(gas_meter, gas)?;
    match log_val {
        Some(write_log::StorageModification::Write { value }) => {
            Ok(Some(value.clone()))
        }
        Some(write_log::StorageModification::Delete) => {
            // Given key has been deleted
            Ok(None)
        }
        Some(write_log::StorageModification::InitAccount { vp_code_hash }) => {
            // Read the VP code hash of a new account
            Ok(Some(vp_code_hash.to_vec()))
        }
        None => {
            // When not found in write log, try
            // to read from the storage
            let (value, gas) = state.db_read(key)?;
            add_gas(gas_meter, gas)?;
            Ok(value)
        }
    }
}

/// Storage read temporary state (after tx execution). It will try to read from
/// only the write log.
pub fn read_temp<S>(
    gas_meter: &RefCell<impl GasMetering>,
    state: &S,
    key: &Key,
) -> Result<Option<Vec<u8>>>
where
    S: StateRead + Debug,
{
    let (log_val, gas) =
        state.write_log().read_temp(key).into_storage_result()?;
    add_gas(gas_meter, gas)?;
    Ok(log_val.cloned())
}

/// Storage `has_key` in prior state (before tx execution). It will try to read
/// from the storage.
pub fn has_key_pre<S>(
    gas_meter: &RefCell<impl GasMetering>,
    state: &S,
    key: &Key,
) -> Result<bool>
where
    S: StateRead + Debug,
{
    // Try to read from the write log first
    let (log_val, gas) =
        state.write_log().read_pre(key).into_storage_result()?;
    add_gas(gas_meter, gas)?;
    match log_val {
        Some(&write_log::StorageModification::Write { .. }) => Ok(true),
        Some(&write_log::StorageModification::Delete) => {
            // The given key has been deleted
            Ok(false)
        }
        Some(&write_log::StorageModification::InitAccount { .. }) => Ok(true),
        None => {
            // When not found in write log, try to check the storage
            let (present, gas) = state.db_has_key(key)?;
            add_gas(gas_meter, gas)?;
            Ok(present)
        }
    }
}

/// Storage `has_key` in posterior state (after tx execution). It will try to
/// check the write log first and if no entry found then the storage.
pub fn has_key_post<S>(
    gas_meter: &RefCell<impl GasMetering>,
    state: &S,
    key: &Key,
) -> Result<bool>
where
    S: StateRead + Debug,
{
    // Try to read from the write log first
    let (log_val, gas) = state.write_log().read(key).into_storage_result()?;
    add_gas(gas_meter, gas)?;
    match log_val {
        Some(write_log::StorageModification::Write { .. }) => Ok(true),
        Some(write_log::StorageModification::Delete) => {
            // The given key has been deleted
            Ok(false)
        }
        Some(write_log::StorageModification::InitAccount { .. }) => Ok(true),
        None => {
            // When not found in write log, try
            // to check the storage
            let (present, gas) = state.db_has_key(key)?;
            add_gas(gas_meter, gas)?;
            Ok(present)
        }
    }
}

/// Getting the chain ID.
pub fn get_chain_id<S>(
    gas_meter: &RefCell<impl GasMetering>,
    state: &S,
) -> Result<ChainId>
where
    S: StateRead + Debug,
{
    let (chain_id, gas) = state.in_mem().get_chain_id();
    add_gas(gas_meter, gas)?;
    Ok(chain_id)
}

/// Getting the block height. The height is that of the block to which the
/// current transaction is being applied if we are in between the
/// `FinalizeBlock` and the `Commit` phases. For all the other phases we return
/// the block height of next block that the consensus process will decide upon
/// (i.e. the block height of the last committed block + 1)
pub fn get_block_height<S>(
    gas_meter: &RefCell<impl GasMetering>,
    state: &S,
) -> Result<BlockHeight>
where
    S: StateRead + Debug,
{
    let (height, gas) = state.in_mem().get_block_height();
    add_gas(gas_meter, gas)?;
    Ok(height)
}

/// Getting the block header.
pub fn get_block_header<S>(
    gas_meter: &RefCell<impl GasMetering>,
    state: &S,
    height: BlockHeight,
) -> Result<Option<BlockHeader>>
where
    S: StateRead + Debug,
{
    let (header, gas) = StateRead::get_block_header(state, Some(height))?;
    add_gas(gas_meter, gas)?;
    Ok(header)
}

/// Getting the block hash. The height is that of the block to which the
/// current transaction is being applied.
pub fn get_tx_code_hash(
    gas_meter: &RefCell<impl GasMetering>,
    batched_tx: &BatchedTxRef<'_>,
) -> Result<Option<Hash>> {
    add_gas(
        gas_meter,
        (HASH_LENGTH as u64)
            .checked_mul(MEMORY_ACCESS_GAS_PER_BYTE)
            .expect("Consts mul that cannot overflow")
            .into(),
    )?;
    let hash = batched_tx
        .tx
        .get_section(batched_tx.cmt.code_sechash())
        .and_then(|x| Section::code_sec(x.as_ref()))
        .map(|x| x.code.hash());
    Ok(hash)
}

/// Getting the block epoch. The epoch is that of the block to which the
/// current transaction is being applied.
pub fn get_block_epoch<S>(
    gas_meter: &RefCell<impl GasMetering>,
    state: &S,
) -> Result<Epoch>
where
    S: StateRead + Debug,
{
    let (epoch, gas) = state.in_mem().get_current_epoch();
    add_gas(gas_meter, gas)?;
    Ok(epoch)
}

/// Getting the transaction index.
pub fn get_tx_index(
    gas_meter: &RefCell<impl GasMetering>,
    indexed_tx: &IndexedTx,
) -> Result<IndexedTx> {
    add_gas(
        gas_meter,
        (TX_INDEX_LENGTH as u64)
            .checked_mul(MEMORY_ACCESS_GAS_PER_BYTE)
            .expect("Consts mul that cannot overflow")
            .into(),
    )?;
    Ok(*indexed_tx)
}

/// Getting the native token's address.
pub fn get_native_token<S>(
    gas_meter: &RefCell<impl GasMetering>,
    state: &S,
) -> Result<Address>
where
    S: StateRead + Debug,
{
    add_gas(
        gas_meter,
        (ESTABLISHED_ADDRESS_BYTES_LEN as u64)
            .checked_mul(MEMORY_ACCESS_GAS_PER_BYTE)
            .expect("Consts mul that cannot overflow")
            .into(),
    )?;
    Ok(state.in_mem().native_token.clone())
}

/// Given the information about predecessor block epochs
pub fn get_pred_epochs<S>(
    gas_meter: &RefCell<impl GasMetering>,
    state: &S,
) -> Result<Epochs>
where
    S: StateRead + Debug,
{
    let len = state.in_mem().block.pred_epochs.first_block_heights.len() as u64;
    add_gas(
        gas_meter,
        checked!(len * 8 * MEMORY_ACCESS_GAS_PER_BYTE)?.into(),
    )?;
    Ok(state.in_mem().block.pred_epochs.clone())
}

/// Query events emitted by the current transaction.
pub fn get_events<S>(
    _gas_meter: &RefCell<impl GasMetering>,
    state: &S,
    event_type: String,
) -> Result<Vec<Event>>
where
    S: StateRead + Debug,
{
    let event_type = EventTypeBuilder::new_with_type(event_type).build();

    Ok(state
        .write_log()
        .lookup_events_with_prefix(&event_type)
        .cloned()
        .collect())
}

/// Storage prefix iterator for prior state (before tx execution), ordered by
/// storage keys. It will try to get an iterator from the storage.
pub fn iter_prefix_pre<'a, D>(
    gas_meter: &RefCell<impl GasMetering>,
    // We cannot use e.g. `&'a State`, because it doesn't live long
    // enough - the lifetime of the `PrefixIter` must depend on the lifetime of
    // references to the `WriteLog` and `DB`.
    write_log: &'a WriteLog,
    db: &'a D,
    prefix: &Key,
) -> Result<PrefixIter<'a, D>>
where
    D: DB + for<'iter> DBIter<'iter>,
{
    let (iter, gas) = namada_state::iter_prefix_pre(write_log, db, prefix)?;
    add_gas(gas_meter, gas)?;
    Ok(iter)
}

/// Storage prefix iterator for posterior state (after tx execution), ordered by
/// storage keys. It will try to get an iterator from the storage.
pub fn iter_prefix_post<'a, D>(
    gas_meter: &RefCell<impl GasMetering>,
    // We cannot use e.g. `&'a State`, because it doesn't live long
    // enough - the lifetime of the `PrefixIter` must depend on the lifetime of
    // references to the `WriteLog` and `DB`.
    write_log: &'a WriteLog,
    db: &'a D,
    prefix: &Key,
) -> Result<PrefixIter<'a, D>>
where
    D: DB + for<'iter> DBIter<'iter>,
{
    let (iter, gas) = namada_state::iter_prefix_post(write_log, db, prefix)?;
    add_gas(gas_meter, gas)?;
    Ok(iter)
}

/// Get the next item in a storage prefix iterator (pre or post).
pub fn iter_next<DB>(
    gas_meter: &RefCell<impl GasMetering>,
    iter: &mut PrefixIter<'_, DB>,
) -> Result<Option<(String, Vec<u8>)>>
where
    DB: namada_state::DB + for<'iter> namada_state::DBIter<'iter>,
{
    if let Some((key, val, gas)) = iter.next() {
        add_gas(gas_meter, gas)?;
        return Ok(Some((key, val)));
    }
    Ok(None)
}
