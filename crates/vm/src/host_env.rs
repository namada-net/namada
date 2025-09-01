//! Virtual machine's host environment exposes functions that may be called from
//! within a virtual machine.

pub mod gas_meter;
pub mod state;

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::num::TryFromIntError;

use namada_account::AccountPublicKeysMap;
use namada_core::address::{self, Address, ESTABLISHED_ADDRESS_BYTES_LEN};
use namada_core::arith::checked;
use namada_core::borsh::{BorshDeserialize, BorshSerializeExt};
use namada_core::chain::BlockHeight;
use namada_core::collections::HashSet;
use namada_core::decode;
use namada_core::hash::Hash;
use namada_core::internal::{HostEnvResult, KeyVal};
use namada_core::storage::{Key, TX_INDEX_LENGTH, TxIndex};
use namada_events::{Event, EventTypeBuilder};
use namada_gas::{
    self as gas, Gas, GasMetering, MEMORY_ACCESS_GAS_PER_BYTE, TxGasMeter,
    VpGasMeter,
};
use namada_state::prefix_iter::{PrefixIteratorId, PrefixIterators};
use namada_state::write_log::{self, WriteLog};
use namada_state::{
    DB, DBIter, InMemory, OptionExt, ResultExt, State, StateRead,
    StorageHasher, StorageRead, StorageWrite,
};
pub use namada_state::{Error, Result};
use namada_token::MaspTransaction;
use namada_token::storage_key::{
    is_any_minted_balance_key, is_any_minter_key, is_any_token_balance_key,
    is_any_token_parameter_key,
};
use namada_tx::data::{InnerTxId, TxSentinel};
use namada_tx::{BatchedTx, BatchedTxRef, Tx, TxCommitments};
use namada_vp::vp_host_fns;
use thiserror::Error;

use self::state::{TxHostEnvState, VpHostEnvState};
#[cfg(feature = "wasm-runtime")]
use super::wasm::{TxCache, VpCache};
use crate::memory::VmMemory;
use crate::{
    HostRef, RoAccess, RoHostRef, RwAccess, RwHostRef, WasmCacheAccess,
};

/// These runtime errors will abort tx WASM execution immediately
#[allow(missing_docs)]
#[allow(clippy::result_large_err)]
#[derive(Error, Debug)]
pub enum TxRuntimeError {
    #[error("Out of gas: {0}")]
    OutOfGas(gas::Error),
    #[error("Gas overflow")]
    GasOverflow,
    #[error("Trying to modify storage for an address that doesn't exit {0}")]
    UnknownAddressStorageModification(Address),
    #[error(
        "Trying to use a validity predicate with an invalid WASM code hash {0}"
    )]
    InvalidVpCodeHash(String),
    #[error("A validity predicate of an account cannot be deleted")]
    CannotDeleteVp,
    #[error("Encoding error: {0}")]
    EncodingError(std::io::Error),
    #[error("Address error: {0}")]
    AddressError(address::DecodeError),
    #[error("Numeric conversion error: {0}")]
    NumConversionError(#[from] TryFromIntError),
    #[error("Memory error: {0}")]
    MemoryError(Box<dyn std::error::Error + Sync + Send + 'static>),
    #[error("No value found in result buffer")]
    NoValueInResultBuffer,
    #[error("VP code is not allowed in allowlist parameter.")]
    DisallowedVp,
}

impl From<TxRuntimeError> for namada_state::Error {
    fn from(value: TxRuntimeError) -> Self {
        Self::new(value)
    }
}

/// Result of a tx host env fn call
pub type TxResult<T> = namada_state::Result<T>;

/// A transaction's host environment
pub struct TxVmEnv<MEM, D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// The VM memory for bi-directional data passing
    pub memory: MEM,
    /// The tx context contains references to host structures.
    pub ctx: TxCtx<D, H, CA>,
}

/// A transaction's host context
#[derive(Debug)]
pub struct TxCtx<D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Mutable access to write log.
    pub write_log: HostRef<RwAccess, WriteLog>,
    /// Read-only access to in-memory state.
    pub in_mem: HostRef<RoAccess, InMemory<H>>,
    /// Read-only access to DB.
    pub db: HostRef<RoAccess, D>,
    /// Storage prefix iterators.
    pub iterators: HostRef<RwAccess, PrefixIterators<'static, D>>,
    /// Transaction gas meter. In  `RefCell` to charge gas in read-only fns.
    pub gas_meter: HostRef<RoAccess, RefCell<gas_meter::GasMeter<TxGasMeter>>>,
    /// Transaction sentinel. In  `RefCell` to charge gas in read-only fns.
    pub sentinel: HostRef<RoAccess, RefCell<TxSentinel>>,
    /// Hash of the wrapper transaction associated with
    /// the current inner tx.
    pub wrapper_hash: HostRef<RoAccess, Hash>,
    /// The transaction code is used for signature verification
    pub tx: HostRef<RoAccess, Tx>,
    /// The commitments inside the transaction
    pub cmt: HostRef<RoAccess, TxCommitments>,
    /// The transaction index is used to identify a shielded transaction's
    /// parent
    pub tx_index: HostRef<RoAccess, TxIndex>,
    /// The verifiers whose validity predicates should be triggered.
    pub verifiers: HostRef<RwAccess, BTreeSet<Address>>,
    /// Cache for 2-step reads from host environment.
    pub result_buffer: HostRef<RwAccess, Option<Vec<u8>>>,
    /// Storage for byte buffer values yielded from the guest.
    pub yielded_value: HostRef<RwAccess, Option<Vec<u8>>>,
    /// VP WASM compilation cache (this is available in tx context, because
    /// we're pre-compiling VPs from [`tx_init_account`])
    #[cfg(feature = "wasm-runtime")]
    pub vp_wasm_cache: HostRef<RwAccess, VpCache<CA>>,
    /// Tx WASM compilation cache
    #[cfg(feature = "wasm-runtime")]
    pub tx_wasm_cache: HostRef<RwAccess, TxCache<CA>>,
    /// To avoid unused parameter without "wasm-runtime" feature
    #[cfg(not(feature = "wasm-runtime"))]
    pub cache_access: std::marker::PhantomData<CA>,
}

impl<MEM, D, H, CA> TxVmEnv<MEM, D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    /// Create a new environment for transaction execution.
    ///
    /// # Safety
    ///
    /// The way the arguments to this function are used is not thread-safe,
    /// we're assuming single-threaded tx execution with exclusive access to the
    /// mutable references.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        memory: MEM,
        write_log: &mut WriteLog,
        in_mem: &InMemory<H>,
        db: &D,
        iterators: &mut PrefixIterators<'static, D>,
        gas_meter: &RefCell<gas_meter::GasMeter<TxGasMeter>>,
        sentinel: &RefCell<TxSentinel>,
        wrapper_hash: &Hash,
        tx: &Tx,
        cmt: &TxCommitments,
        tx_index: &TxIndex,
        verifiers: &mut BTreeSet<Address>,
        result_buffer: &mut Option<Vec<u8>>,
        yielded_value: &mut Option<Vec<u8>>,
        #[cfg(feature = "wasm-runtime")] vp_wasm_cache: &mut VpCache<CA>,
        #[cfg(feature = "wasm-runtime")] tx_wasm_cache: &mut TxCache<CA>,
    ) -> Self {
        let write_log = unsafe { RwHostRef::new(write_log) };
        let in_mem = unsafe { RoHostRef::new(in_mem) };
        let db = unsafe { RoHostRef::new(db) };
        let iterators = unsafe { RwHostRef::new(iterators) };
        let gas_meter = unsafe { RoHostRef::new(gas_meter) };
        let sentinel = unsafe { RoHostRef::new(sentinel) };
        let wrapper_hash = unsafe { RoHostRef::new(wrapper_hash) };
        let tx = unsafe { RoHostRef::new(tx) };
        let cmt = unsafe { RoHostRef::new(cmt) };
        let tx_index = unsafe { RoHostRef::new(tx_index) };
        let verifiers = unsafe { RwHostRef::new(verifiers) };
        let result_buffer = unsafe { RwHostRef::new(result_buffer) };
        let yielded_value = unsafe { RwHostRef::new(yielded_value) };
        #[cfg(feature = "wasm-runtime")]
        let vp_wasm_cache = unsafe { RwHostRef::new(vp_wasm_cache) };
        #[cfg(feature = "wasm-runtime")]
        let tx_wasm_cache = unsafe { RwHostRef::new(tx_wasm_cache) };
        let ctx = TxCtx {
            write_log,
            db,
            in_mem,
            iterators,
            gas_meter,
            sentinel,
            wrapper_hash,
            tx,
            cmt,
            tx_index,
            verifiers,
            result_buffer,
            yielded_value,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache,
            #[cfg(feature = "wasm-runtime")]
            tx_wasm_cache,
            #[cfg(not(feature = "wasm-runtime"))]
            cache_access: std::marker::PhantomData,
        };

        Self { memory, ctx }
    }

    /// Access state from within a tx
    pub fn state(&self) -> TxHostEnvState<'_, D, H> {
        self.ctx.state()
    }
}

impl<MEM, D, H, CA> Clone for TxVmEnv<MEM, D, H, CA>
where
    MEM: Clone,
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    fn clone(&self) -> Self {
        Self {
            memory: self.memory.clone(),
            ctx: self.ctx.clone(),
        }
    }
}

impl<D, H, CA> TxCtx<D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    /// Access state from within a tx
    pub fn state(&self) -> TxHostEnvState<'_, D, H> {
        let write_log = unsafe { self.write_log.get_mut() };
        let db = unsafe { self.db.get() };
        let in_mem = unsafe { self.in_mem.get() };
        let gas_meter = unsafe { self.gas_meter.get() };
        let sentinel = unsafe { self.sentinel.get() };
        TxHostEnvState {
            write_log,
            db,
            in_mem,
            gas_meter,
            sentinel,
        }
    }

    /// Use gas meter and sentinel
    pub fn gas_meter_and_sentinel(
        &self,
    ) -> (
        &RefCell<gas_meter::GasMeter<TxGasMeter>>,
        &RefCell<TxSentinel>,
    ) {
        let gas_meter = unsafe { self.gas_meter.get() };
        let sentinel = unsafe { self.sentinel.get() };
        (gas_meter, sentinel)
    }
}

impl<D, H, CA> Clone for TxCtx<D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    fn clone(&self) -> Self {
        Self {
            write_log: self.write_log,
            db: self.db,
            in_mem: self.in_mem,
            iterators: self.iterators,
            gas_meter: self.gas_meter,
            sentinel: self.sentinel,
            wrapper_hash: self.wrapper_hash,
            tx: self.tx,
            cmt: self.cmt,
            tx_index: self.tx_index,
            verifiers: self.verifiers,
            result_buffer: self.result_buffer,
            yielded_value: self.yielded_value,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache: self.vp_wasm_cache,
            #[cfg(feature = "wasm-runtime")]
            tx_wasm_cache: self.tx_wasm_cache,
            #[cfg(not(feature = "wasm-runtime"))]
            cache_access: std::marker::PhantomData,
        }
    }
}

/// A validity predicate's host environment
pub struct VpVmEnv<MEM, D, H, EVAL, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// The VM memory for bi-directional data passing
    pub memory: MEM,
    /// The VP context contains references to host structures.
    pub ctx: VpCtx<D, H, EVAL, CA>,
}

/// A validity predicate's host context
pub struct VpCtx<D, H, EVAL, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// The address of the account that owns the VP
    pub address: HostRef<RoAccess, Address>,
    /// Read-only access to write log.
    pub write_log: HostRef<RoAccess, WriteLog>,
    /// Read-only access to in-memory state.
    pub in_mem: HostRef<RoAccess, InMemory<H>>,
    /// Read-only access to DB.
    pub db: HostRef<RoAccess, D>,
    /// Storage prefix iterators.
    pub iterators: HostRef<RwAccess, PrefixIterators<'static, D>>,
    /// VP gas meter. In  `RefCell` to charge gas in read-only fns.
    pub gas_meter: HostRef<RoAccess, RefCell<gas_meter::GasMeter<VpGasMeter>>>,
    /// The transaction code is used for signature verification
    pub tx: HostRef<RoAccess, Tx>,
    /// The commitments inside the transaction
    pub cmt: HostRef<RoAccess, TxCommitments>,
    /// The transaction index is used to identify a shielded transaction's
    /// parent
    pub tx_index: HostRef<RoAccess, TxIndex>,
    /// The runner of the [`vp_eval`] function
    pub eval_runner: HostRef<RoAccess, EVAL>,
    /// Cache for 2-step reads from host environment.
    pub result_buffer: HostRef<RwAccess, Option<Vec<u8>>>,
    /// Storage for byte buffer values yielded from the guest.
    pub yielded_value: HostRef<RwAccess, Option<Vec<u8>>>,
    /// The storage keys that have been changed. Used for calls to `eval`.
    pub keys_changed: HostRef<RoAccess, BTreeSet<Key>>,
    /// The verifiers whose validity predicates should be triggered. Used for
    /// calls to `eval`.
    pub verifiers: HostRef<RoAccess, BTreeSet<Address>>,
    /// VP WASM compilation cache
    #[cfg(feature = "wasm-runtime")]
    pub vp_wasm_cache: HostRef<RwAccess, VpCache<CA>>,
    /// To avoid unused parameter without "wasm-runtime" feature
    #[cfg(not(feature = "wasm-runtime"))]
    pub cache_access: std::marker::PhantomData<CA>,
}

/// A Validity predicate runner for calls from the [`vp_eval`] function.
pub trait VpEvaluator {
    /// DB type
    type Db: DB + for<'iter> DBIter<'iter>;
    /// Storage hasher type
    type H: StorageHasher;
    /// Recursive VP evaluator type
    type Eval: VpEvaluator;
    /// WASM compilation cache access
    type CA: WasmCacheAccess;

    /// Evaluate a given validity predicate code with the given input data.
    /// Currently, we can only evaluate VPs using WASM runner with WASM memory.
    ///
    /// Invariant: Calling `VpEvalRunner::eval` from the VP is synchronous as it
    /// shares mutable access to the host context with the VP.
    fn eval(
        &self,
        ctx: VpCtx<Self::Db, Self::H, Self::Eval, Self::CA>,
        vp_code_hash: Hash,
        input_data: BatchedTxRef<'_>,
    ) -> HostEnvResult;
}

impl<MEM, D, H, EVAL, CA> VpVmEnv<MEM, D, H, EVAL, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    /// Create a new environment for validity predicate execution.
    ///
    /// # Safety
    ///
    /// The way the arguments to this function are used is not thread-safe,
    /// we're assuming multi-threaded VP execution, but with with exclusive
    /// access to the mutable references (no shared access).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        memory: MEM,
        address: &Address,
        write_log: &WriteLog,
        in_mem: &InMemory<H>,
        db: &D,
        gas_meter: &RefCell<gas_meter::GasMeter<VpGasMeter>>,
        tx: &Tx,
        cmt: &TxCommitments,
        tx_index: &TxIndex,
        iterators: &mut PrefixIterators<'static, D>,
        verifiers: &BTreeSet<Address>,
        result_buffer: &mut Option<Vec<u8>>,
        yielded_value: &mut Option<Vec<u8>>,
        keys_changed: &BTreeSet<Key>,
        eval_runner: &EVAL,
        #[cfg(feature = "wasm-runtime")] vp_wasm_cache: &mut VpCache<CA>,
    ) -> Self {
        let ctx = VpCtx::new(
            address,
            write_log,
            in_mem,
            db,
            gas_meter,
            tx,
            cmt,
            tx_index,
            iterators,
            verifiers,
            result_buffer,
            yielded_value,
            keys_changed,
            eval_runner,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache,
        );

        Self { memory, ctx }
    }

    /// Access state from within a VP
    pub fn state(&self) -> VpHostEnvState<'_, D, H> {
        self.ctx.state()
    }
}

impl<MEM, D, H, EVAL, CA> Clone for VpVmEnv<MEM, D, H, EVAL, CA>
where
    MEM: Clone,
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    fn clone(&self) -> Self {
        Self {
            memory: self.memory.clone(),
            ctx: self.ctx.clone(),
        }
    }
}

impl<D, H, EVAL, CA> VpCtx<D, H, EVAL, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    /// Create a new context for validity predicate execution.
    ///
    /// # Safety
    ///
    /// The way the arguments to this function are used is not thread-safe,
    /// we're assuming multi-threaded VP execution, but with with exclusive
    /// access to the mutable references (no shared access).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: &Address,
        write_log: &WriteLog,
        in_mem: &InMemory<H>,
        db: &D,
        gas_meter: &RefCell<gas_meter::GasMeter<VpGasMeter>>,
        tx: &Tx,
        cmt: &TxCommitments,
        tx_index: &TxIndex,
        iterators: &mut PrefixIterators<'static, D>,
        verifiers: &BTreeSet<Address>,
        result_buffer: &mut Option<Vec<u8>>,
        yielded_value: &mut Option<Vec<u8>>,
        keys_changed: &BTreeSet<Key>,
        eval_runner: &EVAL,
        #[cfg(feature = "wasm-runtime")] vp_wasm_cache: &mut VpCache<CA>,
    ) -> Self {
        let address = unsafe { RoHostRef::new(address) };
        let write_log = unsafe { RoHostRef::new(write_log) };
        let db = unsafe { RoHostRef::new(db) };
        let in_mem = unsafe { RoHostRef::new(in_mem) };
        let tx = unsafe { RoHostRef::new(tx) };
        let cmt = unsafe { RoHostRef::new(cmt) };
        let tx_index = unsafe { RoHostRef::new(tx_index) };
        let iterators = unsafe { RwHostRef::new(iterators) };
        let gas_meter = unsafe { RoHostRef::new(gas_meter) };
        let verifiers = unsafe { RoHostRef::new(verifiers) };
        let result_buffer = unsafe { RwHostRef::new(result_buffer) };
        let yielded_value = unsafe { RwHostRef::new(yielded_value) };
        let keys_changed = unsafe { RoHostRef::new(keys_changed) };
        let eval_runner = unsafe { RoHostRef::new(eval_runner) };
        #[cfg(feature = "wasm-runtime")]
        let vp_wasm_cache = unsafe { RwHostRef::new(vp_wasm_cache) };
        Self {
            address,
            write_log,
            db,
            in_mem,
            iterators,
            gas_meter,
            tx,
            cmt,
            tx_index,
            eval_runner,
            result_buffer,
            yielded_value,
            keys_changed,
            verifiers,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache,
            #[cfg(not(feature = "wasm-runtime"))]
            cache_access: std::marker::PhantomData,
        }
    }

    /// Access state from within a VP
    pub fn state(&self) -> VpHostEnvState<'_, D, H> {
        let write_log = unsafe { self.write_log.get() };
        let db = unsafe { self.db.get() };
        let in_mem = unsafe { self.in_mem.get() };
        let gas_meter = unsafe { self.gas_meter.get() };
        VpHostEnvState {
            write_log,
            db,
            in_mem,
            gas_meter,
        }
    }

    /// Use gas meter
    pub fn gas_meter(&self) -> &RefCell<gas_meter::GasMeter<VpGasMeter>> {
        unsafe { self.gas_meter.get() }
    }
}

impl<D, H, EVAL, CA> Clone for VpCtx<D, H, EVAL, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    fn clone(&self) -> Self {
        Self {
            address: self.address,
            write_log: self.write_log,
            db: self.db,
            in_mem: self.in_mem,
            iterators: self.iterators,
            gas_meter: self.gas_meter,
            tx: self.tx,
            cmt: self.cmt,
            tx_index: self.tx_index,
            eval_runner: self.eval_runner,
            result_buffer: self.result_buffer,
            yielded_value: self.yielded_value,
            keys_changed: self.keys_changed,
            verifiers: self.verifiers,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache: self.vp_wasm_cache,
            #[cfg(not(feature = "wasm-runtime"))]
            cache_access: std::marker::PhantomData,
        }
    }
}

/// Add a gas cost incured in a transaction
pub fn tx_charge_gas<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    used_gas: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    consume_tx_gas(env, used_gas.into())
}

/// Called from VP wasm to request to use the given gas amount
pub fn vp_charge_gas<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    used_gas: u64,
) -> Result<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = env.ctx.gas_meter();
    println!("vp gas {}", used_gas);
    vp_host_fns::add_gas(gas_meter, used_gas.into())
}

/// Storage `has_key` function exposed to the wasm VM Tx environment. It will
/// try to check the write log first and if no entry found then the storage.
pub fn tx_has_key<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    key_ptr: u64,
    key_len: u64,
) -> TxResult<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    tracing::debug!("tx_has_key {}, key {}", key, key_ptr,);
    println!("tx_has_key {}", key);

    let key = Key::parse(key)?;

    // try to read from the write log first
    let state = env.state();
    let present = state.has_key(&key)?;
    Ok(HostEnvResult::from(present).to_i64())
}

/// Storage read function exposed to the wasm VM Tx environment. It will try to
/// read from the write log first and if no entry found then from the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn tx_read<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    key_ptr: u64,
    key_len: u64,
) -> TxResult<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    tracing::debug!("tx_read {}, key {}", key, key_ptr,);
    println!("tx_read {}", key);

    let key = Key::parse(key)?;

    let state = env.state();
    let value = state.read_bytes(&key)?;
    match value {
        Some(value) => {
            let len: i64 = value
                .len()
                .try_into()
                .map_err(TxRuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
            result_buffer.replace(value);
            Ok(len)
        }
        None => Ok(HostEnvResult::Fail.to_i64()),
    }
}

/// Read temporary value (not committed to storage) from the given key function
/// exposed to the wasm VM Tx environment. It will try to read from the write
/// log only.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn tx_read_temp<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    key_ptr: u64,
    key_len: u64,
) -> TxResult<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    tracing::debug!("tx_read {}, key {}", key, key_ptr,);

    let key = Key::parse(key)?;

    let write_log = unsafe { env.ctx.write_log.get() };
    let (log_val, gas) = write_log.read_temp(&key).into_storage_result()?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    match log_val {
        Some(value) => {
            let len: i64 = value
                .len()
                .try_into()
                .map_err(TxRuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
            result_buffer.replace(value.clone());
            Ok(len)
        }
        None => Ok(HostEnvResult::Fail.to_i64()),
    }
}

/// This function is a helper to handle the first step of reading var-len
/// values from the host.
///
/// In cases where we're reading a value from the host in the guest and
/// we don't know the byte size up-front, we have to read it in 2-steps. The
/// first step reads the value into a result buffer and returns the size (if
/// any) back to the guest, the second step reads the value from cache into a
/// pre-allocated buffer with the obtained size.
pub fn tx_result_buffer<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    result_ptr: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
    let value = result_buffer
        .take()
        .ok_or(TxRuntimeError::NoValueInResultBuffer)?;
    let gas = env
        .memory
        .write_bytes(result_ptr, value)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)
}

/// Storage prefix iterator function exposed to the wasm VM Tx environment.
/// It will try to get an iterator from the storage and return the corresponding
/// ID of the iterator, ordered by storage keys.
pub fn tx_iter_prefix<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    prefix_ptr: u64,
    prefix_len: u64,
) -> TxResult<u64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (prefix, gas) = env
        .memory
        .read_string(prefix_ptr, prefix_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    tracing::debug!("tx_iter_prefix {}", prefix);
    println!("tx_iter_prefix {}", prefix);

    let prefix = Key::parse(prefix)?;

    let write_log = unsafe { env.ctx.write_log.get() };
    let db = unsafe { env.ctx.db.get() };
    let (iter, gas) = namada_state::iter_prefix_post(write_log, db, &prefix)?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    let iterators = unsafe { env.ctx.iterators.get_mut() };
    Ok(iterators
        .insert(iter)
        .ok_or_err_msg("Iterator ID overflow")?
        .id())
}

/// Storage prefix iterator next function exposed to the wasm VM Tx environment.
/// It will try to read from the write log first and if no entry found then from
/// the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn tx_iter_next<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    iter_id: u64,
) -> TxResult<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    tracing::debug!("tx_iter_next iter_id {}", iter_id,);
    println!("tx_iter_next");

    let iterators = unsafe { env.ctx.iterators.get_mut() };
    let iter_id = PrefixIteratorId::new(iter_id);
    while let Some((key, val, iter_gas)) = iterators.next(iter_id) {
        let (log_val, log_gas) = {
            let state = env.state();
            let (log_val, log_gas) = state
                .write_log()
                .read(&Key::parse(key.clone())?)
                .into_storage_result()?;
            (log_val.cloned(), log_gas)
        };
        consume_tx_gas::<MEM, D, H, CA>(env, checked!(iter_gas + log_gas)?)?;
        match log_val {
            Some(write_log::StorageModification::Write { value }) => {
                let key_val = borsh::to_vec(&KeyVal { key, val: value })
                    .map_err(TxRuntimeError::EncodingError)?;
                let len: i64 = key_val
                    .len()
                    .try_into()
                    .map_err(TxRuntimeError::NumConversionError)?;
                let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
                result_buffer.replace(key_val);
                return Ok(len);
            }
            Some(write_log::StorageModification::Delete) => {
                // check the next because the key has already deleted
                continue;
            }
            Some(write_log::StorageModification::InitAccount { .. }) => {
                // a VP of a new account doesn't need to be iterated
                continue;
            }
            None => {
                let key_val = borsh::to_vec(&KeyVal { key, val })
                    .map_err(TxRuntimeError::EncodingError)?;
                let len: i64 = key_val
                    .len()
                    .try_into()
                    .map_err(TxRuntimeError::NumConversionError)?;
                let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
                result_buffer.replace(key_val);
                return Ok(len);
            }
        }
    }
    Ok(HostEnvResult::Fail.to_i64())
}

/// Storage write function exposed to the wasm VM Tx environment. The given
/// key/value will be written to the write log.
pub fn tx_write<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    let (value, gas) = env
        .memory
        .read_bytes(val_ptr, val_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    tracing::debug!("tx_update {}", key);
    println!("tx_write {key}");

    let key = Key::parse(key)?;
    if key.is_validity_predicate().is_some() {
        tx_validate_vp_code_hash::<MEM, D, H, CA>(env, &value, &None)?;
    }

    check_address_existence::<MEM, D, H, CA>(env, &key)?;

    let mut state = env.state();
    state.write_bytes(&key, value)
}

/// Temporary storage write function exposed to the wasm VM Tx environment. The
/// given key/value will be written only to the write log. It will be never
/// written to the storage.
pub fn tx_write_temp<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    let (value, gas) = env
        .memory
        .read_bytes(val_ptr, val_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    tracing::debug!("tx_write_temp {}", key);

    let key = Key::parse(key)?;

    check_address_existence::<MEM, D, H, CA>(env, &key)?;

    let mut state = env.state();
    let (gas, _size_diff) = state.write_log_mut().write_temp(&key, value)?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)
}

fn check_address_existence<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    key: &Key,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    // Get the token if the key is a balance or minter key
    let token = if let Some([token, _]) = is_any_token_balance_key(key) {
        Some(token)
    } else if let Some(token) = is_any_token_parameter_key(key) {
        Some(token)
    } else {
        is_any_minted_balance_key(key).or_else(|| is_any_minter_key(key))
    };

    let state = env.state();
    for addr in key.find_addresses() {
        // skip if the address is a token address
        if Some(&addr) == token {
            continue;
        }
        // skip the check for implicit and internal addresses
        if let Address::Implicit(_) | Address::Internal(_) = &addr {
            continue;
        }
        let vp_key = Key::validity_predicate(&addr);
        let is_present = state.has_key(&vp_key)?;
        if !is_present {
            tracing::info!(
                "Trying to write into storage with a key containing an \
                 address that doesn't exist: {}",
                addr
            );
            return Err(TxRuntimeError::UnknownAddressStorageModification(
                addr,
            )
            .into());
        }
    }
    Ok(())
}

/// Storage delete function exposed to the wasm VM Tx environment. The given
/// key/value will be written as deleted to the write log.
pub fn tx_delete<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    key_ptr: u64,
    key_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    tracing::debug!("tx_delete {}", key);
    println!("tx_delete {key}");

    let key = Key::parse(key)?;
    if key.is_validity_predicate().is_some() {
        return Err(TxRuntimeError::CannotDeleteVp.into());
    }

    let mut state = env.state();
    state.delete(&key)
}

/// Expose the functionality to emit events to the wasm VM's Tx environment.
/// An emitted event will land in the write log.
pub fn tx_emit_event<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    event_ptr: u64,
    event_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (event, gas) = env
        .memory
        .read_bytes(event_ptr, event_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    println!("tx_emit_event");
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    let event: Event = BorshDeserialize::try_from_slice(&event)
        .map_err(TxRuntimeError::EncodingError)?;
    let mut state = env.state();
    let wrapper_hash = unsafe { env.ctx.wrapper_hash.get() };
    let cmt = unsafe { env.ctx.cmt.get() };
    let gas = state
        .write_log_mut()
        .emit_event_with_tx_hashes(
            event,
            Some(InnerTxId {
                wrapper_hash: Some(Cow::Borrowed(wrapper_hash)),
                commitments_hash: Cow::Owned(cmt.get_hash()),
            }),
        )
        .ok_or(TxRuntimeError::GasOverflow)?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)
}

/// Expose the functionality to query events from the wasm VM's Tx environment.
pub fn tx_get_events<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    event_type_ptr: u64,
    event_type_len: u64,
) -> TxResult<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (event_type, gas) = env
        .memory
        .read_string(event_type_ptr, event_type_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    println!("tx_get_events {event_type}");
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    let state = env.state();
    let value = {
        let event_type = EventTypeBuilder::new_with_type(event_type).build();

        let events: Vec<_> = state
            .write_log()
            .lookup_events_with_prefix(&event_type)
            .collect();

        events.serialize_to_vec()
    };
    let len: i64 = value
        .len()
        .try_into()
        .map_err(TxRuntimeError::NumConversionError)?;
    let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
    result_buffer.replace(value);
    Ok(len)
}

/// Storage read prior state (before tx execution) function exposed to the wasm
/// VM VP environment. It will try to read from the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn vp_read_pre<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    key_ptr: u64,
    key_len: u64,
) -> Result<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len.try_into()?)
        .map_err(Into::into)?;
    println!("vp_read_pre {key}");
    let gas_meter = env.ctx.gas_meter();
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)?;

    // try to read from the storage
    let key = Key::parse(key)?;
    let state = env.state();
    let value = vp_host_fns::read_pre(gas_meter, &state, &key)?;
    tracing::debug!(
        "vp_read_pre addr {}, key {}",
        unsafe { env.ctx.address.get() },
        key,
    );
    Ok(match value {
        Some(value) => {
            let len: i64 = value.len().try_into()?;
            let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
            result_buffer.replace(value);
            len
        }
        None => HostEnvResult::Fail.to_i64(),
    })
}

/// Storage read posterior state (after tx execution) function exposed to the
/// wasm VM VP environment. It will try to read from the write log first and if
/// no entry found then from the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn vp_read_post<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    key_ptr: u64,
    key_len: u64,
) -> Result<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len.try_into()?)
        .map_err(Into::into)?;
    println!("vp_read_post {key}");
    let gas_meter = env.ctx.gas_meter();
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)?;

    tracing::debug!("vp_read_post {}, key {}", key, key_ptr,);

    // try to read from the write log first
    let key = Key::parse(key)?;
    let state = env.state();
    let value = vp_host_fns::read_post(gas_meter, &state, &key)?;
    Ok(match value {
        Some(value) => {
            let len: i64 = value.len().try_into()?;
            let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
            result_buffer.replace(value);
            len
        }
        None => HostEnvResult::Fail.to_i64(),
    })
}

/// Storage read temporary state (after tx execution) function exposed to the
/// wasm VM VP environment. It will try to read from only the write log.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn vp_read_temp<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    key_ptr: u64,
    key_len: u64,
) -> Result<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len.try_into()?)
        .map_err(Into::into)?;
    let gas_meter = env.ctx.gas_meter();
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)?;

    tracing::debug!("vp_read_temp {}, key {}", key, key_ptr);

    // try to read from the write log
    let key = Key::parse(key)?;
    let state = env.state();
    let value = vp_host_fns::read_temp(gas_meter, &state, &key)?;
    Ok(match value {
        Some(value) => {
            let len: i64 = value.len().try_into()?;
            let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
            result_buffer.replace(value);
            len
        }
        None => HostEnvResult::Fail.to_i64(),
    })
}

/// This function is a helper to handle the first step of reading var-len
/// values from the host.
///
/// In cases where we're reading a value from the host in the guest and
/// we don't know the byte size up-front, we have to read it in 2-steps. The
/// first step reads the value into a result buffer and returns the size (if
/// any) back to the guest, the second step reads the value from cache into a
/// pre-allocated buffer with the obtained size.
pub fn vp_result_buffer<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    result_ptr: u64,
) -> Result<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
    let value = result_buffer
        .take()
        .ok_or(Error::new_const("No value found in result buffer"))?;
    let gas = env
        .memory
        .write_bytes(result_ptr, value)
        .map_err(Into::into)?;
    let gas_meter = env.ctx.gas_meter();
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)
}

/// Storage `has_key` in prior state (before tx execution) function exposed to
/// the wasm VM VP environment. It will try to read from the storage.
pub fn vp_has_key_pre<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    key_ptr: u64,
    key_len: u64,
) -> Result<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len.try_into()?)
        .map_err(Into::into)?;
    println!("vp_has_key_pre {key}");
    let gas_meter = env.ctx.gas_meter();
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)?;

    tracing::debug!("vp_has_key_pre {}, key {}", key, key_ptr,);

    let key = Key::parse(key)?;
    let state = env.state();
    let present = vp_host_fns::has_key_pre(gas_meter, &state, &key)?;
    Ok(HostEnvResult::from(present).to_i64())
}

/// Storage `has_key` in posterior state (after tx execution) function exposed
/// to the wasm VM VP environment. It will try to check the write log first and
/// if no entry found then the storage.
pub fn vp_has_key_post<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    key_ptr: u64,
    key_len: u64,
) -> Result<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len.try_into()?)
        .map_err(Into::into)?;
    println!("vp_has_key_post {key}");
    let gas_meter = env.ctx.gas_meter();
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)?;

    tracing::debug!("vp_has_key_post {}, key {}", key, key_ptr,);

    let key = Key::parse(key)?;
    let state = env.state();
    let present = vp_host_fns::has_key_post(gas_meter, &state, &key)?;
    Ok(HostEnvResult::from(present).to_i64())
}

/// Storage prefix iterator function for prior state (before tx execution)
/// exposed to the wasm VM VP environment.
///
/// It will try to get an iterator from the storage and return the corresponding
/// ID of the iterator, ordered by storage keys.
pub fn vp_iter_prefix_pre<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    prefix_ptr: u64,
    prefix_len: u64,
) -> Result<u64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (prefix, gas) = env
        .memory
        .read_string(prefix_ptr, prefix_len.try_into()?)
        .map_err(Into::into)?;
    println!("vp_iter_prefix_pre {prefix}");
    let gas_meter = env.ctx.gas_meter();
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)?;

    tracing::debug!("vp_iter_prefix_pre {}", prefix);

    let prefix = Key::parse(prefix)?;

    let write_log = unsafe { env.ctx.write_log.get() };
    let db = unsafe { env.ctx.db.get() };
    let iter = vp_host_fns::iter_prefix_pre(gas_meter, write_log, db, &prefix)?;

    let iterators = unsafe { env.ctx.iterators.get_mut() };
    Ok(iterators
        .insert(iter)
        .ok_or_err_msg("Iterator ID overflow")?
        .id())
}

/// Storage prefix iterator function for posterior state (after tx execution)
/// exposed to the wasm VM VP environment.
///
/// It will try to get an iterator from the storage and return the corresponding
/// ID of the iterator, ordered by storage keys.
pub fn vp_iter_prefix_post<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    prefix_ptr: u64,
    prefix_len: u64,
) -> Result<u64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (prefix, gas) = env
        .memory
        .read_string(prefix_ptr, prefix_len.try_into()?)
        .map_err(Into::into)?;
    println!("vp_iter_prefix_post {prefix}");
    let gas_meter = env.ctx.gas_meter();
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)?;

    tracing::debug!("vp_iter_prefix_post {}", prefix);

    let prefix = Key::parse(prefix)?;

    let write_log = unsafe { env.ctx.write_log.get() };
    let db = unsafe { env.ctx.db.get() };
    let iter =
        vp_host_fns::iter_prefix_post(gas_meter, write_log, db, &prefix)?;

    let iterators = unsafe { env.ctx.iterators.get_mut() };
    Ok(iterators
        .insert(iter)
        .ok_or_err_msg("Iterator ID overflow")?
        .id())
}

/// Storage prefix iterator for prior or posterior state function
/// exposed to the wasm VM VP environment.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn vp_iter_next<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    iter_id: u64,
) -> Result<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    tracing::debug!("vp_iter_next iter_id {}", iter_id);
    println!("vp_iter_next");

    let iterators = unsafe { env.ctx.iterators.get_mut() };
    let iter_id = PrefixIteratorId::new(iter_id);
    if let Some(iter) = iterators.get_mut(iter_id) {
        let gas_meter = env.ctx.gas_meter();
        if let Some((key, val)) = vp_host_fns::iter_next(gas_meter, iter)? {
            let key_val = KeyVal { key, val }.serialize_to_vec();
            let len: i64 = key_val.len().try_into()?;
            let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
            result_buffer.replace(key_val);
            return Ok(len);
        }
    }
    Ok(HostEnvResult::Fail.to_i64())
}

/// Verifier insertion function exposed to the wasm VM Tx environment.
pub fn tx_insert_verifier<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    addr_ptr: u64,
    addr_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (addr, gas) = env
        .memory
        .read_string(addr_ptr, addr_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    tracing::debug!("tx_insert_verifier {}, addr_ptr {}", addr, addr_ptr,);

    let addr = Address::decode(&addr).map_err(TxRuntimeError::AddressError)?;

    let verifiers = unsafe { env.ctx.verifiers.get_mut() };
    // This is not a storage write, use the same multiplier used for a storage
    // read
    consume_tx_gas::<MEM, D, H, CA>(
        env,
        checked!(addr_len * MEMORY_ACCESS_GAS_PER_BYTE)?.into(),
    )?;
    verifiers.insert(addr);

    Ok(())
}

/// Update a validity predicate function exposed to the wasm VM Tx environment
pub fn tx_update_validity_predicate<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    addr_ptr: u64,
    addr_len: u64,
    code_hash_ptr: u64,
    code_hash_len: u64,
    code_tag_ptr: u64,
    code_tag_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (addr, gas) = env
        .memory
        .read_string(addr_ptr, addr_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    let addr = Address::decode(addr).map_err(TxRuntimeError::AddressError)?;
    tracing::debug!("tx_update_validity_predicate for addr {}", addr);

    let (code_tag, gas) = env
        .memory
        .read_bytes(code_tag_ptr, code_tag_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    let code_tag = Option::<String>::try_from_slice(&code_tag)
        .map_err(TxRuntimeError::EncodingError)?;

    let key = Key::validity_predicate(&addr);
    let (code_hash, gas) = env
        .memory
        .read_bytes(code_hash_ptr, code_hash_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    tx_validate_vp_code_hash::<MEM, D, H, CA>(env, &code_hash, &code_tag)?;

    let mut state = env.state();
    let (gas, _size_diff) = state.write_log_mut().write(&key, code_hash)?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)
}

/// Initialize a new account established address.
#[allow(clippy::too_many_arguments)]
pub fn tx_init_account<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    code_hash_ptr: u64,
    code_hash_len: u64,
    code_tag_ptr: u64,
    code_tag_len: u64,
    entropy_source_ptr: u64,
    entropy_source_len: u64,
    result_ptr: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (code_hash, gas) = env
        .memory
        .read_bytes(code_hash_ptr, code_hash_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    let (code_tag, gas) = env
        .memory
        .read_bytes(code_tag_ptr, code_tag_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    let code_tag = Option::<String>::try_from_slice(&code_tag)
        .map_err(TxRuntimeError::EncodingError)?;

    tx_validate_vp_code_hash::<MEM, D, H, CA>(env, &code_hash, &code_tag)?;

    let (entropy_source, gas) = env
        .memory
        .read_bytes(entropy_source_ptr, entropy_source_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;

    tracing::debug!("tx_init_account");

    let code_hash = Hash::try_from(&code_hash[..])
        .map_err(|e| TxRuntimeError::InvalidVpCodeHash(e.to_string()))?;
    let mut state = env.state();
    let (write_log, in_mem, _db) = state.split_borrow();
    let r#gen = &in_mem.address_gen;
    let (addr, gas) = write_log.init_account(r#gen, code_hash, &entropy_source);
    let addr_bytes = addr.serialize_to_vec();
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    let gas = env
        .memory
        .write_bytes(result_ptr, addr_bytes)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)
}

/// Getting the chain ID function exposed to the wasm VM Tx environment.
pub fn tx_get_chain_id<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    result_ptr: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let state = env.state();
    let (chain_id, gas) = state.in_mem().get_chain_id();
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    let gas = env
        .memory
        .write_string(result_ptr, chain_id.to_string())
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)
}

/// Getting the block height function exposed to the wasm VM Tx
/// environment. The height is that of the block to which the current
/// transaction is being applied if we are in between the `FinalizeBlock`
/// and the `Commit` phases. For all the other phases we return the block height
/// of next block that the consensus process will decide upon (i.e. the block
/// height of the last committed block + 1)
pub fn tx_get_block_height<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
) -> TxResult<u64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let state = env.state();
    let (height, gas) = state.in_mem().get_block_height();
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    Ok(height.0)
}

/// Getting the transaction index function exposed to the wasm VM Tx
/// environment. The index is that of the transaction being applied
/// in the current block.
pub fn tx_get_tx_index<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
) -> TxResult<u32>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    consume_tx_gas::<MEM, D, H, CA>(
        env,
        (TX_INDEX_LENGTH as u64)
            .checked_mul(MEMORY_ACCESS_GAS_PER_BYTE)
            .expect("Consts mul that cannot overflow")
            .into(),
    )?;
    let tx_index = unsafe { env.ctx.tx_index.get() };
    Ok(tx_index.0)
}

/// Getting the block height function exposed to the wasm VM VP
/// environment. The height is that of the block to which the current
/// transaction is being applied.
pub fn vp_get_tx_index<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
) -> Result<u32>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = env.ctx.gas_meter();
    let tx_index = unsafe { env.ctx.tx_index.get() };
    let tx_idx = vp_host_fns::get_tx_index(gas_meter, tx_index)?;
    Ok(tx_idx.0)
}

/// Getting the block epoch function exposed to the wasm VM Tx
/// environment. The epoch is that of the block to which the current
/// transaction is being applied.
pub fn tx_get_block_epoch<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
) -> TxResult<u64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let state = env.state();
    let (epoch, gas) = state.in_mem().get_current_epoch();
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    Ok(epoch.0)
}

/// Get predecessor epochs function exposed to the wasm VM Tx environment.
pub fn tx_get_pred_epochs<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
) -> TxResult<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let state = env.state();
    let pred_epochs = state.in_mem().block.pred_epochs.clone();
    let bytes = pred_epochs.serialize_to_vec();
    let len: i64 = bytes
        .len()
        .try_into()
        .map_err(TxRuntimeError::NumConversionError)?;
    let len_u64 = u64::try_from(len)?;
    consume_tx_gas::<MEM, D, H, CA>(
        env,
        checked!(MEMORY_ACCESS_GAS_PER_BYTE * len_u64)?.into(),
    )?;
    let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
    result_buffer.replace(bytes);
    Ok(len)
}

/// Get the native token's address
pub fn tx_get_native_token<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    result_ptr: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    // Gas for getting the native token address from storage
    consume_tx_gas::<MEM, D, H, CA>(
        env,
        (ESTABLISHED_ADDRESS_BYTES_LEN as u64)
            .checked_mul(MEMORY_ACCESS_GAS_PER_BYTE)
            .expect("Consts mul that cannot overflow")
            .into(),
    )?;
    let state = env.state();
    let native_token = state.in_mem().native_token.clone();
    let native_token_string = native_token.encode();
    let gas = env
        .memory
        .write_string(result_ptr, native_token_string)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)
}

/// Getting the block header function exposed to the wasm VM Tx environment.
pub fn tx_get_block_header<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    height: u64,
) -> TxResult<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let state = env.state();
    let (header, gas) =
        StateRead::get_block_header(&state, Some(BlockHeight(height)))?;

    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    Ok(match header {
        Some(h) => {
            let value = h.serialize_to_vec();
            let len: i64 = value
                .len()
                .try_into()
                .map_err(TxRuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
            result_buffer.replace(value);
            len
        }
        None => HostEnvResult::Fail.to_i64(),
    })
}

/// Getting the chain ID function exposed to the wasm VM VP environment.
pub fn vp_get_chain_id<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    result_ptr: u64,
) -> Result<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = env.ctx.gas_meter();
    let state = env.state();
    let chain_id = vp_host_fns::get_chain_id(gas_meter, &state)?;
    let gas = env
        .memory
        .write_string(result_ptr, chain_id.to_string())
        .map_err(Into::into)?;
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)
}

/// Getting the block height function exposed to the wasm VM VP
/// environment. The height is that of the block to which the current
/// transaction is being applied if we are in between the `FinalizeBlock`
/// and the `Commit` phases. For all the other phases we return the block height
/// of next block that the consensus process will decide upon (i.e. the block
/// height of the last committed block + 1)
pub fn vp_get_block_height<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
) -> Result<u64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = env.ctx.gas_meter();
    let state = env.state();
    let height = vp_host_fns::get_block_height(gas_meter, &state)?;
    Ok(height.0)
}

/// Getting the block header function exposed to the wasm VM VP environment.
pub fn vp_get_block_header<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    height: u64,
) -> Result<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = env.ctx.gas_meter();
    let state = env.state();
    let (header, gas) =
        StateRead::get_block_header(&state, Some(BlockHeight(height)))?;
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)?;
    Ok(match header {
        Some(h) => {
            let value = h.serialize_to_vec();
            let len: i64 = value.len().try_into()?;
            let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
            result_buffer.replace(value);
            len
        }
        None => HostEnvResult::Fail.to_i64(),
    })
}

/// Getting the transaction hash function exposed to the wasm VM VP environment.
pub fn vp_get_tx_code_hash<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    result_ptr: u64,
) -> Result<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = env.ctx.gas_meter();
    let tx = unsafe { env.ctx.tx.get() };
    let cmt = unsafe { env.ctx.cmt.get() };
    let batched_tx = tx.batch_ref_tx(cmt);
    let hash = vp_host_fns::get_tx_code_hash(gas_meter, &batched_tx)?;
    let mut result_bytes = vec![];
    if let Some(hash) = hash {
        result_bytes.push(1);
        result_bytes.extend(hash.0);
    } else {
        result_bytes.push(0);
    };
    let gas = env
        .memory
        .write_bytes(result_ptr, result_bytes)
        .map_err(Into::into)?;
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)
}

/// Getting the block epoch function exposed to the wasm VM VP
/// environment. The epoch is that of the block to which the current
/// transaction is being applied.
pub fn vp_get_block_epoch<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
) -> Result<u64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = env.ctx.gas_meter();
    let state = env.state();
    let epoch = vp_host_fns::get_block_epoch(gas_meter, &state)?;
    Ok(epoch.0)
}

/// Get predecessor epochs function exposed to the wasm VM VP environment.
pub fn vp_get_pred_epochs<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
) -> Result<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = env.ctx.gas_meter();
    let state = env.state();
    let pred_epochs = vp_host_fns::get_pred_epochs(gas_meter, &state)?;
    let bytes = pred_epochs.serialize_to_vec();
    let len: i64 = bytes.len().try_into()?;
    let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
    result_buffer.replace(bytes);
    Ok(len)
}

/// Expose the functionality to query events from the wasm VM's VP environment.
pub fn vp_get_events<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    event_type_ptr: u64,
    event_type_len: u64,
) -> Result<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (event_type, gas) = env
        .memory
        .read_string(event_type_ptr, event_type_len.try_into()?)
        .map_err(Into::into)?;
    println!("vp_get_events {event_type}");
    let gas_meter = env.ctx.gas_meter();
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)?;

    let state = env.state();
    let events = vp_host_fns::get_events(gas_meter, &state, event_type)?;
    let value = events.serialize_to_vec();
    let len: i64 = value.len().try_into()?;
    let result_buffer = unsafe { env.ctx.result_buffer.get_mut() };
    result_buffer.replace(value);
    Ok(len)
}

/// Verify a transaction signature in the host environment for better
/// performance
#[allow(clippy::too_many_arguments)]
pub fn vp_verify_tx_section_signature<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    hash_list_ptr: u64,
    hash_list_len: u64,
    public_keys_map_ptr: u64,
    public_keys_map_len: u64,
    signer_ptr: u64,
    signer_len: u64,
    threshold: u8,
) -> Result<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (hash_list, gas) = env
        .memory
        .read_bytes(hash_list_ptr, hash_list_len.try_into()?)
        .map_err(Into::into)?;

    let gas_meter = env.ctx.gas_meter();
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)?;
    let hashes: [Hash; 1] = decode(hash_list)?;

    let (public_keys_map, gas) = env
        .memory
        .read_bytes(public_keys_map_ptr, public_keys_map_len.try_into()?)
        .map_err(Into::into)?;
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)?;
    let public_keys_map: AccountPublicKeysMap = decode(public_keys_map)?;

    let (signer, gas) = env
        .memory
        .read_bytes(signer_ptr, signer_len.try_into()?)
        .map_err(Into::into)?;
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)?;
    let signer: Address = decode(signer)?;

    let tx = unsafe { env.ctx.tx.get() };

    match tx.verify_signatures(
        &HashSet::from_iter(hashes),
        public_keys_map,
        &Some(signer),
        threshold,
        || {
            println!("tx gas {}", gas::VERIFY_TX_SIG_GAS);
            gas_meter
                .borrow_mut()
                .consume(gas::VERIFY_TX_SIG_GAS.into())
        },
    ) {
        Ok(_) => Ok(()),
        Err(err) => match err {
            namada_tx::VerifySigError::Gas(inner) => {
                Err(vp_host_fns::RuntimeError::OutOfGas(inner))
                    .into_storage_result()
            }
            namada_tx::VerifySigError::InvalidSectionSignature(inner) => {
                Err(vp_host_fns::RuntimeError::InvalidSectionSignature(inner))
                    .into_storage_result()
            }
            err => Err(Error::new_alloc(err.to_string())),
        },
    }
}

/// Log a string from exposed to the wasm VM Tx environment. The message will be
/// printed at the [`tracing::Level::INFO`]. This function is for development
/// only.
pub fn tx_log_string<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    str_ptr: u64,
    str_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (str, _gas) = env
        .memory
        .read_string(str_ptr, str_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tracing::info!("WASM Transaction log: {}", str);
    Ok(())
}

/// Validate a VP WASM code hash in a tx environment.
fn tx_validate_vp_code_hash<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    code_hash: &[u8],
    code_tag: &Option<String>,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let code_hash = Hash::try_from(code_hash)
        .map_err(|e| TxRuntimeError::InvalidVpCodeHash(e.to_string()))?;

    // First check that code hash corresponds to the code tag if it is present
    if let Some(tag) = code_tag {
        let hash_key = Key::wasm_hash(tag);
        let (result, gas) = env.state().db_read(&hash_key)?;

        consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
        if let Some(tag_hash) = result {
            let tag_hash = Hash::try_from(&tag_hash[..]).map_err(|e| {
                TxRuntimeError::InvalidVpCodeHash(e.to_string())
            })?;
            if tag_hash != code_hash {
                return Err(TxRuntimeError::InvalidVpCodeHash(
                    "The VP code tag does not correspond to the given code \
                     hash"
                        .to_string(),
                )
                .into());
            }
        } else {
            return Err(TxRuntimeError::InvalidVpCodeHash(
                "The VP code tag doesn't exist".to_string(),
            )
            .into());
        }
    }

    // Then check that VP code hash is in the allowlist.
    if !namada_parameters::is_vp_allowed(&env.ctx.state(), &code_hash)? {
        return Err(TxRuntimeError::DisallowedVp.into());
    }

    // Then check that the corresponding VP code does indeed exist
    let code_key = Key::wasm_code(&code_hash);
    let is_present = env.state().has_key(&code_key)?;
    if !is_present {
        return Err(TxRuntimeError::InvalidVpCodeHash(
            "The corresponding VP code doesn't exist".to_string(),
        )
        .into());
    }
    Ok(())
}

/// Set the sentinel for an invalid tx section commitment
pub fn tx_set_commitment_sentinel<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
) where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    MEM: VmMemory,
    CA: WasmCacheAccess,
{
    let sentinel = unsafe { env.ctx.sentinel.get() };
    sentinel.borrow_mut().set_invalid_commitment();
}

/// Verify a transaction signature
#[allow(clippy::too_many_arguments)]
pub fn tx_verify_tx_section_signature<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    hash_list_ptr: u64,
    hash_list_len: u64,
    public_keys_map_ptr: u64,
    public_keys_map_len: u64,
    threshold: u8,
) -> TxResult<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (hash_list, gas) = env
        .memory
        .read_bytes(hash_list_ptr, hash_list_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;

    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    let hashes = <[Hash; 1]>::try_from_slice(&hash_list)
        .map_err(TxRuntimeError::EncodingError)?;

    let (public_keys_map, gas) = env
        .memory
        .read_bytes(public_keys_map_ptr, public_keys_map_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    let public_keys_map =
        AccountPublicKeysMap::try_from_slice(&public_keys_map)
            .map_err(TxRuntimeError::EncodingError)?;

    let tx = unsafe { env.ctx.tx.get() };

    let (gas_meter, sentinel) = env.ctx.gas_meter_and_sentinel();
    match tx.verify_signatures(
        &HashSet::from_iter(hashes),
        public_keys_map,
        &None,
        threshold,
        || {
            println!("tx gas {}", gas::VERIFY_TX_SIG_GAS);
            gas_meter
                .borrow_mut()
                .consume(gas::VERIFY_TX_SIG_GAS.into())
        },
    ) {
        Ok(_) => Ok(HostEnvResult::Success.to_i64()),
        Err(err) => match err {
            namada_tx::VerifySigError::Gas(inner) => {
                sentinel.borrow_mut().set_out_of_gas();
                Err(TxRuntimeError::OutOfGas(inner))
            }
            namada_tx::VerifySigError::InvalidSectionSignature(_) => {
                Ok(HostEnvResult::Fail.to_i64())
            }
            _ => Ok(HostEnvResult::Fail.to_i64()),
        },
    }
    .into_storage_result()
}

/// Appends the new note commitments to the tree in storage
pub fn tx_update_masp_note_commitment_tree<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    transaction_ptr: u64,
    transaction_len: u64,
) -> TxResult<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (serialized_transaction, gas) = env
        .memory
        .read_bytes(transaction_ptr, transaction_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;

    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    let transaction = MaspTransaction::try_from_slice(&serialized_transaction)
        .map_err(TxRuntimeError::EncodingError)?;

    match namada_token::utils::update_note_commitment_tree(
        &mut env.state(),
        &transaction,
    ) {
        Ok(()) => Ok(HostEnvResult::Success.to_i64()),
        Err(_) => {
            // NOTE: sentinel for gas errors is already set by the
            // update_note_commitment_tree function which in turn calls other
            // host functions
            Ok(HostEnvResult::Fail.to_i64())
        }
    }
}

/// Yield a byte array value from the guest.
pub fn tx_yield_value<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    buf_ptr: u64,
    buf_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (value_to_yield, gas) = env
        .memory
        .read_bytes(buf_ptr, buf_len.try_into()?)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    consume_tx_gas::<MEM, D, H, CA>(env, gas)?;
    let host_buf = unsafe { env.ctx.yielded_value.get_mut() };
    host_buf.replace(value_to_yield);
    Ok(())
}

/// Evaluate a validity predicate with the given input data.
pub fn vp_eval<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    vp_code_hash_ptr: u64,
    vp_code_hash_len: u64,
    input_data_ptr: u64,
    input_data_len: u64,
) -> Result<i64>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator<Db = D, H = H, Eval = EVAL, CA = CA>,
    CA: WasmCacheAccess,
{
    let (vp_code_hash, gas) = env
        .memory
        .read_bytes(vp_code_hash_ptr, vp_code_hash_len.try_into()?)
        .map_err(Into::into)?;

    // The borrowed `gas_meter` must be dropped before eval,
    // which has to borrow it too.
    let tx = {
        let gas_meter = env.ctx.gas_meter();
        println!("vp gas {}", gas.sub);
        vp_host_fns::add_gas(gas_meter, gas)?;

        let (input_data, gas) = env
            .memory
            .read_bytes(input_data_ptr, input_data_len.try_into()?)
            .map_err(Into::into)?;
        println!("vp gas {}", gas.sub);
        vp_host_fns::add_gas(gas_meter, gas)?;
        let tx: BatchedTx = decode(input_data)?;
        tx
    };

    let eval_runner = unsafe { env.ctx.eval_runner.get() };
    let vp_code_hash = Hash(vp_code_hash.try_into().map_err(|e| {
        Error::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Not a valid hash: {:?}", e),
        ))
    })?);
    let batch_ref = BatchedTxRef {
        tx: &tx.tx,
        cmt: &tx.cmt,
    };
    Ok(eval_runner
        .eval(env.ctx.clone(), vp_code_hash, batch_ref)
        .to_i64())
}

/// Get the native token's address
pub fn vp_get_native_token<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    result_ptr: u64,
) -> Result<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = env.ctx.gas_meter();
    let state = env.state();
    let native_token = vp_host_fns::get_native_token(gas_meter, &state)?;
    let native_token_string = native_token.encode();
    let gas = env
        .memory
        .write_string(result_ptr, native_token_string)
        .map_err(Into::into)?;
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(gas_meter, gas)
}

/// Log a string from exposed to the wasm VM VP environment. The message will be
/// printed at the [`tracing::Level::INFO`]. This function is for development
/// only.
pub fn vp_log_string<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    str_ptr: u64,
    str_len: u64,
) -> Result<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (str, _gas) = env
        .memory
        .read_string(str_ptr, str_len.try_into()?)
        .map_err(Into::into)?;
    tracing::info!("WASM Validity predicate log: {}", str);
    Ok(())
}

/// Yield a byte array value from the guest.
pub fn vp_yield_value<MEM, D, H, EVAL, CA>(
    env: &mut VpVmEnv<MEM, D, H, EVAL, CA>,
    buf_ptr: u64,
    buf_len: u64,
) -> Result<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (value_to_yield, gas) = env
        .memory
        .read_bytes(buf_ptr, buf_len.try_into()?)
        .map_err(Into::into)?;
    println!("vp gas {}", gas.sub);
    vp_host_fns::add_gas(env.ctx.gas_meter(), gas)?;
    let host_buf = unsafe { env.ctx.yielded_value.get_mut() };
    host_buf.replace(value_to_yield);
    Ok(())
}

// Internal funtion to charge gas for txs. Called by the other functions in this
// file while the public version is left to be used directly from wasm and as a
// hook for gas instrumentation
fn consume_tx_gas<MEM, D, H, CA>(
    env: &mut TxVmEnv<MEM, D, H, CA>,
    used_gas: Gas,
) -> Result<()>
where
    MEM: VmMemory,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: WasmCacheAccess,
{
    let (gas_meter, sentinel) = env.ctx.gas_meter_and_sentinel();

    println!("tx gas {}", used_gas.sub);

    // if we run out of gas, we need to stop the execution
    gas_meter
        .borrow_mut()
        .consume(used_gas)
        .map_err(|err| {
            sentinel.borrow_mut().set_out_of_gas();
            tracing::info!(
                "Stopping transaction execution because of gas error: {}",
                err
            );

            TxRuntimeError::OutOfGas(err)
        })
        .into_storage_result()
}

/// A helper module for testing
#[cfg(feature = "testing")]
pub mod testing {
    use std::rc::Rc;

    use super::*;
    use crate::memory::testing::NativeMemory;
    use crate::wasm::memory::WasmMemory;

    /// Setup a transaction environment
    #[allow(clippy::too_many_arguments)]
    pub fn tx_env<S, CA>(
        state: &mut S,
        iterators: &mut PrefixIterators<'static, <S as StateRead>::D>,
        verifiers: &mut BTreeSet<Address>,
        gas_meter: &RefCell<gas_meter::GasMeter<TxGasMeter>>,
        sentinel: &RefCell<TxSentinel>,
        tx: &Tx,
        cmt: &TxCommitments,
        tx_index: &TxIndex,
        result_buffer: &mut Option<Vec<u8>>,
        yielded_value: &mut Option<Vec<u8>>,
        #[cfg(feature = "wasm-runtime")] vp_wasm_cache: &mut VpCache<CA>,
        #[cfg(feature = "wasm-runtime")] tx_wasm_cache: &mut TxCache<CA>,
    ) -> TxVmEnv<NativeMemory, <S as StateRead>::D, <S as StateRead>::H, CA>
    where
        S: State,
        CA: WasmCacheAccess,
    {
        let (write_log, in_mem, db) = state.split_borrow();
        TxVmEnv::new(
            NativeMemory,
            write_log,
            in_mem,
            db,
            iterators,
            gas_meter,
            sentinel,
            &Hash::zero(),
            tx,
            cmt,
            tx_index,
            verifiers,
            result_buffer,
            yielded_value,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache,
            #[cfg(feature = "wasm-runtime")]
            tx_wasm_cache,
        )
    }

    /// Setup a transaction environment
    #[allow(clippy::too_many_arguments)]
    pub fn tx_env_with_wasm_memory<S, CA>(
        state: &mut S,
        iterators: &mut PrefixIterators<'static, <S as StateRead>::D>,
        verifiers: &mut BTreeSet<Address>,
        gas_meter: &RefCell<gas_meter::GasMeter<TxGasMeter>>,
        sentinel: &RefCell<TxSentinel>,
        tx: &Tx,
        cmt: &TxCommitments,
        tx_index: &TxIndex,
        result_buffer: &mut Option<Vec<u8>>,
        yielded_value: &mut Option<Vec<u8>>,
        store: Rc<RefCell<wasmer::Store>>,
        #[cfg(feature = "wasm-runtime")] vp_wasm_cache: &mut VpCache<CA>,
        #[cfg(feature = "wasm-runtime")] tx_wasm_cache: &mut TxCache<CA>,
    ) -> TxVmEnv<WasmMemory, <S as StateRead>::D, <S as StateRead>::H, CA>
    where
        S: State,
        CA: WasmCacheAccess,
    {
        let wasm_memory = {
            let mut borrowed_store = store.borrow_mut();
            crate::wasm::memory::prepare_tx_memory(&mut *borrowed_store)
                .unwrap()
        };

        let (write_log, in_mem, db) = state.split_borrow();
        let mut env = TxVmEnv::new(
            WasmMemory::new(Rc::downgrade(&store)),
            write_log,
            in_mem,
            db,
            iterators,
            gas_meter,
            sentinel,
            &Hash::zero(),
            tx,
            cmt,
            tx_index,
            verifiers,
            result_buffer,
            yielded_value,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache,
            #[cfg(feature = "wasm-runtime")]
            tx_wasm_cache,
        );

        env.memory.init_from(&wasm_memory);
        env
    }

    /// Setup a validity predicate environment
    #[allow(clippy::too_many_arguments)]
    pub fn vp_env<S, EVAL, CA>(
        address: &Address,
        state: &S,
        iterators: &mut PrefixIterators<'static, <S as StateRead>::D>,
        gas_meter: &RefCell<gas_meter::GasMeter<VpGasMeter>>,
        tx: &Tx,
        cmt: &TxCommitments,
        tx_index: &TxIndex,
        verifiers: &BTreeSet<Address>,
        result_buffer: &mut Option<Vec<u8>>,
        yielded_value: &mut Option<Vec<u8>>,
        keys_changed: &BTreeSet<Key>,
        eval_runner: &EVAL,
        #[cfg(feature = "wasm-runtime")] vp_wasm_cache: &mut VpCache<CA>,
    ) -> VpVmEnv<NativeMemory, <S as StateRead>::D, <S as StateRead>::H, EVAL, CA>
    where
        S: StateRead,
        EVAL: VpEvaluator,
        CA: WasmCacheAccess,
    {
        VpVmEnv::new(
            NativeMemory,
            address,
            state.write_log(),
            state.in_mem(),
            state.db(),
            gas_meter,
            tx,
            cmt,
            tx_index,
            iterators,
            verifiers,
            result_buffer,
            yielded_value,
            keys_changed,
            eval_runner,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache,
        )
    }
}
