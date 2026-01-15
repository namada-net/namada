//! Wasm runners

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::error::Error as _;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::rc::Rc;

use borsh::BorshDeserialize;
use namada_core::address::Address;
use namada_core::hash::{Error as TxHashError, Hash};
use namada_core::internal::HostEnvResult;
use namada_core::storage::Key;
use namada_core::validity_predicate::VpError;
pub use namada_gas::GasMeterKind;
use namada_gas::{GasMetering, TxGasMeter, VpGasMeter, WASM_MEMORY_PAGE_GAS};
use namada_state::prefix_iter::PrefixIterators;
use namada_state::{DB, DBIter, State, StateRead, StorageHasher, StorageRead};
use namada_tx::data::{TxSentinel, TxType};
use namada_tx::{
    BatchedTxRef, Commitment, IndexedTx, Section, Tx, TxCommitments,
};
use namada_vp::vp_host_fns;
use parity_wasm::elements::Instruction::*;
use parity_wasm::elements::{self, SignExtInstruction};
use thiserror::Error;
use wasmer::sys::{BaseTunables, Features};
use wasmer::{Engine, Module, NativeEngineExt, Store, Target};

use super::TxCache;
use super::memory::{Limit, WasmMemory};
use crate::host_env::gas_meter::GasMeter;
use crate::host_env::{TxVmEnv, VpCtx, VpEvaluator, VpVmEnv};
use crate::types::VpInput;
use crate::wasm::host_env::{WasmGasMeter, tx_imports, vp_imports};
use crate::wasm::{Cache, CacheName, VpCache, memory};
use crate::{
    HostRef, RwAccess, WasmCacheAccess, WasmValidationError,
    validate_untrusted_wasm,
};

/// Allocator function name injected into a expored from wasm
pub const ALLOC_FN_NAME: &str = "_injected_alloc";

const GUEST_MEMORY: &str = "memory";
const TX_ENTRYPOINT: &str = "_apply_tx";
const VP_ENTRYPOINT: &str = "_validate_tx";
const MUT_GLOBAL_GAS_NAME: &str = "_namada_gas";
const WASM_STACK_LIMIT: u32 = u16::MAX as u32;

/// The error type returned by transactions.
// TODO(namada#2980): move this to `core`, to be shared with the wasm vm,
// and make it an `enum` of different variants
type TxError = String;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("VP error: {0}")]
    VpError(VpError),
    #[error("Transaction error: {0}")]
    TxError(TxError),
    #[error("Missing tx section: {0}")]
    MissingSection(String),
    #[error("Memory error: {0}")]
    MemoryError(memory::Error),
    #[error("Unable to inject stack limiter")]
    StackLimiterInjection,
    #[error("Unable to inject alloc")]
    AllocInjection,
    #[error("Wasm deserialization error: {0}")]
    DeserializationError(elements::Error),
    #[error("Wasm serialization error: {0}")]
    SerializationError(elements::Error),
    #[error("Unable to inject gas meter")]
    GasMeterInjection,
    #[error("Wasm compilation error: {0}")]
    CompileError(wasmer::CompileError),
    #[error("Missing wasm memory export, failed with: {0}")]
    MissingModuleMemory(wasmer::ExportError),
    #[error("Missing wasm entrypoint: {0}")]
    MissingModuleEntrypoint(wasmer::ExportError),
    #[error("Missing gas mutable global: {0}")]
    MissingGasMutGlobal(wasmer::ExportError),
    #[error("Failed running wasm with: {0}")]
    RuntimeError(wasmer::RuntimeError),
    #[error("Failed instantiating wasm module with: {0}")]
    // Boxed cause it's 128b
    InstantiationError(Box<wasmer::InstantiationError>),
    #[error(
        "Unexpected module entrypoint interface {entrypoint}, failed with: \
         {error}"
    )]
    UnexpectedModuleEntrypointInterface {
        entrypoint: &'static str,
        error: wasmer::RuntimeError,
    },
    #[error("Wasm validation error: {0}")]
    ValidationError(WasmValidationError),
    #[error("Wasm code hash error: {0}")]
    CodeHash(TxHashError),
    #[error("Unable to load wasm code: {0}")]
    LoadWasmCode(String),
    #[error("Unable to find compiled wasm code")]
    NoCompiledWasmCode,
    #[error("Gas error: {0}")]
    GasError(String),
    #[error("Failed type conversion: {0}")]
    ConversionError(String),
    #[error("Storage error: {0}")]
    Error(String),
    #[error("Tx is not allowed in allowlist parameter")]
    DisallowedTx,
    #[error("Invalid transaction section signature: {0}")]
    InvalidSectionSignature(String),
}

/// Result for functions that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// Returns [`Error::DisallowedTx`] when the given tx is a user tx and its code
/// `Hash` is not included in the `tx_allowlist` parameter.
pub fn check_tx_allowed<S>(
    batched_tx: &BatchedTxRef<'_>,
    storage: &S,
) -> Result<()>
where
    S: StorageRead,
{
    let BatchedTxRef { tx, cmt } = batched_tx;
    if let TxType::Wrapper(_) = tx.header().tx_type {
        if let Some(code_sec) = tx
            .get_section(cmt.code_sechash())
            .and_then(|x| Section::code_sec(&x))
        {
            if namada_parameters::is_tx_allowed(storage, &code_sec.code.hash())
                .map_err(|e| Error::Error(e.to_string()))?
            {
                return Ok(());
            }
        }
        return Err(Error::DisallowedTx);
    }
    Ok(())
}

/// Execute a transaction code. Returns the set verifiers addresses requested by
/// the transaction.
#[allow(clippy::too_many_arguments)]
pub fn tx<S, CA>(
    state: &mut S,
    gas_meter: &RefCell<TxGasMeter>,
    wrapper_hash: Option<&Hash>,
    indexed_tx: &IndexedTx,
    tx: &Tx,
    cmt: &TxCommitments,
    vp_wasm_cache: &mut VpCache<CA>,
    tx_wasm_cache: &mut TxCache<CA>,
    gas_meter_kind: GasMeterKind,
    dry_run: bool,
) -> Result<BTreeSet<Address>>
where
    S: StateRead + State + StorageRead,
    CA: 'static + WasmCacheAccess,
{
    let tx_code = tx
        .get_section(cmt.code_sechash())
        .and_then(|x| Section::code_sec(x.as_ref()))
        .ok_or(Error::MissingSection(cmt.code_sechash().to_string()))?;

    // Check if the tx code is allowed (to be done after the check on the code
    // section commitment to let the replay protection mechanism run some
    // optimizations)
    let batched_tx = tx.batch_ref_tx(cmt);
    check_tx_allowed(&batched_tx, state)?;

    // If the transaction code has a tag, ensure that the tag hash equals the
    // transaction code's hash.
    if let Some(tag) = &tx_code.tag {
        // Get the WASM code hash corresponding to the tag from storage
        let hash_key = Key::wasm_hash(tag);
        let hash_value = state
            .read(&hash_key)
            .map_err(|e| {
                Error::LoadWasmCode(format!(
                    "Read wasm code hash failed from storage: key {}, error {}",
                    hash_key, e
                ))
            })?
            .ok_or_else(|| {
                Error::LoadWasmCode(format!(
                    "No wasm code hash in storage: key {}",
                    hash_key
                ))
            })?;
        // Ensure that the queried code hash equals the transaction's code hash
        let tx_code_hash = tx_code.code.hash();
        if tx_code_hash != hash_value {
            return Err(Error::LoadWasmCode(format!(
                "Transaction code hash does not correspond to tag: tx hash \
                 {}, tag {}, tag hash {}",
                tx_code_hash, tag, hash_value,
            )));
        }
    }

    let (module, store) = fetch_or_compile(
        tx_wasm_cache,
        &tx_code.code,
        state,
        gas_meter,
        gas_meter_kind,
    )?;
    let store = Rc::new(RefCell::new(store));

    let mut iterators: PrefixIterators<'_, <S as StateRead>::D> =
        PrefixIterators::default();
    let mut verifiers = BTreeSet::new();
    let mut result_buffer: Option<Vec<u8>> = None;
    let mut yielded_value: Option<Vec<u8>> = None;

    let sentinel = RefCell::new(TxSentinel::default());
    let (write_log, in_mem, db) = state.split_borrow();
    const ZERO_HASH: Hash = Hash::zero();
    let wrapper_hash = wrapper_hash.unwrap_or(&ZERO_HASH);

    let wasm_gas_meter = RefCell::new(GasMeter::new(
        gas_meter_kind,
        || unsafe {
            // If gas metering is done through a host function, we
            // take the provided gas meter, then restore it after
            // we return from the wasm vm
            TxGasMeter::placeholder()
        },
        || {
            // If gas metering is done through a wasm function, we
            // must provide a reference to the store, where we will
            // look-up a mutable global with the gas count
            WasmGasMeter::uninit()
        },
    ));

    let mut env = TxVmEnv::new(
        WasmMemory::new(Rc::downgrade(&store)),
        dry_run,
        write_log,
        in_mem,
        db,
        &mut iterators,
        &wasm_gas_meter,
        &sentinel,
        wrapper_hash,
        tx,
        cmt,
        indexed_tx,
        &mut verifiers,
        &mut result_buffer,
        &mut yielded_value,
        vp_wasm_cache,
        tx_wasm_cache,
    );

    // Instantiate the wasm module
    let instance = {
        let mut store = store.borrow_mut();
        let imports = tx_imports(&mut *store, env.clone());
        wasmer::Instance::new(&mut *store, &module, &imports)
            .map_err(|e| Error::InstantiationError(Box::new(e)))?
    };

    wasm_gas_meter.borrow_mut().init(
        |meter| {
            *meter = gas_meter
                .replace_with(|_| unsafe { TxGasMeter::placeholder() });

            Ok(())
        },
        |meter| {
            let global = instance
                .exports
                .get_global(MUT_GLOBAL_GAS_NAME)
                .map_err(Error::MissingGasMutGlobal)?;

            meter.init_from(
                &*gas_meter.borrow(),
                global.clone(),
                Rc::downgrade(&store),
            );

            Ok(())
        },
    )?;

    // Fetch guest's main memory
    let guest_memory = instance
        .exports
        .get_memory("memory")
        .map_err(Error::MissingModuleMemory)?;

    env.memory.init_from(guest_memory);

    let memory::TxCallInput {
        tx_data_ptr,
        tx_data_len,
    } = {
        let mut store = store.borrow_mut();
        memory::write_tx_inputs(
            &instance,
            &mut *store,
            guest_memory,
            &batched_tx,
        )
        .map_err(Error::MemoryError)?
    };

    // Get the module's entrypoint to be called
    let apply_tx = {
        let store = store.borrow();
        instance
            .exports
            .get_function(TX_ENTRYPOINT)
            .map_err(Error::MissingModuleEntrypoint)?
            .typed::<(u64, u64), u64>(&*store)
            .map_err(|error| Error::UnexpectedModuleEntrypointInterface {
                entrypoint: TX_ENTRYPOINT,
                error,
            })?
    };

    let result = apply_tx.call(
        unsafe { &mut *RefCell::as_ptr(&*store) },
        tx_data_ptr,
        tx_data_len,
    );

    let wasm_gas_meter = RefCell::into_inner(wasm_gas_meter);
    wasm_gas_meter
        .flush_to_meter(&mut *gas_meter.borrow_mut())
        .map_err(|err| Error::GasError(err.to_string()))?;

    let ok = result.map_err(|err| {
        tracing::debug!("Tx WASM failed with {}", err);

        extract_tx_error(&mut yielded_value, &sentinel, Some(err))
    })?;

    // NB: early drop this data to avoid memory errors
    _ = (instance, env);

    if ok == 1 {
        let store = Rc::into_inner(store)
            .expect("The store must be dropped after execution to avoid leaks");
        let _store = RefCell::into_inner(store);
        Ok(verifiers)
    } else {
        Err(extract_tx_error(&mut yielded_value, &sentinel, None))
    }
}

fn extract_tx_error(
    yielded_value: &mut Option<Vec<u8>>,
    sentinel: &RefCell<TxSentinel>,
    runtime_err: Option<wasmer::RuntimeError>,
) -> Error {
    #[inline]
    fn take(
        yielded_value: &mut Option<Vec<u8>>,
        runtime_err: Option<wasmer::RuntimeError>,
    ) -> Error {
        const UNKNOWN: &str = "Runtime panic caused execution to end abruptly";

        let yielded_err = yielded_value.take().map(|borsh_encoded_err| {
            TxError::try_from_slice(&borsh_encoded_err).map_err(|err| {
                Error::ConversionError(format!(
                    "Failed to extract yielded tx error: {err}"
                ))
            })
        });

        if let Some(result) = yielded_err {
            result.map_or_else(|err| err, Error::TxError)
        } else if let Some(err) = runtime_err {
            Error::RuntimeError(err)
        } else {
            Error::TxError(UNKNOWN.to_owned())
        }
    }

    match *sentinel.borrow() {
        TxSentinel::OutOfGas => {
            Error::GasError(take(yielded_value, runtime_err).to_string())
        }
        TxSentinel::InvalidCommitment => {
            Error::MissingSection(take(yielded_value, runtime_err).to_string())
        }
        TxSentinel::None => take(yielded_value, runtime_err),
    }
}

/// Execute a validity predicate code. Returns whether the validity
/// predicate accepted storage modifications performed by the transaction
/// that triggered the execution.
#[allow(clippy::too_many_arguments)]
pub fn vp<S, CA>(
    vp_code_hash: Hash,
    batched_tx: &BatchedTxRef<'_>,
    indexed_tx: &IndexedTx,
    address: &Address,
    state: &S,
    gas_meter: &RefCell<VpGasMeter>,
    keys_changed: &BTreeSet<Key>,
    verifiers: &BTreeSet<Address>,
    mut vp_wasm_cache: VpCache<CA>,
    gas_meter_kind: GasMeterKind,
    dry_run: bool,
) -> Result<()>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    // Compile the wasm module
    let (module, store) = fetch_or_compile(
        &mut vp_wasm_cache,
        &Commitment::Hash(vp_code_hash),
        state,
        gas_meter,
        gas_meter_kind,
    )?;
    let store = Rc::new(RefCell::new(store));

    let mut iterators: PrefixIterators<'_, <S as StateRead>::D> =
        PrefixIterators::default();
    let mut result_buffer: Option<Vec<u8>> = None;
    let mut yielded_value: Option<Vec<u8>> = None;
    let eval_runner =
        VpEvalWasm::<<S as StateRead>::D, <S as StateRead>::H, CA> {
            db: PhantomData,
            hasher: PhantomData,
            cache_access: PhantomData,
        };
    let BatchedTxRef { tx, cmt } = batched_tx;

    let wasm_gas_meter = RefCell::new(GasMeter::new(
        gas_meter_kind,
        || unsafe { VpGasMeter::placeholder() },
        WasmGasMeter::uninit,
    ));

    let mut env = VpVmEnv::new(
        WasmMemory::new(Rc::downgrade(&store)),
        dry_run,
        address,
        state.write_log(),
        state.in_mem(),
        state.db(),
        &wasm_gas_meter,
        tx,
        cmt,
        indexed_tx,
        &mut iterators,
        verifiers,
        &mut result_buffer,
        &mut yielded_value,
        keys_changed,
        &eval_runner,
        &mut vp_wasm_cache,
    );

    let yielded_value_borrow = env.ctx.yielded_value;

    let imports = {
        let mut store = store.borrow_mut();
        vp_imports(&mut *store, env.clone())
    };

    run_vp(
        store,
        module,
        imports,
        &vp_code_hash,
        batched_tx,
        address,
        keys_changed,
        verifiers,
        yielded_value_borrow,
        |instance: &wasmer::Instance, store: &Rc<RefCell<wasmer::Store>>| {
            // Store ref to guest memory in host data structure
            let guest_memory = instance
                .exports
                .get_memory(GUEST_MEMORY)
                .map_err(Error::MissingModuleMemory)?;

            env.memory.init_from(guest_memory);

            // Initialize gas meter
            wasm_gas_meter.borrow_mut().init(
                |meter| {
                    *meter = gas_meter
                        .replace_with(|_| unsafe { VpGasMeter::placeholder() });

                    Ok(())
                },
                |meter| {
                    let global = instance
                        .exports
                        .get_global(MUT_GLOBAL_GAS_NAME)
                        .map_err(Error::MissingGasMutGlobal)?;

                    meter.init_from(
                        &*gas_meter.borrow(),
                        global.clone(),
                        Rc::downgrade(store),
                    );

                    Ok(())
                },
            )?;

            Ok(guest_memory)
        },
        || {
            let wasm_gas_meter = wasm_gas_meter
                .replace_with(|_| unsafe { GasMeter::vp_placeholder() });

            wasm_gas_meter
                .flush_to_meter(&mut *gas_meter.borrow_mut())
                .map_err(|err| Error::GasError(err.to_string()))
        },
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_vp<Init, Fini>(
    store: Rc<RefCell<wasmer::Store>>,
    module: wasmer::Module,
    vp_imports: wasmer::Imports,
    vp_code_hash: &Hash,
    input_data: &BatchedTxRef<'_>,
    address: &Address,
    keys_changed: &BTreeSet<Key>,
    verifiers: &BTreeSet<Address>,
    yielded_value: HostRef<RwAccess, Option<Vec<u8>>>,
    init_ctx: Init,
    finish_ctx: Fini,
) -> Result<()>
where
    Init: for<'wasm> FnOnce(
        &'wasm wasmer::Instance,
        &'wasm Rc<RefCell<wasmer::Store>>,
    ) -> Result<&'wasm wasmer::Memory>,
    Fini: FnOnce() -> Result<()>,
{
    let input: VpInput<'_> = VpInput {
        addr: address,
        data: input_data,
        keys_changed,
        verifiers,
    };

    // Instantiate the wasm module
    let instance = {
        let mut store = store.borrow_mut();
        wasmer::Instance::new(&mut *store, &module, &vp_imports)
            .map_err(|e| Error::InstantiationError(Box::new(e)))?
    };

    let guest_memory = init_ctx(&instance, &store)?;

    // Write the inputs in the memory exported from the wasm
    // module
    let memory::VpCallInput {
        addr_ptr,
        addr_len,
        data_ptr,
        data_len,
        keys_changed_ptr,
        keys_changed_len,
        verifiers_ptr,
        verifiers_len,
    } = {
        let mut store = store.borrow_mut();
        memory::write_vp_inputs(&instance, &mut *store, guest_memory, input)
            .map_err(Error::MemoryError)?
    };

    // Get the module's entrypoint to be called
    let validate_tx = {
        let store = store.borrow();
        instance
            .exports
            .get_function(VP_ENTRYPOINT)
            .map_err(Error::MissingModuleEntrypoint)?
            .typed::<(u64, u64, u64, u64, u64, u64, u64, u64), u64>(&*store)
            .map_err(|error| Error::UnexpectedModuleEntrypointInterface {
                entrypoint: VP_ENTRYPOINT,
                error,
            })?
    };
    let is_valid = validate_tx
        .call(
            unsafe { &mut *RefCell::as_ptr(&*store) },
            addr_ptr,
            addr_len,
            data_ptr,
            data_len,
            keys_changed_ptr,
            keys_changed_len,
            verifiers_ptr,
            verifiers_len,
        )
        .map_err(|rt_error| {
            let downcasted_err = || {
                let source_err = rt_error.source()?;
                let downcasted_vp_err =
                    source_err.downcast_ref::<vp_host_fns::Error>()?;
                let downcasted_vp_rt_err = downcasted_vp_err
                    .downcast_ref::<vp_host_fns::RuntimeError>(
                )?;

                match downcasted_vp_rt_err {
                    vp_host_fns::RuntimeError::OutOfGas(_) => {
                        Some(Error::GasError(rt_error.to_string()))
                    }
                    vp_host_fns::RuntimeError::InvalidSectionSignature(_) => {
                        Some(Error::InvalidSectionSignature(
                            rt_error.to_string(),
                        ))
                    }
                    _ => None,
                }
            };
            downcasted_err().unwrap_or(Error::RuntimeError(rt_error))
        })?;

    finish_ctx()?;

    tracing::debug!(
        is_valid,
        %vp_code_hash,
        "wasm vp"
    );

    // NB: early drop this data to avoid memory errors
    _ = (instance, vp_imports);

    if is_valid == 1 {
        let store = Rc::into_inner(store)
            .expect("The store must be dropped after execution to avoid leaks");
        let _store = RefCell::into_inner(store);
        Ok(())
    } else {
        unsafe { yielded_value.get_mut() }.take().map_or_else(
            || Err(Error::VpError(VpError::Unspecified)),
            |borsh_encoded_err| {
                let vp_err = VpError::try_from_slice(&borsh_encoded_err)
                    .map_err(|e| Error::ConversionError(e.to_string()))?;
                Err(Error::VpError(vp_err))
            },
        )
    }
}

/// Validity predicate wasm evaluator for `eval` host function calls.
#[derive(Default, Debug)]
pub struct VpEvalWasm<D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
    CA: WasmCacheAccess + 'static,
{
    /// Phantom type for DB
    pub db: PhantomData<*const D>,
    /// Phantom type for hasher
    pub hasher: PhantomData<*const H>,
    /// Phantom type for WASM compilation cache access
    pub cache_access: PhantomData<*const CA>,
}

impl<'a, S, CA> namada_vp::native_vp::VpEvaluator<'a, S, VpCache<CA>, Self>
    for VpEvalWasm<<S as StateRead>::D, <S as StateRead>::H, CA>
where
    S: 'static + StateRead,
    CA: WasmCacheAccess,
{
    fn eval(
        native_ctx: &namada_vp::native_vp::Ctx<'a, S, VpCache<CA>, Self>,
        vp_code_hash: Hash,
        input_data: BatchedTxRef<'_>,
    ) -> namada_state::Result<()> {
        use namada_state::ResultExt;

        let eval_runner =
            VpEvalWasm::<<S as StateRead>::D, <S as StateRead>::H, CA> {
                db: PhantomData,
                hasher: PhantomData,
                cache_access: PhantomData,
            };
        let mut iterators: PrefixIterators<'_, <S as StateRead>::D> =
            PrefixIterators::default();
        let mut result_buffer: Option<Vec<u8>> = None;
        let mut yielded_value: Option<Vec<u8>> = None;
        let mut vp_wasm_cache = native_ctx.vp_wasm_cache.clone();

        let wasm_gas_meter = RefCell::new(GasMeter::new(
            GasMeterKind::MutGlobal,
            || unsafe { VpGasMeter::placeholder() },
            WasmGasMeter::uninit,
        ));

        let ctx = VpCtx::new(
            native_ctx.address,
            native_ctx.state.write_log(),
            native_ctx.state.in_mem(),
            native_ctx.state.db(),
            &wasm_gas_meter,
            native_ctx.tx,
            native_ctx.cmt,
            native_ctx.indexed_tx,
            &mut iterators,
            native_ctx.verifiers,
            &mut result_buffer,
            &mut yielded_value,
            native_ctx.keys_changed,
            &eval_runner,
            &mut vp_wasm_cache,
        );

        eval_runner
            .eval_native_result(
                ctx,
                vp_code_hash,
                input_data,
                |instance, store| {
                    wasm_gas_meter.borrow_mut().init(
                        |meter| {
                            *meter =
                                native_ctx.gas_meter.replace_with(|_| unsafe {
                                    VpGasMeter::placeholder()
                                });

                            Ok(())
                        },
                        |meter| {
                            let global = instance
                                .exports
                                .get_global(MUT_GLOBAL_GAS_NAME)
                                .map_err(Error::MissingGasMutGlobal)?;

                            meter.init_from(
                                &*native_ctx.gas_meter.borrow(),
                                global.clone(),
                                Rc::downgrade(store),
                            );

                            Ok(())
                        },
                    )
                },
                || {
                    let wasm_gas_meter =
                        wasm_gas_meter.replace_with(|_| unsafe {
                            GasMeter::vp_placeholder()
                        });

                    wasm_gas_meter
                        .flush_to_meter(&mut *native_ctx.gas_meter.borrow_mut())
                        .map_err(|err| Error::GasError(err.to_string()))
                },
            )
            .inspect_err(|err| {
                tracing::warn!("VP eval from a native VP failed with: {err}");
            })
            .into_storage_result()?;

        Ok(())
    }
}

impl<D, H, CA> VpEvaluator for VpEvalWasm<D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
    CA: WasmCacheAccess + 'static,
{
    type CA = CA;
    type Db = D;
    type Eval = Self;
    type H = H;

    fn eval(
        &self,
        ctx: VpCtx<D, H, Self, CA>,
        vp_code_hash: Hash,
        input_data: BatchedTxRef<'_>,
    ) -> HostEnvResult {
        let mut new_ctx = ctx.clone();

        let wasm_gas_meter =
            RefCell::new(GasMeter::Native(VpGasMeter::new_from_meter(
                &*unsafe { ctx.gas_meter.get() }.borrow(),
            )));

        new_ctx.gas_meter = unsafe { crate::RoHostRef::new(&wasm_gas_meter) };

        self.eval_native_result(
            new_ctx,
            vp_code_hash,
            input_data,
            |_instance, _store| Ok(()),
            || {
                let wasm_gas_meter = wasm_gas_meter
                    .replace_with(|_| unsafe { GasMeter::vp_placeholder() });

                unsafe { ctx.gas_meter.get() }
                    .borrow_mut()
                    .consume(
                        wasm_gas_meter.native().unwrap().get_vp_consumed_gas(),
                    )
                    .map_err(|err| Error::GasError(err.to_string()))
            },
        )
        .map_or_else(
            |err| {
                tracing::info!("VP eval error {err}");
                HostEnvResult::Fail
            },
            |()| HostEnvResult::Success,
        )
    }
}

impl<D, H, CA> VpEvalWasm<D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
    CA: WasmCacheAccess + 'static,
{
    /// Evaluate the given VP.
    ///
    /// Returns the gas consumed in wasm.
    pub fn eval_native_result<Init, Fini>(
        &self,
        ctx: VpCtx<D, H, Self, CA>,
        vp_code_hash: Hash,
        input_data: BatchedTxRef<'_>,
        init_gas_meter: Init,
        fini_gas_meter: Fini,
    ) -> Result<()>
    where
        Init: for<'wasm> FnOnce(
            &'wasm wasmer::Instance,
            &'wasm Rc<RefCell<wasmer::Store>>,
        ) -> Result<()>,
        Fini: FnOnce() -> Result<()>,
    {
        let address = unsafe { ctx.address.get() };
        let keys_changed = unsafe { ctx.keys_changed.get() };
        let verifiers = unsafe { ctx.verifiers.get() };
        let vp_wasm_cache = unsafe { ctx.vp_wasm_cache.get_mut() };
        let gas_meter = unsafe { ctx.gas_meter.get() };
        let gas_meter_kind = gas_meter.borrow().kind();
        // Compile the wasm module
        let (module, store) = fetch_or_compile(
            vp_wasm_cache,
            &Commitment::Hash(vp_code_hash),
            &ctx.state(),
            gas_meter,
            gas_meter_kind,
        )?;
        let store = Rc::new(RefCell::new(store));

        let mut env = VpVmEnv {
            memory: WasmMemory::new(Rc::downgrade(&store)),
            ctx,
            dry_run: false,
        };
        let yielded_value_borrow = env.ctx.yielded_value;
        let imports = {
            let mut store = store.borrow_mut();
            vp_imports(&mut *store, env.clone())
        };

        run_vp(
            store,
            module,
            imports,
            &vp_code_hash,
            &input_data,
            address,
            keys_changed,
            verifiers,
            yielded_value_borrow,
            |instance, store| {
                // Store ref to guest memory in host data structure
                let guest_memory = instance
                    .exports
                    .get_memory(GUEST_MEMORY)
                    .map_err(Error::MissingModuleMemory)?;

                env.memory.init_from(guest_memory);

                init_gas_meter(instance, store)?;

                Ok(guest_memory)
            },
            fini_gas_meter,
        )
    }
}

/// Prepare a wasm store for untrusted code.
pub fn untrusted_wasm_store(limit: Limit<BaseTunables>) -> wasmer::Store {
    // Use Singlepass compiler with the default settings
    let compiler = wasmer_compiler_singlepass::Singlepass::default();
    let mut engine = <Engine as NativeEngineExt>::new(
        Box::new(compiler),
        // NB: The default target corresponds to the host's triplet
        Target::default(),
        // NB: WASM features are validated via `validate_untrusted_wasm`,
        // so we can use the default features here
        Features::default(),
    );
    engine.set_tunables(limit);
    wasmer::Store::new(engine)
}

/// Inject gas counter and stack-height limiter into the given wasm code
pub fn prepare_wasm_code<T: AsRef<[u8]>>(
    code: T,
    gas_meter_kind: GasMeterKind,
) -> Result<Vec<u8>> {
    let module: elements::Module = elements::deserialize_buffer(code.as_ref())
        .map_err(Error::DeserializationError)?;
    let module = match gas_meter_kind {
        GasMeterKind::HostFn => wasm_instrument::gas_metering::inject(
            module,
            wasm_instrument::gas_metering::host_function::Injector::new(
                "env", "gas",
            ),
            &GasRules,
        )
        .map_err(|_original_module| Error::GasMeterInjection)?,
        GasMeterKind::MutGlobal => wasm_instrument::gas_metering::inject(
            module,
            WasmMutGlobalGasBackend,
            &GasRules,
        )
        .map_err(|_original_module| Error::GasMeterInjection)?,
    };
    let stack_limiter_exempt_fn_ids = {
        // cannot examine imported func ids, so we skip them
        let mut exempt = wasm_instrument::utils::imported_function_ids(&module);

        // when using a mutable wasm global to track gas, we want to match the
        // behavior of the gas host fn not getting instrumented
        if let GasMeterKind::MutGlobal = gas_meter_kind {
            let total_number_of_fns_in_wasm_module: u32 = module
                .functions_space()
                .try_into()
                .expect("the number of wasm functions should fit in 32 bits");

            // NB: the gas wasm fn is appended to the bottom of
            // the module with [`wasm_instrument::gas_metering::inject`]
            let wasm_gas_fn_id = total_number_of_fns_in_wasm_module
                .checked_sub(1)
                .expect("there should be at least one wasm fn in the module");

            exempt.insert(wasm_gas_fn_id);
        }

        exempt
    };
    let module = wasm_instrument::inject_stack_limiter(
        module,
        WASM_STACK_LIMIT,
        &stack_limiter_exempt_fn_ids,
    )
    .map_err(|_original_module| Error::StackLimiterInjection)?;

    let module = inject_alloc(module)?;

    elements::serialize(module).map_err(Error::SerializationError)
}

/// Inject and export allocation function that can be used to grow the initial
/// memory from the host side.
///
/// IMPORTANT: This must not be used for non-initial memory allocations as it
/// assumes writing at location 0.
fn inject_alloc(module: elements::Module) -> Result<elements::Module> {
    use elements::{BlockType, Instruction, Instructions, Local, ValueType};
    use parity_wasm::builder;

    // Index of the function to be injected (note that the result of
    // `builder.push_function` is wrong as it ignores improted fns)
    let fn_ix: u32 = module
        .functions_space()
        .try_into()
        .map_err(|_| Error::AllocInjection)?;
    let mut builder = builder::from_module(module);

    // Alloc fn in WAT:
    //
    // (func (;0;) (type 0) (param i32) (result i32)
    // block  ;; label = @1
    //   local.get 0
    //   i32.const -65536
    //   i32.le_u
    //   if  ;; label = @2
    //     local.get 0
    //     i32.const 65535
    //     i32.add
    //     i32.const 16
    //     i32.shr_u
    //     memory.grow
    //     local.tee 0
    //     i32.const -1
    //     i32.ne
    //     br_if 1 (;@1;)
    //   end
    //   unreachable
    // end
    // local.get 0
    // i32.const 16
    // i32.shl)

    const MEMORY_IX: u8 = 0;
    const WASM_PAGE_SIZE_LOG2: i32 = 16;
    const WASM_PAGE_SIZE: i32 = 1 << WASM_PAGE_SIZE_LOG2;
    let instructions = {
        use Instruction::*;
        vec![
            Block(BlockType::NoResult),
            GetLocal(1),
            I32Const(-WASM_PAGE_SIZE),
            I32LeU,
            If(BlockType::NoResult),
            GetLocal(0),
            I32Const(WASM_PAGE_SIZE - 1),
            I32Add,
            I32Const(WASM_PAGE_SIZE_LOG2),
            I32ShrU,
            GrowMemory(MEMORY_IX),
            TeeLocal(0),
            I32Const(-1),
            I32Ne,
            BrIf(1),
            End,
            Unreachable,
            End,
            GetLocal(0),
            I32Const(WASM_PAGE_SIZE_LOG2),
            I32Shl,
            End,
        ]
    };

    builder.push_function(
        builder::function()
            .signature()
            .with_param(ValueType::I32)
            .with_result(ValueType::I32)
            .build()
            .body()
            .with_instructions(Instructions::new(instructions))
            .with_locals([Local::new(1, ValueType::I32)])
            .build()
            .build(),
    );

    builder.push_export(
        builder::export()
            .field(ALLOC_FN_NAME)
            .internal()
            .func(fn_ix)
            .build(),
    );

    Ok(builder.build())
}

// Fetch or compile a WASM code from the cache or storage. Account for the
// loading and code compilation gas costs.
fn fetch_or_compile<S, CN, CA>(
    wasm_cache: &mut Cache<CN, CA>,
    code_or_hash: &Commitment,
    state: &S,
    gas_meter: &RefCell<impl GasMetering>,
    gas_meter_kind: GasMeterKind,
) -> Result<(Module, Store)>
where
    S: StateRead,
    CN: 'static + CacheName,
    CA: 'static + WasmCacheAccess,
{
    match code_or_hash {
        Commitment::Hash(code_hash) => {
            let code_len_key = Key::wasm_code_len(code_hash);
            let tx_len = state
                .read::<u64>(&code_len_key)
                .map_err(|e| {
                    Error::LoadWasmCode(format!(
                        "Read wasm code length failed: key {code_len_key}, \
                         error {e}"
                    ))
                })?
                .ok_or_else(|| {
                    Error::LoadWasmCode(format!(
                        "No wasm code length in storage: key {code_len_key}"
                    ))
                })?;

            // Gas accounting in any case, even if the compiled module is in
            // cache
            gas_meter
                .borrow_mut()
                .add_wasm_load_from_storage_gas(tx_len)
                .map_err(|e| Error::GasError(e.to_string()))?;
            gas_meter
                .borrow_mut()
                .add_compiling_gas(tx_len)
                .map_err(|e| Error::GasError(e.to_string()))?;

            let (module, store) = match wasm_cache
                .fetch(code_hash, gas_meter_kind)?
            {
                Some((module, store)) => (module, store),
                None => {
                    let key = Key::wasm_code(code_hash);
                    let code = state
                        .read::<Vec<u8>>(&key)
                        .map_err(|e| {
                            Error::LoadWasmCode(format!(
                                "Read wasm code failed: key {key}, error {e}"
                            ))
                        })?
                        .ok_or_else(|| {
                            Error::LoadWasmCode(format!(
                                "No wasm code in storage: key {key}"
                            ))
                        })?;

                    match wasm_cache.compile_or_fetch(code, gas_meter_kind)? {
                        Some((module, store)) => (module, store),
                        None => return Err(Error::NoCompiledWasmCode),
                    }
                }
            };

            Ok((module, store))
        }
        Commitment::Id(code) => {
            let tx_len = code.len() as u64;
            gas_meter
                .borrow_mut()
                .add_wasm_validation_gas(tx_len)
                .map_err(|e| Error::GasError(e.to_string()))?;
            // Validation is only needed for governance proposals. The other
            // transactions are subject to the allowlist and are guaranteed to
            // not contain invalid opcodes.
            validate_untrusted_wasm(code).map_err(Error::ValidationError)?;

            gas_meter
                .borrow_mut()
                .add_compiling_gas(tx_len)
                .map_err(|e| Error::GasError(e.to_string()))?;
            match wasm_cache.compile_or_fetch(code, gas_meter_kind)? {
                Some((module, store)) => Ok((module, store)),
                None => Err(Error::NoCompiledWasmCode),
            }
        }
    }
}

struct GasRules;

impl wasm_instrument::gas_metering::Rules for GasRules {
    fn instruction_cost(
        &self,
        instruction: &wasm_instrument::parity_wasm::elements::Instruction,
    ) -> Option<u32> {
        // NOTE: costs set to 0 don't actually trigger the injection of a call
        // to the gas host function (no useless instructions are
        // injected)
        // NOTE: these costs are taken from the benchmarks crate. None of them
        // should be zero
        let gas = match instruction {
            // NOTE: the real cost of this operation is 57_330 but because of
            // the behavior of the instrumentaiton tools which doesn't account
            // for traps in called functions we need to reduce it to 1 otherwise
            // the gas costs explode
            Unreachable => 1,
            // Just a label, aribitrary cost of 1
            End => 1,
            // Just a label, aribitrary cost of 1
            Else => 1,
            Nop => 1,
            // Just a label, cost of 1
            Block(_) => 1,
            // Just a label, cost of 1
            Loop(_) => 1,
            If(_) => 5,
            Br(_) => 14,
            BrIf(_) => 14,
            BrTable(_) => 56,
            Return => 4,
            Call(_) => 16,
            CallIndirect(_, _) => 28,
            Drop => 1,
            Select => 11,
            GetLocal(_) => 1,
            SetLocal(_) => 2,
            TeeLocal(_) => 2,
            GetGlobal(_) => 4,
            SetGlobal(_) => 5,
            I32Load(_, _) => 8,
            I64Load(_, _) => 8,
            F32Load(_, _) => 9,
            F64Load(_, _) => 9,
            I32Load8S(_, _) => 8,
            I32Load8U(_, _) => 8,
            I32Load16S(_, _) => 8,
            I32Load16U(_, _) => 8,
            I64Load8S(_, _) => 8,
            I64Load8U(_, _) => 8,
            I64Load16S(_, _) => 8,
            I64Load16U(_, _) => 8,
            I64Load32S(_, _) => 7,
            I64Load32U(_, _) => 7,
            I32Store(_, _) => 8,
            I64Store(_, _) => 9,
            F32Store(_, _) => 8,
            F64Store(_, _) => 9,
            I32Store8(_, _) => 7,
            I32Store16(_, _) => 13,
            I64Store8(_, _) => 7,
            I64Store16(_, _) => 12,
            I64Store32(_, _) => 8,
            CurrentMemory(_) => 110,
            GrowMemory(_) => 194,
            I32Const(_) => 1,
            I64Const(_) => 1,
            F32Const(_) => 1,
            F64Const(_) => 1,
            I32Eqz => 6,
            I32Eq => 6,
            I32Ne => 6,
            I32LtS => 6,
            I32LtU => 6,
            I32GtS => 6,
            I32GtU => 6,
            I32LeS => 6,
            I32LeU => 6,
            I32GeS => 6,
            I32GeU => 6,
            I64Eqz => 8,
            I64Eq => 8,
            I64Ne => 8,
            I64LtS => 8,
            I64LtU => 8,
            I64GtS => 8,
            I64GtU => 8,
            I64LeS => 8,
            I64LeU => 8,
            I64GeS => 8,
            I64GeU => 8,
            F32Eq => 10,
            F32Ne => 10,
            F32Lt => 10,
            F32Gt => 9,
            F32Le => 10,
            F32Ge => 10,
            F64Eq => 11,
            F64Ne => 11,
            F64Lt => 11,
            F64Gt => 12,
            F64Le => 11,
            F64Ge => 11,
            I32Clz => 3,
            I32Ctz => 3,
            I32Popcnt => 3,
            I32Add => 4,
            I32Sub => 4,
            I32Mul => 6,
            I32DivS => 18,
            I32DivU => 18,
            I32RemS => 18,
            I32RemU => 18,
            I32And => 4,
            I32Or => 4,
            I32Xor => 4,
            I32Shl => 4,
            I32ShrS => 4,
            I32ShrU => 4,
            I32Rotl => 4,
            I32Rotr => 4,
            I64Clz => 4,
            I64Ctz => 4,
            I64Popcnt => 4,
            I64Add => 7,
            I64Sub => 7,
            I64Mul => 8,
            I64DivS => 30,
            I64DivU => 30,
            I64RemS => 31,
            I64RemU => 30,
            I64And => 7,
            I64Or => 7,
            I64Xor => 7,
            I64Shl => 6,
            I64ShrS => 6,
            I64ShrU => 6,
            I64Rotl => 6,
            I64Rotr => 6,
            F32Abs => 5,
            F32Neg => 4,
            F32Ceil => 7,
            F32Floor => 7,
            F32Trunc => 7,
            F32Nearest => 7,
            F32Sqrt => 10,
            F32Add => 7,
            F32Sub => 7,
            F32Mul => 7,
            F32Div => 10,
            F32Min => 21,
            F32Max => 19,
            F32Copysign => 9,
            F64Abs => 7,
            F64Neg => 5,
            F64Ceil => 9,
            F64Floor => 9,
            F64Trunc => 9,
            F64Nearest => 9,
            F64Sqrt => 19,
            F64Add => 9,
            F64Sub => 9,
            F64Mul => 9,
            F64Div => 12,
            F64Min => 24,
            F64Max => 31,
            F64Copysign => 13,
            I32WrapI64 => 2,
            I32TruncSF32 => 24,
            I32TruncUF32 => 25,
            I32TruncSF64 => 28,
            I32TruncUF64 => 27,
            I64ExtendSI32 => 3,
            I64ExtendUI32 => 2,
            I64TruncSF32 => 24,
            I64TruncUF32 => 39,
            I64TruncSF64 => 27,
            I64TruncUF64 => 46,
            F32ConvertSI32 => 12,
            F32ConvertUI32 => 6,
            F32ConvertSI64 => 6,
            F32ConvertUI64 => 12,
            F32DemoteF64 => 9,
            F64ConvertSI32 => 12,
            F64ConvertUI32 => 12,
            F64ConvertSI64 => 12,
            F64ConvertUI64 => 12,
            F64PromoteF32 => 9,
            I32ReinterpretF32 => 2,
            I64ReinterpretF64 => 3,
            F32ReinterpretI32 => 3,
            F64ReinterpretI64 => 4,
            SignExt(SignExtInstruction::I32Extend8S) => 1,
            SignExt(SignExtInstruction::I32Extend16S) => 1,
            SignExt(SignExtInstruction::I64Extend8S) => 1,
            SignExt(SignExtInstruction::I64Extend16S) => 1,
            SignExt(SignExtInstruction::I64Extend32S) => 1,
        };

        // We always return a cost, forbidden instructions should be rejected at
        // validation time not here
        Some(gas)
    }

    fn memory_grow_cost(
        &self,
    ) -> wasm_instrument::gas_metering::MemoryGrowCost {
        wasm_instrument::gas_metering::MemoryGrowCost::Linear(
            NonZeroU32::new(WASM_MEMORY_PAGE_GAS)
                .expect("Memory grow gas cost should be non-zero"),
        )
    }

    fn call_per_local_cost(&self) -> u32 {
        0
    }
}

struct WasmMutGlobalGasBackend;

impl wasm_instrument::gas_metering::Backend for WasmMutGlobalGasBackend {
    fn gas_meter<R: wasm_instrument::gas_metering::Rules>(
        self,
        module: &elements::Module,
        _rules: &R,
    ) -> wasm_instrument::gas_metering::GasMeter {
        #[allow(clippy::cast_possible_truncation)]
        let gas_global_idx = module.globals_space() as u32;

        let func_instructions = vec![
            // test if we ran out of gas
            GetLocal(0),
            GetGlobal(gas_global_idx),
            I64GeU,
            If(elements::BlockType::NoResult),
            // out of gas, set sentinel and abort
            I64Const(-1i64),
            SetGlobal(gas_global_idx),
            Unreachable,
            End,
            // we still have gas, decrement mut global
            GetGlobal(gas_global_idx),
            GetLocal(0),
            I64Sub,
            SetGlobal(gas_global_idx),
            End,
        ];

        wasm_instrument::gas_metering::GasMeter::Internal {
            global: MUT_GLOBAL_GAS_NAME,
            func_instructions: elements::Instructions::new(func_instructions),
            // we charge no gas for the gas function itself
            cost: 0u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error as StdErrorTrait;

    use assert_matches::assert_matches;
    use itertools::Either;
    use namada_core::arith::checked;
    use namada_core::borsh::BorshSerializeExt;
    use namada_state::StorageWrite;
    use namada_state::testing::TestState;
    use namada_test_utils::{TestWasms, tx_data};
    use namada_token::DenominatedAmount;
    use namada_tx::data::eval_vp::EvalVp;
    use namada_tx::data::{Fee, TxType};
    use namada_tx::{Code, Data};
    use test_log::test;
    use wasmer::WASM_PAGE_SIZE;
    use wasmer_vm::TrapCode;

    use super::memory::{TX_MEMORY_INIT_PAGES, VP_MEMORY_INIT_PAGES};
    use super::*;
    use crate::host_env::{self, TxRuntimeError};
    use crate::wasm;

    const TX_GAS_LIMIT: u64 = 10_000_000_000_000;
    const OUT_OF_GAS_LIMIT: u64 = 10_000;
    const GAS_SCALE: u64 = 1;

    /// Test that we sanitize accesses to invalid addresses in wasm memory.
    #[test]
    fn test_tx_sanitize_invalid_addrs() {
        let tx_code = wasmer::wat2wasm(
            r#"
            (module
                (import "env" "namada_tx_read" (func (param i64 i64) (result i64)))
                (func (param i64 i64) (result i64)
                    i64.const 18446744073709551615
                    i64.const 1
                    (call 0)
                )
                (memory 16)
                (export "memory" (memory 0))
                (export "_apply_tx" (func 1))
            )
            "#
            .as_bytes(),
        )
        .expect("unexpected error converting wat2wasm")
        .into_owned();

        const PANIC_MSG: &str =
            "Test should have failed with a wasm runtime memory error";

        let error = execute_tx_with_code(&tx_code).expect_err(PANIC_MSG);
        assert!(
            matches!(
                assert_tx_rt_mem_error(&error, PANIC_MSG),
                memory::Error::OverflowingOffset(18446744073709551615, 1),
            ),
            "{PANIC_MSG}"
        );
    }

    /// Extract a tx wasm runtime memory error from some [`Error`].
    fn assert_tx_rt_mem_error<'err>(
        error: &'err Error,
        assert_msg: &str,
    ) -> &'err memory::Error {
        let Error::RuntimeError(rt_error) = error else {
            panic!("{assert_msg}: {error}");
        };
        let source_err =
            rt_error.source().expect("No runtime error source found");
        let downcasted_tx_err: &host_env::Error = source_err
            .downcast_ref()
            .unwrap_or_else(|| panic!("{assert_msg}: {source_err}"));
        let downcasted_tx_rt_err: &TxRuntimeError = downcasted_tx_err
            .downcast_ref()
            .unwrap_or_else(|| panic!("{assert_msg}: {source_err}"));
        let TxRuntimeError::MemoryError(tx_mem_err) = downcasted_tx_rt_err
        else {
            panic!("{assert_msg}: {downcasted_tx_rt_err}");
        };
        tx_mem_err
            .downcast_ref()
            .unwrap_or_else(|| panic!("{assert_msg}: {tx_mem_err}"))
    }

    /// Extract a vp wasm runtime memory error from some [`Error`].
    fn assert_vp_rt_mem_error<'err>(
        error: &'err Error,
        assert_msg: &str,
    ) -> &'err memory::Error {
        let Error::RuntimeError(rt_error) = error else {
            panic!("{assert_msg}: {error}");
        };
        let source_err =
            rt_error.source().expect("No runtime error source found");
        let downcasted_vp_err: &host_env::Error = source_err
            .downcast_ref()
            .unwrap_or_else(|| panic!("{assert_msg}: {source_err}"));
        let downcasted_err: &wasm::memory::Error = downcasted_vp_err
            .downcast_ref()
            .unwrap_or_else(|| panic!("{assert_msg}: {downcasted_vp_err}"));
        downcasted_err
    }

    /// Test that when a transaction wasm goes over the stack-height limit, the
    /// execution is aborted.
    #[test]
    // NB: Disabled on aarch64 macOS since a fix for
    // https://github.com/wasmerio/wasmer/issues/4072
    // reduced the available stack space on mac
    #[cfg_attr(all(target_arch = "aarch64", target_os = "macos"), ignore)]
    fn test_tx_stack_limiter() {
        // Because each call into `$loop` inside the wasm consumes 5 stack
        // heights except for the terminal call, this should hit the stack
        // limit.
        let loops = WASM_STACK_LIMIT / 5 - 1;

        let error = loop_in_tx_wasm(loops).expect_err(&format!(
            "Expecting runtime error \"unreachable\" caused by stack-height \
             overflow, loops {}. Got",
            loops,
        ));
        assert_stack_overflow(&error);

        // one less loop shouldn't go over the limit
        let result = loop_in_tx_wasm(loops - 1);
        assert!(result.is_ok(), "Expected success. Got {:?}", result);
    }

    /// Test that when a VP wasm goes over the stack-height limit, the execution
    /// is aborted.
    #[test]
    // NB: Disabled on aarch64 macOS since a fix for
    // https://github.com/wasmerio/wasmer/issues/4072
    // reduced the available stack space on mac
    #[cfg_attr(all(target_arch = "aarch64", target_os = "macos"), ignore)]
    fn test_vp_stack_limiter() {
        // Because each call into `$loop` inside the wasm consumes 5 stack
        // heights except for the terminal call, this should hit the stack
        // limit.
        let loops = WASM_STACK_LIMIT / 5 - 1;

        let error = loop_in_vp_wasm(loops).expect_err(
            "Expecting runtime error caused by stack-height overflow. Got",
        );
        assert_stack_overflow(&error);

        // one less loop shouldn't go over the limit
        let result = loop_in_vp_wasm(loops - 1);
        assert!(result.is_ok(), "Expected success. Got {:?}", result);
    }

    /// Test that when a transaction wasm goes over the memory limit inside the
    /// wasm execution, the execution is aborted.
    #[test]
    fn test_tx_memory_limiter_in_guest() {
        let mut state = TestState::default();
        let gas_meter = RefCell::new(TxGasMeter::new(TX_GAS_LIMIT, GAS_SCALE));
        let indexed_tx = IndexedTx::default();

        // This code will allocate memory of the given size
        let tx_code = TestWasms::TxMemoryLimit.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&tx_code);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = (tx_code.len() as u64).serialize_to_vec();
        let _ = state.write_log_mut().write(&key, tx_code.clone()).unwrap();
        let _ = state.write_log_mut().write(&len_key, code_len).unwrap();

        // Assuming 400 pages, 25.6 MiB limit
        assert_eq!(memory::TX_MEMORY_MAX_PAGES, 400);

        // Allocating `2^24` (16 MiB) should be below the memory limit and
        // shouldn't fail
        let tx_data = 2_usize.pow(24).serialize_to_vec();
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        let (mut tx_cache, _) =
            wasm::compilation_cache::common::testing::tx_cache();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_code.clone(), None));
        outer_tx.set_data(Data::new(tx_data));
        let batched_tx = outer_tx.batch_ref_first_tx().unwrap();
        let result = tx(
            &mut state,
            &gas_meter,
            None,
            &indexed_tx,
            batched_tx.tx,
            batched_tx.cmt,
            &mut vp_cache,
            &mut tx_cache,
            GasMeterKind::MutGlobal,
            false,
        );
        assert!(result.is_ok(), "Expected success, got {:?}", result);

        // Allocating `2^25` (32 MiB) should be above the memory limit and
        // should fail
        let tx_data = 2_usize.pow(25).serialize_to_vec();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_code, None));
        outer_tx.set_data(Data::new(tx_data));
        let batched_tx = outer_tx.batch_ref_first_tx().unwrap();
        let error = tx(
            &mut state,
            &gas_meter,
            None,
            &indexed_tx,
            batched_tx.tx,
            batched_tx.cmt,
            &mut vp_cache,
            &mut tx_cache,
            GasMeterKind::MutGlobal,
            false,
        )
        .expect_err("Expected to run out of memory");

        assert_stack_overflow(&error);
    }

    /// Test that when a validity predicate wasm goes over the memory limit
    /// inside the wasm execution when calling `eval` host function, the `eval`
    /// fails and hence returns `false`.
    #[test]
    fn test_vp_memory_limiter_in_guest_calling_eval() {
        let mut state = TestState::default();
        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(TX_GAS_LIMIT, GAS_SCALE),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();
        let indexed_tx = IndexedTx::default();

        // This code will call `eval` with the other VP below
        let vp_eval = TestWasms::VpEval.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&vp_eval);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = vp_eval.len() as u64;
        state.write(&key, vp_eval).unwrap();
        state.write(&len_key, code_len).unwrap();
        // This code will allocate memory of the given size
        let vp_memory_limit = TestWasms::VpMemoryLimit.read_bytes();
        // store the wasm code
        let limit_code_hash = Hash::sha256(&vp_memory_limit);
        let key = Key::wasm_code(&limit_code_hash);
        let len_key = Key::wasm_code_len(&limit_code_hash);
        let code_len = vp_memory_limit.len() as u64;
        state.write(&key, vp_memory_limit).unwrap();
        state.write(&len_key, code_len).unwrap();

        // Assuming 400 pages, 25.6 MiB limit
        assert_eq!(memory::VP_MEMORY_MAX_PAGES, 400);

        // Allocating `2^24` (16 MiB) should be below the memory limit and
        // shouldn't fail
        let input = 2_usize.pow(24).serialize_to_vec();

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(vec![], None).add_serialized_data(input);

        let eval_vp = EvalVp {
            vp_code_hash: limit_code_hash,
            input: tx.batch_first_tx(),
        };

        let mut outer_tx = Tx::new(state.in_mem().chain_id.clone(), None);
        outer_tx.add_code(vec![], None).add_data(eval_vp);

        let (vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        // When the `eval`ed VP doesn't run out of memory, it should return
        // `true`
        assert!(
            vp(
                code_hash,
                &outer_tx.batch_ref_first_tx().unwrap(),
                &indexed_tx,
                &addr,
                &state,
                &gas_meter,
                &keys_changed,
                &verifiers,
                vp_cache.clone(),
                GasMeterKind::MutGlobal,
                false,
            )
            .is_ok()
        );

        // Allocating `2^25` (32 MiB) should be above the memory limit and
        // should fail
        let input = 2_usize.pow(25).serialize_to_vec();
        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(vec![], None).add_data(input);

        let eval_vp = EvalVp {
            vp_code_hash: limit_code_hash,
            input: tx.batch_first_tx(),
        };

        let mut outer_tx = Tx::new(state.in_mem().chain_id.clone(), None);
        outer_tx.add_code(vec![], None).add_data(eval_vp);

        // When the `eval`ed VP runs out of memory, its result should be
        // `false`, hence we should also get back `false` from the VP that
        // called `eval`.
        assert!(
            vp(
                code_hash,
                &outer_tx.batch_ref_first_tx().unwrap(),
                &indexed_tx,
                &addr,
                &state,
                &gas_meter,
                &keys_changed,
                &verifiers,
                vp_cache,
                GasMeterKind::MutGlobal,
                false,
            )
            .is_err()
        );
    }

    /// Test that when a validity predicate wasm goes over the memory limit
    /// inside the wasm execution, the execution is aborted.
    #[test]
    fn test_vp_memory_limiter_in_guest() {
        let mut state = TestState::default();
        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(TX_GAS_LIMIT, GAS_SCALE),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();
        let indexed_tx = IndexedTx::default();

        // This code will allocate memory of the given size
        let vp_code = TestWasms::VpMemoryLimit.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&vp_code);
        let code_len = vp_code.len() as u64;
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        state.write(&key, vp_code).unwrap();
        state.write(&len_key, code_len).unwrap();

        // Assuming 400 pages, 25.6 MiB limit
        assert_eq!(memory::VP_MEMORY_MAX_PAGES, 400);

        // Allocating `2^24` (16 MiB) should be below the memory limit and
        // shouldn't fail
        let tx_data = 2_usize.pow(24).serialize_to_vec();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.set_code(Code::new(vec![], None));
        let (vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        let result = vp(
            code_hash,
            &outer_tx.batch_ref_first_tx().unwrap(),
            &indexed_tx,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache.clone(),
            GasMeterKind::MutGlobal,
            false,
        );
        assert!(result.is_ok(), "Expected success, got {:?}", result);

        // Allocating `2^25` (32 MiB) should be above the memory limit and
        // should fail
        let tx_data = 2_usize.pow(25).serialize_to_vec();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_data(Data::new(tx_data));
        let error = vp(
            code_hash,
            &outer_tx.batch_ref_first_tx().unwrap(),
            &indexed_tx,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache,
            GasMeterKind::MutGlobal,
            false,
        )
        .expect_err("Expected to run out of memory");

        assert_stack_overflow(&error);
    }

    /// Test that when a transaction wasm goes over the wasm memory limit in the
    /// host input, the execution fails.
    #[test]
    fn test_tx_memory_limiter_in_host_input() {
        let mut state = TestState::default();
        let gas_meter = RefCell::new(TxGasMeter::new(TX_GAS_LIMIT, GAS_SCALE));
        let indexed_tx = IndexedTx::default();

        let tx_no_op = TestWasms::TxNoOp.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&tx_no_op);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = (tx_no_op.len() as u64).serialize_to_vec();
        let _ = state
            .write_log_mut()
            .write(&key, tx_no_op.serialize_to_vec())
            .unwrap();
        let _ = state.write_log_mut().write(&len_key, code_len).unwrap();

        // Assuming 400 pages, 25.6 MiB limit
        assert_eq!(memory::TX_MEMORY_MAX_PAGES, 400);

        // Allocating `2^25` (32 MiB) for the input should be above the memory
        // limit and should fail
        let len = 2_usize.pow(25);
        let tx_data: Vec<u8> = vec![6_u8; len];
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        let (mut tx_cache, _) =
            wasm::compilation_cache::common::testing::tx_cache();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_no_op, None));
        outer_tx.set_data(Data::new(tx_data));
        let batched_tx = outer_tx.batch_ref_first_tx().unwrap();
        let result = tx(
            &mut state,
            &gas_meter,
            None,
            &indexed_tx,
            batched_tx.tx,
            batched_tx.cmt,
            &mut vp_cache,
            &mut tx_cache,
            GasMeterKind::MutGlobal,
            false,
        );
        // Depending on platform, we get a different error from the running out
        // of memory
        match result {
            Err(Error::MemoryError(memory::Error::GuestAlloc(_))) => {
                // as expected
            }
            _ => panic!("Expected to run out of memory, got {:?}", result),
        }
    }

    /// Test that when a validity predicate wasm goes over the wasm memory limit
    /// in the host input, the execution fails.
    #[test]
    fn test_vp_memory_limiter_in_host_input() {
        let mut state = TestState::default();
        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(TX_GAS_LIMIT, GAS_SCALE),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();
        let indexed_tx = IndexedTx::default();

        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&vp_code);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = vp_code.len() as u64;
        state.write(&key, vp_code).unwrap();
        state.write(&len_key, code_len).unwrap();

        // Assuming 400 pages, 25.6 MiB limit
        assert_eq!(memory::VP_MEMORY_MAX_PAGES, 400);

        // Allocating `2^25` (32 MiB) for the input should be above the memory
        // limit and should fail
        let len = 2_usize.pow(25);
        let tx_data: Vec<u8> = vec![6_u8; len];
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.set_code(Code::new(vec![], None));
        let (vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        let result = vp(
            code_hash,
            &outer_tx.batch_ref_first_tx().unwrap(),
            &indexed_tx,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache,
            GasMeterKind::MutGlobal,
            false,
        );
        // Depending on platform, we get a different error from the running out
        // of memory
        match result {
            Err(Error::MemoryError(memory::Error::GuestAlloc(_))) => {
                // as expected
            }
            _ => panic!("Expected to run out of memory, got {:?}", result),
        }
    }

    /// Test that when a transaction wasm goes over the wasm memory limit in the
    /// value returned from host environment call during wasm execution, the
    /// execution is aborted.
    #[test]
    fn test_tx_memory_limiter_in_host_env() {
        let mut state = TestState::default();
        let gas_meter = RefCell::new(TxGasMeter::new(TX_GAS_LIMIT, GAS_SCALE));
        let indexed_tx = IndexedTx::default();

        let tx_read_key = TestWasms::TxReadStorageKey.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&tx_read_key);
        let code_len = (tx_read_key.len() as u64).serialize_to_vec();
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let _ = state
            .write_log_mut()
            .write(&key, tx_read_key.clone())
            .unwrap();
        let _ = state.write_log_mut().write(&len_key, code_len).unwrap();

        // Allocating `2^25` (32 MiB) for a value in storage that the tx
        // attempts to read should be above the memory limit and should
        // fail
        let len = 2_usize.pow(25);
        let value: Vec<u8> = vec![6_u8; len];
        let key_raw = "key";
        let key = Key::parse(key_raw).unwrap();
        // Write the value that should be read by the tx into the storage. When
        // writing directly to storage, the value has to be encoded with
        // Borsh.
        state.write(&key, value).unwrap();
        let tx_data = key.serialize_to_vec();
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        let (mut tx_cache, _) =
            wasm::compilation_cache::common::testing::tx_cache();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_read_key, None));
        outer_tx.set_data(Data::new(tx_data));
        let batched_tx = outer_tx.batch_ref_first_tx().unwrap();
        let error = tx(
            &mut state,
            &gas_meter,
            None,
            &indexed_tx,
            batched_tx.tx,
            batched_tx.cmt,
            &mut vp_cache,
            &mut tx_cache,
            GasMeterKind::MutGlobal,
            false,
        )
        .expect_err("Expected to run out of memory");

        assert_stack_overflow(&error);
    }

    /// Test that when a validity predicate wasm goes over the wasm memory limit
    /// in the value returned from host environment call during wasm
    /// execution, the execution is aborted.
    #[test]
    fn test_vp_memory_limiter_in_host_env() {
        let mut state = TestState::default();
        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(TX_GAS_LIMIT, GAS_SCALE),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();
        let indexed_tx = IndexedTx::default();

        let vp_read_key = TestWasms::VpReadStorageKey.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&vp_read_key);
        let code_len = vp_read_key.len() as u64;
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        state.write(&key, vp_read_key).unwrap();
        state.write(&len_key, code_len).unwrap();

        // Allocating `2^25` (32 MiB) for a value in storage that the tx
        // attempts to read should be above the memory limit and should
        // fail
        let len = 2_usize.pow(25);
        let value: Vec<u8> = vec![6_u8; len];
        let key_raw = "key";
        let key = Key::parse(key_raw).unwrap();
        // Write the value that should be read by the tx into the storage. When
        // writing directly to storage, the value has to be encoded with
        // Borsh.
        state.write(&key, value).unwrap();
        let tx_data = key.serialize_to_vec();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.set_code(Code::new(vec![], None));
        let (vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        let error = vp(
            code_hash,
            &outer_tx.batch_ref_first_tx().unwrap(),
            &indexed_tx,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache,
            GasMeterKind::MutGlobal,
            false,
        )
        .expect_err("Expected to run out of memory");

        assert_stack_overflow(&error);
    }

    /// Test that when a validity predicate wasm goes over the wasm memory limit
    /// in the value returned from host environment call during wasm execution,
    /// inside the wasm execution calling `eval` host function, the `eval` fails
    /// and hence returns `false`.
    #[test]
    fn test_vp_memory_limiter_in_host_env_inside_guest_calling_eval() {
        let mut state = TestState::default();
        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(TX_GAS_LIMIT, GAS_SCALE),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();
        let indexed_tx = IndexedTx::default();

        // This code will call `eval` with the other VP below
        let vp_eval = TestWasms::VpEval.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&vp_eval);
        let code_len = (vp_eval.len() as u64).serialize_to_vec();
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        state.write(&key, vp_eval).unwrap();
        state.write(&len_key, code_len).unwrap();
        // This code will read value from the storage
        let vp_read_key = TestWasms::VpReadStorageKey.read_bytes();
        // store the wasm code
        let read_code_hash = Hash::sha256(&vp_read_key);
        let code_len = (vp_read_key.len() as u64).serialize_to_vec();
        let key = Key::wasm_code(&read_code_hash);
        let len_key = Key::wasm_code_len(&read_code_hash);
        state.write(&key, vp_read_key).unwrap();
        state.write(&len_key, code_len).unwrap();

        // Allocating `2^24` (16 MiB) for a value in storage that the tx
        // attempts to read should be above the memory limit and should
        // fail
        let len = 2_usize.pow(24);
        let value: Vec<u8> = vec![6_u8; len];
        let key_raw = "key";
        let key = Key::parse(key_raw).unwrap();
        // Write the value that should be read by the tx into the storage. When
        // writing directly to storage, the value has to be encoded with
        // Borsh.
        state.write(&key, value).unwrap();
        let input = 2_usize.pow(23).serialize_to_vec();

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(vec![], None).add_serialized_data(input);

        let eval_vp = EvalVp {
            vp_code_hash: read_code_hash,
            input: tx.batch_first_tx(),
        };

        let mut outer_tx = Tx::new(state.in_mem().chain_id.clone(), None);
        outer_tx.add_code(vec![], None).add_data(eval_vp);

        let (vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        assert!(
            vp(
                code_hash,
                &outer_tx.batch_ref_first_tx().unwrap(),
                &indexed_tx,
                &addr,
                &state,
                &gas_meter,
                &keys_changed,
                &verifiers,
                vp_cache,
                GasMeterKind::MutGlobal,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn test_apply_wasm_tx_allowlist() {
        let mut state = TestState::default();

        let tx_read_key = TestWasms::TxReadStorageKey.read_bytes();
        // store the wasm code
        let read_code_hash = Hash::sha256(&tx_read_key);
        let code_len = (tx_read_key.len() as u64).serialize_to_vec();
        let key = Key::wasm_code(&read_code_hash);
        let len_key = Key::wasm_code_len(&read_code_hash);
        state.write(&key, tx_read_key).unwrap();
        state.write(&len_key, code_len).unwrap();

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(
            namada_tx::data::WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                    token: state.in_mem().native_token.clone(),
                },
                namada_core::key::testing::common_sk_from_simple_seed(0)
                    .to_public(),
                0.into(),
            ),
        )));
        tx.add_code_from_hash(read_code_hash, None);
        wrapper_tx.add_code_from_hash(read_code_hash, None);
        tx.add_serialized_data(vec![]);
        wrapper_tx.add_serialized_data(vec![]);
        let mut raw_tx = wrapper_tx.clone();
        raw_tx.update_header(TxType::Raw);
        let batched_tx = wrapper_tx.batch_ref_first_tx().unwrap();

        // Check that using a disallowed wrapper tx leads to an error, but a raw
        // tx is ok even if not allowlisted
        {
            let allowlist = vec![format!("{}-bad", read_code_hash)];
            namada_parameters::update_tx_allowlist_parameter(
                &mut state, allowlist,
            )
            .unwrap();
            state.commit_tx_batch();

            let result = check_tx_allowed(&batched_tx, &state);
            assert_matches!(result.unwrap_err(), Error::DisallowedTx);
            let batched_raw_tx = raw_tx.batch_ref_first_tx().unwrap();
            let result = check_tx_allowed(&batched_raw_tx, &state);
            if let Err(result) = result {
                assert!(!matches!(result, Error::DisallowedTx));
            }
        }

        // Check that using an allowed wrapper tx doesn't lead to
        // `Error::DisallowedTx`
        {
            let allowlist = vec![read_code_hash.to_string()];
            namada_parameters::update_tx_allowlist_parameter(
                &mut state, allowlist,
            )
            .unwrap();
            state.commit_tx_batch();

            let result = check_tx_allowed(&batched_tx, &state);
            if let Err(result) = result {
                assert!(!matches!(result, Error::DisallowedTx));
            }
        }
    }

    /// Test that when a function runs out of gas in guest, the execution is
    /// aborted
    #[test]
    fn test_tx_out_of_gas_in_guest() {
        let mut state = TestState::default();
        let gas_meter =
            RefCell::new(TxGasMeter::new(OUT_OF_GAS_LIMIT, GAS_SCALE));
        let indexed_tx = IndexedTx::default();

        // This code will charge gas in a host function indefinetely
        let tx_code = TestWasms::TxInfiniteGuestGas.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&tx_code);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = (tx_code.len() as u64).serialize_to_vec();
        let _ = state.write_log_mut().write(&key, tx_code.clone()).unwrap();
        let _ = state.write_log_mut().write(&len_key, code_len).unwrap();

        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        let (mut tx_cache, _) =
            wasm::compilation_cache::common::testing::tx_cache();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_code.clone(), None));
        outer_tx.set_data(Data::new(vec![]));
        let batched_tx = outer_tx.batch_ref_first_tx().unwrap();
        let result = tx(
            &mut state,
            &gas_meter,
            None,
            &indexed_tx,
            batched_tx.tx,
            batched_tx.cmt,
            &mut vp_cache,
            &mut tx_cache,
            GasMeterKind::MutGlobal,
            false,
        );

        assert!(matches!(result.unwrap_err(), Error::GasError(_)));
    }

    /// Test that when a function runs out of gas in host, the execution is
    /// aborted from the host env (no cooperation required by the guest).
    #[test]
    fn test_tx_out_of_gas_in_host() {
        let mut state = TestState::default();
        let gas_meter =
            RefCell::new(TxGasMeter::new(OUT_OF_GAS_LIMIT, GAS_SCALE));
        let indexed_tx = IndexedTx::default();

        // This code will charge gas in a host function indefinetely
        let tx_code = TestWasms::TxInfiniteHostGas.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&tx_code);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = (tx_code.len() as u64).serialize_to_vec();
        let _ = state.write_log_mut().write(&key, tx_code.clone()).unwrap();
        let _ = state.write_log_mut().write(&len_key, code_len).unwrap();

        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        let (mut tx_cache, _) =
            wasm::compilation_cache::common::testing::tx_cache();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_code.clone(), None));
        outer_tx.set_data(Data::new(vec![]));
        let batched_tx = outer_tx.batch_ref_first_tx().unwrap();
        let result = tx(
            &mut state,
            &gas_meter,
            None,
            &indexed_tx,
            batched_tx.tx,
            batched_tx.cmt,
            &mut vp_cache,
            &mut tx_cache,
            GasMeterKind::MutGlobal,
            false,
        );

        assert!(matches!(result.unwrap_err(), Error::GasError(_)));
    }

    /// Test that when a vp runs out of gas in guest, the execution is aborted
    #[test]
    fn test_vp_out_of_gas_in_guest() {
        let mut state = TestState::default();
        let indexed_tx = IndexedTx::default();

        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(OUT_OF_GAS_LIMIT, GAS_SCALE),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();

        // This code will charge gas in a host function indefinetely
        let tx_code = TestWasms::VpInfiniteGuestGas.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&tx_code);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = (tx_code.len() as u64).serialize_to_vec();
        let _ = state.write_log_mut().write(&key, tx_code.clone()).unwrap();
        let _ = state.write_log_mut().write(&len_key, code_len).unwrap();

        let (vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_code.clone(), None));
        outer_tx.set_data(Data::new(vec![]));
        let result = vp(
            code_hash,
            &outer_tx.batch_ref_first_tx().unwrap(),
            &indexed_tx,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache.clone(),
            GasMeterKind::MutGlobal,
            false,
        );

        assert!(matches!(result.unwrap_err(), Error::GasError(_)));
    }

    /// Test that when a vp runs out of gas in host, the execution is aborted
    /// from the host env (no cooperation required by the guest).
    #[test]
    fn test_vp_out_of_gas_in_host() {
        let mut state = TestState::default();
        let indexed_tx = IndexedTx::default();

        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(OUT_OF_GAS_LIMIT, GAS_SCALE),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();

        // This code will charge gas in a host function indefinetely
        let tx_code = TestWasms::VpInfiniteHostGas.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&tx_code);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = (tx_code.len() as u64).serialize_to_vec();
        let _ = state.write_log_mut().write(&key, tx_code.clone()).unwrap();
        let _ = state.write_log_mut().write(&len_key, code_len).unwrap();

        let (vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_code.clone(), None));
        outer_tx.set_data(Data::new(vec![]));
        let result = vp(
            code_hash,
            &outer_tx.batch_ref_first_tx().unwrap(),
            &indexed_tx,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache.clone(),
            GasMeterKind::MutGlobal,
            false,
        );

        assert!(matches!(result.unwrap_err(), Error::GasError(_)));
    }

    #[test]
    fn test_tx_ro_memory_wont_grow() {
        // a transaction that accesses memory out of bounds
        let out_of_bounds_index =
            checked!(2usize * TX_MEMORY_INIT_PAGES as usize * WASM_PAGE_SIZE)
                .unwrap();
        let tx_code = wasmer::wat2wasm(format!(
            r#"
            (module
                (import "env" "namada_tx_read" (func (param i64 i64) (result i64)))
                (func (param i64 i64) (result i64)
                    i64.const {out_of_bounds_index}
                    i64.const 1
                    (call 0)
                )
                (memory 16)
                (export "memory" (memory 0))
                (export "_apply_tx" (func 1))
            )
            "#
        ).as_bytes())
        .expect("unexpected error converting wat2wasm")
        .into_owned();

        const PANIC_MSG: &str =
            "Test should have failed with a wasm runtime memory error";

        let error = execute_tx_with_code(&tx_code).expect_err(PANIC_MSG);
        assert!(
            matches!(
                assert_tx_rt_mem_error(&error, PANIC_MSG),
                memory::Error::ReadOnly,
            ),
            "{PANIC_MSG}"
        );
    }

    #[test]
    fn test_vp_ro_memory_wont_grow() {
        // vp code that accesses memory out of bounds
        let out_of_bounds_index =
            checked!(2usize * VP_MEMORY_INIT_PAGES as usize * WASM_PAGE_SIZE)
                .unwrap();
        let vp_code = wasmer::wat2wasm(format!(
            r#"
            (module
                (type (;0;) (func (param i64 i64 i64 i64 i64 i64 i64 i64) (result i64)))
                (import "env" "namada_vp_read_pre" (func (param i64 i64) (result i64)))

                (func $_validate_tx (type 0) (param i64 i64 i64 i64 i64 i64 i64 i64) (result i64)
                    i64.const {out_of_bounds_index}
                    i64.const 1
                    (call 0)
                )

                (table (;0;) 1 1 funcref)
                (memory (;0;) 16)
                (global (;0;) (mut i32) (i32.const 1048576))
                (export "memory" (memory 0))
                (export "_validate_tx" (func $_validate_tx)))
            "#).as_bytes(),
        )
        .expect("unexpected error converting wat2wasm").into_owned();

        const PANIC_MSG: &str =
            "Test should have failed with a wasm runtime memory error";

        let error = execute_vp_with_code(&vp_code).expect_err(PANIC_MSG);
        assert!(
            matches!(
                assert_vp_rt_mem_error(&error, PANIC_MSG),
                memory::Error::ReadOnly,
            ),
            "{PANIC_MSG}"
        );
    }

    #[test]
    fn test_tx_leak() {
        let tx_code = TestWasms::TxNoOp.read_bytes();
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        let (mut tx_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        let mut last_cache_size: Option<usize> = None;
        for _ in 0..3 {
            let _verifiers = execute_tx_with_code_and_cache(
                &tx_code,
                &mut tx_cache,
                &mut vp_cache,
            )
            .unwrap();

            let info = &wasmer_compiler::FRAME_INFO.read().unwrap();
            let info: &GlobalFrameInfo = unsafe { std::mem::transmute(info) };
            if let Some(last_cache_size) = last_cache_size {
                assert_eq!(
                    last_cache_size,
                    info.ranges.len(),
                    "The frame info must not be growing - we're using the \
                     same WASM in each loop"
                );
            } else {
                last_cache_size = Some(info.ranges.len());
            }
        }
    }

    #[test]
    fn test_vp_leak() {
        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        let mut last_cache_size: Option<usize> = None;
        for _ in 0..3 {
            execute_vp_with_code_and_cache(&vp_code, &mut vp_cache).unwrap();

            let info = &wasmer_compiler::FRAME_INFO.read().unwrap();
            let info: &GlobalFrameInfo = unsafe { std::mem::transmute(info) };
            if let Some(last_cache_size) = last_cache_size {
                assert_eq!(
                    last_cache_size,
                    info.ranges.len(),
                    "The frame info must not be growing - we're using the \
                     same WASM in each loop"
                );
            } else {
                last_cache_size = Some(info.ranges.len());
            }
        }
    }

    fn execute_vp_with_code(vp_code: &[u8]) -> Result<()> {
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        execute_vp_with_code_and_cache(vp_code, &mut vp_cache)
    }

    fn execute_vp_with_code_and_cache<CA: 'static + WasmCacheAccess>(
        vp_code: &[u8],
        vp_cache: &mut VpCache<CA>,
    ) -> Result<()> {
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.push_default_inner_tx();
        let indexed_tx = IndexedTx::default();
        let mut state = TestState::default();
        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new(TX_GAS_LIMIT, GAS_SCALE),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();
        // store the vp code
        let code_hash = Hash::sha256(vp_code);
        let code_len = vp_code.len() as u64;
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        state.write(&key, vp_code).unwrap();
        state.write(&len_key, code_len).unwrap();

        vp(
            code_hash,
            &outer_tx.batch_ref_first_tx().unwrap(),
            &indexed_tx,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache.clone(),
            GasMeterKind::MutGlobal,
            false,
        )
    }

    fn execute_tx_with_code(tx_code: &[u8]) -> Result<BTreeSet<Address>> {
        let (mut tx_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        execute_tx_with_code_and_cache(tx_code, &mut tx_cache, &mut vp_cache)
    }

    fn execute_tx_with_code_and_cache<CA: 'static + WasmCacheAccess>(
        tx_code: &[u8],
        tx_cache: &mut TxCache<CA>,
        vp_cache: &mut VpCache<CA>,
    ) -> Result<BTreeSet<Address>> {
        let tx_data = vec![];
        let indexed_tx = IndexedTx::default();
        let mut state = TestState::default();
        let gas_meter = RefCell::new(TxGasMeter::new(TX_GAS_LIMIT, GAS_SCALE));

        // store the tx code
        let code_hash = Hash::sha256(tx_code);
        let code_len = (tx_code.len() as u64).serialize_to_vec();
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let _ = state
            .write_log_mut()
            .write(&key, tx_code.serialize_to_vec())
            .unwrap();
        let _ = state.write_log_mut().write(&len_key, code_len).unwrap();

        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::from_hash(code_hash, None));
        outer_tx.set_data(Data::new(tx_data));
        let batched_tx = outer_tx.batch_ref_first_tx().unwrap();

        tx(
            &mut state,
            &gas_meter,
            None,
            &indexed_tx,
            batched_tx.tx,
            batched_tx.cmt,
            vp_cache,
            tx_cache,
            GasMeterKind::MutGlobal,
            false,
        )
    }

    /// Test that a tx which is larger than the initial WASM memory size gets
    /// executed without issues (the injected alloc fn should be invoked from
    /// host)
    #[test]
    fn test_tx_alloc() {
        let mut state = TestState::default();
        let gas_meter = RefCell::new(TxGasMeter::new(TX_GAS_LIMIT, GAS_SCALE));
        let indexed_tx = IndexedTx::default();

        let tx_write = TestWasms::TxWriteStorageKey.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&tx_write);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = (tx_write.len() as u64).serialize_to_vec();
        let _ = state
            .write_log_mut()
            .write(&key, tx_write.serialize_to_vec())
            .unwrap();
        let _ = state.write_log_mut().write(&len_key, code_len).unwrap();

        // Using `2^21` (2 MiB) for the input should be above the initial memory
        // size and require allocation
        let len = 2_usize.pow(21);
        let value: Vec<u8> = vec![6_u8; len];
        let key_raw = "key";
        let key = Key::parse(key_raw).unwrap();
        let tx_data = tx_data::TxWriteData {
            key: key.clone(),
            value: value.clone(),
        }
        .serialize_to_vec();

        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::vp_cache();
        let (mut tx_cache, _) =
            wasm::compilation_cache::common::testing::tx_cache();

        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_write, None));
        outer_tx.set_data(Data::new(tx_data));
        let batched_tx = outer_tx.batch_ref_first_tx().unwrap();
        tx(
            &mut state,
            &gas_meter,
            None,
            &indexed_tx,
            batched_tx.tx,
            batched_tx.cmt,
            &mut vp_cache,
            &mut tx_cache,
            GasMeterKind::MutGlobal,
            false,
        )
        .unwrap();

        let written_value = state.read_bytes(&key).unwrap().unwrap();
        assert_eq!(value, written_value);
    }

    fn loop_in_tx_wasm(loops: u32) -> Result<BTreeSet<Address>> {
        // A transaction with a recursive loop.
        // The boilerplate code is generated from tx_template.wasm using
        // `wasm2wat` and the loop code is hand-written.
        let tx_code = wasmer::wat2wasm(
            format!(
                r#"
            (module
                (type (;0;) (func (param i64 i64) (result i64)))

                ;; recursive loop, the param is the number of loops
                (func $loop (param i64) (result i64)
                (if
                (result i64)
                (i64.eqz (get_local 0))
                (then (i64.const 1))
                (else (call $loop (i64.sub (get_local 0) (i64.const 1))))))

                (func $_apply_tx (type 0) (param i64 i64) (result i64)
                (call $loop (i64.const {loops})))

                (table (;0;) 1 1 funcref)
                (memory (;0;) 16)
                (global (;0;) (mut i32) (i32.const 1048576))
                (export "memory" (memory 0))
                (export "_apply_tx" (func $_apply_tx)))
            "#
            )
            .as_bytes(),
        )
        .expect("unexpected error converting wat2wasm")
        .into_owned();

        execute_tx_with_code(&tx_code)
    }

    fn loop_in_vp_wasm(loops: u32) -> Result<()> {
        // A validity predicate with a recursive loop.
        // The boilerplate code is generated from vp_template.wasm using
        // `wasm2wat` and the loop code is hand-written.
        let vp_code = wasmer::wat2wasm(format!(
            r#"
            (module
                (type (;0;) (func (param i64 i64 i64 i64 i64 i64 i64 i64) (result i64)))

                ;; recursive loop, the param is the number of loops
                (func $loop (param i64) (result i64)
                (if
                (result i64)
                (i64.eqz (get_local 0))
                (then (i64.const 1))
                (else (call $loop (i64.sub (get_local 0) (i64.const 1))))))

                (func $_validate_tx (type 0) (param i64 i64 i64 i64 i64 i64 i64 i64) (result i64)
                (call $loop (i64.const {})))

                (table (;0;) 1 1 funcref)
                (memory (;0;) 16)
                (global (;0;) (mut i32) (i32.const 1048576))
                (export "memory" (memory 0))
                (export "_validate_tx" (func $_validate_tx)))
            "#, loops).as_bytes(),
        )
            .expect("unexpected error converting wat2wasm").into_owned();

        execute_vp_with_code(&vp_code)
    }

    fn get_trap_code(error: &Error) -> Either<TrapCode, String> {
        if let Error::RuntimeError(err) = error {
            if let Some(trap_code) = err.clone().to_trap() {
                Either::Left(trap_code)
            } else {
                Either::Right(format!("Missing trap code {}", err))
            }
        } else {
            Either::Right(format!("Unexpected error {}", error))
        }
    }

    fn assert_stack_overflow(error: &Error) {
        let trap_code = get_trap_code(error);
        // Depending on platform, we get a different error from the overflow
        assert!(
            // Universal engine error (currently used on mac)
            trap_code ==
                Either::Left(wasmer_vm::TrapCode::UnreachableCodeReached) ||
            // Dylib engine error (used elsewhere)
                trap_code ==
                Either::Left(wasmer_vm::TrapCode::StackOverflow),
        );
    }

    /// The following definitions are copied from wasmer v4.3.5
    /// `lib/compiler/src/engine/trap/frame_info.rs` to access internal
    /// fields that are otherwise private. This must be carefully maintained
    /// while we workaround the leak before it's fixed in wasmer.
    pub struct GlobalFrameInfo {
        ranges: BTreeMap<usize, ModuleInfoFrameInfo>,
    }
    struct ModuleInfoFrameInfo {
        _start: usize,
        _functions: BTreeMap<usize, FunctionInfo>,
        _module: std::sync::Arc<wasmer_types::ModuleInfo>,
        _frame_infos: wasmer_compiler::FrameInfosVariant,
    }
    struct FunctionInfo {
        _start: usize,
        _local_index: wasmer_types::LocalFunctionIndex,
    }
}
