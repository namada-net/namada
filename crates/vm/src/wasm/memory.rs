//! Wasm memory is used for bi-directionally passing data between the host and a
//! wasm instance.

use std::cell::RefCell;
use std::ptr::NonNull;
use std::rc::{self, Rc};
use std::str::Utf8Error;

use namada_core::arith::{self, checked};
use namada_core::borsh::BorshSerializeExt;
use namada_gas::{Gas, MEMORY_ACCESS_GAS_PER_BYTE};
use namada_tx::BatchedTxRef;
use thiserror::Error;
use wasmer::sys::BaseTunables;
use wasmer::{
    Memory, MemoryError, MemoryType, Pages, Store, TableType, Target, Tunables,
    WASM_PAGE_SIZE, vm,
};
use wasmer_vm::{
    MemoryStyle, TableStyle, VMMemoryDefinition, VMTableDefinition,
};

use crate::memory::VmMemory;
use crate::types::VpInput;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Attempted to modify read-only memory")]
    ReadOnly,
    #[error("Offset {0}+{1} overflows 32 bits storage")]
    OverflowingOffset(u64, usize),
    #[error("Failed initializing the memory: {0}")]
    InitMemoryError(wasmer::MemoryError),
    #[error("Failed to grow memory: {0}")]
    Grow(wasmer::MemoryError),
    #[error("Wasm memory access error: {0}")]
    Access(#[from] wasmer::MemoryAccessError),
    #[error("Encoding error: {0}")]
    EncodingError(std::io::Error),
    #[error("Memory is not initialized")]
    UninitializedMemory,
    #[error("Invalid utf8 string read from memory")]
    InvalidUtf8String(Utf8Error),
    #[error("Arithmetic {0}")]
    Arith(#[from] arith::Error),
    #[error("{0}")]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error("Failed to allocate memory: {0}")]
    GuestAlloc(wasmer::RuntimeError),
}

/// Result of a function that may fail
pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for namada_state::Error {
    fn from(value: Error) -> Self {
        namada_state::Error::new(value)
    }
}

// The bounds are set in number of pages, the actual size is multiplied by
// `wasmer::WASM_PAGE_SIZE = 64kiB`.
//
// TODO: set bounds to accommodate for wasm env size
//
/// Initial pages in tx memory
pub const TX_MEMORY_INIT_PAGES: u32 = 100; // 6.4 MiB
/// Mamixmum pages in tx memory
pub const TX_MEMORY_MAX_PAGES: u32 = 200; // 12.8 MiB
/// Initial pages in VP memory
pub const VP_MEMORY_INIT_PAGES: u32 = 100; // 6.4 MiB
/// Mamixmum pages in VP memory
pub const VP_MEMORY_MAX_PAGES: u32 = 200; // 12.8 MiB

/// Prepare memory for instantiating a transaction module
pub fn prepare_tx_memory(
    store: &mut impl wasmer::AsStoreMut,
) -> Result<wasmer::Memory> {
    let mem_type = wasmer::MemoryType::new(
        TX_MEMORY_INIT_PAGES,
        Some(TX_MEMORY_MAX_PAGES),
        false,
    );
    Memory::new(store, mem_type).map_err(Error::InitMemoryError)
}

/// Prepare memory for instantiating a validity predicate module
pub fn prepare_vp_memory(
    store: &mut impl wasmer::AsStoreMut,
) -> Result<wasmer::Memory> {
    let mem_type = wasmer::MemoryType::new(
        VP_MEMORY_INIT_PAGES,
        Some(VP_MEMORY_MAX_PAGES),
        false,
    );
    let memory =
        Memory::new(store, mem_type).map_err(Error::InitMemoryError)?;
    Ok(memory)
}

/// Input data for transaction wasm call
pub struct TxCallInput {
    /// Raw pointer to the data
    pub tx_data_ptr: u64,
    /// Length of the data
    pub tx_data_len: u64,
}

/// Write transaction inputs into wasm memory
pub fn write_tx_inputs(
    instance: &wasmer::Instance,
    store: &mut impl wasmer::AsStoreMut,
    memory: &wasmer::Memory,
    tx_data: &BatchedTxRef<'_>,
) -> Result<TxCallInput> {
    let tx_data_bytes = tx_data.serialize_to_vec();
    let tx_data_len = tx_data_bytes.len() as u64;
    let tx_data_ptr = wasm_alloc(instance, store, tx_data_len)?;

    write_memory_bytes(store, memory, tx_data_ptr, &tx_data_bytes)?;

    Ok(TxCallInput {
        tx_data_ptr,
        tx_data_len,
    })
}

/// Input data for validity predicate wasm call
#[derive(Clone, Debug)]
pub struct VpCallInput {
    /// Pointer to the address
    pub addr_ptr: u64,
    /// Length of the address
    pub addr_len: u64,
    /// Pointer to the data
    pub data_ptr: u64,
    /// Length of the data
    pub data_len: u64,
    /// Pointer to the serialized changed keys
    pub keys_changed_ptr: u64,
    /// Length of the serialized changed keys
    pub keys_changed_len: u64,
    /// Pointer to the serialized verifiers
    pub verifiers_ptr: u64,
    /// Length of the serialized verifiers
    pub verifiers_len: u64,
}

/// Write validity predicate inputs into wasm memory
pub fn write_vp_inputs(
    instance: &wasmer::Instance,
    store: &mut impl wasmer::AsStoreMut,
    memory: &wasmer::Memory,
    VpInput {
        addr,
        data,
        keys_changed,
        verifiers,
    }: VpInput<'_>,
) -> Result<VpCallInput> {
    let addr_bytes = addr.serialize_to_vec();
    let addr_len = addr_bytes.len() as _;

    let data_bytes = data.serialize_to_vec();
    let data_len = data_bytes.len() as _;

    let keys_changed_bytes = keys_changed.serialize_to_vec();
    let keys_changed_len = keys_changed_bytes.len() as _;

    let verifiers_bytes = verifiers.serialize_to_vec();
    let verifiers_len = verifiers_bytes.len() as _;

    let bytes = [
        &addr_bytes[..],
        &data_bytes[..],
        &keys_changed_bytes[..],
        &verifiers_bytes[..],
    ]
    .concat();
    let bytes_len = bytes.len() as u64;

    let addr_ptr = wasm_alloc(instance, store, bytes_len)?;
    let data_ptr = checked!(addr_ptr + addr_len)?;
    let keys_changed_ptr = checked!(data_ptr + data_len)?;
    let verifiers_ptr = checked!(keys_changed_ptr + keys_changed_len)?;

    write_memory_bytes(store, memory, addr_ptr, bytes)?;

    Ok(VpCallInput {
        addr_ptr,
        addr_len,
        data_ptr,
        data_len,
        keys_changed_ptr,
        keys_changed_len,
        verifiers_ptr,
        verifiers_len,
    })
}

/// Allocated inside the wasm instance using the injected function and return a
/// ptr to it
fn wasm_alloc(
    instance: &wasmer::Instance,
    store: &mut impl wasmer::AsStoreMut,
    len: u64,
) -> Result<u64> {
    let alloc_fn = instance
        .exports
        .get_function(super::run::ALLOC_FN_NAME)
        .unwrap()
        .typed::<i32, i32>(&*store)
        .unwrap();

    let len: i32 = len.try_into().map_err(Error::TryFromInt)?;
    let ptr = alloc_fn.call(&mut *store, len).map_err(Error::GuestAlloc)?;
    let ptr: u64 = ptr.try_into().map_err(Error::TryFromInt)?;
    Ok(ptr)
}

/// Check that the given offset and length fits into the memory bounds. If not,
/// it will try to grow the memory.
fn check_bounds<F, S>(
    store: &mut S,
    memory: &Memory,
    base_addr: u64,
    offset: usize,
    grow_callback: F,
) -> Result<()>
where
    S: wasmer::AsStoreMut,
    F: Fn(u64, &Memory, &mut S) -> Result<()>,
{
    let store_mut = store.as_store_mut();
    let memview = memory.view(&store_mut);

    tracing::debug!(
        "check_bounds pages {}, data_size {}, base_addr {base_addr}, offset \
         {offset}",
        memview.size().0,
        memview.data_size(),
    );
    let desired_offset = base_addr
        .checked_add(offset as u64)
        .and_then(|off| {
            if off < u64::from(u32::MAX) {
                // wasm pointers are 32 bits wide, therefore we can't
                // read from/write to offsets past `u32::MAX`
                Some(off)
            } else {
                None
            }
        })
        .ok_or(Error::OverflowingOffset(base_addr, offset))?;
    if memview.data_size() < desired_offset {
        grow_callback(desired_offset, memory, store)?;
    }
    Ok(())
}

/// Read bytes from memory at the given offset and length
fn read_memory_bytes(
    store: &mut impl wasmer::AsStoreMut,
    memory: &Memory,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>> {
    check_bounds(
        store,
        memory,
        offset,
        len,
        |_desired_offset, _memory, _store| Err(Error::ReadOnly),
    )?;
    let mut buf = vec![0; len];
    memory.view(&store.as_store_mut()).read(offset, &mut buf)?;
    Ok(buf)
}

/// Write bytes into memory at the given offset
fn write_memory_bytes(
    store: &mut impl wasmer::AsStoreMut,
    memory: &Memory,
    offset: u64,
    bytes: impl AsRef<[u8]>,
) -> Result<()> {
    let buf = bytes.as_ref();
    check_bounds(
        store,
        memory,
        offset,
        buf.len() as _,
        |desired_offset, memory, store| {
            let store_mut = store.as_store_mut();
            let memview = memory.view(&store_mut);

            let cur_pages = memview.size().0 as usize;
            let capacity = checked!(cur_pages * WASM_PAGE_SIZE)?;

            // usizes should be at least 32 bits wide on most architectures,
            // so this cast shouldn't cause panics, given the invariant that
            // `desired_offset` is at most a 32 bit wide value. moreover,
            // `capacity` should not be larger than `memory.data_size()`,
            // so this subtraction should never fail
            let desired_offset = usize::try_from(desired_offset)?;
            let missing = checked!(desired_offset - capacity)?;

            // extrapolate the number of pages missing to allow addressing
            // the desired memory offset
            let req_pages =
                checked!((missing + WASM_PAGE_SIZE - 1) / WASM_PAGE_SIZE)?;
            let req_pages: u32 = u32::try_from(req_pages)?;

            tracing::debug!(req_pages, "Attempting to grow wasm memory");

            memory.grow(store, req_pages).map_err(Error::Grow)?;
            tracing::debug!(
                mem_size = memory.view(&store.as_store_mut()).data_size(),
                "Wasm memory size has been successfully extended"
            );

            Ok(())
        },
    )?;
    memory.view(&store.as_store_mut()).write(offset, buf)?;
    Ok(())
}

/// The wasm memory
#[derive(Debug, Clone)]
pub struct WasmMemory {
    store: rc::Weak<RefCell<Store>>,
    memory: Rc<RefCell<Option<wasmer::Memory>>>,
}

// TODO(namada#3313): Wasm memory is neither `Send` nor `Sync`, but we must
// implement it for now for the code to compile.
unsafe impl Send for WasmMemory {}
unsafe impl Sync for WasmMemory {}

impl WasmMemory {
    /// Build a new wasm memory.
    pub fn new(store: rc::Weak<RefCell<Store>>) -> Self {
        Self {
            store,
            memory: Rc::new(RefCell::new(None)),
        }
    }

    /// Initialize the host memory with a pointer to the given memory.
    pub fn init_from(&mut self, memory: &Memory) {
        if self.memory.borrow().is_some() {
            tracing::error!("wasm memory is already initialized");
            return;
        }
        *self.memory.borrow_mut() = Some(memory.clone());
    }

    /// Access the inner [`Memory`].
    #[inline]
    fn access<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Memory) -> Result<T>,
    {
        let borrow = self.memory.borrow();
        let memory = borrow.as_ref().ok_or(Error::UninitializedMemory)?;
        f(memory)
    }
}

impl VmMemory for WasmMemory {
    type Error = Error;

    /// Read bytes from memory at the given offset and length, return the bytes
    /// and the gas cost
    fn read_bytes(
        &mut self,
        offset: u64,
        len: usize,
    ) -> Result<(Vec<u8>, Gas)> {
        self.access(|memory| {
            let store = self
                .store
                .upgrade()
                .expect("Store must be accessible while the WASM is running");
            let mut store = store.borrow_mut();
            let bytes = read_memory_bytes(&mut *store, memory, offset, len)?;
            let len = bytes.len() as u64;
            let gas = checked!(len * MEMORY_ACCESS_GAS_PER_BYTE)?;
            Ok((bytes, gas.into()))
        })
    }

    /// Write bytes into memory at the given offset and return the gas cost
    fn write_bytes(
        &mut self,
        offset: u64,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Gas> {
        self.access(|memory| {
            // No need for a separate gas multiplier for writes since we are
            // only writing to memory and we already charge gas for
            // every memory page allocated
            let len = bytes.as_ref().len() as u64;
            let gas = checked!(len * MEMORY_ACCESS_GAS_PER_BYTE)?;
            let store = self
                .store
                .upgrade()
                .expect("Store must be accessible while the WASM is running");
            let mut store = store.borrow_mut();
            write_memory_bytes(&mut *store, memory, offset, bytes)?;
            Ok(gas.into())
        })
    }

    /// Read string from memory at the given offset and bytes length, and return
    /// the gas cost
    fn read_string(
        &mut self,
        offset: u64,
        len: usize,
    ) -> Result<(String, Gas)> {
        let (bytes, gas) = self.read_bytes(offset, len)?;
        let string = std::str::from_utf8(&bytes)
            .map_err(Error::InvalidUtf8String)?
            .to_string();
        Ok((string, gas))
    }

    /// Write string into memory at the given offset and return the gas cost
    #[allow(dead_code)]
    fn write_string(&mut self, offset: u64, string: String) -> Result<Gas> {
        self.write_bytes(offset, string.as_bytes())
    }
}

/// A custom [`Tunables`] to set a WASM memory limits.
///
/// Adapted from <https://github.com/wasmerio/wasmer/blob/29d7b4a5f1c401d9a1e95086ed85878c8407ec16/examples/tunables_limit_memory.rs>.
pub struct Limit<T: Tunables> {
    /// The maximum a linear memory is allowed to be (in Wasm pages, 64 KiB
    /// each). Since Wasmer ensures there is only none or one memory, this
    /// is practically an upper limit for the guest memory.
    limit: Pages,
    /// The base implementation we delegate all the logic to
    base: T,
}

/// A [`Limit`] with memory limit setup for validity predicate WASM
/// execution.
pub fn vp_limit() -> Limit<BaseTunables> {
    let base = BaseTunables::for_target(&Target::default());
    let limit = Pages(VP_MEMORY_MAX_PAGES);
    Limit { limit, base }
}

/// A [`Limit`] with memory limit setup for transaction WASM execution.
pub fn tx_limit() -> Limit<BaseTunables> {
    let base = BaseTunables::for_target(&Target::default());
    let limit = Pages(TX_MEMORY_MAX_PAGES);
    Limit { limit, base }
}

impl<T: Tunables> Limit<T> {
    /// Takes an input memory type as requested by the guest and sets
    /// a maximum if missing. The resulting memory type is final if
    /// valid. However, this can produce invalid types, such that
    /// validate_memory must be called before creating the memory.
    fn adjust_memory(&self, requested: &MemoryType) -> MemoryType {
        let mut adjusted = *requested;
        if requested.maximum.is_none() {
            adjusted.maximum = Some(self.limit);
        }
        adjusted
    }

    /// Ensures the a given memory type does not exceed the memory limit.
    /// Call this after adjusting the memory.
    fn validate_memory(
        &self,
        ty: &MemoryType,
    ) -> std::result::Result<(), MemoryError> {
        if ty.minimum > self.limit {
            return Err(MemoryError::Generic(
                "Minimum exceeds the allowed memory limit".to_string(),
            ));
        }

        if let Some(max) = ty.maximum {
            if max > self.limit {
                return Err(MemoryError::Generic(
                    "Maximum exceeds the allowed memory limit".to_string(),
                ));
            }
        } else {
            return Err(MemoryError::Generic("Maximum unset".to_string()));
        }

        Ok(())
    }
}

impl<T: Tunables> Tunables for Limit<T> {
    /// Construct a `MemoryStyle` for the provided `MemoryType`
    ///
    /// Delegated to base.
    fn memory_style(&self, memory: &MemoryType) -> MemoryStyle {
        let adjusted = self.adjust_memory(memory);
        self.base.memory_style(&adjusted)
    }

    /// Construct a `TableStyle` for the provided `TableType`
    ///
    /// Delegated to base.
    fn table_style(&self, table: &TableType) -> TableStyle {
        self.base.table_style(table)
    }

    /// Create a memory owned by the host given a [`MemoryType`] and a
    /// [`MemoryStyle`].
    ///
    /// The requested memory type is validated, adjusted to the limited and then
    /// passed to base.
    fn create_host_memory(
        &self,
        ty: &MemoryType,
        style: &MemoryStyle,
    ) -> std::result::Result<vm::VMMemory, MemoryError> {
        let adjusted = self.adjust_memory(ty);
        self.validate_memory(&adjusted)?;
        self.base.create_host_memory(&adjusted, style)
    }

    /// Create a memory owned by the VM given a [`MemoryType`] and a
    /// [`MemoryStyle`].
    ///
    /// Delegated to base.
    unsafe fn create_vm_memory(
        &self,
        ty: &MemoryType,
        style: &MemoryStyle,
        vm_definition_location: NonNull<VMMemoryDefinition>,
    ) -> std::result::Result<vm::VMMemory, MemoryError> {
        let adjusted = self.adjust_memory(ty);
        self.validate_memory(&adjusted)?;
        self.base
            .create_vm_memory(&adjusted, style, vm_definition_location)
    }

    /// Create a table owned by the host given a [`TableType`] and a
    /// [`TableStyle`].
    ///
    /// Delegated to base.
    fn create_host_table(
        &self,
        ty: &TableType,
        style: &TableStyle,
    ) -> std::result::Result<vm::VMTable, String> {
        self.base.create_host_table(ty, style)
    }

    /// Create a table owned by the VM given a [`TableType`] and a
    /// [`TableStyle`].
    ///
    /// Delegated to base.
    unsafe fn create_vm_table(
        &self,
        ty: &TableType,
        style: &TableStyle,
        vm_definition_location: NonNull<VMTableDefinition>,
    ) -> std::result::Result<vm::VMTable, String> {
        self.base.create_vm_table(ty, style, vm_definition_location)
    }
}

#[cfg(test)]
mod tests {
    use wasmer::sys::Features;
    use wasmer::{
        Cranelift, Engine, Instance, Module, NativeEngineExt, Store, Target,
        wat2wasm,
    };

    use super::*;

    #[test]
    fn test_wasm_tunables_limit_memory() {
        // A Wasm module with one exported memory (min: 7 pages, max: unset)
        let wat = br#"(module (memory 7) (export "memory" (memory 0)))"#;

        // Alternatively: A Wasm module with one exported memory (min: 7 pages,
        // max: 80 pages) let wat = br#"(module (memory 7 80) (export
        // "memory" (memory 0)))"#;

        let wasm_bytes = wat2wasm(wat).unwrap();

        // Any compiler and any engine do the job here
        let compiler = Cranelift::default();
        let mut engine = <Engine as NativeEngineExt>::new(
            Box::new(compiler),
            Target::default(),
            Features::default(),
        );

        let base = BaseTunables::for_target(&Target::default());
        let limit = Pages(24);
        let tunables = Limit { limit, base };
        engine.set_tunables(tunables);

        // Create a store, that holds the engine and our custom tunables
        let mut store = Store::new(engine);

        println!("Compiling module...");
        let module = Module::new(&store, wasm_bytes).unwrap();

        println!("Instantiating module...");
        let import_object = wasmer::imports! {};

        // Now at this point, our custom tunables are used
        let instance =
            Instance::new(&mut store, &module, &import_object).unwrap();

        // Check what happened
        let mut memories: Vec<Memory> = instance
            .exports
            .iter()
            .memories()
            .map(|pair| pair.1.clone())
            .collect();
        assert_eq!(memories.len(), 1);

        let first_memory = memories.pop().unwrap();
        println!("Memory of this instance: {:?}", first_memory);
        assert_eq!(first_memory.ty(&store).maximum.unwrap(), limit);
    }
}
