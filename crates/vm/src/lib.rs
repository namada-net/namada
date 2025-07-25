//! Virtual machine modules for running transactions and validity predicates.

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

use std::marker::PhantomData;
use std::ptr::NonNull;

use wasmparser::{Validator, WasmFeatures};

pub mod host_env;
pub mod memory;
pub mod types;
#[cfg(feature = "wasm-runtime")]
pub mod wasm;
use thiserror::Error;

const UNTRUSTED_WASM_FEATURES: WasmFeatures = WasmFeatures {
    mutable_global: false,
    saturating_float_to_int: false,
    sign_extension: true,
    reference_types: false,
    multi_value: false,
    bulk_memory: false,
    simd: false,
    relaxed_simd: false,
    threads: false,
    tail_call: false,
    floats: true,
    multi_memory: false,
    exceptions: false,
    memory64: false,
    extended_const: false,
    component_model: false,
    component_model_nested_names: false,
    component_model_values: false,
    function_references: false,
    memory_control: false,
    gc: false,
};

#[allow(missing_docs)]
#[derive(Error, Debug, Clone)]
pub enum WasmValidationError {
    #[error(
        "Invalid WASM using forbidden features: {0}. Expected: \
         {UNTRUSTED_WASM_FEATURES:?}"
    )]
    ForbiddenWasmFeatures(wasmparser::BinaryReaderError),
}

/// WASM Cache access level, used to limit dry-ran transactions to read-only
/// cache access.
pub trait WasmCacheAccess: Clone + std::fmt::Debug + Default {
    /// Is access read/write?
    fn is_read_write() -> bool;
}

/// Regular read/write caches access
#[derive(Debug, Clone, Default)]
pub struct WasmCacheRwAccess;
impl WasmCacheAccess for WasmCacheRwAccess {
    fn is_read_write() -> bool {
        true
    }
}

/// Restricted read-only access for dry-ran transactions
#[derive(Debug, Clone, Default)]
pub struct WasmCacheRoAccess;

impl WasmCacheAccess for WasmCacheRoAccess {
    fn is_read_write() -> bool {
        false
    }
}

/// Read-only access to host data.
#[derive(Debug)]
pub enum RoAccess {}

/// Read and write access to host data.
#[derive(Debug)]
pub enum RwAccess {}

/// Reference to host environment data, to be used from wasm
/// to implement host functions.
#[derive(Debug)]
pub struct HostRef<ACCESS, T: ?Sized> {
    data: NonNull<T>,
    _access: PhantomData<*const ACCESS>,
}

impl<ACCESS, T> Clone for HostRef<ACCESS, T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        *self
    }
}

impl<ACCESS, T> Copy for HostRef<ACCESS, T> {}

/// [`HostRef`] with read-write access.
pub type RwHostRef<T> = HostRef<RwAccess, T>;

/// [`HostRef`] with read-only access.
pub type RoHostRef<T> = HostRef<RoAccess, T>;

// TODO: ensure `T` is `Send` and `Sync`
unsafe impl<ACCESS, T> Send for HostRef<ACCESS, T> {}
unsafe impl<ACCESS, T> Sync for HostRef<ACCESS, T> {}

impl<T> HostRef<RoAccess, T> {
    /// Wrap a reference to the VM environment.
    ///
    /// # Safety
    ///
    /// The caller must ensure the reference to the VM environment
    /// is valid and non-null.
    pub unsafe fn new(host_structure: &T) -> Self {
        Self {
            data: unsafe {
                NonNull::new_unchecked(host_structure as *const _ as *mut _)
            },
            _access: PhantomData,
        }
    }

    /// Get a reference from the VM environment.
    ///
    /// # Safety
    ///
    /// The caller must ensure the reference to the VM environment
    /// is still valid.
    pub unsafe fn get<'a>(&self) -> &'a T {
        unsafe { self.data.as_ref() }
    }
}

impl<T> HostRef<RwAccess, T> {
    /// Wrap a mutable reference to the VM environment.
    ///
    /// # Safety
    ///
    /// The caller must ensure the reference to the VM environment
    /// is valid and non-null.
    pub unsafe fn new(host_structure: &mut T) -> Self {
        Self {
            data: unsafe { NonNull::new_unchecked(host_structure as *mut _) },
            _access: PhantomData,
        }
    }

    /// Get a reference from the VM environment.
    ///
    /// # Safety
    ///
    /// The caller must ensure the reference to the VM environment
    /// is still valid.
    pub unsafe fn get<'a>(&self) -> &'a T {
        unsafe { self.data.as_ref() }
    }

    /// Get a mutable reference from the VM environment.
    ///
    /// # Safety
    ///
    /// The caller must ensure the reference to the VM environment
    /// is still valid. Moreover, the caller must guarantee that the
    /// returned reference is not aliased, to avoid data races.
    pub unsafe fn get_mut<'a>(&self) -> &'a mut T {
        unsafe { &mut *self.data.as_ptr() }
    }
}

/// Validate an untrusted wasm code with restrictions that we place such code
/// (e.g. transaction and validity predicates)
pub fn validate_untrusted_wasm(
    wasm_code: impl AsRef<[u8]>,
) -> Result<(), WasmValidationError> {
    let mut validator = Validator::new_with_features(UNTRUSTED_WASM_FEATURES);
    let _types = validator
        .validate_all(wasm_code.as_ref())
        .map_err(WasmValidationError::ForbiddenWasmFeatures)?;
    Ok(())
}
