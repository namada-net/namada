//! This crate contains library code for validity predicate WASM. Most of the
//! code is re-exported from the `namada_vm_env` crate.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

/// IBC events and storage keys.
pub mod ibc {
    pub use namada_ibc::event::{IbcEvent, IbcEventType};
    pub use namada_ibc::storage::is_ibc_key;
}

// used in the VP input
use core::slice;
pub use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::str::FromStr;

use chain::ChainId;
pub use namada_core::address::Address;
pub use namada_core::borsh::{
    BorshDeserialize, BorshSerialize, BorshSerializeExt,
};
use namada_core::chain::{
    BlockHeader, BlockHeight, CHAIN_ID_LENGTH, Epoch, Epochs,
};
pub use namada_core::collections::HashSet;
use namada_core::hash::{HASH_LENGTH, Hash};
use namada_core::internal::HostEnvResult;
use namada_core::masp_primitives::asset_type::AssetType;
use namada_core::storage::TxIndex;
pub use namada_core::validity_predicate::{VpError, VpErrorExtResult};
pub use namada_core::*;
use namada_events::{Event, EventType};
use namada_gas::Gas;
pub use namada_governance::pgf::storage as pgf_storage;
pub use namada_governance::storage as gov_storage;
pub use namada_macros::validity_predicate;
pub use namada_storage::{
    Error, OptionExt, ResultExt, StorageRead, iter_prefix, iter_prefix_bytes,
};
pub use namada_tx::{BatchedTx, IndexedTx, Section, Tx};
use namada_vm_env::vp::*;
use namada_vm_env::{read_from_buffer, read_key_val_bytes_from_buffer};
pub use namada_vp_env::{VpEnv, collection_validation};
pub use sha2::{Digest, Sha256, Sha384, Sha512};
use tx::{BatchedTxRef, TxCommitments};
pub use {
    namada_account as account, namada_parameters as parameters,
    namada_proof_of_stake as proof_of_stake, namada_token as token,
    namada_tx as tx,
};

/// SHA-256 hash of given bytes
pub fn sha256(bytes: &[u8]) -> Hash {
    let digest = Sha256::digest(bytes);
    Hash(*digest.as_ref())
}

/// Log a string. The message will be printed at the `tracing::Level::Info`.
pub fn log_string<T: AsRef<str>>(msg: T) {
    let msg = msg.as_ref();
    unsafe {
        namada_vp_log_string(msg.as_ptr() as _, msg.len() as _);
    }
}

/// Checks if a proposal id is being executed
pub fn is_proposal_accepted(ctx: &Ctx, proposal_id: u64) -> VpEnvResult<bool> {
    let proposal_execution_key =
        gov_storage::keys::get_proposal_execution_key(proposal_id);

    ctx.has_key_pre(&proposal_execution_key).into_vp_error()
}

/// Verify section signatures
#[cold]
#[inline(never)]
fn verify_signatures(ctx: &Ctx, tx: &Tx, owner: &Address) -> VpResult {
    let public_keys_index_map =
        account::public_keys_index_map(&ctx.pre(), owner).into_vp_error()?;
    let threshold = account::threshold(&ctx.pre(), owner)
        .into_vp_error()?
        .unwrap_or(1);

    // Serialize parameters
    let public_keys_map = public_keys_index_map.serialize_to_vec();
    let targets = [tx.raw_header_hash()].serialize_to_vec();
    let signer = owner.serialize_to_vec();

    unsafe {
        namada_vp_verify_tx_section_signature(
            targets.as_ptr() as _,
            targets.len() as _,
            public_keys_map.as_ptr() as _,
            public_keys_map.len() as _,
            signer.as_ptr() as _,
            signer.len() as _,
            threshold,
        );
    }
    Ok(())
}

/// Utility to minimize signature verification ops.
#[derive(Default)]
#[repr(transparent)]
pub struct VerifySigGadget {
    has_validated_sig: bool,
}

impl VerifySigGadget {
    /// Create a new [`VerifySigGadget`].
    pub const fn new() -> Self {
        Self {
            has_validated_sig: false,
        }
    }

    /// Verify a tx signature, only paying the cost of this operation once.
    #[inline(always)]
    pub fn verify_signatures(
        &mut self,
        ctx: &Ctx,
        tx_data: &Tx,
        cmt: &TxCommitments,
        owner: &Address,
    ) -> VpResult {
        if !self.has_validated_sig {
            // First check that the memo section of this inner tx has not been
            // tampered with
            if cmt.memo_hash != namada_core::hash::Hash::zero() {
                tx_data.get_section(&cmt.memo_hash).ok_or_else(|| {
                    VpError::Erased(format!(
                        "Memo section with hash {} is missing",
                        cmt.memo_hash
                    ))
                })?;
            }

            // Then check the signature
            verify_signatures(ctx, tx_data, owner)?;
            self.has_validated_sig = true;
        }
        Ok(())
    }

    /// Identical to [`Self::verify_signatures`], but execute a predicate before
    /// validating a sig. If the predicate returns false, we do not check tx
    /// signatures.
    #[inline(always)]
    pub fn verify_signatures_when<F: FnOnce() -> bool>(
        &mut self,
        predicate: F,
        ctx: &Ctx,
        tx_data: &Tx,
        cmt: &TxCommitments,
        owner: &Address,
    ) -> VpResult {
        if predicate() {
            self.verify_signatures(ctx, tx_data, cmt, owner)?;
        }
        Ok(())
    }
}

/// Format and log a string in a debug build.
///
/// In WASM target debug build, the message will be printed at the
/// `tracing::Level::Info` when executed in the VM. An optimized build will
/// omit any `debug_log!` statements unless `-C debug-assertions` is passed to
/// the compiler.
///
/// In non-WASM target, the message is simply printed out to stdout.
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {{
        (
            if cfg!(target_arch = "wasm32") {
                if cfg!(debug_assertions)
                {
                    log_string(format!($($arg)*));
                }
            } else {
                println!($($arg)*);
            }
        )
    }};
}

/// VP execution context provides access to storage prior and posterior to the
/// transaction execution and host environment functions.
#[derive(Debug)]
pub struct Ctx(());

impl Ctx {
    /// Create a host context. The context on WASM side is only provided by
    /// the VM once its being executed (in here it's implicit). But
    /// because we want to have interface identical with the native
    /// VPs, in which the context is explicit, in here we're just
    /// using an empty `Ctx` to "fake" it.
    ///
    /// # Safety
    ///
    /// When using `#[validity_predicate]` macro from `namada_macros`,
    /// the constructor should not be called from transactions and validity
    /// predicates implementation directly - they receive `&Self` as
    /// an argument provided by the macro that wrap the low-level WASM
    /// interface with Rust native types.
    ///
    /// Otherwise, this should only be called once to initialize this "fake"
    /// context in order to benefit from type-safety of the host environment
    /// methods implemented on the context.
    #[allow(clippy::new_without_default)]
    pub const unsafe fn new() -> Self {
        Self(())
    }

    /// Read access to the prior storage (state before tx execution)
    /// via [`trait@StorageRead`].
    pub fn pre(&self) -> CtxPreStorageRead<'_> {
        CtxPreStorageRead { _ctx: self }
    }

    /// Read access to the posterior storage (state after tx execution)
    /// via [`trait@StorageRead`].
    pub fn post(&self) -> CtxPostStorageRead<'_> {
        CtxPostStorageRead { _ctx: self }
    }

    /// Yield a byte array value back to the host environment.
    pub fn yield_value<V: AsRef<[u8]>>(&self, value: V) {
        let value = value.as_ref();
        unsafe {
            namada_vp_yield_value(value.as_ptr() as _, value.len() as _);
        }
    }
}

/// Read access to the prior storage (state before tx execution) via
/// [`trait@StorageRead`].
#[derive(Debug)]
pub struct CtxPreStorageRead<'a> {
    _ctx: &'a Ctx,
}

/// Read access to the posterior storage (state after tx execution) via
/// [`trait@StorageRead`].
#[derive(Debug)]
pub struct CtxPostStorageRead<'a> {
    _ctx: &'a Ctx,
}

/// Result of `VpEnv` or `namada_storage::StorageRead` method call
pub type VpEnvResult<T> = Result<T, VpError>;

/// Validity predicate result
pub type VpResult = VpEnvResult<()>;

/// Accept a transaction
pub fn accept() -> VpResult {
    Ok(())
}

/// Reject a transaction
pub fn reject() -> VpResult {
    Err(VpError::Unspecified)
}

/// Storage key-val pair iterator
#[derive(Debug)]
pub struct KeyValIterator<T>(pub u64, pub PhantomData<T>);

impl<'view> VpEnv<'view> for Ctx {
    type Post = CtxPostStorageRead<'view>;
    type Pre = CtxPreStorageRead<'view>;
    type PrefixIter<'iter> = KeyValIterator<(String, Vec<u8>)>;

    fn pre(&'view self) -> Self::Pre {
        CtxPreStorageRead { _ctx: self }
    }

    fn post(&'view self) -> Self::Post {
        CtxPostStorageRead { _ctx: self }
    }

    fn read_temp<T: BorshDeserialize>(
        &self,
        key: &storage::Key,
    ) -> Result<Option<T>, Error> {
        let key = key.to_string();
        let read_result =
            unsafe { namada_vp_read_temp(key.as_ptr() as _, key.len() as _) };
        Ok(read_from_buffer(read_result, namada_vp_result_buffer)
            .and_then(|t| T::try_from_slice(&t[..]).ok()))
    }

    fn read_bytes_temp(
        &self,
        key: &storage::Key,
    ) -> Result<Option<Vec<u8>>, Error> {
        let key = key.to_string();
        let read_result =
            unsafe { namada_vp_read_temp(key.as_ptr() as _, key.len() as _) };
        Ok(read_from_buffer(read_result, namada_vp_result_buffer))
    }

    fn get_chain_id(&self) -> Result<ChainId, Error> {
        // Both `CtxPreStorageRead` and `CtxPostStorageRead` have the same impl
        get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight, Error> {
        // Both `CtxPreStorageRead` and `CtxPostStorageRead` have the same impl
        get_block_height()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>, Error> {
        // Both `CtxPreStorageRead` and `CtxPostStorageRead` have the same impl
        get_block_header(height)
    }

    fn get_block_epoch(&self) -> Result<Epoch, Error> {
        // Both `CtxPreStorageRead` and `CtxPostStorageRead` have the same impl
        get_block_epoch()
    }

    fn get_pred_epochs(&self) -> namada_storage::Result<chain::Epochs> {
        // Both `CtxPreStorageRead` and `CtxPostStorageRead` have the same impl
        get_pred_epochs()
    }

    fn get_tx_index(&self) -> Result<IndexedTx, Error> {
        get_tx_index().map(|(block_height, block_index, batch_index)| {
            IndexedTx {
                block_height,
                block_index,
                batch_index,
            }
        })
    }

    fn get_native_token(&self) -> Result<Address, Error> {
        // Both `CtxPreStorageRead` and `CtxPostStorageRead` have the same impl
        get_native_token()
    }

    fn get_events(&self, event_type: &EventType) -> Result<Vec<Event>, Error> {
        let event_type = event_type.to_string();
        let read_result = unsafe {
            namada_vp_get_events(
                event_type.as_ptr() as _,
                event_type.len() as _,
            )
        };
        match read_from_buffer(read_result, namada_vp_result_buffer) {
            Some(value) => Ok(Vec::<Event>::try_from_slice(&value[..])
                .expect("The conversion shouldn't fail")),
            None => Ok(Vec::new()),
        }
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> Result<Self::PrefixIter<'iter>, Error> {
        iter_prefix_pre_impl(prefix)
    }

    fn eval(
        &self,
        vp_code_hash: Hash,
        input_data: BatchedTxRef<'_>,
    ) -> Result<(), Error> {
        let input_data_bytes = input_data.serialize_to_vec();

        HostEnvResult::success_or(
            unsafe {
                namada_vp_eval(
                    vp_code_hash.0.as_ptr() as _,
                    vp_code_hash.0.len() as _,
                    input_data_bytes.as_ptr() as _,
                    input_data_bytes.len() as _,
                )
            },
            Error::SimpleMessage("VP rejected the tx"),
        )
    }

    fn get_tx_code_hash(&self) -> Result<Option<Hash>, Error> {
        let result = Vec::with_capacity(HASH_LENGTH + 1);
        unsafe {
            namada_vp_get_tx_code_hash(result.as_ptr() as _);
        }
        let slice =
            unsafe { slice::from_raw_parts(result.as_ptr(), HASH_LENGTH + 1) };
        Ok(if slice[0] == 1 {
            Some(Hash(
                slice[1..HASH_LENGTH + 1]
                    .try_into()
                    .expect("Cannot convert the hash"),
            ))
        } else {
            None
        })
    }

    fn charge_gas(&self, used_gas: Gas) -> Result<(), Error> {
        unsafe { namada_vp_charge_gas(used_gas.into()) };
        Ok(())
    }
}

impl namada_tx::action::Read for Ctx {
    type Err = Error;

    fn read_temp<T: BorshDeserialize>(
        &self,
        key: &storage::Key,
    ) -> Result<Option<T>, Self::Err> {
        VpEnv::read_temp(self, key)
    }
}

impl StorageRead for CtxPreStorageRead<'_> {
    type PrefixIter<'iter>
        = KeyValIterator<(String, Vec<u8>)>
    where
        Self: 'iter;

    fn read_bytes(&self, key: &storage::Key) -> Result<Option<Vec<u8>>, Error> {
        let key = key.to_string();
        let read_result =
            unsafe { namada_vp_read_pre(key.as_ptr() as _, key.len() as _) };
        Ok(read_from_buffer(read_result, namada_vp_result_buffer))
    }

    fn has_key(&self, key: &storage::Key) -> Result<bool, Error> {
        let key = key.to_string();
        let found =
            unsafe { namada_vp_has_key_pre(key.as_ptr() as _, key.len() as _) };
        Ok(HostEnvResult::is_success(found))
    }

    fn has_conversion(
        &self,
        asset_type: &AssetType,
    ) -> namada_storage::Result<bool> {
        let asset_type = asset_type.serialize_to_vec();
        let found = unsafe {
            namada_vp_has_conversion(
                asset_type.as_ptr() as _,
                asset_type.len() as _,
            )
        };
        Ok(HostEnvResult::is_success(found))
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> Result<Self::PrefixIter<'iter>, Error> {
        iter_prefix_pre_impl(prefix)
    }

    // ---- Methods below share the same implementation in `pre/post` ----

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Error> {
        let read_result = unsafe { namada_vp_iter_next(iter.0) };
        Ok(read_key_val_bytes_from_buffer(
            read_result,
            namada_vp_result_buffer,
        ))
    }

    fn get_chain_id(&self) -> Result<ChainId, Error> {
        get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight, Error> {
        get_block_height()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>, Error> {
        get_block_header(height)
    }

    fn get_block_epoch(&self) -> Result<Epoch, Error> {
        get_block_epoch()
    }

    fn get_pred_epochs(&self) -> namada_storage::Result<chain::Epochs> {
        get_pred_epochs()
    }

    fn get_tx_index(
        &self,
    ) -> Result<(BlockHeight, TxIndex, Option<u32>), Error> {
        get_tx_index()
    }

    fn get_native_token(&self) -> Result<Address, Error> {
        get_native_token()
    }
}

impl StorageRead for CtxPostStorageRead<'_> {
    type PrefixIter<'iter>
        = KeyValIterator<(String, Vec<u8>)>
    where
        Self: 'iter;

    fn read_bytes(&self, key: &storage::Key) -> Result<Option<Vec<u8>>, Error> {
        let key = key.to_string();
        let read_result =
            unsafe { namada_vp_read_post(key.as_ptr() as _, key.len() as _) };
        Ok(read_from_buffer(read_result, namada_vp_result_buffer))
    }

    fn has_key(&self, key: &storage::Key) -> Result<bool, Error> {
        let key = key.to_string();
        let found = unsafe {
            namada_vp_has_key_post(key.as_ptr() as _, key.len() as _)
        };
        Ok(HostEnvResult::is_success(found))
    }

    fn has_conversion(
        &self,
        asset_type: &AssetType,
    ) -> namada_storage::Result<bool> {
        let asset_type = asset_type.serialize_to_vec();
        let found = unsafe {
            namada_vp_has_conversion(
                asset_type.as_ptr() as _,
                asset_type.len() as _,
            )
        };
        Ok(HostEnvResult::is_success(found))
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> Result<Self::PrefixIter<'iter>, Error> {
        iter_prefix_post_impl(prefix)
    }

    // ---- Methods below share the same implementation in `pre/post` ----

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Error> {
        let read_result = unsafe { namada_vp_iter_next(iter.0) };
        Ok(read_key_val_bytes_from_buffer(
            read_result,
            namada_vp_result_buffer,
        ))
    }

    fn get_chain_id(&self) -> Result<ChainId, Error> {
        get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight, Error> {
        get_block_height()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>, Error> {
        get_block_header(height)
    }

    fn get_block_epoch(&self) -> Result<Epoch, Error> {
        get_block_epoch()
    }

    fn get_pred_epochs(&self) -> namada_storage::Result<chain::Epochs> {
        get_pred_epochs()
    }

    fn get_tx_index(
        &self,
    ) -> Result<(BlockHeight, TxIndex, Option<u32>), Error> {
        get_tx_index()
    }

    fn get_native_token(&self) -> Result<Address, Error> {
        get_native_token()
    }
}

fn iter_prefix_pre_impl(
    prefix: &storage::Key,
) -> Result<KeyValIterator<(String, Vec<u8>)>, Error> {
    let prefix = prefix.to_string();
    let iter_id = unsafe {
        namada_vp_iter_prefix_pre(prefix.as_ptr() as _, prefix.len() as _)
    };
    Ok(KeyValIterator(iter_id, PhantomData))
}

fn iter_prefix_post_impl(
    prefix: &storage::Key,
) -> Result<KeyValIterator<(String, Vec<u8>)>, Error> {
    let prefix = prefix.to_string();
    let iter_id = unsafe {
        namada_vp_iter_prefix_post(prefix.as_ptr() as _, prefix.len() as _)
    };
    Ok(KeyValIterator(iter_id, PhantomData))
}

fn get_chain_id() -> Result<ChainId, Error> {
    let result = Vec::with_capacity(CHAIN_ID_LENGTH);
    unsafe {
        namada_vp_get_chain_id(result.as_ptr() as _);
    }
    let slice =
        unsafe { slice::from_raw_parts(result.as_ptr(), CHAIN_ID_LENGTH) };
    Ok(ChainId::from_str(
        std::str::from_utf8(slice).expect("Chain ID must be valid utf8"),
    )
    .expect("Chain ID must be valid"))
}

fn get_block_height() -> Result<BlockHeight, Error> {
    Ok(BlockHeight(unsafe { namada_vp_get_block_height() }))
}

fn get_block_header(height: BlockHeight) -> Result<Option<BlockHeader>, Error> {
    let read_result = unsafe { namada_vp_get_block_header(height.0) };
    match read_from_buffer(read_result, namada_vp_result_buffer) {
        Some(value) => Ok(Some(
            BlockHeader::try_from_slice(&value[..])
                .expect("The conversion shouldn't fail"),
        )),
        None => Ok(None),
    }
}

fn get_block_epoch() -> Result<Epoch, Error> {
    Ok(Epoch(unsafe { namada_vp_get_block_epoch() }))
}

fn get_tx_index() -> Result<(BlockHeight, TxIndex, Option<u32>), Error> {
    // NOTE: the conversion to i64 is infallible
    let read_result = unsafe { namada_vp_get_tx_index() } as i64;
    let bytes = read_from_buffer(read_result, namada_vp_result_buffer).ok_or(
        Error::SimpleMessage(
            "Missing result from `namada_vp_get_tx_index` call",
        ),
    )?;
    let IndexedTx {
        block_height,
        block_index,
        batch_index,
    } = namada_core::decode(bytes).expect("Cannot decode tx index");
    Ok((block_height, block_index, batch_index))
}

fn get_pred_epochs() -> Result<Epochs, Error> {
    let read_result = unsafe { namada_vp_get_pred_epochs() };
    let bytes = read_from_buffer(read_result, namada_vp_result_buffer).ok_or(
        Error::SimpleMessage(
            "Missing result from `namada_vp_get_pred_epochs` call",
        ),
    )?;
    Ok(namada_core::decode(bytes).expect("Cannot decode pred epochs"))
}

fn get_native_token() -> Result<Address, Error> {
    let result = Vec::with_capacity(address::ADDRESS_LEN);
    unsafe {
        namada_vp_get_native_token(result.as_ptr() as _);
    }
    let slice =
        unsafe { slice::from_raw_parts(result.as_ptr(), address::ADDRESS_LEN) };
    let address_str =
        std::str::from_utf8(slice).expect("Cannot decode native address");
    Ok(Address::decode(address_str).expect("Cannot decode native address"))
}
