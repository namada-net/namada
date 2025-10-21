//! This crate contains library code for transaction WASM.

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

pub mod account;
pub mod ibc;
pub mod key;
pub mod pgf;
pub mod proof_of_stake;
pub mod token;

use core::slice;
use std::marker::PhantomData;
use std::str::FromStr;

use chain::ChainId;
use namada_account::AccountPublicKeysMap;
pub use namada_core::address::Address;
pub use namada_core::borsh::{
    BorshDeserialize, BorshSerialize, BorshSerializeExt,
};
use namada_core::chain::CHAIN_ID_LENGTH;
pub use namada_core::chain::{
    BLOCK_HASH_LENGTH, BlockHash, BlockHeader, BlockHeight, Epoch,
};
pub use namada_core::ethereum_events::EthAddress;
use namada_core::internal::HostEnvResult;
use namada_core::key::common;
use namada_core::masp_primitives::asset_type::AssetType;
use namada_core::storage::TxIndex;
pub use namada_core::{address, encode, eth_bridge_pool, storage, *};
pub use namada_events::extend::Log;
pub use namada_events::{
    EmitEvents, Event, EventLevel, EventToEmit, EventType,
};
pub use namada_governance::storage as gov_storage;
pub use namada_macros::transaction;
pub use namada_parameters::storage as parameters_storage;
pub use namada_state::{
    Error, OptionExt, Result, ResultExt, StorageRead, StorageWrite,
    collections, iter_prefix, iter_prefix_bytes,
};
use namada_token::MaspTransaction;
pub use namada_tx::{BatchedTx, Section, Tx, action, data as transaction};
pub use namada_tx_env::TxEnv;
use namada_vm_env::tx::*;
use namada_vm_env::{read_from_buffer, read_key_val_bytes_from_buffer};
pub use {
    namada_gas as gas, namada_governance as governance,
    namada_parameters as parameters,
};

/// Log a string. The message will be printed at the `tracing::Level::Info`.
pub fn log_string<T: AsRef<str>>(msg: T) {
    let msg = msg.as_ref();
    unsafe {
        namada_tx_log_string(msg.as_ptr() as _, msg.len() as _);
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

/// Execution context provides access to the host environment functions
#[derive(Debug, Clone)]
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
    /// When using `#[transaction]` macro from `namada_macros`,
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

    /// Yield a byte array value back to the host environment.
    pub fn yield_value<V: AsRef<[u8]>>(&self, value: V) {
        let value = value.as_ref();
        unsafe {
            namada_tx_yield_value(value.as_ptr() as _, value.len() as _);
        }
    }

    /// Get the transaction data for the specified inner tx
    pub fn get_tx_data(&mut self, batched_tx: &BatchedTx) -> Result<Vec<u8>> {
        let BatchedTx { tx, cmt } = batched_tx;

        tx.data(cmt).ok_or_err_msg("Missing data").inspect_err(|_| {
            self.set_commitment_sentinel();
        })
    }
}

/// Transaction result
pub type TxResult = Result<()>;

/// Storage key-val pair iterator
#[derive(Debug)]
pub struct KeyValIterator<T>(pub u64, pub PhantomData<T>);

impl StorageRead for Ctx {
    type PrefixIter<'iter> = KeyValIterator<(String, Vec<u8>)>;

    fn read_bytes(&self, key: &storage::Key) -> Result<Option<Vec<u8>>> {
        let key = key.to_string();
        let read_result =
            unsafe { namada_tx_read(key.as_ptr() as _, key.len() as _) };
        Ok(read_from_buffer(read_result, namada_tx_result_buffer))
    }

    fn has_key(&self, key: &storage::Key) -> Result<bool> {
        let key = key.to_string();
        let found =
            unsafe { namada_tx_has_key(key.as_ptr() as _, key.len() as _) };
        Ok(HostEnvResult::is_success(found))
    }

    fn has_conversion(&self, asset_type: &AssetType) -> Result<bool> {
        let asset_type = asset_type.serialize_to_vec();
        let found = unsafe {
            namada_tx_has_conversion(
                asset_type.as_ptr() as _,
                asset_type.len() as _,
            )
        };
        Ok(HostEnvResult::is_success(found))
    }

    fn get_chain_id(&self) -> Result<ChainId> {
        let result = Vec::with_capacity(CHAIN_ID_LENGTH);
        unsafe {
            namada_tx_get_chain_id(result.as_ptr() as _);
        }
        let slice =
            unsafe { slice::from_raw_parts(result.as_ptr(), CHAIN_ID_LENGTH) };
        Ok(ChainId::from_str(
            std::str::from_utf8(slice).expect("Chain ID must be valid utf8"),
        )
        .expect("Chain ID must be valid"))
    }

    fn get_block_height(&self) -> Result<BlockHeight> {
        Ok(BlockHeight(unsafe { namada_tx_get_block_height() }))
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>> {
        let read_result = unsafe { namada_tx_get_block_header(height.0) };
        match read_from_buffer(read_result, namada_tx_result_buffer) {
            Some(value) => Ok(Some(
                BlockHeader::try_from_slice(&value[..])
                    .expect("The conversion shouldn't fail"),
            )),
            None => Ok(None),
        }
    }

    fn get_block_epoch(&self) -> Result<namada_core::chain::Epoch> {
        Ok(Epoch(unsafe { namada_tx_get_block_epoch() }))
    }

    fn get_pred_epochs(&self) -> Result<namada_core::chain::Epochs> {
        let read_result = unsafe { namada_tx_get_pred_epochs() };
        let bytes = read_from_buffer(read_result, namada_tx_result_buffer)
            .ok_or(Error::SimpleMessage(
                "Missing result from `namada_tx_get_pred_epochs` call",
            ))?;
        Ok(namada_core::decode(bytes).expect("Cannot decode pred epochs"))
    }

    /// Get the native token address
    fn get_native_token(&self) -> Result<Address> {
        let result = Vec::with_capacity(address::ADDRESS_LEN);
        unsafe {
            namada_tx_get_native_token(result.as_ptr() as _);
        }
        let slice = unsafe {
            slice::from_raw_parts(result.as_ptr(), address::ADDRESS_LEN)
        };
        let address_str =
            std::str::from_utf8(slice).expect("Cannot decode native address");
        Ok(Address::decode(address_str).expect("Cannot decode native address"))
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> Result<Self::PrefixIter<'iter>> {
        let prefix = prefix.to_string();
        let iter_id = unsafe {
            namada_tx_iter_prefix(prefix.as_ptr() as _, prefix.len() as _)
        };
        Ok(KeyValIterator(iter_id, PhantomData))
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>> {
        let read_result = unsafe { namada_tx_iter_next(iter.0) };
        Ok(read_key_val_bytes_from_buffer(
            read_result,
            namada_tx_result_buffer,
        ))
    }

    fn get_tx_index(&self) -> Result<TxIndex> {
        let tx_index = unsafe { namada_tx_get_tx_index() };
        Ok(TxIndex(tx_index))
    }
}

impl StorageWrite for Ctx {
    fn write_bytes(
        &mut self,
        key: &storage::Key,
        val: impl AsRef<[u8]>,
    ) -> Result<()> {
        let key = key.to_string();
        unsafe {
            namada_tx_write(
                key.as_ptr() as _,
                key.len() as _,
                val.as_ref().as_ptr() as _,
                val.as_ref().len() as _,
            )
        };
        Ok(())
    }

    fn delete(&mut self, key: &storage::Key) -> Result<()> {
        let key = key.to_string();
        unsafe { namada_tx_delete(key.as_ptr() as _, key.len() as _) };
        Ok(())
    }
}

impl EmitEvents for Ctx {
    #[inline]
    fn emit<E>(&mut self, event: E)
    where
        E: EventToEmit,
    {
        _ = self.emit_event(event);
    }

    fn emit_many<B, E>(&mut self, event_batch: B)
    where
        B: IntoIterator<Item = E>,
        E: EventToEmit,
    {
        for event in event_batch {
            self.emit(event.into());
        }
    }
}

impl TxEnv for Ctx {
    fn read_bytes_temp(&self, key: &storage::Key) -> Result<Option<Vec<u8>>> {
        let key = key.to_string();
        let read_result =
            unsafe { namada_tx_read_temp(key.as_ptr() as _, key.len() as _) };
        Ok(read_from_buffer(read_result, namada_tx_result_buffer))
    }

    fn write_bytes_temp(
        &mut self,
        key: &storage::Key,
        val: impl AsRef<[u8]>,
    ) -> Result<()> {
        let key = key.to_string();
        unsafe {
            namada_tx_write_temp(
                key.as_ptr() as _,
                key.len() as _,
                val.as_ref().as_ptr() as _,
                val.as_ref().len() as _,
            )
        };
        Ok(())
    }

    fn insert_verifier(&mut self, addr: &Address) -> Result<()> {
        let addr = addr.encode();
        unsafe {
            namada_tx_insert_verifier(addr.as_ptr() as _, addr.len() as _)
        }
        Ok(())
    }

    fn init_account(
        &mut self,
        code_hash: impl AsRef<[u8]>,
        code_tag: &Option<String>,
        entropy_source: &[u8],
    ) -> Result<Address> {
        let code_hash = code_hash.as_ref();
        let code_tag = code_tag.serialize_to_vec();
        let result = Vec::with_capacity(address::ESTABLISHED_ADDRESS_BYTES_LEN);
        unsafe {
            namada_tx_init_account(
                code_hash.as_ptr() as _,
                code_hash.len() as _,
                code_tag.as_ptr() as _,
                code_tag.len() as _,
                entropy_source.as_ptr() as _,
                entropy_source.len() as _,
                result.as_ptr() as _,
            )
        };
        let slice = unsafe {
            slice::from_raw_parts(
                result.as_ptr(),
                address::ESTABLISHED_ADDRESS_BYTES_LEN,
            )
        };
        Ok(Address::try_from_slice(slice)
            .expect("Decoding address created by the ledger shouldn't fail"))
    }

    fn update_validity_predicate(
        &mut self,
        addr: &Address,
        code_hash: impl AsRef<[u8]>,
        code_tag: &Option<String>,
    ) -> Result<()> {
        let addr = addr.encode();
        let code_hash = code_hash.as_ref();
        let code_tag = code_tag.serialize_to_vec();
        unsafe {
            namada_tx_update_validity_predicate(
                addr.as_ptr() as _,
                addr.len() as _,
                code_hash.as_ptr() as _,
                code_hash.len() as _,
                code_tag.as_ptr() as _,
                code_tag.len() as _,
            )
        };
        Ok(())
    }

    fn emit_event<E: EventToEmit>(&mut self, event: E) -> Result<()> {
        let event: Event = event.into();
        let event = borsh::to_vec(&event).unwrap();
        unsafe { namada_tx_emit_event(event.as_ptr() as _, event.len() as _) };
        Ok(())
    }

    fn charge_gas(&mut self, used_gas: u64) -> Result<()> {
        unsafe { namada_tx_charge_gas(used_gas) };
        Ok(())
    }

    fn get_events(&self, event_type: &EventType) -> Result<Vec<Event>> {
        let event_type = event_type.to_string();
        let read_result = unsafe {
            namada_tx_get_events(
                event_type.as_ptr() as _,
                event_type.len() as _,
            )
        };
        match read_from_buffer(read_result, namada_tx_result_buffer) {
            Some(value) => Ok(Vec::<Event>::try_from_slice(&value[..])
                .expect("The conversion shouldn't fail")),
            None => Ok(Vec::new()),
        }
    }

    fn set_commitment_sentinel(&mut self) {
        unsafe { namada_tx_set_commitment_sentinel() }
    }

    fn update_masp_note_commitment_tree(
        transaction: &MaspTransaction,
    ) -> Result<bool> {
        update_masp_note_commitment_tree(transaction)
    }
}

impl namada_tx::action::Read for Ctx {
    type Err = Error;

    fn read_temp<T: namada_core::borsh::BorshDeserialize>(
        &self,
        key: &storage::Key,
    ) -> Result<Option<T>> {
        TxEnv::read_temp(self, key)
    }
}

impl namada_tx::action::Write for Ctx {
    fn write_temp<T: BorshSerialize>(
        &mut self,
        key: &storage::Key,
        val: T,
    ) -> Result<()> {
        TxEnv::write_temp(self, key, val)
    }
}

/// Verify section signatures against the given list of keys
pub fn verify_signatures_of_pks(
    tx: &Tx,
    pks: Vec<common::PublicKey>,
) -> Result<bool> {
    // Require signatures from all the given keys
    let threshold = u8::try_from(pks.len()).into_storage_result()?;
    let public_keys_index_map = AccountPublicKeysMap::from_iter(pks);

    // Serialize parameters
    let public_keys_map = public_keys_index_map.serialize_to_vec();
    let targets = [tx.raw_header_hash()].serialize_to_vec();

    let valid = unsafe {
        namada_tx_verify_tx_section_signature(
            targets.as_ptr() as _,
            targets.len() as _,
            public_keys_map.as_ptr() as _,
            public_keys_map.len() as _,
            threshold,
        )
    };

    Ok(HostEnvResult::is_success(valid))
}

/// Update the masp note commitment tree in storage with the new notes
pub fn update_masp_note_commitment_tree(
    transaction: &MaspTransaction,
) -> Result<bool> {
    // Serialize transaction
    let transaction = transaction.serialize_to_vec();

    let valid = unsafe {
        namada_tx_update_masp_note_commitment_tree(
            transaction.as_ptr() as _,
            transaction.len() as _,
        )
    };

    Ok(HostEnvResult::is_success(valid))
}
