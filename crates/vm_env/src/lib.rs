//! This crate contains the WASM VM low-level interface.

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

use namada_core::borsh::BorshDeserialize;
pub use namada_core::internal::{HostEnvResult, KeyVal};

macro_rules! extern_c {
    ($($defs:tt)*) => {
        #[cfg(feature = "c_unwind")]
        extern "C-unwind" { $($defs)* }

        #[cfg(not(feature = "c_unwind"))]
        extern "C" { $($defs)* }
    }
}

/// Transaction environment imports
pub mod tx {
    // These host functions are implemented in the Namada's [`host_env`]
    // module. The environment provides calls to them via this C interface.
    extern_c! {
        /// Read variable-length data when we don't know the size up-front,
        /// returns the size of the value (can be 0), or -1 if the key is
        /// not present. If a value is found, it will be placed in the read
        /// cache, because we cannot allocate a buffer for it before we know
        /// its size.
        pub fn namada_tx_read(key_ptr: u64, key_len: u64) -> i64;

        /// Read variable-length temporary state when we don't know the size
        /// up-front, returns the size of the value (can be 0), or -1 if
        /// the key is not present. If a value is found, it will be placed in
        /// the result buffer, because we cannot allocate a buffer for
        /// it before we know its size.
        pub fn namada_tx_read_temp(key_ptr: u64, key_len: u64) -> i64;

        /// Read a value from result buffer.
        pub fn namada_tx_result_buffer(result_ptr: u64);

        /// Returns 1 if the key is present, -1 otherwise.
        pub fn namada_tx_has_key(key_ptr: u64, key_len: u64) -> i64;

        /// Write key/value
        pub fn namada_tx_write(
            key_ptr: u64,
            key_len: u64,
            val_ptr: u64,
            val_len: u64,
        );

        /// Write a temporary key/value
        pub fn namada_tx_write_temp(
            key_ptr: u64,
            key_len: u64,
            val_ptr: u64,
            val_len: u64,
        );

        /// Delete the given key and its value
        pub fn namada_tx_delete(key_ptr: u64, key_len: u64);

        /// Get an ID of a data iterator with key prefix, ordered by storage
        /// keys.
        pub fn namada_tx_iter_prefix(prefix_ptr: u64, prefix_len: u64) -> u64;

        /// Returns the size of the value (can be 0), or -1 if there's no next
        /// value. If a value is found, it will be placed in the read
        /// cache, because we cannot allocate a buffer for it before we know
        /// its size.
        pub fn namada_tx_iter_next(iter_id: u64) -> i64;

        /// Insert a verifier
        pub fn namada_tx_insert_verifier(addr_ptr: u64, addr_len: u64);

        /// Update a validity predicate
        pub fn namada_tx_update_validity_predicate(
            addr_ptr: u64,
            addr_len: u64,
            code_hash_ptr: u64,
            code_hash_len: u64,
            code_tag_ptr: u64,
            code_tag_len: u64,
        );

        /// Initialize a new account
        pub fn namada_tx_init_account(
            code_hash_ptr: u64,
            code_hash_len: u64,
            code_tag_ptr: u64,
            code_tag_len: u64,
            entropy_source_ptr: u64,
            entropy_source_len: u64,
            result_ptr: u64,
        );

        /// Emit an event
        pub fn namada_tx_emit_event(event_ptr: u64, event_len: u64);

        /// Get events
        pub fn namada_tx_get_events(
            event_type_ptr: u64,
            event_type_len: u64,
        ) -> i64;

        /// Get the chain ID
        pub fn namada_tx_get_chain_id(result_ptr: u64);

        /// Get the current block height
        pub fn namada_tx_get_block_height() -> u64;

        /// Get the current block header
        pub fn namada_tx_get_block_header(height: u64) -> i64;

        /// Get the current block epoch
        pub fn namada_tx_get_block_epoch() -> u64;

        /// Get the predecessor epochs
        pub fn namada_tx_get_pred_epochs() -> i64;

        /// Get the current tx index
        pub fn namada_tx_get_tx_index() -> u32;

        /// Get the native token address
        pub fn namada_tx_get_native_token(result_ptr: u64);

        /// Requires a node running with "Info" log level
        pub fn namada_tx_log_string(str_ptr: u64, str_len: u64);

        /// Charge the provided amount of gas for the current tx
        pub fn namada_tx_charge_gas(used_gas: u64);

        /// Set the sentinel for a wrong tx section commitment
        pub fn namada_tx_set_commitment_sentinel();

        /// Verify the signatures of a tx
        pub fn namada_tx_verify_tx_section_signature(
            hash_list_ptr: u64,
            hash_list_len: u64,
            public_keys_map_ptr: u64,
            public_keys_map_len: u64,
            threshold: u8,
        ) -> i64;

        /// Update the masp note commitment tree with the new notes
        pub fn namada_tx_update_masp_note_commitment_tree(
            transaction_ptr: u64,
            transaction_len: u64,
        ) -> i64;

        /// Yield a byte array value back to the host.
        pub fn namada_tx_yield_value(buf_ptr: u64, buf_len: u64);
    }
}

/// Validity predicate environment imports
pub mod vp {
    // These host functions are implemented in the Namada's [`host_env`]
    // module. The environment provides calls to them via this C interface.
    extern_c! {
        /// Read variable-length prior state when we don't know the size
        /// up-front, returns the size of the value (can be 0), or -1 if
        /// the key is not present. If a value is found, it will be placed in
        /// the result buffer, because we cannot allocate a buffer for
        /// it before we know its size.
        pub fn namada_vp_read_pre(key_ptr: u64, key_len: u64) -> i64;

        /// Read variable-length posterior state when we don't know the size
        /// up-front, returns the size of the value (can be 0), or -1 if
        /// the key is not present. If a value is found, it will be placed in
        /// the result buffer, because we cannot allocate a buffer for
        /// it before we know its size.
        pub fn namada_vp_read_post(key_ptr: u64, key_len: u64) -> i64;

        /// Read variable-length temporary state when we don't know the size
        /// up-front, returns the size of the value (can be 0), or -1 if
        /// the key is not present. If a value is found, it will be placed in
        /// the result buffer, because we cannot allocate a buffer for
        /// it before we know its size.
        pub fn namada_vp_read_temp(key_ptr: u64, key_len: u64) -> i64;

        /// Read a value from result buffer.
        pub fn namada_vp_result_buffer(result_ptr: u64);

        /// Returns 1 if the key is present in prior state, -1 otherwise.
        pub fn namada_vp_has_key_pre(key_ptr: u64, key_len: u64) -> i64;

        /// Returns 1 if the key is present in posterior state, -1 otherwise.
        pub fn namada_vp_has_key_post(key_ptr: u64, key_len: u64) -> i64;

        /// Get an ID of a data iterator with key prefix in prior state, ordered
        /// by storage keys.
        pub fn namada_vp_iter_prefix_pre(
            prefix_ptr: u64,
            prefix_len: u64,
        ) -> u64;

        /// Get an ID of a data iterator with key prefix in posterior state,
        /// ordered by storage keys.
        pub fn namada_vp_iter_prefix_post(
            prefix_ptr: u64,
            prefix_len: u64,
        ) -> u64;

        /// Read variable-length iterator's next value when we don't know the
        /// size up-front, returns the size of the value (can be 0), or
        /// -1 if the key is not present. If a value is found, it will be
        /// placed in the result buffer, because we cannot allocate a
        /// buffer for it before we know its size.
        pub fn namada_vp_iter_next(iter_id: u64) -> i64;

        /// Get the chain ID
        pub fn namada_vp_get_chain_id(result_ptr: u64);

        /// Get the current block height
        pub fn namada_vp_get_block_height() -> u64;

        /// Get the current block header
        pub fn namada_vp_get_block_header(height: u64) -> i64;

        /// Get the current tx hash
        pub fn namada_vp_get_tx_code_hash(result_ptr: u64);

        /// Get the current block epoch
        pub fn namada_vp_get_block_epoch() -> u64;

        /// Get the predecessor epochs
        pub fn namada_vp_get_pred_epochs() -> i64;

        /// Get the current tx index
        pub fn namada_vp_get_tx_index() -> u32;

        /// Get the native token address
        pub fn namada_vp_get_native_token(result_ptr: u64);

        /// Get events emitted by the current tx
        pub fn namada_vp_get_events(
            event_type_ptr: u64,
            event_type_len: u64,
        ) -> i64;

        /// Yield a byte array value back to the host.
        pub fn namada_vp_yield_value(buf_ptr: u64, buf_len: u64);

        /// Requires a node running with "Info" log level
        pub fn namada_vp_log_string(str_ptr: u64, str_len: u64);

        /// Verify the signatures of a tx
        pub fn namada_vp_verify_tx_section_signature(
            hash_list_ptr: u64,
            hash_list_len: u64,
            public_keys_map_ptr: u64,
            public_keys_map_len: u64,
            signer_ptr: u64,
            signer_len: u64,
            threshold: u8,
        );

        /// Verify the signatures of an authorization
        pub fn namada_vp_verify_signature(
            public_key_ptr: u64,
            public_key_len: u64,
            auth_ptr: u64,
            auth_len: u64,
        );

        /// Evaluate a validity-predicate
        pub fn namada_vp_eval(
            vp_code_hash_ptr: u64,
            vp_code_hash_len: u64,
            input_data_ptr: u64,
            input_data_len: u64,
        ) -> i64;

        /// Charge the provided amount of gas for the current vp
        pub fn namada_vp_charge_gas(used_gas: u64);
    }
}

/// This function is a helper to handle the second step of reading var-len
/// values from the host.
///
/// In cases where we're reading a value from the host in the guest and
/// we don't know the byte size up-front, we have to read it in 2-steps. The
/// first step reads the value into a result buffer and returns the size (if
/// any) back to the guest, the second step reads the value from cache into a
/// pre-allocated buffer with the obtained size.
pub fn read_from_buffer(
    read_result: i64,
    #[cfg(feature = "c_unwind")] result_buffer: unsafe extern "C-unwind" fn(
        u64,
    ),
    #[cfg(not(feature = "c_unwind"))] result_buffer: unsafe extern "C" fn(u64),
) -> Option<Vec<u8>> {
    if HostEnvResult::is_fail(read_result) {
        None
    } else {
        let len = usize::try_from(read_result).ok()?;
        let result = vec![0u8; len];
        let offset = result.as_slice().as_ptr() as u64;
        unsafe { result_buffer(offset) };
        Some(result)
    }
}

/// This function is a helper to handle the second step of reading var-len
/// values in a key-value pair from the host.
pub fn read_key_val_bytes_from_buffer(
    read_result: i64,
    #[cfg(feature = "c_unwind")] result_buffer: unsafe extern "C-unwind" fn(
        u64,
    ),
    #[cfg(not(feature = "c_unwind"))] result_buffer: unsafe extern "C" fn(u64),
) -> Option<(String, Vec<u8>)> {
    let key_val = read_from_buffer(read_result, result_buffer)
        .and_then(|t| KeyVal::try_from_slice(&t[..]).ok());
    key_val.map(|key_val| (key_val.key, key_val.val))
}
