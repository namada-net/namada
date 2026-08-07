//! Parameters storage

use namada_core::address::Address;
use namada_core::dec::Dec;
use namada_core::storage::DbKeySeg;
pub use namada_core::storage::Key;
use namada_macros::StorageKeys;
use namada_state::{Error, Result, StorageRead};

use super::ADDRESS;

#[derive(StorageKeys)]
struct Keys {
    // ========================================
    // Ethereum bridge parameters
    // ========================================
    /// Sub-key for storing the initial Ethereum block height when
    /// events will first be extracted from.
    eth_start_height: &'static str,
    /// Sub-key for storing the active / inactive status of the Ethereum
    /// bridge.
    active_status: &'static str,
    /// Sub-key for storing the minimum confirmations parameter
    min_confirmations: &'static str,
    /// Sub-key for storing the Ethereum address for wNam.
    native_erc20: &'static str,
    /// Sub-lkey for storing the Ethereum address of the bridge contract.
    bridge_contract_address: &'static str,
    // ========================================
    // Core parameters
    // ========================================
    epoch_duration: &'static str,
    epochs_per_year: &'static str,
    masp_epoch_multiplier: &'static str,
    implicit_vp: &'static str,
    tx_allowlist: &'static str,
    vp_allowlist: &'static str,
    max_proposal_bytes: &'static str,
    max_tx_bytes: &'static str,
    max_block_gas: &'static str,
    minimum_gas_price: &'static str,
    masp_fee_payment_gas_limit: &'static str,
    gas_scale: &'static str,
    native_token_transferable: &'static str,
    masp_over_ibc_fees: &'static str,
}

/// Returns if the key is a parameter key.
pub fn is_parameter_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &ADDRESS)
}

/// Returns if the key is a protocol parameter key.
pub fn is_protocol_parameter_key(key: &Key) -> bool {
    let segment = match &key.segments[..] {
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(segment)]
            if addr == &ADDRESS =>
        {
            segment.as_str()
        }
        _ => return false,
    };
    Keys::ALL.binary_search(&segment).is_ok()
}

/// Returns if the key is an epoch storage key.
pub fn is_epoch_duration_storage_key(key: &Key) -> bool {
    is_epoch_duration_key_at_addr(key, &ADDRESS)
}

/// Returns if the key is the tx_allowlist key.
pub fn is_tx_allowlist_key(key: &Key) -> bool {
    is_tx_allowlist_key_at_addr(key, &ADDRESS)
}

/// Returns if the key is the vp_allowlist key.
pub fn is_vp_allowlist_key(key: &Key) -> bool {
    is_vp_allowlist_key_at_addr(key, &ADDRESS)
}

/// Returns if the key is the implicit VP key.
pub fn is_implicit_vp_key(key: &Key) -> bool {
    is_implicit_vp_key_at_addr(key, &ADDRESS)
}

/// Returns if the key is the epoch_per_year key.
pub fn is_epochs_per_year_key(key: &Key) -> bool {
    is_epochs_per_year_key_at_addr(key, &ADDRESS)
}

/// Returns if the key is the max proposal bytes key.
pub fn is_max_proposal_bytes_key(key: &Key) -> bool {
    is_max_proposal_bytes_key_at_addr(key, &ADDRESS)
}

/// Returns if the key is the max tx bytes key.
pub fn is_max_tx_bytes_key(key: &Key) -> bool {
    is_max_tx_bytes_key_at_addr(key, &ADDRESS)
}

/// Storage key used for epoch parameter.
pub fn get_epoch_duration_storage_key() -> Key {
    get_epoch_duration_key_at_addr(ADDRESS)
}

/// Storage key used for vp allowlist parameter.
pub fn get_vp_allowlist_storage_key() -> Key {
    get_vp_allowlist_key_at_addr(ADDRESS)
}

/// Storage key used for tx allowlist parameter.
pub fn get_tx_allowlist_storage_key() -> Key {
    get_tx_allowlist_key_at_addr(ADDRESS)
}

/// Storage key used for the fee unshielding gas limit
pub fn get_masp_fee_payment_gas_limit_key() -> Key {
    get_masp_fee_payment_gas_limit_key_at_addr(ADDRESS)
}

/// Storage key used for the gas scale
pub fn get_gas_scale_key() -> Key {
    get_gas_scale_key_at_addr(ADDRESS)
}

/// Storage key used for implicit VP parameter.
pub fn get_implicit_vp_key() -> Key {
    get_implicit_vp_key_at_addr(ADDRESS)
}

/// Storage key used for epochs_per_year parameter.
pub fn get_epochs_per_year_key() -> Key {
    get_epochs_per_year_key_at_addr(ADDRESS)
}

/// Storage key used for masp_epoch_multiplier parameter.
pub fn get_masp_epoch_multiplier_key() -> Key {
    get_masp_epoch_multiplier_key_at_addr(ADDRESS)
}

/// Storage key used for the max proposal bytes.
pub fn get_max_proposal_bytes_key() -> Key {
    get_max_proposal_bytes_key_at_addr(ADDRESS)
}

/// Storage key used for the max tx bytes.
pub fn get_max_tx_bytes_key() -> Key {
    get_max_tx_bytes_key_at_addr(ADDRESS)
}

/// Storage key used for the max block gas.
pub fn get_max_block_gas_key() -> Key {
    get_max_block_gas_key_at_addr(ADDRESS)
}

/// Storage key used for the gas cost table
pub fn get_gas_cost_key() -> Key {
    get_minimum_gas_price_key_at_addr(ADDRESS)
}

/// Helper function to retrieve the `max_block_gas` protocol parameter from
/// storage
pub fn get_max_block_gas(storage: &impl StorageRead) -> Result<u64> {
    storage
        .read(&get_max_block_gas_key())?
        .ok_or(Error::SimpleMessage(
            "Missing max_block_gas parameter from storage",
        ))
}

/// Helper function to retrieve the `gas_scale` protocol parameter from
/// storage
pub fn get_gas_scale(storage: &impl StorageRead) -> Result<u64> {
    storage
        .read(&get_gas_scale_key())?
        .ok_or(Error::SimpleMessage(
            "Missing gas_scale parameter from storage",
        ))
}

/// Storage key used for the flag to enable the native token transfer
pub fn get_native_token_transferable_key() -> Key {
    get_native_token_transferable_key_at_addr(ADDRESS)
}

/// Helper function to retrieve the `is_native_token_transferable` protocol
/// parameter from storage
pub fn is_native_token_transferable(
    storage: &impl StorageRead,
) -> Result<bool> {
    storage.read(&get_native_token_transferable_key())?.ok_or(
        Error::SimpleMessage(
            "Missing is_native_token_transferable parameter from storage",
        ),
    )
}

/// Storage key used to store the fee percentage associated with IBC shieldings
/// of the token with address `token_addr`.
pub fn get_masp_over_ibc_shielding_fees_of_token_key(
    token_addr: &Address,
) -> Key {
    get_masp_over_ibc_fees_key_at_addr(ADDRESS)
        .with_segment("shieldings".to_owned())
        .with_segment(token_addr.clone())
}

/// Storage key used to store the fee percentage associated with IBC
/// unshieldings of the token with address `token_addr`.
pub fn get_masp_over_ibc_unshielding_fees_of_token_key(
    token_addr: &Address,
) -> Key {
    get_masp_over_ibc_fees_key_at_addr(ADDRESS)
        .with_segment("unshieldings".to_owned())
        .with_segment(token_addr.clone())
}

/// Get the shielding fee percentage over IBC of the token with address
/// `token_addr`.
pub fn read_masp_over_ibc_shielding_fee(
    storage: &impl StorageRead,
    token_addr: &Address,
) -> Result<Option<Dec>> {
    storage.read(&get_masp_over_ibc_shielding_fees_of_token_key(token_addr))
}

/// Get the unshielding fee percentage over IBC of the token with address
/// `token_addr`.
pub fn read_masp_over_ibc_unshielding_fee(
    storage: &impl StorageRead,
    token_addr: &Address,
) -> Result<Option<Dec>> {
    storage.read(&get_masp_over_ibc_unshielding_fees_of_token_key(token_addr))
}
