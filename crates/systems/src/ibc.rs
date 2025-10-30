//! IBC abstract interfaces

use std::collections::{BTreeMap, BTreeSet};

use masp_primitives::transaction::TransparentAddress;
use masp_primitives::transaction::components::ValueSum;
use namada_core::address::Address;
use namada_core::borsh::BorshDeserialize;
use namada_core::masp::TAddrData;
use namada_core::{masp_primitives, storage, token};
pub use namada_storage::Result;

/// Abstract IBC storage read interface
pub trait Read<S> {
    /// Extract MASP transaction from IBC envelope
    fn try_extract_masp_tx_from_envelope<Transfer: BorshDeserialize>(
        tx_data: &[u8],
    ) -> Option<masp_primitives::transaction::Transaction>;

    /// Apply relevant IBC packets to the changed balances structure
    fn apply_ibc_packet<Transfer: BorshDeserialize>(
        storage: &S,
        tx_data: &[u8],
        acc: ChangedBalances,
        keys_changed: &BTreeSet<storage::Key>,
    ) -> Result<ChangedBalances>;
}

/// Balances changed by a transaction
#[derive(Default, Debug, Clone)]
pub struct ChangedBalances {
    /// Map between MASP transparent address and Namada types
    pub decoder: BTreeMap<TransparentAddress, TAddrData>,
    /// Balances before the tx
    pub pre: BTreeMap<TransparentAddress, ValueSum<Address, token::Amount>>,
    /// Balances after the tx
    pub post: BTreeMap<TransparentAddress, ValueSum<Address, token::Amount>>,
}
