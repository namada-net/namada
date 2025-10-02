//! IBC abstract interfaces

use std::collections::{BTreeMap, BTreeSet};

use masp_primitives::transaction::TransparentAddress;
use masp_primitives::transaction::components::ValueSum;
use namada_core::address::Address;
use namada_core::borsh::BorshDeserialize;
use namada_core::masp::{MaspTxData, TAddrData};
use namada_core::{masp_primitives, storage, token};
pub use namada_storage::Result;
use namada_storage::StorageRead;

use crate::parameters;

/// Abstract IBC storage read interface
pub trait Read<S> {
    /// The extracted MASP tx type
    type ExtractedMaspTx: MaspTxData;

    /// Extract MASP transaction from IBC envelope
    fn try_extract_masp_tx_from_envelope<Transfer, Params, R>(
        ctx: &R,
        tx_data: &[u8],
    ) -> Result<Option<Self::ExtractedMaspTx>>
    where
        Transfer: BorshDeserialize,
        Params: parameters::Read<R>,
        R: StorageRead;

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
