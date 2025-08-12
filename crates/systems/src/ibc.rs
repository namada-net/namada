//! IBC abstract interfaces

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::transaction::TransparentAddress;
use masp_primitives::transaction::components::ValueSum;
use namada_core::address::Address;
use namada_core::borsh::BorshSerializeExt;
use namada_core::bytes::HEXUPPER;
use namada_core::key::common;
use namada_core::masp::{MaspTransaction, TAddrData};
use namada_core::{masp_primitives, storage, token};
pub use namada_storage::Result;
use namada_tx::{Authorization, Signer};

/// Shielding data in IBC packet memo
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct IbcShieldingData {
    /// The MASP transaction that does the shielding
    pub masp_tx: MaspTransaction,
    /// The account that will pay the shielding fee
    pub shielding_fee_authorization: Authorization,
    /// The token that the shielding fee will be paid in
    pub shielding_fee_token: Address,
}

impl IbcShieldingData {
    /// Get the public key of the account that is paying the shielding fee
    pub fn get_signer(&self) -> Option<&common::PublicKey> {
        match &self.shielding_fee_authorization.signer {
            Signer::Address(_) => None,
            Signer::PubKeys(pks) => pks.first(),
        }
    }
}

impl From<&IbcShieldingData> for String {
    fn from(data: &IbcShieldingData) -> Self {
        HEXUPPER.encode(&data.serialize_to_vec())
    }
}

impl From<IbcShieldingData> for String {
    fn from(data: IbcShieldingData) -> Self {
        (&data).into()
    }
}

impl fmt::Display for IbcShieldingData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from(self))
    }
}

impl FromStr for IbcShieldingData {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let bytes = HEXUPPER
            .decode(s.as_bytes())
            .map_err(|err| err.to_string())?;
        IbcShieldingData::try_from_slice(&bytes).map_err(|err| err.to_string())
    }
}

/// Abstract IBC storage read interface
pub trait Read<S> {
    /// Extract MASP transaction from IBC envelope
    fn try_extract_masp_tx_from_envelope<Transfer: BorshDeserialize>(
        tx_data: &[u8],
    ) -> Result<Option<IbcShieldingData>>;

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
