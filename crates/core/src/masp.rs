//! MASP types

use std::collections::BTreeMap;
use std::fmt::Display;
use std::num::ParseIntError;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use masp_primitives::asset_type::AssetType;
use masp_primitives::consensus::BranchId;
#[cfg(feature = "rand")]
use masp_primitives::sapling::Rseed;
use masp_primitives::sapling::{Node, Note, Nullifier, ViewingKey};
use masp_primitives::transaction::components::sapling::{
    Authorized, GrothProofBytes,
};
use masp_primitives::transaction::components::{
    ConvertDescription, I128Sum, OutputDescription, SpendDescription, TxIn,
    TxOut, sapling, transparent,
};
use masp_primitives::transaction::{
    Transaction, TransactionData, TransparentAddress, TxId, TxVersion,
};
pub use masp_primitives::transaction::{
    Transaction as MaspTransaction, TxId as TxIdInner,
};
use masp_primitives::zip32::{ExtendedKey, PseudoExtendedKey};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
#[cfg(feature = "rand")]
use rand_core::{CryptoRng, RngCore};
use ripemd::Digest as RipemdDigest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;

use crate::address::{Address, DecodeError, HASH_HEX_LEN, IBC, MASP};
use crate::borsh::BorshSerializeExt;
use crate::chain::{BlockHeight, Epoch};
use crate::impl_display_and_from_str_via_format;
use crate::masp_primitives::transaction::components::transparent::Authorized as TAuthorized;
use crate::string_encoding::{
    self, MASP_EXT_FULL_VIEWING_KEY_HRP, MASP_EXT_SPENDING_KEY_HRP,
    MASP_PAYMENT_ADDRESS_HRP,
};
use crate::token::{Denomination, MaspDigitPos, NATIVE_MAX_DECIMAL_PLACES};

/// Serialize the given TxId
pub fn serialize_txid<S>(txid: &TxIdInner, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(txid.as_ref())
}

/// Deserialize the given TxId
pub fn deserialize_txid<'de, D>(deserializer: D) -> Result<TxIdInner, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(TxIdInner::from_bytes(Deserialize::deserialize(
        deserializer,
    )?))
}

/// Wrapper for masp_primitive's TxId
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Serialize,
    Deserialize,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Debug,
    Eq,
    PartialEq,
    Copy,
    Ord,
    PartialOrd,
    Hash,
)]
pub struct MaspTxId(
    #[serde(
        serialize_with = "serialize_txid",
        deserialize_with = "deserialize_txid"
    )]
    pub TxIdInner,
);

impl From<TxIdInner> for MaspTxId {
    fn from(txid: TxIdInner) -> Self {
        Self(txid)
    }
}

impl Display for MaspTxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Wrapper type around `Epoch` for type safe operations involving the masp
/// epoch
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Clone,
    Copy,
    Debug,
    Default,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct MaspEpoch(Epoch);

impl Display for MaspEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for MaspEpoch {
    type Err = ParseIntError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let inner: Epoch = Epoch::from_str(s)?;
        Ok(Self(inner))
    }
}

impl MaspEpoch {
    /// Converts and `Epoch` into a `MaspEpoch` based on the provided conversion
    /// rate
    pub fn try_from_epoch(
        epoch: Epoch,
        masp_epoch_multiplier: u64,
    ) -> Result<Self, &'static str> {
        Ok(Self(
            epoch
                .checked_div(masp_epoch_multiplier)
                .ok_or("Masp epoch multiplier cannot be 0")?,
        ))
    }

    /// Iterate a range of epochs, inclusive of the start and end.
    pub fn iter_bounds_inclusive(
        start: Self,
        end: Self,
    ) -> impl DoubleEndedIterator<Item = Self> + Clone {
        Epoch::iter_bounds_inclusive(start.0, end.0).map(Self)
    }

    /// Returns a 0 masp epoch
    pub const fn zero() -> Self {
        Self(Epoch(0))
    }

    /// Change to the previous masp epoch.
    pub fn prev(&self) -> Option<Self> {
        Some(Self(self.0.checked_sub(1)?))
    }

    /// Change to the next masp epoch.
    pub fn next(&self) -> Option<Self> {
        Some(Self(self.0.checked_add(1)?))
    }

    /// Initialize a new masp epoch from the provided one
    #[cfg(any(test, feature = "testing"))]
    pub const fn new(epoch: u64) -> Self {
        Self(Epoch(epoch))
    }
}

/// The plain representation of a MASP aaset
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Clone,
    Debug,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct AssetData {
    /// The token associated with this asset type
    pub token: Address,
    /// The denomination associated with the above toke
    pub denom: Denomination,
    /// The digit position covered by this asset type
    pub position: MaspDigitPos,
    /// The epoch of the asset type, if any
    pub epoch: Option<MaspEpoch>,
}

impl AssetData {
    /// Make asset type corresponding to given address and epoch
    pub fn encode(&self) -> Result<AssetType, std::io::Error> {
        // Timestamp the chosen token with the current epoch
        let token_bytes = self.serialize_to_vec();
        // Generate the unique asset identifier from the unique token address
        AssetType::new(token_bytes.as_ref()).map_err(|_| {
            std::io::Error::other("unable to create asset type".to_string())
        })
    }

    /// Give this pre-asset type the given epoch if already has an epoch. Return
    /// the replaced value.
    pub fn redate(self, to: MaspEpoch) -> Self {
        if self.epoch.is_some() {
            Self {
                epoch: Some(to),
                ..self
            }
        } else {
            self
        }
    }

    /// Update the MaspEpoch to the next one
    pub fn redate_to_next_epoch(self) -> Self {
        if let Some(next) = self.epoch.as_ref().and_then(MaspEpoch::next) {
            Self {
                epoch: Some(next),
                ..self
            }
        } else {
            self
        }
    }

    /// Remove the epoch associated with this pre-asset type
    pub fn undate(self) -> Self {
        Self {
            epoch: None,
            ..self
        }
    }
}

/// Make asset type corresponding to given address and epoch
pub fn encode_asset_type(
    token: Address,
    denom: Denomination,
    position: MaspDigitPos,
    epoch: Option<MaspEpoch>,
) -> Result<AssetType, std::io::Error> {
    AssetData {
        token,
        denom,
        position,
        epoch,
    }
    .encode()
}

/// Encode the assets that are used for masp rewards. The address supplied to
/// this function must be that of the native token.
pub fn encode_reward_asset_types(
    native_token: &Address,
) -> Result<[AssetType; 4], std::io::Error> {
    // Construct MASP asset type for rewards. Always deflate and timestamp
    // reward tokens with the zeroth epoch to minimize the number of convert
    // notes clients have to use. This trick works under the assumption that
    // reward tokens will then be reinflated back to the current epoch.
    Ok([
        encode_asset_type(
            native_token.clone(),
            NATIVE_MAX_DECIMAL_PLACES.into(),
            MaspDigitPos::Zero,
            Some(MaspEpoch::zero()),
        )?,
        encode_asset_type(
            native_token.clone(),
            NATIVE_MAX_DECIMAL_PLACES.into(),
            MaspDigitPos::One,
            Some(MaspEpoch::zero()),
        )?,
        encode_asset_type(
            native_token.clone(),
            NATIVE_MAX_DECIMAL_PLACES.into(),
            MaspDigitPos::Two,
            Some(MaspEpoch::zero()),
        )?,
        encode_asset_type(
            native_token.clone(),
            NATIVE_MAX_DECIMAL_PLACES.into(),
            MaspDigitPos::Three,
            Some(MaspEpoch::zero()),
        )?,
    ])
}

/// MASP token map
pub type TokenMap = BTreeMap<String, Address>;

/// MASP token precision
pub type Precision = u128;

// enough capacity to store the payment address
const PAYMENT_ADDRESS_SIZE: usize = 43;

/// Wrapper for masp_primitive's DiversifierIndex
#[derive(Clone, Debug, Copy, Eq, PartialEq, Default)]
pub struct DiversifierIndex(masp_primitives::zip32::DiversifierIndex);

impl From<masp_primitives::zip32::DiversifierIndex> for DiversifierIndex {
    fn from(idx: masp_primitives::zip32::DiversifierIndex) -> Self {
        Self(idx)
    }
}

impl From<DiversifierIndex> for masp_primitives::zip32::DiversifierIndex {
    fn from(value: DiversifierIndex) -> Self {
        value.0
    }
}

impl TryFrom<u128> for DiversifierIndex {
    type Error = std::num::TryFromIntError;

    fn try_from(idx: u128) -> Result<DiversifierIndex, Self::Error> {
        // Diversifier is supposed to be 11 bytes. So right-shifting it by 3
        // bytes should yield a 64-bit integer.
        u64::try_from(idx >> 24)?;
        let mut result = [0; 11];
        result[..11].copy_from_slice(&idx.to_le_bytes()[0..11]);
        Ok(masp_primitives::zip32::DiversifierIndex(result).into())
    }
}

impl From<DiversifierIndex> for u128 {
    fn from(div: DiversifierIndex) -> Self {
        let mut u128_bytes = [0u8; 16];
        u128_bytes[0..11].copy_from_slice(&div.0.0[..]);
        u128::from_le_bytes(u128_bytes)
    }
}

/// The describing a failure to parse a diversifier index
#[derive(Clone, Debug, Copy, Default)]
pub struct ParseDiversifierError;

impl std::fmt::Display for ParseDiversifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        "unable to parse diversifier index".fmt(f)
    }
}

impl FromStr for DiversifierIndex {
    type Err = ParseDiversifierError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        u128::from_str(s)
            .map_err(|_| ParseDiversifierError)?
            .try_into()
            .map_err(|_| ParseDiversifierError)
    }
}

impl Display for DiversifierIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        u128::from(*self).fmt(f)
    }
}

impl serde::Serialize for DiversifierIndex {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(&self.to_string(), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DiversifierIndex {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        Self::from_str(&encoded).map_err(D::Error::custom)
    }
}

/// Wrapper for masp_primitive's FullViewingKey
#[derive(
    Clone,
    Debug,
    Copy,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
)]
pub struct ExtendedViewingKey(masp_primitives::zip32::ExtendedFullViewingKey);

impl ExtendedViewingKey {
    /// Encode `Self` to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0; 169];
        self.0
            .write(&mut bytes[..])
            .expect("should be able to serialize an ExtendedFullViewingKey");
        bytes.to_vec()
    }

    /// Try to decode `Self` from bytes
    pub fn decode_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        masp_primitives::zip32::ExtendedFullViewingKey::read(&mut &bytes[..])
            .map(Self)
    }

    /// Get the underlying viewing key
    pub fn as_viewing_key(&self) -> ViewingKey {
        self.0.fvk.vk
    }
}

impl string_encoding::Format for ExtendedViewingKey {
    type EncodedBytes<'a> = Vec<u8>;

    const HRP: string_encoding::Hrp =
        string_encoding::Hrp::parse_unchecked(MASP_EXT_FULL_VIEWING_KEY_HRP);

    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }

    fn decode_bytes(
        bytes: &[u8],
    ) -> Result<Self, string_encoding::DecodeError> {
        Self::decode_bytes(bytes).map_err(DecodeError::InvalidBytes)
    }
}

impl_display_and_from_str_via_format!(ExtendedViewingKey);

impl string_encoding::Format for PaymentAddress {
    type EncodedBytes<'a> = Vec<u8>;

    const HRP: string_encoding::Hrp =
        string_encoding::Hrp::parse_unchecked(MASP_PAYMENT_ADDRESS_HRP);

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PAYMENT_ADDRESS_SIZE);
        bytes.extend_from_slice(self.0.to_bytes().as_slice());
        bytes
    }

    fn decode_bytes(
        bytes: &[u8],
    ) -> Result<Self, string_encoding::DecodeError> {
        if bytes.len() != PAYMENT_ADDRESS_SIZE {
            return Err(DecodeError::InvalidInnerEncoding(format!(
                "expected {PAYMENT_ADDRESS_SIZE} bytes for the payment address"
            )));
        }
        let payment_addr =
            masp_primitives::sapling::PaymentAddress::from_bytes(&{
                let mut payment_addr = [0u8; PAYMENT_ADDRESS_SIZE];
                payment_addr.copy_from_slice(&bytes[0..]);
                payment_addr
            })
            .ok_or_else(|| {
                DecodeError::InvalidInnerEncoding(
                    "invalid payment address provided".to_string(),
                )
            })?;
        Ok(Self(payment_addr))
    }
}

impl_display_and_from_str_via_format!(PaymentAddress);

impl From<ExtendedViewingKey>
    for masp_primitives::zip32::ExtendedFullViewingKey
{
    fn from(key: ExtendedViewingKey) -> Self {
        key.0
    }
}

impl From<masp_primitives::zip32::ExtendedFullViewingKey>
    for ExtendedViewingKey
{
    fn from(key: masp_primitives::zip32::ExtendedFullViewingKey) -> Self {
        Self(key)
    }
}

impl From<ExtendedViewingKey> for masp_primitives::sapling::ViewingKey {
    fn from(value: ExtendedViewingKey) -> Self {
        let fvk = masp_primitives::zip32::ExtendedFullViewingKey::from(value);
        fvk.fvk.vk
    }
}

impl serde::Serialize for ExtendedViewingKey {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.to_string();
        serde::Serialize::serialize(&encoded, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ExtendedViewingKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        Self::from_str(&encoded).map_err(D::Error::custom)
    }
}

/// Wrapper for masp_primitive's PaymentAddress
#[derive(
    Clone,
    Debug,
    Copy,
    PartialOrd,
    Ord,
    Eq,
    PartialEq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct PaymentAddress(masp_primitives::sapling::PaymentAddress);

impl PaymentAddress {
    /// Hash this payment address
    pub fn hash(&self) -> String {
        let bytes = self.0.serialize_to_vec();
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        // hex of the first 40 chars of the hash
        format!("{:.width$X}", hasher.finalize(), width = HASH_HEX_LEN)
    }

    /// Encode a payment address in compatibility mode (i.e. with the legacy
    /// Bech32 encoding)
    pub fn encode_compat(&self) -> String {
        use crate::string_encoding::Format;

        bech32::encode::<bech32::Bech32>(Self::HRP, self.to_bytes().as_ref())
            .unwrap_or_else(|_| {
                panic!(
                    "The human-readable part {} should never cause a failure",
                    Self::HRP
                )
            })
    }

    /// Create a note owned by this payment address
    #[cfg(feature = "rand")]
    pub fn create_note<RNG>(
        &self,
        asset_type: AssetType,
        value: u64,
        csprng: &mut RNG,
    ) -> Option<masp_primitives::sapling::Note>
    where
        RNG: CryptoRng + RngCore,
    {
        self.0.create_note(
            asset_type,
            value,
            Rseed::AfterZip212({
                let mut buf = [0u8; 32];
                csprng.fill_bytes(&mut buf);
                buf
            }),
        )
    }
}

impl From<PaymentAddress> for masp_primitives::sapling::PaymentAddress {
    fn from(addr: PaymentAddress) -> Self {
        addr.0
    }
}

impl From<masp_primitives::sapling::PaymentAddress> for PaymentAddress {
    fn from(addr: masp_primitives::sapling::PaymentAddress) -> Self {
        Self(addr)
    }
}

impl serde::Serialize for PaymentAddress {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.to_string();
        serde::Serialize::serialize(&encoded, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for PaymentAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        Self::from_str(&encoded).map_err(D::Error::custom)
    }
}

/// Wrapper for masp_primitive's ExtendedSpendingKey
#[derive(
    Clone,
    Debug,
    Copy,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Hash,
    Eq,
    PartialEq,
)]
pub struct ExtendedSpendingKey(masp_primitives::zip32::ExtendedSpendingKey);

impl string_encoding::Format for ExtendedSpendingKey {
    type EncodedBytes<'a> = Vec<u8>;

    const HRP: string_encoding::Hrp =
        string_encoding::Hrp::parse_unchecked(MASP_EXT_SPENDING_KEY_HRP);

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0; 169];
        self.0
            .write(&mut &mut bytes[..])
            .expect("should be able to serialize an ExtendedSpendingKey");
        bytes.to_vec()
    }

    fn decode_bytes(
        bytes: &[u8],
    ) -> Result<Self, string_encoding::DecodeError> {
        masp_primitives::zip32::ExtendedSpendingKey::read(&mut &bytes[..])
            .map_err(|op| DecodeError::InvalidInnerEncoding(op.to_string()))
            .map(Self)
    }
}

impl_display_and_from_str_via_format!(ExtendedSpendingKey);

impl ExtendedSpendingKey {
    /// Derive a viewing key
    pub fn to_viewing_key(&self) -> ExtendedViewingKey {
        ExtendedViewingKey::from(
            #[allow(deprecated)]
            {
                self.0.to_extended_full_viewing_key()
            },
        )
    }
}

impl From<ExtendedSpendingKey> for masp_primitives::zip32::ExtendedSpendingKey {
    fn from(key: ExtendedSpendingKey) -> Self {
        key.0
    }
}

impl From<masp_primitives::zip32::ExtendedSpendingKey> for ExtendedSpendingKey {
    fn from(key: masp_primitives::zip32::ExtendedSpendingKey) -> Self {
        Self(key)
    }
}

impl serde::Serialize for ExtendedSpendingKey {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.to_string();
        serde::Serialize::serialize(&encoded, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ExtendedSpendingKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        Self::from_str(&encoded).map_err(D::Error::custom)
    }
}

/// Represents a source of funds for a transfer
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum TransferSource {
    /// A transfer coming from a transparent address
    Address(Address),
    /// A transfer coming from a shielded address
    ExtendedKey(PseudoExtendedKey),
}

impl TransferSource {
    /// Get the transparent address that this source would effectively draw from
    pub fn effective_address(&self) -> Address {
        match self {
            Self::Address(x) => x.clone(),
            // An ExtendedSpendingKey for a source effectively means that
            // assets will be drawn from the MASP
            Self::ExtendedKey(_) => MASP,
        }
    }

    /// Get the contained extended key, if any
    pub fn spending_key(&self) -> Option<PseudoExtendedKey> {
        match self {
            Self::ExtendedKey(x) => Some(*x),
            _ => None,
        }
    }

    /// Get the contained extended key, if any
    pub fn spending_key_mut(&mut self) -> Option<&mut PseudoExtendedKey> {
        match self {
            Self::ExtendedKey(x) => Some(x),
            _ => None,
        }
    }

    /// Get the contained transparent address, if any
    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Address(x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Get the contained transparent address data, if any
    pub fn t_addr_data(&self) -> Option<TAddrData> {
        match self {
            Self::Address(x) => Some(TAddrData::Addr(x.clone())),
            _ => None,
        }
    }
}

impl Display for TransferSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(x) => x.fmt(f),
            Self::ExtendedKey(x) => {
                ExtendedViewingKey::from(x.to_viewing_key()).fmt(f)
            }
        }
    }
}

/// Represents the pre-image to a TransparentAddress
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    BorshDeserialize,
    BorshSerialize,
    BorshDeserializer,
)]
pub enum TAddrData {
    /// A transparent address within Namada
    Addr(Address),
    /// An IBC address
    Ibc(String),
}

impl TAddrData {
    /// Get the transparent address that this target would effectively go to
    pub fn effective_address(&self) -> Address {
        match self {
            Self::Addr(x) => x.clone(),
            // An IBC signer address effectively means that assets are
            // associated with the IBC internal address
            Self::Ibc(_) => IBC,
        }
    }

    /// Get the contained IBC receiver, if any
    pub fn ibc_receiver_address(&self) -> Option<String> {
        match self {
            Self::Ibc(address) => Some(address.clone()),
            _ => None,
        }
    }

    /// Get the contained Address, if any
    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Addr(x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Convert transparent address data into a transparent address
    pub fn taddress(&self) -> TransparentAddress {
        TransparentAddress(<[u8; 20]>::from(ripemd::Ripemd160::digest(
            sha2::Sha256::digest(self.serialize_to_vec()),
        )))
    }
}

/// Convert a receiver string to a TransparentAddress
pub fn ibc_taddr(receiver: String) -> TransparentAddress {
    TAddrData::Ibc(receiver).taddress()
}

/// Convert a Namada Address to a TransparentAddress
pub fn addr_taddr(addr: Address) -> TransparentAddress {
    TAddrData::Addr(addr).taddress()
}

/// Represents a target for the funds of a transfer
#[derive(
    Debug,
    Clone,
    BorshDeserialize,
    BorshSerialize,
    BorshDeserializer,
    Hash,
    Eq,
    PartialEq,
)]
pub enum TransferTarget {
    /// A transfer going to a transparent address
    Address(Address),
    /// A transfer going to a shielded address
    PaymentAddress(PaymentAddress),
    /// A transfer going to an IBC address
    Ibc(String),
}

impl TransferTarget {
    /// Get the transparent address that this target would effectively go to
    pub fn effective_address(&self) -> Address {
        match self {
            Self::Address(x) => x.clone(),
            // A PaymentAddress for a target effectively means that assets will
            // be sent to the MASP
            Self::PaymentAddress(_) => MASP,
            // An IBC signer address for a target effectively means that assets
            // will be sent to the IBC internal address
            Self::Ibc(_) => IBC,
        }
    }

    /// Get the contained PaymentAddress, if any
    pub fn payment_address(&self) -> Option<PaymentAddress> {
        match self {
            Self::PaymentAddress(address) => Some(*address),
            _ => None,
        }
    }

    /// Get the contained Address, if any
    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Address(x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Get the contained TAddrData, if any
    pub fn t_addr_data(&self) -> Option<TAddrData> {
        match self {
            Self::Address(x) => Some(TAddrData::Addr(x.clone())),
            Self::Ibc(x) => Some(TAddrData::Ibc(x.clone())),
            _ => None,
        }
    }
}

impl Display for TransferTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(x) => x.fmt(f),
            Self::PaymentAddress(address) => address.fmt(f),
            Self::Ibc(x) => x.fmt(f),
        }
    }
}

/// Represents the owner of arbitrary funds
#[allow(clippy::large_enum_variant)]
#[derive(
    Debug,
    Clone,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub enum BalanceOwner {
    /// A balance stored at a transparent address
    Address(Address),
    /// A balance stored at a shielded address
    FullViewingKey(ExtendedViewingKey),
}

impl BalanceOwner {
    /// Get the contained Address, if any
    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Address(x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Get the contained FullViewingKey, if any
    pub fn full_viewing_key(&self) -> Option<ExtendedViewingKey> {
        match self {
            Self::FullViewingKey(x) => Some(*x),
            _ => None,
        }
    }
}

impl Display for BalanceOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BalanceOwner::Address(addr) => addr.fmt(f),
            BalanceOwner::FullViewingKey(fvk) => fvk.fmt(f),
        }
    }
}

/// Represents any MASP value
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum MaspValue {
    /// A MASP PaymentAddress
    PaymentAddress(PaymentAddress),
    /// A MASP ExtendedSpendingKey
    ExtendedSpendingKey(ExtendedSpendingKey),
    /// A MASP FullViewingKey
    FullViewingKey(ExtendedViewingKey),
}

impl FromStr for MaspValue {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try to decode this value first as a PaymentAddress, then as an
        // ExtendedSpendingKey, then as FullViewingKey
        PaymentAddress::from_str(s)
            .map(Self::PaymentAddress)
            .or_else(|_err| {
                ExtendedSpendingKey::from_str(s).map(Self::ExtendedSpendingKey)
            })
            .or_else(|_err| {
                ExtendedViewingKey::from_str(s).map(Self::FullViewingKey)
            })
    }
}

/// A set of shared behaviors for types representing
/// a MASP change
pub trait MaspTxData: BorshSerialize + BorshDeserialize {
    /// The amounts in the Masp transaction
    fn value_balance(&self) -> I128Sum;

    /// A list of nullifiers corresponding to notes spent by this tx
    fn nullifiers(&self) -> Vec<Nullifier> {
        self.shielded_spends()
            .iter()
            .map(|ss| ss.nullifier)
            .collect()
    }

    /// Commitments to the notes in this transaction
    fn note_commitments(&self) -> Option<Vec<Node>>;

    /// Check if this data is expired
    fn is_expired(&self, current_height: BlockHeight) -> bool;

    /// Get the spend descriptions
    fn shielded_spends(&self) -> Vec<SpendDescription<Authorized>>;

    /// Get the used conversions
    fn shielded_converts(&self) -> Vec<ConvertDescription<GrothProofBytes>>;

    /// Get the shielded outputs
    fn shielded_outputs(&self) -> Vec<OutputDescription<GrothProofBytes>>;

    /// Get the transparent inputs
    fn transparent_inputs(&self) -> Vec<TxIn<TAuthorized>>;

    /// Get the transparent outputs
    fn transparent_outputs(&self) -> Vec<TxOut>;

    /// Get a full MASP tx for verifying if applicable
    fn verifiable_tx(&self) -> Option<&Transaction>;
}

impl MaspTxData for Transaction {
    fn value_balance(&self) -> I128Sum {
        self.sapling_value_balance()
    }

    fn note_commitments(&self) -> Option<Vec<Node>> {
        self.sapling_bundle().map(|bundle| {
            bundle
                .shielded_outputs
                .iter()
                .map(|d| Node::from_scalar(d.cmu))
                .collect()
        })
    }

    fn is_expired(&self, current_height: BlockHeight) -> bool {
        u64::from(current_height) > u64::from(self.expiry_height())
    }

    fn shielded_spends(&self) -> Vec<SpendDescription<Authorized>> {
        self.sapling_bundle()
            .map(|bundle| bundle.shielded_spends.clone())
            .unwrap_or_default()
    }

    fn shielded_converts(&self) -> Vec<ConvertDescription<GrothProofBytes>> {
        self.sapling_bundle()
            .map(|bundle| bundle.shielded_converts.clone())
            .unwrap_or_default()
    }

    fn shielded_outputs(&self) -> Vec<OutputDescription<GrothProofBytes>> {
        self.sapling_bundle()
            .map(|bundle| bundle.shielded_outputs.clone())
            .unwrap_or_default()
    }

    fn transparent_inputs(&self) -> Vec<TxIn<TAuthorized>> {
        self.transparent_bundle()
            .map(|b| b.vin.clone())
            .unwrap_or_default()
    }

    fn transparent_outputs(&self) -> Vec<TxOut> {
        self.transparent_bundle()
            .map(|b| b.vout.clone())
            .unwrap_or_default()
    }

    fn verifiable_tx(&self) -> Option<&Transaction> {
        Some(self)
    }
}

/// There are two ways to contribute to the MASP:
///  1.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
#[allow(clippy::large_enum_variant)]
pub enum ShieldedData {
    ///  A full MASP transaction
    Tx(MaspTransaction),
    /// A newly mined Note
    Note(Vec<Note>),
}

impl ShieldedData {
    /// Converts to a dummy tx. This is not generally safe. It
    /// is primarily intended to support backwards compatability
    /// with MASP indexer and shielded sync APIs.
    pub fn to_dummy_tx(self) -> MaspTransaction {
        MaspTransaction::transaction(TxId::from_bytes([0u8; 32]), {
            let sig = [0u8; 64];
            TransactionData::from_parts(
                    TxVersion::MASPv5,
                    BranchId::MASP,
                    0,
                    0.into(),
                    Some(transparent::Bundle {
                        vin: self.transparent_inputs(),
                        vout: vec![],
                        authorization: transparent::Authorized,
                    }),
                    Some(sapling::Bundle{
                        shielded_spends: vec![],
                        shielded_converts: vec![],
                        shielded_outputs: self.shielded_outputs(),
                        value_balance: self.value_balance(),
                        authorization: Authorized{binding_sig: masp_primitives::sapling::redjubjub::Signature::read(&mut sig.as_slice()).unwrap()},
                    })
                )
        })
    }

    /// A method to deserialize bytes for either an instance of `Self` or
    /// a raw MASP tx.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        MaspTransaction::try_from_slice(bytes)
            .map(Self::Tx)
            .or_else(|_| Self::try_from_slice(bytes))
    }
}

impl MaspTxData for ShieldedData {
    fn value_balance(&self) -> I128Sum {
        match self {
            ShieldedData::Tx(tx) => tx.value_balance(),
            ShieldedData::Note(notes) => notes
                .iter()
                .map(|n| I128Sum::from_pair(n.asset_type, i128::from(n.value)))
                .sum(),
        }
    }

    fn note_commitments(&self) -> Option<Vec<Node>> {
        match self {
            ShieldedData::Tx(tx) => tx.note_commitments(),
            ShieldedData::Note(notes) => {
                Some(notes.iter().map(|n| n.commitment()).collect())
            }
        }
    }

    fn is_expired(&self, current_height: BlockHeight) -> bool {
        match self {
            ShieldedData::Tx(tx) => tx.is_expired(current_height),
            ShieldedData::Note(_) => false,
        }
    }

    fn shielded_spends(&self) -> Vec<SpendDescription<Authorized>> {
        match self {
            ShieldedData::Tx(tx) => tx.shielded_spends(),
            ShieldedData::Note(_) => vec![],
        }
    }

    fn shielded_converts(&self) -> Vec<ConvertDescription<GrothProofBytes>> {
        match self {
            ShieldedData::Tx(tx) => tx.shielded_converts(),
            ShieldedData::Note(_) => vec![],
        }
    }

    /// N.B. This method should not be relied upon. It is used as a shim
    /// for API compatability reasons.
    fn shielded_outputs(&self) -> Vec<OutputDescription<GrothProofBytes>> {
        const GROTH_PROOF_BYTES: usize = 48 + 96 + 48;
        match self {
            ShieldedData::Tx(tx) => tx.shielded_outputs(),
            ShieldedData::Note(notes) => notes
                .iter()
                .map(|n| OutputDescription {
                    cv: Default::default(),
                    cmu: n.cmu(),
                    ephemeral_key: [0u8; 32].into(),
                    enc_ciphertext: [0; 612],
                    out_ciphertext: [0; 80],
                    zkproof: [0u8; GROTH_PROOF_BYTES],
                })
                .collect(),
        }
    }

    fn transparent_inputs(&self) -> Vec<TxIn<TAuthorized>> {
        match self {
            ShieldedData::Tx(tx) => tx.transparent_inputs(),
            ShieldedData::Note(notes) => {
                let script = TransferSource::Address(IBC)
                    .t_addr_data()
                    .unwrap()
                    .taddress();
                notes
                    .iter()
                    .map(|note| TxIn {
                        asset_type: note.asset_type,
                        value: note.value,
                        address: script,
                        transparent_sig: (),
                    })
                    .collect()
            }
        }
    }

    fn transparent_outputs(&self) -> Vec<TxOut> {
        match self {
            ShieldedData::Tx(tx) => tx.transparent_outputs(),
            ShieldedData::Note(_) => vec![],
        }
    }

    fn verifiable_tx(&self) -> Option<&MaspTransaction> {
        match self {
            ShieldedData::Tx(tx) => Some(tx),
            ShieldedData::Note(_) => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::address;

    #[test]
    fn test_extended_spending_key_serialize() {
        let sk = ExtendedSpendingKey::from(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]),
        );
        let serialized = serde_json::to_string(&sk).unwrap();
        let deserialized: ExtendedSpendingKey =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(sk, deserialized);
    }

    #[test]
    fn test_transfer_source_display() {
        let addr = address::testing::established_address_1();
        assert_eq!(addr.to_string(), TransferSource::Address(addr).to_string());

        let sk = masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]);
        assert_eq!(
            ExtendedViewingKey::from(sk.to_viewing_key()).to_string(),
            TransferSource::ExtendedKey(sk.into()).to_string()
        );
    }

    #[test]
    fn test_transfer_source_address() {
        let addr =
            TransferSource::Address(address::testing::established_address_1())
                .address();
        assert_eq!(addr.unwrap(), address::testing::established_address_1());

        let addr = TransferSource::ExtendedKey(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]).into(),
        )
        .address();
        assert!(addr.is_none());
    }

    #[test]
    fn test_transfer_source_t_addr_data() {
        let addr =
            TransferSource::Address(address::testing::established_address_1())
                .t_addr_data();
        assert_eq!(
            addr.unwrap(),
            TAddrData::Addr(address::testing::established_address_1())
        );

        let addr = TransferSource::ExtendedKey(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]).into(),
        )
        .address();
        assert!(addr.is_none());
    }

    #[test]
    fn test_transfer_source_effective_address() {
        let source =
            TransferSource::Address(address::testing::established_address_1());
        assert_eq!(
            source.effective_address(),
            address::testing::established_address_1()
        );

        let sk = masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]);
        let source = TransferSource::ExtendedKey(sk.into());
        assert_eq!(source.effective_address(), MASP);
    }

    #[test]
    fn test_pa_hash() {
        let sk = ExtendedSpendingKey::from(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]),
        );
        let (_diversifier, pa) = sk.0.default_address();
        let pa = PaymentAddress::from(pa);

        assert_eq!(pa.hash(), "F902054A142024BA72998F7AA6D5F7DB1700E489");
    }

    #[test]
    fn test_taddrdata_address() {
        let addr = TAddrData::Addr(address::testing::established_address_1())
            .address();
        assert_eq!(addr.unwrap(), address::testing::established_address_1());

        let addr = TAddrData::Ibc(String::new()).address();
        assert!(addr.is_none());
    }

    #[test]
    fn test_taddrdata_ibc_receiver_address() {
        let addr = TAddrData::Addr(address::testing::established_address_1())
            .ibc_receiver_address();
        assert!(addr.is_none());

        let addr = TAddrData::Ibc("test".to_owned()).ibc_receiver_address();
        assert_eq!(addr.unwrap(), "test");
    }

    #[test]
    fn test_taddrdata_effective_address() {
        let data = TAddrData::Addr(address::testing::established_address_1());
        assert_eq!(
            data.effective_address(),
            address::testing::established_address_1()
        );

        let data = TAddrData::Ibc(String::new());
        assert_eq!(data.effective_address(), IBC);
    }

    #[test]
    fn test_transfer_target_effective_address() {
        let target =
            TransferTarget::Address(address::testing::established_address_1());
        assert_eq!(
            target.effective_address(),
            address::testing::established_address_1()
        );

        let sk = ExtendedSpendingKey::from(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]),
        );
        let (_diversifier, pa) = sk.0.default_address();
        let pa = PaymentAddress::from(pa);
        let target = TransferTarget::PaymentAddress(pa);
        assert_eq!(target.effective_address(), MASP);

        let target = TransferTarget::Ibc(String::new());
        assert_eq!(target.effective_address(), IBC);
    }

    #[test]
    fn test_transfer_target_address() {
        let target =
            TransferTarget::Address(address::testing::established_address_1())
                .address();
        assert_eq!(target.unwrap(), address::testing::established_address_1());

        let sk = ExtendedSpendingKey::from(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]),
        );
        let (_diversifier, pa) = sk.0.default_address();
        let pa = PaymentAddress::from(pa);
        let target = TransferTarget::PaymentAddress(pa).address();
        assert!(target.is_none());

        let target = TransferTarget::Ibc(String::new()).address();
        assert!(target.is_none());
    }

    #[test]
    fn test_transfer_target_t_addr_data() {
        let target =
            TransferTarget::Address(address::testing::established_address_1())
                .t_addr_data();
        assert_eq!(
            target.unwrap(),
            TAddrData::Addr(address::testing::established_address_1())
        );

        let sk = ExtendedSpendingKey::from(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]),
        );
        let (_diversifier, pa) = sk.0.default_address();
        let pa = PaymentAddress::from(pa);
        let target = TransferTarget::PaymentAddress(pa).t_addr_data();
        assert!(target.is_none());

        let target = TransferTarget::Ibc(String::new()).t_addr_data();
        assert_eq!(target.unwrap(), TAddrData::Ibc(String::new()));
    }

    #[test]
    fn test_transfer_target_display() {
        let addr = address::testing::established_address_1();

        let sk = ExtendedSpendingKey::from(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]),
        );
        let (_diversifier, pa) = sk.0.default_address();
        let pa = PaymentAddress::from(pa);

        const IBC_ADDR: &str = "noble18st0wqx84av8y6xdlss9d6m2nepyqwj6nfxxuv";

        assert_eq!(addr.to_string(), TransferTarget::Address(addr).to_string());

        assert_eq!(
            pa.to_string(),
            TransferTarget::PaymentAddress(pa).to_string()
        );

        assert_eq!(
            IBC_ADDR.to_owned(),
            TransferTarget::Ibc(IBC_ADDR.to_owned()).to_string()
        );
    }

    #[test]
    fn test_balance_owner_full_viewing_key() {
        let sk = ExtendedSpendingKey::from(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]),
        );
        let vk = sk.to_viewing_key();
        assert_eq!(
            vk.clone(),
            BalanceOwner::FullViewingKey(vk).full_viewing_key().unwrap()
        );

        let addr = address::testing::established_address_1();
        assert!(BalanceOwner::Address(addr).full_viewing_key().is_none());
    }

    #[test]
    fn test_balance_owner_display() {
        let addr = address::testing::established_address_1();

        let sk = ExtendedSpendingKey::from(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]),
        );
        let vk = sk.to_viewing_key();

        assert_eq!(addr.to_string(), BalanceOwner::Address(addr).to_string());

        assert_eq!(
            vk.to_string(),
            BalanceOwner::FullViewingKey(vk).to_string()
        );
    }

    #[test]
    fn test_balance_owner_borsh() {
        let addr = address::testing::established_address_1();

        let owner = BalanceOwner::Address(addr);
        let serialized = owner.serialize_to_vec();
        let deserialized =
            BalanceOwner::try_from_slice(&serialized[..]).unwrap();
        assert_eq!(owner, deserialized);

        let sk = ExtendedSpendingKey::from(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]),
        );
        let vk = sk.to_viewing_key();

        let owner = BalanceOwner::FullViewingKey(vk);
        let serialized = owner.serialize_to_vec();
        let deserialized =
            BalanceOwner::try_from_slice(&serialized[..]).unwrap();
        assert_eq!(owner, deserialized);
    }

    #[test]
    fn test_transfer_target_borsh() {
        let addr = address::testing::established_address_1();

        let target = TransferTarget::Address(addr);
        let serialized = target.serialize_to_vec();
        let deserialized =
            TransferTarget::try_from_slice(&serialized[..]).unwrap();
        assert_eq!(target, deserialized);

        let sk = ExtendedSpendingKey::from(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]),
        );
        let (_diversifier, pa) = sk.0.default_address();
        let pa = PaymentAddress::from(pa);

        let target = TransferTarget::PaymentAddress(pa);
        let serialized = target.serialize_to_vec();
        let deserialized =
            TransferTarget::try_from_slice(&serialized[..]).unwrap();
        assert_eq!(target, deserialized);

        const IBC_ADDR: &str = "noble18st0wqx84av8y6xdlss9d6m2nepyqwj6nfxxuv";

        let target = TransferTarget::Ibc(IBC_ADDR.to_owned());
        let serialized = target.serialize_to_vec();
        let deserialized =
            TransferTarget::try_from_slice(&serialized[..]).unwrap();
        assert_eq!(target, deserialized);
    }

    #[test]
    fn test_masp_tx_id_display() {
        let tx_id = MaspTxId::from(TxIdInner::from_bytes([
            10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 12, 11,
        ]));
        assert_eq!(
            tx_id.to_string(),
            "0b0c00000000000000000000000000000000000000000000000000000000000a"
        );
    }

    #[test]
    fn test_masp_tx_id_basics() {
        let tx_id = MaspTxId::from(TxIdInner::from_bytes([
            0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        let tx_id_str = serde_json::to_string(&tx_id).unwrap();
        let decoded: MaspTxId = serde_json::from_str(&tx_id_str).unwrap();
        assert_eq!(tx_id, decoded);
    }

    #[test]
    fn test_masp_epoch_basics() {
        let epoch = MaspEpoch::new(123);
        let epoch_str = epoch.to_string();
        assert_eq!(&epoch_str, "123");
        let decoded = MaspEpoch::from_str(&epoch_str).unwrap();
        assert_eq!(epoch, decoded);
    }

    #[test]
    fn test_masp_asset_data_basics() {
        let data = AssetData {
            token: address::testing::nam(),
            denom: Denomination(6),
            position: MaspDigitPos::One,
            epoch: None,
        };

        let data = data.undate();
        assert!(data.epoch.is_none());

        let epoch_0 = MaspEpoch::new(3);
        let mut data = data.redate(epoch_0);
        assert!(data.epoch.is_none());
        data.epoch = Some(epoch_0);

        let epoch_1 = MaspEpoch::new(5);
        let data = data.redate(epoch_1);
        assert_eq!(data.epoch, Some(epoch_1));
    }

    #[test]
    fn test_masp_keys_basics() {
        let sk = ExtendedSpendingKey::from(
            masp_primitives::zip32::ExtendedSpendingKey::master(&[0_u8]),
        );
        string_encoding::testing::test_string_formatting(&sk);

        let vk = sk.to_viewing_key();
        string_encoding::testing::test_string_formatting(&vk);

        let (_diversifier, pa) = sk.0.default_address();
        let pa = PaymentAddress::from(pa);
        string_encoding::testing::test_string_formatting(&pa);
    }
}
