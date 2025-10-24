//! Implements raw addresses, which can be turned into transparent
//! addresses on Namada.

#![allow(dead_code)]

use std::borrow::Cow;
use std::marker::PhantomData;

use num_enum::TryFromPrimitive;

use super::HASH_LEN;

/// Number of bytes required to encode a raw address.
pub const ADDR_ENCODING_LEN: usize = 1 + HASH_LEN;

/// Default data stored by raw addresses.
const ADDR_DEFAULT_DATA: [u8; HASH_LEN] = [0; HASH_LEN];

/// Tag type used to indicate a raw address has yet to be validated.
#[derive(Clone, Debug)]
pub enum Unvalidated {}

/// Tag type used to indicate a raw address has been validated.
#[derive(Clone, Debug)]
pub enum Validated {}

/// Discriminant byte used to discern between different raw address kinds.
// =================================================================
// __WARNING__: Take extreme care when changing these values, as you
// might break compatibility between different binaries, and trigger
// network forks.
// =================================================================
#[repr(u8)]
#[derive(
    Hash, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, TryFromPrimitive,
)]
pub enum Discriminant {
    /// Implicit raw address.
    Implicit = 0,
    /// Established raw address.
    Established = 1,
    /// Proof-of-stake raw address.
    Pos = 2,
    /// Proof-of-stake slash pool raw address.
    SlashPool = 3,
    /// Protocol parameters raw address.
    Parameters = 4,
    /// Governance raw address.
    Governance = 5,
    /// IBC raw address.
    Ibc = 6,
    /// Ethereum bridge raw address.
    #[deprecated]
    EthBridge = 7,
    /// Bridge pool raw address.
    #[deprecated]
    BridgePool = 8,
    /// Multitoken raw address.
    Multitoken = 9,
    /// Public goods funding raw address.
    Pgf = 10,
    /// ERC20 raw address.
    #[deprecated]
    Erc20 = 11,
    /// NUT raw address.
    #[deprecated]
    Nut = 12,
    /// IBC token raw address.
    IbcToken = 13,
    /// MASP raw address.
    Masp = 14,
    /// Temporary storage address.
    TempStorage = 15,
    /// Replay protection
    ReplayProtection = 16,
}

/// Raw address representation.
#[derive(Clone, Debug)]
pub struct Address<'data, S> {
    /// Discriminant bytes of some raw address.
    ///
    /// ___INVARIANT__: This value should be unique per
    /// raw address kind.
    discriminant: Discriminant,
    /// Discriminant specific data.
    data: Cow<'data, [u8; HASH_LEN]>,
    /// The raw address state.
    _state: PhantomData<S>,
}

impl<S> Address<'_, S> {
    /// Retrieve the data field of this raw address.
    pub const fn data(&self) -> &[u8; HASH_LEN] {
        match &self.data {
            Cow::Borrowed(data) => data,
            Cow::Owned(data) => data,
        }
    }

    /// Retrieve the discriminant of this raw address.
    pub const fn discriminant(&self) -> Discriminant {
        self.discriminant
    }

    /// Return an owned raw address.
    #[inline]
    pub fn to_owned(&self) -> Address<'static, S> {
        Address {
            discriminant: self.discriminant,
            _state: PhantomData,
            data: Cow::Owned(*self.data),
        }
    }

    /// Check whether this raw address contains the default
    /// address data [`ADDR_DEFAULT_DATA`].
    const fn has_default_data(&self) -> bool {
        !matches!(
            self.discriminant,
            Discriminant::Implicit
                | Discriminant::Established
                | Discriminant::IbcToken,
        )
    }
}

impl Address<'static, Unvalidated> {
    /// Attempt to parse a raw address from the input slice.
    pub fn try_from_slice(raw_addr: &[u8]) -> Option<Self> {
        if raw_addr.len() != ADDR_ENCODING_LEN {
            return None;
        }
        let discriminant = raw_addr[0].try_into().ok()?;
        Self::from_discriminant(discriminant)
            .try_with_data_slice(&raw_addr[1..])
    }

    /// Return a new unvalidated raw address.
    pub const fn from_discriminant(discriminant: Discriminant) -> Self {
        Self {
            discriminant,
            data: Cow::Borrowed(&ADDR_DEFAULT_DATA),
            _state: PhantomData,
        }
    }

    /// Attempt to swap the data field of this raw address.
    ///
    /// This method will fail if the size of the input buffer is
    /// different from [`HASH_LEN`].
    pub fn try_with_data_slice(self, data: &[u8]) -> Option<Self> {
        let data: [u8; HASH_LEN] = data.try_into().ok()?;
        Some(self.with_data_array(data))
    }
}

impl<'data> Address<'data, Unvalidated> {
    /// Swap the data field of this raw address.
    pub const fn with_data_array(
        self,
        data: [u8; HASH_LEN],
    ) -> Address<'static, Unvalidated> {
        Address {
            discriminant: self.discriminant,
            _state: PhantomData,
            data: Cow::Owned(data),
        }
    }

    /// Swap the data field of this raw address.
    pub const fn with_data_array_ref(
        self,
        data: &[u8; HASH_LEN],
    ) -> Address<'_, Unvalidated> {
        Address {
            discriminant: self.discriminant,
            _state: PhantomData,
            data: Cow::Borrowed(data),
        }
    }

    /// Check the correctness of the raw address, returning a
    /// validated raw address that can be converted to
    pub fn validate(self) -> Option<Address<'data, Validated>> {
        if self.has_default_data() && *self.data != ADDR_DEFAULT_DATA {
            return None;
        }
        Some(self.validate_unsafe())
    }

    /// Validates the raw address.
    ///
    /// Do not call this before validating its internal state.
    const fn validate_unsafe(self) -> Address<'data, Validated> {
        let Self {
            discriminant, data, ..
        } = self;
        Address {
            _state: PhantomData,
            discriminant,
            data,
        }
    }
}

impl Address<'_, Validated> {
    /// Encode the raw address as a byte array.
    pub fn to_bytes(&self) -> [u8; ADDR_ENCODING_LEN] {
        let mut output = [0u8; ADDR_ENCODING_LEN];
        output[0] = self.discriminant as u8;
        output[1..].copy_from_slice(&*self.data);
        output
    }
}
