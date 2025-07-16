//! Protocol parameters types

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read};
use std::num::NonZeroU64;

use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

use super::address::Address;
use super::hash::Hash;
use super::time::DurationSecs;
use super::token;
use crate::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use crate::token::Amount;

/// Protocol parameters
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct Parameters {
    /// Max payload size, in bytes, for a mempool tx.
    pub max_tx_bytes: u32,
    /// Epoch duration (read only)
    pub epoch_duration: EpochDuration,
    /// Max payload size, in bytes, for a tx batch proposal.
    pub max_proposal_bytes: ProposalBytes,
    /// Max gas for block
    pub max_block_gas: u64,
    /// Allowed validity predicate hashes (read only)
    pub vp_allowlist: Vec<String>,
    /// Allowed tx hashes (read only)
    pub tx_allowlist: Vec<String>,
    /// Implicit accounts validity predicate WASM code hash
    pub implicit_vp_code_hash: Option<Hash>,
    /// Expected number of epochs per year (read only)
    pub epochs_per_year: u64,
    /// The multiplier for masp epochs (it requires this amount of epochs to
    /// transition to the next masp epoch)
    pub masp_epoch_multiplier: u64,
    /// The gas limit for a masp transaction paying fees
    pub masp_fee_payment_gas_limit: u64,
    /// The amount of NAM the MASP shielding fee costs
    pub masp_nam_shielding_fee: Amount,
    /// Gas scale
    pub gas_scale: u64,
    /// Map of the cost per gas unit for every token allowed for fee payment
    pub minimum_gas_price: BTreeMap<Address, token::Amount>,
    /// Enable the native token transfer if it is true
    pub is_native_token_transferable: bool,
}

/// Epoch duration. A new epoch begins as soon as both the `min_num_of_blocks`
/// and `min_duration` have passed since the beginning of the current epoch.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct EpochDuration {
    /// Minimum number of blocks in an epoch
    pub min_num_of_blocks: u64,
    /// Minimum duration of an epoch
    pub min_duration: DurationSecs,
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters {
            max_tx_bytes: 1024 * 1024,
            epoch_duration: EpochDuration {
                min_num_of_blocks: 1,
                min_duration: DurationSecs(3600),
            },
            max_proposal_bytes: Default::default(),
            max_block_gas: 100,
            vp_allowlist: vec![],
            tx_allowlist: vec![],
            implicit_vp_code_hash: Default::default(),
            epochs_per_year: 365,
            masp_epoch_multiplier: 2,
            masp_fee_payment_gas_limit: 0,
            masp_nam_shielding_fee: Amount::zero(),
            gas_scale: 100_000_000,
            minimum_gas_price: Default::default(),
            is_native_token_transferable: true,
        }
    }
}

/// Configuration parameter for the upper limit on the number
/// of bytes transactions can occupy in a block proposal.
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    BorshSerialize,
    BorshDeserializer,
)]
#[repr(transparent)]
pub struct ProposalBytes {
    inner: NonZeroU64,
}

impl BorshDeserialize for ProposalBytes {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let value: u64 = BorshDeserialize::deserialize_reader(reader)?;
        Self::new(value).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "ProposalBytes value must be in the range 1 - {}",
                    Self::RAW_MAX.get()
                ),
            )
        })
    }
}

impl Serialize for ProposalBytes {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_u64(self.inner.get())
    }
}

impl<'de> Deserialize<'de> for ProposalBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = ProposalBytes;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "a u64 in the range 1 - {}",
                    ProposalBytes::RAW_MAX.get()
                )
            }

            fn visit_u64<E>(self, size: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ProposalBytes::new(size).ok_or_else(|| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Unsigned(size),
                        &self,
                    )
                })
            }

            // NOTE: this is only needed because of a bug in the toml parser
            // - https://github.com/toml-rs/toml-rs/issues/256
            // - https://github.com/toml-rs/toml/issues/512
            //
            // TODO(namada#3243): switch to `toml_edit` for TOML parsing
            fn visit_i64<E>(self, size: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let max_bytes = u64::try_from(size).map_err(|_e| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Signed(size),
                        &self,
                    )
                })?;
                ProposalBytes::new(max_bytes).ok_or_else(|| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Signed(size),
                        &self,
                    )
                })
            }
        }

        deserializer.deserialize_u64(Visitor)
    }
}

impl BorshSchema for ProposalBytes {
    fn add_definitions_recursively(
        definitions: &mut std::collections::BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        let fields = borsh::schema::Fields::NamedFields(vec![(
            "inner".into(),
            u64::declaration(),
        )]);
        let definition = borsh::schema::Definition::Struct { fields };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        std::any::type_name::<Self>().into()
    }
}

impl Default for ProposalBytes {
    #[inline]
    fn default() -> Self {
        Self {
            inner: Self::RAW_DEFAULT,
        }
    }
}

// constants
impl ProposalBytes {
    /// The upper bound of a [`ProposalBytes`] value.
    pub const MAX: ProposalBytes = ProposalBytes {
        inner: Self::RAW_MAX,
    };
    /// The (raw) default value for a [`ProposalBytes`].
    ///
    /// This value must be within the range `[1 B, RAW_MAX MiB]`.
    const RAW_DEFAULT: NonZeroU64 = Self::RAW_MAX;
    /// The (raw) upper bound of a [`ProposalBytes`] value.
    ///
    /// The maximum space a serialized Tendermint block can
    /// occupy is 100 MiB. We reserve 10 MiB for serialization
    /// overhead, evidence and header data. For P2P safety
    /// reasons (i.e. DoS protection) we hardcap the size of
    /// tx data to 6 MiB.
    const RAW_MAX: NonZeroU64 = NonZeroU64::new(6 * 1024 * 1024).unwrap();
}

impl ProposalBytes {
    /// Return the number of bytes as a [`u64`] value.
    #[inline]
    pub const fn get(self) -> u64 {
        self.inner.get()
    }

    /// Try to construct a new [`ProposalBytes`] instance,
    /// from the given `max_bytes` value.
    ///
    /// This function will return [`None`] if `max_bytes` is not within
    /// the inclusive range of 1 to [`ProposalBytes::MAX`].
    #[inline]
    pub fn new(max_bytes: u64) -> Option<Self> {
        NonZeroU64::new(max_bytes)
            .map(|inner| Self { inner })
            .and_then(|value| {
                if value.get() > Self::RAW_MAX.get() {
                    None
                } else {
                    Some(value)
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Test if [`ProposalBytes`] serde serialization is correct.
        #[test]
        fn test_proposal_size_serialize_roundtrip(s in 1u64..=ProposalBytes::MAX.get()) {
            let size = ProposalBytes::new(s).expect("Test failed");
            assert_eq!(size.get(), s);
            let json = serde_json::to_string(&size).expect("Test failed");
            let deserialized: ProposalBytes =
                serde_json::from_str(&json).expect("Test failed");
            assert_eq!(size, deserialized);
        }
    }
}
