//! IBC-related data types

use std::collections::BTreeMap;
use std::fmt::Display;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::{DecodePartial, HEXLOWER, HEXLOWER_PERMISSIVE};
use ibc::core::host::types::identifiers::{ChannelId, PortId};
pub use ibc::*;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

use super::address::HASH_LEN;
use crate::address::Address;
use crate::hash::Hash;
use crate::token::{self, DenominatedAmount};

/// IBC token hash derived from a denomination.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[repr(transparent)]
pub struct IbcTokenHash(pub [u8; HASH_LEN]);

impl Display for IbcTokenHash {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0))
    }
}

impl FromStr for IbcTokenHash {
    type Err = DecodePartial;

    fn from_str(h: &str) -> Result<Self, Self::Err> {
        let mut output = [0u8; HASH_LEN];
        HEXLOWER_PERMISSIVE.decode_mut(h.as_ref(), &mut output)?;
        Ok(IbcTokenHash(output))
    }
}

/// IBC transaction data section hash
pub type IbcTxDataHash = Hash;

/// The target of a PGF payment
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Ord,
    Eq,
    PartialOrd,
    BorshDeserializer,
    Hash,
)]
pub struct PGFIbcTarget {
    /// The target address on the target chain
    pub target: String,
    /// The amount of token to fund the target address
    pub amount: token::Amount,
    /// Port ID to fund
    pub port_id: PortId,
    /// Channel ID to fund
    pub channel_id: ChannelId,
}

impl BorshSerialize for PGFIbcTarget {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.target, writer)?;
        BorshSerialize::serialize(&self.amount, writer)?;
        BorshSerialize::serialize(&self.port_id.to_string(), writer)?;
        BorshSerialize::serialize(&self.channel_id.to_string(), writer)
    }
}

impl borsh::BorshDeserialize for PGFIbcTarget {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let target: String = BorshDeserialize::deserialize_reader(reader)?;
        let amount: token::Amount =
            BorshDeserialize::deserialize_reader(reader)?;
        let port_id: String = BorshDeserialize::deserialize_reader(reader)?;
        let port_id: PortId = port_id.parse().map_err(|err| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Error decoding port ID: {}", err),
            )
        })?;
        let channel_id: String = BorshDeserialize::deserialize_reader(reader)?;
        let channel_id: ChannelId = channel_id.parse().map_err(|err| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Error decoding channel ID: {}", err),
            )
        })?;
        Ok(Self {
            target,
            amount,
            port_id,
            channel_id,
        })
    }
}

impl borsh::BorshSchema for PGFIbcTarget {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        let fields = borsh::schema::Fields::NamedFields(vec![
            ("target".into(), String::declaration()),
            ("amount".into(), token::Amount::declaration()),
            ("port_id".into(), String::declaration()),
            ("channel_id".into(), String::declaration()),
        ]);
        let definition = borsh::schema::Definition::Struct { fields };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        std::any::type_name::<Self>().into()
    }
}

/// The data needed to perform the transparent transfer of the frontend provider
/// MASP sustainability fee when shielding via IBC
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct MaspFrontendSusFee {
    /// The address of the frontend provider
    pub target: Address,
    /// The token of the fee (must match the token being shielded)
    pub token: Address,
    /// The amount of the fee
    pub amt: DenominatedAmount,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{decode, encode};

    #[test]
    fn test_ibc_token_hash() {
        let hash = IbcTokenHash([
            0_u8, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let hash_str = hash.to_string();
        assert_eq!("00ff000000000000000000000000000000000000", &hash_str);

        let decoded = IbcTokenHash::from_str(&hash_str).unwrap();
        assert_eq!(decoded, hash);

        // Hex decoding is case-insensitive
        let decoded =
            IbcTokenHash::from_str("00FF000000000000000000000000000000000000")
                .unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_ibc_pgf_target() {
        let target = PGFIbcTarget {
            target: "123".to_string(),
            amount: token::Amount::from_u64(123456789),
            port_id: PortId::new("10".to_string()).unwrap(),
            channel_id: ChannelId::new(5),
        };
        let bytes = encode(&target);
        let decoded: PGFIbcTarget = decode(bytes).unwrap();
        assert_eq!(target, decoded);
    }
}
