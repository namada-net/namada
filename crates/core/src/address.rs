//! Implements transparent addresses as described in [Accounts
//! Addresses](docs/src/explore/design/ledger/accounts.md#addresses).

mod raw;

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::HEXUPPER;
use ibc::primitives::Signer;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ethereum_events::EthAddress;
use crate::ibc::IbcTokenHash;
use crate::key::PublicKeyHash;
use crate::{impl_display_and_from_str_via_format, key, string_encoding};

/// The length of an established [`Address`] encoded with Borsh.
pub const ESTABLISHED_ADDRESS_BYTES_LEN: usize = 21;

/// The length of [`Address`] encoded with Bech32m.
// NOTE: This must be kept in sync with the bech32 HRP.
// Uppercase prefixes might result in a different length,
// so tread carefully when changing this value.
pub const ADDRESS_LEN: usize =
    string_encoding::ADDRESS_HRP.len() + 1 + HASH_HEX_LEN;

/// Length of a hash of an address as a hexadecimal string
pub const HASH_HEX_LEN: usize = 40;

/// Length of a trimmed hash of an address.
pub const HASH_LEN: usize = 20;

/// SHA-256 hash len
///
/// ```
/// use sha2::Digest;
/// assert_eq!(
///     sha2::Sha256::output_size(),
///     namada_core::address::SHA_HASH_LEN
/// );
/// ```
pub const SHA_HASH_LEN: usize = 32;

/// Internal IBC address
pub const IBC: Address = Address::Internal(InternalAddress::Ibc);
/// Internal ledger parameters address
pub const PARAMETERS: Address = Address::Internal(InternalAddress::Parameters);
/// Internal PoS address
pub const POS: Address = Address::Internal(InternalAddress::PoS);
/// Internal PoS slash pool address
pub const POS_SLASH_POOL: Address =
    Address::Internal(InternalAddress::PosSlashPool);
/// Internal Governance address
pub const GOV: Address = Address::Internal(InternalAddress::Governance);
/// Internal Public Goods funding address
pub const PGF: Address = Address::Internal(InternalAddress::Pgf);
/// Internal MASP address
pub const MASP: Address = Address::Internal(InternalAddress::Masp);
/// Internal Multitoken address
pub const MULTITOKEN: Address = Address::Internal(InternalAddress::Multitoken);
/// Internal Eth bridge address
pub const ETH_BRIDGE: Address = Address::Internal(InternalAddress::EthBridge);
/// Address with temporary storage is used to pass data from txs to VPs which is
/// never committed to DB
pub const TEMP_STORAGE: Address =
    Address::Internal(InternalAddress::TempStorage);

/// Error from decoding address from string
pub type DecodeError = string_encoding::DecodeError;

/// Result of decoding address from string
pub type Result<T> = std::result::Result<T, DecodeError>;

/// An account's address
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    Hash,
)]
pub enum Address {
    /// An established address is generated on-chain
    Established(EstablishedAddress),
    /// An implicit address is derived from a cryptographic key
    Implicit(ImplicitAddress),
    /// An internal address represents a module with a native VP
    Internal(InternalAddress),
}

impl From<raw::Address<'_, raw::Validated>> for Address {
    fn from(raw_addr: raw::Address<'_, raw::Validated>) -> Self {
        match raw_addr.discriminant() {
            raw::Discriminant::Implicit => Address::Implicit(ImplicitAddress(
                PublicKeyHash(*raw_addr.data()),
            )),
            raw::Discriminant::Established => {
                Address::Established(EstablishedAddress {
                    hash: *raw_addr.data(),
                })
            }
            raw::Discriminant::Pos => Address::Internal(InternalAddress::PoS),
            raw::Discriminant::SlashPool => {
                Address::Internal(InternalAddress::PosSlashPool)
            }
            raw::Discriminant::Parameters => {
                Address::Internal(InternalAddress::Parameters)
            }
            raw::Discriminant::Governance => {
                Address::Internal(InternalAddress::Governance)
            }
            raw::Discriminant::Ibc => Address::Internal(InternalAddress::Ibc),
            raw::Discriminant::EthBridge => {
                Address::Internal(InternalAddress::EthBridge)
            }
            raw::Discriminant::BridgePool => {
                Address::Internal(InternalAddress::EthBridgePool)
            }
            raw::Discriminant::Multitoken => {
                Address::Internal(InternalAddress::Multitoken)
            }
            raw::Discriminant::Pgf => Address::Internal(InternalAddress::Pgf),
            raw::Discriminant::Erc20 => Address::Internal(
                InternalAddress::Erc20(EthAddress(*raw_addr.data())),
            ),
            raw::Discriminant::Nut => Address::Internal(InternalAddress::Nut(
                EthAddress(*raw_addr.data()),
            )),
            raw::Discriminant::IbcToken => Address::Internal(
                InternalAddress::IbcToken(IbcTokenHash(*raw_addr.data())),
            ),
            raw::Discriminant::Masp => Address::Internal(InternalAddress::Masp),
            raw::Discriminant::TempStorage => {
                Address::Internal(InternalAddress::TempStorage)
            }
            raw::Discriminant::ReplayProtection => {
                Address::Internal(InternalAddress::ReplayProtection)
            }
        }
    }
}

impl From<Address> for raw::Address<'static, raw::Validated> {
    #[inline]
    fn from(address: Address) -> Self {
        raw::Address::from(&address).to_owned()
    }
}

impl<'addr> From<&'addr Address> for raw::Address<'addr, raw::Validated> {
    fn from(address: &'addr Address) -> Self {
        match address {
            Address::Established(EstablishedAddress { hash }) => {
                raw::Address::from_discriminant(raw::Discriminant::Established)
                    .with_data_array_ref(hash)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Implicit(ImplicitAddress(key::PublicKeyHash(pkh))) => {
                raw::Address::from_discriminant(raw::Discriminant::Implicit)
                    .with_data_array_ref(pkh)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::PoS) => {
                raw::Address::from_discriminant(raw::Discriminant::Pos)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::PosSlashPool) => {
                raw::Address::from_discriminant(raw::Discriminant::SlashPool)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Parameters) => {
                raw::Address::from_discriminant(raw::Discriminant::Parameters)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Governance) => {
                raw::Address::from_discriminant(raw::Discriminant::Governance)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Ibc) => {
                raw::Address::from_discriminant(raw::Discriminant::Ibc)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::IbcToken(IbcTokenHash(
                hash,
            ))) => raw::Address::from_discriminant(raw::Discriminant::IbcToken)
                .with_data_array_ref(hash)
                .validate()
                .expect("This raw address is valid"),
            Address::Internal(InternalAddress::EthBridge) => {
                raw::Address::from_discriminant(raw::Discriminant::EthBridge)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::EthBridgePool) => {
                raw::Address::from_discriminant(raw::Discriminant::BridgePool)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Erc20(EthAddress(eth_addr))) => {
                raw::Address::from_discriminant(raw::Discriminant::Erc20)
                    .with_data_array_ref(eth_addr)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Nut(EthAddress(eth_addr))) => {
                raw::Address::from_discriminant(raw::Discriminant::Nut)
                    .with_data_array_ref(eth_addr)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Multitoken) => {
                raw::Address::from_discriminant(raw::Discriminant::Multitoken)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Pgf) => {
                raw::Address::from_discriminant(raw::Discriminant::Pgf)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Masp) => {
                raw::Address::from_discriminant(raw::Discriminant::Masp)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::TempStorage) => {
                raw::Address::from_discriminant(raw::Discriminant::TempStorage)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::ReplayProtection) => {
                raw::Address::from_discriminant(
                    raw::Discriminant::ReplayProtection,
                )
                .validate()
                .expect("This raw address is valid")
            }
        }
    }
}

// We're using the string format of addresses (bech32m) for ordering to ensure
// that addresses as strings, storage keys and storage keys as strings preserve
// the order.
impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.encode().cmp(&other.encode())
    }
}

impl Address {
    /// Encode an address with Bech32m encoding
    pub fn encode(&self) -> String {
        string_encoding::Format::encode(self)
    }

    /// Encode an address in compatibility mode (i.e. with the legacy Bech32
    /// encoding)
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

    /// Decode an address from Bech32m encoding
    pub fn decode(string: impl AsRef<str>) -> Result<Self> {
        string_encoding::Format::decode(string)
    }

    /// Try to get a raw hash of an address, only defined for established and
    /// implicit addresses.
    pub fn raw_hash(&self) -> Option<String> {
        match self {
            Address::Established(established) => {
                let hash_hex = HEXUPPER.encode(&established.hash);
                Some(hash_hex)
            }
            Address::Implicit(ImplicitAddress(implicit)) => {
                let hash_hex = HEXUPPER.encode(&implicit.0);
                Some(hash_hex)
            }
            Address::Internal(_) => None,
        }
    }

    fn pretty_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_pretty_string())
    }

    /// Print the type of the address and its bech32m encoded value
    pub fn to_pretty_string(&self) -> String {
        match self {
            Address::Established(_) => {
                format!("Established: {}", self.encode())
            }
            Address::Implicit(_) => {
                format!("Implicit: {}", self.encode())
            }
            Address::Internal(kind) => {
                format!("Internal {}: {}", kind, self.encode())
            }
        }
    }

    /// If the address established?
    pub fn is_established(&self) -> bool {
        matches!(self, Address::Established(_))
    }

    /// If the address implicit?
    pub fn is_implicit(&self) -> bool {
        matches!(self, Address::Implicit(_))
    }

    /// If the address internal?
    pub fn is_internal(&self) -> bool {
        matches!(self, Address::Internal(_))
    }
}

impl string_encoding::Format for Address {
    type EncodedBytes<'a> = [u8; raw::ADDR_ENCODING_LEN];

    const HRP: string_encoding::Hrp =
        string_encoding::Hrp::parse_unchecked(string_encoding::ADDRESS_HRP);

    fn to_bytes(&self) -> [u8; raw::ADDR_ENCODING_LEN] {
        let raw_addr: raw::Address<'_, _> = self.into();
        raw_addr.to_bytes()
    }

    fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let unvalidated_raw_addr = raw::Address::try_from_slice(bytes)
            .ok_or_else(|| {
                DecodeError::InvalidInnerEncoding(
                    "Invalid raw address length".to_string(),
                )
            })?;
        let validated_raw_addr =
            unvalidated_raw_addr.validate().ok_or_else(|| {
                DecodeError::InvalidInnerEncoding(
                    "Invalid address discriminant and data pair".to_string(),
                )
            })?;
        Ok(validated_raw_addr.into())
    }
}

impl_display_and_from_str_via_format!(Address);

impl serde::Serialize for Address {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.encode();
        serde::Serialize::serialize(&encoded, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        Self::decode(encoded).map_err(D::Error::custom)
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.pretty_fmt(f)
    }
}

impl From<&Address> for Signer {
    fn from(address: &Address) -> Signer {
        address.to_string().into()
    }
}

impl From<Address> for Signer {
    fn from(address: Address) -> Signer {
        (&address).into()
    }
}

impl TryFrom<&Signer> for Address {
    type Error = DecodeError;

    fn try_from(signer: &Signer) -> Result<Self> {
        // The given address should be an address or payment address. When
        // sending a token from a spending key, it has been already
        // replaced with the MASP address.
        Address::decode(signer.as_ref()).or(
            match crate::masp::PaymentAddress::from_str(signer.as_ref()) {
                Ok(_) => Ok(MASP),
                Err(_) => Err(DecodeError::InvalidInnerEncoding(format!(
                    "Invalid address for IBC transfer: {signer}"
                ))),
            },
        )
    }
}

impl TryFrom<Signer> for Address {
    type Error = DecodeError;

    fn try_from(signer: Signer) -> Result<Self> {
        (&signer).try_into()
    }
}

/// An established address is generated on-chain
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct EstablishedAddress {
    hash: [u8; HASH_LEN],
}

impl From<[u8; HASH_LEN]> for EstablishedAddress {
    fn from(hash: [u8; HASH_LEN]) -> Self {
        Self { hash }
    }
}

impl From<[u8; SHA_HASH_LEN]> for EstablishedAddress {
    fn from(input_hash: [u8; SHA_HASH_LEN]) -> Self {
        let mut hash = [0; HASH_LEN];
        hash.copy_from_slice(&input_hash[..HASH_LEN]);
        Self { hash }
    }
}

impl string_encoding::Format for EstablishedAddress {
    type EncodedBytes<'a> = [u8; raw::ADDR_ENCODING_LEN];

    const HRP: string_encoding::Hrp =
        string_encoding::Hrp::parse_unchecked(string_encoding::ADDRESS_HRP);

    #[inline]
    fn to_bytes(&self) -> [u8; raw::ADDR_ENCODING_LEN] {
        Address::Established(self.hash.into()).to_bytes()
    }

    #[inline]
    fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        match Address::decode_bytes(bytes)? {
            Address::Established(established) => Ok(established),
            address => Err(DecodeError::InvalidInnerEncoding(format!(
                "Expected established address, got {address:?}"
            ))),
        }
    }
}

impl_display_and_from_str_via_format!(EstablishedAddress);

/// A generator of established addresses
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct EstablishedAddressGen {
    last_hash: [u8; SHA_HASH_LEN],
}

impl EstablishedAddressGen {
    /// Initialize a new address generator with a given randomness seed.
    pub fn new(seed: impl AsRef<str>) -> Self {
        Self {
            last_hash: Sha256::digest(seed.as_ref().as_bytes()).into(),
        }
    }

    /// Generate a new established address. Requires a source of randomness as
    /// arbitrary bytes. In the ledger, this could be some unpredictable value,
    /// such as hash of the transaction that has initialized the new address.
    pub fn generate_address(
        &mut self,
        rng_source: impl AsRef<[u8]>,
    ) -> Address {
        self.last_hash = {
            let mut hasher_state = Sha256::new();
            hasher_state.update(self.last_hash);
            hasher_state.update(rng_source);
            hasher_state.finalize()
        }
        .into();
        Address::Established(self.last_hash.into())
    }
}

/// An implicit address is derived from a cryptographic key
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    Default,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct ImplicitAddress(pub key::PublicKeyHash);

impl From<&key::common::PublicKey> for ImplicitAddress {
    fn from(pk: &key::common::PublicKey) -> Self {
        ImplicitAddress(pk.into())
    }
}

impl From<&key::common::PublicKey> for Address {
    fn from(pk: &key::common::PublicKey) -> Self {
        Self::Implicit(pk.into())
    }
}

/// An internal address represents a module with a native VP
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum InternalAddress {
    /// Proof-of-stake
    PoS,
    /// Proof-of-stake slash pool contains slashed tokens
    PosSlashPool,
    /// Protocol parameters
    Parameters,
    /// Inter-blockchain communication
    Ibc,
    /// IBC-related token
    IbcToken(IbcTokenHash),
    /// Governance address
    Governance,
    /// Bridge to Ethereum
    EthBridge,
    /// The pool of transactions to be relayed to Ethereum
    EthBridgePool,
    /// ERC20 token for Ethereum bridge
    Erc20(EthAddress),
    /// Non-usable ERC20 tokens
    Nut(EthAddress),
    /// Multitoken
    Multitoken,
    /// Pgf
    Pgf,
    /// Masp
    Masp,
    /// Replay protection
    ReplayProtection,
    /// Address with temporary storage is used to pass data from txs to VPs
    /// which is never committed to DB
    TempStorage,
}

impl Display for InternalAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::PoS => "PoS".to_string(),
                Self::PosSlashPool => "PosSlashPool".to_string(),
                Self::Parameters => "Parameters".to_string(),
                Self::Governance => "Governance".to_string(),
                Self::Ibc => "IBC".to_string(),
                Self::IbcToken(hash) => format!("IbcToken: {}", hash),
                Self::EthBridge => "EthBridge".to_string(),
                Self::EthBridgePool => "EthBridgePool".to_string(),
                Self::Erc20(eth_addr) => format!("Erc20: {}", eth_addr),
                Self::Nut(eth_addr) => format!("Non-usable token: {eth_addr}"),
                Self::Multitoken => "Multitoken".to_string(),
                Self::Pgf => "PGF".to_string(),
                Self::Masp => "MASP".to_string(),
                Self::ReplayProtection => "ReplayProtection".to_string(),
                Self::TempStorage => "TempStorage".to_string(),
            }
        )
    }
}

impl InternalAddress {
    /// Certain internal addresses have reserved aliases.
    pub fn try_from_alias(alias: &str) -> Option<Self> {
        match alias {
            "pos" => Some(InternalAddress::PoS),
            "ibc" => Some(InternalAddress::Ibc),
            "ethbridge" => Some(InternalAddress::EthBridge),
            "bridgepool" => Some(InternalAddress::EthBridgePool),
            "governance" => Some(InternalAddress::Governance),
            "masp" => Some(InternalAddress::Masp),
            "replayprotection" => Some(InternalAddress::ReplayProtection),
            "pgf" => Some(InternalAddress::Pgf),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::borsh::BorshSerializeExt;

    /// Run `cargo test gen_established_address -- --nocapture` to generate a
    /// new established address.
    #[test]
    pub fn gen_established_address() {
        for _ in 0..10 {
            let address = testing::gen_established_address();
            println!("address {}", address);
        }
    }

    /// Run `cargo test gen_implicit_address -- --nocapture` to generate a
    /// new established address.
    #[test]
    pub fn gen_implicit_address() {
        for _ in 0..10 {
            let address = testing::gen_implicit_address();
            println!("address {}", address);
        }
    }

    #[test]
    fn test_address_serde_serialize() {
        let original_address =
            Address::decode("tnam1q8j5s6xp55p05yznwnftkv3kr9gjtsw3nq7x6tw5")
                .unwrap();
        let expect = "\"tnam1q8j5s6xp55p05yznwnftkv3kr9gjtsw3nq7x6tw5\"";
        let decoded_address: Address =
            serde_json::from_str(expect).expect("could not read JSON");
        assert_eq!(original_address, decoded_address);

        let encoded_address = serde_json::to_string(&original_address).unwrap();
        assert_eq!(encoded_address, expect);
    }

    proptest! {
        #[test]
        /// Check that all the address types are of the same length
        /// `ADDRESS_LEN` when bech32m encoded, and that that decoding them
        /// yields back the same value.
        fn test_encoded_address_length(address in testing::arb_address()) {
            let encoded: String = address.encode();
            assert_eq!(encoded.len(), ADDRESS_LEN);
            // Also roundtrip check that we decode back the same value
            let decoded = Address::decode(&encoded).unwrap();
            assert_eq!(address, decoded);
        }

        #[test]
        fn test_established_address_bytes_length(address in testing::arb_established_address()) {
            let address = Address::Established(address);
            let bytes = address.serialize_to_vec();
            assert_eq!(bytes.len(), ESTABLISHED_ADDRESS_BYTES_LEN);
        }

        #[test]
        fn test_compat_addr_decode_bech32(address in testing::arb_address()) {
            let encoded: String = address.encode();
            let encoded_compat: String = address.encode_compat();

            assert_ne!(encoded, encoded_compat);

            let decoded: Address = encoded.parse().unwrap();
            let decoded_compat: Address = encoded_compat.parse().unwrap();

            assert_eq!(decoded, decoded_compat);
        }
    }
}

/// Generate a new established address.
#[cfg(any(test, feature = "rand"))]
pub fn gen_established_address(seed: impl AsRef<str>) -> Address {
    use rand::prelude::ThreadRng;
    use rand::{RngCore, thread_rng};

    EstablishedAddressGen::new(seed).generate_address({
        let mut thread_local_rng: ThreadRng = thread_rng();
        let mut buffer = [0u8; 32];

        thread_local_rng.fill_bytes(&mut buffer[..]);
        buffer
    })
}

/// Generate a new established address. Unlike `gen_established_address`, this
/// will give the same address for the same `seed`.
pub fn gen_deterministic_established_address(seed: impl AsRef<str>) -> Address {
    let mut key_gen = EstablishedAddressGen::new(seed);
    key_gen.generate_address("")
}

/// Helpers for testing with addresses.
#[cfg(any(test, feature = "testing", feature = "benches"))]
pub mod testing {
    use proptest::prelude::*;

    use super::*;
    use crate::collections::HashMap;
    use crate::key::*;
    use crate::token::Denomination;

    /// Generate a new established address.
    pub fn gen_established_address() -> Address {
        let seed = "such randomness, much wow";
        super::gen_established_address(seed)
    }

    /// Derive an established address from a simple seed (`u64`).
    pub fn address_from_simple_seed(seed: u64) -> Address {
        super::gen_deterministic_established_address(seed.to_string())
    }

    /// Generate a new implicit address.
    pub fn gen_implicit_address() -> Address {
        let keypair: common::SecretKey =
            key::testing::gen_keypair::<ed25519::SigScheme>()
                .try_to_sk()
                .unwrap();
        let pkh = PublicKeyHash::from(&keypair.ref_to());
        Address::Implicit(ImplicitAddress(pkh))
    }

    /// A sampled established address for tests
    pub fn established_address_1() -> Address {
        Address::decode("tnam1q8j5s6xp55p05yznwnftkv3kr9gjtsw3nq7x6tw5")
            .expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_2() -> Address {
        Address::decode("tnam1q9k6y928edsh3wsw6xu9d92vwfhjcf8n2qn3g5y8")
            .expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_3() -> Address {
        Address::decode("tnam1q93zjrvl48w798ena2cg3lhg6s6gzhpssc766yvs")
            .expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_4() -> Address {
        Address::decode("tnam1q8g8780290hs6p6qtuqaknlc62akwgyn4cj48tkq")
            .expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_5() -> Address {
        Address::decode("tnam1qyftuue8fq25ezm0s8vj75d3qz759r2225ug7hll")
            .expect("The token address decoding shouldn't fail")
    }

    /// Generate an arbitrary [`Address`] (established or implicit).
    pub fn arb_non_internal_address() -> impl Strategy<Value = Address> {
        prop_oneof![
            arb_established_address().prop_map(Address::Established),
            arb_implicit_address().prop_map(Address::Implicit),
            arb_whitelisted_address(),
        ]
    }

    /// Generate an arbitrary [`Address`] (established, implicit or internal).
    pub fn arb_address() -> impl Strategy<Value = Address> {
        prop_oneof![
            arb_established_address().prop_map(Address::Established),
            arb_implicit_address().prop_map(Address::Implicit),
            arb_internal_address().prop_map(Address::Internal),
            arb_whitelisted_address(),
        ]
    }

    /// A list of tokens whitelisted on hardware wallets
    pub fn address_whitelist() -> HashMap<Address, &'static str> {
        const EXPECT: &str = "The token address decoding shouldn't fail";
        let nam =
            Address::decode("tnam1q9gr66cvu4hrzm0sd5kmlnjje82gs3xlfg3v6nu7");
        let osmo =
            Address::decode("tnam1p5z8ruwyu7ha8urhq2l0dhpk2f5dv3ts7uyf2n75");
        let atom =
            Address::decode("tnam1pkg30gnt4q0zn7j00r6hms4ajrxn6f5ysyyl7w9m");
        let tia =
            Address::decode("tnam1pklj3kwp0cpsdvv56584rsajty974527qsp8n0nm");
        let st_osmo =
            Address::decode("tnam1p4px8sw3am4qvetj7eu77gftm4fz4hcw2ulpldc7");
        let st_atom =
            Address::decode("tnam1p5z5538v3kdk3wdx7r2hpqm4uq9926dz3ughcp7n");
        let st_tia =
            Address::decode("tnam1ph6xhf0defk65hm7l5ursscwqdj8ehrcdv300u4g");
        let mut whitelist = HashMap::new();
        whitelist.insert(nam.expect(EXPECT), "NAM");
        whitelist.insert(osmo.expect(EXPECT), "uOSMO");
        whitelist.insert(atom.expect(EXPECT), "uATOM");
        whitelist.insert(tia.expect(EXPECT), "uTIA");
        whitelist.insert(st_osmo.expect(EXPECT), "ustOSMO");
        whitelist.insert(st_atom.expect(EXPECT), "ustATOM");
        whitelist.insert(st_tia.expect(EXPECT), "ustTIA");
        whitelist
    }

    /// Generate an arbitrary whitelisted address
    pub fn arb_whitelisted_address() -> impl Strategy<Value = Address> {
        any::<prop::sample::Selector>().prop_map(|selector| {
            selector.select(address_whitelist().keys().cloned())
        })
    }

    /// Generate an arbitrary [`EstablishedAddress`].
    pub fn arb_established_address() -> impl Strategy<Value = EstablishedAddress>
    {
        any::<Vec<u8>>().prop_map(|rng_source| {
            let mut key_gen = EstablishedAddressGen::new("seed");
            match key_gen.generate_address(rng_source) {
                Address::Established(addr) => addr,
                _ => {
                    panic!(
                        "Assuming key gen to only generated established \
                         addresses"
                    )
                }
            }
        })
    }

    /// Generate an arbitrary [`ImplicitAddress`].
    pub fn arb_implicit_address() -> impl Strategy<Value = ImplicitAddress> {
        key::testing::arb_keypair::<ed25519::SigScheme>().prop_map(|keypair| {
            let keypair: common::SecretKey = keypair.try_to_sk().unwrap();
            let pkh = PublicKeyHash::from(&keypair.ref_to());
            ImplicitAddress(pkh)
        })
    }

    /// Generate an arbitrary [`InternalAddress`].
    pub fn arb_internal_address() -> impl Strategy<Value = InternalAddress> {
        // This is here for match exhaustion check to remind to add any new
        // internal addresses below.
        match InternalAddress::PoS {
            InternalAddress::PoS => {}
            InternalAddress::PosSlashPool => {}
            InternalAddress::Governance => {}
            InternalAddress::Parameters => {}
            InternalAddress::Ibc => {}
            InternalAddress::IbcToken(_) => {}
            InternalAddress::EthBridge => {}
            InternalAddress::EthBridgePool => {}
            InternalAddress::Erc20(_) => {}
            InternalAddress::Nut(_) => {}
            InternalAddress::Pgf => {}
            InternalAddress::Masp => {}
            InternalAddress::Multitoken => {}
            InternalAddress::ReplayProtection => {}
            InternalAddress::TempStorage => {} /* Add new addresses in the
                                                * `prop_oneof` below. */
        };
        prop_oneof![
            Just(InternalAddress::PoS),
            Just(InternalAddress::PosSlashPool),
            Just(InternalAddress::Ibc),
            Just(InternalAddress::Parameters),
            arb_ibc_token(),
            Just(InternalAddress::Governance),
            Just(InternalAddress::EthBridge),
            Just(InternalAddress::EthBridgePool),
            arb_erc20(),
            arb_nut(),
            Just(InternalAddress::Multitoken),
            Just(InternalAddress::Pgf),
            Just(InternalAddress::Masp),
            Just(InternalAddress::ReplayProtection),
            Just(InternalAddress::TempStorage),
        ]
    }

    fn arb_ibc_token() -> impl Strategy<Value = InternalAddress> {
        ("[a-zA-Z0-9_]{2,128}", any::<u64>()).prop_map(|(id, counter)| {
            let mut hasher = sha2::Sha256::new();
            let s = format!(
                "{}/{}/{}",
                id,
                format_args!("channel-{}", counter),
                &nam()
            );
            hasher.update(&s);
            let hash = hasher.finalize();
            let hash = IbcTokenHash({
                let input: &[u8; SHA_HASH_LEN] = hash.as_ref();
                let mut output = [0; HASH_LEN];
                output.copy_from_slice(&input[..HASH_LEN]);
                output
            });
            InternalAddress::IbcToken(hash)
        })
    }

    fn arb_erc20() -> impl Strategy<Value = InternalAddress> {
        proptest::array::uniform20(proptest::num::u8::ANY).prop_map(|addr| {
            InternalAddress::Erc20(crate::ethereum_events::EthAddress(addr))
        })
    }

    fn arb_nut() -> impl Strategy<Value = InternalAddress> {
        proptest::array::uniform20(proptest::num::u8::ANY).prop_map(|addr| {
            InternalAddress::Nut(crate::ethereum_events::EthAddress(addr))
        })
    }

    /// NAM token address for testing
    pub fn nam() -> Address {
        Address::decode("tnam1q99c37u38grkdcc2qze0hz4zjjd8zr3yucd3mzgz")
            .expect("The token address decoding shouldn't fail")
    }

    /// BTC token address for testing
    pub fn btc() -> Address {
        Address::decode("tnam1qy7jxng788scr4fdqxqxtc2ze2guq5478cml9cd9")
            .expect("The token address decoding shouldn't fail")
    }

    /// ETH token address for testing
    pub fn eth() -> Address {
        Address::decode("tnam1qyr9vd8ltunq72qc7pk58v7jdsedt4mggqqpxs03")
            .expect("The token address decoding shouldn't fail")
    }

    /// DOT token address for testing
    pub fn dot() -> Address {
        Address::decode("tnam1qx6k4wau5t6m8g2hjq55fje2ynpvh5t27s8p3p0l")
            .expect("The token address decoding shouldn't fail")
    }

    /// Imaginary token address for testing
    pub fn schnitzel() -> Address {
        Address::decode("tnam1q9euzsu2qfv4y6p0dqaga20n0u0yp8c3ec006yg2")
            .expect("The token address decoding shouldn't fail")
    }

    /// Imaginary token address for testing
    pub fn apfel() -> Address {
        Address::decode("tnam1qxlmdmw2y6hzvjg34zca8r6d4s6zmtkhty8myzu4")
            .expect("The token address decoding shouldn't fail")
    }

    /// Imaginary token address for testing
    pub fn kartoffel() -> Address {
        Address::decode("tnam1q87teqzjytwa9xd9qk8u558xxnrwuzdjzs7zvhzr")
            .expect("The token address decoding shouldn't fail")
    }

    /// Imaginary eth address for testing
    pub const fn wnam() -> EthAddress {
        // "DEADBEEF DEADBEEF DEADBEEF DEADBEEF DEADBEEF"
        EthAddress([
            222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239, 222,
            173, 190, 239, 222, 173, 190, 239,
        ])
    }

    /// A hash map of tokens addresses with their informal currency codes and
    /// number of decimal places.
    pub fn tokens() -> HashMap<&'static str, Denomination> {
        vec![
            ("nam", 6.into()),
            ("btc", 8.into()),
            ("eth", 18.into()),
            ("dot", 10.into()),
            ("schnitzel", 6.into()),
            ("apfel", 6.into()),
            ("kartoffel", 6.into()),
        ]
        .into_iter()
        .collect()
    }
}
