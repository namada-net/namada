//! Cryptographic keys
use std::fmt::{self, Display};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::{HEXLOWER, HEXUPPER};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
#[cfg(any(test, feature = "rand"))]
use rand::{CryptoRng, RngCore};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::{
    ParsePublicKeyError, ParseSecretKeyError, ParseSignatureError, RefTo,
    SchemeType, SigScheme as SigSchemeTrait, VerifySigError, ed25519,
    secp256k1,
};
use crate::borsh::BorshSerializeExt;
use crate::ethereum_events::EthAddress;
use crate::key::{SignableBytes, StorageHasher};
use crate::{impl_display_and_from_str_via_format, string_encoding};

/// Public key
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub enum CommonPublicKey {
    /// Encapsulate Ed25519 public keys
    Ed25519(ed25519::PublicKey),
    /// Encapsulate Secp256k1 public keys
    Secp256k1(secp256k1::PublicKey),
}

/// Public key
pub type PublicKey = CommonPublicKey;

const ED25519_PK_PREFIX: &str = "ED25519_PK_PREFIX";
const SECP256K1_PK_PREFIX: &str = "SECP256K1_PK_PREFIX";

impl Serialize for PublicKey {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // String encoded, because toml doesn't support enums
        let prefix = match self {
            PublicKey::Ed25519(_) => ED25519_PK_PREFIX,
            PublicKey::Secp256k1(_) => SECP256K1_PK_PREFIX,
        };
        let keypair_string = format!("{}{}", prefix, self);
        Serialize::serialize(&keypair_string, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let keypair_string: String =
            serde::Deserialize::deserialize(deserializer)
                .map_err(D::Error::custom)?;
        if let Some(raw) = keypair_string.strip_prefix(ED25519_PK_PREFIX) {
            PublicKey::from_str(raw).map_err(D::Error::custom)
        } else if let Some(raw) =
            keypair_string.strip_prefix(SECP256K1_PK_PREFIX)
        {
            PublicKey::from_str(raw).map_err(D::Error::custom)
        } else {
            Err(D::Error::custom(
                "Could not deserialize SecretKey do to invalid prefix",
            ))
        }
    }
}

impl super::PublicKey for PublicKey {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_pk<PK: super::PublicKey>(
        pk: &PK,
    ) -> Result<Self, ParsePublicKeyError> {
        if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.serialize_to_vec().as_slice())
                .map_err(ParsePublicKeyError::InvalidEncoding)
        } else if PK::TYPE == ed25519::PublicKey::TYPE {
            Ok(Self::Ed25519(
                ed25519::PublicKey::try_from_slice(
                    pk.serialize_to_vec().as_slice(),
                )
                .map_err(ParsePublicKeyError::InvalidEncoding)?,
            ))
        } else if PK::TYPE == secp256k1::PublicKey::TYPE {
            Ok(Self::Secp256k1(
                secp256k1::PublicKey::try_from_slice(
                    pk.serialize_to_vec().as_slice(),
                )
                .map_err(ParsePublicKeyError::InvalidEncoding)?,
            ))
        } else {
            Err(ParsePublicKeyError::MismatchedScheme)
        }
    }
}

/// String decoding error
pub type DecodeError = string_encoding::DecodeError;

impl string_encoding::Format for PublicKey {
    type EncodedBytes<'a> = Vec<u8>;

    const HRP: string_encoding::Hrp =
        string_encoding::Hrp::parse_unchecked(string_encoding::COMMON_PK_HRP);

    fn to_bytes(&self) -> Vec<u8> {
        self.serialize_to_vec()
    }

    fn decode_bytes(
        bytes: &[u8],
    ) -> Result<Self, string_encoding::DecodeError> {
        BorshDeserialize::try_from_slice(bytes)
            .map_err(DecodeError::InvalidBytes)
    }
}

impl_display_and_from_str_via_format!(PublicKey);

impl From<PublicKey> for crate::tendermint::PublicKey {
    fn from(value: PublicKey) -> Self {
        use crate::tendermint::PublicKey as TmPK;
        match value {
            PublicKey::Ed25519(ed25519::PublicKey(pk)) => {
                TmPK::from_raw_ed25519(pk.as_bytes()).unwrap()
            }
            PublicKey::Secp256k1(secp256k1::PublicKey(pk)) => {
                TmPK::from_raw_secp256k1(&pk.to_sec1_bytes()).unwrap()
            }
        }
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum EthAddressConvError {
    #[error("Eth key cannot be ed25519, only secp256k1")]
    CannotBeEd25519,
}

impl TryFrom<&PublicKey> for EthAddress {
    type Error = EthAddressConvError;

    fn try_from(value: &PublicKey) -> Result<Self, Self::Error> {
        match value {
            PublicKey::Ed25519(_) => Err(EthAddressConvError::CannotBeEd25519),
            PublicKey::Secp256k1(pk) => Ok(EthAddress::from(pk)),
        }
    }
}

/// Secret key
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
#[allow(clippy::large_enum_variant)]
pub enum SecretKey {
    /// Encapsulate Ed25519 secret keys
    Ed25519(ed25519::SecretKey),
    /// Encapsulate Secp256k1 secret keys
    Secp256k1(secp256k1::SecretKey),
}

impl Serialize for SecretKey {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // String encoded, because toml doesn't support enums
        let prefix = match self {
            SecretKey::Ed25519(_) => "ED25519_SK_PREFIX",
            SecretKey::Secp256k1(_) => "SECP256K1_SK_PREFIX",
        };
        let keypair_string = format!("{}{}", prefix, self);
        Serialize::serialize(&keypair_string, serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let keypair_string: String =
            serde::Deserialize::deserialize(deserializer)
                .map_err(D::Error::custom)?;
        if let Some(raw) = keypair_string.strip_prefix("ED25519_SK_PREFIX") {
            SecretKey::from_str(raw).map_err(D::Error::custom)
        } else if let Some(raw) =
            keypair_string.strip_prefix("SECP256K1_SK_PREFIX")
        {
            SecretKey::from_str(raw).map_err(D::Error::custom)
        } else {
            Err(D::Error::custom(
                "Could not deserialize SecretKey do to invalid prefix",
            ))
        }
    }
}

impl SecretKey {
    /// Derive public key from this secret key
    pub fn to_public(&self) -> PublicKey {
        self.ref_to()
    }
}

impl super::SecretKey for SecretKey {
    type PublicKey = PublicKey;

    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_sk<SK: super::SecretKey>(
        sk: &SK,
    ) -> Result<Self, ParseSecretKeyError> {
        if SK::TYPE == Self::TYPE {
            Self::try_from_slice(sk.serialize_to_vec().as_ref())
                .map_err(ParseSecretKeyError::InvalidEncoding)
        } else if SK::TYPE == ed25519::SecretKey::TYPE {
            Ok(Self::Ed25519(
                ed25519::SecretKey::try_from_slice(
                    sk.serialize_to_vec().as_ref(),
                )
                .map_err(ParseSecretKeyError::InvalidEncoding)?,
            ))
        } else if SK::TYPE == secp256k1::SecretKey::TYPE {
            Ok(Self::Secp256k1(
                secp256k1::SecretKey::try_from_slice(
                    sk.serialize_to_vec().as_ref(),
                )
                .map_err(ParseSecretKeyError::InvalidEncoding)?,
            ))
        } else {
            Err(ParseSecretKeyError::MismatchedScheme)
        }
    }
}

impl RefTo<PublicKey> for SecretKey {
    fn ref_to(&self) -> PublicKey {
        match self {
            SecretKey::Ed25519(sk) => PublicKey::Ed25519(sk.ref_to()),
            SecretKey::Secp256k1(sk) => PublicKey::Secp256k1(sk.ref_to()),
        }
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.serialize_to_vec()))
    }
}

impl FromStr for SecretKey {
    type Err = ParseSecretKeyError;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let vec = HEXLOWER
            .decode(str.as_ref())
            .map_err(ParseSecretKeyError::InvalidHex)?;
        Self::try_from_slice(vec.as_slice())
            .map_err(ParseSecretKeyError::InvalidEncoding)
    }
}

/// Signature
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub enum CommonSignature {
    /// Encapsulate Ed25519 signatures
    Ed25519(ed25519::Signature),
    /// Encapsulate Secp256k1 signatures
    Secp256k1(secp256k1::Signature),
}

/// Signature
pub type Signature = CommonSignature;

impl string_encoding::Format for Signature {
    type EncodedBytes<'a> = Vec<u8>;

    const HRP: string_encoding::Hrp =
        string_encoding::Hrp::parse_unchecked(string_encoding::COMMON_SIG_HRP);

    fn to_bytes(&self) -> Vec<u8> {
        self.serialize_to_vec()
    }

    fn decode_bytes(
        bytes: &[u8],
    ) -> Result<Self, string_encoding::DecodeError> {
        BorshDeserialize::try_from_slice(bytes)
            .map_err(DecodeError::InvalidBytes)
    }
}

impl Serialize for CommonSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = HEXUPPER.encode(&self.serialize_to_vec());
        serializer.serialize_str(&hex_str)
    }
}

// Implement custom deserialization
impl<'de> Deserialize<'de> for CommonSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignatureVisitor;

        impl Visitor<'_> for SignatureVisitor {
            type Value = CommonSignature;

            fn expecting(
                &self,
                formatter: &mut fmt::Formatter<'_>,
            ) -> fmt::Result {
                formatter.write_str(
                    "a hex string representing either an Ed25519 or Secp256k1 \
                     signature",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let bytes =
                    HEXUPPER.decode(value.as_bytes()).map_err(E::custom)?;
                CommonSignature::try_from_slice(&bytes)
                    .map_err(|e| E::custom(e.to_string()))
            }
        }

        deserializer.deserialize_str(SignatureVisitor)
    }
}

impl_display_and_from_str_via_format!(Signature);

impl From<ed25519::Signature> for Signature {
    fn from(sig: ed25519::Signature) -> Self {
        Signature::Ed25519(sig)
    }
}

impl From<secp256k1::Signature> for Signature {
    fn from(sig: secp256k1::Signature) -> Self {
        Signature::Secp256k1(sig)
    }
}

impl super::Signature for Signature {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_sig<SIG: super::Signature>(
        sig: &SIG,
    ) -> Result<Self, ParseSignatureError> {
        if SIG::TYPE == Self::TYPE {
            Self::try_from_slice(sig.serialize_to_vec().as_slice())
                .map_err(ParseSignatureError::InvalidEncoding)
        } else if SIG::TYPE == ed25519::Signature::TYPE {
            Ok(Self::Ed25519(
                ed25519::Signature::try_from_slice(
                    sig.serialize_to_vec().as_slice(),
                )
                .map_err(ParseSignatureError::InvalidEncoding)?,
            ))
        } else if SIG::TYPE == secp256k1::Signature::TYPE {
            Ok(Self::Secp256k1(
                secp256k1::Signature::try_from_slice(
                    sig.serialize_to_vec().as_slice(),
                )
                .map_err(ParseSignatureError::InvalidEncoding)?,
            ))
        } else {
            Err(ParseSignatureError::MismatchedScheme)
        }
    }
}

/// An implementation of the common signature scheme
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
    Default,
)]
pub struct SigScheme;

impl super::SigScheme for SigScheme {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;

    const TYPE: SchemeType = SchemeType::Common;

    #[cfg(any(test, feature = "rand"))]
    fn generate<R>(_csprng: &mut R) -> SecretKey
    where
        R: CryptoRng + RngCore,
    {
        panic!(
            "Cannot generate common signing scheme. Must convert from \
             alternative scheme."
        );
    }

    fn from_bytes(_seed: [u8; 32]) -> Self::SecretKey {
        unimplemented!(
            "Cannot generate common signing scheme. Must convert from \
             alternative scheme."
        );
    }

    fn sign_with_hasher<H>(
        keypair: &SecretKey,
        data: impl super::SignableBytes,
    ) -> Self::Signature
    where
        H: 'static + StorageHasher,
    {
        match keypair {
            SecretKey::Ed25519(kp) => Signature::Ed25519(
                ed25519::SigScheme::sign_with_hasher::<H>(kp, data),
            ),
            SecretKey::Secp256k1(kp) => Signature::Secp256k1(
                secp256k1::SigScheme::sign_with_hasher::<H>(kp, data),
            ),
        }
    }

    fn verify_signature_with_hasher<H>(
        pk: &Self::PublicKey,
        data: &impl SignableBytes,
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError>
    where
        H: 'static + StorageHasher,
    {
        match (pk, sig) {
            (PublicKey::Ed25519(pk), Signature::Ed25519(sig)) => {
                ed25519::SigScheme::verify_signature_with_hasher::<H>(
                    pk, data, sig,
                )
            }
            (PublicKey::Secp256k1(pk), Signature::Secp256k1(sig)) => {
                secp256k1::SigScheme::verify_signature_with_hasher::<H>(
                    pk, data, sig,
                )
            }
            _ => Err(VerifySigError::MismatchedScheme),
        }
    }

    fn mock(keypair: &SecretKey) -> Self::Signature {
        match keypair {
            SecretKey::Ed25519(kp) => {
                Signature::Ed25519(ed25519::SigScheme::mock(kp))
            }
            SecretKey::Secp256k1(kp) => {
                Signature::Secp256k1(secp256k1::SigScheme::mock(kp))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `cargo test gen_ed25519_keypair -- --nocapture` to generate a
    /// new ed25519 keypair wrapped in `common` key types.
    #[test]
    fn gen_ed25519_keypair() {
        let secret_key =
            SecretKey::Ed25519(crate::key::testing::gen_keypair::<
                ed25519::SigScheme,
            >());
        let public_key = secret_key.to_public();
        println!("Public key: {}", public_key);
        println!("Secret key: {}", secret_key);
    }
}
