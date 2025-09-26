//! Ed25519 keys and related functionality

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::HEXLOWER;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
#[cfg(any(test, feature = "rand"))]
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    ParsePublicKeyError, ParseSecretKeyError, ParseSignatureError, RefTo,
    SchemeType, SigScheme as SigSchemeTrait, SignableBytes, VerifySigError,
};
use crate::borsh::BorshSerializeExt;
use crate::key::StorageHasher;

const PUBLIC_KEY_LENGTH: usize = 32;
const SECRET_KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;

/// Ed25519 public key
#[derive(
    Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshDeserializer,
)]
pub struct PublicKey(pub ed25519_consensus::VerificationKey);

impl super::PublicKey for PublicKey {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_pk<PK: super::PublicKey>(
        pk: &PK,
    ) -> Result<Self, ParsePublicKeyError> {
        if PK::TYPE == super::common::PublicKey::TYPE {
            super::common::PublicKey::try_from_pk(pk).and_then(|x| match x {
                super::common::PublicKey::Ed25519(epk) => Ok(epk),
                _ => Err(ParsePublicKeyError::MismatchedScheme),
            })
        } else if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.serialize_to_vec().as_slice())
                .map_err(ParsePublicKeyError::InvalidEncoding)
        } else {
            Err(ParsePublicKeyError::MismatchedScheme)
        }
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(PublicKey(
            ed25519_consensus::VerificationKey::try_from(
                <[u8; PUBLIC_KEY_LENGTH] as BorshDeserialize>::deserialize_reader(
                    reader,
                )?
                    .as_ref(),
            )
                .map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
                })?,
        ))
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0.to_bytes(), writer)
    }
}

impl BorshSchema for PublicKey {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        // Encoded as `[u8; PUBLIC_KEY_LENGTH]`
        let elements = "u8".into();
        let length = PUBLIC_KEY_LENGTH as u64;
        // let definition = borsh::schema::Definition::Array { elements, length
        // };
        let definition = borsh::schema::Definition::Sequence {
            length_width: 0,
            length_range: 0..=length,
            elements,
        };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        "ed25519::PublicKey".into()
    }
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0.to_bytes()))
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = HEXLOWER
            .decode(s.as_ref())
            .map_err(ParsePublicKeyError::InvalidHex)?;
        BorshDeserialize::try_from_slice(&vec)
            .map_err(ParsePublicKeyError::InvalidEncoding)
    }
}

/// Ed25519 secret key
#[derive(
    Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, BorshDeserializer,
)]
pub struct SecretKey(pub Box<ed25519_consensus::SigningKey>);

impl super::SecretKey for SecretKey {
    type PublicKey = PublicKey;

    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_sk<PK: super::SecretKey>(
        pk: &PK,
    ) -> Result<Self, ParseSecretKeyError> {
        if PK::TYPE == super::common::SecretKey::TYPE {
            super::common::SecretKey::try_from_sk(pk).and_then(|x| match x {
                super::common::SecretKey::Ed25519(epk) => Ok(epk),
                _ => Err(ParseSecretKeyError::MismatchedScheme),
            })
        } else if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.serialize_to_vec().as_slice())
                .map_err(ParseSecretKeyError::InvalidEncoding)
        } else {
            Err(ParseSecretKeyError::MismatchedScheme)
        }
    }
}

impl RefTo<PublicKey> for SecretKey {
    fn ref_to(&self) -> PublicKey {
        PublicKey(self.0.verification_key())
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> SecretKey {
        SecretKey(Box::new(ed25519_consensus::SigningKey::from(
            self.0.to_bytes(),
        )))
    }
}

impl BorshDeserialize for SecretKey {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(SecretKey(Box::new(
            ed25519_consensus::SigningKey::try_from(
                <[u8; SECRET_KEY_LENGTH] as BorshDeserialize>::deserialize_reader(
                    reader,
                )?
                    .as_ref(),
            )
                .map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
                })?,
        )))
    }
}

impl BorshSerialize for SecretKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0.to_bytes(), writer)
    }
}

impl BorshSchema for SecretKey {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        // Encoded as `[u8; SECRET_KEY_LENGTH]`
        let elements = "u8".into();
        let length = SECRET_KEY_LENGTH as u64;
        // let definition = borsh::schema::Definition::Array { elements, length
        // };
        let definition = borsh::schema::Definition::Sequence {
            length_width: 0,
            length_range: 0..=length,
            elements,
        };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        "ed25519::SecretKey".into()
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0.to_bytes()))
    }
}

impl FromStr for SecretKey {
    type Err = ParseSecretKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = HEXLOWER
            .decode(s.as_ref())
            .map_err(ParseSecretKeyError::InvalidHex)?;
        BorshDeserialize::try_from_slice(&vec)
            .map_err(ParseSecretKeyError::InvalidEncoding)
    }
}

/// Ed25519 signature
#[derive(
    Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshDeserializer,
)]
pub struct Signature(pub ed25519_consensus::Signature);

impl super::Signature for Signature {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_sig<PK: super::Signature>(
        pk: &PK,
    ) -> Result<Self, ParseSignatureError> {
        if PK::TYPE == super::common::Signature::TYPE {
            super::common::Signature::try_from_sig(pk).and_then(|x| match x {
                super::common::Signature::Ed25519(epk) => Ok(epk),
                _ => Err(ParseSignatureError::MismatchedScheme),
            })
        } else if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.serialize_to_vec().as_slice())
                .map_err(ParseSignatureError::InvalidEncoding)
        } else {
            Err(ParseSignatureError::MismatchedScheme)
        }
    }
}

impl BorshDeserialize for Signature {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(Signature(
            ed25519_consensus::Signature::try_from(
                <[u8; SIGNATURE_LENGTH] as BorshDeserialize>::deserialize_reader(reader)?
                    .as_ref(),
            )
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
            })?,
        ))
    }
}

impl BorshSerialize for Signature {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.to_bytes().serialize(writer)
    }
}

impl BorshSchema for Signature {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        // Encoded as `[u8; SIGNATURE_LENGTH]`
        let elements = "u8".into();
        let length = SIGNATURE_LENGTH as u64;
        // let definition = borsh::schema::Definition::Array { elements, length
        // };
        let definition = borsh::schema::Definition::Sequence {
            length_width: 0,
            length_range: 0..=length,
            elements,
        };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        "ed25519::Signature".into()
    }
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

/// An implementation of the Ed25519 signature scheme
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
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

    const TYPE: SchemeType = SchemeType::Ed25519;

    #[cfg(any(test, feature = "rand"))]
    fn generate<R>(csprng: &mut R) -> SecretKey
    where
        R: CryptoRng + RngCore,
    {
        SecretKey(Box::new(ed25519_consensus::SigningKey::new(csprng)))
    }

    fn from_bytes(bytes: [u8; 32]) -> SecretKey {
        SecretKey(Box::new(ed25519_consensus::SigningKey::from(bytes)))
    }

    fn sign_with_hasher<H>(
        keypair: &SecretKey,
        data: impl SignableBytes,
    ) -> Self::Signature
    where
        H: 'static + StorageHasher,
    {
        Signature(keypair.0.sign(&data.signable_hash::<H>()))
    }

    fn verify_signature_with_hasher<H>(
        pk: &Self::PublicKey,
        data: &impl SignableBytes,
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError>
    where
        H: 'static + StorageHasher,
    {
        #[cfg(not(fuzzing))]
        {
            pk.0.verify(&sig.0, &data.signable_hash::<H>())
                .map_err(|err| VerifySigError::SigVerifyError(err.to_string()))
        }

        #[cfg(fuzzing)]
        {
            let _ = (pk, data, sig);
            Ok(())
        }
    }

    fn mock(_: &Self::SecretKey) -> Self::Signature {
        Signature(ed25519_consensus::Signature::from([0; 64]))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PublicKey {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'_>,
    ) -> arbitrary::Result<Self> {
        let seed: [u8; 32] = arbitrary::Arbitrary::arbitrary(u)?;
        let sk = ed25519_consensus::SigningKey::from(seed);
        Ok(Self(sk.verification_key()))
    }

    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        // Signing key seed size
        (32, Some(32))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Signature {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'_>,
    ) -> arbitrary::Result<Self> {
        let seed: [u8; 32] = arbitrary::Arbitrary::arbitrary(u)?;
        let sk = ed25519_consensus::SigningKey::from(seed);
        Ok(Self(sk.sign(&[0_u8])))
    }

    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        // Signing key seed size
        (32, Some(32))
    }
}
