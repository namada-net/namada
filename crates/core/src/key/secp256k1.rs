//! secp256k1 keys and related functionality

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::{Debug, Display};
use std::hash::{Hash, Hasher};
use std::io::{ErrorKind, Read, Write};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::HEXLOWER;
use ethabi::Token;
use k256::ecdsa::RecoveryId;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
#[cfg(any(test, feature = "rand"))]
use rand::{CryptoRng, RngCore};
use serde::de::{Error, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Serialize, Serializer};

use super::{
    ParsePublicKeyError, ParseSecretKeyError, ParseSignatureError, RefTo,
    SchemeType, SigScheme as SigSchemeTrait, SignableBytes, VerifySigError,
};
use crate::borsh::BorshSerializeExt;
use crate::eth_abi::Encode;
use crate::ethereum_events::EthAddress;
use crate::key::StorageHasher;

/// The provided constant is for a traditional
/// signature on this curve. For Ethereum, an extra byte is included
/// that prevents malleability attacks.
pub const SIGNATURE_SIZE: usize = 64 + 1;

/// secp256k1 public key
#[derive(
    Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshDeserializer,
)]
pub struct PublicKey(pub k256::PublicKey);

/// Size of a compressed public key bytes
const COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;
/// Size of a secret key bytes
pub(crate) const SECRET_KEY_SIZE: usize = 32;

impl super::PublicKey for PublicKey {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_pk<PK: super::PublicKey>(
        pk: &PK,
    ) -> Result<Self, ParsePublicKeyError> {
        if PK::TYPE == super::common::PublicKey::TYPE {
            super::common::PublicKey::try_from_pk(pk).and_then(|x| match x {
                super::common::PublicKey::Secp256k1(epk) => Ok(epk),
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
        // deserialize the bytes first
        let mut key_buf = [0u8; COMPRESSED_PUBLIC_KEY_SIZE];
        reader.read_exact(&mut key_buf[..])?;
        let pk = k256::PublicKey::from_sec1_bytes(&key_buf).map_err(|e| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("Error decoding secp256k1 public key: {}", e),
            )
        })?;
        Ok(PublicKey(pk))
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_sec1_bytes())?;
        Ok(())
    }
}

impl BorshSchema for PublicKey {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        // Encoded as `[u8; COMPRESSED_PUBLIC_KEY_SIZE]`
        let elements = "u8".into();
        let length = COMPRESSED_PUBLIC_KEY_SIZE as u64;
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
        "secp256k1::PublicKey".into()
    }
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_sec1_bytes().hash(state);
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_sec1_bytes().cmp(&other.0.to_sec1_bytes())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0.to_sec1_bytes()))
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = HEXLOWER
            .decode(s.as_bytes())
            .map_err(ParsePublicKeyError::InvalidHex)?;
        BorshDeserialize::try_from_slice(&vec)
            .map_err(ParsePublicKeyError::InvalidEncoding)
    }
}

impl From<k256::PublicKey> for PublicKey {
    fn from(pk: k256::PublicKey) -> Self {
        Self(pk)
    }
}

impl From<&PublicKey> for EthAddress {
    fn from(pk: &PublicKey) -> Self {
        use tiny_keccak::Hasher;

        let mut hasher = tiny_keccak::Keccak::v256();
        let pk_bytes = &pk.0.to_encoded_point(false).to_bytes()[1..];
        hasher.update(pk_bytes);
        let mut output = [0_u8; 32];
        hasher.finalize(&mut output);
        let mut addr = [0; 20];
        addr.copy_from_slice(&output[12..]);
        EthAddress(addr)
    }
}

/// Secp256k1 secret key
#[derive(Debug, Clone, BorshDeserializer)]
pub struct SecretKey(pub Box<k256::SecretKey>);

impl super::SecretKey for SecretKey {
    type PublicKey = PublicKey;

    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_sk<PK: super::SecretKey>(
        pk: &PK,
    ) -> Result<Self, ParseSecretKeyError> {
        if PK::TYPE == super::common::SecretKey::TYPE {
            super::common::SecretKey::try_from_sk(pk).and_then(|x| match x {
                super::common::SecretKey::Secp256k1(epk) => Ok(epk),
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

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let arr: [u8; SECRET_KEY_SIZE] = self.0.to_bytes().into();
        serde::Serialize::serialize(&arr, serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let arr_res: [u8; SECRET_KEY_SIZE] =
            serde::Deserialize::deserialize(deserializer)?;
        let key =
            k256::SecretKey::from_slice(&arr_res).map_err(D::Error::custom);
        Ok(SecretKey(Box::new(key.unwrap())))
    }
}

impl BorshDeserialize for SecretKey {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        // deserialize the bytes first
        let bytes: [u8; SECRET_KEY_SIZE] =
            BorshDeserialize::deserialize_reader(reader)?;
        let sk = k256::SecretKey::from_slice(&bytes).map_err(|e| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("Error decoding secp256k1 secret key: {}", e),
            )
        })?;
        Ok(SecretKey(Box::new(sk)))
    }
}

impl BorshSerialize for SecretKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let bytes: [u8; SECRET_KEY_SIZE] = self.0.to_bytes().into();
        BorshSerialize::serialize(&bytes, writer)
    }
}

impl BorshSchema for SecretKey {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        // Encoded as `[u8; SECRET_KEY_SIZE]`
        let elements = "u8".into();
        let length = SECRET_KEY_SIZE as u64;
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
        "secp256k1::SecretKey".into()
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXLOWER.encode(self.0.to_bytes().as_ref()))
    }
}

impl FromStr for SecretKey {
    type Err = ParseSecretKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = HEXLOWER
            .decode(s.as_bytes())
            .map_err(ParseSecretKeyError::InvalidHex)?;
        BorshDeserialize::try_from_slice(&vec)
            .map_err(ParseSecretKeyError::InvalidEncoding)
    }
}

impl RefTo<PublicKey> for SecretKey {
    fn ref_to(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }
}

/// Secp256k1 signature
#[derive(Clone, Debug, Eq, PartialEq, BorshDeserializer)]
pub struct Signature(pub k256::ecdsa::Signature, pub RecoveryId);

impl super::Signature for Signature {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_sig<PK: super::Signature>(
        pk: &PK,
    ) -> Result<Self, ParseSignatureError> {
        if PK::TYPE == super::common::Signature::TYPE {
            super::common::Signature::try_from_sig(pk).and_then(|x| match x {
                super::common::Signature::Secp256k1(epk) => Ok(epk),
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

// NB: `RecoveryId` does not implement `serde` traits, so we can't derive them
// either
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(2)?;

        seq.serialize_element(&self.0)?;
        seq.serialize_element(&self.1.to_byte())?;

        seq.end()
    }
}

// NB: `RecoveryId` does not implement `serde` traits, so we can't derive them
// either
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SigVisitor;

        impl<'de> Visitor<'de> for SigVisitor {
            type Value = Signature;

            fn expecting(
                &self,
                formatter: &mut fmt::Formatter<'_>,
            ) -> fmt::Result {
                formatter.write_str("a secp256k1 signature")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Signature, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let inner_sig: k256::ecdsa::Signature = seq
                    .next_element()?
                    .ok_or_else(|| Error::custom("Missing inner signature"))?;
                let recovery_id = seq.next_element()?.ok_or_else(|| {
                    Error::custom("Missing signature recovery id")
                })?;

                let recovery_id = RecoveryId::from_byte(recovery_id)
                    .ok_or_else(|| {
                        Error::custom("Invalid signature recovery id")
                    })?;

                Ok(Signature(inner_sig, recovery_id))
            }
        }

        deserializer.deserialize_tuple(2, SigVisitor)
    }
}

impl BorshDeserialize for Signature {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        // deserialize the bytes first
        let (sig_bytes, recovery_id): ([u8; 64], u8) =
            BorshDeserialize::deserialize_reader(reader)?;

        Ok(Signature(
            k256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding secp256k1 signature: {}", e),
                )
            })?,
            RecoveryId::from_byte(recovery_id).ok_or_else(|| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "Error decoding secp256k1 signature recovery byte",
                )
            })?,
        ))
    }
}

impl BorshSerialize for Signature {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let sig_bytes: [u8; 64] = self.0.to_bytes().into();
        BorshSerialize::serialize(&(sig_bytes, self.1.to_byte()), writer)
    }
}

impl BorshSchema for Signature {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        // Encoded as `([u8; SIGNATURE_SIZE], u8)`
        let signature = <[u8; SIGNATURE_SIZE]>::declaration();
        <[u8; SIGNATURE_SIZE]>::add_definitions_recursively(definitions);
        let recovery = "u8".into();
        let definition = borsh::schema::Definition::Tuple {
            elements: vec![signature, recovery],
        };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        "secp256k1::Signature".into()
    }
}

impl Signature {
    /// OpenZeppelin consumes v values in the range [27, 28],
    /// rather than [0, 1], the latter returned by `k256`.
    const V_FIX: u8 = 27;

    /// Given a v signature parameter, flip its value
    /// (i.e. negate the input).
    ///
    /// __INVARIANT__: The value of `v` must be in the range [0, 1].
    #[inline(always)]
    fn flip_v(v: u8) -> u8 {
        debug_assert!(v == 0 || v == 1);
        v ^ 1
    }

    /// Returns the `r`, `s` and `v` parameters of this [`Signature`],
    /// destroying the original value in the process.
    ///
    /// The returned signature is unique (i.e. non-malleable). This
    /// ensures OpenZeppelin considers the signature valid.
    pub fn into_eth_rsv(self) -> ([u8; 32], [u8; 32], u8) {
        // A recovery id (dubbed v) is used by secp256k1 signatures
        // to signal verifying code if a signature had been malleable
        // or not (based on whether the s field of the signature was odd
        // or not). In the `k256` dependency, the low-bit signifies the
        // y-coordinate, associated with s, being odd.
        let v = self.1.to_byte() & 1;
        // Check if s needs to be normalized. In case it does,
        // we must flip the value of v (e.g. 0 -> 1).
        let (s, v) = if let Some(signature) = self.0.normalize_s() {
            let normalized_s = signature.s();
            (normalized_s, Self::flip_v(v))
        } else {
            (self.0.s(), v)
        };
        let r = self.0.r();
        // Cannot overflow as `v` is 0 or 1
        #[allow(clippy::arithmetic_side_effects)]
        let v = v + Self::V_FIX;
        (r.to_bytes().into(), s.to_bytes().into(), v)
    }
}

impl Encode<1> for Signature {
    fn tokenize(&self) -> [Token; 1] {
        let (r, s, v) = self.clone().into_eth_rsv();
        let r = Token::FixedBytes(r.to_vec());
        let s = Token::FixedBytes(s.to_vec());
        let v = Token::Uint(v.into());
        [Token::Tuple(vec![r, s, v])]
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
        match self.0.to_bytes().cmp(&other.0.to_bytes()) {
            Ordering::Equal => self.1.cmp(&other.1),
            res => res,
        }
    }
}

impl TryFrom<&[u8; 65]> for Signature {
    type Error = ParseSignatureError;

    fn try_from(sig: &[u8; 65]) -> Result<Self, Self::Error> {
        let recovery_id = RecoveryId::from_byte(sig[64]).ok_or_else(|| {
            ParseSignatureError::InvalidEncoding(std::io::Error::other(
                "Invalid recovery byte",
            ))
        })?;
        let sig =
            k256::ecdsa::Signature::from_slice(&sig[..64]).map_err(|err| {
                ParseSignatureError::InvalidEncoding(std::io::Error::other(err))
            })?;
        Ok(Self(sig, recovery_id))
    }
}

/// An implementation of the Secp256k1 signature scheme
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

    const TYPE: SchemeType = SchemeType::Secp256k1;

    #[cfg(any(test, feature = "rand"))]
    fn generate<R>(csprng: &mut R) -> SecretKey
    where
        R: CryptoRng + RngCore,
    {
        SecretKey(Box::new(k256::SecretKey::random(csprng)))
    }

    fn from_bytes(sk: [u8; 32]) -> SecretKey {
        SecretKey(Box::new(
            k256::SecretKey::from_slice(&sk)
                .expect("Secret key parsing should not fail."),
        ))
    }

    fn sign_with_hasher<H>(
        keypair: &SecretKey,
        data: impl SignableBytes,
    ) -> Self::Signature
    where
        H: 'static + StorageHasher,
    {
        let sig_key = k256::ecdsa::SigningKey::from(keypair.0.as_ref());
        let msg = data.signable_hash::<H>();
        let (sig, recovery_id) = sig_key
            .sign_prehash_recoverable(&msg)
            .expect("Must be able to sign");
        Signature(sig, recovery_id)
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
            use k256::ecdsa::signature::hazmat::PrehashVerifier;

            let vrf_key = k256::ecdsa::VerifyingKey::from(&pk.0);
            let msg = data.signable_hash::<H>();
            vrf_key.verify_prehash(&msg, &sig.0).map_err(|e| {
                VerifySigError::SigVerifyError(format!(
                    "Error verifying secp256k1 signature: {}",
                    e
                ))
            })
        }

        #[cfg(fuzzing)]
        {
            let _ = (pk, data, sig);
            Ok(())
        }
    }

    fn mock(_: &Self::SecretKey) -> Self::Signature {
        Signature(
            k256::ecdsa::Signature::from_scalars(
                k256::Scalar::ONE,
                k256::Scalar::ONE,
            )
            .unwrap(),
            RecoveryId::from_byte(0).unwrap(),
        )
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PublicKey {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'_>,
    ) -> arbitrary::Result<Self> {
        use rand::SeedableRng;
        let seed: [u8; 32] = arbitrary::Arbitrary::arbitrary(u)?;
        Ok(Self(
            k256::SecretKey::random(&mut rand::rngs::StdRng::from_seed(seed))
                .public_key(),
        ))
    }

    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        // StdRng seed len
        (32, Some(32))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Signature {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'_>,
    ) -> arbitrary::Result<Self> {
        use rand::SeedableRng;
        let seed: [u8; 32] = arbitrary::Arbitrary::arbitrary(u)?;
        let sk =
            k256::SecretKey::random(&mut rand::rngs::StdRng::from_seed(seed));
        let sig_key = k256::ecdsa::SigningKey::from(&sk);
        let (sig, recovery_id) = sig_key
            .sign_prehash_recoverable(&[0_u8; 32])
            .expect("Must be able to sign");
        Ok(Self(sig, recovery_id))
    }

    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        // StdRng seed len
        (32, Some(32))
    }
}

#[cfg(test)]
mod test {

    use super::*;

    /// test vector from https://bitcoin.stackexchange.com/a/89848
    const SECRET_KEY_HEX: &str =
        "c2c72dfbff11dfb4e9d5b0a20c620c58b15bb7552753601f043db91331b0db15";

    /// Test that we can recover an Ethereum address from
    /// a public secp key.
    #[test]
    fn test_eth_address_from_secp() {
        let expected_pk_hex = "a225bf565ff4ea039bccba3e26456e910cd74e4616d67ee0a166e26da6e5e55a08d0fa1659b4b547ba7139ca531f62907b9c2e72b80712f1c81ece43c33f4b8b";
        let expected_eth_addr_hex = "6ea27154616a29708dce7650b475dd6b82eba6a3";

        let sk_bytes = HEXLOWER.decode(SECRET_KEY_HEX.as_bytes()).unwrap();
        let sk = SecretKey::try_from_slice(&sk_bytes[..]).unwrap();
        let pk: PublicKey = sk.ref_to();
        // We're removing the first byte with tag
        let pk_hex =
            HEXLOWER.encode(&pk.0.to_encoded_point(false).to_bytes()[1..]);
        assert_eq!(expected_pk_hex, pk_hex);

        let eth_addr: EthAddress = (&pk).into();
        let eth_addr_hex = HEXLOWER.encode(&eth_addr.0[..]);
        assert_eq!(expected_eth_addr_hex, eth_addr_hex);
    }

    /// Test serializing and then de-serializing a signature
    /// with Serde is idempotent.
    #[test]
    fn test_roundtrip_serde() {
        let sk_bytes = HEXLOWER.decode(SECRET_KEY_HEX.as_bytes()).unwrap();
        let sk = SecretKey::try_from_slice(&sk_bytes[..]).unwrap();
        let to_sign = "test".as_bytes();
        let mut signature = SigScheme::sign(&sk, to_sign);
        signature.1 = RecoveryId::from_byte(3).expect("Test failed");
        let sig_json = serde_json::to_string(&signature).expect("Test failed");
        let sig: Signature =
            serde_json::from_str(&sig_json).expect("Test failed");
        assert_eq!(sig, signature)
    }

    /// Test serializing and then de-serializing a signature
    /// with Borsh is idempotent.
    #[test]
    fn test_roundtrip_borsh() {
        let sk_bytes = HEXLOWER.decode(SECRET_KEY_HEX.as_bytes()).unwrap();
        let sk = SecretKey::try_from_slice(&sk_bytes[..]).unwrap();
        let to_sign = "test".as_bytes();
        let mut signature = SigScheme::sign(&sk, to_sign);
        signature.1 = RecoveryId::from_byte(3).expect("Test failed");
        let sig_bytes = signature.serialize_to_vec();
        let sig = Signature::try_from_slice(sig_bytes.as_slice())
            .expect("Test failed");
        assert_eq!(sig, signature);
    }
}
