use std::collections::BTreeMap;
use std::hash::Hash;

use masp_primitives::transaction::Transaction;
use masp_primitives::transaction::builder::Builder;
use masp_primitives::transaction::components::sapling::builder::SaplingMetadata;
use masp_primitives::zip32::ExtendedFullViewingKey;
use namada_account::AccountPublicKeysMap;
use namada_account::common::SignOrMockKey;
use namada_core::address::Address;
use namada_core::borsh::{
    self, BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
};
use namada_core::chain::ChainId;
use namada_core::collections::HashSet;
use namada_core::key::*;
use namada_core::masp::{AssetData, MaspTxId};
use namada_core::time::DateTimeUtc;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::data::protocol::ProtocolTx;
use crate::data::{TxType, WrapperTx, hash_tx};
use crate::sign::VerifySigError;
use crate::{SALT_LENGTH, Tx, hex_data_serde, hex_salt_serde};

/// A section of a transaction. Carries an independent piece of information
/// necessary for the processing of a transaction.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
    PartialEq,
)]
pub enum Section {
    /// Transaction data that needs to be sent to hardware wallets
    Data(Data),
    /// Transaction data that does not need to be sent to hardware wallets
    ExtraData(Code),
    /// Transaction code. Sending to hardware wallets optional
    Code(Code),
    /// A transaction header/protocol signature
    Authorization(Authorization),
    /// Embedded MASP transaction section
    #[serde(
        serialize_with = "borsh_serde::<TransactionSerde, _>",
        deserialize_with = "serde_borsh::<TransactionSerde, _, _>"
    )]
    MaspTx(Transaction),
    /// A section providing the auxiliary inputs used to construct a MASP
    /// transaction. Only send to wallet, never send to protocol.
    MaspBuilder(MaspBuilder),
    /// Wrap a header with a section for the purposes of computing hashes
    Header(Header),
}

/// A Namada transaction header indicating where transaction subcomponents can
/// be found
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
    PartialEq,
)]
pub struct Header {
    /// The chain which this transaction is being submitted to
    pub chain_id: ChainId,
    /// The time at which this transaction expires
    pub expiration: Option<DateTimeUtc>,
    /// A transaction timestamp
    pub timestamp: DateTimeUtc,
    /// The commitments to the transaction's sections
    pub batch: HashSet<TxCommitments>,
    /// Whether the inner txs should be executed atomically
    pub atomic: bool,
    /// The type of this transaction
    pub tx_type: TxType,
}

impl Header {
    /// Make a new header of the given transaction type
    pub fn new(tx_type: TxType) -> Self {
        Self {
            tx_type,
            chain_id: ChainId::default(),
            expiration: None,
            #[allow(clippy::disallowed_methods)]
            timestamp: DateTimeUtc::now(),
            batch: Default::default(),
            atomic: Default::default(),
        }
    }

    /// Get the hash of this transaction header.
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.serialize_to_vec());
        hasher
    }

    /// Get the wrapper header if it is present
    pub fn wrapper(&self) -> Option<WrapperTx> {
        if let TxType::Wrapper(wrapper) = &self.tx_type {
            Some(*wrapper.clone())
        } else {
            None
        }
    }

    /// Get the protocol header if it is present
    pub fn protocol(&self) -> Option<ProtocolTx> {
        if let TxType::Protocol(protocol) = &self.tx_type {
            Some(*protocol.clone())
        } else {
            None
        }
    }
}

impl Section {
    /// Hash this section. Section hashes are useful for signatures and also for
    /// allowing transaction sections to cross reference.
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        // Get the index corresponding to this variant
        let discriminant = self.serialize_to_vec()[0];
        // Use Borsh's discriminant in the Section's hash
        hasher.update([discriminant]);
        match self {
            Self::Data(data) => data.hash(hasher),
            Self::ExtraData(extra) => extra.hash(hasher),
            Self::Code(code) => code.hash(hasher),
            Self::Authorization(signature) => signature.hash(hasher),
            Self::MaspBuilder(mb) => mb.hash(hasher),
            Self::MaspTx(tx) => {
                hasher.update(tx.serialize_to_vec());
                hasher
            }
            Self::Header(header) => header.hash(hasher),
        }
    }

    /// Get the hash of this section
    pub fn get_hash(&self) -> namada_core::hash::Hash {
        namada_core::hash::Hash(
            self.hash(&mut Sha256::new()).finalize_reset().into(),
        )
    }

    /// Extract the data from this section if possible
    pub fn data(&self) -> Option<Data> {
        if let Self::Data(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }

    /// Extract the extra data from this section if possible
    pub fn extra_data_sec(&self) -> Option<Code> {
        if let Self::ExtraData(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }

    /// Extract the extra data from this section if possible
    pub fn extra_data(&self) -> Option<Vec<u8>> {
        if let Self::ExtraData(data) = self {
            data.code.id()
        } else {
            None
        }
    }

    /// Extract the code from this section is possible
    pub fn code_sec(&self) -> Option<Code> {
        if let Self::Code(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }

    /// Extract the code from this section is possible
    pub fn code(&self) -> Option<Vec<u8>> {
        if let Self::Code(data) = self {
            data.code.id()
        } else {
            None
        }
    }

    /// Extract the signature from this section if possible
    pub fn signature(&self) -> Option<Authorization> {
        if let Self::Authorization(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }

    /// Extract the MASP transaction from this section if possible
    pub fn masp_tx(&self) -> Option<Transaction> {
        if let Self::MaspTx(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }

    /// Extract the MASP builder from this section if possible
    pub fn masp_builder(&self) -> Option<MaspBuilder> {
        if let Self::MaspBuilder(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }
}

/// A section representing transaction data
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct Data {
    /// Salt with additional random data (usually a timestamp)
    #[serde(with = "hex_salt_serde")]
    pub salt: [u8; SALT_LENGTH],
    /// Data bytes
    #[serde(with = "hex_data_serde")]
    pub data: Vec<u8>,
}

impl PartialEq for Data {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Data {
    /// Make a new data section with the given bytes
    pub fn new(data: Vec<u8>) -> Self {
        use rand_core::{OsRng, RngCore};

        Self {
            salt: {
                let mut buf = [0; SALT_LENGTH];
                OsRng.fill_bytes(&mut buf);
                buf
            },
            data,
        }
    }

    /// Hash this data section
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.serialize_to_vec());
        hasher
    }
}

/// Represents either some code bytes or their SHA-256 hash
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub enum Commitment {
    /// Result of applying hash function to bytes
    Hash(namada_core::hash::Hash),
    /// Result of applying identity function to bytes
    Id(Vec<u8>),
}

impl PartialEq for Commitment {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Commitment {
    /// Return the contained hash commitment
    pub fn hash(&self) -> namada_core::hash::Hash {
        match self {
            Self::Id(code) => hash_tx(code),
            Self::Hash(hash) => *hash,
        }
    }

    /// Return the result of applying identity function if there is any
    pub fn id(&self) -> Option<Vec<u8>> {
        if let Self::Id(code) = self {
            Some(code.clone())
        } else {
            None
        }
    }
}

/// A section representing transaction code
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct Code {
    /// Additional random data
    #[serde(with = "hex_salt_serde")]
    pub salt: [u8; SALT_LENGTH],
    /// Actual transaction code
    pub code: Commitment,
    /// The tag for the transaction code
    pub tag: Option<String>,
}

impl PartialEq for Code {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
    }
}

impl Code {
    /// Make a new code section with the given bytes
    pub fn new(code: Vec<u8>, tag: Option<String>) -> Self {
        use rand_core::{OsRng, RngCore};

        Self {
            salt: {
                let mut buf = [0; SALT_LENGTH];
                OsRng.fill_bytes(&mut buf);
                buf
            },
            code: Commitment::Id(code),
            tag,
        }
    }

    /// Make a new code section with the given hash
    pub fn from_hash(
        hash: namada_core::hash::Hash,
        tag: Option<String>,
    ) -> Self {
        use rand_core::{OsRng, RngCore};

        Self {
            salt: {
                let mut buf = [0; SALT_LENGTH];
                OsRng.fill_bytes(&mut buf);
                buf
            },
            code: Commitment::Hash(hash),
            tag,
        }
    }

    /// Hash this code section
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.salt);
        hasher.update(self.code.hash());
        hasher.update(self.tag.serialize_to_vec());
        hasher
    }
}

/// A memo field (bytes).
pub type Memo = Vec<u8>;

/// Indicates the list of public keys against which signatures will be verified
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub enum Signer {
    /// The address of a multisignature account
    Address(Address),
    /// The public keys that constitute a signer
    PubKeys(Vec<common::PublicKey>),
}

impl PartialEq for Signer {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Address(address), Self::Address(other_address)) => {
                address == other_address
            }
            (Self::PubKeys(pubkeys), Self::PubKeys(other_pubkeys)) => {
                // Check equivalence of the pubkeys ignoring the specific
                // ordering and duplicates (the PartialEq
                // implementation of IndexSet ignores the order)
                let unique_pubkeys =
                    HashSet::<&common::PublicKey>::from_iter(pubkeys.iter());
                let unique_other_pubkeys =
                    HashSet::<&common::PublicKey>::from_iter(
                        other_pubkeys.iter(),
                    );

                unique_pubkeys == unique_other_pubkeys
            }
            (Self::Address(addr), Self::PubKeys(pubkeys))
            | (Self::PubKeys(pubkeys), Self::Address(addr)) => {
                // If the set of public keys contains a single key we can try to
                // see if the key matches the address
                if pubkeys.len() == 1 {
                    addr == &pubkeys.first().unwrap().into()
                } else {
                    false
                }
            }
        }
    }
}

/// A section representing a multisig over another section
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct Authorization {
    /// The hash of the section being signed
    pub targets: Vec<namada_core::hash::Hash>,
    /// The public keys against which the signatures should be verified
    pub signer: Signer,
    /// The signature over the above hash
    pub signatures: BTreeMap<u8, common::Signature>,
}

impl PartialEq for Authorization {
    fn eq(&self, other: &Self) -> bool {
        // Deconstruct the two instances to ensure we don't forget any new field
        let Authorization {
            targets,
            signer,
            signatures,
        } = self;
        let Authorization {
            targets: other_targets,
            signer: other_signer,
            signatures: other_signatures,
        } = other;

        if signer != other_signer || signatures != other_signatures {
            return false;
        }

        // Check equivalence of the targets ignoring the specific ordering and
        // duplicates (the PartialEq implementation of IndexSet ignores the
        // order)
        let unique_targets =
            HashSet::<&namada_account::Hash>::from_iter(targets.iter());
        let unique_other_targets =
            HashSet::<&namada_account::Hash>::from_iter(other_targets.iter());

        unique_targets == unique_other_targets
    }
}

impl Authorization {
    // FIXME: can remove these two indirections?
    /// Sign the given section hash with the given key and return a section
    pub fn new(
        targets: Vec<namada_core::hash::Hash>,
        secret_keys: BTreeMap<u8, common::SecretKey>,
        signer: Option<Address>,
    ) -> Self {
        Self::create_signatures(targets, secret_keys, signer)
    }

    /// Place mock signatures over the given section hash with
    /// the given key and return a section
    pub fn mock(
        targets: Vec<namada_core::hash::Hash>,
        pubkeys: BTreeMap<u8, common::PublicKey>,
        signer: Option<Address>,
    ) -> Self {
        Self::create_signatures(targets, pubkeys, signer)
    }

    pub(crate) fn create_signatures(
        targets: Vec<namada_core::hash::Hash>,
        keys: BTreeMap<u8, impl SignOrMockKey>,
        signer: Option<Address>,
    ) -> Self {
        // If no signer address is given, then derive the signer's public keys
        // from the given keys.
        let signer = if let Some(addr) = signer {
            Signer::Address(addr)
        } else {
            // Make sure the corresponding public keys can be represented by a
            // vector instead of a map
            assert!(
                keys.keys().cloned().eq(0..(u8::try_from(keys.len())
                    .expect("Number of keys must not exceed `u8::MAX`"))),
                "keys must be enumerated when signer address is absent"
            );
            Signer::PubKeys(keys.values().map(|key| key.pubkey()).collect())
        };

        // Commit to the given targets
        let partial = Self {
            targets,
            signer,
            signatures: BTreeMap::new(),
        };
        let target = partial.get_raw_hash();
        // Turn the map of keys into a map of signatures over the commitment
        // made above
        let signatures = keys
            .iter()
            .map(|(idx, key)| (*idx, key.sign(target)))
            .collect();
        Self {
            signatures,
            ..partial
        }
    }

    /// Hash this signature section
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.serialize_to_vec());
        hasher
    }

    /// Get the hash of this section
    pub fn get_hash(&self) -> namada_core::hash::Hash {
        namada_core::hash::Hash(
            self.hash(&mut Sha256::new()).finalize_reset().into(),
        )
    }

    /// Get a hash of this section with its signer and signatures removed
    pub fn get_raw_hash(&self) -> namada_core::hash::Hash {
        Self {
            signer: Signer::PubKeys(vec![]),
            signatures: BTreeMap::new(),
            ..self.clone()
        }
        .get_hash()
    }

    /// Verify that the signature contained in this section is valid
    pub fn verify_signature<F>(
        &self,
        verified_pks: &mut HashSet<u8>,
        public_keys_index_map: &AccountPublicKeysMap,
        signer: &Option<Address>,
        consume_verify_sig_gas: &mut F,
    ) -> std::result::Result<u8, VerifySigError>
    where
        F: FnMut() -> std::result::Result<(), namada_gas::Error>,
    {
        // Records whether there are any successful verifications
        let mut verifications = 0;
        match &self.signer {
            // Verify the signatures against the given public keys if the
            // account addresses match
            Signer::Address(addr) if Some(addr) == signer.as_ref() => {
                for (idx, sig) in &self.signatures {
                    if let Some(pk) =
                        public_keys_index_map.get_public_key_from_index(*idx)
                    {
                        consume_verify_sig_gas()?;
                        common::SigScheme::verify_signature(
                            &pk,
                            &self.get_raw_hash(),
                            sig,
                        )?;
                        verified_pks.insert(*idx);
                        // Cannot overflow
                        #[allow(clippy::arithmetic_side_effects)]
                        {
                            verifications += 1;
                        }
                    }
                }
            }
            // If the account addresses do not match, then there is no efficient
            // way to map signatures to the given public keys
            Signer::Address(_) => {}
            // Verify the signatures against the subset of this section's public
            // keys that are also in the given map
            Signer::PubKeys(pks) => {
                let hash = self.get_raw_hash();
                if pks.len() > usize::from(u8::MAX) {
                    return Err(VerifySigError::PksOverflow);
                }
                #[allow(clippy::disallowed_types)] // ordering doesn't matter
                let unique_pks: std::collections::HashSet<
                    &common::PublicKey,
                > = std::collections::HashSet::from_iter(pks.iter());
                if unique_pks.len() != pks.len() {
                    return Err(VerifySigError::RepeatedPks);
                }
                for (idx, pk) in pks.iter().enumerate() {
                    let map_idx =
                        public_keys_index_map.get_index_from_public_key(pk);

                    // Use the first signature when fuzzing as the map is
                    // unlikely to contain matching PKs
                    #[cfg(fuzzing)]
                    let map_idx = map_idx.or(Some(0_u8));

                    if let Some(map_idx) = map_idx {
                        let sig_idx = u8::try_from(idx)
                            .map_err(|_| VerifySigError::PksOverflow)?;
                        consume_verify_sig_gas()?;
                        let sig = self
                            .signatures
                            .get(&sig_idx)
                            .ok_or(VerifySigError::MissingSignature)?;
                        common::SigScheme::verify_signature(pk, &hash, sig)?;
                        verified_pks.insert(map_idx);
                        // Cannot overflow
                        #[allow(clippy::arithmetic_side_effects)]
                        {
                            verifications += 1;
                        }
                    }
                }
            }
        }

        // There's usually not enough signatures when fuzzing, this makes it
        // more likely to pass authorization.
        #[cfg(fuzzing)]
        {
            verifications = 1;
        }

        Ok(verifications)
    }

    /// Mock a signature verification while still consuming gas. Used
    /// for dry-running txs.
    pub fn dry_run_signature<F>(
        &self,
        verified_pks: &mut HashSet<u8>,
        public_keys_index_map: &AccountPublicKeysMap,
        signer: &Option<Address>,
        consume_verify_sig_gas: &mut F,
    ) -> std::result::Result<u8, VerifySigError>
    where
        F: FnMut() -> std::result::Result<(), namada_gas::Error>,
    {
        // Records whether there are any successful verifications
        let mut verifications = 0;
        match &self.signer {
            // Verify the signatures against the given public keys if the
            // account addresses match
            Signer::Address(addr) if Some(addr) == signer.as_ref() => {
                for idx in self.signatures.keys() {
                    if public_keys_index_map
                        .get_public_key_from_index(*idx)
                        .is_some()
                    {
                        consume_verify_sig_gas()?;
                        verified_pks.insert(*idx);
                        // Cannot overflow
                        #[allow(clippy::arithmetic_side_effects)]
                        {
                            verifications += 1;
                        }
                    }
                }
            }
            // If the account addresses do not match, then there is no efficient
            // way to map signatures to the given public keys
            Signer::Address(_) => {}
            // Verify the signatures against the subset of this section's public
            // keys that are also in the given map
            Signer::PubKeys(pks) => {
                if pks.len() > usize::from(u8::MAX) {
                    return Err(VerifySigError::PksOverflow);
                }
                #[allow(clippy::disallowed_types)] // ordering doesn't matter
                let unique_pks: std::collections::HashSet<
                    &common::PublicKey,
                > = std::collections::HashSet::from_iter(pks.iter());
                if unique_pks.len() != pks.len() {
                    return Err(VerifySigError::RepeatedPks);
                }
                for (idx, pk) in pks.iter().enumerate() {
                    let map_idx =
                        public_keys_index_map.get_index_from_public_key(pk);

                    if let Some(map_idx) = map_idx {
                        let sig_idx = u8::try_from(idx)
                            .map_err(|_| VerifySigError::PksOverflow)?;
                        consume_verify_sig_gas()?;
                        _ = self
                            .signatures
                            .get(&sig_idx)
                            .ok_or(VerifySigError::MissingSignature)?;
                        verified_pks.insert(map_idx);
                        // Cannot overflow
                        #[allow(clippy::arithmetic_side_effects)]
                        {
                            verifications += 1;
                        }
                    }
                }
            }
        }

        Ok(verifications)
    }
}

/// A section representing a multisig over another section
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct CompressedAuthorization {
    /// The hash of the section being signed
    pub targets: Vec<u8>,
    /// The public keys against which the signatures should be verified
    pub signer: Signer,
    /// The signature over the above hash
    pub signatures: BTreeMap<u8, common::Signature>,
}

impl CompressedAuthorization {
    /// Decompress this signature object with respect to the given transaction
    /// by looking up the necessary section hashes. Used by constrained hardware
    /// wallets.
    pub fn expand(self, tx: &Tx) -> Authorization {
        let mut targets = Vec::new();
        for idx in self.targets {
            if idx == 0 {
                // The "zeroth" section is the header
                targets.push(tx.header_hash());
            } else if idx == 255 {
                // The 255th section is the raw header
                targets.push(tx.raw_header_hash());
            } else {
                targets.push(
                    tx.sections[(idx as usize)
                        .checked_sub(1)
                        .expect("cannot underflow")]
                    .get_hash(),
                );
            }
        }
        Authorization {
            targets,
            signer: self.signer,
            signatures: self.signatures,
        }
    }
}

/// An inner transaction of the batch, represented by its commitments to the
/// [`Code`], [`Data`] and [`Memo`] sections
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Debug,
    Default,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
)]
pub struct TxCommitments {
    /// The SHA-256 hash of the transaction's code section
    pub code_hash: namada_core::hash::Hash,
    /// The SHA-256 hash of the transaction's data section
    pub data_hash: namada_core::hash::Hash,
    /// The SHA-256 hash of the transaction's memo section
    ///
    /// In case a memo is not present in the transaction, a
    /// byte array filled with zeroes is present instead
    pub memo_hash: namada_core::hash::Hash,
}

impl TxCommitments {
    /// Get the hash of this transaction's code
    pub fn code_sechash(&self) -> &namada_core::hash::Hash {
        &self.code_hash
    }

    /// Get the transaction data hash
    pub fn data_sechash(&self) -> &namada_core::hash::Hash {
        &self.data_hash
    }

    /// Get the hash of this transaction's memo
    pub fn memo_sechash(&self) -> &namada_core::hash::Hash {
        &self.memo_hash
    }

    /// Hash the commitments to the transaction's sections
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.serialize_to_vec());
        hasher
    }

    /// Get the hash of this Commitments
    pub fn get_hash(&self) -> namada_core::hash::Hash {
        namada_core::hash::Hash(
            self.hash(&mut Sha256::new()).finalize_reset().into(),
        )
    }
}

/// A section providing the auxiliary inputs used to construct a MASP
/// transaction
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct MaspBuilder {
    /// The MASP transaction that this section witnesses
    pub target: MaspTxId,
    /// The decoded set of asset types used by the transaction. Useful for
    /// offline wallets trying to display AssetTypes.
    pub asset_types: HashSet<AssetData>,
    /// Track how Info objects map to descriptors and outputs
    #[serde(
        serialize_with = "borsh_serde::<SaplingMetadataSerde, _>",
        deserialize_with = "serde_borsh::<SaplingMetadataSerde, _, _>"
    )]
    pub metadata: SaplingMetadata,
    /// The data that was used to construct the target transaction
    #[serde(
        serialize_with = "borsh_serde::<BuilderSerde, _>",
        deserialize_with = "serde_borsh::<BuilderSerde, _, _>"
    )]
    pub builder: Builder<(), ExtendedFullViewingKey, ()>,
}

impl PartialEq for MaspBuilder {
    fn eq(&self, other: &Self) -> bool {
        self.target == other.target
    }
}

impl MaspBuilder {
    /// Get the hash of this ciphertext section. This operation is done in such
    /// a way it matches the hash of the type pun
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.serialize_to_vec());
        hasher
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for MaspBuilder {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'_>,
    ) -> arbitrary::Result<Self> {
        use masp_primitives::transaction::builder::MapBuilder;
        use masp_primitives::transaction::components::sapling::builder::MapBuilder as SapMapBuilder;
        use masp_primitives::zip32::ExtendedSpendingKey;
        struct WalletMap;

        impl<P1>
            SapMapBuilder<P1, ExtendedSpendingKey, (), ExtendedFullViewingKey>
            for WalletMap
        {
            fn map_params(&self, _s: P1) {}

            fn map_key(
                &self,
                s: ExtendedSpendingKey,
            ) -> ExtendedFullViewingKey {
                (&s).into()
            }
        }
        impl<P1, N1>
            MapBuilder<
                P1,
                ExtendedSpendingKey,
                N1,
                (),
                ExtendedFullViewingKey,
                (),
            > for WalletMap
        {
            fn map_notifier(&self, _s: N1) {}
        }

        let target_height = masp_primitives::consensus::BlockHeight::from(
            u.int_in_range(0_u32..=100_000_000)?,
        );
        Ok(MaspBuilder {
            target: arbitrary::Arbitrary::arbitrary(u)?,
            asset_types: arbitrary::Arbitrary::arbitrary(u)?,
            metadata: arbitrary::Arbitrary::arbitrary(u)?,
            builder: Builder::new(
                masp_primitives::consensus::TestNetwork,
                target_height,
            )
            .map_builder(WalletMap),
        })
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        arbitrary::size_hint::and_all(
                        &[
                            <masp_primitives::consensus::BlockHeight as arbitrary::Arbitrary>::size_hint(depth),
                            <MaspTxId as arbitrary::Arbitrary>::size_hint(depth),
                            <HashSet<AssetData> as arbitrary::Arbitrary>::size_hint(depth),
                            <SaplingMetadata as arbitrary::Arbitrary>::size_hint(depth),
                        ],
                    )
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TransactionSerde(Vec<u8>);

impl From<Vec<u8>> for TransactionSerde {
    fn from(tx: Vec<u8>) -> Self {
        Self(tx)
    }
}

impl From<TransactionSerde> for Vec<u8> {
    fn from(tx: TransactionSerde) -> Vec<u8> {
        tx.0
    }
}

/// A structure to facilitate Serde (de)serializations of Builders
#[derive(serde::Serialize, serde::Deserialize)]
struct BuilderSerde(Vec<u8>);

impl From<Vec<u8>> for BuilderSerde {
    fn from(tx: Vec<u8>) -> Self {
        Self(tx)
    }
}

impl From<BuilderSerde> for Vec<u8> {
    fn from(tx: BuilderSerde) -> Vec<u8> {
        tx.0
    }
}

/// A structure to facilitate Serde (de)serializations of SaplingMetadata
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SaplingMetadataSerde(Vec<u8>);

impl From<Vec<u8>> for SaplingMetadataSerde {
    fn from(tx: Vec<u8>) -> Self {
        Self(tx)
    }
}

impl From<SaplingMetadataSerde> for Vec<u8> {
    fn from(tx: SaplingMetadataSerde) -> Vec<u8> {
        tx.0
    }
}

fn borsh_serde<T, S>(
    obj: &impl BorshSerialize,
    ser: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: From<Vec<u8>>,
    T: serde::Serialize,
{
    Into::<T>::into(obj.serialize_to_vec()).serialize(ser)
}

fn serde_borsh<'de, T, S, U>(ser: S) -> std::result::Result<U, S::Error>
where
    S: serde::Deserializer<'de>,
    T: Into<Vec<u8>>,
    T: serde::Deserialize<'de>,
    U: BorshDeserialize,
{
    BorshDeserialize::try_from_slice(&Into::<Vec<u8>>::into(T::deserialize(
        ser,
    )?))
    .map_err(S::Error::custom)
}

#[cfg(test)]
mod test {
    use testing::gen_keypair;

    use super::*;

    #[test]
    fn auth_verify_sig_cannot_overflow() {
        // The number of PKs in a multi-sig is limited to `u8::MAX`.
        // We're checking that having an extra one is handled correctly.
        const ABOVE_LIMIT: usize = u8::MAX as usize + 1;

        let sk: common::SecretKey =
            gen_keypair::<ed25519::SigScheme>().try_to_sk().unwrap();
        let pk = sk.to_public();

        // Repeat the same PK - they don't have to be unique
        let pks: Vec<common::PublicKey> =
            std::iter::repeat_n(pk.clone(), ABOVE_LIMIT).collect();
        let raw_auth = Authorization {
            targets: vec![],
            signer: Signer::PubKeys(pks),
            signatures: Default::default(),
        };
        let hash = raw_auth.get_raw_hash();
        let sig = common::SigScheme::sign(&sk, hash);

        // Add the same signature for each PK index
        let signatures = BTreeMap::from_iter(
            (0..ABOVE_LIMIT).map(|ix| (u8::try_from(ix).unwrap(), sig.clone())),
        );
        let auth = Authorization {
            signatures,
            ..raw_auth
        };

        let mut verified_pks = HashSet::new();
        let public_keys_index_map = AccountPublicKeysMap::from_iter([pk]);

        // This call must not panic
        let res = auth.verify_signature(
            &mut verified_pks,
            &public_keys_index_map,
            &None,
            &mut || Ok(()),
        );
        assert!(matches!(res.unwrap_err(), VerifySigError::PksOverflow))
    }
}
